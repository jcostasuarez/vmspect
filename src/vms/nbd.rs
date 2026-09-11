//! Client and connector for `qemu-nbd` (Network Block Device).
//!
//! Provides access to disk formats that are not supported natively (or that the user forces
//! through `qemu-nbd`) by serving the image through a background `qemu-nbd` subprocess and
//! reading blocks via a UNIX socket or a loopback TCP socket (127.0.0.1). This avoids the cost
//! of repeatedly spawning subprocesses or writing temporary files to disk.

use crate::models::{ImageInfo, Options};
use crate::vms::stream::new_command;
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::sleep;
use std::time::{Duration, Instant};

const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_REPLY_MAGIC: u32 = 0x6744_6698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_DISC: u16 = 2;

const NBD_OPT_EXPORT_NAME: u32 = 1;
const DEFAULT_NBD_TIMEOUT: Duration = Duration::from_secs(3);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_millis(200);

fn remaining(deadline: Instant, context: &str) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, format!("Timed out {context}")))
}

fn contextualize_timeout(error: io::Error, context: &str) -> io::Error {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        io::Error::new(io::ErrorKind::TimedOut, format!("Timed out {context}"))
    } else {
        io::Error::new(error.kind(), format!("NBD {context}: {error}"))
    }
}

/// Process-wide accounting for active qemu-nbd sessions.
static NBD_SESSIONS: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();

struct NbdSessionPermit;

impl NbdSessionPermit {
    fn acquire(options: &Options, deadline: Instant) -> io::Result<Self> {
        let (active, wake) = NBD_SESSIONS.get_or_init(|| (Mutex::new(0), Condvar::new()));
        let limit = options.nbd_max_sessions.max(1);
        let mut count = active.lock().unwrap_or_else(|error| error.into_inner());
        while *count >= limit {
            if options
                .cancel_token
                .as_ref()
                .map(|token| token.load(Ordering::Acquire))
                .unwrap_or(false)
            {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Inspection cancelled",
                ));
            }
            let wait = remaining(deadline, "waiting for an NBD session slot")?
                .min(Duration::from_millis(50));
            let (new_count, _) = wake
                .wait_timeout(count, wait)
                .unwrap_or_else(|error| error.into_inner());
            count = new_count;
        }
        *count += 1;
        Ok(Self)
    }
}

impl Drop for NbdSessionPermit {
    fn drop(&mut self) {
        let (active, wake) = NBD_SESSIONS.get_or_init(|| (Mutex::new(0), Condvar::new()));
        let mut count = active.lock().unwrap_or_else(|error| error.into_inner());
        *count = count.saturating_sub(1);
        wake.notify_one();
    }
}
const NBD_IHAVEOPT_MAGIC: u64 = 0x4948_4156_454F_5054; // "IHAVEOPT"

/// Transport abstraction for the NBD communication stream (TCP or UNIX socket).
enum StreamTransport {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl StreamTransport {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            StreamTransport::Tcp(stream) => stream.set_read_timeout(timeout),
            #[cfg(unix)]
            StreamTransport::Unix(stream) => stream.set_read_timeout(timeout),
        }
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            StreamTransport::Tcp(stream) => stream.set_write_timeout(timeout),
            #[cfg(unix)]
            StreamTransport::Unix(stream) => stream.set_write_timeout(timeout),
        }
    }

    fn shutdown(&self) -> io::Result<()> {
        match self {
            StreamTransport::Tcp(s) => s.shutdown(std::net::Shutdown::Both),
            #[cfg(unix)]
            StreamTransport::Unix(s) => s.shutdown(std::net::Shutdown::Both),
        }
    }
}

impl Read for StreamTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            StreamTransport::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            StreamTransport::Unix(s) => s.read(buf),
        }
    }
}

impl Write for StreamTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            StreamTransport::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            StreamTransport::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            StreamTransport::Tcp(s) => s.flush(),
            #[cfg(unix)]
            StreamTransport::Unix(s) => s.flush(),
        }
    }
}

/// Minimal client for the NBD (Network Block Device) protocol.
pub struct NbdStream {
    stream: StreamTransport,
    export_size: u64,
    request_id: u64,
    io_timeout: Duration,
    disconnected: bool,
}

impl NbdStream {
    fn read_exact_until(
        stream: &mut StreamTransport,
        buffer: &mut [u8],
        deadline: Instant,
        context: &str,
    ) -> io::Result<()> {
        let mut read = 0;
        while read < buffer.len() {
            stream.set_read_timeout(Some(remaining(deadline, context)?))?;
            match stream.read(&mut buffer[read..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("NBD {context}: connection closed"),
                    ))
                }
                Ok(n) => read += n,
                Err(error) => return Err(contextualize_timeout(error, context)),
            }
        }
        Ok(())
    }

    fn write_all_until(
        stream: &mut StreamTransport,
        buffer: &[u8],
        deadline: Instant,
        context: &str,
    ) -> io::Result<()> {
        let mut written = 0;
        while written < buffer.len() {
            stream.set_write_timeout(Some(remaining(deadline, context)?))?;
            match stream.write(&buffer[written..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("NBD {context}: connection closed"),
                    ))
                }
                Ok(n) => written += n,
                Err(error) => return Err(contextualize_timeout(error, context)),
            }
        }
        stream.set_write_timeout(Some(remaining(deadline, context)?))?;
        stream
            .flush()
            .map_err(|error| contextualize_timeout(error, context))
    }

    /// Performs the standard (newstyle) handshake over the provided transport.
    fn handshake(
        mut stream: StreamTransport,
        deadline: Instant,
        io_timeout: Duration,
    ) -> io::Result<Self> {
        // Magic: "NBDMAGIC" (8 bytes) + "IHAVEOPT" (8 bytes) + flags (2 bytes)
        let mut banner = [0u8; 18];
        Self::read_exact_until(&mut stream, &mut banner, deadline, "reading NBD banner")?;

        if &banner[0..8] != b"NBDMAGIC" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid NBD signature from the server",
            ));
        }

        let opt_magic = banner
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Buffer too small for opt_magic")
            })?;
        if opt_magic != NBD_IHAVEOPT_MAGIC {
            // Old-style handshake
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "The NBD server does not use the newstyle handshake",
            ));
        }

        let _server_flags = banner
            .get(16..18)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_be_bytes)
            .unwrap_or(0);

        // 2. Send client flags (NBD_FLAG_C_FIXED_NEWSTYLE = 1)
        let client_flags: u32 = 1;
        Self::write_all_until(
            &mut stream,
            &client_flags.to_be_bytes(),
            deadline,
            "sending NBD client flags",
        )?;

        // 3. Negotiate the export (NBD_OPT_EXPORT_NAME = 1, export_name = "")
        let export_name = b"";
        let mut opt_req = Vec::with_capacity(16 + export_name.len());
        opt_req.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
        opt_req.extend_from_slice(&NBD_OPT_EXPORT_NAME.to_be_bytes());
        opt_req.extend_from_slice(&(export_name.len() as u32).to_be_bytes());
        opt_req.extend_from_slice(export_name);
        Self::write_all_until(&mut stream, &opt_req, deadline, "requesting NBD export")?;

        // 4. Receive the export reply.
        // export_size (8 bytes) + flags (2 bytes) + zeros (124 bytes) = 134 bytes
        let mut resp = [0u8; 134];
        Self::read_exact_until(&mut stream, &mut resp, deadline, "reading NBD export reply")?;

        let export_size = resp
            .get(0..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer too small for export_size",
                )
            })?;

        stream.set_read_timeout(Some(io_timeout))?;
        stream.set_write_timeout(Some(io_timeout))?;
        Ok(Self {
            stream,
            export_size,
            request_id: 1,
            io_timeout,
            disconnected: false,
        })
    }

    /// Connects to an NBD server and performs the standard (newstyle) handshake over TCP.
    pub fn connect(address: &str) -> io::Result<Self> {
        Self::connect_tcp(address)
    }

    /// Connects to an NBD server over TCP and performs the standard handshake.
    pub fn connect_tcp(address: &str) -> io::Result<Self> {
        Self::connect_tcp_with_timeout(address, DEFAULT_NBD_TIMEOUT)
    }

    fn connect_tcp_with_timeout(address: &str, timeout: Duration) -> io::Result<Self> {
        Self::connect_tcp_with_timeouts(address, timeout, timeout)
    }

    fn connect_tcp_with_timeouts(
        address: &str,
        handshake_timeout: Duration,
        io_timeout: Duration,
    ) -> io::Result<Self> {
        let deadline = Instant::now() + handshake_timeout;
        let addresses = address.to_socket_addrs()?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect_timeout(
                &address,
                remaining(deadline, "connecting to NBD server")?,
            ) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Self::handshake(StreamTransport::Tcp(stream), deadline, io_timeout);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "NBD address did not resolve",
            )
        }))
    }

    /// Connects to an NBD server via a UNIX domain socket.
    pub fn connect_unix(path: &Path) -> io::Result<Self> {
        Self::connect_unix_with_timeout(path, DEFAULT_NBD_TIMEOUT)
    }

    fn connect_unix_with_timeout(path: &Path, timeout: Duration) -> io::Result<Self> {
        Self::connect_unix_with_timeouts(path, timeout, timeout)
    }

    fn connect_unix_with_timeouts(
        path: &Path,
        handshake_timeout: Duration,
        io_timeout: Duration,
    ) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(path)?;
            Self::handshake(
                StreamTransport::Unix(stream),
                Instant::now() + handshake_timeout,
                io_timeout,
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (path, handshake_timeout, io_timeout);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UNIX domain sockets are not supported on this platform",
            ))
        }
    }

    /// Returns the total size, in bytes, exported by the NBD server.
    pub fn export_size(&self) -> u64 {
        self.export_size
    }

    /// Reads a chunk of bytes starting at `offset` of length `len`.
    pub fn read_range(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        if offset >= self.export_size {
            return Ok(Vec::new());
        }

        let adjusted_len = len.min((self.export_size - offset) as usize);
        let req_id = self.request_id;
        self.request_id = self.request_id.wrapping_add(1);

        // Build the NBD request header (28 bytes)
        // 4: Magic, 2: Flags, 2: Command, 8: Handle, 8: Offset, 4: Length
        let mut req = [0u8; 28];
        req[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        req[4..6].copy_from_slice(&0u16.to_be_bytes());
        req[6..8].copy_from_slice(&NBD_CMD_READ.to_be_bytes());
        req[8..16].copy_from_slice(&req_id.to_be_bytes());
        req[16..24].copy_from_slice(&offset.to_be_bytes());
        req[24..28].copy_from_slice(&(adjusted_len as u32).to_be_bytes());

        let deadline = Instant::now() + self.io_timeout;
        Self::write_all_until(&mut self.stream, &req, deadline, "sending NBD read request")?;

        // Read the response header (16 bytes)
        // 4: Magic, 4: Error, 8: Handle
        let mut resp_hdr = [0u8; 16];
        Self::read_exact_until(
            &mut self.stream,
            &mut resp_hdr,
            deadline,
            "reading NBD reply header",
        )?;

        let magic = resp_hdr
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Buffer too small for magic")
            })?;
        if magic != NBD_REPLY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("NBD reply with invalid magic: 0x{:08X}", magic),
            ));
        }

        let error_code = resp_hdr
            .get(4..8)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer too small for error_code",
                )
            })?;
        if error_code != 0 {
            return Err(io::Error::other(format!(
                "Error reported by the NBD server: {}",
                error_code
            )));
        }

        let handle = resp_hdr
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Buffer too small for handle")
            })?;
        if handle != req_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NBD request identifier is out of sync",
            ));
        }

        let mut data = vec![0u8; adjusted_len];
        Self::read_exact_until(
            &mut self.stream,
            &mut data,
            deadline,
            "reading NBD reply data",
        )?;

        Ok(data)
    }

    /// Cleanly closes the NBD session by sending the disconnect command and closing the socket.
    pub fn disconnect(&mut self) {
        if self.disconnected {
            return;
        }
        self.disconnected = true;
        let req_id = self.request_id;
        let mut req = [0u8; 28];
        req[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        req[6..8].copy_from_slice(&NBD_CMD_DISC.to_be_bytes());
        req[8..16].copy_from_slice(&req_id.to_be_bytes());
        // Cleanup must remain bounded even when normal I/O permits a longer timeout.
        let cleanup_timeout = self.io_timeout.min(PROCESS_CLEANUP_TIMEOUT);
        let deadline = Instant::now() + cleanup_timeout;
        let _ = Self::write_all_until(&mut self.stream, &req, deadline, "sending NBD disconnect");
        let _ = self.stream.shutdown();
    }
}

impl Drop for NbdStream {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Selected connection transport used to negotiate with the `qemu-nbd` subprocess.
///
/// Models the mutually exclusive choice between a UNIX socket and a loopback TCP connection
/// as a type invariant, avoiding invalid intermediate states at runtime.
enum NbdTransport {
    Tcp(String),
    Unix(PathBuf),
}

impl NbdTransport {
    fn connect(&self, deadline: Instant, io_timeout: Duration) -> io::Result<NbdStream> {
        let timeout = remaining(deadline, "connecting to qemu-nbd")?;
        match self {
            NbdTransport::Unix(path) => {
                NbdStream::connect_unix_with_timeouts(path, timeout, io_timeout)
            }
            NbdTransport::Tcp(address) => {
                NbdStream::connect_tcp_with_timeouts(address, timeout, io_timeout)
            }
        }
    }

    fn unix_socket(&self) -> Option<PathBuf> {
        match self {
            NbdTransport::Unix(path) => Some(path.clone()),
            NbdTransport::Tcp(_) => None,
        }
    }
}

#[cfg(windows)]
fn new_nbd_command(path: &Path) -> std::process::Command {
    let is_batch_script = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| matches!(extension.to_ascii_lowercase().as_str(), "cmd" | "bat"))
        .unwrap_or(false);

    if is_batch_script {
        let mut command = new_command("cmd.exe");
        command.arg("/C").arg("call").arg(path);
        command
    } else {
        new_command(path)
    }
}

#[cfg(not(windows))]
fn new_nbd_command(path: &Path) -> std::process::Command {
    new_command(path)
}

/// Makes a best effort to terminate and reap a child without allowing cleanup to block forever.
///
/// A child that does not exit within [`PROCESS_CLEANUP_TIMEOUT`] may remain alive after this
/// function returns. Returns whether the child was reaped, which makes reading its stderr safe.
fn terminate_and_reap(child: &mut Child) -> bool {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return true;
    }

    let _ = child.kill();
    let deadline = Instant::now() + PROCESS_CLEANUP_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) | Err(_) => sleep(Duration::from_millis(10)),
        }
    }
    matches!(child.try_wait(), Ok(Some(_)))
}

fn terminate_and_collect_stderr(child: &mut Child) -> String {
    if terminate_and_reap(child) {
        read_child_stderr(child)
    } else {
        String::new()
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let mut stderr_text = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut stderr_text);
    }
    stderr_text.trim().to_string()
}

fn nbd_exit_message(path: &Path, status: std::process::ExitStatus, stderr: &str) -> String {
    if stderr.is_empty() {
        format!(
            "qemu-nbd '{}' exited with code {:?}",
            path.display(),
            status.code()
        )
    } else {
        format!(
            "qemu-nbd '{}' exited with code {:?}; stderr: {}",
            path.display(),
            status.code(),
            stderr
        )
    }
}

/// Reader backed by a `qemu-nbd` server running in the background.
pub struct NbdReader {
    // Fields are ordered so the stream and process are dropped before the permit.
    client: RefCell<NbdStream>,
    process: Child,
    unix_socket: Option<PathBuf>,
    _permit: NbdSessionPermit,
}

impl NbdReader {
    /// Spawns a `qemu-nbd` subprocess and connects via NBD using the default options.
    pub fn open(
        qemu_nbd_path: &Path,
        info: &ImageInfo,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        let options = Options {
            cancel_token,
            ..Options::default()
        };
        Self::open_with_options(qemu_nbd_path, info, &options)
    }

    /// Spawns a `qemu-nbd` subprocess with the given options and connects via NBD
    /// (over a UNIX socket or a loopback TCP connection according to the configuration).
    pub fn open_with_options(
        qemu_nbd_path: &Path,
        info: &ImageInfo,
        options: &Options,
    ) -> io::Result<Self> {
        if let Some(ref cancel) = options.cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Inspection cancelled by the user",
                ));
            }
        }

        let timeout = options.connection_timeout.unwrap_or(DEFAULT_NBD_TIMEOUT);
        let deadline = Instant::now() + timeout;
        let permit = NbdSessionPermit::acquire(options, deadline)?;
        let mut cmd = new_nbd_command(qemu_nbd_path);
        cmd.arg("--read-only");

        // Only include --persistent when explicitly requested
        if options.nbd_persistent {
            cmd.arg("--persistent");
        }

        // Append additional CLI arguments
        for arg in &options.extra_nbd_args {
            cmd.arg(arg);
        }

        let transport = if let Some(ref socket_path) = options.unix_socket {
            // Remove any orphaned socket file that may already exist
            let _ = std::fs::remove_file(socket_path);
            cmd.arg("-k").arg(socket_path);
            NbdTransport::Unix(socket_path.clone())
        } else {
            // Dynamically allocate an ephemeral TCP port on 127.0.0.1
            let port = {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                listener.local_addr()?.port()
            };
            cmd.arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string());
            NbdTransport::Tcp(format!("127.0.0.1:{}", port))
        };

        cmd.arg(&info.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            io::Error::other(format!(
                "Could not start qemu-nbd ({}): {}",
                qemu_nbd_path.display(),
                e
            ))
        })?;

        // Retry connection and handshake within the single initialization deadline.
        let mut client_opt = None;
        let mut last_connection_error = None;

        while Instant::now() < deadline {
            if let Some(ref cancel) = options.cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    let _ = terminate_and_reap(&mut child);
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Inspection cancelled",
                    ));
                }
            }

            // Check whether the process terminated prematurely with an error.
            match child.try_wait() {
                Ok(Some(status)) => {
                    let err_msg = read_child_stderr(&mut child);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        nbd_exit_message(qemu_nbd_path, status, &err_msg),
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    let stderr = terminate_and_collect_stderr(&mut child);
                    let detail = if stderr.is_empty() {
                        format!(
                            "Could not query qemu-nbd '{}' process status: {}",
                            qemu_nbd_path.display(),
                            error
                        )
                    } else {
                        format!(
                            "Could not query qemu-nbd '{}' process status: {}; stderr: {}",
                            qemu_nbd_path.display(),
                            error,
                            stderr
                        )
                    };
                    return Err(io::Error::other(detail));
                }
            }

            match transport.connect(deadline, timeout) {
                Ok(stream) => {
                    client_opt = Some(stream);
                    break;
                }
                Err(error) => {
                    let retryable = matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::NotFound
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::AddrNotAvailable
                    );
                    if !retryable {
                        let stderr = terminate_and_collect_stderr(&mut child);
                        let detail = if stderr.is_empty() {
                            format!(
                                "qemu-nbd '{}' NBD handshake failed: {}",
                                qemu_nbd_path.display(),
                                error
                            )
                        } else {
                            format!(
                                "qemu-nbd '{}' NBD handshake failed: {}; stderr: {}",
                                qemu_nbd_path.display(),
                                error,
                                stderr
                            )
                        };
                        return Err(io::Error::new(error.kind(), detail));
                    }
                    last_connection_error = Some(error);
                    sleep(Duration::from_millis(50));
                }
            }
        }

        let client = match client_opt {
            Some(c) => c,
            None => {
                // The connection attempt can consume the final polling interval. Check one
                // last time before reporting a timeout so an already-exited qemu-nbd keeps its
                // exit code and stderr.
                if let Ok(Some(status)) = child.try_wait() {
                    let err_msg = read_child_stderr(&mut child);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        nbd_exit_message(qemu_nbd_path, status, &err_msg),
                    ));
                }

                let stderr = terminate_and_collect_stderr(&mut child);
                let last_error = last_connection_error
                    .map(|error| format!("; last connection error: {error}"))
                    .unwrap_or_default();
                let detail = if stderr.is_empty() {
                    format!(
                        "Timed out waiting for qemu-nbd '{}' to accept connections{}",
                        qemu_nbd_path.display(),
                        last_error
                    )
                } else {
                    format!(
                        "Timed out waiting for qemu-nbd '{}' to accept connections; stderr: {}{}",
                        qemu_nbd_path.display(),
                        stderr,
                        last_error
                    )
                };
                return Err(io::Error::new(io::ErrorKind::TimedOut, detail));
            }
        };

        Ok(Self {
            client: RefCell::new(client),
            process: child,
            unix_socket: transport.unix_socket(),
            _permit: permit,
        })
    }

    /// Returns the virtual size of the disk exported by the NBD server.
    pub fn virtual_size(&self) -> u64 {
        self.client.borrow().export_size()
    }

    /// Reads an arbitrary byte range directly through the NBD socket.
    pub fn read_range(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.client.borrow_mut().read_range(offset, len)
    }
}

impl Drop for NbdReader {
    fn drop(&mut self) {
        // 1. Close the read/connection stream first.
        self.client.borrow_mut().disconnect();

        // 2. Check whether the subprocess already finished, or force a defensive kill and reap.
        match self.process.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = terminate_and_reap(&mut self.process);
            }
        }

        // 3. Clean up the UNIX socket file if one was configured.
        if let Some(ref path) = self.unix_socket {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Locates the `qemu-nbd` binary on the system.
pub fn resolve_qemu_nbd(explicit: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "qemu-nbd executable was not found on the system at the configured path '{}'",
                path.display()
            ),
        ));
    }

    if let Some(value) = std::env::var_os("QEMU_NBD") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "qemu-nbd executable was not found on the system via QEMU_NBD='{}'",
                path.display()
            ),
        ));
    }

    let candidates = [
        r"C:\Program Files\qemu\qemu-nbd.exe",
        r"C:\Program Files (x86)\qemu\qemu-nbd.exe",
        "/usr/bin/qemu-nbd",
        "/usr/local/bin/qemu-nbd",
        "/opt/homebrew/bin/qemu-nbd",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }

    // Look up in PATH. A successful spawn is enough to establish that the executable exists;
    // qemu-nbd's exit code for `--version` is not relevant to resolution.
    match new_command("qemu-nbd")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(_) => Ok(PathBuf::from("qemu-nbd")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "qemu-nbd executable was not found on the system. Install it, add it to PATH, define QEMU_NBD, or use --qemu-nbd <path>.",
        )),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("Could not resolve qemu-nbd from PATH: {error}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nbd_request_magic() {
        assert_eq!(NBD_REQUEST_MAGIC, 0x2560_9513);
        assert_eq!(NBD_REPLY_MAGIC, 0x6744_6698);
        assert_eq!(NBD_CMD_READ, 0);
        assert_eq!(NBD_CMD_DISC, 2);
    }

    #[test]
    fn test_nbd_stream_tcp_handshake_times_out_without_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });

        let started = Instant::now();
        let error = match NbdStream::connect_tcp_with_timeout(&address, Duration::from_millis(200))
        {
            Ok(_) => panic!("a server that never sends its banner must time out"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(server);
    }

    #[test]
    fn test_nbd_stream_handshake_preserves_io_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(120));

            let mut banner = Vec::new();
            banner.extend_from_slice(b"NBDMAGIC");
            banner.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
            banner.extend_from_slice(&0u16.to_be_bytes());
            stream.write_all(&banner).unwrap();

            let mut client_flags = [0u8; 4];
            stream.read_exact(&mut client_flags).unwrap();
            let mut opt_req = [0u8; 16];
            stream.read_exact(&mut opt_req).unwrap();

            let mut export_reply = vec![0u8; 134];
            export_reply[0..8].copy_from_slice(&4u64.to_be_bytes());
            stream.write_all(&export_reply).unwrap();

            let mut read_request = [0u8; 28];
            stream.read_exact(&mut read_request).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });

        let mut nbd =
            NbdStream::connect_tcp_with_timeout(&address, Duration::from_millis(200)).unwrap();
        let read_started = Instant::now();
        let error = nbd.read_range(0, 4).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(read_started.elapsed() >= Duration::from_millis(160));
        drop(nbd);
        server.join().unwrap();
    }

    #[test]
    fn test_nbd_stream_tcp_mock_handshake_and_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // 1. Send initial banner (18 bytes)
            let mut banner = Vec::new();
            banner.extend_from_slice(b"NBDMAGIC");
            banner.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
            banner.extend_from_slice(&0u16.to_be_bytes());
            stream.write_all(&banner).unwrap();
            stream.flush().unwrap();

            // 2. Read client flags (4 bytes)
            let mut client_flags = [0u8; 4];
            stream.read_exact(&mut client_flags).unwrap();
            assert_eq!(u32::from_be_bytes(client_flags), 1);

            // 3. Read option request (16 bytes)
            let mut opt_req = [0u8; 16];
            stream.read_exact(&mut opt_req).unwrap();

            // 4. Send export reply (134 bytes): export size = 2048
            let mut export_reply = vec![0u8; 134];
            export_reply[0..8].copy_from_slice(&2048u64.to_be_bytes());
            stream.write_all(&export_reply).unwrap();
            stream.flush().unwrap();

            // 5. Read the read request (28 bytes)
            let mut read_req = [0u8; 28];
            stream.read_exact(&mut read_req).unwrap();
            assert_eq!(
                u32::from_be_bytes(read_req[0..4].try_into().unwrap()),
                NBD_REQUEST_MAGIC
            );
            assert_eq!(
                u16::from_be_bytes(read_req[6..8].try_into().unwrap()),
                NBD_CMD_READ
            );
            let handle = u64::from_be_bytes(read_req[8..16].try_into().unwrap());
            let offset = u64::from_be_bytes(read_req[16..24].try_into().unwrap());
            let len = u32::from_be_bytes(read_req[24..28].try_into().unwrap());
            assert_eq!(offset, 100);
            assert_eq!(len, 4);

            // 6. Send the read reply (16-byte header + 4-byte payload)
            let mut reply_hdr = [0u8; 16];
            reply_hdr[0..4].copy_from_slice(&NBD_REPLY_MAGIC.to_be_bytes());
            reply_hdr[4..8].copy_from_slice(&0u32.to_be_bytes());
            reply_hdr[8..16].copy_from_slice(&handle.to_be_bytes());
            stream.write_all(&reply_hdr).unwrap();
            stream.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
            stream.flush().unwrap();

            // 7. Read the disconnect (28 bytes)
            let mut disc_req = [0u8; 28];
            stream.read_exact(&mut disc_req).unwrap();
            assert_eq!(
                u16::from_be_bytes(disc_req[6..8].try_into().unwrap()),
                NBD_CMD_DISC
            );
        });

        let mut nbd = NbdStream::connect_tcp(&addr).unwrap();
        assert_eq!(nbd.export_size(), 2048);

        let data = nbd.read_range(100, 4).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        nbd.disconnect();
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_nbd_stream_unix_mock_handshake_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("nbd_test.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let mut banner = Vec::new();
            banner.extend_from_slice(b"NBDMAGIC");
            banner.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
            banner.extend_from_slice(&0u16.to_be_bytes());
            stream.write_all(&banner).unwrap();
            stream.flush().unwrap();

            let mut client_flags = [0u8; 4];
            stream.read_exact(&mut client_flags).unwrap();

            let mut opt_req = [0u8; 16];
            stream.read_exact(&mut opt_req).unwrap();

            let mut export_reply = vec![0u8; 134];
            export_reply[0..8].copy_from_slice(&4096u64.to_be_bytes());
            stream.write_all(&export_reply).unwrap();
            stream.flush().unwrap();

            let mut read_req = [0u8; 28];
            stream.read_exact(&mut read_req).unwrap();
            let handle = u64::from_be_bytes(read_req[8..16].try_into().unwrap());

            let mut reply_hdr = [0u8; 16];
            reply_hdr[0..4].copy_from_slice(&NBD_REPLY_MAGIC.to_be_bytes());
            reply_hdr[8..16].copy_from_slice(&handle.to_be_bytes());
            stream.write_all(&reply_hdr).unwrap();
            stream.write_all(&[0x11, 0x22, 0x33, 0x44]).unwrap();
            stream.flush().unwrap();

            let mut disc_req = [0u8; 28];
            let _ = stream.read_exact(&mut disc_req);
        });

        let mut nbd = NbdStream::connect_unix(&sock_path).unwrap();
        assert_eq!(nbd.export_size(), 4096);

        let data = nbd.read_range(0, 4).unwrap();
        assert_eq!(data, vec![0x11, 0x22, 0x33, 0x44]);

        drop(nbd);
        server.join().unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn test_nbd_stream_unix_unsupported_on_non_unix() {
        let res = NbdStream::connect_unix(Path::new("C:\\temp\\dummy.sock"));
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_options_nbd_configuration() {
        let opc = Options::default()
            .with_unix_socket("/tmp/nbd.sock")
            .with_extra_nbd_args(vec!["--cache=writeback".to_string()])
            .with_connection_timeout(Duration::from_millis(500))
            .with_nbd_persistent(false);

        assert_eq!(opc.unix_socket, Some(PathBuf::from("/tmp/nbd.sock")));
        assert_eq!(opc.extra_nbd_args, vec!["--cache=writeback".to_string()]);
        assert_eq!(opc.connection_timeout, Some(Duration::from_millis(500)));
        assert!(!opc.nbd_persistent);
    }

    #[test]
    fn test_nbd_process_failure_preserves_path_code_and_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let helper_path = if cfg!(windows) {
            dir.path().join("fake qemu-nbd.cmd")
        } else {
            dir.path().join("fake-qemu-nbd")
        };

        #[cfg(windows)]
        std::fs::write(
            &helper_path,
            "@echo off\r\necho simulated qemu-nbd failure 1>&2\r\nexit 23\r\n",
        )
        .unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(
                &helper_path,
                "#!/bin/sh\nprintf '%s\\n' 'simulated qemu-nbd failure' >&2\nexit 23\n",
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&helper_path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&helper_path, permissions).unwrap();
        }

        let image_path = dir.path().join("disk.raw");
        std::fs::write(&image_path, [0u8; 512]).unwrap();
        let info = ImageInfo {
            path: image_path,
            format: "raw".to_string(),
            virtual_size: 512,
            actual_size: 512,
            hypervisor: crate::models::Hypervisor::Unknown,
        };
        let options = Options {
            connection_timeout: Some(Duration::from_secs(1)),
            ..Options::default()
        };

        let error = match NbdReader::open_with_options(&helper_path, &info, &options) {
            Ok(_) => panic!("the failing qemu-nbd helper must not connect"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        let message = error.to_string();
        assert!(message.contains("fake qemu-nbd"), "message: {message}");
        assert!(message.contains("23"), "message: {message}");
        assert!(
            message.contains("simulated qemu-nbd failure"),
            "message: {message}"
        );
    }
}
