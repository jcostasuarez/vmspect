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
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
const NBD_REPLY_MAGIC: u32 = 0x6744_6698;
const NBD_CMD_READ: u16 = 0;
const NBD_CMD_DISC: u16 = 2;

const NBD_OPT_EXPORT_NAME: u32 = 1;
const NBD_IHAVEOPT_MAGIC: u64 = 0x4948_4156_454F_5054; // "IHAVEOPT"

/// Transport abstraction for the NBD communication stream (TCP or UNIX socket).
enum StreamTransport {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl StreamTransport {
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
}

impl NbdStream {
    /// Performs the standard (newstyle) handshake over the provided transport.
    fn handshake(mut stream: StreamTransport) -> io::Result<Self> {
        // 1. Read the initial banner from the server.
        // Magic: "NBDMAGIC" (8 bytes) + "IHAVEOPT" (8 bytes) + flags (2 bytes)
        let mut banner = [0u8; 18];
        stream.read_exact(&mut banner)?;

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
        stream.write_all(&client_flags.to_be_bytes())?;

        // 3. Negotiate the export (NBD_OPT_EXPORT_NAME = 1, export_name = "")
        let export_name = b"";
        let mut opt_req = Vec::with_capacity(16 + export_name.len());
        opt_req.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
        opt_req.extend_from_slice(&NBD_OPT_EXPORT_NAME.to_be_bytes());
        opt_req.extend_from_slice(&(export_name.len() as u32).to_be_bytes());
        opt_req.extend_from_slice(export_name);
        stream.write_all(&opt_req)?;
        stream.flush()?;

        // 4. Receive the export reply.
        // export_size (8 bytes) + flags (2 bytes) + zeros (124 bytes) = 134 bytes
        let mut resp = [0u8; 134];
        stream.read_exact(&mut resp)?;

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

        Ok(Self {
            stream,
            export_size,
            request_id: 1,
        })
    }

    /// Connects to an NBD server and performs the standard (newstyle) handshake over TCP.
    pub fn connect(address: &str) -> io::Result<Self> {
        Self::connect_tcp(address)
    }

    /// Connects to an NBD server over TCP and performs the standard handshake.
    pub fn connect_tcp(address: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(address)?;
        stream.set_nodelay(true)?;
        Self::handshake(StreamTransport::Tcp(stream))
    }

    /// Connects to an NBD server via a UNIX domain socket.
    pub fn connect_unix(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(path)?;
            Self::handshake(StreamTransport::Unix(stream))
        }
        #[cfg(not(unix))]
        {
            let _ = path;
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

        self.stream.write_all(&req)?;
        self.stream.flush()?;

        // Read the response header (16 bytes)
        // 4: Magic, 4: Error, 8: Handle
        let mut resp_hdr = [0u8; 16];
        self.stream.read_exact(&mut resp_hdr)?;

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
        self.stream.read_exact(&mut data)?;

        Ok(data)
    }

    /// Cleanly closes the NBD session by sending the disconnect command and closing the socket.
    pub fn disconnect(&mut self) {
        let req_id = self.request_id;
        let mut req = [0u8; 28];
        req[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        req[6..8].copy_from_slice(&NBD_CMD_DISC.to_be_bytes());
        req[8..16].copy_from_slice(&req_id.to_be_bytes());
        let _ = self.stream.write_all(&req);
        let _ = self.stream.flush();
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
    fn connect(&self) -> io::Result<NbdStream> {
        match self {
            NbdTransport::Unix(path) => NbdStream::connect_unix(path),
            NbdTransport::Tcp(address) => NbdStream::connect_tcp(address),
        }
    }

    fn unix_socket(&self) -> Option<PathBuf> {
        match self {
            NbdTransport::Unix(path) => Some(path.clone()),
            NbdTransport::Tcp(_) => None,
        }
    }
}

/// Reader backed by a `qemu-nbd` server running in the background.
pub struct NbdReader {
    process: Child,
    client: RefCell<NbdStream>,
    unix_socket: Option<PathBuf>,
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

        let mut cmd = new_command(qemu_nbd_path);
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

        // Retry the connection with polling bounded by connection_timeout (3s default)
        let timeout = options
            .connection_timeout
            .unwrap_or_else(|| Duration::from_secs(3));
        let start = Instant::now();
        let mut client_opt = None;

        while start.elapsed() < timeout {
            if let Some(ref cancel) = options.cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Inspection cancelled",
                    ));
                }
            }

            // Check whether the process terminated prematurely with an error
            if let Ok(Some(status)) = child.try_wait() {
                let mut err_msg = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_string(&mut err_msg);
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!(
                        "qemu-nbd exited with code {:?}: {}",
                        status.code(),
                        err_msg.trim()
                    ),
                ));
            }

            match transport.connect() {
                Ok(stream) => {
                    client_opt = Some(stream);
                    break;
                }
                Err(_) => {
                    sleep(Duration::from_millis(50));
                }
            }
        }

        let client = match client_opt {
            Some(c) => c,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Timed out waiting for the qemu-nbd server to accept connections",
                ));
            }
        };

        Ok(Self {
            process: child,
            client: RefCell::new(client),
            unix_socket: transport.unix_socket(),
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
                let _ = self.process.kill();
                let _ = self.process.wait();
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
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("The supplied qemu-nbd path does not exist: {}", p.display()),
        ));
    }

    if let Ok(env) = std::env::var("QEMU_NBD") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Ok(p);
        }
    }

    let candidates = [
        r"C:\Program Files\qemu\qemu-nbd.exe",
        r"C:\Program Files (x86)\qemu\qemu-nbd.exe",
        "/usr/bin/qemu-nbd",
        "/usr/local/bin/qemu-nbd",
        "/opt/homebrew/bin/qemu-nbd",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Ok(p);
        }
    }

    // Look up in PATH
    let on_path = new_command("qemu-nbd")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if on_path {
        return Ok(PathBuf::from("qemu-nbd"));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "The qemu-nbd executable was not found on the system. Install it, add it to PATH, define QEMU_NBD, or use --qemu-nbd <path>.",
    ))
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
}
