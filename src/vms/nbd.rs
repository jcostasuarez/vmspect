//! Cliente y conector para `qemu-nbd` (Network Block Device).
//!
//! Permite acceder a formatos de disco no soportados de manera nativa (o forzados)
//! sirviendo la imagen mediante un subproceso de `qemu-nbd` en segundo plano
//! y leyendo bloques a través de un socket UNIX o TCP loopback (127.0.0.1), evitando el costo
//! de invocar subprocesos repetitivos y escribir archivos temporales a disco.

use crate::models::{InfoImagen, Opciones};
use crate::vms::stream::nuevo_comando;
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

/// Abstracción de transporte para stream de comunicación NBD (TCP o Socket UNIX).
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

/// Cliente mínimo para el protocolo NBD (Network Block Device).
pub struct NbdStream {
    stream: StreamTransport,
    tamano_export: u64,
    request_id: u64,
}

impl NbdStream {
    /// Realiza el handshake estándar (newstyle) sobre el transporte proporcionado.
    fn handshake(mut stream: StreamTransport) -> io::Result<Self> {
        // 1. Lectura del banner inicial del servidor
        // Magic: "NBDMAGIC" (8 bytes) + "IHAVEOPT" (8 bytes) + flags (2 bytes)
        let mut banner = [0u8; 18];
        stream.read_exact(&mut banner)?;

        if &banner[0..8] != b"NBDMAGIC" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Firma NBD inválida en el servidor",
            ));
        }

        let opt_magic = banner
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer insuficiente para opt_magic",
                )
            })?;
        if opt_magic != NBD_IHAVEOPT_MAGIC {
            // Si es un handshake antiguo (oldstyle)
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "El servidor NBD no utiliza newstyle handshake",
            ));
        }

        let _server_flags = banner
            .get(16..18)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_be_bytes)
            .unwrap_or(0);

        // 2. Enviar client flags (NBD_FLAG_C_FIXED_NEWSTYLE = 1)
        let client_flags: u32 = 1;
        stream.write_all(&client_flags.to_be_bytes())?;

        // 3. Negociar exportación (NBD_OPT_EXPORT_NAME = 1, export_name = "")
        let export_name = b"";
        let mut opt_req = Vec::with_capacity(16 + export_name.len());
        opt_req.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
        opt_req.extend_from_slice(&NBD_OPT_EXPORT_NAME.to_be_bytes());
        opt_req.extend_from_slice(&(export_name.len() as u32).to_be_bytes());
        opt_req.extend_from_slice(export_name);
        stream.write_all(&opt_req)?;
        stream.flush()?;

        // 4. Recibir respuesta de exportación
        // tamano_export (8 bytes) + flags (2 bytes) + ceros (124 bytes) = 134 bytes
        let mut resp = [0u8; 134];
        stream.read_exact(&mut resp)?;

        let tamano_export = resp
            .get(0..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer insuficiente para tamano_export",
                )
            })?;

        Ok(Self {
            stream,
            tamano_export,
            request_id: 1,
        })
    }

    /// Conecta a un servidor NBD y realiza el handshake estándar (newstyle) sobre TCP.
    pub fn conectar(direccion: &str) -> io::Result<Self> {
        Self::conectar_tcp(direccion)
    }

    /// Conecta a un servidor NBD sobre TCP y realiza el handshake estándar.
    pub fn conectar_tcp(direccion: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(direccion)?;
        stream.set_nodelay(true)?;
        Self::handshake(StreamTransport::Tcp(stream))
    }

    /// Conecta a un servidor NBD mediante un socket de dominio UNIX.
    pub fn conectar_unix(ruta: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let stream = std::os::unix::net::UnixStream::connect(ruta)?;
            Self::handshake(StreamTransport::Unix(stream))
        }
        #[cfg(not(unix))]
        {
            let _ = ruta;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Sockets de dominio UNIX no están soportados en esta plataforma",
            ))
        }
    }

    /// Obtiene el tamaño total exportado por el servidor NBD en bytes.
    pub fn tamano_export(&self) -> u64 {
        self.tamano_export
    }

    /// Lee una porción de bytes en `offset` con longitud `len`.
    pub fn leer_rango(&mut self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        if offset >= self.tamano_export {
            return Ok(Vec::new());
        }

        let len_ajustado = len.min((self.tamano_export - offset) as usize);
        let req_id = self.request_id;
        self.request_id = self.request_id.wrapping_add(1);

        // Armar cabecera de petición NBD (28 bytes)
        // 4: Magic, 2: Flags, 2: Command, 8: Handle, 8: Offset, 4: Length
        let mut req = [0u8; 28];
        req[0..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
        req[4..6].copy_from_slice(&0u16.to_be_bytes());
        req[6..8].copy_from_slice(&NBD_CMD_READ.to_be_bytes());
        req[8..16].copy_from_slice(&req_id.to_be_bytes());
        req[16..24].copy_from_slice(&offset.to_be_bytes());
        req[24..28].copy_from_slice(&(len_ajustado as u32).to_be_bytes());

        self.stream.write_all(&req)?;
        self.stream.flush()?;

        // Leer cabecera de respuesta (16 bytes)
        // 4: Magic, 4: Error, 8: Handle
        let mut resp_hdr = [0u8; 16];
        self.stream.read_exact(&mut resp_hdr)?;

        let magic = resp_hdr
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Buffer insuficiente para magic")
            })?;
        if magic != NBD_REPLY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Respuesta NBD con magic inválido: 0x{:08X}", magic),
            ));
        }

        let error_code = resp_hdr
            .get(4..8)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer insuficiente para error_code",
                )
            })?;
        if error_code != 0 {
            return Err(io::Error::other(format!(
                "Error reportado por servidor NBD: {}",
                error_code
            )));
        }

        let handle = resp_hdr
            .get(8..16)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Buffer insuficiente para handle",
                )
            })?;
        if handle != req_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Identificador de petición NBD desincronizado",
            ));
        }

        let mut datos = vec![0u8; len_ajustado];
        self.stream.read_exact(&mut datos)?;

        Ok(datos)
    }

    /// Cierra limpiamente la sesión NBD enviando el comando disconnect y cerrando el socket.
    pub fn desconectar(&mut self) {
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
        self.desconectar();
    }
}

/// Transporte de conexión seleccionado para negociar con el subproceso `qemu-nbd`.
///
/// Modela como invariante de tipos la elección mutuamente excluyente entre socket UNIX y
/// TCP loopback, evitando estados intermedios inválidos en tiempo de ejecución.
enum TransporteNbd {
    Tcp(String),
    Unix(PathBuf),
}

impl TransporteNbd {
    fn conectar(&self) -> io::Result<NbdStream> {
        match self {
            TransporteNbd::Unix(ruta) => NbdStream::conectar_unix(ruta),
            TransporteNbd::Tcp(direccion) => NbdStream::conectar_tcp(direccion),
        }
    }

    fn socket_unix(&self) -> Option<PathBuf> {
        match self {
            TransporteNbd::Unix(ruta) => Some(ruta.clone()),
            TransporteNbd::Tcp(_) => None,
        }
    }
}

/// Lector respaldado por un servidor `qemu-nbd` ejecutándose en segundo plano.
pub struct LectorNbd {
    proceso: Child,
    client: RefCell<NbdStream>,
    socket_unix: Option<PathBuf>,
}

impl LectorNbd {
    /// Inicia un subproceso de `qemu-nbd` y se conecta mediante NBD usando opciones por defecto.
    pub fn abrir(
        ruta_qemu_nbd: &Path,
        info: &InfoImagen,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        let opciones = Opciones {
            cancel_token,
            ..Opciones::default()
        };
        Self::abrir_con_opciones(ruta_qemu_nbd, info, &opciones)
    }

    /// Inicia un subproceso de `qemu-nbd` con las opciones dadas y se conecta mediante NBD
    /// (sobre Socket UNIX o TCP loopback según configuración).
    pub fn abrir_con_opciones(
        ruta_qemu_nbd: &Path,
        info: &InfoImagen,
        opciones: &Opciones,
    ) -> io::Result<Self> {
        if let Some(ref cancel) = opciones.cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Inspección cancelada por el usuario",
                ));
            }
        }

        let mut cmd = nuevo_comando(ruta_qemu_nbd);
        cmd.arg("--read-only");

        // Incluir --persistent solo si fue explícitamente solicitado
        if opciones.persistente_nbd {
            cmd.arg("--persistent");
        }

        // Agregar argumentos CLI adicionales
        for arg in &opciones.args_extra_nbd {
            cmd.arg(arg);
        }

        let transporte = if let Some(ref ruta_sock) = opciones.socket_unix {
            // Eliminar socket huérfano preexistente si existe
            let _ = std::fs::remove_file(ruta_sock);
            cmd.arg("-k").arg(ruta_sock);
            TransporteNbd::Unix(ruta_sock.clone())
        } else {
            // Asignación dinámica de puerto TCP efímero en 127.0.0.1
            let puerto = {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                listener.local_addr()?.port()
            };
            cmd.arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(puerto.to_string());
            TransporteNbd::Tcp(format!("127.0.0.1:{}", puerto))
        };

        cmd.arg(&info.ruta)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            io::Error::other(format!(
                "No se pudo iniciar qemu-nbd ({}): {}",
                ruta_qemu_nbd.display(),
                e
            ))
        })?;

        // Reintentos de conexión con polling acotado por timeout_conexion (defecto 3s)
        let timeout = opciones
            .timeout_conexion
            .unwrap_or_else(|| Duration::from_secs(3));
        let inicio = Instant::now();
        let mut client_opt = None;

        while inicio.elapsed() < timeout {
            if let Some(ref cancel) = opciones.cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Inspección cancelada",
                    ));
                }
            }

            // Verificar si el proceso terminó prematuramente con error
            if let Ok(Some(status)) = child.try_wait() {
                let mut err_msg = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_string(&mut err_msg);
                }
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!(
                        "qemu-nbd finalizó con código {:?}: {}",
                        status.code(),
                        err_msg.trim()
                    ),
                ));
            }

            match transporte.conectar() {
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
                    "Tiempo de espera agotado al conectar con el servidor qemu-nbd",
                ));
            }
        };

        Ok(Self {
            proceso: child,
            client: RefCell::new(client),
            socket_unix: transporte.socket_unix(),
        })
    }

    /// Obtiene el tamaño virtual del disco exportado por el servidor NBD.
    pub fn tamano_virtual(&self) -> u64 {
        self.client.borrow().tamano_export()
    }

    /// Lee un rango arbitrario de bytes directamente a través del socket NBD.
    pub fn leer_rango(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        self.client.borrow_mut().leer_rango(offset, len)
    }
}

impl Drop for LectorNbd {
    fn drop(&mut self) {
        // 1. Cerrar primero el stream de lectura/conexión
        self.client.borrow_mut().desconectar();

        // 2. Comprobar si el subproceso finalizó o forzar kill defensivo y cosechar código de salida
        match self.proceso.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = self.proceso.kill();
                let _ = self.proceso.wait();
            }
        }

        // 3. Limpiar socket UNIX si fue configurado
        if let Some(ref ruta) = self.socket_unix {
            let _ = std::fs::remove_file(ruta);
        }
    }
}

/// Localiza el binario de `qemu-nbd` en el sistema.
pub fn resolver_qemu_nbd(explicita: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(p) = explicita {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("La ruta indicada para qemu-nbd no existe: {}", p.display()),
        ));
    }

    if let Ok(env) = std::env::var("QEMU_NBD") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Ok(p);
        }
    }

    let candidatos = [
        r"C:\Program Files\qemu\qemu-nbd.exe",
        r"C:\Program Files (x86)\qemu\qemu-nbd.exe",
        "/usr/bin/qemu-nbd",
        "/usr/local/bin/qemu-nbd",
        "/opt/homebrew/bin/qemu-nbd",
    ];
    for c in candidatos {
        let p = PathBuf::from(c);
        if p.exists() {
            return Ok(p);
        }
    }

    // Verificar en PATH
    let en_path = nuevo_comando("qemu-nbd")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if en_path {
        return Ok(PathBuf::from("qemu-nbd"));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No se encontró el ejecutable qemu-nbd en el sistema. Instálalo, añádelo al PATH, define QEMU_NBD o usa --qemu-nbd <ruta>.",
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
    fn test_nbd_stream_tcp_mock_handshake_y_lectura() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // 1. Enviar banner inicial (18 bytes)
            let mut banner = Vec::new();
            banner.extend_from_slice(b"NBDMAGIC");
            banner.extend_from_slice(&NBD_IHAVEOPT_MAGIC.to_be_bytes());
            banner.extend_from_slice(&0u16.to_be_bytes());
            stream.write_all(&banner).unwrap();
            stream.flush().unwrap();

            // 2. Leer client flags (4 bytes)
            let mut client_flags = [0u8; 4];
            stream.read_exact(&mut client_flags).unwrap();
            assert_eq!(u32::from_be_bytes(client_flags), 1);

            // 3. Leer option request (16 bytes)
            let mut opt_req = [0u8; 16];
            stream.read_exact(&mut opt_req).unwrap();

            // 4. Enviar export reply (134 bytes): export size = 2048
            let mut export_reply = vec![0u8; 134];
            export_reply[0..8].copy_from_slice(&2048u64.to_be_bytes());
            stream.write_all(&export_reply).unwrap();
            stream.flush().unwrap();

            // 5. Leer petición de lectura (28 bytes)
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

            // 6. Enviar respuesta de lectura (16 bytes header + 4 bytes payload)
            let mut reply_hdr = [0u8; 16];
            reply_hdr[0..4].copy_from_slice(&NBD_REPLY_MAGIC.to_be_bytes());
            reply_hdr[4..8].copy_from_slice(&0u32.to_be_bytes());
            reply_hdr[8..16].copy_from_slice(&handle.to_be_bytes());
            stream.write_all(&reply_hdr).unwrap();
            stream.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
            stream.flush().unwrap();

            // 7. Leer disconnect (28 bytes)
            let mut disc_req = [0u8; 28];
            stream.read_exact(&mut disc_req).unwrap();
            assert_eq!(
                u16::from_be_bytes(disc_req[6..8].try_into().unwrap()),
                NBD_CMD_DISC
            );
        });

        let mut nbd = NbdStream::conectar_tcp(&addr).unwrap();
        assert_eq!(nbd.tamano_export(), 2048);

        let datos = nbd.leer_rango(100, 4).unwrap();
        assert_eq!(datos, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        nbd.desconectar();
        server.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_nbd_stream_unix_mock_handshake_y_lectura() {
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

        let mut nbd = NbdStream::conectar_unix(&sock_path).unwrap();
        assert_eq!(nbd.tamano_export(), 4096);

        let datos = nbd.leer_rango(0, 4).unwrap();
        assert_eq!(datos, vec![0x11, 0x22, 0x33, 0x44]);

        drop(nbd);
        server.join().unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn test_nbd_stream_unix_unsupported_en_no_unix() {
        let res = NbdStream::conectar_unix(Path::new("C:\\temp\\dummy.sock"));
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_opciones_nbd_configuracion() {
        let opc = Opciones::default()
            .with_socket_unix("/tmp/nbd.sock")
            .with_extra_nbd_args(vec!["--cache=writeback".to_string()])
            .with_connection_timeout(Duration::from_millis(500))
            .with_persistente_nbd(false);

        assert_eq!(opc.socket_unix, Some(PathBuf::from("/tmp/nbd.sock")));
        assert_eq!(opc.args_extra_nbd, vec!["--cache=writeback".to_string()]);
        assert_eq!(opc.timeout_conexion, Some(Duration::from_millis(500)));
        assert!(!opc.persistente_nbd);
    }
}
