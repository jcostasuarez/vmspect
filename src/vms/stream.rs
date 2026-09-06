//! Acceso al disco virtual: lectura nativa cuando es posible y `qemu-nbd` para formatos complejos.
//!
//! Jerarquía
//! ---------
//! - [`LectorDisco`]: fachada única. Decide el backend al abrir la imagen y
//!   ofrece `leer_rango(offset, len)` sobre coordenadas del disco virtual.
//!   - **Nativo** (`std::fs::File` + `Seek`, sin procesos hijos): imágenes
//!     `raw`, VMDK `monolithicSparse` sin padre, y VMDK con descriptor de texto
//!     cuyos extents sean `FLAT`/`VMFS`/`SPARSE`/`ZERO` (monolithicFlat,
//!     twoGbMaxExtentFlat/Sparse, vmfs).
//!   - **qemu-nbd** ([`LectorNbd`]): formatos complejos (VDI, VHD/VHDX, QCOW2,
//!     VMDK streamOptimized, snapshots/deltas, backing files...).
//! - [`DiscoVirtual`]: vista `Read + Seek` sobre un rango del disco (una
//!   partición) con caché LRU de chunks. Es lo que consumen los parsers.

use crate::models::traits::{MemoryMapper, VmDriver};
use crate::models::{Estadisticas, Hipervisor, InfoImagen, Opciones};
use crate::vms::nbd::{self, LectorNbd};
use crate::vms::vmdk::{self, Apertura, ExtentSparse};
use positioned_io::ReadAt;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const SECTOR: u64 = 512;

/// Instancia un proceso hijo asegurando que en Windows no se cree ni abra una ventana de consola.
#[inline]
pub(crate) fn nuevo_comando<S: AsRef<std::ffi::OsStr>>(prog: S) -> Command {
    let mut cmd = Command::new(prog);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Abre un archivo en modo solo lectura con permisos compartidos no bloqueantes (en Windows).
pub(crate) fn abrir_archivo_lectura(ruta: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        // Permite lectura, escritura y eliminación compartida por otros procesos concurrentes
        opts.share_mode(7);
        opts.open(ruta)
    }
    #[cfg(not(windows))]
    {
        File::open(ruta)
    }
}

// -----------------------------------------------------------------------------
// Identificación de la imagen (sin procesos si la cabecera es reconocible)
// -----------------------------------------------------------------------------

fn formato_por_extension(ruta: &Path) -> Option<&'static str> {
    let ext = ruta.extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "vmdk" => "vmdk",
        "vdi" => "vdi",
        "vhd" => "vpc",
        "vhdx" => "vhdx",
        "qcow2" => "qcow2",
        "qcow" => "qcow",
        "qed" => "qed",
        "img" | "raw" | "dd" | "bin" => "raw",
        _ => return None,
    })
}

/// Reconoce el formato por la firma de los primeros bytes. `None` si es ambiguo.
fn formato_por_firma(cabecera: &[u8]) -> Option<&'static str> {
    if cabecera.len() < 8 {
        return None;
    }
    if vmdk::es_cabecera_sparse(cabecera) || vmdk::es_descriptor_texto(cabecera) {
        return Some("vmdk");
    }
    if cabecera.starts_with(b"<<< ") && cabecera.len() >= 0x44 {
        // Texto "<<< Oracle VM VirtualBox Disk Image >>>" + firma 0xBEDA107F en 0x40.
        if cabecera[0x40..0x44] == [0x7F, 0x10, 0xDA, 0xBE] {
            return Some("vdi");
        }
    }
    if cabecera.starts_with(b"conectix") {
        return Some("vpc");
    }
    if cabecera.starts_with(b"vhdxfile") {
        return Some("vhdx");
    }
    if cabecera.starts_with(b"QFI\xfb") {
        return Some("qcow2");
    }
    if cabecera.starts_with(b"QED\0") {
        return Some("qed");
    }
    None
}

/// Identifica la imagen inspeccionando cabeceras y descriptores de formato.
pub(crate) fn identificar_imagen(_qemu_nbd: Option<&Path>, ruta: &Path) -> io::Result<InfoImagen> {
    let mut archivo = abrir_archivo_lectura(ruta)?;
    let tamano_archivo = archivo.metadata()?.len();
    let mut cabecera = vec![0u8; 1024.min(tamano_archivo as usize)];
    let _ = archivo.read(&mut cabecera);

    let formato = formato_por_firma(&cabecera).or_else(|| formato_por_extension(ruta));

    match formato {
        Some("raw") => Ok(InfoImagen {
            ruta: ruta.to_path_buf(),
            formato: "raw".to_string(),
            tamano_virtual: tamano_archivo,
            tamano_real: tamano_archivo,
            hipervisor: Hipervisor::Desconocido,
        }),
        Some("vmdk") => {
            if let Some(capacidad) = capacidad_vmdk_nativa(ruta, &cabecera)? {
                let tamano_real = calcular_tamano_real_vmdk(ruta, &cabecera);
                return Ok(InfoImagen {
                    ruta: ruta.to_path_buf(),
                    formato: "vmdk".to_string(),
                    tamano_virtual: capacidad,
                    tamano_real,
                    hipervisor: Hipervisor::VMware,
                });
            }
            let tamano_real = calcular_tamano_real_vmdk(ruta, &cabecera);
            Ok(InfoImagen {
                ruta: ruta.to_path_buf(),
                formato: "vmdk".to_string(),
                tamano_virtual: tamano_archivo,
                tamano_real: if tamano_real > 0 {
                    tamano_real
                } else {
                    tamano_archivo
                },
                hipervisor: Hipervisor::VMware,
            })
        }
        Some("qcow2") => {
            let mut tamano_virtual = tamano_archivo;
            if cabecera.len() >= 32 && cabecera.starts_with(b"QFI\xfb") {
                if let Ok(tam) = cabecera[24..32].try_into().map(u64::from_be_bytes) {
                    if tam > 0 {
                        tamano_virtual = tam;
                    }
                }
            }
            Ok(InfoImagen {
                ruta: ruta.to_path_buf(),
                formato: "qcow2".to_string(),
                tamano_virtual,
                tamano_real: tamano_archivo,
                hipervisor: Hipervisor::Qemu,
            })
        }
        Some("vpc") | Some("vhd") => {
            let mut tamano_virtual = tamano_archivo;
            if tamano_archivo >= 512 {
                let mut footer = [0u8; 512];
                if archivo.seek(SeekFrom::Start(tamano_archivo - 512)).is_ok()
                    && archivo.read_exact(&mut footer).is_ok()
                    && footer.starts_with(b"conectix")
                {
                    if let Ok(tam) = footer[48..56].try_into().map(u64::from_be_bytes) {
                        if tam > 0 {
                            tamano_virtual = tam;
                        }
                    }
                } else if cabecera.starts_with(b"conectix") {
                    if let Ok(tam) = cabecera[48..56].try_into().map(u64::from_be_bytes) {
                        if tam > 0 {
                            tamano_virtual = tam;
                        }
                    }
                }
            }
            Ok(InfoImagen {
                ruta: ruta.to_path_buf(),
                formato: "vpc".to_string(),
                tamano_virtual,
                tamano_real: tamano_archivo,
                hipervisor: Hipervisor::HyperV,
            })
        }
        Some("vdi") => {
            let mut tamano_virtual = tamano_archivo;
            if cabecera.len() >= 0x178 && cabecera.starts_with(b"<<< ") {
                if let Ok(tam) = cabecera[0x170..0x178].try_into().map(u64::from_le_bytes) {
                    if tam > 0 {
                        tamano_virtual = tam;
                    }
                }
            }
            Ok(InfoImagen {
                ruta: ruta.to_path_buf(),
                formato: "vdi".to_string(),
                tamano_virtual,
                tamano_real: tamano_archivo,
                hipervisor: Hipervisor::VirtualBox,
            })
        }
        Some(fmt) => {
            let hip = Hipervisor::desde_formato(fmt);
            Ok(InfoImagen {
                ruta: ruta.to_path_buf(),
                formato: fmt.to_string(),
                tamano_virtual: tamano_archivo,
                tamano_real: tamano_archivo,
                hipervisor: hip,
            })
        }
        None => {
            let fmt = formato_por_extension(ruta).unwrap_or("raw");
            Ok(InfoImagen {
                ruta: ruta.to_path_buf(),
                formato: fmt.to_string(),
                tamano_virtual: tamano_archivo,
                tamano_real: tamano_archivo,
                hipervisor: Hipervisor::desde_formato(fmt),
            })
        }
    }
}

/// Capacidad virtual de un VMDK leída de su cabecera/descriptor. `None` si no se pudo.
fn capacidad_vmdk_nativa(ruta: &Path, cabecera: &[u8]) -> io::Result<Option<u64>> {
    if vmdk::es_cabecera_sparse(cabecera) {
        let cab = vmdk::leer_cabecera_sparse(cabecera)?;
        return Ok(Some(cab.capacidad_sectores * SECTOR));
    }
    if vmdk::es_descriptor_texto(cabecera) {
        let texto = fs::read_to_string(ruta).unwrap_or_default();
        let d = vmdk::parsear_descriptor(&texto);
        let total: u64 = d.extents.iter().map(|e| e.sectores).sum();
        if total > 0 {
            return Ok(Some(total * SECTOR));
        }
    }
    Ok(None)
}

/// Calcula el tamaño físico real ocupado en disco por un VMDK (descriptor + extents asociados).
fn calcular_tamano_real_vmdk(vmdk_path: &Path, cabecera: &[u8]) -> u64 {
    let mut total_bytes = fs::metadata(vmdk_path).map(|m| m.len()).unwrap_or(0);

    if vmdk::es_descriptor_texto(cabecera) {
        if let Ok(texto) = fs::read_to_string(vmdk_path) {
            let descriptor = vmdk::parsear_descriptor(&texto);
            for extent in &descriptor.extents {
                if let Some(nombre_archivo) = &extent.archivo {
                    let ruta_extent = vmdk::resolver_ruta_extent(vmdk_path, nombre_archivo);
                    if let Ok(meta) = fs::metadata(&ruta_extent) {
                        total_bytes += meta.len();
                    }
                }
            }
        }
    }

    total_bytes
}

// -----------------------------------------------------------------------------
// Backends nativos y NBD
// -----------------------------------------------------------------------------

/// Un extent de un VMDK con descriptor de texto, ya abierto.
struct ExtentAbierto {
    /// Posición del extent dentro del disco virtual (bytes).
    inicio: u64,
    longitud: u64,
    datos: DatosExtent,
}

enum DatosExtent {
    /// Extent plano: los bytes están tal cual en el archivo desde `offset`.
    Plano {
        archivo: File,
        offset: u64,
    },
    Sparse(ExtentSparse),
    Cero,
}

enum Backend {
    /// Archivo raw: el disco virtual es el archivo.
    Raw(File),
    /// VMDK monolithicSparse.
    Sparse(ExtentSparse),
    /// VMDK con descriptor de texto y uno o más extents.
    Extents(Vec<ExtentAbierto>),
    /// Servidor qemu-nbd conectado por socket TCP en segundo plano (liviano y rápido).
    Nbd(LectorNbd),
}

/// Fachada de acceso al disco virtual. Elige backend nativo o qemu-nbd al abrir.
pub struct LectorDisco {
    backend: RefCell<Backend>,
    tamano_virtual: u64,
    modo_acceso: String,
    stats: RefCell<Estadisticas>,
    cancel_token: Option<Arc<AtomicBool>>,
}

impl LectorDisco {
    /// Abre la imagen seleccionando automáticamente el backend más óptimo.
    ///
    /// Prioridad:
    /// 1. Backend nativo Rust (RAW / VMDK sparse / VMDK flat).
    /// 2. `qemu-nbd` (socket local UNIX o TCP streaming, sin overhead de archivos temporales).
    pub fn abrir(
        qemu_nbd: Option<&Path>,
        info: &InfoImagen,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        let opciones = Opciones {
            qemu_nbd: qemu_nbd.map(|p| p.to_path_buf()),
            cancel_token,
            ..Opciones::default()
        };
        Self::abrir_con_opciones(info, &opciones)
    }

    /// Abre la imagen seleccionando automáticamente el backend más óptimo según las [`Opciones`] provistas.
    pub fn abrir_con_opciones(info: &InfoImagen, opciones: &Opciones) -> io::Result<Self> {
        let (backend, modo, tamano_ajustado) = match abrir_nativo(info)? {
            Apertura::Nativa((b, modo)) => (b, format!("nativo ({})", modo), info.tamano_virtual),
            Apertura::NecesitaNbd(motivo) => {
                let ruta_nbd = nbd::resolver_qemu_nbd(opciones.qemu_nbd.as_deref())?;
                let lector_nbd = LectorNbd::abrir_con_opciones(&ruta_nbd, info, opciones)?;
                let tam_nbd = lector_nbd.tamano_virtual().max(info.tamano_virtual);
                let canal = if opciones.socket_unix.is_some() {
                    "unix"
                } else {
                    "tcp"
                };
                (
                    Backend::Nbd(lector_nbd),
                    format!("qemu-nbd {} ({})", canal, motivo),
                    tam_nbd,
                )
            }
        };

        Ok(Self {
            backend: RefCell::new(backend),
            tamano_virtual: tamano_ajustado,
            stats: RefCell::new(Estadisticas {
                modo_acceso: modo.clone(),
                ..Estadisticas::default()
            }),
            modo_acceso: modo,
            cancel_token: opciones.cancel_token.clone(),
        })
    }

    /// Construye la fachada forzando el backend `qemu-nbd`.
    pub fn desde_nbd(
        lector: LectorNbd,
        info: &InfoImagen,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Self {
        let tamano_virtual = lector.tamano_virtual().max(info.tamano_virtual);
        let modo = "qemu-nbd tcp (forzado)".to_string();
        Self {
            backend: RefCell::new(Backend::Nbd(lector)),
            tamano_virtual,
            stats: RefCell::new(Estadisticas {
                modo_acceso: modo.clone(),
                ..Estadisticas::default()
            }),
            modo_acceso: modo,
            cancel_token,
        }
    }

    /// Obtiene una descripción textual del modo de acceso utilizado.
    pub fn modo_acceso(&self) -> &str {
        &self.modo_acceso
    }

    /// Obtiene una copia de las métricas y estadísticas recopiladas durante la lectura.
    pub fn estadisticas(&self) -> Estadisticas {
        self.stats.borrow().clone()
    }

    /// Tamaño de chunk aconsejado para [`DiscoVirtual`].
    pub fn tamano_chunk_recomendado(&self) -> u64 {
        match &*self.backend.borrow() {
            Backend::Raw(_) | Backend::Sparse(_) | Backend::Extents(_) => 256 * 1024,
            Backend::Nbd(_) => 512 * 1024,
        }
    }

    /// Lee `[offset, offset+len)` del disco virtual. Devuelve menos bytes al llegar al final.
    pub fn leer_rango(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if let Some(ref cancel) = self.cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Análisis cancelado por el usuario",
                ));
            }
        }

        if offset >= self.tamano_virtual || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.tamano_virtual - offset) as usize);

        let datos = match &mut *self.backend.borrow_mut() {
            Backend::Raw(archivo) => {
                let mut buf = vec![0u8; len];
                archivo.seek(SeekFrom::Start(offset))?;
                vmdk::leer_o_ceros(archivo, &mut buf)?;
                buf
            }
            Backend::Sparse(extent) => {
                let mut buf = vec![0u8; len];
                let n = extent.leer_en(offset, &mut buf)?;
                buf.truncate(n);
                buf
            }
            Backend::Extents(extents) => leer_de_extents(extents, offset, len)?,
            Backend::Nbd(nbd) => {
                self.stats.borrow_mut().peticiones_nbd += 1;
                nbd.leer_rango(offset, len)?
            }
        };

        self.stats.borrow_mut().bytes_leidos += datos.len() as u64;
        Ok(datos)
    }
}

impl VmDriver for LectorDisco {
    fn tamano_virtual(&self) -> u64 {
        self.tamano_virtual
    }

    fn leer_rango(&self, offset: u64, buf: &mut [u8]) -> crate::error::Result<()> {
        let datos = self.leer_rango(offset, buf.len())?;
        buf[..datos.len()].copy_from_slice(&datos);
        if datos.len() < buf.len() {
            buf[datos.len()..].fill(0);
        }
        Ok(())
    }

    fn modo_acceso(&self) -> &str {
        &self.modo_acceso
    }

    fn es_nativo(&self) -> bool {
        matches!(
            &*self.backend.borrow(),
            Backend::Raw(_) | Backend::Sparse(_) | Backend::Extents(_)
        )
    }

    fn tamano_chunk_recomendado(&self) -> u64 {
        self.tamano_chunk_recomendado()
    }
}

fn leer_de_extents(extents: &mut [ExtentAbierto], offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut hecho = 0usize;

    while hecho < len {
        let pos = offset + hecho as u64;
        let Some(ext) = extents
            .iter_mut()
            .find(|e| pos >= e.inicio && pos < e.inicio + e.longitud)
        else {
            // Hueco no cubierto por ningún extent: ceros.
            break;
        };
        let dentro = pos - ext.inicio;
        let n = ((ext.longitud - dentro) as usize).min(len - hecho);
        let destino = &mut buf[hecho..hecho + n];

        match &mut ext.datos {
            DatosExtent::Plano {
                archivo,
                offset: base,
            } => {
                archivo.seek(SeekFrom::Start(*base + dentro))?;
                vmdk::leer_o_ceros(archivo, destino)?;
            }
            DatosExtent::Sparse(sparse) => {
                let leido = sparse.leer_en(dentro, destino)?;
                destino[leido..].fill(0);
            }
            DatosExtent::Cero => destino.fill(0),
        }
        hecho += n;
    }
    Ok(buf)
}

/// Intenta construir un backend nativo. Devuelve el motivo si hace falta `qemu-nbd`.
fn abrir_nativo(info: &InfoImagen) -> io::Result<Apertura<(Backend, String)>> {
    match info.formato.to_ascii_lowercase().as_str() {
        "raw" => Ok(Apertura::Nativa((
            Backend::Raw(abrir_archivo_lectura(&info.ruta)?),
            "raw".to_string(),
        ))),
        "vmdk" => abrir_vmdk_nativo(&info.ruta),
        otro => Ok(Apertura::NecesitaNbd(format!("formato {}", otro))),
    }
}

fn abrir_vmdk_nativo(ruta: &Path) -> io::Result<Apertura<(Backend, String)>> {
    let mut archivo = abrir_archivo_lectura(ruta)?;
    let mut cabecera = [0u8; 512];
    let n = archivo.read(&mut cabecera)?;
    let cabecera = &cabecera[..n];

    // --- Caso 1: monolithicSparse (cabecera binaria KDMV con descriptor embebido)
    if vmdk::es_cabecera_sparse(cabecera) {
        let cab = vmdk::leer_cabecera_sparse(cabecera)?;

        if cab.descriptor_offset != 0 && cab.descriptor_sectores != 0 {
            let mut texto = vec![0u8; (cab.descriptor_sectores * SECTOR) as usize];
            archivo.seek(SeekFrom::Start(cab.descriptor_offset * SECTOR))?;
            vmdk::leer_o_ceros(&mut archivo, &mut texto)?;
            let d = vmdk::parsear_descriptor(&String::from_utf8_lossy(&texto));
            if d.tiene_padre() {
                return Ok(Apertura::NecesitaNbd(
                    "VMDK delta/snapshot con disco padre".to_string(),
                ));
            }
            // Un sparse monolítico que declara varios extents es raro; delegar.
            if d.extents.len() > 1 {
                return Ok(Apertura::NecesitaNbd(
                    "VMDK sparse con múltiples extents declarados".to_string(),
                ));
            }
        }

        return Ok(match ExtentSparse::desde_cabecera(archivo, ruta, cab)? {
            Apertura::Nativa(ext) => {
                Apertura::Nativa((Backend::Sparse(ext), "vmdk monolithicSparse".to_string()))
            }
            Apertura::NecesitaNbd(m) => Apertura::NecesitaNbd(m),
        });
    }

    // --- Caso 2: descriptor de texto con extents externos
    if vmdk::es_descriptor_texto(cabecera) {
        let texto = fs::read_to_string(ruta)?;
        let d = vmdk::parsear_descriptor(&texto);
        if d.tiene_padre() {
            return Ok(Apertura::NecesitaNbd(
                "VMDK delta/snapshot con disco padre".to_string(),
            ));
        }
        if d.extents.is_empty() {
            return Ok(Apertura::NecesitaNbd(
                "descriptor VMDK sin extents".to_string(),
            ));
        }

        let mut extents = Vec::with_capacity(d.extents.len());
        let mut inicio = 0u64;
        for e in &d.extents {
            let longitud = e.sectores * SECTOR;
            let datos = match e.tipo.as_str() {
                "ZERO" => DatosExtent::Cero,
                "FLAT" | "VMFS" | "VMFSRAW" => {
                    let Some(nombre) = &e.archivo else {
                        return Ok(Apertura::NecesitaNbd("extent FLAT sin archivo".to_string()));
                    };
                    let ruta_ext = vmdk::resolver_ruta_extent(ruta, nombre);
                    DatosExtent::Plano {
                        archivo: abrir_archivo_lectura(&ruta_ext).map_err(|err| {
                            io::Error::new(
                                err.kind(),
                                format!(
                                    "No se pudo abrir el extent {}: {}",
                                    ruta_ext.display(),
                                    err
                                ),
                            )
                        })?,
                        offset: e.offset_sectores * SECTOR,
                    }
                }
                "SPARSE" | "VMFSSPARSE" => {
                    let Some(nombre) = &e.archivo else {
                        return Ok(Apertura::NecesitaNbd(
                            "extent SPARSE sin archivo".to_string(),
                        ));
                    };
                    let ruta_ext = vmdk::resolver_ruta_extent(ruta, nombre);
                    match ExtentSparse::abrir(&ruta_ext)? {
                        Apertura::Nativa(s) => DatosExtent::Sparse(s),
                        Apertura::NecesitaNbd(m) => return Ok(Apertura::NecesitaNbd(m)),
                    }
                }
                otro => {
                    return Ok(Apertura::NecesitaNbd(format!(
                        "extent VMDK de tipo {} no soportado",
                        otro
                    )));
                }
            };
            extents.push(ExtentAbierto {
                inicio,
                longitud,
                datos,
            });
            inicio += longitud;
        }

        let tipo = if d.create_type.is_empty() {
            format!("{} extents", extents.len())
        } else {
            d.create_type.clone()
        };
        return Ok(Apertura::Nativa((
            Backend::Extents(extents),
            format!("vmdk {}", tipo),
        )));
    }

    Ok(Apertura::NecesitaNbd(
        "VMDK con cabecera no reconocida".to_string(),
    ))
}

// -----------------------------------------------------------------------------
// Disco virtual con Read + Seek y caché de chunks
// -----------------------------------------------------------------------------

/// Vista `Read + Seek` de un rango del disco virtual (normalmente una partición).
///
/// Los accesos se agrupan en chunks alineados de `tamano_chunk` bytes que se
/// obtienen bajo demanda con [`VmDriver`] y se conservan en una caché LRU.
pub struct DiscoVirtual<'a> {
    driver: &'a dyn VmDriver,
    base: u64,
    longitud: u64,
    posicion: u64,
    tamano_chunk: u64,
    cache: RefCell<VecDeque<(u64, Vec<u8>)>>,
    max_chunks: usize,
}

impl<'a> DiscoVirtual<'a> {
    /// Crea una vista sobre `[base, base+longitud)` del disco.
    pub fn new(driver: &'a dyn VmDriver, base: u64, longitud: u64, tamano_chunk: u64) -> Self {
        let tamano_chunk = tamano_chunk.max(512).next_power_of_two();
        Self {
            driver,
            base,
            longitud,
            posicion: 0,
            tamano_chunk,
            cache: RefCell::new(VecDeque::new()),
            // ~64 MiB de caché independientemente del tamaño de chunk.
            max_chunks: ((64 * 1024 * 1024) / tamano_chunk).clamp(4, 512) as usize,
        }
    }

    /// Vista sobre el disco completo.
    pub fn completo(driver: &'a dyn VmDriver, tamano_chunk: u64) -> Self {
        Self::new(driver, 0, driver.tamano_virtual(), tamano_chunk)
    }

    /// Devuelve la longitud en bytes del rango mapeado.
    pub fn longitud(&self) -> u64 {
        self.longitud
    }

    /// Devuelve el desplazamiento base en bytes dentro del disco virtual.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Lee datos atendiendo desde la caché de chunks LRU y cargando bloques alineados si no están en memoria.
    fn leer_con_cache(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        if pos >= self.longitud || buf.is_empty() {
            return Ok(0);
        }
        let total = (self.longitud - pos).min(buf.len() as u64) as usize;
        let mut transferidos = 0;

        while transferidos < total {
            let offset_actual = pos + transferidos as u64;
            let indice_chunk = offset_actual / self.tamano_chunk;
            let dentro_chunk = (offset_actual % self.tamano_chunk) as usize;

            // Asegurar que el chunk requerido esté en el frente de la caché
            {
                let mut cache = self.cache.borrow_mut();
                if let Some(p) = cache.iter().position(|(i, _)| *i == indice_chunk) {
                    if p > 0 {
                        if let Some(entrada) = cache.remove(p) {
                            cache.push_front(entrada);
                        }
                    }
                } else {
                    // Cargar chunk desde el driver liberando momentáneamente el borrow de la caché
                    drop(cache);
                    let abs = self.base + indice_chunk * self.tamano_chunk;
                    let len_chunk = self.tamano_chunk as usize;
                    let mut leidos = vec![0u8; len_chunk];
                    let total_virtual = self.driver.tamano_virtual();
                    if abs < total_virtual {
                        let a_leer = len_chunk.min((total_virtual - abs) as usize);
                        leidos.truncate(a_leer);
                        self.driver
                            .leer_rango(abs, &mut leidos)
                            .map_err(|e| io::Error::other(e.to_string()))?;
                    } else {
                        leidos.clear();
                    }
                    let mut cache = self.cache.borrow_mut();
                    if cache.len() >= self.max_chunks {
                        cache.pop_back();
                    }
                    cache.push_front((indice_chunk, leidos));
                }
            }

            let cache = self.cache.borrow();
            let (_, datos) = &cache[0];

            if dentro_chunk >= datos.len() {
                break;
            }

            let disponibles = datos.len() - dentro_chunk;
            let a_copiar = (total - transferidos).min(disponibles);
            buf[transferidos..transferidos + a_copiar]
                .copy_from_slice(&datos[dentro_chunk..dentro_chunk + a_copiar]);
            transferidos += a_copiar;
        }

        Ok(transferidos)
    }
}

impl Read for DiscoVirtual<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.leer_con_cache(self.posicion, buf)?;
        self.posicion += n as u64;
        Ok(n)
    }
}

impl Seek for DiscoVirtual<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let nueva = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.longitud as i128 + d as i128,
            SeekFrom::Current(d) => self.posicion as i128 + d as i128,
        };
        if nueva < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek a una posición negativa",
            ));
        }
        self.posicion = nueva as u64;
        Ok(self.posicion)
    }
}

impl<'a> ReadAt for DiscoVirtual<'a> {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.leer_con_cache(pos, buf)
    }
}

impl<'a> MemoryMapper for DiscoVirtual<'a> {
    fn leer_en_offset(&mut self, offset: u64, buf: &mut [u8]) -> crate::error::Result<usize> {
        self.leer_con_cache(offset, buf).map_err(Into::into)
    }

    fn longitud(&self) -> u64 {
        self.longitud
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_disco_virtual_read_seek() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_disk.raw");
        {
            let mut f = File::create(&file_path).unwrap();
            let mut data = Vec::new();
            for i in 0..1024u32 {
                data.extend_from_slice(&i.to_le_bytes());
            }
            f.write_all(&data).unwrap();
        }

        let info = InfoImagen {
            ruta: file_path.clone(),
            formato: "raw".to_string(),
            tamano_virtual: 4096,
            tamano_real: 4096,
            hipervisor: Hipervisor::Desconocido,
        };

        let lector = LectorDisco::abrir(None, &info, None).unwrap();
        assert!(lector.es_nativo());
        assert_eq!(lector.tamano_virtual(), 4096);

        let mut disco = DiscoVirtual::new(&lector, 0, 4096, 512);
        assert_eq!(disco.base(), 0);
        assert_eq!(disco.longitud(), 4096);

        let disco_completo = DiscoVirtual::completo(&lector, 512);
        assert_eq!(disco_completo.base(), 0);
        assert_eq!(disco_completo.longitud(), 4096);

        // Read first 8 bytes
        let mut buf = [0u8; 8];
        disco.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[0..4], &0u32.to_le_bytes());
        assert_eq!(&buf[4..8], &1u32.to_le_bytes());

        // Seek
        disco.seek(SeekFrom::Start(100 * 4)).unwrap();
        disco.read_exact(&mut buf[0..4]).unwrap();
        assert_eq!(&buf[0..4], &100u32.to_le_bytes());

        // ReadAt
        let mut read_at_buf = [0u8; 4];
        let n = disco.read_at(250 * 4, &mut read_at_buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&read_at_buf, &250u32.to_le_bytes());
    }

    #[test]
    fn test_formato_por_extension() {
        assert_eq!(formato_por_extension(Path::new("test.vmdk")), Some("vmdk"));
        assert_eq!(
            formato_por_extension(Path::new("test.qcow2")),
            Some("qcow2")
        );
        assert_eq!(formato_por_extension(Path::new("test.vdi")), Some("vdi"));
        assert_eq!(formato_por_extension(Path::new("test.vhdx")), Some("vhdx"));
        assert_eq!(formato_por_extension(Path::new("test.raw")), Some("raw"));
        assert_eq!(formato_por_extension(Path::new("test.xyz")), None);
    }
}
