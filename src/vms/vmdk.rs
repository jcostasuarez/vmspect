//! Lector nativo del formato VMDK (sin procesos externos ni `qemu-nbd`).
//!
//! Cubre los casos habituales de una VM "limpia" exportada por VMware:
//! - `monolithicSparse`: un solo archivo con cabecera `KDMV`, descriptor
//!   embebido y grains de 64 KiB direccionados por directorio y tablas.
//! - `monolithicFlat` / `twoGbMaxExtent*` / `vmfs`: descriptor de texto que
//!   apunta a uno o varios extents `FLAT` (raw con offset) o `SPARSE`.
//!
//! Cualquier otra cosa (grains comprimidos / `streamOptimized`, disco padre o
//! snapshot, tipos de extent desconocidos) se delega a `qemu-nbd`.
//!
//! Referencia: "Virtual Disk Format 5.0", VMware Technical Note.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const SECTOR: u64 = 512;
const MAGIC_KDMV: &[u8; 4] = b"KDMV";
const FLAG_GRAINS_COMPRIMIDOS: u32 = 1 << 16;
const FLAG_MARCADORES: u32 = 1 << 17;

/// Resultado de intentar abrir algo de forma nativa.
pub enum Apertura<T> {
    Nativa(T),
    /// El formato es válido pero requiere delegación a `qemu-nbd`; se indica el motivo.
    NecesitaNbd(String),
}

// -----------------------------------------------------------------------------
// Cabecera de extent sparse
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CabeceraSparse {
    pub _version: u32,
    pub flags: u32,
    pub capacidad_sectores: u64,
    pub grain_sectores: u64,
    pub descriptor_offset: u64,
    pub descriptor_sectores: u64,
    pub gtes_por_gt: u32,
    pub rgd_offset: u64,
    pub gd_offset: u64,
    pub compresion: u16,
}

pub fn es_cabecera_sparse(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[0..4] == MAGIC_KDMV
}

pub fn leer_cabecera_sparse(buf: &[u8]) -> io::Result<CabeceraSparse> {
    if buf.len() < 80 || !es_cabecera_sparse(buf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Cabecera VMDK sparse inválida",
        ));
    }
    let u32_en = |o: usize| -> io::Result<u32> {
        buf.get(o..o + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Buffer insuficiente para u32")
            })
    };
    let u64_en = |o: usize| -> io::Result<u64> {
        buf.get(o..o + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Buffer insuficiente para u64")
            })
    };
    Ok(CabeceraSparse {
        _version: u32_en(4)?,
        flags: u32_en(8)?,
        capacidad_sectores: u64_en(12)?,
        grain_sectores: u64_en(20)?,
        descriptor_offset: u64_en(28)?,
        descriptor_sectores: u64_en(36)?,
        gtes_por_gt: u32_en(44)?,
        rgd_offset: u64_en(48)?,
        gd_offset: u64_en(56)?,
        compresion: u16::from_le_bytes([buf[77], buf[78]]),
    })
}

impl CabeceraSparse {
    /// Motivo por el que este extent no puede leerse de forma nativa, si lo hay.
    pub fn motivo_no_soportado(&self) -> Option<String> {
        if self.compresion != 0 || self.flags & (FLAG_GRAINS_COMPRIMIDOS | FLAG_MARCADORES) != 0 {
            return Some("VMDK con grains comprimidos (streamOptimized)".to_string());
        }
        if self.gd_offset == u64::MAX || self.gd_offset == 0 {
            return Some("VMDK sin directorio de grains en cabecera".to_string());
        }
        if self.grain_sectores == 0 || !self.grain_sectores.is_power_of_two() {
            return Some(format!(
                "VMDK con tamaño de grain no soportado ({} sectores)",
                self.grain_sectores
            ));
        }
        if self.gtes_por_gt == 0 || self.capacidad_sectores == 0 {
            return Some("VMDK con cabecera sparse incoherente".to_string());
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Descriptor de texto
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Descriptor {
    pub create_type: String,
    pub parent_cid: Option<u32>,
    pub parent_file_name_hint: Option<String>,
    pub extents: Vec<ExtentDescriptor>,
}

#[derive(Debug, Clone)]
pub struct ExtentDescriptor {
    pub _acceso: String,
    pub sectores: u64,
    /// FLAT, SPARSE, ZERO, VMFS, VMFSSPARSE...
    pub tipo: String,
    pub archivo: Option<String>,
    pub offset_sectores: u64,
}

impl Descriptor {
    pub fn tiene_padre(&self) -> bool {
        self.parent_file_name_hint
            .as_ref()
            .map(|h| !h.trim().is_empty())
            .unwrap_or(false)
            || matches!(self.parent_cid, Some(cid) if cid != 0xFFFF_FFFF)
    }
}

pub fn es_descriptor_texto(buf: &[u8]) -> bool {
    let inicio = &buf[..buf.len().min(64)];
    let texto = String::from_utf8_lossy(inicio);
    texto.trim_start().starts_with("# Disk DescriptorFile")
}

pub fn parsear_descriptor(texto: &str) -> Descriptor {
    let mut d = Descriptor::default();
    for linea in texto.lines() {
        let linea = linea.trim_matches(|c| c == '\0' || c == ' ' || c == '\t' || c == '\r');
        if linea.is_empty() || linea.starts_with('#') {
            continue;
        }

        let tokens = tokenizar(linea);
        if tokens.is_empty() {
            continue;
        }

        match tokens[0].to_ascii_uppercase().as_str() {
            "RW" | "RDONLY" | "NOACCESS" if tokens.len() >= 3 => {
                let sectores = tokens[1].parse().unwrap_or(0);
                let tipo = tokens[2].to_ascii_uppercase();
                let archivo = tokens.get(3).cloned();
                let offset_sectores = tokens.get(4).and_then(|t| t.parse().ok()).unwrap_or(0);
                d.extents.push(ExtentDescriptor {
                    _acceso: tokens[0].to_ascii_uppercase(),
                    sectores,
                    tipo,
                    archivo,
                    offset_sectores,
                });
            }
            _ => {
                if let Some((clave, valor)) = linea.split_once('=') {
                    let clave = clave.trim();
                    let valor = valor.trim().trim_matches('"');
                    match clave.to_ascii_lowercase().as_str() {
                        "createtype" => d.create_type = valor.to_string(),
                        "parentcid" => d.parent_cid = u32::from_str_radix(valor, 16).ok(),
                        "parentfilenamehint" => {
                            d.parent_file_name_hint = Some(valor.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    d
}

/// Divide por espacios respetando cadenas entre comillas dobles.
fn tokenizar(linea: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut actual = String::new();
    let mut entre_comillas = false;
    for c in linea.chars() {
        match c {
            '"' => entre_comillas = !entre_comillas,
            ' ' | '\t' if !entre_comillas => {
                if !actual.is_empty() {
                    tokens.push(std::mem::take(&mut actual));
                }
            }
            _ => actual.push(c),
        }
    }
    if !actual.is_empty() {
        tokens.push(actual);
    }
    tokens
}

// -----------------------------------------------------------------------------
// Extent sparse: lectura por grains
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct ExtentSparse {
    archivo: File,
    grain_bytes: u64,
    gtes_por_gt: u32,
    capacidad_bytes: u64,
    /// Directorio de grains completo (pequeño: 4 bytes por cada 32 MiB de disco).
    directorio: Vec<u32>,
    /// Tablas de grains cargadas bajo demanda, indexadas por su posición en el directorio.
    tablas: HashMap<u32, Vec<u32>>,
}

impl ExtentSparse {
    pub fn abrir(ruta: &Path) -> io::Result<Apertura<Self>> {
        let mut archivo = crate::vms::stream::abrir_archivo_lectura(ruta)?;
        let mut buf = [0u8; 512];
        archivo.read_exact(&mut buf)?;
        let cab = leer_cabecera_sparse(&buf)?;
        Self::desde_cabecera(archivo, ruta, cab)
    }

    pub fn desde_cabecera(
        mut archivo: File,
        _ruta: &Path,
        cab: CabeceraSparse,
    ) -> io::Result<Apertura<Self>> {
        if let Some(motivo) = cab.motivo_no_soportado() {
            return Ok(Apertura::NecesitaNbd(motivo));
        }

        let grain_bytes = cab.grain_sectores * SECTOR;
        let bytes_por_gt = grain_bytes * cab.gtes_por_gt as u64;
        let capacidad_bytes = cab.capacidad_sectores * SECTOR;
        let num_gts = capacidad_bytes.div_ceil(bytes_por_gt);
        if num_gts > 1 << 20 {
            return Ok(Apertura::NecesitaNbd(
                "VMDK con un directorio de grains desproporcionado".to_string(),
            ));
        }

        // Si el GD primario no es válido pero el redundante está marcado como usado, usarlo.
        let gd_offset = if cab.flags & 0x2 != 0 && cab.rgd_offset != 0 && cab.rgd_offset != u64::MAX
        {
            cab.rgd_offset
        } else {
            cab.gd_offset
        };

        let mut crudo = vec![0u8; (num_gts * 4) as usize];
        archivo.seek(SeekFrom::Start(gd_offset * SECTOR))?;
        archivo.read_exact(&mut crudo)?;
        let directorio = crudo
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&[b0, b1, b2, b3]| u32::from_le_bytes([b0, b1, b2, b3]))
            .collect();

        Ok(Apertura::Nativa(Self {
            archivo,
            grain_bytes,
            gtes_por_gt: cab.gtes_por_gt,
            capacidad_bytes,
            directorio,
            tablas: HashMap::new(),
        }))
    }

    fn tabla(&mut self, indice_gd: u32) -> io::Result<Option<&[u32]>> {
        let gde = match self.directorio.get(indice_gd as usize) {
            Some(&g) if g > 1 => g as u64,
            // 0 o 1: toda la tabla sin asignar → ceros.
            _ => return Ok(None),
        };
        if !self.tablas.contains_key(&indice_gd) {
            let mut crudo = vec![0u8; self.gtes_por_gt as usize * 4];
            self.archivo.seek(SeekFrom::Start(gde * SECTOR))?;
            self.archivo.read_exact(&mut crudo)?;
            let tabla: Vec<u32> = crudo
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&[b0, b1, b2, b3]| u32::from_le_bytes([b0, b1, b2, b3]))
                .collect();
            self.tablas.insert(indice_gd, tabla);
        }
        Ok(self.tablas.get(&indice_gd).map(|t| t.as_slice()))
    }

    /// Rellena `buf` con los datos del disco virtual a partir de `offset`.
    ///
    /// Las zonas no asignadas se devuelven como ceros. Devuelve cuántos bytes de
    /// `buf` quedan dentro de la capacidad del extent.
    pub fn leer_en(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.capacidad_bytes {
            return Ok(0);
        }
        let total = buf.len().min((self.capacidad_bytes - offset) as usize);
        let mut hecho = 0usize;

        while hecho < total {
            let pos = offset + hecho as u64;
            let grain = pos / self.grain_bytes;
            let dentro = (pos % self.grain_bytes) as usize;
            let n = (self.grain_bytes as usize - dentro).min(total - hecho);

            let indice_gd = (grain / self.gtes_por_gt as u64) as u32;
            let indice_gte = (grain % self.gtes_por_gt as u64) as usize;

            let sector_grain = self
                .tabla(indice_gd)?
                .and_then(|t| t.get(indice_gte).copied())
                .unwrap_or(0);

            let destino = &mut buf[hecho..hecho + n];
            if sector_grain > 1 {
                self.archivo.seek(SeekFrom::Start(
                    sector_grain as u64 * SECTOR + dentro as u64,
                ))?;
                leer_o_ceros(&mut self.archivo, destino)?;
            } else {
                destino.fill(0);
            }
            hecho += n;
        }
        Ok(total)
    }
}

/// Lee hasta llenar `buf`; si el archivo termina antes, rellena el resto con ceros.
pub fn leer_o_ceros<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut leido = 0;
    while leido < buf.len() {
        match r.read(&mut buf[leido..]) {
            Ok(0) => {
                buf[leido..].fill(0);
                return Ok(());
            }
            Ok(n) => leido += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Resuelve la ruta de un extent relativa al directorio del descriptor.
pub fn resolver_ruta_extent(descriptor: &Path, archivo: &str) -> PathBuf {
    let p = Path::new(archivo);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    descriptor
        .parent()
        .map(|d| d.join(p))
        .unwrap_or_else(|| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenizar() {
        let tokens = tokenizar("RW 20971520 FLAT \"Windows-flat.vmdk\" 0");
        assert_eq!(
            tokens,
            vec!["RW", "20971520", "FLAT", "Windows-flat.vmdk", "0"]
        );
    }

    #[test]
    fn test_parsear_descriptor() {
        let texto = r#"
# Disk DescriptorFile
version=1
CID=7b844f21
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 4194304 FLAT "disk-f001.vmdk" 0
RW 4194304 FLAT "disk-f002.vmdk" 0
"#;
        let d = parsear_descriptor(texto);
        assert_eq!(d.create_type, "twoGbMaxExtentFlat");
        assert_eq!(d.extents.len(), 2);
        assert_eq!(d.extents[0]._acceso, "RW");
        assert_eq!(d.extents[0].sectores, 4194304);
        assert_eq!(d.extents[0].archivo.as_deref(), Some("disk-f001.vmdk"));
        assert!(!d.tiene_padre());
    }

    #[test]
    fn test_resolver_ruta_extent() {
        let desc = Path::new("C:/vms/win/disk.vmdk");
        let ext = resolver_ruta_extent(desc, "disk-f001.vmdk");
        assert_eq!(ext, Path::new("C:/vms/win/disk-f001.vmdk"));
    }
}
