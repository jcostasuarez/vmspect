//! Módulo de descubrimiento, verificación de integridad y análisis de capacidades de inspección de imágenes de máquinas virtuales.
//!
//! Proporciona funciones de alto nivel para:
//! - Detección y filtrado inteligente de imágenes de disco (.vmdk, .qcow2, .vdi, .vhd, .vhdx, .raw, .img).
//! - Ignorar extents secundarios o archivos delta (`*-flat.vmdk`, `*-s001.vmdk`, `*-delta.vmdk`, etc.).
//! - Verificación rápida de firmas de encabezado (Magic Numbers) sin leer el disco completo.
//! - Análisis previo para determinar si una imagen puede procesarse de forma nativa o si requiere `qemu-nbd`.

use crate::error::{Result, VmSpectError};
use crate::vms::vmdk;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Extensiones de archivo reconocidas para imágenes de máquinas virtuales.
pub const EXTENSIONES_SOPORTADAS: &[&str] = &["vmdk", "qcow2", "vdi", "vhd", "vhdx", "raw", "img"];

/// Magic bytes para el formato QCOW2 (`QFI\xfb`).
pub const MAGIC_QCOW2: &[u8; 4] = b"QFI\xfb";

/// Magic bytes para el formato VMDK sparse binario (`KDMV`).
pub const MAGIC_VMDK_KDMV: &[u8; 4] = b"KDMV";

/// Magic bytes para el formato VHDX (`vhdxfile`).
pub const MAGIC_VHDX: &[u8; 8] = b"vhdxfile";

/// Magic bytes para el formato VHD / VirtualPC (`conectix`).
pub const MAGIC_VHD_CONECTIX: &[u8; 8] = b"conectix";

/// Firma de imagen VirtualBox VDI en offset 0x40 (`0xBEDA107F` en little-endian).
pub const MAGIC_VDI_SIGNATURE: &[u8; 4] = &[0x7F, 0x10, 0xDA, 0xBE];

/// Prefijo de texto para encabezados VDI antiguos de Sun VirtualBox.
pub const MAGIC_VDI_PREFIX_SUN: &[u8] = b"<<< Sun VirtualBox Disk Image >>>";

/// Prefijo de texto para encabezados VDI de Oracle VM VirtualBox.
pub const MAGIC_VDI_PREFIX_ORACLE: &[u8] = b"<<< Oracle VM VirtualBox Disk Image >>>";

/// Comprueba si la ruta especificada corresponde a un extent secundario, archivo de delta o fragmento
/// que no constituye el descriptor o archivo principal de la máquina virtual.
///
/// Filtra patrones como:
/// - `*-flat.vmdk`, `*_flat.vmdk`
/// - `*-delta.vmdk`, `*_delta.vmdk`
/// - `*-sesparse.vmdk`, `*_sesparse.vmdk`
/// - `*-s[0-9]*.vmdk`, `*_s[0-9]*.vmdk` (extents divididos de VMDK)
/// - `*-sys.vhd`, `*_sys.vhd`, `*-delta.vhd`, `*_delta.vhd`
/// - `*-sys.vhdx`, `*_sys.vhdx`, `*-delta.vhdx`, `*_delta.vhdx`
///
/// # Parámetros
///
/// - `ruta`: Ruta al archivo a verificar.
///
/// # Ejemplos
///
/// ```
/// use std::path::Path;
/// use vmspect::vms::discovery::es_extent_secundario;
///
/// assert!(es_extent_secundario(Path::new("disco-flat.vmdk")));
/// assert!(es_extent_secundario(Path::new("disco-s001.vmdk")));
/// assert!(es_extent_secundario(Path::new("snapshot-delta.vmdk")));
/// assert!(!es_extent_secundario(Path::new("disco.vmdk")));
/// ```
pub fn es_extent_secundario(ruta: &Path) -> bool {
    let nombre = match ruta.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };

    if nombre.ends_with(".vmdk") {
        let stem = match ruta.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_ascii_lowercase(),
            None => return false,
        };

        if stem.ends_with("-flat")
            || stem.ends_with("_flat")
            || stem.ends_with("-delta")
            || stem.ends_with("_delta")
            || stem.ends_with("-sesparse")
            || stem.ends_with("_sesparse")
        {
            return true;
        }

        for sep in &["-s", "_s"] {
            if let Some(pos) = stem.rfind(sep) {
                let suffix = &stem[pos + sep.len()..];
                if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }
    } else if nombre.ends_with(".vhd") || nombre.ends_with(".vhdx") {
        let stem = match ruta.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_ascii_lowercase(),
            None => return false,
        };
        if stem.ends_with("-sys")
            || stem.ends_with("_sys")
            || stem.ends_with("-delta")
            || stem.ends_with("_delta")
        {
            return true;
        }
    }

    false
}

/// Alias en inglés para [`es_extent_secundario`].
pub use es_extent_secundario as is_secondary_extent;

/// Determina si una ruta corresponde a una imagen de disco de máquina virtual soportada.
///
/// Realiza una validación rápida y no invasiva:
/// 1. Verifica que la extensión sea compatible (`.vmdk`, `.qcow2`, `.vdi`, `.vhd`, `.vhdx`, `.raw`, `.img`).
/// 2. Aplica filtros para ignorar extents secundarios o deltas (ej. `*-s001.vmdk`, `*-flat.vmdk`).
/// 3. Si el archivo existe en disco, valida que no sea un directorio y que su tamaño sea mayor a 0.
///
/// # Parámetros
///
/// - `ruta`: Ruta al archivo o candidato a imagen.
///
/// # Retorno
///
/// `true` si la ruta representa una imagen de VM candidata, `false` en caso contrario.
///
/// # Ejemplos
///
/// ```
/// use std::path::Path;
/// use vmspect::es_imagen_vm;
///
/// assert!(es_imagen_vm(Path::new("ubuntu.qcow2")));
/// assert!(es_imagen_vm(Path::new("disco.vmdk")));
/// assert!(!es_imagen_vm(Path::new("disco-flat.vmdk")));
/// assert!(!es_imagen_vm(Path::new("archivo.txt")));
/// ```
pub fn es_imagen_vm(ruta: &Path) -> bool {
    if ruta.is_dir() {
        return false;
    }

    let ext = match ruta.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return false,
    };

    if !EXTENSIONES_SOPORTADAS.contains(&ext.as_str()) {
        return false;
    }

    if es_extent_secundario(ruta) {
        return false;
    }

    if let Ok(meta) = fs::metadata(ruta) {
        if !meta.is_file() || meta.len() == 0 {
            return false;
        }
    }

    true
}

/// Alias en inglés para [`es_imagen_vm`].
pub use es_imagen_vm as is_vm_image;

/// Lista todas las imágenes de máquinas virtuales encontradas en un directorio dado.
///
/// # Parámetros
///
/// - `directorio`: Ruta del directorio a inspeccionar.
/// - `recursivo`: Si es `true`, busca de manera recursiva en todos los subdirectorios.
///
/// # Errores
///
/// Devuelve [`VmSpectError::ImageNotFound`] si el directorio no existe, o [`VmSpectError::Io`]
/// si ocurre un fallo al acceder a los elementos del sistema de archivos.
///
/// # Ejemplos
///
/// ```no_run
/// use std::path::Path;
/// use vmspect::listar_vms;
///
/// let vms = listar_vms(Path::new("/var/lib/libvirt/images"), false)?;
/// println!("Encontradas {} imágenes", vms.len());
/// # Ok::<(), vmspect::VmSpectError>(())
/// ```
pub fn listar_vms(directorio: &Path, recursivo: bool) -> Result<Vec<PathBuf>> {
    if !directorio.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Directorio no encontrado: {}",
            directorio.display()
        )));
    }
    if !directorio.is_dir() {
        return Err(VmSpectError::Other(format!(
            "La ruta especificada no es un directorio: {}",
            directorio.display()
        )));
    }

    let mut imagenes = Vec::new();
    let mut cola = VecDeque::new();
    cola.push_back(directorio.to_path_buf());

    while let Some(dir_actual) = cola.pop_front() {
        let entries = match fs::read_dir(&dir_actual) {
            Ok(entries) => entries,
            Err(e) => return Err(VmSpectError::Io(e)),
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => return Err(VmSpectError::Io(e)),
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => return Err(VmSpectError::Io(e)),
            };

            if file_type.is_dir() {
                if recursivo {
                    cola.push_back(path);
                }
            } else if file_type.is_file() && es_imagen_vm(&path) {
                imagenes.push(path);
            }
        }
    }

    imagenes.sort();
    Ok(imagenes)
}

/// Alias en inglés para [`listar_vms`].
pub use listar_vms as list_vms;

/// Cuenta la cantidad de imágenes de máquinas virtuales presentes en un directorio.
///
/// # Parámetros
///
/// - `directorio`: Directorio a examinar.
/// - `recursivo`: Indica si se deben incluir subdirectorios.
///
/// # Errores
///
/// Devuelve un error si el directorio no existe o no se puede leer.
pub fn contar_vms(directorio: &Path, recursivo: bool) -> Result<usize> {
    listar_vms(directorio, recursivo).map(|lista| lista.len())
}

/// Alias en inglés para [`contar_vms`].
pub use contar_vms as count_vms;

/// Comprueba si existe al menos una imagen de máquina virtual en el directorio indicado.
///
/// Realiza una búsqueda optimizada con cortocircuito temprano (retorna `Ok(true)` en cuanto
/// encuentra el primer archivo coincidente, sin recorrer el resto del directorio).
///
/// # Parámetros
///
/// - `directorio`: Directorio a examinar.
/// - `recursivo`: Indica si se deben incluir subdirectorios.
///
/// # Errores
///
/// Devuelve un error si el directorio no existe o no se puede leer.
pub fn hay_vms(directorio: &Path, recursivo: bool) -> Result<bool> {
    if !directorio.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Directorio no encontrado: {}",
            directorio.display()
        )));
    }
    if !directorio.is_dir() {
        return Err(VmSpectError::Other(format!(
            "La ruta especificada no es un directorio: {}",
            directorio.display()
        )));
    }

    let mut cola = VecDeque::new();
    cola.push_back(directorio.to_path_buf());

    while let Some(dir_actual) = cola.pop_front() {
        let entries = match fs::read_dir(&dir_actual) {
            Ok(entries) => entries,
            Err(e) => return Err(VmSpectError::Io(e)),
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => return Err(VmSpectError::Io(e)),
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => return Err(VmSpectError::Io(e)),
            };

            if file_type.is_dir() {
                if recursivo {
                    cola.push_back(path);
                }
            } else if file_type.is_file() && es_imagen_vm(&path) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Alias en inglés para [`hay_vms`].
pub use hay_vms as has_vms;

/// Verifica la integridad y formato de una imagen de disco mediante inspección rápida de sus Magic Bytes.
///
/// Lee exclusivamente el bloque inicial de encabezado (hasta 4 KB) o el pie de página (en VHD fijo),
/// garantizando mínima sobrecarga de E/S.
///
/// Firmas validadas según formato:
/// - **QCOW2:** `QFI\xfb` (`[0x51, 0x46, 0x49, 0xFB]`)
/// - **VMDK:** `KDMV` (`[0x4B, 0x44, 0x4D, 0x56]`) o descriptor de texto `# Disk DescriptorFile` / `# VMDK Header`
/// - **VDI:** `<<< Sun/Oracle VirtualBox Disk Image >>>` o firma `[0x7F, 0x10, 0xDA, 0xBE]` en offset `0x40`
/// - **VHDX:** `vhdxfile` (`[0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65]`)
/// - **VHD:** `conectix` (`[0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78]`) en cabecera o pie de 512 bytes
/// - **RAW / IMG:** Archivo válido no vacío con estructura mínima de disco (MBR/GPT o tamaño coherente).
///
/// # Parámetros
///
/// - `ruta`: Ruta de la imagen de disco a verificar.
///
/// # Retorno
///
/// - `Ok(true)` si la imagen posee una firma válida correspondiente a su formato.
/// - `Ok(false)` si el encabezado no coincide con la firma esperada o está corrupto.
/// - `Err(VmSpectError)` si la imagen no existe o falla la lectura de E/S.
pub fn verificar_integridad_imagen(ruta: &Path) -> Result<bool> {
    if !ruta.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Imagen no encontrada: {}",
            ruta.display()
        )));
    }

    let mut archivo = File::open(ruta).map_err(VmSpectError::Io)?;
    let tamano = archivo.metadata().map_err(VmSpectError::Io)?.len();

    if tamano == 0 {
        return Ok(false);
    }

    let cant_leer = (tamano as usize).min(4096);
    let mut cabecera = vec![0u8; cant_leer];
    archivo
        .read_exact(&mut cabecera)
        .map_err(VmSpectError::Io)?;

    let ext = ruta
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "qcow2" => Ok(cabecera.len() >= 4 && cabecera.starts_with(MAGIC_QCOW2)),
        "vmdk" => {
            if cabecera.len() >= 4 && cabecera.starts_with(MAGIC_VMDK_KDMV) {
                return Ok(true);
            }
            let texto = String::from_utf8_lossy(&cabecera);
            let texto_trim = texto.trim_start();
            if texto_trim.starts_with("# Disk DescriptorFile")
                || texto_trim.starts_with("# VMDK Header")
                || texto_trim.starts_with("# VMDK")
                || texto_trim.contains("# Disk DescriptorFile")
            {
                return Ok(true);
            }
            Ok(false)
        }
        "vdi" => {
            if cabecera.starts_with(b"<<< ") {
                if cabecera.starts_with(MAGIC_VDI_PREFIX_SUN)
                    || cabecera.starts_with(MAGIC_VDI_PREFIX_ORACLE)
                {
                    return Ok(true);
                }
                if cabecera.len() >= 0x44 && cabecera[0x40..0x44] == *MAGIC_VDI_SIGNATURE {
                    return Ok(true);
                }
            }
            if cabecera.len() >= 0x44 && cabecera[0x40..0x44] == *MAGIC_VDI_SIGNATURE {
                return Ok(true);
            }
            Ok(false)
        }
        "vhdx" => Ok(cabecera.len() >= 8 && cabecera.starts_with(MAGIC_VHDX)),
        "vhd" => {
            if cabecera.len() >= 8
                && (cabecera.starts_with(MAGIC_VHD_CONECTIX) || cabecera.starts_with(b"cxsparse"))
            {
                return Ok(true);
            }
            if tamano >= 512 {
                let mut footer = [0u8; 512];
                archivo
                    .seek(SeekFrom::Start(tamano - 512))
                    .map_err(VmSpectError::Io)?;
                archivo.read_exact(&mut footer).map_err(VmSpectError::Io)?;
                if footer.starts_with(MAGIC_VHD_CONECTIX) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "raw" | "img" => {
            if tamano < 512 {
                return Ok(false);
            }
            // Firma MBR en 510..512 (0x55, 0xAA)
            if cabecera.len() >= 512 && cabecera[510] == 0x55 && cabecera[511] == 0xAA {
                return Ok(true);
            }
            // Firma GPT en 512..520 ("EFI PART")
            if cabecera.len() >= 520 && &cabecera[512..520] == b"EFI PART" {
                return Ok(true);
            }
            Ok(true)
        }
        _ => {
            if cabecera.starts_with(MAGIC_QCOW2)
                || cabecera.starts_with(MAGIC_VMDK_KDMV)
                || cabecera.starts_with(MAGIC_VHDX)
                || cabecera.starts_with(MAGIC_VHD_CONECTIX)
                || (cabecera.len() >= 0x44 && cabecera[0x40..0x44] == *MAGIC_VDI_SIGNATURE)
            {
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

/// Alias en inglés para [`verificar_integridad_imagen`].
pub use verificar_integridad_imagen as verify_image_integrity;

/// Realiza un análisis temprano para determinar si la imagen de disco requiere delegar el montaje a `qemu-nbd`
/// o si puede ser procesada directamente mediante el motor nativo de Rust en `vmspect`.
///
/// # Criterio de Decisión:
/// - **Nativo (`Ok(false)`):** Formatos RAW, IMG o imágenes VMDK monolíticas estándar (monolithicSparse o monolithicFlat).
/// - **Requiere NBD (`Ok(true)`):** Formatos complejos como QCOW2, VDI, VHD, VHDX, snapshots anidados con disco padre,
///   imágenes multi-extent/split (`twoGbMaxExtentSparse`), o compresión de grains (`streamOptimized`).
///
/// # Parámetros
///
/// - `ruta`: Ruta de la imagen de disco a evaluar.
///
/// # Errores
///
/// Devuelve un error si el archivo no existe o no se puede acceder a su encabezado.
pub fn requiere_nbd(ruta: &Path) -> Result<bool> {
    if !ruta.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Imagen no encontrada: {}",
            ruta.display()
        )));
    }

    let ext = ruta
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "raw" | "img" => Ok(false),
        "qcow2" | "vdi" | "vhd" | "vhdx" => Ok(true),
        "vmdk" => {
            let mut archivo = File::open(ruta).map_err(VmSpectError::Io)?;
            let mut cabecera = [0u8; 512];
            let n = archivo.read(&mut cabecera).map_err(VmSpectError::Io)?;
            let cabecera = &cabecera[..n];

            if vmdk::es_cabecera_sparse(cabecera) {
                let cab = match vmdk::leer_cabecera_sparse(cabecera) {
                    Ok(c) => c,
                    Err(_) => return Ok(true),
                };

                if cab.motivo_no_soportado().is_some() {
                    return Ok(true);
                }

                if cab.descriptor_offset != 0 && cab.descriptor_sectores != 0 {
                    let bytes_desc = (cab.descriptor_sectores * vmdk::SECTOR) as usize;
                    let mut texto = vec![0u8; bytes_desc.min(64 * 1024)];
                    if archivo
                        .seek(SeekFrom::Start(cab.descriptor_offset * vmdk::SECTOR))
                        .is_ok()
                        && archivo.read_exact(&mut texto).is_ok()
                    {
                        let d = vmdk::parsear_descriptor(&String::from_utf8_lossy(&texto));
                        if d.tiene_padre() || d.extents.len() > 1 {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            } else if vmdk::es_descriptor_texto(cabecera) {
                let texto = fs::read_to_string(ruta).map_err(VmSpectError::Io)?;
                let d = vmdk::parsear_descriptor(&texto);

                if d.tiene_padre() || d.extents.is_empty() {
                    return Ok(true);
                }

                if d.extents.len() > 1
                    || d.create_type
                        .to_ascii_lowercase()
                        .contains("twogbmaxextent")
                {
                    return Ok(true);
                }

                if d.extents.len() == 1 {
                    let tipo = d.extents[0].tipo.to_ascii_uppercase();
                    if tipo == "FLAT" || tipo == "ZERO" {
                        return Ok(false);
                    }
                }

                Ok(true)
            } else {
                Ok(true)
            }
        }
        _ => Ok(true),
    }
}

/// Alias en inglés para [`requiere_nbd`].
pub use requiere_nbd as requires_nbd;

/// Determina si la imagen de disco requiere delegación a herramientas QEMU / NBD.
///
/// Equivalente directo a [`requiere_nbd`].
pub fn requiere_qemu(ruta: &Path) -> Result<bool> {
    requiere_nbd(ruta)
}

/// Alias en inglés para [`requiere_qemu`].
pub use requiere_qemu as requires_qemu;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_es_extent_secundario() {
        assert!(es_extent_secundario(Path::new("ubuntu-flat.vmdk")));
        assert!(es_extent_secundario(Path::new("ubuntu_flat.vmdk")));
        assert!(es_extent_secundario(Path::new("ubuntu-delta.vmdk")));
        assert!(es_extent_secundario(Path::new("ubuntu-sesparse.vmdk")));
        assert!(es_extent_secundario(Path::new("windows-s001.vmdk")));
        assert!(es_extent_secundario(Path::new("windows-s02.vmdk")));
        assert!(es_extent_secundario(Path::new("windows_s1.vmdk")));
        assert!(es_extent_secundario(Path::new("disk-sys.vhd")));
        assert!(es_extent_secundario(Path::new("disk_sys.vhd")));
        assert!(es_extent_secundario(Path::new("disk-delta.vhd")));
        assert!(es_extent_secundario(Path::new("disk-delta.vhdx")));

        // Válidos (no secundarios)
        assert!(!es_extent_secundario(Path::new("ubuntu.vmdk")));
        assert!(!es_extent_secundario(Path::new("windows-server.vmdk")));
        assert!(!es_extent_secundario(Path::new("disk.qcow2")));
        assert!(!es_extent_secundario(Path::new("disk.vdi")));
        assert!(!es_extent_secundario(Path::new("disk.vhd")));
        assert!(!es_extent_secundario(Path::new("disk.vhdx")));
        assert!(!es_extent_secundario(Path::new("disk.raw")));
    }

    #[test]
    fn test_es_imagen_vm() {
        assert!(es_imagen_vm(Path::new("vm.vmdk")));
        assert!(es_imagen_vm(Path::new("vm.qcow2")));
        assert!(es_imagen_vm(Path::new("vm.vdi")));
        assert!(es_imagen_vm(Path::new("vm.vhd")));
        assert!(es_imagen_vm(Path::new("vm.vhdx")));
        assert!(es_imagen_vm(Path::new("vm.raw")));
        assert!(es_imagen_vm(Path::new("vm.img")));

        assert!(!es_imagen_vm(Path::new("vm-flat.vmdk")));
        assert!(!es_imagen_vm(Path::new("vm-s001.vmdk")));
        assert!(!es_imagen_vm(Path::new("vm.iso")));
        assert!(!es_imagen_vm(Path::new("vm.txt")));
    }

    #[test]
    fn test_verificar_integridad_qcow2() {
        let dir = tempdir().unwrap();
        let ruta = dir.path().join("test.qcow2");
        let mut f = File::create(&ruta).unwrap();
        f.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();

        assert!(verificar_integridad_imagen(&ruta).unwrap());

        let ruta_invalida = dir.path().join("invalido.qcow2");
        let mut f2 = File::create(&ruta_invalida).unwrap();
        f2.write_all(b"NOT_QCOW2_HEADER").unwrap();

        assert!(!verificar_integridad_imagen(&ruta_invalida).unwrap());
    }

    #[test]
    fn test_verificar_integridad_vmdk() {
        let dir = tempdir().unwrap();

        // 1. KDMV sparse
        let ruta_sparse = dir.path().join("sparse.vmdk");
        let mut f1 = File::create(&ruta_sparse).unwrap();
        f1.write_all(b"KDMV\x01\x00\x00\x00").unwrap();
        assert!(verificar_integridad_imagen(&ruta_sparse).unwrap());

        // 2. Descriptor de texto
        let ruta_desc = dir.path().join("desc.vmdk");
        let mut f2 = File::create(&ruta_desc).unwrap();
        f2.write_all(b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\n")
            .unwrap();
        assert!(verificar_integridad_imagen(&ruta_desc).unwrap());
    }

    #[test]
    fn test_verificar_integridad_vdi_vhdx_vhd() {
        let dir = tempdir().unwrap();

        // VHDX
        let ruta_vhdx = dir.path().join("test.vhdx");
        let mut f = File::create(&ruta_vhdx).unwrap();
        f.write_all(b"vhdxfile\x00\x00\x00\x00").unwrap();
        assert!(verificar_integridad_imagen(&ruta_vhdx).unwrap());

        // VHD dinámico
        let ruta_vhd = dir.path().join("test.vhd");
        let mut f2 = File::create(&ruta_vhd).unwrap();
        f2.write_all(b"conectix\x00\x00\x00\x00").unwrap();
        assert!(verificar_integridad_imagen(&ruta_vhd).unwrap());

        // VDI
        let ruta_vdi = dir.path().join("test.vdi");
        let mut f3 = File::create(&ruta_vdi).unwrap();
        let mut header_vdi = vec![0u8; 100];
        header_vdi[..MAGIC_VDI_PREFIX_ORACLE.len()].copy_from_slice(MAGIC_VDI_PREFIX_ORACLE);
        header_vdi[0x40..0x44].copy_from_slice(MAGIC_VDI_SIGNATURE);
        f3.write_all(&header_vdi).unwrap();
        assert!(verificar_integridad_imagen(&ruta_vdi).unwrap());
    }

    #[test]
    fn test_listar_contar_hay_vms() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();

        let vm1 = dir.path().join("ubuntu.qcow2");
        let vm2 = dir.path().join("disco.vmdk");
        let extent = dir.path().join("disco-flat.vmdk");
        let vm3 = sub.join("windows.vhdx");
        let dummy = dir.path().join("notas.txt");

        File::create(&vm1).unwrap().write_all(b"data").unwrap();
        File::create(&vm2).unwrap().write_all(b"data").unwrap();
        File::create(&extent).unwrap().write_all(b"data").unwrap();
        File::create(&vm3).unwrap().write_all(b"data").unwrap();
        File::create(&dummy).unwrap().write_all(b"data").unwrap();

        // No recursivo
        let vms_no_rec = listar_vms(dir.path(), false).unwrap();
        assert_eq!(vms_no_rec.len(), 2);
        assert!(vms_no_rec.contains(&vm1));
        assert!(vms_no_rec.contains(&vm2));
        assert!(!vms_no_rec.contains(&extent));
        assert_eq!(contar_vms(dir.path(), false).unwrap(), 2);
        assert!(hay_vms(dir.path(), false).unwrap());

        // Recursivo
        let vms_rec = listar_vms(dir.path(), true).unwrap();
        assert_eq!(vms_rec.len(), 3);
        assert!(vms_rec.contains(&vm3));
        assert_eq!(contar_vms(dir.path(), true).unwrap(), 3);
        assert!(hay_vms(dir.path(), true).unwrap());

        // Directorio vacío
        let dir_vacio = tempdir().unwrap();
        assert_eq!(contar_vms(dir_vacio.path(), true).unwrap(), 0);
        assert!(!hay_vms(dir_vacio.path(), true).unwrap());
    }

    #[test]
    fn test_requiere_nbd_formatos() {
        let dir = tempdir().unwrap();

        let raw = dir.path().join("disco.raw");
        File::create(&raw).unwrap().write_all(b"raw data").unwrap();
        assert!(!requiere_nbd(&raw).unwrap());

        let qcow2 = dir.path().join("disco.qcow2");
        File::create(&qcow2).unwrap().write_all(b"qcow2").unwrap();
        assert!(requiere_nbd(&qcow2).unwrap());
        assert!(requiere_qemu(&qcow2).unwrap());

        let vhdx = dir.path().join("disco.vhdx");
        File::create(&vhdx).unwrap().write_all(b"vhdx").unwrap();
        assert!(requiere_nbd(&vhdx).unwrap());

        // Descriptor VMDK monolítico flat
        let vmdk_flat_desc = dir.path().join("monolithic_flat.vmdk");
        let mut f_desc = File::create(&vmdk_flat_desc).unwrap();
        f_desc
            .write_all(
                b"# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"data.flat\" 0\n",
            )
            .unwrap();
        assert!(!requiere_nbd(&vmdk_flat_desc).unwrap());

        // Descriptor VMDK con padre (snapshot) -> requiere NBD
        let vmdk_snap = dir.path().join("snapshot.vmdk");
        let mut f_snap = File::create(&vmdk_snap).unwrap();
        f_snap
            .write_all(
                b"# Disk DescriptorFile\nparentFileNameHint=\"base.vmdk\"\nRW 2048 FLAT \"snap.flat\" 0\n",
            )
            .unwrap();
        assert!(requiere_nbd(&vmdk_snap).unwrap());
    }
}
