//! Identificación de la tabla de particiones, los sistemas de archivos y el
//! sistema operativo invitado a partir de los primeros sectores del disco.
//!
//! Solo lee lo imprescindible: el sector 0 (MBR / protective MBR), la cabecera
//! GPT y su tabla de entradas, y el primer sector de cada partición para
//! identificar la firma del sistema de archivos. Con eso basta para decidir si
//! el invitado es Windows (NTFS) o Linux (ext*/XFS/Btrfs) sin recorrer el disco.

use crate::models::options::InspectionProgress;
use crate::models::traits::VmDriver;
use crate::models::{EsquemaParticion, Particion, SistemaArchivos, SistemaOperativo};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const SECTOR: u64 = 512;

fn leer_bloques(driver: &dyn VmDriver, bs: u64, indice: u64, cantidad: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; (cantidad * bs) as usize];
    driver
        .leer_rango(indice * bs, &mut buf)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(buf)
}

#[derive(Debug)]
pub(crate) struct DiscoDetectado {
    pub esquema: EsquemaParticion,
    pub particiones: Vec<Particion>,
    pub sistema_operativo: SistemaOperativo,
}

pub fn detectar_con_progreso(
    driver: &dyn VmDriver,
    cancel_token: Option<Arc<AtomicBool>>,
    progreso: Option<Arc<InspectionProgress>>,
) -> io::Result<DiscoDetectado> {
    if let Some(ref cancel) = cancel_token {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Análisis cancelado por el usuario",
            ));
        }
    }

    // Sector 0 + cabecera GPT (sector 1) en una sola invocación.
    let cabecera = leer_bloques(driver, SECTOR, 0, 2)?;
    if cabecera.len() < SECTOR as usize {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "El disco virtual es demasiado pequeño para contener un sector de arranque",
        ));
    }
    let mbr = &cabecera[..SECTOR as usize];

    let (esquema, mut particiones) = if cabecera.len() >= 1024 && &cabecera[512..520] == b"EFI PART"
    {
        (
            EsquemaParticion::Gpt,
            leer_gpt(driver, &cabecera[512..1024])?,
        )
    } else if mbr[510] == 0x55 && mbr[511] == 0xAA {
        let entradas = leer_mbr(driver, mbr)?;
        if entradas.is_empty() && identificar_fs(mbr) != SistemaArchivos::Desconocido {
            // Volumen sin tabla de particiones (p. ej. VHD de solo datos).
            (
                EsquemaParticion::SinTabla,
                vec![particion_unica(driver, mbr)],
            )
        } else {
            (EsquemaParticion::Mbr, entradas)
        }
    } else {
        (
            EsquemaParticion::SinTabla,
            vec![particion_unica(driver, mbr)],
        )
    };

    if let Some(ref cancel) = cancel_token {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Análisis cancelado por el usuario",
            ));
        }
    }

    // Identificar el sistema de archivos real de cada partición leyendo su primer sector.
    for p in particiones.iter_mut() {
        if let Some(ref cancel) = cancel_token {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Análisis cancelado por el usuario",
                ));
            }
        }

        if p.sistema_archivos == SistemaArchivos::Desconocido && p.tamano > 0 {
            let primer_sector = leer_bloques(driver, SECTOR, p.inicio / SECTOR, 1)?;
            if primer_sector.len() == SECTOR as usize {
                p.sistema_archivos = identificar_fs(&primer_sector);
                if p.sistema_archivos == SistemaArchivos::Desconocido {
                    // ext*/XFS/Btrfs no tienen firma en el sector 0 de la partición.
                    p.sistema_archivos = identificar_fs_linux(driver, p.inicio)?;
                }
            }
        }

        if let Some(ref prog) = progreso {
            prog.increment_completed_tasks();
        }
    }

    let sistema_operativo = clasificar_so(&particiones);

    Ok(DiscoDetectado {
        esquema,
        particiones,
        sistema_operativo,
    })
}

fn particion_unica(driver: &dyn VmDriver, sector0: &[u8]) -> Particion {
    Particion {
        indice: 0,
        inicio: 0,
        tamano: driver.tamano_virtual(),
        tipo: "Volumen sin tabla de particiones".to_string(),
        sistema_archivos: identificar_fs(sector0),
        etiqueta: None,
    }
}

// -----------------------------------------------------------------------------
// MBR
// -----------------------------------------------------------------------------

fn leer_mbr(driver: &dyn VmDriver, mbr: &[u8]) -> io::Result<Vec<Particion>> {
    let mut particiones = Vec::new();
    for i in 0..4 {
        let e = &mbr[446 + i * 16..446 + (i + 1) * 16];
        let tipo = e[4];
        let lba_inicio = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let sectores = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
        if tipo == 0 || sectores == 0 {
            continue;
        }

        // Partición extendida: recorrer la cadena de EBR.
        if matches!(tipo, 0x05 | 0x0F | 0x85) {
            leer_cadena_extendida(driver, lba_inicio, &mut particiones)?;
            continue;
        }

        particiones.push(Particion {
            indice: particiones.len(),
            inicio: lba_inicio * SECTOR,
            tamano: sectores * SECTOR,
            tipo: nombre_tipo_mbr(tipo),
            sistema_archivos: SistemaArchivos::Desconocido,
            etiqueta: None,
        });
    }
    Ok(particiones)
}

fn leer_cadena_extendida(
    driver: &dyn VmDriver,
    lba_extendida: u64,
    salida: &mut Vec<Particion>,
) -> io::Result<()> {
    let mut lba_ebr = lba_extendida;
    // Límite defensivo frente a cadenas corruptas o cíclicas.
    for _ in 0..64 {
        let ebr = leer_bloques(driver, SECTOR, lba_ebr, 1)?;
        if ebr.len() < 512 || ebr[510] != 0x55 || ebr[511] != 0xAA {
            break;
        }
        let e = &ebr[446..462];
        let tipo = e[4];
        let rel_inicio = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let sectores = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
        if tipo != 0 && sectores != 0 {
            salida.push(Particion {
                indice: salida.len(),
                inicio: (lba_ebr + rel_inicio) * SECTOR,
                tamano: sectores * SECTOR,
                tipo: nombre_tipo_mbr(tipo),
                sistema_archivos: SistemaArchivos::Desconocido,
                etiqueta: None,
            });
        }
        let sig = &ebr[462..478];
        let rel_siguiente = u32::from_le_bytes([sig[8], sig[9], sig[10], sig[11]]) as u64;
        if sig[4] == 0 || rel_siguiente == 0 {
            break;
        }
        lba_ebr = lba_extendida + rel_siguiente;
    }
    Ok(())
}

fn nombre_tipo_mbr(tipo: u8) -> String {
    let nombre = match tipo {
        0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => "FAT",
        0x07 => "NTFS / exFAT / HPFS",
        0x27 => "Windows RE (oculta)",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xEE => "GPT protective",
        0xEF => "EFI System",
        0xFD => "Linux RAID",
        _ => "Otro",
    };
    format!("{} (0x{:02X})", nombre, tipo)
}

// -----------------------------------------------------------------------------
// GPT
// -----------------------------------------------------------------------------

fn leer_gpt(driver: &dyn VmDriver, cabecera: &[u8]) -> io::Result<Vec<Particion>> {
    let lba_entradas = cabecera
        .get(72..80)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Error al leer lba_entradas en GPT",
            )
        })?;
    let num_entradas = cabecera
        .get(80..84)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|n| n as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Error al leer num_entradas en GPT",
            )
        })?;
    let tam_entrada = cabecera
        .get(84..88)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|n| n as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Error al leer tam_entrada en GPT",
            )
        })?;

    if tam_entrada < 128 || num_entradas == 0 || num_entradas > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Cabecera GPT con parámetros de tabla inválidos",
        ));
    }

    let bytes_tabla = num_entradas * tam_entrada;
    let sectores_tabla = bytes_tabla.div_ceil(SECTOR);
    let tabla = leer_bloques(driver, SECTOR, lba_entradas, sectores_tabla)?;

    let mut particiones = Vec::new();
    for i in 0..num_entradas as usize {
        let ini = i * tam_entrada as usize;
        if ini + 128 > tabla.len() {
            break;
        }
        let e = &tabla[ini..ini + 128];
        let guid_tipo = &e[0..16];
        if guid_tipo.iter().all(|b| *b == 0) {
            continue;
        }
        let primer_lba = match e
            .get(32..40)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        {
            Some(lba) => lba,
            None => continue,
        };
        let ultimo_lba = match e
            .get(40..48)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        {
            Some(lba) => lba,
            None => continue,
        };
        if ultimo_lba < primer_lba {
            continue;
        }
        let nombre_utf16: Vec<u16> = e[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
            .take_while(|u| *u != 0)
            .collect();
        let etiqueta = String::from_utf16_lossy(&nombre_utf16).trim().to_string();

        particiones.push(Particion {
            indice: particiones.len(),
            inicio: primer_lba * SECTOR,
            tamano: (ultimo_lba - primer_lba + 1) * SECTOR,
            tipo: nombre_tipo_gpt(guid_tipo).to_string(),
            sistema_archivos: SistemaArchivos::Desconocido,
            etiqueta: if etiqueta.is_empty() {
                None
            } else {
                Some(etiqueta)
            },
        });
    }
    Ok(particiones)
}

/// Formatea un GUID en su forma mixed-endian textual (como lo muestra Windows/gdisk).
fn guid_a_texto(g: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

fn nombre_tipo_gpt(guid: &[u8]) -> &'static str {
    match guid_a_texto(guid).as_str() {
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft Reserved",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows Recovery",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" => "Linux root (x86-64)",
        "21686148-6449-6E6F-744E-656564454649" => "BIOS boot",
        _ => "Otro",
    }
}

// -----------------------------------------------------------------------------
// Firmas de sistemas de archivos
// -----------------------------------------------------------------------------

/// Identifica sistemas de archivos cuya firma está en el primer sector.
pub fn identificar_fs(sector: &[u8]) -> SistemaArchivos {
    if sector.len() < 512 {
        return SistemaArchivos::Desconocido;
    }
    if &sector[3..11] == b"NTFS    " {
        return SistemaArchivos::Ntfs;
    }
    if &sector[0..4] == b"XFSB" {
        return SistemaArchivos::Xfs;
    }
    if &sector[0..8] == b"LABELONE" {
        return SistemaArchivos::Lvm2;
    }
    let es_fat = (&sector[54..62] == b"FAT12   "
        || &sector[54..62] == b"FAT16   "
        || &sector[82..90] == b"FAT32   ")
        && sector[510] == 0x55
        && sector[511] == 0xAA;
    if es_fat {
        return SistemaArchivos::Fat;
    }
    SistemaArchivos::Desconocido
}

/// Sistemas de archivos Linux cuyo superbloque está desplazado dentro de la partición.
fn identificar_fs_linux(driver: &dyn VmDriver, inicio: u64) -> io::Result<SistemaArchivos> {
    // ext2/3/4: superbloque en +1024, magic 0xEF53 en el offset 56 del superbloque.
    let sb = leer_bloques(driver, SECTOR, inicio / SECTOR + 2, 2)?;
    if sb.len() >= 0x64 && sb[56] == 0x53 && sb[57] == 0xEF {
        let feature_compat = sb
            .get(0x5C..0x60)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let feature_incompat = sb
            .get(0x60..0x64)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        const HAS_JOURNAL: u32 = 0x0004;
        const INCOMPAT_EXTENTS: u32 = 0x0040;
        const INCOMPAT_64BIT: u32 = 0x0080;
        const INCOMPAT_FLEX_BG: u32 = 0x0200;
        return Ok(
            if feature_incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG) != 0 {
                SistemaArchivos::Ext4
            } else if feature_compat & HAS_JOURNAL != 0 {
                SistemaArchivos::Ext3
            } else {
                SistemaArchivos::Ext2
            },
        );
    }

    // Btrfs: superbloque en +64 KiB, magic "_BHRfS_M" en el offset 0x40.
    let sb_btrfs = leer_bloques(driver, SECTOR, inicio / SECTOR + 128, 1)?;
    if sb_btrfs.len() >= 0x48 && &sb_btrfs[0x40..0x48] == b"_BHRfS_M" {
        return Ok(SistemaArchivos::Btrfs);
    }

    // Linux swap: firma "SWAPSPACE2" al final de la primera página (4 KiB).
    let pagina = leer_bloques(driver, SECTOR, inicio / SECTOR + 7, 1)?;
    if pagina.len() == 512 && &pagina[512 - 10..] == b"SWAPSPACE2" {
        return Ok(SistemaArchivos::LinuxSwap);
    }

    Ok(SistemaArchivos::Desconocido)
}

fn clasificar_so(particiones: &[Particion]) -> SistemaOperativo {
    let hay_ntfs = particiones
        .iter()
        .any(|p| p.sistema_archivos == SistemaArchivos::Ntfs);
    let hay_linux = particiones.iter().any(|p| {
        matches!(
            p.sistema_archivos,
            SistemaArchivos::Ext2
                | SistemaArchivos::Ext3
                | SistemaArchivos::Ext4
                | SistemaArchivos::Xfs
                | SistemaArchivos::Btrfs
                | SistemaArchivos::Lvm2
        )
    });

    match (hay_ntfs, hay_linux) {
        (true, false) => SistemaOperativo::Windows,
        (false, true) => SistemaOperativo::Linux,
        // Arranque dual o disco mixto: se prioriza Windows porque es el único
        // parser que hoy extrae información útil.
        (true, true) => SistemaOperativo::Windows,
        (false, false) => SistemaOperativo::Desconocido,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identificar_fs_ntfs() {
        let mut sector = [0u8; 512];
        sector[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(identificar_fs(&sector), SistemaArchivos::Ntfs);
    }

    #[test]
    fn test_identificar_fs_xfs() {
        let mut sector = [0u8; 512];
        sector[0..4].copy_from_slice(b"XFSB");
        assert_eq!(identificar_fs(&sector), SistemaArchivos::Xfs);
    }

    #[test]
    fn test_identificar_fs_fat() {
        let mut sector = [0u8; 512];
        sector[54..62].copy_from_slice(b"FAT16   ");
        sector[510] = 0x55;
        sector[511] = 0xAA;
        assert_eq!(identificar_fs(&sector), SistemaArchivos::Fat);
    }

    #[test]
    fn test_guid_a_texto() {
        let guid = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
            0x99, 0xC7,
        ];
        assert_eq!(guid_a_texto(&guid), "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    }

    #[test]
    fn test_clasificar_so() {
        let p_ntfs = Particion {
            indice: 0,
            inicio: 1048576,
            tamano: 10737418240,
            tipo: "NTFS".to_string(),
            sistema_archivos: SistemaArchivos::Ntfs,
            etiqueta: None,
        };
        assert_eq!(clasificar_so(&[p_ntfs]), SistemaOperativo::Windows);

        let p_ext4 = Particion {
            indice: 0,
            inicio: 1048576,
            tamano: 10737418240,
            tipo: "Linux".to_string(),
            sistema_archivos: SistemaArchivos::Ext4,
            etiqueta: None,
        };
        assert_eq!(clasificar_so(&[p_ext4]), SistemaOperativo::Linux);
    }
}
