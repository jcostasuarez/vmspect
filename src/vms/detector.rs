//! Identification of the partition table, file systems and guest operating system
//! from the leading sectors of the disk.
//!
//! Reads only what is strictly necessary: sector 0 (MBR / protective MBR), the GPT header and
//! its entry table, and the first sector of each partition to identify its file system signature.
//! That is enough to decide whether the guest is Windows (NTFS) or Linux (ext*/XFS/Btrfs)
//! without traversing the whole disk.

use crate::models::options::InspectionProgress;
use crate::models::traits::VmDriver;
use crate::models::{FileSystem, OperatingSystem, Partition, PartitionScheme};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const SECTOR: u64 = 512;

fn read_blocks(driver: &dyn VmDriver, bs: u64, index: u64, count: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; (count * bs) as usize];
    driver
        .read_range(index * bs, &mut buf)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(buf)
}

#[derive(Debug)]
pub(crate) struct DetectedDisk {
    pub scheme: PartitionScheme,
    pub partitions: Vec<Partition>,
    pub operating_system: OperatingSystem,
}

pub fn detect_with_progress(
    driver: &dyn VmDriver,
    cancel_token: Option<Arc<AtomicBool>>,
    progress: Option<Arc<InspectionProgress>>,
) -> io::Result<DetectedDisk> {
    if let Some(ref cancel) = cancel_token {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Analysis cancelled by the user",
            ));
        }
    }

    // Sector 0 + GPT header (sector 1) in a single call.
    let header = read_blocks(driver, SECTOR, 0, 2)?;
    if header.len() < SECTOR as usize {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "The virtual disk is too small to contain a boot sector",
        ));
    }
    let mbr = &header[..SECTOR as usize];

    let (scheme, mut partitions) = if header.len() >= 1024 && &header[512..520] == b"EFI PART" {
        (PartitionScheme::Gpt, read_gpt(driver, &header[512..1024])?)
    } else if mbr[510] == 0x55 && mbr[511] == 0xAA {
        let entries = read_mbr(driver, mbr)?;
        if entries.is_empty() && identify_fs(mbr) != FileSystem::Unknown {
            // Volume without a partition table (e.g. a data-only VHD).
            (PartitionScheme::None, vec![single_partition(driver, mbr)])
        } else {
            (PartitionScheme::Mbr, entries)
        }
    } else {
        (PartitionScheme::None, vec![single_partition(driver, mbr)])
    };

    if let Some(ref cancel) = cancel_token {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Analysis cancelled by the user",
            ));
        }
    }

    // Identify the actual file system of each partition by reading its first sector.
    for p in partitions.iter_mut() {
        if let Some(ref cancel) = cancel_token {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Analysis cancelled by the user",
                ));
            }
        }

        if p.file_system == FileSystem::Unknown && p.size > 0 {
            let first_sector = read_blocks(driver, SECTOR, p.start / SECTOR, 1)?;
            if first_sector.len() == SECTOR as usize {
                p.file_system = identify_fs(&first_sector);
                if p.file_system == FileSystem::Unknown {
                    // ext*/XFS/Btrfs do not have a signature in the partition's sector 0.
                    p.file_system = identify_linux_fs(driver, p.start)?;
                }
            }
        }

        if let Some(ref prog) = progress {
            prog.increment_completed_tasks();
        }
    }

    let operating_system = classify_os(&partitions);

    Ok(DetectedDisk {
        scheme,
        partitions,
        operating_system,
    })
}

fn single_partition(driver: &dyn VmDriver, sector0: &[u8]) -> Partition {
    Partition {
        index: 0,
        start: 0,
        size: driver.virtual_size(),
        kind: "Volume without a partition table".to_string(),
        file_system: identify_fs(sector0),
        label: None,
    }
}

// -----------------------------------------------------------------------------
// MBR
// -----------------------------------------------------------------------------

fn read_mbr(driver: &dyn VmDriver, mbr: &[u8]) -> io::Result<Vec<Partition>> {
    let mut partitions = Vec::new();
    for i in 0..4 {
        let e = &mbr[446 + i * 16..446 + (i + 1) * 16];
        let kind = e[4];
        let lba_start = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let sectors = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
        if kind == 0 || sectors == 0 {
            continue;
        }

        // Extended partition: walk the EBR chain.
        if matches!(kind, 0x05 | 0x0F | 0x85) {
            read_extended_chain(driver, lba_start, &mut partitions)?;
            continue;
        }

        partitions.push(Partition {
            index: partitions.len(),
            start: lba_start * SECTOR,
            size: sectors * SECTOR,
            kind: mbr_type_name(kind),
            file_system: FileSystem::Unknown,
            label: None,
        });
    }
    Ok(partitions)
}

fn read_extended_chain(
    driver: &dyn VmDriver,
    lba_extended: u64,
    output: &mut Vec<Partition>,
) -> io::Result<()> {
    let mut lba_ebr = lba_extended;
    // Defensive bound to guard against corrupt or cyclic chains.
    for _ in 0..64 {
        let ebr = read_blocks(driver, SECTOR, lba_ebr, 1)?;
        if ebr.len() < 512 || ebr[510] != 0x55 || ebr[511] != 0xAA {
            break;
        }
        let e = &ebr[446..462];
        let kind = e[4];
        let rel_start = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let sectors = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
        if kind != 0 && sectors != 0 {
            output.push(Partition {
                index: output.len(),
                start: (lba_ebr + rel_start) * SECTOR,
                size: sectors * SECTOR,
                kind: mbr_type_name(kind),
                file_system: FileSystem::Unknown,
                label: None,
            });
        }
        let next = &ebr[462..478];
        let rel_next = u32::from_le_bytes([next[8], next[9], next[10], next[11]]) as u64;
        if next[4] == 0 || rel_next == 0 {
            break;
        }
        lba_ebr = lba_extended + rel_next;
    }
    Ok(())
}

fn mbr_type_name(kind: u8) -> String {
    let name = match kind {
        0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => "FAT",
        0x07 => "NTFS / exFAT / HPFS",
        0x27 => "Windows RE (hidden)",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xEE => "GPT protective",
        0xEF => "EFI System",
        0xFD => "Linux RAID",
        _ => "Other",
    };
    format!("{} (0x{:02X})", name, kind)
}

// -----------------------------------------------------------------------------
// GPT
// -----------------------------------------------------------------------------

fn read_gpt(driver: &dyn VmDriver, header: &[u8]) -> io::Result<Vec<Partition>> {
    let lba_entries = header
        .get(72..80)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Error reading lba_entries in the GPT header",
            )
        })?;
    let num_entries = header
        .get(80..84)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|n| n as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Error reading num_entries in the GPT header",
            )
        })?;
    let entry_size = header
        .get(84..88)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .map(|n| n as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Error reading entry_size in the GPT header",
            )
        })?;

    if entry_size < 128 || num_entries == 0 || num_entries > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GPT header has invalid table parameters",
        ));
    }

    let table_bytes = num_entries * entry_size;
    let table_sectors = table_bytes.div_ceil(SECTOR);
    let table = read_blocks(driver, SECTOR, lba_entries, table_sectors)?;

    let mut partitions = Vec::new();
    for i in 0..num_entries as usize {
        let start = i * entry_size as usize;
        if start + 128 > table.len() {
            break;
        }
        let e = &table[start..start + 128];
        let kind_guid = &e[0..16];
        if kind_guid.iter().all(|b| *b == 0) {
            continue;
        }
        let first_lba = match e
            .get(32..40)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        {
            Some(lba) => lba,
            None => continue,
        };
        let last_lba = match e
            .get(40..48)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        {
            Some(lba) => lba,
            None => continue,
        };
        if last_lba < first_lba {
            continue;
        }
        let name_utf16: Vec<u16> = e[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
            .take_while(|u| *u != 0)
            .collect();
        let label = String::from_utf16_lossy(&name_utf16).trim().to_string();

        partitions.push(Partition {
            index: partitions.len(),
            start: first_lba * SECTOR,
            size: (last_lba - first_lba + 1) * SECTOR,
            kind: gpt_type_name(kind_guid).to_string(),
            file_system: FileSystem::Unknown,
            label: if label.is_empty() { None } else { Some(label) },
        });
    }
    Ok(partitions)
}

/// Formats a GUID into its mixed-endian textual form (as displayed by Windows / gdisk).
fn guid_to_text(g: &[u8]) -> String {
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

fn gpt_type_name(guid: &[u8]) -> &'static str {
    match guid_to_text(guid).as_str() {
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data",
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => "Microsoft Reserved",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows Recovery",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" => "Linux root (x86-64)",
        "21686148-6449-6E6F-744E-656564454649" => "BIOS boot",
        _ => "Other",
    }
}

// -----------------------------------------------------------------------------
// File system signatures
// -----------------------------------------------------------------------------

/// Identifies file systems whose signature lives in the partition's first sector.
pub fn identify_fs(sector: &[u8]) -> FileSystem {
    if sector.len() < 512 {
        return FileSystem::Unknown;
    }
    if &sector[3..11] == b"NTFS    " {
        return FileSystem::Ntfs;
    }
    if &sector[0..4] == b"XFSB" {
        return FileSystem::Xfs;
    }
    if &sector[0..8] == b"LABELONE" {
        return FileSystem::Lvm2;
    }
    let is_fat = (&sector[54..62] == b"FAT12   "
        || &sector[54..62] == b"FAT16   "
        || &sector[82..90] == b"FAT32   ")
        && sector[510] == 0x55
        && sector[511] == 0xAA;
    if is_fat {
        return FileSystem::Fat;
    }
    FileSystem::Unknown
}

/// Linux file systems whose superblock is offset inside the partition.
fn identify_linux_fs(driver: &dyn VmDriver, start: u64) -> io::Result<FileSystem> {
    // ext2/3/4: superblock at +1024, magic 0xEF53 at superblock offset 56.
    let sb = read_blocks(driver, SECTOR, start / SECTOR + 2, 2)?;
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
                FileSystem::Ext4
            } else if feature_compat & HAS_JOURNAL != 0 {
                FileSystem::Ext3
            } else {
                FileSystem::Ext2
            },
        );
    }

    // Btrfs: superblock at +64 KiB, magic "_BHRfS_M" at offset 0x40.
    let sb_btrfs = read_blocks(driver, SECTOR, start / SECTOR + 128, 1)?;
    if sb_btrfs.len() >= 0x48 && &sb_btrfs[0x40..0x48] == b"_BHRfS_M" {
        return Ok(FileSystem::Btrfs);
    }

    // Linux swap: signature "SWAPSPACE2" at the end of the first page (4 KiB).
    let page = read_blocks(driver, SECTOR, start / SECTOR + 7, 1)?;
    if page.len() == 512 && &page[512 - 10..] == b"SWAPSPACE2" {
        return Ok(FileSystem::LinuxSwap);
    }

    Ok(FileSystem::Unknown)
}

fn classify_os(partitions: &[Partition]) -> OperatingSystem {
    let has_ntfs = partitions.iter().any(|p| p.file_system == FileSystem::Ntfs);
    let has_linux = partitions.iter().any(|p| {
        matches!(
            p.file_system,
            FileSystem::Ext2
                | FileSystem::Ext3
                | FileSystem::Ext4
                | FileSystem::Xfs
                | FileSystem::Btrfs
                | FileSystem::Lvm2
        )
    });

    match (has_ntfs, has_linux) {
        (true, false) => OperatingSystem::Windows,
        (false, true) => OperatingSystem::Linux,
        // Dual-boot or mixed disk: Windows is preferred since it is the only parser that
        // currently extracts useful information.
        (true, true) => OperatingSystem::Windows,
        (false, false) => OperatingSystem::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_fs_ntfs() {
        let mut sector = [0u8; 512];
        sector[3..11].copy_from_slice(b"NTFS    ");
        assert_eq!(identify_fs(&sector), FileSystem::Ntfs);
    }

    #[test]
    fn test_identify_fs_xfs() {
        let mut sector = [0u8; 512];
        sector[0..4].copy_from_slice(b"XFSB");
        assert_eq!(identify_fs(&sector), FileSystem::Xfs);
    }

    #[test]
    fn test_identify_fs_fat() {
        let mut sector = [0u8; 512];
        sector[54..62].copy_from_slice(b"FAT16   ");
        sector[510] = 0x55;
        sector[511] = 0xAA;
        assert_eq!(identify_fs(&sector), FileSystem::Fat);
    }

    #[test]
    fn test_guid_to_text() {
        let guid = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
            0x99, 0xC7,
        ];
        assert_eq!(guid_to_text(&guid), "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    }

    #[test]
    fn test_classify_os() {
        let p_ntfs = Partition {
            index: 0,
            start: 1048576,
            size: 10737418240,
            kind: "NTFS".to_string(),
            file_system: FileSystem::Ntfs,
            label: None,
        };
        assert_eq!(classify_os(&[p_ntfs]), OperatingSystem::Windows);

        let p_ext4 = Partition {
            index: 0,
            start: 1048576,
            size: 10737418240,
            kind: "Linux".to_string(),
            file_system: FileSystem::Ext4,
            label: None,
        };
        assert_eq!(classify_os(&[p_ext4]), OperatingSystem::Linux);
    }
}
