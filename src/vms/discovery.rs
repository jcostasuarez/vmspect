//! Discovery, integrity verification and inspection capability analysis of VM disk images.
//!
//! Provides high-level helpers for:
//! - Smart detection and filtering of disk images (.vmdk, .qcow2, .vdi, .vhd, .vhdx, .raw, .img).
//! - Ignoring secondary extents and delta files (`*-flat.vmdk`, `*-s001.vmdk`, `*-delta.vmdk`, ...).
//! - Quick header (Magic Number) signature verification without reading the entire disk.
//! - Pre-flight analysis to decide whether an image can be processed natively or requires `qemu-nbd`.

use crate::error::{Result, VmSpectError};
use crate::vms::vmdk;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// File extensions recognized as VM disk images.
pub const SUPPORTED_EXTENSIONS: &[&str] = &["vmdk", "qcow2", "vdi", "vhd", "vhdx", "raw", "img"];

/// Magic bytes for the QCOW2 format (`QFI\xfb`).
pub const MAGIC_QCOW2: &[u8; 4] = b"QFI\xfb";

/// Magic bytes for the binary sparse VMDK format (`KDMV`).
pub const MAGIC_VMDK_KDMV: &[u8; 4] = b"KDMV";

/// Magic bytes for the VHDX format (`vhdxfile`).
pub const MAGIC_VHDX: &[u8; 8] = b"vhdxfile";

/// Magic bytes for the VHD / VirtualPC format (`conectix`).
pub const MAGIC_VHD_CONECTIX: &[u8; 8] = b"conectix";

/// VirtualBox VDI image signature at offset 0x40 (`0xBEDA107F` little-endian).
pub const MAGIC_VDI_SIGNATURE: &[u8; 4] = &[0x7F, 0x10, 0xDA, 0xBE];

/// Text prefix for legacy Sun VirtualBox VDI headers.
pub const MAGIC_VDI_PREFIX_SUN: &[u8] = b"<<< Sun VirtualBox Disk Image >>>";

/// Text prefix for Oracle VM VirtualBox VDI headers.
pub const MAGIC_VDI_PREFIX_ORACLE: &[u8] = b"<<< Oracle VM VirtualBox Disk Image >>>";

/// Checks whether the supplied path corresponds to a secondary extent, delta file or fragment
/// that is not the descriptor or primary disk file of the virtual machine.
///
/// Filters out patterns such as:
/// - `*-flat.vmdk`, `*_flat.vmdk`
/// - `*-delta.vmdk`, `*_delta.vmdk`
/// - `*-sesparse.vmdk`, `*_sesparse.vmdk`
/// - `*-s[0-9]*.vmdk`, `*_s[0-9]*.vmdk` (split VMDK extents)
/// - `*-sys.vhd`, `*_sys.vhd`, `*-delta.vhd`, `*_delta.vhd`
/// - `*-sys.vhdx`, `*_sys.vhdx`, `*-delta.vhdx`, `*_delta.vhdx`
///
/// # Parameters
///
/// - `path`: Path to the file to test.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use vmspect::vms::discovery::is_secondary_extent;
///
/// assert!(is_secondary_extent(Path::new("disk-flat.vmdk")));
/// assert!(is_secondary_extent(Path::new("disk-s001.vmdk")));
/// assert!(is_secondary_extent(Path::new("snapshot-delta.vmdk")));
/// assert!(!is_secondary_extent(Path::new("disk.vmdk")));
/// ```
pub fn is_secondary_extent(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_ascii_lowercase(),
        None => return false,
    };

    if name.ends_with(".vmdk") {
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
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
    } else if name.ends_with(".vhd") || name.ends_with(".vhdx") {
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
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

/// Determines whether a path corresponds to a supported VM disk image.
///
/// Performs a fast, non-invasive validation:
/// 1. Verifies the extension is supported (`.vmdk`, `.qcow2`, `.vdi`, `.vhd`, `.vhdx`, `.raw`, `.img`).
/// 2. Applies filters to ignore secondary extents or deltas (e.g. `*-s001.vmdk`, `*-flat.vmdk`).
/// 3. If the file exists on disk, validates that it is not a directory and that its size is > 0.
///
/// # Parameters
///
/// - `path`: Path to the candidate file or directory.
///
/// # Returns
///
/// `true` if the path represents a candidate VM image, `false` otherwise.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use vmspect::is_vm_image;
///
/// assert!(is_vm_image(Path::new("ubuntu.qcow2")));
/// assert!(is_vm_image(Path::new("disk.vmdk")));
/// assert!(!is_vm_image(Path::new("disk-flat.vmdk")));
/// assert!(!is_vm_image(Path::new("notes.txt")));
/// ```
pub fn is_vm_image(path: &Path) -> bool {
    if path.is_dir() {
        return false;
    }

    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return false,
    };

    if !SUPPORTED_EXTENSIONS.contains(&ext.as_str()) {
        return false;
    }

    if is_secondary_extent(path) {
        return false;
    }

    if let Ok(meta) = fs::metadata(path) {
        if !meta.is_file() || meta.len() == 0 {
            return false;
        }
    }

    true
}

/// Lists every VM disk image found in the supplied directory.
///
/// # Parameters
///
/// - `directory`: Directory to scan.
/// - `recursive`: If `true`, descends into every subdirectory.
///
/// # Errors
///
/// Returns [`VmSpectError::ImageNotFound`] when the directory does not exist, or
/// [`VmSpectError::Io`] if reading the directory entries fails.
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use vmspect::list_vms;
///
/// let vms = list_vms(Path::new("/var/lib/libvirt/images"), false)?;
/// println!("Found {} images", vms.len());
/// # Ok::<(), vmspect::VmSpectError>(())
/// ```
pub fn list_vms(directory: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    if !directory.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Directory not found: {}",
            directory.display()
        )));
    }
    if !directory.is_dir() {
        return Err(VmSpectError::Other(format!(
            "The supplied path is not a directory: {}",
            directory.display()
        )));
    }

    let mut images = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(directory.to_path_buf());

    while let Some(current_dir) = queue.pop_front() {
        let entries = match fs::read_dir(&current_dir) {
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
                if recursive {
                    queue.push_back(path);
                }
            } else if file_type.is_file() && is_vm_image(&path) {
                images.push(path);
            }
        }
    }

    images.sort();
    Ok(images)
}

/// Counts the number of VM disk images present in the supplied directory.
///
/// # Parameters
///
/// - `directory`: Directory to scan.
/// - `recursive`: Whether to include subdirectories.
///
/// # Errors
///
/// Returns an error when the directory does not exist or cannot be read.
pub fn count_vms(directory: &Path, recursive: bool) -> Result<usize> {
    list_vms(directory, recursive).map(|list| list.len())
}

/// Reports whether at least one VM disk image is present in the supplied directory.
///
/// Performs an optimized search with early-exit short-circuiting: returns `Ok(true)` as soon as
/// the first matching file is found, without scanning the rest of the directory.
///
/// # Parameters
///
/// - `directory`: Directory to scan.
/// - `recursive`: Whether to include subdirectories.
///
/// # Errors
///
/// Returns an error when the directory does not exist or cannot be read.
pub fn has_vms(directory: &Path, recursive: bool) -> Result<bool> {
    if !directory.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Directory not found: {}",
            directory.display()
        )));
    }
    if !directory.is_dir() {
        return Err(VmSpectError::Other(format!(
            "The supplied path is not a directory: {}",
            directory.display()
        )));
    }

    let mut queue = VecDeque::new();
    queue.push_back(directory.to_path_buf());

    while let Some(current_dir) = queue.pop_front() {
        let entries = match fs::read_dir(&current_dir) {
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
                if recursive {
                    queue.push_back(path);
                }
            } else if file_type.is_file() && is_vm_image(&path) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Verifies the integrity and format of a disk image by quickly inspecting its magic bytes.
///
/// Only the leading header block (up to 4 KiB) or the footer (for fixed VHDs) is read, keeping
/// I/O overhead minimal.
///
/// Validated signatures per format:
/// - **QCOW2:** `QFI\xfb` (`[0x51, 0x46, 0x49, 0xFB]`)
/// - **VMDK:** `KDMV` (`[0x4B, 0x44, 0x4D, 0x56]`) or text descriptor `# Disk DescriptorFile` / `# VMDK Header`
/// - **VDI:** `<<< Sun/Oracle VirtualBox Disk Image >>>` or signature `[0x7F, 0x10, 0xDA, 0xBE]` at offset `0x40`
/// - **VHDX:** `vhdxfile` (`[0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65]`)
/// - **VHD:** `conectix` (`[0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78]`) at the header or 512-byte footer
/// - **RAW / IMG:** Valid non-empty file with a minimal disk structure (MBR/GPT or coherent size).
///
/// # Parameters
///
/// - `path`: Path of the disk image to verify.
///
/// # Returns
///
/// - `Ok(true)` if the image has a valid signature for its format.
/// - `Ok(false)` if the header does not match the expected signature or is corrupt.
/// - `Err(VmSpectError)` when the image is missing or I/O fails.
pub fn verify_image_integrity(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Image not found: {}",
            path.display()
        )));
    }

    let mut file = File::open(path).map_err(VmSpectError::Io)?;
    let size = file.metadata().map_err(VmSpectError::Io)?.len();

    if size == 0 {
        return Ok(false);
    }

    let to_read = (size as usize).min(4096);
    let mut header = vec![0u8; to_read];
    file.read_exact(&mut header).map_err(VmSpectError::Io)?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "qcow2" => Ok(header.len() >= 4 && header.starts_with(MAGIC_QCOW2)),
        "vmdk" => {
            if header.len() >= 4 && header.starts_with(MAGIC_VMDK_KDMV) {
                return Ok(true);
            }
            let text = String::from_utf8_lossy(&header);
            let trimmed_text = text.trim_start();
            if trimmed_text.starts_with("# Disk DescriptorFile")
                || trimmed_text.starts_with("# VMDK Header")
                || trimmed_text.starts_with("# VMDK")
                || trimmed_text.contains("# Disk DescriptorFile")
            {
                return Ok(true);
            }
            Ok(false)
        }
        "vdi" => {
            if header.starts_with(b"<<< ") {
                if header.starts_with(MAGIC_VDI_PREFIX_SUN)
                    || header.starts_with(MAGIC_VDI_PREFIX_ORACLE)
                {
                    return Ok(true);
                }
                if header.len() >= 0x44 && header[0x40..0x44] == *MAGIC_VDI_SIGNATURE {
                    return Ok(true);
                }
            }
            if header.len() >= 0x44 && header[0x40..0x44] == *MAGIC_VDI_SIGNATURE {
                return Ok(true);
            }
            Ok(false)
        }
        "vhdx" => Ok(header.len() >= 8 && header.starts_with(MAGIC_VHDX)),
        "vhd" => {
            if header.len() >= 8
                && (header.starts_with(MAGIC_VHD_CONECTIX) || header.starts_with(b"cxsparse"))
            {
                return Ok(true);
            }
            if size >= 512 {
                let mut footer = [0u8; 512];
                file.seek(SeekFrom::Start(size - 512))
                    .map_err(VmSpectError::Io)?;
                file.read_exact(&mut footer).map_err(VmSpectError::Io)?;
                if footer.starts_with(MAGIC_VHD_CONECTIX) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "raw" | "img" => {
            if size < 512 {
                return Ok(false);
            }
            // MBR signature at 510..512 (0x55, 0xAA)
            if header.len() >= 512 && header[510] == 0x55 && header[511] == 0xAA {
                return Ok(true);
            }
            // GPT signature at 512..520 ("EFI PART")
            if header.len() >= 520 && &header[512..520] == b"EFI PART" {
                return Ok(true);
            }
            Ok(true)
        }
        _ => {
            if header.starts_with(MAGIC_QCOW2)
                || header.starts_with(MAGIC_VMDK_KDMV)
                || header.starts_with(MAGIC_VHDX)
                || header.starts_with(MAGIC_VHD_CONECTIX)
                || (header.len() >= 0x44 && header[0x40..0x44] == *MAGIC_VDI_SIGNATURE)
            {
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

/// Performs a pre-flight analysis to determine whether the disk image must be delegated to
/// `qemu-nbd` or can be processed directly by the native Rust engine in `vmspect`.
///
/// # Decision criteria:
/// - **Native (`Ok(false)`):** RAW, IMG or standard monolithic VMDK images
///   (`monolithicSparse` or `monolithicFlat`).
/// - **Requires NBD (`Ok(true)`):** Complex formats such as QCOW2, VDI, VHD, VHDX, nested
///   snapshots with a parent disk, multi-extent / split images (`twoGbMaxExtentSparse`),
///   or grain-compressed images (`streamOptimized`).
///
/// # Parameters
///
/// - `path`: Path of the disk image to evaluate.
///
/// # Errors
///
/// Returns an error when the file does not exist or the header cannot be read.
pub fn requires_nbd(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Err(VmSpectError::ImageNotFound(format!(
            "Image not found: {}",
            path.display()
        )));
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "raw" | "img" => Ok(false),
        "qcow2" | "vdi" | "vhd" | "vhdx" => Ok(true),
        "vmdk" => {
            let mut file = File::open(path).map_err(VmSpectError::Io)?;
            let mut header = [0u8; 512];
            let n = file.read(&mut header).map_err(VmSpectError::Io)?;
            let header = &header[..n];

            if vmdk::is_sparse_header(header) {
                let cab = match vmdk::read_sparse_header(header) {
                    Ok(c) => c,
                    Err(_) => return Ok(true),
                };

                if cab.unsupported_reason().is_some() {
                    return Ok(true);
                }

                if cab.descriptor_offset != 0 && cab.descriptor_sectors != 0 {
                    let bytes_desc = (cab.descriptor_sectors * vmdk::SECTOR) as usize;
                    let mut text = vec![0u8; bytes_desc.min(64 * 1024)];
                    if file
                        .seek(SeekFrom::Start(cab.descriptor_offset * vmdk::SECTOR))
                        .is_ok()
                        && file.read_exact(&mut text).is_ok()
                    {
                        let d = vmdk::parse_descriptor(&String::from_utf8_lossy(&text));
                        if d.has_parent() || d.extents.len() > 1 {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            } else if vmdk::is_text_descriptor(header) {
                let text = fs::read_to_string(path).map_err(VmSpectError::Io)?;
                let d = vmdk::parse_descriptor(&text);

                if d.has_parent() || d.extents.is_empty() {
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
                    let kind = d.extents[0].kind.to_ascii_uppercase();
                    if kind == "FLAT" || kind == "ZERO" {
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

/// Determines whether the disk image requires delegation to QEMU / NBD tools.
///
/// Direct equivalent of [`requires_nbd`].
pub fn requires_qemu(path: &Path) -> Result<bool> {
    requires_nbd(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_is_secondary_extent() {
        assert!(is_secondary_extent(Path::new("ubuntu-flat.vmdk")));
        assert!(is_secondary_extent(Path::new("ubuntu_flat.vmdk")));
        assert!(is_secondary_extent(Path::new("ubuntu-delta.vmdk")));
        assert!(is_secondary_extent(Path::new("ubuntu-sesparse.vmdk")));
        assert!(is_secondary_extent(Path::new("windows-s001.vmdk")));
        assert!(is_secondary_extent(Path::new("windows-s02.vmdk")));
        assert!(is_secondary_extent(Path::new("windows_s1.vmdk")));
        assert!(is_secondary_extent(Path::new("disk-sys.vhd")));
        assert!(is_secondary_extent(Path::new("disk_sys.vhd")));
        assert!(is_secondary_extent(Path::new("disk-delta.vhd")));
        assert!(is_secondary_extent(Path::new("disk-delta.vhdx")));

        // Valid (not secondary)
        assert!(!is_secondary_extent(Path::new("ubuntu.vmdk")));
        assert!(!is_secondary_extent(Path::new("windows-server.vmdk")));
        assert!(!is_secondary_extent(Path::new("disk.qcow2")));
        assert!(!is_secondary_extent(Path::new("disk.vdi")));
        assert!(!is_secondary_extent(Path::new("disk.vhd")));
        assert!(!is_secondary_extent(Path::new("disk.vhdx")));
        assert!(!is_secondary_extent(Path::new("disk.raw")));
    }

    #[test]
    fn test_is_vm_image() {
        assert!(is_vm_image(Path::new("vm.vmdk")));
        assert!(is_vm_image(Path::new("vm.qcow2")));
        assert!(is_vm_image(Path::new("vm.vdi")));
        assert!(is_vm_image(Path::new("vm.vhd")));
        assert!(is_vm_image(Path::new("vm.vhdx")));
        assert!(is_vm_image(Path::new("vm.raw")));
        assert!(is_vm_image(Path::new("vm.img")));

        assert!(!is_vm_image(Path::new("vm-flat.vmdk")));
        assert!(!is_vm_image(Path::new("vm-s001.vmdk")));
        assert!(!is_vm_image(Path::new("vm.iso")));
        assert!(!is_vm_image(Path::new("vm.txt")));
    }

    #[test]
    fn test_verify_integrity_qcow2() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.qcow2");
        let mut f = File::create(&path).unwrap();
        f.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();

        assert!(verify_image_integrity(&path).unwrap());

        let invalid_path = dir.path().join("invalid.qcow2");
        let mut f2 = File::create(&invalid_path).unwrap();
        f2.write_all(b"NOT_QCOW2_HEADER").unwrap();

        assert!(!verify_image_integrity(&invalid_path).unwrap());
    }

    #[test]
    fn test_verify_integrity_vmdk() {
        let dir = tempdir().unwrap();

        // 1. KDMV sparse
        let sparse_path = dir.path().join("sparse.vmdk");
        let mut f1 = File::create(&sparse_path).unwrap();
        f1.write_all(b"KDMV\x01\x00\x00\x00").unwrap();
        assert!(verify_image_integrity(&sparse_path).unwrap());

        // 2. Text descriptor
        let desc_path = dir.path().join("desc.vmdk");
        let mut f2 = File::create(&desc_path).unwrap();
        f2.write_all(b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\n")
            .unwrap();
        assert!(verify_image_integrity(&desc_path).unwrap());
    }

    #[test]
    fn test_verify_integrity_vdi_vhdx_vhd() {
        let dir = tempdir().unwrap();

        // VHDX
        let vhdx_path = dir.path().join("test.vhdx");
        let mut f = File::create(&vhdx_path).unwrap();
        f.write_all(b"vhdxfile\x00\x00\x00\x00").unwrap();
        assert!(verify_image_integrity(&vhdx_path).unwrap());

        // Dynamic VHD
        let vhd_path = dir.path().join("test.vhd");
        let mut f2 = File::create(&vhd_path).unwrap();
        f2.write_all(b"conectix\x00\x00\x00\x00").unwrap();
        assert!(verify_image_integrity(&vhd_path).unwrap());

        // VDI
        let vdi_path = dir.path().join("test.vdi");
        let mut f3 = File::create(&vdi_path).unwrap();
        let mut header_vdi = vec![0u8; 100];
        header_vdi[..MAGIC_VDI_PREFIX_ORACLE.len()].copy_from_slice(MAGIC_VDI_PREFIX_ORACLE);
        header_vdi[0x40..0x44].copy_from_slice(MAGIC_VDI_SIGNATURE);
        f3.write_all(&header_vdi).unwrap();
        assert!(verify_image_integrity(&vdi_path).unwrap());
    }

    #[test]
    fn test_list_count_has_vms() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();

        let vm1 = dir.path().join("ubuntu.qcow2");
        let vm2 = dir.path().join("disk.vmdk");
        let extent = dir.path().join("disk-flat.vmdk");
        let vm3 = sub.join("windows.vhdx");
        let dummy = dir.path().join("notes.txt");

        File::create(&vm1).unwrap().write_all(b"data").unwrap();
        File::create(&vm2).unwrap().write_all(b"data").unwrap();
        File::create(&extent).unwrap().write_all(b"data").unwrap();
        File::create(&vm3).unwrap().write_all(b"data").unwrap();
        File::create(&dummy).unwrap().write_all(b"data").unwrap();

        // Non-recursive
        let vms_non_rec = list_vms(dir.path(), false).unwrap();
        assert_eq!(vms_non_rec.len(), 2);
        assert!(vms_non_rec.contains(&vm1));
        assert!(vms_non_rec.contains(&vm2));
        assert!(!vms_non_rec.contains(&extent));
        assert_eq!(count_vms(dir.path(), false).unwrap(), 2);
        assert!(has_vms(dir.path(), false).unwrap());

        // Recursive
        let vms_rec = list_vms(dir.path(), true).unwrap();
        assert_eq!(vms_rec.len(), 3);
        assert!(vms_rec.contains(&vm3));
        assert_eq!(count_vms(dir.path(), true).unwrap(), 3);
        assert!(has_vms(dir.path(), true).unwrap());

        // Empty directory
        let empty_dir = tempdir().unwrap();
        assert_eq!(count_vms(empty_dir.path(), true).unwrap(), 0);
        assert!(!has_vms(empty_dir.path(), true).unwrap());
    }

    #[test]
    fn test_requires_nbd_formats() {
        let dir = tempdir().unwrap();

        let raw = dir.path().join("disk.raw");
        File::create(&raw).unwrap().write_all(b"raw data").unwrap();
        assert!(!requires_nbd(&raw).unwrap());

        let qcow2 = dir.path().join("disk.qcow2");
        File::create(&qcow2).unwrap().write_all(b"qcow2").unwrap();
        assert!(requires_nbd(&qcow2).unwrap());
        assert!(requires_qemu(&qcow2).unwrap());

        let vhdx = dir.path().join("disk.vhdx");
        File::create(&vhdx).unwrap().write_all(b"vhdx").unwrap();
        assert!(requires_nbd(&vhdx).unwrap());

        // Monolithic flat VMDK descriptor
        let vmdk_flat_desc = dir.path().join("monolithic_flat.vmdk");
        let mut f_desc = File::create(&vmdk_flat_desc).unwrap();
        f_desc
            .write_all(
                b"# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"data.flat\" 0\n",
            )
            .unwrap();
        assert!(!requires_nbd(&vmdk_flat_desc).unwrap());

        // VMDK descriptor with a parent (snapshot) -> requires NBD
        let vmdk_snap = dir.path().join("snapshot.vmdk");
        let mut f_snap = File::create(&vmdk_snap).unwrap();
        f_snap
            .write_all(
                b"# Disk DescriptorFile\nparentFileNameHint=\"base.vmdk\"\nRW 2048 FLAT \"snap.flat\" 0\n",
            )
            .unwrap();
        assert!(requires_nbd(&vmdk_snap).unwrap());
    }
}
