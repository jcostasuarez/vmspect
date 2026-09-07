//! Native reader for the VMDK format (no external processes or `qemu-nbd`).
//!
//! Covers the typical cases of a "clean" VM exported by VMware:
//! - `monolithicSparse`: a single file with a `KDMV` header, embedded descriptor
//!   and 64 KiB grains addressed via directory and grain tables.
//! - `monolithicFlat` / `twoGbMaxExtent*` / `vmfs`: a text descriptor that
//!   points to one or more `FLAT` (raw with offset) or `SPARSE` extents.
//!
//! Anything else (compressed grains / `streamOptimized`, parent disk or
//! snapshot, unknown extent types) is delegated to `qemu-nbd`.
//!
//! Reference: "Virtual Disk Format 5.0", VMware Technical Note.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const SECTOR: u64 = 512;
const MAGIC_KDMV: &[u8; 4] = b"KDMV";
const FLAG_GRAINS_COMPRIMIDOS: u32 = 1 << 16;
const FLAG_MARCADORES: u32 = 1 << 17;

/// Result of attempting to open something natively.
pub enum OpenResult<T> {
    Native(T),
    /// The format is valid but requires delegation to `qemu-nbd`; the reason is included.
    NeedsNbd(String),
}

// -----------------------------------------------------------------------------
// Sparse extent header
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SparseHeader {
    pub _version: u32,
    pub flags: u32,
    pub capacity_sectors: u64,
    pub grain_sectors: u64,
    pub descriptor_offset: u64,
    pub descriptor_sectors: u64,
    pub gtes_per_gt: u32,
    pub rgd_offset: u64,
    pub gd_offset: u64,
    pub compression: u16,
}

pub fn is_sparse_header(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[0..4] == MAGIC_KDMV
}

pub fn read_sparse_header(buf: &[u8]) -> io::Result<SparseHeader> {
    if buf.len() < 80 || !is_sparse_header(buf) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid VMDK sparse header",
        ));
    }
    let u32_at = |o: usize| -> io::Result<u32> {
        buf.get(o..o + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too small for u32"))
    };
    let u64_at = |o: usize| -> io::Result<u64> {
        buf.get(o..o + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Buffer too small for u64"))
    };
    Ok(SparseHeader {
        _version: u32_at(4)?,
        flags: u32_at(8)?,
        capacity_sectors: u64_at(12)?,
        grain_sectors: u64_at(20)?,
        descriptor_offset: u64_at(28)?,
        descriptor_sectors: u64_at(36)?,
        gtes_per_gt: u32_at(44)?,
        rgd_offset: u64_at(48)?,
        gd_offset: u64_at(56)?,
        compression: u16::from_le_bytes([buf[77], buf[78]]),
    })
}

impl SparseHeader {
    /// Returns the reason why this extent cannot be read natively, if any.
    pub fn unsupported_reason(&self) -> Option<String> {
        if self.compression != 0 || self.flags & (FLAG_GRAINS_COMPRIMIDOS | FLAG_MARCADORES) != 0 {
            return Some("VMDK with compressed grains (streamOptimized)".to_string());
        }
        if self.gd_offset == u64::MAX || self.gd_offset == 0 {
            return Some("VMDK without a grain directory in its header".to_string());
        }
        if self.grain_sectors == 0 || !self.grain_sectors.is_power_of_two() {
            return Some(format!(
                "VMDK with unsupported grain size ({} sectors)",
                self.grain_sectors
            ));
        }
        if self.gtes_per_gt == 0 || self.capacity_sectors == 0 {
            return Some("VMDK with inconsistent sparse header".to_string());
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Text descriptor
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
    pub _access: String,
    pub sectors: u64,
    /// FLAT, SPARSE, ZERO, VMFS, VMFSSPARSE, ...
    pub kind: String,
    pub file: Option<String>,
    pub offset_sectors: u64,
}

impl Descriptor {
    pub fn has_parent(&self) -> bool {
        self.parent_file_name_hint
            .as_ref()
            .map(|h| !h.trim().is_empty())
            .unwrap_or(false)
            || matches!(self.parent_cid, Some(cid) if cid != 0xFFFF_FFFF)
    }
}

pub fn is_text_descriptor(buf: &[u8]) -> bool {
    let start = &buf[..buf.len().min(64)];
    let text = String::from_utf8_lossy(start);
    text.trim_start().starts_with("# Disk DescriptorFile")
}

pub fn parse_descriptor(text: &str) -> Descriptor {
    let mut d = Descriptor::default();
    for line in text.lines() {
        let line = line.trim_matches(|c| c == '\0' || c == ' ' || c == '\t' || c == '\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens = tokenize(line);
        if tokens.is_empty() {
            continue;
        }

        match tokens[0].to_ascii_uppercase().as_str() {
            "RW" | "RDONLY" | "NOACCESS" if tokens.len() >= 3 => {
                let sectors = tokens[1].parse().unwrap_or(0);
                let kind = tokens[2].to_ascii_uppercase();
                let file = tokens.get(3).cloned();
                let offset_sectors = tokens.get(4).and_then(|t| t.parse().ok()).unwrap_or(0);
                d.extents.push(ExtentDescriptor {
                    _access: tokens[0].to_ascii_uppercase(),
                    sectors,
                    kind,
                    file,
                    offset_sectors,
                });
            }
            _ => {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim().trim_matches('"');
                    match key.to_ascii_lowercase().as_str() {
                        "createtype" => d.create_type = value.to_string(),
                        "parentcid" => d.parent_cid = u32::from_str_radix(value, 16).ok(),
                        "parentfilenamehint" => {
                            d.parent_file_name_hint = Some(value.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    d
}

/// Splits on whitespace while respecting double-quoted strings.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

// -----------------------------------------------------------------------------
// Sparse extent: grain-based reading
// -----------------------------------------------------------------------------
#[derive(Debug)]
pub struct SparseExtent {
    file: File,
    grain_bytes: u64,
    gtes_per_gt: u32,
    capacity_bytes: u64,
    /// Complete grain directory (small: 4 bytes per each 32 MiB of disk).
    directory: Vec<u32>,
    /// Grain tables loaded on demand, indexed by their position in the directory.
    tables: HashMap<u32, Vec<u32>>,
}

impl SparseExtent {
    pub fn open(path: &Path) -> io::Result<OpenResult<Self>> {
        let mut file = crate::vms::stream::open_read_file(path)?;
        let mut buf = [0u8; 512];
        file.read_exact(&mut buf)?;
        let cab = read_sparse_header(&buf)?;
        Self::from_header(file, path, cab)
    }

    pub fn from_header(
        mut file: File,
        _path: &Path,
        cab: SparseHeader,
    ) -> io::Result<OpenResult<Self>> {
        if let Some(reason) = cab.unsupported_reason() {
            return Ok(OpenResult::NeedsNbd(reason));
        }

        let grain_bytes = cab.grain_sectors * SECTOR;
        let bytes_per_gt = grain_bytes * cab.gtes_per_gt as u64;
        let capacity_bytes = cab.capacity_sectors * SECTOR;
        let num_gts = capacity_bytes.div_ceil(bytes_per_gt);
        if num_gts > 1 << 20 {
            return Ok(OpenResult::NeedsNbd(
                "VMDK with a disproportionate grain directory".to_string(),
            ));
        }

        // If the primary GD is invalid but the redundant one is marked as used, use it.
        let gd_offset = if cab.flags & 0x2 != 0 && cab.rgd_offset != 0 && cab.rgd_offset != u64::MAX
        {
            cab.rgd_offset
        } else {
            cab.gd_offset
        };

        let mut raw = vec![0u8; (num_gts * 4) as usize];
        file.seek(SeekFrom::Start(gd_offset * SECTOR))?;
        file.read_exact(&mut raw)?;
        let directory = raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&[b0, b1, b2, b3]| u32::from_le_bytes([b0, b1, b2, b3]))
            .collect();

        Ok(OpenResult::Native(Self {
            file,
            grain_bytes,
            gtes_per_gt: cab.gtes_per_gt,
            capacity_bytes,
            directory,
            tables: HashMap::new(),
        }))
    }

    fn table(&mut self, gd_index: u32) -> io::Result<Option<&[u32]>> {
        let gde = match self.directory.get(gd_index as usize) {
            Some(&g) if g > 1 => g as u64,
            // 0 or 1: the whole table is unallocated -> zeroes.
            _ => return Ok(None),
        };
        if !self.tables.contains_key(&gd_index) {
            let mut raw = vec![0u8; self.gtes_per_gt as usize * 4];
            self.file.seek(SeekFrom::Start(gde * SECTOR))?;
            self.file.read_exact(&mut raw)?;
            let table: Vec<u32> = raw
                .as_chunks::<4>()
                .0
                .iter()
                .map(|&[b0, b1, b2, b3]| u32::from_le_bytes([b0, b1, b2, b3]))
                .collect();
            self.tables.insert(gd_index, table);
        }
        Ok(self.tables.get(&gd_index).map(|t| t.as_slice()))
    }

    /// Fills `buf` with the virtual disk data starting at `offset`.
    ///
    /// Unallocated regions are returned as zeroes. Returns how many bytes of
    /// `buf` fall within the extent's capacity.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.capacity_bytes {
            return Ok(0);
        }
        let total = buf.len().min((self.capacity_bytes - offset) as usize);
        let mut done = 0usize;

        while done < total {
            let pos = offset + done as u64;
            let grain = pos / self.grain_bytes;
            let within = (pos % self.grain_bytes) as usize;
            let n = (self.grain_bytes as usize - within).min(total - done);

            let gd_index = (grain / self.gtes_per_gt as u64) as u32;
            let gte_index = (grain % self.gtes_per_gt as u64) as usize;

            let grain_sector = self
                .table(gd_index)?
                .and_then(|t| t.get(gte_index).copied())
                .unwrap_or(0);

            let dst = &mut buf[done..done + n];
            if grain_sector > 1 {
                self.file.seek(SeekFrom::Start(
                    grain_sector as u64 * SECTOR + within as u64,
                ))?;
                read_or_zeros(&mut self.file, dst)?;
            } else {
                dst.fill(0);
            }
            done += n;
        }
        Ok(total)
    }
}

/// Reads as much as needed to fill `buf`; if the file ends first, the remainder is filled with zeroes.
pub fn read_or_zeros<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        match r.read(&mut buf[read..]) {
            Ok(0) => {
                buf[read..].fill(0);
                return Ok(());
            }
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Resolves the path of an extent relative to the descriptor's directory.
pub fn resolve_extent_path(descriptor: &Path, file: &str) -> PathBuf {
    let p = Path::new(file);
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
    fn test_tokenize() {
        let tokens = tokenize("RW 20971520 FLAT \"Windows-flat.vmdk\" 0");
        assert_eq!(
            tokens,
            vec!["RW", "20971520", "FLAT", "Windows-flat.vmdk", "0"]
        );
    }

    #[test]
    fn test_parse_descriptor() {
        let text = r#"
# Disk DescriptorFile
version=1
CID=7b844f21
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 4194304 FLAT "disk-f001.vmdk" 0
RW 4194304 FLAT "disk-f002.vmdk" 0
"#;
        let d = parse_descriptor(text);
        assert_eq!(d.create_type, "twoGbMaxExtentFlat");
        assert_eq!(d.extents.len(), 2);
        assert_eq!(d.extents[0]._access, "RW");
        assert_eq!(d.extents[0].sectors, 4194304);
        assert_eq!(d.extents[0].file.as_deref(), Some("disk-f001.vmdk"));
        assert!(!d.has_parent());
    }

    #[test]
    fn test_resolve_extent_path() {
        let desc = Path::new("C:/vms/win/disk.vmdk");
        let ext = resolve_extent_path(desc, "disk-f001.vmdk");
        assert_eq!(ext, Path::new("C:/vms/win/disk-f001.vmdk"));
    }
}
