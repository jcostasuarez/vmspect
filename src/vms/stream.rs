//! Virtual disk access: native parsing when possible and `qemu-nbd` for complex formats.
//!
//! Hierarchy
//! ---------
//! - [`DiskReader`]: single façade. Picks the backend when the image is opened
//!   and exposes `read_range(offset, len)` on virtual disk coordinates.
//!   - **Native** (`std::fs::File` + `Seek`, no child processes): `raw` images,
//!     `monolithicSparse` VMDKs without a parent, and VMDK text-descriptor
//!     files whose extents are `FLAT` / `VMFS` / `SPARSE` / `ZERO`
//!     (`monolithicFlat`, `twoGbMaxExtentFlat`/`Sparse`, `vmfs`).
//!   - **`qemu-nbd`** ([`NbdReader`]): complex formats (VDI, VHD/VHDX, QCOW2,
//!     streamOptimized VMDK, snapshots/deltas, backing files, ...).
//! - [`VirtualDisk`]: `Read + Seek` view of a disk range (typically a single
//!   partition) with an LRU chunk cache. Consumed by the parsers.

use crate::error::VmSpectError;
use crate::models::traits::{MemoryMapper, VmDriver};
use crate::models::{Hypervisor, ImageInfo, Options, Stats};
use crate::vms::nbd::{self, NbdReader};
use crate::vms::vmdk::{self, OpenResult, SparseExtent};
use positioned_io::ReadAt;
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const SECTOR: u64 = 512;

/// Builds a child process ensuring that on Windows no console window is created or shown.
#[inline]
pub(crate) fn new_command<S: AsRef<std::ffi::OsStr>>(prog: S) -> Command {
    let mut cmd = Command::new(prog);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Opens a file in read-only mode with shared, non-blocking permissions (Windows).
pub(crate) fn open_read_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        // Allow concurrent read, write and delete access by other processes.
        opts.share_mode(7);
        opts.open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

// -----------------------------------------------------------------------------
// Image identification (without spawning a process if the header is recognizable)
// -----------------------------------------------------------------------------

fn format_by_extension(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
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

/// Recognizes the format by inspecting the leading-byte signature. Returns `None` when ambiguous.
fn format_by_signature(header: &[u8]) -> Option<&'static str> {
    if header.len() < 8 {
        return None;
    }
    if vmdk::is_sparse_header(header) || vmdk::is_text_descriptor(header) {
        return Some("vmdk");
    }
    if header.starts_with(b"<<< ") && header.len() >= 0x44 {
        // Text "<<< Oracle VM VirtualBox Disk Image >>>" + signature 0xBEDA107F at offset 0x40.
        if header[0x40..0x44] == [0x7F, 0x10, 0xDA, 0xBE] {
            return Some("vdi");
        }
    }
    if header.starts_with(b"conectix") {
        return Some("vpc");
    }
    if header.starts_with(b"vhdxfile") {
        return Some("vhdx");
    }
    if header.starts_with(b"QFI\xfb") {
        return Some("qcow2");
    }
    if header.starts_with(b"QED\0") {
        return Some("qed");
    }
    None
}

/// Identifies the image by inspecting its headers and format descriptors.
pub(crate) fn identify_image(_qemu_nbd: Option<&Path>, path: &Path) -> io::Result<ImageInfo> {
    let mut file = open_read_file(path)?;
    let file_size = file.metadata()?.len();
    let mut header = vec![0u8; 1024.min(file_size as usize)];
    let _ = file.read(&mut header);

    let format = format_by_signature(&header).or_else(|| format_by_extension(path));

    match format {
        Some("raw") => Ok(ImageInfo {
            path: path.to_path_buf(),
            format: "raw".to_string(),
            virtual_size: file_size,
            actual_size: file_size,
            hypervisor: Hypervisor::Unknown,
        }),
        Some("vmdk") => {
            if let Some(capacity) = native_vmdk_capacity(path, &header)? {
                let actual_size = compute_actual_vmdk_size(path, &header);
                return Ok(ImageInfo {
                    path: path.to_path_buf(),
                    format: "vmdk".to_string(),
                    virtual_size: capacity,
                    actual_size,
                    hypervisor: Hypervisor::VMware,
                });
            }
            let actual_size = compute_actual_vmdk_size(path, &header);
            Ok(ImageInfo {
                path: path.to_path_buf(),
                format: "vmdk".to_string(),
                virtual_size: file_size,
                actual_size: if actual_size > 0 {
                    actual_size
                } else {
                    file_size
                },
                hypervisor: Hypervisor::VMware,
            })
        }
        Some("qcow2") => {
            let mut virtual_size = file_size;
            if header.len() >= 32 && header.starts_with(b"QFI\xfb") {
                if let Ok(size) = header[24..32].try_into().map(u64::from_be_bytes) {
                    if size > 0 {
                        virtual_size = size;
                    }
                }
            }
            Ok(ImageInfo {
                path: path.to_path_buf(),
                format: "qcow2".to_string(),
                virtual_size,
                actual_size: file_size,
                hypervisor: Hypervisor::Qemu,
            })
        }
        Some("vpc") | Some("vhd") => {
            let mut virtual_size = file_size;
            if file_size >= 512 {
                let mut footer = [0u8; 512];
                if file.seek(SeekFrom::Start(file_size - 512)).is_ok()
                    && file.read_exact(&mut footer).is_ok()
                    && footer.starts_with(b"conectix")
                {
                    if let Ok(size) = footer[48..56].try_into().map(u64::from_be_bytes) {
                        if size > 0 {
                            virtual_size = size;
                        }
                    }
                } else if header.starts_with(b"conectix") {
                    if let Ok(size) = header[48..56].try_into().map(u64::from_be_bytes) {
                        if size > 0 {
                            virtual_size = size;
                        }
                    }
                }
            }
            Ok(ImageInfo {
                path: path.to_path_buf(),
                format: "vpc".to_string(),
                virtual_size,
                actual_size: file_size,
                hypervisor: Hypervisor::HyperV,
            })
        }
        Some("vdi") => {
            let mut virtual_size = file_size;
            if header.len() >= 0x178 && header.starts_with(b"<<< ") {
                if let Ok(size) = header[0x170..0x178].try_into().map(u64::from_le_bytes) {
                    if size > 0 {
                        virtual_size = size;
                    }
                }
            }
            Ok(ImageInfo {
                path: path.to_path_buf(),
                format: "vdi".to_string(),
                virtual_size,
                actual_size: file_size,
                hypervisor: Hypervisor::VirtualBox,
            })
        }
        Some(fmt) => {
            let hypervisor = Hypervisor::from_format(fmt);
            Ok(ImageInfo {
                path: path.to_path_buf(),
                format: fmt.to_string(),
                virtual_size: file_size,
                actual_size: file_size,
                hypervisor,
            })
        }
        None => {
            let fmt = format_by_extension(path).unwrap_or("raw");
            Ok(ImageInfo {
                path: path.to_path_buf(),
                format: fmt.to_string(),
                virtual_size: file_size,
                actual_size: file_size,
                hypervisor: Hypervisor::from_format(fmt),
            })
        }
    }
}

/// Virtual capacity of a VMDK read from its header/descriptor. `None` if it could not be determined.
fn native_vmdk_capacity(path: &Path, header: &[u8]) -> io::Result<Option<u64>> {
    if vmdk::is_sparse_header(header) {
        let cab = vmdk::read_sparse_header(header)?;
        return Ok(Some(cab.capacity_sectors * SECTOR));
    }
    if vmdk::is_text_descriptor(header) {
        let text = fs::read_to_string(path).unwrap_or_default();
        let d = vmdk::parse_descriptor(&text);
        let total: u64 = d.extents.iter().map(|e| e.sectors).sum();
        if total > 0 {
            return Ok(Some(total * SECTOR));
        }
    }
    Ok(None)
}

/// Computes the actual physical size on disk occupied by a VMDK (descriptor + associated extents).
fn compute_actual_vmdk_size(vmdk_path: &Path, header: &[u8]) -> u64 {
    let mut total_bytes = fs::metadata(vmdk_path).map(|m| m.len()).unwrap_or(0);

    if vmdk::is_text_descriptor(header) {
        if let Ok(text) = fs::read_to_string(vmdk_path) {
            let descriptor = vmdk::parse_descriptor(&text);
            for extent in &descriptor.extents {
                if let Some(file_name) = &extent.file {
                    let extent_path = vmdk::resolve_extent_path(vmdk_path, file_name);
                    if let Ok(meta) = fs::metadata(&extent_path) {
                        total_bytes += meta.len();
                    }
                }
            }
        }
    }

    total_bytes
}

// -----------------------------------------------------------------------------
// Native and NBD backends
// -----------------------------------------------------------------------------

/// An extent of a text-descriptor VMDK, already opened.
struct OpenExtent {
    /// Position of the extent inside the virtual disk (in bytes).
    start: u64,
    length: u64,
    data: ExtentData,
}

enum ExtentData {
    /// Flat extent: the bytes live as-is in the file from `offset` onwards.
    Flat {
        file: File,
        offset: u64,
    },
    Sparse(SparseExtent),
    Zero,
}

enum Backend {
    /// Raw file: the virtual disk IS the file.
    Raw(File),
    /// monolithicSparse VMDK.
    Sparse(SparseExtent),
    /// VMDK with a text descriptor and one or more extents.
    Extents(Vec<OpenExtent>),
    /// `qemu-nbd` server connected over a TCP socket in the background (lightweight and fast).
    Nbd(NbdReader),
}

/// Façade over the virtual disk. Picks the native or `qemu-nbd` backend at open time.
pub struct DiskReader {
    backend: RefCell<Backend>,
    virtual_size: u64,
    access_mode: String,
    stats: RefCell<Stats>,
    cancel_token: Option<Arc<AtomicBool>>,
}

impl DiskReader {
    /// Opens the image, automatically selecting the most optimal backend.
    ///
    /// Priority:
    /// 1. Native Rust backend (RAW / sparse VMDK / flat VMDK).
    /// 2. `qemu-nbd` (local UNIX socket or streaming TCP, with no temp-file overhead).
    pub fn open(
        qemu_nbd: Option<&Path>,
        info: &ImageInfo,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        let options = Options {
            qemu_nbd: qemu_nbd.map(|p| p.to_path_buf()),
            cancel_token,
            ..Options::default()
        };
        Self::open_with_options(info, &options)
    }

    /// Opens the image, automatically selecting the most optimal backend for the supplied [`Options`].
    pub fn open_with_options(info: &ImageInfo, options: &Options) -> io::Result<Self> {
        Self::open_with_options_diagnostic(info, options).map_err(diagnostic_to_io)
    }

    /// Internal opening path that retains the distinction between disk and tool failures.
    pub(crate) fn open_with_options_diagnostic(
        info: &ImageInfo,
        options: &Options,
    ) -> crate::error::Result<Self> {
        let (backend, mode, size_adjusted) = match open_native(info)? {
            OpenResult::Native((b, mode)) => (b, format!("native ({})", mode), info.virtual_size),
            OpenResult::NeedsNbd(reason) => {
                let nbd_path = nbd::resolve_qemu_nbd(options.qemu_nbd.as_deref())
                    .map_err(|error| VmSpectError::QemuNotFound(error.to_string()))?;
                let nbd_reader = NbdReader::open_with_options(&nbd_path, info, options)
                    .map_err(nbd_error_to_vm)?;
                let size_nbd = nbd_reader.virtual_size().max(info.virtual_size);
                let channel = if options.unix_socket.is_some() {
                    "unix"
                } else {
                    "tcp"
                };
                (
                    Backend::Nbd(nbd_reader),
                    format!("qemu-nbd {} ({})", channel, reason),
                    size_nbd,
                )
            }
        };

        Ok(Self {
            backend: RefCell::new(backend),
            virtual_size: size_adjusted,
            stats: RefCell::new(Stats {
                access_mode: mode.clone(),
                ..Stats::default()
            }),
            access_mode: mode,
            cancel_token: options.cancel_token.clone(),
        })
    }

    /// Builds the façade forcing the `qemu-nbd` backend.
    pub fn from_nbd(
        reader: NbdReader,
        info: &ImageInfo,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Self {
        let virtual_size = reader.virtual_size().max(info.virtual_size);
        let mode = "qemu-nbd tcp (forced)".to_string();
        Self {
            backend: RefCell::new(Backend::Nbd(reader)),
            virtual_size,
            stats: RefCell::new(Stats {
                access_mode: mode.clone(),
                ..Stats::default()
            }),
            access_mode: mode,
            cancel_token,
        }
    }

    /// Returns a textual description of the access mode in use.
    pub fn access_mode(&self) -> &str {
        &self.access_mode
    }

    /// Returns a copy of the metrics and statistics collected during reads.
    pub fn stats(&self) -> Stats {
        self.stats.borrow().clone()
    }

    /// Recommended chunk size for [`VirtualDisk`].
    pub fn recommended_chunk_size(&self) -> u64 {
        match &*self.backend.borrow() {
            Backend::Raw(_) | Backend::Sparse(_) | Backend::Extents(_) => 256 * 1024,
            Backend::Nbd(_) => 512 * 1024,
        }
    }

    /// Reads `[offset, offset+len)` from the virtual disk. May return fewer bytes when reaching the end.
    pub fn read_range(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if let Some(ref cancel) = self.cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Analysis cancelled by the user",
                ));
            }
        }

        if offset >= self.virtual_size || len == 0 {
            return Ok(Vec::new());
        }
        let len = len.min((self.virtual_size - offset) as usize);

        let data = match &mut *self.backend.borrow_mut() {
            Backend::Raw(file) => {
                let mut buf = vec![0u8; len];
                file.seek(SeekFrom::Start(offset))?;
                vmdk::read_or_zeros(file, &mut buf)?;
                buf
            }
            Backend::Sparse(extent) => {
                let mut buf = vec![0u8; len];
                let n = extent.read_at(offset, &mut buf)?;
                buf.truncate(n);
                buf
            }
            Backend::Extents(extents) => read_from_extents(extents, offset, len)?,
            Backend::Nbd(nbd) => {
                self.stats.borrow_mut().nbd_requests += 1;
                nbd.read_range(offset, len)?
            }
        };

        self.stats.borrow_mut().bytes_read += data.len() as u64;
        Ok(data)
    }
}

fn diagnostic_to_io(error: VmSpectError) -> io::Error {
    match error {
        VmSpectError::Io(source) => source,
        other => io::Error::new(diagnostic_error_kind(&other), other),
    }
}

fn diagnostic_error_kind(error: &VmSpectError) -> io::ErrorKind {
    match error {
        VmSpectError::ImageNotFound(_) => io::ErrorKind::NotFound,
        VmSpectError::MissingDiskComponent { source, .. } => source.kind(),
        VmSpectError::QemuNotFound(_) => io::ErrorKind::NotFound,
        VmSpectError::Cancelled => io::ErrorKind::Interrupted,
        _ => io::ErrorKind::Other,
    }
}

fn nbd_error_to_vm(error: io::Error) -> VmSpectError {
    if error.kind() == io::ErrorKind::Interrupted {
        VmSpectError::Cancelled
    } else {
        VmSpectError::Nbd(error.to_string())
    }
}

impl VmDriver for DiskReader {
    fn virtual_size(&self) -> u64 {
        self.virtual_size
    }

    fn read_range(&self, offset: u64, buf: &mut [u8]) -> crate::error::Result<()> {
        let data = self.read_range(offset, buf.len())?;
        buf[..data.len()].copy_from_slice(&data);
        if data.len() < buf.len() {
            buf[data.len()..].fill(0);
        }
        Ok(())
    }

    fn access_mode(&self) -> &str {
        &self.access_mode
    }

    fn is_native(&self) -> bool {
        matches!(
            &*self.backend.borrow(),
            Backend::Raw(_) | Backend::Sparse(_) | Backend::Extents(_)
        )
    }

    fn recommended_chunk_size(&self) -> u64 {
        self.recommended_chunk_size()
    }
}

fn read_from_extents(extents: &mut [OpenExtent], offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut done = 0usize;

    while done < len {
        let pos = offset + done as u64;
        let Some(ext) = extents
            .iter_mut()
            .find(|e| pos >= e.start && pos < e.start + e.length)
        else {
            // Gap not covered by any extent: zeroes.
            break;
        };
        let within = pos - ext.start;
        let n = ((ext.length - within) as usize).min(len - done);
        let dst = &mut buf[done..done + n];

        match &mut ext.data {
            ExtentData::Flat { file, offset: base } => {
                file.seek(SeekFrom::Start(*base + within))?;
                vmdk::read_or_zeros(file, dst)?;
            }
            ExtentData::Sparse(sparse) => {
                let read = sparse.read_at(within, dst)?;
                dst[read..].fill(0);
            }
            ExtentData::Zero => dst.fill(0),
        }
        done += n;
    }
    Ok(buf)
}

/// Attempts to construct a native backend. Returns the reason when `qemu-nbd` is required.
fn open_main_image_file(path: &Path) -> crate::error::Result<File> {
    open_read_file(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            VmSpectError::ImageNotFound(path.display().to_string())
        } else {
            VmSpectError::Io(source)
        }
    })
}

fn open_native(info: &ImageInfo) -> crate::error::Result<OpenResult<(Backend, String)>> {
    match info.format.to_ascii_lowercase().as_str() {
        "raw" => Ok(OpenResult::Native((
            Backend::Raw(open_main_image_file(&info.path)?),
            "raw".to_string(),
        ))),
        "vmdk" => open_vmdk_native(&info.path),
        other => Ok(OpenResult::NeedsNbd(format!("format {}", other))),
    }
}

fn validate_parent_reference(
    descriptor_path: &Path,
    descriptor: &vmdk::Descriptor,
) -> crate::error::Result<()> {
    if let Some(parent_name) = descriptor
        .parent_file_name_hint
        .as_deref()
        .filter(|name| !name.trim().is_empty())
    {
        let parent_path = vmdk::resolve_extent_path(descriptor_path, parent_name);
        vmdk::ensure_component_exists(
            descriptor_path,
            parent_name,
            &parent_path,
            "VMDK parent disk",
        )?;
    }
    Ok(())
}

fn validate_extent_paths(
    descriptor_path: &Path,
    descriptor: &vmdk::Descriptor,
) -> crate::error::Result<()> {
    for extent in &descriptor.extents {
        if extent.kind == "ZERO" {
            continue;
        }
        let Some(name) = extent.file.as_deref() else {
            continue;
        };
        let resolved_path = vmdk::resolve_extent_path(descriptor_path, name);
        vmdk::ensure_component_exists(descriptor_path, name, &resolved_path, "VMDK extent")?;
    }
    Ok(())
}

fn validate_descriptor_components(
    descriptor_path: &Path,
    descriptor: &vmdk::Descriptor,
) -> crate::error::Result<()> {
    validate_parent_reference(descriptor_path, descriptor)?;
    validate_extent_paths(descriptor_path, descriptor)
}

const MAX_VMDK_PARENT_DEPTH: usize = 32;

/// Validates external VMDK dependencies before a backend is selected.
///
/// This preflight is also used when `force_nbd` is enabled. Selecting qemu-nbd must not turn a
/// missing descriptor component into a tool-resolution error.
pub(crate) fn validate_vmdk_components(path: &Path) -> crate::error::Result<()> {
    let mut visited = HashSet::new();
    validate_vmdk_components_inner(path, &mut visited, 0, None)
}

fn validate_vmdk_components_inner(
    path: &Path,
    visited: &mut HashSet<std::path::PathBuf>,
    depth: usize,
    parent_context: Option<(&Path, &str)>,
) -> crate::error::Result<()> {
    if depth > MAX_VMDK_PARENT_DEPTH {
        return Err(VmSpectError::Parse(format!(
            "VMDK parent chain exceeds the maximum depth of {} at '{}'",
            MAX_VMDK_PARENT_DEPTH,
            path.display()
        )));
    }

    let identity = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(identity) {
        return Err(VmSpectError::Parse(format!(
            "VMDK parent chain contains a cycle at '{}'",
            path.display()
        )));
    }

    let mut file = match parent_context {
        Some((descriptor_path, declared_name)) => {
            vmdk::open_component_file(path, descriptor_path, declared_name, "VMDK parent disk")?
        }
        None => open_main_image_file(path)?,
    };
    let mut header = [0u8; 512];
    let n = file.read(&mut header)?;
    let header = &header[..n];

    let descriptor = if vmdk::is_sparse_header(header) {
        let cab = vmdk::read_sparse_header(header)?;
        if cab.descriptor_offset == 0 || cab.descriptor_sectors == 0 {
            None
        } else {
            let mut text = vec![0u8; (cab.descriptor_sectors * SECTOR) as usize];
            file.seek(SeekFrom::Start(cab.descriptor_offset * SECTOR))?;
            vmdk::read_or_zeros(&mut file, &mut text)?;
            Some(vmdk::parse_descriptor(&String::from_utf8_lossy(&text)))
        }
    } else if vmdk::is_text_descriptor(header) {
        let text = fs::read_to_string(path)?;
        Some(vmdk::parse_descriptor(&text))
    } else {
        None
    };

    let Some(descriptor) = descriptor else {
        return Ok(());
    };

    validate_descriptor_components(path, &descriptor)?;

    if let Some(parent_name) = descriptor
        .parent_file_name_hint
        .as_deref()
        .filter(|name| !name.trim().is_empty())
    {
        let parent_path = vmdk::resolve_extent_path(path, parent_name);
        validate_vmdk_components_inner(
            &parent_path,
            visited,
            depth + 1,
            Some((path, parent_name)),
        )?;
    }

    Ok(())
}

fn open_vmdk_native(path: &Path) -> crate::error::Result<OpenResult<(Backend, String)>> {
    validate_vmdk_components(path)?;
    let mut file = open_main_image_file(path)?;
    let mut header = [0u8; 512];
    let n = file.read(&mut header)?;
    let header = &header[..n];

    // --- Case 1: monolithicSparse (binary KDMV header with embedded descriptor)
    if vmdk::is_sparse_header(header) {
        let cab = vmdk::read_sparse_header(header)?;

        if cab.descriptor_offset != 0 && cab.descriptor_sectors != 0 {
            let mut text = vec![0u8; (cab.descriptor_sectors * SECTOR) as usize];
            file.seek(SeekFrom::Start(cab.descriptor_offset * SECTOR))?;
            vmdk::read_or_zeros(&mut file, &mut text)?;
            let d = vmdk::parse_descriptor(&String::from_utf8_lossy(&text));
            if d.has_parent() {
                return Ok(OpenResult::NeedsNbd(
                    "VMDK delta/snapshot with a parent disk".to_string(),
                ));
            }
            // A monolithic sparse declaring multiple extents is rare; delegate, but first
            // validate all declared files so a missing component is not reported as qemu-nbd.
            if d.extents.len() > 1 {
                return Ok(OpenResult::NeedsNbd(
                    "VMDK sparse with multiple declared extents".to_string(),
                ));
            }
        }

        return Ok(match SparseExtent::from_header(file, path, cab)? {
            OpenResult::Native(ext) => {
                OpenResult::Native((Backend::Sparse(ext), "vmdk monolithicSparse".to_string()))
            }
            OpenResult::NeedsNbd(m) => OpenResult::NeedsNbd(m),
        });
    }

    // --- Case 2: text descriptor with external extents
    if vmdk::is_text_descriptor(header) {
        let text = fs::read_to_string(path)?;
        let d = vmdk::parse_descriptor(&text);
        if d.has_parent() {
            return Ok(OpenResult::NeedsNbd(
                "VMDK delta/snapshot with a parent disk".to_string(),
            ));
        }
        if d.extents.is_empty() {
            return Ok(OpenResult::NeedsNbd(
                "VMDK descriptor with no extents".to_string(),
            ));
        }

        let mut extents = Vec::with_capacity(d.extents.len());
        let mut start = 0u64;
        for e in &d.extents {
            let length = e.sectors * SECTOR;
            let data = match e.kind.as_str() {
                "ZERO" => ExtentData::Zero,
                "FLAT" | "VMFS" | "VMFSRAW" => {
                    let Some(name) = &e.file else {
                        return Ok(OpenResult::NeedsNbd(
                            "FLAT extent without a file".to_string(),
                        ));
                    };
                    let ext_path = vmdk::resolve_extent_path(path, name);
                    ExtentData::Flat {
                        file: vmdk::open_component_file(&ext_path, path, name, "VMDK extent")?,
                        offset: e.offset_sectors * SECTOR,
                    }
                }
                "SPARSE" | "VMFSSPARSE" => {
                    let Some(name) = &e.file else {
                        return Ok(OpenResult::NeedsNbd(
                            "SPARSE extent without a file".to_string(),
                        ));
                    };
                    let ext_path = vmdk::resolve_extent_path(path, name);
                    match SparseExtent::open(&ext_path, path, name, "VMDK extent")? {
                        OpenResult::Native(s) => ExtentData::Sparse(s),
                        OpenResult::NeedsNbd(m) => return Ok(OpenResult::NeedsNbd(m)),
                    }
                }
                other => {
                    return Ok(OpenResult::NeedsNbd(format!(
                        "VMDK extent of type {} is not supported",
                        other
                    )));
                }
            };
            extents.push(OpenExtent {
                start,
                length,
                data,
            });
            start += length;
        }

        let tipo = if d.create_type.is_empty() {
            format!("{} extents", extents.len())
        } else {
            d.create_type.clone()
        };
        return Ok(OpenResult::Native((
            Backend::Extents(extents),
            format!("vmdk {}", tipo),
        )));
    }

    Ok(OpenResult::NeedsNbd(
        "VMDK with unrecognized header".to_string(),
    ))
}

// -----------------------------------------------------------------------------
// Virtual disk with Read + Seek and chunk cache
// -----------------------------------------------------------------------------

/// `Read + Seek` view of a virtual disk range (typically a single partition).
///
/// Reads are grouped into aligned chunks of `chunk_size` bytes that are
/// fetched on demand via [`VmDriver`] and kept in an LRU chunk cache.
pub struct VirtualDisk<'a> {
    driver: &'a dyn VmDriver,
    base: u64,
    length: u64,
    position: u64,
    chunk_size: u64,
    cache: RefCell<VecDeque<(u64, Vec<u8>)>>,
    max_chunks: usize,
}

impl<'a> VirtualDisk<'a> {
    /// Creates a view over `[base, base+length)` of the disk.
    pub fn new(driver: &'a dyn VmDriver, base: u64, length: u64, chunk_size: u64) -> Self {
        let chunk_size = chunk_size.max(512).next_power_of_two();
        Self {
            driver,
            base,
            length,
            position: 0,
            chunk_size,
            cache: RefCell::new(VecDeque::new()),
            // ~64 MiB of cache regardless of the chunk size.
            max_chunks: ((64 * 1024 * 1024) / chunk_size).clamp(4, 512) as usize,
        }
    }

    /// View over the entire disk.
    pub fn full(driver: &'a dyn VmDriver, chunk_size: u64) -> Self {
        Self::new(driver, 0, driver.virtual_size(), chunk_size)
    }

    /// Returns the length, in bytes, of the mapped range.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Returns the base offset, in bytes, within the virtual disk.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Reads data through the LRU chunk cache, loading aligned blocks on demand when missing.
    fn read_with_cache(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        if pos >= self.length || buf.is_empty() {
            return Ok(0);
        }
        let total = (self.length - pos).min(buf.len() as u64) as usize;
        let mut transferred = 0;

        while transferred < total {
            let current_offset = pos + transferred as u64;
            let chunk_index = current_offset / self.chunk_size;
            let within_chunk = (current_offset % self.chunk_size) as usize;

            // Make sure the required chunk sits at the front of the cache.
            {
                let mut cache = self.cache.borrow_mut();
                if let Some(p) = cache.iter().position(|(i, _)| *i == chunk_index) {
                    if p > 0 {
                        if let Some(entry) = cache.remove(p) {
                            cache.push_front(entry);
                        }
                    }
                } else {
                    // Load the chunk from the driver, briefly releasing the cache borrow.
                    drop(cache);
                    let abs = self.base + chunk_index * self.chunk_size;
                    let chunk_len = self.chunk_size as usize;
                    let mut read = vec![0u8; chunk_len];
                    let total_virtual = self.driver.virtual_size();
                    if abs < total_virtual {
                        let to_read = chunk_len.min((total_virtual - abs) as usize);
                        read.truncate(to_read);
                        self.driver
                            .read_range(abs, &mut read)
                            .map_err(|e| io::Error::other(e.to_string()))?;
                    } else {
                        read.clear();
                    }
                    let mut cache = self.cache.borrow_mut();
                    if cache.len() >= self.max_chunks {
                        cache.pop_back();
                    }
                    cache.push_front((chunk_index, read));
                }
            }

            let cache = self.cache.borrow();
            let (_, data) = &cache[0];

            if within_chunk >= data.len() {
                break;
            }

            let available = data.len() - within_chunk;
            let to_copy = (total - transferred).min(available);
            buf[transferred..transferred + to_copy]
                .copy_from_slice(&data[within_chunk..within_chunk + to_copy]);
            transferred += to_copy;
        }

        Ok(transferred)
    }
}

impl Read for VirtualDisk<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_with_cache(self.position, buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VirtualDisk<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.length as i128 + d as i128,
            SeekFrom::Current(d) => self.position as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative position",
            ));
        }
        self.position = new as u64;
        Ok(self.position)
    }
}

impl<'a> ReadAt for VirtualDisk<'a> {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.read_with_cache(pos, buf)
    }
}

impl<'a> MemoryMapper for VirtualDisk<'a> {
    fn read_at_offset(&mut self, offset: u64, buf: &mut [u8]) -> crate::error::Result<usize> {
        self.read_with_cache(offset, buf).map_err(Into::into)
    }

    fn length(&self) -> u64 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_virtual_disk_read_seek() {
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

        let info = ImageInfo {
            path: file_path.clone(),
            format: "raw".to_string(),
            virtual_size: 4096,
            actual_size: 4096,
            hypervisor: Hypervisor::Unknown,
        };

        let reader = DiskReader::open(None, &info, None).unwrap();
        assert!(reader.is_native());
        assert_eq!(reader.virtual_size(), 4096);

        let mut disk = VirtualDisk::new(&reader, 0, 4096, 512);
        assert_eq!(disk.base(), 0);
        assert_eq!(disk.length(), 4096);

        let full_disk = VirtualDisk::full(&reader, 512);
        assert_eq!(full_disk.base(), 0);
        assert_eq!(full_disk.length(), 4096);

        // Read first 8 bytes
        let mut buf = [0u8; 8];
        disk.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[0..4], &0u32.to_le_bytes());
        assert_eq!(&buf[4..8], &1u32.to_le_bytes());

        // Seek
        disk.seek(SeekFrom::Start(100 * 4)).unwrap();
        disk.read_exact(&mut buf[0..4]).unwrap();
        assert_eq!(&buf[0..4], &100u32.to_le_bytes());

        // ReadAt
        let mut read_at_buf = [0u8; 4];
        let n = disk.read_at(250 * 4, &mut read_at_buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&read_at_buf, &250u32.to_le_bytes());
    }

    #[test]
    fn test_format_by_extension() {
        assert_eq!(format_by_extension(Path::new("test.vmdk")), Some("vmdk"));
        assert_eq!(format_by_extension(Path::new("test.qcow2")), Some("qcow2"));
        assert_eq!(format_by_extension(Path::new("test.vdi")), Some("vdi"));
        assert_eq!(format_by_extension(Path::new("test.vhdx")), Some("vhdx"));
        assert_eq!(format_by_extension(Path::new("test.raw")), Some("raw"));
        assert_eq!(format_by_extension(Path::new("test.xyz")), None);
    }
}
