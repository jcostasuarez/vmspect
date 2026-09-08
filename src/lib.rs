//! # vmspect
//!
//! `vmspect` is a Rust library designed for the static inspection, analysis and
//! information extraction of virtual machine disk images (VMDK, RAW, QCOW2, VHD, etc.).
//!
//! It can examine partition-table structures (MBR/GPT), identify the hosted operating
//! system (Windows/Linux) and extract complete lists of installed software in a
//! non-invasive way (without booting the VM or mounting the disk on the host).
//!
//! ## Key Features
//!
//! - **Hybrid access:** Native Rust parser for common formats (VMDK/RAW) with a lightweight
//!   dynamic-streaming layer via `qemu-nbd` (local TCP) for complex formats (`QCOW2`,
//!   `VHDX`, `VDI`, ...).
//! - **Multi-OS support:** Full software extraction from the Windows Registry (`NTFS`) and
//!   DPKG indexes on Linux (`EXT4`).
//! - **Agnostic extraction:** Complete and unfiltered collection of software and system
//!   metadata.
//! - **Lock-free progress reporting:** Atomic metrics that integrate cleanly with GUI
//!   front-ends (Tauri / Egui / CLI) via [`InspectionProgress`].
//! - **Graceful shutdown and result preservation:** Cooperative cancellation via
//!   [`CancellationToken`] that preserves all completed reports up to the interruption.
//! - **Open architecture:** Traits ([`VmDriver`], [`MemoryMapper`], [`OsInspector`]) and
//!   an extensible engine ([`InspectionEngine`], [`ConcurrentProcessor`]).
//!
//! ## Quick Usage Example
//!
//! ```rust,no_run
//! use std::path::Path;
//! use vmspect::prelude::*;
//!
//! fn main() -> Result<()> {
//!     let path = Path::new("virtual_disk.vmdk");
//!     let options = Options::default();
//!
//!     let report = inspect_with_progress(path, &options, |progress: InspectionProgressEvent| {
//!         println!("[{:>3}%] {} - {}", progress.percentage, progress.stage,
//!             progress.detail.unwrap_or_default());
//!     })?;
//!
//!     println!("Detected OS: {:?}", report.operating_system);
//!     println!("Found programs: {}", report.installed_programs.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Concurrent Processing with Cancellation and Partial Results
//!
//! ```rust,no_run
//! use std::path::PathBuf;
//! use std::sync::atomic::Ordering;
//! use vmspect::prelude::*;
//!
//! fn main() -> Result<()> {
//!     let paths = vec![
//!         PathBuf::from("vm1.vmdk"),
//!         PathBuf::from("vm2.raw"),
//!         PathBuf::from("vm3.qcow2"),
//!     ];
//!
//!     let cancel = CancellationToken::new();
//!     let options = Options::default().with_cancellation_token(&cancel);
//!     let engine = InspectionEngine::new(options);
//!
//!     // Cancellation can be requested from any thread:
//!     // cancel.cancel();
//!
//!     // Returns the reports that completed successfully before and during shutdown:
//!     let completed_reports = engine.inspect_batch(paths, 4)?;
//!     println!("Preserved reports: {}", completed_reports.len());
//!
//!     Ok(())
//! }
//! ```

#![deny(missing_docs)]

pub mod engine;
pub mod error;
pub mod models;
pub(crate) mod parsers;
pub mod prelude;
pub mod vms;

// Flat public-API re-exports for ergonomic consumption from the crate root.
pub use crate::vms::discovery::{
    count_vms, has_vms, is_secondary_extent, is_vm_image, list_vms, requires_nbd, requires_qemu,
    verify_image_integrity,
};
pub use crate::vms::stream::VirtualDisk;
pub use engine::{ConcurrentProcessor, InspectionEngine};
pub use error::{Result, VmSpectError};
pub use models::{
    format_bytes, AnalysisResult, CancellationToken, FileSystem, GuestInfo, GuestTools, Hypervisor,
    ImageInfo, InspectionOptions, InspectionProgress, InspectionProgressEvent, InspectionReport,
    MemoryMapper, OperatingSystem, Options, OsInspector, Partition, PartitionScheme, Program,
    ProgressSnapshot, Stats, VmDriver,
};

use std::path::Path;

/// Performs a full static inspection of a disk image using a plain-text callback.
///
/// This function is primarily designed for CLI applications or console scripts where
/// status output is printed line by line via text messages (`&str`).
///
/// # Parameters
///
/// - `image_path`: Reference to the [`Path`] of the virtual disk file (`.vmdk`, `.raw`, ...).
/// - `options`: Inspection configuration ([`Options`]), which controls apps/system analysis and paths.
/// - `progress`: Mutable callback receiving `&str` references with the description of the current step.
///
/// # Errors
///
/// Returns a [`VmSpectError`] if:
/// - The file at `image_path` does not exist ([`VmSpectError::ImageNotFound`]).
/// - A VMDK descriptor references a missing extent or parent disk
///   ([`VmSpectError::MissingDiskComponent`]). The error contains both the declared and
///   resolved component paths, plus the original operating-system error.
/// - The inspection was cancelled by the user ([`VmSpectError::Cancelled`]).
/// - An I/O read error occurs on the image ([`VmSpectError::Io`]).
/// - The image requires the `qemu-nbd` server and the executable is unavailable
///   ([`VmSpectError::QemuNotFound`]).
/// - Starting or communicating with `qemu-nbd` fails ([`VmSpectError::Nbd`]), including the
///   executable path, exit code and `stderr` when the subprocess provides them.
/// - The partition table or underlying file system cannot be recognized
///   ([`VmSpectError::FileSystem`]).
///
/// # Example
///
/// ```rust,no_run
/// use std::path::Path;
/// use vmspect::{inspect, Options};
///
/// let path = Path::new("C:\\VMs\\Windows10.vmdk");
/// let options = Options::default();
///
/// let result = inspect(path, &options, &mut |message| {
///     println!("LOG: {}", message);
/// });
/// ```
pub fn inspect(
    image_path: &Path,
    options: &Options,
    progress: &mut dyn FnMut(&str),
) -> Result<InspectionReport> {
    let engine = InspectionEngine::new(options.clone());
    engine.inspect_with_progress(image_path, |p| {
        let msg = match &p.detail {
            Some(d) => format!("[{:>3}%] {} - {}", p.percentage, p.stage, d),
            None => format!("[{:>3}%] {}", p.percentage, p.stage),
        };
        progress(&msg);
    })
}

/// Performs a static inspection reporting structured progress events (`0` to `100%`).
///
/// This is the recommended option for integrations with GUI environments (such as **Tauri**,
/// **Electron** or **Egui**), as it emits a serializable [`InspectionProgressEvent`] with
/// bounded percentages and descriptions of the current stage.
///
/// # Parameters
///
/// - `image_path`: Reference to the [`Path`] of the virtual disk image.
/// - `options`: Engine configuration ([`Options`]).
/// - `progress_callback`: Closure implementing `FnMut(InspectionProgressEvent)`, invoked
///   sequentially during the analysis.
///
/// # Emitted Percentage Flow
///
/// - **`5% - 15%`**: Image format identification and read-backend setup.
/// - **`25% - 45%`**: Partitioning scheme (MBR/GPT) and file-system signature detection.
/// - **`55%`**: Deep OS analysis (NTFS Registry / DPKG package extraction).
/// - **`90%`**: Report generation and consolidation.
/// - **`100%`**: Final report delivery and performance metrics computation.
pub fn inspect_with_progress<F>(
    image_path: &Path,
    options: &Options,
    progress_callback: F,
) -> Result<InspectionReport>
where
    F: FnMut(InspectionProgressEvent),
{
    let engine = InspectionEngine::new(options.clone());
    engine.inspect_with_progress(image_path, progress_callback)
}
