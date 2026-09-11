//! Traits and abstract contracts independent of the hypervisor or operating system.

use crate::error::Result;
use crate::models::{GuestInfo, Options, Partition, Program};
use std::io::{Read, Seek};

/// Consolidated result returned by the inspection of an operating system.
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// Detailed information about the detected operating system.
    pub guest_info: GuestInfo,
    /// List of identified programs and packages.
    pub programs: Vec<Program>,
    /// Non-fatal warnings collected during the analysis (e.g. Windows Registry
    /// hives that were corrupt or dirty and from which we gracefully degraded).
    pub warnings: Vec<String>,
}

/// Abstract contract for drivers that access virtual machine images or hypervisors.
pub trait VmDriver {
    /// Returns the total virtual size of the disk in bytes.
    fn virtual_size(&self) -> u64;

    /// Reads a byte range from the virtual `offset` until `buf` is filled.
    fn read_range(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Name or description of the access mode used by the driver.
    fn access_mode(&self) -> &str;

    /// Indicates whether the driver operates natively in Rust without external subprocesses.
    fn is_native(&self) -> bool;

    /// Recommended chunk size for block-oriented operations with this driver.
    fn recommended_chunk_size(&self) -> u64 {
        1024 * 1024
    }

    /// Records a bounded-cache hit. Drivers that do not collect I/O metrics can ignore it.
    fn record_cache_hit(&self) {}
}

/// Abstract contract for memory, block or virtual disk range mappers.
pub trait MemoryMapper: Read + Seek {
    /// Reads a block of data at an absolute `offset` within the mapped space.
    fn read_at_offset(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Returns the total length of the mapped space.
    fn length(&self) -> u64;
}

/// Abstract contract for guest operating system analyzers (Windows, Linux, etc.).
pub trait OsInspector {
    /// Runs the file system analysis and extracts the OS info and installed software.
    fn analyze(
        &self,
        driver: &dyn VmDriver,
        partitions: &[Partition],
        chunk_size: u64,
        options: &Options,
    ) -> Result<AnalysisResult>;
}
