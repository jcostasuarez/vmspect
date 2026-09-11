//! Models for disk images, hypervisors and inspection statistics.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Source hypervisor inferred from the disk image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hypervisor {
    /// VMware ESXi, Workstation or Fusion.
    VMware,
    /// Oracle VirtualBox.
    VirtualBox,
    /// Microsoft Hyper-V or Virtual PC.
    HyperV,
    /// QEMU / KVM.
    Qemu,
    /// Unknown hypervisor or origin format.
    Unknown,
}

impl Hypervisor {
    /// Deduces the hypervisor from the extension or format name returned by inspection.
    pub fn from_format(format: &str) -> Self {
        match format.to_ascii_lowercase().as_str() {
            "vmdk" => Hypervisor::VMware,
            "vdi" => Hypervisor::VirtualBox,
            "vpc" | "vhd" | "vhdx" => Hypervisor::HyperV,
            "qcow" | "qcow2" | "qed" => Hypervisor::Qemu,
            _ => Hypervisor::Unknown,
        }
    }

    /// Human-readable hypervisor name.
    pub fn name(&self) -> &'static str {
        match self {
            Hypervisor::VMware => "VMware",
            Hypervisor::VirtualBox => "VirtualBox",
            Hypervisor::HyperV => "Hyper-V / Virtual PC",
            Hypervisor::Qemu => "QEMU / KVM",
            Hypervisor::Unknown => "Unknown (raw image or other)",
        }
    }
}

/// Descriptive information and dimensions of the examined disk image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Path of the disk file on the host file system.
    pub path: PathBuf,
    /// Detected format (e.g. "vmdk", "vdi", "vhdx", "qcow2", "raw").
    pub format: String,
    /// Total virtual capacity reported by the virtual disk, in bytes.
    pub virtual_size: u64,
    /// Actual physical size occupied on disk by the image file, in bytes.
    pub actual_size: u64,
    /// Hypervisor associated with the image.
    pub hypervisor: Hypervisor,
}

/// Performance statistics and metrics collected during the inspection process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    /// Read backend used, normally `direct-read (...)`; `qemu-nbd` is only used after explicit opt-in.
    pub access_mode: String,
    /// Number of requests issued to the NBD socket when the explicit external backend is used.
    #[serde(default)]
    pub nbd_requests: u64,
    /// Number of range reads issued to the image backend.
    #[serde(default)]
    pub read_operations: u64,
    /// Number of image reads avoided by the bounded `VirtualDisk` cache.
    #[serde(default)]
    pub cache_hits: u64,
    /// Total bytes extracted from the virtual disk.
    #[serde(default)]
    pub bytes_read: u64,
    /// Source classification when it can be determined without probing the host. `unc-network`
    /// is reliable for UNC paths; mapped drives and synchronized folders remain `unclassified`.
    #[serde(default)]
    pub source_location: String,
    /// `Some(true)` only when the source is reliably known to be a UNC network path.
    #[serde(default)]
    pub source_is_network: Option<bool>,
    /// Duration of format and metadata identification.
    #[serde(default)]
    pub identification_duration_ms: u64,
    /// Duration of backend initialization.
    #[serde(default)]
    pub backend_initialization_duration_ms: u64,
    /// Duration of partition and file-system signature detection.
    #[serde(default)]
    pub partition_detection_duration_ms: u64,
    /// Duration of guest operating-system inventory extraction.
    #[serde(default)]
    pub guest_analysis_duration_ms: u64,
    /// Duration of final report consolidation.
    #[serde(default)]
    pub report_generation_duration_ms: u64,
    /// Total time the inspection process took, expressed in milliseconds.
    #[serde(default)]
    pub duration_ms: u64,
}

/// Utility function that converts an integer byte count into a lexical formatted
/// representation (B, KiB, MiB, GiB, TiB).
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx < UNITS.len() - 1 {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNITS[idx])
    } else {
        format!("{:.1} {}", value, UNITS[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 2), "2.0 GiB");
    }

    #[test]
    fn test_hypervisor_from_format() {
        assert_eq!(Hypervisor::from_format("vmdk"), Hypervisor::VMware);
        assert_eq!(Hypervisor::from_format("vdi"), Hypervisor::VirtualBox);
        assert_eq!(Hypervisor::from_format("vhdx"), Hypervisor::HyperV);
        assert_eq!(Hypervisor::from_format("qcow2"), Hypervisor::Qemu);
        assert_eq!(Hypervisor::from_format("raw"), Hypervisor::Unknown);
    }
}
