//! Models for partitions, schemes and file systems.

use serde::{Deserialize, Serialize};

/// Partition table scheme present in the virtual disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionScheme {
    /// Traditional Master Boot Record.
    Mbr,
    /// GUID Partition Table.
    Gpt,
    /// The disk lacks a partition table: the file system starts directly at sector 0.
    None,
}

/// Type of file system identified in a partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileSystem {
    /// New Technology File System (Windows).
    Ntfs,
    /// File Allocation Table (FAT12/FAT16/FAT32/exFAT).
    Fat,
    /// Second Extended Filesystem (Linux).
    Ext2,
    /// Third Extended Filesystem (Linux).
    Ext3,
    /// Fourth Extended Filesystem (Linux).
    Ext4,
    /// High-performance journaling file system (Linux).
    Xfs,
    /// B-tree file system (Linux).
    Btrfs,
    /// Linux swap partition.
    LinuxSwap,
    /// LVM2 Physical Volume (Linux Logical Volume Manager).
    Lvm2,
    /// Unrecognized or unsupported file system.
    Unknown,
}

impl FileSystem {
    /// Returns whether the file system natively belongs to the Linux ecosystem.
    pub fn is_linux(&self) -> bool {
        matches!(
            self,
            FileSystem::Ext2
                | FileSystem::Ext3
                | FileSystem::Ext4
                | FileSystem::Xfs
                | FileSystem::Btrfs
                | FileSystem::LinuxSwap
                | FileSystem::Lvm2
        )
    }

    /// Friendly, standardized name of the file system.
    pub fn name(&self) -> &'static str {
        match self {
            FileSystem::Ntfs => "NTFS",
            FileSystem::Fat => "FAT",
            FileSystem::Ext2 => "ext2",
            FileSystem::Ext3 => "ext3",
            FileSystem::Ext4 => "ext4",
            FileSystem::Xfs => "XFS",
            FileSystem::Btrfs => "Btrfs",
            FileSystem::LinuxSwap => "Linux swap",
            FileSystem::Lvm2 => "LVM2 PV",
            FileSystem::Unknown => "unknown",
        }
    }
}

/// General classification of the guest operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatingSystem {
    /// Microsoft Windows operating systems.
    Windows,
    /// Linux distributions.
    Linux,
    /// Unidentified or unsupported operating system.
    Unknown,
}

impl OperatingSystem {
    /// Returns a representative emoji for the operating system, for console UIs.
    pub fn icon(&self) -> &'static str {
        match self {
            OperatingSystem::Windows => "🪟",
            OperatingSystem::Linux => "🐧",
            OperatingSystem::Unknown => "❓",
        }
    }
}

/// Representation of a physical partition located inside the virtual disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    /// Sequential index of the partition within the table.
    pub index: usize,
    /// Absolute offset in bytes where the partition starts on the virtual disk.
    pub start: u64,
    /// Total size of the partition expressed in bytes.
    pub size: u64,
    /// Declared partition type (MBR byte or translated GPT GUID).
    pub kind: String,
    /// File system detected by inspecting the signature of the first sector of the partition.
    pub file_system: FileSystem,
    /// Optional label or volume name assigned to the partition.
    pub label: Option<String>,
}

impl Partition {
    /// Returns `true` if the partition's file system is NTFS.
    pub fn is_ntfs(&self) -> bool {
        matches!(self.file_system, FileSystem::Ntfs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_system() {
        assert!(FileSystem::Ext4.is_linux());
        assert!(!FileSystem::Ntfs.is_linux());
        assert_eq!(FileSystem::Ntfs.name(), "NTFS");
    }
}
