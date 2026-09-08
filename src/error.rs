//! Centralized error handling for `vmspect`.

use std::path::Path;

use thiserror::Error;

/// Enumeration of error kinds that may be produced during inspection and analysis.
#[derive(Debug, Error)]
pub enum VmSpectError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failure while parsing disk structures, partitions, file systems or registry hives.
    #[error("Parse error: {0}")]
    Parse(String),

    /// Unsupported or unrecognized operating system.
    #[error("Unsupported operating system: {0}")]
    UnsupportedOs(String),

    /// Unsupported or unknown disk image format.
    #[error("Unsupported image format: {0}")]
    UnsupportedFormat(String),

    /// The specified image does not exist at the given path.
    #[error("Disk image not found: {0}")]
    ImageNotFound(String),

    /// The inspection operation was cancelled by the user or cancellation token.
    #[error("Inspection was cancelled by the user")]
    Cancelled,

    /// A disk descriptor references a component that cannot be opened.
    ///
    /// VMDK descriptors commonly reference external extent files and parent disks. This
    /// error deliberately keeps the descriptor path, the name as declared by the descriptor,
    /// the resolved path and the original operating-system error so an integrator can repair
    /// the input set instead of troubleshooting `qemu-nbd` installation.
    #[error("Missing {component_type} '{declared_name}' referenced by '{descriptor_path}'. Resolved path: '{resolved_path}'. OS error: {source}")]
    MissingDiskComponent {
        /// Path of the descriptor that declared the missing component.
        descriptor_path: String,
        /// Name exactly as declared by the descriptor.
        declared_name: String,
        /// Path obtained after resolving the declaration relative to the descriptor.
        resolved_path: String,
        /// Human-readable component kind, such as `VMDK extent` or `VMDK parent disk`.
        component_type: String,
        /// Original error returned by the operating system.
        #[source]
        source: std::io::Error,
    },

    /// `qemu-nbd` binary or tool not found on the system.
    #[error("QEMU tool not available: {0}")]
    QemuNotFound(String),

    /// Error while initializing or communicating with the NBD server.
    #[error("NBD protocol error: {0}")]
    Nbd(String),

    /// Error reading or navigating the file system (NTFS, EXT4, etc.).
    #[error("File system error: {0}")]
    FileSystem(String),

    /// Error extracting or analyzing Windows Registry hives.
    #[error("Windows Registry error: {0}")]
    WindowsRegistry(String),

    /// Configuration or options error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Generic or descriptive inspection failure message.
    #[error("Inspection error: {0}")]
    Other(String),
}

impl VmSpectError {
    /// Builds a component error while preserving the original OS error for missing paths.
    pub(crate) fn from_disk_component_io(
        descriptor_path: &Path,
        declared_name: &str,
        resolved_path: &Path,
        component_type: &str,
        operation: &str,
        source: std::io::Error,
    ) -> Self {
        if source.kind() == std::io::ErrorKind::NotFound {
            Self::MissingDiskComponent {
                descriptor_path: descriptor_path.display().to_string(),
                declared_name: declared_name.to_string(),
                resolved_path: resolved_path.display().to_string(),
                component_type: component_type.to_string(),
                source,
            }
        } else {
            let message = format!(
                "Could not {operation} {component_type} '{declared_name}' referenced by '{}'. Resolved path: '{}': {source}",
                descriptor_path.display(),
                resolved_path.display(),
            );
            Self::Io(std::io::Error::new(source.kind(), message))
        }
    }
}

impl From<String> for VmSpectError {
    fn from(msg: String) -> Self {
        VmSpectError::Other(msg)
    }
}

impl From<&str> for VmSpectError {
    fn from(msg: &str) -> Self {
        VmSpectError::Other(msg.to_string())
    }
}

/// Standard `Result` alias used across the `vmspect` library.
pub type Result<T> = std::result::Result<T, VmSpectError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err_io = VmSpectError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(err_io.to_string().contains("I/O error"));

        let err_cancel = VmSpectError::Cancelled;
        assert_eq!(
            err_cancel.to_string(),
            "Inspection was cancelled by the user"
        );

        let err_other: VmSpectError = "something failed".into();
        assert_eq!(err_other.to_string(), "Inspection error: something failed");
    }
}
