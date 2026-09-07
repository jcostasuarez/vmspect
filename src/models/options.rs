//! Configuration options, progress events and the final inspection report.

use crate::models::image::{ImageInfo, Stats};
use crate::models::partition::{OperatingSystem, Partition, PartitionScheme};
use crate::models::software::{GuestInfo, Program};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Reusable cancellation token based on atomic flags.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    inner: Arc<AtomicBool>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    /// Creates a new cancellation token in the not-cancelled state (`false`).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a token from an existing `Arc<AtomicBool>`.
    pub fn from_arc(inner: Arc<AtomicBool>) -> Self {
        Self { inner }
    }

    /// Requests cancellation of the associated tasks.
    pub fn cancel(&self) {
        self.inner.store(true, Ordering::Release);
    }

    /// Indicates whether cancellation has been requested (thread-safe lock-free read with Acquire order).
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    /// Returns a reference to the inner `Arc<AtomicBool>`.
    pub fn as_arc(&self) -> &Arc<AtomicBool> {
        &self.inner
    }

    /// Clones the inner `Arc<AtomicBool>`.
    pub fn clone_arc(&self) -> Arc<AtomicBool> {
        self.inner.clone()
    }
}

/// Immutable snapshot of the progress for external inspection or serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    /// Global completion percentage (0..=100).
    pub percentage: u8,
    /// Numeric identifier of the current stage.
    pub stage_id: u8,
    /// Number of completed tasks.
    pub completed_tasks: usize,
    /// Total number of scheduled tasks.
    pub total_tasks: usize,
    /// Bytes read or processed.
    pub bytes_processed: u64,
    /// Total virtual or expected bytes.
    pub total_bytes: u64,
    /// Indicates whether the analysis has been cancelled.
    pub cancelled: bool,
}

/// Atomic, lock-free metrics and progress shareable between threads.
#[derive(Debug)]
pub struct InspectionProgress {
    /// Total estimated or registered tasks.
    pub total_tasks: AtomicUsize,
    /// Completed tasks.
    pub completed_tasks: AtomicUsize,
    /// Total bytes processed.
    pub bytes_processed: AtomicU64,
    /// Total estimated or known bytes.
    pub total_bytes: AtomicU64,
    /// Completion percentage (0..=100).
    pub percentage: AtomicU8,
    /// Numeric ID of the current stage.
    pub stage_id: AtomicU8,
    /// Atomic cancellation flag.
    pub cancelled: AtomicBool,
}

impl Default for InspectionProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl InspectionProgress {
    /// Creates a new instance with all counters set to zero.
    pub fn new() -> Self {
        Self {
            total_tasks: AtomicUsize::new(0),
            completed_tasks: AtomicUsize::new(0),
            bytes_processed: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            percentage: AtomicU8::new(0),
            stage_id: AtomicU8::new(0),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Creates a new instance linked to an external cancellation token.
    pub fn with_cancellation_token(token: Option<&Arc<AtomicBool>>) -> Self {
        let cancelled = if let Some(t) = token {
            AtomicBool::new(t.load(Ordering::Acquire))
        } else {
            AtomicBool::new(false)
        };
        Self {
            total_tasks: AtomicUsize::new(0),
            completed_tasks: AtomicUsize::new(0),
            bytes_processed: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            percentage: AtomicU8::new(0),
            stage_id: AtomicU8::new(0),
            cancelled,
        }
    }

    /// Returns the current completion percentage as a floating-point value `[0.0, 100.0]`.
    /// Low-cost lock-free operation based on atomic loads with Relaxed ordering.
    #[inline]
    pub fn completion_percentage(&self) -> f32 {
        let pct = self.percentage.load(Ordering::Relaxed);
        let total = self.total_tasks.load(Ordering::Relaxed);
        if total > 0 {
            let done = self.completed_tasks.load(Ordering::Relaxed);
            let calc = (done as f32 / total as f32) * 100.0;
            calc.clamp(pct as f32, 100.0)
        } else {
            (pct.min(100)) as f32
        }
    }

    /// Indicates whether the analysis has received a cancellation signal (lock-free, Acquire).
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Signals cancellation of the analysis (Release).
    #[inline]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Sets the global progress percentage (0..=100).
    #[inline]
    pub fn set_percentage(&self, pct: u8) {
        self.percentage.store(pct.min(100), Ordering::Relaxed);
    }

    /// Sets the identifier of the current stage.
    #[inline]
    pub fn set_stage_id(&self, stage: u8) {
        self.stage_id.store(stage, Ordering::Relaxed);
    }

    /// Returns the identifier of the current stage.
    #[inline]
    pub fn stage_id(&self) -> u8 {
        self.stage_id.load(Ordering::Relaxed)
    }

    /// Atomically adds to the bytes processed counter.
    #[inline]
    pub fn add_bytes_processed(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Returns the total number of bytes processed so far.
    #[inline]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    /// Sets the expected total byte size for the analysis.
    #[inline]
    pub fn set_total_bytes(&self, total: u64) {
        self.total_bytes.store(total, Ordering::Relaxed);
    }

    /// Returns the total estimated bytes.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Configures the total number of estimated tasks in the work plan.
    #[inline]
    pub fn set_total_tasks(&self, total: usize) {
        self.total_tasks.store(total, Ordering::Relaxed);
    }

    /// Returns the total number of planned tasks.
    #[inline]
    pub fn total_tasks(&self) -> usize {
        self.total_tasks.load(Ordering::Relaxed)
    }

    /// Increments the completed-tasks counter by one.
    #[inline]
    pub fn increment_completed_tasks(&self) {
        self.completed_tasks.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of tasks completed so far.
    #[inline]
    pub fn completed_tasks(&self) -> usize {
        self.completed_tasks.load(Ordering::Relaxed)
    }

    /// Returns an immutable snapshot of the progress state.
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            percentage: self.percentage.load(Ordering::Relaxed),
            stage_id: self.stage_id.load(Ordering::Relaxed),
            completed_tasks: self.completed_tasks.load(Ordering::Relaxed),
            total_tasks: self.total_tasks.load(Ordering::Relaxed),
            bytes_processed: self.bytes_processed.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            cancelled: self.cancelled.load(Ordering::Acquire),
        }
    }
}

/// Execution options passed to the inspection engine.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Options {
    /// If `true`, disables collection of installed applications (`--no-apps`).
    pub no_apps: bool,
    /// If `true`, disables collection of operating system information (`--no-system`).
    pub no_system: bool,
    /// If `true`, forces reading of the `SYSTEM` hive in addition to `SOFTWARE` on Windows.
    pub include_system: bool,
    /// Explicit path to the `qemu-nbd` binary. If `None`, it is searched automatically.
    pub qemu_nbd: Option<PathBuf>,
    /// Chunk size (bytes) used by the read cache. `None` sets the automatic optimal size.
    pub chunk_size: Option<u64>,
    /// If `true`, forces the use of `qemu-nbd` even if the format admits native reading in Rust.
    pub force_nbd: bool,
    /// Specifies the path to a UNIX domain socket (`--socket-path` / `-k` in qemu-nbd) instead of
    /// the default loopback TCP port.
    pub unix_socket: Option<PathBuf>,
    /// Passes arbitrary additional CLI arguments/flags to the `qemu-nbd` subprocess
    /// (e.g. cache optimizations, `--detect-zeroes`, etc.).
    pub extra_nbd_args: Vec<String>,
    /// Maximum wait time for the `qemu-nbd` server to be ready and accept connections
    /// (TCP or UNIX) during the initial handshake.
    pub connection_timeout: Option<Duration>,
    /// Flag to optionally include `--persistent`. Defaults to `false`.
    pub nbd_persistent: bool,
    /// Optional atomic cancellation token to abort the inspection early.
    #[serde(skip)]
    pub cancel_token: Option<Arc<AtomicBool>>,
}

/// Alias for [`Options`] under the `InspectionOptions` naming.
pub type InspectionOptions = Options;

impl Options {
    /// Indicates whether installed-application analysis should run (returns `!self.no_apps`).
    #[inline]
    pub fn should_analyze_apps(&self) -> bool {
        !self.no_apps
    }

    /// Indicates whether operating-system information analysis should run (returns `!self.no_system`).
    #[inline]
    pub fn should_analyze_system(&self) -> bool {
        !self.no_system
    }

    /// Sets the explicit path to the `qemu-nbd` binary.
    pub fn with_qemu_nbd(mut self, path: PathBuf) -> Self {
        self.qemu_nbd = Some(path);
        self
    }

    /// Configures whether the `qemu-nbd` backend should be forced.
    pub fn with_force_nbd(mut self, force: bool) -> Self {
        self.force_nbd = force;
        self
    }

    /// Sets the path to a UNIX domain socket (`-k`) for `qemu-nbd` communication.
    pub fn with_unix_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.unix_socket = Some(path.into());
        self
    }

    /// Sets additional CLI arguments/flags for the `qemu-nbd` subprocess.
    pub fn with_extra_nbd_args(mut self, args: Vec<String>) -> Self {
        self.extra_nbd_args = args;
        self
    }

    /// Defines the maximum wait time for the `qemu-nbd` server to accept the initial connection.
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = Some(timeout);
        self
    }

    /// Configures whether `qemu-nbd` should run with the `--persistent` flag.
    pub fn with_nbd_persistent(mut self, persistent: bool) -> Self {
        self.nbd_persistent = persistent;
        self
    }

    /// Assigns or replaces the atomic cancellation token.
    pub fn with_cancel_token(mut self, token: Arc<AtomicBool>) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Assigns or replaces the cancellation token via [`CancellationToken`].
    pub fn with_cancellation_token(mut self, token: &CancellationToken) -> Self {
        self.cancel_token = Some(token.clone_arc());
        self
    }
}

/// Progress event emitted periodically to external consumers (CLI or Tauri UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionProgressEvent {
    /// Global completion percentage (0..=100).
    pub percentage: u8,
    /// Short name of the current phase or task (e.g. "Reading MBR/GPT...", "Analyzing NTFS...").
    pub stage: String,
    /// Optional additional technical information about the progress.
    pub detail: Option<String>,
}

/// Complete and consolidated inspection report of the virtual disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionReport {
    /// Information about the inspected image file.
    pub image: ImageInfo,
    /// Detected partition table scheme.
    pub scheme: PartitionScheme,
    /// List of identified partitions.
    pub partitions: Vec<Partition>,
    /// General classification of the detected operating system.
    pub operating_system: OperatingSystem,
    /// Detailed metadata of the installed OS.
    pub guest_info: GuestInfo,
    /// List of structured programs found on the system (Name, Version, Publisher).
    pub installed_programs: Vec<Program>,
    /// Non-fatal warnings collected during the inspection (e.g. a Windows
    /// Registry that was dirty or damaged and from which we gracefully
    /// degraded without aborting the rest of the pipeline).
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Performance metrics associated with the inspection.
    pub stats: Stats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_defaults() {
        let opts = Options::default();
        assert!(!opts.no_apps);
        assert!(!opts.no_system);
        assert!(opts.should_analyze_apps());
        assert!(opts.should_analyze_system());
    }

    #[test]
    fn test_options_no_apps() {
        let opts = Options {
            no_apps: true,
            ..Options::default()
        };
        assert!(!opts.should_analyze_apps());
        assert!(opts.should_analyze_system());
    }

    #[test]
    fn test_options_no_system() {
        let opts = Options {
            no_system: true,
            ..Options::default()
        };
        assert!(opts.should_analyze_apps());
        assert!(!opts.should_analyze_system());
    }

    #[test]
    fn test_options_nbd_advanced() {
        let opts = Options::default()
            .with_unix_socket("/tmp/qemu-test.sock")
            .with_extra_nbd_args(vec!["--cache=none".into(), "--detect-zeroes=on".into()])
            .with_connection_timeout(Duration::from_secs(10))
            .with_nbd_persistent(true);

        assert_eq!(opts.unix_socket, Some(PathBuf::from("/tmp/qemu-test.sock")));
        assert_eq!(
            opts.extra_nbd_args,
            vec!["--cache=none".to_string(), "--detect-zeroes=on".to_string()]
        );
        assert_eq!(opts.connection_timeout, Some(Duration::from_secs(10)));
        assert!(opts.nbd_persistent);
    }
}
