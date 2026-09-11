//! Configuration options, progress events and the final inspection report.

use crate::error::VmSpectError;
use crate::models::image::{ImageInfo, Stats};
use crate::models::partition::{OperatingSystem, Partition, PartitionScheme};
use crate::models::software::{GuestInfo, GuestTools, Program};
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
    /// Completion percentage (0..=100). When tasks are scheduled, it is derived from
    /// `completed_tasks / total_tasks * 100`.
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
    // Keeps an externally supplied cancellation token observable by snapshots.
    cancellation_token: Option<Arc<AtomicBool>>,
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
            cancellation_token: None,
        }
    }

    /// Creates a new instance linked to an external cancellation token.
    pub fn with_cancellation_token(token: Option<&Arc<AtomicBool>>) -> Self {
        let cancelled = token
            .map(|token| token.load(Ordering::Acquire))
            .unwrap_or(false);
        Self {
            total_tasks: AtomicUsize::new(0),
            completed_tasks: AtomicUsize::new(0),
            bytes_processed: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            percentage: AtomicU8::new(0),
            stage_id: AtomicU8::new(0),
            cancelled: AtomicBool::new(cancelled),
            cancellation_token: token.cloned(),
        }
    }

    #[inline]
    fn task_completion_percentage(completed: usize, total: usize) -> u8 {
        if total == 0 {
            return 0;
        }

        ((completed.min(total) as u128 * 100) / total as u128) as u8
    }

    /// Returns the current completion percentage as a floating-point value `[0.0, 100.0]`.
    ///
    /// When a task plan is configured, this is calculated from completed and total tasks.
    /// The operation uses only atomic loads and never blocks inspection workers.
    #[inline]
    pub fn completion_percentage(&self) -> f32 {
        let total = self.total_tasks.load(Ordering::Relaxed);
        if total == 0 {
            return self.percentage.load(Ordering::Relaxed) as f32;
        }

        let completed = self.completed_tasks.load(Ordering::Relaxed);
        if completed >= total {
            100.0
        } else {
            // Keep a partially cancelled batch below 100% even when f32 rounding is coarse.
            (((completed as f64 / total as f64) * 100.0).min(99.999_99)) as f32
        }
    }

    /// Indicates whether the analysis has received a cancellation signal (lock-free, Acquire).
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .cancellation_token
                .as_ref()
                .map(|token| token.load(Ordering::Acquire))
                .unwrap_or(false)
    }

    /// Signals cancellation of the analysis and its linked token, if any (Release).
    #[inline]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(token) = &self.cancellation_token {
            token.store(true, Ordering::Release);
        }
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

    /// Resets the aggregate metrics before a new inspection batch starts.
    ///
    /// The cancellation state remains linked to its configured token, so a token that was
    /// already cancelled still prevents a new batch from starting work.
    pub(crate) fn reset_for_batch(&self, total: usize) {
        self.completed_tasks.store(0, Ordering::Relaxed);
        self.bytes_processed.store(0, Ordering::Relaxed);
        self.total_bytes.store(0, Ordering::Relaxed);
        self.percentage.store(0, Ordering::Relaxed);
        self.stage_id.store(0, Ordering::Relaxed);
        self.cancelled.store(false, Ordering::Release);
        self.total_tasks.store(total, Ordering::Relaxed);
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
        let completed = self
            .completed_tasks
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let total = self.total_tasks.load(Ordering::Relaxed);
        if total > 0 {
            self.percentage.store(
                Self::task_completion_percentage(completed, total),
                Ordering::Relaxed,
            );
        }
    }

    /// Returns the number of tasks completed so far.
    #[inline]
    pub fn completed_tasks(&self) -> usize {
        self.completed_tasks.load(Ordering::Relaxed)
    }

    /// Returns an immutable snapshot of the progress state without taking locks.
    pub fn snapshot(&self) -> ProgressSnapshot {
        let total_tasks = self.total_tasks.load(Ordering::Relaxed);
        let completed_tasks = self.completed_tasks.load(Ordering::Relaxed);
        let percentage = if total_tasks > 0 {
            Self::task_completion_percentage(completed_tasks, total_tasks)
        } else {
            self.percentage.load(Ordering::Relaxed)
        };

        ProgressSnapshot {
            percentage,
            stage_id: self.stage_id.load(Ordering::Relaxed),
            completed_tasks,
            total_tasks,
            bytes_processed: self.bytes_processed.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            cancelled: self.is_cancelled(),
        }
    }
}

/// Execution options passed to the inspection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Maximum simultaneous `qemu-nbd` sessions used by a batch. Native readers are not limited.
    pub nbd_max_sessions: usize,
}

/// Alias for [`Options`] under the `InspectionOptions` naming.
pub type InspectionOptions = Options;

impl Default for Options {
    fn default() -> Self {
        Self {
            no_apps: false,
            no_system: false,
            include_system: false,
            qemu_nbd: None,
            chunk_size: None,
            force_nbd: false,
            unix_socket: None,
            extra_nbd_args: Vec::new(),
            connection_timeout: None,
            nbd_persistent: false,
            cancel_token: None,
            nbd_max_sessions: 2,
        }
    }
}

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

    /// Sets the maximum number of simultaneous `qemu-nbd` sessions. Zero is treated as one.
    pub fn with_nbd_max_sessions(mut self, max_sessions: usize) -> Self {
        self.nbd_max_sessions = max_sessions.max(1);
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

/// Lightweight initial view of an inspection, suitable for GUI and IPC lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionSummary {
    /// Path to the inspected image.
    pub path: PathBuf,
    /// Detected operating system.
    pub operating_system: OperatingSystem,
    /// Detected guest integration tools, if any.
    pub guest_tools: Option<GuestTools>,
    /// Inspection duration in milliseconds.
    pub duration_ms: u64,
    /// Read backend used during inspection.
    pub access_mode: String,
    /// Non-fatal inspection warnings.
    pub warnings: Vec<String>,
}

/// Per-image error returned by a tolerant inspection batch.
#[derive(Debug)]
pub struct ImageInspectionError {
    /// Path of the image that could not be inspected.
    pub path: PathBuf,
    /// Original inspection error.
    pub error: VmSpectError,
}

impl Serialize for ImageInspectionError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ImageInspectionError", 2)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("error", &self.error.to_string())?;
        state.end()
    }
}

/// Successful reports and per-image failures from an inspection batch.
#[derive(Debug, Serialize)]
pub struct BatchResult {
    /// Reports for images inspected successfully, in input order.
    pub reports: Vec<InspectionReport>,
    /// Errors for images that could not be inspected, in input order.
    pub errors: Vec<ImageInspectionError>,
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

impl InspectionReport {
    /// Produces the lightweight initial view without installed-program data.
    pub fn summary(&self) -> InspectionSummary {
        InspectionSummary {
            path: self.image.path.clone(),
            operating_system: self.operating_system,
            guest_tools: self.guest_info.guest_tools.clone(),
            duration_ms: self.stats.duration_ms,
            access_mode: self.stats.access_mode.clone(),
            warnings: self.warnings.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_cancellation_token_is_visible_in_snapshots() {
        let token = Arc::new(AtomicBool::new(false));
        let progress = InspectionProgress::with_cancellation_token(Some(&token));

        token.store(true, Ordering::Release);
        assert!(progress.is_cancelled());
        assert!(progress.snapshot().cancelled);

        let token = Arc::new(AtomicBool::new(false));
        let progress = InspectionProgress::with_cancellation_token(Some(&token));
        progress.cancel();
        assert!(token.load(Ordering::Acquire));
    }

    #[test]
    fn test_options_defaults() {
        let opts = Options::default();
        assert!(!opts.no_apps);
        assert!(!opts.no_system);
        assert!(opts.should_analyze_apps());
        assert!(opts.should_analyze_system());
        assert!(!opts.force_nbd);
        assert_eq!(opts.nbd_max_sessions, 2);
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
    fn test_summary_omits_installed_programs() {
        let report = InspectionReport {
            image: ImageInfo {
                path: PathBuf::from("vm.raw"),
                format: "raw".to_string(),
                virtual_size: 1,
                actual_size: 1,
                hypervisor: crate::models::Hypervisor::Unknown,
            },
            scheme: PartitionScheme::None,
            partitions: Vec::new(),
            operating_system: OperatingSystem::Unknown,
            guest_info: GuestInfo::default(),
            installed_programs: vec![Program {
                name: "secret app".to_string(),
                ..Program::default()
            }],
            warnings: vec!["warning".to_string()],
            stats: Stats {
                access_mode: "native".to_string(),
                duration_ms: 12,
                ..Stats::default()
            },
        };
        let summary = report.summary();
        let json = serde_json::to_value(summary).unwrap();
        assert!(json.get("installed_programs").is_none());
        assert_eq!(json["path"], "vm.raw");
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
