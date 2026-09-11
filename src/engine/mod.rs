//! Concurrency processing engine, task coordination and Graceful Shutdown.

use crate::error::{Result, VmSpectError};
use crate::models::options::{
    BatchResult, ImageInspectionError, InspectionProgress, InspectionProgressEvent,
    InspectionSummary, Options,
};
use crate::models::traits::AnalysisResult;
use crate::models::InspectionReport;
use crate::operation::acquire_active_operation;
use crate::parsers;
use crate::vms;
use crate::vms::stream::{identify_image, DiskReader};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::Barrier;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// Concurrent processor with Graceful Shutdown support and lock-free progress reporting.
pub struct ConcurrentProcessor;

impl ConcurrentProcessor {
    /// Runs a series of tasks in parallel using a worker pool with Graceful Shutdown support
    /// and partial-result preservation.
    ///
    /// # Graceful Shutdown guarantees:
    /// 1. If `cancel_token` is active before starting or becomes active during execution:
    ///    - No new pending tasks are pulled from the queue or started.
    ///    - Workers currently processing a task finish safely and release their resources.
    /// 2. The function strictly waits for **all** active threads to finish via `.join()`.
    /// 3. **Partial Result Preservation**: If cancellation is requested, the function **does not**
    ///    discard results already completed; it returns the list of all successfully processed
    ///    results up to the moment of cancellation.
    pub fn process_in_parallel<T, R, F>(
        items: Vec<T>,
        cancel_token: Option<Arc<AtomicBool>>,
        progress: Option<Arc<InspectionProgress>>,
        max_workers: usize,
        f: F,
    ) -> Result<Vec<R>>
    where
        T: Send + 'static,
        R: Send + 'static,
        F: Fn(T) -> Result<R> + Send + Sync + 'static,
    {
        if items.is_empty() {
            return Ok(Vec::new());
        }

        // If already cancelled at the start, do not spawn threads and return an empty vector
        if let Some(ref cancel) = cancel_token {
            if cancel.load(Ordering::Acquire) {
                return Ok(Vec::new());
            }
        }

        if let Some(ref p) = progress {
            p.set_total_tasks(items.len());
        }

        let total_items = items.len();
        let num_workers = max_workers.max(1).min(total_items).min(32);

        let queue = Arc::new(Mutex::new(
            items
                .into_iter()
                .enumerate()
                .collect::<VecDeque<(usize, T)>>(),
        ));
        let results = Arc::new(Mutex::new(Vec::<(usize, R)>::with_capacity(total_items)));
        let stored_error = Arc::new(Mutex::new(None::<VmSpectError>));
        let f = Arc::new(f);

        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(num_workers);

        for worker_id in 0..num_workers {
            let queue_clone = Arc::clone(&queue);
            let results_clone = Arc::clone(&results);
            let error_clone = Arc::clone(&stored_error);
            let cancel_clone = cancel_token.clone();
            let progress_clone = progress.clone();
            let f_clone = Arc::clone(&f);

            let builder = std::thread::Builder::new().name(format!("vmspect-worker-{}", worker_id));

            let handle = builder.spawn(move || {
                loop {
                    // 1. Check cancellation before dequeuing a new task
                    if let Some(ref cancel) = cancel_clone {
                        if cancel.load(Ordering::Acquire) {
                            break;
                        }
                    }

                    // 2. Pull the next task
                    let task = {
                        let mut q = queue_clone.lock().unwrap_or_else(|e| e.into_inner());
                        q.pop_front()
                    };

                    let Some((idx, item)) = task else {
                        break;
                    };

                    // 3. Check cancellation immediately before starting processing
                    if let Some(ref cancel) = cancel_clone {
                        if cancel.load(Ordering::Acquire) {
                            break;
                        }
                    }

                    // 4. Run the task safely and release resources normally
                    let result = f_clone(item);

                    match result {
                        Ok(value) => {
                            let mut res = results_clone.lock().unwrap_or_else(|e| e.into_inner());
                            res.push((idx, value));
                            if let Some(ref p) = progress_clone {
                                p.increment_completed_tasks();
                            }
                        }
                        Err(e) => {
                            if !matches!(e, VmSpectError::Cancelled) {
                                let mut err_guard =
                                    error_clone.lock().unwrap_or_else(|e| e.into_inner());
                                if err_guard.is_none() {
                                    *err_guard = Some(e);
                                }
                            }
                            break;
                        }
                    }
                }
            });

            if let Ok(h) = handle {
                handles.push(h);
            }
        }

        // 5. Graceful Shutdown: rigorously wait for every thread to finish
        for handle in handles {
            let _ = handle.join();
        }

        // 6. If there was an error unrelated to cancellation and no active cancellation
        let was_cancelled = cancel_token
            .as_ref()
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(false);

        if !was_cancelled {
            if let Some(err) = stored_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                return Err(err);
            }
        }

        // 7. Preserve and return all completed results (including those finished during shutdown)
        let mut res = Arc::try_unwrap(results)
            .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
            .unwrap_or_else(|m| std::mem::take(&mut *m.lock().unwrap_or_else(|e| e.into_inner())));
        res.sort_by_key(|(idx, _)| *idx);
        Ok(res.into_iter().map(|(_, val)| val).collect())
    }

    /// Processes and inspects a set of disk images in parallel.
    ///
    /// Preserves the [`InspectionReport`]s that completed even if the operation is cancelled.
    pub fn inspect_images<P: AsRef<Path> + Send + 'static>(
        paths: Vec<P>,
        options: &Options,
        max_workers: usize,
    ) -> Result<Vec<InspectionReport>> {
        let options = options.clone();
        let cancel = options.cancel_token.clone();
        Self::process_in_parallel(paths, cancel, None, max_workers, move |path| {
            let engine = InspectionEngine::new(options.clone());
            engine.inspect(path.as_ref())
        })
    }
}

#[cfg(test)]
#[derive(Debug)]
struct BatchTestPause {
    entered: Arc<Barrier>,
    resume: Arc<Barrier>,
}

#[cfg(test)]
impl BatchTestPause {
    fn wait(&self) {
        self.entered.wait();
        self.resume.wait();
    }
}

/// Inspection engine with concurrency support, lock-free metrics and clean shutdown (Graceful Shutdown).
#[derive(Debug, Clone)]
pub struct InspectionEngine {
    options: Options,
    progress: Arc<InspectionProgress>,
    cancel_token: Arc<AtomicBool>,
    #[cfg(test)]
    batch_test_pause: Option<Arc<BatchTestPause>>,
}

impl Default for InspectionEngine {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl InspectionEngine {
    /// Creates a new inspection engine with the provided options.
    pub fn new(options: Options) -> Self {
        let cancel_token = options
            .cancel_token
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

        let progress = Arc::new(InspectionProgress::with_cancellation_token(Some(
            &cancel_token,
        )));

        let mut options = options;
        options.cancel_token = Some(cancel_token.clone());

        Self {
            options,
            progress,
            cancel_token,
            #[cfg(test)]
            batch_test_pause: None,
        }
    }

    /// Constructor alias for fluent initialization with custom options.
    pub fn with_options(options: Options) -> Self {
        Self::new(options)
    }

    /// Returns the shared atomic progress structure ([`InspectionProgress`]).
    ///
    /// Call this before [`Self::inspect_batch`] and poll the returned [`Arc`] from a GUI, service,
    /// or timer. Snapshot and counter reads use atomics and do not block inspection workers.
    pub fn progress(&self) -> Arc<InspectionProgress> {
        self.progress.clone()
    }

    /// Direct query of the current completion percentage `[0.0, 100.0]`.
    /// Thread-safe, low-cost, lock-free operation.
    pub fn completion_percentage(&self) -> f32 {
        self.progress.completion_percentage()
    }

    /// Requests immediate and clean cancellation of the inspection.
    pub fn cancel(&self) {
        self.cancel_token.store(true, Ordering::Release);
        self.progress.cancel();
    }

    /// Indicates whether the current analysis has been cancelled (lock-free).
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.load(Ordering::Acquire) || self.progress.is_cancelled()
    }

    /// Runs the inspection of the disk image synchronously.
    pub fn inspect(&self, image_path: &Path) -> Result<InspectionReport> {
        self.run_inspection(image_path, None)
    }

    /// Runs the inspection notifying structured events to a callback.
    pub fn inspect_with_progress<F>(
        &self,
        image_path: &Path,
        mut callback: F,
    ) -> Result<InspectionReport>
    where
        F: FnMut(InspectionProgressEvent),
    {
        self.run_inspection(image_path, Some(&mut callback))
    }

    /// Starts the inspection in a dedicated background thread, returning a [`JoinHandle`].
    ///
    /// # Errors
    ///
    /// Returns [`VmSpectError::Io`] if the operating system cannot create a new thread
    /// (e.g. due to resource exhaustion). The actual inspection, once started, reports
    /// its errors through the inner [`Result`] of the [`JoinHandle`].
    pub fn inspect_background(
        &self,
        image_path: &Path,
    ) -> Result<std::thread::JoinHandle<Result<InspectionReport>>> {
        let engine = self.clone();
        let path = image_path.to_path_buf();
        std::thread::Builder::new()
            .name("vmspect-bg-inspect".to_string())
            .spawn(move || engine.inspect(&path))
            .map_err(VmSpectError::Io)
    }

    /// Inspects a set of disk images without allowing one image failure to abort the batch.
    ///
    /// Successful reports and per-image errors preserve input order. Cancellation stops accepting
    /// new paths while retaining all results completed before and during shutdown. Obtain
    /// [`InspectionProgress`] with [`Self::progress`] before starting this method, then poll its
    /// lock-free [`InspectionProgress::snapshot`] or task counters from another thread or task.
    /// Each image that finishes, including one that returns an error, increments
    /// `completed_tasks`. Batch progress aggregates image counts; its stage and byte fields are
    /// reset for the batch but are not aggregated from individual workers. This method never
    /// invokes user callbacks or UI/IPC code.
    pub fn inspect_batch<P: AsRef<Path> + Send + 'static>(
        &self,
        paths: Vec<P>,
        max_workers: usize,
    ) -> Result<BatchResult> {
        let _guard = acquire_active_operation()?;
        let paths = paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect::<Vec<_>>();
        let total = paths.len();
        self.progress.reset_for_batch(total);
        if total == 0 {
            return Ok(BatchResult {
                reports: Vec::new(),
                errors: Vec::new(),
            });
        }

        let queue = Arc::new(Mutex::new(
            paths.into_iter().enumerate().collect::<VecDeque<_>>(),
        ));
        let outcomes = Arc::new(Mutex::new(Vec::with_capacity(total)));
        let options = self.options.clone();
        let cancel = self.cancel_token.clone();
        let progress = self.progress.clone();
        #[cfg(test)]
        let batch_test_pause = self.batch_test_pause.clone();
        let workers = max_workers.max(1).min(total).min(32);
        let mut handles = Vec::with_capacity(workers);
        for worker_id in 0..workers {
            let queue = queue.clone();
            let outcomes = outcomes.clone();
            let options = options.clone();
            let cancel = cancel.clone();
            let progress = progress.clone();
            #[cfg(test)]
            let batch_test_pause = batch_test_pause.clone();
            let handle = std::thread::Builder::new()
                .name(format!("vmspect-batch-{worker_id}"))
                .spawn(move || {
                    #[cfg(test)]
                    let mut batch_test_pause = batch_test_pause;

                    loop {
                        if cancel.load(Ordering::Acquire) {
                            break;
                        }
                        let Some((index, path)) =
                            queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front()
                        else {
                            break;
                        };
                        if cancel.load(Ordering::Acquire) {
                            break;
                        }

                        let result = InspectionEngine::new(options.clone()).inspect(&path);
                        outcomes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push((index, path, result));
                        progress.increment_completed_tasks();
                        #[cfg(test)]
                        if let Some(pause) = batch_test_pause.take() {
                            pause.wait();
                        }
                    }
                });

            match handle {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(VmSpectError::Io(error));
                }
            }
        }

        for handle in handles {
            let _ = handle.join();
        }

        let mut outcomes = Arc::try_unwrap(outcomes)
            .map(|outcomes| outcomes.into_inner().unwrap_or_else(|e| e.into_inner()))
            .unwrap_or_else(|outcomes| {
                std::mem::take(&mut *outcomes.lock().unwrap_or_else(|e| e.into_inner()))
            });
        outcomes.sort_by_key(|(index, _, _)| *index);

        let mut reports = Vec::new();
        let mut errors = Vec::new();
        for (_, path, outcome) in outcomes {
            match outcome {
                Ok(report) => reports.push(report),
                Err(error) => errors.push(ImageInspectionError { path, error }),
            }
        }

        Ok(BatchResult { reports, errors })
    }

    /// Runs a lightweight inspection suitable for an initial GUI/IPC listing.
    pub fn inspect_summary(&self, image_path: &Path) -> Result<InspectionSummary> {
        let mut options = self.options.clone();
        options.no_apps = true;
        InspectionEngine::new(options)
            .inspect(image_path)
            .map(|report| report.summary())
    }

    fn run_inspection(
        &self,
        image_path: &Path,
        mut callback: Option<&mut dyn FnMut(InspectionProgressEvent)>,
    ) -> Result<InspectionReport> {
        let start = Instant::now();

        if let Err(error) = std::fs::metadata(image_path) {
            if error.kind() == std::io::ErrorKind::NotFound {
                return Err(VmSpectError::ImageNotFound(
                    image_path.display().to_string(),
                ));
            }
            return Err(VmSpectError::Io(error));
        }

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        let mut effective_options = self.options.clone();
        effective_options.cancel_token = Some(self.cancel_token.clone());

        // --- STAGE 1 (5% - 15%): Image identification ---
        self.progress.set_stage_id(1);
        self.progress.set_percentage(5);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 5,
                stage: "Identifying disk image".into(),
                detail: Some(format!("Analyzing {}", image_path.display())),
            });
        }

        let image =
            identify_image(effective_options.qemu_nbd.as_deref(), image_path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    VmSpectError::ImageNotFound(image_path.display().to_string())
                } else {
                    VmSpectError::Io(error)
                }
            })?;
        let identification_duration_ms = start.elapsed().as_millis() as u64;

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        self.progress.set_total_bytes(image.virtual_size);
        self.progress.set_percentage(15);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 15,
                stage: "Initializing read backend".into(),
                detail: Some(format!(
                    "Format: {} | Hypervisor: {} | Size: {}",
                    image.format,
                    image.hypervisor.name(),
                    crate::models::format_bytes(image.virtual_size)
                )),
            });
        }

        if effective_options.force_nbd {
            if let Some(ref mut cb) = callback {
                cb(InspectionProgressEvent {
                    percentage: 15,
                    stage: "Explicit external backend enabled".into(),
                    detail: Some(
                        "Warning: qemu-nbd will be launched as an explicitly requested, read-only helper. It does not mount or attach the image in the host OS."
                            .into(),
                    ),
                });
            }
        }
        let backend_started = Instant::now();
        let reader = DiskReader::open_with_options_diagnostic(&image, &effective_options)?;
        let backend_initialization_duration_ms = backend_started.elapsed().as_millis() as u64;
        tracing::info!(
            backend = reader.access_mode(),
            source_location = %reader.stats().source_location,
            "virtual image read backend initialized"
        );

        let chunk_size = effective_options
            .chunk_size
            .unwrap_or_else(|| reader.recommended_chunk_size());

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        // --- STAGE 2 (25% - 45%): Partition detection ---
        self.progress.set_stage_id(2);
        self.progress.set_percentage(25);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 25,
                stage: "Reading partition table".into(),
                detail: Some(format!(
                    "Access: {} | Chunk size: {}",
                    reader.access_mode(),
                    crate::models::format_bytes(chunk_size)
                )),
            });
        }

        let partition_started = Instant::now();
        let disk = vms::detector::detect_with_progress(
            &reader,
            Some(self.cancel_token.clone()),
            Some(self.progress.clone()),
        )
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::Interrupted && self.is_cancelled() {
                VmSpectError::Cancelled
            } else {
                VmSpectError::Io(error)
            }
        })?;
        let partition_detection_duration_ms = partition_started.elapsed().as_millis() as u64;

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        self.progress.set_percentage(45);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 45,
                stage: "Analyzing file systems".into(),
                detail: Some(format!(
                    "{} partitions found. OS detected: {:?}",
                    disk.partitions.len(),
                    disk.operating_system
                )),
            });
        }

        // --- STAGE 3 (55% - 85%): Operating system analysis ---
        self.progress.set_stage_id(3);
        self.progress.set_percentage(55);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 55,
                stage: format!("Analyzing operating system ({:?})", disk.operating_system),
                detail: Some("Starting system files / Registry scan".into()),
            });
        }

        // Graceful Degradation: a failure during the guest OS analysis
        // (e.g. dirty/corrupt Windows Registry) must NOT abort the
        // entire pipeline. It is logged as a warning and inspection
        // continues with already-collected image, partition and FS data.
        let guest_analysis_started = Instant::now();
        let result = if effective_options.should_analyze_system()
            || effective_options.should_analyze_apps()
        {
            let inspector = parsers::get_inspector(&disk.operating_system);
            match inspector.analyze(&reader, &disk.partitions, chunk_size, &effective_options) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!(
                        "Could not complete the guest OS analysis; continuing with image/partition data only: {}",
                        e
                    );
                    AnalysisResult {
                        warnings: vec![msg],
                        ..AnalysisResult::default()
                    }
                }
            }
        } else {
            AnalysisResult::default()
        };

        let guest_analysis_duration_ms = guest_analysis_started.elapsed().as_millis() as u64;
        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        // --- STAGE 4 (90% - 100%): Consolidation and report ---
        self.progress.set_stage_id(4);
        self.progress.set_percentage(90);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 90,
                stage: "Generating final report".into(),
                detail: Some(format!(
                    "{} programs/packages identified",
                    result.programs.len()
                )),
            });
        }

        let report_started = Instant::now();
        let mut stats = reader.stats();
        stats.identification_duration_ms = identification_duration_ms;
        stats.backend_initialization_duration_ms = backend_initialization_duration_ms;
        stats.partition_detection_duration_ms = partition_detection_duration_ms;
        stats.guest_analysis_duration_ms = guest_analysis_duration_ms;
        stats.report_generation_duration_ms = report_started.elapsed().as_millis() as u64;
        stats.duration_ms = start.elapsed().as_millis() as u64;
        tracing::info!(
            backend = %stats.access_mode,
            bytes_read = stats.bytes_read,
            read_operations = stats.read_operations,
            cache_hits = stats.cache_hits,
            identification_duration_ms = stats.identification_duration_ms,
            backend_initialization_duration_ms = stats.backend_initialization_duration_ms,
            partition_detection_duration_ms = stats.partition_detection_duration_ms,
            guest_analysis_duration_ms = stats.guest_analysis_duration_ms,
            report_generation_duration_ms = stats.report_generation_duration_ms,
            duration_ms = stats.duration_ms,
            "virtual image inspection completed"
        );

        let report = InspectionReport {
            image,
            scheme: disk.scheme,
            partitions: disk.partitions,
            operating_system: disk.operating_system,
            guest_info: result.guest_info,
            installed_programs: result.programs,
            warnings: result.warnings,
            stats,
        };

        self.progress.set_percentage(100);
        if let Some(ref mut cb) = callback {
            cb(InspectionProgressEvent {
                percentage: 100,
                stage: "Analysis completed successfully".into(),
                detail: Some(format!(
                    "Backend: {} | Reads: {} | Bytes: {} | Cache hits: {}",
                    report.stats.access_mode,
                    report.stats.read_operations,
                    crate::models::format_bytes(report.stats.bytes_read),
                    report.stats.cache_hits
                )),
            });
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_atomic_progress_metadata_and_percentage() {
        let prog = InspectionProgress::new();
        assert_eq!(prog.completion_percentage(), 0.0);
        assert!(!prog.is_cancelled());

        prog.set_percentage(50);
        assert_eq!(prog.completion_percentage(), 50.0);

        prog.set_total_tasks(10);
        prog.increment_completed_tasks();
        prog.increment_completed_tasks();
        assert_eq!(prog.completed_tasks(), 2);
        assert_eq!(prog.total_tasks(), 10);
        assert_eq!(prog.completion_percentage(), 20.0);

        prog.add_bytes_processed(2048);
        assert_eq!(prog.bytes_processed(), 2048);

        prog.set_total_bytes(4096);
        assert_eq!(prog.total_bytes(), 4096);

        prog.set_stage_id(3);
        assert_eq!(prog.stage_id(), 3);

        let snap = prog.snapshot();
        assert_eq!(snap.percentage, 20);
        assert_eq!(snap.stage_id, 3);
        assert_eq!(snap.completed_tasks, 2);
        assert_eq!(snap.total_tasks, 10);
        assert_eq!(snap.bytes_processed, 2048);
        assert_eq!(snap.total_bytes, 4096);
        assert!(!snap.cancelled);

        prog.reset_for_batch(4);
        let reset = prog.snapshot();
        assert_eq!(reset.percentage, 0);
        assert_eq!(reset.stage_id, 0);
        assert_eq!(reset.completed_tasks, 0);
        assert_eq!(reset.total_tasks, 4);
        assert_eq!(reset.bytes_processed, 0);
        assert_eq!(reset.total_bytes, 0);

        prog.cancel();
        assert!(prog.is_cancelled());
        assert!(prog.snapshot().cancelled);
    }

    #[test]
    fn test_concurrent_processor_normal_execution() {
        let items: Vec<u32> = (1..=20).collect();
        let cancel = Arc::new(AtomicBool::new(false));
        let prog = Arc::new(InspectionProgress::new());

        let results = ConcurrentProcessor::process_in_parallel(
            items.clone(),
            Some(cancel),
            Some(prog.clone()),
            4,
            |x| Ok(x * 2),
        )
        .expect("parallel processing successful");

        assert_eq!(results.len(), 20);
        for (i, &val) in results.iter().enumerate() {
            assert_eq!(val, (i as u32 + 1) * 2);
        }
        assert_eq!(prog.completed_tasks(), 20);
    }

    #[test]
    fn test_concurrent_processor_graceful_shutdown_cancellation() {
        let items: Vec<u32> = (1..=50).collect();
        let cancel = Arc::new(AtomicBool::new(false));
        let prog = Arc::new(InspectionProgress::new());

        let cancel_clone = cancel.clone();
        let prog_worker = prog.clone();
        let tasks_started = Arc::new(AtomicUsize::new(0));
        let tasks_started_clone = tasks_started.clone();

        let handle = std::thread::spawn(move || {
            ConcurrentProcessor::process_in_parallel(
                items,
                Some(cancel_clone),
                Some(prog_worker),
                4,
                move |_item| {
                    let num = tasks_started_clone.fetch_add(1, Ordering::SeqCst);
                    if num >= 2 {
                        sleep(Duration::from_millis(50));
                    }
                    Ok(())
                },
            )
        });

        // Deterministic wait (bounded by a safety timeout) until at least two
        // fast tasks have finished before cancelling. Avoids racing the clock,
        // which can fail intermittently under load.
        let wait_start = Instant::now();
        while prog.completed_tasks() < 2 && wait_start.elapsed() < Duration::from_secs(5) {
            sleep(Duration::from_millis(1));
        }
        cancel.store(true, Ordering::Release);

        let result = handle.join().expect("coordinator thread finished");
        let partial_results = result.expect("must preserve partial results");
        assert!(
            !partial_results.is_empty(),
            "Must preserve the completed results"
        );
        assert!(
            partial_results.len() < 50,
            "Must not process all items if cancelled"
        );

        let total_started = tasks_started.load(Ordering::SeqCst);
        assert!(
            total_started < 50,
            "Pending tasks must not have started after cancellation (started: {})",
            total_started
        );
    }

    #[test]
    fn test_batch_collects_image_errors_in_input_order() {
        let _operation_lock = crate::operation::lock_test_operation();
        let engine = InspectionEngine::new(Options::default());
        let result = engine
            .inspect_batch(vec!["missing-first.vmdk", "missing-second.vmdk"], 2)
            .unwrap();
        assert!(result.reports.is_empty());
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].path.ends_with("missing-first.vmdk"));
        assert!(result.errors[1].path.ends_with("missing-second.vmdk"));
        assert_eq!(engine.progress().completed_tasks(), 2);
    }

    #[test]
    fn test_batch_progress_can_be_polled_while_running_and_is_monotonic() {
        let _operation_lock = crate::operation::lock_test_operation();
        let pause = Arc::new(BatchTestPause {
            entered: Arc::new(Barrier::new(2)),
            resume: Arc::new(Barrier::new(2)),
        });
        let mut engine = InspectionEngine::new(Options::default());
        engine.batch_test_pause = Some(pause.clone());
        let engine = Arc::new(engine);
        let progress = engine.progress();
        let worker_engine = Arc::clone(&engine);
        let handle = std::thread::spawn(move || {
            worker_engine.inspect_batch(
                vec!["missing-poll-first.vmdk", "missing-poll-second.vmdk"],
                1,
            )
        });

        pause.entered.wait();
        let first = progress.snapshot();
        let second = progress.snapshot();
        assert!(!handle.is_finished());
        assert_eq!(first.total_tasks, 2);
        assert_eq!(first.completed_tasks, 1);
        assert_eq!(first.percentage, 50);
        assert_eq!(progress.completion_percentage(), 50.0);
        assert!(second.completed_tasks >= first.completed_tasks);
        assert!(second.percentage >= first.percentage);

        pause.resume.wait();
        let batch = handle
            .join()
            .expect("batch worker thread panicked")
            .expect("batch inspection succeeds despite image errors");
        let final_snapshot = progress.snapshot();
        assert_eq!(batch.reports.len(), 0);
        assert_eq!(batch.errors.len(), 2);
        assert!(final_snapshot.completed_tasks >= second.completed_tasks);
        assert_eq!(final_snapshot.total_tasks, 2);
        assert_eq!(final_snapshot.completed_tasks, 2);
        assert_eq!(final_snapshot.percentage, 100);
        assert_eq!(progress.completion_percentage(), 100.0);
    }

    #[test]
    fn test_batch_cancellation_preserves_partial_progress() {
        let _operation_lock = crate::operation::lock_test_operation();
        let pause = Arc::new(BatchTestPause {
            entered: Arc::new(Barrier::new(2)),
            resume: Arc::new(Barrier::new(2)),
        });
        let mut engine = InspectionEngine::new(Options::default());
        engine.batch_test_pause = Some(pause.clone());
        let engine = Arc::new(engine);
        let progress = engine.progress();
        let worker_engine = Arc::clone(&engine);
        let handle = std::thread::spawn(move || {
            worker_engine.inspect_batch(
                vec!["missing-cancel-first.vmdk", "missing-cancel-second.vmdk"],
                1,
            )
        });

        pause.entered.wait();
        let partial = progress.snapshot();
        assert_eq!(partial.total_tasks, 2);
        assert_eq!(partial.completed_tasks, 1);
        assert_eq!(partial.percentage, 50);

        engine.cancel();
        pause.resume.wait();
        let batch = handle
            .join()
            .expect("batch worker thread panicked")
            .expect("cancellation preserves completed batch outcomes");
        let final_snapshot = progress.snapshot();
        assert!(final_snapshot.cancelled);
        assert_eq!(batch.reports.len(), 0);
        assert_eq!(batch.errors.len(), 1);
        assert_eq!(final_snapshot.total_tasks, 2);
        assert_eq!(final_snapshot.completed_tasks, 1);
        assert_eq!(final_snapshot.percentage, 50);
        assert_eq!(progress.completion_percentage(), 50.0);
    }

    #[test]
    fn test_inspection_engine_progress_and_cancellation_api() {
        let options = Options::default();
        let engine = InspectionEngine::new(options);

        assert_eq!(engine.completion_percentage(), 0.0);
        assert!(!engine.is_cancelled());

        let prog = engine.progress();
        prog.set_percentage(75);
        assert_eq!(engine.completion_percentage(), 75.0);

        engine.cancel();
        assert!(engine.is_cancelled());
        assert!(engine.progress().is_cancelled());
    }
}
