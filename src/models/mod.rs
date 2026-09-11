//! Main module of domain data structures and traits.

pub mod image;
pub mod options;
pub mod partition;
pub mod software;
pub mod traits;

// Re-exports to facilitate flat access within the `models` submodule.
pub use image::{format_bytes, Hypervisor, ImageInfo, Stats};
pub use options::{
    BatchProgressEvent, BatchResult, CancellationToken, ImageInspectionError, InspectionOptions,
    InspectionProgress, InspectionProgressEvent, InspectionReport, InspectionSummary, Options,
    ProgressSnapshot,
};
pub use partition::{FileSystem, OperatingSystem, Partition, PartitionScheme};
pub use software::{GuestInfo, GuestTools, Program};
pub use traits::{AnalysisResult, MemoryMapper, OsInspector, VmDriver};
