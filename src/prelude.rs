//! Prelude with the most common imports for using `vmspect`.

pub use crate::engine::{ConcurrentProcessor, InspectionEngine};
pub use crate::error::{Result, VmSpectError};
pub use crate::models::image::{format_bytes, Hypervisor, ImageInfo, Stats};
pub use crate::models::options::{
    CancellationToken, InspectionOptions, InspectionProgress, InspectionProgressEvent,
    InspectionReport, Options, ProgressSnapshot,
};
pub use crate::models::partition::{FileSystem, OperatingSystem, Partition, PartitionScheme};
pub use crate::models::software::{GuestInfo, GuestTools, Program};
pub use crate::models::traits::{AnalysisResult, MemoryMapper, OsInspector, VmDriver};
pub use crate::vms::discovery::{
    count_vms, has_vms, is_secondary_extent, is_vm_image, list_vms, requires_nbd, requires_qemu,
    verify_image_integrity,
};
pub use crate::vms::stream::VirtualDisk;
pub use crate::{inspect, inspect_with_progress};
