//! Disk access layer for virtual machines.
//!
//! - [`stream`]: `DiskReader` facade (native or `qemu-nbd`) and `Read + Seek` view.
//! - [`vmdk`]: native VMDK parser (sparse, flat, multi-extent).
//! - [`detector`]: partition table, file systems and guest OS detection.
//! - [`discovery`]: discovery, integrity verification and inspection-capability analysis.

pub(crate) mod detector;
pub mod discovery;
pub mod nbd;
pub mod stream;
pub(crate) mod vmdk;
