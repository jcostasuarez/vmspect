//! Capa de acceso a discos de máquinas virtuales.
//!
//! - [`stream`]: fachada `LectorDisco` (nativo o `qemu-nbd`) y vista `Read + Seek`.
//! - [`vmdk`]: parser nativo del formato VMDK (sparse, flat, multi-extent).
//! - [`detector`]: tabla de particiones, sistemas de archivos y S.O. invitado.
//! - [`discovery`]: descubrimiento, verificación de integridad y análisis de capacidades de inspección.

pub(crate) mod detector;
pub mod discovery;
pub mod nbd;
pub mod stream;
pub(crate) mod vmdk;
