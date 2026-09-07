//! Módulo principal de estructuras de datos y traits del dominio.

pub mod image;
pub mod options;
pub mod partition;
pub mod software;
pub mod traits;

// Re-exportaciones para facilitar el acceso plano dentro del submódulo models
pub use image::{formatear_bytes, Estadisticas, Hipervisor, InfoImagen};
pub use options::{
    CancellationToken, InformeInspeccion, InspectionProgress, Opciones, OpcionesInspeccion,
    ProgresoInspeccion, ProgresoSnapshot,
};
pub use partition::{EsquemaParticion, Particion, SistemaArchivos, SistemaOperativo};
pub use software::{HerramientasGuest, Programa, VMInfo};
pub use traits::{InspectorOS, MemoryMapper, ResultadoAnalisis, VmDriver};
