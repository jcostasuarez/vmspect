//! Preludio con las importaciones más comunes para usar `vmspect`.

pub use crate::engine::{InspectionEngine, MotorInspeccion, ProcesadorConcurrente};
pub use crate::error::{Result, VmSpectError};
pub use crate::models::image::{formatear_bytes, Estadisticas, Hipervisor, InfoImagen};
pub use crate::models::options::{
    CancellationToken, InformeInspeccion, InspectionProgress, Opciones, OpcionesInspeccion,
    ProgresoInspeccion, ProgresoSnapshot,
};
pub use crate::models::partition::{
    EsquemaParticion, Particion, SistemaArchivos, SistemaOperativo,
};
pub use crate::models::software::{Programa, VMInfo};
pub use crate::models::traits::{InspectorOS, MemoryMapper, ResultadoAnalisis, VmDriver};
pub use crate::vms::discovery::{
    contar_vms, count_vms, es_extent_secundario, es_imagen_vm, has_vms, hay_vms,
    is_secondary_extent, is_vm_image, list_vms, listar_vms, requiere_nbd, requiere_qemu,
    requires_nbd, requires_qemu, verificar_integridad_imagen, verify_image_integrity,
};
pub use crate::vms::stream::DiscoVirtual;
pub use crate::{inspeccionar, inspeccionar_con_progreso, inspect, inspect_with_progress};
