//! # vmspect
//!
//! `vmspect` es una biblioteca en Rust diseñada para la inspección estática,
//! análisis y extracción de información en imágenes de disco de máquinas virtuales (VMDK, RAW, QCOW2, VHD, etc.).
//!
//! Permite examinar la estructura de particiones (MBR/GPT), identificar el Sistema Operativo hospedado (Windows/Linux)
//! y extraer listas completas de software instalado de forma no invasiva (sin arrancar la VM ni montar el disco en el host).
//!
//! ## Características Principales
//!
//! - **Acceso Híbrido:** Parser nativo en Rust para formatos comunes (VMDK/RAW) con streaming dinámico ultra-liviano mediante `qemu-nbd` (TCP local) para formatos complejos (`QCOW2`, `VHDX`, `VDI`, etc.).
//! - **Soporte Multi-OS:** Extracción completa de software desde el Registro de Windows (`NTFS`) e índices DPKG en Linux (`EXT4`).
//! - **Extracción Agnóstica:** Recolección íntegra y sin filtros de software y metadatos de sistema.
//! - **Reporte de Progreso Lock-Free:** Métricas atómicas e integrables con interfaces gráficas (Tauri/Egui/CLI) mediante [`InspectionProgress`].
//! - **Graceful Shutdown y Preservación de Resultados:** Cancelación cooperativa limpia mediante [`CancellationToken`] que preserva todos los informes completados hasta la interrupción.
//! - **Arquitectura Abierta:** Traits ([`VmDriver`], [`MemoryMapper`], [`InspectorOS`]) y motor extensible ([`MotorInspeccion`], [`ProcesadorConcurrente`]).
//!
//! ## Ejemplo de Uso Rápido
//!
//! ```rust,no_run
//! use std::path::Path;
//! use vmspect::prelude::*;
//!
//! fn main() -> Result<()> {
//!     let ruta = Path::new("disco_virtual.vmdk");
//!     let opciones = Opciones::default();
//!
//!     let informe = inspeccionar_con_progreso(ruta, &opciones, |progreso: ProgresoInspeccion| {
//!         println!("[{:>3}%] {} - {}", progreso.porcentaje, progreso.etapa, progreso.detalle.unwrap_or_default());
//!     })?;
//!
//!     println!("Sistema detectado: {:?}", informe.sistema_operativo);
//!     println!("Programas hallados: {}", informe.programas.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Ejemplo de Procesamiento Concurrente con Cancelación y Resultados Parciales
//!
//! ```rust,no_run
//! use std::path::PathBuf;
//! use std::sync::atomic::Ordering;
//! use vmspect::prelude::*;
//!
//! fn main() -> Result<()> {
//!     let rutas = vec![
//!         PathBuf::from("vm1.vmdk"),
//!         PathBuf::from("vm2.raw"),
//!         PathBuf::from("vm3.qcow2"),
//!     ];
//!
//!     let cancel = CancellationToken::new();
//!     let opciones = Opciones::default().with_cancellation_token(&cancel);
//!     let motor = MotorInspeccion::new(opciones);
//!
//!     // Se puede solicitar la cancelación en cualquier momento desde otro hilo:
//!     // cancel.cancel();
//!
//!     // Devuelve los informes completados exitosamente antes y durante el shutdown:
//!     let informes_completados = motor.inspeccionar_lote(rutas, 4)?;
//!     println!("Informes preservados: {}", informes_completados.len());
//!
//!     Ok(())
//! }
//! ```

#![deny(missing_docs)]

pub mod engine;
pub mod error;
pub mod models;
pub(crate) mod parsers;
pub mod prelude;
pub mod vms;

// Re-exportaciones públicas de la API para aplanar el consumo desde la raíz del crate.
pub use crate::vms::discovery::{
    contar_vms, count_vms, es_extent_secundario, es_imagen_vm, has_vms, hay_vms,
    is_secondary_extent, is_vm_image, list_vms, listar_vms, requiere_nbd, requiere_qemu,
    requires_nbd, requires_qemu, verificar_integridad_imagen, verify_image_integrity,
};
pub use crate::vms::stream::DiscoVirtual;
pub use engine::{InspectionEngine, MotorInspeccion, ProcesadorConcurrente};
pub use error::{Result, VmSpectError};
pub use models::{
    formatear_bytes, CancellationToken, EsquemaParticion, Estadisticas, HerramientasGuest,
    Hipervisor, InfoImagen, InformeInspeccion, InspectionProgress, InspectorOS, MemoryMapper,
    Opciones, OpcionesInspeccion, Particion, Programa, ProgresoInspeccion, ProgresoSnapshot,
    ResultadoAnalisis, SistemaArchivos, SistemaOperativo, VMInfo, VmDriver,
};

use std::path::Path;

/// Realiza una inspección estática completa de una imagen de disco utilizando un callback de texto plano.
///
/// Esta función está diseñada principalmente para aplicaciones CLI o scripts de consola donde
/// la salida de estado se imprime línea a línea mediante mensajes de texto (`&str`).
///
/// # Parámetros
///
/// - `ruta_imagen`: Referencia al [`Path`] del archivo de disco virtual (`.vmdk`, `.raw`, etc.).
/// - `opciones`: Configuración de la inspección ([`Opciones`]), que incluye control de análisis de apps/sistema y rutas.
/// - `progreso`: Callback mutable que recibe referencias a cadenas de texto (`&str`) con la descripción del paso actual.
///
/// # Errores
///
/// Devuelve un [`VmSpectError`] si:
/// - El archivo en `ruta_imagen` no existe ([`VmSpectError::ImageNotFound`]).
/// - La inspección fue cancelada por el usuario ([`VmSpectError::Cancelled`]).
/// - Ocurre un error de lectura de I/O en la imagen ([`VmSpectError::Io`]).
/// - La imagen requiere el servidor `qemu-nbd` y el ejecutable no está disponible ([`VmSpectError::QemuNotFound`]).
/// - No se puede reconocer la tabla de particiones o el sistema de archivos subyacente ([`VmSpectError::FileSystem`]).
///
/// # Ejemplo
///
/// ```rust,no_run
/// use std::path::Path;
/// use vmspect::{inspeccionar, Opciones};
///
/// let ruta = Path::new("C:\\VMs\\Windows10.vmdk");
/// let opciones = Opciones::default();
///
/// let resultado = inspeccionar(ruta, &opciones, &mut |mensaje| {
///     println!("LOG: {}", mensaje);
/// });
/// ```
pub fn inspeccionar(
    ruta_imagen: &Path,
    opciones: &Opciones,
    progreso: &mut dyn FnMut(&str),
) -> Result<InformeInspeccion> {
    let motor = MotorInspeccion::new(opciones.clone());
    motor.inspeccionar_con_progreso(ruta_imagen, |p| {
        let msg = match &p.detalle {
            Some(d) => format!("[{:>3}%] {} - {}", p.porcentaje, p.etapa, d),
            None => format!("[{:>3}%] {}", p.porcentaje, p.etapa),
        };
        progreso(&msg);
    })
}

/// Realiza una inspección estática reportando eventos de progreso estructurados (`0` al `100%`).
///
/// Esta función es la opción recomendada para integraciones con entornos de interfaz gráfica (como **Tauri**, **Electron** o **Egui**),
/// ya que emite una estructura [`ProgresoInspeccion`] serializable con porcentajes acotados y descripciones de la etapa actual.
///
/// # Parámetros
///
/// - `ruta_imagen`: Referencia al [`Path`] de la imagen de disco virtual.
/// - `opciones`: Configuración del motor ([`Opciones`]).
/// - `callback_progreso`: Un closure que implementa `FnMut(ProgresoInspeccion)`, invocado secuencialmente durante el análisis.
///
/// # Flujo de Porcentajes Emitidos
///
/// - **`5% - 15%`**: Identificación del formato de la imagen y apertura del backend de lectura.
/// - **`25% - 45%`**: Detección del esquema de particionado (MBR/GPT) y firmas de File System.
/// - **`55%`**: Análisis profundo del SO (extracción de Registro NTFS / paquetes DPKG).
/// - **`90%`**: Generación y consolidación del informe.
/// - **`100%`**: Finalización del reporte y cálculo de métricas de rendimiento.
pub fn inspeccionar_con_progreso<F>(
    ruta_imagen: &Path,
    opciones: &Opciones,
    callback_progreso: F,
) -> Result<InformeInspeccion>
where
    F: FnMut(ProgresoInspeccion),
{
    let motor = MotorInspeccion::new(opciones.clone());
    motor.inspeccionar_con_progreso(ruta_imagen, callback_progreso)
}

/// Alias en inglés para [`inspeccionar`].
pub use inspeccionar as inspect;

/// Alias en inglés para [`inspeccionar_con_progreso`].
pub use inspeccionar_con_progreso as inspect_with_progress;
