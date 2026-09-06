//! Opciones de configuración, eventos de progreso e informe final de inspección.

use crate::models::image::{Estadisticas, InfoImagen};
use crate::models::partition::{EsquemaParticion, Particion, SistemaOperativo};
use crate::models::software::{Programa, VMInfo};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Token de cancelación reutilizable basado en banderas atómicas.
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
    /// Crea un nuevo token de cancelación en estado no cancelado (`false`).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Crea un token a partir de un `Arc<AtomicBool>` existente.
    pub fn from_arc(inner: Arc<AtomicBool>) -> Self {
        Self { inner }
    }

    /// Solicita la cancelación de las tareas asociadas.
    pub fn cancel(&self) {
        self.inner.store(true, Ordering::Release);
    }

    /// Alias en español para [`cancel`].
    pub fn cancelar(&self) {
        self.cancel();
    }

    /// Indica si se ha solicitado la cancelación (lectura thread-safe lock-free con orden Acquire).
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    /// Alias en español para [`is_cancelled`].
    pub fn esta_cancelado(&self) -> bool {
        self.is_cancelled()
    }

    /// Obtiene una referencia al `Arc<AtomicBool>` interno.
    pub fn as_arc(&self) -> &Arc<AtomicBool> {
        &self.inner
    }

    /// Clona el `Arc<AtomicBool>` interno.
    pub fn clone_arc(&self) -> Arc<AtomicBool> {
        self.inner.clone()
    }
}

/// Instantánea inmutable del progreso para inspección externa o serialización.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgresoSnapshot {
    /// Porcentaje de avance global (de 0 a 100).
    pub porcentaje: u8,
    /// Identificador numérico de la etapa en curso.
    pub etapa_id: u8,
    /// Cantidad de tareas completadas.
    pub tareas_completadas: usize,
    /// Total de tareas programadas.
    pub total_tareas: usize,
    /// Bytes leídos o procesados.
    pub bytes_procesados: u64,
    /// Total de bytes virtuales o esperados.
    pub bytes_totales: u64,
    /// Indica si el análisis ha sido cancelado.
    pub cancelado: bool,
}

/// Métricas y progreso atómico de la inspección compartibles entre hilos sin bloqueos (lock-free).
#[derive(Debug)]
pub struct InspectionProgress {
    /// Tareas totales estimadas o registradas.
    pub total_tareas: AtomicUsize,
    /// Tareas completadas.
    pub tareas_completadas: AtomicUsize,
    /// Bytes totales procesados.
    pub bytes_procesados: AtomicU64,
    /// Bytes totales estimados o conocidos.
    pub bytes_totales: AtomicU64,
    /// Porcentaje de completitud (0 a 100).
    pub porcentaje: AtomicU8,
    /// Código o ID de la etapa actual.
    pub etapa_id: AtomicU8,
    /// Flag atómico de cancelación.
    pub cancelado: AtomicBool,
}

impl Default for InspectionProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl InspectionProgress {
    /// Crea una nueva instancia con todos los contadores en cero.
    pub fn new() -> Self {
        Self {
            total_tareas: AtomicUsize::new(0),
            tareas_completadas: AtomicUsize::new(0),
            bytes_procesados: AtomicU64::new(0),
            bytes_totales: AtomicU64::new(0),
            porcentaje: AtomicU8::new(0),
            etapa_id: AtomicU8::new(0),
            cancelado: AtomicBool::new(false),
        }
    }

    /// Crea una nueva instancia vinculada a un token de cancelación externo.
    pub fn con_token_cancelacion(token: Option<&Arc<AtomicBool>>) -> Self {
        let cancelado = if let Some(t) = token {
            AtomicBool::new(t.load(Ordering::Acquire))
        } else {
            AtomicBool::new(false)
        };
        Self {
            total_tareas: AtomicUsize::new(0),
            tareas_completadas: AtomicUsize::new(0),
            bytes_procesados: AtomicU64::new(0),
            bytes_totales: AtomicU64::new(0),
            porcentaje: AtomicU8::new(0),
            etapa_id: AtomicU8::new(0),
            cancelado,
        }
    }

    /// Obtiene el porcentaje de completitud actual en punto flotante `[0.0, 100.0]`.
    /// Operación lock-free de bajo costo basada en cargas atómicas con orden Relaxed.
    #[inline]
    pub fn completion_percentage(&self) -> f32 {
        let pct = self.porcentaje.load(Ordering::Relaxed);
        let total = self.total_tareas.load(Ordering::Relaxed);
        if total > 0 {
            let done = self.tareas_completadas.load(Ordering::Relaxed);
            let calc = (done as f32 / total as f32) * 100.0;
            calc.clamp(pct as f32, 100.0)
        } else {
            (pct.min(100)) as f32
        }
    }

    /// Alias en español para [`completion_percentage`].
    #[inline]
    pub fn porcentaje_completitud(&self) -> f32 {
        self.completion_percentage()
    }

    /// Indica si el análisis ha recibido una señal de cancelación (lock-free, Acquire).
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancelado.load(Ordering::Acquire)
    }

    /// Alias en español para [`is_cancelled`].
    #[inline]
    pub fn esta_cancelado(&self) -> bool {
        self.is_cancelled()
    }

    /// Señaliza la cancelación del análisis (Release).
    #[inline]
    pub fn cancel(&self) {
        self.cancelado.store(true, Ordering::Release);
    }

    /// Alias en español para [`cancel`].
    #[inline]
    pub fn cancelar(&self) {
        self.cancel();
    }

    /// Establece el porcentaje global de avance (0..=100).
    #[inline]
    pub fn set_percentage(&self, pct: u8) {
        self.porcentaje.store(pct.min(100), Ordering::Relaxed);
    }

    /// Establece el identificador de la etapa actual.
    #[inline]
    pub fn set_stage_id(&self, stage: u8) {
        self.etapa_id.store(stage, Ordering::Relaxed);
    }

    /// Obtiene el identificador de la etapa actual.
    #[inline]
    pub fn stage_id(&self) -> u8 {
        self.etapa_id.load(Ordering::Relaxed)
    }

    /// Suma bytes leídos o procesados de manera atómica.
    #[inline]
    pub fn add_bytes_processed(&self, bytes: u64) {
        self.bytes_procesados.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Obtiene el número total de bytes procesados hasta ahora.
    #[inline]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_procesados.load(Ordering::Relaxed)
    }

    /// Configura el tamaño total en bytes esperado para el análisis.
    #[inline]
    pub fn set_total_bytes(&self, total: u64) {
        self.bytes_totales.store(total, Ordering::Relaxed);
    }

    /// Obtiene el total de bytes estimados.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_totales.load(Ordering::Relaxed)
    }

    /// Configura el total de tareas estimadas en el plan de trabajo.
    #[inline]
    pub fn set_total_tasks(&self, total: usize) {
        self.total_tareas.store(total, Ordering::Relaxed);
    }

    /// Obtiene el total de tareas planificadas.
    #[inline]
    pub fn total_tasks(&self) -> usize {
        self.total_tareas.load(Ordering::Relaxed)
    }

    /// Incrementa en uno el contador de tareas completadas.
    #[inline]
    pub fn increment_completed_tasks(&self) {
        self.tareas_completadas.fetch_add(1, Ordering::Relaxed);
    }

    /// Obtiene la cantidad de tareas completadas hasta el momento.
    #[inline]
    pub fn completed_tasks(&self) -> usize {
        self.tareas_completadas.load(Ordering::Relaxed)
    }

    /// Obtiene una instantánea inmutable del estado del progreso.
    pub fn snapshot(&self) -> ProgresoSnapshot {
        ProgresoSnapshot {
            porcentaje: self.porcentaje.load(Ordering::Relaxed),
            etapa_id: self.etapa_id.load(Ordering::Relaxed),
            tareas_completadas: self.tareas_completadas.load(Ordering::Relaxed),
            total_tareas: self.total_tareas.load(Ordering::Relaxed),
            bytes_procesados: self.bytes_procesados.load(Ordering::Relaxed),
            bytes_totales: self.bytes_totales.load(Ordering::Relaxed),
            cancelado: self.cancelado.load(Ordering::Acquire),
        }
    }
}

/// Opciones de ejecución pasadas al motor de inspección.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Opciones {
    /// Si es `true`, desactiva la recolección de aplicaciones instaladas (`--noapps`).
    pub noapps: bool,
    /// Si es `true`, desactiva la recolección de información del sistema operativo (`--nosystem`).
    pub nosystem: bool,
    /// Si es `true`, fuerza la lectura de la colmena `SYSTEM` además de `SOFTWARE` en Windows.
    pub incluir_system: bool,
    /// Ruta explícita al binario `qemu-nbd`. Si es `None`, se busca automáticamente en el sistema.
    pub qemu_nbd: Option<PathBuf>,
    /// Tamaño de chunk (bytes) utilizado por la caché de lectura. `None` establece el tamaño óptimo automático.
    pub tamano_chunk: Option<u64>,
    /// Si es `true`, fuerza el uso de `qemu-nbd` incluso si el formato admite lectura nativa en Rust.
    pub forzar_nbd: bool,
    /// Especifica la ruta a un socket de dominio UNIX (`--socket-path` / `-k` en qemu-nbd) en lugar del puerto TCP loopback por defecto.
    pub socket_unix: Option<PathBuf>,
    /// Pasa argumentos o flags CLI adicionales arbitrarios al subproceso `qemu-nbd` (ej. optimizaciones de caché, `--detect-zeroes`, etc.).
    pub args_extra_nbd: Vec<String>,
    /// Tiempo máximo de espera para que el servidor `qemu-nbd` esté listo y acepte conexiones (TCP o UNIX) durante el handshake inicial.
    pub timeout_conexion: Option<Duration>,
    /// Bandera para incluir opcionalmente `--persistent`. Por defecto es `false`.
    pub persistente_nbd: bool,
    /// Token de cancelación atómico opcional para abortar la inspección anticipadamente.
    #[serde(skip)]
    pub cancel_token: Option<Arc<AtomicBool>>,
}

/// Alias para [`Opciones`] bajo la nomenclatura `OpcionesInspeccion`.
pub type OpcionesInspeccion = Opciones;

impl Opciones {
    /// Indica si se debe ejecutar el análisis y extracción de aplicaciones instaladas (retorna `!self.noapps`).
    #[inline]
    pub fn debe_analizar_apps(&self) -> bool {
        !self.noapps
    }

    /// Alias en inglés para [`debe_analizar_apps`](Self::debe_analizar_apps).
    #[inline]
    pub fn should_analyze_apps(&self) -> bool {
        self.debe_analizar_apps()
    }

    /// Indica si se debe ejecutar el análisis y extracción de información del sistema operativo (retorna `!self.nosystem`).
    #[inline]
    pub fn debe_analizar_sistema(&self) -> bool {
        !self.nosystem
    }

    /// Alias en inglés para [`debe_analizar_sistema`](Self::debe_analizar_sistema).
    #[inline]
    pub fn should_analyze_system(&self) -> bool {
        self.debe_analizar_sistema()
    }

    /// Asigna la ruta explícita al binario `qemu-nbd`.
    pub fn with_qemu_nbd(mut self, path: PathBuf) -> Self {
        self.qemu_nbd = Some(path);
        self
    }

    /// Configura si se debe forzar el uso del backend `qemu-nbd`.
    pub fn with_forzar_nbd(mut self, forzar: bool) -> Self {
        self.forzar_nbd = forzar;
        self
    }

    /// Asigna la ruta a un socket de dominio UNIX (`-k`) para la comunicación con `qemu-nbd`.
    pub fn with_socket_unix(mut self, ruta: impl Into<PathBuf>) -> Self {
        self.socket_unix = Some(ruta.into());
        self
    }

    /// Asigna argumentos o flags CLI adicionales para el subproceso `qemu-nbd`.
    pub fn with_extra_nbd_args(mut self, args: Vec<String>) -> Self {
        self.args_extra_nbd = args;
        self
    }

    /// Define el tiempo máximo de espera para que el servidor `qemu-nbd` acepte la conexión inicial.
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_conexion = Some(timeout);
        self
    }

    /// Configura si `qemu-nbd` debe ejecutarse con la bandera `--persistent`.
    pub fn with_persistente_nbd(mut self, persistente: bool) -> Self {
        self.persistente_nbd = persistente;
        self
    }

    /// Asigna o reemplaza el token de cancelación atómico.
    pub fn with_cancel_token(mut self, token: Arc<AtomicBool>) -> Self {
        self.cancel_token = Some(token);
        self
    }

    /// Asigna o reemplaza el token de cancelación mediante [`CancellationToken`].
    pub fn with_cancellation_token(mut self, token: &CancellationToken) -> Self {
        self.cancel_token = Some(token.clone_arc());
        self
    }
}

/// Evento de progreso emitido periódicamente hacia consumidores externos (CLI o Tauri UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgresoInspeccion {
    /// Porcentaje de avance global (de 0 a 100).
    pub porcentaje: u8,
    /// Nombre corto de la fase o tarea actual (ej. "Leyendo MBR/GPT...", "Analizando NTFS...").
    pub etapa: String,
    /// Información técnica adicional u opcional sobre el progreso.
    pub detalle: Option<String>,
}

/// Resultado completo y consolidado de la inspección del disco virtual.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformeInspeccion {
    /// Información sobre el archivo de imagen inspeccionado.
    pub imagen: InfoImagen,
    /// Esquema de tabla de particiones hallado.
    pub esquema: EsquemaParticion,
    /// Lista de particiones identificadas.
    pub particiones: Vec<Particion>,
    /// Clasificación general del sistema operativo detectado.
    pub sistema_operativo: SistemaOperativo,
    /// Metadatos detallados del SO instalado.
    pub vm_info: VMInfo,
    /// Lista de programas estructurados hallados en el sistema (Nombre, Versión, Editor).
    pub programas: Vec<Programa>,
    /// Métricas de rendimiento asociadas a la inspección.
    pub estadisticas: Estadisticas,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opciones_defecto() {
        let opc = Opciones::default();
        assert!(!opc.noapps);
        assert!(!opc.nosystem);
        assert!(opc.debe_analizar_apps());
        assert!(opc.debe_analizar_sistema());
    }

    #[test]
    fn test_opciones_alias_ingles_should_analyze() {
        let opc = Opciones {
            noapps: true,
            ..Opciones::default()
        };
        assert_eq!(opc.should_analyze_apps(), opc.debe_analizar_apps());
        assert_eq!(opc.should_analyze_system(), opc.debe_analizar_sistema());
        assert!(!opc.should_analyze_apps());
        assert!(opc.should_analyze_system());
    }

    #[test]
    fn test_opciones_noapps() {
        let opc = Opciones {
            noapps: true,
            ..Opciones::default()
        };
        assert!(!opc.debe_analizar_apps());
        assert!(opc.debe_analizar_sistema());
    }

    #[test]
    fn test_opciones_nosystem() {
        let opc = Opciones {
            nosystem: true,
            ..Opciones::default()
        };
        assert!(opc.debe_analizar_apps());
        assert!(!opc.debe_analizar_sistema());
    }

    #[test]
    fn test_opciones_nbd_avanzadas() {
        let opc = Opciones::default()
            .with_socket_unix("/tmp/qemu-test.sock")
            .with_extra_nbd_args(vec!["--cache=none".into(), "--detect-zeroes=on".into()])
            .with_connection_timeout(Duration::from_secs(10))
            .with_persistente_nbd(true);

        assert_eq!(opc.socket_unix, Some(PathBuf::from("/tmp/qemu-test.sock")));
        assert_eq!(
            opc.args_extra_nbd,
            vec!["--cache=none".to_string(), "--detect-zeroes=on".to_string()]
        );
        assert_eq!(opc.timeout_conexion, Some(Duration::from_secs(10)));
        assert!(opc.persistente_nbd);
    }
}
