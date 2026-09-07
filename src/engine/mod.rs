//! Motor de procesamiento concurrente, coordinación de tareas y Graceful Shutdown.

use crate::error::{Result, VmSpectError};
use crate::models::options::{InspectionProgress, Opciones, ProgresoInspeccion};
use crate::models::traits::ResultadoAnalisis;
use crate::models::InformeInspeccion;
use crate::parsers;
use crate::vms;
use crate::vms::nbd::{self, LectorNbd};
use crate::vms::stream::{identificar_imagen, LectorDisco};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// Procesador concurrente con soporte para Graceful Shutdown y reporte de progreso lock-free.
pub struct ProcesadorConcurrente;

impl ProcesadorConcurrente {
    /// Ejecuta una serie de tareas en paralelo utilizando un pool de workers con soporte para Graceful Shutdown y preservación de resultados parciales.
    ///
    /// # Garantías de Graceful Shutdown:
    /// 1. Si `cancel_token` está activo antes de comenzar o se activa durante la ejecución:
    ///    - No se extraen ni inician nuevas tareas pendientes de la cola.
    ///    - Los workers que estén procesando una tarea terminan de forma segura y liberan sus recursos.
    /// 2. La función espera obligatoriamente a que **todos** los hilos activos finalicen mediante `.join()`.
    /// 3. **Preservación de Resultados Parciales**: Si se solicita la cancelación, la función **no** descarta
    ///    los resultados ya completados; devuelve la lista con todos los resultados procesados exitosamente
    ///    hasta el momento de la cancelación.
    pub fn procesar_en_paralelo<T, R, F>(
        items: Vec<T>,
        cancel_token: Option<Arc<AtomicBool>>,
        progreso: Option<Arc<InspectionProgress>>,
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

        // Si ya está cancelado al inicio, no inicia hilos y retorna vector vacío
        if let Some(ref cancel) = cancel_token {
            if cancel.load(Ordering::Acquire) {
                return Ok(Vec::new());
            }
        }

        if let Some(ref p) = progreso {
            p.set_total_tasks(items.len());
        }

        let total_items = items.len();
        let num_workers = max_workers.max(1).min(total_items).min(32);

        let cola = Arc::new(Mutex::new(
            items
                .into_iter()
                .enumerate()
                .collect::<VecDeque<(usize, T)>>(),
        ));
        let resultados = Arc::new(Mutex::new(Vec::<(usize, R)>::with_capacity(total_items)));
        let error_almacenado = Arc::new(Mutex::new(None::<VmSpectError>));
        let f = Arc::new(f);

        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(num_workers);

        for worker_id in 0..num_workers {
            let cola_clone = Arc::clone(&cola);
            let resultados_clone = Arc::clone(&resultados);
            let error_clone = Arc::clone(&error_almacenado);
            let cancel_clone = cancel_token.clone();
            let progreso_clone = progreso.clone();
            let f_clone = Arc::clone(&f);

            let builder = std::thread::Builder::new().name(format!("vmspect-worker-{}", worker_id));

            let handle = builder.spawn(move || {
                loop {
                    // 1. Verificar cancelación antes de desencolar una nueva tarea
                    if let Some(ref cancel) = cancel_clone {
                        if cancel.load(Ordering::Acquire) {
                            break;
                        }
                    }

                    // 2. Extraer la siguiente tarea
                    let tarea = {
                        let mut q = cola_clone.lock().unwrap_or_else(|e| e.into_inner());
                        q.pop_front()
                    };

                    let Some((idx, item)) = tarea else {
                        break;
                    };

                    // 3. Verificar cancelación inmediatamente antes de iniciar el procesamiento
                    if let Some(ref cancel) = cancel_clone {
                        if cancel.load(Ordering::Acquire) {
                            break;
                        }
                    }

                    // 4. Ejecutar la tarea de forma segura y liberar recursos normalmente
                    let resultado = f_clone(item);

                    match resultado {
                        Ok(valor) => {
                            let mut res =
                                resultados_clone.lock().unwrap_or_else(|e| e.into_inner());
                            res.push((idx, valor));
                            if let Some(ref p) = progreso_clone {
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

        // 5. Graceful Shutdown: esperar rigurosamente a que todos los hilos terminen
        for handle in handles {
            let _ = handle.join();
        }

        // 6. Si hubo un error no relacionado con cancelación y no hay cancelación activa
        let fue_cancelado = cancel_token
            .as_ref()
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(false);

        if !fue_cancelado {
            if let Some(err) = error_almacenado
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                return Err(err);
            }
        }

        // 7. Preservar y devolver todos los resultados completados (incluidos los terminados durante el shutdown)
        let mut res = Arc::try_unwrap(resultados)
            .map(|m| m.into_inner().unwrap_or_else(|e| e.into_inner()))
            .unwrap_or_else(|m| std::mem::take(&mut *m.lock().unwrap_or_else(|e| e.into_inner())));
        res.sort_by_key(|(idx, _)| *idx);
        Ok(res.into_iter().map(|(_, val)| val).collect())
    }

    /// Procesa e inspecciona un conjunto de imágenes de disco en paralelo.
    ///
    /// Preserva los [`InformeInspeccion`] completados incluso si se cancela la operación.
    pub fn inspeccionar_imagenes<P: AsRef<Path> + Send + 'static>(
        rutas: Vec<P>,
        opciones: &Opciones,
        max_workers: usize,
    ) -> Result<Vec<InformeInspeccion>> {
        let opciones = opciones.clone();
        let cancel = opciones.cancel_token.clone();
        Self::procesar_en_paralelo(rutas, cancel, None, max_workers, move |ruta| {
            let motor = MotorInspeccion::new(opciones.clone());
            motor.inspeccionar(ruta.as_ref())
        })
    }
}

/// Motor de inspección con soporte de concurrencia, métricas lock-free y parada limpia (Graceful Shutdown).
#[derive(Debug, Clone)]
pub struct MotorInspeccion {
    opciones: Opciones,
    progreso: Arc<InspectionProgress>,
    cancel_token: Arc<AtomicBool>,
}

impl Default for MotorInspeccion {
    fn default() -> Self {
        Self::new(Opciones::default())
    }
}

impl MotorInspeccion {
    /// Crea un nuevo motor de inspección con las opciones proporcionadas.
    pub fn new(opciones: Opciones) -> Self {
        let cancel_token = opciones
            .cancel_token
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

        let progreso = Arc::new(InspectionProgress::con_token_cancelacion(Some(
            &cancel_token,
        )));

        let mut opciones = opciones;
        opciones.cancel_token = Some(cancel_token.clone());

        Self {
            opciones,
            progreso,
            cancel_token,
        }
    }

    /// Alias constructor para inicialización fluida con opciones personalizadas.
    pub fn with_options(opciones: Opciones) -> Self {
        Self::new(opciones)
    }

    /// Obtiene una referencia compartida a la estructura atómica de progreso ([`InspectionProgress`]).
    ///
    /// Permite a clientes (GUI/CLI/servicios) consultar métricas y porcentaje de forma lock-free.
    pub fn progress(&self) -> Arc<InspectionProgress> {
        self.progreso.clone()
    }

    /// Alias en español para [`progress`].
    pub fn progreso(&self) -> Arc<InspectionProgress> {
        self.progress()
    }

    /// Consulta directa del porcentaje de completitud actual `[0.0, 100.0]`.
    /// Operación thread-safe, de bajo costo y lock-free.
    pub fn completion_percentage(&self) -> f32 {
        self.progreso.completion_percentage()
    }

    /// Alias en español para [`completion_percentage`].
    pub fn porcentaje_completitud(&self) -> f32 {
        self.completion_percentage()
    }

    /// Solicita la cancelación inmediata y limpia de la inspección.
    pub fn cancel(&self) {
        self.cancel_token.store(true, Ordering::Release);
        self.progreso.cancel();
    }

    /// Alias en español para [`cancel`].
    pub fn cancelar(&self) {
        self.cancel();
    }

    /// Indica si el análisis actual ha sido cancelado (lock-free).
    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.load(Ordering::Acquire) || self.progreso.is_cancelled()
    }

    /// Alias en español para [`is_cancelled`].
    pub fn esta_cancelado(&self) -> bool {
        self.is_cancelled()
    }

    /// Ejecuta la inspección de la imagen de disco de forma síncrona.
    pub fn inspeccionar(&self, ruta_imagen: &Path) -> Result<InformeInspeccion> {
        self.ejecutar_inspeccion(ruta_imagen, None)
    }

    /// Alias en inglés para [`inspeccionar`].
    pub fn inspect(&self, ruta_imagen: &Path) -> Result<InformeInspeccion> {
        self.inspeccionar(ruta_imagen)
    }

    /// Ejecuta la inspección notificando eventos estructurados a un callback.
    pub fn inspeccionar_con_progreso<F>(
        &self,
        ruta_imagen: &Path,
        mut callback: F,
    ) -> Result<InformeInspeccion>
    where
        F: FnMut(ProgresoInspeccion),
    {
        self.ejecutar_inspeccion(ruta_imagen, Some(&mut callback))
    }

    /// Alias en inglés para [`inspeccionar_con_progreso`].
    pub fn inspect_with_progress<F>(
        &self,
        ruta_imagen: &Path,
        callback: F,
    ) -> Result<InformeInspeccion>
    where
        F: FnMut(ProgresoInspeccion),
    {
        self.inspeccionar_con_progreso(ruta_imagen, callback)
    }

    /// Inicia la inspección en un hilo de fondo dedicado, devolviendo un [`JoinHandle`].
    ///
    /// # Errores
    ///
    /// Devuelve [`VmSpectError::Io`] si el sistema operativo no puede crear un nuevo hilo
    /// (por ejemplo, por agotamiento de recursos). La propia inspección, una vez en marcha,
    /// reporta sus errores a través del [`Result`] interno del [`JoinHandle`].
    pub fn inspeccionar_en_segundo_plano(
        &self,
        ruta_imagen: &Path,
    ) -> Result<std::thread::JoinHandle<Result<InformeInspeccion>>> {
        let motor = self.clone();
        let ruta = ruta_imagen.to_path_buf();
        std::thread::Builder::new()
            .name("vmspect-bg-inspect".to_string())
            .spawn(move || motor.inspeccionar(&ruta))
            .map_err(VmSpectError::Io)
    }

    /// Alias en inglés para [`inspeccionar_en_segundo_plano`].
    pub fn inspect_background(
        &self,
        ruta_imagen: &Path,
    ) -> Result<std::thread::JoinHandle<Result<InformeInspeccion>>> {
        self.inspeccionar_en_segundo_plano(ruta_imagen)
    }

    /// Inspecciona un conjunto de imágenes de disco en paralelo usando múltiples workers.
    ///
    /// Preserva los resultados procesados antes y durante la solicitud de cancelación.
    pub fn inspeccionar_lote<P: AsRef<Path> + Send + 'static>(
        &self,
        rutas: Vec<P>,
        max_workers: usize,
    ) -> Result<Vec<InformeInspeccion>> {
        let opciones = self.opciones.clone();
        let cancel = Some(self.cancel_token.clone());
        let progreso = Some(self.progreso.clone());
        ProcesadorConcurrente::procesar_en_paralelo(
            rutas,
            cancel,
            progreso,
            max_workers,
            move |ruta| {
                let motor = MotorInspeccion::new(opciones.clone());
                motor.inspeccionar(ruta.as_ref())
            },
        )
    }

    /// Alias en inglés para [`inspeccionar_lote`].
    pub fn inspect_batch<P: AsRef<Path> + Send + 'static>(
        &self,
        rutas: Vec<P>,
        max_workers: usize,
    ) -> Result<Vec<InformeInspeccion>> {
        self.inspeccionar_lote(rutas, max_workers)
    }

    fn ejecutar_inspeccion(
        &self,
        ruta_imagen: &Path,
        mut callback: Option<&mut dyn FnMut(ProgresoInspeccion)>,
    ) -> Result<InformeInspeccion> {
        let inicio = Instant::now();

        if !ruta_imagen.exists() {
            return Err(VmSpectError::ImageNotFound(
                ruta_imagen.display().to_string(),
            ));
        }

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        let mut opciones_efectivas = self.opciones.clone();
        opciones_efectivas.cancel_token = Some(self.cancel_token.clone());

        // --- ETAPA 1 (5% - 15%): Identificación de la Imagen ---
        self.progreso.set_stage_id(1);
        self.progreso.set_percentage(5);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 5,
                etapa: "Identificando imagen de disco".into(),
                detalle: Some(format!("Analizando {}", ruta_imagen.display())),
            });
        }

        let imagen = identificar_imagen(opciones_efectivas.qemu_nbd.as_deref(), ruta_imagen)?;

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        self.progreso.set_total_bytes(imagen.tamano_virtual);
        self.progreso.set_percentage(15);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 15,
                etapa: "Inicializando backend de lectura".into(),
                detalle: Some(format!(
                    "Formato: {} | Hipervisor: {} | Tamaño: {}",
                    imagen.formato,
                    imagen.hipervisor.nombre(),
                    crate::models::formatear_bytes(imagen.tamano_virtual)
                )),
            });
        }

        let lector = if opciones_efectivas.forzar_nbd {
            let ruta_nbd = match nbd::resolver_qemu_nbd(opciones_efectivas.qemu_nbd.as_deref()) {
                Ok(r) => r,
                Err(_) => {
                    return Err(VmSpectError::QemuNotFound(
                        "No se encontró el ejecutable qemu-nbd en el sistema".to_string(),
                    ));
                }
            };
            let lector_nbd = LectorNbd::abrir_con_opciones(&ruta_nbd, &imagen, &opciones_efectivas)
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::Interrupted => VmSpectError::Cancelled,
                    _ => VmSpectError::Nbd(e.to_string()),
                })?;
            LectorDisco::desde_nbd(lector_nbd, &imagen, Some(self.cancel_token.clone()))
        } else {
            match LectorDisco::abrir_con_opciones(&imagen, &opciones_efectivas) {
                Ok(l) => l,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        return Err(VmSpectError::QemuNotFound(
                            "No se encontró el ejecutable qemu-nbd en el sistema".to_string(),
                        ));
                    }
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        return Err(VmSpectError::Cancelled);
                    }
                    return Err(VmSpectError::Io(e));
                }
            }
        };

        let tamano_chunk = opciones_efectivas
            .tamano_chunk
            .unwrap_or_else(|| lector.tamano_chunk_recomendado());

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        // --- ETAPA 2 (25% - 45%): Detección de Particiones ---
        self.progreso.set_stage_id(2);
        self.progreso.set_percentage(25);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 25,
                etapa: "Leyendo tabla de particiones".into(),
                detalle: Some(format!(
                    "Acceso: {} | Chunk size: {}",
                    lector.modo_acceso(),
                    crate::models::formatear_bytes(tamano_chunk)
                )),
            });
        }

        let disco = vms::detector::detectar_con_progreso(
            &lector,
            Some(self.cancel_token.clone()),
            Some(self.progreso.clone()),
        )?;

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        self.progreso.set_percentage(45);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 45,
                etapa: "Analizando sistemas de archivos".into(),
                detalle: Some(format!(
                    "{} particiones encontradas. SO detectado: {:?}",
                    disco.particiones.len(),
                    disco.sistema_operativo
                )),
            });
        }

        // --- ETAPA 3 (55% - 85%): Análisis del Sistema Operativo ---
        self.progreso.set_stage_id(3);
        self.progreso.set_percentage(55);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 55,
                etapa: format!(
                    "Analizando sistema operativo ({:?})",
                    disco.sistema_operativo
                ),
                detalle: Some("Iniciando escaneo de archivos del sistema / Registro".into()),
            });
        }

        // Graceful Degradation: un fallo durante el análisis del sistema operativo
        // invitado (ej. Registro de Windows sucio/corrupto) NO debe abortar el
        // pipeline completo. Se registra como advertencia y se continua con los
        // datos de imagen, particiones y sistemas de archivos ya recopilados.
        let resultado = if opciones_efectivas.debe_analizar_sistema()
            || opciones_efectivas.debe_analizar_apps()
        {
            let inspector = parsers::obtener_inspector(&disco.sistema_operativo);
            match inspector.analizar(
                &lector,
                &disco.particiones,
                tamano_chunk,
                &opciones_efectivas,
            ) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!(
                        "No se pudo completar el análisis del sistema operativo invitado, se continúa solo con los datos de imagen/particiones: {}",
                        e
                    );
                    tracing::warn!("{}", msg);
                    ResultadoAnalisis {
                        advertencias: vec![msg],
                        ..ResultadoAnalisis::default()
                    }
                }
            }
        } else {
            ResultadoAnalisis::default()
        };

        if self.is_cancelled() {
            return Err(VmSpectError::Cancelled);
        }

        // --- ETAPA 4 (90% - 100%): Consolidación e Informe ---
        self.progreso.set_stage_id(4);
        self.progreso.set_percentage(90);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 90,
                etapa: "Generando informe final".into(),
                detalle: Some(format!(
                    "{} programas/paquetes identificados",
                    resultado.programas.len()
                )),
            });
        }

        let mut estadisticas = lector.estadisticas();
        estadisticas.duracion_ms = inicio.elapsed().as_millis() as u64;

        let informe = InformeInspeccion {
            imagen,
            esquema: disco.esquema,
            particiones: disco.particiones,
            sistema_operativo: disco.sistema_operativo,
            vm_info: resultado.vm_info,
            programas: resultado.programas,
            advertencias: resultado.advertencias,
            estadisticas,
        };

        self.progreso.set_percentage(100);
        if let Some(ref mut cb) = callback {
            cb(ProgresoInspeccion {
                porcentaje: 100,
                etapa: "Análisis completado exitosamente".into(),
                detalle: None,
            });
        }

        Ok(informe)
    }
}

/// Alias en inglés para [`MotorInspeccion`].
pub type InspectionEngine = MotorInspeccion;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_progreso_atomico_metadatos_y_porcentaje() {
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

        prog.add_bytes_processed(2048);
        assert_eq!(prog.bytes_processed(), 2048);

        prog.set_total_bytes(4096);
        assert_eq!(prog.total_bytes(), 4096);

        prog.set_stage_id(3);
        assert_eq!(prog.stage_id(), 3);

        let snap = prog.snapshot();
        assert_eq!(snap.porcentaje, 50);
        assert_eq!(snap.etapa_id, 3);
        assert_eq!(snap.tareas_completadas, 2);
        assert_eq!(snap.total_tareas, 10);
        assert_eq!(snap.bytes_procesados, 2048);
        assert_eq!(snap.bytes_totales, 4096);
        assert!(!snap.cancelado);

        prog.cancel();
        assert!(prog.is_cancelled());
        assert!(prog.snapshot().cancelado);
    }

    #[test]
    fn test_procesador_concurrente_ejecucion_normal() {
        let items: Vec<u32> = (1..=20).collect();
        let cancel = Arc::new(AtomicBool::new(false));
        let prog = Arc::new(InspectionProgress::new());

        let resultados = ProcesadorConcurrente::procesar_en_paralelo(
            items.clone(),
            Some(cancel),
            Some(prog.clone()),
            4,
            |x| Ok(x * 2),
        )
        .expect("procesamiento paralelo exitoso");

        assert_eq!(resultados.len(), 20);
        for (i, &val) in resultados.iter().enumerate() {
            assert_eq!(val, (i as u32 + 1) * 2);
        }
        assert_eq!(prog.completed_tasks(), 20);
    }

    #[test]
    fn test_procesador_concurrente_graceful_shutdown_cancelacion() {
        let items: Vec<u32> = (1..=50).collect();
        let cancel = Arc::new(AtomicBool::new(false));
        let prog = Arc::new(InspectionProgress::new());

        let cancel_clon = cancel.clone();
        let prog_worker = prog.clone();
        let tareas_iniciadas = Arc::new(AtomicUsize::new(0));
        let tareas_iniciadas_clon = tareas_iniciadas.clone();

        let handle = std::thread::spawn(move || {
            ProcesadorConcurrente::procesar_en_paralelo(
                items,
                Some(cancel_clon),
                Some(prog_worker),
                4,
                move |_item| {
                    let num = tareas_iniciadas_clon.fetch_add(1, Ordering::SeqCst);
                    if num >= 2 {
                        sleep(Duration::from_millis(50));
                    }
                    Ok(())
                },
            )
        });

        // Espera determinista (acotada por un timeout de seguridad) a que al menos dos
        // tareas rápidas hayan finalizado antes de cancelar. Evita una carrera contra el
        // reloj que podría fallar de forma intermitente si el sistema está bajo carga.
        let inicio_espera = Instant::now();
        while prog.completed_tasks() < 2 && inicio_espera.elapsed() < Duration::from_secs(5) {
            sleep(Duration::from_millis(1));
        }
        cancel.store(true, Ordering::Release);

        let resultado = handle.join().expect("hilo coordinador finalizó");
        let resultados_parciales = resultado.expect("debe preservar resultados parciales");
        assert!(
            !resultados_parciales.is_empty(),
            "Debe haber preservado los resultados completados"
        );
        assert!(
            resultados_parciales.len() < 50,
            "No debe procesar todos los elementos si fue cancelado"
        );

        let total_iniciadas = tareas_iniciadas.load(Ordering::SeqCst);
        assert!(
            total_iniciadas < 50,
            "Las tareas pendientes no deben haber iniciado tras la cancelación (iniciadas: {})",
            total_iniciadas
        );
    }

    #[test]
    fn test_motor_inspeccion_api_consulta_progreso_y_cancelacion() {
        let opciones = Opciones::default();
        let motor = MotorInspeccion::new(opciones);

        assert_eq!(motor.completion_percentage(), 0.0);
        assert!(!motor.is_cancelled());

        let prog = motor.progress();
        prog.set_percentage(75);
        assert_eq!(motor.completion_percentage(), 75.0);

        motor.cancel();
        assert!(motor.is_cancelled());
        assert!(motor.progreso().is_cancelled());
    }
}
