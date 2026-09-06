# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/),
y este proyecto se adhiere al [Versionado Semántico](https://semver.org/lang/es/) (mientras
la versión mayor sea `0`, los incrementos de la versión menor pueden incluir cambios
incompatibles, según lo previsto por SemVer para la serie `0.y.z`).

## [0.2.0] - 2026-09-06

Release de consolidación de API, backend `qemu-nbd` híbrido y procesamiento concurrente,
precedido de una auditoría exhaustiva de calidad, consistencia de API y correcto
funcionamiento de todo el crate.

### Añadido

- Alias en inglés `Opciones::should_analyze_apps` / `Opciones::should_analyze_system`
  para `debe_analizar_apps` / `debe_analizar_sistema`, completando la cobertura
  bilingüe (Español/Inglés) de los métodos principales de configuración del motor.
- `CHANGELOG.md` para documentar el historial de cambios del crate.

### Cambiado

- **[Breaking]** `MotorInspeccion::inspeccionar_en_segundo_plano` (`inspect_background`)
  ahora devuelve `Result<JoinHandle<Result<InformeInspeccion>>>` en lugar de
  `JoinHandle<Result<InformeInspeccion>>`, propagando como `VmSpectError::Io` cualquier
  fallo del sistema operativo al crear el hilo en segundo plano, en lugar de generar
  un panic.

### Corregido

- Eliminados todos los usos de `.unwrap()` / `.expect()` en código de producción
  (`src/`) que podían provocar panics inesperados:
  - `ProcesadorConcurrente::procesar_en_paralelo` ahora se recupera correctamente de
    un `Mutex` envenenado (`PoisonError::into_inner`) en lugar de propagar el panic
    ante un hipotético hilo previamente abortado.
  - Eliminado el `.expect()` al crear el hilo de `inspeccionar_en_segundo_plano` (ver
    "Cambiado" arriba).
- Sustituido un `unreachable!()` en el conector `qemu-nbd` (`vms::nbd::LectorNbd`) por
  una garantía a nivel de tipos (`enum TransporteNbd`), eliminando el último punto de
  panic potencial en la selección de transporte híbrido TCP/socket UNIX.
- Corregidas 8 advertencias de `clippy::field_reassign_with_default`,
  `clippy::useless_vec` y `clippy::cloned_ref_to_slice_refs` detectadas al ejecutar
  `cargo clippy --all-targets -- -D warnings` (código de producción y de pruebas).
- Eliminada una condición de carrera intermitente (*flaky test*) en
  `test_procesador_concurrente_graceful_shutdown_cancelacion`: la espera basada en
  `sleep` de duración fija antes de cancelar se reemplazó por una espera activa
  determinista sobre `InspectionProgress::completed_tasks()` (con timeout de
  seguridad), eliminando fallos intermitentes bajo carga del sistema.

### Auditoría de calidad realizada

- **API pública**: revisión de `src/lib.rs`, `src/prelude.rs` y los módulos `vms`,
  `engine`, `models` y `error`; confirmada la ausencia de tipos internos filtrados
  (los módulos `parsers`, `vms::detector` y `vms::vmdk` permanecen `pub(crate)`) y de
  requisitos de inicialización complejos u ocultos.
- **Documentación**: se confirmó el cumplimiento de `#![deny(missing_docs)]` en toda
  la API pública (sin advertencias al compilar).
- **Pipeline de inspección**: validado el descubrimiento/filtrado de extents
  secundarios (`*-flat.vmdk`, `*-delta.vmdk`, `*-s001.vmdk`, etc.), la verificación de
  Magic Bytes (QCOW2, VMDK, VDI, VHD, VHDX, RAW), la selección de backend
  (nativo vs. `qemu-nbd` híbrido TCP/UNIX), los tres modos de inspección
  (`inspeccionar`, `inspeccionar_con_progreso`, `ProcesadorConcurrente`), la
  cancelación cooperativa con preservación de resultados parciales y la limpieza
  defensiva en `Drop` de `LectorNbd` / `NbdStream` (sin procesos huérfanos).
- **Validación técnica** (100% en verde):
  - `cargo check --all-targets`
  - `cargo clippy --all-targets -- -D warnings` (cero advertencias)
  - `cargo test --all` (41 tests unitarios + 7 de integración + 6 doc-tests)
  - `cargo fmt --all -- --check`

## [0.1.0] - 2026-09-06

- Versión inicial del crate `vmspect`: inspección estática de imágenes de disco de
  máquinas virtuales (VMDK, RAW, QCOW2, VDI, VHD, VHDX), detección de esquemas de
  partición MBR/GPT, identificación de sistemas de archivos (NTFS, FAT, ext2/3/4,
  XFS, Btrfs, LVM2, swap), extracción de software instalado en Windows
  (Registro vía NTFS) y Linux (`dpkg` vía ext2/3/4), backend híbrido nativo/`qemu-nbd`,
  procesamiento concurrente con cancelación cooperativa y reporte de progreso
  lock-free.
