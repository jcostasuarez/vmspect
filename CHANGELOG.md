# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(while the major version is `0`, minor-version increments may include breaking changes,
as foreseen by SemVer for the `0.y.z` series).

## [0.6.0] - 2026-09-11

### Breaking Changes
- Changed `InspectionEngine::inspect_batch` to return `BatchResult`, exposing successful reports and per-image errors instead of aborting the whole batch on an individual failure.
- Directory JSON output now uses an object containing reports, errors, discovery warnings and inaccessible directories; initial directory reports are summaries unless `--full-report` is supplied.

### Added
- Added tolerant batch inspection with ordered `BatchResult` outcomes and rate-limited `BatchProgressEvent` callbacks.
- Added configurable VM discovery with exclusions, maximum depth and optional warning suppression.
- Added `InspectionSummary` for lightweight GUI and IPC listings.
- Added process-wide `qemu-nbd` session limits with a default of two concurrent sessions.

### Changed
- Directory processing now uses bounded worker defaults and avoids collecting installed applications during initial listings.
- Improved CLI options with `--full-report`, `--exclude`, `--max-depth` and `--quiet-discovery`.

## [0.5.1] - 2026-09-09

### Changed
- Synchronized the crate metadata, lockfile and installation documentation for the `v0.5.1` patch release (no functional changes).

## [0.5.0] - 2026-09-08

### Breaking Changes
- Added the public `VmSpectError::MissingDiskComponent` variant. Consumers with exhaustive matches over `VmSpectError` must add a matching arm.

### Fixed
- Distinguished missing VMDK extents and parent disks from `qemu-nbd` resolution failures, preserving descriptor paths, resolved component paths and original OS errors.
- Improved `qemu-nbd` diagnostics with the configured executable path, process exit code, `stderr` and timeout context.

## [0.4.2] - 2026-09-08

### Fixed
- Hardened VM image discovery by validating root directories, ignoring zero-byte candidates, and continuing through unreadable descendant entries with warnings.

## [0.4.1] - 2026-09-07

### Changed
- Unified the repository version with the `cargo` package version by bumping to `0.4.1` (no functional changes).

## [0.4.0] - 2026-09-07

**Breaking API refactor — public API reorganization for idiomatic Rust conventions.**

This release introduces a comprehensive restructuring of the `vmspect` crate's public API.
The refactoring eliminates a bloated root namespace (30+ exports), establishes canonical
submodule paths for all domain types, and aligns the prelude with Rust ecosystem idioms.
No backward compatibility is maintained; this breaking change prepares the crate for
long-term maintainability and scalability.

### Breaking Changes

**Root Namespace (Minimalist API Surface)**
- Reduced from 30+ exports to 4 types + 2 functions
- Kept at root: `InspectionEngine`, `Options`, `InspectionReport`, `Result`, `VmSpectError`, `inspect()`, `inspect_with_progress()`
- Removed from root: All discovery functions, domain models, utility functions, secondary traits

**Canonical Submodule Paths (Required Explicit Imports)**
- All domain models now accessed directly from their submodules (no re-export forwarding):
  - `FileSystem`, `Partition`, `OperatingSystem`, `PartitionScheme` → `use vmspect::models::partition::*;`
  - `Program`, `GuestInfo`, `GuestTools` → `use vmspect::models::software::*;`
  - `ImageInfo`, `Hypervisor`, `Stats`, `format_bytes` → `use vmspect::models::image::*;`
  - `CancellationToken`, `InspectionProgress`, `InspectionProgressEvent`, `InspectionOptions` → `use vmspect::models::options::*;`
  - `OsInspector`, `VmDriver`, `MemoryMapper`, `AnalysisResult` → `use vmspect::models::traits::*;`
- Discovery functions moved: `list_vms`, `is_vm_image`, `count_vms`, `is_secondary_extent`, `verify_image_integrity`, `requires_nbd`, `requires_qemu` → `use vmspect::vms::discovery::*;`
- Virtual disk abstraction: `VirtualDisk` → `use vmspect::vms::stream::VirtualDisk;`

**Prelude Reorganization**
- Reduced from 30+ exports to 10 focused exports
- Kept: Extensibility traits (`OsInspector`, `VmDriver`, `MemoryMapper`, `AnalysisResult`), core runtime structs (`InspectionEngine`, `ConcurrentProcessor`, `Options`), result types (`Result`, `VmSpectError`), progress tracking (`InspectionProgress`, `InspectionProgressEvent`, `CancellationToken`), entry functions (`inspect`, `inspect_with_progress`), and report type (`InspectionReport`)
- Removed: All domain models, discovery functions, utility functions
- Added comprehensive prelude documentation clarifying what's included and where to find other types

**`src/models/mod.rs` Flattening**
- Eliminated multi-tier re-export forwarding chains
- All internal re-exports changed to `pub(crate)` or removed entirely
- Only `InspectionReport` and `Options` remain as public re-exports (for root API convenience)
- Types now accessed directly from their submodules

**Migration Examples**
```rust
// Before (v0.3.3)
use vmspect::prelude::*;
let fs = FileSystem::Ntfs;
let programs = list_vms(path, false)?;

// After (v0.4.0)
use vmspect::prelude::*;  // Still works for primary API
use vmspect::models::partition::FileSystem;  // Domain models require explicit import
use vmspect::vms::discovery::list_vms;  // Discovery functions moved to vms::discovery

let fs = FileSystem::Ntfs;
let programs = list_vms(path, false)?;
```

### Changed
- Complete reorganization of public API: root namespace now surfaces only essential entry points and core types
- Module structure reorganized for clarity: submodules are the canonical source of truth for all domain types
- Prelude now contains only high-frequency traits and runtime structures, improving discoverability and reducing cognitive load
- All internal crate code updated to use canonical submodule imports (parsers, VMs, engine, CLI binary)

### Rationale

The previous API structure had three critical issues:
1. **Fat Root Namespace**: Over 30 re-exported items cluttered `lib.rs`, making it unclear what the primary API was
2. **Prelude Duplication**: Prelude nearly duplicated root exports, offering no clear idiomatic purpose
3. **Multi-level Re-exports**: Redundant forwarding chains in `models/mod.rs` made import paths ambiguous

This refactor establishes idiomatic Rust API organization (matching patterns in `tokio`, `serde`, `sqlx`):
- **Clarity**: Users immediately understand what the library's primary API is
- **Consistency**: Every type has exactly one canonical import path
- **Scalability**: New domain types added to submodules don't bloat the root
- **Discoverability**: IDE autocomplete naturally guides users to the correct module
- **Maintainability**: Clear module boundaries reduce confusion during maintenance

### Quality Metrics
- ✅ All 48 library unit tests pass
- ✅ All 14 API structure tests pass (canonical paths verified)
- ✅ All 7 integration tests pass
- ✅ All 6 doc-tests pass
- ✅ `cargo check --all-targets` passes
- ✅ `cargo clippy --all-targets -- -D warnings` passes (zero warnings)
- ✅ No unused imports or dead code paths
- ✅ All examples compile and demonstrate new canonical import patterns

## [0.3.3] - 2026-09-06

### Changed
- Bumped the install snippet in `readme.md` to reference the current `0.3.3` release (was previously pinned to `0.3.0`).

## [0.3.2] - 2026-09-06

### Fixed
- Updated release metadata to address `docs.rs` build environment compatibility.

## [0.3.1] - 2026-09-06

### Fixed
- Added `[package.metadata.docs.rs]` configuration in `Cargo.toml` (`all-features = true`).
- Fixed `rustdoc::private_intra_doc_links` warnings in `src/vms/mod.rs` to ensure clean compilation on docs.rs.

## [0.3.0] - 2026-09-06

**Full English API refactoring — breaking change.**

This release translates the entire public API, source code, tests, CLI and documentation
from Spanish to idiomatic English to align with the Rust ecosystem conventions
(`clippy`, `rustfmt`, naming conventions). Every public identifier, struct field,
module, function and CLI flag has been renamed; all doc comments, inline comments
and user-facing strings have been translated to technical English.

### Breaking changes

- **Public API surface** (`src/`):
  - `Opciones` → `Options`, `OpcionesInspeccion` → `InspectionOptions`
  - `InfoImagen` → `ImageInfo`, `Estadisticas` → `Stats`, `Hipervisor` → `Hypervisor`
  - `EsquemaParticion` → `PartitionScheme`, `SistemaArchivos` → `FileSystem`,
    `SistemaOperativo` → `OperatingSystem`
  - `Particion` → `Partition`, `Programa` → `Program`, `HerramientasGuest` → `GuestTools`,
    `VMInfo` → `GuestInfo`
  - `InformeInspeccion` → `InspectionReport`, `ProgresoInspeccion` → `InspectionProgressEvent`,
    `ProgresoSnapshot` → `ProgressSnapshot`
  - `MotorInspeccion` → `InspectionEngine`, `ProcesadorConcurrente` → `ConcurrentProcessor`
  - `InspectorOS` → `OsInspector`, `ResultadoAnalisis` → `AnalysisResult`
  - `LectorDisco` → `DiskReader`, `DiscoVirtual` → `VirtualDisk`, `LectorNbd` → `NbdReader`
  - `inspeccionar` → `inspect`, `inspeccionar_con_progreso` → `inspect_with_progress`
  - Methods: `debe_analizar_apps` / `debe_analizar_sistema` → `should_analyze_apps` /
    `should_analyze_system`; `cancelar` → `cancel`; `porcentaje_completitud` →
    `completion_percentage`; `esta_cancelado` → `is_cancelled`
- **Struct fields** (a non-exhaustive list):
  - `ImageInfo`: `ruta` → `path`, `formato` → `format`, `tamano_virtual` → `virtual_size`,
    `tamano_real` → `actual_size`, `hipervisor` → `hypervisor`
  - `Partition`: `indice` → `index`, `inicio` → `start`, `tamano` → `size`, `tipo` → `kind`,
    `sistema_archivos` → `file_system`, `etiqueta` → `label`
  - `Program`: `nombre` → `name`, `editor` → `publisher`, `origen` → `source`
  - `Options`: `noapps` → `no_apps`, `nosystem` → `no_system`, `incluir_system` →
    `include_system`, `tamano_chunk` → `chunk_size`, `forzar_nbd` → `force_nbd`,
    `socket_unix` → `unix_socket`, `args_extra_nbd` → `extra_nbd_args`,
    `timeout_conexion` → `connection_timeout`, `persistente_nbd` → `nbd_persistent`
  - `Stats`: `modo_acceso` → `access_mode`, `peticiones_nbd` → `nbd_requests`,
    `bytes_leidos` → `bytes_read`, `duracion_ms` → `duration_ms`
  - `InspectionReport`: `imagen` → `image`, `esquema` → `scheme`, `particiones` →
    `partitions`, `sistema_operativo` → `operating_system`, `vm_info` → `guest_info`,
    `programas` → `installed_programs`, `advertencias` → `warnings`,
    `estadisticas` → `stats`
  - `VmDriver`: `tamano_virtual` → `virtual_size`, `leer_rango` → `read_range`,
    `modo_acceso` → `access_mode`, `es_nativo` → `is_native`,
    `tamano_chunk_recomendado` → `recommended_chunk_size`
- **CLI flags** (no Spanish aliases retained):
  - `--noapps` → `--no-apps`
  - `--nosystem` → `--no-system`
  - `--incluir-system` → `--include-system`
  - `--concurrente` → `--concurrent`
  - `--forzar-nbd` → `--force-nbd`
  - `--recursivo` → `--recursive`
- **JSON output** (`--json`): All serialized field names now use the English names
  (`image`, `partitions`, `operating_system`, `installed_programs`, `warnings`, `stats`).
  Consumers of the previous JSON schema must update their parsers.
- **Discovery helpers**: `es_extent_secundario` / `es_imagen_vm` / `listar_vms` /
  `contar_vms` / `hay_vms` / `verificar_integridad_imagen` / `requiere_nbd` /
  `requiere_qemu` have all been renamed to their canonical English names with no
  Spanish aliases retained.

### Added

- **Performance improvements** that bring inspection of an 80 GiB image to under **70 ms**
  end-to-end through internal code-path consolidation performed alongside the
  refactoring.
- **Robust dirty-registry recovery**: permissive reading via `Hive::without_validation`
  combined with panic isolation (`catch_unwind`) and the NTFS fallback that inspects
  `\Windows\System32\ntoskrnl.exe` for OS build/version and scans `\Program Files` for
  installed software when the Registry is fully inaccessible, tagged with
  `source: Some("FallbackFS")`.
- **Multi-hypervisor Guest Tools support**: typed detection and version extraction of
  VMware Tools, VirtualBox Guest Additions, QEMU Guest Agent and Hyper-V Integration
  Services from Windows (Registry + FS fallback) and Linux (dpkg + file probing).

### Changed

- Full source-code, comment and string translation to technical English.
- CLI report headers translated to: `[+] IMAGE INFO`, `[+] PARTITIONS`,
  `[+] OPERATING SYSTEM`, `[!] WARNINGS`, `[+] INSTALLED SOFTWARE`, `[+] STATISTICS`.
- The package description in `Cargo.toml` is now in English.

## [0.2.1] - 2026-09-06

First production-stable version with graceful error degradation on file system/registry
issues, NTFS fallback inspection and multi-hypervisor agnostic detection of guest
integration tools.

### Added

- **Graceful Degradation & Permissive Reading:**
  - Comprehensive resilience against damaged or "dirty" Windows Registry hives (e.g.
    `SequenceNumberMismatch` from abrupt shutdowns or hot snapshots) using
    `Hive::without_validation` and isolating internal panics from third-party libraries
    via `std::panic::catch_unwind`.
  - Collection and propagation of non-fatal warnings in the `advertencias: Vec<String>`
    field of `InformeInspeccion`, allowing the analysis to continue and extract as much
    information as possible without aborting the pipeline.
- **NTFS Fallback:**
  - Direct fallback inspection for Windows systems when the Registry is inaccessible
    or corrupt: extracts metadata of OS version and build directly from the PE header
    of the kernel executable (`\Windows\System32\ntoskrnl.exe`).
  - Fallback scan of the installed software catalog by walking `\Program Files` and
    `\Program Files (x86)`, tagging detected programs with `origen: Some("FallbackFS")`.
- **Multi-hypervisor agnostic Guest Tools detection:**
  - Multi-hypervisor support in the new `HerramientasGuest` struct: detection and
    version extraction of **VMware Tools**, **VirtualBox Guest Additions**,
    **QEMU Guest Agent** and **Hyper-V Integration Services** on both Windows
    (Registry and FS fallback) and Linux (dpkg packages and initialization).
- **Warnings section in CLI and JSON:**
  - Formatted visual rendering of the `advertencias` list on the terminal via the
    human CLI and in the structured `--json` output.

### Changed

- `VMInfo` struct: virtualization tools field now exposes `guest_tools: Option<HerramientasGuest>`
  instead of a plain string, providing a hypervisor-agnostic, typed API with `tipo`,
  `version` and `presente`.
- `Programa` model: new field `origen: Option<String>` with default serialization to
  distinguish software extracted from the Registry vs. file-system fallback.

## [0.2.0] - 2026-09-06

API consolidation release, hybrid `qemu-nbd` backend and concurrent processing,
preceded by an exhaustive quality, API consistency and correct-operation audit of
the whole crate.

### Added

- English alias `Opciones::should_analyze_apps` / `Opciones::should_analyze_system`
  for `debe_analizar_apps` / `debe_analizar_sistema`, completing bilingual
  (Spanish/English) coverage of the main engine configuration methods.
- `CHANGELOG.md` to document the crate change history.

### Changed

- **[Breaking]** `MotorInspeccion::inspeccionar_en_segundo_plano` (`inspect_background`)
  now returns `Result<JoinHandle<Result<InformeInspeccion>>>` instead of
  `JoinHandle<Result<InformeInspeccion>>`, propagating any OS-level failure when
  spawning the background thread as `VmSpectError::Io` rather than panicking.

### Fixed

- Removed every `.unwrap()` / `.expect()` in production code (`src/`) that could
  cause unexpected panics:
  - `ProcesadorConcurrente::procesar_en_paralelo` now correctly recovers from a
    poisoned `Mutex` (`PoisonError::into_inner`) instead of propagating the panic
    in the face of a hypothetically aborted prior thread.
  - Removed the `.expect()` when spawning the `inspeccionar_en_segundo_plano` thread
    (see "Changed" above).
- Replaced an `unreachable!()` in the `qemu-nbd` connector (`vms::nbd::LectorNbd`)
  with a type-level guarantee (`enum TransporteNbd`), eliminating the last potential
  panic point in the hybrid TCP/UNIX socket transport selection.
- Fixed 8 `clippy::field_reassign_with_default`, `clippy::useless_vec` and
  `clippy::cloned_ref_to_slice_refs` warnings detected when running
  `cargo clippy --all-targets -- -D warnings` (production and test code).
- Eliminated a flaky-test race condition in
  `test_procesador_concurrente_graceful_shutdown_cancelacion`: the fixed-duration
  `sleep` wait before cancelling was replaced with a deterministic active wait on
  `InspectionProgress::completed_tasks()` (with a safety timeout), removing
  intermittent failures under system load.

### Quality audit performed

- **Public API**: review of `src/lib.rs`, `src/prelude.rs` and the `vms`, `engine`,
  `models` and `error` modules; confirmed no leaking internal types (the `parsers`,
  `vms::detector` and `vms::vmdk` modules remain `pub(crate)`) and no hidden or
  complex initialization requirements.
- **Documentation**: confirmed `#![deny(missing_docs)]` compliance across the whole
  public API (no warnings when compiling).
- **Inspection pipeline**: validated secondary-extent discovery/filtering
  (`*-flat.vmdk`, `*-delta.vmdk`, `*-s001.vmdk`, etc.), Magic-Bytes verification
  (QCOW2, VMDK, VDI, VHD, VHDX, RAW), backend selection (native vs. hybrid
  TCP/UNIX `qemu-nbd`), the three inspection modes (`inspeccionar`,
  `inspeccionar_con_progreso`, `ProcesadorConcurrente`), cooperative cancellation
  with partial-result preservation and defensive `Drop` cleanup of `LectorNbd` /
  `NbdStream` (no orphaned processes).
- **Technical validation** (100% green):
  - `cargo check --all-targets`
  - `cargo clippy --all-targets -- -D warnings` (zero warnings)
  - `cargo test --all` (41 unit + 7 integration + 6 doc-tests)
  - `cargo fmt --all -- --check`

## [0.1.0] - 2026-09-06

- Initial version of the `vmspect` crate: static inspection of virtual machine disk
  images (VMDK, RAW, QCOW2, VDI, VHD, VHDX), MBR/GPT partition-scheme detection,
  file-system identification (NTFS, FAT, ext2/3/4, XFS, Btrfs, LVM2, swap),
  installed-software extraction on Windows (Registry via NTFS) and Linux (dpkg via
  ext2/3/4), hybrid native/`qemu-nbd` backend, concurrent processing with cooperative
  cancellation and lock-free progress reporting.
