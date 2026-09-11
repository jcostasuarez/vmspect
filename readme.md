# vmspect

[![Crates.io](https://img.shields.io/crates/v/vmspect.svg)](https://crates.io/crates/vmspect)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)]()

`vmspect` is a Rust library and CLI tool for **ultra-fast static inspection, forensic analysis and information extraction of virtual machine disk images** (VMDK, RAW, QCOW2, VHD, VHDX, VDI, etc.).

It can examine partition-table structures (MBR/GPT), identify the guest operating system (Windows/Linux), extract complete lists of installed software and detect integration tools (Guest Tools) in a **non-invasive** way. Standard inspection opens the image read-only and never boots, mounts or attaches it to the host, so it needs no administrator privileges and creates no visible drive.

---

## 🚀 Key Features

- **Direct-read by default, with bounded I/O:**
  - **Native Rust parser:** Direct, read-only on-demand reads for `RAW` and supported `VMDK` layouts (`monolithicSparse`, `monolithicFlat`, `twoGbMaxExtentFlat/Sparse`, etc.), without child processes, temporary image copies, host mounting or attachment.
  - **Explicit external compatibility mode:** Formats without a native parser (`QCOW2`, `VHDX`, `VDI`, compressed/streamOptimized VMDK) fail clearly in standard mode. Only `--force-nbd` / `Options::with_force_nbd(true)` starts `qemu-nbd` as a read-only helper; it is never an automatic fallback and does not mount or attach a host volume.
  - **Bounded cache and telemetry:** The parser loads only needed ranges into a bounded 64 MiB LRU cache and reports backend, reads, bytes, cache hits and phase durations.
- **Resilience against dirty registries and NTFS fallback (Graceful Degradation):**
  - **Permissive Windows Registry reading:** Tolerance for dirty or damaged registry hives (`SequenceNumberMismatch` caused by abrupt shutdowns or hot snapshots) using `Hive::without_validation` and isolating internal panics from third-party libraries via `catch_unwind`.
  - **NTFS fallback inspection:** If the Registry hives are totally inaccessible, `vmspect` gracefully degrades by inspecting the PE header of `\Windows\System32\ntoskrnl.exe` directly to extract the OS build and version, and scans `\Program Files`, tagging applications as `source: Some("FallbackFS")`.
  - **Non-fatal warnings list:** Reports issues in the `warnings` field of the report without aborting the inspection pipeline.
- **Multi-hypervisor, hypervisor-agnostic Guest Tools detection:**
  - Full and typed support in the `GuestTools` struct to identify and extract the version of:
    - **VMware Tools / open-vm-tools**
    - **VirtualBox Guest Additions**
    - **QEMU Guest Agent**
    - **Hyper-V Integration Services**
- **Supported guest operating systems:**
  - **Windows (NTFS):** Extracts Registry hives (`SOFTWARE` and `SYSTEM`) by parsing uninstall keys (32 and 64-bit), operating system version, build number, Service Pack and Guest Tools.
  - **Linux (ext2 / ext3 / ext4):** Reads `/etc/os-release`, `/etc/hostname` and analyzes the `/var/lib/dpkg/status` package database along with virtualization agents.
- **Scheme and file-system detection:**
  - Partition schemes: **MBR**, **GPT** and **Volumes without a partition table**.
  - Signature recognition: **NTFS**, **FAT12/16/32**, **ext2/3/4**, **XFS**, **Btrfs**, **LVM2 PV**, **Linux Swap**.
- **Agnostic and complete extraction:**
  - Default, complete collection of all applications and system information without noise filters or proprietary categorizations.
  - Support for `--no-apps` (disables application collection) and `--no-system` (disables OS metadata collection) flags.
- **Designed for UI and CLI:**
  - Exposes lock-free batch progress snapshots for external polling without report or program data.
  - Cancellation support via atomic tokens (`Arc<AtomicBool>` / `CancellationToken`) while preserving partial results.
  - Directory discovery is explicit and configurable with exclusions and a maximum depth. Initial directory results skip installed-program extraction; use `--full-report` or a full inspection when that data is required.
  - `qemu-nbd` sessions are limited process-wide (default: two) when explicitly enabled; direct readers do not consume a session.

---

## Política de no montaje y diagnóstico de `qemu-nbd`

El análisis estándar es **direct-read**: abre el archivo de imagen y sus extents en modo solo lectura,
lee cabeceras, tablas de partición y los rangos demandados por los parsers de NTFS/ext4. No usa
`Mount-DiskImage`, `diskpart`, `AttachVirtualDisk`, WMI/CIM, Hyper-V ni adaptadores de montaje,
y no crea letras de unidad, volúmenes, recursos compartidos ni copias temporales de la imagen.

Para formatos que aún no tienen parser directo, el análisis estándar devuelve un error
`UnsupportedFormat` en vez de lanzar un fallback. `--force-nbd` es una decisión explícita y muestra
una advertencia antes de iniciar el ayudante `qemu-nbd` de solo lectura. Este ayudante expone un
socket local al proceso, no una unidad del sistema operativo.

Las rutas UNC se marcan como origen de red en `Stats`; las unidades mapeadas y las carpetas
sincronizadas no se etiquetan de forma especulativa porque no puede detectarse de modo fiable sin
consultar servicios específicos del host. La biblioteca no escribe archivos de resultados: el
llamador decide dónde serializar el informe.

Un descriptor VMDK no siempre contiene los datos del disco. Puede declarar varios extents
(`FLAT`, `VMFS`, `VMFSRAW`, `SPARSE` o `VMFSSPARSE`) y también puede apuntar a un disco padre
mediante `parentFileNameHint`. Todos esos archivos forman parte de la entrada que debe estar
disponible para la inspección.

Cuando falta un componente, `vmspect` devuelve `VmSpectError::MissingDiskComponent` en lugar de
`VmSpectError::QemuNotFound`. El error conserva el nombre declarado, el descriptor principal,
la ruta resuelta y el error original del sistema operativo. Por ejemplo:

```text
Missing VMDK extent 'disk-s001.vmdk' referenced by 'fixtures/sample-vm/disk.vmdk'. Resolved path: 'fixtures/sample-vm/disk-s001.vmdk'. OS error: file not found.
```

`qemu-nbd` no puede reparar una cadena VMDK incompleta: solo proporciona acceso a una imagen
que ya es coherente. Si falta un extent o un disco padre, hay que recuperar el archivo correcto
desde el almacenamiento original o desde una copia consistente. No se debe renombrar otro
extent para sustituir al faltante, porque eso puede mezclar segmentos distintos y producir una
imagen silenciosamente corrupta.

Los errores de resolución del ejecutable (`qemu_nbd`, `QEMU_NBD` o `PATH`) se reportan como
`QemuNotFound`. Los fallos del proceso ya iniciado —código de salida distinto de cero,
`stderr`, handshake o timeout NBD— se reportan como `Nbd` y conservan el contexto de ejecución.

---

## 📂 Crate Structure

The project follows the standard Rust library package convention:

```text
vmspect/
├── Cargo.toml               # Crate configuration, metadata and dependencies
├── readme.md                # Main documentation
├── LICENSE                  # MIT / Apache-2.0 license
├── src/
│   ├── lib.rs               # Library entry point (public API and re-exports)
│   ├── models/              # Domain types (InspectionReport, GuestInfo, Partition, etc.)
│   │   ├── image.rs
│   │   ├── options.rs       # Inspection options, progress and cancellation
│   │   ├── partition.rs
│   │   ├── software.rs      # Program and GuestInfo models
│   │   └── traits.rs        # Abstract traits (OsInspector, VmDriver, MemoryMapper)
│   ├── parsers/             # Per-OS analyzers
│   │   ├── mod.rs           # OsInspector trait and polymorphic factory
│   │   ├── windows.rs       # NTFS extraction and Registry parsing (nt-hive)
│   │   ├── linux.rs         # ext4 superblock reading and DPKG database
│   │   └── desconocido.rs   # Handling of unrecognized operating systems
│   └── vms/                 # Disk access and virtualization layer
│       ├── mod.rs           # Disk access module
│       ├── detector.rs       # MBR/GPT detection and FS signatures
│       ├── nbd.rs           # Native NBD client and qemu-nbd connector
│       ├── stream.rs        # DiskReader facade and VirtualDisk view (Read + Seek)
│       └── vmdk.rs          # Native VMDK parser (sparse and descriptors)
├── tests/                   # Integration tests
│   └── integration_test.rs
└── examples/                # Ready-to-run usage examples
    ├── basic_inspection.rs
    └── batch_polling.rs
```

---

## 📦 Installation

Add `vmspect` to your `Cargo.toml`:

```toml
[dependencies]
vmspect = "0.8.0"
```

---

## 💡 Examples as a Library

### 1. Full Inspection with Guest Tools, Warnings and Progress

```rust
use std::path::Path;
use vmspect::{inspect_with_progress, Options, InspectionProgressEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new("virtual_disk.vmdk");
    
    // Options configuration (e.g. full OS and application analysis)
    let options = Options::default();

    let report = inspect_with_progress(path, &options, |p: InspectionProgressEvent| {
        println!("[{:>3}%] {} - {}", p.percentage, p.stage, p.detail.unwrap_or_default());
    })?;

    println!("Disk format: {}", report.image.format);
    println!("Operating system: {:?}", report.operating_system);
    println!("OS details: {}", report.guest_info.formatted_os_string());
    
    // Hypervisor-agnostic Guest Tools detection (VMware, VirtualBox, QEMU, Hyper-V)
    if let Some(ref tools) = report.guest_info.guest_tools {
        if tools.present {
            println!("Guest tools: {} (version: {})", tools.kind, tools.version.as_deref().unwrap_or("N/A"));
        }
    }

    // Non-fatal warnings (graceful Registry/FS degradation)
    if !report.warnings.is_empty() {
        println!("Inspection warnings:");
        for w in &report.warnings {
            println!("  [!] {}", w);
        }
    }

    println!("Partitions detected: {}", report.partitions.len());
    println!("Installed software found: {}", report.installed_programs.len());

    for prog in report.installed_programs.iter().take(10) {
        let source = prog.source.as_deref().map(|s| format!(" [{}]", s)).unwrap_or_default();
        println!(
            " - {} (v{}) [Publisher: {}]{}",
            prog.name,
            prog.version.as_deref().unwrap_or("N/A"),
            prog.publisher.as_deref().unwrap_or("N/A"),
            source
        );
    }

    Ok(())
}
```

### 2. Advanced Extraction Options

```rust
use vmspect::Options;

// Disable application or system extraction depending on performance needs:
let light_options = Options {
    no_apps: true,           // Skip installed-software scan
    no_system: false,        // Keep OS detection and Guest Tools
    force_nbd: false,        // Standard mode: never launch an external fallback
    ..Options::default()
};

assert!(!light_options.should_analyze_apps());
assert!(light_options.should_analyze_system());
```

### 3. Concurrent Batch Processing with Polling

`InspectionEngine::inspect_batch` never calls UI, IPC, serialization, or user callback code.
Obtain `engine.progress()` before starting the batch and poll its atomic snapshot from a
separate thread, task, or timer. Reading progress does not block workers. A cancelled batch
can finish with `completed_tasks < total_tasks`, so the worker handle also determines when to
stop polling.

```rust
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use vmspect::{InspectionEngine, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let images = vec![
        PathBuf::from("srv1.vmdk"),
        PathBuf::from("srv2.raw"),
        PathBuf::from("srv3.qcow2"),
        PathBuf::from("srv4.vhdx"),
    ];

    let engine = Arc::new(InspectionEngine::new(Options::default()));
    let progress = engine.progress();

    let worker_engine = Arc::clone(&engine);
    let handle = std::thread::spawn(move || worker_engine.inspect_batch(images, 2));

    loop {
        let snapshot = progress.snapshot();
        let percentage = progress.completion_percentage();
        let completed = progress.completed_tasks();
        let total = progress.total_tasks();

        // Update the external UI with `snapshot`. Poll every 250-500 ms.
        println!("[{percentage:>5.1}%] {completed}/{total}");

        // `is_finished` also handles empty and partially cancelled batches.
        if handle.is_finished()
            || (snapshot.total_tasks > 0 && snapshot.completed_tasks >= snapshot.total_tasks)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let result = handle.join().expect("worker thread panicked")?;
    println!("Total reports recovered: {}", result.reports.len());
    println!("Image errors: {}", result.errors.len());
    Ok(())
}
```

### GUI / IPC initial listing

For a GUI or IPC service, callers must always select the VM folders to discover; `vmspect`
does not scan drive roots or any default location. Use `list_vms_with_options` to apply
recursion, exclusions and depth limits. Perform the initial directory batch with
`Options { no_apps: true, ..Options::default() }`, display each `InspectionSummary`, and
run an individual full inspection only when the user opens a VM and needs
`installed_programs`. Batch JSON is an object with `reports` and `errors`; directory JSON
contains summaries unless `--full-report` is explicitly supplied.

### 4. Tauri / Async Runtime Integration

Run `inspect_batch` in `tauri::async_runtime::spawn_blocking`. Keep an
`Arc<InspectionEngine>` in managed application state, expose a lightweight independent command
that returns `engine.progress().snapshot()`, and have the frontend invoke that command from a
250-500 ms timer. Do not emit events from the inspection worker.

```rust,ignore
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use vmspect::{BatchResult, InspectionEngine, Options, ProgressSnapshot};

struct InspectionState {
    engine: Arc<InspectionEngine>,
}

#[tauri::command]
async fn inspect_vms(
    state: State<'_, InspectionState>,
    paths: Vec<PathBuf>,
) -> Result<BatchResult, String> {
    let engine = Arc::clone(&state.engine);
    tauri::async_runtime::spawn_blocking(move || engine.inspect_batch(paths, 2))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn inspection_progress(state: State<'_, InspectionState>) -> ProgressSnapshot {
    state.engine.progress().snapshot()
}
```

The UI polls `inspection_progress` independently while `inspect_vms` runs. The inspection
worker neither emits Tauri events nor serializes progress payloads.

---

## 🖥️ Command-Line Interface (CLI) Usage

`vmspect` ships a high-performance terminal binary:

```bash
# Standard inspection with human-formatted output:
vmspect /path/to/disk.vmdk

# Structured JSON output (ideal for scripts, CI/CD pipelines and forensic analysis):
vmspect /path/to/disk.qcow2 --json

# Concurrent recursive scan of a full VM directory:
vmspect /var/lib/libvirt/images/ --concurrent --recursive --workers 8

# Fast inspection skipping application extraction:
vmspect /path/to/disk.vhdx --no-apps

# Inspection skipping OS metadata:
vmspect /path/to/disk.raw --no-system
```

---

## 🛠️ Running Tests and Examples

### Run Unit and Integration Tests:
```bash
cargo test
```

### Run Example with a Real Disk:
```bash
cargo run --example basic_inspection -- /path/to/your/disk.vmdk
```

---

## 📄 License

This project is licensed under the **MIT** or **Apache-2.0** license at your option.