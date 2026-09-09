# vmspect

[![Crates.io](https://img.shields.io/crates/v/vmspect.svg)](https://crates.io/crates/vmspect)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)]()

`vmspect` is a Rust library and CLI tool for **ultra-fast static inspection, forensic analysis and information extraction of virtual machine disk images** (VMDK, RAW, QCOW2, VHD, VHDX, VDI, etc.).

It can examine partition-table structures (MBR/GPT), identify the guest operating system (Windows/Linux), extract complete lists of installed software and detect integration tools (Guest Tools) in a **non-invasive** way (without booting the virtual machine or requiring mount privileges on the host).

---

## 🚀 Key Features

- **Efficient, lightweight streaming:**
  - **Native Rust parser:** Direct, ultra-low-latency reading for `RAW` and `VMDK` images (`monolithicSparse`, `monolithicFlat`, `twoGbMaxExtentFlat/Sparse`, etc.) without external dependencies or child processes.
  - **Integrated `qemu-nbd` server:** For complex formats (`QCOW2`, `VHDX`, `VDI`, compressed/streamOptimized VMDK), connects over a local TCP socket (`127.0.0.1`) or UNIX sockets using the standard NBD protocol, with direct block streaming and no temporary files on disk.
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
  - Emits progress events in structured percentages (`0%` to `100%`) ideal for **Tauri**, **egui** or **Electron**.
  - Cancellation support via atomic tokens (`Arc<AtomicBool>` / `CancellationToken`) while preserving partial results.

---

## Diagnóstico de componentes VMDK y `qemu-nbd`

Un descriptor VMDK no siempre contiene los datos del disco. Puede declarar varios extents
(`FLAT`, `VMFS`, `VMFSRAW`, `SPARSE` o `VMFSSPARSE`) y también puede apuntar a un disco padre
mediante `parentFileNameHint`. Todos esos archivos forman parte de la entrada que debe estar
disponible para la inspección.

Cuando falta un componente, `vmspect` devuelve `VmSpectError::MissingDiskComponent` en lugar de
`VmSpectError::QemuNotFound`. El error conserva el nombre declarado, el descriptor principal,
la ruta resuelta y el error original del sistema operativo. Por ejemplo, con rutas sintéticas:

```text
Missing VMDK extent 'sample-disk-s001.vmdk' referenced by 'C:\virtual-machines\sample\sample-disk.vmdk'. Resolved path: 'C:\virtual-machines\sample\sample-disk-s001.vmdk'. OS error: The system cannot find the file specified.
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
    └── basic_inspection.rs
```

---

## 📦 Installation

Add `vmspect` to your `Cargo.toml`:

```toml
[dependencies]
vmspect = "0.5.1"
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
    force_nbd: false,        // Use the ultra-fast native parser when available
    ..Options::default()
};

assert!(!light_options.should_analyze_apps());
assert!(light_options.should_analyze_system());
```

### 3. Concurrent Processing and Result Preservation on Cancellation

`ConcurrentProcessor` and `InspectionEngine` provide clean shutdown (Graceful Shutdown) with **partial-result preservation**. When the cancellation token is triggered, worker threads do not accept new images, safely finish the in-progress analysis and return all successfully processed reports:

```rust
use std::path::PathBuf;
use vmspect::prelude::*;

fn main() -> Result<()> {
    let paths = vec![
        PathBuf::from("srv1.vmdk"),
        PathBuf::from("srv2.raw"),
        PathBuf::from("srv3.qcow2"),
        PathBuf::from("srv4.vhdx"),
    ];

    let cancel = CancellationToken::new();
    let options = Options::default()
        .with_cancellation_token(&cancel);

    let engine = InspectionEngine::new(options);

    // Cancel at any time from another thread or callback:
    // cancel.cancel();

    // Returns all reports completed before and during cancellation:
    let completed_reports = engine.inspect_batch(paths, 4)?;

    println!("Total reports recovered: {}", completed_reports.len());
    for r in &completed_reports {
        println!(" - {} (OS: {:?})", r.image.path.display(), r.operating_system);
    }

    Ok(())
}
```

### 4. Tauri / Async Runtime Integration

```rust,ignore
use tauri::Emitter;
use vmspect::{inspect_with_progress, InspectionReport, InspectionProgressEvent, Options};

#[tauri::command]
async fn inspect_vm(app_handle: tauri::AppHandle, path: String) -> Result<InspectionReport, String> {
    let path = std::path::PathBuf::from(path);
    let options = Options::default();

    tauri::async_runtime::spawn_blocking(move || {
        inspect_with_progress(&path, &options, |p: InspectionProgressEvent| {
            let _ = app_handle.emit("inspection_progress", p);
        })
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
```

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

### Run Example with a Disk Image:
```bash
cargo run --example basic_inspection -- /path/to/your/disk.vmdk
```

---

## 📄 License

This project is licensed under the **MIT** or **Apache-2.0** license at your option.