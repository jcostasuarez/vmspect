# vmspect

[![Crates.io](https://img.shields.io/crates/v/vmspect.svg)](https://crates.io/crates/vmspect)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)]()

`vmspect` es una biblioteca (crate) en Rust para la **inspección estática, análisis forense y extracción de información de imágenes de disco de máquinas virtuales** (VMDK, RAW, QCOW2, VHD, VHDX, VDI, etc.).

Permite examinar la estructura de particiones (MBR/GPT), identificar el Sistema Operativo huésped (Windows/Linux) y extraer listas completas de software instalado y metadatos de forma **no invasiva** (sin arrancar la máquina virtual ni requerir permisos de montaje en el host).

---

## 🚀 Características Principales

- **Acceso Híbrido y Liviano:**
  - **Parser nativo en Rust:** Lectura directa y de alto rendimiento para imágenes `RAW` y `VMDK` (`monolithicSparse`, `monolithicFlat`, `twoGbMaxExtentFlat/Sparse`, etc.) sin dependencias externas ni procesos secundarios.
  - **Servidor `qemu-nbd` integrado:** Para formatos complejos (`QCOW2`, `VHDX`, `VDI`, VMDK comprimidos/streamOptimized), conecta mediante socket TCP local (`127.0.0.1`) con el protocolo NBD estándar, con streaming directo de bloques y sin archivos temporales en disco.
- **Sistemas Operativos Huésped:**
  - **Windows (NTFS):** Extrae las colmenas del Registro (`SOFTWARE` y `SYSTEM`) parseando llaves de desinstalación (32 y 64 bits), versión del sistema operativo, compilación (Build), Service Pack y versión de *VMware Tools*.
  - **Linux (ext2 / ext3 / ext4):** Lee `/etc/os-release`, `/etc/hostname` y analiza la base de datos de paquetes `/var/lib/dpkg/status` junto con *open-vm-tools*.
- **Detección de Esquemas y Sistemas de Archivos:**
  - Esquemas de particionado: **MBR**, **GPT** y **Volúmenes sin tabla de particiones**.
  - Reconocimiento de firmas: **NTFS**, **FAT12/16/32**, **ext2/3/4**, **XFS**, **Btrfs**, **LVM2 PV**, **Linux Swap**.
- **Extracción Agnóstica y Completa:**
  - Recolección completa por defecto de todas las aplicaciones e información del sistema sin filtros de ruido ni categorizaciones propietarias.
  - Soporte de banderas `--noapps` (desactiva recolección de aplicaciones) y `--nosystem` (desactiva recolección de metadatos del SO).
- **Diseñado para UI y CLI:**
  - Emisión de eventos de progreso en porcentajes estructurados (`0%` a `100%`) ideales para **Tauri**, **egui** o **Electron**.
  - Soporte de cancelación mediante tokens atómicos (`Arc<AtomicBool>` / `CancellationToken`).

---

## 📂 Estructura del Crate

El proyecto sigue la convención estándar de paquetes de biblioteca en Rust:

```text
vmspect/
├── Cargo.toml               # Configuración del crate, metadatos y dependencias
├── readme.md                # Documentación principal
├── LICENSE                  # Licencia MIT / Apache-2.0
├── src/
│   ├── lib.rs               # Punto de entrada de la librería (API pública y re-exports)
│   ├── models/              # Tipos de dominio (InformeInspeccion, VMInfo, Particion, etc.)
│   │   ├── image.rs
│   │   ├── options.rs       # Opciones de inspección, progreso y cancelación
│   │   ├── partition.rs
│   │   ├── software.rs      # Modelos de Programa y VMInfo
│   │   └── traits.rs        # Traits abstractos (InspectorOS, VmDriver, MemoryMapper)
│   ├── parsers/             # Analizadores por sistema operativo
│   │   ├── mod.rs           # Trait InspectorOS y fábrica polimórfica
│   │   ├── windows.rs       # Extracción NTFS y parseo de Registro (nt-hive)
│   │   ├── linux.rs         # Lectura de superbloque ext4 y base DPKG
│   │   └── desconocido.rs   # Manejo de sistemas no reconocidos
│   └── vms/                 # Capa de acceso a disco y virtualización
│       ├── mod.rs           # Módulo de acceso a disco
│       ├── detector.rs      # Detección de MBR/GPT y firmas de FS
│       ├── nbd.rs           # Cliente NBD nativo y conector qemu-nbd
│       ├── stream.rs        # Fachada LectorDisco y vista DiscoVirtual (Read + Seek)
│       └── vmdk.rs          # Parser nativo de VMDK (sparse y descriptores)
├── tests/                   # Tests de integración
│   └── integration_test.rs
└── examples/                # Ejemplos de uso listos para ejecutar
    └── basic_inspection.rs
```

---

## 📦 Instalación

Añade `vmspect` a tu `Cargo.toml`:

```toml
[dependencies]
vmspect = "0.2"
```

---

## 💡 Ejemplos de Uso

### 1. Inspección Rápida con Progreso en Consola

```rust
use std::path::Path;
use vmspect::{inspeccionar_con_progreso, Opciones, ProgresoInspeccion};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ruta = Path::new("disco_virtual.vmdk");
    let opciones = Opciones::default();

    let informe = inspeccionar_con_progreso(ruta, &opciones, |p: ProgresoInspeccion| {
        println!("[{:>3}%] {} - {}", p.porcentaje, p.etapa, p.detalle.unwrap_or_default());
    })?;

    println!("Formato de disco: {}", informe.imagen.formato);
    println!("Sistema Operativo: {:?}", informe.sistema_operativo);
    println!("Detalles SO: {}", informe.vm_info.os_cadena_formateada());
    println!("Particiones detectadas: {}", informe.particiones.len());
    println!("Software instalado encontrado: {}", informe.programas.len());

    for prog in informe.programas.iter().take(10) {
        println!(" - {} (v{}) [Editor: {}]", prog.nombre, prog.version.as_deref().unwrap_or("N/D"), prog.editor.as_deref().unwrap_or("N/D"));
    }

    Ok(())
}
```

### 3. Procesamiento Concurrente y Preservación de Resultados ante Cancelación

`ProcesadorConcurrente` y `MotorInspeccion` ofrecen soporte de parada limpia (Graceful Shutdown) con garantía de **preservación de resultados parciales**. Cuando se activa el token de cancelación, los hilos de trabajo no aceptan nuevas imágenes, finalizan de manera segura el análisis en curso y devuelven todos los informes procesados con éxito:

```rust
use std::path::PathBuf;
use vmspect::prelude::*;

fn main() -> Result<()> {
    let rutas = vec![
        PathBuf::from("srv1.vmdk"),
        PathBuf::from("srv2.raw"),
        PathBuf::from("srv3.qcow2"),
        PathBuf::from("srv4.vhdx"),
    ];

    let cancel = CancellationToken::new();
    let opciones = Opciones::default()
        .with_cancellation_token(&cancel);

    let motor = MotorInspeccion::new(opciones);

    // Cancelar en cualquier momento desde otro hilo o callback:
    // cancel.cancel();

    // Devuelve todos los informes completados antes y durante la cancelación:
    let informes_completados = motor.inspeccionar_lote(rutas, 4)?;

    println!("Total de informes recuperados tras la ejecución: {}", informes_completados.len());
    for inf in &informes_completados {
        println!(" - {} (SO: {:?})", inf.imagen.ruta.display(), inf.sistema_operativo);
    }

    Ok(())
}
```

### 4. Integración con Tauri / Runtimes Asíncronos

```rust,ignore
use tauri::Emitter;
use vmspect::{inspeccionar_con_progreso, InformeInspeccion, Opciones, ProgresoInspeccion};

#[tauri::command]
async fn inspeccionar_vm(app_handle: tauri::AppHandle, ruta: String) -> Result<InformeInspeccion, String> {
    let path = std::path::PathBuf::from(ruta);
    let opciones = Opciones::default();

    tauri::async_runtime::spawn_blocking(move || {
        inspeccionar_con_progreso(&path, &opciones, |p: ProgresoInspeccion| {
            let _ = app_handle.emit("progreso_inspeccion", p);
        })
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
```

### 5. Control de Cancelación mediante Tokens

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::path::Path;
use vmspect::{inspeccionar, Opciones};

let cancel_token = Arc::new(AtomicBool::new(false));

let opciones = Opciones {
    cancel_token: Some(cancel_token.clone()),
    ..Opciones::default()
};

// En cualquier momento desde otro hilo:
// cancel_token.store(true, Ordering::Release);
```

---

## 🛠️ Ejecución de Pruebas y Ejemplos

### Correr Tests Unitarios e Integrales:
```bash
cargo test
```

### Ejecutar Ejemplo con un Disco Real:
```bash
cargo run --example basic_inspection -- ruta/a/tu/disco.vmdk
```

---

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia **MIT** o **Apache-2.0** a tu elección.
