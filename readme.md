# vmspect

[![Crates.io](https://img.shields.io/crates/v/vmspect.svg)](https://crates.io/crates/vmspect)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)]()

`vmspect` es una biblioteca (crate) y herramienta CLI en Rust para la **inspección estática ultra-rápida, análisis forense y extracción de información de imágenes de disco de máquinas virtuales** (VMDK, RAW, QCOW2, VHD, VHDX, VDI, etc.).

Permite examinar la estructura de particiones (MBR/GPT), identificar el Sistema Operativo huésped (Windows/Linux), extraer listas completas de software instalado y detectar herramientas de integración (Guest Tools) de forma **no invasiva** (sin arrancar la máquina virtual ni requerir permisos de montaje en el host).

---

## 🚀 Características Principales

- **Rendimiento eficiente y streaming liviano:**
  - **Parser nativo en Rust:** Lectura directa y de latencia ultra-baja para imágenes `RAW` y `VMDK` (`monolithicSparse`, `monolithicFlat`, `twoGbMaxExtentFlat/Sparse`, etc.) sin dependencias externas ni procesos secundarios.
  - **Servidor `qemu-nbd` integrado:** Para formatos complejos (`QCOW2`, `VHDX`, `VDI`, VMDK comprimidos/streamOptimized), conecta mediante socket TCP local (`127.0.0.1`) o sockets UNIX con el protocolo NBD estándar, con streaming directo de bloques y sin archivos temporales en disco.
- **Resiliencia ante Registros Sucios y Fallback NTFS (Graceful Degradation):**
  - **Lectura permisiva del Registro de Windows:** Tolerancia a colmenas de Registro sucias o dañadas (`SequenceNumberMismatch` provocado por apagados abruptos o snapshots en caliente) utilizando `Hive::without_validation` y aislamiento de panics internos con `catch_unwind`.
  - **Inspección NTFS Fallback:** En caso de colmenas de Registro totalmente inaccesibles, `vmspect` degrada elegantemente inspeccionando directamente el encabezado PE de `\Windows\System32\ntoskrnl.exe` para extraer compilación y versión del SO, y escanea `\Program Files` marcando las aplicaciones con `origen: Some("FallbackFS")`.
  - **Lista de Advertencias no fatales:** Reporte de incidencias en el campo `advertencias` del informe sin abortar el pipeline de inspección.
- **Detección Agnóstica Multi-Hipervisor de Guest Tools:**
  - Soporte completo y tipado en la estructura `HerramientasGuest` para identificar y extraer la versión de:
    - **VMware Tools / open-vm-tools**
    - **VirtualBox Guest Additions**
    - **QEMU Guest Agent**
    - **Hyper-V Integration Services**
- **Sistemas Operativos Huésped Soportados:**
  - **Windows (NTFS):** Extrae las colmenas del Registro (`SOFTWARE` y `SYSTEM`) parseando llaves de desinstalación (32 y 64 bits), versión del sistema operativo, compilación (Build), Service Pack y Guest Tools.
  - **Linux (ext2 / ext3 / ext4):** Lee `/etc/os-release`, `/etc/hostname` y analiza la base de datos de paquetes `/var/lib/dpkg/status` junto con agentes de virtualización.
- **Detección de Esquemas y Sistemas de Archivos:**
  - Esquemas de particionado: **MBR**, **GPT** y **Volúmenes sin tabla de particiones**.
  - Reconocimiento de firmas: **NTFS**, **FAT12/16/32**, **ext2/3/4**, **XFS**, **Btrfs**, **LVM2 PV**, **Linux Swap**.
- **Extracción Agnóstica y Completa:**
  - Recolección completa por defecto de todas las aplicaciones e información del sistema sin filtros de ruido ni categorizaciones propietarias.
  - Soporte de banderas `--noapps` (desactiva recolección de aplicaciones) y `--nosystem` (desactiva recolección de metadatos del SO).
- **Diseñado para UI y CLI:**
  - Emisión de eventos de progreso en porcentajes estructurados (`0%` a `100%`) ideales para **Tauri**, **egui** o **Electron**.
  - Soporte de cancelación mediante tokens atómicos (`Arc<AtomicBool>` / `CancellationToken`) preservando resultados parciales.

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
vmspect = "0.2.1"
```

---

## 💡 Ejemplos de Uso como Biblioteca

### 1. Inspección Completa con Guest Tools, Advertencias y Progreso

```rust
use std::path::Path;
use vmspect::{inspeccionar_con_progreso, Opciones, ProgresoInspeccion};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ruta = Path::new("disco_virtual.vmdk");
    
    // Configuración de opciones (ej. análisis completo de SO y aplicaciones)
    let opciones = Opciones::default();

    let informe = inspeccionar_con_progreso(ruta, &opciones, |p: ProgresoInspeccion| {
        println!("[{:>3}%] {} - {}", p.porcentaje, p.etapa, p.detalle.unwrap_or_default());
    })?;

    println!("Formato de disco: {}", informe.imagen.formato);
    println!("Sistema Operativo: {:?}", informe.sistema_operativo);
    println!("Detalles SO: {}", informe.vm_info.os_cadena_formateada());
    
    // Detección agnóstica de Guest Tools (VMware, VirtualBox, QEMU, Hyper-V)
    if let Some(ref tools) = informe.vm_info.guest_tools {
        if tools.presente {
            println!("Herramientas Guest: {} (Versión: {})", tools.tipo, tools.version.as_deref().unwrap_or("N/D"));
        }
    }

    // Advertencias no fatales (degradación elegante de registro/filesystem)
    if !informe.advertencias.is_empty() {
        println!("Advertencias de inspección:");
        for adv in &informe.advertencias {
            println!("  [!] {}", adv);
        }
    }

    println!("Particiones detectadas: {}", informe.particiones.len());
    println!("Software instalado encontrado: {}", informe.programas.len());

    for prog in informe.programas.iter().take(10) {
        let origen = prog.origen.as_deref().map(|o| format!(" [{}]", o)).unwrap_or_default();
        println!(
            " - {} (v{}) [Editor: {}]{}",
            prog.nombre,
            prog.version.as_deref().unwrap_or("N/D"),
            prog.editor.as_deref().unwrap_or("N/D"),
            origen
        );
    }

    Ok(())
}
```

### 2. Opciones Avanzadas de Extracción

```rust
use vmspect::Opciones;

// Desactivar extracción de apps o sistema según necesidades de rendimiento:
let opciones_ligeras = Opciones {
    noapps: true,          // Omite escaneo de software instalado
    nosystem: false,       // Conserva detección de SO y Guest Tools
    forzar_nbd: false,     // Usa parser nativo ultra-rápido si está disponible
    ..Opciones::default()
};

assert!(!opciones_ligeras.should_analyze_apps());
assert!(opciones_ligeras.should_analyze_system());
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

---

## 🖥️ Uso desde Línea de Comandos (CLI)

`vmspect` incluye un binario de alto rendimiento para terminal:

```bash
# Inspección estándar con salida formateada para humanos:
vmspect /ruta/a/disco.vmdk

# Salida estructurada en JSON (ideal para scripts, pipelines CI/CD y análisis forense):
vmspect /ruta/a/disco.qcow2 --json

# Escaneo concurrente y recursivo de un directorio completo de VMs:
vmspect /var/lib/libvirt/images/ --concurrente --recursivo --workers 8

# Inspección rápida omitiendo extracción de aplicaciones:
vmspect /ruta/a/disco.vhdx --noapps

# Inspección omitiendo metadatos del SO:
vmspect /ruta/a/disco.raw --nosystem
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
