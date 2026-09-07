//! # CLI de vmspect
//!
//! Punto de entrada de línea de comandos para la inspección y análisis estático de imágenes de disco virtual.
//! Permite analizar imágenes individuales o escanear directorios completos en modo secuencial o concurrente.

use std::env;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use vmspect::prelude::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Configuración parseada desde la línea de comandos.
#[derive(Debug, Default)]
struct ConfigCli {
    /// Ruta obligatoria al archivo de imagen o directorio objetivo.
    ruta_objetivo: Option<PathBuf>,
    /// Imprime la salida formateada en JSON estructurado.
    formato_json: bool,
    /// Ejecuta el análisis en paralelo mediante [`ProcesadorConcurrente`].
    concurrente: bool,
    /// Fuerza el uso de `qemu-nbd` incluso para formatos nativos.
    forzar_nbd: bool,
    /// Búsqueda recursiva en subdirectorios cuando el objetivo es un directorio.
    recursivo: bool,
    /// Desactiva la recolección de aplicaciones instaladas.
    noapps: bool,
    /// Desactiva la recolección de metadatos del sistema operativo.
    nosystem: bool,
    /// Fuerza la lectura de la colmena `SYSTEM` en Windows.
    incluir_system: bool,
    /// Cantidad máxima de hilos workers para el modo concurrente.
    max_workers: Option<usize>,
}

fn imprimir_ayuda() {
    println!(
        r#"vmspect {VERSION} - Inspección estática y análisis forense de imágenes de disco virtual

USO:
    vmspect [OPCIONES] <RUTA>

ARGUMENTOS:
    <RUTA>                     Ruta a un archivo de disco virtual (.vmdk, .raw, .qcow2, .vhdx, .vdi, etc.)
                               o a un directorio que contenga imágenes de máquinas virtuales.

OPCIONES:
    --json                     Imprime los resultados en formato JSON estructurado a través de stdout.
    --concurrente              Habilita el procesamiento concurrente de imágenes mediante ProcesadorConcurrente.
    --forzar-nbd               Fuerza el backend qemu-nbd para todos los formatos de disco.
    -r, --recursivo            Busca imágenes recursivamente al escanear un directorio.
    --noapps                   Omite la extracción del catálogo de software instalado.
    --nosystem                 Omite la extracción de información y metadatos del SO invitado.
    --incluir-system           Extrae también la colmena SYSTEM del Registro en imágenes Windows.
    -w, --workers <NUM>        Número máximo de hilos concurrentes (por defecto: núcleos lógicos del sistema).
    -h, --help                 Muestra esta información de ayuda.
    -V, --version              Muestra la versión actual de la herramienta.

EJEMPLOS:
    vmspect disco.vmdk
    vmspect disco.qcow2 --json
    vmspect /var/lib/libvirt/images/ --concurrente --recursivo
    vmspect C:\VMs\Windows10.vmdk --forzar-nbd
"#
    );
}

fn imprimir_version() {
    println!("vmspect {}", VERSION);
}

fn parsear_argumentos() -> std::result::Result<ConfigCli, String> {
    parsear_argumentos_desde(env::args().skip(1))
}

fn parsear_argumentos_desde<I>(mut args: I) -> std::result::Result<ConfigCli, String>
where
    I: Iterator<Item = String>,
{
    let mut config = ConfigCli::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                imprimir_ayuda();
                process::exit(0);
            }
            "-V" | "--version" => {
                imprimir_version();
                process::exit(0);
            }
            "--json" => {
                config.formato_json = true;
            }
            "--concurrente" => {
                config.concurrente = true;
            }
            "--forzar-nbd" => {
                config.forzar_nbd = true;
            }
            "-r" | "--recursivo" => {
                config.recursivo = true;
            }
            "--noapps" => {
                config.noapps = true;
            }
            "--nosystem" => {
                config.nosystem = true;
            }
            "--incluir-system" => {
                config.incluir_system = true;
            }
            "-w" | "--workers" => {
                let valor = args
                    .next()
                    .ok_or_else(|| "Se requiere un valor numérico para --workers".to_string())?;
                let num = valor
                    .parse::<usize>()
                    .map_err(|_| format!("Número de workers inválido: '{}'", valor))?;
                config.max_workers = Some(num);
            }
            otro if otro.starts_with("--workers=") => {
                let valor = otro.trim_start_matches("--workers=");
                let num = valor
                    .parse::<usize>()
                    .map_err(|_| format!("Número de workers inválido: '{}'", valor))?;
                config.max_workers = Some(num);
            }
            otro if otro.starts_with('-') => {
                return Err(format!(
                    "Opción desconocida: '{}'. Usa --help para ver las opciones disponibles.",
                    otro
                ));
            }
            posicional => {
                if config.ruta_objetivo.is_none() {
                    config.ruta_objetivo = Some(PathBuf::from(posicional));
                } else {
                    return Err(format!("Argumento posicional inesperado: '{}'", posicional));
                }
            }
        }
    }

    Ok(config)
}

fn main() {
    let config = match parsear_argumentos() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Error de argumentos: {}", err);
            eprintln!("Ejecute 'vmspect --help' para consultar el uso correcto.");
            process::exit(1);
        }
    };

    let ruta = match config.ruta_objetivo {
        Some(ref p) => p,
        None => {
            eprintln!("Error: Se requiere especificar la ruta a una imagen de disco o directorio.");
            eprintln!("Uso: vmspect [OPCIONES] <RUTA>");
            eprintln!("Ejecute 'vmspect --help' para más información.");
            process::exit(1);
        }
    };

    if !ruta.exists() {
        eprintln!("Error: La ruta especificada no existe: {}", ruta.display());
        process::exit(1);
    }

    let opciones = Opciones {
        forzar_nbd: config.forzar_nbd,
        noapps: config.noapps,
        nosystem: config.nosystem,
        incluir_system: config.incluir_system,
        ..Default::default()
    };

    if ruta.is_file() {
        ejecutar_archivo(ruta, &opciones, config.formato_json);
    } else if ruta.is_dir() {
        ejecutar_directorio(ruta, &config, &opciones);
    } else {
        eprintln!(
            "Error: La ruta especificada no es un archivo ni un directorio válido: {}",
            ruta.display()
        );
        process::exit(1);
    }
}

fn ejecutar_archivo(ruta: &Path, opciones: &Opciones, formato_json: bool) {
    if es_extent_secundario(ruta) && !formato_json {
        eprintln!(
            "Nota: '{}' parece ser un fragmento secundario (extent). Si el análisis falla, intente apuntar al descriptor principal .vmdk.",
            ruta.display()
        );
    }

    if formato_json {
        let motor = MotorInspeccion::new(opciones.clone());
        match motor.inspeccionar(ruta) {
            Ok(informe) => match serde_json::to_string_pretty(&informe) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error al serializar JSON: {}", e);
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Error de inspección en '{}': {}", ruta.display(), e);
                process::exit(1);
            }
        }
    } else {
        println!("============================================================");
        println!("  Iniciando inspección de: {}", ruta.display());
        println!("============================================================");

        let inicio = Instant::now();
        let resultado = inspeccionar_con_progreso(ruta, opciones, |progreso| {
            let detalle_str = progreso.detalle.as_deref().unwrap_or("");
            if !detalle_str.is_empty() {
                eprintln!(
                    "[{:>3}%] {} ({})",
                    progreso.porcentaje, progreso.etapa, detalle_str
                );
            } else {
                eprintln!("[{:>3}%] {}", progreso.porcentaje, progreso.etapa);
            }
        });

        match resultado {
            Ok(informe) => {
                imprimir_informe_humano(&informe, inicio.elapsed().as_millis() as u64);
            }
            Err(e) => {
                eprintln!(
                    "\nError al inspeccionar la imagen '{}': {}",
                    ruta.display(),
                    e
                );
                process::exit(1);
            }
        }
    }
}

fn ejecutar_directorio(directorio: &Path, config: &ConfigCli, opciones: &Opciones) {
    let imagenes = match listar_vms(directorio, config.recursivo) {
        Ok(imgs) => imgs,
        Err(e) => {
            eprintln!(
                "Error al listar imágenes en '{}': {}",
                directorio.display(),
                e
            );
            process::exit(1);
        }
    };

    if imagenes.is_empty() {
        if config.formato_json {
            println!("[]");
        } else {
            println!(
                "No se encontraron imágenes de disco virtual en '{}'.",
                directorio.display()
            );
        }
        return;
    }

    let max_workers = config.max_workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    if config.concurrente {
        if !config.formato_json {
            println!("============================================================");
            println!(
                "  Escaneo Concurrente: {} imágenes encontradas",
                imagenes.len()
            );
            println!("  Directorio: {}", directorio.display());
            println!("  Hilos de trabajo (Workers): {}", max_workers);
            println!("============================================================\n");
        }

        let inicio = Instant::now();
        let resultado =
            ProcesadorConcurrente::inspeccionar_imagenes(imagenes, opciones, max_workers);

        match resultado {
            Ok(informes) => {
                if config.formato_json {
                    match serde_json::to_string_pretty(&informes) {
                        Ok(json) => println!("{}", json),
                        Err(e) => {
                            eprintln!("Error al serializar JSON: {}", e);
                            process::exit(1);
                        }
                    }
                } else {
                    for (i, informe) in informes.iter().enumerate() {
                        println!(
                            "\n--- [Imagen {}/{}] ----------------------------------------",
                            i + 1,
                            informes.len()
                        );
                        imprimir_informe_humano(informe, informe.estadisticas.duracion_ms);
                    }

                    let duracion_total = inicio.elapsed().as_millis() as u64;
                    println!("\n============================================================");
                    println!("  Resumen Lote Concurrente:");
                    println!("  Total imágenes procesadas: {}", informes.len());
                    println!(
                        "  Tiempo total transcurrido: {} ms ({:.2} s)",
                        duracion_total,
                        duracion_total as f64 / 1000.0
                    );
                    println!("============================================================");
                }
            }
            Err(e) => {
                eprintln!("Error durante el procesamiento concurrente: {}", e);
                process::exit(1);
            }
        }
    } else {
        // Modo secuencial para el directorio
        if !config.formato_json {
            println!("============================================================");
            println!(
                "  Escaneo Secuencial: {} imágenes encontradas",
                imagenes.len()
            );
            println!("  Directorio: {}", directorio.display());
            println!("============================================================\n");
        }

        let inicio = Instant::now();
        let mut informes = Vec::with_capacity(imagenes.len());

        for (i, ruta_img) in imagenes.iter().enumerate() {
            if !config.formato_json {
                println!(
                    "[{}/{}] Inspeccionando '{}'...",
                    i + 1,
                    imagenes.len(),
                    ruta_img.display()
                );
            }

            let motor = MotorInspeccion::new(opciones.clone());
            match motor.inspeccionar(ruta_img) {
                Ok(informe) => {
                    if !config.formato_json {
                        imprimir_informe_humano(&informe, informe.estadisticas.duracion_ms);
                        println!();
                    }
                    informes.push(informe);
                }
                Err(e) => {
                    eprintln!(
                        "Advertencia: Falló el análisis de '{}': {}",
                        ruta_img.display(),
                        e
                    );
                }
            }
        }

        if config.formato_json {
            match serde_json::to_string_pretty(&informes) {
                Ok(json) => println!("{}", json),
                Err(e) => {
                    eprintln!("Error al serializar JSON: {}", e);
                    process::exit(1);
                }
            }
        } else {
            let duracion_total = inicio.elapsed().as_millis() as u64;
            println!("============================================================");
            println!("  Resumen Escaneo Secuencial:");
            println!(
                "  Imágenes completadas con éxito: {}/{}",
                informes.len(),
                imagenes.len()
            );
            println!(
                "  Tiempo total: {} ms ({:.2} s)",
                duracion_total,
                duracion_total as f64 / 1000.0
            );
            println!("============================================================");
        }
    }
}

fn imprimir_informe_humano(informe: &InformeInspeccion, duracion_ms: u64) {
    let img = &informe.imagen;
    let so = &informe.sistema_operativo;
    let info = &informe.vm_info;

    println!("\n[+] INFORMACIÓN DE LA IMAGEN");
    println!("    Archivo:         {}", img.ruta.display());
    println!("    Formato:         {}", img.formato.to_uppercase());
    println!("    Hipervisor:      {}", img.hipervisor.nombre());
    println!(
        "    Tamaño Virtual:  {} ({} bytes)",
        formatear_bytes(img.tamano_virtual),
        img.tamano_virtual
    );
    println!(
        "    Tamaño en Disco: {} ({} bytes)",
        formatear_bytes(img.tamano_real),
        img.tamano_real
    );

    println!("\n[+] PARTICIONES ({:?})", informe.esquema);
    if informe.particiones.is_empty() {
        println!("    (No se identificaron particiones reconocibles)");
    } else {
        for p in &informe.particiones {
            let etiqueta = p
                .etiqueta
                .as_deref()
                .map(|e| format!(" [Etiqueta: {}]", e))
                .unwrap_or_default();
            println!(
                "    #{} - FS: {:<10} Tamaño: {:<10} Offset: {:<12} Tipo: {}{}",
                p.indice,
                p.sistema_archivos.nombre(),
                formatear_bytes(p.tamano),
                p.inicio,
                p.tipo,
                etiqueta
            );
        }
    }

    println!("\n[+] SISTEMA OPERATIVO {}", so.icono());
    println!("    Familia:         {:?}", so);
    if !info.os_nombre.is_empty() {
        println!("    Nombre / Versión: {}", info.os_cadena_formateada());
    } else {
        println!("    Nombre / Versión: No detectado o no disponible");
    }
    if let Some(ref tools) = info.vmtools_version {
        println!("    VM Guest Tools:  {}", tools);
    }

    if !informe.advertencias.is_empty() {
        println!("\n[!] ADVERTENCIAS ({})", informe.advertencias.len());
        for adv in &informe.advertencias {
            println!("    - {}", adv);
        }
    }

    println!("\n[+] SOFTWARE INSTALADO ({})", informe.programas.len());
    if informe.programas.is_empty() {
        println!("    (Sin aplicaciones detectadas o extracción deshabilitada)");
    } else {
        for (idx, prog) in informe.programas.iter().enumerate() {
            let ver = prog.version.as_deref().unwrap_or("-");
            let editor = prog.editor.as_deref().unwrap_or("-");
            println!(
                "    {:>4}. {:<45} | Versión: {:<20} | Editor: {}",
                idx + 1,
                prog.nombre,
                ver,
                editor
            );
        }
    }

    println!("\n[+] ESTADÍSTICAS Y RENDIMIENTO");
    println!("    Modo de Acceso:  {}", informe.estadisticas.modo_acceso);
    println!(
        "    Bytes Leídos:    {}",
        formatear_bytes(informe.estadisticas.bytes_leidos)
    );
    if informe.estadisticas.peticiones_nbd > 0 {
        println!(
            "    Peticiones NBD:  {}",
            informe.estadisticas.peticiones_nbd
        );
    }
    println!(
        "    Duración:        {} ms ({:.2} s)",
        duracion_ms,
        duracion_ms as f64 / 1000.0
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsear_argumentos_basico() {
        let args = vec!["imagen.vmdk".to_string()];
        let cfg = parsear_argumentos_desde(args.into_iter()).unwrap();
        assert_eq!(cfg.ruta_objetivo, Some(PathBuf::from("imagen.vmdk")));
        assert!(!cfg.formato_json);
        assert!(!cfg.concurrente);
        assert!(!cfg.forzar_nbd);
    }

    #[test]
    fn test_parsear_banderas_opcionales() {
        let args = vec![
            "--json".to_string(),
            "--concurrente".to_string(),
            "--forzar-nbd".to_string(),
            "--recursivo".to_string(),
            "--noapps".to_string(),
            "--nosystem".to_string(),
            "--incluir-system".to_string(),
            "--workers".to_string(),
            "8".to_string(),
            "/ruta/vms".to_string(),
        ];
        let cfg = parsear_argumentos_desde(args.into_iter()).unwrap();
        assert_eq!(cfg.ruta_objetivo, Some(PathBuf::from("/ruta/vms")));
        assert!(cfg.formato_json);
        assert!(cfg.concurrente);
        assert!(cfg.forzar_nbd);
        assert!(cfg.recursivo);
        assert!(cfg.noapps);
        assert!(cfg.nosystem);
        assert!(cfg.incluir_system);
        assert_eq!(cfg.max_workers, Some(8));
    }

    #[test]
    fn test_parsear_workers_formato_igual() {
        let args = vec!["--workers=12".to_string(), "disco.qcow2".to_string()];
        let cfg = parsear_argumentos_desde(args.into_iter()).unwrap();
        assert_eq!(cfg.max_workers, Some(12));
        assert_eq!(cfg.ruta_objetivo, Some(PathBuf::from("disco.qcow2")));
    }

    #[test]
    fn test_parsear_opcion_desconocida_error() {
        let args = vec!["--opcion-inexistente".to_string(), "disco.raw".to_string()];
        let err = parsear_argumentos_desde(args.into_iter()).unwrap_err();
        assert!(err.contains("Opción desconocida"));
    }

    #[test]
    fn test_parsear_multiples_posicionales_error() {
        let args = vec!["disco1.vmdk".to_string(), "disco2.vmdk".to_string()];
        let err = parsear_argumentos_desde(args.into_iter()).unwrap_err();
        assert!(err.contains("Argumento posicional inesperado"));
    }
}
