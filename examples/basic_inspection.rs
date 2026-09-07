use std::path::Path;
use vmspect::{inspeccionar_con_progreso, Opciones, ProgresoInspeccion};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let ruta_disco = if args.len() > 1 {
        Path::new(&args[1])
    } else {
        println!("Uso: cargo run --example basic_inspection -- <ruta_a_imagen_disco>");
        println!("Ejemplo: cargo run --example basic_inspection -- disco.vmdk");
        return Ok(());
    };

    let opciones = Opciones::default();

    println!("Iniciando inspección de '{}'...", ruta_disco.display());
    let informe = inspeccionar_con_progreso(ruta_disco, &opciones, |p: ProgresoInspeccion| {
        println!(
            "[{:>3}%] {}{}",
            p.porcentaje,
            p.etapa,
            p.detalle.map(|d| format!(" - {}", d)).unwrap_or_default()
        );
    })?;

    println!("\n=== INFORME DE INSPECCIÓN ===");
    println!(
        "Formato: {} ({})",
        informe.imagen.formato,
        informe.imagen.hipervisor.nombre()
    );
    println!("Esquema de particiones: {:?}", informe.esquema);
    println!(
        "Sistema Operativo: {} {:?}",
        informe.sistema_operativo.icono(),
        informe.sistema_operativo
    );
    println!("Detalles SO: {}", informe.vm_info.os_cadena_formateada());
    if let Some(ref tools) = informe.vm_info.guest_tools {
        if tools.presente {
            println!(
                "Guest Tools: {} (Versión: {})",
                tools.tipo,
                tools.version.as_deref().unwrap_or("N/D")
            );
        }
    }
    println!("Particiones encontradas: {}", informe.particiones.len());
    for p in &informe.particiones {
        println!(
            "  - #{} [{}] {} (Inicio: 0x{:X}, Tamaño: {} bytes)",
            p.indice,
            p.tipo,
            p.sistema_archivos.nombre(),
            p.inicio,
            p.tamano
        );
    }
    println!("Programas identificados: {}", informe.programas.len());
    for prog in informe.programas.iter().take(15) {
        println!(
            "  * {} (Versión: {}, Editor: {})",
            prog.nombre,
            prog.version.as_deref().unwrap_or("N/D"),
            prog.editor.as_deref().unwrap_or("N/D")
        );
    }

    Ok(())
}
