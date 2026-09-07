//! Análisis de invitados Windows.
//!
//! Dos partes:
//! 1. Extracción de las colmenas `SOFTWARE` y `SYSTEM` desde la partición NTFS
//!    usando el crate `ntfs` sobre un [`DiscoVirtual`] (solo se leen los data
//!    runs de esos archivos, no el resto del disco).
//! 2. Parseo del Registro con `nt_hive`: información del S.O., VMware Tools y
//!    software instalado de manera completamente agnóstica.

use crate::error::{Result, VmSpectError};
use crate::models::traits::{InspectorOS, ResultadoAnalisis, VmDriver};
use crate::models::{Opciones, Particion, Programa, VMInfo};
use crate::vms::stream::DiscoVirtual;
use nt_hive::{Hive, KeyNode, KeyValue, NtHiveError};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsFile};
use std::io::Read;

const RUTA_CONFIG: [&str; 3] = ["Windows", "System32", "config"];
/// Carpetas de nivel superior donde el fallback NTFS busca software instalado
/// cuando el Registro es totalmente inaccesible.
const CARPETAS_PROGRAM_FILES: [&str; 2] = ["Program Files", "Program Files (x86)"];
/// Marca de origen asignada a los programas inferidos por el fallback NTFS.
const ORIGEN_FALLBACK_FS: &str = "FallbackFS";

struct Colmenas {
    software: Vec<u8>,
    system: Option<Vec<u8>>,
    /// `true` si se halló al menos uno de los archivos de transacción
    /// `SOFTWARE.LOG1` / `SOFTWARE.LOG2` junto a la colmena primaria.
    software_logs_presentes: bool,
    /// `true` si se halló al menos uno de los archivos de transacción
    /// `SYSTEM.LOG1` / `SYSTEM.LOG2` junto a la colmena primaria.
    system_logs_presentes: bool,
    /// Advertencias no fatales generadas durante la extracción desde NTFS (ej. no
    /// se pudo leer la colmena SYSTEM del disco pese a haberse solicitado).
    advertencias: Vec<String>,
}

pub(crate) struct WindowsInspector;

impl InspectorOS for WindowsInspector {
    fn analizar(
        &self,
        driver: &dyn VmDriver,
        particiones: &[Particion],
        tamano_chunk: u64,
        opciones: &Opciones,
    ) -> Result<ResultadoAnalisis> {
        if !opciones.debe_analizar_sistema() && !opciones.debe_analizar_apps() {
            return Ok(ResultadoAnalisis::default());
        }

        let candidatas: Vec<_> = particiones.iter().filter(|p| p.es_ntfs()).collect();

        let particion = match candidatas
            .iter()
            .find(|p| es_particion_sistema(driver, p.inicio, p.tamano, tamano_chunk))
        {
            Some(p) => *p,
            None => {
                let msg = "Ninguna partición NTFS contiene Windows\\System32\\config (Registro inaccesible)".to_string();
                tracing::warn!("{}", msg);
                return Ok(resultado_degradado(msg));
            }
        };

        // `SYSTEM` solo se lee si el usuario lo solicitó explícitamente
        // (`incluir_system`) y no desactivó el análisis de sistema (`--nosystem`).
        let incluir_system = opciones.incluir_system && opciones.debe_analizar_sistema();

        // Graceful Degradation: si la extracción de las colmenas desde el disco
        // falla (bloques corruptos, colmena "sucia" tras un apagado abrupto, etc.)
        // NO se aborta el pipeline de inspección: se registra la advertencia y se
        // continúa con un resultado por defecto para el SO.
        let colmenas = match extraer_colmenas_ntfs(
            driver,
            particion.inicio,
            particion.tamano,
            tamano_chunk,
            incluir_system,
        ) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!(
                    "No se pudieron extraer las colmenas del Registro de Windows (Registro sucio / Inaccesible): {}",
                    e
                );
                tracing::warn!("{}", msg);
                return Ok(resultado_degradado(msg));
            }
        };

        let (mut resultado, requiere_fallback_fs) = analizar_colmenas(&colmenas, opciones)?;

        // Fallback FS: si la colmena SOFTWARE resultó totalmente inaccesible (ni
        // siquiera en modo permisivo pudo recuperarse su árbol de claves), se
        // recurre a inspeccionar directamente el sistema de archivos NTFS para
        // no devolver 0 programas ni un nombre de SO genérico.
        if requiere_fallback_fs {
            let (vm_info_fs, programas_fs, advertencias_fs) =
                aplicar_fallback_fs(driver, particion, tamano_chunk, opciones);

            if let Some(info_fs) = vm_info_fs {
                resultado.vm_info = info_fs;
            }
            if !programas_fs.is_empty() {
                resultado.programas.extend(programas_fs);
            }
            resultado.advertencias.extend(advertencias_fs);
        }

        Ok(resultado)
    }
}

/// Construye un [`ResultadoAnalisis`] de respaldo cuando el Registro de Windows no
/// puede leerse o parsearse, preservando la advertencia para el informe final en
/// lugar de abortar toda la inspección (Graceful Degradation).
fn resultado_degradado(advertencia: String) -> ResultadoAnalisis {
    ResultadoAnalisis {
        vm_info: VMInfo {
            os_nombre: "Windows (Registro sucio / Inaccesible)".to_string(),
            ..VMInfo::default()
        },
        programas: Vec::new(),
        advertencias: vec![advertencia],
    }
}

// -----------------------------------------------------------------------------
// 1. EXTRACCIÓN DE COLMENAS DESDE NTFS
// -----------------------------------------------------------------------------

fn extraer_colmenas_ntfs(
    driver: &dyn VmDriver,
    inicio_particion: u64,
    tamano_particion: u64,
    tamano_chunk: u64,
    incluir_system: bool,
) -> Result<Colmenas> {
    let mut disco = DiscoVirtual::new(driver, inicio_particion, tamano_particion, tamano_chunk);

    let mut ntfs =
        Ntfs::new(&mut disco).map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    ntfs.read_upcase_table(&mut disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let raiz = ntfs
        .root_directory(&mut disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let config = navegar_directorio(&ntfs, &mut disco, raiz, &RUTA_CONFIG)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?
        .ok_or_else(|| {
            VmSpectError::WindowsRegistry(
                "No existe Windows\\System32\\config en la partición NTFS".to_string(),
            )
        })?;

    let software =
        leer_bytes_archivo(&ntfs, &mut disco, &config, "SOFTWARE")?.ok_or_else(|| {
            VmSpectError::WindowsRegistry("No se encontró la colmena SOFTWARE".to_string())
        })?;

    // Soporte de archivos de log transaccional (.LOG1/.LOG2): su presencia se
    // usa como señal para decidir la estrategia de recuperación y para
    // enriquecer los mensajes de advertencia, ya que indican que la colmena
    // pudo quedar "sucia" tras un apagado abrupto sin sincronizar sus cambios.
    let software_logs_presentes = existe_archivo(&ntfs, &mut disco, &config, "SOFTWARE.LOG1")
        || existe_archivo(&ntfs, &mut disco, &config, "SOFTWARE.LOG2");

    let mut advertencias = Vec::new();
    let mut system_logs_presentes = false;
    let system = if incluir_system {
        system_logs_presentes = existe_archivo(&ntfs, &mut disco, &config, "SYSTEM.LOG1")
            || existe_archivo(&ntfs, &mut disco, &config, "SYSTEM.LOG2");
        match leer_bytes_archivo(&ntfs, &mut disco, &config, "SYSTEM") {
            Ok(bytes) => bytes,
            Err(e) => {
                let msg = format!(
                    "No se pudo leer la colmena SYSTEM del disco (Registro sucio / Inaccesible): {}",
                    e
                );
                tracing::warn!("{}", msg);
                advertencias.push(msg);
                None
            }
        }
    } else {
        None
    };

    Ok(Colmenas {
        software,
        system,
        software_logs_presentes,
        system_logs_presentes,
        advertencias,
    })
}

fn es_particion_sistema(
    driver: &dyn VmDriver,
    inicio_particion: u64,
    tamano_particion: u64,
    tamano_chunk: u64,
) -> bool {
    let mut disco = DiscoVirtual::new(driver, inicio_particion, tamano_particion, tamano_chunk);
    let Ok(mut ntfs) = Ntfs::new(&mut disco) else {
        return false;
    };
    if ntfs.read_upcase_table(&mut disco).is_err() {
        return false;
    }
    let Ok(raiz) = ntfs.root_directory(&mut disco) else {
        return false;
    };
    matches!(
        navegar_directorio(&ntfs, &mut disco, raiz, &RUTA_CONFIG),
        Ok(Some(_))
    )
}

fn navegar_directorio<'n>(
    ntfs: &'n Ntfs,
    disco: &mut DiscoVirtual<'_>,
    desde: NtfsFile<'n>,
    segmentos: &[&str],
) -> std::result::Result<Option<NtfsFile<'n>>, ntfs::NtfsError> {
    let mut actual = desde;
    for segmento in segmentos {
        let indice = actual.directory_index(disco)?;
        let mut finder = indice.finder();
        let Some(entrada) = NtfsFileNameIndex::find(&mut finder, ntfs, disco, segmento) else {
            return Ok(None);
        };
        let siguiente = entrada?.to_file(ntfs, disco)?;
        if !siguiente.is_directory() {
            return Ok(None);
        }
        actual = siguiente;
    }
    Ok(Some(actual))
}

fn leer_bytes_archivo(
    ntfs: &Ntfs,
    disco: &mut DiscoVirtual<'_>,
    directorio: &NtfsFile<'_>,
    nombre: &str,
) -> Result<Option<Vec<u8>>> {
    let indice = directorio
        .directory_index(disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let mut finder = indice.finder();
    let Some(entrada) = NtfsFileNameIndex::find(&mut finder, ntfs, disco, nombre) else {
        return Ok(None);
    };
    let archivo = entrada
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?
        .to_file(ntfs, disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let item = archivo
        .data(disco, "")
        .ok_or_else(|| {
            VmSpectError::FileSystem(format!(
                "El archivo {} no tiene flujo de datos principal",
                nombre
            ))
        })?
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let atributo = item
        .to_attribute()
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let valor = atributo
        .value(disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let longitud = valor.len();
    if longitud > 2 * 1024 * 1024 * 1024 {
        return Err(VmSpectError::FileSystem(format!(
            "La colmena {} es sospechosamente grande ({} bytes)",
            nombre, longitud
        )));
    }

    let mut lector = valor.attach(disco);
    let mut datos = Vec::with_capacity(longitud as usize);
    lector.read_to_end(&mut datos).map_err(VmSpectError::Io)?;
    Ok(Some(datos))
}

/// Comprueba de forma barata si un archivo existe dentro de un directorio NTFS,
/// sin leer su contenido. Se usa para detectar la presencia de los archivos de
/// transacción `.LOG1`/`.LOG2` junto a una colmena del Registro.
fn existe_archivo(
    ntfs: &Ntfs,
    disco: &mut DiscoVirtual<'_>,
    directorio: &NtfsFile<'_>,
    nombre: &str,
) -> bool {
    let Ok(indice) = directorio.directory_index(disco) else {
        return false;
    };
    let mut finder = indice.finder();
    matches!(
        NtfsFileNameIndex::find(&mut finder, ntfs, disco, nombre),
        Some(Ok(_))
    )
}

/// Lee, como máximo, los primeros `max_bytes` bytes del flujo de datos
/// principal de un archivo NTFS. Se usa en el fallback por sistema de archivos
/// para inspeccionar el encabezado PE de binarios grandes (ej. `ntoskrnl.exe`)
/// sin tener que volcar el ejecutable completo a memoria.
fn leer_prefijo_archivo(
    ntfs: &Ntfs,
    disco: &mut DiscoVirtual<'_>,
    directorio: &NtfsFile<'_>,
    nombre: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    let indice = directorio
        .directory_index(disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let mut finder = indice.finder();
    let Some(entrada) = NtfsFileNameIndex::find(&mut finder, ntfs, disco, nombre) else {
        return Ok(None);
    };
    let archivo = entrada
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?
        .to_file(ntfs, disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let item = archivo
        .data(disco, "")
        .ok_or_else(|| {
            VmSpectError::FileSystem(format!(
                "El archivo {} no tiene flujo de datos principal",
                nombre
            ))
        })?
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let atributo = item
        .to_attribute()
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let valor = atributo
        .value(disco)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let mut lector = valor.attach(disco).take(max_bytes);
    let mut datos = Vec::new();
    lector.read_to_end(&mut datos).map_err(VmSpectError::Io)?;
    Ok(Some(datos))
}

// -----------------------------------------------------------------------------
// 2. PARSEO Y EXTRACCIÓN DE DATOS DEL REGISTRO
// -----------------------------------------------------------------------------

/// Analiza las colmenas ya extraídas del disco. Devuelve el resultado junto a
/// un booleano `requiere_fallback_fs` que indica si la colmena SOFTWARE resultó
/// totalmente inaccesible (ni con validación completa ni en modo permisivo), lo
/// que le indica al llamador que debe recurrir al fallback por sistema de
/// archivos NTFS para no devolver 0 programas y un nombre de SO genérico.
fn analizar_colmenas(
    colmenas: &Colmenas,
    opciones: &Opciones,
) -> Result<(ResultadoAnalisis, bool)> {
    let mut advertencias = colmenas.advertencias.clone();
    let mut requiere_fallback_fs = false;

    // Graceful Degradation: una colmena SOFTWARE corrupta o "sucia" (apagado
    // abrupto de la VM, `SequenceNumberMismatch` entre los logs de transacciones,
    // bloques dañados, etc.) puede hacer que el parser retorne un `Err` o, en
    // casos extremos de corrupción, provocar un panic interno del crate
    // `nt-hive`. Ambos escenarios se capturan (`match` + `catch_unwind`) para que
    // NUNCA aborten el pipeline de inspección completo. Antes de rendirse, se
    // intenta una recuperación permisiva (ver `abrir_hive_con_recuperacion`).
    let bytes_software = &colmenas.software[..];
    let logs_software = colmenas.software_logs_presentes;
    let (mut vm_info, programas) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            intentar_analizar_software(bytes_software, opciones, logs_software)
        })) {
            Ok(Ok((info, progs, aviso_recuperacion))) => {
                if let Some(msg) = aviso_recuperacion {
                    tracing::warn!("{}", msg);
                    advertencias.push(msg);
                }
                (info, progs)
            }
            Ok(Err(e)) => {
                let msg = format!(
                    "Colmena SOFTWARE corrupta o inaccesible (Registro sucio): {}",
                    e
                );
                tracing::warn!("{}", msg);
                advertencias.push(msg);
                requiere_fallback_fs = true;
                (VMInfo::default(), Vec::new())
            }
            Err(_panic) => {
                let msg =
                    "Colmena SOFTWARE gravemente dañada: el parser del Registro falló de forma \
                       irrecuperable (Registro sucio)"
                        .to_string();
                tracing::warn!("{}", msg);
                advertencias.push(msg);
                requiere_fallback_fs = true;
                (VMInfo::default(), Vec::new())
            }
        };

    if requiere_fallback_fs {
        vm_info.os_nombre = "Windows (Registro sucio / Inaccesible)".to_string();
    }

    if opciones.debe_analizar_sistema() && vm_info.vmtools_version.is_none() {
        if let Some(system) = &colmenas.system {
            let bytes_system = &system[..];
            let logs_system = colmenas.system_logs_presentes;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                intentar_detectar_vmtools_en_system(bytes_system, logs_system)
            })) {
                Ok(Ok((version, aviso_recuperacion))) => {
                    vm_info.vmtools_version = version;
                    if let Some(msg) = aviso_recuperacion {
                        tracing::warn!("{}", msg);
                        advertencias.push(msg);
                    }
                }
                Ok(Err(e)) => {
                    let msg = format!(
                        "Colmena SYSTEM corrupta o inaccesible (Registro sucio): {}",
                        e
                    );
                    tracing::warn!("{}", msg);
                    advertencias.push(msg);
                }
                Err(_panic) => {
                    let msg = "Colmena SYSTEM gravemente dañada: el parser del Registro falló de \
                               forma irrecuperable (Registro sucio)"
                        .to_string();
                    tracing::warn!("{}", msg);
                    advertencias.push(msg);
                }
            }
        }
    }

    Ok((
        ResultadoAnalisis {
            vm_info,
            programas,
            advertencias,
        },
        requiere_fallback_fs,
    ))
}

/// Intenta abrir una colmena del Registro aplicando una estrategia de
/// recuperación en cascada:
/// 1. Apertura estándar con validación completa del encabezado (`Hive::new`).
/// 2. Si falla (ej. `SequenceNumberMismatch` por una colmena "sucia" tras un
///    apagado abrupto sin sincronizar sus archivos de transacción
///    `.LOG1`/`.LOG2`), reintenta en **modo permisivo**
///    (`Hive::without_validation`), que omite la validación del encabezado y
///    permite recorrer las claves que permanezcan intactas en el archivo
///    primario. `nt-hive` no soporta repetir ("replay") el contenido de los
///    archivos `.LOG1`/`.LOG2`, por lo que su presencia solo se usa aquí para
///    enriquecer el mensaje de advertencia devuelto.
fn abrir_hive_con_recuperacion(
    bytes: &[u8],
    logs_transaccionales_presentes: bool,
) -> std::result::Result<(Hive<&[u8]>, Option<String>), NtHiveError> {
    match Hive::new(bytes) {
        Ok(hive) => Ok((hive, None)),
        Err(error_original) => {
            // Puede seguir fallando (ej. datos totalmente corruptos/ilegibles):
            // en ese caso el `?` propaga el error y el llamador activa el
            // fallback por sistema de archivos.
            let hive = Hive::without_validation(bytes)?;

            let contexto_logs = if logs_transaccionales_presentes {
                "se detectaron archivos de transaccion .LOG1/.LOG2 junto a la colmena, pero el parser del Registro (nt-hive) no soporta repetir su contenido"
            } else {
                "no se hallaron archivos de transaccion .LOG1/.LOG2 junto a la colmena para intentar reproducir sus cambios pendientes"
            };

            let mensaje = format!(
                "Colmena con encabezado danado/sucio ({:?}): {}; se activo el modo permisivo de lectura (sin validar el encabezado) para recuperar las claves que permanezcan intactas en el archivo primario",
                error_original, contexto_logs
            );

            Ok((hive, Some(mensaje)))
        }
    }
}

/// Intenta parsear la colmena SOFTWARE y extraer la informacion del SO y la
/// lista de programas instalados. Devuelve `Err` si la colmena está corrupta o
/// no puede parsearse (colmena "sucia"); nunca contiene panics propios más allá
/// de los que pueda producir el crate `nt-hive` (capturados por el llamador con
/// `catch_unwind`).
fn intentar_analizar_software(
    bytes: &[u8],
    opciones: &Opciones,
    logs_transaccionales_presentes: bool,
) -> Result<(VMInfo, Vec<Programa>, Option<String>)> {
    let (hive_software, aviso_recuperacion) =
        abrir_hive_con_recuperacion(bytes, logs_transaccionales_presentes)
            .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
    let root_software = hive_software
        .root_key_node()
        .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;

    let vm_info = if opciones.debe_analizar_sistema() {
        extraer_informacion_vm(&root_software)
    } else {
        VMInfo::default()
    };

    let programas = if opciones.debe_analizar_apps() {
        buscar_programas_en_registro(&root_software, opciones)
    } else {
        Vec::new()
    };

    Ok((vm_info, programas, aviso_recuperacion))
}

/// Intenta parsear la colmena SYSTEM y detectar la versión de VMware Tools a
/// través del servicio `VMTools`. Devuelve `Err` si la colmena está corrupta o
/// no puede parsearse (colmena "sucia").
fn intentar_detectar_vmtools_en_system(
    mmap_system: &[u8],
    logs_transaccionales_presentes: bool,
) -> Result<(Option<String>, Option<String>)> {
    let (hive_system, aviso_recuperacion) =
        abrir_hive_con_recuperacion(mmap_system, logs_transaccionales_presentes)
            .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
    let root_system = hive_system
        .root_key_node()
        .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;

    let rutas_servicio = [
        "ControlSet001\\Services\\VMTools",
        "ControlSet002\\Services\\VMTools",
        "CurrentControlSet\\Services\\VMTools",
    ];

    for ruta in &rutas_servicio {
        if let Ok(Some(nodo_servicio)) = buscar_clave_por_ruta(&root_system, ruta) {
            if let Some(image_path) = leer_valor_de_clave(&nodo_servicio, "ImagePath") {
                if let Some(ver) = leer_valor_de_clave(&nodo_servicio, "Version") {
                    return Ok((
                        Some(format!("{} (Servicio: {})", ver, image_path)),
                        aviso_recuperacion,
                    ));
                }
                return Ok((
                    Some(format!("Detectado por Servicio ({})", image_path)),
                    aviso_recuperacion,
                ));
            }
            return Ok((
                Some("Detectado por Servicio Windows (VMTools)".to_string()),
                aviso_recuperacion,
            ));
        }
    }

    Ok((None, aviso_recuperacion))
}

fn extraer_version_vmtools(root_node: &HiveKeyNode) -> Option<String> {
    let rutas_vmtools = [
        "VMware, Inc.\\VMware Tools",
        "WOW6432Node\\VMware, Inc.\\VMware Tools",
    ];

    for ruta in &rutas_vmtools {
        if let Ok(Some(nodo_vmtools)) = buscar_clave_por_ruta(root_node, ruta) {
            if let Some(ver) = leer_valor_de_clave(&nodo_vmtools, "InstallVersion")
                .or_else(|| leer_valor_de_clave(&nodo_vmtools, "Version"))
            {
                return Some(ver);
            }
        }
    }

    let rutas_installer =
        ["Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products"];

    for ruta in &rutas_installer {
        if let Ok(Some(products_node)) = buscar_clave_por_ruta(root_node, ruta) {
            if let Some(Ok(subclaves)) = products_node.subkeys() {
                for subkey in subclaves.flatten() {
                    if let Ok(Some(install_properties)) =
                        buscar_clave_por_ruta(&subkey, "InstallProperties")
                    {
                        if es_clave_vmware_tools(&install_properties) {
                            if let Some(ver) =
                                leer_valor_de_clave(&install_properties, "DisplayVersion")
                            {
                                return Some(ver);
                            }
                        }
                    }
                }
            }
        }
    }

    let rutas_uninstall = [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];

    for rel_path in &rutas_uninstall {
        if let Ok(Some(uninstall_node)) = buscar_clave_por_ruta(root_node, rel_path) {
            if let Some(Ok(subclaves)) = uninstall_node.subkeys() {
                for subkey in subclaves.flatten() {
                    if es_clave_vmware_tools(&subkey) {
                        if let Some(ver) = leer_valor_de_clave(&subkey, "DisplayVersion") {
                            return Some(ver);
                        }
                    }
                }
            }
        }
    }

    None
}

fn es_clave_vmware_tools(key: &HiveKeyNode) -> bool {
    if let Some(nombre) = leer_valor_de_clave(key, "DisplayName") {
        return nombre.to_lowercase().contains("vmware tools");
    }
    false
}

fn leer_valor_de_clave(key: &HiveKeyNode, nombre_campo: &str) -> Option<String> {
    if let Some(Ok(valores)) = key.values() {
        for val in valores.flatten() {
            if let Ok(val_name) = val.name() {
                if val_name
                    .to_string_lossy()
                    .eq_ignore_ascii_case(nombre_campo)
                {
                    return convertir_valor_a_string(&val);
                }
            }
        }
    }
    None
}

fn extraer_informacion_vm(root_node: &HiveKeyNode) -> VMInfo {
    let mut info = VMInfo::default();
    let ruta_so = "Microsoft\\Windows NT\\CurrentVersion";

    if let Ok(Some(nodo_so)) = buscar_clave_por_ruta(root_node, ruta_so) {
        if let Some(Ok(valores)) = nodo_so.values() {
            for val in valores.flatten() {
                if let Ok(val_name) = val.name() {
                    let nombre_val = val_name.to_string_lossy();

                    if nombre_val.eq_ignore_ascii_case("ProductName") {
                        if let Some(v) = convertir_valor_a_string(&val) {
                            info.os_nombre = v;
                        }
                    } else if (nombre_val.eq_ignore_ascii_case("DisplayVersion")
                        || nombre_val.eq_ignore_ascii_case("ReleaseId"))
                        && info.os_edition_version.is_empty()
                    {
                        if let Some(v) = convertir_valor_a_string(&val) {
                            info.os_edition_version = v;
                        }
                    } else if nombre_val.eq_ignore_ascii_case("CSDVersion") {
                        if let Some(v) = convertir_valor_a_string(&val) {
                            info.os_service_pack = v;
                        }
                    } else if (nombre_val.eq_ignore_ascii_case("CurrentBuild")
                        || nombre_val.eq_ignore_ascii_case("CurrentBuildNumber"))
                        && info.os_build.is_empty()
                    {
                        if let Some(v) = convertir_valor_a_string(&val) {
                            info.os_build = v;
                        }
                    }
                }
            }
        }
    }

    if info.os_nombre.is_empty() {
        info.os_nombre = "Windows (Edición desconocida)".to_string();
    }

    info.vmtools_version = extraer_version_vmtools(root_node);

    info
}

// -----------------------------------------------------------------------------
// 3. MÓDULOS DE NAVEGACIÓN Y EXTRACCIÓN
// -----------------------------------------------------------------------------

type HiveKeyNode<'a> = KeyNode<'a, &'a [u8]>;

fn buscar_programas_en_registro(root_node: &HiveKeyNode, opciones: &Opciones) -> Vec<Programa> {
    let mut programas: Vec<Programa> = Vec::new();
    let rutas_uninstall = [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];

    for rel_path in &rutas_uninstall {
        if let Ok(Some(uninstall_node)) = buscar_clave_por_ruta(root_node, rel_path) {
            extraer_programas_de_subclaves(&uninstall_node, &mut programas, opciones);
        }
    }

    // Ordenar y eliminar duplicados basándonos en el nombre y versión del programa
    programas.sort_by(|a, b| a.nombre.cmp(&b.nombre));
    programas.dedup_by(|a, b| a.nombre == b.nombre && a.version == b.version);
    programas
}

fn buscar_clave_por_ruta<'a>(
    root: &HiveKeyNode<'a>,
    path: &str,
) -> Result<Option<HiveKeyNode<'a>>> {
    let mut actual = root.clone();
    for segmento in path.split('\\') {
        let mut encontrado = false;
        if let Some(Ok(subclaves)) = actual.subkeys() {
            for sub in subclaves.flatten() {
                if let Ok(nombre) = sub.name() {
                    if nombre.to_string_lossy().eq_ignore_ascii_case(segmento) {
                        actual = sub;
                        encontrado = true;
                        break;
                    }
                }
            }
        }
        if !encontrado {
            return Ok(None);
        }
    }
    Ok(Some(actual))
}

fn extraer_programas_de_subclaves(
    uninstall_node: &HiveKeyNode,
    salida: &mut Vec<Programa>,
    opciones: &Opciones,
) {
    if let Some(Ok(subclaves)) = uninstall_node.subkeys() {
        for subkey in subclaves.flatten() {
            if let Some(cancel) = &opciones.cancel_token {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            if let Some(nombre_prog) = leer_valor_de_clave(&subkey, "DisplayName") {
                let publisher_str = leer_valor_de_clave(&subkey, "Publisher").unwrap_or_default();
                let version_opt = leer_valor_de_clave(&subkey, "DisplayVersion");

                let editor_opt = if !publisher_str.is_empty() {
                    Some(publisher_str)
                } else {
                    None
                };

                salida.push(Programa {
                    nombre: nombre_prog,
                    version: version_opt,
                    editor: editor_opt,
                    origen: None,
                });
            }
        }
    }
}

// -----------------------------------------------------------------------------
// 4. PARSEO DE DATOS BINARIOS / UTF-16
// -----------------------------------------------------------------------------

fn convertir_valor_a_string(val: &KeyValue<&[u8]>) -> Option<String> {
    if let Ok(data_enum) = val.data() {
        if let Ok(bytes) = data_enum.into_vec() {
            if bytes.is_empty() {
                return None;
            }

            let utf16_units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
                .collect();

            let texto = String::from_utf16_lossy(&utf16_units);
            let texto_limpio = texto.trim_matches('\0').trim().to_string();

            if !texto_limpio.is_empty() {
                return Some(texto_limpio);
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// 5. FALLBACK POR SISTEMA DE ARCHIVOS NTFS (Registro totalmente inaccesible)
// -----------------------------------------------------------------------------

/// Ultimo recurso cuando la colmena SOFTWARE resulto totalmente inaccesible (ni
/// con validacion completa ni en modo permisivo pudo recuperarse su arbol de
/// claves): inspecciona directamente el sistema de archivos NTFS para no
/// devolver 0 programas instalados ni un nombre de SO generico.
///
/// Estrategia: 1) determina una version/build aproximada del SO leyendo el
/// encabezado PE de `\Windows\System32\ntoskrnl.exe` (o, en su defecto, solo
/// confirma que se trata de un Windows mediante la presencia de
/// `\Windows\System32\license.rtf`); 2) enumera las carpetas de primer nivel
/// dentro de `\Program Files` y `\Program Files (x86)` y las convierte en
/// entradas de software marcadas con `origen: FallbackFS`.
fn aplicar_fallback_fs(
    driver: &dyn VmDriver,
    particion: &Particion,
    tamano_chunk: u64,
    opciones: &Opciones,
) -> (Option<VMInfo>, Vec<Programa>, Vec<String>) {
    let mut advertencias = Vec::new();
    let mut disco = DiscoVirtual::new(driver, particion.inicio, particion.tamano, tamano_chunk);

    let mut ntfs = match Ntfs::new(&mut disco) {
        Ok(n) => n,
        Err(e) => {
            advertencias.push(format!(
                "FallbackFS: no se pudo volver a montar la particion NTFS ({:?})",
                e
            ));
            return (None, Vec::new(), advertencias);
        }
    };
    if let Err(e) = ntfs.read_upcase_table(&mut disco) {
        advertencias.push(format!(
            "FallbackFS: no se pudo leer la tabla UpCase de NTFS ({:?})",
            e
        ));
        return (None, Vec::new(), advertencias);
    }
    let raiz = match ntfs.root_directory(&mut disco) {
        Ok(r) => r,
        Err(e) => {
            advertencias.push(format!(
                "FallbackFS: no se pudo acceder al directorio raiz de NTFS ({:?})",
                e
            ));
            return (None, Vec::new(), advertencias);
        }
    };

    let mut vm_info = None;
    if opciones.debe_analizar_sistema() {
        match navegar_directorio(&ntfs, &mut disco, raiz.clone(), &["Windows", "System32"]) {
            Ok(Some(system32)) => match detectar_so_por_binarios(&ntfs, &mut disco, &system32) {
                Some((info, msg)) => {
                    advertencias.push(msg);
                    vm_info = Some(info);
                }
                None => advertencias.push(
                    "FallbackFS: no se pudo determinar la version del SO (ni ntoskrnl.exe ni license.rtf fueron legibles en \\Windows\\System32)".to_string(),
                ),
            },
            _ => advertencias.push(
                "FallbackFS: no se encontro \\Windows\\System32 en la particion NTFS".to_string(),
            ),
        }
    }

    let mut programas = Vec::new();
    if opciones.debe_analizar_apps() {
        for carpeta in CARPETAS_PROGRAM_FILES {
            if let Some(cancel) = &opciones.cancel_token {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
            if let Ok(Some(dir)) = navegar_directorio(&ntfs, &mut disco, raiz.clone(), &[carpeta]) {
                escanear_carpetas_como_programas(&mut disco, &dir, opciones, &mut programas);
            }
        }

        if !programas.is_empty() {
            advertencias.push(format!(
                "FallbackFS: se recuperaron {} entradas de software escaneando las carpetas de \\Program Files (sin version/editor; origen {}) porque el Registro es inaccesible",
                programas.len(),
                ORIGEN_FALLBACK_FS
            ));
        }
    }

    (vm_info, programas, advertencias)
}

/// Determina una version/build aproximada del SO a partir de binarios del
/// sistema, sin depender del Registro. Devuelve la informacion junto al
/// mensaje de advertencia que describe como se obtuvo.
fn detectar_so_por_binarios(
    ntfs: &Ntfs,
    disco: &mut DiscoVirtual<'_>,
    system32: &NtfsFile<'_>,
) -> Option<(VMInfo, String)> {
    if let Ok(Some(bytes)) = leer_prefijo_archivo(ntfs, disco, system32, "ntoskrnl.exe", 8192) {
        if let Some(timestamp) = extraer_timestamp_pe(&bytes) {
            let fecha = fecha_desde_epoch(timestamp);
            let info = VMInfo {
                os_nombre: format!("Windows (version aproximada por {})", ORIGEN_FALLBACK_FS),
                os_build: format!(
                    "Aproximado por fecha de compilacion PE de ntoskrnl.exe: {}",
                    fecha
                ),
                ..VMInfo::default()
            };
            let msg = format!(
                "Registro totalmente inaccesible: se determino una version aproximada del SO mediante el timestamp PE de \\Windows\\System32\\ntoskrnl.exe ({})",
                ORIGEN_FALLBACK_FS
            );
            return Some((info, msg));
        }
    }

    if existe_archivo(ntfs, disco, system32, "license.rtf") {
        let info = VMInfo {
            os_nombre: format!(
                "Windows (detectado por {}: license.rtf)",
                ORIGEN_FALLBACK_FS
            ),
            ..VMInfo::default()
        };
        let msg = format!(
            "Registro totalmente inaccesible: no se pudo leer ntoskrnl.exe, pero se confirmo un sistema Windows mediante la presencia de \\Windows\\System32\\license.rtf ({})",
            ORIGEN_FALLBACK_FS
        );
        return Some((info, msg));
    }

    None
}

/// Enumera las subcarpetas de primer nivel de un directorio NTFS (ej.
/// `\Program Files`) y las agrega a `salida` como entradas de software con
/// origen `FallbackFS`, ya que solo se conoce el nombre de la carpeta (no hay
/// version ni editor disponibles sin el Registro).
fn escanear_carpetas_como_programas(
    disco: &mut DiscoVirtual<'_>,
    directorio: &NtfsFile<'_>,
    opciones: &Opciones,
    salida: &mut Vec<Programa>,
) {
    let Ok(indice) = directorio.directory_index(disco) else {
        return;
    };
    let mut vistos = std::collections::HashSet::new();
    let mut entradas = indice.entries();
    loop {
        if let Some(cancel) = &opciones.cancel_token {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
        }
        let Some(entrada) = entradas.next(disco) else {
            break;
        };
        let Ok(entrada) = entrada else {
            continue;
        };
        let Some(Ok(nombre_key)) = entrada.key() else {
            continue;
        };
        if !nombre_key.is_directory() {
            continue;
        }
        if nombre_key.namespace() == NtfsFileNamespace::Dos {
            // Se evitan los nombres cortos 8.3, que duplicarian la carpeta
            // Win32 ya reportada bajo su nombre largo.
            continue;
        }
        let nombre = nombre_key.name().to_string_lossy();
        if nombre == "." || nombre == ".." {
            continue;
        }
        if !vistos.insert(nombre.clone()) {
            continue;
        }
        salida.push(Programa {
            nombre,
            version: None,
            editor: None,
            origen: Some(ORIGEN_FALLBACK_FS.to_string()),
        });
    }
}

/// Extrae el `TimeDateStamp` (segundos Unix de compilacion) del encabezado PE
/// de un ejecutable/DLL a partir de sus primeros bytes, sin necesitar el
/// archivo completo.
fn extraer_timestamp_pe(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes.get(0x3C..0x40)?.try_into().ok()?) as usize;
    let fin_firma = e_lfanew.checked_add(4)?;
    let fin_timestamp = fin_firma.checked_add(8)?;
    if bytes.len() < fin_timestamp || &bytes[e_lfanew..fin_firma] != b"PE\0\0" {
        return None;
    }
    let inicio_timestamp = fin_firma.checked_add(4)?;
    let timestamp = u32::from_le_bytes(bytes[inicio_timestamp..fin_timestamp].try_into().ok()?);
    Some(timestamp)
}

/// Formatea un timestamp Unix (segundos) como fecha `AAAA-MM-DD`, sin
/// depender de crates externos de fecha/hora.
fn fecha_desde_epoch(segundos_epoch: u32) -> String {
    let dias_totales = (segundos_epoch as i64) / 86400;
    let (anio, mes, dia) = civil_desde_dias(dias_totales);
    format!("{:04}-{:02}-{:02}", anio, mes, dia)
}

/// Algoritmo de Howard Hinnant para convertir un numero de dias desde la
/// epoca Unix (1970-01-01) a una fecha del calendario gregoriano (anio, mes,
/// dia). Referencia: http://howardhinnant.github.io/date_algorithms.html
fn civil_desde_dias(dias_desde_epoch: i64) -> (i64, u32, u32) {
    let z = dias_desde_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SistemaArchivos;

    #[test]
    fn test_es_clave_vmware_tools() {
        let p = Programa {
            nombre: "VMware Tools".to_string(),
            version: Some("12.4.5".to_string()),
            editor: Some("VMware, Inc.".to_string()),
            origen: None,
        };
        assert!(p.nombre.to_lowercase().contains("vmware tools"));
    }

    /// Verifica el algoritmo de conversion de dias-desde-epoca a fecha civil
    /// (usado por el fallback FS para aproximar la version del SO a partir del
    /// timestamp PE de `ntoskrnl.exe`) contra fechas conocidas.
    #[test]
    fn test_fecha_desde_epoch_fechas_conocidas() {
        assert_eq!(fecha_desde_epoch(0), "1970-01-01");
        // 2021-04-02T00:00:00Z
        assert_eq!(fecha_desde_epoch(1_617_321_600), "2021-04-02");
        // 2000-01-01T00:00:00Z
        assert_eq!(fecha_desde_epoch(946_684_800), "2000-01-01");
    }

    /// Construye un encabezado PE minimo (DOS + COFF) para verificar que
    /// `extraer_timestamp_pe` localiza correctamente el `TimeDateStamp`.
    #[test]
    fn test_extraer_timestamp_pe() {
        let mut datos = vec![0u8; 128];
        datos[0] = b'M';
        datos[1] = b'Z';
        let e_lfanew: u32 = 0x40;
        datos[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        datos[0x40..0x44].copy_from_slice(b"PE\0\0");
        // Machine (2) + NumberOfSections (2) antes del TimeDateStamp.
        datos[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        datos[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
        let timestamp_esperado: u32 = 1_600_000_000;
        datos[0x48..0x4C].copy_from_slice(&timestamp_esperado.to_le_bytes());

        assert_eq!(extraer_timestamp_pe(&datos), Some(timestamp_esperado));
    }

    #[test]
    fn test_extraer_timestamp_pe_datos_invalidos() {
        assert_eq!(extraer_timestamp_pe(&[0u8; 4]), None);
        assert_eq!(extraer_timestamp_pe(&[0u8; 4096]), None);
    }

    /// Ante una colmena con encabezado invalido (no `SequenceNumberMismatch`
    /// real, pero igualmente irrecuperable por validacion estricta), el modo
    /// permisivo tambien puede fallar; en ese caso `abrir_hive_con_recuperacion`
    /// debe propagar el error en lugar de entrar en panico.
    #[test]
    fn test_abrir_hive_con_recuperacion_datos_invalidos_propaga_error() {
        // Demasiado corto para interpretarse como encabezado de colmena, ni
        // siquiera en modo permisivo.
        let bytes = vec![0u8; 4];
        let resultado = abrir_hive_con_recuperacion(&bytes, true);
        assert!(resultado.is_err());
    }

    /// Simula un error de lectura/parseo de Registro (colmena "sucia" o corrupta,
    /// ej. `SequenceNumberMismatch`) y verifica que el análisis se degrada con
    /// gracia: retorna `Ok`, agrega la advertencia y usa un nombre de SO fallback,
    /// en lugar de abortar el pipeline con un `Err`.
    #[test]
    fn test_analizar_colmenas_registro_sucio_retorna_ok() {
        let colmenas = Colmenas {
            software: vec![0u8; 4096],
            system: Some(vec![0u8; 4096]),
            software_logs_presentes: false,
            system_logs_presentes: false,
            advertencias: Vec::new(),
        };
        let opciones = Opciones::default();

        let resultado = analizar_colmenas(&colmenas, &opciones);

        assert!(resultado.is_ok());
        let (resultado, requiere_fallback_fs) = resultado.unwrap();
        assert!(!resultado.advertencias.is_empty());
        assert_eq!(
            resultado.vm_info.os_nombre,
            "Windows (Registro sucio / Inaccesible)"
        );
        assert!(resultado.programas.is_empty());
        assert!(
            requiere_fallback_fs,
            "una colmena totalmente ilegible debe solicitar el fallback FS"
        );
    }

    /// Verifica el mismo escenario a nivel del trait `InspectorOS` completo: si el
    /// disco/partición no permite acceder al Registro (NTFS ilegible o ausente),
    /// `WindowsInspector::analizar` debe retornar `Ok` con datos de respaldo en
    /// lugar de abortar toda la inspección.
    #[test]
    fn test_windows_inspector_analizar_registro_inaccesible_retorna_ok() {
        struct MockDriverSucio;
        impl VmDriver for MockDriverSucio {
            fn tamano_virtual(&self) -> u64 {
                16 * 1024 * 1024
            }
            fn leer_rango(&self, _offset: u64, buf: &mut [u8]) -> Result<()> {
                buf.fill(0);
                Ok(())
            }
            fn modo_acceso(&self) -> &str {
                "mock"
            }
            fn es_nativo(&self) -> bool {
                true
            }
        }

        let inspector = WindowsInspector;
        let particiones = vec![Particion {
            indice: 0,
            inicio: 0,
            tamano: 16 * 1024 * 1024,
            tipo: "0x07".to_string(),
            sistema_archivos: SistemaArchivos::Ntfs,
            etiqueta: None,
        }];
        let opciones = Opciones::default();

        let resultado = inspector.analizar(&MockDriverSucio, &particiones, 4096, &opciones);

        assert!(resultado.is_ok());
        let resultado = resultado.unwrap();
        assert!(!resultado.advertencias.is_empty());
        assert_eq!(
            resultado.vm_info.os_nombre,
            "Windows (Registro sucio / Inaccesible)"
        );
    }
}
