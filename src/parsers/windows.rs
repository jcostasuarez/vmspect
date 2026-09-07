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
use nt_hive::{Hive, KeyNode, KeyValue};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::{Ntfs, NtfsFile};
use std::io::Read;

const RUTA_CONFIG: [&str; 3] = ["Windows", "System32", "config"];

struct Colmenas {
    software: Vec<u8>,
    system: Option<Vec<u8>>,
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

        analizar_colmenas(&colmenas, opciones)
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

    let mut advertencias = Vec::new();
    let system = if incluir_system {
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

// -----------------------------------------------------------------------------
// 2. PARSEO Y EXTRACCIÓN DE DATOS DEL REGISTRO
// -----------------------------------------------------------------------------

fn analizar_colmenas(colmenas: &Colmenas, opciones: &Opciones) -> Result<ResultadoAnalisis> {
    let mut advertencias = colmenas.advertencias.clone();
    let mut registro_danado = false;

    // Graceful Degradation: una colmena SOFTWARE corrupta o "sucia" (apagado
    // abrupto de la VM, `SequenceNumberMismatch` entre los logs de transacciones,
    // bloques dañados, etc.) puede hacer que el parser retorne un `Err` o, en
    // casos extremos de corrupción, provocar un panic interno del crate
    // `nt-hive`. Ambos escenarios se capturan (`match` + `catch_unwind`) para que
    // NUNCA aborten el pipeline de inspección completo.
    let bytes_software = &colmenas.software[..];
    let (mut vm_info, programas) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            intentar_analizar_software(bytes_software, opciones)
        })) {
            Ok(Ok(datos)) => datos,
            Ok(Err(e)) => {
                let msg = format!(
                    "Colmena SOFTWARE corrupta o inaccesible (Registro sucio): {}",
                    e
                );
                tracing::warn!("{}", msg);
                advertencias.push(msg);
                registro_danado = true;
                (VMInfo::default(), Vec::new())
            }
            Err(_panic) => {
                let msg =
                    "Colmena SOFTWARE gravemente dañada: el parser del Registro falló de forma \
                       irrecuperable (Registro sucio)"
                        .to_string();
                tracing::warn!("{}", msg);
                advertencias.push(msg);
                registro_danado = true;
                (VMInfo::default(), Vec::new())
            }
        };

    if registro_danado {
        vm_info.os_nombre = "Windows (Registro sucio / Inaccesible)".to_string();
    }

    if opciones.debe_analizar_sistema() && vm_info.vmtools_version.is_none() {
        if let Some(system) = &colmenas.system {
            let bytes_system = &system[..];
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                intentar_detectar_vmtools_en_system(bytes_system)
            })) {
                Ok(Ok(version)) => vm_info.vmtools_version = version,
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

    Ok(ResultadoAnalisis {
        vm_info,
        programas,
        advertencias,
    })
}

/// Intenta parsear la colmena SOFTWARE y extraer la información del SO y la
/// lista de programas instalados. Devuelve `Err` si la colmena está corrupta o
/// no puede parsearse (colmena "sucia"); nunca contiene panics propios más allá
/// de los que pueda producir el crate `nt-hive` (capturados por el llamador con
/// `catch_unwind`).
fn intentar_analizar_software(
    bytes: &[u8],
    opciones: &Opciones,
) -> Result<(VMInfo, Vec<Programa>)> {
    let hive_software =
        Hive::new(bytes).map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
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

    Ok((vm_info, programas))
}

/// Intenta parsear la colmena SYSTEM y detectar la versión de VMware Tools a
/// través del servicio `VMTools`. Devuelve `Err` si la colmena está corrupta o
/// no puede parsearse (colmena "sucia").
fn intentar_detectar_vmtools_en_system(mmap_system: &[u8]) -> Result<Option<String>> {
    let hive_system =
        Hive::new(mmap_system).map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
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
                    return Ok(Some(format!("{} (Servicio: {})", ver, image_path)));
                }
                return Ok(Some(format!("Detectado por Servicio ({})", image_path)));
            }
            return Ok(Some("Detectado por Servicio Windows (VMTools)".to_string()));
        }
    }

    Ok(None)
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
        };
        assert!(p.nombre.to_lowercase().contains("vmware tools"));
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
            advertencias: Vec::new(),
        };
        let opciones = Opciones::default();

        let resultado = analizar_colmenas(&colmenas, &opciones);

        assert!(resultado.is_ok());
        let resultado = resultado.unwrap();
        assert!(!resultado.advertencias.is_empty());
        assert_eq!(
            resultado.vm_info.os_nombre,
            "Windows (Registro sucio / Inaccesible)"
        );
        assert!(resultado.programas.is_empty());
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
