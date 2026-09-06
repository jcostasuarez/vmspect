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

        let particion = candidatas
            .iter()
            .find(|p| es_particion_sistema(driver, p.inicio, p.tamano, tamano_chunk))
            .copied()
            .ok_or_else(|| {
                VmSpectError::WindowsRegistry(
                    "Ninguna partición NTFS contiene Windows\\System32\\config".to_string(),
                )
            })?;

        let colmenas = extraer_colmenas_ntfs(
            driver,
            particion.inicio,
            particion.tamano,
            tamano_chunk,
            opciones.incluir_system,
        )?;

        analizar_colmenas(&colmenas, opciones)
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

    let system = if incluir_system {
        leer_bytes_archivo(&ntfs, &mut disco, &config, "SYSTEM")
            .ok()
            .flatten()
    } else {
        None
    };

    Ok(Colmenas { software, system })
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
    let hive_software = Hive::new(&colmenas.software[..])
        .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
    let root_software = hive_software
        .root_key_node()
        .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;

    let mut vm_info = if opciones.debe_analizar_sistema() {
        extraer_informacion_vm(&root_software)
    } else {
        VMInfo::default()
    };

    if opciones.debe_analizar_sistema() {
        if let Some(system) = &colmenas.system {
            if vm_info.vmtools_version.is_none() {
                vm_info.vmtools_version = detectar_servicio_vmtools_en_system(&system[..]);
            }
        }
    }

    let programas = if opciones.debe_analizar_apps() {
        buscar_programas_en_registro(&root_software, opciones)
    } else {
        Vec::new()
    };

    Ok(ResultadoAnalisis { vm_info, programas })
}

fn detectar_servicio_vmtools_en_system(mmap_system: &[u8]) -> Option<String> {
    if let Ok(hive_system) = Hive::new(mmap_system) {
        if let Ok(root_system) = hive_system.root_key_node() {
            let rutas_servicio = [
                "ControlSet001\\Services\\VMTools",
                "ControlSet002\\Services\\VMTools",
                "CurrentControlSet\\Services\\VMTools",
            ];

            for ruta in &rutas_servicio {
                if let Ok(Some(nodo_servicio)) = buscar_clave_por_ruta(&root_system, ruta) {
                    if let Some(image_path) = leer_valor_de_clave(&nodo_servicio, "ImagePath") {
                        if let Some(ver) = leer_valor_de_clave(&nodo_servicio, "Version") {
                            return Some(format!("{} (Servicio: {})", ver, image_path));
                        }
                        return Some(format!("Detectado por Servicio ({})", image_path));
                    }
                    return Some("Detectado por Servicio Windows (VMTools)".to_string());
                }
            }
        }
    }
    None
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

    #[test]
    fn test_es_clave_vmware_tools() {
        let p = Programa {
            nombre: "VMware Tools".to_string(),
            version: Some("12.4.5".to_string()),
            editor: Some("VMware, Inc.".to_string()),
        };
        assert!(p.nombre.to_lowercase().contains("vmware tools"));
    }
}
