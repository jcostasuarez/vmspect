//! Análisis de invitados Linux utilizando la crate ext4.
//!
//! Realiza la lectura del sistema de archivos en espacio de usuario sin montar
//! la partición en el sistema operativo anfitrión.
use crate::error::Result;
use crate::models::traits::{InspectorOS, ResultadoAnalisis, VmDriver};
use crate::models::{Opciones, Particion, Programa, SistemaArchivos, VMInfo};
use crate::vms::stream::DiscoVirtual;
use ext4::SuperBlock;
use positioned_io::ReadAt;

use std::io::Read;

pub(crate) struct LinuxInspector;

impl InspectorOS for LinuxInspector {
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

        let mut candidatas: Vec<_> = particiones
            .iter()
            .filter(|p| {
                matches!(
                    p.sistema_archivos,
                    SistemaArchivos::Ext4 | SistemaArchivos::Ext3 | SistemaArchivos::Ext2
                )
            })
            .collect();

        candidatas.sort_by_key(|p| std::cmp::Reverse(p.tamano));

        for particion in candidatas {
            let mut disco =
                DiscoVirtual::new(driver, particion.inicio, particion.tamano, tamano_chunk);

            if let Ok(sb) = SuperBlock::new(&mut disco) {
                if let Ok(resultado) = analizar_sistema_archivos(&sb, opciones) {
                    return Ok(resultado);
                }
            }
        }

        // Fallback
        Ok(ResultadoAnalisis {
            vm_info: if opciones.debe_analizar_sistema() {
                VMInfo {
                    os_nombre: "Linux (No se pudo leer rootfs)".to_string(),
                    ..VMInfo::default()
                }
            } else {
                VMInfo::default()
            },
            programas: Vec::new(),
        })
    }
}

fn analizar_sistema_archivos<R: ReadAt>(
    sb: &SuperBlock<R>,
    opciones: &Opciones,
) -> Result<ResultadoAnalisis> {
    let mut vm_info = VMInfo::default();
    let mut programas = Vec::new();

    if opciones.debe_analizar_sistema() {
        if let Ok(contenido) = leer_archivo_texto(sb, "/etc/os-release")
            .or_else(|_| leer_archivo_texto(sb, "/usr/lib/os-release"))
        {
            parsear_os_release(&contenido, &mut vm_info);
        }

        if let Ok(hostname) = leer_archivo_texto(sb, "/etc/hostname") {
            let name = hostname.trim();
            if !name.is_empty() {
                vm_info.os_edition_version = format!("Host: {}", name);
            }
        }
    }

    if let Ok(dpkg_status) = leer_archivo_texto(sb, "/var/lib/dpkg/status") {
        let (pkgs, vmtools_ver) = parsear_dpkg_status(&dpkg_status, opciones);
        if opciones.debe_analizar_apps() {
            programas.extend(pkgs);
        }
        if opciones.debe_analizar_sistema() {
            if let Some(ver) = vmtools_ver {
                vm_info.vmtools_version = Some(ver);
            }
        }
    }

    if opciones.debe_analizar_apps() {
        // Ordenar y deduplicar respetando la estructura Programa
        programas.sort_by(|a, b| a.nombre.cmp(&b.nombre));
        programas.dedup_by(|a, b| a.nombre == b.nombre && a.version == b.version);
    }

    Ok(ResultadoAnalisis { vm_info, programas })
}

fn parsear_dpkg_status(contenido: &str, opciones: &Opciones) -> (Vec<Programa>, Option<String>) {
    let mut paquetes = Vec::new();
    let mut version_vmtools = None;

    let mut pkg_actual = String::new();
    let mut ver_actual = String::new();
    let mut seccion_actual = String::new();
    let mut instalado = false;

    let debe_apps = opciones.debe_analizar_apps();

    let procesar_paquete = |pkg: &str,
                            ver: &str,
                            sec: &str,
                            inst: bool,
                            pkgs: &mut Vec<Programa>,
                            vmtools_ver: &mut Option<String>| {
        if inst && !pkg.is_empty() {
            // Capturar la versión explícita para las herramientas de integración
            if (pkg == "open-vm-tools" || pkg == "open-vm-tools-desktop") && vmtools_ver.is_none() {
                *vmtools_ver = Some(format!("open-vm-tools {}", ver));
            }

            if debe_apps {
                let version_opt = if !ver.is_empty() {
                    Some(ver.to_string())
                } else {
                    None
                };

                let editor_opt = if !sec.is_empty() {
                    Some(sec.to_string())
                } else {
                    None
                };

                pkgs.push(Programa {
                    nombre: pkg.to_string(),
                    version: version_opt,
                    editor: editor_opt,
                });
            }
        }
    };

    for linea in contenido.lines() {
        if let Some(cancel) = &opciones.cancel_token {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }

        if linea.starts_with("Package: ") {
            pkg_actual = linea.trim_start_matches("Package: ").trim().to_string();
        } else if linea.starts_with("Status: ") {
            instalado = linea.contains("install ok installed");
        } else if linea.starts_with("Version: ") {
            ver_actual = linea.trim_start_matches("Version: ").trim().to_string();
        } else if linea.starts_with("Section: ") {
            seccion_actual = linea.trim_start_matches("Section: ").trim().to_string();
        } else if linea.trim().is_empty() {
            procesar_paquete(
                &pkg_actual,
                &ver_actual,
                &seccion_actual,
                instalado,
                &mut paquetes,
                &mut version_vmtools,
            );
            pkg_actual.clear();
            ver_actual.clear();
            seccion_actual.clear();
            instalado = false;
        }
    }

    // Procesar último paquete si no había línea vacía al final
    procesar_paquete(
        &pkg_actual,
        &ver_actual,
        &seccion_actual,
        instalado,
        &mut paquetes,
        &mut version_vmtools,
    );

    (paquetes, version_vmtools)
}

/// Lee un archivo de texto de la partición ext4 y lo devuelve como String.
fn leer_archivo_texto<R: ReadAt>(sb: &SuperBlock<R>, ruta: &str) -> Result<String> {
    let entry = sb
        .resolve_path(ruta)
        .map_err(|e| crate::error::VmSpectError::FileSystem(format!("{:?}", e)))?;
    let inode = sb
        .load_inode(entry.inode)
        .map_err(|e| crate::error::VmSpectError::FileSystem(format!("{:?}", e)))?;
    let mut reader = sb
        .open(&inode)
        .map_err(|e| crate::error::VmSpectError::FileSystem(format!("{:?}", e)))?;
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

/// Parsea `/etc/os-release` extrayendo el nombre y versión del SO.
fn parsear_os_release(contenido: &str, info: &mut VMInfo) {
    for linea in contenido.lines() {
        let linea = linea.trim();
        if linea.starts_with('#') || !linea.contains('=') {
            continue;
        }

        let mut partes = linea.splitn(2, '=');
        let clave = partes.next().unwrap_or("").trim();
        let valor = partes
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .trim_matches('\'');

        match clave {
            "PRETTY_NAME" => info.os_nombre = valor.to_string(),
            "VERSION_ID" if info.os_build.is_empty() => info.os_build = valor.to_string(),
            "NAME" if info.os_nombre.is_empty() => info.os_nombre = valor.to_string(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parsear_os_release() {
        let os_release = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
"#;
        let mut info = VMInfo::default();
        parsear_os_release(os_release, &mut info);
        assert_eq!(info.os_nombre, "Ubuntu 22.04.3 LTS");
        assert_eq!(info.os_build, "22.04");
    }

    #[test]
    fn test_parsear_dpkg_status_agnostico() {
        let dpkg = r#"
Package: open-vm-tools
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 3120
Maintainer: Ubuntu Developers
Architecture: amd64
Version: 2:12.1.5-1ubuntu0.22.04.4

Package: mosquitto
Status: install ok installed
Priority: optional
Section: net
Version: 2.0.11-1ubuntu1.1

Package: libc6
Status: install ok installed
Priority: required
Section: libs
Version: 2.35-0ubuntu3.4

Package: python3-minimal
Status: install ok installed
Priority: optional
Section: python
Version: 3.10.6-1~22.04
"#;
        let opciones = Opciones::default();
        let (paquetes, vmtools) = parsear_dpkg_status(dpkg, &opciones);
        assert_eq!(
            vmtools.as_deref(),
            Some("open-vm-tools 2:12.1.5-1ubuntu0.22.04.4")
        );
        // Debe incluir TODOS los paquetes sin filtrar por librerías, prefijos o sufijos
        assert_eq!(paquetes.len(), 4);
        assert!(paquetes.iter().any(|p| p.nombre == "open-vm-tools"));
        assert!(paquetes.iter().any(|p| p.nombre == "mosquitto"));
        assert!(paquetes.iter().any(|p| p.nombre == "libc6"));
        assert!(paquetes.iter().any(|p| p.nombre == "python3-minimal"));
    }

    #[test]
    fn test_parsear_dpkg_status_noapps() {
        let dpkg = r#"
Package: open-vm-tools
Status: install ok installed
Priority: optional
Section: admin
Version: 2:12.1.5-1ubuntu0.22.04.4

Package: mosquitto
Status: install ok installed
Priority: optional
Section: net
Version: 2.0.11-1ubuntu1.1
"#;
        let opciones = Opciones {
            noapps: true,
            ..Opciones::default()
        };
        let (paquetes, vmtools) = parsear_dpkg_status(dpkg, &opciones);
        assert_eq!(
            vmtools.as_deref(),
            Some("open-vm-tools 2:12.1.5-1ubuntu0.22.04.4")
        );
        assert!(paquetes.is_empty());
    }
}
