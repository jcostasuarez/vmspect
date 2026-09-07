//! Modelos de programas, paquetes de software e información del sistema operativo invitado.

use serde::{Deserialize, Serialize};

/// Representa un programa o paquete de software instalado detectado en el SO huésped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Programa {
    /// Nombre visible del programa (DisplayName en Windows / Package Name en Linux).
    pub nombre: String,
    /// Versión instalada (DisplayVersion / Version).
    pub version: Option<String>,
    /// Editor o fabricante (Publisher / Maintainer / Section).
    pub editor: Option<String>,
    /// Origen de la detección cuando no proviene del mecanismo principal de
    /// extracción (Registro / gestor de paquetes). Por ejemplo, `"FallbackFS"`
    /// cuando el programa se infirió escaneando `\Program Files` porque el
    /// Registro de Windows resultó totalmente inaccesible.
    #[serde(default)]
    pub origen: Option<String>,
}

/// Información sobre las herramientas de integración para invitados (Guest Tools / Additions / Agents).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HerramientasGuest {
    /// Tipo o suite de herramientas (ej. "VMware Tools", "VirtualBox Guest Additions", "QEMU Guest Agent", "Hyper-V Integration Services").
    pub tipo: String,
    /// Versión instalada de las herramientas, si está disponible (ej. "13.0.5.0", "7.0.12").
    pub version: Option<String>,
    /// Indica si las herramientas o servicios de integración están presentes en el sistema huésped.
    pub presente: bool,
}

/// Contiene los metadatos detallados del sistema operativo detectado y sus componentes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VMInfo {
    /// Nombre del sistema operativo (ej. "Windows 10 Pro", "Ubuntu 22.04 LTS").
    pub os_nombre: String,
    /// Edición o versión del SO.
    pub os_edition_version: String,
    /// Service Pack instalado en sistemas Windows.
    pub os_service_pack: String,
    /// Número de compilación (Build) del SO.
    pub os_build: String,
    /// Información sobre herramientas de integración para invitados (Guest Tools / Additions / Agents).
    pub guest_tools: Option<HerramientasGuest>,
}

impl VMInfo {
    /// Formatea los metadatos del SO en una cadena de texto legible consolidando versión, build y Service Pack.
    pub fn os_cadena_formateada(&self) -> String {
        let mut detalles = Vec::new();
        if !self.os_service_pack.is_empty() {
            detalles.push(self.os_service_pack.clone());
        }
        if !self.os_edition_version.is_empty() {
            detalles.push(format!("Versión {}", self.os_edition_version));
        }
        if !self.os_build.is_empty() {
            detalles.push(format!("Build {}", self.os_build));
        }

        if detalles.is_empty() {
            self.os_nombre.clone()
        } else {
            format!("{} ({})", self.os_nombre, detalles.join(" - "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vminfo_formateado() {
        let info = VMInfo {
            os_nombre: "Windows 10 Pro".to_string(),
            os_edition_version: "22H2".to_string(),
            os_build: "19045".to_string(),
            os_service_pack: "SP1".to_string(),
            ..VMInfo::default()
        };

        let s = info.os_cadena_formateada();
        assert!(s.contains("Windows 10 Pro"));
        assert!(s.contains("SP1"));
        assert!(s.contains("Versión 22H2"));
        assert!(s.contains("Build 19045"));
    }

    #[test]
    fn test_programa_agnostico() {
        let prog = Programa {
            nombre: "libssl3".to_string(),
            version: Some("3.0.2".to_string()),
            editor: Some("libs".to_string()),
            origen: None,
        };
        assert_eq!(prog.nombre, "libssl3");
        assert_eq!(prog.version.as_deref(), Some("3.0.2"));
        assert_eq!(prog.editor.as_deref(), Some("libs"));
        assert_eq!(prog.origen, None);
    }

    #[test]
    fn test_herramientas_guest_serializacion() {
        let tools = HerramientasGuest {
            tipo: "VirtualBox Guest Additions".to_string(),
            version: Some("7.0.12".to_string()),
            presente: true,
        };
        assert_eq!(tools.tipo, "VirtualBox Guest Additions");
        assert_eq!(tools.version.as_deref(), Some("7.0.12"));
        assert!(tools.presente);
    }
}
