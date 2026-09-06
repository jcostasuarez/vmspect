//! Módulo de analizadores por sistema operativo.

pub(crate) mod desconocido;
pub(crate) mod linux;
pub(crate) mod windows;

use crate::models::traits::InspectorOS;
use crate::models::SistemaOperativo;

pub(crate) fn obtener_inspector(so: &SistemaOperativo) -> Box<dyn InspectorOS> {
    match so {
        SistemaOperativo::Windows => Box::new(windows::WindowsInspector),
        SistemaOperativo::Linux => Box::new(linux::LinuxInspector),
        SistemaOperativo::Desconocido => Box::new(desconocido::DesconocidoInspector),
    }
}
