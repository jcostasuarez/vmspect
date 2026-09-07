//! Per-operating-system analyzer modules.

pub(crate) mod desconocido;
pub(crate) mod linux;
pub(crate) mod windows;

use crate::models::traits::OsInspector;
use crate::models::OperatingSystem;

pub(crate) fn get_inspector(os: &OperatingSystem) -> Box<dyn OsInspector> {
    match os {
        OperatingSystem::Windows => Box::new(windows::WindowsInspector),
        OperatingSystem::Linux => Box::new(linux::LinuxInspector),
        OperatingSystem::Unknown => Box::new(desconocido::UnknownInspector),
    }
}
