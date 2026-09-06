//! Modelos relacionados con imágenes de disco, hipervisores y estadísticas de inspección.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Hipervisor de origen, inferido del formato de la imagen de disco.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hipervisor {
    /// VMware ESXi, Workstation o Fusion.
    VMware,
    /// Oracle VirtualBox.
    VirtualBox,
    /// Microsoft Hyper-V o Virtual PC.
    HyperV,
    /// QEMU / KVM.
    Qemu,
    /// Hipervisor o formato de origen desconocido.
    Desconocido,
}

impl Hipervisor {
    /// Deduce el hipervisor a partir de la extensión o nombre de formato devuelto por la inspección.
    pub fn desde_formato(formato: &str) -> Self {
        match formato.to_ascii_lowercase().as_str() {
            "vmdk" => Hipervisor::VMware,
            "vdi" => Hipervisor::VirtualBox,
            "vpc" | "vhd" | "vhdx" => Hipervisor::HyperV,
            "qcow" | "qcow2" | "qed" => Hipervisor::Qemu,
            _ => Hipervisor::Desconocido,
        }
    }

    /// Nombre descriptivo del hipervisor.
    pub fn nombre(&self) -> &'static str {
        match self {
            Hipervisor::VMware => "VMware",
            Hipervisor::VirtualBox => "VirtualBox",
            Hipervisor::HyperV => "Hyper-V / Virtual PC",
            Hipervisor::Qemu => "QEMU / KVM",
            Hipervisor::Desconocido => "Desconocido (imagen raw u otro)",
        }
    }
}

/// Información descriptiva y dimensiones de la imagen de disco examinada.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoImagen {
    /// Ruta del archivo de disco en el sistema de archivos host.
    pub ruta: PathBuf,
    /// Formato detectado (ej. "vmdk", "vdi", "vhdx", "qcow2", "raw").
    pub formato: String,
    /// Capacidad total expresada por el disco virtual en bytes.
    pub tamano_virtual: u64,
    /// Tamaño físico realmente ocupado en disco por el archivo de la imagen en bytes.
    pub tamano_real: u64,
    /// Hipervisor asociado a la imagen.
    pub hipervisor: Hipervisor,
}

/// Estadísticas y métricas de rendimiento recolectadas durante el proceso de inspección.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Estadisticas {
    /// Descripción del backend de acceso empleado (ej. "nativo (...)" o "qemu-nbd tcp (...)").
    pub modo_acceso: String,
    /// Cantidad de peticiones realizadas al backend de lectura (socket NBD en modo virtualizado).
    pub peticiones_nbd: u64,
    /// Cantidad total de bytes extraídos físicamente desde el disco virtual.
    pub bytes_leidos: u64,
    /// Tiempo total que tomó el proceso de inspección expresado en milisegundos.
    pub duracion_ms: u64,
}

/// Función utilitaria que convierte un valor entero en bytes a una representación léxica formateada (B, KiB, MiB, GiB, TiB).
pub fn formatear_bytes(bytes: u64) -> String {
    const UNIDADES: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut valor = bytes as f64;
    let mut idx = 0;
    while valor >= 1024.0 && idx < UNIDADES.len() - 1 {
        valor /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{} {}", bytes, UNIDADES[idx])
    } else {
        format!("{:.1} {}", valor, UNIDADES[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatear_bytes() {
        assert_eq!(formatear_bytes(500), "500 B");
        assert_eq!(formatear_bytes(1024), "1.0 KiB");
        assert_eq!(formatear_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(formatear_bytes(1024 * 1024 * 1024 * 2), "2.0 GiB");
    }

    #[test]
    fn test_hipervisor_desde_formato() {
        assert_eq!(Hipervisor::desde_formato("vmdk"), Hipervisor::VMware);
        assert_eq!(Hipervisor::desde_formato("vdi"), Hipervisor::VirtualBox);
        assert_eq!(Hipervisor::desde_formato("vhdx"), Hipervisor::HyperV);
        assert_eq!(Hipervisor::desde_formato("qcow2"), Hipervisor::Qemu);
        assert_eq!(Hipervisor::desde_formato("raw"), Hipervisor::Desconocido);
    }
}
