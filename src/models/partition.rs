//! Modelos de particiones, esquemas y sistemas de archivos.

use serde::{Deserialize, Serialize};

/// Esquema de la tabla de particiones presente en el disco virtual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EsquemaParticion {
    /// Master Boot Record tradicional.
    Mbr,
    /// GUID Partition Table.
    Gpt,
    /// El disco carece de tabla de particiones: el sistema de archivos inicia directamente en el sector 0.
    SinTabla,
}

/// Tipo de sistema de archivos identificado en una partición.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SistemaArchivos {
    /// New Technology File System (Windows).
    Ntfs,
    /// File Allocation Table (FAT12/FAT16/FAT32/exFAT).
    Fat,
    /// Second Extended Filesystem (Linux).
    Ext2,
    /// Third Extended Filesystem (Linux).
    Ext3,
    /// Fourth Extended Filesystem (Linux).
    Ext4,
    /// High-performance journaling file system (Linux).
    Xfs,
    /// B-tree file system (Linux).
    Btrfs,
    /// Partición de intercambio de Linux.
    LinuxSwap,
    /// Volumen Físico de LVM2 (Linux Logical Volume Manager).
    Lvm2,
    /// Sistema de archivos no reconocido o no soportado.
    Desconocido,
}

impl SistemaArchivos {
    /// Determina si el sistema de archivos pertenece nativamente al ecosistema Linux.
    pub fn es_linux(&self) -> bool {
        matches!(
            self,
            SistemaArchivos::Ext2
                | SistemaArchivos::Ext3
                | SistemaArchivos::Ext4
                | SistemaArchivos::Xfs
                | SistemaArchivos::Btrfs
                | SistemaArchivos::LinuxSwap
                | SistemaArchivos::Lvm2
        )
    }

    /// Nombre amigable y estandarizado del sistema de archivos.
    pub fn nombre(&self) -> &'static str {
        match self {
            SistemaArchivos::Ntfs => "NTFS",
            SistemaArchivos::Fat => "FAT",
            SistemaArchivos::Ext2 => "ext2",
            SistemaArchivos::Ext3 => "ext3",
            SistemaArchivos::Ext4 => "ext4",
            SistemaArchivos::Xfs => "XFS",
            SistemaArchivos::Btrfs => "Btrfs",
            SistemaArchivos::LinuxSwap => "Linux swap",
            SistemaArchivos::Lvm2 => "LVM2 PV",
            SistemaArchivos::Desconocido => "desconocido",
        }
    }
}

/// Clasificación general de la familia del sistema operativo invitado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SistemaOperativo {
    /// Sistemas operativos Microsoft Windows.
    Windows,
    /// Distribuciones Linux.
    Linux,
    /// Sistema operativo no identificado o no soportado.
    Desconocido,
}

impl SistemaOperativo {
    /// Devuelve un emoji representativo del sistema operativo para interfaces de consola.
    pub fn icono(&self) -> &'static str {
        match self {
            SistemaOperativo::Windows => "🪟",
            SistemaOperativo::Linux => "🐧",
            SistemaOperativo::Desconocido => "❓",
        }
    }
}

/// Representación de una partición física localizada dentro del disco virtual.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Particion {
    /// Índice secuencial de la partición dentro de la tabla.
    pub indice: usize,
    /// Desplazamiento absoluto en bytes donde inicia la partición en el disco virtual.
    pub inicio: u64,
    /// Tamaño total de la partición expresado en bytes.
    pub tamano: u64,
    /// Tipo de partición declarado (byte MBR o GUID GPT traducido).
    pub tipo: String,
    /// Sistema de archivos detectado inspeccionando la firma del primer sector de la partición.
    pub sistema_archivos: SistemaArchivos,
    /// Etiqueta o volumen opcional asignado a la partición.
    pub etiqueta: Option<String>,
}

impl Particion {
    /// Devuelve `true` si el sistema de archivos de la partición es NTFS.
    pub fn es_ntfs(&self) -> bool {
        matches!(self.sistema_archivos, SistemaArchivos::Ntfs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sistema_archivos() {
        assert!(SistemaArchivos::Ext4.es_linux());
        assert!(!SistemaArchivos::Ntfs.es_linux());
        assert_eq!(SistemaArchivos::Ntfs.nombre(), "NTFS");
    }
}
