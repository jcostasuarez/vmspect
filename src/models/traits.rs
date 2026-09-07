//! Traits y contratos abstractos independientes del hipervisor o sistema operativo.

use crate::error::Result;
use crate::models::{Opciones, Particion, Programa, VMInfo};
use std::io::{Read, Seek};

/// Resultado consolidado devuelto por la inspección de un sistema operativo.
#[derive(Debug, Clone, Default)]
pub struct ResultadoAnalisis {
    /// Información detallada del sistema operativo detectado.
    pub vm_info: VMInfo,
    /// Lista de programas y paquetes identificados.
    pub programas: Vec<Programa>,
    /// Advertencias no fatales recolectadas durante el análisis (ej. colmenas del
    /// Registro de Windows corruptas o "sucias" de las que se degradó con gracia).
    pub advertencias: Vec<String>,
}

/// Contrato abstracto para drivers de acceso a imágenes de máquinas virtuales o hipervisores.
pub trait VmDriver {
    /// Devuelve el tamaño virtual total del disco en bytes.
    fn tamano_virtual(&self) -> u64;

    /// Lee un rango de bytes desde el desplazamiento `offset` virtual hasta llenar `buf`.
    fn leer_rango(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// Nombre o descripción del modo de acceso utilizado por el driver.
    fn modo_acceso(&self) -> &str;

    /// Indica si el driver opera de forma nativa en Rust sin subprocesos externos.
    fn es_nativo(&self) -> bool;

    /// Tamaño de chunk recomendado para operaciones en bloque con este driver.
    fn tamano_chunk_recomendado(&self) -> u64 {
        1024 * 1024
    }
}

/// Contrato abstracto para mapeadores de memoria, bloques o rangos de disco virtual.
pub trait MemoryMapper: Read + Seek {
    /// Lee un bloque de datos en un desplazamiento absoluto `offset` dentro del espacio mapeado.
    fn leer_en_offset(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Devuelve la longitud total del espacio mapeado.
    fn longitud(&self) -> u64;
}

/// Contrato abstracto para analizadores de sistemas operativos invitados (Windows, Linux, etc.).
pub trait InspectorOS {
    /// Ejecuta el análisis del sistema de archivos y extrae la información del SO y software instalado.
    fn analizar(
        &self,
        driver: &dyn VmDriver,
        particiones: &[Particion],
        tamano_chunk: u64,
        opciones: &Opciones,
    ) -> Result<ResultadoAnalisis>;
}
