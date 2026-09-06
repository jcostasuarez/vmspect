//! Manejo centralizado de errores para `vmspect`.

use thiserror::Error;

/// Enumeración con los tipos de errores que pueden producirse durante la inspección y análisis.
#[derive(Debug, Error)]
pub enum VmSpectError {
    /// Error de entrada/salida (I/O).
    #[error("Error de E/S: {0}")]
    Io(#[from] std::io::Error),

    /// Error durante el parseo de estructuras de disco, particiones, sistemas de archivos o registros.
    #[error("Error de parseo: {0}")]
    Parse(String),

    /// Sistema operativo no soportado o no reconocido.
    #[error("Sistema operativo no soportado: {0}")]
    UnsupportedOs(String),

    /// Formato de imagen de disco no soportado o desconocido.
    #[error("Formato de imagen no soportado: {0}")]
    UnsupportedFormat(String),

    /// La imagen especificada no existe en la ruta indicada.
    #[error("Imagen de disco no encontrada: {0}")]
    ImageNotFound(String),

    /// La operación de inspección fue cancelada por el usuario o token de cancelación.
    #[error("La inspección fue cancelada por el usuario")]
    Cancelled,

    /// Binario o herramienta `qemu-nbd` no encontrada en el sistema.
    #[error("Herramienta QEMU no disponible: {0}")]
    QemuNotFound(String),

    /// Error durante la inicialización o comunicación con el servidor NBD.
    #[error("Error de protocolo NBD: {0}")]
    Nbd(String),

    /// Error en la lectura o navegación del sistema de archivos (NTFS, EXT4, etc.).
    #[error("Error de sistema de archivos: {0}")]
    FileSystem(String),

    /// Error en la extracción o análisis de colmenas del Registro de Windows.
    #[error("Error en el Registro de Windows: {0}")]
    WindowsRegistry(String),

    /// Error de configuración u opciones.
    #[error("Error de configuración: {0}")]
    Config(String),

    /// Error genérico o mensaje descriptivo de fallo durante el análisis.
    #[error("Error de inspección: {0}")]
    Other(String),
}

impl From<String> for VmSpectError {
    fn from(msg: String) -> Self {
        VmSpectError::Other(msg)
    }
}

impl From<&str> for VmSpectError {
    fn from(msg: &str) -> Self {
        VmSpectError::Other(msg.to_string())
    }
}

/// Alias estándar de `Result` utilizado en toda la biblioteca `vmspect`.
pub type Result<T> = std::result::Result<T, VmSpectError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err_io = VmSpectError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "archivo no encontrado",
        ));
        assert!(err_io.to_string().contains("Error de E/S"));

        let err_cancel = VmSpectError::Cancelled;
        assert_eq!(
            err_cancel.to_string(),
            "La inspección fue cancelada por el usuario"
        );

        let err_other: VmSpectError = "algo falló".into();
        assert_eq!(err_other.to_string(), "Error de inspección: algo falló");
    }
}
