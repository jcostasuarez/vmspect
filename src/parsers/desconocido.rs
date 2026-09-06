use crate::error::Result;
use crate::models::traits::{InspectorOS, ResultadoAnalisis, VmDriver};
use crate::models::{Opciones, Particion, VMInfo};

pub(crate) struct DesconocidoInspector;

impl InspectorOS for DesconocidoInspector {
    fn analizar(
        &self,
        _driver: &dyn VmDriver,
        _particiones: &[Particion],
        _tamano_chunk: u64,
        opciones: &Opciones,
    ) -> Result<ResultadoAnalisis> {
        Ok(ResultadoAnalisis {
            vm_info: if opciones.debe_analizar_sistema() {
                VMInfo {
                    os_nombre: "Sistema operativo desconocido".to_string(),
                    ..VMInfo::default()
                }
            } else {
                VMInfo::default()
            },
            programas: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_desconocido_inspector() {
        let inspector = DesconocidoInspector;
        let opciones = Opciones::default();
        let res = inspector
            .analizar(&MockDriver, &[], 4096, &opciones)
            .unwrap();
        assert_eq!(res.vm_info.os_nombre, "Sistema operativo desconocido");
        assert!(res.programas.is_empty());

        let opciones_nosys = Opciones {
            nosystem: true,
            ..Opciones::default()
        };
        let res_nosys = inspector
            .analizar(&MockDriver, &[], 4096, &opciones_nosys)
            .unwrap();
        assert_eq!(res_nosys.vm_info.os_nombre, "");
    }

    struct MockDriver;
    impl VmDriver for MockDriver {
        fn tamano_virtual(&self) -> u64 {
            0
        }
        fn leer_rango(&self, _offset: u64, _buf: &mut [u8]) -> Result<()> {
            Ok(())
        }
        fn modo_acceso(&self) -> &str {
            "mock"
        }
        fn es_nativo(&self) -> bool {
            true
        }
    }
}
