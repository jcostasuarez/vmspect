use crate::error::Result;
use crate::models::traits::{AnalysisResult, OsInspector, VmDriver};
use crate::models::{GuestInfo, Options, Partition};

pub(crate) struct UnknownInspector;

impl OsInspector for UnknownInspector {
    fn analyze(
        &self,
        _driver: &dyn VmDriver,
        _partitions: &[Partition],
        _chunk_size: u64,
        options: &Options,
    ) -> Result<AnalysisResult> {
        Ok(AnalysisResult {
            guest_info: if options.should_analyze_system() {
                GuestInfo {
                    os_name: "Unknown operating system".to_string(),
                    ..GuestInfo::default()
                }
            } else {
                GuestInfo::default()
            },
            programs: Vec::new(),
            warnings: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_inspector() {
        let inspector = UnknownInspector;
        let options = Options::default();
        let res = inspector.analyze(&MockDriver, &[], 4096, &options).unwrap();
        assert_eq!(res.guest_info.os_name, "Unknown operating system");
        assert!(res.programs.is_empty());

        let options_nosys = Options {
            no_system: true,
            ..Options::default()
        };
        let res_nosys = inspector
            .analyze(&MockDriver, &[], 4096, &options_nosys)
            .unwrap();
        assert_eq!(res_nosys.guest_info.os_name, "");
    }

    struct MockDriver;
    impl VmDriver for MockDriver {
        fn virtual_size(&self) -> u64 {
            0
        }
        fn read_range(&self, _offset: u64, _buf: &mut [u8]) -> Result<()> {
            Ok(())
        }
        fn access_mode(&self) -> &str {
            "mock"
        }
        fn is_native(&self) -> bool {
            true
        }
    }
}
