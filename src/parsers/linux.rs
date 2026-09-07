//! Linux guest analysis using the `ext4` crate.
//!
//! Reads the file system in user space without mounting the partition on the host operating system.
use crate::error::Result;
use crate::models::traits::{AnalysisResult, OsInspector, VmDriver};
use crate::models::{FileSystem, GuestInfo, GuestTools, Options, Partition, Program};
use crate::vms::stream::VirtualDisk;
use ext4::SuperBlock;
use positioned_io::ReadAt;

use std::io::Read;

pub(crate) struct LinuxInspector;

impl OsInspector for LinuxInspector {
    fn analyze(
        &self,
        driver: &dyn VmDriver,
        partitions: &[Partition],
        chunk_size: u64,
        options: &Options,
    ) -> Result<AnalysisResult> {
        if !options.should_analyze_system() && !options.should_analyze_apps() {
            return Ok(AnalysisResult::default());
        }

        let mut candidates: Vec<_> = partitions
            .iter()
            .filter(|p| {
                matches!(
                    p.file_system,
                    FileSystem::Ext4 | FileSystem::Ext3 | FileSystem::Ext2
                )
            })
            .collect();

        candidates.sort_by_key(|p| std::cmp::Reverse(p.size));

        for partition in candidates {
            let mut disk = VirtualDisk::new(driver, partition.start, partition.size, chunk_size);

            if let Ok(sb) = SuperBlock::new(&mut disk) {
                if let Ok(result) = analyze_file_system(&sb, options) {
                    return Ok(result);
                }
            }
        }

        // Fallback
        Ok(AnalysisResult {
            guest_info: if options.should_analyze_system() {
                GuestInfo {
                    os_name: "Linux (rootfs could not be read)".to_string(),
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

fn analyze_file_system<R: ReadAt>(sb: &SuperBlock<R>, options: &Options) -> Result<AnalysisResult> {
    let mut guest_info = GuestInfo::default();
    let mut programs = Vec::new();

    if options.should_analyze_system() {
        if let Ok(content) = read_text_file(sb, "/etc/os-release")
            .or_else(|_| read_text_file(sb, "/usr/lib/os-release"))
        {
            parse_os_release(&content, &mut guest_info);
        }

        if let Ok(hostname) = read_text_file(sb, "/etc/hostname") {
            let name = hostname.trim();
            if !name.is_empty() {
                guest_info.os_edition = format!("Host: {}", name);
            }
        }
    }

    if let Ok(dpkg_status) = read_text_file(sb, "/var/lib/dpkg/status") {
        let (pkgs, guest_tools) = parse_dpkg_status(&dpkg_status, options);
        if options.should_analyze_apps() {
            programs.extend(pkgs);
        }
        if options.should_analyze_system() {
            if let Some(tools) = guest_tools {
                guest_info.guest_tools = Some(tools);
            }
        }
    }

    if options.should_analyze_system() && guest_info.guest_tools.is_none() {
        guest_info.guest_tools = detect_guest_tools_linux_files(sb);
    }

    if options.should_analyze_apps() {
        // Sort and deduplicate respecting the Program structure
        programs.sort_by(|a, b| a.name.cmp(&b.name));
        programs.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    }

    Ok(AnalysisResult {
        guest_info,
        programs,
        warnings: Vec::new(),
    })
}

/// Inspects binaries or service units of the Linux guest OS to detect integration tool
/// suites (VMware Tools, VirtualBox Guest Additions, QEMU Guest Agent and Hyper-V
/// Integration Services) when they are not provided by the package manager.
fn detect_guest_tools_linux_files<R: ReadAt>(sb: &SuperBlock<R>) -> Option<GuestTools> {
    // 1. VMware
    let vmware_paths = [
        "/usr/bin/vmtoolsd",
        "/usr/sbin/vmtoolsd",
        "/bin/vmtoolsd",
        "/sbin/vmtoolsd",
        "/etc/vmware-tools",
        "/lib/systemd/system/open-vm-tools.service",
        "/etc/systemd/system/open-vm-tools.service",
    ];
    for path in &vmware_paths {
        if sb.resolve_path(path).is_ok() {
            return Some(GuestTools {
                kind: "VMware Tools".to_string(),
                version: None,
                present: true,
            });
        }
    }

    // 2. VirtualBox
    let vbox_paths = [
        "/usr/sbin/VBoxService",
        "/usr/bin/VBoxService",
        "/usr/sbin/vboxservice",
        "/usr/bin/vboxservice",
        "/sbin/VBoxService",
        "/lib/systemd/system/vboxadd-service.service",
        "/etc/systemd/system/vboxadd-service.service",
        "/opt/VBoxGuestAdditions",
    ];
    for path in &vbox_paths {
        if sb.resolve_path(path).is_ok() {
            return Some(GuestTools {
                kind: "VirtualBox Guest Additions".to_string(),
                version: None,
                present: true,
            });
        }
    }

    // 3. QEMU Guest Agent
    let qemu_paths = [
        "/usr/bin/qemu-ga",
        "/usr/sbin/qemu-ga",
        "/lib/systemd/system/qemu-guest-agent.service",
        "/etc/systemd/system/qemu-guest-agent.service",
    ];
    for path in &qemu_paths {
        if sb.resolve_path(path).is_ok() {
            return Some(GuestTools {
                kind: "QEMU Guest Agent".to_string(),
                version: None,
                present: true,
            });
        }
    }

    // 4. Hyper-V
    let hyperv_paths = [
        "/usr/sbin/hv_kvp_daemon",
        "/usr/bin/hv_kvp_daemon",
        "/usr/sbin/hv_vss_daemon",
        "/usr/sbin/hv_fcopy_daemon",
        "/lib/systemd/system/hv-kvp-daemon.service",
        "/lib/systemd/system/hypervkvp.service",
    ];
    for path in &hyperv_paths {
        if sb.resolve_path(path).is_ok() {
            return Some(GuestTools {
                kind: "Hyper-V Integration Services".to_string(),
                version: None,
                present: true,
            });
        }
    }

    None
}

fn parse_dpkg_status(content: &str, options: &Options) -> (Vec<Program>, Option<GuestTools>) {
    let mut packages = Vec::new();
    let mut guest_tools: Option<GuestTools> = None;

    let mut current_pkg = String::new();
    let mut current_ver = String::new();
    let mut current_section = String::new();
    let mut installed = false;

    let should_apps = options.should_analyze_apps();

    let process_package = |pkg: &str,
                           ver: &str,
                           sec: &str,
                           inst: bool,
                           pkgs: &mut Vec<Program>,
                           tools: &mut Option<GuestTools>| {
        if inst && !pkg.is_empty() {
            // Capture hypervisor-agnostic integration tools
            if tools.is_none() {
                let ver_opt = if !ver.is_empty() {
                    Some(ver.to_string())
                } else {
                    None
                };

                if pkg == "open-vm-tools" || pkg == "open-vm-tools-desktop" {
                    *tools = Some(GuestTools {
                        kind: "VMware Tools".to_string(),
                        version: ver_opt,
                        present: true,
                    });
                } else if pkg == "virtualbox-guest-utils"
                    || pkg == "virtualbox-guest-x11"
                    || pkg == "virtualbox-guest-dkms"
                    || pkg == "virtualbox-guest-additions-iso"
                {
                    *tools = Some(GuestTools {
                        kind: "VirtualBox Guest Additions".to_string(),
                        version: ver_opt,
                        present: true,
                    });
                } else if pkg == "qemu-guest-agent" {
                    *tools = Some(GuestTools {
                        kind: "QEMU Guest Agent".to_string(),
                        version: ver_opt,
                        present: true,
                    });
                } else if pkg == "hyperv-daemons"
                    || pkg == "hv-kvp-daemon-init"
                    || pkg == "linux-cloud-tools-virtual"
                {
                    *tools = Some(GuestTools {
                        kind: "Hyper-V Integration Services".to_string(),
                        version: ver_opt,
                        present: true,
                    });
                }
            }

            if should_apps {
                let version_opt = if !ver.is_empty() {
                    Some(ver.to_string())
                } else {
                    None
                };

                let publisher_opt = if !sec.is_empty() {
                    Some(sec.to_string())
                } else {
                    None
                };

                pkgs.push(Program {
                    name: pkg.to_string(),
                    version: version_opt,
                    publisher: publisher_opt,
                    source: None,
                });
            }
        }
    };

    for line in content.lines() {
        if let Some(cancel) = &options.cancel_token {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }

        if line.starts_with("Package: ") {
            current_pkg = line.trim_start_matches("Package: ").trim().to_string();
        } else if line.starts_with("Status: ") {
            installed = line.contains("install ok installed");
        } else if line.starts_with("Version: ") {
            current_ver = line.trim_start_matches("Version: ").trim().to_string();
        } else if line.starts_with("Section: ") {
            current_section = line.trim_start_matches("Section: ").trim().to_string();
        } else if line.trim().is_empty() {
            process_package(
                &current_pkg,
                &current_ver,
                &current_section,
                installed,
                &mut packages,
                &mut guest_tools,
            );
            current_pkg.clear();
            current_ver.clear();
            current_section.clear();
            installed = false;
        }
    }

    // Process the last package if there was no blank line at the end.
    process_package(
        &current_pkg,
        &current_ver,
        &current_section,
        installed,
        &mut packages,
        &mut guest_tools,
    );

    (packages, guest_tools)
}

/// Reads a text file from the ext4 partition and returns it as a String.
fn read_text_file<R: ReadAt>(sb: &SuperBlock<R>, path: &str) -> Result<String> {
    let entry = sb
        .resolve_path(path)
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

/// Parses `/etc/os-release`, extracting the OS name and version.
fn parse_os_release(content: &str, info: &mut GuestInfo) {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains('=') {
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .trim_matches('\'');

        match key {
            "PRETTY_NAME" => info.os_name = value.to_string(),
            "VERSION_ID" if info.os_build.is_empty() => info.os_build = value.to_string(),
            "NAME" if info.os_name.is_empty() => info.os_name = value.to_string(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release() {
        let os_release = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
"#;
        let mut info = GuestInfo::default();
        parse_os_release(os_release, &mut info);
        assert_eq!(info.os_name, "Ubuntu 22.04.3 LTS");
        assert_eq!(info.os_build, "22.04");
    }

    #[test]
    fn test_parse_dpkg_status_agnostic() {
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
        let options = Options::default();
        let (packages, tools) = parse_dpkg_status(dpkg, &options);
        assert_eq!(
            tools,
            Some(GuestTools {
                kind: "VMware Tools".to_string(),
                version: Some("2:12.1.5-1ubuntu0.22.04.4".to_string()),
                present: true,
            })
        );
        // Must include ALL packages without filtering by libraries, prefixes or suffixes
        assert_eq!(packages.len(), 4);
        assert!(packages.iter().any(|p| p.name == "open-vm-tools"));
        assert!(packages.iter().any(|p| p.name == "mosquitto"));
        assert!(packages.iter().any(|p| p.name == "libc6"));
        assert!(packages.iter().any(|p| p.name == "python3-minimal"));
    }

    #[test]
    fn test_parse_dpkg_status_no_apps() {
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
        let options = Options {
            no_apps: true,
            ..Options::default()
        };
        let (packages, tools) = parse_dpkg_status(dpkg, &options);
        assert_eq!(
            tools,
            Some(GuestTools {
                kind: "VMware Tools".to_string(),
                version: Some("2:12.1.5-1ubuntu0.22.04.4".to_string()),
                present: true,
            })
        );
        assert!(packages.is_empty());
    }

    #[test]
    fn test_parse_dpkg_status_multiple_hypervisors() {
        let dpkg_vbox = r#"
Package: virtualbox-guest-utils
Status: install ok installed
Priority: optional
Section: admin
Version: 7.0.12-dfsg-1
"#;
        let (_, tools_vbox) = parse_dpkg_status(dpkg_vbox, &Options::default());
        assert_eq!(
            tools_vbox,
            Some(GuestTools {
                kind: "VirtualBox Guest Additions".to_string(),
                version: Some("7.0.12-dfsg-1".to_string()),
                present: true,
            })
        );

        let dpkg_qemu = r#"
Package: qemu-guest-agent
Status: install ok installed
Priority: optional
Section: admin
Version: 1:8.2.2+ds-0ubuntu1
"#;
        let (_, tools_qemu) = parse_dpkg_status(dpkg_qemu, &Options::default());
        assert_eq!(
            tools_qemu,
            Some(GuestTools {
                kind: "QEMU Guest Agent".to_string(),
                version: Some("1:8.2.2+ds-0ubuntu1".to_string()),
                present: true,
            })
        );

        let dpkg_hyperv = r#"
Package: hyperv-daemons
Status: install ok installed
Priority: optional
Section: admin
Version: 5.15.0-91.101
"#;
        let (_, tools_hyperv) = parse_dpkg_status(dpkg_hyperv, &Options::default());
        assert_eq!(
            tools_hyperv,
            Some(GuestTools {
                kind: "Hyper-V Integration Services".to_string(),
                version: Some("5.15.0-91.101".to_string()),
                present: true,
            })
        );
    }
}
