//! Models for programs, software packages and guest OS information.

use serde::{Deserialize, Serialize};

/// Represents an installed program or software package detected in the guest OS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Program {
    /// Visible program name (DisplayName on Windows / Package Name on Linux).
    pub name: String,
    /// Installed version (DisplayVersion / Version).
    pub version: Option<String>,
    /// Publisher or manufacturer (Publisher / Maintainer / Section).
    pub publisher: Option<String>,
    /// Detection origin when it did not come from the primary extraction
    /// mechanism (Registry / package manager). For example, `"FallbackFS"`
    /// when the program was inferred by scanning `\Program Files` because
    /// the Windows Registry was totally inaccessible.
    #[serde(default)]
    pub source: Option<String>,
}

/// Information about the guest integration tools (Guest Tools / Additions / Agents).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GuestTools {
    /// Type or suite of tools (e.g. "VMware Tools", "VirtualBox Guest Additions",
    /// "QEMU Guest Agent", "Hyper-V Integration Services").
    pub kind: String,
    /// Installed version of the tools, if available (e.g. "13.0.5.0", "7.0.12").
    pub version: Option<String>,
    /// Indicates whether the tools or integration services are present on the guest system.
    pub present: bool,
}

/// Detailed metadata of the detected operating system and its components.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GuestInfo {
    /// Operating system name (e.g. "Windows 10 Pro", "Ubuntu 22.04 LTS").
    pub os_name: String,
    /// OS edition or version.
    pub os_edition: String,
    /// Service Pack installed on Windows systems.
    pub os_service_pack: String,
    /// Build number of the OS.
    pub os_build: String,
    /// Information about guest integration tools (Guest Tools / Additions / Agents).
    pub guest_tools: Option<GuestTools>,
}

impl GuestInfo {
    /// Formats the OS metadata into a human-readable string consolidating version, build and Service Pack.
    pub fn formatted_os_string(&self) -> String {
        let mut details = Vec::new();
        if !self.os_service_pack.is_empty() {
            details.push(self.os_service_pack.clone());
        }
        if !self.os_edition.is_empty() {
            details.push(format!("Version {}", self.os_edition));
        }
        if !self.os_build.is_empty() {
            details.push(format!("Build {}", self.os_build));
        }

        if details.is_empty() {
            self.os_name.clone()
        } else {
            format!("{} ({})", self.os_name, details.join(" - "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_info_formatted() {
        let info = GuestInfo {
            os_name: "Windows 10 Pro".to_string(),
            os_edition: "22H2".to_string(),
            os_build: "19045".to_string(),
            os_service_pack: "SP1".to_string(),
            ..GuestInfo::default()
        };

        let s = info.formatted_os_string();
        assert!(s.contains("Windows 10 Pro"));
        assert!(s.contains("SP1"));
        assert!(s.contains("Version 22H2"));
        assert!(s.contains("Build 19045"));
    }

    #[test]
    fn test_program_agnostic() {
        let prog = Program {
            name: "libssl3".to_string(),
            version: Some("3.0.2".to_string()),
            publisher: Some("libs".to_string()),
            source: None,
        };
        assert_eq!(prog.name, "libssl3");
        assert_eq!(prog.version.as_deref(), Some("3.0.2"));
        assert_eq!(prog.publisher.as_deref(), Some("libs"));
        assert_eq!(prog.source, None);
    }

    #[test]
    fn test_guest_tools_serialization() {
        let tools = GuestTools {
            kind: "VirtualBox Guest Additions".to_string(),
            version: Some("7.0.12".to_string()),
            present: true,
        };
        assert_eq!(tools.kind, "VirtualBox Guest Additions");
        assert_eq!(tools.version.as_deref(), Some("7.0.12"));
        assert!(tools.present);
    }
}
