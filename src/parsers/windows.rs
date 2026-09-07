//! Windows guest analysis.
//!
//! Two parts:
//! 1. Extraction of the `SOFTWARE` and `SYSTEM` hives from the NTFS partition using
//!    the `ntfs` crate over a [`VirtualDisk`] (only the data runs of those files
//!    are read, not the rest of the disk).
//! 2. Registry parsing with `nt_hive`: OS information, VMware Tools and installed
//!    software in a fully hypervisor-agnostic way.

use crate::error::{Result, VmSpectError};
use crate::models::traits::{AnalysisResult, OsInspector, VmDriver};
use crate::models::{GuestInfo, GuestTools, Options, Partition, Program};
use crate::vms::stream::VirtualDisk;
use nt_hive::{Hive, KeyNode, KeyValue, NtHiveError};
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::NtfsFileNamespace;
use ntfs::{Ntfs, NtfsFile};
use std::io::Read;

const CONFIG_PATH: [&str; 3] = ["Windows", "System32", "config"];
/// Top-level folders where the NTFS fallback looks for installed software
/// when the Registry is completely inaccessible.
const PROGRAM_FILES_DIRS: [&str; 2] = ["Program Files", "Program Files (x86)"];
/// Origin tag assigned to programs inferred by the NTFS fallback.
const FALLBACK_FS_ORIGIN: &str = "FallbackFS";

struct Hives {
    software: Vec<u8>,
    system: Option<Vec<u8>>,
    /// `true` if at least one of the `SOFTWARE.LOG1` / `SOFTWARE.LOG2` transaction
    /// files was found alongside the primary hive.
    software_logs_present: bool,
    /// `true` if at least one of the `SYSTEM.LOG1` / `SYSTEM.LOG2` transaction
    /// files was found alongside the primary hive.
    system_logs_present: bool,
    /// Non-fatal warnings generated during NTFS extraction (e.g. the SYSTEM
    /// hive could not be read from disk even though it was requested).
    warnings: Vec<String>,
}

pub(crate) struct WindowsInspector;

impl OsInspector for WindowsInspector {
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

        let candidates: Vec<_> = partitions.iter().filter(|p| p.is_ntfs()).collect();

        let partition = match candidates
            .iter()
            .find(|p| is_system_partition(driver, p.start, p.size, chunk_size))
        {
            Some(p) => *p,
            None => {
                let msg =
                    "No NTFS partition contains Windows\\System32\\config (Registry inaccessible)"
                        .to_string();
                tracing::warn!("{}", msg);
                return Ok(degraded_result(msg));
            }
        };

        // `SYSTEM` is only read when the user explicitly requested it
        // (`include_system`) and has not disabled system analysis (`--no-system`).
        let include_system = options.include_system && options.should_analyze_system();

        // Graceful Degradation: if extracting the hives from the disk fails
        // (corrupt blocks, dirty hive after a hard shutdown, etc.) the inspection
        // pipeline is NOT aborted: the warning is recorded and inspection continues
        // with a default result for the OS.
        let hives = match extract_ntfs_hives(
            driver,
            partition.start,
            partition.size,
            chunk_size,
            include_system,
        ) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!(
                    "Could not extract the Windows Registry hives (dirty / inaccessible Registry): {}",
                    e
                );
                tracing::warn!("{}", msg);
                return Ok(degraded_result(msg));
            }
        };

        let (mut result, requires_fs_fallback) = analyze_hives(&hives, options)?;

        // Fallback FS: if the SOFTWARE hive was completely inaccessible (not even
        // the permissive mode could recover its key tree), fall back to inspecting
        // the NTFS file system directly so we do not return zero programs and a
        // generic OS name.
        if requires_fs_fallback {
            let (vm_info_fs, programs_fs, warnings_fs) =
                apply_fs_fallback(driver, partition, chunk_size, options);

            if let Some(info_fs) = vm_info_fs {
                result.guest_info = info_fs;
            }
            if !programs_fs.is_empty() {
                result.programs.extend(programs_fs);
            }
            result.warnings.extend(warnings_fs);
        }

        Ok(result)
    }
}

/// Builds a fallback [`AnalysisResult`] when the Windows Registry cannot be read or
/// parsed, preserving the warning for the final report instead of aborting the
/// inspection (Graceful Degradation).
fn degraded_result(warning: String) -> AnalysisResult {
    AnalysisResult {
        guest_info: GuestInfo {
            os_name: "Windows (dirty / inaccessible Registry)".to_string(),
            ..GuestInfo::default()
        },
        programs: Vec::new(),
        warnings: vec![warning],
    }
}

// -----------------------------------------------------------------------------
// 1. HIVE EXTRACTION FROM NTFS
// -----------------------------------------------------------------------------

fn extract_ntfs_hives(
    driver: &dyn VmDriver,
    partition_start: u64,
    partition_size: u64,
    chunk_size: u64,
    include_system: bool,
) -> Result<Hives> {
    let mut disk = VirtualDisk::new(driver, partition_start, partition_size, chunk_size);

    let mut ntfs =
        Ntfs::new(&mut disk).map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    ntfs.read_upcase_table(&mut disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let root = ntfs
        .root_directory(&mut disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let config = navigate_directory(&ntfs, &mut disk, root, &CONFIG_PATH)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?
        .ok_or_else(|| {
            VmSpectError::WindowsRegistry(
                "Windows\\System32\\config does not exist on the NTFS partition".to_string(),
            )
        })?;

    let software = read_file_bytes(&ntfs, &mut disk, &config, "SOFTWARE")?
        .ok_or_else(|| VmSpectError::WindowsRegistry("SOFTWARE hive not found".to_string()))?;

    // Transactional log files (.LOG1/.LOG2) support: their presence is used as a
    // signal to decide the recovery strategy and to enrich the warning messages,
    // since they indicate the hive may have been left "dirty" after an abrupt
    // shutdown that did not flush pending changes.
    let software_logs_present = file_exists(&ntfs, &mut disk, &config, "SOFTWARE.LOG1")
        || file_exists(&ntfs, &mut disk, &config, "SOFTWARE.LOG2");

    let mut warnings = Vec::new();
    let mut system_logs_present = false;
    let system = if include_system {
        system_logs_present = file_exists(&ntfs, &mut disk, &config, "SYSTEM.LOG1")
            || file_exists(&ntfs, &mut disk, &config, "SYSTEM.LOG2");
        match read_file_bytes(&ntfs, &mut disk, &config, "SYSTEM") {
            Ok(bytes) => bytes,
            Err(e) => {
                let msg = format!(
                    "Could not read the SYSTEM hive from disk (dirty / inaccessible Registry): {}",
                    e
                );
                tracing::warn!("{}", msg);
                warnings.push(msg);
                None
            }
        }
    } else {
        None
    };

    Ok(Hives {
        software,
        system,
        software_logs_present,
        system_logs_present,
        warnings,
    })
}

fn is_system_partition(
    driver: &dyn VmDriver,
    partition_start: u64,
    partition_size: u64,
    chunk_size: u64,
) -> bool {
    let mut disk = VirtualDisk::new(driver, partition_start, partition_size, chunk_size);
    let Ok(mut ntfs) = Ntfs::new(&mut disk) else {
        return false;
    };
    if ntfs.read_upcase_table(&mut disk).is_err() {
        return false;
    }
    let Ok(root) = ntfs.root_directory(&mut disk) else {
        return false;
    };
    matches!(
        navigate_directory(&ntfs, &mut disk, root, &CONFIG_PATH),
        Ok(Some(_))
    )
}

fn navigate_directory<'n>(
    ntfs: &'n Ntfs,
    disk: &mut VirtualDisk<'_>,
    from: NtfsFile<'n>,
    segments: &[&str],
) -> std::result::Result<Option<NtfsFile<'n>>, ntfs::NtfsError> {
    let mut current = from;
    for segment in segments {
        let index = current.directory_index(disk)?;
        let mut finder = index.finder();
        let Some(entry) = NtfsFileNameIndex::find(&mut finder, ntfs, disk, segment) else {
            return Ok(None);
        };
        let next = entry?.to_file(ntfs, disk)?;
        if !next.is_directory() {
            return Ok(None);
        }
        current = next;
    }
    Ok(Some(current))
}

fn read_file_bytes(
    ntfs: &Ntfs,
    disk: &mut VirtualDisk<'_>,
    directory: &NtfsFile<'_>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let index = directory
        .directory_index(disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let mut finder = index.finder();
    let Some(entry) = NtfsFileNameIndex::find(&mut finder, ntfs, disk, name) else {
        return Ok(None);
    };
    let file = entry
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?
        .to_file(ntfs, disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let item = file
        .data(disk, "")
        .ok_or_else(|| {
            VmSpectError::FileSystem(format!("The file {} has no default data stream", name))
        })?
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let attribute = item
        .to_attribute()
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let value = attribute
        .value(disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let length = value.len();
    if length > 2 * 1024 * 1024 * 1024 {
        return Err(VmSpectError::FileSystem(format!(
            "Hive {} is suspiciously large ({} bytes)",
            name, length
        )));
    }

    let mut reader = value.attach(disk);
    let mut data = Vec::with_capacity(length as usize);
    reader.read_to_end(&mut data).map_err(VmSpectError::Io)?;
    Ok(Some(data))
}

/// Cheaply checks whether a file exists inside an NTFS directory, without reading its
/// contents. Used to detect the presence of `.LOG1`/`.LOG2` transaction files alongside a
/// Registry hive.
fn file_exists(
    ntfs: &Ntfs,
    disk: &mut VirtualDisk<'_>,
    directory: &NtfsFile<'_>,
    name: &str,
) -> bool {
    let Ok(index) = directory.directory_index(disk) else {
        return false;
    };
    let mut finder = index.finder();
    matches!(
        NtfsFileNameIndex::find(&mut finder, ntfs, disk, name),
        Some(Ok(_))
    )
}

/// Reads, at most, the first `max_bytes` bytes of the default data stream of an NTFS file.
/// Used by the file-system fallback to inspect the PE header of large binaries
/// (e.g. `ntoskrnl.exe`) without having to slurp the whole executable into memory.
fn read_file_prefix(
    ntfs: &Ntfs,
    disk: &mut VirtualDisk<'_>,
    directory: &NtfsFile<'_>,
    name: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    let index = directory
        .directory_index(disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let mut finder = index.finder();
    let Some(entry) = NtfsFileNameIndex::find(&mut finder, ntfs, disk, name) else {
        return Ok(None);
    };
    let file = entry
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?
        .to_file(ntfs, disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let item = file
        .data(disk, "")
        .ok_or_else(|| {
            VmSpectError::FileSystem(format!("The file {} has no default data stream", name))
        })?
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let attribute = item
        .to_attribute()
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;
    let value = attribute
        .value(disk)
        .map_err(|e| VmSpectError::FileSystem(format!("{:?}", e)))?;

    let mut reader = value.attach(disk).take(max_bytes);
    let mut data = Vec::new();
    reader.read_to_end(&mut data).map_err(VmSpectError::Io)?;
    Ok(Some(data))
}

// -----------------------------------------------------------------------------
// 2. REGISTRY PARSING AND DATA EXTRACTION
// -----------------------------------------------------------------------------

/// Analyzes the hives already extracted from disk. Returns the result together with
/// a `requires_fs_fallback` boolean that indicates whether the SOFTWARE hive was
/// completely inaccessible (neither with full validation nor in permissive mode),
/// signalling the caller to fall back to inspecting the NTFS file system directly so
/// it does not return zero programs and a generic OS name.
fn analyze_hives(hives: &Hives, options: &Options) -> Result<(AnalysisResult, bool)> {
    let mut warnings = hives.warnings.clone();
    let mut requires_fs_fallback = false;

    // Graceful Degradation: a corrupt or "dirty" SOFTWARE hive (abrupt VM
    // shutdown, `SequenceNumberMismatch` between the transaction logs, damaged
    // blocks, etc.) can make the parser return `Err` or, in extreme corruption,
    // trigger an internal panic in the `nt-hive` crate. Both scenarios are caught
    // (`match` + `catch_unwind`) so they NEVER abort the full inspection pipeline.
    // Before giving up, a permissive recovery is attempted (see
    // `open_hive_with_recovery`).
    let software_bytes = &hives.software[..];
    let software_logs = hives.software_logs_present;
    let (mut guest_info, programs) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            try_analyze_software(software_bytes, options, software_logs)
        })) {
            Ok(Ok((info, progs, recovery_notice))) => {
                if let Some(msg) = recovery_notice {
                    tracing::warn!("{}", msg);
                    warnings.push(msg);
                }
                (info, progs)
            }
            Ok(Err(e)) => {
                let msg = format!(
                    "SOFTWARE hive corrupt or inaccessible (dirty Registry): {}",
                    e
                );
                tracing::warn!("{}", msg);
                warnings.push(msg);
                requires_fs_fallback = true;
                (GuestInfo::default(), Vec::new())
            }
            Err(_panic) => {
                let msg =
                    "SOFTWARE hive severely damaged: the Registry parser failed irrecoverably \
                       (dirty Registry)"
                        .to_string();
                tracing::warn!("{}", msg);
                warnings.push(msg);
                requires_fs_fallback = true;
                (GuestInfo::default(), Vec::new())
            }
        };

    if requires_fs_fallback {
        guest_info.os_name = "Windows (dirty / inaccessible Registry)".to_string();
    }

    if options.should_analyze_system() && guest_info.guest_tools.is_none() {
        if let Some(system) = &hives.system {
            let system_bytes = &system[..];
            let system_logs = hives.system_logs_present;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                try_detect_guest_tools_in_system(system_bytes, system_logs)
            })) {
                Ok(Ok((tools, recovery_notice))) => {
                    guest_info.guest_tools = tools;
                    if let Some(msg) = recovery_notice {
                        tracing::warn!("{}", msg);
                        warnings.push(msg);
                    }
                }
                Ok(Err(e)) => {
                    let msg = format!(
                        "SYSTEM hive corrupt or inaccessible (dirty Registry): {}",
                        e
                    );
                    tracing::warn!("{}", msg);
                    warnings.push(msg);
                }
                Err(_panic) => {
                    let msg = "SYSTEM hive severely damaged: the Registry parser failed \
                               irrecoverably (dirty Registry)"
                        .to_string();
                    tracing::warn!("{}", msg);
                    warnings.push(msg);
                }
            }
        }
    }

    Ok((
        AnalysisResult {
            guest_info,
            programs,
            warnings,
        },
        requires_fs_fallback,
    ))
}

/// Attempts to open a Registry hive using a cascade recovery strategy:
/// 1. Standard open with full header validation (`Hive::new`).
/// 2. If that fails (e.g. `SequenceNumberMismatch` due to a "dirty" hive after an
///    abrupt shutdown that did not flush its `.LOG1`/`.LOG2` transaction files),
///    retry in **permissive mode** (`Hive::without_validation`), which skips header
///    validation and lets you walk the keys that remain intact in the primary file.
///    `nt-hive` does not support replaying `.LOG1`/`.LOG2` content, so their
///    presence is only used here to enrich the returned warning message.
fn open_hive_with_recovery(
    bytes: &[u8],
    transactional_logs_present: bool,
) -> std::result::Result<(Hive<&[u8]>, Option<String>), NtHiveError> {
    match Hive::new(bytes) {
        Ok(hive) => Ok((hive, None)),
        Err(original_error) => {
            // It can still fail (e.g. completely corrupt / unreadable data): in
            // that case `?` propagates the error and the caller activates the
            // file-system fallback.
            let hive = Hive::without_validation(bytes)?;

            let logs_context = if transactional_logs_present {
                "transactional .LOG1/.LOG2 files were detected alongside the hive, but the Registry parser (nt-hive) cannot replay their contents"
            } else {
                "no transactional .LOG1/.LOG2 files were found alongside the hive to attempt replaying pending changes"
            };

            let message = format!(
                "Hive with damaged/dirty header ({:?}): {}; permissive read mode (no header validation) was activated to recover the keys still intact in the primary file",
                original_error, logs_context
            );

            Ok((hive, Some(message)))
        }
    }
}

/// Attempts to parse the SOFTWARE hive and extract OS information and the list of
/// installed programs. Returns `Err` if the hive is corrupt or cannot be parsed
/// (dirty hive); it never introduces panics of its own beyond those that may be
/// produced by the `nt-hive` crate (caught by the caller via `catch_unwind`).
fn try_analyze_software(
    bytes: &[u8],
    options: &Options,
    transactional_logs_present: bool,
) -> Result<(GuestInfo, Vec<Program>, Option<String>)> {
    let (software_hive, recovery_notice) =
        open_hive_with_recovery(bytes, transactional_logs_present)
            .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
    let software_root = software_hive
        .root_key_node()
        .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;

    let guest_info = if options.should_analyze_system() {
        extract_guest_info(&software_root)
    } else {
        GuestInfo::default()
    };

    let programs = if options.should_analyze_apps() {
        search_programs_in_registry(&software_root, options)
    } else {
        Vec::new()
    };

    Ok((guest_info, programs, recovery_notice))
}

/// Attempts to parse the SYSTEM hive and detect hypervisor integration tool
/// services or drivers (VMware Tools, VirtualBox Guest Additions, QEMU Guest Agent /
/// VirtIO, Hyper-V Integration Services).
fn try_detect_guest_tools_in_system(
    system_bytes: &[u8],
    transactional_logs_present: bool,
) -> Result<(Option<GuestTools>, Option<String>)> {
    let (system_hive, recovery_notice) =
        open_hive_with_recovery(system_bytes, transactional_logs_present)
            .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;
    let system_root = system_hive
        .root_key_node()
        .map_err(|e| VmSpectError::WindowsRegistry(format!("{:?}", e)))?;

    let control_set_prefixes = ["ControlSet001", "ControlSet002", "CurrentControlSet"];

    let services_by_kind = [
        // VMware
        (
            "VMware Tools",
            &[
                "VMTools",
                "vmvss",
                "vmusbmouse",
                "vmx_svga",
                "pvscsi",
                "vmxnet3",
            ][..],
        ),
        // VirtualBox
        (
            "VirtualBox Guest Additions",
            &[
                "VBoxGuest",
                "VBoxService",
                "VBoxMouse",
                "VBoxSF",
                "VBoxVideo",
                "VBoxWddm",
            ][..],
        ),
        // QEMU / KVM / VirtIO
        (
            "QEMU Guest Agent",
            &[
                "QEMU-GA",
                "qemu-ga",
                "viostor",
                "netkvm",
                "vioscsi",
                "vioserial",
                "viorng",
                "balloon",
            ][..],
        ),
        // Hyper-V
        (
            "Hyper-V Integration Services",
            &[
                "vmbus",
                "hypervkvp",
                "hv_kvp",
                "vmicheartbeat",
                "vmicshutdown",
                "vmictimesync",
                "vmicvss",
                "vmicrdv",
            ][..],
        ),
    ];

    for prefix in &control_set_prefixes {
        for (kind, services) in &services_by_kind {
            for srv in *services {
                let path = format!("{}\\Services\\{}", prefix, srv);
                if let Ok(Some(service_node)) = find_key_by_path(&system_root, &path) {
                    let version = read_value_from_key(&service_node, "Version")
                        .or_else(|| read_value_from_key(&service_node, "DriverVersion"));
                    return Ok((
                        Some(GuestTools {
                            kind: kind.to_string(),
                            version,
                            present: true,
                        }),
                        recovery_notice,
                    ));
                }
            }
        }
    }

    Ok((None, recovery_notice))
}

fn extract_guest_tools_software(root_node: &HiveKeyNode) -> Option<GuestTools> {
    // 1. Direct per-hypervisor configuration keys.
    // VMware Tools
    let vmware_paths = [
        "VMware, Inc.\\VMware Tools",
        "WOW6432Node\\VMware, Inc.\\VMware Tools",
    ];
    for path in &vmware_paths {
        if let Ok(Some(node)) = find_key_by_path(root_node, path) {
            let ver = read_value_from_key(&node, "InstallVersion")
                .or_else(|| read_value_from_key(&node, "Version"));
            return Some(GuestTools {
                kind: "VMware Tools".to_string(),
                version: ver,
                present: true,
            });
        }
    }

    // VirtualBox Guest Additions
    let vbox_paths = [
        "Oracle\\VirtualBox Guest Additions",
        "WOW6432Node\\Oracle\\VirtualBox Guest Additions",
    ];
    for path in &vbox_paths {
        if let Ok(Some(node)) = find_key_by_path(root_node, path) {
            let ver = read_value_from_key(&node, "Version");
            return Some(GuestTools {
                kind: "VirtualBox Guest Additions".to_string(),
                version: ver,
                present: true,
            });
        }
    }

    // QEMU Guest Agent & VirtIO
    let qemu_paths = [
        "QEMU Guest Agent",
        "WOW6432Node\\QEMU Guest Agent",
        "Red Hat\\VirtIO",
        "WOW6432Node\\Red Hat\\VirtIO",
        "Red Hat\\Virtio",
        "WOW6432Node\\Red Hat\\Virtio",
    ];
    for path in &qemu_paths {
        if let Ok(Some(node)) = find_key_by_path(root_node, path) {
            let ver = read_value_from_key(&node, "Version")
                .or_else(|| read_value_from_key(&node, "DisplayVersion"))
                .or_else(|| read_value_from_key(&node, "InstallVersion"));
            return Some(GuestTools {
                kind: "QEMU Guest Agent".to_string(),
                version: ver,
                present: true,
            });
        }
    }

    // Hyper-V Integration Services
    let hyperv_paths = [
        "Microsoft\\Virtual Machine\\Auto",
        "WOW6432Node\\Microsoft\\Virtual Machine\\Auto",
        "Microsoft\\Virtual Machine\\Guest\\Parameters",
    ];
    for path in &hyperv_paths {
        if let Ok(Some(node)) = find_key_by_path(root_node, path) {
            let ver = read_value_from_key(&node, "IntegrationServicesVersion")
                .or_else(|| read_value_from_key(&node, "Version"));
            return Some(GuestTools {
                kind: "Hyper-V Integration Services".to_string(),
                version: ver,
                present: true,
            });
        }
    }

    // 2. Search under MSI Installer / Products keys.
    let installer_paths =
        ["Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products"];

    for path in &installer_paths {
        if let Ok(Some(products_node)) = find_key_by_path(root_node, path) {
            if let Some(Ok(subkeys)) = products_node.subkeys() {
                for subkey in subkeys.flatten() {
                    if let Ok(Some(install_properties)) =
                        find_key_by_path(&subkey, "InstallProperties")
                    {
                        if let Some((kind, ver)) = classify_guest_tools_key(&install_properties) {
                            return Some(GuestTools {
                                kind,
                                version: ver,
                                present: true,
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. Search under Uninstall keys.
    let uninstall_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];

    for rel_path in &uninstall_paths {
        if let Ok(Some(uninstall_node)) = find_key_by_path(root_node, rel_path) {
            if let Some(Ok(subkeys)) = uninstall_node.subkeys() {
                for subkey in subkeys.flatten() {
                    if let Some((kind, ver)) = classify_guest_tools_key(&subkey) {
                        return Some(GuestTools {
                            kind,
                            version: ver,
                            present: true,
                        });
                    }
                }
            }
        }
    }

    None
}

fn classify_guest_tools_key(key: &HiveKeyNode) -> Option<(String, Option<String>)> {
    if let Some(name) = read_value_from_key(key, "DisplayName") {
        let name_lower = name.to_lowercase();
        let ver = read_value_from_key(key, "DisplayVersion");

        if name_lower.contains("vmware tools") {
            return Some(("VMware Tools".to_string(), ver));
        }
        if name_lower.contains("virtualbox guest additions")
            || name_lower.contains("oracle vm virtualbox guest additions")
        {
            return Some(("VirtualBox Guest Additions".to_string(), ver));
        }
        if name_lower.contains("qemu guest agent")
            || name_lower.contains("virtio")
            || name_lower.contains("red hat virtio")
        {
            return Some(("QEMU Guest Agent".to_string(), ver));
        }
        if name_lower.contains("hyper-v integration services")
            || name_lower.contains("hyper-v guest components")
        {
            return Some(("Hyper-V Integration Services".to_string(), ver));
        }
    }
    None
}

fn read_value_from_key(key: &HiveKeyNode, field_name: &str) -> Option<String> {
    if let Some(Ok(values)) = key.values() {
        for val in values.flatten() {
            if let Ok(val_name) = val.name() {
                if val_name.to_string_lossy().eq_ignore_ascii_case(field_name) {
                    return convert_value_to_string(&val);
                }
            }
        }
    }
    None
}

fn extract_guest_info(root_node: &HiveKeyNode) -> GuestInfo {
    let mut info = GuestInfo::default();
    let os_path = "Microsoft\\Windows NT\\CurrentVersion";

    if let Ok(Some(os_node)) = find_key_by_path(root_node, os_path) {
        if let Some(Ok(values)) = os_node.values() {
            for val in values.flatten() {
                if let Ok(val_name) = val.name() {
                    let val_name_str = val_name.to_string_lossy();

                    if val_name_str.eq_ignore_ascii_case("ProductName") {
                        if let Some(v) = convert_value_to_string(&val) {
                            info.os_name = v;
                        }
                    } else if (val_name_str.eq_ignore_ascii_case("DisplayVersion")
                        || val_name_str.eq_ignore_ascii_case("ReleaseId"))
                        && info.os_edition.is_empty()
                    {
                        if let Some(v) = convert_value_to_string(&val) {
                            info.os_edition = v;
                        }
                    } else if val_name_str.eq_ignore_ascii_case("CSDVersion") {
                        if let Some(v) = convert_value_to_string(&val) {
                            info.os_service_pack = v;
                        }
                    } else if (val_name_str.eq_ignore_ascii_case("CurrentBuild")
                        || val_name_str.eq_ignore_ascii_case("CurrentBuildNumber"))
                        && info.os_build.is_empty()
                    {
                        if let Some(v) = convert_value_to_string(&val) {
                            info.os_build = v;
                        }
                    }
                }
            }
        }
    }

    if info.os_name.is_empty() {
        info.os_name = "Windows (Unknown edition)".to_string();
    }

    info.guest_tools = extract_guest_tools_software(root_node);

    info
}

// -----------------------------------------------------------------------------
// 3. NAVIGATION AND EXTRACTION MODULES
// -----------------------------------------------------------------------------

type HiveKeyNode<'a> = KeyNode<'a, &'a [u8]>;

fn search_programs_in_registry(root_node: &HiveKeyNode, options: &Options) -> Vec<Program> {
    let mut programs: Vec<Program> = Vec::new();
    let uninstall_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];

    for rel_path in &uninstall_paths {
        if let Ok(Some(uninstall_node)) = find_key_by_path(root_node, rel_path) {
            extract_programs_from_subkeys(&uninstall_node, &mut programs, options);
        }
    }

    // Sort and deduplicate based on program name and version.
    programs.sort_by(|a, b| a.name.cmp(&b.name));
    programs.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    programs
}

fn find_key_by_path<'a>(root: &HiveKeyNode<'a>, path: &str) -> Result<Option<HiveKeyNode<'a>>> {
    let mut current = root.clone();
    for segment in path.split('\\') {
        let mut found = false;
        if let Some(Ok(subkeys)) = current.subkeys() {
            for sub in subkeys.flatten() {
                if let Ok(name) = sub.name() {
                    if name.to_string_lossy().eq_ignore_ascii_case(segment) {
                        current = sub;
                        found = true;
                        break;
                    }
                }
            }
        }
        if !found {
            return Ok(None);
        }
    }
    Ok(Some(current))
}

fn extract_programs_from_subkeys(
    uninstall_node: &HiveKeyNode,
    output: &mut Vec<Program>,
    options: &Options,
) {
    if let Some(Ok(subkeys)) = uninstall_node.subkeys() {
        for subkey in subkeys.flatten() {
            if let Some(cancel) = &options.cancel_token {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }

            if let Some(prog_name) = read_value_from_key(&subkey, "DisplayName") {
                let publisher_str = read_value_from_key(&subkey, "Publisher").unwrap_or_default();
                let version_opt = read_value_from_key(&subkey, "DisplayVersion");

                let publisher_opt = if !publisher_str.is_empty() {
                    Some(publisher_str)
                } else {
                    None
                };

                output.push(Program {
                    name: prog_name,
                    version: version_opt,
                    publisher: publisher_opt,
                    source: None,
                });
            }
        }
    }
}

// -----------------------------------------------------------------------------
// 4. BINARY / UTF-16 DATA PARSING
// -----------------------------------------------------------------------------

fn convert_value_to_string(val: &KeyValue<&[u8]>) -> Option<String> {
    if let Ok(data_enum) = val.data() {
        if let Ok(bytes) = data_enum.into_vec() {
            if bytes.is_empty() {
                return None;
            }

            let utf16_units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[b0, b1]| u16::from_le_bytes([b0, b1]))
                .collect();

            let text = String::from_utf16_lossy(&utf16_units);
            let clean_text = text.trim_matches('\0').trim().to_string();

            if !clean_text.is_empty() {
                return Some(clean_text);
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// 5. NTFS FILE-SYSTEM FALLBACK (Registry completely inaccessible)
// -----------------------------------------------------------------------------

/// Last resort when the SOFTWARE hive is completely inaccessible (not even the permissive
/// mode could recover its key tree): inspect the NTFS file system directly so we do not
/// return zero installed programs and a generic OS name.
///
/// Strategy: 1) derive an approximate version/build of the OS by reading the PE header
/// of `\Windows\System32\ntoskrnl.exe` (or, failing that, just confirm Windows is present
/// via `\Windows\System32\license.rtf`); 2) enumerate the top-level folders under
/// `\Program Files` and `\Program Files (x86)` and turn them into software entries tagged
/// with `source: FallbackFS`.
fn apply_fs_fallback(
    driver: &dyn VmDriver,
    partition: &Partition,
    chunk_size: u64,
    options: &Options,
) -> (Option<GuestInfo>, Vec<Program>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut disk = VirtualDisk::new(driver, partition.start, partition.size, chunk_size);

    let mut ntfs = match Ntfs::new(&mut disk) {
        Ok(n) => n,
        Err(e) => {
            warnings.push(format!(
                "FallbackFS: could not re-mount the NTFS partition ({:?})",
                e
            ));
            return (None, Vec::new(), warnings);
        }
    };
    if let Err(e) = ntfs.read_upcase_table(&mut disk) {
        warnings.push(format!(
            "FallbackFS: could not read the NTFS UpCase table ({:?})",
            e
        ));
        return (None, Vec::new(), warnings);
    }
    let root = match ntfs.root_directory(&mut disk) {
        Ok(r) => r,
        Err(e) => {
            warnings.push(format!(
                "FallbackFS: could not access the NTFS root directory ({:?})",
                e
            ));
            return (None, Vec::new(), warnings);
        }
    };

    let mut guest_info = None;
    if options.should_analyze_system() {
        match navigate_directory(&ntfs, &mut disk, root.clone(), &["Windows", "System32"]) {
            Ok(Some(system32)) => match detect_os_from_binaries(&ntfs, &mut disk, &system32) {
                Some((info, msg)) => {
                    warnings.push(msg);
                    guest_info = Some(info);
                }
                None => warnings.push(
                    "FallbackFS: could not determine the OS version (neither ntoskrnl.exe nor license.rtf were readable in \\Windows\\System32)".to_string(),
                ),
            },
            _ => warnings.push(
                "FallbackFS: \\Windows\\System32 was not found on the NTFS partition".to_string(),
            ),
        }
    }

    let mut programs = Vec::new();
    if options.should_analyze_apps() {
        for folder in PROGRAM_FILES_DIRS {
            if let Some(cancel) = &options.cancel_token {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
            }
            if let Ok(Some(dir)) = navigate_directory(&ntfs, &mut disk, root.clone(), &[folder]) {
                scan_folders_as_programs(&mut disk, &dir, options, &mut programs);
            }
        }

        if !programs.is_empty() {
            warnings.push(format!(
                "FallbackFS: recovered {} software entries by scanning the \\Program Files folders (no version/publisher; origin {}) because the Registry is inaccessible",
                programs.len(),
                FALLBACK_FS_ORIGIN
            ));
        }
    }

    (guest_info, programs, warnings)
}

/// Derives an approximate version/build of the OS from system binaries, without
/// depending on the Registry. Returns the information along with the warning
/// describing how it was obtained.
fn detect_os_from_binaries(
    ntfs: &Ntfs,
    disk: &mut VirtualDisk<'_>,
    system32: &NtfsFile<'_>,
) -> Option<(GuestInfo, String)> {
    if let Ok(Some(bytes)) = read_file_prefix(ntfs, disk, system32, "ntoskrnl.exe", 8192) {
        if let Some(timestamp) = extract_pe_timestamp(&bytes) {
            let date = date_from_epoch(timestamp);
            let info = GuestInfo {
                os_name: format!("Windows (approximate version from {})", FALLBACK_FS_ORIGIN),
                os_build: format!(
                    "Approximated from the PE compilation timestamp of ntoskrnl.exe: {}",
                    date
                ),
                ..GuestInfo::default()
            };
            let msg = format!(
                "Registry completely inaccessible: an approximate OS version was determined from the PE timestamp of \\Windows\\System32\\ntoskrnl.exe ({})",
                FALLBACK_FS_ORIGIN
            );
            return Some((info, msg));
        }
    }

    if file_exists(ntfs, disk, system32, "license.rtf") {
        let info = GuestInfo {
            os_name: format!("Windows (detected by {}: license.rtf)", FALLBACK_FS_ORIGIN),
            ..GuestInfo::default()
        };
        let msg = format!(
            "Registry completely inaccessible: ntoskrnl.exe could not be read, but Windows was confirmed via the presence of \\Windows\\System32\\license.rtf ({})",
            FALLBACK_FS_ORIGIN
        );
        return Some((info, msg));
    }

    None
}

/// Enumerates the first-level subfolders of an NTFS directory (e.g. `\Program Files`)
/// and adds them to `output` as software entries with origin `FallbackFS`, since only
/// the folder name is known (no version or publisher without the Registry).
fn scan_folders_as_programs(
    disk: &mut VirtualDisk<'_>,
    directory: &NtfsFile<'_>,
    options: &Options,
    output: &mut Vec<Program>,
) {
    let Ok(index) = directory.directory_index(disk) else {
        return;
    };
    let mut seen = std::collections::HashSet::new();
    let mut entries = index.entries();
    loop {
        if let Some(cancel) = &options.cancel_token {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
        }
        let Some(entry) = entries.next(disk) else {
            break;
        };
        let Ok(entry) = entry else {
            continue;
        };
        let Some(Ok(name_key)) = entry.key() else {
            continue;
        };
        if !name_key.is_directory() {
            continue;
        }
        if name_key.namespace() == NtfsFileNamespace::Dos {
            // Skip short 8.3 names, which would duplicate the Win32 folder
            // already reported under its long name.
            continue;
        }
        let name = name_key.name().to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }
        if !seen.insert(name.clone()) {
            continue;
        }
        output.push(Program {
            name,
            version: None,
            publisher: None,
            source: Some(FALLBACK_FS_ORIGIN.to_string()),
        });
    }
}

/// Extracts the `TimeDateStamp` (Unix compilation seconds) from the PE header of an
/// executable/DLL using only its leading bytes, without needing the whole file.
fn extract_pe_timestamp(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes.get(0x3C..0x40)?.try_into().ok()?) as usize;
    let signature_end = e_lfanew.checked_add(4)?;
    let timestamp_end = signature_end.checked_add(8)?;
    if bytes.len() < timestamp_end || &bytes[e_lfanew..signature_end] != b"PE\0\0" {
        return None;
    }
    let timestamp_start = signature_end.checked_add(4)?;
    let timestamp = u32::from_le_bytes(bytes[timestamp_start..timestamp_end].try_into().ok()?);
    Some(timestamp)
}

/// Formats a Unix timestamp (seconds) as a `YYYY-MM-DD` date without depending on
/// external date/time crates.
fn date_from_epoch(epoch_seconds: u32) -> String {
    let total_days = (epoch_seconds as i64) / 86400;
    let (year, month, day) = civil_from_days(total_days);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

/// Howard Hinnant's algorithm for converting a number of days since the Unix epoch
/// (1970-01-01) to a Gregorian calendar date (year, month, day).
/// Reference: http://howardhinnant.github.io/date_algorithms.html
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::FileSystem;

    #[test]
    fn test_classification_guest_tools_strings() {
        let tests = [
            ("VMware Tools", "VMware Tools"),
            (
                "Oracle VM VirtualBox Guest Additions 7.0.12",
                "VirtualBox Guest Additions",
            ),
            ("QEMU Guest Agent", "QEMU Guest Agent"),
            ("Red Hat VirtIO Ethernet Adapter", "QEMU Guest Agent"),
            (
                "Hyper-V Integration Services",
                "Hyper-V Integration Services",
            ),
        ];

        for (name, expected_kind) in tests {
            let name_lower = name.to_lowercase();
            let mut detected = None;
            if name_lower.contains("vmware tools") {
                detected = Some("VMware Tools");
            } else if name_lower.contains("virtualbox guest additions")
                || name_lower.contains("oracle vm virtualbox guest additions")
            {
                detected = Some("VirtualBox Guest Additions");
            } else if name_lower.contains("qemu guest agent")
                || name_lower.contains("virtio")
                || name_lower.contains("red hat virtio")
            {
                detected = Some("QEMU Guest Agent");
            } else if name_lower.contains("hyper-v integration services")
                || name_lower.contains("hyper-v guest components")
            {
                detected = Some("Hyper-V Integration Services");
            }
            assert_eq!(detected, Some(expected_kind));
        }
    }

    /// Verifies the epoch-days-to-civil-date algorithm (used by the FS fallback
    /// to approximate the OS version from the PE timestamp of `ntoskrnl.exe`)
    /// against known dates.
    #[test]
    fn test_date_from_epoch_known_dates() {
        assert_eq!(date_from_epoch(0), "1970-01-01");
        // 2021-04-02T00:00:00Z
        assert_eq!(date_from_epoch(1_617_321_600), "2021-04-02");
        // 2000-01-01T00:00:00Z
        assert_eq!(date_from_epoch(946_684_800), "2000-01-01");
    }

    /// Builds a minimal PE header (DOS + COFF) to verify that
    /// `extract_pe_timestamp` correctly locates the `TimeDateStamp`.
    #[test]
    fn test_extract_pe_timestamp() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        let e_lfanew: u32 = 0x40;
        data[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        data[0x40..0x44].copy_from_slice(b"PE\0\0");
        // Machine (2) + NumberOfSections (2) precede the TimeDateStamp.
        data[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        data[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
        let expected_timestamp: u32 = 1_600_000_000;
        data[0x48..0x4C].copy_from_slice(&expected_timestamp.to_le_bytes());

        assert_eq!(extract_pe_timestamp(&data), Some(expected_timestamp));
    }

    #[test]
    fn test_extract_pe_timestamp_invalid_data() {
        assert_eq!(extract_pe_timestamp(&[0u8; 4]), None);
        assert_eq!(extract_pe_timestamp(&[0u8; 4096]), None);
    }

    /// When the hive header is invalid (not a real `SequenceNumberMismatch`,
    /// but equally unrecoverable by strict validation), the permissive mode can
    /// also fail; in that case `open_hive_with_recovery` must propagate the
    /// error instead of panicking.
    #[test]
    fn test_open_hive_with_recovery_invalid_data_propagates_error() {
        // Too short to be interpreted as a hive header, even in permissive mode.
        let bytes = vec![0u8; 4];
        let result = open_hive_with_recovery(&bytes, true);
        assert!(result.is_err());
    }

    /// Simulates a Registry read/parse error (dirty or corrupt hive, e.g.
    /// `SequenceNumberMismatch`) and verifies that analysis degrades gracefully:
    /// returns `Ok`, adds the warning and uses a fallback OS name instead of
    /// aborting the pipeline with `Err`.
    #[test]
    fn test_analyze_hives_dirty_registry_returns_ok() {
        let hives = Hives {
            software: vec![0u8; 4096],
            system: Some(vec![0u8; 4096]),
            software_logs_present: false,
            system_logs_present: false,
            warnings: Vec::new(),
        };
        let options = Options::default();

        let result = analyze_hives(&hives, &options);

        assert!(result.is_ok());
        let (result, requires_fs_fallback) = result.unwrap();
        assert!(!result.warnings.is_empty());
        assert_eq!(
            result.guest_info.os_name,
            "Windows (dirty / inaccessible Registry)"
        );
        assert!(result.programs.is_empty());
        assert!(
            requires_fs_fallback,
            "a totally unreadable hive must request the FS fallback"
        );
    }

    /// Verifies the same scenario at the full `OsInspector` trait level: if the
    /// disk/partition does not allow accessing the Registry (NTFS unreadable or
    /// absent), `WindowsInspector::analyze` must return `Ok` with fallback data
    /// instead of aborting the entire inspection.
    #[test]
    fn test_windows_inspector_analyze_inaccessible_registry_returns_ok() {
        struct MockDriverDirty;
        impl VmDriver for MockDriverDirty {
            fn virtual_size(&self) -> u64 {
                16 * 1024 * 1024
            }
            fn read_range(&self, _offset: u64, buf: &mut [u8]) -> Result<()> {
                buf.fill(0);
                Ok(())
            }
            fn access_mode(&self) -> &str {
                "mock"
            }
            fn is_native(&self) -> bool {
                true
            }
        }

        let inspector = WindowsInspector;
        let partitions = vec![Partition {
            index: 0,
            start: 0,
            size: 16 * 1024 * 1024,
            kind: "0x07".to_string(),
            file_system: FileSystem::Ntfs,
            label: None,
        }];
        let options = Options::default();

        let result = inspector.analyze(&MockDriverDirty, &partitions, 4096, &options);

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(!result.warnings.is_empty());
        assert_eq!(
            result.guest_info.os_name,
            "Windows (dirty / inaccessible Registry)"
        );
    }
}
