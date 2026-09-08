use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use vmspect::prelude::*;
use vmspect::vms::stream::DiskReader;

#[test]
fn test_options_defaults_and_helpers() {
    // a) By default (no flags): both system and apps should be analyzed
    let opts = Options::default();
    assert!(!opts.no_apps, "By default no_apps must be false");
    assert!(!opts.no_system, "By default no_system must be false");
    assert!(
        opts.should_analyze_apps(),
        "By default should_analyze_apps() must return true"
    );
    assert!(
        opts.should_analyze_system(),
        "By default should_analyze_system() must return true"
    );

    // b) With --no-apps: extract system, skip apps
    let opts_no_apps = Options {
        no_apps: true,
        ..Options::default()
    };
    assert!(
        !opts_no_apps.should_analyze_apps(),
        "With no_apps=true, should_analyze_apps() must return false"
    );
    assert!(
        opts_no_apps.should_analyze_system(),
        "With no_apps=true, should_analyze_system() must remain true"
    );

    // c) With --no-system: extract apps, skip system
    let opts_no_system = Options {
        no_system: true,
        ..Options::default()
    };
    assert!(
        opts_no_system.should_analyze_apps(),
        "With no_system=true, should_analyze_apps() must remain true"
    );
    assert!(
        !opts_no_system.should_analyze_system(),
        "With no_system=true, should_analyze_system() must return false"
    );

    // d) With both flags (--no-apps and --no-system)
    let opts_both = Options {
        no_apps: true,
        no_system: true,
        ..Options::default()
    };
    assert!(!opts_both.should_analyze_apps());
    assert!(!opts_both.should_analyze_system());
}

#[test]
fn test_inspection_options_alias_and_builder() {
    let token = Arc::new(AtomicBool::new(false));
    let opts: InspectionOptions = InspectionOptions::default().with_cancel_token(token.clone());
    assert!(opts.cancel_token.is_some());

    let ctoken = CancellationToken::new();
    let opts2 = Options::default()
        .with_cancellation_token(&ctoken)
        .with_qemu_nbd(std::path::PathBuf::from("/usr/bin/qemu-nbd"))
        .with_force_nbd(true)
        .with_unix_socket("/var/run/qemu-test.sock")
        .with_extra_nbd_args(vec!["--cache=none".into(), "--detect-zeroes=on".into()])
        .with_connection_timeout(std::time::Duration::from_secs(5))
        .with_nbd_persistent(false);

    assert!(opts2.cancel_token.is_some());
    assert_eq!(
        opts2.qemu_nbd,
        Some(std::path::PathBuf::from("/usr/bin/qemu-nbd"))
    );
    assert!(opts2.force_nbd);
    assert_eq!(
        opts2.unix_socket,
        Some(std::path::PathBuf::from("/var/run/qemu-test.sock"))
    );
    assert_eq!(
        opts2.extra_nbd_args,
        vec!["--cache=none".to_string(), "--detect-zeroes=on".to_string()]
    );
    assert_eq!(
        opts2.connection_timeout,
        Some(std::time::Duration::from_secs(5))
    );
    assert!(!opts2.nbd_persistent);
}

#[test]
fn test_qemu_not_found_when_nbd_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let qcow2_path = dir.path().join("server.qcow2");
    let mut f1 = std::fs::File::create(&qcow2_path).unwrap();
    use std::io::Write;
    f1.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();

    let options = Options {
        qemu_nbd: Some(std::path::PathBuf::from("nonexistent_qemu_nbd_path")),
        ..Options::default()
    };
    let engine = InspectionEngine::new(options);

    let res = engine.inspect(&qcow2_path);
    assert!(res.is_err(), "Should fail because qemu-nbd cannot be found");
    match res {
        Err(VmSpectError::QemuNotFound(msg)) => {
            assert!(
                msg.contains("qemu-nbd executable was not found on the system"),
                "Unexpected message: {}",
                msg
            );
            assert!(
                msg.contains("nonexistent_qemu_nbd_path"),
                "The configured qemu-nbd path must be included: {}",
                msg
            );
        }
        other => panic!("Expected VmSpectError::QemuNotFound, got: {:?}", other),
    }
}

#[test]
fn test_concurrent_processor_partial_preservation_on_cancellation() {
    use std::thread::sleep;
    use std::time::Duration;

    let items: Vec<u32> = (1..=30).collect();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    let handle = std::thread::spawn(move || {
        ConcurrentProcessor::process_in_parallel(items, Some(cancel_clone), None, 4, |item| {
            if item >= 3 {
                sleep(Duration::from_millis(40));
            }
            Ok(item * 10)
        })
    });

    sleep(Duration::from_millis(15));
    cancel.store(true, std::sync::atomic::Ordering::Release);

    let res = handle.join().expect("thread finished");
    let results = res.expect("must preserve partial results");
    assert!(
        !results.is_empty(),
        "Must contain the results finished before cancellation"
    );
    assert!(
        results.len() < 30,
        "Not all items should have been processed"
    );
    for r in &results {
        assert_eq!(r % 10, 0);
    }
}

#[test]
fn test_agnostic_extraction_without_rules_or_filters() {
    // d) Agnostic extraction: verifies that applications are not filtered by noise lists
    // nor by proprietary categorizations.
    let sample_packages = [
        Program {
            name: "libc6".to_string(),
            version: Some("2.35-0ubuntu3".to_string()),
            publisher: Some("libs".to_string()),
            source: None,
        },
        Program {
            name: "python3-minimal".to_string(),
            version: Some("3.10.6-1".to_string()),
            publisher: Some("python".to_string()),
            source: None,
        },
        Program {
            name: "libssl3".to_string(),
            version: Some("3.0.2-0ubuntu1".to_string()),
            publisher: Some("libs".to_string()),
            source: None,
        },
        Program {
            name: "linux-image-5.15.0-generic".to_string(),
            version: Some("5.15.0-88.98".to_string()),
            publisher: Some("kernel".to_string()),
            source: None,
        },
        Program {
            name: "Siemens TIA Portal V18".to_string(),
            version: Some("18.0".to_string()),
            publisher: Some("Siemens AG".to_string()),
            source: None,
        },
        Program {
            name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)".to_string(),
            version: Some("14.36.32532".to_string()),
            publisher: Some("Microsoft Corporation".to_string()),
            source: None,
        },
    ];

    // All packages must be preserved in full.
    assert_eq!(sample_packages.len(), 6);
    assert!(sample_packages.iter().any(|p| p.name.starts_with("lib")));
    assert!(sample_packages
        .iter()
        .any(|p| p.name.starts_with("python3")));
    assert!(sample_packages
        .iter()
        .any(|p| p.name.contains("Redistributable")));
    assert!(sample_packages.iter().any(|p| p.name.contains("Siemens")));
}

#[test]
fn test_engine_with_nonexistent_paths() {
    let invalid_path = std::path::Path::new("nonexistent_path_12345.vmdk");
    let options = Options::default();
    let engine = InspectionEngine::new(options);

    let res = engine.inspect(invalid_path);
    assert!(res.is_err());
    match res {
        Err(VmSpectError::ImageNotFound(p)) => {
            assert!(p.contains("nonexistent_path_12345.vmdk"));
        }
        other => panic!("Expected ImageNotFound, got: {:?}", other),
    }
}

#[test]
fn test_discovery_api_and_integrity() {
    let dir = tempfile::tempdir().unwrap();

    // Create test images
    let qcow2_path = dir.path().join("server.qcow2");
    let mut f1 = std::fs::File::create(&qcow2_path).unwrap();
    use std::io::Write;
    f1.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();

    let raw_path = dir.path().join("backup.raw");
    let mut f2 = std::fs::File::create(&raw_path).unwrap();
    let mut raw_data = vec![0u8; 1024];
    raw_data[510] = 0x55;
    raw_data[511] = 0xAA;
    f2.write_all(&raw_data).unwrap();

    let extent_flat = dir.path().join("server-flat.vmdk");
    std::fs::File::create(&extent_flat)
        .unwrap()
        .write_all(b"extent")
        .unwrap();

    // 1. is_vm_image
    assert!(is_vm_image(&qcow2_path));
    assert!(is_vm_image(&raw_path));
    assert!(!is_vm_image(&extent_flat));

    // 2. list_vms
    let list = list_vms(dir.path(), false).unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.contains(&qcow2_path));
    assert!(list.contains(&raw_path));
    assert!(!list.contains(&extent_flat));

    // 3. count_vms
    assert_eq!(count_vms(dir.path(), false).unwrap(), 2);

    // 4. has_vms
    assert!(has_vms(dir.path(), false).unwrap());

    // 5. verify_image_integrity
    assert!(verify_image_integrity(&qcow2_path).unwrap());
    assert!(verify_image_integrity(&raw_path).unwrap());

    // 6. requires_nbd / requires_qemu
    assert!(requires_nbd(&qcow2_path).unwrap());
    assert!(requires_qemu(&qcow2_path).unwrap());

    assert!(!requires_nbd(&raw_path).unwrap());
    assert!(!requires_qemu(&raw_path).unwrap());
}

#[test]
fn test_missing_vmdk_extent_has_component_context_not_qemu_error() {
    let dir = tempfile::tempdir().unwrap();
    let descriptor_dir = dir
        .path()
        .join("PLC N°4")
        .join("Máquinas Virtuales")
        .join("VM");
    std::fs::create_dir_all(&descriptor_dir).unwrap();

    let descriptor_path = descriptor_dir.join("drive-0-cl2.vmdk");
    std::fs::write(
        &descriptor_path,
        r#"# Disk DescriptorFile
version=1
CID=abcdef01
parentCID=ffffffff
createType="twoGbMaxExtentSparse"

# Extent description
RW 8 SPARSE "drive-0-cl2-s001.vmdk"
RW 8 SPARSE "drive-0-cl2-s002.vmdk"
"#,
    )
    .unwrap();
    // Deliberately create only s002: opening s001 must produce the component error.
    std::fs::write(descriptor_dir.join("drive-0-cl2-s002.vmdk"), []).unwrap();

    let result = InspectionEngine::new(Options::default()).inspect(&descriptor_path);
    match result {
        Err(VmSpectError::MissingDiskComponent {
            descriptor_path: actual_descriptor,
            declared_name,
            resolved_path,
            component_type,
            source,
        }) => {
            assert_eq!(actual_descriptor, descriptor_path.display().to_string());
            assert_eq!(declared_name, "drive-0-cl2-s001.vmdk");
            assert_eq!(
                resolved_path,
                descriptor_dir
                    .join("drive-0-cl2-s001.vmdk")
                    .display()
                    .to_string()
            );
            assert_eq!(component_type, "VMDK extent");
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        Err(VmSpectError::QemuNotFound(message)) => {
            panic!("missing VMDK extent was misclassified as QemuNotFound: {message}");
        }
        other => panic!("Expected MissingDiskComponent, got: {other:?}"),
    }

    let message = match InspectionEngine::new(Options::default()).inspect(&descriptor_path) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("the incomplete descriptor must fail"),
    };
    assert!(message.contains("drive-0-cl2-s001.vmdk"));
    assert!(message.contains(
        &descriptor_dir
            .join("drive-0-cl2-s001.vmdk")
            .display()
            .to_string()
    ));

    let forced_result = InspectionEngine::new(Options {
        force_nbd: true,
        qemu_nbd: Some(descriptor_dir.join("missing-qemu-nbd.exe")),
        ..Options::default()
    })
    .inspect(&descriptor_path);
    assert!(
        matches!(
            forced_result,
            Err(VmSpectError::MissingDiskComponent { .. })
        ),
        "force_nbd must not hide a missing VMDK component: {forced_result:?}"
    );
}

#[test]
fn test_missing_extent_in_parent_chain_has_parent_descriptor_context() {
    let dir = tempfile::tempdir().unwrap();
    let child_path = dir.path().join("snapshot.vmdk");
    let parent_path = dir.path().join("base.vmdk");

    std::fs::write(
        &child_path,
        r#"# Disk DescriptorFile
version=1
CID=abcdef01
parentCID=abcdef02
parentFileNameHint="base.vmdk"
createType="monolithicSparse"
RW 1 ZERO
"#,
    )
    .unwrap();
    std::fs::write(
        &parent_path,
        r#"# Disk DescriptorFile
version=1
CID=abcdef02
parentCID=ffffffff
createType="twoGbMaxExtentFlat"
RW 1 FLAT "base-s001.vmdk" 0
"#,
    )
    .unwrap();

    let result = InspectionEngine::new(Options::default()).inspect(&child_path);
    match result {
        Err(VmSpectError::MissingDiskComponent {
            descriptor_path,
            declared_name,
            resolved_path,
            component_type,
            ..
        }) => {
            assert_eq!(descriptor_path, parent_path.display().to_string());
            assert_eq!(declared_name, "base-s001.vmdk");
            assert_eq!(
                resolved_path,
                dir.path().join("base-s001.vmdk").display().to_string()
            );
            assert_eq!(component_type, "VMDK extent");
        }
        other => panic!("Expected parent-chain MissingDiskComponent, got: {other:?}"),
    }
}

fn write_failing_qemu_nbd_helper(path: &std::path::Path) {
    #[cfg(windows)]
    std::fs::write(
        path,
        "@echo off\r\necho simulated qemu-nbd failure 1>&2\r\nexit 23\r\n",
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(
            path,
            "#!/bin/sh\nprintf '%s\\n' 'simulated qemu-nbd failure' >&2\nexit 23\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }
}

#[test]
fn test_qemu_nbd_failure_is_preserved_as_public_nbd_error() {
    let dir = tempfile::tempdir().unwrap();
    let helper_path = if cfg!(windows) {
        dir.path().join("fake qemu-nbd.cmd")
    } else {
        dir.path().join("fake-qemu-nbd")
    };
    write_failing_qemu_nbd_helper(&helper_path);

    let image_path = dir.path().join("server.qcow2");
    std::fs::write(&image_path, b"QFI\xfb\x00\x00\x00\x03").unwrap();
    let result = InspectionEngine::new(Options {
        qemu_nbd: Some(helper_path.clone()),
        connection_timeout: Some(std::time::Duration::from_secs(1)),
        ..Options::default()
    })
    .inspect(&image_path);

    match result {
        Err(VmSpectError::Nbd(message)) => {
            assert!(message.contains(&helper_path.display().to_string()));
            assert!(message.contains("23"));
            assert!(message.contains("simulated qemu-nbd failure"));
        }
        other => panic!("Expected VmSpectError::Nbd, got: {other:?}"),
    }
}

fn write_minimal_sparse_extent(path: &std::path::Path) {
    let mut bytes = vec![0u8; 1024];
    bytes[0..4].copy_from_slice(b"KDMV");
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[12..20].copy_from_slice(&1u64.to_le_bytes()); // capacity: one sector
    bytes[20..28].copy_from_slice(&1u64.to_le_bytes()); // one-sector grains
    bytes[44..48].copy_from_slice(&1u32.to_le_bytes()); // one GTE per grain table
    bytes[56..64].copy_from_slice(&1u64.to_le_bytes()); // grain directory at sector 1
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn test_complete_sparse_vmdk_descriptor_opens_natively() {
    let dir = tempfile::tempdir().unwrap();
    let descriptor_path = dir.path().join("complete.vmdk");
    std::fs::write(
        &descriptor_path,
        r#"# Disk DescriptorFile
version=1
CID=abcdef01
parentCID=ffffffff
createType="twoGbMaxExtentSparse"
RW 1 SPARSE "complete-s001.vmdk"
RW 1 SPARSE "complete-s002.vmdk"
"#,
    )
    .unwrap();
    write_minimal_sparse_extent(&dir.path().join("complete-s001.vmdk"));
    write_minimal_sparse_extent(&dir.path().join("complete-s002.vmdk"));

    let info = ImageInfo {
        path: descriptor_path,
        format: "vmdk".to_string(),
        virtual_size: 1024,
        actual_size: 2048,
        hypervisor: Hypervisor::VMware,
    };
    let reader = DiskReader::open_with_options(&info, &Options::default()).unwrap();
    assert!(reader.is_native());
    assert!(reader.access_mode().contains("twoGbMaxExtentSparse"));
}

#[test]
fn test_vmdk_paths_with_spaces_and_unicode_open_natively() {
    let dir = tempfile::tempdir().unwrap();
    let image_dir = dir
        .path()
        .join("PLC N°4")
        .join("Máquinas Virtuales")
        .join("VM");
    std::fs::create_dir_all(&image_dir).unwrap();
    let descriptor_path = image_dir.join("drive.vmdk");
    let extent_path = image_dir.join("drive extent s001.vmdk");
    std::fs::write(
        &descriptor_path,
        r#"# Disk DescriptorFile
version=1
CID=abcdef01
parentCID=ffffffff
createType="twoGbMaxExtentFlat"
RW 1 FLAT "drive extent s001.vmdk" 0
"#,
    )
    .unwrap();
    std::fs::write(&extent_path, [0u8; 512]).unwrap();

    let info = ImageInfo {
        path: descriptor_path,
        format: "vmdk".to_string(),
        virtual_size: 512,
        actual_size: 512,
        hypervisor: Hypervisor::VMware,
    };
    let reader = DiskReader::open_with_options(&info, &Options::default()).unwrap();
    assert!(reader.is_native());
    assert!(reader.access_mode().contains("twoGbMaxExtentFlat"));
}
