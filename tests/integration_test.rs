use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use vmspect::prelude::*;

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
            name: "Example Application V18".to_string(),
            version: Some("18.0".to_string()),
            publisher: Some("Example Publisher".to_string()),
            source: None,
        },
        Program {
            name: "Example Runtime Redistributable (x64)".to_string(),
            version: Some("14.36.32532".to_string()),
            publisher: Some("Example Publisher".to_string()),
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
    assert!(sample_packages.iter().any(|p| p.name.contains("Example Application")));
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
