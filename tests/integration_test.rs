use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vmspect::prelude::*;

fn test_operation_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn write_fixture_image(path: &std::path::Path) {
    let mut bytes = vec![0u8; 1024];
    bytes[510] = 0x55;
    bytes[511] = 0xAA;
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn configurable_discovery_and_summary_are_public() {
    let _guard = test_operation_guard();
    let tempdir = tempfile::tempdir().unwrap();
    let fixtures = tempdir.path().join("fixtures");
    let excluded = fixtures.join("excluded");
    std::fs::create_dir_all(&excluded).unwrap();
    write_fixture_image(&fixtures.join("sample-vm.raw"));
    write_fixture_image(&excluded.join("fixture-vm.raw"));

    let discovery = list_vms_with_options(
        &fixtures,
        &DiscoveryOptions {
            recursive: true,
            excluded_directories: vec![PathBuf::from("excluded")],
            emit_warnings: false,
            max_depth: Some(1),
        },
    )
    .unwrap();
    assert_eq!(discovery.images.len(), 1);
    assert!(discovery.warnings.is_empty());

    let summary = InspectionEngine::new(Options::default())
        .inspect_summary(&discovery.images[0])
        .unwrap();
    let json = serde_json::to_value(summary).unwrap();
    assert!(json.get("installed_programs").is_none());
    assert!(json.get("partitions").is_none());
    assert!(json.get("stats").is_none());
}

#[test]
fn tolerant_batch_preserves_reports_errors_and_json_shape() {
    let _guard = test_operation_guard();
    let tempdir = tempfile::tempdir().unwrap();
    let valid = tempdir.path().join("sample-vm.raw");
    let missing = tempdir.path().join("fixture-vm.raw");
    write_fixture_image(&valid);

    let batch = InspectionEngine::new(Options::default())
        .inspect_batch(vec![valid.clone(), missing.clone()], 2)
        .unwrap();
    assert_eq!(batch.reports.len(), 1);
    assert_eq!(batch.errors.len(), 1);
    assert_eq!(batch.reports[0].image.path, valid);
    assert_eq!(batch.errors[0].path, missing);

    let json = serde_json::to_value(&batch).unwrap();
    assert!(json["reports"].is_array());
    assert!(json["errors"].is_array());

    let empty = InspectionEngine::new(Options::default())
        .inspect_batch(Vec::<PathBuf>::new(), 1)
        .unwrap();
    assert_eq!(
        serde_json::to_value(empty).unwrap(),
        serde_json::json!({"reports": [], "errors": []})
    );
}

#[test]
fn batch_progress_is_lightweight_and_works_with_errors() {
    let _guard = test_operation_guard();
    let tempdir = tempfile::tempdir().unwrap();
    let valid = tempdir.path().join("sample-vm.raw");
    let missing = tempdir.path().join("fixture-vm.raw");
    write_fixture_image(&valid);
    let mut events = Vec::new();

    let batch = InspectionEngine::new(Options::default())
        .inspect_batch_with_progress(vec![valid, missing], 1, |event| events.push(event))
        .unwrap();
    assert_eq!(batch.reports.len() + batch.errors.len(), 2);
    assert!(!events.is_empty());
    assert_eq!(events.last().unwrap().stage, "Batch completed");
    let event_json = serde_json::to_value(events.last().unwrap()).unwrap();
    assert!(event_json.get("installed_programs").is_none());
    assert!(event_json.get("reports").is_none());
}

#[test]
fn cancellation_keeps_completed_batch_outcomes() {
    let _guard = test_operation_guard();
    let tempdir = tempfile::tempdir().unwrap();
    let first = tempdir.path().join("sample-vm.raw");
    let second = tempdir.path().join("fixture-vm.raw");
    write_fixture_image(&first);
    write_fixture_image(&second);
    let cancelled = Arc::new(AtomicBool::new(true));
    let engine = InspectionEngine::new(Options::default().with_cancel_token(cancelled));
    let batch = engine.inspect_batch(vec![first, second], 1).unwrap();
    assert!(batch.reports.is_empty());
    assert!(batch.errors.is_empty());
}

#[test]
fn options_have_safe_nbd_defaults() {
    let options = Options::default();
    assert!(!options.force_nbd);
    assert_eq!(options.nbd_max_sessions, 2);
}
