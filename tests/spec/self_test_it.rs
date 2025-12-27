use clustor::spec::self_test::{SpecSelfTestError, SpecSelfTestHarness};
use clustor::telemetry::MetricsRegistry;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;
use tempfile::tempdir;

#[test]
fn spec_self_test_runs_and_persists() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION", "1");
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("self_test.json");
    let mut registry = MetricsRegistry::new("clustor");
    let now = SystemTime::now();
    let harness = SpecSelfTestHarness::new()
        .with_test("AppendEntriesFormat", "Spec §2.1", Box::new(|| true))
        .with_test("SnapshotManifest", "Appendix C", Box::new(|| true));
    let result = harness.run(&path, &mut registry, now).unwrap();
    assert_eq!(result.total, 2);
    assert!(!result.skipped);
    assert!(path.exists());
    std::env::remove_var("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION");
}

#[test]
fn spec_self_test_rejects_empty_suite() {
    let _guard = env_lock().lock().unwrap();
    std::env::set_var("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION", "1");
    let mut registry = MetricsRegistry::new("clustor");
    let harness = SpecSelfTestHarness::new();
    let err = harness
        .run("/tmp/spec_self_test.json", &mut registry, SystemTime::now())
        .unwrap_err();
    assert!(matches!(err, SpecSelfTestError::NoTestsRegistered));
    std::env::remove_var("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION");
}

#[test]
fn spec_self_test_can_be_skipped_via_env() {
    let _guard = env_lock().lock().unwrap();
    std::env::remove_var("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION");
    std::env::set_var("CLUSTOR_SKIP_ARTIFACT_VALIDATION", "1");
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("self_test.json");
    let mut registry = MetricsRegistry::new("clustor");
    let now = SystemTime::now();
    let harness =
        SpecSelfTestHarness::new().with_test("AppendEntriesFormat", "Spec §2.1", Box::new(|| true));
    let result = harness.run(&path, &mut registry, now).unwrap();
    std::env::remove_var("CLUSTOR_SKIP_ARTIFACT_VALIDATION");
    assert!(result.skipped);
    assert_eq!(result.total, 0);
    assert_eq!(result.passed, 0);
}

#[test]
fn spec_self_test_skips_when_artifacts_missing_by_default() {
    let _guard = env_lock().lock().unwrap();
    std::env::remove_var("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION");
    std::env::remove_var("CLUSTOR_SKIP_ARTIFACT_VALIDATION");
    assert!(
        !Path::new("artifacts").exists(),
        "artifacts directory should be absent"
    );
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("self_test.json");
    let mut registry = MetricsRegistry::new("clustor");
    let now = SystemTime::now();
    let harness =
        SpecSelfTestHarness::new().with_test("AppendEntriesFormat", "Spec §2.1", Box::new(|| true));
    let result = harness.run(&path, &mut registry, now).unwrap();
    assert!(result.skipped);
    assert_eq!(result.total, 0);
    assert_eq!(result.passed, 0);
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}
