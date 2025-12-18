use crate::telemetry::MetricsRegistry;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type SpecCheckFn = Box<dyn Fn() -> bool + Send + Sync>;

#[derive(Default)]
pub struct SpecSelfTestHarness {
    tests: Vec<SpecTestCase>,
}

impl SpecSelfTestHarness {
    pub fn new() -> Self {
        Self { tests: Vec::new() }
    }

    pub fn with_test(
        mut self,
        name: impl Into<String>,
        requirement: impl Into<String>,
        check: SpecCheckFn,
    ) -> Self {
        self.tests.push(SpecTestCase {
            name: name.into(),
            requirement: requirement.into(),
            check,
        });
        self
    }

    pub fn register(
        &mut self,
        name: impl Into<String>,
        requirement: impl Into<String>,
        check: SpecCheckFn,
    ) -> &mut Self {
        self.tests.push(SpecTestCase {
            name: name.into(),
            requirement: requirement.into(),
            check,
        });
        self
    }

    pub fn run(
        &self,
        output_path: impl AsRef<Path>,
        metrics: &mut MetricsRegistry,
        now: SystemTime,
    ) -> Result<SpecSelfTestResult, SpecSelfTestError> {
        if self.tests.is_empty() {
            return Err(SpecSelfTestError::NoTestsRegistered);
        }
        let mut outcomes = Vec::with_capacity(self.tests.len());
        let timestamp_ms = now.duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let skip_validation = should_skip_spec_validation();
        if skip_validation {
            metrics.inc_counter("spec.self_test.skipped", 1);
        } else {
            for test in &self.tests {
                let passed = (test.check)();
                metrics.inc_counter("spec.self_test.samples", 1);
                outcomes.push(SpecTestOutcome {
                    name: test.name.clone(),
                    requirement: test.requirement.clone(),
                    passed,
                    ran_at_unix_ms: timestamp_ms,
                });
            }
        }
        let result = SpecSelfTestResult {
            generated_at_ms: timestamp_ms,
            total: if skip_validation {
                0
            } else {
                outcomes.len() as u64
            },
            passed: if skip_validation {
                0
            } else {
                outcomes.iter().filter(|o| o.passed).count() as u64
            },
            outcomes,
            skipped: skip_validation,
        };
        let payload = serde_json::to_vec_pretty(&result)?;
        let path = output_path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::File::create(path)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        Ok(result)
    }
}

struct SpecTestCase {
    name: String,
    requirement: String,
    check: SpecCheckFn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecSelfTestResult {
    pub generated_at_ms: u64,
    pub total: u64,
    pub passed: u64,
    pub outcomes: Vec<SpecTestOutcome>,
    pub skipped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecTestOutcome {
    pub name: String,
    pub requirement: String,
    pub passed: bool,
    pub ran_at_unix_ms: u64,
}

fn should_skip_spec_validation() -> bool {
    if std::env::var_os("CLUSTOR_REQUIRE_ARTIFACT_VALIDATION").is_some() {
        return false;
    }
    if std::env::var_os("CLUSTOR_SKIP_ARTIFACT_VALIDATION").is_some() {
        return true;
    }
    !Path::new("artifacts").exists()
}

#[derive(Debug, Error)]
pub enum SpecSelfTestError {
    #[error("no spec self-test cases registered")]
    NoTestsRegistered,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("system time error: {0}")]
    Time(#[from] std::time::SystemTimeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::MetricsRegistry;
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
        let harness = SpecSelfTestHarness::new().with_test(
            "AppendEntriesFormat",
            "Spec §2.1",
            Box::new(|| true),
        );
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
        let harness = SpecSelfTestHarness::new().with_test(
            "AppendEntriesFormat",
            "Spec §2.1",
            Box::new(|| true),
        );
        let result = harness.run(&path, &mut registry, now).unwrap();
        assert!(result.skipped);
        assert_eq!(result.total, 0);
        assert_eq!(result.passed, 0);
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }
}
