use crate::bootstrap::boot_record::{BootRecordError, BootRecordStore};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct FsyncProbeContext {
    pub wal_path: String,
    pub dataset_guid: String,
    pub device_serials: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct FsyncProbeConfig {
    pub samples: usize,
    pub probe_bytes: u64,
}

impl Default for FsyncProbeConfig {
    fn default() -> Self {
        Self {
            samples: 128,
            probe_bytes: 4 * 1024 * 1024,
        }
    }
}

pub trait ProbeTarget {
    fn run_sample(
        &mut self,
        sample_idx: usize,
        total_samples: usize,
    ) -> Result<Duration, ProbeIoError>;

    fn finalize(&mut self) -> Result<(), ProbeIoError> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProbeIoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("device error: {0}")]
    Device(String),
}

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error(transparent)]
    Target(#[from] ProbeIoError),
    #[error("insufficient samples: got {got}, required {required}")]
    InsufficientSamples { got: usize, required: usize },
    #[error("sample count {count} exceeds u32::MAX")]
    SampleCountOverflow { count: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsyncProbeResult {
    pub p99_ms: u64,
    pub sample_count: u32,
    pub dataset_guid: String,
    pub wal_path: String,
    pub device_serials: Vec<String>,
    pub measured_at_ms: u64,
}

impl FsyncProbeResult {
    pub fn telemetry(&self) -> FsyncProbeTelemetry {
        FsyncProbeTelemetry {
            dataset_guid: self.dataset_guid.clone(),
            wal_path: self.wal_path.clone(),
            p99_ms: self.p99_ms,
            sample_count: self.sample_count,
            device_serials: self.device_serials.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsyncProbeTelemetry {
    pub dataset_guid: String,
    pub wal_path: String,
    pub p99_ms: u64,
    pub sample_count: u32,
    pub device_serials: Vec<String>,
}

impl From<&FsyncProbeResult> for FsyncProbeTelemetry {
    fn from(value: &FsyncProbeResult) -> Self {
        value.telemetry()
    }
}

pub trait ProbeTelemetrySink {
    fn publish(&self, payload: &FsyncProbeTelemetry) -> Result<(), TelemetryError>;
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("telemetry publish failed: {0}")]
    Transport(String),
}

pub struct FsyncProbeRunner<'a, T: ProbeTarget> {
    target: &'a mut T,
    config: FsyncProbeConfig,
    context: FsyncProbeContext,
}

impl<'a, T: ProbeTarget> FsyncProbeRunner<'a, T> {
    pub fn new(target: &'a mut T, config: FsyncProbeConfig, context: FsyncProbeContext) -> Self {
        Self {
            target,
            config,
            context,
        }
    }

    pub fn run(&mut self, now: SystemTime) -> Result<FsyncProbeResult, ProbeError> {
        let mut durations = Vec::with_capacity(self.config.samples);
        for idx in 0..self.config.samples {
            durations.push(self.target.run_sample(idx, self.config.samples)?);
        }
        self.target.finalize()?;

        if durations.len() < self.config.samples {
            return Err(ProbeError::InsufficientSamples {
                got: durations.len(),
                required: self.config.samples,
            });
        }

        let sample_count =
            u32::try_from(durations.len()).map_err(|_| ProbeError::SampleCountOverflow {
                count: durations.len(),
            })?;

        let p99_duration = percentile(&mut durations, 0.99);
        let p99_ms = duration_to_ms(p99_duration);
        let measured_at_ms = system_time_to_ms(now);

        let mut device_serials = self.context.device_serials.clone();
        device_serials.sort();
        device_serials.dedup();

        Ok(FsyncProbeResult {
            p99_ms,
            sample_count,
            dataset_guid: self.context.dataset_guid.clone(),
            wal_path: self.context.wal_path.clone(),
            device_serials,
            measured_at_ms,
        })
    }
}

pub fn run_probe_and_persist<T, S>(
    runner: &mut FsyncProbeRunner<T>,
    store: &BootRecordStore,
    telemetry: &S,
    now: SystemTime,
) -> Result<FsyncProbeResult, ProbeSupervisorError>
where
    T: ProbeTarget,
    S: ProbeTelemetrySink,
{
    let mut record = store.load_or_default()?;
    let result = runner.run(now)?;
    record.fsync_probe = Some(result.clone());
    store.persist(&record)?;
    telemetry.publish(&FsyncProbeTelemetry::from(&result))?;
    Ok(result)
}

#[derive(Debug, Error)]
pub enum ProbeSupervisorError {
    #[error(transparent)]
    Probe(#[from] ProbeError),
    #[error(transparent)]
    BootRecord(#[from] BootRecordError),
    #[error(transparent)]
    Telemetry(#[from] TelemetryError),
}

#[derive(Debug)]
pub struct GroupFsyncGuard;

#[derive(Debug, Clone, Copy)]
pub struct GroupFsyncGuardConfig {
    pub required_samples: u32,
    pub max_p99_ms: u64,
    pub max_consecutive_failures: usize,
}

impl Default for GroupFsyncGuardConfig {
    fn default() -> Self {
        Self {
            required_samples: 128,
            max_p99_ms: 20,
            max_consecutive_failures: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupFsyncDecision {
    Eligible,
    ForceStrict(GuardrailReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardrailReason {
    NoProbeAvailable,
    InsufficientSamples {
        observed: u32,
        required: u32,
    },
    ProbeTooSlow {
        p99_ms: u64,
        max_p99_ms: u64,
        consecutive_failures: usize,
        max_failures: usize,
    },
}

impl GroupFsyncGuard {
    pub fn evaluate(
        history: &[FsyncProbeResult],
        config: GroupFsyncGuardConfig,
    ) -> GroupFsyncDecision {
        let Some(latest) = history.last() else {
            return GroupFsyncDecision::ForceStrict(GuardrailReason::NoProbeAvailable);
        };

        if latest.sample_count < config.required_samples {
            return GroupFsyncDecision::ForceStrict(GuardrailReason::InsufficientSamples {
                observed: latest.sample_count,
                required: config.required_samples,
            });
        }

        if latest.p99_ms > config.max_p99_ms {
            let failures = history
                .iter()
                .rev()
                .take_while(|result| result.p99_ms > config.max_p99_ms)
                .count();
            return GroupFsyncDecision::ForceStrict(GuardrailReason::ProbeTooSlow {
                p99_ms: latest.p99_ms,
                max_p99_ms: config.max_p99_ms,
                consecutive_failures: failures,
                max_failures: config.max_consecutive_failures,
            });
        }

        GroupFsyncDecision::Eligible
    }
}

fn percentile(durations: &mut [Duration], quantile: f64) -> Duration {
    if durations.is_empty() {
        return Duration::ZERO;
    }
    durations.sort();
    let rank = ((durations.len() as f64) * quantile).ceil() as usize;
    let idx = rank.saturating_sub(1).min(durations.len() - 1);
    durations[idx]
}

fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn system_time_to_ms(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;

    struct MockTarget {
        samples: Vec<Duration>,
        cursor: usize,
        finalized: bool,
    }

    impl MockTarget {
        fn new(samples: Vec<Duration>) -> Self {
            Self {
                samples,
                cursor: 0,
                finalized: false,
            }
        }
    }

    impl ProbeTarget for MockTarget {
        fn run_sample(
            &mut self,
            _sample_idx: usize,
            _total_samples: usize,
        ) -> Result<Duration, ProbeIoError> {
            let duration = self
                .samples
                .get(self.cursor)
                .copied()
                .unwrap_or(Duration::from_millis(1));
            self.cursor += 1;
            Ok(duration)
        }

        fn finalize(&mut self) -> Result<(), ProbeIoError> {
            self.finalized = true;
            Ok(())
        }
    }

    struct RecordingSink {
        payloads: Arc<Mutex<Vec<FsyncProbeTelemetry>>>,
        publish_calls: AtomicUsize,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                payloads: Arc::new(Mutex::new(Vec::new())),
                publish_calls: AtomicUsize::new(0),
            }
        }
    }

    impl ProbeTelemetrySink for RecordingSink {
        fn publish(&self, payload: &FsyncProbeTelemetry) -> Result<(), TelemetryError> {
            self.publish_calls.fetch_add(1, Ordering::Relaxed);
            self.payloads.lock().unwrap().push(payload.clone());
            Ok(())
        }
    }

    #[test]
    fn runner_computes_p99() {
        let samples = (0..128)
            .map(|i| Duration::from_millis(i as u64))
            .collect::<Vec<_>>();
        let mut target = MockTarget::new(samples);
        let context = FsyncProbeContext {
            wal_path: "/wal".into(),
            dataset_guid: "guid-1".into(),
            device_serials: vec!["disk-a".into()],
        };
        let mut runner = FsyncProbeRunner::new(&mut target, FsyncProbeConfig::default(), context);
        let result = runner
            .run(SystemTime::UNIX_EPOCH + Duration::from_secs(10))
            .unwrap();
        assert!(target.finalized);
        assert!(result.p99_ms >= 126);
        assert_eq!(result.sample_count, 128);
        assert_eq!(result.dataset_guid, "guid-1");
    }

    #[test]
    fn supervisor_persists_and_publishes() {
        let samples = vec![Duration::from_millis(10); 128];
        let mut target = MockTarget::new(samples);
        let context = FsyncProbeContext {
            wal_path: "/wal".into(),
            dataset_guid: "guid-zfs".into(),
            device_serials: vec!["disk-a".into(), "disk-b".into()],
        };
        let mut runner = FsyncProbeRunner::new(&mut target, FsyncProbeConfig::default(), context);
        let tmp_path = std::env::temp_dir().join(format!(
            "boot-record-{}.json",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = BootRecordStore::new(&tmp_path);
        let sink = RecordingSink::new();

        let result = run_probe_and_persist(
            &mut runner,
            &store,
            &sink,
            SystemTime::UNIX_EPOCH + Duration::from_secs(5),
        )
        .unwrap();

        assert!(sink.publish_calls.load(Ordering::Relaxed) > 0);
        let record = store.load_or_default().unwrap();
        assert!(record.fsync_probe.is_some());
        std::fs::remove_file(tmp_path).unwrap();
        assert_eq!(result.sample_count, 128);
    }

    #[test]
    fn guard_enforces_thresholds() {
        let context = FsyncProbeContext {
            wal_path: "/wal".into(),
            dataset_guid: "guid".into(),
            device_serials: vec!["disk".into()],
        };
        let mut target = MockTarget::new(vec![Duration::from_millis(5); 128]);
        let mut runner = FsyncProbeRunner::new(&mut target, FsyncProbeConfig::default(), context);
        let result = runner.run(SystemTime::now()).unwrap();
        let decision = GroupFsyncGuard::evaluate(
            std::slice::from_ref(&result),
            GroupFsyncGuardConfig::default(),
        );
        assert!(matches!(decision, GroupFsyncDecision::Eligible));

        let slow = FsyncProbeResult {
            p99_ms: 25,
            ..result
        };
        let history = vec![slow.clone(), slow.clone(), slow];
        let decision = GroupFsyncGuard::evaluate(&history, GroupFsyncGuardConfig::default());
        assert!(matches!(
            decision,
            GroupFsyncDecision::ForceStrict(GuardrailReason::ProbeTooSlow { .. })
        ));
    }
}
