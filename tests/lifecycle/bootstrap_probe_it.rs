#[path = "../support/lifecycle/probe.rs"]
mod probe_support;

use clustor::lifecycle::bootstrap::{
    run_probe_and_persist, BootRecordStore, FsyncProbeConfig, FsyncProbeContext, FsyncProbeResult,
    FsyncProbeRunner, GroupFsyncDecision, GroupFsyncGuard, GroupFsyncGuardConfig, GuardrailReason,
};
use probe_support::{MockProbeTarget, RecordingSink};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

#[test]
fn runner_computes_p99() {
    let samples = (0..128)
        .map(|i| Duration::from_millis(i as u64))
        .collect::<Vec<_>>();
    let mut target = MockProbeTarget::new(samples);
    let context = FsyncProbeContext {
        wal_path: "/wal".into(),
        dataset_guid: "guid-1".into(),
        device_serials: vec!["disk-a".into()],
    };
    let mut runner = FsyncProbeRunner::new(&mut target, FsyncProbeConfig::default(), context);
    let result = runner
        .run(SystemTime::UNIX_EPOCH + Duration::from_secs(10))
        .expect("probe result");
    assert!(target.finalized());
    assert_eq!(result.sample_count, 128);
    assert_eq!(result.dataset_guid, "guid-1");
    assert!(result.p99_ms >= 126);
}

#[test]
fn supervisor_persists_and_publishes() {
    let samples = vec![Duration::from_millis(10); 128];
    let mut target = MockProbeTarget::new(samples);
    let context = FsyncProbeContext {
        wal_path: "/wal".into(),
        dataset_guid: "guid-zfs".into(),
        device_serials: vec!["disk-a".into(), "disk-b".into()],
    };
    let mut runner = FsyncProbeRunner::new(&mut target, FsyncProbeConfig::default(), context);
    let dir = TempDir::new().expect("tempdir");
    let store = BootRecordStore::new(dir.path().join("boot_record.json"));
    let sink = RecordingSink::new();

    let result = run_probe_and_persist(
        &mut runner,
        &store,
        &sink,
        SystemTime::UNIX_EPOCH + Duration::from_secs(5),
    )
    .expect("probe supervisor");

    assert!(sink.publish_calls() > 0);
    let record = store.load_or_default().expect("load record");
    assert!(record.fsync_probe.is_some());
    assert_eq!(result.sample_count, 128);
}

#[test]
fn guard_enforces_thresholds() {
    fn run_probe(samples: Vec<Duration>) -> FsyncProbeResult {
        let context = FsyncProbeContext {
            wal_path: "/wal".into(),
            dataset_guid: "guid".into(),
            device_serials: vec!["disk".into()],
        };
        let mut target = MockProbeTarget::new(samples);
        let mut runner = FsyncProbeRunner::new(&mut target, FsyncProbeConfig::default(), context);
        runner.run(SystemTime::now()).unwrap()
    }

    let result = run_probe(vec![Duration::from_millis(5); 128]);
    let decision = GroupFsyncGuard::evaluate(
        std::slice::from_ref(&result),
        GroupFsyncGuardConfig::default(),
    );
    assert!(matches!(decision, GroupFsyncDecision::Eligible));

    let mut history = Vec::new();
    for _ in 0..3 {
        let slow = FsyncProbeResult {
            p99_ms: 25,
            ..result.clone()
        };
        history.push(slow);
    }
    let decision = GroupFsyncGuard::evaluate(&history, GroupFsyncGuardConfig::default());
    assert!(matches!(
        decision,
        GroupFsyncDecision::ForceStrict(GuardrailReason::ProbeTooSlow { .. })
    ));
}
