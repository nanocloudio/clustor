use clustor::lifecycle::bootstrap::probe::{FsyncProbeResult, GroupFsyncGuardConfig};
use clustor::persistence::storage::guard::{FsyncMode, GroupFsyncPolicy};

#[test]
fn switches_modes_based_on_probes() {
    let mut policy = GroupFsyncPolicy::new(GroupFsyncGuardConfig::default());
    policy.record_probe(probe(10));
    assert_eq!(policy.mode(), FsyncMode::Group);
    policy.record_probe(probe(40));
    policy.record_probe(probe(40));
    policy.record_probe(probe(40));
    assert_eq!(policy.mode(), FsyncMode::Strict);
}

fn probe(ms: u64) -> FsyncProbeResult {
    FsyncProbeResult {
        p99_ms: ms,
        sample_count: 128,
        dataset_guid: "guid".into(),
        wal_path: "wal".into(),
        device_serials: vec!["disk".into()],
        measured_at_ms: 0,
    }
}
