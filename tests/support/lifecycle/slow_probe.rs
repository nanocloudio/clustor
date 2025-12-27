use clustor::lifecycle::bootstrap::FsyncProbeResult;

pub fn slow_probe(p99_ms: u64) -> FsyncProbeResult {
    FsyncProbeResult {
        p99_ms,
        sample_count: 128,
        dataset_guid: "dataset-guid".into(),
        wal_path: "/wal".into(),
        device_serials: vec!["disk0".into()],
        measured_at_ms: 0,
    }
}
