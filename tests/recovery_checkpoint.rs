use clustor::consensus::{ConsensusCore, ConsensusCoreConfig};
use clustor::cp::{CpProofCoordinator, CpUnavailableReason};
use clustor::durability::{DurabilityLogEntry, IoMode, RecoveryStatus};
use clustor::storage::layout::WalSegmentRef;
use clustor::storage::{EntryFrameBuilder, WalReplayScanner};
use clustor::telemetry::MetricsRegistry;
use std::fs;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn corrupt_wal_forces_local_only_and_telemetry() {
    let temp = tempdir().unwrap();
    let segment_path = temp.path().join("segment-0000000001.log");
    let frame = EntryFrameBuilder::new(1, 1)
        .metadata(vec![1, 2, 3])
        .payload(b"payload".to_vec())
        .build();
    let mut bytes = frame.encode();
    let len = bytes.len();
    bytes[len - 1] ^= 0xAA;
    fs::write(&segment_path, bytes).unwrap();

    let segments = vec![WalSegmentRef {
        seq: 1,
        log_path: segment_path.clone(),
        index_path: None,
    }];
    let wal = WalReplayScanner::scan(&segments).unwrap();
    assert!(wal.truncation.is_some());

    let entries = vec![DurabilityLogEntry::new(1, 1, 1, IoMode::Strict, 0)];
    let status = RecoveryStatus::new(&wal, &entries);
    let mut registry = MetricsRegistry::new("clustor");
    status.record_metrics(&mut registry);

    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.apply_recovery_status(&status, now);
    let err = coordinator
        .guard_read_index(now)
        .expect_err("recovery should force LocalOnly");
    assert_eq!(
        err.response().reason,
        CpUnavailableReason::NeededForReadIndex
    );

    let snapshot = registry.snapshot();
    assert!(
        snapshot.gauges["clustor.wal.recovery_truncated_bytes"] > 0,
        "expected truncated byte gauge to be > 0"
    );
}
