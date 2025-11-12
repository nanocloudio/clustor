use clustor::bootstrap::probe::{FsyncProbeResult, GroupFsyncGuardConfig};
use clustor::durability::RecoveryStatus;
use clustor::storage::{EntryFrameError, WalTruncation};
use clustor::{
    ConsensusCore, ConsensusCoreConfig, CpDegradationMetrics, DurabilityProof, GateOperation,
    GroupFsyncPolicy, IncidentCorrelator, IncidentDecision, MetricsRegistry,
    StrictFallbackMetricsPublisher,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn telemetry_checkpoint_registry_and_correlator() {
    let mut registry = MetricsRegistry::new("clustor");
    registry.inc_counter("cp.cache_hits", 5);
    registry.register_histogram("latency_ns", 1_000);
    registry
        .observe_histogram("latency_ns", 250.0)
        .expect("hist registered");
    let snapshot = registry.snapshot();
    assert!(snapshot.counters.contains_key("clustor.cp.cache_hits"));

    let mut correlator = IncidentCorrelator::new(Duration::from_secs(60));
    let now = Instant::now();
    assert_eq!(
        correlator.record("cp-cache-expired", now),
        IncidentDecision::Triggered
    );
    assert_eq!(
        correlator.record("cp-cache-expired", now + Duration::from_secs(5)),
        IncidentDecision::Suppressed
    );

    let mut metrics = CpDegradationMetrics::default();
    metrics.record_warning();
    metrics.record_expired();
    metrics.record_strict_only();
    assert_eq!(metrics.cache_warning_events, 1);
    assert_eq!(metrics.cache_expired_events, 1);
    assert_eq!(metrics.strict_only_transitions, 1);
}

#[test]
fn telemetry_checkpoint_reports_term_ids() {
    let mut policy = GroupFsyncPolicy::new(GroupFsyncGuardConfig::default());
    let strict_term = policy.telemetry().mode_term;
    assert_eq!(strict_term.term_id, "TERM-0001");

    let probe = |ms| FsyncProbeResult {
        p99_ms: ms,
        sample_count: 128,
        dataset_guid: "guid".into(),
        wal_path: "wal".into(),
        device_serials: vec!["disk".into()],
        measured_at_ms: 0,
    };
    policy.record_probe(probe(5));
    let group_term = policy.telemetry().mode_term;
    assert_eq!(group_term.term_id, "TERM-0002");
}

#[test]
fn telemetry_checkpoint_records_strict_fallback_metrics() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut publisher = StrictFallbackMetricsPublisher::new();
    let mut registry = MetricsRegistry::new("clustor");
    let now = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(4, 40), now);
    kernel.register_strict_write();
    kernel
        .guard(GateOperation::EnableGroupFsync)
        .expect_err("strict fallback blocks group fsync");
    kernel
        .guard(GateOperation::EnableLeaseReads)
        .expect_err("strict fallback blocks leases");
    kernel
        .guard(GateOperation::GrantFollowerReadSnapshotCapability)
        .expect_err("strict fallback blocks follower capability");
    kernel
        .guard(GateOperation::EnableSnapshotDelta)
        .expect_err("strict fallback blocks snapshot delta");
    publisher.publish(
        &mut registry,
        &kernel.telemetry(now + Duration::from_secs(1)),
    );

    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot.counters["clustor.strict_fallback_gate_blocked.DurabilityTransitionToGroup"],
        1
    );
    assert_eq!(
        snapshot.counters["clustor.strict_fallback_gate_blocked.LeaseEnable"],
        1
    );
    assert_eq!(
        snapshot.counters["clustor.strict_fallback_gate_blocked.FollowerCapabilityGrant"],
        1
    );
    assert_eq!(
        snapshot.counters["clustor.strict_fallback_gate_blocked.SnapshotDeltaEnable"],
        1
    );
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_blocking_read_index"],
        1
    );
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_pending_entries"],
        1
    );
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_last_local_proof.term"],
        4
    );
}

#[test]
fn recovery_status_emits_truncation_metric() {
    let mut registry = MetricsRegistry::new("clustor");
    let status = RecoveryStatus {
        strict_required: true,
        truncation: Some(WalTruncation {
            segment_seq: 7,
            path: PathBuf::from("wal/segment-0000000007.log"),
            offset: 256,
            truncated_bytes: 256,
            error: EntryFrameError::TooShort,
        }),
        proof: None,
    };
    status.record_metrics(&mut registry);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.gauges["clustor.wal.recovery_truncated_bytes"], 256);
}

#[test]
fn telemetry_checkpoint_metric_snapshot_serializes_counts() {
    let mut registry = MetricsRegistry::new("clustor");
    registry.register_golden_histograms();
    registry.inc_counter("cp.cache_hits", 9);
    registry.set_gauge("flow.ready_partitions", 4);
    registry
        .observe_histogram("clustor.wal.fsync_latency_ms", 3.0)
        .expect("histogram registered");
    let snapshot = registry.snapshot();
    let json = serde_json::to_value(&snapshot).expect("snapshot serializes");
    assert_eq!(
        json["gauges"]["clustor.flow.ready_partitions"],
        serde_json::json!(4)
    );
    assert_eq!(
        json["counters"]["clustor.cp.cache_hits"],
        serde_json::json!(9)
    );
    let histogram = json["histograms"]["clustor.wal.fsync_latency_ms"]
        .as_array()
        .expect("histogram counts");
    assert!(histogram
        .iter()
        .any(|bucket| bucket.as_u64().unwrap_or(0) > 0));
}
