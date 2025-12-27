use clustor::{
    SnapshotDeltaChainState, SnapshotDeltaChainTelemetry, SnapshotFallbackTelemetry,
    SnapshotOnlyReadyState, SnapshotReadError, WhyPublisher, WhySchemaHeader, WhySnapshotBlocked,
};

pub fn sample_snapshot_blocked_publisher(partition: &str) -> WhyPublisher {
    let publisher = WhyPublisher::default();
    let header = WhySchemaHeader::new(partition, 1, 1, 0);
    let fallback = SnapshotFallbackTelemetry {
        partition_ready_ratio_snapshot: 0.5,
        snapshot_manifest_age_ms: 10,
        snapshot_only_ready_state: SnapshotOnlyReadyState::Degraded,
        snapshot_only_min_ready_ratio: 0.8,
        snapshot_only_slo_breach_total: 1,
    };
    let delta = SnapshotDeltaChainTelemetry {
        state: SnapshotDeltaChainState::Idle,
        chain_length: 0,
        last_manifest_id: Some("manifest-1".into()),
        last_full_snapshot_ms: Some(100),
        last_snapshot_ms: Some(200),
    };
    let report = WhySnapshotBlocked::new(
        header,
        "manifest-1",
        fallback,
        Some(delta),
        SnapshotReadError::SnapshotOnlyUnavailable,
    );
    publisher.update_snapshot_blocked(partition, report);
    publisher
}
