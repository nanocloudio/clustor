#![cfg(feature = "snapshot-crypto")]

use super::readyz_support::{
    build_capability_matrix, build_readyz_snapshot, disk_override, readiness_record,
    sample_delta_telemetry, sample_export_telemetry,
};
use clustor::readyz::{readyz_from_warmup_snapshot, OverrideStatus, ReadyStateHealth};
use std::collections::HashMap;

#[test]
fn snapshot_reports_capabilities_and_overrides() {
    let (matrix, manifest_digest) = build_capability_matrix();
    let record = readiness_record("p1", 0.9);
    let ratios = HashMap::from([(String::from("p1"), 0.8)]);
    let doc = disk_override("999999");
    let override_status = OverrideStatus::from_disk_override(&doc, 0).expect("override converts");
    let delta = sample_delta_telemetry();
    let barrier_map = HashMap::from([(String::from("p1"), String::from("barrier-1"))]);
    let (warmup_snapshot, _) = build_readyz_snapshot(record.clone(), &ratios, &barrier_map, vec![]);
    let snapshot = readyz_from_warmup_snapshot(
        &warmup_snapshot,
        &ratios,
        &barrier_map,
        &matrix,
        manifest_digest.clone(),
        vec![override_status.clone()],
    )
    .expect("readyz snapshot builds")
    .with_export_telemetry(sample_export_telemetry())
    .with_delta_chain(delta.clone());

    assert_eq!(snapshot.capabilities().len(), matrix.entries().len());
    assert_eq!(snapshot.overrides().len(), 1);
    let why = snapshot.why_not_ready("p1").expect("partition captured");
    assert_eq!(why.health, ReadyStateHealth::WarmupPending);
    assert_eq!(why.readiness_digest, snapshot.readiness_digest());
    assert_eq!(why.activation_barrier_id.as_deref(), Some("barrier-1"));
    assert_eq!(snapshot.publish_period_ms(), 1_000);
    assert_eq!(snapshot.skipped_publications_total(), 0);
    assert_eq!(snapshot.feature_manifest_digest(), manifest_digest);
    let warmup = snapshot.warmup_summary();
    assert_eq!(warmup.total, 1);
    assert_eq!(warmup.ready, 0);
    assert!(warmup.ready_fraction() < 0.5);
    assert_eq!(
        snapshot
            .export_telemetry()
            .unwrap()
            .chunk_rate_bytes_per_sec,
        512
    );
    assert_eq!(
        snapshot.delta_chain().unwrap().state,
        clustor::SnapshotDeltaChainState::Idle
    );
}
