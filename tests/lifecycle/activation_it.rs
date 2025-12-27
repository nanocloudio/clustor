use clustor::lifecycle::activation::{
    readiness_digest, ActivationBarrier, ActivationBarrierEvaluator, ActivationBarrierState,
    ShadowApplyState, WarmupReadinessPublisher, WarmupReadinessRecord,
};

fn barrier() -> ActivationBarrier {
    ActivationBarrier {
        barrier_id: "barrier-1".into(),
        bundle_id: "bundle-1".into(),
        partitions: vec!["p1".into(), "p2".into()],
        readiness_threshold: 0.8,
        warmup_deadline_ms: 10_000,
        readiness_window_ms: 5_000,
    }
}

fn record(partition: &str, ratio: f64, updated_at: u64) -> WarmupReadinessRecord {
    WarmupReadinessRecord {
        partition_id: partition.into(),
        bundle_id: "bundle-1".into(),
        shadow_apply_state: ShadowApplyState::Ready,
        shadow_apply_checkpoint_index: 42,
        warmup_ready_ratio: ratio,
        updated_at_ms: updated_at,
    }
}

#[test]
fn barrier_ready_when_all_partitions_ready() {
    let barrier = barrier();
    let readiness = vec![record("p1", 0.9, 8_000), record("p2", 0.85, 8_500)];
    let decision = ActivationBarrierEvaluator::evaluate(&barrier, &readiness, 9_000).unwrap();
    assert!(matches!(decision.state, ActivationBarrierState::Ready));
    assert!(decision.readiness_digest.starts_with("0x"));
}

#[test]
fn barrier_pending_when_partition_missing_or_stale() {
    let barrier = barrier();
    let readiness = vec![record("p1", 0.9, 8_000)];
    let decision = ActivationBarrierEvaluator::evaluate(&barrier, &readiness, 9_000).unwrap();
    assert!(matches!(
        decision.state,
        ActivationBarrierState::Pending { .. }
    ));
    if let ActivationBarrierState::Pending { missing_partitions } = decision.state {
        assert_eq!(missing_partitions, &["p2".to_string()]);
    }
}

#[test]
fn barrier_expired_past_deadline() {
    let barrier = barrier();
    let readiness = vec![record("p1", 0.9, 8_000), record("p2", 0.85, 8_500)];
    let decision = ActivationBarrierEvaluator::evaluate(&barrier, &readiness, 11_000).unwrap();
    assert!(matches!(decision.state, ActivationBarrierState::Expired));
}

#[test]
fn readiness_digest_is_stable() {
    let records = vec![record("p1", 0.9, 8_000), record("p2", 0.5, 8_500)];
    let digest1 = readiness_digest(&records).unwrap();
    let digest2 = readiness_digest(&records).unwrap();
    assert_eq!(digest1, digest2);
    assert!(digest1.starts_with("0x"));
}

#[test]
fn publisher_tracks_skipped_publications() {
    let mut publisher = WarmupReadinessPublisher::new(1_000);
    publisher.upsert(record("p1", 0.5, 0));
    let snapshot = publisher.snapshot(0);
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(snapshot.skipped_publications_total, 0);
    let snapshot = publisher.snapshot(3_000);
    assert_eq!(snapshot.skipped_publications_total, 1);
}
