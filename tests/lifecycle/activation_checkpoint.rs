use clustor::{
    readiness_digest, ActivationBarrier, ActivationBarrierEvaluator, ActivationBarrierState,
    ShadowApplyState, WarmupReadinessPublisher, WarmupReadinessRecord,
};

fn record(partition: &str, ratio: f64, updated_at_ms: u64) -> WarmupReadinessRecord {
    WarmupReadinessRecord {
        partition_id: partition.into(),
        bundle_id: "bundle-1".into(),
        shadow_apply_state: ShadowApplyState::Ready,
        shadow_apply_checkpoint_index: 42,
        warmup_ready_ratio: ratio,
        updated_at_ms,
    }
}

fn barrier() -> ActivationBarrier {
    ActivationBarrier {
        barrier_id: "barrier-1".into(),
        bundle_id: "bundle-1".into(),
        partitions: vec!["p1".into(), "p2".into()],
        readiness_threshold: 0.8,
        warmup_deadline_ms: 50_000,
        readiness_window_ms: 5_000,
    }
}

#[test]
fn activation_checkpoint_digest_matches_readiness_feed() {
    let mut publisher = WarmupReadinessPublisher::new(1_000);
    publisher.upsert(record("p1", 0.9, 40_000));
    publisher.upsert(record("p2", 0.85, 40_500));

    let snapshot = publisher.snapshot(41_000);
    let digest = readiness_digest(&snapshot.records).unwrap();
    let decision =
        ActivationBarrierEvaluator::evaluate(&barrier(), &snapshot.records, 41_000).unwrap();

    assert!(matches!(decision.state, ActivationBarrierState::Ready));
    assert_eq!(decision.readiness_digest, digest);
}

#[test]
fn activation_checkpoint_reports_pending_state_and_digest() {
    let mut publisher = WarmupReadinessPublisher::new(1_000);
    publisher.upsert(record("p1", 0.9, 10_000));
    // Missing p2 readiness

    let snapshot = publisher.snapshot(15_000);
    let decision =
        ActivationBarrierEvaluator::evaluate(&barrier(), &snapshot.records, 15_000).unwrap();
    match decision.state {
        ActivationBarrierState::Pending { missing_partitions } => {
            assert_eq!(missing_partitions, vec!["p2"]);
        }
        other => panic!("expected pending barrier, got {other:?}"),
    }
    assert_eq!(
        decision.readiness_digest,
        readiness_digest(&snapshot.records).unwrap()
    );
}
