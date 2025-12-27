use clustor::replication::consensus::{
    ConsensusCore, ConsensusCoreConfig, DurabilityProof, GateOperation, GateViolation,
    StrictFallbackBlockingReason, StrictFallbackMetricsPublisher, StrictFallbackState,
};
use clustor::telemetry::MetricsRegistry;
use std::time::{Duration, Instant};

#[test]
fn alert_and_demote_follow_configured_windows() {
    let config = ConsensusCoreConfig::new(Duration::from_secs(5), Duration::from_secs(10));
    let mut kernel = ConsensusCore::new(config);
    let now = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(1, 10), now);

    let before_alert = kernel.status(now + Duration::from_secs(4));
    assert!(!before_alert.should_alert);
    assert!(!before_alert.demotion.should_demote);

    let after_alert = kernel.status(now + Duration::from_secs(6));
    assert!(after_alert.should_alert);
    assert!(!after_alert.demotion.should_demote);

    let after_demote = kernel.status(now + Duration::from_secs(11));
    assert!(after_demote.demotion.should_demote);
    assert_eq!(
        after_demote.demotion.reason,
        Some(clustor::replication::consensus::DemotionReason::LocalOnlyTimeout)
    );
}

#[test]
fn override_pauses_local_only_demotion() {
    let config = ConsensusCoreConfig::new(Duration::from_secs(2), Duration::from_secs(5));
    let mut kernel = ConsensusCore::new(config);
    let start = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(2, 20), start);

    kernel.renew_local_only_override(Duration::from_secs(4), start + Duration::from_secs(3));
    let within_override = kernel.status(start + Duration::from_secs(6));
    assert!(within_override.should_alert);
    assert!(!within_override.demotion.should_demote);

    let after_override = kernel.status(start + Duration::from_secs(8));
    assert!(after_override.demotion.should_demote);
}

#[test]
fn pending_entries_only_increment_in_fallback() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    kernel.register_strict_write();
    assert_eq!(kernel.pending_entries(), 0);

    let now = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(1, 1), now);
    kernel.register_strict_write();
    kernel.register_strict_write();
    assert_eq!(kernel.pending_entries(), 2);

    kernel.mark_proof_published(DurabilityProof::new(1, 10));
    assert_eq!(kernel.pending_entries(), 0);
    assert!(!kernel.is_strict_fallback());
    assert!(matches!(
        kernel.state(),
        StrictFallbackState::ProofPublished
    ));
}

#[test]
fn strict_fallback_blocks_guarded_operations() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let now = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(4, 40), now);

    for (op, expected) in [
        (
            GateOperation::EnableGroupFsync,
            GateViolation::ModeConflictStrictFallback,
        ),
        (
            GateOperation::EnableLeaseReads,
            GateViolation::CpUnavailableNeededForReadIndex,
        ),
        (
            GateOperation::GrantFollowerReadSnapshotCapability,
            GateViolation::FollowerCapabilityRevoked,
        ),
        (
            GateOperation::EnableSnapshotDelta,
            GateViolation::CpUnavailableCacheExpired,
        ),
        (
            GateOperation::ReadIndex,
            GateViolation::CpUnavailableNeededForReadIndex,
        ),
    ] {
        let err = kernel
            .guard(op)
            .expect_err("operation unexpectedly allowed");
        assert_eq!(err, expected);
    }

    kernel.mark_proof_published(DurabilityProof::new(4, 50));
    for op in [
        GateOperation::EnableGroupFsync,
        GateOperation::GrantFollowerReadSnapshotCapability,
        GateOperation::EnableSnapshotDelta,
        GateOperation::ReadIndex,
    ] {
        assert!(kernel.guard(op).is_ok());
    }
}

#[test]
fn strict_fallback_truth_table_matches_spec() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let now = Instant::now();

    assert_eq!(kernel.state(), StrictFallbackState::Healthy);
    for &op in all_operations() {
        assert!(
            kernel.guard(op).is_ok(),
            "operation {:?} should pass while Healthy",
            op
        );
    }

    kernel.enter_strict_fallback(DurabilityProof::new(9, 90), now);
    assert!(kernel.is_strict_fallback());

    for (op, violation) in [
        (
            GateOperation::EnableGroupFsync,
            GateViolation::ModeConflictStrictFallback,
        ),
        (
            GateOperation::EnableLeaseReads,
            GateViolation::CpUnavailableNeededForReadIndex,
        ),
        (
            GateOperation::GrantFollowerReadSnapshotCapability,
            GateViolation::FollowerCapabilityRevoked,
        ),
        (
            GateOperation::EnableSnapshotDelta,
            GateViolation::CpUnavailableCacheExpired,
        ),
        (
            GateOperation::ReadIndex,
            GateViolation::CpUnavailableNeededForReadIndex,
        ),
    ] {
        let eval = kernel.evaluate_gate(op);
        assert!(
            !eval.allowed,
            "operation {:?} should be blocked while LocalOnly",
            op
        );
        assert_eq!(eval.violation, Some(violation));

        let explanation = kernel
            .explain_gate(&eval, now + Duration::from_secs(1))
            .expect("blocked operations must have a Why payload");
        assert_eq!(explanation.operation, op);
        assert_eq!(explanation.violation, violation);
        assert_eq!(explanation.state, StrictFallbackState::LocalOnly);
        assert_eq!(
            explanation.last_local_proof,
            Some(DurabilityProof::new(9, 90))
        );
        assert_eq!(explanation.pending_entries, kernel.pending_entries());
        assert_eq!(explanation.decision_epoch, kernel.decision_epoch());
    }

    kernel.mark_proof_published(DurabilityProof::new(10, 120));
    assert_eq!(kernel.state(), StrictFallbackState::ProofPublished);
    assert!(!kernel.is_strict_fallback());
    for &op in all_operations() {
        assert!(
            kernel.guard(op).is_ok(),
            "operation {:?} should unblock once ProofPublished",
            op
        );
    }
}

#[test]
fn telemetry_and_why_surfaces_reflect_state() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let start = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(6, 60), start);

    kernel
        .guard(GateOperation::EnableGroupFsync)
        .expect_err("group fsync should be gated");
    kernel
        .guard(GateOperation::GrantFollowerReadSnapshotCapability)
        .expect_err("follower capability should be gated");

    let snapshot = kernel.telemetry(start + Duration::from_secs(1));
    assert!(snapshot.blocking_read_index);
    assert_eq!(snapshot.gate_blocks.durability_transition_to_group, 1);
    assert_eq!(snapshot.gate_blocks.follower_capability_grant, 1);

    let evaluation = kernel.evaluate_gate(GateOperation::EnableSnapshotDelta);
    let why = kernel
        .explain_gate(&evaluation, start + Duration::from_secs(2))
        .expect("should surface gate reason");
    assert_eq!(why.operation, GateOperation::EnableSnapshotDelta);
    assert_eq!(why.violation, GateViolation::CpUnavailableCacheExpired);
    assert_eq!(why.state, StrictFallbackState::LocalOnly);

    kernel.record_gate_block(&evaluation);
    let later = kernel.telemetry(start + Duration::from_secs(3));
    assert_eq!(later.gate_blocks.snapshot_delta_enable, 1);
    assert_eq!(
        later.blocking_reason,
        Some(StrictFallbackBlockingReason::CacheExpired)
    );

    kernel.mark_proof_published(DurabilityProof::new(7, 70));
    let healthy_eval = kernel.evaluate_gate(GateOperation::EnableGroupFsync);
    assert!(kernel
        .explain_gate(&healthy_eval, start + Duration::from_secs(4))
        .is_none());
}

#[test]
fn metrics_publisher_exports_spec_fields() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let start = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(3, 30), start);
    kernel.register_strict_write();
    kernel.register_strict_write();

    for op in [
        GateOperation::EnableGroupFsync,
        GateOperation::EnableLeaseReads,
        GateOperation::GrantFollowerReadSnapshotCapability,
        GateOperation::EnableSnapshotDelta,
    ] {
        kernel
            .guard(op)
            .expect_err("strict fallback should block gate operations");
    }

    let mut registry = MetricsRegistry::new("clustor");
    let mut publisher = StrictFallbackMetricsPublisher::new();
    publisher.publish(
        &mut registry,
        &kernel.telemetry(start + Duration::from_secs(1)),
    );

    let snapshot = registry.snapshot();
    assert_eq!(snapshot.gauges["clustor.strict_fallback_state"], 1);
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_pending_entries"],
        2
    );
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_last_local_proof.term"],
        3
    );

    publisher.publish(
        &mut registry,
        &kernel.telemetry(start + Duration::from_secs(2)),
    );
    let snapshot2 = registry.snapshot();
    assert_eq!(
        snapshot2.counters["clustor.strict_fallback_gate_blocked.SnapshotDeltaEnable"],
        1
    );
}

#[test]
fn decision_epoch_tracks_transitions_and_overrides() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let start = Instant::now();
    assert_eq!(kernel.decision_epoch(), 0);

    kernel.enter_strict_fallback(DurabilityProof::new(1, 1), start);
    assert_eq!(kernel.decision_epoch(), 1);

    kernel.renew_local_only_override(Duration::from_secs(5), start);
    assert_eq!(kernel.decision_epoch(), 2);

    kernel.clear_local_only_override();
    assert_eq!(kernel.decision_epoch(), 3);

    let eval = kernel.evaluate_gate(GateOperation::EnableSnapshotDelta);
    kernel.record_gate_block(&eval);
    assert_eq!(
        kernel.blocking_reason(),
        Some(StrictFallbackBlockingReason::CacheExpired)
    );

    kernel.mark_proof_published(DurabilityProof::new(1, 10));
    assert_eq!(kernel.decision_epoch(), 4);
    assert_eq!(kernel.blocking_reason(), None);

    kernel.mark_healthy();
    assert_eq!(kernel.decision_epoch(), 5);
}

#[test]
fn state_snapshot_reflects_gate_state() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let now = Instant::now();
    kernel.enter_strict_fallback(DurabilityProof::new(2, 20), now);
    kernel.register_strict_write();

    let eval = kernel.evaluate_gate(GateOperation::EnableGroupFsync);
    kernel.record_gate_block(&eval);

    let snapshot = kernel.snapshot_state();
    assert_eq!(snapshot.state, StrictFallbackState::LocalOnly);
    assert!(snapshot.strict_fallback);
    assert_eq!(snapshot.pending_entries, 1);
    assert_eq!(snapshot.last_local_proof, Some(DurabilityProof::new(2, 20)));
    assert_eq!(snapshot.last_published_proof, None);
    assert_eq!(
        snapshot.blocking_reason,
        Some(StrictFallbackBlockingReason::ModeConflictStrictFallback)
    );
    assert_eq!(snapshot.decision_epoch, kernel.decision_epoch());

    kernel.mark_proof_published(DurabilityProof::new(3, 30));
    let cleared = kernel.snapshot_state();
    assert_eq!(cleared.state, StrictFallbackState::ProofPublished);
    assert!(!cleared.strict_fallback);
    assert_eq!(cleared.pending_entries, 0);
    assert_eq!(
        cleared.last_published_proof,
        Some(DurabilityProof::new(3, 30))
    );
    assert!(cleared.blocking_reason.is_none());
    assert!(cleared.decision_epoch > snapshot.decision_epoch);
}

fn all_operations() -> &'static [GateOperation] {
    &[
        GateOperation::EnableGroupFsync,
        GateOperation::EnableLeaseReads,
        GateOperation::GrantFollowerReadSnapshotCapability,
        GateOperation::EnableSnapshotDelta,
        GateOperation::ReadIndex,
    ]
}
