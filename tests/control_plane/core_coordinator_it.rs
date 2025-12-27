use clustor::control_plane::core::{
    CpCachePolicy, CpCacheState, CpProofCoordinator, CpUnavailableReason, ReadGateClause,
    ReadGateInputs,
};
use clustor::durability::recovery::RecoveryStatus;
use clustor::replication::consensus::{
    ConsensusCore, ConsensusCoreConfig, DurabilityProof, StrictFallbackBlockingReason,
    StrictFallbackState,
};
use clustor::telemetry::MetricsRegistry;
use clustor::CommitVisibility;
use std::time::{Duration, Instant};

#[test]
fn read_index_blocks_until_cp_ack() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(1, 10), now);

    let err = coordinator
        .guard_read_index(now + Duration::from_millis(1))
        .expect_err("ReadIndex should fail while LocalOnly");
    let response = err.response();
    assert_eq!(response.reason, CpUnavailableReason::NeededForReadIndex);
    assert_eq!(response.strict_state, StrictFallbackState::LocalOnly);
    assert!(response.explanation.is_some());
    assert_eq!(
        response.strict_fallback_blocking_reason,
        Some(StrictFallbackBlockingReason::NeededForReadIndex)
    );
    assert_eq!(response.decision_epoch, 1);
    assert_eq!(
        response.explanation.as_ref().unwrap().blocking_reason,
        StrictFallbackBlockingReason::NeededForReadIndex
    );

    coordinator.publish_cp_proof_at(DurabilityProof::new(1, 10), now);
    assert!(coordinator
        .guard_read_index(now + Duration::from_millis(2))
        .is_ok());
}

#[test]
fn read_index_permit_requires_predicate() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(2, 20), now);
    coordinator.publish_cp_proof_at(DurabilityProof::new(2, 20), now + Duration::from_millis(1));
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::DurableOnly,
        wal_committed_index: 20,
        raft_commit_index: 20,
    };
    let permit = coordinator
        .evaluate_read_index_permit(inputs, now + Duration::from_millis(2))
        .expect("predicate should pass");
    assert_eq!(permit.quorum_index, 20);
    assert!(coordinator.read_gate_status().can_serve);
}

#[test]
fn read_gate_reports_failed_clause() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(3, 30), now);
    coordinator.publish_cp_proof_at(DurabilityProof::new(3, 30), now + Duration::from_millis(1));
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::CommitAllowsPreDurable,
        wal_committed_index: 30,
        raft_commit_index: 30,
    };
    let err = coordinator
        .evaluate_read_index_permit(inputs, now + Duration::from_millis(2))
        .expect_err("predicate should reject");
    assert_eq!(
        err.response().reason,
        CpUnavailableReason::NeededForReadIndex
    );
    assert_eq!(
        coordinator.read_gate_status().failed_clause,
        Some(ReadGateClause::CommitVisibility)
    );
}

#[test]
fn read_gate_surfaces_index_gap() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(4, 40), now);
    coordinator.publish_cp_proof_at(DurabilityProof::new(4, 40), now + Duration::from_millis(1));
    let inputs = ReadGateInputs {
        commit_visibility: CommitVisibility::DurableOnly,
        wal_committed_index: 39,
        raft_commit_index: 40,
    };
    let err = coordinator
        .evaluate_read_index_permit(inputs, now + Duration::from_millis(2))
        .expect_err("index gap should block");
    assert_eq!(err.response().ledger_index, Some(39));
    assert_eq!(err.response().required_index, Some(40));
    assert_eq!(
        coordinator.read_gate_status().failed_clause,
        Some(ReadGateClause::IndexInequality)
    );
}

#[test]
fn read_gate_metrics_publish_status() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let coordinator = CpProofCoordinator::new(kernel);
    let mut registry = MetricsRegistry::new("clustor");
    coordinator.publish_read_gate_metrics(&mut registry);
    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot
            .gauges
            .get("clustor.cp.read_gate.failed_clause_present"),
        Some(&1)
    );
}

#[test]
fn cache_expiry_forces_cp_unavailable() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(1, 5), now);
    coordinator.set_cache_state(CpCacheState::Expired { age_ms: 400_000 });

    let err = coordinator
        .guard_read_index(now)
        .expect_err("cache expiry should block reads");
    let response = err.response();
    assert_eq!(response.reason, CpUnavailableReason::CacheExpired);
    assert!(response.explanation.is_none());
    assert_eq!(
        response.strict_fallback_blocking_reason,
        Some(StrictFallbackBlockingReason::CacheExpired)
    );
    assert_eq!(response.decision_epoch, 1);

    coordinator.set_cache_state(CpCacheState::Stale { age_ms: 270_000 });
    coordinator.load_local_ledger(DurabilityProof::new(2, 20), now);
    let err = coordinator
        .guard_read_index(now)
        .expect_err("LocalOnly should still block reads");
    assert_eq!(err.response().cache_warning_ms_remaining, Some(30_000));
}

#[test]
fn circuit_breaker_opens_and_recovers() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let mut now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(1, 10), now);
    let mut opened = None;
    for _ in 0..10 {
        let err = coordinator
            .guard_read_index(now)
            .expect_err("strict fallback should block");
        let response = err.response().clone();
        if response.reason == CpUnavailableReason::CircuitBreakerOpen {
            opened = Some(response);
            break;
        }
        now += Duration::from_millis(1);
    }
    let response = opened.expect("breaker should eventually open");
    assert_eq!(response.reason, CpUnavailableReason::CircuitBreakerOpen);
    assert_eq!(
        response.strict_fallback_blocking_reason,
        Some(StrictFallbackBlockingReason::CircuitBreakerOpen)
    );
    now += Duration::from_secs(10);
    coordinator.publish_cp_proof_at(DurabilityProof::new(1, 10), now);
    assert!(coordinator
        .guard_read_index(now + Duration::from_millis(1))
        .is_ok());
}

#[test]
fn recovery_status_forces_strict_mode() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    let status = RecoveryStatus {
        strict_required: true,
        truncation: None,
        proof: Some(DurabilityProof::new(4, 40)),
    };
    coordinator.apply_recovery_status(&status, now);
    let snapshot = coordinator.consensus_core_status(now);
    assert_eq!(snapshot.state, StrictFallbackState::LocalOnly);
    assert_eq!(
        snapshot.blocking_reason,
        Some(StrictFallbackBlockingReason::NeededForReadIndex)
    );
}

#[test]
fn recovery_status_noop_when_clean() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    let status = RecoveryStatus {
        strict_required: false,
        truncation: None,
        proof: Some(DurabilityProof::new(0, 0)),
    };
    coordinator.apply_recovery_status(&status, now);
    let snapshot = coordinator.consensus_core_status(now);
    assert_eq!(snapshot.state, StrictFallbackState::Healthy);
}

#[test]
fn proof_ttl_enforces_cache_expiry_and_metrics() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 500);
    let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
    let now = Instant::now();
    coordinator.publish_cp_proof_at(DurabilityProof::new(5, 50), now);
    let mut registry = MetricsRegistry::new("clustor");
    coordinator.publish_cache_metrics(&mut registry, now + Duration::from_millis(600));
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.gauges["clustor.cp.cache_age_ms"], 600);
    let state = coordinator.refresh_cache_state(now + Duration::from_millis(600));
    assert!(matches!(state, CpCacheState::Expired { .. }));
}

#[test]
fn strict_fallback_metrics_publish_through_coordinator() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let mut registry = MetricsRegistry::new("clustor");
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(8, 80), now);
    coordinator.consensus_core_mut().register_strict_write();
    coordinator.publish_strict_fallback_metrics(&mut registry, now + Duration::from_millis(1));
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.gauges["clustor.strict_fallback_state"], 1);
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_pending_entries"],
        1
    );
    assert_eq!(snapshot.gauges["clustor.strict_fallback_decision_epoch"], 1);
    assert_eq!(
        snapshot.gauges["clustor.strict_fallback_blocking_reason.None"],
        1
    );
}

#[test]
fn cache_refresh_due_follows_warning_window() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 800);
    let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
    let now = Instant::now();
    coordinator.publish_cp_proof_at(DurabilityProof::new(9, 90), now);
    assert!(
        !coordinator.cache_refresh_due(now + Duration::from_millis(200)),
        "warn threshold should not trigger early"
    );
    let warn_time = now + Duration::from_millis(650);
    assert!(
        coordinator.cache_refresh_due(warn_time),
        "warning should fire after cache_warn_ms"
    );
    coordinator.record_cache_refresh(warn_time);
    assert!(
        !coordinator.cache_refresh_due(warn_time + Duration::from_millis(10)),
        "manual refresh resets warning window"
    );
}

#[test]
fn read_index_permit_exposes_proof_and_cache_state() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(12, 120), now);
    coordinator.publish_cp_proof_at(DurabilityProof::new(12, 120), now);
    let permit = coordinator
        .guard_read_index_with_quorum(120, now + Duration::from_millis(1))
        .expect("permit should be granted");
    assert_eq!(permit.quorum_index, 120);
    assert_eq!(
        permit.last_published_proof,
        Some(DurabilityProof::new(12, 120))
    );
    assert!(matches!(permit.cache_state, CpCacheState::Fresh));
}

#[test]
fn read_gate_errors_track_cache_transitions() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 500);
    let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(4, 40), now);

    let err = coordinator
        .guard_read_index(now + Duration::from_millis(1))
        .expect_err("LocalOnly blocks read index");
    assert_eq!(
        err.response().reason,
        CpUnavailableReason::NeededForReadIndex
    );

    coordinator.publish_cp_proof_at(DurabilityProof::new(4, 40), now);
    assert!(coordinator
        .guard_read_index(now + Duration::from_millis(2))
        .is_ok());

    let expired_at = now + Duration::from_millis(600);
    let err = coordinator
        .guard_read_index(expired_at)
        .expect_err("expired cache blocks read index");
    assert_eq!(err.response().reason, CpUnavailableReason::CacheExpired);

    coordinator.record_cache_refresh(expired_at);
    assert!(coordinator
        .guard_read_index(expired_at + Duration::from_millis(1))
        .is_ok());
}

#[test]
fn ledger_gap_blocks_read_index() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(3, 30), now);
    coordinator.publish_cp_proof_at(DurabilityProof::new(3, 30), now);

    let err = coordinator
        .guard_read_index_with_quorum(10, now + Duration::from_millis(1))
        .expect_err("ledger gap should block");
    assert_eq!(err.response().ledger_index, Some(10));
    assert_eq!(err.response().required_index, Some(30));
    assert_eq!(
        err.response().strict_fallback_blocking_reason,
        Some(StrictFallbackBlockingReason::NeededForReadIndex)
    );
}

#[cfg(feature = "snapshot-crypto")]
#[test]
fn snapshot_import_guard_requires_local_only_state() {
    use clustor::control_plane::core::{
        StrictFallbackSnapshotImportError, StrictFallbackSnapshotImportReason,
    };

    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    let now = Instant::now();
    let err = coordinator
        .authorize_snapshot_import(
            StrictFallbackSnapshotImportReason::new("DRFailover").unwrap(),
            now,
        )
        .expect_err("imports require LocalOnly");
    assert!(matches!(
        err,
        StrictFallbackSnapshotImportError::StateNotLocalOnly { state }
        if state == StrictFallbackState::Healthy
    ));
}
