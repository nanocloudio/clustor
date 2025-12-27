#![cfg(feature = "snapshot-crypto")]

#[path = "../support/persistence/snapshot_fallback_data.rs"]
mod snapshot_fallback_data;

use clustor::consensus::StrictFallbackState;
use clustor::persistence::snapshot::{
    SnapshotDeltaPolicy, SnapshotDeltaPolicyError, SnapshotFallbackController, SnapshotReadError,
    SnapshotTrigger, SnapshotTriggerConfig, SnapshotTriggerReason,
};
use clustor::SnapshotReadiness;
use snapshot_fallback_data::{full_delta, manifest, read_request, readiness};

#[test]
fn snapshot_fallback_requires_header() {
    let controller = SnapshotFallbackController::new(readiness());
    let err = controller
        .handle_request(read_request(false, StrictFallbackState::LocalOnly))
        .unwrap_err();
    assert!(matches!(err, SnapshotReadError::MissingSnapshotOnlyHeader));
}

#[test]
fn snapshot_fallback_requires_allowed_strict_state() {
    let controller = SnapshotFallbackController::new(readiness());
    let err = controller
        .handle_request(read_request(true, StrictFallbackState::Healthy))
        .unwrap_err();
    assert!(matches!(
        err,
        SnapshotReadError::StrictStateUnavailable { .. }
    ));
}

#[test]
fn snapshot_fallback_enforces_min_ratio() {
    let mut controller = SnapshotFallbackController::new(readiness());
    controller.update_readiness(clustor::SnapshotReadiness {
        applied_index_snapshot: 40,
        manifest_generated_ms: readiness().manifest_generated_ms,
        ..readiness()
    });
    let err = controller
        .handle_request(read_request(true, StrictFallbackState::LocalOnly))
        .unwrap_err();
    assert!(matches!(err, SnapshotReadError::SnapshotOnlyUnavailable));
}

#[test]
fn snapshot_fallback_rejects_when_metrics_absent() {
    let controller = SnapshotFallbackController::new(SnapshotReadiness {
        last_advertised_ready_index: 0,
        applied_index_snapshot: 0,
        ..readiness()
    });
    let err = controller
        .handle_request(read_request(true, StrictFallbackState::LocalOnly))
        .unwrap_err();
    assert!(matches!(err, SnapshotReadError::SnapshotOnlyUnavailable));
}

#[test]
fn snapshot_fallback_returns_manifest_details() {
    let controller = SnapshotFallbackController::new(readiness());
    let response = controller
        .handle_request(read_request(true, StrictFallbackState::ProofPublished))
        .expect("fallback succeeds");
    assert_eq!(response.manifest_id, "m1");
    assert_eq!(response.base_index, 100);
    assert!(response.readiness_ratio >= 0.9);
    assert!(response.headers.snapshot_only);
}

#[test]
fn snapshot_trigger_honors_thresholds() {
    let mut trigger = SnapshotTrigger::new(SnapshotTriggerConfig::default());
    let under = trigger.evaluate(clustor::SNAPSHOT_LOG_BYTES_TARGET - 1, 0, 1_000);
    assert!(!under.should_trigger);

    let log_trigger = trigger.evaluate(clustor::SNAPSHOT_LOG_BYTES_TARGET, 0, 2_000);
    assert!(matches!(
        log_trigger.reason,
        Some(SnapshotTriggerReason::LogBytes)
    ));
    trigger.record_snapshot(2_000);

    let interval_trigger = trigger.evaluate(0, 0, 2_000 + clustor::SNAPSHOT_MAX_INTERVAL_MS);
    assert!(matches!(
        interval_trigger.reason,
        Some(SnapshotTriggerReason::Interval)
    ));
    trigger.record_snapshot(3_000);

    let lag_trigger = trigger.evaluate(
        0,
        clustor::SNAPSHOT_CATCHUP_THRESHOLD_BYTES,
        3_000 + clustor::SNAPSHOT_MAX_INTERVAL_MS / 2,
    );
    assert!(matches!(
        lag_trigger.reason,
        Some(SnapshotTriggerReason::FollowerLag)
    ));
    let telemetry = trigger.telemetry(3_500);
    assert_eq!(
        telemetry.pending_reason,
        Some(SnapshotTriggerReason::FollowerLag)
    );
    assert_eq!(telemetry.last_snapshot_ms, 3_000);
}

#[test]
fn snapshot_fallback_telemetry_tracks_ready_state() {
    let mut controller = SnapshotFallbackController::new(readiness());
    let telemetry = controller.telemetry(2_000);
    assert!(matches!(
        telemetry.snapshot_only_ready_state,
        clustor::SnapshotOnlyReadyState::Healthy
    ));
    assert_eq!(telemetry.snapshot_manifest_age_ms, 1_000);

    controller.update_readiness(clustor::SnapshotReadiness {
        applied_index_snapshot: 10,
        manifest_generated_ms: 500,
        ..readiness()
    });
    let degraded = controller.telemetry(2_500);
    assert!(matches!(
        degraded.snapshot_only_ready_state,
        clustor::SnapshotOnlyReadyState::Degraded
    ));

    controller.record_snapshot_only_result(500, true, 2_500);
    let after_breach = controller.telemetry(2_800);
    assert!(after_breach.snapshot_only_slo_breach_total >= 1);
}

#[test]
fn snapshot_delta_policy_enforces_chain_and_windows() {
    let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
    policy.set_profile_capability(true);
    policy.set_cp_gate(true);

    let mut full = manifest();
    full.manifest_id = "full".into();
    assert!(matches!(
        policy.record_manifest(&full_delta("d1", "full", 1), 0),
        Err(SnapshotDeltaPolicyError::FullSnapshotUnknown)
    ));

    policy.record_manifest(&full, 0).expect("full allowed");
    let delta = full_delta("d1", "full", 1);
    policy
        .record_manifest(&delta, 5_000)
        .expect("delta allowed");
    assert!(matches!(
        policy.record_manifest(&full_delta("d2", "d1", 2), 20_000),
        Err(SnapshotDeltaPolicyError::DeltaEmitWindowExceeded)
    ));

    policy
        .record_manifest(&full_delta("d2", "d1", 2), 8_000)
        .expect("second delta allowed");
    assert!(matches!(
        policy.record_manifest(&full_delta("overflow", "d2", 3), 9_000),
        Err(SnapshotDeltaPolicyError::DeltaChainExceeded { .. })
    ));

    let mut gated = SnapshotDeltaPolicy::new(1, 10_000, 30_000);
    assert!(matches!(
        gated.record_manifest(&full_delta("d1", "full", 1), 0),
        Err(SnapshotDeltaPolicyError::DeltaDisabled)
    ));
    gated.record_manifest(&full, 0).expect("full allowed");
    assert!(matches!(
        gated.record_manifest(&full_delta("d2", "d1", 1), 1_000),
        Err(SnapshotDeltaPolicyError::DeltaDisabled)
    ));
}

#[test]
fn snapshot_delta_policy_reports_telemetry_states() {
    let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
    policy.set_profile_capability(true);
    policy.set_cp_gate(true);
    let mut full = manifest();
    full.manifest_id = "full".into();
    policy.record_manifest(&full, 0).expect("full allowed");
    let telemetry = policy.telemetry();
    assert_eq!(telemetry.state, clustor::SnapshotDeltaChainState::Idle);

    let delta = full_delta("d1", "full", 1);
    policy
        .record_manifest(&delta, 1_000)
        .expect("delta allowed");
    let telemetry = policy.telemetry();
    assert_eq!(telemetry.state, clustor::SnapshotDeltaChainState::Building);
    assert_eq!(telemetry.chain_length, 1);

    let bad_delta = full_delta("d2", "unknown", 2);
    let err = policy
        .record_manifest(&bad_delta, 1_500)
        .expect_err("stale parent rejected");
    assert!(matches!(
        err,
        SnapshotDeltaPolicyError::DeltaParentMismatch { .. }
    ));
    assert_eq!(
        policy.telemetry().state,
        clustor::SnapshotDeltaChainState::Orphaned
    );
}
