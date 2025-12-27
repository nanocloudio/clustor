#![cfg(feature = "snapshot-crypto")]

#[path = "../support/persistence/snapshot_follower_data.rs"]
mod snapshot_follower_data;

use clustor::persistence::snapshot::{
    FollowerCapabilityGate, FollowerReadError, FollowerSnapshotReadError,
    SnapshotFallbackController, SnapshotReadRequest,
};
use clustor::replication::consensus::{
    ConsensusCore, ConsensusCoreConfig, DurabilityProof, StrictFallbackState,
};
use snapshot_follower_data::readiness;
use std::time::Instant;

#[test]
fn follower_reads_require_capability_and_healthy_state() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut gate = FollowerCapabilityGate::new();

    kernel.enter_strict_fallback(DurabilityProof::new(1, 1), Instant::now());
    assert_eq!(
        gate.ensure_follower_read_allowed(&mut kernel),
        Err(FollowerReadError::CapabilityRevoked)
    );

    kernel.mark_proof_published(DurabilityProof::new(1, 1));
    assert_eq!(
        gate.ensure_follower_read_allowed(&mut kernel),
        Err(FollowerReadError::CapabilityMissing)
    );

    gate.set_follower_read_capability(true);
    assert!(gate.ensure_follower_read_allowed(&mut kernel).is_ok());
}

#[test]
fn snapshot_delta_requires_enabled_flag() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut gate = FollowerCapabilityGate::new();
    gate.set_snapshot_delta_enabled(false);
    assert_eq!(
        gate.ensure_snapshot_delta_allowed(&mut kernel),
        Err(FollowerReadError::SnapshotDeltaDisabled)
    );
    gate.set_snapshot_delta_enabled(true);
    assert!(gate.ensure_snapshot_delta_allowed(&mut kernel).is_ok());
}

#[test]
fn snapshot_reads_fail_when_capability_revoked() {
    let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    kernel.mark_proof_published(DurabilityProof::new(1, 1));
    let mut gate = FollowerCapabilityGate::new();
    gate.set_follower_read_capability(true);
    let controller = SnapshotFallbackController::new(readiness());
    let request = SnapshotReadRequest {
        partition_id: "p1".into(),
        read_semantics_snapshot_only: true,
        strict_state: StrictFallbackState::ProofPublished,
        cp_cache_age_ms: 10,
    };
    let response = gate
        .serve_snapshot_read(&mut kernel, &controller, request.clone())
        .expect("snapshot read should succeed");
    assert!(response.headers.snapshot_only);
    kernel.enter_strict_fallback(DurabilityProof::new(2, 10), Instant::now());
    let err = gate
        .serve_snapshot_read(&mut kernel, &controller, request)
        .expect_err("revoked capability should fail");
    assert_eq!(
        err,
        FollowerSnapshotReadError::Capability(FollowerReadError::CapabilityRevoked)
    );
}
