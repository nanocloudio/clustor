//! Follower read capability gating.

use crate::consensus::{ConsensusCore, GateOperation, GateViolation};
use crate::snapshot::{
    SnapshotFallbackController, SnapshotReadError, SnapshotReadRequest, SnapshotReadResponse,
};
use thiserror::Error;

#[derive(Debug, Default)]
pub struct FollowerCapabilityGate {
    follower_read_snapshot_capability: bool,
    snapshot_delta_enabled: bool,
}

impl FollowerCapabilityGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_follower_read_capability(&mut self, granted: bool) {
        self.follower_read_snapshot_capability = granted;
    }

    pub fn set_snapshot_delta_enabled(&mut self, enabled: bool) {
        self.snapshot_delta_enabled = enabled;
    }

    pub fn ensure_follower_read_allowed(
        &self,
        kernel: &mut ConsensusCore,
    ) -> Result<(), FollowerReadError> {
        match kernel.guard(GateOperation::GrantFollowerReadSnapshotCapability) {
            Ok(_) => {}
            Err(GateViolation::FollowerCapabilityRevoked) => {
                return Err(FollowerReadError::CapabilityRevoked);
            }
            Err(_) => return Err(FollowerReadError::StrictFallback),
        }
        if !self.follower_read_snapshot_capability {
            return Err(FollowerReadError::CapabilityMissing);
        }
        Ok(())
    }

    pub fn ensure_snapshot_delta_allowed(
        &self,
        kernel: &mut ConsensusCore,
    ) -> Result<(), FollowerReadError> {
        if kernel.guard(GateOperation::EnableSnapshotDelta).is_err() {
            return Err(FollowerReadError::StrictFallback);
        }
        if !self.snapshot_delta_enabled {
            return Err(FollowerReadError::SnapshotDeltaDisabled);
        }
        Ok(())
    }

    pub fn serve_snapshot_read(
        &self,
        kernel: &mut ConsensusCore,
        controller: &SnapshotFallbackController,
        request: SnapshotReadRequest,
    ) -> Result<SnapshotReadResponse, FollowerSnapshotReadError> {
        self.ensure_follower_read_allowed(kernel)?;
        controller
            .handle_request(request)
            .map_err(FollowerSnapshotReadError::Snapshot)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FollowerReadError {
    #[error("follower_read_snapshot_capability not granted")]
    CapabilityMissing,
    #[error("follower read capability revoked by strict fallback")]
    CapabilityRevoked,
    #[error("snapshot delta APIs disabled")]
    SnapshotDeltaDisabled,
    #[error("strict fallback prohibits follower reads")]
    StrictFallback,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FollowerSnapshotReadError {
    #[error(transparent)]
    Capability(#[from] FollowerReadError),
    #[error("snapshot fallback rejected request: {0:?}")]
    Snapshot(SnapshotReadError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ConsensusCore, ConsensusCoreConfig, DurabilityProof, StrictFallbackState,
    };
    use crate::snapshot::{SnapshotFallbackController, SnapshotReadRequest, SnapshotReadiness};
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

    fn snapshot_readiness() -> SnapshotReadiness {
        SnapshotReadiness {
            manifest_id: "m-1".into(),
            base_index: 1,
            content_hash: "digest".into(),
            applied_index_snapshot: 100,
            last_advertised_ready_index: 100,
            manifest_generated_ms: 1,
        }
    }

    #[test]
    fn snapshot_reads_fail_when_capability_revoked() {
        let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        kernel.mark_proof_published(DurabilityProof::new(1, 1));
        let mut gate = FollowerCapabilityGate::new();
        gate.set_follower_read_capability(true);
        let controller = SnapshotFallbackController::new(snapshot_readiness());
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
}
