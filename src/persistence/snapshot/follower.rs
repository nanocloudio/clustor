//! Follower read capability gating.

use crate::replication::consensus::{ConsensusCore, GateOperation, GateViolation};
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
