//! Follower read capability gating.

use crate::consensus::{ConsensusCore, GateOperation};
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
        if kernel
            .guard(GateOperation::GrantFollowerReadSnapshotCapability)
            .is_err()
        {
            return Err(FollowerReadError::StrictFallback);
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
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FollowerReadError {
    #[error("follower_read_snapshot_capability not granted")]
    CapabilityMissing,
    #[error("snapshot delta APIs disabled")]
    SnapshotDeltaDisabled,
    #[error("strict fallback prohibits follower reads")]
    StrictFallback,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{ConsensusCore, ConsensusCoreConfig, DurabilityProof};
    use std::time::Instant;

    #[test]
    fn follower_reads_require_capability_and_healthy_state() {
        let mut kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut gate = FollowerCapabilityGate::new();

        kernel.enter_strict_fallback(DurabilityProof::new(1, 1), Instant::now());
        assert_eq!(
            gate.ensure_follower_read_allowed(&mut kernel),
            Err(FollowerReadError::StrictFallback)
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
}
