use crate::consensus::{ConsensusCoreStatus, StrictFallbackState, StrictFallbackWhy};
use crate::cp::CpCacheState;
use crate::raft::PartitionQuorumStatus;
#[cfg(feature = "snapshot-crypto")]
use crate::snapshot::{SnapshotDeltaChainTelemetry, SnapshotFallbackTelemetry, SnapshotReadError};
use crate::terminology::{RuntimeTerm, TERM_STRICT};
#[cfg(feature = "snapshot-crypto")]
use crate::terminology::{TERM_FOLLOWER_READ_SNAPSHOT, TERM_SNAPSHOT_DELTA};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct WhySchemaHeader {
    pub schema_version: u16,
    pub generated_at_ms: u64,
    pub partition_id: String,
    pub routing_epoch: u64,
    pub durability_mode_epoch: u64,
}

impl WhySchemaHeader {
    pub fn new(
        partition_id: impl Into<String>,
        routing_epoch: u64,
        durability_mode_epoch: u64,
        generated_at_ms: u64,
    ) -> Self {
        Self {
            schema_version: WHY_SCHEMA_VERSION,
            generated_at_ms,
            partition_id: partition_id.into(),
            routing_epoch,
            durability_mode_epoch,
        }
    }
}

const WHY_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LocalRole {
    Leader,
    Follower,
    Candidate,
}

#[derive(Debug, Clone, Serialize)]
pub struct WhyNotLeader {
    pub header: WhySchemaHeader,
    pub leader_id: Option<String>,
    pub local_role: LocalRole,
    pub strict_state: StrictFallbackState,
    pub cp_cache_state: CpCacheState,
    pub quorum_status: PartitionQuorumStatus,
    pub pending_entries: u64,
    pub runtime_terms: Vec<RuntimeTerm>,
    pub strict_fallback_why: Option<StrictFallbackWhy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_ids_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
}

impl WhyNotLeader {
    pub fn from_status(
        header: WhySchemaHeader,
        leader_id: Option<String>,
        local_role: LocalRole,
        cp_cache_state: CpCacheState,
        consensus: ConsensusCoreStatus,
        quorum_status: PartitionQuorumStatus,
        strict_fallback_why: Option<StrictFallbackWhy>,
    ) -> Self {
        Self {
            header,
            leader_id,
            local_role,
            strict_state: consensus.state,
            cp_cache_state,
            quorum_status,
            pending_entries: consensus.pending_entries,
            runtime_terms: vec![TERM_STRICT],
            strict_fallback_why,
            truncated_ids_count: None,
            continuation_token: None,
        }
    }

    pub fn with_truncation(
        mut self,
        truncated_ids_count: u32,
        continuation_token: Option<impl Into<String>>,
    ) -> Self {
        if truncated_ids_count > 0 {
            self.truncated_ids_count = Some(truncated_ids_count);
            self.continuation_token = continuation_token.map(|token| token.into());
        }
        self
    }
}

#[cfg(feature = "snapshot-crypto")]
#[derive(Debug, Clone, Serialize)]
pub struct WhySnapshotBlocked {
    pub header: WhySchemaHeader,
    pub manifest_id: String,
    pub fallback: SnapshotFallbackTelemetry,
    pub delta_chain: Option<SnapshotDeltaChainTelemetry>,
    pub error: SnapshotReadError,
    pub runtime_terms: Vec<RuntimeTerm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_ids_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
}

#[cfg(feature = "snapshot-crypto")]
impl WhySnapshotBlocked {
    pub fn new(
        header: WhySchemaHeader,
        manifest_id: impl Into<String>,
        fallback: SnapshotFallbackTelemetry,
        delta_chain: Option<SnapshotDeltaChainTelemetry>,
        error: SnapshotReadError,
    ) -> Self {
        let mut runtime_terms = vec![TERM_FOLLOWER_READ_SNAPSHOT];
        if delta_chain.is_some() {
            runtime_terms.push(TERM_SNAPSHOT_DELTA);
        }
        Self {
            header,
            manifest_id: manifest_id.into(),
            fallback,
            delta_chain,
            error,
            runtime_terms,
            truncated_ids_count: None,
            continuation_token: None,
        }
    }

    pub fn with_truncation(
        mut self,
        truncated_ids_count: u32,
        continuation_token: Option<impl Into<String>>,
    ) -> Self {
        if truncated_ids_count > 0 {
            self.truncated_ids_count = Some(truncated_ids_count);
            self.continuation_token = continuation_token.map(|token| token.into());
        }
        self
    }
}

#[cfg(all(test, feature = "snapshot-crypto"))]
mod tests {
    use super::*;
    use crate::consensus::{ConsensusCoreStatus, DemotionStatus, StrictFallbackBlockingReason};
    use crate::cp::CpCacheState;
    use crate::snapshot::SnapshotOnlyReadyState;

    fn consensus_status(state: StrictFallbackState) -> ConsensusCoreStatus {
        ConsensusCoreStatus {
            state,
            strict_fallback: matches!(state, StrictFallbackState::LocalOnly),
            pending_entries: 42,
            local_only_duration: None,
            should_alert: false,
            demotion: DemotionStatus::none(),
            last_local_proof: None,
            last_published_proof: None,
            decision_epoch: 7,
            blocking_reason: Some(StrictFallbackBlockingReason::NeededForReadIndex),
        }
    }

    #[test]
    fn why_not_leader_carries_runtime_terms() {
        let header = WhySchemaHeader::new("p1", 9, 3, 1234);
        let quorum = PartitionQuorumStatus {
            committed_index: 99,
            committed_term: 5,
            quorum_size: 3,
        };
        let why = WhyNotLeader::from_status(
            header,
            Some("leader-a".into()),
            LocalRole::Follower,
            CpCacheState::Fresh,
            consensus_status(StrictFallbackState::LocalOnly),
            quorum.clone(),
            None,
        );
        assert_eq!(why.quorum_status.committed_index, quorum.committed_index);
        assert!(why.runtime_terms.contains(&TERM_STRICT));
    }

    #[test]
    fn why_snapshot_blocked_infers_terms() {
        let header = WhySchemaHeader::new("p2", 11, 4, 5555);
        let telemetry = SnapshotFallbackTelemetry {
            partition_ready_ratio_snapshot: 0.5,
            snapshot_manifest_age_ms: 1_000,
            snapshot_only_ready_state: SnapshotOnlyReadyState::Degraded,
            snapshot_only_min_ready_ratio: 0.8,
            snapshot_only_slo_breach_total: 3,
        };
        let delta = SnapshotDeltaChainTelemetry {
            state: SnapshotDeltaChainState::Idle,
            chain_length: 2,
            last_manifest_id: Some("m1".into()),
            last_full_snapshot_ms: Some(100),
            last_snapshot_ms: Some(200),
        };
        let why = WhySnapshotBlocked::new(
            header,
            "manifest-x",
            telemetry.clone(),
            Some(delta.clone()),
            SnapshotReadError::SnapshotOnlyUnavailable,
        );
        assert_eq!(
            why.fallback.snapshot_only_ready_state,
            telemetry.snapshot_only_ready_state
        );
        assert!(why.runtime_terms.contains(&TERM_FOLLOWER_READ_SNAPSHOT));
        assert!(why.runtime_terms.contains(&TERM_SNAPSHOT_DELTA));
        assert_eq!(why.delta_chain.unwrap().chain_length, delta.chain_length);
    }

    #[test]
    fn why_schema_header_sets_version_and_epochs() {
        let header = WhySchemaHeader::new("p7", 4, 2, 42);
        assert_eq!(header.schema_version, WHY_SCHEMA_VERSION);
        assert_eq!(header.partition_id, "p7");
        assert_eq!(header.routing_epoch, 4);
        assert_eq!(header.durability_mode_epoch, 2);
    }

    #[test]
    fn why_not_leader_truncation_metadata_applies() {
        let header = WhySchemaHeader::new("p9", 2, 1, 999);
        let quorum = PartitionQuorumStatus {
            committed_index: 10,
            committed_term: 2,
            quorum_size: 3,
        };
        let why = WhyNotLeader::from_status(
            header,
            None,
            LocalRole::Follower,
            CpCacheState::Stale { age_ms: 5_000 },
            consensus_status(StrictFallbackState::LocalOnly),
            quorum,
            None,
        )
        .with_truncation(5, Some("token-1"));
        assert_eq!(why.truncated_ids_count, Some(5));
        assert_eq!(why.continuation_token.as_deref(), Some("token-1"));
    }

    #[test]
    fn why_snapshot_blocked_applies_truncation_metadata() {
        let header = WhySchemaHeader::new("p10", 3, 2, 123);
        let telemetry = SnapshotFallbackTelemetry {
            partition_ready_ratio_snapshot: 0.5,
            snapshot_manifest_age_ms: 1_000,
            snapshot_only_ready_state: SnapshotOnlyReadyState::Healthy,
            snapshot_only_min_ready_ratio: 0.8,
            snapshot_only_slo_breach_total: 1,
        };
        let why = WhySnapshotBlocked::new(
            header,
            "manifest-trunc",
            telemetry,
            None,
            SnapshotReadError::SnapshotOnlyUnavailable,
        )
        .with_truncation(3, None::<String>);
        assert_eq!(why.truncated_ids_count, Some(3));
        assert!(why.continuation_token.is_none());
    }

    use crate::snapshot::SnapshotDeltaChainState;
}
