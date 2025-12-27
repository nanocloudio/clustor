use crate::control_plane::core::CpCacheState;
use crate::replication::consensus::{ConsensusCoreStatus, StrictFallbackState, StrictFallbackWhy};
use crate::replication::raft::PartitionQuorumStatus;
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
