#![cfg(feature = "net")]

use clustor::control_plane::core::CpCacheState;
use clustor::net::control_plane::why::{LocalRole, WhyNotLeader, WhySchemaHeader};
use clustor::replication::consensus::{
    ConsensusCoreStatus, DemotionStatus, StrictFallbackBlockingReason, StrictFallbackState,
};
use clustor::replication::raft::PartitionQuorumStatus;
use clustor::terminology::TERM_STRICT;

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
    let header = WhySchemaHeader::new("p1", 9, 3, 1_234);
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
fn why_schema_header_sets_version_and_epochs() {
    let header = WhySchemaHeader::new("p7", 4, 2, 42);
    assert_eq!(header.partition_id, "p7");
    assert_eq!(header.routing_epoch, 4);
    assert_eq!(header.durability_mode_epoch, 2);
    assert_eq!(header.schema_version, 1);
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

#[cfg(feature = "snapshot-crypto")]
mod snapshot_tests {
    use super::*;
    use clustor::{
        SnapshotDeltaChainState, SnapshotDeltaChainTelemetry, SnapshotFallbackTelemetry,
        SnapshotOnlyReadyState, SnapshotReadError, WhySnapshotBlocked,
    };

    #[test]
    fn why_snapshot_blocked_infers_terms() {
        let header = WhySchemaHeader::new("p2", 11, 4, 5_555);
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
        assert!(why
            .runtime_terms
            .contains(&clustor::terminology::TERM_FOLLOWER_READ_SNAPSHOT));
        assert!(why
            .runtime_terms
            .contains(&clustor::terminology::TERM_SNAPSHOT_DELTA));
        assert_eq!(why.delta_chain.unwrap().chain_length, delta.chain_length);
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
}
