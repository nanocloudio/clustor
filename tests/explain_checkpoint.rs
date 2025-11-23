#![cfg(feature = "snapshot-crypto")]

use clustor::consensus::{
    ConsensusCoreStatus, DemotionStatus, StrictFallbackBlockingReason, StrictFallbackState,
};
use clustor::cp::CpCacheState;
use clustor::raft::PartitionQuorumStatus;
use clustor::snapshot::{SnapshotFallbackTelemetry, SnapshotOnlyReadyState, SnapshotReadError};
use clustor::why::{LocalRole, WhyNotLeader, WhySchemaHeader, WhySnapshotBlocked};
use serde_json::json;
use std::time::Duration;

fn consensus_status(state: StrictFallbackState) -> ConsensusCoreStatus {
    ConsensusCoreStatus {
        state,
        strict_fallback: matches!(state, StrictFallbackState::LocalOnly),
        pending_entries: 7,
        local_only_duration: Some(Duration::from_secs(2)),
        should_alert: false,
        demotion: DemotionStatus::none(),
        last_local_proof: None,
        last_published_proof: None,
        decision_epoch: 4,
        blocking_reason: Some(StrictFallbackBlockingReason::NeededForReadIndex),
    }
}

#[test]
fn explain_checkpoint_serializes_why_not_leader_snapshot() {
    let header = WhySchemaHeader::new("partition-a", 5, 3, 4_567);
    let quorum = PartitionQuorumStatus {
        committed_index: 512,
        committed_term: 8,
        quorum_size: 3,
    };
    let report = WhyNotLeader::from_status(
        header,
        Some("leader-x".into()),
        LocalRole::Follower,
        CpCacheState::Cached { age_ms: 15_000 },
        consensus_status(StrictFallbackState::LocalOnly),
        quorum,
        None,
    )
    .with_truncation(2, Some("continuation-a"));
    let json = serde_json::to_value(&report).expect("serde renders why");
    assert_eq!(json["header"]["partition_id"], json!("partition-a"));
    assert_eq!(json["leader_id"], json!("leader-x"));
    assert_eq!(json["continuation_token"], json!("continuation-a"));
    assert_eq!(json["truncated_ids_count"], json!(2));
    assert!(!json["runtime_terms"].as_array().unwrap().is_empty());
}

#[test]
fn explain_checkpoint_serializes_why_snapshot_blocked_snapshot() {
    let header = WhySchemaHeader::new("partition-b", 9, 4, 9_999);
    let fallback = SnapshotFallbackTelemetry {
        partition_ready_ratio_snapshot: 0.4,
        snapshot_manifest_age_ms: 10_000,
        snapshot_only_ready_state: SnapshotOnlyReadyState::Degraded,
        snapshot_only_min_ready_ratio: 0.8,
        snapshot_only_slo_breach_total: 2,
    };
    let report = WhySnapshotBlocked::new(
        header,
        "manifest-123",
        fallback,
        None,
        SnapshotReadError::SnapshotOnlyUnavailable,
    )
    .with_truncation(1, None::<String>);
    let json = serde_json::to_value(&report).expect("serde renders snapshot");
    assert_eq!(json["header"]["partition_id"], json!("partition-b"));
    assert_eq!(json["manifest_id"], json!("manifest-123"));
    assert_eq!(json["truncated_ids_count"], json!(1));
    assert!(json["runtime_terms"].is_array());
}
