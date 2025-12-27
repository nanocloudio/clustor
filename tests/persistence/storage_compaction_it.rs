use clustor::persistence::storage::compaction::{
    authorization_chain_hash, compute_compaction_floor, CompactionBlockReason, CompactionDecision,
    CompactionGate, CompactionPlanRequest, CompactionState, ManifestAuthorizationLog, ManifestGate,
    SegmentHealth, SnapshotAuthorizationRecord,
};
use clustor::persistence::storage::layout::CompactionAuthAck;
use tempfile::TempDir;

fn compaction_state(
    quorum_applied: u64,
    snapshot_base: u64,
    quorum_sm_durable: u64,
    manifest_gate: ManifestGate,
) -> CompactionState {
    CompactionState {
        learner_slack_floor: None,
        quorum_applied_index: quorum_applied,
        snapshot_base_index: snapshot_base,
        quorum_sm_durable_index: quorum_sm_durable,
        guard_bytes_satisfied: true,
        learner_retirement_pending: false,
        manifest_gate,
    }
}

fn manifest_gate(record: Option<SnapshotAuthorizationRecord>) -> ManifestGate {
    ManifestGate {
        relisted: record.is_some(),
        signature_valid: record.is_some(),
        acknowledgement: record
            .as_ref()
            .map(|rec| CompactionAuthAck::from_record(rec, None, 0)),
        authorization: record,
    }
}

#[test]
fn compaction_blocks_when_manifest_missing() {
    let state = compaction_state(
        100,
        90,
        100,
        ManifestGate {
            relisted: false,
            signature_valid: false,
            authorization: None,
            acknowledgement: None,
        },
    );
    let request = CompactionPlanRequest {
        state,
        segments: Vec::new(),
    };
    let decision = CompactionGate::plan(request);
    assert!(matches!(
        decision,
        CompactionDecision::Blocked(reasons)
        if reasons.iter().any(|reason| matches!(reason, CompactionBlockReason::ManifestMissing))
    ));
}

#[test]
fn compaction_blocks_when_snapshot_base_not_durable() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m1".into(),
        base_index: 90,
        auth_seq: 5,
        manifest_hash: "abc".into(),
        recorded_at_ms: 0,
        chain_hash: authorization_chain_hash(None, "m1", 5, "abc"),
    };
    let state = compaction_state(100, 90, 80, manifest_gate(Some(record)));
    let request = CompactionPlanRequest {
        state,
        segments: Vec::new(),
    };
    let decision = CompactionGate::plan(request);
    assert!(matches!(
        decision,
        CompactionDecision::Blocked(reasons)
        if reasons.iter().any(|reason| matches!(reason, CompactionBlockReason::SnapshotBaseNotDurable { .. }))
    ));
}

#[test]
fn compaction_ready_skips_nonce_and_rewrite_segments() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m1".into(),
        base_index: 90,
        auth_seq: 7,
        manifest_hash: "abc".into(),
        recorded_at_ms: 0,
        chain_hash: authorization_chain_hash(None, "m1", 7, "abc"),
    };
    let segments = vec![
        SegmentHealth {
            segment_seq: 1,
            max_index_in_segment: 80,
            has_pending_nonce_reservation: false,
            abandon_record_present: false,
            rewrite_inflight: false,
        },
        SegmentHealth {
            segment_seq: 2,
            max_index_in_segment: 70,
            has_pending_nonce_reservation: true,
            abandon_record_present: false,
            rewrite_inflight: false,
        },
        SegmentHealth {
            segment_seq: 3,
            max_index_in_segment: 60,
            has_pending_nonce_reservation: false,
            abandon_record_present: false,
            rewrite_inflight: true,
        },
    ];
    let request = CompactionPlanRequest {
        state: compaction_state(100, 90, 120, manifest_gate(Some(record))),
        segments,
    };
    let decision = CompactionGate::plan(request);
    match decision {
        CompactionDecision::Ready {
            floor_effective,
            deletable_segments,
            skipped_segments,
        } => {
            assert_eq!(floor_effective, 90);
            assert_eq!(deletable_segments, vec![1]);
            assert_eq!(skipped_segments.len(), 2);
        }
        other => panic!("expected CompactionDecision::Ready, got {other:?}"),
    }
}

#[test]
fn compaction_ready_allows_nonce_abandon_segments() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m1".into(),
        base_index: 90,
        auth_seq: 7,
        manifest_hash: "abc".into(),
        recorded_at_ms: 0,
        chain_hash: authorization_chain_hash(None, "m1", 7, "abc"),
    };
    let segments = vec![
        SegmentHealth {
            segment_seq: 1,
            max_index_in_segment: 80,
            has_pending_nonce_reservation: false,
            abandon_record_present: false,
            rewrite_inflight: false,
        },
        SegmentHealth {
            segment_seq: 2,
            max_index_in_segment: 75,
            has_pending_nonce_reservation: true,
            abandon_record_present: true,
            rewrite_inflight: false,
        },
    ];
    let request = CompactionPlanRequest {
        state: compaction_state(100, 90, 120, manifest_gate(Some(record))),
        segments,
    };
    let decision = CompactionGate::plan(request);
    match decision {
        CompactionDecision::Ready {
            floor_effective,
            deletable_segments,
            skipped_segments,
        } => {
            assert_eq!(floor_effective, 90);
            assert_eq!(deletable_segments, vec![1, 2]);
            assert!(skipped_segments.is_empty());
        }
        other => panic!("expected CompactionDecision::Ready, got {other:?}"),
    }
}

#[test]
fn manifest_log_appends_and_reads() {
    let tmp = TempDir::new().expect("tempdir");
    let log_path = tmp.path().join("manifest.log");
    let log = ManifestAuthorizationLog::new(&log_path);
    let first = SnapshotAuthorizationRecord {
        manifest_id: "m2".into(),
        base_index: 42,
        auth_seq: 1,
        manifest_hash: "deadbeef".into(),
        recorded_at_ms: 123,
        chain_hash: authorization_chain_hash(None, "m2", 1, "deadbeef"),
    };
    log.append(&first).expect("append first");
    assert_eq!(log.latest().unwrap().unwrap(), first);
    let second = SnapshotAuthorizationRecord {
        manifest_id: "m3".into(),
        base_index: 50,
        auth_seq: 2,
        manifest_hash: "cafe".into(),
        recorded_at_ms: 124,
        chain_hash: authorization_chain_hash(Some(first.chain_hash.as_str()), "m3", 2, "cafe"),
    };
    log.append(&second).expect("append second");
    let records = log.load().expect("load records");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0], first);
    assert_eq!(records[1], second);
}

#[test]
fn compute_floor_respects_learner_guard() {
    let floor = compute_compaction_floor(Some(1_250), 1_300, 1_200, 1_400);
    assert_eq!(floor, 1_250);
}

#[test]
fn compute_floor_clamped_by_durable_index() {
    let floor = compute_compaction_floor(Some(900), 1_500, 1_200, 950);
    assert_eq!(floor, 950);
}

#[test]
fn compute_floor_uses_quorum_and_base_when_allowed() {
    let floor = compute_compaction_floor(None, 1_800, 1_200, 2_000);
    assert_eq!(floor, 1_200);
}

#[test]
fn compaction_blocks_when_guard_bytes_not_met() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m1".into(),
        base_index: 90,
        auth_seq: 5,
        manifest_hash: "abc".into(),
        recorded_at_ms: 0,
        chain_hash: authorization_chain_hash(None, "m1", 5, "abc"),
    };
    let request = CompactionPlanRequest {
        state: CompactionState {
            learner_slack_floor: Some(5),
            quorum_applied_index: 100,
            snapshot_base_index: 90,
            quorum_sm_durable_index: 105,
            guard_bytes_satisfied: false,
            learner_retirement_pending: false,
            manifest_gate: manifest_gate(Some(record)),
        },
        segments: Vec::new(),
    };
    let decision = CompactionGate::plan(request);
    assert!(matches!(
        decision,
        CompactionDecision::Blocked(reasons)
        if reasons
            .iter()
            .any(|reason| matches!(reason, CompactionBlockReason::GuardBytesExceeded))
    ));
}

#[test]
fn compaction_blocks_on_learner_retirement() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m1".into(),
        base_index: 90,
        auth_seq: 5,
        manifest_hash: "abc".into(),
        recorded_at_ms: 0,
        chain_hash: authorization_chain_hash(None, "m1", 5, "abc"),
    };
    let request = CompactionPlanRequest {
        state: CompactionState {
            learner_slack_floor: Some(5),
            quorum_applied_index: 100,
            snapshot_base_index: 90,
            quorum_sm_durable_index: 105,
            guard_bytes_satisfied: true,
            learner_retirement_pending: true,
            manifest_gate: manifest_gate(Some(record)),
        },
        segments: Vec::new(),
    };
    let decision = CompactionGate::plan(request);
    assert!(matches!(
        decision,
        CompactionDecision::Blocked(reasons)
        if reasons
            .iter()
            .any(|reason| matches!(reason, CompactionBlockReason::LearnerRetirementPending))
    ));
}
