use clustor::bootstrap::probe::GroupFsyncGuardConfig;
use clustor::storage::{
    CompactionAuthAck, CompactionBlockReason, CompactionDecision, CompactionGate,
    CompactionPlanRequest, CompactionState, DataEncryptionKey, EntryFrameBuilder, GroupFsyncPolicy,
    ManifestGate, NonceLedgerConfig, NonceReservationLedger, SegmentHeader, SegmentHeaderError,
    SegmentHealth, SegmentManager, SegmentSkipReason, SnapshotAuthorizationRecord, WalAead,
    WAL_CRYPTO_BLOCK_BYTES,
};

#[test]
fn wal_segment_flush_order_preserved() {
    let mut manager = SegmentManager::with_capacity(64);
    let first = EntryFrameBuilder::new(1, 1).payload(vec![1; 40]).build();
    let second = EntryFrameBuilder::new(1, 2).payload(vec![2; 16]).build();
    manager.append(&first);
    manager.append(&second);
    manager.flush();
    let flushes = manager.drain_flushes();
    assert!(flushes.len() >= 2);
    assert!(flushes[0].ends_with(&first.encode()));
}

#[test]
fn group_fsync_policy_switches_modes() {
    use clustor::bootstrap::probe::FsyncProbeResult;
    let mut policy = GroupFsyncPolicy::new(GroupFsyncGuardConfig::default());
    let probe = |ms| FsyncProbeResult {
        p99_ms: ms,
        sample_count: 128,
        dataset_guid: "guid".into(),
        wal_path: "wal".into(),
        device_serials: vec!["disk".into()],
        measured_at_ms: 0,
    };
    policy.record_probe(probe(10));
    assert_eq!(policy.mode(), clustor::storage::FsyncMode::Group);
    policy.record_probe(probe(40));
    policy.record_probe(probe(40));
    policy.record_probe(probe(40));
    assert_eq!(policy.mode(), clustor::storage::FsyncMode::Strict);
}

#[test]
fn compaction_blocks_without_manifest_ack() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m-1".into(),
        base_index: 90,
        auth_seq: 7,
        manifest_hash: "abc123".into(),
        recorded_at_ms: 0,
    };
    let state = compaction_state(record.clone(), None);
    let decision = CompactionGate::plan(CompactionPlanRequest {
        state,
        segments: Vec::new(),
    });
    match decision {
        CompactionDecision::Blocked(reasons) => {
            assert!(reasons
                .iter()
                .any(|reason| matches!(reason, CompactionBlockReason::ManifestAckMissing { .. })));
        }
        other => panic!("expected blocked decision, got {:?}", other),
    }
}

#[test]
fn compaction_skips_segments_with_pending_nonce_until_abandon() {
    let record = SnapshotAuthorizationRecord {
        manifest_id: "m-2".into(),
        base_index: 120,
        auth_seq: 8,
        manifest_hash: "def456".into(),
        recorded_at_ms: 0,
    };
    let ack = CompactionAuthAck {
        manifest_id: "m-2".into(),
        auth_seq: 8,
        acked_at_ms: 1,
    };
    let mut state = compaction_state(record.clone(), Some(ack));
    state.quorum_applied_index = 140;
    let mut ledger = NonceReservationLedger::new(4);
    ledger.reserve(4, 0).unwrap();
    ledger.record_completion(0).unwrap();
    assert!(ledger.has_outstanding_reservations());

    let pending_segment = SegmentHealth {
        segment_seq: 4,
        max_index_in_segment: 100,
        has_pending_nonce_reservation: true,
        abandon_record_present: false,
        rewrite_inflight: false,
    };

    let decision = CompactionGate::plan(CompactionPlanRequest {
        state: state.clone(),
        segments: vec![pending_segment],
    });

    match decision {
        CompactionDecision::Ready {
            deletable_segments,
            skipped_segments,
            ..
        } => {
            assert!(deletable_segments.is_empty());
            assert!(matches!(
                skipped_segments.as_slice(),
                [SegmentSkipReason::NonceReservationPending { segment_seq: 4 }]
            ));
        }
        _ => panic!("expected ready decision with skipped segment"),
    }

    let abandon_segment = SegmentHealth {
        segment_seq: 4,
        max_index_in_segment: 100,
        has_pending_nonce_reservation: true,
        abandon_record_present: true,
        rewrite_inflight: false,
    };
    let decision = CompactionGate::plan(CompactionPlanRequest {
        state,
        segments: vec![abandon_segment],
    });
    match decision {
        CompactionDecision::Ready {
            deletable_segments, ..
        } => assert_eq!(deletable_segments, vec![4]),
        _ => panic!("expected pending segment to be deletable once abandoned"),
    }
}

#[test]
fn wal_segment_header_detects_tampering() {
    let key = DataEncryptionKey::new(1, [7u8; 32]);
    let aead = WalAead::new(&key, "partition-x");
    let header = SegmentHeader::new(1, 11, key.epoch);
    let mut sealed = header.seal_block(&aead, key.epoch).unwrap();
    sealed[5] ^= 0xFF;
    let err = SegmentHeader::open_block(&aead, key.epoch, header.segment_seq, &sealed)
        .expect_err("tamper detection should fail");
    assert!(matches!(err, SegmentHeaderError::Crypto(_)));
}

#[test]
fn nonce_reservations_emit_gap_telemetry() {
    let mut ledger = NonceReservationLedger::with_config(
        3,
        NonceLedgerConfig {
            warn_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64,
            abandon_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64 * 2,
        },
    );
    ledger.reserve(2, 0).unwrap();
    assert!(ledger.warn_gap());
    assert!(!ledger.needs_scrub());
    ledger.reserve(2, 0).unwrap();
    assert!(ledger.needs_scrub());
    let telemetry = ledger.telemetry();
    assert_eq!(telemetry.committed_blocks, 0);
    assert!(telemetry.gap_bytes >= 4 * WAL_CRYPTO_BLOCK_BYTES as u64);
}

fn compaction_state(
    record: SnapshotAuthorizationRecord,
    ack: Option<CompactionAuthAck>,
) -> CompactionState {
    CompactionState {
        learner_slack_floor: None,
        quorum_applied_index: record.base_index + 5,
        snapshot_base_index: record.base_index,
        quorum_sm_durable_index: record.base_index + 5,
        guard_bytes_satisfied: true,
        learner_retirement_pending: false,
        manifest_gate: ManifestGate {
            relisted: true,
            signature_valid: true,
            authorization: Some(record),
            acknowledgement: ack,
        },
    }
}
