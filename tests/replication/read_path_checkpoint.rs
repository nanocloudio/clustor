use clustor::{
    AckRecord, ConsensusCore, ConsensusCoreConfig, CpProofCoordinator, DurabilityLedger,
    DurabilityProof, IoMode, PartitionQuorumConfig,
};
use std::time::Instant;

fn record(replica: &str, index: u64) -> AckRecord {
    AckRecord {
        replica: clustor::ReplicaId::new(replica.to_string()),
        term: 4,
        index,
        segment_seq: 1,
        io_mode: IoMode::Strict,
    }
}

#[test]
fn ledger_quorum_enables_read_index_when_proof_matches() {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }
    ledger.record_ack(record("leader", 50)).unwrap();
    ledger.record_ack(record("f1", 50)).unwrap();

    let mut coordinator =
        CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    let now = Instant::now();
    coordinator.load_local_ledger(DurabilityProof::new(4, 50), now);
    coordinator.publish_cp_proof_at(DurabilityProof::new(4, 50), now);

    let permit = coordinator
        .guard_read_index_with_quorum(ledger.status().committed_index, now)
        .expect("ledger and CP proof aligned");
    assert_eq!(permit.quorum_index, 50);
}

#[test]
fn ack_handle_tracks_quorum_for_read_index() {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }
    let mut handle = ledger.ack_handle(4, 60);
    let leader_ack = ledger.record_ack(record("leader", 60)).unwrap();
    assert!(!handle.observe(&leader_ack.record));
    let f1_ack = ledger.record_ack(record("f1", 60)).unwrap();
    assert!(handle.observe(&f1_ack.record));
    assert!(handle.is_satisfied());
}
