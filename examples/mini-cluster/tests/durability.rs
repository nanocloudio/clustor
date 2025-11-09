use clustor::durability::{AckRecord, DurabilityLedger, IoMode};
use clustor::raft::{PartitionQuorumConfig, ReplicaId};

fn build_ledger() -> DurabilityLedger {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }
    ledger
}

#[test]
fn quorum_index_advances_after_majority() {
    let mut ledger = build_ledger();
    let leader_record = AckRecord {
        replica: ReplicaId::new("leader".to_string()),
        term: 1,
        index: 10,
        segment_seq: 7,
        io_mode: IoMode::Strict,
    };
    let update = ledger.record_ack(leader_record).expect("leader ack");
    assert_eq!(update.quorum_index, 0, "single ack must not advance quorum");

    let follower_record = AckRecord {
        replica: ReplicaId::new("f1".to_string()),
        term: 1,
        index: 10,
        segment_seq: 8,
        io_mode: IoMode::Strict,
    };
    let update = ledger
        .record_ack(follower_record)
        .expect("follower ack");
    assert_eq!(update.quorum_index, 10);
}

#[test]
fn rejects_index_regression_for_replica() {
    let mut ledger = build_ledger();
    let replica = ReplicaId::new("f2".to_string());
    let first = AckRecord {
        replica: replica.clone(),
        term: 1,
        index: 5,
        segment_seq: 3,
        io_mode: IoMode::Strict,
    };
    ledger.record_ack(first).expect("first ack");

    let regression = AckRecord {
        replica,
        term: 1,
        index: 4,
        segment_seq: 2,
        io_mode: IoMode::Strict,
    };
    let err = ledger.record_ack(regression).expect_err("regression must fail");
    assert!(format!("{}", err).contains("regression"));
}
