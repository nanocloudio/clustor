use clustor::persistence::durability::{
    AckRecord, DurabilityAckMessage, DurabilityLedger, DurabilityMetricsPublisher, IoMode,
};
use clustor::replication::raft::{PartitionQuorumConfig, ReplicaId};
use clustor::telemetry::MetricsRegistry;

#[test]
fn ack_handle_waits_for_quorum() {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }

    let mut handle = ledger.ack_handle(2, 20);
    let rec = |replica: &str| AckRecord {
        replica: ReplicaId::new(replica.to_string()),
        term: 2,
        index: 20,
        segment_seq: 7,
        io_mode: IoMode::Strict,
    };

    let update = ledger.record_ack(rec("leader")).unwrap();
    assert_eq!(update.quorum_index, 0);
    assert!(!handle.observe(&update.record));

    let update = ledger.record_ack(rec("f1")).unwrap();
    assert!(handle.observe(&update.record));
    assert!(handle.is_satisfied());
    let proof = ledger.latest_proof().unwrap();
    assert_eq!(proof.index, 20);
}

#[test]
fn ack_handle_ignores_lower_indices() {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }
    let mut handle = ledger.ack_handle(5, 50);
    let low = AckRecord {
        replica: ReplicaId::new("leader"),
        term: 5,
        index: 40,
        segment_seq: 1,
        io_mode: IoMode::Strict,
    };
    assert!(!handle.observe(&low));
    let leader_high = AckRecord {
        index: 55,
        ..low.clone()
    };
    assert!(!handle.observe(&leader_high));
    let follower_high = AckRecord {
        replica: ReplicaId::new("f1"),
        index: 55,
        ..low.clone()
    };
    assert!(handle.observe(&follower_high));
}

#[test]
fn ingest_ack_computes_quorum_index() {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }

    let ack = |replica: &str| DurabilityAckMessage {
        replica: ReplicaId::new(replica.to_string()),
        term: 3,
        last_fsynced_index: 30,
        segment_seq: 11,
        io_mode: IoMode::Strict,
    };

    let update = ledger.ingest_ack(ack("leader")).unwrap();
    assert_eq!(update.quorum_index, 0);
    let update = ledger.ingest_ack(ack("f1")).unwrap();
    assert_eq!(update.quorum_index, 30);
}

#[test]
fn metrics_publisher_exports_quorum_stats() {
    let mut ledger = DurabilityLedger::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        ledger.register_replica(id);
    }
    let ack = DurabilityAckMessage {
        replica: ReplicaId::new("leader"),
        term: 4,
        last_fsynced_index: 12,
        segment_seq: 5,
        io_mode: IoMode::Strict,
    };
    ledger.ingest_ack(ack).unwrap();

    let mut registry = MetricsRegistry::new("clustor");
    let mut publisher = DurabilityMetricsPublisher::new();
    publisher.publish(&mut registry, &ledger);
    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot.gauges["clustor.durability.last_quorum_fsynced_index"],
        ledger.status().committed_index
    );
}
