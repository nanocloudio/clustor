use crate::consensus::DurabilityProof;
use crate::raft::{
    PartitionQuorum, PartitionQuorumConfig, PartitionQuorumStatus, QuorumError, ReplicaId,
};
use crate::telemetry::MetricsRegistry;
use crate::terminology::{RuntimeTerm, TERM_GROUP_FSYNC, TERM_STRICT};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const DURABILITY_SPEC_CLAUSE: &str = "§6.Durability";
#[derive(Debug, Clone)]
pub struct AckRecord {
    pub replica: ReplicaId,
    pub term: u64,
    pub index: u64,
    pub segment_seq: u64,
    pub io_mode: IoMode,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoMode {
    Strict,
    Group,
}

impl IoMode {
    pub fn runtime_term(&self) -> RuntimeTerm {
        match self {
            IoMode::Strict => TERM_STRICT,
            IoMode::Group => TERM_GROUP_FSYNC,
        }
    }
}

#[derive(Debug)]
pub struct DurabilityLedger {
    quorum: PartitionQuorum,
    last_record: Option<AckRecord>,
}

impl DurabilityLedger {
    pub fn new(config: PartitionQuorumConfig) -> Self {
        Self {
            quorum: PartitionQuorum::new(config),
            last_record: None,
        }
    }

    pub fn register_replica(&mut self, replica: impl Into<ReplicaId>) {
        self.quorum.register_replica(replica);
    }

    pub fn record_ack(&mut self, record: AckRecord) -> Result<LedgerUpdate, LedgerError> {
        let previous_committed = self.quorum.status().committed_index;
        self.quorum
            .record_match(record.replica.clone(), record.term, record.index)
            .map_err(LedgerError::Quorum)?;
        let quorum_index = self.quorum.advance_commit(record.term);
        self.last_record = Some(record.clone());
        if quorum_index > previous_committed {
            let runtime_term = record.io_mode.runtime_term();
            info!(
                "event=durability_proof clause={} replica={:?} term={} index={} quorum_index={} io_mode={} term_id={}",
                DURABILITY_SPEC_CLAUSE,
                record.replica,
                record.term,
                record.index,
                quorum_index,
                runtime_term.canonical,
                runtime_term.term_id
            );
        }
        Ok(LedgerUpdate {
            record,
            quorum_index,
        })
    }

    pub fn ingest_ack(&mut self, ack: DurabilityAckMessage) -> Result<LedgerUpdate, LedgerError> {
        let record = AckRecord {
            replica: ack.replica,
            term: ack.term,
            index: ack.last_fsynced_index,
            segment_seq: ack.segment_seq,
            io_mode: ack.io_mode,
        };
        self.record_ack(record)
    }

    pub fn status(&self) -> PartitionQuorumStatus {
        self.quorum.status()
    }

    pub fn pending_entries(&self) -> u64 {
        match (
            self.last_record.as_ref(),
            self.quorum.status().committed_index,
        ) {
            (Some(last), committed) => last.index.saturating_sub(committed),
            _ => 0,
        }
    }

    pub fn latest_proof(&self) -> Option<DurabilityProof> {
        let status = self.quorum.status();
        if status.committed_index == 0 {
            None
        } else {
            Some(DurabilityProof::new(
                status.committed_term,
                status.committed_index,
            ))
        }
    }

    pub fn ack_handle(&self, target_term: u64, target_index: u64) -> AckHandle {
        AckHandle::new(target_term, target_index, self.quorum.status().quorum_size)
    }

    pub fn batching_allowed(&self, target_index: u64) -> bool {
        self.quorum.status().committed_index >= target_index
    }
}

#[derive(Debug, Clone)]
pub struct LedgerUpdate {
    pub record: AckRecord,
    pub quorum_index: u64,
}

#[derive(Debug, Clone)]
pub struct DurabilityAckMessage {
    pub replica: ReplicaId,
    pub term: u64,
    pub last_fsynced_index: u64,
    pub segment_seq: u64,
    pub io_mode: IoMode,
}

#[derive(Debug, Default)]
pub struct DurabilityMetricsPublisher;

impl DurabilityMetricsPublisher {
    pub fn new() -> Self {
        Self
    }

    pub fn publish(&mut self, registry: &mut MetricsRegistry, ledger: &DurabilityLedger) {
        let status = ledger.status();
        registry.set_gauge(
            "durability.last_quorum_fsynced_index",
            status.committed_index,
        );
        registry.set_gauge("durability.last_quorum_fsynced_term", status.committed_term);
        registry.set_gauge("durability.pending_entries", ledger.pending_entries());
    }
}

#[derive(Debug)]
pub struct AckHandle {
    target_term: u64,
    target_index: u64,
    quorum: usize,
    acked: HashSet<ReplicaId>,
    satisfied: bool,
}

impl AckHandle {
    pub fn new(target_term: u64, target_index: u64, quorum: usize) -> Self {
        Self {
            target_term,
            target_index,
            quorum,
            acked: HashSet::new(),
            satisfied: false,
        }
    }

    pub fn observe(&mut self, record: &AckRecord) -> bool {
        if self.satisfied {
            return true;
        }
        if record.term < self.target_term || record.index < self.target_index {
            return false;
        }
        self.acked.insert(record.replica.clone());
        if self.acked.len() >= self.quorum {
            self.satisfied = true;
        }
        self.satisfied
    }

    pub fn is_satisfied(&self) -> bool {
        self.satisfied
    }

    pub fn target(&self) -> (u64, u64) {
        (self.target_term, self.target_index)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Quorum(#[from] QuorumError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::MetricsRegistry;

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
}
