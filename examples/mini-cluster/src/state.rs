use crate::peers::PeerInfo;
use crate::storage::{AppendedEntry, PersistentState};
use clustor::consensus::{ConsensusCore, ConsensusCoreConfig, DurabilityProof, GateOperation, GateViolation};
use clustor::durability::{AckRecord, DurabilityLedger, IoMode};
use clustor::raft::ReplicaId;
use clustor::{RaftLogEntry, RaftLogStore};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventRecord {
    pub source: String,
    pub message: String,
}

#[derive(Clone)]
pub struct AppState {
    pub node_id: String,
    pub events: Arc<Mutex<Vec<EventRecord>>>,
    pub durability_ledger: Arc<Mutex<DurabilityLedger>>,
    pub last_quorum_fsynced: Arc<AtomicU64>,
    pub consensus_core: Arc<Mutex<ConsensusCore>>,
    pub current_term: Arc<AtomicU64>,
    pub leadership_epoch: Arc<AtomicU64>,
    pub storage: PersistentState,
    pub log: Arc<Mutex<RaftLogStore>>,
    pub peers: Arc<Vec<PeerInfo>>,
    pub last_applied: Arc<AtomicU64>,
    pub peer_down_after: std::time::Duration,
}

impl AppState {
    pub fn record_leader_ack(&self, appended: &AppendedEntry) {
        self.record_ack(
            ReplicaId::new(self.node_id.clone()),
            appended.entry.term,
            appended.entry.index,
            appended.segment_seq,
            IoMode::Strict,
        );
    }

    pub fn record_peer_ack(&self, peer_id: &str, term: u64, match_index: u64) {
        if match_index == 0 {
            return;
        }
        self.record_ack(
            ReplicaId::new(peer_id.to_string()),
            term,
            match_index,
            match_index,
            IoMode::Strict,
        );
    }

    fn record_ack(
        &self,
        replica: ReplicaId,
        term: u64,
        index: u64,
        segment_seq: u64,
        io_mode: IoMode,
    ) {
        let mut ledger = self.durability_ledger.lock();
        match ledger.record_ack(AckRecord {
            replica,
            term,
            index,
            segment_seq,
            io_mode,
        }) {
            Ok(update) => {
                self.last_quorum_fsynced
                    .store(update.quorum_index, Ordering::SeqCst);
                self.reconcile_strict_fallback(update.quorum_index);
            }
            Err(err) => {
                log::warn!("durability ack rejected: {err}");
            }
        }
    }

    pub fn on_local_append(&self, entry: &RaftLogEntry) {
        let mut core = self.consensus_core.lock();
        core.enter_strict_fallback(DurabilityProof::new(entry.term, entry.index), Instant::now());
        core.register_strict_write();
    }

    pub fn reconcile_strict_fallback(&self, quorum_index: u64) {
        let log_tail = self.log.lock().last_index();
        let mut core = self.consensus_core.lock();
        if log_tail > quorum_index {
            core.enter_strict_fallback(
                DurabilityProof::new(self.current_term.load(Ordering::SeqCst), quorum_index),
                Instant::now(),
            );
        } else {
            core.mark_healthy();
        }
    }

    pub fn guard_read(&self) -> Result<(), GateViolation> {
        let mut core = self.consensus_core.lock();
        core.guard(GateOperation::ReadIndex)
    }
}

pub fn append_local_entry(
    state: &AppState,
    record: &EventRecord,
    term: u64,
) -> Result<RaftLogEntry, String> {
    let payload = serde_json::to_vec(record).map_err(|err| format!("encode event payload failed: {err}"))?;
    let appended = state
        .storage
        .append_payload(term, payload)
        .map_err(|err| format!("log append failed: {err}"))?;
    state.on_local_append(&appended.entry);
    state.record_leader_ack(&appended);
    apply_committed_entries(
        std::slice::from_ref(&appended.entry),
        &state.events,
        &state.last_applied,
    );
    Ok(appended.entry)
}

pub fn apply_committed_entries(
    entries: &[RaftLogEntry],
    events: &Arc<Mutex<Vec<EventRecord>>>,
    last_applied: &Arc<AtomicU64>,
) {
    if entries.is_empty() {
        return;
    }
    let mut applied = last_applied.load(Ordering::SeqCst);
    let mut new_records = Vec::new();
    for entry in entries {
        if entry.index <= applied {
            continue;
        }
        match serde_json::from_slice::<EventRecord>(&entry.payload) {
            Ok(record) => {
                new_records.push(record);
                applied = entry.index;
            }
            Err(err) => {
                log::error!("failed to decode event payload at index {}: {err}", entry.index);
            }
        }
    }
    if new_records.is_empty() {
        return;
    }
    let mut guard = events.lock();
    guard.extend(new_records);
    last_applied.store(applied, Ordering::SeqCst);
}

pub fn new_consensus_core() -> Arc<Mutex<ConsensusCore>> {
    Arc::new(Mutex::new(ConsensusCore::new(
        ConsensusCoreConfig::default(),
    )))
}
