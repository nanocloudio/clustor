use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clustor::durability::ledger::IoMode;
use clustor::durability::{DurabilityLogEntry, DurabilityLogWriter};
use clustor::{RaftLogEntry, RaftLogStore, RaftMetadata, RaftMetadataStore};
use parking_lot::Mutex;

const DEFAULT_CRYPTO_BLOCK_BYTES: u64 = 4096;

#[derive(Debug, Clone)]
pub struct AppendedEntry {
    pub entry: RaftLogEntry,
    pub segment_seq: u64,
}

#[derive(Clone)]
pub struct PersistentState {
    log: Arc<Mutex<RaftLogStore>>,
    metadata_store: RaftMetadataStore,
    metadata: Arc<Mutex<RaftMetadata>>,
    durability_log: Arc<Mutex<DurabilityLogWriter>>,
    wal_tracker: Arc<Mutex<WalReservationTracker>>,
}

impl PersistentState {
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state_dir = state_dir.as_ref();
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("failed to create state dir {}", state_dir.display()))?;
        let log_path = state_dir.join("raft.log");
        let log_store = RaftLogStore::open(&log_path)
            .with_context(|| format!("open raft log {}", log_path.display()))?;
        let metadata_path = state_dir.join("raft_metadata.json");
        let metadata_store = RaftMetadataStore::new(metadata_path);
        let mut metadata = metadata_store
            .load_or_default()
            .context("load raft metadata")?;
        if metadata.wal_block_size == 0 {
            metadata.wal_block_size = DEFAULT_CRYPTO_BLOCK_BYTES as u32;
        }
        metadata.last_log_index = log_store.last_index();
        metadata.last_log_term = log_store.last_term_index().map(|s| s.term).unwrap_or(0);
        metadata.wal_next_block = metadata
            .wal_next_block
            .max(calculate_block_cursor(&log_path, metadata.wal_block_size as u64));
        metadata_store
            .persist(&metadata)
            .context("persist metadata after recovery")?;
        let wal_tracker = WalReservationTracker::from_metadata(&metadata);
        let durability_path = state_dir.join("wal_durability.log");
        let durability_log = DurabilityLogWriter::open(&durability_path)
            .with_context(|| format!("open durability log {}", durability_path.display()))?;
        Ok(Self {
            log: Arc::new(Mutex::new(log_store)),
            metadata_store,
            metadata: Arc::new(Mutex::new(metadata)),
            durability_log: Arc::new(Mutex::new(durability_log)),
            wal_tracker: Arc::new(Mutex::new(wal_tracker)),
        })
    }

    pub fn log_handle(&self) -> Arc<Mutex<RaftLogStore>> {
        self.log.clone()
    }

    pub fn entries_from(&self, index: u64) -> Vec<RaftLogEntry> {
        self.log.lock().entries_from(index)
    }

    #[cfg(test)]
    pub fn metadata_snapshot(&self) -> RaftMetadata {
        self.metadata.lock().clone()
    }

    pub fn append_payload(&self, term: u64, payload: Vec<u8>) -> Result<AppendedEntry> {
        let mut log = self.log.lock();
        let next_index = log.last_index() + 1;
        let entry = RaftLogEntry::new(term, next_index, payload);
        let serialized_entry = serde_json::to_vec(&entry)?;
        log.append(entry.clone())?;
        drop(log);

        let mut tracker = self.wal_tracker.lock();
        let reservation = tracker.reserve(serialized_entry.len() + 1);
        let mut metadata = self.metadata.lock();
        metadata.last_log_index = entry.index;
        metadata.last_log_term = entry.term;
        metadata.wal_next_block = tracker.next_block();
        metadata.wal_block_size = tracker.block_size() as u32;
        self.metadata_store.persist(&metadata)?;
        drop(metadata);
        drop(tracker);

        self.append_durability_record(entry.term, entry.index, reservation.start_block)?;
        Ok(AppendedEntry {
            entry,
            segment_seq: reservation.start_block,
        })
    }

    fn append_durability_record(
        &self,
        term: u64,
        index: u64,
        segment_seq: u64,
    ) -> Result<()> {
        let mut log = self.durability_log.lock();
        let entry = DurabilityLogEntry {
            term,
            index,
            segment_seq,
            io_mode: IoMode::Strict,
            timestamp_ms: current_time_ms(),
        };
        log.append(&entry)?;
        Ok(())
    }
}

fn calculate_block_cursor(path: &Path, block: u64) -> u64 {
    match std::fs::metadata(path) {
        Ok(meta) => ((meta.len() + block - 1) / block) as u64,
        Err(_) => 0,
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone)]
struct WalReservationTracker {
    block_size: u64,
    next_block: u64,
}

impl WalReservationTracker {
    fn from_metadata(meta: &RaftMetadata) -> Self {
        let block_size = if meta.wal_block_size == 0 {
            DEFAULT_CRYPTO_BLOCK_BYTES
        } else {
            meta.wal_block_size as u64
        };
        Self {
            block_size,
            next_block: meta.wal_next_block,
        }
    }

    fn reserve(&mut self, bytes: usize) -> WalReservation {
        let blocks = divide_round_up(bytes as u64, self.block_size).max(1);
        let start = self.next_block;
        self.next_block += blocks;
        WalReservation {
            start_block: start,
            blocks,
        }
    }

    fn next_block(&self) -> u64 {
        self.next_block
    }

    fn block_size(&self) -> u64 {
        self.block_size
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct WalReservation {
    start_block: u64,
    blocks: u64,
}

fn divide_round_up(value: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    (value + divisor - 1) / divisor
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn restart_recovers_metadata_and_log() {
        let dir = tempdir().unwrap();
        {
            let state = PersistentState::open(dir.path()).unwrap();
            state.append_payload(1, b"alpha".to_vec()).unwrap();
            state.append_payload(1, b"beta".to_vec()).unwrap();
        }
        {
            let state = PersistentState::open(dir.path()).unwrap();
            let metadata = state.metadata_snapshot();
            assert_eq!(metadata.last_log_index, 2);
            assert_eq!(metadata.last_log_term, 1);
            assert!(metadata.wal_next_block >= 2);
            let entries = state.entries_from(1);
            assert_eq!(entries.len(), 2);
        }
    }
}
