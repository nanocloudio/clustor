use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clustor::durability::ledger::IoMode;
use clustor::durability::{DurabilityLogEntry, DurabilityLogWriter};
use clustor::{RaftLogEntry, RaftLogStore, RaftMetadata, RaftMetadataStore, WalWriter};
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
    wal_writer: Arc<Mutex<WalWriter>>,
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
        if let Some(tail) = log_store.last_term_index() {
            metadata.record_log_tail(tail.term, tail.index);
        }
        let wal_path = state_dir.join("wal.bin");
        let block_size = if metadata.wal_block_size == 0 {
            DEFAULT_CRYPTO_BLOCK_BYTES
        } else {
            metadata.wal_block_size as u64
        };
        metadata.wal_block_size = block_size as u32;
        let mut wal_writer = WalWriter::open(&wal_path, block_size)
            .with_context(|| format!("open wal {}", wal_path.display()))?;
        wal_writer.align_next_block(metadata.wal_next_block);
        metadata.wal_next_block = wal_writer.next_block();
        metadata_store
            .persist(&metadata)
            .context("persist metadata after recovery")?;
        let durability_path = state_dir.join("wal_durability.log");
        let durability_log = DurabilityLogWriter::open(&durability_path)
            .with_context(|| format!("open durability log {}", durability_path.display()))?;
        Ok(Self {
            log: Arc::new(Mutex::new(log_store)),
            metadata_store,
            metadata: Arc::new(Mutex::new(metadata)),
            durability_log: Arc::new(Mutex::new(durability_log)),
            wal_writer: Arc::new(Mutex::new(wal_writer)),
        })
    }

    pub fn log_handle(&self) -> Arc<Mutex<RaftLogStore>> {
        self.log.clone()
    }

    pub fn current_term(&self) -> u64 {
        self.metadata.lock().current_term
    }

    pub fn voted_for(&self) -> Option<String> {
        self.metadata.lock().voted_for.clone()
    }

    pub fn set_current_term(&self, term: u64) -> Result<(), String> {
        self.with_metadata(|metadata| metadata.update_term(term))
    }

    pub fn record_vote(&self, candidate: Option<&str>) -> Result<(), String> {
        self.with_metadata(|metadata| match candidate {
            Some(id) => metadata.record_vote(id),
            None => metadata.reset_vote(),
        })
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

        let mut wal_writer = self.wal_writer.lock();
        let wal_result = wal_writer
            .append_frame(&serialized_entry)
            .context("append wal frame")?;
        let mut metadata = self.metadata.lock();
        metadata.record_log_tail(entry.term, entry.index);
        metadata.wal_next_block = wal_writer.next_block();
        metadata.wal_block_size = wal_writer.block_size() as u32;
        self.metadata_store.persist(&metadata)?;
        drop(metadata);
        drop(wal_writer);

        self.append_durability_record(
            entry.term,
            entry.index,
            wal_result.reservation.start_block,
        )?;
        Ok(AppendedEntry {
            entry,
            segment_seq: wal_result.reservation.start_block,
        })
    }

    fn append_durability_record(
        &self,
        term: u64,
        index: u64,
        segment_seq: u64,
    ) -> Result<()> {
        let mut log = self.durability_log.lock();
        let entry = DurabilityLogEntry::new(
            term,
            index,
            segment_seq,
            IoMode::Strict,
            current_time_ms(),
        );
        log.append(&entry)?;
        Ok(())
    }
}

impl PersistentState {
    fn with_metadata<F>(&self, mutator: F) -> Result<(), String>
    where
        F: FnOnce(&mut RaftMetadata),
    {
        let mut metadata = self.metadata.lock();
        mutator(&mut metadata);
        self.metadata_store
            .persist(&metadata)
            .map_err(|err| format!("persist metadata failed: {err}"))?;
        Ok(())
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
            let tail = metadata.log_tail().unwrap();
            assert_eq!(tail.index, 2);
            assert_eq!(tail.term, 1);
            assert!(metadata.wal_next_block >= 1);
            let entries = state.entries_from(1);
            assert_eq!(entries.len(), 2);
        }
    }

    #[test]
    fn wal_cursor_recovers_after_restart() {
        let dir = tempdir().unwrap();
        let next_block = {
            let state = PersistentState::open(dir.path()).unwrap();
            state.append_payload(1, b"alpha".to_vec()).unwrap();
            state.metadata_snapshot().wal_next_block
        };
        let state = PersistentState::open(dir.path()).unwrap();
        state.append_payload(1, b"beta".to_vec()).unwrap();
        let metadata = state.metadata_snapshot();
        assert!(metadata.wal_next_block >= next_block);
        assert_eq!(metadata.log_tail().unwrap().index, 2);
    }
}
