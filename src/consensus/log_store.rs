use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Persistent Raft metadata tracking the node's `current_term` and vote state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RaftMetadata {
    pub current_term: u64,
    pub voted_for: Option<String>,
    pub last_applied: u64,
    pub last_log_term: u64,
    pub last_log_index: u64,
    pub wal_block_size: u32,
    pub wal_next_block: u64,
}

impl RaftMetadata {
    pub fn record_vote(&mut self, candidate_id: impl Into<String>) {
        self.voted_for = Some(candidate_id.into());
    }

    pub fn reset_vote(&mut self) {
        self.voted_for = None;
    }

    pub fn update_term(&mut self, term: u64) {
        if term > self.current_term {
            self.current_term = term;
            self.voted_for = None;
        }
    }

    pub fn note_append(&mut self, term: u64, index: u64) {
        if term > self.last_log_term || index > self.last_log_index {
            self.last_log_term = term;
            self.last_log_index = index;
        }
    }
}

/// JSON-backed metadata store persisted under `/state/<partition>/raft_metadata.json`.
#[derive(Debug, Clone)]
pub struct RaftMetadataStore {
    path: PathBuf,
}

impl RaftMetadataStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_or_default(&self) -> Result<RaftMetadata, RaftMetadataError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(RaftMetadata::default()),
            Err(err) => Err(RaftMetadataError::Io(err)),
        }
    }

    pub fn persist(&self, metadata: &RaftMetadata) -> Result<(), RaftMetadataError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut file = File::create(&tmp)?;
        let payload = serde_json::to_vec_pretty(metadata)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum RaftMetadataError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Logical log entry (payload is opaque to the Raft layer).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RaftLogEntry {
    pub term: u64,
    pub index: u64,
    pub payload: Vec<u8>,
}

impl RaftLogEntry {
    pub fn new(term: u64, index: u64, payload: Vec<u8>) -> Self {
        Self {
            term,
            index,
            payload,
        }
    }
}

/// Compact `(term,index)` snapshots written alongside the log for fast reloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermIndexSnapshot {
    pub term: u64,
    pub index: u64,
}

/// Append-only Raft log with an auxiliary snapshot file containing `{term,index}` pairs.
#[derive(Debug)]
pub struct RaftLogStore {
    log_path: PathBuf,
    index_path: PathBuf,
    entries: Vec<RaftLogEntry>,
    index: Vec<TermIndexSnapshot>,
}

impl RaftLogStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RaftLogError> {
        let log_path = path.into();
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut index_path = log_path.clone();
        index_path.set_extension("idx");

        let entries = Self::load_entries(&log_path)?;
        let index = if index_path.exists() {
            Self::load_snapshot(&index_path)?
        } else {
            Self::rebuild_snapshot(&entries)
        };

        Ok(Self {
            log_path,
            index_path,
            entries,
            index,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn last_term_index(&self) -> Option<TermIndexSnapshot> {
        self.index.last().cloned()
    }

    pub fn entry(&self, index: u64) -> Option<&RaftLogEntry> {
        self.entries.iter().find(|entry| entry.index == index)
    }

    pub fn entries_from(&self, start_index: u64) -> Vec<RaftLogEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.index >= start_index)
            .cloned()
            .collect()
    }

    pub fn first_index(&self) -> u64 {
        self.entries.first().map(|entry| entry.index).unwrap_or(0)
    }

    pub fn last_index(&self) -> u64 {
        self.entries.last().map(|entry| entry.index).unwrap_or(0)
    }

    pub fn term_at(&self, index: u64) -> Option<u64> {
        self.entry(index).map(|entry| entry.term)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn append_batch(&mut self, entries: &[RaftLogEntry]) -> Result<(), RaftLogError> {
        for entry in entries {
            if self
                .entry(entry.index)
                .map(|existing| existing.term == entry.term)
                .unwrap_or(false)
            {
                continue;
            }
            self.append(entry.clone())?;
        }
        Ok(())
    }

    pub fn append(&mut self, entry: RaftLogEntry) -> Result<(), RaftLogError> {
        match self.entries.last() {
            Some(last) if entry.index != last.index + 1 => {
                return Err(RaftLogError::NonSequentialAppend {
                    expected: last.index + 1,
                    attempted: entry.index,
                });
            }
            None if entry.index != 1 => {
                return Err(RaftLogError::NonSequentialAppend {
                    expected: 1,
                    attempted: entry.index,
                });
            }
            Some(last) if entry.term < last.term => {
                return Err(RaftLogError::TermRegression {
                    previous: last.term,
                    attempted: entry.term,
                });
            }
            _ => {}
        }

        let line = serde_json::to_string(&entry)?;
        Self::append_line(&self.log_path, &line)?;
        self.entries.push(entry.clone());

        let snapshot = TermIndexSnapshot {
            term: entry.term,
            index: entry.index,
        };
        let snapshot_line = serde_json::to_string(&snapshot)?;
        Self::append_line(&self.index_path, &snapshot_line)?;
        self.index.push(snapshot);
        Ok(())
    }

    pub fn truncate_from(&mut self, index: u64) -> Result<(), RaftLogError> {
        if index == 0 {
            return Err(RaftLogError::InvalidTruncateIndex(0));
        }
        let original_len = self.entries.len();
        self.entries.retain(|entry| entry.index < index);
        if self.entries.len() == original_len {
            return Ok(());
        }
        self.index.retain(|snapshot| snapshot.index < index);
        self.rewrite_files()?;
        Ok(())
    }

    fn rewrite_files(&self) -> Result<(), RaftLogError> {
        Self::rewrite_json_lines(&self.log_path, &self.entries)?;
        Self::rewrite_json_lines(&self.index_path, &self.index)?;
        Ok(())
    }

    fn rewrite_json_lines<T: Serialize>(path: &Path, items: &[T]) -> Result<(), RaftLogError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("rewrite");
        let mut file = File::create(&tmp)?;
        for item in items {
            let line = serde_json::to_string(item)?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        fs::rename(tmp, path)?;
        Ok(())
    }

    fn append_line(path: &Path, line: &str) -> Result<(), RaftLogError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    fn load_entries(path: &Path) -> Result<Vec<RaftLogEntry>, RaftLogError> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            entries.push(serde_json::from_str(&line)?);
        }
        Ok(entries)
    }

    fn load_snapshot(path: &Path) -> Result<Vec<TermIndexSnapshot>, RaftLogError> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut snapshots = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            snapshots.push(serde_json::from_str(&line)?);
        }
        Ok(snapshots)
    }

    fn rebuild_snapshot(entries: &[RaftLogEntry]) -> Vec<TermIndexSnapshot> {
        entries
            .iter()
            .map(|entry| TermIndexSnapshot {
                term: entry.term,
                index: entry.index,
            })
            .collect()
    }
}

#[derive(Debug, Error)]
pub enum RaftLogError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("expected next index {expected}, attempted {attempted}")]
    NonSequentialAppend { expected: u64, attempted: u64 },
    #[error("term regression: previous={previous}, attempted={attempted}")]
    TermRegression { previous: u64, attempted: u64 },
    #[error("truncate index must be >0 (observed {0})")]
    InvalidTruncateIndex(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn append_and_reload_persists_entries() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("raft.log");
        {
            let mut store = RaftLogStore::open(&log_path).unwrap();
            store
                .append(RaftLogEntry::new(1, 1, b"cmd1".to_vec()))
                .unwrap();
            store
                .append(RaftLogEntry::new(1, 2, b"cmd2".to_vec()))
                .unwrap();
        }
        let store = RaftLogStore::open(&log_path).unwrap();
        assert_eq!(store.len(), 2);
        let snapshot = store.last_term_index().unwrap();
        assert_eq!(snapshot.index, 2);
        assert_eq!(snapshot.term, 1);
    }

    #[test]
    fn truncate_rewrites_snapshot() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("raft.log");
        let mut store = RaftLogStore::open(&log_path).unwrap();
        for i in 1..=3 {
            store
                .append(RaftLogEntry::new(1, i, format!("cmd{i}").into_bytes()))
                .unwrap();
        }
        store.truncate_from(3).unwrap();
        assert_eq!(store.len(), 2);
        let reopened = RaftLogStore::open(&log_path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(reopened.last_term_index().unwrap().index, 2);
    }

    #[test]
    fn metadata_store_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = RaftMetadataStore::new(tmp.path().join("raft_metadata.json"));
        let mut meta = RaftMetadata {
            current_term: 5,
            ..Default::default()
        };
        meta.record_vote("node-a");
        store.persist(&meta).unwrap();
        let loaded = store.load_or_default().unwrap();
        assert_eq!(loaded.current_term, 5);
        assert_eq!(loaded.voted_for.as_deref(), Some("node-a"));
    }
}
