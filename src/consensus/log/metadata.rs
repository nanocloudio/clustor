use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Compact `(term,index)` snapshots written alongside the log for fast reloads.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermIndexSnapshot {
    pub term: u64,
    pub index: u64,
}

/// `(term,index)` reference to the latest known log tail.
pub type LogTailRef = TermIndexSnapshot;

/// Persistent Raft metadata tracking the node's `current_term` and vote state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RaftMetadata {
    pub current_term: u64,
    pub voted_for: Option<String>,
    #[serde(default)]
    pub last_applied: u64,
    #[serde(default)]
    pub log_tail: Option<LogTailRef>,
    #[serde(default)]
    pub wal_block_size: u32,
    #[serde(default)]
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
        self.record_log_tail(term, index);
    }

    pub fn record_log_tail(&mut self, term: u64, index: u64) {
        if let Some(existing) = self.log_tail {
            if existing.term > term {
                return;
            }
            if existing.term == term && existing.index >= index {
                return;
            }
        }
        self.log_tail = Some(LogTailRef { term, index });
    }

    pub fn log_tail(&self) -> Option<LogTailRef> {
        self.log_tail
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
