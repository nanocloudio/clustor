use crate::consensus::DurabilityProof;
use crate::durability::ledger::IoMode;
use log::error;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
#[cfg(not(unix))]
use std::io::Write;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurabilityLogEntry {
    pub term: u64,
    pub index: u64,
    pub segment_seq: u64,
    pub io_mode: IoMode,
    pub timestamp_ms: u64,
}

#[derive(Debug)]
pub struct DurabilityLogWriter {
    path: PathBuf,
    file: File,
    next_offset: u64,
}

const DURABILITY_WAL_SPEC: &str = "§6.2.WAL";

impl DurabilityLogWriter {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DurabilityLogError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        let next_offset = file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            file,
            next_offset,
        })
    }

    pub fn append(&mut self, entry: &DurabilityLogEntry) -> Result<(), DurabilityLogError> {
        let mut payload = serde_json::to_vec(entry)?;
        payload.push(b'\n');
        self.write_payload(&payload)?;
        self.next_offset = self.next_offset.saturating_add(payload.len() as u64);
        self.file.sync_data().map_err(|err| {
            error!(
                "event=wal_fdatasync_failed clause={} path={} error={}",
                DURABILITY_WAL_SPEC,
                self.path.display(),
                err
            );
            err
        })?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_all(&mut self) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
        self.file.seek(SeekFrom::Start(0))?;
        let reader = BufReader::new(&self.file);
        parse_entries(reader)
    }

    fn write_payload(&mut self, payload: &[u8]) -> Result<(), DurabilityLogError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            self.file.write_all_at(payload, self.next_offset)?;
        }
        #[cfg(not(unix))]
        {
            self.file.seek(SeekFrom::Start(self.next_offset))?;
            self.file.write_all(payload)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct DurabilityLogReplay;

impl DurabilityLogReplay {
    pub fn load(path: impl AsRef<Path>) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        parse_entries(reader)
    }

    pub fn replay(entries: &[DurabilityLogEntry]) -> ReplayOutcome {
        let mut last_index = 0;
        let mut last_term = 0;
        let mut clean = Vec::new();
        for entry in entries {
            if entry.index < last_index || (entry.index == last_index && entry.term < last_term) {
                return ReplayOutcome {
                    entries: clean,
                    error: Some(ReplayError::Corruption { index: entry.index }),
                };
            }
            clean.push(entry.clone());
            last_index = entry.index;
            last_term = entry.term;
        }
        ReplayOutcome {
            entries: clean,
            error: None,
        }
    }

    pub fn publish_proof(entries: &[DurabilityLogEntry]) -> Option<DurabilityProof> {
        entries
            .last()
            .map(|entry| DurabilityProof::new(entry.term, entry.index))
    }
}

#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    pub entries: Vec<DurabilityLogEntry>,
    pub error: Option<ReplayError>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ReplayError {
    #[error("corruption detected at index {index}")]
    Corruption { index: u64 },
}

#[derive(Debug, Error)]
pub enum DurabilityLogError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn parse_entries<R: BufRead>(reader: R) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_corruption() {
        let entries = vec![
            DurabilityLogEntry {
                term: 1,
                index: 10,
                segment_seq: 1,
                io_mode: IoMode::Strict,
                timestamp_ms: 0,
            },
            DurabilityLogEntry {
                term: 1,
                index: 5,
                segment_seq: 2,
                io_mode: IoMode::Strict,
                timestamp_ms: 0,
            },
        ];
        let outcome = DurabilityLogReplay::replay(&entries);
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.error, Some(ReplayError::Corruption { index: 5 }));
    }

    #[test]
    fn clean_log_replays_without_error() {
        let entries = vec![
            DurabilityLogEntry {
                term: 1,
                index: 1,
                segment_seq: 1,
                io_mode: IoMode::Strict,
                timestamp_ms: 0,
            },
            DurabilityLogEntry {
                term: 1,
                index: 2,
                segment_seq: 2,
                io_mode: IoMode::Strict,
                timestamp_ms: 0,
            },
        ];
        let outcome = DurabilityLogReplay::replay(&entries);
        assert_eq!(outcome.entries.len(), 2);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn writer_persists_and_replays_entries() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("wal").join("durability.log");
        let mut writer = DurabilityLogWriter::open(&path).unwrap();
        let entry = DurabilityLogEntry {
            term: 7,
            index: 42,
            segment_seq: 9,
            io_mode: IoMode::Strict,
            timestamp_ms: 1234,
        };
        writer.append(&entry).unwrap();
        let mut writer = DurabilityLogWriter::open(&path).unwrap();
        let entries = writer.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, 42);
    }
}
