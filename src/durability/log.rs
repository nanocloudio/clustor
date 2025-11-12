use crate::consensus::DurabilityProof;
use crate::durability::ledger::IoMode;
use crc32fast::Hasher;
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
    pub record_crc32c: u32,
}

impl DurabilityLogEntry {
    pub fn new(
        term: u64,
        index: u64,
        segment_seq: u64,
        io_mode: IoMode,
        timestamp_ms: u64,
    ) -> Self {
        let mut entry = Self {
            term,
            index,
            segment_seq,
            io_mode,
            timestamp_ms,
            record_crc32c: 0,
        };
        entry.record_crc32c = entry.compute_crc();
        entry
    }

    pub fn validate_crc(&self) -> bool {
        self.record_crc32c == self.compute_crc()
    }

    pub fn normalized(&self) -> Self {
        let mut clone = self.clone();
        clone.record_crc32c = clone.compute_crc();
        clone
    }

    fn compute_crc(&self) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.term.to_le_bytes());
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&self.segment_seq.to_le_bytes());
        hasher.update(&[self.io_mode as u8]);
        hasher.update(&self.timestamp_ms.to_le_bytes());
        hasher.finalize()
    }
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
        let entry = entry.normalized();
        let mut payload = serde_json::to_vec(&entry)?;
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
    #[error("durability log CRC mismatch at index {index}")]
    CorruptRecord { index: u64 },
}

fn parse_entries<R: BufRead>(reader: R) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: DurabilityLogEntry = serde_json::from_str(&line)?;
        if !entry.validate_crc() {
            return Err(DurabilityLogError::CorruptRecord { index: entry.index });
        }
        entries.push(entry);
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
            DurabilityLogEntry::new(1, 10, 1, IoMode::Strict, 0),
            DurabilityLogEntry::new(1, 5, 2, IoMode::Strict, 0),
        ];
        let outcome = DurabilityLogReplay::replay(&entries);
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.error, Some(ReplayError::Corruption { index: 5 }));
    }

    #[test]
    fn clean_log_replays_without_error() {
        let entries = vec![
            DurabilityLogEntry::new(1, 1, 1, IoMode::Strict, 0),
            DurabilityLogEntry::new(1, 2, 2, IoMode::Strict, 0),
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
        let entry = DurabilityLogEntry::new(7, 42, 9, IoMode::Strict, 1234);
        writer.append(&entry).unwrap();
        let mut writer = DurabilityLogWriter::open(&path).unwrap();
        let entries = writer.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, 42);
    }

    #[test]
    fn read_all_rejects_crc_mismatch() {
        use std::fs;
        let temp = tempdir().unwrap();
        let path = temp.path().join("wal").join("durability.log");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut writer = DurabilityLogWriter::open(&path).unwrap();
        let entry = DurabilityLogEntry::new(3, 9, 2, IoMode::Strict, 0);
        writer.append(&entry).unwrap();

        // Corrupt the CRC by rewriting the on-disk record.
        let content = fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&content).unwrap();
        json["record_crc32c"] = serde_json::json!(0);
        let mut payload = serde_json::to_vec(&json).unwrap();
        payload.push(b'\n');
        fs::write(&path, payload).unwrap();

        let mut reader = DurabilityLogWriter::open(&path).unwrap();
        let err = reader.read_all().unwrap_err();
        assert!(matches!(err, DurabilityLogError::CorruptRecord { .. }));
    }
}
