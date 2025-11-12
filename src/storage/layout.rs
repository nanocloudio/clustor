use crate::bootstrap::boot_record::{BootRecord, BootRecordError, BootRecordStore};
use crate::consensus::RaftMetadataStore;
use crate::storage::compaction::{authorization_chain_hash, SnapshotAuthorizationRecord};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_LOG_SUFFIX: &str = ".log";
const SEGMENT_INDEX_SUFFIX: &str = ".idx";
const SNAPSHOT_PREFIX: &str = "snap-";
const MANIFEST_FILE: &str = "manifest.json";

/// Describes the canonical storage layout rooted at `/state/<partition_id>/`.
#[derive(Debug, Clone)]
pub struct StorageLayout {
    root: PathBuf,
}

impl StorageLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn paths(&self) -> StoragePaths {
        StoragePaths {
            root: self.root.clone(),
            wal_dir: self.root.join("wal"),
            snapshot_dir: self.root.join("snapshot"),
            definitions_dir: self.root.join("definitions"),
            metadata_file: self.root.join("metadata.json"),
            raft_metadata_file: self.root.join("raft_metadata.json"),
            boot_record_file: self.root.join("boot_record.json"),
            manifest_authorizations: self.root.join("snapshot/manifest_authorizations.log"),
            durability_log: self.root.join("wal/durability.log"),
        }
    }

    pub fn ensure(&self) -> Result<(), StorageLayoutError> {
        let paths = self.paths();
        fs::create_dir_all(&paths.wal_dir)?;
        fs::create_dir_all(&paths.snapshot_dir)?;
        fs::create_dir_all(&paths.definitions_dir)?;
        if let Some(parent) = paths.metadata_file.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = paths.raft_metadata_file.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = paths.boot_record_file.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        if let Some(parent) = paths.manifest_authorizations.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    pub fn metadata_store(&self) -> StorageMetadataStore {
        StorageMetadataStore::new(self.paths().metadata_file)
    }

    pub fn boot_record_store(&self) -> BootRecordStore {
        BootRecordStore::new(self.paths().boot_record_file)
    }

    pub fn raft_metadata_store(&self) -> RaftMetadataStore {
        RaftMetadataStore::new(self.paths().raft_metadata_file.clone())
    }

    pub fn load_state(&self) -> Result<StorageState, StorageLayoutError> {
        self.ensure()?;
        let paths = self.paths();
        let metadata = self.metadata_store().load_or_default()?;
        let boot_record = self.boot_record_store().load_or_default()?;
        let wal_segments = discover_wal_segments(&paths.wal_dir)?;
        let snapshots = discover_snapshots(&paths.snapshot_dir)?;
        Ok(StorageState {
            wal_segments,
            snapshots,
            metadata,
            boot_record,
            manifest_authorizations: paths.manifest_authorizations.clone(),
            definitions_dir: paths.definitions_dir.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct StoragePaths {
    pub root: PathBuf,
    pub wal_dir: PathBuf,
    pub snapshot_dir: PathBuf,
    pub definitions_dir: PathBuf,
    pub metadata_file: PathBuf,
    pub raft_metadata_file: PathBuf,
    pub boot_record_file: PathBuf,
    pub manifest_authorizations: PathBuf,
    pub durability_log: PathBuf,
}

#[derive(Debug)]
pub struct StorageState {
    pub wal_segments: Vec<WalSegmentRef>,
    pub snapshots: Vec<SnapshotEntry>,
    pub metadata: StorageMetadata,
    pub boot_record: BootRecord,
    pub manifest_authorizations: PathBuf,
    pub definitions_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct StorageMetadata {
    #[serde(default)]
    pub partition_id: String,
    #[serde(default)]
    pub snapshot_base_index: u64,
    #[serde(default)]
    pub quorum_applied_index: u64,
    #[serde(default)]
    pub compaction: CompactionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CompactionMetadata {
    #[serde(default)]
    pub latest_manifest_id: Option<String>,
    #[serde(default)]
    pub acknowledgements: Vec<CompactionAuthAck>,
    #[serde(default)]
    pub learner_retirement_pending: bool,
    #[serde(default)]
    pub nonce_abandons: Vec<NonceReservationAbandon>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompactionAuthAck {
    pub manifest_id: String,
    pub auth_seq: u64,
    pub manifest_hash: String,
    pub acked_at_ms: u64,
    pub chain_hash: String,
}

impl CompactionAuthAck {
    pub fn from_record(
        record: &SnapshotAuthorizationRecord,
        previous_chain: Option<&str>,
        acked_at_ms: u64,
    ) -> Self {
        Self {
            manifest_id: record.manifest_id.clone(),
            auth_seq: record.auth_seq,
            manifest_hash: record.manifest_hash.clone(),
            acked_at_ms,
            chain_hash: authorization_chain_hash(
                previous_chain,
                &record.manifest_id,
                record.auth_seq,
                &record.manifest_hash,
            ),
        }
    }
}

impl CompactionMetadata {
    pub fn record_ack(&mut self, ack: CompactionAuthAck) {
        self.latest_manifest_id = Some(ack.manifest_id.clone());
        self.acknowledgements.push(ack);
    }

    pub fn ack_for(&self, manifest_id: &str) -> Option<&CompactionAuthAck> {
        self.acknowledgements
            .iter()
            .find(|candidate| candidate.manifest_id == manifest_id)
    }

    pub fn record_abandon(&mut self, abandon: NonceReservationAbandon) {
        self.nonce_abandons.push(abandon);
    }

    pub fn abandon_for(&self, segment_seq: u64) -> Option<&NonceReservationAbandon> {
        self.nonce_abandons
            .iter()
            .find(|record| record.segment_seq == segment_seq)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NonceReservationAbandon {
    pub segment_seq: u64,
    pub abandon_reason: String,
    pub recorded_at_ms: u64,
}

#[derive(Debug)]
pub struct StorageMetadataStore {
    path: PathBuf,
}

impl StorageMetadataStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load_or_default(&self) -> Result<StorageMetadata, StorageMetadataError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(StorageMetadata::default()),
            Err(err) => Err(StorageMetadataError::Io(err)),
        }
    }

    pub fn persist(&self, metadata: &StorageMetadata) -> Result<(), StorageMetadataError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.path.with_extension("tmp");
        let mut file = fs::File::create(&tmp_path)?;
        let payload = serde_json::to_vec_pretty(metadata)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        fs::rename(tmp_path, &self.path)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Error)]
pub enum StorageMetadataError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalSegmentRef {
    pub seq: u64,
    pub log_path: PathBuf,
    pub index_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    pub term: u64,
    pub index: u64,
    pub manifest_path: PathBuf,
}

fn discover_wal_segments(dir: &Path) -> Result<Vec<WalSegmentRef>, StorageLayoutError> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if !has_suffix(&entry.file_name(), SEGMENT_LOG_SUFFIX) {
            continue;
        }
        let file_name = entry.file_name();
        let seq = parse_segment_seq(&file_name)
            .ok_or_else(|| StorageLayoutError::InvalidSegmentName { path: entry.path() })?;
        let index_name = replace_suffix(&file_name, SEGMENT_LOG_SUFFIX, SEGMENT_INDEX_SUFFIX);
        let index_path = dir.join(&index_name);
        segments.push(WalSegmentRef {
            seq,
            log_path: entry.path(),
            index_path: index_path.is_file().then_some(index_path),
        });
    }
    segments.sort_by_key(|segment| segment.seq);
    Ok(segments)
}

fn discover_snapshots(dir: &Path) -> Result<Vec<SnapshotEntry>, StorageLayoutError> {
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(SNAPSHOT_PREFIX) {
            continue;
        }
        let parts: Vec<&str> = name.split('-').collect();
        if parts.len() != 3 {
            return Err(StorageLayoutError::InvalidSnapshotDirectory { path: entry.path() });
        }
        let term = parts[1]
            .parse()
            .map_err(|_| StorageLayoutError::InvalidSnapshotDirectory { path: entry.path() })?;
        let index = parts[2]
            .parse()
            .map_err(|_| StorageLayoutError::InvalidSnapshotDirectory { path: entry.path() })?;
        let manifest_path = entry.path().join(MANIFEST_FILE);
        snapshots.push(SnapshotEntry {
            term,
            index,
            manifest_path,
        });
    }
    snapshots.sort_by_key(|snap| (snap.term, snap.index));
    Ok(snapshots)
}

fn parse_segment_seq(name: &OsStr) -> Option<u64> {
    let name = name.to_str()?;
    if !name.starts_with(SEGMENT_PREFIX) || !name.ends_with(SEGMENT_LOG_SUFFIX) {
        return None;
    }
    let digits = &name[SEGMENT_PREFIX.len()..name.len() - SEGMENT_LOG_SUFFIX.len()];
    digits.parse().ok()
}

fn has_suffix(name: &OsStr, suffix: &str) -> bool {
    name.to_str()
        .map(|value| value.ends_with(suffix))
        .unwrap_or(false)
}

fn replace_suffix(name: &OsStr, from: &str, to: &str) -> String {
    name.to_str()
        .map(|value| {
            if let Some(stripped) = value.strip_suffix(from) {
                format!("{stripped}{to}")
            } else {
                value.to_string()
            }
        })
        .unwrap_or_default()
}

#[derive(Debug, Error)]
pub enum StorageLayoutError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("metadata error: {0}")]
    Metadata(#[from] StorageMetadataError),
    #[error("boot record error: {0}")]
    BootRecord(#[from] BootRecordError),
    #[error("invalid WAL segment filename: {path:?}")]
    InvalidSegmentName { path: PathBuf },
    #[error("invalid snapshot directory: {path:?}")]
    InvalidSnapshotDirectory { path: PathBuf },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::boot_record::BootRecord;
    use tempfile::TempDir;

    #[test]
    fn raft_metadata_store_aligns_with_layout() {
        let tmp = TempDir::new().unwrap();
        let layout = StorageLayout::new(tmp.path());
        let store = layout.raft_metadata_store();
        assert_eq!(
            store.path().strip_prefix(tmp.path()).unwrap(),
            Path::new("raft_metadata.json")
        );
    }

    #[test]
    fn ensures_tree_and_loads_defaults() {
        let tmp = TempDir::new().unwrap();
        let layout = StorageLayout::new(tmp.path());
        let state = layout.load_state().unwrap();
        assert!(state.wal_segments.is_empty());
        assert!(state.snapshots.is_empty());
        assert_eq!(state.metadata.partition_id, "");
        assert!(layout.paths().wal_dir.exists());
        assert!(layout.paths().snapshot_dir.exists());
    }

    #[test]
    fn discovers_segments_and_snapshots() {
        let tmp = TempDir::new().unwrap();
        let layout = StorageLayout::new(tmp.path());
        layout.ensure().unwrap();

        let wal_dir = layout.paths().wal_dir.clone();
        fs::write(wal_dir.join("segment-0000000001.log"), b"log").unwrap();
        fs::write(wal_dir.join("segment-0000000001.idx"), b"idx").unwrap();
        fs::write(wal_dir.join("segment-0000000002.log"), b"log").unwrap();

        let snap_dir = layout.paths().snapshot_dir.join("snap-5-42");
        fs::create_dir_all(&snap_dir).unwrap();
        fs::write(snap_dir.join(MANIFEST_FILE), b"{}").unwrap();

        let metadata = StorageMetadata {
            partition_id: "p1".into(),
            ..StorageMetadata::default()
        };
        layout.metadata_store().persist(&metadata).unwrap();

        let boot = BootRecord {
            fsync_probe: None,
            disk_policy: None,
        };
        let store = layout.boot_record_store();
        store.persist(&boot).unwrap();

        let state = layout.load_state().unwrap();
        assert_eq!(state.metadata.partition_id, "p1");
        assert_eq!(state.wal_segments.len(), 2);
        assert_eq!(state.wal_segments[0].seq, 1);
        assert!(state.wal_segments[0].index_path.is_some());
        assert_eq!(state.snapshots.len(), 1);
        assert_eq!(state.snapshots[0].term, 5);
        assert_eq!(state.snapshots[0].index, 42);
    }
}
