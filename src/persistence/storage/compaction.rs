use crate::storage::layout::{CompactionAuthAck, StorageMetadata};
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Represents the current inputs needed to evaluate compaction gates.
#[derive(Debug, Clone)]
pub struct CompactionState {
    pub learner_slack_floor: Option<u64>,
    pub quorum_applied_index: u64,
    pub snapshot_base_index: u64,
    pub quorum_sm_durable_index: u64,
    pub guard_bytes_satisfied: bool,
    pub learner_retirement_pending: bool,
    pub manifest_gate: ManifestGate,
}

#[derive(Debug, Clone)]
pub struct ManifestGate {
    pub relisted: bool,
    pub signature_valid: bool,
    pub authorization: Option<SnapshotAuthorizationRecord>,
    pub acknowledgement: Option<CompactionAuthAck>,
}

impl ManifestGate {
    pub fn validate(&self, expected_base_index: u64) -> Result<(), CompactionBlockReason> {
        let Some(record) = &self.authorization else {
            return Err(CompactionBlockReason::ManifestMissing);
        };
        if record.base_index != expected_base_index {
            return Err(CompactionBlockReason::ManifestBaseIndexMismatch {
                manifest_base_index: record.base_index,
                snapshot_base_index: expected_base_index,
            });
        }
        if !self.relisted {
            return Err(CompactionBlockReason::ManifestNotRelisted);
        }
        if !self.signature_valid {
            return Err(CompactionBlockReason::ManifestSignatureInvalid {
                manifest_id: record.manifest_id.clone(),
            });
        }
        match &self.acknowledgement {
            Some(ack)
                if ack.manifest_id == record.manifest_id
                    && ack.auth_seq == record.auth_seq
                    && ack.manifest_hash == record.manifest_hash =>
            {
                Ok(())
            }
            Some(ack) => Err(CompactionBlockReason::ManifestAckMismatch {
                manifest_id: record.manifest_id.clone(),
                expected_auth_seq: record.auth_seq,
                observed_auth_seq: ack.auth_seq,
            }),
            None => Err(CompactionBlockReason::ManifestAckMissing {
                manifest_id: record.manifest_id.clone(),
                expected_auth_seq: record.auth_seq,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentHealth {
    pub segment_seq: u64,
    pub max_index_in_segment: u64,
    pub has_pending_nonce_reservation: bool,
    pub abandon_record_present: bool,
    pub rewrite_inflight: bool,
}

impl SegmentHealth {
    pub fn eligible_for_deletion(&self, floor: u64) -> bool {
        self.max_index_in_segment < floor
    }

    pub fn is_nonce_safe(&self) -> bool {
        !self.has_pending_nonce_reservation || self.abandon_record_present
    }
}

#[derive(Debug)]
pub struct CompactionPlanRequest {
    pub state: CompactionState,
    pub segments: Vec<SegmentHealth>,
}

#[derive(Debug)]
pub enum CompactionDecision {
    Blocked(Vec<CompactionBlockReason>),
    Ready {
        floor_effective: u64,
        deletable_segments: Vec<u64>,
        skipped_segments: Vec<SegmentSkipReason>,
    },
}

#[derive(Debug)]
pub enum SegmentSkipReason {
    NonceReservationPending { segment_seq: u64 },
    RewriteInflight { segment_seq: u64 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompactionBlockReason {
    #[error("manifest authorization missing")]
    ManifestMissing,
    #[error("manifest base index mismatch: manifest={manifest_base_index}, snapshot={snapshot_base_index}")]
    ManifestBaseIndexMismatch {
        manifest_base_index: u64,
        snapshot_base_index: u64,
    },
    #[error("manifest has not been re-listed")]
    ManifestNotRelisted,
    #[error("manifest signature invalid for {manifest_id}")]
    ManifestSignatureInvalid { manifest_id: String },
    #[error("compaction ack missing for manifest {manifest_id} seq {expected_auth_seq}")]
    ManifestAckMissing {
        manifest_id: String,
        expected_auth_seq: u64,
    },
    #[error(
        "compaction ack mismatch for manifest {manifest_id}: expected seq {expected_auth_seq}, observed {observed_auth_seq}"
    )]
    ManifestAckMismatch {
        manifest_id: String,
        expected_auth_seq: u64,
        observed_auth_seq: u64,
    },
    #[error(
        "quorum sm_durable_index {quorum_sm_durable_index} below snapshot base {snapshot_base_index}"
    )]
    SnapshotBaseNotDurable {
        quorum_sm_durable_index: u64,
        snapshot_base_index: u64,
    },
    #[error("checkpoint guard bytes not satisfied")]
    GuardBytesExceeded,
    #[error("learner retirement pending blocks compaction")]
    LearnerRetirementPending,
}

pub struct CompactionGate;

impl CompactionGate {
    pub fn plan(request: CompactionPlanRequest) -> CompactionDecision {
        let mut blockers = Vec::new();
        let floor = compute_compaction_floor(
            request.state.learner_slack_floor,
            request.state.quorum_applied_index,
            request.state.snapshot_base_index,
            request.state.quorum_sm_durable_index,
        );

        if request.state.quorum_sm_durable_index < request.state.snapshot_base_index {
            blockers.push(CompactionBlockReason::SnapshotBaseNotDurable {
                quorum_sm_durable_index: request.state.quorum_sm_durable_index,
                snapshot_base_index: request.state.snapshot_base_index,
            });
        }
        if !request.state.guard_bytes_satisfied {
            blockers.push(CompactionBlockReason::GuardBytesExceeded);
        }
        if request.state.learner_retirement_pending {
            blockers.push(CompactionBlockReason::LearnerRetirementPending);
        }
        if let Err(reason) = request
            .state
            .manifest_gate
            .validate(request.state.snapshot_base_index)
        {
            blockers.push(reason);
        }

        if !blockers.is_empty() {
            return CompactionDecision::Blocked(blockers);
        }

        let mut deletable = Vec::new();
        let mut skipped = Vec::new();
        for seg in request.segments {
            if !seg.eligible_for_deletion(floor) {
                continue;
            }
            if seg.rewrite_inflight {
                skipped.push(SegmentSkipReason::RewriteInflight {
                    segment_seq: seg.segment_seq,
                });
                continue;
            }
            if !seg.is_nonce_safe() {
                skipped.push(SegmentSkipReason::NonceReservationPending {
                    segment_seq: seg.segment_seq,
                });
                continue;
            }
            deletable.push(seg.segment_seq);
        }

        CompactionDecision::Ready {
            floor_effective: floor,
            deletable_segments: deletable,
            skipped_segments: skipped,
        }
    }
}

pub fn compute_compaction_floor(
    learner_slack_floor: Option<u64>,
    quorum_applied_index: u64,
    snapshot_base_index: u64,
    quorum_sm_durable_index: u64,
) -> u64 {
    let learner_floor = learner_slack_floor.unwrap_or(0);
    let quorum_floor = quorum_applied_index.min(snapshot_base_index);
    let floor = learner_floor.max(quorum_floor);
    floor.min(quorum_sm_durable_index)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotAuthorizationRecord {
    pub manifest_id: String,
    pub base_index: u64,
    pub auth_seq: u64,
    pub manifest_hash: String,
    pub recorded_at_ms: u64,
    pub chain_hash: String,
}

const ZERO_CHAIN: [u8; 32] = [0u8; 32];

pub fn authorization_chain_hash(
    previous_chain: Option<&str>,
    manifest_id: &str,
    auth_seq: u64,
    manifest_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    if let Some(prev) = previous_chain {
        let trimmed = prev.strip_prefix("0x").unwrap_or(prev);
        if let Ok(bytes) = hex::decode(trimmed) {
            if bytes.len() == ZERO_CHAIN.len() {
                hasher.update(bytes);
            } else {
                hasher.update(ZERO_CHAIN);
            }
        } else {
            hasher.update(ZERO_CHAIN);
        }
    } else {
        hasher.update(ZERO_CHAIN);
    }
    hasher.update(manifest_id.as_bytes());
    hasher.update(auth_seq.to_be_bytes());
    hasher.update(manifest_hash.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

pub struct ManifestAuthorizationLog {
    path: PathBuf,
}

impl ManifestAuthorizationLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, record: &SnapshotAuthorizationRecord) -> Result<(), ManifestLogError> {
        let latest = self.latest()?;
        if let Some(latest_record) = &latest {
            if record.auth_seq <= latest_record.auth_seq {
                return Err(ManifestLogError::OutOfOrderSeq {
                    expected: latest_record.auth_seq + 1,
                    observed: record.auth_seq,
                });
            }
        }
        let expected_chain = authorization_chain_hash(
            latest.as_ref().map(|entry| entry.chain_hash.as_str()),
            &record.manifest_id,
            record.auth_seq,
            &record.manifest_hash,
        );
        if record.chain_hash != expected_chain {
            return Err(ManifestLogError::ChainMismatch {
                expected: expected_chain,
                observed: record.chain_hash.clone(),
            });
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(record)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load(&self) -> Result<Vec<SnapshotAuthorizationRecord>, ManifestLogError> {
        match fs::File::open(&self.path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let mut records = Vec::new();
                for line in reader.lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    records.push(serde_json::from_str(&line)?);
                }
                Ok(records)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(ManifestLogError::Io(err)),
        }
    }

    pub fn latest(&self) -> Result<Option<SnapshotAuthorizationRecord>, ManifestLogError> {
        let records = self.load()?;
        Ok(records.into_iter().last())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Error)]
pub enum ManifestLogError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("authorization sequence out of order: expected {expected}, observed {observed}")]
    OutOfOrderSeq { expected: u64, observed: u64 },
    #[error("authorization chain mismatch: expected {expected}, observed {observed}")]
    ChainMismatch { expected: String, observed: String },
}

pub fn manifest_gate_from_metadata(
    metadata: &StorageMetadata,
    latest_record: Option<SnapshotAuthorizationRecord>,
    relisted: bool,
    signature_valid: bool,
) -> ManifestGate {
    let acknowledgement = latest_record
        .as_ref()
        .and_then(|record| metadata.compaction.ack_for(&record.manifest_id))
        .cloned();
    ManifestGate {
        relisted,
        signature_valid,
        authorization: latest_record,
        acknowledgement,
    }
}
