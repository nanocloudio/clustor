use crate::storage::layout::{CompactionAuthAck, StorageMetadata};
use serde::{Deserialize, Serialize};
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
                if ack.manifest_id == record.manifest_id && ack.auth_seq == record.auth_seq =>
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
    if quorum_sm_durable_index < snapshot_base_index {
        return snapshot_base_index;
    }
    let learner_floor = learner_slack_floor.unwrap_or(0);
    let quorum_floor = quorum_applied_index.min(snapshot_base_index);
    learner_floor.max(quorum_floor)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotAuthorizationRecord {
    pub manifest_id: String,
    pub base_index: u64,
    pub auth_seq: u64,
    pub manifest_hash: String,
    pub recorded_at_ms: u64,
}

pub struct ManifestAuthorizationLog {
    path: PathBuf,
}

impl ManifestAuthorizationLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, record: &SnapshotAuthorizationRecord) -> Result<(), ManifestLogError> {
        if let Some(latest) = self.latest()? {
            if record.auth_seq <= latest.auth_seq {
                return Err(ManifestLogError::OutOfOrderSeq {
                    expected: latest.auth_seq + 1,
                    observed: record.auth_seq,
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn computes_floor_with_learner_guard() {
        let floor = compute_compaction_floor(Some(1_250), 1_300, 1_200, 1_400);
        assert_eq!(floor, 1_250);
    }

    #[test]
    fn blocks_when_manifest_missing() {
        let state = CompactionState {
            learner_slack_floor: None,
            quorum_applied_index: 100,
            snapshot_base_index: 90,
            quorum_sm_durable_index: 100,
            guard_bytes_satisfied: true,
            learner_retirement_pending: false,
            manifest_gate: ManifestGate {
                relisted: false,
                signature_valid: false,
                authorization: None,
                acknowledgement: None,
            },
        };
        let request = CompactionPlanRequest {
            state,
            segments: Vec::new(),
        };
        match CompactionGate::plan(request) {
            CompactionDecision::Blocked(reasons) => {
                assert!(matches!(reasons[0], CompactionBlockReason::ManifestMissing));
            }
            _ => panic!("expected blocked"),
        }
    }

    #[test]
    fn ready_plan_skips_nonce_and_rewrite_segments() {
        let record = SnapshotAuthorizationRecord {
            manifest_id: "m1".into(),
            base_index: 90,
            auth_seq: 7,
            manifest_hash: "abc".into(),
            recorded_at_ms: 0,
        };
        let ack = CompactionAuthAck {
            manifest_id: "m1".into(),
            auth_seq: 7,
            acked_at_ms: 0,
        };
        let state = CompactionState {
            learner_slack_floor: None,
            quorum_applied_index: 100,
            snapshot_base_index: 90,
            quorum_sm_durable_index: 120,
            guard_bytes_satisfied: true,
            learner_retirement_pending: false,
            manifest_gate: ManifestGate {
                relisted: true,
                signature_valid: true,
                authorization: Some(record),
                acknowledgement: Some(ack),
            },
        };
        let segments = vec![
            SegmentHealth {
                segment_seq: 1,
                max_index_in_segment: 80,
                has_pending_nonce_reservation: false,
                abandon_record_present: false,
                rewrite_inflight: false,
            },
            SegmentHealth {
                segment_seq: 2,
                max_index_in_segment: 70,
                has_pending_nonce_reservation: true,
                abandon_record_present: false,
                rewrite_inflight: false,
            },
            SegmentHealth {
                segment_seq: 3,
                max_index_in_segment: 60,
                has_pending_nonce_reservation: false,
                abandon_record_present: false,
                rewrite_inflight: true,
            },
        ];
        let decision = CompactionGate::plan(CompactionPlanRequest { state, segments });
        match decision {
            CompactionDecision::Ready {
                floor_effective,
                deletable_segments,
                skipped_segments,
            } => {
                assert_eq!(floor_effective, 90);
                assert_eq!(deletable_segments, vec![1]);
                assert_eq!(skipped_segments.len(), 2);
            }
            _ => panic!("expected ready"),
        }
    }

    #[test]
    fn manifest_log_appends_and_reads() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("manifest.log");
        let log = ManifestAuthorizationLog::new(&log_path);
        let record = SnapshotAuthorizationRecord {
            manifest_id: "m2".into(),
            base_index: 42,
            auth_seq: 1,
            manifest_hash: "deadbeef".into(),
            recorded_at_ms: 123,
        };
        log.append(&record).unwrap();
        let read_back = log.latest().unwrap().unwrap();
        assert_eq!(read_back, record);
        let second = SnapshotAuthorizationRecord {
            manifest_id: "m3".into(),
            base_index: 50,
            auth_seq: 2,
            manifest_hash: "cafe".into(),
            recorded_at_ms: 124,
        };
        log.append(&second).unwrap();
        let records = log.load().unwrap();
        assert_eq!(records.len(), 2);
    }
}
