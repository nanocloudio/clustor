use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

const QUORUM_SPEC_CLAUSE: &str = "§0.2.Raft";

/// Unique identifier for replicas/voters within a partition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplicaId(String);

impl ReplicaId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl From<&str> for ReplicaId {
    fn from(value: &str) -> Self {
        ReplicaId::new(value)
    }
}

impl From<String> for ReplicaId {
    fn from(value: String) -> Self {
        ReplicaId::new(value)
    }
}

/// Configuration for quorum calculations.
#[derive(Debug, Clone, Copy)]
pub struct PartitionQuorumConfig {
    voters: usize,
}

impl PartitionQuorumConfig {
    pub fn new(voters: usize) -> Self {
        assert!(voters >= 1, "partition must have at least one voter");
        Self { voters }
    }

    pub fn voters(&self) -> usize {
        self.voters
    }

    pub fn quorum(&self) -> usize {
        self.voters / 2 + 1
    }
}

/// Snapshot of a replica's log progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaProgress {
    pub matched_index: u64,
    pub matched_term: u64,
}

impl ReplicaProgress {
    pub fn new(matched_term: u64, matched_index: u64) -> Self {
        Self {
            matched_term,
            matched_index,
        }
    }
}

/// Aggregated status exported for telemetry or tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionQuorumStatus {
    pub committed_index: u64,
    pub committed_term: u64,
    pub quorum_size: usize,
}

#[derive(Debug)]
pub struct PartitionQuorum {
    config: PartitionQuorumConfig,
    progress: HashMap<ReplicaId, ReplicaProgress>,
    committed_index: u64,
    committed_term: u64,
}

impl PartitionQuorum {
    pub fn new(config: PartitionQuorumConfig) -> Self {
        Self {
            config,
            progress: HashMap::with_capacity(config.voters),
            committed_index: 0,
            committed_term: 0,
        }
    }

    pub fn register_replica(&mut self, id: impl Into<ReplicaId>) {
        let id = id.into();
        self.progress.entry(id).or_insert(ReplicaProgress {
            matched_index: 0,
            matched_term: 0,
        });
    }

    pub fn record_match(
        &mut self,
        id: impl Into<ReplicaId>,
        matched_term: u64,
        matched_index: u64,
    ) -> Result<(), QuorumError> {
        let id = id.into();
        let replica_id = id.clone();
        let progress = self.progress.entry(id).or_insert(ReplicaProgress {
            matched_index: 0,
            matched_term: 0,
        });

        if matched_index < progress.matched_index {
            warn!(
                "event=raft_quorum_violation clause={} kind=MatchedIndexRegression replica={} previous={} attempted={}",
                QUORUM_SPEC_CLAUSE,
                replica_label(&replica_id),
                progress.matched_index,
                matched_index
            );
            return Err(QuorumError::MatchedIndexRegression {
                previous: progress.matched_index,
                attempted: matched_index,
            });
        }

        if matched_index == progress.matched_index
            && matched_index != 0
            && matched_term < progress.matched_term
        {
            warn!(
                "event=raft_quorum_violation clause={} kind=TermRegressionAtIndex replica={} index={} previous_term={} attempted_term={}",
                QUORUM_SPEC_CLAUSE,
                replica_label(&replica_id),
                matched_index,
                progress.matched_term,
                matched_term
            );
            return Err(QuorumError::TermRegressionAtIndex {
                index: matched_index,
                previous_term: progress.matched_term,
                attempted_term: matched_term,
            });
        }

        progress.matched_index = matched_index;
        progress.matched_term = matched_term;
        Ok(())
    }

    /// Applies a follower-reported conflict by dropping its matched index.
    /// Never allows truncation beneath the committed index.
    pub fn record_conflict(
        &mut self,
        id: impl Into<ReplicaId>,
        new_index: u64,
        new_term: u64,
    ) -> Result<(), QuorumError> {
        let id = id.into();
        let replica_id = id.clone();
        if new_index < self.committed_index {
            warn!(
                "event=raft_quorum_violation clause={} kind=ConflictBeforeCommit committed_index={} attempted={}",
                QUORUM_SPEC_CLAUSE,
                self.committed_index,
                new_index
            );
            return Err(QuorumError::ConflictBeforeCommit {
                committed_index: self.committed_index,
                attempted: new_index,
            });
        }

        let entry = self.progress.entry(id).or_insert(ReplicaProgress {
            matched_index: 0,
            matched_term: 0,
        });

        if new_index > entry.matched_index {
            warn!(
                "event=raft_quorum_violation clause={} kind=ConflictAdvancesProgress replica={} current_index={} attempted_index={}",
                QUORUM_SPEC_CLAUSE,
                replica_label(&replica_id),
                entry.matched_index,
                new_index
            );
            return Err(QuorumError::ConflictAdvancesProgress {
                current: entry.matched_index,
                attempted: new_index,
            });
        }

        entry.matched_index = new_index;
        entry.matched_term = new_term;
        Ok(())
    }

    /// Ensures the caller only appends entries when the follower shares the requested prefix.
    pub fn ensure_log_match(
        &self,
        id: &ReplicaId,
        prev_index: u64,
        prev_term: u64,
    ) -> Result<(), QuorumError> {
        let progress = self.progress.get(id).ok_or_else(|| {
            warn!(
                "event=raft_quorum_violation clause={} kind=UnknownReplica replica={:?}",
                QUORUM_SPEC_CLAUSE, id
            );
            QuorumError::UnknownReplica
        })?;
        if progress.matched_index < prev_index {
            warn!(
                "event=raft_quorum_violation clause={} kind=MissingPrefix replica={:?} needed_index={} replica_index={}",
                QUORUM_SPEC_CLAUSE,
                id,
                prev_index,
                progress.matched_index
            );
            return Err(QuorumError::MissingPrefix {
                needed_index: prev_index,
                replica_index: progress.matched_index,
            });
        }

        if progress.matched_index == prev_index && progress.matched_term != prev_term {
            warn!(
                "event=raft_quorum_violation clause={} kind=TermMismatch replica={:?} index={} expected={} observed={}",
                QUORUM_SPEC_CLAUSE,
                id,
                prev_index,
                progress.matched_term,
                prev_term
            );
            return Err(QuorumError::TermMismatch {
                index: prev_index,
                expected: progress.matched_term,
                observed: prev_term,
            });
        }

        Ok(())
    }

    /// Advances the committed index when a quorum replicated an entry from the leader's term.
    pub fn advance_commit(&mut self, leader_term: u64) -> u64 {
        if self.progress.len() < self.config.quorum() {
            return self.committed_index;
        }

        let mut matches: Vec<ReplicaProgress> = self.progress.values().copied().collect();
        matches.sort_by(|a, b| {
            a.matched_index
                .cmp(&b.matched_index)
                .then_with(|| a.matched_term.cmp(&b.matched_term))
        });

        let candidate = matches[matches.len() - self.config.quorum()];
        if candidate.matched_index > self.committed_index && candidate.matched_term == leader_term {
            self.committed_index = candidate.matched_index;
            self.committed_term = candidate.matched_term;
            info!(
                "event=raft_commit_advance clause={} committed_index={} committed_term={} quorum_size={}",
                QUORUM_SPEC_CLAUSE,
                self.committed_index,
                self.committed_term,
                self.config.quorum()
            );
        }
        self.committed_index
    }

    pub fn status(&self) -> PartitionQuorumStatus {
        PartitionQuorumStatus {
            committed_index: self.committed_index,
            committed_term: self.committed_term,
            quorum_size: self.config.quorum(),
        }
    }

    pub fn is_candidate_up_to_date(&self, candidate_term: u64, candidate_index: u64) -> bool {
        let max = self
            .progress
            .values()
            .max_by(|a, b| compare_progress(a, b))
            .copied()
            .unwrap_or(ReplicaProgress {
                matched_index: 0,
                matched_term: 0,
            });

        compare_log(
            cand_id(candidate_term, candidate_index),
            cand_id(max.matched_term, max.matched_index),
        ) != Ordering::Less
    }
}

fn replica_label(replica: &ReplicaId) -> &str {
    &replica.0
}

fn compare_progress(a: &ReplicaProgress, b: &ReplicaProgress) -> Ordering {
    compare_log(
        cand_id(a.matched_term, a.matched_index),
        cand_id(b.matched_term, b.matched_index),
    )
}

fn compare_log(a: (u64, u64), b: (u64, u64)) -> Ordering {
    match a.0.cmp(&b.0) {
        Ordering::Equal => a.1.cmp(&b.1),
        other => other,
    }
}

fn cand_id(term: u64, index: u64) -> (u64, u64) {
    (term, index)
}

#[derive(Debug, thiserror::Error)]
pub enum QuorumError {
    #[error("replica matched index regression: previous={previous} attempted={attempted}")]
    MatchedIndexRegression { previous: u64, attempted: u64 },

    #[error(
        "term regression at index {index}: previous={previous_term} attempted={attempted_term}"
    )]
    TermRegressionAtIndex {
        index: u64,
        previous_term: u64,
        attempted_term: u64,
    },

    #[error(
        "conflict attempts to drop below committed index {committed_index} (attempted {attempted})"
    )]
    ConflictBeforeCommit {
        committed_index: u64,
        attempted: u64,
    },

    #[error("conflict advance detected (current {current}, attempted {attempted})")]
    ConflictAdvancesProgress { current: u64, attempted: u64 },

    #[error("unknown replica")]
    UnknownReplica,

    #[error("replica missing required prefix: needed {needed_index}, replica {replica_index}")]
    MissingPrefix {
        needed_index: u64,
        replica_index: u64,
    },

    #[error("term mismatch at index {index}: expected {expected}, observed {observed}")]
    TermMismatch {
        index: u64,
        expected: u64,
        observed: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(id: &str) -> ReplicaId {
        ReplicaId::new(id)
    }

    #[test]
    fn record_progress_is_monotone() {
        let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(3));
        quorum.register_replica("a");
        quorum.record_match("a", 1, 10).unwrap();

        let err = quorum.record_match("a", 1, 9).unwrap_err();
        assert!(matches!(err, QuorumError::MatchedIndexRegression { .. }));

        let err = quorum.record_match("a", 0, 10).unwrap_err();
        assert!(matches!(err, QuorumError::TermRegressionAtIndex { .. }));
    }

    #[test]
    fn advance_commit_respects_leader_term() {
        let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(5));
        for id in ["a", "b", "c", "d", "e"] {
            quorum.register_replica(id);
        }

        for id in ["a", "b", "c"] {
            quorum.record_match(id, 2, 15).unwrap();
        }
        quorum.record_match("d", 1, 20).unwrap();
        quorum.record_match("e", 1, 20).unwrap();

        let committed = quorum.advance_commit(2);
        assert_eq!(committed, 15);
        assert_eq!(quorum.status().committed_term, 2);

        let committed = quorum.advance_commit(3);
        assert_eq!(committed, 15, "cannot advance without matching term");
    }

    #[test]
    fn ensure_log_match_blocks_missing_prefix() {
        let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(3));
        quorum.register_replica("a");
        quorum.record_match("a", 5, 50).unwrap();

        let err = quorum
            .ensure_log_match(&rid("a"), 60, 6)
            .expect_err("should fail when follower is behind");
        assert!(matches!(err, QuorumError::MissingPrefix { .. }));
    }

    #[test]
    fn candidate_up_to_date_follows_term_then_index() {
        let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(3));
        for id in ["a", "b", "c"] {
            quorum.register_replica(id);
            quorum.record_match(id, 3, 30).unwrap();
        }
        assert!(quorum.is_candidate_up_to_date(3, 30));
        assert!(quorum.is_candidate_up_to_date(4, 10));
        assert!(!quorum.is_candidate_up_to_date(2, 100));
    }
}
