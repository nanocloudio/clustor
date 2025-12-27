use crate::replication::consensus::{RaftLogError, RaftLogStore};
use crate::replication::raft::rpc::{AppendEntriesRequest, AppendEntriesResponse};
use log::warn;

/// Applies AppendEntries RPCs to a `RaftLogStore`, enforcing log matching and truncation rules.
#[derive(Debug)]
pub struct AppendEntriesProcessor<'a> {
    log: &'a mut RaftLogStore,
}

#[derive(Debug)]
pub struct AppendEntriesCoordinator<'a> {
    processor: AppendEntriesProcessor<'a>,
    wal_cursor: u64,
}

#[derive(Debug, Clone)]
pub struct AppendEntriesReport {
    pub outcome: AppendEntriesOutcome,
    pub previous_wal_index: u64,
    pub current_wal_index: u64,
}

const RAFT_SPEC_CLAUSE: &str = "§3.1.LogMatching";

impl<'a> AppendEntriesProcessor<'a> {
    pub fn new(log: &'a mut RaftLogStore) -> Self {
        Self { log }
    }

    pub fn apply(
        &mut self,
        request: &AppendEntriesRequest,
    ) -> Result<AppendEntriesOutcome, RaftLogError> {
        if request.prev_log_index > 0 {
            match self.log.entry(request.prev_log_index)? {
                Some(entry) if entry.term == request.prev_log_term => {}
                Some(entry) => {
                    warn!(
                        "event=raft_append_reject clause={} reason=term_mismatch prev_log_index={} expected_term={} observed_term={} leader_term={}",
                        RAFT_SPEC_CLAUSE,
                        request.prev_log_index,
                        request.prev_log_term,
                        entry.term,
                        request.term
                    );
                    return Ok(AppendEntriesOutcome::conflict(
                        entry.index,
                        Some(entry.term),
                    ));
                }
                None => {
                    warn!(
                        "event=raft_append_reject clause={} reason=missing_prefix prev_log_index={} leader_term={}",
                        RAFT_SPEC_CLAUSE,
                        request.prev_log_index,
                        request.term
                    );
                    return Ok(AppendEntriesOutcome::conflict(request.prev_log_index, None));
                }
            }
        }

        let mut append_from = request.entries.len();
        for (idx, entry) in request.entries.iter().enumerate() {
            if let Some(existing) = self.log.entry(entry.index)? {
                if existing.term != entry.term {
                    warn!(
                        "event=raft_truncate_conflict clause={} reason=term_conflict index={} existing_term={} incoming_term={} leader_term={}",
                        RAFT_SPEC_CLAUSE,
                        entry.index,
                        existing.term,
                        entry.term,
                        request.term
                    );
                    self.log.truncate_from(entry.index)?;
                    append_from = idx;
                    break;
                } else {
                    append_from = idx + 1;
                    continue;
                }
            } else {
                append_from = idx;
                break;
            }
        }

        if append_from < request.entries.len() {
            self.log.append_batch(&request.entries[append_from..])?;
        }
        let match_index = request
            .entries
            .last()
            .map(|entry| entry.index)
            .unwrap_or(request.prev_log_index);
        Ok(AppendEntriesOutcome::success(match_index))
    }
}

impl<'a> AppendEntriesCoordinator<'a> {
    pub fn new(log: &'a mut RaftLogStore) -> Self {
        let cursor = log.last_index();
        Self {
            processor: AppendEntriesProcessor::new(log),
            wal_cursor: cursor,
        }
    }

    pub fn apply(
        &mut self,
        request: &AppendEntriesRequest,
    ) -> Result<AppendEntriesReport, RaftLogError> {
        let outcome = self.processor.apply(request)?;
        let previous = self.wal_cursor;
        if outcome.success {
            self.wal_cursor = outcome.match_index;
        }
        Ok(AppendEntriesReport {
            outcome,
            previous_wal_index: previous,
            current_wal_index: self.wal_cursor,
        })
    }

    pub fn wal_cursor(&self) -> u64 {
        self.wal_cursor
    }
}

impl AppendEntriesReport {
    pub fn conflict(&self) -> Option<(u64, Option<u64>)> {
        if self.outcome.success {
            None
        } else {
            self.outcome
                .conflict_index
                .map(|idx| (idx, self.outcome.conflict_term))
        }
    }

    pub fn success(&self) -> bool {
        self.outcome.success
    }

    pub fn advanced(&self) -> bool {
        self.success() && self.current_wal_index > self.previous_wal_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendEntriesOutcome {
    pub success: bool,
    pub match_index: u64,
    pub conflict_index: Option<u64>,
    pub conflict_term: Option<u64>,
}

impl AppendEntriesOutcome {
    pub fn success(match_index: u64) -> Self {
        Self {
            success: true,
            match_index,
            conflict_index: None,
            conflict_term: None,
        }
    }

    pub fn conflict(conflict_index: u64, conflict_term: Option<u64>) -> Self {
        Self {
            success: false,
            match_index: 0,
            conflict_index: Some(conflict_index),
            conflict_term,
        }
    }

    pub fn to_response(self, term: u64) -> AppendEntriesResponse {
        AppendEntriesResponse {
            term,
            success: self.success,
            match_index: self.match_index,
            conflict_index: self.conflict_index,
            conflict_term: self.conflict_term,
        }
    }
}

/// Simple batching helper that groups heartbeat (empty) AppendEntries requests.
#[derive(Debug)]
pub struct HeartbeatBatcher {
    max_batch: usize,
    pending: Vec<AppendEntriesRequest>,
}

impl HeartbeatBatcher {
    pub fn new(max_batch: usize) -> Self {
        assert!(max_batch > 0);
        Self {
            max_batch,
            pending: Vec::with_capacity(max_batch),
        }
    }

    pub fn enqueue(&mut self, request: AppendEntriesRequest) -> Option<Vec<AppendEntriesRequest>> {
        self.pending.push(request);
        if self.pending.len() >= self.max_batch {
            Some(self.flush())
        } else {
            None
        }
    }

    pub fn flush(&mut self) -> Vec<AppendEntriesRequest> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let mut drained = Vec::new();
        std::mem::swap(&mut drained, &mut self.pending);
        drained
    }
}
