use crate::replication::raft::{ReplicaId, ReplicaProgress};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct JointConsensusConfig {
    pub finalize_timeout: Duration,
    pub target_index: u64,
}

impl Default for JointConsensusConfig {
    fn default() -> Self {
        Self {
            finalize_timeout: Duration::from_secs(30),
            target_index: 0,
        }
    }
}

#[derive(Debug)]
pub struct JointConsensusManager {
    config: JointConsensusConfig,
    state: Option<JointState>,
}

impl JointConsensusManager {
    pub fn new(config: JointConsensusConfig) -> Self {
        Self {
            config,
            state: None,
        }
    }

    pub fn begin_transition(
        &mut self,
        old: HashSet<ReplicaId>,
        new: HashSet<ReplicaId>,
        now: Instant,
    ) {
        self.state = Some(JointState {
            old,
            new,
            progress: HashMap::new(),
            started_at: now,
            last_progress: now,
        });
    }

    pub fn record_progress(&mut self, replica: ReplicaId, progress: ReplicaProgress, now: Instant) {
        if let Some(state) = self.state.as_mut() {
            state.progress.insert(replica, progress);
            state.last_progress = now;
        }
    }

    pub fn status(&self, now: Instant) -> Option<JointConsensusStatus> {
        let state = self.state.as_ref()?;
        let ready = state.new.iter().all(|replica| {
            matches!(
                state.progress.get(replica),
                Some(progress) if progress.matched_index >= self.config.target_index
            )
        });
        if ready {
            return Some(JointConsensusStatus::Ready);
        }

        if now.saturating_duration_since(state.last_progress) > self.config.finalize_timeout {
            return Some(JointConsensusStatus::RollbackNeeded(
                JointRollbackReason::Timeout,
            ));
        }

        for replica in &state.new {
            if let Some(progress) = state.progress.get(replica) {
                if progress.matched_index + 128 < self.config.target_index {
                    return Some(JointConsensusStatus::RollbackNeeded(
                        JointRollbackReason::LaggingReplica {
                            replica: replica.clone(),
                            gap: self.config.target_index - progress.matched_index,
                        },
                    ));
                }
            }
        }

        Some(JointConsensusStatus::Pending(JointConsensusTelemetry {
            old_replicas: state.old.len(),
            new_replicas: state.new.len(),
            caught_up: state
                .new
                .iter()
                .filter(|replica| {
                    state
                        .progress
                        .get(*replica)
                        .map(|progress| progress.matched_index >= self.config.target_index)
                        .unwrap_or(false)
                })
                .count(),
            elapsed_ms: now.saturating_duration_since(state.started_at).as_millis() as u64,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JointConsensusStatus {
    Pending(JointConsensusTelemetry),
    Ready,
    RollbackNeeded(JointRollbackReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JointRollbackReason {
    Timeout,
    LaggingReplica { replica: ReplicaId, gap: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JointConsensusTelemetry {
    pub old_replicas: usize,
    pub new_replicas: usize,
    pub caught_up: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
struct JointState {
    old: HashSet<ReplicaId>,
    new: HashSet<ReplicaId>,
    progress: HashMap<ReplicaId, ReplicaProgress>,
    started_at: Instant,
    last_progress: Instant,
}
