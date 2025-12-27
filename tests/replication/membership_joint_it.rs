use clustor::replication::membership::{
    JointConsensusConfig, JointConsensusManager, JointConsensusStatus, JointRollbackReason,
};
use clustor::replication::raft::{ReplicaId, ReplicaProgress};
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::{Duration, Instant};

fn rid(id: &str) -> ReplicaId {
    ReplicaId::new(id.to_string())
}

#[test]
fn transition_ready_when_all_caught_up() {
    let mut manager = JointConsensusManager::new(JointConsensusConfig {
        finalize_timeout: Duration::from_secs(10),
        target_index: 100,
    });
    let now = Instant::now();
    manager.begin_transition(
        HashSet::from_iter([rid("a"), rid("b"), rid("c")]),
        HashSet::from_iter([rid("a"), rid("b"), rid("c"), rid("d")]),
        now,
    );
    manager.record_progress(rid("a"), ReplicaProgress::new(5, 150), now);
    manager.record_progress(rid("d"), ReplicaProgress::new(5, 120), now);
    manager.record_progress(rid("b"), ReplicaProgress::new(5, 101), now);
    manager.record_progress(rid("c"), ReplicaProgress::new(5, 101), now);
    assert!(matches!(
        manager.status(now),
        Some(JointConsensusStatus::Ready)
    ));
}

#[test]
fn rollback_on_timeout() {
    let mut manager = JointConsensusManager::new(JointConsensusConfig {
        finalize_timeout: Duration::from_millis(5),
        target_index: 100,
    });
    let now = Instant::now();
    manager.begin_transition(HashSet::new(), HashSet::from_iter([rid("x")]), now);
    let status = manager.status(now + Duration::from_millis(10));
    assert!(matches!(
        status,
        Some(JointConsensusStatus::RollbackNeeded(
            JointRollbackReason::Timeout
        ))
    ));
}
