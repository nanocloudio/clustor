use clustor::membership::{
    evaluate_survivability, CatchUpDecision, JointConsensusConfig, JointConsensusManager,
    LearnerCatchUpConfig, LearnerCatchUpEvaluator, SurvivabilityInputs,
};
use clustor::raft::ReplicaId;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::{Duration, Instant};

fn rid(id: &str) -> ReplicaId {
    ReplicaId::new(id.to_string())
}

#[test]
fn joint_transition_rolls_back_when_survivability_fails() {
    let mut manager = JointConsensusManager::new(JointConsensusConfig {
        finalize_timeout: Duration::from_millis(1),
        target_index: 50,
    });
    let now = Instant::now();
    manager.begin_transition(
        HashSet::from_iter([rid("a"), rid("b"), rid("c")]),
        HashSet::from_iter([rid("a"), rid("b"), rid("c"), rid("d")]),
        now,
    );
    let status = manager.status(now + Duration::from_millis(5)).unwrap();
    assert!(matches!(
        status,
        clustor::membership::JointConsensusStatus::RollbackNeeded(_)
    ));

    let survivability = evaluate_survivability(SurvivabilityInputs {
        voters: 4,
        healthy: 3,
        planned_outages: 2,
        fault_domains: 2,
        tolerated_faults: 1,
    });
    assert!(matches!(
        survivability.quorum_result,
        clustor::membership::SurvivabilityResult::Fail
    ));
}

#[test]
fn learner_catch_up_combined_with_joint_manager_reaches_ready() {
    let mut manager = JointConsensusManager::new(JointConsensusConfig {
        finalize_timeout: Duration::from_secs(5),
        target_index: 100,
    });
    let now = Instant::now();
    manager.begin_transition(
        HashSet::from_iter([rid("a"), rid("b"), rid("c")]),
        HashSet::from_iter([rid("a"), rid("b"), rid("c"), rid("d")]),
        now,
    );

    let mut evaluator = LearnerCatchUpEvaluator::new(LearnerCatchUpConfig::default());
    evaluator.record_progress(90, 0, now);
    assert_eq!(
        evaluator.evaluate(200, 0, now + Duration::from_secs(1)),
        CatchUpDecision::Healthy
    );

    evaluator.record_progress(210, 0, now + Duration::from_secs(2));
    assert_eq!(
        evaluator.evaluate(220, 0, now + Duration::from_secs(2)),
        CatchUpDecision::Healthy
    );

    manager.record_progress(
        rid("d"),
        clustor::raft::ReplicaProgress::new(7, 205),
        now + Duration::from_secs(2),
    );
    manager.record_progress(
        rid("b"),
        clustor::raft::ReplicaProgress::new(7, 205),
        now + Duration::from_secs(2),
    );
    manager.record_progress(
        rid("a"),
        clustor::raft::ReplicaProgress::new(7, 205),
        now + Duration::from_secs(2),
    );
    manager.record_progress(
        rid("c"),
        clustor::raft::ReplicaProgress::new(7, 205),
        now + Duration::from_secs(2),
    );

    let status = manager.status(now + Duration::from_secs(3)).unwrap();
    assert!(matches!(
        status,
        clustor::membership::JointConsensusStatus::Ready
    ));
}
