use clustor::{
    ElectionController, ElectionProfile, PartitionQuorum, PartitionQuorumConfig, ReplicaId,
};

fn rid(id: &str) -> ReplicaId {
    ReplicaId::new(id.to_string())
}

#[test]
fn three_voter_commit_requires_majority_term_match() {
    let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(3));
    for id in ["leader", "f1", "f2"] {
        quorum.register_replica(id);
    }

    quorum.record_match("leader", 4, 40).unwrap();
    quorum.record_match("f1", 3, 40).unwrap();
    assert_eq!(quorum.advance_commit(4), 0, "term mismatch blocks commit");

    quorum.record_match("f1", 4, 40).unwrap();
    let committed = quorum.advance_commit(4);
    assert_eq!(committed, 40);
    quorum
        .ensure_log_match(&rid("f1"), 40, 4)
        .expect("matching prefix validates");
}

#[test]
fn five_voter_pre_vote_only_grants_up_to_date_candidates() {
    let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(5));
    for id in ["leader", "a", "b", "c", "d"] {
        quorum.register_replica(id);
        quorum.record_match(id, 5, 55).unwrap();
    }

    let controller = ElectionController::new(ElectionProfile::Throughput, 99);
    let decision = controller.evaluate_pre_vote(&quorum, 5, 54);
    assert!(
        matches!(decision, clustor::PreVoteDecision::Rejected(_)),
        "candidate lagging index must be rejected"
    );
}
