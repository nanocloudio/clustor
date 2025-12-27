use clustor::replication::raft::{PartitionQuorum, PartitionQuorumConfig, QuorumError, ReplicaId};

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
