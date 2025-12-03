use clustor::{
    AppendEntriesProcessor, AppendEntriesRequest, ElectionController, ElectionProfile,
    RaftLogEntry, RaftLogStore, RaftRouting,
};
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn new_store() -> (TempDir, RaftLogStore) {
    let tmp = TempDir::new().unwrap();
    let store = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    (tmp, store)
}

fn routing(epoch: u64) -> RaftRouting {
    RaftRouting::alias("partition-test", epoch)
}

#[test]
fn append_entries_resolves_log_divergence() {
    let (_tmp, mut follower) = new_store();
    follower
        .append(RaftLogEntry::new(1, 1, b"alpha".to_vec()))
        .unwrap();
    follower
        .append(RaftLogEntry::new(2, 2, b"stale".to_vec()))
        .unwrap();

    let entries = vec![
        RaftLogEntry::new(2, 2, b"beta".to_vec()),
        RaftLogEntry::new(2, 3, b"gamma".to_vec()),
    ];
    let request = AppendEntriesRequest {
        term: 3,
        leader_id: "leader-a".into(),
        prev_log_index: 1,
        prev_log_term: 1,
        leader_commit: 3,
        entries,
        routing: routing(3),
    };
    let mut processor = AppendEntriesProcessor::new(&mut follower);
    let outcome = processor.apply(&request).unwrap();
    assert!(outcome.success);
    assert_eq!(outcome.match_index, 3);
    assert_eq!(follower.last_index(), 3);
    assert_eq!(follower.term_at(2), Some(2));
}

#[test]
fn follower_catches_up_over_multiple_batches() {
    let (_tmp, mut follower) = new_store();
    let mut processor = AppendEntriesProcessor::new(&mut follower);
    let batch_a = AppendEntriesRequest {
        term: 5,
        leader_id: "leader-b".into(),
        prev_log_index: 0,
        prev_log_term: 0,
        leader_commit: 0,
        entries: vec![
            RaftLogEntry::new(5, 1, b"cmd1".to_vec()),
            RaftLogEntry::new(5, 2, b"cmd2".to_vec()),
        ],
        routing: routing(5),
    };
    processor.apply(&batch_a).unwrap();

    let batch_b = AppendEntriesRequest {
        term: 5,
        leader_id: "leader-b".into(),
        prev_log_index: 2,
        prev_log_term: 5,
        leader_commit: 2,
        entries: vec![
            RaftLogEntry::new(5, 3, b"cmd3".to_vec()),
            RaftLogEntry::new(5, 4, b"cmd4".to_vec()),
        ],
        routing: routing(5),
    };
    let outcome = processor.apply(&batch_b).unwrap();
    assert!(outcome.success);
    assert_eq!(follower.last_index(), 4);
}

#[test]
fn candidate_re_election_resets_timer() {
    let mut controller = ElectionController::new(ElectionProfile::Latency, 99);
    let now = Instant::now();
    let mut candidate = controller.spawn_candidate("node-a", 7, now);
    assert!(!candidate.timer().expired(now));
    candidate.timer_mut().reset(now, Duration::from_millis(5));
    assert!(candidate.timer().expired(now + Duration::from_millis(6)));

    candidate.record_vote("node-b", true);
    candidate.record_vote("node-c", true);
    assert!(candidate.quorum_reached(2));
}
