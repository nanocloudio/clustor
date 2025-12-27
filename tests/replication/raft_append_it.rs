use clustor::replication::consensus::{RaftLogEntry, RaftLogStore};
use clustor::replication::raft::append::{
    AppendEntriesCoordinator, AppendEntriesProcessor, HeartbeatBatcher,
};
use clustor::replication::raft::rpc::{AppendEntriesRequest, RaftRouting};
use tempfile::TempDir;

fn store() -> (TempDir, RaftLogStore) {
    let tmp = TempDir::new().unwrap();
    let log = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    (tmp, log)
}

fn routing(epoch: u64) -> RaftRouting {
    RaftRouting::alias("partition-test", epoch)
}

#[test]
fn applies_entries_and_advances_match_index() {
    let (_tmp, mut log) = store();
    log.append(RaftLogEntry::new(1, 1, b"a".to_vec())).unwrap();
    log.append(RaftLogEntry::new(1, 2, b"b".to_vec())).unwrap();
    let mut processor = AppendEntriesProcessor::new(&mut log);
    let request = AppendEntriesRequest {
        term: 2,
        leader_id: "l".into(),
        prev_log_index: 2,
        prev_log_term: 1,
        leader_commit: 2,
        entries: vec![
            RaftLogEntry::new(2, 3, b"c".to_vec()),
            RaftLogEntry::new(2, 4, b"d".to_vec()),
        ],
        routing: routing(2),
    };
    let outcome = processor.apply(&request).unwrap();
    assert!(outcome.success);
    assert_eq!(outcome.match_index, 4);
    assert_eq!(log.last_index(), 4);
}

#[test]
fn detects_conflicting_prefix() {
    let (_tmp, mut log) = store();
    log.append(RaftLogEntry::new(1, 1, b"a".to_vec())).unwrap();
    log.append(RaftLogEntry::new(2, 2, b"b".to_vec())).unwrap();
    log.append(RaftLogEntry::new(2, 3, b"c".to_vec())).unwrap();
    let mut processor = AppendEntriesProcessor::new(&mut log);
    let request = AppendEntriesRequest {
        term: 3,
        leader_id: "l".into(),
        prev_log_index: 2,
        prev_log_term: 2,
        leader_commit: 1,
        entries: vec![RaftLogEntry::new(3, 3, b"x".to_vec())],
        routing: routing(3),
    };
    let outcome = processor.apply(&request).unwrap();
    assert!(outcome.success);
    assert_eq!(log.term_at(3), Some(3));
}

#[test]
fn reports_missing_prefix() {
    let (_tmp, mut log) = store();
    let mut processor = AppendEntriesProcessor::new(&mut log);
    let request = AppendEntriesRequest {
        term: 1,
        leader_id: "l".into(),
        prev_log_index: 5,
        prev_log_term: 1,
        leader_commit: 0,
        entries: Vec::new(),
        routing: routing(1),
    };
    let outcome = processor.apply(&request).unwrap();
    assert!(!outcome.success);
    assert_eq!(outcome.conflict_index, Some(5));
}

#[test]
fn batches_heartbeats() {
    let mut batcher = HeartbeatBatcher::new(2);
    assert!(batcher
        .enqueue(AppendEntriesRequest::heartbeat(1, "l", 0, routing(1)))
        .is_none());
    let flushed = batcher
        .enqueue(AppendEntriesRequest::heartbeat(1, "l", 0, routing(1)))
        .unwrap();
    assert_eq!(flushed.len(), 2);
    assert!(batcher.flush().is_empty());
}

#[test]
fn coordinator_advances_cursor_on_success() {
    let (_tmp, mut log) = store();
    log.append(RaftLogEntry::new(1, 1, b"a".to_vec())).unwrap();
    let mut coordinator = AppendEntriesCoordinator::new(&mut log);
    assert_eq!(coordinator.wal_cursor(), 1);
    let request = AppendEntriesRequest {
        term: 2,
        leader_id: "l".into(),
        prev_log_index: 1,
        prev_log_term: 1,
        leader_commit: 1,
        entries: vec![
            RaftLogEntry::new(2, 2, b"b".to_vec()),
            RaftLogEntry::new(2, 3, b"c".to_vec()),
        ],
        routing: routing(2),
    };
    let report = coordinator.apply(&request).unwrap();
    assert!(report.success());
    assert!(report.advanced());
    assert_eq!(report.previous_wal_index, 1);
    assert_eq!(report.current_wal_index, 3);
}

#[test]
fn coordinator_preserves_cursor_on_conflict() {
    let (_tmp, mut log) = store();
    log.append(RaftLogEntry::new(1, 1, b"a".to_vec())).unwrap();
    log.append(RaftLogEntry::new(2, 2, b"b".to_vec())).unwrap();
    let mut coordinator = AppendEntriesCoordinator::new(&mut log);
    let request = AppendEntriesRequest {
        term: 3,
        leader_id: "l".into(),
        prev_log_index: 2,
        prev_log_term: 1,
        leader_commit: 2,
        entries: vec![RaftLogEntry::new(3, 3, b"c".to_vec())],
        routing: routing(3),
    };
    let report = coordinator.apply(&request).unwrap();
    assert!(!report.success());
    assert_eq!(report.previous_wal_index, report.current_wal_index);
    let conflict = report.conflict().expect("conflict expected");
    assert_eq!(conflict.0, 2);
}
