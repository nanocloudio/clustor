#[path = "../support/env.rs"]
mod env_support;

use clustor::replication::consensus::{RaftLogEntry, RaftLogStore};
use env_support::EnvVarGuard;
use tempfile::TempDir;

fn store_with_encoding(env_value: Option<&str>) -> (TempDir, RaftLogStore, EnvVarGuard) {
    let guard = match env_value {
        Some(value) => EnvVarGuard::set("CLUSTOR_LOG_ENCODING", value),
        None => EnvVarGuard::clear("CLUSTOR_LOG_ENCODING"),
    };
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("raft.log");
    let store = RaftLogStore::open(&log_path).unwrap();
    (tmp, store, guard)
}

#[test]
fn append_and_reload_persists_entries() {
    let (tmp, mut store, _guard) = store_with_encoding(None);
    store
        .append(RaftLogEntry::new(1, 1, b"cmd1".to_vec()))
        .unwrap();
    store
        .append(RaftLogEntry::new(1, 2, b"cmd2".to_vec()))
        .unwrap();
    drop(store);
    let reopened = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    assert_eq!(reopened.len(), 2);
    assert_eq!(reopened.last_term_index().unwrap().index, 2);
}

#[test]
fn rotates_segments_when_exceeding_threshold() {
    let (tmp, mut store, _guard) = store_with_encoding(None);
    for i in 1..=20 {
        let payload = vec![0u8; 1_048_576];
        store.append(RaftLogEntry::new(1, i, payload)).unwrap();
    }
    let segment_dir = tmp.path().join("raft.segments");
    let segment_count = std::fs::read_dir(&segment_dir).unwrap().count();
    assert!(segment_count > 1, "expected multiple segment files");
    drop(store);
    let reopened = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    assert_eq!(reopened.len(), 20);
}

#[test]
fn truncate_and_discard_drop_segments() {
    let (tmp, mut store, _guard) = store_with_encoding(None);
    for i in 1..=5 {
        store
            .append(RaftLogEntry::new(1, i, vec![i as u8]))
            .unwrap();
    }
    store.truncate_from(4).unwrap();
    assert_eq!(store.last_index(), 3);
    store.discard_through(2).unwrap();
    assert_eq!(store.first_index(), 3);
    drop(store);
    let reopened = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    assert_eq!(reopened.first_index(), 3);
    assert_eq!(reopened.last_index(), 3);
}

#[test]
fn stream_iterator_reads_entries() {
    let (tmp, mut store, _guard) = store_with_encoding(None);
    for i in 1..=6 {
        store
            .append(RaftLogEntry::new(1, i, vec![i as u8]))
            .unwrap();
    }
    drop(store);
    let reopened = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    let stream = reopened.stream_from(2).unwrap();
    let collected: Vec<_> = stream.map(|entry| entry.unwrap().index).collect();
    assert_eq!(collected, vec![2, 3, 4, 5, 6]);
}

#[test]
fn binary_encoding_round_trip() {
    let (tmp, mut store, _guard) = store_with_encoding(Some("binary"));
    store
        .append(RaftLogEntry::new(1, 1, b"alpha".to_vec()))
        .unwrap();
    store
        .append(RaftLogEntry::new(1, 2, b"beta".to_vec()))
        .unwrap();
    drop(store);
    let reopened = RaftLogStore::open(tmp.path().join("raft.log")).unwrap();
    assert_eq!(reopened.len(), 2);
    assert_eq!(reopened.last_term_index().unwrap().index, 2);
}
