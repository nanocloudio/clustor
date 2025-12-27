use clustor::lifecycle::bootstrap::boot_record::BootRecord;
use clustor::{StorageLayout, StorageMetadata};
use std::path::Path;
use tempfile::TempDir;

#[test]
fn raft_metadata_store_aligns_with_layout() {
    let tmp = TempDir::new().expect("tempdir");
    let layout = StorageLayout::new(tmp.path());
    let store = layout.raft_metadata_store();
    assert_eq!(
        store.path().strip_prefix(tmp.path()).unwrap(),
        Path::new("raft_metadata.json")
    );
}

#[test]
fn ensure_tree_and_load_defaults() {
    let tmp = TempDir::new().expect("tempdir");
    let layout = StorageLayout::new(tmp.path());
    let state = layout.load_state().expect("load state");
    assert!(state.wal_segments.is_empty());
    assert!(state.snapshots.is_empty());
    assert_eq!(state.metadata.partition_id, "");
    assert!(layout.paths().wal_dir.exists());
    assert!(layout.paths().snapshot_dir.exists());
}

#[test]
fn discover_segments_and_snapshots() {
    use std::fs;

    let tmp = TempDir::new().expect("tempdir");
    let layout = StorageLayout::new(tmp.path());
    layout.ensure().expect("ensure dirs");

    let wal_dir = layout.paths().wal_dir.clone();
    fs::write(wal_dir.join("segment-0000000001.log"), b"log").unwrap();
    fs::write(wal_dir.join("segment-0000000001.idx"), b"idx").unwrap();
    fs::write(wal_dir.join("segment-0000000002.log"), b"log").unwrap();

    let snap_dir = layout.paths().snapshot_dir.join("snap-5-42");
    fs::create_dir_all(&snap_dir).unwrap();
    fs::write(snap_dir.join("manifest.json"), b"{}").unwrap();

    let metadata = StorageMetadata {
        partition_id: "p1".into(),
        ..StorageMetadata::default()
    };
    layout.metadata_store().persist(&metadata).unwrap();

    let boot = BootRecord {
        fsync_probe: None,
        disk_policy: None,
    };
    let store = layout.boot_record_store();
    store.persist(&boot).unwrap();

    let state = layout.load_state().unwrap();
    assert_eq!(state.metadata.partition_id, "p1");
    assert_eq!(state.wal_segments.len(), 2);
    assert_eq!(state.wal_segments[0].seq, 1);
    assert!(state.wal_segments[0].index_path.is_some());
    assert_eq!(state.snapshots.len(), 1);
    assert_eq!(state.snapshots[0].term, 5);
    assert_eq!(state.snapshots[0].index, 42);
}
