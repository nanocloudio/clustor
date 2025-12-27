use clustor::persistence::storage::replay::WalReplayScanner;
use clustor::storage::entry::{EntryFrame, EntryFrameBuilder, EntryFrameError};
use clustor::storage::layout::WalSegmentRef;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn scanner_returns_frames_in_order() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("segment-0000000001.log");
    write_segment(&path, &[frame(1, 1), frame(1, 2)]);
    let segments = vec![WalSegmentRef {
        seq: 1,
        log_path: path.clone(),
        index_path: None,
    }];
    let result = WalReplayScanner::scan(&segments).unwrap();
    assert!(result.truncation.is_none());
    assert_eq!(result.frames.len(), 2);
    assert_eq!(result.frames[1].header.index, 2);
}

#[test]
fn scanner_reports_truncation_on_corruption() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("segment-0000000002.log");
    let mut bytes = frame(1, 1).encode();
    let len = bytes.len();
    bytes[len - 1] ^= 0xFF;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let segments = vec![WalSegmentRef {
        seq: 2,
        log_path: path.clone(),
        index_path: None,
    }];
    let result = WalReplayScanner::scan(&segments).unwrap();
    assert!(result.frames.is_empty());
    let trunc = result.truncation.expect("expected truncation");
    assert_eq!(trunc.segment_seq, 2);
    assert!(
        matches!(
            trunc.error,
            EntryFrameError::CrcMismatch | EntryFrameError::MerkleMismatch
        ),
        "unexpected error: {:?}",
        trunc.error
    );
}

fn frame(term: u64, index: u64) -> EntryFrame {
    EntryFrameBuilder::new(term, index)
        .metadata(vec![0; 2])
        .payload(b"hello-world".to_vec())
        .build()
}

fn write_segment(path: &Path, frames: &[EntryFrame]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = Vec::new();
    for frame in frames {
        bytes.extend_from_slice(&frame.encode());
    }
    std::fs::write(path, bytes).unwrap();
}
