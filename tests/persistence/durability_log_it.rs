#[path = "../support/env.rs"]
mod env_support;

use clustor::persistence::durability::log::{
    retry_io, DurabilityLogEntry, DurabilityLogError, DurabilityLogReplay, DurabilityLogWriter,
    ReplayError,
};
use clustor::IoMode;
use env_support::EnvVarGuard;
use serde_json::Value;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::tempdir;

#[test]
fn retry_io_handles_interrupts() {
    let attempts = AtomicUsize::new(0);
    retry_io(
        || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(io::Error::new(io::ErrorKind::Interrupted, "flaky"))
            } else {
                Ok(())
            }
        },
        "durability_retry",
        Path::new("/tmp/test"),
    )
    .expect("retry succeeds");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[test]
fn detects_corruption() {
    let entries = vec![
        DurabilityLogEntry::new(1, 10, 1, IoMode::Strict, 0),
        DurabilityLogEntry::new(1, 5, 2, IoMode::Strict, 0),
    ];
    let outcome = DurabilityLogReplay::replay(&entries);
    assert_eq!(outcome.entries.len(), 1);
    assert_eq!(outcome.error, Some(ReplayError::Corruption { index: 5 }));
}

#[test]
fn clean_log_replays_without_error() {
    let entries = vec![
        DurabilityLogEntry::new(1, 1, 1, IoMode::Strict, 0),
        DurabilityLogEntry::new(1, 2, 2, IoMode::Strict, 0),
    ];
    let outcome = DurabilityLogReplay::replay(&entries);
    assert_eq!(outcome.entries.len(), 2);
    assert!(outcome.error.is_none());
}

#[test]
fn writer_persists_and_replays_entries() {
    let _guard = EnvVarGuard::clear("CLUSTOR_WAL_CODEC");
    let temp = tempdir().unwrap();
    let path = temp.path().join("wal").join("durability.log");
    let mut writer = DurabilityLogWriter::open(&path).unwrap();
    let entry = DurabilityLogEntry::new(7, 42, 9, IoMode::Strict, 1234);
    writer.append(&entry).unwrap();
    let mut writer = DurabilityLogWriter::open(&path).unwrap();
    let entries = writer.read_all().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].index, 42);
}

#[test]
fn read_all_rejects_crc_mismatch() {
    use std::fs;

    let _guard = EnvVarGuard::clear("CLUSTOR_WAL_CODEC");
    let temp = tempdir().unwrap();
    let path = temp.path().join("wal").join("durability.log");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut writer = DurabilityLogWriter::open(&path).unwrap();
    let entry = DurabilityLogEntry::new(3, 9, 2, IoMode::Strict, 0);
    writer.append(&entry).unwrap();

    let content = fs::read_to_string(&path).unwrap();
    let mut json: Value = serde_json::from_str(&content).unwrap();
    json["record_crc32c"] = serde_json::json!(0);
    let mut payload = serde_json::to_vec(&json).unwrap();
    payload.push(b'\n');
    fs::write(&path, payload).unwrap();

    let mut reader = DurabilityLogWriter::open(&path).unwrap();
    let err = reader.read_all().unwrap_err();
    assert!(matches!(err, DurabilityLogError::CorruptRecord { .. }));
}

#[test]
fn binary_codec_round_trip() {
    let _guard = EnvVarGuard::set("CLUSTOR_WAL_CODEC", "binary");
    let temp = tempdir().unwrap();
    let path = temp.path().join("wal").join("binary.log");
    let mut writer = DurabilityLogWriter::open(&path).unwrap();
    for i in 0u64..3 {
        writer
            .append(&DurabilityLogEntry::new(1, i + 1, i, IoMode::Group, 99))
            .unwrap();
    }
    let mut reader = DurabilityLogWriter::open(&path).unwrap();
    let entries = reader.read_all().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].io_mode, IoMode::Group);
}
