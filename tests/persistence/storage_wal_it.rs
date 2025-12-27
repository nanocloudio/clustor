use clustor::persistence::storage::wal::retry_io;
use clustor::WalWriter;
use std::fs;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::tempdir;

#[test]
fn wal_writer_reserves_nonce_windows_monotonically() {
    let dir = tempdir().unwrap();
    let wal_path = dir.path().join("wal.bin");
    let mut writer = WalWriter::open(&wal_path, 4096).unwrap();
    let first = writer.append_frame(b"alpha").unwrap();
    assert_eq!(first.reservation.start_block, 0);
    let second = writer.append_frame(&vec![0u8; 7000]).unwrap();
    assert!(second.reservation.start_block > 0);
    drop(writer);
    assert!(fs::metadata(wal_path).unwrap().len() > 0);
}

#[test]
fn wal_writer_aligns_next_block_with_metadata_cursor() {
    let dir = tempdir().unwrap();
    let wal_path = dir.path().join("wal.bin");
    let mut writer = WalWriter::open(&wal_path, 4096).unwrap();
    writer.align_next_block(10);
    assert_eq!(writer.next_block(), 10);
}

#[test]
fn wal_retry_io_retries_interrupts() {
    let attempts = AtomicUsize::new(0);
    retry_io(
        || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(io::Error::new(io::ErrorKind::Interrupted, "flaky"))
            } else {
                Ok(())
            }
        },
        "wal_retry_test",
    )
    .expect("retry succeeds");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}
