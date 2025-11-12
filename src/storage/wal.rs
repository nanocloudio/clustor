use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(not(unix))]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::FileExt;

use thiserror::Error;

/// Reservation covering a contiguous range of WAL crypto blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalReservation {
    pub start_block: u64,
    pub blocks: u64,
}

/// Persistent WAL writer that enforces `pwrite` → `fdatasync` ordering.
#[derive(Debug)]
pub struct WalWriter {
    path: PathBuf,
    file: File,
    cursor: u64,
    tracker: WalReservationTracker,
    block_size: u64,
}

impl WalWriter {
    pub fn open(path: impl Into<PathBuf>, block_size: u64) -> Result<Self, WalWriterError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        let cursor = file.seek(SeekFrom::End(0))?;
        let tracker = WalReservationTracker::new(block_size, divide_round_up(cursor, block_size));
        Ok(Self {
            path,
            file,
            cursor,
            tracker,
            block_size,
        })
    }

    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    pub fn next_block(&self) -> u64 {
        self.tracker.next_block()
    }

    /// Aligns the next reservation cursor with an externally recorded watermark.
    pub fn align_next_block(&mut self, target: u64) {
        self.tracker.align(target);
    }

    pub fn append_frame(&mut self, payload: &[u8]) -> Result<WalAppendResult, WalWriterError> {
        let offset = self.cursor;
        let len = payload.len() as u64;
        self.write_at(payload, offset)?;
        self.cursor = self.cursor.saturating_add(len);
        self.file.sync_data()?;
        let reservation = self.tracker.reserve(payload.len());
        Ok(WalAppendResult {
            offset,
            len,
            reservation,
        })
    }

    fn write_at(&mut self, payload: &[u8], offset: u64) -> Result<(), WalWriterError> {
        #[cfg(unix)]
        {
            self.file.write_all_at(payload, offset)?;
        }
        #[cfg(not(unix))]
        {
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(payload)?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone)]
struct WalReservationTracker {
    block_size: u64,
    next_block: u64,
}

impl WalReservationTracker {
    fn new(block_size: u64, next_block: u64) -> Self {
        Self {
            block_size,
            next_block,
        }
    }

    fn reserve(&mut self, bytes: usize) -> WalReservation {
        let blocks = divide_round_up(bytes as u64, self.block_size).max(1);
        let start_block = self.next_block;
        self.next_block = self.next_block.saturating_add(blocks);
        WalReservation {
            start_block,
            blocks,
        }
    }

    fn align(&mut self, target: u64) {
        self.next_block = self.next_block.max(target);
    }

    fn next_block(&self) -> u64 {
        self.next_block
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WalAppendResult {
    pub offset: u64,
    pub len: u64,
    pub reservation: WalReservation,
}

#[derive(Debug, Error)]
pub enum WalWriterError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

fn divide_round_up(value: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    value.div_ceil(divisor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reserves_nonce_windows_monotonically() {
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
    fn align_next_block_respects_metadata_cursor() {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("wal.bin");
        let mut writer = WalWriter::open(&wal_path, 4096).unwrap();
        writer.align_next_block(10);
        assert_eq!(writer.next_block(), 10);
    }
}
