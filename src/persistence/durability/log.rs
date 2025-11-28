use crate::durability::ledger::IoMode;
use crate::replication::consensus::DurabilityProof;
use crate::retry::RetryPolicy;
use crate::storage::SharedBufferedWriter;
use crate::util::error::StorageError;
use crc32fast::Hasher;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{File, OpenOptions};
#[cfg(not(unix))]
use std::io::Write;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use thiserror::Error;

const DURABILITY_LOG_IO_MAX_ATTEMPTS: usize = 3;
const DURABILITY_LOG_IO_BACKOFF: Duration = Duration::from_millis(20);
const DURABILITY_LOG_FLUSH_THRESHOLD: usize = 32 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurabilityLogEntry {
    pub term: u64,
    pub index: u64,
    pub segment_seq: u64,
    pub io_mode: IoMode,
    pub timestamp_ms: u64,
    pub record_crc32c: u32,
}

impl DurabilityLogEntry {
    pub fn new(
        term: u64,
        index: u64,
        segment_seq: u64,
        io_mode: IoMode,
        timestamp_ms: u64,
    ) -> Self {
        let mut entry = Self {
            term,
            index,
            segment_seq,
            io_mode,
            timestamp_ms,
            record_crc32c: 0,
        };
        entry.record_crc32c = entry.compute_crc();
        entry
    }

    pub fn validate_crc(&self) -> bool {
        self.record_crc32c == self.compute_crc()
    }

    pub fn normalized(&self) -> Self {
        let mut clone = self.clone();
        clone.record_crc32c = clone.compute_crc();
        clone
    }

    fn compute_crc(&self) -> u32 {
        let mut hasher = Hasher::new();
        hasher.update(&self.term.to_le_bytes());
        hasher.update(&self.index.to_le_bytes());
        hasher.update(&self.segment_seq.to_le_bytes());
        hasher.update(&[self.io_mode as u8]);
        hasher.update(&self.timestamp_ms.to_le_bytes());
        hasher.finalize()
    }
}

const BINARY_LOG_RECORD_BYTES: usize = 8 + 8 + 8 + 1 + 8 + 4;

trait WalFrameCodec: Send + Sync {
    fn encode(
        &self,
        entry: &DurabilityLogEntry,
        out: &mut Vec<u8>,
    ) -> Result<(), DurabilityLogError>;

    fn decode(
        &self,
        reader: &mut dyn BufRead,
    ) -> Result<Option<DurabilityLogEntry>, DurabilityLogError>;

    fn name(&self) -> &'static str;
}

struct JsonWalCodec;
struct BinaryWalCodec;

impl WalFrameCodec for JsonWalCodec {
    fn encode(
        &self,
        entry: &DurabilityLogEntry,
        out: &mut Vec<u8>,
    ) -> Result<(), DurabilityLogError> {
        serde_json::to_writer(&mut *out, entry)?;
        out.push(b'\n');
        Ok(())
    }

    fn decode(
        &self,
        reader: &mut dyn BufRead,
    ) -> Result<Option<DurabilityLogEntry>, DurabilityLogError> {
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 {
                return Ok(None);
            }
            if line.trim().is_empty() {
                continue;
            }
            let entry = serde_json::from_str(&line)?;
            return Ok(Some(entry));
        }
    }

    fn name(&self) -> &'static str {
        "json"
    }
}

impl WalFrameCodec for BinaryWalCodec {
    fn encode(
        &self,
        entry: &DurabilityLogEntry,
        out: &mut Vec<u8>,
    ) -> Result<(), DurabilityLogError> {
        out.extend_from_slice(&entry.term.to_le_bytes());
        out.extend_from_slice(&entry.index.to_le_bytes());
        out.extend_from_slice(&entry.segment_seq.to_le_bytes());
        out.push(entry.io_mode as u8);
        out.extend_from_slice(&entry.timestamp_ms.to_le_bytes());
        out.extend_from_slice(&entry.record_crc32c.to_le_bytes());
        Ok(())
    }

    fn decode(
        &self,
        reader: &mut dyn BufRead,
    ) -> Result<Option<DurabilityLogEntry>, DurabilityLogError> {
        let mut buf = [0u8; BINARY_LOG_RECORD_BYTES];
        let mut read = 0;
        while read < buf.len() {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                if read == 0 {
                    return Ok(None);
                } else {
                    return Err(DurabilityLogError::Storage(StorageError::from(
                        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated wal frame"),
                    )));
                }
            }
            let take = (buf.len() - read).min(chunk.len());
            buf[read..read + take].copy_from_slice(&chunk[..take]);
            reader.consume(take);
            read += take;
        }
        let mut cursor = &buf[..];
        let term = read_u64(&mut cursor)?;
        let index = read_u64(&mut cursor)?;
        let segment_seq = read_u64(&mut cursor)?;
        let io_mode_byte = read_u8(&mut cursor)?;
        let io_mode = match io_mode_byte {
            0 => IoMode::Strict,
            1 => IoMode::Group,
            other => {
                return Err(DurabilityLogError::Storage(StorageError::from(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid io mode {other}"),
                    ),
                )))
            }
        };
        let timestamp_ms = read_u64(&mut cursor)?;
        let record_crc32c = read_u32(&mut cursor)?;
        Ok(Some(DurabilityLogEntry {
            term,
            index,
            segment_seq,
            io_mode,
            timestamp_ms,
            record_crc32c,
        }))
    }

    fn name(&self) -> &'static str {
        "binary"
    }
}

fn read_u64(cursor: &mut &[u8]) -> Result<u64, DurabilityLogError> {
    if cursor.len() < 8 {
        return Err(DurabilityLogError::Storage(StorageError::from(
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated wal frame"),
        )));
    }
    let (head, tail) = cursor.split_at(8);
    *cursor = tail;
    let mut array = [0u8; 8];
    array.copy_from_slice(head);
    Ok(u64::from_le_bytes(array))
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32, DurabilityLogError> {
    if cursor.len() < 4 {
        return Err(DurabilityLogError::Storage(StorageError::from(
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated wal frame"),
        )));
    }
    let (head, tail) = cursor.split_at(4);
    *cursor = tail;
    let mut array = [0u8; 4];
    array.copy_from_slice(head);
    Ok(u32::from_le_bytes(array))
}

fn read_u8(cursor: &mut &[u8]) -> Result<u8, DurabilityLogError> {
    if cursor.is_empty() {
        return Err(DurabilityLogError::Storage(StorageError::from(
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated wal frame"),
        )));
    }
    let (head, tail) = cursor.split_at(1);
    *cursor = tail;
    Ok(head[0])
}

fn selected_codec() -> Arc<dyn WalFrameCodec + Send + Sync> {
    match std::env::var("CLUSTOR_WAL_CODEC") {
        Ok(value) if value.eq_ignore_ascii_case("binary") => Arc::new(BinaryWalCodec),
        _ => Arc::new(JsonWalCodec),
    }
}

pub struct DurabilityLogWriter {
    path: PathBuf,
    file: File,
    buffer: SharedBufferedWriter,
    codec: Arc<dyn WalFrameCodec + Send + Sync>,
    write_buf: Vec<u8>,
}

impl fmt::Debug for DurabilityLogWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurabilityLogWriter")
            .field("path", &self.path)
            .field("codec", &self.codec.name())
            .finish()
    }
}

const DURABILITY_WAL_SPEC: &str = "§6.2.WAL";

impl DurabilityLogWriter {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DurabilityLogError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        let mut writer_file = file.try_clone()?;
        let end = writer_file.seek(SeekFrom::End(0))?;
        writer_file.seek(SeekFrom::Start(end))?;
        let buffer =
            SharedBufferedWriter::new(writer_file, 64 * 1024, DURABILITY_LOG_FLUSH_THRESHOLD);
        Ok(Self {
            path,
            file,
            buffer,
            codec: selected_codec(),
            write_buf: Vec::with_capacity(512),
        })
    }

    pub fn append(&mut self, entry: &DurabilityLogEntry) -> Result<(), DurabilityLogError> {
        let entry = entry.normalized();
        self.write_buf.clear();
        self.codec.encode(&entry, &mut self.write_buf)?;
        retry_io(
            || self.buffer.write_all(&self.write_buf),
            "durability_log_write",
            &self.path,
        )
        .map_err(StorageError::from)?;
        retry_io(|| self.buffer.flush(), "durability_log_flush", &self.path)
            .map_err(StorageError::from)?;
        retry_io(|| self.buffer.sync_data(), "wal_fdatasync", &self.path).map_err(|err| {
            error!(
                "event=wal_fdatasync_failed clause={} path={} error={}",
                DURABILITY_WAL_SPEC,
                self.path.display(),
                err
            );
            StorageError::from(err)
        })?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read_all(&mut self) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
        self.buffer.flush().map_err(StorageError::from)?;
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let reader = BufReader::new(file);
        parse_entries(reader, &*self.codec)
    }
}

#[derive(Debug, Default)]
pub struct DurabilityLogReplay;

impl DurabilityLogReplay {
    pub fn load(path: impl AsRef<Path>) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let codec = selected_codec();
        parse_entries(reader, &*codec)
    }

    pub fn replay(entries: &[DurabilityLogEntry]) -> ReplayOutcome {
        let mut last_index = 0;
        let mut last_term = 0;
        let mut clean = Vec::new();
        for entry in entries {
            if entry.index < last_index || (entry.index == last_index && entry.term < last_term) {
                return ReplayOutcome {
                    entries: clean,
                    error: Some(ReplayError::Corruption { index: entry.index }),
                };
            }
            clean.push(entry.clone());
            last_index = entry.index;
            last_term = entry.term;
        }
        ReplayOutcome {
            entries: clean,
            error: None,
        }
    }

    pub fn publish_proof(entries: &[DurabilityLogEntry]) -> Option<DurabilityProof> {
        entries
            .last()
            .map(|entry| DurabilityProof::new(entry.term, entry.index))
    }
}

#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    pub entries: Vec<DurabilityLogEntry>,
    pub error: Option<ReplayError>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ReplayError {
    #[error("corruption detected at index {index}")]
    Corruption { index: u64 },
}

#[derive(Debug, Error)]
pub enum DurabilityLogError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("durability log CRC mismatch at index {index}")]
    CorruptRecord { index: u64 },
}

impl From<std::io::Error> for DurabilityLogError {
    fn from(err: std::io::Error) -> Self {
        DurabilityLogError::Storage(StorageError::from(err))
    }
}

impl From<serde_json::Error> for DurabilityLogError {
    fn from(err: serde_json::Error) -> Self {
        DurabilityLogError::Storage(StorageError::from(err))
    }
}

fn retry_io<F>(mut op: F, label: &str, path: &Path) -> io::Result<()>
where
    F: FnMut() -> io::Result<()>,
{
    let policy = RetryPolicy::linear(DURABILITY_LOG_IO_MAX_ATTEMPTS, DURABILITY_LOG_IO_BACKOFF);
    let mut retry = policy.handle();
    loop {
        match op() {
            Ok(()) => return Ok(()),
            Err(err) if should_retry(&err) => {
                if let Some(delay) = retry.next_delay() {
                    warn!(
                        "event=durability_log_retry clause={} path={} attempt={} error={}",
                        label,
                        path.display(),
                        retry.attempts(),
                        err
                    );
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                } else {
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }
    }
}

fn should_retry(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn parse_entries(
    reader: impl BufRead,
    codec: &dyn WalFrameCodec,
) -> Result<Vec<DurabilityLogEntry>, DurabilityLogError> {
    let mut reader = reader;
    let mut entries = Vec::new();
    while let Some(entry) = codec.decode(&mut reader)? {
        if !entry.validate_crc() {
            return Err(DurabilityLogError::CorruptRecord { index: entry.index });
        }
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use tempfile::tempdir;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire_lock() -> MutexGuard<'static, ()> {
            ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
        }

        fn set(key: &'static str, value: &str) -> Self {
            let lock = Self::acquire_lock();
            let original = env::var(key).ok();
            env::set_var(key, value);
            Self {
                key,
                original,
                _lock: lock,
            }
        }

        fn clear(key: &'static str) -> Self {
            let lock = Self::acquire_lock();
            let original = env::var(key).ok();
            env::remove_var(key);
            Self {
                key,
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                env::set_var(self.key, value);
            } else {
                env::remove_var(self.key);
            }
            // lock guard drops automatically here
        }
    }

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
        let _guard = EnvGuard::clear("CLUSTOR_WAL_CODEC");
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
        let _guard = EnvGuard::clear("CLUSTOR_WAL_CODEC");
        use std::fs;
        let temp = tempdir().unwrap();
        let path = temp.path().join("wal").join("durability.log");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut writer = DurabilityLogWriter::open(&path).unwrap();
        let entry = DurabilityLogEntry::new(3, 9, 2, IoMode::Strict, 0);
        writer.append(&entry).unwrap();

        // Corrupt the CRC by rewriting the on-disk record.
        let content = fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&content).unwrap();
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
        let _guard = EnvGuard::set("CLUSTOR_WAL_CODEC", "binary");
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
}
