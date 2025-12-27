use super::encoding::{self, LogEncoding, LOG_BINARY_HEADER};
use super::metadata::TermIndexSnapshot;
use crate::util::error::StorageError;
use memmap2::Mmap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

/// Segment files live alongside the configured log path.
const SEGMENT_FILE_PREFIX: &str = "segment-";
const SEGMENT_FILE_SUFFIX: &str = ".log";
const MANIFEST_VERSION: u32 = 1;
const DEFAULT_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_CACHE_SEGMENTS: usize = 2;

/// Append-only Raft log split into individually mapped segments.
#[derive(Debug)]
pub struct RaftLogStore {
    segment_dir: PathBuf,
    manifest_path: PathBuf,
    snapshot_hint_path: PathBuf,
    encoding: LogEncoding,
    segment_bytes: u64,
    cache_segments: usize,
    segments: Vec<LogSegment>,
    next_segment_id: u64,
    snapshot_hint: Option<TermIndexSnapshot>,
    active_writer: Option<SegmentWriter>,
}

impl RaftLogStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RaftLogError> {
        Self::open_internal(path.into(), None)
    }

    fn open_internal(
        base_path: PathBuf,
        forced: Option<LogEncoding>,
    ) -> Result<Self, RaftLogError> {
        if let Some(parent) = base_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let segment_dir = base_path.with_extension("segments");
        let manifest_path = base_path.with_extension("manifest");
        let snapshot_hint_path = base_path.with_extension("snap");
        fs::create_dir_all(&segment_dir)?;

        let mut manifest = if manifest_path.exists() {
            SegmentManifest::load(&manifest_path)?
        } else {
            SegmentManifest::new()
        };

        let manifest_encoding = manifest.encoding.as_deref().and_then(|value| match value {
            "json" => Some(LogEncoding::Json),
            "binary" => Some(LogEncoding::Binary),
            _ => None,
        });
        let encoding = forced
            .or(manifest_encoding)
            .or_else(|| encoding::LogEncoding::detect(&base_path).ok().flatten())
            .unwrap_or_else(LogEncoding::default_for_new_file);
        manifest.encoding = Some(match encoding {
            LogEncoding::Json => "json".to_string(),
            LogEncoding::Binary => "binary".to_string(),
        });
        let segment_bytes = manifest.segment_bytes.unwrap_or(DEFAULT_SEGMENT_BYTES);
        let cache_segments = manifest.cache_segments.unwrap_or(DEFAULT_CACHE_SEGMENTS);

        let mut segments = Vec::new();
        for descriptor in manifest.segments.iter() {
            let path = segment_dir.join(&descriptor.file_name);
            let segment = LogSegment::from_descriptor(descriptor.clone(), path);
            segments.push(segment);
        }

        let next_segment_id = manifest
            .next_segment_id
            .unwrap_or_else(|| segments.last().map(|segment| segment.id() + 1).unwrap_or(0));
        let snapshot_hint = if snapshot_hint_path.exists() {
            Some(load_snapshot_hint(&snapshot_hint_path)?)
        } else {
            None
        };

        let mut store = Self {
            segment_dir,
            manifest_path,
            snapshot_hint_path,
            encoding,
            segment_bytes,
            cache_segments,
            segments,
            next_segment_id,
            snapshot_hint,
            active_writer: None,
        };

        store.ensure_active_segment()?;
        store.enforce_cache_budget()?;
        store.persist_manifest()?;
        Ok(store)
    }

    fn manifest(&self) -> SegmentManifest {
        SegmentManifest {
            version: MANIFEST_VERSION,
            encoding: Some(match self.encoding {
                LogEncoding::Json => "json".into(),
                LogEncoding::Binary => "binary".into(),
            }),
            segment_bytes: Some(self.segment_bytes),
            cache_segments: Some(self.cache_segments),
            next_segment_id: Some(self.next_segment_id),
            segments: self
                .segments
                .iter()
                .map(|segment| segment.descriptor.clone())
                .collect(),
        }
    }

    fn persist_manifest(&self) -> Result<(), RaftLogError> {
        self.manifest().store(&self.manifest_path)
    }

    fn ensure_active_segment(&mut self) -> Result<(), RaftLogError> {
        if self.active_writer.is_some() {
            return Ok(());
        }
        if let Some(last) = self.segments.last_mut() {
            let mut writer = SegmentWriter::open(last.path(), self.encoding)?;
            writer.seek_to_end()?;
            last.refresh_length()?;
            self.active_writer = Some(writer);
            return Ok(());
        }
        self.start_new_segment(1)
    }

    fn start_new_segment(&mut self, start_index: u64) -> Result<(), RaftLogError> {
        let id = self.next_segment_id;
        self.next_segment_id = self.next_segment_id.saturating_add(1);
        let file_name = format!("{SEGMENT_FILE_PREFIX}{id:016x}{SEGMENT_FILE_SUFFIX}");
        let path = self.segment_dir.join(&file_name);
        let descriptor = SegmentDescriptor {
            id,
            file_name,
            start_index,
            end_index: start_index.saturating_sub(1),
            bytes: 0,
        };
        let segment = LogSegment::from_descriptor(descriptor, path.clone());
        let writer = SegmentWriter::create(path, self.encoding)?;
        self.segments.push(segment);
        if let Some(last) = self.segments.last_mut() {
            if matches!(self.encoding, LogEncoding::Binary) {
                last.descriptor.bytes = LOG_BINARY_HEADER.len() as u64;
            }
        }
        self.active_writer = Some(writer);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.entry_count())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn first_index(&self) -> u64 {
        self.segments
            .first()
            .map(|segment| segment.start_index())
            .unwrap_or(0)
    }

    pub fn last_index(&self) -> u64 {
        self.segments
            .last()
            .map(|segment| segment.end_index())
            .unwrap_or(0)
    }

    pub fn last_term_index(&self) -> Option<TermIndexSnapshot> {
        self.segments
            .iter()
            .rev()
            .find_map(|segment| segment.last_term_index())
    }

    pub fn term_at(&self, index: u64) -> Option<u64> {
        self.entry(index).ok().flatten().map(|entry| entry.term)
    }

    pub fn entry(&self, index: u64) -> Result<Option<RaftLogEntry>, RaftLogError> {
        let segment = match self.segment_containing(index) {
            Some(segment) => segment,
            None => return Ok(None),
        };
        segment.entry(index, self.encoding)
    }

    fn segment_containing(&self, index: u64) -> Option<&LogSegment> {
        self.segments.iter().find(|segment| segment.contains(index))
    }

    pub fn entries_from(&self, start_index: u64) -> Vec<RaftLogEntry> {
        let mut out = Vec::new();
        let mut idx = start_index;
        while let Some(segment) = self.segment_containing(idx) {
            let entries = match segment.entries_from(idx, self.encoding) {
                Ok(entries) => entries,
                Err(_) => break,
            };
            if entries.is_empty() {
                break;
            }
            idx = entries.last().map(|entry| entry.index + 1).unwrap_or(idx);
            out.extend(entries);
        }
        out
    }

    pub fn copy_entries_in_range(
        &self,
        start_index: u64,
        end_index: u64,
        out: &mut Vec<RaftLogEntry>,
    ) {
        out.clear();
        if start_index > end_index {
            return;
        }
        for entry in self.entries_from(start_index) {
            if entry.index > end_index {
                break;
            }
            out.push(entry);
        }
    }

    pub fn append_batch(&mut self, entries: &[RaftLogEntry]) -> Result<(), RaftLogError> {
        for entry in entries {
            self.append(entry.clone())?;
        }
        Ok(())
    }

    pub fn append(&mut self, entry: RaftLogEntry) -> Result<(), RaftLogError> {
        let expected_index = self.last_index().saturating_add(1);
        if entry.index != expected_index {
            return Err(RaftLogError::NonSequentialAppend {
                expected: expected_index,
                attempted: entry.index,
            });
        }
        if let Some(last) = self.last_term_index() {
            if entry.term < last.term {
                return Err(RaftLogError::TermRegression {
                    previous: last.term,
                    attempted: entry.term,
                });
            }
        }

        let encoded = encode_entry(&entry, self.encoding)?;
        self.ensure_active_segment()?;
        if self.should_roll_segment(encoded.len() as u64) {
            self.rotate_segment(entry.index)?;
        }
        let writer = self.active_writer.as_mut().ok_or_else(|| {
            RaftLogError::Storage(StorageError::Io(io::Error::other("missing active segment")))
        })?;
        writer.append_raw(&encoded)?;
        let segment = self
            .segments
            .last_mut()
            .expect("segments must exist after ensure_active_segment");
        segment.observe_append(entry.clone(), encoded.len() as u64);
        self.persist_manifest()?;
        self.enforce_cache_budget()?;
        Ok(())
    }

    fn rotate_segment(&mut self, next_index: u64) -> Result<(), RaftLogError> {
        if let Some(writer) = self.active_writer.as_mut() {
            writer.flush_and_sync()?;
        }
        self.active_writer = None;
        self.start_new_segment(next_index)
    }

    fn should_roll_segment(&self, next_bytes: u64) -> bool {
        match self.active_writer.as_ref() {
            Some(writer) => writer.bytes() + next_bytes > self.segment_bytes,
            None => false,
        }
    }

    fn enforce_cache_budget(&mut self) -> Result<(), RaftLogError> {
        let mut keep = VecDeque::new();
        let segments_len = self.segments.len();
        for (idx, segment) in self.segments.iter_mut().enumerate() {
            if segments_len - idx <= self.cache_segments {
                segment.ensure_cached(self.encoding)?;
                keep.push_back(segment.id());
            } else {
                segment.drop_cache(self.encoding);
            }
        }
        Ok(())
    }

    pub fn truncate_from(&mut self, index: u64) -> Result<(), RaftLogError> {
        if index == 0 {
            return Err(RaftLogError::InvalidTruncateIndex(0));
        }
        if index > self.last_index() + 1 {
            return Ok(());
        }
        while let Some(segment) = self.segments.last() {
            if index > segment.end_index() {
                break;
            }
            let start = segment.start_index();
            if index <= start {
                let removed = self.segments.pop().unwrap();
                removed.delete_file()?;
                continue;
            }
            let should_remove = {
                let segment = self.segments.last_mut().unwrap();
                segment.truncate_from(index, self.encoding)?
            };
            if should_remove {
                let removed = self.segments.pop().unwrap();
                removed.delete_file().ok();
            }
            break;
        }
        self.persist_manifest()?;
        self.active_writer = None;
        self.ensure_active_segment()?;
        Ok(())
    }

    pub fn discard_through(&mut self, index: u64) -> Result<(), RaftLogError> {
        if index == 0 {
            return Ok(());
        }
        while let Some(segment) = self.segments.first() {
            if index < segment.start_index() {
                break;
            }
            if index >= segment.end_index() {
                let removed = self.segments.remove(0);
                removed.delete_file()?;
                continue;
            }
            let should_remove = {
                let segment = self.segments.first_mut().unwrap();
                segment.discard_through(index, self.encoding)?
            };
            if should_remove {
                let removed = self.segments.remove(0);
                removed.delete_file().ok();
            }
            break;
        }
        self.persist_manifest()?;
        Ok(())
    }

    pub fn snapshot_hint(&self) -> Option<TermIndexSnapshot> {
        self.snapshot_hint
    }

    pub fn persist_snapshot_hint(&mut self, hint: TermIndexSnapshot) -> Result<(), RaftLogError> {
        if self
            .snapshot_hint
            .map(|existing| existing.index >= hint.index)
            .unwrap_or(false)
        {
            return Ok(());
        }
        store_snapshot_hint(&self.snapshot_hint_path, &hint)?;
        self.snapshot_hint = Some(hint);
        Ok(())
    }

    pub fn stream_from(&self, start_index: u64) -> Result<RaftLogStream, RaftLogError> {
        let mut descriptors = Vec::new();
        for segment in &self.segments {
            if segment.end_index() < start_index {
                continue;
            }
            descriptors.push(StreamDescriptor {
                descriptor: segment.descriptor.clone(),
                mmap: segment.mmap.clone(),
            });
        }
        Ok(RaftLogStream::new(
            descriptors,
            self.segment_dir.clone(),
            self.encoding,
            start_index,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentDescriptor {
    id: u64,
    file_name: String,
    start_index: u64,
    end_index: u64,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentManifest {
    version: u32,
    encoding: Option<String>,
    segment_bytes: Option<u64>,
    cache_segments: Option<usize>,
    next_segment_id: Option<u64>,
    segments: Vec<SegmentDescriptor>,
}

impl SegmentManifest {
    fn new() -> Self {
        Self {
            version: MANIFEST_VERSION,
            encoding: None,
            segment_bytes: Some(DEFAULT_SEGMENT_BYTES),
            cache_segments: Some(DEFAULT_CACHE_SEGMENTS),
            next_segment_id: Some(0),
            segments: Vec::new(),
        }
    }

    fn load(path: &Path) -> Result<Self, RaftLogError> {
        let bytes = fs::read(path)?;
        let manifest: SegmentManifest = serde_json::from_slice(&bytes)?;
        Ok(manifest)
    }

    fn store(&self, path: &Path) -> Result<(), RaftLogError> {
        let bytes = serde_json::to_vec_pretty(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
        Ok(())
    }
}

#[derive(Debug)]
struct LogSegment {
    descriptor: SegmentDescriptor,
    path: PathBuf,
    cache: Option<Vec<RaftLogEntry>>,
    mmap: Option<Arc<Mmap>>,
}

impl LogSegment {
    fn from_descriptor(descriptor: SegmentDescriptor, path: PathBuf) -> Self {
        Self {
            descriptor,
            path,
            cache: None,
            mmap: None,
        }
    }

    fn id(&self) -> u64 {
        self.descriptor.id
    }

    fn start_index(&self) -> u64 {
        self.descriptor.start_index
    }

    fn end_index(&self) -> u64 {
        self.descriptor.end_index
    }

    fn entry_count(&self) -> usize {
        if self.end_index() < self.start_index() {
            0
        } else {
            (self.end_index() - self.start_index() + 1) as usize
        }
    }

    fn contains(&self, index: u64) -> bool {
        index >= self.start_index() && index <= self.end_index()
    }

    fn last_term_index(&self) -> Option<TermIndexSnapshot> {
        let entries = self.cache.as_ref()?;
        entries.last().map(|entry| TermIndexSnapshot {
            term: entry.term,
            index: entry.index,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn refresh_length(&mut self) -> Result<(), RaftLogError> {
        self.descriptor.bytes = self.path.metadata()?.len();
        Ok(())
    }

    fn ensure_cached(&mut self, encoding: LogEncoding) -> Result<(), RaftLogError> {
        if self.cache.is_some() {
            return Ok(());
        }
        let entries = load_entries_from_path(&self.path, encoding)?;
        self.cache = Some(entries);
        self.mmap = None;
        Ok(())
    }

    fn drop_cache(&mut self, encoding: LogEncoding) {
        self.cache = None;
        self.mmap = None;
        if matches!(encoding, LogEncoding::Binary) {
            if let Ok(file) = File::open(&self.path) {
                unsafe {
                    if let Ok(map) = Mmap::map(&file) {
                        self.mmap = Some(Arc::new(map));
                    }
                }
            }
        }
    }

    fn entry(
        &self,
        index: u64,
        encoding: LogEncoding,
    ) -> Result<Option<RaftLogEntry>, RaftLogError> {
        if !self.contains(index) {
            return Ok(None);
        }
        if let Some(cache) = &self.cache {
            return Ok(cache.iter().find(|entry| entry.index == index).cloned());
        }
        let mut stream = SegmentReadCursor::open(&self.path, encoding, self.mmap.clone())?;
        while let Some(entry) = stream.next_entry()? {
            if entry.index == index {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    fn entries_from(
        &self,
        start_index: u64,
        encoding: LogEncoding,
    ) -> Result<Vec<RaftLogEntry>, RaftLogError> {
        if start_index > self.end_index() {
            return Ok(Vec::new());
        }
        if let Some(cache) = &self.cache {
            let entries = cache
                .iter()
                .filter(|entry| entry.index >= start_index)
                .cloned()
                .collect();
            return Ok(entries);
        }
        let mut cursor = SegmentReadCursor::open(&self.path, encoding, self.mmap.clone())?;
        let mut out = Vec::new();
        while let Some(entry) = cursor.next_entry()? {
            if entry.index >= start_index {
                out.push(entry);
            }
        }
        Ok(out)
    }

    fn observe_append(&mut self, entry: RaftLogEntry, delta_bytes: u64) {
        self.descriptor.end_index = entry.index;
        self.descriptor.bytes = self.descriptor.bytes.saturating_add(delta_bytes);
        if let Some(cache) = self.cache.as_mut() {
            cache.push(entry);
        }
    }

    fn truncate_from(&mut self, index: u64, encoding: LogEncoding) -> Result<bool, RaftLogError> {
        if index <= self.start_index() {
            self.delete_file()?;
            self.descriptor.end_index = self.start_index().saturating_sub(1);
            self.cache = None;
            self.mmap = None;
            return Ok(true);
        }
        self.ensure_cached(encoding)?;
        if self.cache.is_some() {
            if let Some(cache) = self.cache.as_mut() {
                cache.retain(|entry| entry.index < index);
                if let Some(last) = cache.last() {
                    self.descriptor.end_index = last.index;
                } else {
                    self.descriptor.end_index = self.descriptor.start_index.saturating_sub(1);
                }
            }
            self.rewrite_with_cache(encoding)?;
            let empty = self
                .cache
                .as_ref()
                .map(|cache| cache.is_empty())
                .unwrap_or(true);
            return Ok(empty);
        }
        Ok(false)
    }

    fn discard_through(&mut self, index: u64, encoding: LogEncoding) -> Result<bool, RaftLogError> {
        if index >= self.end_index() {
            self.delete_file()?;
            self.descriptor.start_index = index + 1;
            self.descriptor.end_index = index;
            self.cache = None;
            self.mmap = None;
            return Ok(true);
        }
        self.ensure_cached(encoding)?;
        if self.cache.is_some() {
            if let Some(cache) = self.cache.as_mut() {
                cache.retain(|entry| entry.index > index);
                if let Some(first) = cache.first() {
                    self.descriptor.start_index = first.index;
                } else {
                    self.descriptor.start_index = index + 1;
                }
            }
            self.rewrite_with_cache(encoding)?;
            let empty = self
                .cache
                .as_ref()
                .map(|cache| cache.is_empty())
                .unwrap_or(true);
            return Ok(empty);
        }
        Ok(false)
    }

    fn rewrite_with_cache(&mut self, encoding: LogEncoding) -> Result<(), RaftLogError> {
        let cache = match &self.cache {
            Some(cache) => cache.clone(),
            None => return Ok(()),
        };
        let tmp = self.path.with_extension("rewrite");
        {
            let mut writer = SegmentWriter::create(tmp.clone(), encoding)?;
            for entry in &cache {
                let encoded = encode_entry(entry, encoding)?;
                writer.append_raw(&encoded)?;
            }
            writer.flush_and_sync()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.descriptor.end_index = cache
            .last()
            .map(|entry| entry.index)
            .unwrap_or_else(|| self.start_index().saturating_sub(1));
        self.refresh_length()?;
        self.mmap = None;
        Ok(())
    }

    fn delete_file(&self) -> Result<(), RaftLogError> {
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct SegmentWriter {
    writer: BufWriter<File>,
    path: PathBuf,
    bytes: u64,
}

impl SegmentWriter {
    fn create(path: PathBuf, encoding: LogEncoding) -> Result<Self, RaftLogError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        let writer = BufWriter::new(file);
        let mut segment_writer = Self {
            writer,
            path,
            bytes: 0,
        };
        if matches!(encoding, LogEncoding::Binary) {
            segment_writer.append_raw(&LOG_BINARY_HEADER)?;
        }
        Ok(segment_writer)
    }

    fn open(path: &Path, encoding: LogEncoding) -> Result<Self, RaftLogError> {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        if matches!(encoding, LogEncoding::Binary) && file.metadata()?.len() == 0 {
            file.write_all(&LOG_BINARY_HEADER)?;
        }
        let writer = BufWriter::new(file);
        Ok(Self {
            writer,
            path: path.to_path_buf(),
            bytes: 0,
        })
    }

    fn seek_to_end(&mut self) -> Result<(), RaftLogError> {
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        let len = file.seek(SeekFrom::End(0))?;
        self.writer = BufWriter::new(file);
        self.bytes = len;
        Ok(())
    }

    fn append_raw(&mut self, bytes: &[u8]) -> Result<(), RaftLogError> {
        self.writer.write_all(bytes)?;
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn flush_and_sync(&mut self) -> Result<(), RaftLogError> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    fn bytes(&self) -> u64 {
        self.bytes
    }
}

struct SegmentReadCursor {
    reader: SegmentReader,
}

impl SegmentReadCursor {
    fn open(
        path: &Path,
        encoding: LogEncoding,
        mmap: Option<Arc<Mmap>>,
    ) -> Result<Self, RaftLogError> {
        Ok(Self {
            reader: SegmentReader::open(path, encoding, mmap)?,
        })
    }

    fn next_entry(&mut self) -> Result<Option<RaftLogEntry>, RaftLogError> {
        self.reader.next_entry()
    }
}

enum SegmentReader {
    Json(BufReader<File>),
    BinaryFile(BufReader<File>),
    BinaryMmap { data: Arc<Mmap>, offset: usize },
}

impl SegmentReader {
    fn open(
        path: &Path,
        encoding: LogEncoding,
        mmap: Option<Arc<Mmap>>,
    ) -> Result<Self, RaftLogError> {
        match encoding {
            LogEncoding::Json => {
                let file = File::open(path)?;
                Ok(SegmentReader::Json(BufReader::new(file)))
            }
            LogEncoding::Binary => {
                if let Some(map) = mmap {
                    return Ok(SegmentReader::BinaryMmap {
                        data: map,
                        offset: LOG_BINARY_HEADER.len(),
                    });
                }
                let file = File::open(path)?;
                let mut reader = BufReader::new(file);
                let mut header = [0u8; LOG_BINARY_HEADER.len()];
                reader.read_exact(&mut header).ok();
                Ok(SegmentReader::BinaryFile(reader))
            }
        }
    }

    fn next_entry(&mut self) -> Result<Option<RaftLogEntry>, RaftLogError> {
        match self {
            SegmentReader::Json(reader) => {
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 {
                        return Ok(None);
                    }
                    if line.trim().is_empty() {
                        continue;
                    }
                    let entry = serde_json::from_str(&line)?;
                    return Ok(Some(entry));
                }
            }
            SegmentReader::BinaryFile(reader) => match read_binary_record(reader) {
                Ok(entry) => Ok(Some(entry)),
                Err(RaftLogError::BinaryRecord) => Ok(None),
                Err(other) => Err(other),
            },
            SegmentReader::BinaryMmap { data, offset } => {
                if *offset >= data.len() {
                    return Ok(None);
                }
                let mut cursor = &data[*offset..];
                let before = cursor.len();
                match read_binary_record(&mut cursor) {
                    Ok(entry) => {
                        let consumed = before - cursor.len();
                        let new_offset = (*offset).saturating_add(consumed);
                        *offset = new_offset;
                        Ok(Some(entry))
                    }
                    Err(RaftLogError::BinaryRecord) => {
                        *offset = data.len();
                        Ok(None)
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }
}

struct StreamDescriptor {
    descriptor: SegmentDescriptor,
    mmap: Option<Arc<Mmap>>,
}

pub struct RaftLogStream {
    descriptors: Vec<StreamDescriptor>,
    segment_dir: PathBuf,
    encoding: LogEncoding,
    current_segment: Option<(usize, SegmentReadCursor)>,
    start_index: u64,
}

impl RaftLogStream {
    fn new(
        descriptors: Vec<StreamDescriptor>,
        segment_dir: PathBuf,
        encoding: LogEncoding,
        start_index: u64,
    ) -> Self {
        Self {
            descriptors,
            segment_dir,
            encoding,
            current_segment: None,
            start_index,
        }
    }
}

impl Iterator for RaftLogStream {
    type Item = Result<RaftLogEntry, RaftLogError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((idx, cursor)) = &mut self.current_segment {
                match cursor.next_entry() {
                    Ok(Some(entry)) => {
                        if entry.index < self.start_index {
                            continue;
                        }
                        self.start_index = entry.index + 1;
                        return Some(Ok(entry));
                    }
                    Ok(None) => {
                        let next_idx = *idx + 1;
                        self.current_segment = None;
                        if next_idx >= self.descriptors.len() {
                            return None;
                        }
                        continue;
                    }
                    Err(err) => {
                        self.current_segment = None;
                        return Some(Err(err));
                    }
                }
            } else {
                let next_idx = if let Some((idx, _)) = &self.current_segment {
                    *idx + 1
                } else {
                    self.descriptors
                        .iter()
                        .position(|descriptor| descriptor.descriptor.end_index >= self.start_index)
                        .unwrap_or(self.descriptors.len())
                };
                if next_idx >= self.descriptors.len() {
                    return None;
                }
                let descriptor = &self.descriptors[next_idx];
                let path = self.segment_dir.join(&descriptor.descriptor.file_name);
                match SegmentReadCursor::open(&path, self.encoding, descriptor.mmap.clone()) {
                    Ok(cursor) => self.current_segment = Some((next_idx, cursor)),
                    Err(err) => return Some(Err(err)),
                }
            }
        }
    }
}

fn encode_entry(entry: &RaftLogEntry, encoding: LogEncoding) -> Result<Vec<u8>, RaftLogError> {
    match encoding {
        LogEncoding::Json => {
            let mut bytes = serde_json::to_vec(entry)?;
            bytes.push(b'\n');
            Ok(bytes)
        }
        LogEncoding::Binary => {
            let mut buf = Vec::new();
            buf.write_all(&entry.term.to_le_bytes())?;
            buf.write_all(&entry.index.to_le_bytes())?;
            let len: u32 =
                entry
                    .payload
                    .len()
                    .try_into()
                    .map_err(|_| RaftLogError::RecordTooLarge {
                        len: entry.payload.len(),
                    })?;
            buf.write_all(&len.to_le_bytes())?;
            buf.write_all(&entry.payload)?;
            Ok(buf)
        }
    }
}

fn load_entries_from_path(
    path: &Path,
    encoding: LogEncoding,
) -> Result<Vec<RaftLogEntry>, RaftLogError> {
    match encoding {
        LogEncoding::Json => load_entries_json(path),
        LogEncoding::Binary => load_entries_binary(path),
    }
}

fn load_entries_json(path: &Path) -> Result<Vec<RaftLogEntry>, RaftLogError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        entries.push(serde_json::from_str(&line)?);
    }
    Ok(entries)
}

fn load_entries_binary(path: &Path) -> Result<Vec<RaftLogEntry>, RaftLogError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut file = File::open(path)?;
    let mut header = [0u8; LOG_BINARY_HEADER.len()];
    if file.read_exact(&mut header).is_err() {
        return Ok(Vec::new());
    }
    if header != LOG_BINARY_HEADER {
        return Err(RaftLogError::BinaryHeader);
    }
    let mut entries = Vec::new();
    loop {
        match read_binary_record(&mut file) {
            Ok(entry) => entries.push(entry),
            Err(RaftLogError::BinaryRecord) => break,
            Err(err) => return Err(err),
        }
    }
    Ok(entries)
}

fn read_binary_record<R: Read>(reader: &mut R) -> Result<RaftLogEntry, RaftLogError> {
    let mut term = [0u8; 8];
    if reader.read_exact(&mut term).is_err() {
        return Err(RaftLogError::BinaryRecord);
    }
    let mut index = [0u8; 8];
    reader.read_exact(&mut index)?;
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(RaftLogEntry {
        term: u64::from_le_bytes(term),
        index: u64::from_le_bytes(index),
        payload,
    })
}

fn load_snapshot_hint(path: &Path) -> Result<TermIndexSnapshot, RaftLogError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn store_snapshot_hint(path: &Path, hint: &TermIndexSnapshot) -> Result<(), RaftLogError> {
    let bytes = serde_json::to_vec(hint)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RaftLogEntry {
    pub term: u64,
    pub index: u64,
    pub payload: Vec<u8>,
}

impl RaftLogEntry {
    pub fn new(term: u64, index: u64, payload: Vec<u8>) -> Self {
        Self {
            term,
            index,
            payload,
        }
    }
}

#[derive(Debug, Error)]
pub enum RaftLogError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("expected next index {expected}, attempted {attempted}")]
    NonSequentialAppend { expected: u64, attempted: u64 },
    #[error("term regression: previous={previous}, attempted={attempted}")]
    TermRegression { previous: u64, attempted: u64 },
    #[error("truncate index must be >0 (observed {0})")]
    InvalidTruncateIndex(u64),
    #[error("binary log header missing or corrupt")]
    BinaryHeader,
    #[error("binary log record truncated or corrupt")]
    BinaryRecord,
    #[error("log record too large (len={len})")]
    RecordTooLarge { len: usize },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}
