use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};

/// Shared buffered writer that automatically flushes when buffered bytes exceed a threshold.
#[derive(Debug)]
pub struct SharedBufferedWriter {
    inner: BufWriter<File>,
    flush_threshold: usize,
    buffered: usize,
}

impl SharedBufferedWriter {
    pub fn new(file: File, capacity: usize, flush_threshold: usize) -> Self {
        Self {
            inner: BufWriter::with_capacity(capacity, file),
            flush_threshold,
            buffered: 0,
        }
    }

    pub fn with_position(
        mut file: File,
        capacity: usize,
        flush_threshold: usize,
    ) -> io::Result<Self> {
        let end = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(end))?;
        Ok(Self::new(file, capacity, flush_threshold))
    }

    pub fn write_all(&mut self, payload: &[u8]) -> io::Result<()> {
        self.inner.write_all(payload)?;
        self.buffered = self.buffered.saturating_add(payload.len());
        if self.flush_threshold > 0 && self.buffered >= self.flush_threshold {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()?;
        self.buffered = 0;
        Ok(())
    }

    pub fn sync_data(&mut self) -> io::Result<()> {
        self.inner.get_ref().sync_data()
    }

    pub fn into_inner(self) -> io::Result<File> {
        self.inner.into_inner().map_err(|err| err.into_error())
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered
    }
}
