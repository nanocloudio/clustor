use crate::storage::entry::{EntryFrame, EntryFrameError};
use crate::storage::layout::WalSegmentRef;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::PathBuf;
use thiserror::Error;

const MIN_FRAME_PREFIX: usize = 8 + 8 + 8 + 2 + 4; // term + index + timestamp + metadata_len + payload_len
const CRC_LEN: usize = 4;
const MERKLE_LEN: usize = 32;

#[derive(Debug)]
pub struct WalReplayResult {
    pub frames: Vec<EntryFrame>,
    pub truncation: Option<WalTruncation>,
}

impl WalReplayResult {
    pub fn enforce_truncation(&self) -> Result<(), WalReplayError> {
        if let Some(truncation) = &self.truncation {
            let file = OpenOptions::new().write(true).open(&truncation.path)?;
            file.set_len(truncation.offset)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WalTruncation {
    pub segment_seq: u64,
    pub path: PathBuf,
    pub offset: u64,
    pub truncated_bytes: u64,
    pub error: EntryFrameError,
}

pub struct WalReplayScanner;

impl WalReplayScanner {
    pub fn scan(segments: &[WalSegmentRef]) -> Result<WalReplayResult, WalReplayError> {
        let mut frames = Vec::new();
        for segment in segments {
            let mut file = File::open(&segment.log_path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            let mut cursor = 0usize;
            while cursor < buf.len() {
                match decode_frame(&buf, cursor) {
                    Ok((frame, next_cursor)) => {
                        frames.push(frame);
                        cursor = next_cursor;
                    }
                    Err(err) => {
                        let truncated = buf.len().saturating_sub(cursor) as u64;
                        return Ok(WalReplayResult {
                            frames,
                            truncation: Some(WalTruncation {
                                segment_seq: segment.seq,
                                path: segment.log_path.clone(),
                                offset: cursor as u64,
                                truncated_bytes: truncated,
                                error: err,
                            }),
                        });
                    }
                }
            }
        }
        Ok(WalReplayResult {
            frames,
            truncation: None,
        })
    }
}

fn decode_frame(buf: &[u8], cursor: usize) -> Result<(EntryFrame, usize), EntryFrameError> {
    if buf.len() - cursor < MIN_FRAME_PREFIX + CRC_LEN + MERKLE_LEN {
        return Err(EntryFrameError::TooShort);
    }
    let metadata_len = read_u16(&buf[cursor + 8 + 8 + 8..cursor + 8 + 8 + 8 + 2]) as usize;
    let payload_len = read_u32(&buf[cursor + 8 + 8 + 8 + 2..cursor + 8 + 8 + 8 + 2 + 4]) as usize;
    let total_len = MIN_FRAME_PREFIX + metadata_len + payload_len + CRC_LEN + MERKLE_LEN;
    if cursor + total_len > buf.len() {
        return Err(EntryFrameError::Corrupt);
    }
    let slice = &buf[cursor..cursor + total_len];
    let frame = EntryFrame::decode(slice)?;
    Ok((frame, cursor + total_len))
}

fn read_u16(bytes: &[u8]) -> u16 {
    let mut array = [0u8; 2];
    array.copy_from_slice(&bytes[..2]);
    u16::from_le_bytes(array)
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut array = [0u8; 4];
    array.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(array)
}

#[derive(Debug, Error)]
pub enum WalReplayError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("frame error: {0}")]
    Frame(#[from] EntryFrameError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::entry::EntryFrameBuilder;
    use crate::storage::layout::WalSegmentRef;
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
}
