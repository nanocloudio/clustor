use crc32fast::Hasher as Crc32Hasher;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub term: u64,
    pub index: u64,
    pub timestamp_ms: u64,
    pub metadata_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleDigest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFrame {
    pub header: FrameHeader,
    pub metadata: Vec<u8>,
    pub payload: Vec<u8>,
    pub crc32: u32,
    pub merkle: MerkleDigest,
}

impl EntryFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.term.to_le_bytes());
        bytes.extend_from_slice(&self.header.index.to_le_bytes());
        bytes.extend_from_slice(&self.header.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(&self.header.metadata_len.to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.metadata);
        bytes.extend_from_slice(&self.payload);
        bytes.extend_from_slice(&self.crc32.to_le_bytes());
        bytes.extend_from_slice(&self.merkle.0);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EntryFrameError> {
        if bytes.len() < 8 * 2 + 8 + 2 + 4 + 4 + 32 {
            return Err(EntryFrameError::TooShort);
        }
        let mut cursor = 0;
        let term = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| EntryFrameError::Corrupt)?,
        );
        cursor += 8;
        let index = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| EntryFrameError::Corrupt)?,
        );
        cursor += 8;
        let timestamp_ms = u64::from_le_bytes(
            bytes[cursor..cursor + 8]
                .try_into()
                .map_err(|_| EntryFrameError::Corrupt)?,
        );
        cursor += 8;
        let metadata_len = u16::from_le_bytes(
            bytes[cursor..cursor + 2]
                .try_into()
                .map_err(|_| EntryFrameError::Corrupt)?,
        );
        cursor += 2;
        let payload_len = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| EntryFrameError::Corrupt)?,
        ) as usize;
        cursor += 4;

        let metadata_end = cursor + metadata_len as usize;
        if metadata_end > bytes.len() {
            return Err(EntryFrameError::Corrupt);
        }
        let payload_end = metadata_end + payload_len;
        if payload_end + 4 + 32 > bytes.len() {
            return Err(EntryFrameError::Corrupt);
        }
        let metadata = bytes[cursor..metadata_end].to_vec();
        let payload = bytes[metadata_end..payload_end].to_vec();
        cursor = payload_end;
        let crc32 = u32::from_le_bytes(
            bytes[cursor..cursor + 4]
                .try_into()
                .map_err(|_| EntryFrameError::Corrupt)?,
        );
        cursor += 4;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[cursor..cursor + 32]);

        let frame = EntryFrame {
            header: FrameHeader {
                term,
                index,
                timestamp_ms,
                metadata_len,
            },
            metadata,
            payload,
            crc32,
            merkle: MerkleDigest(digest),
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), EntryFrameError> {
        if self.metadata.len() > u16::MAX as usize {
            return Err(EntryFrameError::MetadataTooLarge);
        }
        if self.header.metadata_len as usize != self.metadata.len() {
            return Err(EntryFrameError::MetadataLengthMismatch);
        }
        let mut hasher = Crc32Hasher::new();
        hasher.update(&self.metadata);
        hasher.update(&self.payload);
        let crc = hasher.finalize();
        if crc != self.crc32 {
            return Err(EntryFrameError::CrcMismatch);
        }
        let mut sha = Sha256::new();
        sha.update(&self.payload);
        let computed: [u8; 32] = sha.finalize().into();
        if computed != self.merkle.0 {
            return Err(EntryFrameError::MerkleMismatch);
        }
        Ok(())
    }
}

pub struct EntryFrameBuilder {
    header: FrameHeader,
    metadata: Vec<u8>,
    payload: Vec<u8>,
}

impl EntryFrameBuilder {
    pub fn new(term: u64, index: u64) -> Self {
        Self {
            header: FrameHeader {
                term,
                index,
                timestamp_ms: current_time_ms(),
                metadata_len: 0,
            },
            metadata: Vec::new(),
            payload: Vec::new(),
        }
    }

    pub fn metadata(mut self, bytes: Vec<u8>) -> Self {
        self.header.metadata_len = bytes.len() as u16;
        self.metadata = bytes;
        self
    }

    pub fn payload(mut self, bytes: Vec<u8>) -> Self {
        self.payload = bytes;
        self
    }

    pub fn build(self) -> EntryFrame {
        let mut crc = Crc32Hasher::new();
        crc.update(&self.metadata);
        crc.update(&self.payload);
        let crc32 = crc.finalize();
        let mut sha = Sha256::new();
        sha.update(&self.payload);
        let digest: [u8; 32] = sha.finalize().into();
        EntryFrame {
            header: self.header,
            metadata: self.metadata,
            payload: self.payload,
            crc32,
            merkle: MerkleDigest(digest),
        }
    }
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum EntryFrameError {
    #[error("frame too short")]
    TooShort,
    #[error("metadata length mismatch")]
    MetadataLengthMismatch,
    #[error("metadata size exceeds limit")]
    MetadataTooLarge,
    #[error("CRC mismatch")]
    CrcMismatch,
    #[error("Merkle mismatch")]
    MerkleMismatch,
    #[error("corrupt frame data")]
    Corrupt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let frame = EntryFrameBuilder::new(7, 42)
            .metadata(vec![1, 2, 3])
            .payload(b"hello".to_vec())
            .build();
        let bytes = frame.encode();
        let decoded = EntryFrame::decode(&bytes).unwrap();
        assert_eq!(frame, decoded);
    }
}
