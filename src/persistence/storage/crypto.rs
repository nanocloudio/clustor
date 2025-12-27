use crate::replication::transport::{CatalogNegotiationReport, ForwardCompatTracker};
use crate::storage::layout::NonceReservationAbandon;
// aes-gcm relies on generic-array 0.14, so suppress the upstream deprecation locally.
#[allow(deprecated)]
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use thiserror::Error;

pub const WAL_CRYPTO_BLOCK_BYTES: u16 = 4096;
pub const MAX_RESERVATION_BLOCKS: u32 = 1024;
const WAL_FORMAT_VERSION_V1: u8 = 1;
const AAD_VERSION: u8 = 1;
const IV_DOMAIN: &[u8] = b"WAL-Block-IV v1";
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEpoch {
    pub kek_version: u32,
    pub dek_epoch: u32,
    pub integrity_mac_epoch: u32,
}

#[derive(Debug, Default)]
pub struct KeyEpochTracker {
    current: Option<KeyEpoch>,
}

impl KeyEpochTracker {
    pub fn observe(&mut self, candidate: KeyEpoch) -> Result<(), KeyEpochError> {
        if let Some(current) = self.current {
            if candidate.kek_version < current.kek_version
                || candidate.dek_epoch < current.dek_epoch
                || candidate.integrity_mac_epoch < current.integrity_mac_epoch
            {
                return Err(KeyEpochError::Replay {
                    observed: candidate,
                    current,
                });
            }
        }
        self.current = Some(candidate);
        Ok(())
    }

    pub fn current(&self) -> Option<KeyEpoch> {
        self.current
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyEpochError {
    #[error("key epoch replay detected: observed={observed:?}, current={current:?}")]
    Replay {
        observed: KeyEpoch,
        current: KeyEpoch,
    },
}

#[derive(Debug, Clone)]
pub struct DataEncryptionKey {
    pub epoch: u32,
    pub bytes: [u8; 32],
}

impl DataEncryptionKey {
    pub fn new(epoch: u32, bytes: [u8; 32]) -> Self {
        Self { epoch, bytes }
    }
}

pub struct WalAead {
    cipher: Aes256Gcm,
    crypto_block_bytes: u16,
    partition_id: String,
}

impl WalAead {
    pub fn new(key: &DataEncryptionKey, partition_id: impl Into<String>) -> Self {
        let cipher = Aes256Gcm::new(key_ref(&key.bytes));
        Self {
            cipher,
            crypto_block_bytes: WAL_CRYPTO_BLOCK_BYTES,
            partition_id: partition_id.into(),
        }
    }

    pub fn encrypt_block(
        &self,
        dek_epoch: u32,
        segment_seq: u64,
        block_counter: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() != self.crypto_block_bytes as usize {
            return Err(CryptoError::BlockSizeMismatch {
                expected: self.crypto_block_bytes as usize,
                observed: plaintext.len(),
            });
        }
        let mut buffer = plaintext.to_vec();
        let nonce_bytes = derive_nonce(dek_epoch, segment_seq, block_counter);
        let aad = build_aad(&self.partition_id, dek_epoch, segment_seq);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce_ref(&nonce_bytes), &aad, &mut buffer)
            .map_err(|_| CryptoError::Encrypt)?;
        buffer.extend(tag.iter().copied());
        Ok(buffer)
    }

    pub fn decrypt_block(
        &self,
        dek_epoch: u32,
        segment_seq: u64,
        block_counter: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let expected_len = self.crypto_block_bytes as usize + TAG_LEN;
        if ciphertext.len() != expected_len {
            return Err(CryptoError::BlockSizeMismatch {
                expected: expected_len,
                observed: ciphertext.len(),
            });
        }
        let (data, tag_bytes) = ciphertext.split_at(self.crypto_block_bytes as usize);
        let nonce_bytes = derive_nonce(dek_epoch, segment_seq, block_counter);
        let aad = build_aad(&self.partition_id, dek_epoch, segment_seq);
        let mut buf = data.to_vec();
        self.cipher
            .decrypt_in_place_detached(nonce_ref(&nonce_bytes), &aad, &mut buf, tag_ref(tag_bytes))
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(buf)
    }
}

fn build_aad(partition_id: &str, dek_epoch: u32, segment_seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + 2 + partition_id.len() + 4 + 8);
    aad.push(AAD_VERSION);
    let id_len = u16::try_from(partition_id.len()).unwrap_or(u16::MAX);
    aad.extend_from_slice(&id_len.to_be_bytes());
    aad.extend_from_slice(partition_id.as_bytes());
    aad.extend_from_slice(&dek_epoch.to_be_bytes());
    aad.extend_from_slice(&segment_seq.to_be_bytes());
    aad
}

fn derive_nonce(dek_epoch: u32, segment_seq: u64, block_counter: u64) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(dek_epoch.to_be_bytes());
    hasher.update(segment_seq.to_be_bytes());
    hasher.update(block_counter.to_be_bytes());
    hasher.update(IV_DOMAIN);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&digest[..12]);
    iv
}

#[allow(deprecated)]
fn key_ref(bytes: &[u8; 32]) -> &Key<Aes256Gcm> {
    Key::<Aes256Gcm>::from_slice(bytes)
}

#[allow(deprecated)]
fn nonce_ref(bytes: &[u8; 12]) -> &GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    GenericArray::from_slice(bytes)
}

#[allow(deprecated)]
fn tag_ref(bytes: &[u8]) -> &GenericArray<u8, <Aes256Gcm as AeadCore>::TagSize> {
    GenericArray::from_slice(bytes)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("block size mismatch: expected {expected} bytes, observed {observed}")]
    BlockSizeMismatch { expected: usize, observed: usize },
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeader {
    pub wal_format_version: u8,
    pub segment_seq: u64,
    pub crypto_block_bytes: u16,
    pub dek_epoch: u32,
    pub reserved: u16,
}

impl SegmentHeader {
    pub fn new(wal_format_version: u8, segment_seq: u64, dek_epoch: u32) -> Self {
        Self {
            wal_format_version,
            segment_seq,
            crypto_block_bytes: WAL_CRYPTO_BLOCK_BYTES,
            dek_epoch,
            reserved: 0,
        }
    }

    pub fn encode(&self) -> [u8; 17] {
        let mut bytes = [0u8; 17];
        bytes[0] = self.wal_format_version;
        bytes[1..9].copy_from_slice(&self.segment_seq.to_be_bytes());
        bytes[9..11].copy_from_slice(&self.crypto_block_bytes.to_be_bytes());
        bytes[11..15].copy_from_slice(&self.dek_epoch.to_be_bytes());
        bytes[15..17].copy_from_slice(&self.reserved.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SegmentHeaderError> {
        let mut tracker = ForwardCompatTracker::noop();
        Self::decode_with_tracker(bytes, &mut tracker)
    }

    pub fn decode_with_report(
        bytes: &[u8],
        report: &mut CatalogNegotiationReport,
    ) -> Result<Self, SegmentHeaderError> {
        let mut tracker = ForwardCompatTracker::new(report);
        Self::decode_with_tracker(bytes, &mut tracker)
    }

    pub fn decode_with_tracker(
        bytes: &[u8],
        tracker: &mut ForwardCompatTracker<'_>,
    ) -> Result<Self, SegmentHeaderError> {
        if bytes.len() < 17 {
            return Err(SegmentHeaderError::TooShort);
        }
        let wal_format_version = bytes[0];
        if wal_format_version != WAL_FORMAT_VERSION_V1 {
            tracker
                .record_violation(format!(
                    "segment_header.wal_format_version={wal_format_version}"
                ))
                .map_err(|err| SegmentHeaderError::ForwardCompat(err.to_string()))?;
            return Err(SegmentHeaderError::UnsupportedFormatVersion {
                observed: wal_format_version,
                expected: WAL_FORMAT_VERSION_V1,
            });
        }
        Ok(Self {
            wal_format_version,
            segment_seq: u64::from_be_bytes(
                bytes[1..9]
                    .try_into()
                    .map_err(|_| SegmentHeaderError::TooShort)?,
            ),
            crypto_block_bytes: u16::from_be_bytes(
                bytes[9..11]
                    .try_into()
                    .map_err(|_| SegmentHeaderError::TooShort)?,
            ),
            dek_epoch: u32::from_be_bytes(
                bytes[11..15]
                    .try_into()
                    .map_err(|_| SegmentHeaderError::TooShort)?,
            ),
            reserved: u16::from_be_bytes(
                bytes[15..17]
                    .try_into()
                    .map_err(|_| SegmentHeaderError::TooShort)?,
            ),
        })
    }

    pub fn validate(&self, expected_block_bytes: u16) -> Result<(), SegmentHeaderError> {
        if self.crypto_block_bytes != expected_block_bytes {
            return Err(SegmentHeaderError::CryptoBlockMismatch {
                observed: self.crypto_block_bytes,
                expected: expected_block_bytes,
            });
        }
        Ok(())
    }

    pub fn seal_block(&self, aead: &WalAead, dek_epoch: u32) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; WAL_CRYPTO_BLOCK_BYTES as usize];
        buffer[..17].copy_from_slice(&self.encode());
        aead.encrypt_block(dek_epoch, self.segment_seq, 0, &buffer)
    }

    pub fn open_block(
        aead: &WalAead,
        dek_epoch: u32,
        segment_seq: u64,
        ciphertext: &[u8],
    ) -> Result<Self, SegmentHeaderError> {
        let plaintext = aead
            .decrypt_block(dek_epoch, segment_seq, 0, ciphertext)
            .map_err(|err| SegmentHeaderError::Crypto(err.to_string()))?;
        SegmentHeader::decode(&plaintext[..17])
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SegmentHeaderError {
    #[error("segment header too short")]
    TooShort,
    #[error("crypto block size mismatch: expected {expected}, observed {observed}")]
    CryptoBlockMismatch { observed: u16, expected: u16 },
    #[error("unsupported WAL format version {observed} (expected {expected})")]
    UnsupportedFormatVersion { observed: u8, expected: u8 },
    #[error("failed to record forward-compat violation: {0}")]
    ForwardCompat(String),
    #[error("segment header crypto failure: {0}")]
    Crypto(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceReservationRange {
    pub segment_seq: u64,
    pub start_block: u64,
    pub block_count: u32,
    pub reserved_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct NonceLedgerConfig {
    pub warn_gap_bytes: u64,
    pub abandon_gap_bytes: u64,
}

impl Default for NonceLedgerConfig {
    fn default() -> Self {
        Self {
            warn_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64 * 1024,
            abandon_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64 * 2048,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceReservationTelemetry {
    pub committed_blocks: u64,
    pub reserved_blocks: u64,
    pub gap_bytes: u64,
}

pub struct NonceReservationLedger {
    segment_seq: u64,
    max_blocks_per_reservation: u32,
    committed_tail: u64,
    reserved_tail: u64,
    pending_completions: BTreeSet<u64>,
    active_ranges: VecDeque<NonceReservationRange>,
    config: NonceLedgerConfig,
}

impl NonceReservationLedger {
    pub fn new(segment_seq: u64) -> Self {
        Self::with_config(segment_seq, NonceLedgerConfig::default())
    }

    pub fn with_config(segment_seq: u64, config: NonceLedgerConfig) -> Self {
        Self {
            segment_seq,
            max_blocks_per_reservation: MAX_RESERVATION_BLOCKS,
            committed_tail: 0,
            reserved_tail: 0,
            pending_completions: BTreeSet::new(),
            active_ranges: VecDeque::new(),
            config,
        }
    }

    pub fn reserve(
        &mut self,
        block_count: u32,
        reserved_at_ms: u64,
    ) -> Result<NonceReservationRange, NonceLedgerError> {
        if block_count == 0 {
            return Err(NonceLedgerError::InvalidReservation);
        }
        if block_count > self.max_blocks_per_reservation {
            return Err(NonceLedgerError::ReservationTooLarge {
                requested: block_count,
                max: self.max_blocks_per_reservation,
            });
        }
        let range = NonceReservationRange {
            segment_seq: self.segment_seq,
            start_block: self.reserved_tail,
            block_count,
            reserved_at_ms,
        };
        self.reserved_tail += block_count as u64;
        self.active_ranges.push_back(range.clone());
        Ok(range)
    }

    pub fn reserve_default(
        &mut self,
        reserved_at_ms: u64,
    ) -> Result<NonceReservationRange, NonceLedgerError> {
        self.reserve(self.max_blocks_per_reservation, reserved_at_ms)
    }

    pub fn record_completion(&mut self, block_counter: u64) -> Result<(), NonceLedgerError> {
        if block_counter >= self.reserved_tail {
            return Err(NonceLedgerError::CompletionOutsideReservation {
                block_counter,
                reserved_tail: self.reserved_tail,
            });
        }
        if block_counter < self.committed_tail {
            return Ok(());
        }
        if !self.pending_completions.insert(block_counter) {
            return Ok(());
        }
        self.advance_committed();
        Ok(())
    }

    fn advance_committed(&mut self) {
        while self.pending_completions.remove(&self.committed_tail) {
            self.committed_tail += 1;
            self.prune_consumed_ranges();
        }
    }

    fn prune_consumed_ranges(&mut self) {
        while let Some(front) = self.active_ranges.front() {
            let range_end = front.start_block + front.block_count as u64;
            if range_end <= self.committed_tail {
                self.active_ranges.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn has_outstanding_reservations(&self) -> bool {
        self.committed_tail < self.reserved_tail
    }

    pub fn gap_bytes(&self) -> u64 {
        (self.reserved_tail - self.committed_tail) * WAL_CRYPTO_BLOCK_BYTES as u64
    }

    pub fn warn_gap(&self) -> bool {
        self.gap_bytes() >= self.config.warn_gap_bytes
    }

    pub fn needs_scrub(&self) -> bool {
        self.gap_bytes() > self.config.abandon_gap_bytes
    }

    pub fn telemetry(&self) -> NonceReservationTelemetry {
        NonceReservationTelemetry {
            committed_blocks: self.committed_tail,
            reserved_blocks: self.reserved_tail,
            gap_bytes: self.gap_bytes(),
        }
    }

    pub fn abandon(
        &mut self,
        reason: impl Into<String>,
        recorded_at_ms: u64,
    ) -> NonceReservationAbandon {
        self.pending_completions.clear();
        self.active_ranges.clear();
        self.committed_tail = 0;
        self.reserved_tail = 0;
        NonceReservationAbandon {
            segment_seq: self.segment_seq,
            abandon_reason: reason.into(),
            recorded_at_ms,
        }
    }

    pub fn committed_blocks(&self) -> u64 {
        self.committed_tail
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceLedgerError {
    #[error("reservation size {requested} exceeds max {max}")]
    ReservationTooLarge { requested: u32, max: u32 },
    #[error("reservation must allocate at least one block")]
    InvalidReservation,
    #[error("completion {block_counter} outside reserved tail (reserved tail {reserved_tail})")]
    CompletionOutsideReservation {
        block_counter: u64,
        reserved_tail: u64,
    },
}
