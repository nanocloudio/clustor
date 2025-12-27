use crate::retry::RetryPolicy;
use crate::storage::DataEncryptionKey;
#[allow(deprecated)]
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use log::{info, warn};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroize;

use super::manifest::{compute_hash, ManifestEncryption, SnapshotChunk};
use super::telemetry::SnapshotImportNodeTelemetrySnapshot;
use super::SNAPSHOT_IMPORT_NODE_FLOOR_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnapshotExportProfile {
    #[default]
    Latency,
    Throughput,
    Wan,
}

impl SnapshotExportProfile {
    pub fn caps(&self) -> SnapshotExportCaps {
        match self {
            SnapshotExportProfile::Latency => SnapshotExportCaps {
                max_chunk_bytes: 4 * 1024 * 1024,
                max_total_bytes: 256 * 1024 * 1024,
                max_chunks: 128,
            },
            SnapshotExportProfile::Throughput => SnapshotExportCaps {
                max_chunk_bytes: 8 * 1024 * 1024,
                max_total_bytes: 1024 * 1024 * 1024,
                max_chunks: 256,
            },
            SnapshotExportProfile::Wan => SnapshotExportCaps {
                max_chunk_bytes: 2 * 1024 * 1024,
                max_total_bytes: 128 * 1024 * 1024,
                max_chunks: 256,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotExportCaps {
    pub max_chunk_bytes: u64,
    pub max_total_bytes: u64,
    pub max_chunks: usize,
}

#[derive(Debug, Clone)]
pub struct SnapshotChunkPayload {
    pub chunk: SnapshotChunk,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotImportRetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub time_budget: Duration,
    pub jitter_fraction: f64,
}

impl Default for SnapshotImportRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(1_000),
            max_delay: Duration::from_millis(10_000),
            time_budget: Duration::from_secs(60),
            jitter_fraction: 0.25,
        }
    }
}

impl SnapshotImportRetryPolicy {
    pub fn to_retry_policy(self) -> RetryPolicy {
        RetryPolicy::exponential((self.max_retries + 1) as usize, self.base_delay)
            .with_max_delay(self.max_delay)
            .with_time_budget(Some(self.time_budget))
            .with_jitter(self.jitter_fraction)
    }
}

pub struct SnapshotChunkImporter {
    cipher: Aes256Gcm,
    dek_epoch: u32,
    iv_salt: String,
    retry: RetryPolicy,
}

impl SnapshotChunkImporter {
    pub fn new(key: &DataEncryptionKey, iv_salt: impl Into<String>) -> Self {
        Self::with_retry_policy(key, iv_salt, SnapshotImportRetryPolicy::default())
    }

    pub fn with_retry_policy(
        key: &DataEncryptionKey,
        iv_salt: impl Into<String>,
        retry: SnapshotImportRetryPolicy,
    ) -> Self {
        Self {
            cipher: Aes256Gcm::new(key_ref(&key.bytes)),
            dek_epoch: key.epoch,
            iv_salt: iv_salt.into(),
            retry: retry.to_retry_policy(),
        }
    }

    pub fn import_chunk(
        &self,
        manifest_id: &str,
        payload: &SnapshotChunkPayload,
    ) -> Result<Vec<u8>, SnapshotImportError> {
        self.import_chunk_with_retry(manifest_id, payload, Instant::now())
    }

    fn import_chunk_with_retry(
        &self,
        manifest_id: &str,
        payload: &SnapshotChunkPayload,
        start: Instant,
    ) -> Result<Vec<u8>, SnapshotImportError> {
        let mut retry = self.retry.handle_from(start);
        loop {
            match self.decrypt_once(manifest_id, payload) {
                Ok(bytes) => return Ok(bytes),
                Err(err @ SnapshotImportError::UnknownChunk { .. }) => return Err(err),
                Err(err) => {
                    if let Some(delay) = retry.next_delay() {
                        if delay.is_zero() {
                            continue;
                        }
                        thread::sleep(delay);
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    fn decrypt_once(
        &self,
        manifest_id: &str,
        payload: &SnapshotChunkPayload,
    ) -> Result<Vec<u8>, SnapshotImportError> {
        let chunk_id = payload.chunk.chunk_id.clone();
        let chunk_index =
            chunk_index_from_id(&chunk_id).ok_or_else(|| SnapshotImportError::Decrypt {
                chunk_id: chunk_id.clone(),
            })?;
        let mut ciphertext = payload.ciphertext.clone();
        if ciphertext.len() < 16 {
            return Err(SnapshotImportError::Decrypt {
                chunk_id: chunk_id.clone(),
            });
        }
        let tag_split = ciphertext.len() - 16;
        let (body, tag) = ciphertext.split_at_mut(tag_split);
        let mut plaintext = body.to_vec();
        let aad = build_chunk_aad(manifest_id, chunk_index, payload.chunk.len);
        let nonce = derive_chunk_nonce(self.dek_epoch, &self.iv_salt, chunk_index);
        if self
            .cipher
            .decrypt_in_place_detached(nonce_ref(&nonce), &aad, &mut plaintext, tag_ref(tag))
            .is_err()
        {
            plaintext.zeroize();
            return Err(SnapshotImportError::Decrypt { chunk_id });
        }
        if compute_hash(&plaintext) != payload.chunk.digest {
            plaintext.zeroize();
            return Err(SnapshotImportError::DigestMismatch { chunk_id });
        }
        Ok(plaintext)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotImportError {
    #[error("chunk {chunk_id} not found in buffer")]
    UnknownChunk { chunk_id: String },
    #[error("chunk digest mismatch for {chunk_id}")]
    DigestMismatch { chunk_id: String },
    #[error("failed to decrypt chunk {chunk_id}")]
    Decrypt { chunk_id: String },
    #[error("snapshot import node buffer exhausted (usage={usage_bytes} limit={limit_bytes})")]
    NodePressure { usage_bytes: u64, limit_bytes: u64 },
    #[error("snapshot import queue exceeded {kind} limit (observed={observed} limit={limit})")]
    QueueLimit {
        kind: SnapshotQueueLimit,
        observed: usize,
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotQueueLimit {
    Bytes,
    Entries,
    Batches,
}

impl fmt::Display for SnapshotQueueLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotQueueLimit::Bytes => write!(f, "byte"),
            SnapshotQueueLimit::Entries => write!(f, "entry"),
            SnapshotQueueLimit::Batches => write!(f, "batch"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StagedChunk {
    pub chunk_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SnapshotStagingStore {
    staged: Vec<StagedChunk>,
}

impl SnapshotStagingStore {
    pub fn new() -> Self {
        Self { staged: Vec::new() }
    }

    pub fn stage(&mut self, chunk_id: impl Into<String>, bytes: Vec<u8>) {
        self.staged.push(StagedChunk {
            chunk_id: chunk_id.into(),
            bytes,
        });
    }

    pub fn total_bytes(&self) -> usize {
        self.staged.iter().map(|chunk| chunk.bytes.len()).sum()
    }

    pub fn chunks(&self) -> &[StagedChunk] {
        &self.staged
    }
}

#[derive(Debug)]
pub struct SnapshotImportNodeBudget {
    node_ram_bytes: u64,
    ram_fraction: f64,
    hard_cap_bytes: u64,
    usage_bytes: u64,
    peak_usage_bytes: u64,
}

impl SnapshotImportNodeBudget {
    pub fn new(node_ram_bytes: u64, ram_fraction: f64, hard_cap_bytes: u64) -> Self {
        Self {
            node_ram_bytes,
            ram_fraction,
            hard_cap_bytes,
            usage_bytes: 0,
            peak_usage_bytes: 0,
        }
    }

    pub fn limit_bytes(&self) -> u64 {
        let fraction = self.ram_fraction.clamp(0.05, 0.25);
        let fraction_cap = ((self.node_ram_bytes as f64) * fraction).floor() as u64;
        let floor = SNAPSHOT_IMPORT_NODE_FLOOR_BYTES;
        let bounded = fraction_cap.max(floor);
        bounded.min(self.hard_cap_bytes)
    }

    pub fn try_reserve(&mut self, bytes: u64) -> Result<(), SnapshotImportError> {
        let limit = self.limit_bytes();
        if bytes > limit {
            return Err(SnapshotImportError::NodePressure {
                usage_bytes: self.usage_bytes,
                limit_bytes: limit,
            });
        }
        let new_usage = self.usage_bytes.saturating_add(bytes);
        if new_usage > limit {
            return Err(SnapshotImportError::NodePressure {
                usage_bytes: self.usage_bytes,
                limit_bytes: limit,
            });
        }
        self.usage_bytes = new_usage;
        if new_usage > self.peak_usage_bytes {
            self.peak_usage_bytes = new_usage;
        }
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) {
        self.usage_bytes = self.usage_bytes.saturating_sub(bytes);
    }

    pub fn telemetry(&self) -> SnapshotImportNodeTelemetrySnapshot {
        SnapshotImportNodeTelemetrySnapshot {
            usage_bytes: self.usage_bytes,
            peak_usage_bytes: self.peak_usage_bytes,
            limit_bytes: self.limit_bytes(),
        }
    }
}

pub struct SnapshotChunkExporter {
    caps: SnapshotExportCaps,
    cipher: Aes256Gcm,
    dek_epoch: u32,
    iv_salt: String,
}

impl SnapshotChunkExporter {
    pub fn new(
        profile: SnapshotExportProfile,
        key: &DataEncryptionKey,
        iv_salt: impl Into<String>,
    ) -> Self {
        Self::with_caps(profile.caps(), key, iv_salt)
    }

    /// Builds an exporter with explicitly provided limits.
    ///
    /// This is primarily intended for tests that need to exercise the exporter
    /// without writing hundreds of megabytes.
    pub fn with_caps(
        caps: SnapshotExportCaps,
        key: &DataEncryptionKey,
        iv_salt: impl Into<String>,
    ) -> Self {
        let iv_salt = iv_salt.into();
        let cipher = Aes256Gcm::new(key_ref(&key.bytes));
        Self {
            caps,
            cipher,
            dek_epoch: key.epoch,
            iv_salt,
        }
    }

    pub fn caps(&self) -> SnapshotExportCaps {
        self.caps
    }

    pub fn encryption(&self) -> ManifestEncryption {
        ManifestEncryption {
            dek_epoch: self.dek_epoch,
            iv_salt: self.iv_salt.clone(),
        }
    }

    pub fn export_reader<R: Read>(
        &self,
        manifest_id: &str,
        mut reader: R,
        chunk_bytes: usize,
    ) -> Result<Vec<SnapshotChunkPayload>, SnapshotExportError> {
        info!(
            "event=snapshot_export_start clause={} manifest_id={} chunk_bytes={} max_chunk_bytes={} max_chunks={} max_total_bytes={}",
            super::SNAPSHOT_EXPORT_SPEC,
            manifest_id,
            chunk_bytes,
            self.caps.max_chunk_bytes,
            self.caps.max_chunks,
            self.caps.max_total_bytes
        );
        if chunk_bytes == 0 {
            warn!(
                "event=snapshot_export_block clause={} manifest_id={} reason=invalid_chunk_size",
                super::SNAPSHOT_EXPORT_SPEC,
                manifest_id
            );
            return Err(SnapshotExportError::InvalidChunkSize);
        }
        if chunk_bytes as u64 > self.caps.max_chunk_bytes {
            warn!(
                "event=snapshot_export_block clause={} manifest_id={} reason=chunk_size_exceeded requested={} limit={}",
                super::SNAPSHOT_EXPORT_SPEC,
                manifest_id,
                chunk_bytes,
                self.caps.max_chunk_bytes
            );
            return Err(SnapshotExportError::ChunkSizeExceeded {
                requested: chunk_bytes as u64,
                limit: self.caps.max_chunk_bytes,
            });
        }
        let mut offset = 0u64;
        let mut total = 0u64;
        let mut chunk_index = 0u64;
        let mut result = Vec::new();
        let mut buffer = vec![0u8; chunk_bytes];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if chunk_index as usize >= self.caps.max_chunks {
                warn!(
                    "event=snapshot_export_block clause={} manifest_id={} reason=chunk_count_exceeded chunk_index={} limit={}",
                    super::SNAPSHOT_EXPORT_SPEC,
                    manifest_id,
                    chunk_index,
                    self.caps.max_chunks
                );
                return Err(SnapshotExportError::ChunkCountExceeded {
                    limit: self.caps.max_chunks,
                });
            }
            total = total
                .checked_add(read as u64)
                .ok_or(SnapshotExportError::TotalBytesExceeded)?;
            if total > self.caps.max_total_bytes {
                warn!(
                    "event=snapshot_export_block clause={} manifest_id={} reason=total_bytes_exceeded total_bytes={} limit={}",
                    super::SNAPSHOT_EXPORT_SPEC,
                    manifest_id,
                    total,
                    self.caps.max_total_bytes
                );
                return Err(SnapshotExportError::TotalBytesExceeded);
            }
            let plaintext = &buffer[..read];
            let digest = compute_hash(plaintext);
            let ciphertext = self
                .encrypt_chunk(manifest_id, chunk_index, plaintext)
                .map_err(|err| {
                    warn!(
                        "event=snapshot_export_block clause={} manifest_id={} reason=encrypt_failure chunk_index={} error={:?}",
                        super::SNAPSHOT_EXPORT_SPEC,
                        manifest_id,
                        chunk_index,
                        err
                    );
                    SnapshotExportError::Encrypt
                })?;
            let chunk = SnapshotChunk {
                chunk_id: format!("{manifest_id}-{chunk_index:04}"),
                offset,
                len: read as u64,
                digest,
            };
            offset += read as u64;
            result.push(SnapshotChunkPayload { chunk, ciphertext });
            chunk_index += 1;
        }
        Ok(result)
    }

    fn encrypt_chunk(
        &self,
        manifest_id: &str,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SnapshotCryptoError> {
        let mut buffer = plaintext.to_vec();
        let aad = build_chunk_aad(manifest_id, chunk_index, plaintext.len() as u64);
        let nonce = derive_chunk_nonce(self.dek_epoch, &self.iv_salt, chunk_index);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce_ref(&nonce), &aad, &mut buffer)
            .map_err(|_| SnapshotCryptoError::Encrypt)?;
        let tag: [u8; 16] = tag.into();
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }
}

#[derive(Debug, Error)]
pub enum SnapshotExportError {
    #[error("chunk size must be non-zero")]
    InvalidChunkSize,
    #[error("chunk size {requested} exceeds limit {limit}")]
    ChunkSizeExceeded { requested: u64, limit: u64 },
    #[error("chunk count exceeds limit {limit}")]
    ChunkCountExceeded { limit: usize },
    #[error("total bytes exceed profile cap")]
    TotalBytesExceeded,
    #[error("encryption failure")]
    Encrypt,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum SnapshotCryptoError {
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
}

fn derive_chunk_nonce(dek_epoch: u32, iv_salt: &str, chunk_idx: u64) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(dek_epoch.to_be_bytes());
    hasher.update(iv_salt.as_bytes());
    hasher.update(chunk_idx.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

fn chunk_index_from_id(chunk_id: &str) -> Option<u64> {
    chunk_id
        .rsplit_once('-')
        .and_then(|(_, idx)| idx.parse::<u64>().ok())
}

fn build_chunk_aad(manifest_id: &str, chunk_idx: u64, len: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(manifest_id.len() + 16);
    aad.extend_from_slice(manifest_id.as_bytes());
    aad.extend_from_slice(&chunk_idx.to_be_bytes());
    aad.extend_from_slice(&len.to_be_bytes());
    aad
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
