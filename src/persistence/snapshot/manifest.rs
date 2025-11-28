use crate::storage::{
    authorization_chain_hash, ManifestAuthorizationLog, ManifestLogError,
    SnapshotAuthorizationRecord,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct SnapshotManifestBuilder {
    manifest: SnapshotManifest,
}

impl SnapshotManifestBuilder {
    pub fn new(manifest_id: impl Into<String>) -> Self {
        Self {
            manifest: SnapshotManifest {
                manifest_id: manifest_id.into(),
                version_id: 0,
                producer_version: String::new(),
                emit_version: String::new(),
                base_term: 0,
                base_index: 0,
                chunks: Vec::new(),
                logical_markers: Vec::new(),
                encryption: ManifestEncryption {
                    dek_epoch: 0,
                    iv_salt: String::new(),
                },
                snapshot_kind: SnapshotKind::Full,
                delta_parent_manifest_id: None,
                delta_chain_length: 0,
                ap_pane_digest: None,
                dedup_shards: Vec::new(),
                commit_epoch_vector: Vec::new(),
                content_hash: None,
            },
        }
    }

    pub fn version_id(mut self, version_id: u64) -> Self {
        self.manifest.version_id = version_id;
        self
    }

    pub fn producer(mut self, producer: impl Into<String>, emit: impl Into<String>) -> Self {
        self.manifest.producer_version = producer.into();
        self.manifest.emit_version = emit.into();
        self
    }

    pub fn base(mut self, term: u64, index: u64) -> Self {
        self.manifest.base_term = term;
        self.manifest.base_index = index;
        self
    }

    pub fn encryption(mut self, dek_epoch: u32, iv_salt: impl Into<String>) -> Self {
        self.manifest.encryption = ManifestEncryption {
            dek_epoch,
            iv_salt: iv_salt.into(),
        };
        self
    }

    pub fn add_chunk(mut self, chunk: SnapshotChunk) -> Self {
        self.manifest.chunks.push(chunk);
        self
    }

    pub fn add_marker(mut self, marker: impl Into<String>) -> Self {
        self.manifest.logical_markers.push(marker.into());
        self
    }

    pub fn snapshot_kind(mut self, kind: SnapshotKind) -> Self {
        self.manifest.snapshot_kind = kind;
        self
    }

    pub fn delta_parent(
        mut self,
        parent_manifest_id: impl Into<String>,
        chain_length: u32,
    ) -> Self {
        self.manifest.delta_parent_manifest_id = Some(parent_manifest_id.into());
        self.manifest.delta_chain_length = chain_length;
        self
    }

    pub fn ap_pane_digest(mut self, digest: impl Into<String>) -> Self {
        self.manifest.ap_pane_digest = Some(digest.into());
        self
    }

    pub fn add_dedup_shard(mut self, shard: DedupShardDigest) -> Self {
        self.manifest.dedup_shards.push(shard);
        self
    }

    pub fn add_commit_epoch(mut self, entry: CommitEpochEntry) -> Self {
        self.manifest.commit_epoch_vector.push(entry);
        self
    }

    pub fn finalize<S: ManifestSigner>(
        mut self,
        signer: &S,
    ) -> Result<SignedSnapshotManifest, ManifestError> {
        self.manifest.chunks.sort_by_key(|chunk| chunk.offset);
        self.manifest
            .dedup_shards
            .sort_by(|a, b| a.shard_id.cmp(&b.shard_id));
        self.manifest
            .commit_epoch_vector
            .sort_by(|a, b| a.dimension.cmp(&b.dimension));
        let canonical_without_signature = canonicalize_without_signature(&self.manifest)?;
        let hash = compute_hash(&canonical_without_signature);
        self.manifest.content_hash = Some(hash.clone());
        let canonical = canonicalize_without_signature(&self.manifest)?;
        let signature = signer.sign(&canonical)?;
        Ok(SignedSnapshotManifest {
            manifest: self.manifest,
            signature,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunk {
    pub chunk_id: String,
    pub offset: u64,
    pub len: u64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEncryption {
    pub dek_epoch: u32,
    pub iv_salt: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotKind {
    Full,
    Delta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DedupShardDigest {
    pub shard_id: String,
    pub ledger_epoch: u64,
    pub shard_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitEpochEntry {
    pub dimension: String,
    pub epoch: u64,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub manifest_id: String,
    pub version_id: u64,
    pub producer_version: String,
    pub emit_version: String,
    pub base_term: u64,
    pub base_index: u64,
    pub chunks: Vec<SnapshotChunk>,
    pub logical_markers: Vec<String>,
    pub encryption: ManifestEncryption,
    pub snapshot_kind: SnapshotKind,
    pub delta_parent_manifest_id: Option<String>,
    pub delta_chain_length: u32,
    pub ap_pane_digest: Option<String>,
    pub dedup_shards: Vec<DedupShardDigest>,
    pub commit_epoch_vector: Vec<CommitEpochEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SignedSnapshotManifest {
    pub manifest: SnapshotManifest,
    pub signature: ManifestSignature,
}

impl SignedSnapshotManifest {
    pub fn canonical_json(&self) -> Result<Vec<u8>, ManifestError> {
        let mut value = serde_json::to_value(&self.manifest)?;
        if let serde_json::Value::Object(ref mut obj) = value {
            obj.insert("signature".into(), serde_json::to_value(&self.signature)?);
        }
        canonicalize_value(&value)
    }
}

#[derive(Debug, Clone)]
pub struct ManifestVerification {
    pub manifest_id: String,
    pub version_id: u64,
    pub cache_hit: bool,
}

pub struct SnapshotManifestVerifier<S: ManifestSigner> {
    signer: S,
    min_version: u64,
    max_version: u64,
    cache: SnapshotTrustCache,
}

impl<S: ManifestSigner> SnapshotManifestVerifier<S> {
    pub fn new(signer: S, min_version: u64, max_version: u64, cache_ttl: Duration) -> Self {
        assert!(
            min_version <= max_version,
            "manifest version window invalid"
        );
        Self {
            signer,
            min_version,
            max_version,
            cache: SnapshotTrustCache::new(cache_ttl),
        }
    }

    pub fn verify(
        &mut self,
        signed: &SignedSnapshotManifest,
        now: Instant,
    ) -> Result<ManifestVerification, ManifestVerificationError> {
        if signed.manifest.version_id < self.min_version
            || signed.manifest.version_id > self.max_version
        {
            return Err(ManifestVerificationError::VersionOutOfRange {
                version_id: signed.manifest.version_id,
                min: self.min_version,
                max: self.max_version,
            });
        }

        let manifest_id = signed.manifest.manifest_id.clone();
        if self.cache.is_trusted(&manifest_id, now) {
            return Ok(ManifestVerification {
                manifest_id,
                version_id: signed.manifest.version_id,
                cache_hit: true,
            });
        }

        let canonical = canonicalize_without_signature(&signed.manifest)?;
        if !self.signer.verify(&canonical, &signed.signature) {
            return Err(ManifestVerificationError::SignatureInvalid {
                manifest_id: signed.manifest.manifest_id.clone(),
            });
        }

        self.cache.insert(&signed.manifest.manifest_id, now);
        Ok(ManifestVerification {
            manifest_id: signed.manifest.manifest_id.clone(),
            version_id: signed.manifest.version_id,
            cache_hit: false,
        })
    }
}

#[derive(Debug, Error)]
pub enum ManifestVerificationError {
    #[error("manifest version {version_id} outside allowed window [{min}, {max}]")]
    VersionOutOfRange { version_id: u64, min: u64, max: u64 },
    #[error("manifest signature invalid for {manifest_id}")]
    SignatureInvalid { manifest_id: String },
    #[error(transparent)]
    Manifest(#[from] ManifestError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSignature {
    pub algorithm: String,
    pub value: String,
}

pub trait ManifestSigner {
    fn algorithm(&self) -> &'static str;
    fn sign(&self, payload: &[u8]) -> Result<ManifestSignature, ManifestError>;
    fn verify(&self, payload: &[u8], signature: &ManifestSignature) -> bool;
}

#[derive(Debug, Clone)]
pub struct HmacManifestSigner {
    key: Vec<u8>,
}

impl HmacManifestSigner {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self {
            key: key.as_ref().to_vec(),
        }
    }
}

impl ManifestSigner for HmacManifestSigner {
    fn algorithm(&self) -> &'static str {
        "HMAC-SHA256"
    }

    fn sign(&self, payload: &[u8]) -> Result<ManifestSignature, ManifestError> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.key).map_err(|_| ManifestError::Signer)?;
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        Ok(ManifestSignature {
            algorithm: self.algorithm().to_string(),
            value: hex::encode(result),
        })
    }

    fn verify(&self, payload: &[u8], signature: &ManifestSignature) -> bool {
        if signature.algorithm != self.algorithm() {
            return false;
        }
        if let Ok(expected) = hex::decode(&signature.value) {
            let mut mac = match <HmacSha256 as Mac>::new_from_slice(&self.key)
                .map_err(|_| ManifestError::Signer)
            {
                Ok(mac) => mac,
                Err(_) => return false,
            };
            mac.update(payload);
            mac.verify_slice(&expected).is_ok()
        } else {
            false
        }
    }
}

pub(crate) fn compute_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("0x{}", hex::encode(digest))
}

pub(super) fn canonicalize_without_signature(
    manifest: &SnapshotManifest,
) -> Result<Vec<u8>, ManifestError> {
    let mut value = serde_json::to_value(manifest)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }
    canonicalize_value(&value)
}

fn canonicalize_value(value: &serde_json::Value) -> Result<Vec<u8>, ManifestError> {
    fn sort(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    new_map.insert(key.clone(), sort(&map[key]));
                }
                serde_json::Value::Object(new_map)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    let sorted = sort(value);
    serde_json::to_vec(&sorted).map_err(ManifestError::from)
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("signer error")]
    Signer,
}

pub struct SnapshotAuthorizer {
    log: ManifestAuthorizationLog,
}

impl SnapshotAuthorizer {
    pub fn new(log: ManifestAuthorizationLog) -> Self {
        Self { log }
    }

    pub fn authorize(
        &self,
        manifest_path: &Path,
        signed: &SignedSnapshotManifest,
        auth_seq: u64,
        recorded_at_ms: u64,
    ) -> Result<SnapshotAuthorizationRecord, SnapshotAuthorizationError> {
        let manifest_hash = signed
            .manifest
            .content_hash
            .clone()
            .ok_or(SnapshotAuthorizationError::MissingHash)?;
        let previous = self.log.latest()?;
        let metadata = fs::metadata(manifest_path)?;
        if !metadata.is_file() {
            return Err(SnapshotAuthorizationError::NotAFile);
        }
        let file = fs::OpenOptions::new().read(true).open(manifest_path)?;
        file.sync_all()?;
        drop(file);
        let prev_chain = previous.as_ref().map(|record| record.chain_hash.as_str());
        let record = SnapshotAuthorizationRecord {
            manifest_id: signed.manifest.manifest_id.clone(),
            base_index: signed.manifest.base_index,
            auth_seq,
            manifest_hash: manifest_hash.clone(),
            recorded_at_ms,
            chain_hash: authorization_chain_hash(
                prev_chain,
                &signed.manifest.manifest_id,
                auth_seq,
                &manifest_hash,
            ),
        };
        self.log.append(&record)?;
        Ok(record)
    }
}

#[derive(Debug, Error)]
pub enum SnapshotAuthorizationError {
    #[error("manifest missing content hash")]
    MissingHash,
    #[error("manifest path is not a file")]
    NotAFile,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Log(#[from] ManifestLogError),
}

#[derive(Debug, Clone)]
pub struct SnapshotDeltaPolicy {
    profile_allows: bool,
    cp_gate_enabled: bool,
    delta_chain_max: u32,
    delta_emit_period_ms: u64,
    full_emit_period_ms: u64,
    last_full_snapshot_ms: Option<u64>,
    last_snapshot_ms: Option<u64>,
    current_chain_length: u32,
    last_manifest_id: Option<String>,
    chain_state: SnapshotDeltaChainState,
}

impl SnapshotDeltaPolicy {
    pub fn new(delta_chain_max: u32, delta_emit_period_ms: u64, full_emit_period_ms: u64) -> Self {
        Self {
            profile_allows: false,
            cp_gate_enabled: false,
            delta_chain_max,
            delta_emit_period_ms,
            full_emit_period_ms,
            last_full_snapshot_ms: None,
            last_snapshot_ms: None,
            current_chain_length: 0,
            last_manifest_id: None,
            chain_state: SnapshotDeltaChainState::Idle,
        }
    }

    pub fn set_profile_capability(&mut self, allowed: bool) {
        self.profile_allows = allowed;
    }

    pub fn set_cp_gate(&mut self, enabled: bool) {
        self.cp_gate_enabled = enabled;
    }

    pub fn record_manifest(
        &mut self,
        manifest: &SnapshotManifest,
        emitted_at_ms: u64,
    ) -> Result<(), SnapshotDeltaPolicyError> {
        match manifest.snapshot_kind {
            SnapshotKind::Full => {
                if manifest.delta_parent_manifest_id.is_some() {
                    return Err(SnapshotDeltaPolicyError::FullSnapshotHasParent);
                }
                if manifest.delta_chain_length != 0 {
                    return Err(
                        SnapshotDeltaPolicyError::FullSnapshotUnexpectedChainLength {
                            observed: manifest.delta_chain_length,
                        },
                    );
                }
                self.last_full_snapshot_ms = Some(emitted_at_ms);
                self.last_snapshot_ms = Some(emitted_at_ms);
                self.current_chain_length = 0;
                self.last_manifest_id = Some(manifest.manifest_id.clone());
                self.chain_state = SnapshotDeltaChainState::Idle;
                Ok(())
            }
            SnapshotKind::Delta => {
                if !self.profile_allows || !self.cp_gate_enabled || self.delta_chain_max == 0 {
                    self.chain_state = SnapshotDeltaChainState::Orphaned;
                    return Err(SnapshotDeltaPolicyError::DeltaDisabled);
                }
                if self.current_chain_length >= self.delta_chain_max {
                    self.chain_state = SnapshotDeltaChainState::Orphaned;
                    return Err(SnapshotDeltaPolicyError::DeltaChainExceeded {
                        max: self.delta_chain_max,
                    });
                }
                if let Some(last_delta) = self.last_snapshot_ms {
                    if emitted_at_ms.saturating_sub(last_delta) > self.delta_emit_period_ms {
                        self.chain_state = SnapshotDeltaChainState::Orphaned;
                        return Err(SnapshotDeltaPolicyError::DeltaEmitWindowExceeded);
                    }
                }
                if let Some(last_full) = self.last_full_snapshot_ms {
                    if emitted_at_ms.saturating_sub(last_full) > self.full_emit_period_ms {
                        self.chain_state = SnapshotDeltaChainState::Orphaned;
                        return Err(SnapshotDeltaPolicyError::FullSnapshotWindowExceeded);
                    }
                } else {
                    self.chain_state = SnapshotDeltaChainState::Orphaned;
                    return Err(SnapshotDeltaPolicyError::FullSnapshotUnknown);
                }
                let expected_parent = self
                    .last_manifest_id
                    .clone()
                    .ok_or(SnapshotDeltaPolicyError::DeltaParentMissing)?;
                let observed_parent = manifest
                    .delta_parent_manifest_id
                    .clone()
                    .ok_or(SnapshotDeltaPolicyError::DeltaParentMissing)?;
                if observed_parent != expected_parent {
                    self.chain_state = SnapshotDeltaChainState::Orphaned;
                    return Err(SnapshotDeltaPolicyError::DeltaParentMismatch {
                        expected: expected_parent,
                        observed: observed_parent,
                    });
                }
                let expected_length = self.current_chain_length + 1;
                if manifest.delta_chain_length != expected_length {
                    self.chain_state = SnapshotDeltaChainState::Orphaned;
                    return Err(SnapshotDeltaPolicyError::DeltaChainLengthMismatch {
                        expected: expected_length,
                        observed: manifest.delta_chain_length,
                    });
                }
                self.current_chain_length = manifest.delta_chain_length;
                self.last_snapshot_ms = Some(emitted_at_ms);
                self.last_manifest_id = Some(manifest.manifest_id.clone());
                self.chain_state = SnapshotDeltaChainState::Building;
                Ok(())
            }
        }
    }

    pub fn telemetry(&self) -> SnapshotDeltaChainTelemetry {
        SnapshotDeltaChainTelemetry {
            state: self.chain_state,
            chain_length: self.current_chain_length,
            last_manifest_id: self.last_manifest_id.clone(),
            last_full_snapshot_ms: self.last_full_snapshot_ms,
            last_snapshot_ms: self.last_snapshot_ms,
        }
    }

    pub fn mark_orphaned(&mut self) {
        self.chain_state = SnapshotDeltaChainState::Orphaned;
    }

    pub fn current_chain_length(&self) -> u32 {
        self.current_chain_length
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnapshotDeltaPolicyError {
    #[error("incremental snapshots disabled for this profile or gate")]
    DeltaDisabled,
    #[error("delta chain exceeded max length {max}")]
    DeltaChainExceeded { max: u32 },
    #[error("delta emit window exceeded")]
    DeltaEmitWindowExceeded,
    #[error("full snapshot emit window exceeded")]
    FullSnapshotWindowExceeded,
    #[error("full snapshot reference unknown")]
    FullSnapshotUnknown,
    #[error("full snapshot unexpectedly declared parent manifest")]
    FullSnapshotHasParent,
    #[error("full snapshot reported non-zero delta_chain_length {observed}")]
    FullSnapshotUnexpectedChainLength { observed: u32 },
    #[error("delta manifest missing parent reference")]
    DeltaParentMissing,
    #[error("delta manifest parent mismatch: expected {expected}, observed {observed}")]
    DeltaParentMismatch { expected: String, observed: String },
    #[error("delta manifest chain length mismatch: expected {expected}, observed {observed}")]
    DeltaChainLengthMismatch { expected: u32, observed: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SnapshotDeltaChainState {
    Idle,
    Building,
    Orphaned,
}

impl SnapshotDeltaChainState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SnapshotDeltaChainState::Idle => "Idle",
            SnapshotDeltaChainState::Building => "Building",
            SnapshotDeltaChainState::Orphaned => "Orphaned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotDeltaChainTelemetry {
    pub state: SnapshotDeltaChainState,
    pub chain_length: u32,
    pub last_manifest_id: Option<String>,
    pub last_full_snapshot_ms: Option<u64>,
    pub last_snapshot_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SnapshotImportValidator {
    cp_commit_epochs: HashMap<String, u64>,
}

impl SnapshotImportValidator {
    pub fn new(cp_commit_epochs: HashMap<String, u64>) -> Self {
        Self { cp_commit_epochs }
    }

    pub fn validate_manifest(
        &self,
        manifest: &SnapshotManifest,
    ) -> Result<(), SnapshotImportValidationError> {
        if manifest
            .ap_pane_digest
            .as_deref()
            .is_none_or(|digest| digest.is_empty())
        {
            return Err(SnapshotImportValidationError::MissingApPaneDigest);
        }
        if manifest.dedup_shards.is_empty() {
            return Err(SnapshotImportValidationError::MissingDedupShards);
        }
        if manifest.commit_epoch_vector.is_empty() {
            return Err(SnapshotImportValidationError::MissingCommitEpochVector);
        }
        self.validate_commit_epochs(manifest)?;
        Ok(())
    }

    fn validate_commit_epochs(
        &self,
        manifest: &SnapshotManifest,
    ) -> Result<(), SnapshotImportValidationError> {
        for entry in &manifest.commit_epoch_vector {
            let expected = self.cp_commit_epochs.get(&entry.dimension).ok_or_else(|| {
                SnapshotImportValidationError::CommitEpochMissing {
                    dimension: entry.dimension.clone(),
                }
            })?;
            if expected != &entry.epoch {
                return Err(SnapshotImportValidationError::CommitEpochMismatch {
                    dimension: entry.dimension.clone(),
                    expected: *expected,
                    observed: entry.epoch,
                });
            }
        }
        Ok(())
    }

    pub fn validate_and_record(
        &self,
        manifest: &SnapshotManifest,
        emitted_at_ms: u64,
        policy: &mut SnapshotDeltaPolicy,
    ) -> Result<(), SnapshotImportValidationError> {
        self.validate_manifest(manifest)?;
        policy
            .record_manifest(manifest, emitted_at_ms)
            .map_err(SnapshotImportValidationError::DeltaPolicy)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnapshotImportValidationError {
    #[error("ap pane digest missing from manifest")]
    MissingApPaneDigest,
    #[error("dedup shard digests missing from manifest")]
    MissingDedupShards,
    #[error("commit epoch vector missing from manifest")]
    MissingCommitEpochVector,
    #[error(
        "commit epoch mismatch for dimension {dimension}: expected {expected}, observed {observed}"
    )]
    CommitEpochMismatch {
        dimension: String,
        expected: u64,
        observed: u64,
    },
    #[error("commit epoch missing for dimension {dimension}")]
    CommitEpochMissing { dimension: String },
    #[error(transparent)]
    DeltaPolicy(#[from] SnapshotDeltaPolicyError),
}

struct SnapshotTrustCache {
    ttl: Duration,
    entries: HashMap<String, Instant>,
}

impl SnapshotTrustCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: HashMap::new(),
        }
    }

    fn is_trusted(&mut self, manifest_id: &str, now: Instant) -> bool {
        self.evict(now);
        if let Some(expiry) = self.entries.get_mut(manifest_id) {
            if *expiry > now {
                if !self.ttl.is_zero() {
                    *expiry = now.checked_add(self.ttl).unwrap_or(*expiry);
                }
                return true;
            }
        }
        false
    }

    fn insert(&mut self, manifest_id: &str, now: Instant) {
        if self.ttl.is_zero() {
            return;
        }
        let expiry = now.checked_add(self.ttl).unwrap_or(now);
        self.entries.insert(manifest_id.to_string(), expiry);
    }

    fn evict(&mut self, now: Instant) {
        self.entries.retain(|_, expiry| *expiry > now);
    }
}
