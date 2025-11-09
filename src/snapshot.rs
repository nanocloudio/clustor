use crate::consensus::StrictFallbackState;
use crate::storage::{
    DataEncryptionKey, ManifestAuthorizationLog, ManifestLogError, SnapshotAuthorizationRecord,
};
#[allow(deprecated)]
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use hmac::{Hmac, Mac};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

const SNAPSHOT_EXPORT_SPEC: &str = "§5.2.SnapshotExport";
const SNAPSHOT_THROTTLE_SPEC: &str = "§7.1.SnapshotThrottle";
const SNAPSHOT_ONLY_SPEC: &str = "§8.SnapshotOnly";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SnapshotExportTelemetry {
    pub chunk_rate_bytes_per_sec: u64,
    pub backlog_bytes: u64,
}

#[derive(Debug)]
pub struct SnapshotExportController {
    max_inflight_bytes: usize,
    rate_limit_bytes_per_sec: u64,
    backlog_bytes: usize,
    window_start: Option<Instant>,
    window_bytes: u64,
    last_rate: u64,
    last_state: SnapshotThrottleState,
}

pub struct SnapshotChunkImporter {
    cipher: Aes256Gcm,
    dek_epoch: u32,
    iv_salt: String,
}

impl SnapshotChunkImporter {
    pub fn new(key: &DataEncryptionKey, iv_salt: impl Into<String>) -> Self {
        Self {
            cipher: Aes256Gcm::new(key_ref(&key.bytes)),
            dek_epoch: key.epoch,
            iv_salt: iv_salt.into(),
        }
    }

    pub fn import_chunk(
        &self,
        manifest_id: &str,
        payload: &SnapshotChunkPayload,
    ) -> Result<Vec<u8>, SnapshotImportError> {
        if compute_hash(&payload.ciphertext) != payload.chunk.digest {
            return Err(SnapshotImportError::DigestMismatch {
                chunk_id: payload.chunk.chunk_id.clone(),
            });
        }
        let chunk_index = chunk_index_from_id(&payload.chunk.chunk_id).ok_or_else(|| {
            SnapshotImportError::Decrypt {
                chunk_id: payload.chunk.chunk_id.clone(),
            }
        })?;
        let mut ciphertext = payload.ciphertext.clone();
        if ciphertext.len() < 16 {
            return Err(SnapshotImportError::Decrypt {
                chunk_id: payload.chunk.chunk_id.clone(),
            });
        }
        let tag_split = ciphertext.len() - 16;
        let (body, tag) = ciphertext.split_at_mut(tag_split);
        let mut plaintext = body.to_vec();
        self.cipher
            .decrypt_in_place_detached(
                nonce_ref(&derive_chunk_nonce(
                    self.dek_epoch,
                    &self.iv_salt,
                    chunk_index,
                )),
                &build_chunk_aad(manifest_id, chunk_index, payload.chunk.len),
                &mut plaintext,
                tag_ref(tag),
            )
            .map_err(|_| SnapshotImportError::Decrypt {
                chunk_id: payload.chunk.chunk_id.clone(),
            })?;
        Ok(plaintext)
    }
}

#[derive(Debug, Clone)]
pub struct StagedChunk {
    pub chunk_id: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SnapshotStagingStore {
    chunks: Vec<StagedChunk>,
    total_bytes: usize,
}

impl SnapshotStagingStore {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            total_bytes: 0,
        }
    }

    pub fn stage(&mut self, chunk_id: impl Into<String>, bytes: Vec<u8>) {
        self.total_bytes = self.total_bytes.saturating_add(bytes.len());
        self.chunks.push(StagedChunk {
            chunk_id: chunk_id.into(),
            bytes,
        });
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn chunks(&self) -> &[StagedChunk] {
        &self.chunks
    }
}

impl SnapshotExportController {
    pub fn new(max_inflight_bytes: usize, rate_limit_bytes_per_sec: u64) -> Self {
        Self {
            max_inflight_bytes,
            rate_limit_bytes_per_sec,
            backlog_bytes: 0,
            window_start: None,
            window_bytes: 0,
            last_rate: 0,
            last_state: SnapshotThrottleState::Open,
        }
    }

    pub fn enqueue(&mut self, chunk_bytes: usize, now: Instant) -> SnapshotThrottleEnvelope {
        self.backlog_bytes = self.backlog_bytes.saturating_add(chunk_bytes);
        self.record_rate(chunk_bytes as u64, now);
        let envelope = self.envelope();
        self.log_envelope(&envelope, "enqueue");
        envelope
    }

    pub fn complete(&mut self, chunk_bytes: usize) {
        self.backlog_bytes = self.backlog_bytes.saturating_sub(chunk_bytes);
        let envelope = self.envelope();
        self.log_envelope(&envelope, "complete");
    }

    pub fn telemetry(&self) -> SnapshotExportTelemetry {
        SnapshotExportTelemetry {
            chunk_rate_bytes_per_sec: self.last_rate,
            backlog_bytes: self.backlog_bytes as u64,
        }
    }

    fn record_rate(&mut self, bytes: u64, now: Instant) {
        match self.window_start {
            Some(start) if now.duration_since(start) < Duration::from_secs(1) => {}
            _ => {
                self.window_start = Some(now);
                self.window_bytes = 0;
            }
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        if self.rate_limit_bytes_per_sec == 0 {
            self.last_rate = self.window_bytes;
        } else {
            self.last_rate = self.window_bytes.min(self.rate_limit_bytes_per_sec);
        }
    }

    fn envelope(&self) -> SnapshotThrottleEnvelope {
        if self.backlog_bytes >= self.max_inflight_bytes {
            SnapshotThrottleEnvelope {
                state: SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes {
                    buffered: self.backlog_bytes,
                    limit: self.max_inflight_bytes,
                }),
                buffered_bytes: self.backlog_bytes,
            }
        } else if self.rate_limit_bytes_per_sec > 0
            && self.window_bytes > self.rate_limit_bytes_per_sec
        {
            SnapshotThrottleEnvelope {
                state: SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit {
                    observed_bps: self.window_bytes,
                    limit_bps: self.rate_limit_bytes_per_sec,
                }),
                buffered_bytes: self.backlog_bytes,
            }
        } else {
            SnapshotThrottleEnvelope {
                state: SnapshotThrottleState::Open,
                buffered_bytes: self.backlog_bytes,
            }
        }
    }

    fn log_envelope(&mut self, envelope: &SnapshotThrottleEnvelope, phase: &str) {
        if self.last_state == envelope.state {
            return;
        }
        match &envelope.state {
            SnapshotThrottleState::Open => info!(
                "event=snapshot_throttle_open clause={} phase={} buffered_bytes={}",
                SNAPSHOT_THROTTLE_SPEC, phase, envelope.buffered_bytes
            ),
            SnapshotThrottleState::Throttled(reason) => warn!(
                "event=snapshot_throttle clause={} phase={} reason={:?} buffered_bytes={}",
                SNAPSHOT_THROTTLE_SPEC, phase, reason, envelope.buffered_bytes
            ),
        }
        self.last_state = envelope.state.clone();
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotReadiness {
    pub manifest_id: String,
    pub base_index: u64,
    pub content_hash: String,
    pub applied_index_snapshot: u64,
    pub last_advertised_ready_index: u64,
    pub manifest_generated_ms: u64,
}

impl SnapshotReadiness {
    pub fn readiness_ratio(&self) -> f64 {
        if self.last_advertised_ready_index == 0 {
            return 0.0;
        }
        let ratio = self.applied_index_snapshot as f64 / self.last_advertised_ready_index as f64;
        ratio.clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotReadRequest {
    pub partition_id: String,
    pub read_semantics_snapshot_only: bool,
    pub strict_state: StrictFallbackState,
    pub cp_cache_age_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SnapshotReadResponse {
    pub manifest_id: String,
    pub base_index: u64,
    pub content_hash: String,
    pub applied_index: u64,
    pub readiness_ratio: f64,
    pub headers: SnapshotReadHeaders,
}

#[derive(Debug, Clone)]
pub struct SnapshotReadHeaders {
    pub snapshot_only: bool,
    pub snapshot_manifest_id: String,
    pub cp_cache_age_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SnapshotReadError {
    MissingSnapshotOnlyHeader,
    StrictStateUnavailable { state: StrictFallbackState },
    SnapshotOnlyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SnapshotOnlyReadyState {
    Healthy,
    Degraded,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotFallbackTelemetry {
    pub partition_ready_ratio_snapshot: f64,
    pub snapshot_manifest_age_ms: u64,
    pub snapshot_only_ready_state: SnapshotOnlyReadyState,
    pub snapshot_only_min_ready_ratio: f64,
    pub snapshot_only_slo_breach_total: u64,
}

#[derive(Debug, Clone)]
pub struct SnapshotFallbackController {
    readiness: SnapshotReadiness,
    min_ready_ratio: f64,
    slo_tracker: SnapshotSloTracker,
}

impl SnapshotFallbackController {
    pub const SNAPSHOT_ONLY_MIN_READY_RATIO: f64 = 0.80;

    pub fn new(readiness: SnapshotReadiness) -> Self {
        Self {
            readiness,
            min_ready_ratio: Self::SNAPSHOT_ONLY_MIN_READY_RATIO,
            slo_tracker: SnapshotSloTracker::new(400, 300_000),
        }
    }

    pub fn with_min_ready_ratio(mut self, ratio: f64) -> Self {
        self.min_ready_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn readiness(&self) -> &SnapshotReadiness {
        &self.readiness
    }

    pub fn update_readiness(&mut self, readiness: SnapshotReadiness) {
        self.readiness = readiness;
    }

    pub fn handle_request(
        &self,
        request: SnapshotReadRequest,
    ) -> Result<SnapshotReadResponse, SnapshotReadError> {
        if !request.read_semantics_snapshot_only {
            warn!(
                "event=snapshot_read_reject clause={} partition_id={} reason=missing_snapshot_only_header strict_state={:?}",
                SNAPSHOT_ONLY_SPEC,
                request.partition_id,
                request.strict_state
            );
            return Err(SnapshotReadError::MissingSnapshotOnlyHeader);
        }
        match request.strict_state {
            StrictFallbackState::LocalOnly | StrictFallbackState::ProofPublished => {}
            other => {
                warn!(
                    "event=snapshot_read_reject clause={} partition_id={} reason=strict_state_unavailable strict_state={:?}",
                    SNAPSHOT_ONLY_SPEC,
                    request.partition_id,
                    other
                );
                return Err(SnapshotReadError::StrictStateUnavailable { state: other });
            }
        }
        let ratio = self.readiness_ratio();
        if ratio + f64::EPSILON < self.min_ready_ratio {
            warn!(
                "event=snapshot_read_reject clause={} partition_id={} reason=readiness_ratio readiness_ratio={:.3} min_ready_ratio={} strict_state={:?}",
                SNAPSHOT_ONLY_SPEC,
                request.partition_id,
                ratio,
                self.min_ready_ratio,
                request.strict_state
            );
            return Err(SnapshotReadError::SnapshotOnlyUnavailable);
        }
        info!(
            "event=snapshot_read_grant clause={} partition_id={} readiness_ratio={:.3} min_ready_ratio={} strict_state={:?} cp_cache_age_ms={}",
            SNAPSHOT_ONLY_SPEC,
            request.partition_id,
            ratio,
            self.min_ready_ratio,
            request.strict_state,
            request.cp_cache_age_ms
        );
        Ok(SnapshotReadResponse {
            manifest_id: self.readiness.manifest_id.clone(),
            base_index: self.readiness.base_index,
            content_hash: self.readiness.content_hash.clone(),
            applied_index: self.readiness.applied_index_snapshot,
            readiness_ratio: ratio,
            headers: SnapshotReadHeaders {
                snapshot_only: true,
                snapshot_manifest_id: self.readiness.manifest_id.clone(),
                cp_cache_age_ms: request.cp_cache_age_ms,
            },
        })
    }

    pub fn telemetry(&self, now_ms: u64) -> SnapshotFallbackTelemetry {
        SnapshotFallbackTelemetry {
            partition_ready_ratio_snapshot: self.readiness_ratio(),
            snapshot_manifest_age_ms: now_ms.saturating_sub(self.readiness.manifest_generated_ms),
            snapshot_only_ready_state: self.ready_state(),
            snapshot_only_min_ready_ratio: self.min_ready_ratio,
            snapshot_only_slo_breach_total: self.slo_tracker.breaches(),
        }
    }

    pub fn record_snapshot_only_result(&mut self, latency_ms: u64, success: bool, now_ms: u64) {
        self.slo_tracker.record(latency_ms, success, now_ms);
    }

    fn readiness_ratio(&self) -> f64 {
        self.readiness.readiness_ratio()
    }

    fn ready_state(&self) -> SnapshotOnlyReadyState {
        let ratio = self.readiness_ratio();
        if ratio + f64::EPSILON < self.min_ready_ratio {
            if ratio <= f64::EPSILON {
                SnapshotOnlyReadyState::Expired
            } else {
                SnapshotOnlyReadyState::Degraded
            }
        } else {
            SnapshotOnlyReadyState::Healthy
        }
    }
}

#[derive(Debug, Clone)]
struct SnapshotSloTracker {
    window_start_ms: u64,
    window_total: u64,
    window_success: u64,
    latency_breach: bool,
    slo_latency_budget_ms: u64,
    slo_window_ms: u64,
    breaches: u64,
}

impl SnapshotSloTracker {
    fn new(latency_budget_ms: u64, window_ms: u64) -> Self {
        Self {
            window_start_ms: 0,
            window_total: 0,
            window_success: 0,
            latency_breach: false,
            slo_latency_budget_ms: latency_budget_ms,
            slo_window_ms: window_ms,
            breaches: 0,
        }
    }

    fn record(&mut self, latency_ms: u64, success: bool, now_ms: u64) {
        if self.window_start_ms == 0 {
            self.window_start_ms = now_ms;
        }
        if now_ms.saturating_sub(self.window_start_ms) > self.slo_window_ms {
            self.reset_window(now_ms);
        }
        self.window_total = self.window_total.saturating_add(1);
        if success {
            self.window_success = self.window_success.saturating_add(1);
        }
        if latency_ms > self.slo_latency_budget_ms {
            self.latency_breach = true;
        }
        let success_ratio = if self.window_total == 0 {
            1.0
        } else {
            self.window_success as f64 / self.window_total as f64
        };
        if success_ratio < 0.995 || self.latency_breach {
            self.breaches = self.breaches.saturating_add(1);
            self.reset_window(now_ms);
        }
    }

    fn reset_window(&mut self, now_ms: u64) {
        self.window_start_ms = now_ms;
        self.window_total = 0;
        self.window_success = 0;
        self.latency_breach = false;
    }

    fn breaches(&self) -> u64 {
        self.breaches
    }
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
        let caps = profile.caps();
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
            SNAPSHOT_EXPORT_SPEC,
            manifest_id,
            chunk_bytes,
            self.caps.max_chunk_bytes,
            self.caps.max_chunks,
            self.caps.max_total_bytes
        );
        if chunk_bytes == 0 {
            warn!(
                "event=snapshot_export_block clause={} manifest_id={} reason=invalid_chunk_size",
                SNAPSHOT_EXPORT_SPEC, manifest_id
            );
            return Err(SnapshotExportError::InvalidChunkSize);
        }
        if chunk_bytes as u64 > self.caps.max_chunk_bytes {
            warn!(
                "event=snapshot_export_block clause={} manifest_id={} reason=chunk_size_exceeded requested={} limit={}",
                SNAPSHOT_EXPORT_SPEC,
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
                    SNAPSHOT_EXPORT_SPEC,
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
                    SNAPSHOT_EXPORT_SPEC,
                    manifest_id,
                    total,
                    self.caps.max_total_bytes
                );
                return Err(SnapshotExportError::TotalBytesExceeded);
            }
            let plaintext = &buffer[..read];
            let ciphertext = self
                .encrypt_chunk(manifest_id, chunk_index, plaintext)
                .map_err(|err| {
                    warn!(
                        "event=snapshot_export_block clause={} manifest_id={} reason=encrypt_failure chunk_index={} error={:?}",
                        SNAPSHOT_EXPORT_SPEC,
                        manifest_id,
                        chunk_index,
                        err
                    );
                    SnapshotExportError::Encrypt
                })?;
            let digest = compute_hash(&ciphertext);
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
        let total_bytes = total;
        let chunk_count = result.len();
        info!(
            "event=snapshot_export_finish clause={} manifest_id={} chunks={} total_bytes={}",
            SNAPSHOT_EXPORT_SPEC, manifest_id, chunk_count, total_bytes
        );
        Ok(result)
    }

    fn encrypt_chunk(
        &self,
        manifest_id: &str,
        chunk_index: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SnapshotCryptoError> {
        let mut buffer = plaintext.to_vec();
        let nonce = derive_chunk_nonce(self.dek_epoch, &self.iv_salt, chunk_index);
        let aad = build_chunk_aad(manifest_id, chunk_index, plaintext.len() as u64);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce_ref(&nonce), &aad, &mut buffer)
            .map_err(|_| SnapshotCryptoError::Encrypt)?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

fn compute_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("0x{}", hex::encode(digest))
}

fn canonicalize_without_signature(manifest: &SnapshotManifest) -> Result<Vec<u8>, ManifestError> {
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

#[derive(Debug, Error)]
pub enum SnapshotCryptoError {
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
}

#[allow(deprecated)]
fn key_ref(bytes: &[u8; 32]) -> &Key<Aes256Gcm> {
    Key::<Aes256Gcm>::from_slice(bytes)
}

#[allow(deprecated)]
fn nonce_ref(bytes: &[u8; 12]) -> &GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize> {
    GenericArray::from_slice(bytes)
}

#[allow(deprecated, dead_code)]
fn tag_ref(bytes: &[u8]) -> &GenericArray<u8, <Aes256Gcm as AeadCore>::TagSize> {
    GenericArray::from_slice(bytes)
}

fn bytes_to_u64(bytes: usize) -> u64 {
    bytes.try_into().unwrap_or(u64::MAX)
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
        if signed.manifest.content_hash.is_none() {
            return Err(SnapshotAuthorizationError::MissingHash);
        }
        let metadata = fs::metadata(manifest_path)?;
        if !metadata.is_file() {
            return Err(SnapshotAuthorizationError::NotAFile);
        }
        let file = fs::OpenOptions::new().read(true).open(manifest_path)?;
        file.sync_all()?;
        drop(file);
        let record = SnapshotAuthorizationRecord {
            manifest_id: signed.manifest.manifest_id.clone(),
            base_index: signed.manifest.base_index,
            auth_seq,
            manifest_hash: signed.manifest.content_hash.clone().unwrap(),
            recorded_at_ms,
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
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Log(#[from] ManifestLogError),
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
        self.entries.retain(|_, expires| *expires > now);
    }
}

#[derive(Debug, Clone)]
pub struct AppendEntriesBatch {
    pub chunk_id: String,
    pub bytes: usize,
}

impl AppendEntriesBatch {
    pub fn new(chunk_id: impl Into<String>, bytes: usize) -> Self {
        Self {
            chunk_id: chunk_id.into(),
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotThrottleState {
    Open,
    Throttled(SnapshotThrottleReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotThrottleReason {
    InFlightBytes { buffered: usize, limit: usize },
    RateLimit { observed_bps: u64, limit_bps: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotThrottleEnvelope {
    pub state: SnapshotThrottleState,
    pub buffered_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotImportConfig {
    pub max_inflight_bytes: usize,
    pub resume_ratio: f32,
    pub max_bytes_per_second: u64,
}

impl SnapshotImportConfig {
    pub fn new(max_inflight_bytes: usize) -> Self {
        Self {
            max_inflight_bytes,
            resume_ratio: 0.6,
            max_bytes_per_second: 0,
        }
    }

    pub fn with_resume_ratio(mut self, ratio: f32) -> Self {
        self.resume_ratio = ratio;
        self
    }

    pub fn with_bandwidth(mut self, max_bytes_per_second: u64) -> Self {
        self.max_bytes_per_second = max_bytes_per_second;
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct SnapshotImportTelemetry {
    throttle_events: u64,
    resume_events: u64,
    max_buffered_bytes: usize,
    last_reason: Option<SnapshotThrottleReason>,
}

impl SnapshotImportTelemetry {
    fn record_transition(
        &mut self,
        previous: &SnapshotThrottleState,
        current: &SnapshotThrottleState,
        buffered: usize,
    ) {
        if buffered > self.max_buffered_bytes {
            self.max_buffered_bytes = buffered;
        }
        match (previous, current) {
            (SnapshotThrottleState::Open, SnapshotThrottleState::Throttled(reason)) => {
                self.throttle_events += 1;
                self.last_reason = Some(reason.clone());
            }
            (SnapshotThrottleState::Throttled(_), SnapshotThrottleState::Throttled(reason)) => {
                self.last_reason = Some(reason.clone());
            }
            (SnapshotThrottleState::Throttled(_), SnapshotThrottleState::Open) => {
                self.resume_events += 1;
            }
            _ => {}
        }
    }

    fn snapshot(&self) -> SnapshotImportTelemetrySnapshot {
        SnapshotImportTelemetrySnapshot {
            throttle_events: self.throttle_events,
            resume_events: self.resume_events,
            max_buffered_bytes: self.max_buffered_bytes,
            last_reason: self.last_reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotImportTelemetrySnapshot {
    pub throttle_events: u64,
    pub resume_events: u64,
    pub max_buffered_bytes: usize,
    pub last_reason: Option<SnapshotThrottleReason>,
}

#[derive(Debug)]
pub struct SnapshotAppendEntriesCoordinator {
    config: SnapshotImportConfig,
    buffered_bytes: usize,
    inflight: VecDeque<AppendEntriesBatch>,
    telemetry: SnapshotImportTelemetry,
    last_state: SnapshotThrottleState,
    rate_window_start: Instant,
    rate_window_bytes: u64,
}

impl SnapshotAppendEntriesCoordinator {
    pub fn new(max_inflight_bytes: usize) -> Self {
        Self::with_config(SnapshotImportConfig::new(max_inflight_bytes))
    }

    pub fn with_config(config: SnapshotImportConfig) -> Self {
        Self {
            config,
            buffered_bytes: 0,
            inflight: VecDeque::new(),
            telemetry: SnapshotImportTelemetry::default(),
            last_state: SnapshotThrottleState::Open,
            rate_window_start: Instant::now(),
            rate_window_bytes: 0,
        }
    }

    pub fn enqueue(&mut self, batch: AppendEntriesBatch) -> SnapshotThrottleEnvelope {
        self.enqueue_at(batch, Instant::now())
    }

    pub fn enqueue_at(
        &mut self,
        batch: AppendEntriesBatch,
        now: Instant,
    ) -> SnapshotThrottleEnvelope {
        self.buffered_bytes += batch.bytes;
        let bytes = batch.bytes;
        self.inflight.push_back(batch);
        self.record_transfer(bytes_to_u64(bytes), now);
        self.envelope_at(now)
    }

    pub fn complete(
        &mut self,
        chunk_id: &str,
    ) -> Result<SnapshotThrottleEnvelope, SnapshotImportError> {
        self.complete_at(chunk_id, Instant::now())
    }

    pub fn complete_at(
        &mut self,
        chunk_id: &str,
        now: Instant,
    ) -> Result<SnapshotThrottleEnvelope, SnapshotImportError> {
        let pos = self
            .inflight
            .iter()
            .position(|batch| batch.chunk_id == chunk_id)
            .ok_or_else(|| SnapshotImportError::UnknownChunk {
                chunk_id: chunk_id.to_string(),
            })?;
        let batch = self.inflight.remove(pos).expect("position valid");
        self.buffered_bytes = self.buffered_bytes.saturating_sub(batch.bytes);
        self.refresh_rate_window(now);
        Ok(self.envelope_at(now))
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn telemetry(&self) -> SnapshotImportTelemetrySnapshot {
        self.telemetry.snapshot()
    }

    pub fn config(&self) -> SnapshotImportConfig {
        self.config
    }

    fn envelope_at(&mut self, now: Instant) -> SnapshotThrottleEnvelope {
        self.refresh_rate_window(now);
        let mut reason = None;
        if self.should_throttle_buffer() {
            reason = Some(SnapshotThrottleReason::InFlightBytes {
                buffered: self.buffered_bytes,
                limit: self.config.max_inflight_bytes,
            });
        } else if let Some(rate_reason) = self.rate_limit_reason() {
            reason = Some(rate_reason);
        }

        let state = match reason {
            Some(reason) => SnapshotThrottleState::Throttled(reason),
            None => SnapshotThrottleState::Open,
        };
        self.telemetry
            .record_transition(&self.last_state, &state, self.buffered_bytes);
        self.last_state = state.clone();
        SnapshotThrottleEnvelope {
            state,
            buffered_bytes: self.buffered_bytes,
        }
    }

    fn should_throttle_buffer(&self) -> bool {
        let at_cap = self.buffered_bytes >= self.config.max_inflight_bytes;
        let above_resume = self.buffered_bytes > self.resume_threshold();
        match self.last_state {
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes { .. }) => {
                above_resume
            }
            _ => at_cap,
        }
    }

    fn resume_threshold(&self) -> usize {
        let ratio = self.config.resume_ratio.clamp(0.0, 1.0);
        ((self.config.max_inflight_bytes as f32) * ratio).ceil() as usize
    }

    fn record_transfer(&mut self, bytes: u64, now: Instant) {
        if self.config.max_bytes_per_second == 0 {
            return;
        }
        self.refresh_rate_window(now);
        self.rate_window_bytes = self.rate_window_bytes.saturating_add(bytes);
    }

    fn refresh_rate_window(&mut self, now: Instant) {
        if now.duration_since(self.rate_window_start) >= Duration::from_secs(1) {
            self.rate_window_start = now;
            self.rate_window_bytes = 0;
        }
    }

    fn rate_limit_reason(&self) -> Option<SnapshotThrottleReason> {
        if self.config.max_bytes_per_second == 0 {
            return None;
        }
        if self.rate_window_bytes > self.config.max_bytes_per_second {
            Some(SnapshotThrottleReason::RateLimit {
                observed_bps: self.rate_window_bytes,
                limit_bps: self.config.max_bytes_per_second,
            })
        } else {
            None
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageLayout;
    use std::io::Cursor;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    #[test]
    fn manifest_builder_generates_stable_hash() {
        let signer = HmacManifestSigner::new(b"secret");
        let chunk = SnapshotChunk {
            chunk_id: "c1".into(),
            offset: 0,
            len: 1024,
            digest: "abc".into(),
        };
        let signed = SnapshotManifestBuilder::new("m1")
            .version_id(7)
            .producer("node", "emit")
            .base(5, 50)
            .encryption(2, "salt")
            .add_chunk(chunk)
            .finalize(&signer)
            .unwrap();
        let canonical = canonicalize_without_signature(&signed.manifest).unwrap();
        assert!(signer.verify(&canonical, &signed.signature));
        assert!(signed.manifest.content_hash.is_some());
    }

    #[test]
    fn snapshot_authorizer_writes_record() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("state");
        let layout = StorageLayout::new(&data_dir);
        layout.ensure().unwrap();
        let manifest_path = data_dir.join("snapshot").join("manifest.json");
        fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        fs::write(&manifest_path, b"{}").unwrap();
        let log = ManifestAuthorizationLog::new(layout.paths().manifest_authorizations);
        let authorizer = SnapshotAuthorizer::new(log);
        let signer = HmacManifestSigner::new(b"secret");
        let signed = SnapshotManifestBuilder::new("mid")
            .version_id(1)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(2, "salt")
            .add_chunk(SnapshotChunk {
                chunk_id: "c".into(),
                offset: 0,
                len: 1,
                digest: "d".into(),
            })
            .finalize(&signer)
            .unwrap();
        let record = authorizer
            .authorize(&manifest_path, &signed, 7, 123)
            .unwrap();
        assert_eq!(record.auth_seq, 7);
    }

    #[test]
    fn chunk_exporter_encrypts_chunks_with_aead() {
        let key = DataEncryptionKey::new(3, [9u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let caps = exporter.caps();
        let chunk_size = (caps.max_chunk_bytes / 4) as usize;
        let payload = vec![1u8; chunk_size * 3 + 10];
        let chunks = exporter
            .export_reader("snap", Cursor::new(&payload), chunk_size)
            .unwrap();
        assert_eq!(chunks.len(), 4);

        let cipher = Aes256Gcm::new(key_ref(&key.bytes));
        let mut recovered = Vec::new();
        for (idx, payload_chunk) in chunks.iter().enumerate() {
            let (data, tag) = payload_chunk
                .ciphertext
                .split_at(payload_chunk.ciphertext.len() - 16);
            let mut buf = data.to_vec();
            let nonce = derive_chunk_nonce(key.epoch, "salt", idx as u64);
            let aad = build_chunk_aad("snap", idx as u64, payload_chunk.chunk.len);
            cipher
                .decrypt_in_place_detached(nonce_ref(&nonce), &aad, &mut buf, tag_ref(tag))
                .expect("decryptable");
            recovered.extend_from_slice(&buf);
        }
        assert_eq!(recovered[..payload.len()], payload[..]);
    }

    #[test]
    fn chunk_exporter_enforces_chunk_caps() {
        let key = DataEncryptionKey::new(5, [1u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let invalid_chunk = exporter.caps().max_chunk_bytes as usize + 1;
        let err = exporter
            .export_reader("snap", Cursor::new(vec![0u8; invalid_chunk]), invalid_chunk)
            .unwrap_err();
        assert!(matches!(err, SnapshotExportError::ChunkSizeExceeded { .. }));
    }

    #[test]
    fn chunk_exporter_enforces_total_cap() {
        let key = DataEncryptionKey::new(6, [2u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Wan, &key, "salt");
        let caps = exporter.caps();
        let total = caps.max_total_bytes as usize + 1;
        let err = exporter
            .export_reader(
                "snap",
                Cursor::new(vec![7u8; total]),
                caps.max_chunk_bytes as usize,
            )
            .unwrap_err();
        assert!(matches!(err, SnapshotExportError::TotalBytesExceeded));
    }

    #[test]
    fn manifest_verifier_uses_trust_cache() {
        let signer = HmacManifestSigner::new(b"secret");
        let signed = SnapshotManifestBuilder::new("m1")
            .version_id(5)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(2, "salt")
            .add_chunk(SnapshotChunk {
                chunk_id: "c".into(),
                offset: 0,
                len: 1,
                digest: "d".into(),
            })
            .finalize(&signer)
            .unwrap();
        let mut verifier = SnapshotManifestVerifier::new(
            HmacManifestSigner::new(b"secret"),
            1,
            10,
            Duration::from_secs(60),
        );
        let now = Instant::now();
        let verdict = verifier.verify(&signed, now).unwrap();
        assert!(!verdict.cache_hit);
        let cached = verifier
            .verify(&signed, now + Duration::from_secs(1))
            .unwrap();
        assert!(cached.cache_hit);
    }

    #[test]
    fn manifest_verifier_detects_version_and_signature_issues() {
        let signer = HmacManifestSigner::new(b"secret");
        let signed = SnapshotManifestBuilder::new("m2")
            .version_id(2)
            .producer("node", "emit")
            .base(1, 1)
            .encryption(1, "salt")
            .finalize(&signer)
            .unwrap();
        let mut verifier = SnapshotManifestVerifier::new(
            HmacManifestSigner::new(b"secret"),
            3,
            5,
            Duration::from_secs(5),
        );
        let err = verifier.verify(&signed, Instant::now()).unwrap_err();
        assert!(matches!(
            err,
            ManifestVerificationError::VersionOutOfRange { .. }
        ));

        let mut bad_signature = signed.clone();
        bad_signature.signature.value = "deadbeef".into();
        let mut verifier = SnapshotManifestVerifier::new(
            HmacManifestSigner::new(b"secret"),
            1,
            5,
            Duration::from_secs(5),
        );
        let err = verifier.verify(&bad_signature, Instant::now()).unwrap_err();
        assert!(matches!(
            err,
            ManifestVerificationError::SignatureInvalid { .. }
        ));
    }

    #[test]
    fn append_entries_coordinator_throttles_on_capacity() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::new(256);
        let envelope = coordinator.enqueue(AppendEntriesBatch::new("c1", 128));
        assert_eq!(envelope.buffered_bytes, 128);
        assert!(matches!(envelope.state, SnapshotThrottleState::Open));

        let envelope = coordinator.enqueue(AppendEntriesBatch::new("c2", 160));
        assert!(matches!(
            envelope.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes { .. })
        ));
        assert_eq!(coordinator.buffered_bytes(), 288);

        let _ = coordinator.complete("c1").unwrap();
        let final_env = coordinator.complete("c2").unwrap();
        assert!(matches!(final_env.state, SnapshotThrottleState::Open));
    }

    #[test]
    fn append_entries_coordinator_errors_on_unknown_chunk() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::new(128);
        coordinator.enqueue(AppendEntriesBatch::new("c1", 64));
        let err = coordinator.complete("missing").unwrap_err();
        assert!(matches!(err, SnapshotImportError::UnknownChunk { .. }));
    }

    #[test]
    fn append_entries_hysteresis_and_telemetry() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
            SnapshotImportConfig::new(200).with_resume_ratio(0.5),
        );
        let now = Instant::now();
        coordinator.enqueue_at(AppendEntriesBatch::new("c1", 150), now);
        let throttled = coordinator.enqueue_at(AppendEntriesBatch::new("c2", 80), now);
        assert!(matches!(
            throttled.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes { .. })
        ));

        // Removing 150 bytes drops buffered to 80 which is below resume threshold.
        let resumed = coordinator
            .complete_at("c1", now + Duration::from_millis(1))
            .unwrap();
        assert!(matches!(resumed.state, SnapshotThrottleState::Open));
        let telemetry = coordinator.telemetry();
        assert_eq!(telemetry.throttle_events, 1);
        assert_eq!(telemetry.resume_events, 1);
        assert_eq!(telemetry.max_buffered_bytes, 230);
    }

    #[test]
    fn append_entries_rate_limit_throttle() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
            SnapshotImportConfig::new(1024).with_bandwidth(256),
        );
        let now = Instant::now();
        coordinator.enqueue_at(AppendEntriesBatch::new("c1", 128), now);
        let envelope = coordinator.enqueue_at(AppendEntriesBatch::new("c2", 200), now);
        assert!(matches!(
            envelope.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit { .. })
        ));
    }

    #[test]
    fn snapshot_chunk_importer_decrypts_payloads() {
        let key = DataEncryptionKey::new(12, [4u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let plaintext = vec![0xEEu8; 256];
        let chunks = exporter
            .export_reader("fixture", Cursor::new(plaintext.clone()), 64)
            .expect("chunks");
        let importer = SnapshotChunkImporter::new(&key, "salt");
        let mut store = SnapshotStagingStore::new();
        for chunk in &chunks {
            let staged = importer
                .import_chunk("fixture", chunk)
                .expect("chunk decrypts");
            store.stage(&chunk.chunk.chunk_id, staged);
        }
        assert_eq!(store.total_bytes(), plaintext.len());
        assert_eq!(store.chunks().len(), chunks.len());
    }

    #[test]
    fn snapshot_chunk_importer_detects_bad_digest() {
        let key = DataEncryptionKey::new(13, [8u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let chunks = exporter
            .export_reader("fixture", Cursor::new(vec![0x55u8; 64]), 64)
            .expect("chunks");
        let mut tampered = chunks[0].clone();
        tampered.chunk.digest = "0xdeadbeef".into();
        let importer = SnapshotChunkImporter::new(&key, "salt");
        let err = importer
            .import_chunk("fixture", &tampered)
            .expect_err("digest mismatch");
        assert!(matches!(err, SnapshotImportError::DigestMismatch { .. }));
    }

    fn readiness() -> SnapshotReadiness {
        SnapshotReadiness {
            manifest_id: "m1".into(),
            base_index: 100,
            content_hash: "0xdeadbeef".into(),
            applied_index_snapshot: 90,
            last_advertised_ready_index: 100,
            manifest_generated_ms: 1_000,
        }
    }

    fn request(snapshot_only: bool, state: StrictFallbackState) -> SnapshotReadRequest {
        SnapshotReadRequest {
            partition_id: "p1".into(),
            read_semantics_snapshot_only: snapshot_only,
            strict_state: state,
            cp_cache_age_ms: 42,
        }
    }

    fn manifest() -> SnapshotManifest {
        let signer = HmacManifestSigner::new(b"manifest");
        SnapshotManifestBuilder::new("m1")
            .version_id(1)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(2, "salt")
            .ap_pane_digest("0x1")
            .add_dedup_shard(DedupShardDigest {
                shard_id: "default".into(),
                ledger_epoch: 1,
                shard_digest: "0xaaa".into(),
            })
            .add_commit_epoch(CommitEpochEntry {
                dimension: "cp".into(),
                epoch: 5,
                checksum: "0xbeef".into(),
            })
            .finalize(&signer)
            .unwrap()
            .manifest
    }

    fn full_delta(id: &str, parent: &str, chain_length: u32) -> SnapshotManifest {
        let mut delta = manifest();
        delta.manifest_id = id.into();
        delta.snapshot_kind = SnapshotKind::Delta;
        delta.delta_parent_manifest_id = Some(parent.into());
        delta.delta_chain_length = chain_length;
        delta
    }

    #[allow(clippy::too_many_arguments)]
    fn manifest_from_chunks(
        manifest_id: &str,
        kind: SnapshotKind,
        parent: Option<&str>,
        chain_length: u32,
        chunks: &[SnapshotChunkPayload],
        signer: &HmacManifestSigner,
        dek_epoch: u32,
        iv_salt: &str,
    ) -> SnapshotManifest {
        let mut builder = SnapshotManifestBuilder::new(manifest_id)
            .version_id(1)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(dek_epoch, iv_salt.to_owned())
            .ap_pane_digest("0x1")
            .add_dedup_shard(DedupShardDigest {
                shard_id: "default".into(),
                ledger_epoch: 1,
                shard_digest: "0xaaa".into(),
            })
            .add_commit_epoch(CommitEpochEntry {
                dimension: "cp".into(),
                epoch: 5,
                checksum: "0xbeef".into(),
            })
            .snapshot_kind(kind);
        if let Some(parent_id) = parent {
            builder = builder.delta_parent(parent_id, chain_length);
        }
        for chunk in chunks {
            builder = builder.add_chunk(chunk.chunk.clone());
        }
        builder.finalize(signer).unwrap().manifest
    }

    #[test]
    fn snapshot_fallback_requires_header() {
        let controller = SnapshotFallbackController::new(readiness());
        let err = controller
            .handle_request(request(false, StrictFallbackState::LocalOnly))
            .unwrap_err();
        assert!(matches!(err, SnapshotReadError::MissingSnapshotOnlyHeader));
    }

    #[test]
    fn snapshot_fallback_requires_allowed_strict_state() {
        let controller = SnapshotFallbackController::new(readiness());
        let err = controller
            .handle_request(request(true, StrictFallbackState::Healthy))
            .unwrap_err();
        assert!(matches!(
            err,
            SnapshotReadError::StrictStateUnavailable { .. }
        ));
    }

    #[test]
    fn snapshot_fallback_enforces_min_ratio() {
        let mut controller = SnapshotFallbackController::new(readiness());
        controller.update_readiness(SnapshotReadiness {
            applied_index_snapshot: 40,
            manifest_generated_ms: readiness().manifest_generated_ms,
            ..readiness()
        });
        let err = controller
            .handle_request(request(true, StrictFallbackState::LocalOnly))
            .unwrap_err();
        assert!(matches!(err, SnapshotReadError::SnapshotOnlyUnavailable));
    }

    #[test]
    fn snapshot_fallback_rejects_when_metrics_absent() {
        let controller = SnapshotFallbackController::new(SnapshotReadiness {
            last_advertised_ready_index: 0,
            applied_index_snapshot: 0,
            ..readiness()
        });
        let err = controller
            .handle_request(request(true, StrictFallbackState::LocalOnly))
            .unwrap_err();
        assert!(matches!(err, SnapshotReadError::SnapshotOnlyUnavailable));
    }

    #[test]
    fn snapshot_fallback_returns_manifest_details() {
        let controller = SnapshotFallbackController::new(readiness());
        let response = controller
            .handle_request(request(true, StrictFallbackState::ProofPublished))
            .expect("fallback succeeds");
        assert_eq!(response.manifest_id, "m1");
        assert_eq!(response.base_index, 100);
        assert!(response.readiness_ratio >= 0.9);
        assert!(response.headers.snapshot_only);
        assert_eq!(response.headers.snapshot_manifest_id, "m1");
        assert_eq!(response.headers.cp_cache_age_ms, 42);
    }

    #[test]
    fn snapshot_fallback_telemetry_tracks_ready_state() {
        let mut controller = SnapshotFallbackController::new(readiness());
        let telemetry = controller.telemetry(2_000);
        assert!(matches!(
            telemetry.snapshot_only_ready_state,
            SnapshotOnlyReadyState::Healthy
        ));
        assert_eq!(telemetry.snapshot_manifest_age_ms, 1_000);

        controller.update_readiness(SnapshotReadiness {
            applied_index_snapshot: 10,
            manifest_generated_ms: 500,
            ..readiness()
        });
        let degraded = controller.telemetry(2_500);
        assert!(matches!(
            degraded.snapshot_only_ready_state,
            SnapshotOnlyReadyState::Degraded
        ));

        controller.record_snapshot_only_result(500, true, 2_500);
        let after_breach = controller.telemetry(2_800);
        assert!(after_breach.snapshot_only_slo_breach_total >= 1);
    }

    #[test]
    fn snapshot_delta_policy_enforces_chain_and_windows() {
        let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);

        let mut full = manifest();
        full.manifest_id = "full".into();
        assert!(matches!(
            policy.record_manifest(&full_delta("d1", "full", 1), 0),
            Err(SnapshotDeltaPolicyError::FullSnapshotUnknown)
        ));

        policy
            .record_manifest(&full, 0)
            .expect("full snapshot allowed");
        let delta = full_delta("d1", "full", 1);
        policy
            .record_manifest(&delta, 5_000)
            .expect("delta allowed");
        assert!(matches!(
            policy.record_manifest(&full_delta("d2", "d1", 2), 20_000),
            Err(SnapshotDeltaPolicyError::DeltaEmitWindowExceeded)
        ));

        policy
            .record_manifest(&full_delta("d2", "d1", 2), 8_000)
            .expect("second delta allowed");
        assert!(matches!(
            policy.record_manifest(&full_delta("overflow", "d2", 3), 9_000),
            Err(SnapshotDeltaPolicyError::DeltaChainExceeded { .. })
        ));

        let mut gated = SnapshotDeltaPolicy::new(1, 10_000, 30_000);
        assert!(matches!(
            gated.record_manifest(&full_delta("d1", "full", 1), 0),
            Err(SnapshotDeltaPolicyError::DeltaDisabled)
        ));
        gated
            .record_manifest(&full, 0)
            .expect("full snapshot allowed");
        assert!(matches!(
            gated.record_manifest(&full_delta("d2", "d1", 1), 1_000),
            Err(SnapshotDeltaPolicyError::DeltaDisabled)
        ));
    }

    #[test]
    fn snapshot_delta_policy_reports_telemetry_states() {
        let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);
        let mut full = manifest();
        full.manifest_id = "full".into();
        policy
            .record_manifest(&full, 0)
            .expect("full snapshot allowed");
        let telemetry = policy.telemetry();
        assert_eq!(telemetry.state, SnapshotDeltaChainState::Idle);

        let delta = full_delta("d1", "full", 1);
        policy
            .record_manifest(&delta, 1_000)
            .expect("delta allowed");
        let telemetry = policy.telemetry();
        assert_eq!(telemetry.state, SnapshotDeltaChainState::Building);
        assert_eq!(telemetry.chain_length, 1);

        let bad_delta = full_delta("d2", "unknown", 2);
        let err = policy
            .record_manifest(&bad_delta, 1_500)
            .expect_err("stale parent rejected");
        assert!(matches!(
            err,
            SnapshotDeltaPolicyError::DeltaParentMismatch { .. }
        ));
        assert_eq!(policy.telemetry().state, SnapshotDeltaChainState::Orphaned);
    }

    #[test]
    fn snapshot_import_validator_rejects_missing_metadata() {
        let validator = SnapshotImportValidator::new(HashMap::new());
        let mut bad_manifest = manifest();
        bad_manifest.ap_pane_digest = None;
        bad_manifest.dedup_shards.clear();
        bad_manifest.commit_epoch_vector.clear();
        assert!(matches!(
            validator.validate_manifest(&bad_manifest),
            Err(SnapshotImportValidationError::MissingApPaneDigest)
        ));
    }

    #[test]
    fn snapshot_import_validator_checks_commit_epochs_and_policy() {
        let mut epochs = HashMap::new();
        epochs.insert("cp".into(), 5);
        let validator = SnapshotImportValidator::new(epochs.clone());
        let manifest = manifest();
        validator.validate_manifest(&manifest).unwrap();

        let mut wrong_epochs = HashMap::new();
        wrong_epochs.insert("cp".into(), 7);
        let bad_validator = SnapshotImportValidator::new(wrong_epochs);
        assert!(matches!(
            bad_validator.validate_manifest(&manifest),
            Err(SnapshotImportValidationError::CommitEpochMismatch { .. })
        ));

        let mut policy = SnapshotDeltaPolicy::new(1, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);
        validator
            .validate_and_record(&manifest, 0, &mut policy)
            .expect("full manifest allowed");
        let mut delta_manifest = manifest.clone();
        delta_manifest.manifest_id = "delta-1".into();
        delta_manifest.snapshot_kind = SnapshotKind::Delta;
        delta_manifest.delta_parent_manifest_id = Some(manifest.manifest_id.clone());
        delta_manifest.delta_chain_length = 1;
        validator
            .validate_and_record(&delta_manifest, 5_000, &mut policy)
            .expect("first delta allowed");
        assert!(matches!(
            validator.validate_and_record(&delta_manifest, 6_000, &mut policy),
            Err(SnapshotImportValidationError::DeltaPolicy(
                SnapshotDeltaPolicyError::DeltaChainExceeded { .. }
            ))
        ));
    }

    #[test]
    fn snapshot_import_flow_succeeds_for_full_and_delta() {
        let key = DataEncryptionKey::new(7, [42u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let signer = HmacManifestSigner::new(b"import-flow");
        let payload = vec![0xAAu8; 2048];
        let chunks = exporter
            .export_reader("full-success", Cursor::new(&payload), 512)
            .expect("chunks generated");
        let full_manifest = manifest_from_chunks(
            "full-success",
            SnapshotKind::Full,
            None,
            0,
            &chunks,
            &signer,
            key.epoch,
            "salt",
        );

        let importer = SnapshotChunkImporter::new(&key, "salt");
        let mut staging = SnapshotStagingStore::new();
        for chunk in &chunks {
            let bytes = importer
                .import_chunk(&full_manifest.manifest_id, chunk)
                .expect("chunk decrypts");
            staging.stage(&chunk.chunk.chunk_id, bytes);
        }
        assert_eq!(staging.total_bytes(), payload.len());

        let mut epochs = HashMap::new();
        epochs.insert("cp".into(), 5);
        let validator = SnapshotImportValidator::new(epochs);
        let mut policy = SnapshotDeltaPolicy::new(3, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);
        validator
            .validate_and_record(&full_manifest, 0, &mut policy)
            .expect("full manifest accepted");

        let delta_payload = exporter
            .export_reader("delta-success", Cursor::new(&payload[..1024]), 256)
            .expect("delta chunks");
        let delta_manifest = manifest_from_chunks(
            "delta-success",
            SnapshotKind::Delta,
            Some(&full_manifest.manifest_id),
            1,
            &delta_payload,
            &signer,
            key.epoch,
            "salt",
        );
        validator
            .validate_and_record(&delta_manifest, 5_000, &mut policy)
            .expect("delta manifest accepted");
        assert_eq!(policy.telemetry().chain_length, 1);
    }

    #[test]
    fn snapshot_import_flow_rejects_tampering_and_orphans() {
        let key = DataEncryptionKey::new(8, [7u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let signer = HmacManifestSigner::new(b"import-orphan");
        let payload = vec![0xBBu8; 1024];
        let chunks = exporter
            .export_reader("full-orphan", Cursor::new(&payload), 512)
            .expect("chunks generated");
        let full_manifest = manifest_from_chunks(
            "full-orphan",
            SnapshotKind::Full,
            None,
            0,
            &chunks,
            &signer,
            key.epoch,
            "salt",
        );

        let importer = SnapshotChunkImporter::new(&key, "salt");
        let mut tampered = chunks[0].clone();
        tampered.chunk.digest = "0xdeadbeef".into();
        let err = importer
            .import_chunk(&full_manifest.manifest_id, &tampered)
            .expect_err("tampered chunk rejected");
        assert!(matches!(err, SnapshotImportError::DigestMismatch { .. }));

        let mut epochs = HashMap::new();
        epochs.insert("cp".into(), 5);
        let validator = SnapshotImportValidator::new(epochs);
        let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);
        validator
            .validate_and_record(&full_manifest, 0, &mut policy)
            .expect("full manifest accepted");

        let orphan_manifest = manifest_from_chunks(
            "delta-orphan",
            SnapshotKind::Delta,
            Some("missing-parent"),
            1,
            &chunks,
            &signer,
            key.epoch,
            "salt",
        );
        let err = validator
            .validate_and_record(&orphan_manifest, 2_000, &mut policy)
            .expect_err("orphan delta rejected");
        assert!(matches!(
            err,
            SnapshotImportValidationError::DeltaPolicy(
                SnapshotDeltaPolicyError::DeltaParentMismatch { .. }
            )
        ));
    }

    #[test]
    fn snapshot_export_controller_enforces_backlog() {
        let mut controller = SnapshotExportController::new(256, 0);
        let now = Instant::now();
        let open = controller.enqueue(128, now);
        assert!(matches!(open.state, SnapshotThrottleState::Open));
        let throttled = controller.enqueue(200, now);
        assert!(matches!(
            throttled.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes { .. })
        ));
        controller.complete(200);
        let recovered = controller.enqueue(64, now + Duration::from_secs(1));
        assert!(matches!(recovered.state, SnapshotThrottleState::Open));
        let telemetry = controller.telemetry();
        assert_eq!(telemetry.backlog_bytes, 192);
    }

    #[test]
    fn snapshot_export_controller_enforces_rate_limit() {
        let mut controller = SnapshotExportController::new(1_024, 300);
        let now = Instant::now();
        let throttled = controller.enqueue(400, now);
        assert!(matches!(
            throttled.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit { .. })
        ));
        controller.complete(400);
        let reopened = controller.enqueue(100, now + Duration::from_secs(1));
        assert!(matches!(reopened.state, SnapshotThrottleState::Open));
        let telemetry = controller.telemetry();
        assert!(telemetry.chunk_rate_bytes_per_sec <= 300);
    }
}
