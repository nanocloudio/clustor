use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const FEATURE_GATE_SPEC: &str = "§14.FeatureGates";

#[derive(Debug, Clone, Copy)]
pub struct FutureGateDescriptor {
    pub name: &'static str,
    pub slug: &'static str,
    pub cp_object: &'static str,
    pub predicate: &'static str,
}

pub fn future_gates() -> &'static [FutureGateDescriptor] {
    static GATES: &[FutureGateDescriptor] = &[
        FutureGateDescriptor {
            name: "Leader leases",
            slug: "leader_leases",
            cp_object: "LeaseEnable",
            predicate:
                "All voters advertise lease_gap_max > 0, CP cache Fresh, durability proof published",
        },
        FutureGateDescriptor {
            name: "PID auto-tuner",
            slug: "pid_auto_tune",
            cp_object: "FlowPidAutoTune",
            predicate: "Partition profile in {Throughput,WAN}, io_writer_mode=FixedUring",
        },
        FutureGateDescriptor {
            name: "Incremental snapshots",
            slug: "snapshot_delta",
            cp_object: "SnapshotDeltaEnable",
            predicate: "snapshot.delta_chain_max > 0, CP cache Fresh, follower capability granted",
        },
        FutureGateDescriptor {
            name: "BLAKE3 Merkle leaves",
            slug: "blake3_merkle",
            cp_object: "IntegrityHashSuite",
            predicate: "All replicas advertise blake3 support, integrity_mac_epoch >= 2",
        },
    ];
    GATES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FeatureGateState {
    Enabled,
    #[default]
    Disabled,
    Revoked,
}

impl FeatureGateState {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeatureGateState::Enabled => "Enabled",
            FeatureGateState::Disabled => "Disabled",
            FeatureGateState::Revoked => "Revoked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeatureGateTelemetryEntry {
    pub feature: &'static str,
    pub slug: &'static str,
    pub gate_state_metric: String,
    pub gate_state_digest_metric: String,
    pub predicate_digest_metric: String,
    pub predicate_digest: String,
    pub gate_state_digest: String,
    pub state_value: FeatureGateState,
}

#[derive(Debug, Clone)]
pub struct FeatureGateTelemetry {
    entries: Vec<FeatureGateTelemetryEntry>,
}

impl Default for FeatureGateTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureGateTelemetry {
    pub fn new() -> Self {
        let entries = future_gates()
            .iter()
            .map(|gate| {
                let predicate_digest = digest_predicate(gate.predicate);
                let gate_state_digest =
                    digest_gate_state(gate.slug, FeatureGateState::Disabled, &predicate_digest);
                FeatureGateTelemetryEntry {
                    feature: gate.name,
                    slug: gate.slug,
                    gate_state_metric: format!("feature.{}_gate_state", gate.slug),
                    gate_state_digest_metric: format!("feature.{}_gate_state_digest", gate.slug),
                    predicate_digest_metric: format!("feature.{}_predicate_digest", gate.slug),
                    predicate_digest,
                    gate_state_digest,
                    state_value: FeatureGateState::Disabled,
                }
            })
            .collect();
        Self { entries }
    }

    pub fn entries(&self) -> &[FeatureGateTelemetryEntry] {
        &self.entries
    }

    pub fn update_from_matrix(&mut self, matrix: &FeatureCapabilityMatrix) {
        for entry in &mut self.entries {
            if let Some(state) = matrix.entry(entry.slug) {
                if entry.state_value != state.gate_state {
                    info!(
                        "event=feature_gate_state clause={} feature={} slug={} cp_object={} prev_state={} next_state={} predicate_digest={}",
                        FEATURE_GATE_SPEC,
                        entry.feature,
                        entry.slug,
                        state.cp_object,
                        entry.state_value.as_str(),
                        state.gate_state.as_str(),
                        state.predicate_digest
                    );
                }
                entry.state_value = state.gate_state;
                entry.predicate_digest = state.predicate_digest.clone();
                entry.gate_state_digest = state.gate_state_digest.clone();
            }
        }
    }
}

fn digest_predicate(predicate: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(predicate.as_bytes());
    hex::encode(hasher.finalize())
}

fn digest_gate_state(slug: &str, state: FeatureGateState, predicate_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slug.as_bytes());
    hasher.update(state.as_str().as_bytes());
    hasher.update(predicate_digest.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureManifestEntry {
    pub gate: String,
    pub cp_object: String,
    pub predicate_digest: String,
    #[serde(default)]
    pub gate_state: FeatureGateState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureManifest {
    pub schema_version: u32,
    pub generated_at_ms: u64,
    pub features: Vec<FeatureManifestEntry>,
    pub signature: String,
}

impl FeatureManifest {
    pub fn write_to(&self, output: impl AsRef<Path>) -> Result<(), FeatureManifestError> {
        let payload = serde_json::to_vec_pretty(self)?;
        if let Some(parent) = output.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, payload)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, FeatureManifestError> {
        let bytes = fs::read(path)?;
        let manifest = serde_json::from_slice(&bytes)?;
        Ok(manifest)
    }

    pub fn verify_signature(&self, verifying_key_hex: &str) -> Result<(), FeatureManifestError> {
        let payload = FeatureManifestPayload {
            schema_version: self.schema_version,
            generated_at_ms: self.generated_at_ms,
            features: self.features.clone(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        let key_bytes: [u8; 32] = hex::decode(verifying_key_hex)
            .map_err(|_| FeatureManifestError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| FeatureManifestError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| FeatureManifestError::InvalidPublicKey)?;
        let signature_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| FeatureManifestError::InvalidSignature)?
            .try_into()
            .map_err(|_| FeatureManifestError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| FeatureManifestError::SignatureVerificationFailed)?;
        Ok(())
    }

    pub fn capability_matrix(&self) -> Result<FeatureCapabilityMatrix, FeatureManifestError> {
        FeatureCapabilityMatrix::from_manifest(self)
    }

    pub fn digest(&self) -> Result<String, FeatureManifestError> {
        let payload = FeatureManifestPayload {
            schema_version: self.schema_version,
            generated_at_ms: self.generated_at_ms,
            features: self.features.clone(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }
}

pub struct FeatureManifestBuilder {
    schema_version: u32,
    gate_states: HashMap<String, FeatureGateState>,
}

impl Default for FeatureManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureManifestBuilder {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            gate_states: HashMap::new(),
        }
    }

    pub fn with_gate_state(mut self, slug: impl Into<String>, state: FeatureGateState) -> Self {
        self.gate_states.insert(slug.into(), state);
        self
    }

    pub fn build(&self, signing_key: &SigningKey) -> Result<FeatureManifest, FeatureManifestError> {
        let payload = FeatureManifestPayload {
            schema_version: self.schema_version,
            generated_at_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            features: future_gates()
                .iter()
                .map(|gate| FeatureManifestEntry {
                    gate: gate.slug.into(),
                    cp_object: gate.cp_object.into(),
                    predicate_digest: digest_predicate(gate.predicate),
                    gate_state: *self
                        .gate_states
                        .get(gate.slug)
                        .unwrap_or(&FeatureGateState::Disabled),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(FeatureManifest {
            schema_version: payload.schema_version,
            generated_at_ms: payload.generated_at_ms,
            features: payload.features,
            signature: hex::encode(signature.to_bytes()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FeatureCapabilityMatrix {
    entries: Vec<FeatureCapabilityState>,
}

#[derive(Debug, Clone)]
pub struct FeatureCapabilityState {
    pub feature: &'static str,
    pub slug: &'static str,
    pub cp_object: &'static str,
    pub predicate_digest: String,
    pub gate_state: FeatureGateState,
    pub gate_state_digest: String,
}

impl FeatureCapabilityMatrix {
    pub fn from_manifest(manifest: &FeatureManifest) -> Result<Self, FeatureManifestError> {
        let mut entries = Vec::new();
        for descriptor in future_gates() {
            let entry = manifest
                .features
                .iter()
                .find(|entry| entry.gate == descriptor.slug)
                .ok_or_else(|| FeatureManifestError::GateMissing {
                    gate: descriptor.slug.into(),
                })?;
            let expected_digest = digest_predicate(descriptor.predicate);
            if entry.predicate_digest != expected_digest {
                return Err(FeatureManifestError::PredicateDigestMismatch {
                    gate: descriptor.slug.into(),
                    expected: expected_digest,
                    observed: entry.predicate_digest.clone(),
                });
            }
            let state = FeatureCapabilityState {
                feature: descriptor.name,
                slug: descriptor.slug,
                cp_object: descriptor.cp_object,
                predicate_digest: entry.predicate_digest.clone(),
                gate_state: entry.gate_state,
                gate_state_digest: digest_gate_state(
                    descriptor.slug,
                    entry.gate_state,
                    &entry.predicate_digest,
                ),
            };
            entries.push(state);
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[FeatureCapabilityState] {
        &self.entries
    }

    pub fn entry(&self, slug: &str) -> Option<&FeatureCapabilityState> {
        self.entries.iter().find(|entry| entry.slug == slug)
    }
}

#[derive(Debug, Error)]
pub enum FeatureManifestError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("system time error: {0}")]
    Time(#[from] std::time::SystemTimeError),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("feature manifest missing gate {gate}")]
    GateMissing { gate: String },
    #[error("predicate digest mismatch for gate {gate}: expected {expected}, observed {observed}")]
    PredicateDigestMismatch {
        gate: String,
        expected: String,
        observed: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeatureManifestPayload {
    schema_version: u32,
    generated_at_ms: u64,
    features: Vec<FeatureManifestEntry>,
}

#[derive(Debug)]
pub struct ParkedFeatureGate {
    enabled: bool,
    audit: Vec<ParkedFeatureAudit>,
    allowed_features: Option<HashSet<String>>,
}

impl Default for ParkedFeatureGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ParkedFeatureGate {
    pub fn new() -> Self {
        Self {
            enabled: Self::env_enabled(),
            audit: Vec::new(),
            allowed_features: None,
        }
    }

    pub fn with_manifest(
        manifest: FeatureManifest,
        verifying_key_hex: &str,
    ) -> Result<Self, FeatureManifestError> {
        Self::build_gate(manifest, verifying_key_hex, Self::env_enabled())
    }

    pub fn enforce(
        &mut self,
        feature_name: impl Into<String>,
        actor: impl Into<String>,
        now: Instant,
    ) -> Result<(), ParkedFeatureError> {
        if !self.enabled {
            Err(ParkedFeatureError::FeatureDisabled)
        } else {
            let feature = feature_name.into();
            if let Some(features) = &self.allowed_features {
                if !features.contains(&feature) {
                    return Err(ParkedFeatureError::FeatureDisabled);
                }
            } else {
                return Err(ParkedFeatureError::FeatureDisabled);
            }
            self.audit.push(ParkedFeatureAudit {
                feature,
                actor: actor.into(),
                used_at: now,
            });
            Ok(())
        }
    }

    fn env_enabled() -> bool {
        env::var("CLUSTOR_ENABLE_PARKED_FEATURES")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn build_gate(
        manifest: FeatureManifest,
        verifying_key_hex: &str,
        enabled: bool,
    ) -> Result<Self, FeatureManifestError> {
        manifest.verify_signature(verifying_key_hex)?;
        let allowed = manifest
            .features
            .iter()
            .map(|entry| entry.gate.clone())
            .collect();
        Ok(Self {
            enabled,
            audit: Vec::new(),
            allowed_features: Some(allowed),
        })
    }

    pub fn audit_log(&self) -> &[ParkedFeatureAudit] {
        &self.audit
    }

    pub fn allowed_features(&self) -> Option<&HashSet<String>> {
        self.allowed_features.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct ParkedFeatureAudit {
    pub feature: String,
    pub actor: String,
    pub used_at: Instant,
}

#[derive(Debug, Error)]
pub enum ParkedFeatureError {
    #[error("feature is parked in Appendix P and cannot be enabled")]
    FeatureDisabled,
}
