use crate::replication::consensus::{ConsensusCoreManifest, ConsensusCoreManifestError};
use crate::replication::flow::FlowProfile;
use crate::replication::transport::{
    CatalogNegotiationConfig, CatalogNegotiationReport, NegotiationError,
};
use hex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapStep {
    DiskScrub,
    KeyFetch,
    CpHandshake,
}

#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub disk_scrub_ms: u64,
    pub key_fetch_ms: u64,
    pub handshake_ms: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            disk_scrub_ms: 250,
            key_fetch_ms: 150,
            handshake_ms: 400,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapPipeline {
    config: BootstrapConfig,
    events: Vec<BootstrapEvent>,
}

#[derive(Debug, Clone)]
pub struct BootstrapEvent {
    pub step: BootstrapStep,
    pub started_at: Instant,
    pub finished_at: Instant,
}

impl BootstrapPipeline {
    pub fn new(config: BootstrapConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
        }
    }

    pub fn run(
        &mut self,
        request: BootstrapRequest,
        now: Instant,
    ) -> Result<BootstrapReport, BootstrapError> {
        let partition_id = request.partition_id.clone();
        if request.dataset_path.is_empty() {
            return Err(BootstrapError::InvalidDataset);
        }
        let manifest = self.validate_manifest(&request.manifest)?;
        let catalog_negotiation = request
            .catalog_negotiation
            .negotiate(Path::new(&request.dataset_path), manifest.catalog)?;
        self.events.clear();
        self.simulate_step(BootstrapStep::DiskScrub, now, self.config.disk_scrub_ms);
        self.simulate_step(
            BootstrapStep::KeyFetch,
            now + Duration::from_millis(self.config.disk_scrub_ms),
            self.config.key_fetch_ms,
        );
        self.simulate_step(
            BootstrapStep::CpHandshake,
            now + Duration::from_millis(self.config.disk_scrub_ms + self.config.key_fetch_ms),
            self.config.handshake_ms,
        );
        Ok(BootstrapReport {
            partition_id,
            events: self.events.clone(),
            catalog_negotiation,
        })
    }

    fn simulate_step(&mut self, step: BootstrapStep, started_at: Instant, duration_ms: u64) {
        let finished_at = started_at + Duration::from_millis(duration_ms);
        self.events.push(BootstrapEvent {
            step,
            started_at,
            finished_at,
        });
    }

    fn validate_manifest(
        &self,
        manifest: &ManifestValidationConfig,
    ) -> Result<ConsensusCoreManifest, BootstrapError> {
        match ConsensusCoreManifest::load_verified(
            &manifest.manifest_path,
            manifest.expected_schema_version,
            &manifest.public_key_hex,
        ) {
            Ok(loaded) => {
                self.verify_proof_bundle(&loaded, &manifest.proof_bundle_path)?;
                self.verify_feature_manifest(&loaded, &manifest.feature_manifest_path)?;
                Ok(loaded)
            }
            Err(ConsensusCoreManifestError::UnsupportedProofBundleSchema { found, .. }) => {
                Err(BootstrapError::ManifestSchemaMismatch {
                    expected: manifest.expected_schema_version,
                    found,
                })
            }
            Err(err) => Err(BootstrapError::Manifest(err)),
        }
    }

    fn verify_proof_bundle(
        &self,
        manifest: &ConsensusCoreManifest,
        path: &Path,
    ) -> Result<(), BootstrapError> {
        if !path.exists() {
            return Err(BootstrapError::ProofBundleMissing(path.to_path_buf()));
        }
        let hash = sha256_file(path)?;
        if hash != manifest.proof_bundle.bundle_sha256 {
            return Err(BootstrapError::ProofBundleHashMismatch {
                expected: manifest.proof_bundle.bundle_sha256.clone(),
                found: hash,
            });
        }
        Ok(())
    }

    fn verify_feature_manifest(
        &self,
        manifest: &ConsensusCoreManifest,
        path: &Path,
    ) -> Result<(), BootstrapError> {
        if !path.exists() {
            return Err(BootstrapError::FeatureManifestMissing(path.to_path_buf()));
        }
        let hash = sha256_file(path)?;
        if hash != manifest.feature_manifest_sha256 {
            return Err(BootstrapError::FeatureManifestHashMismatch {
                expected: manifest.feature_manifest_sha256.clone(),
                found: hash,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapRequest {
    pub partition_id: String,
    pub dataset_path: String,
    pub manifest: ManifestValidationConfig,
    pub catalog_negotiation: CatalogNegotiationConfig,
}

#[derive(Debug, Clone)]
pub struct BootstrapReport {
    pub partition_id: String,
    pub events: Vec<BootstrapEvent>,
    pub catalog_negotiation: CatalogNegotiationReport,
}

#[derive(Debug, Clone)]
pub struct ManifestValidationConfig {
    pub manifest_path: PathBuf,
    pub public_key_hex: String,
    pub expected_schema_version: u16,
    pub proof_bundle_path: PathBuf,
    pub feature_manifest_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("dataset path missing")]
    InvalidDataset,
    #[error("manifest schema mismatch (expected {expected}, found {found})")]
    ManifestSchemaMismatch { expected: u16, found: u16 },
    #[error(transparent)]
    Manifest(#[from] ConsensusCoreManifestError),
    #[error("proof bundle missing at {0:?}")]
    ProofBundleMissing(PathBuf),
    #[error("feature manifest missing at {0:?}")]
    FeatureManifestMissing(PathBuf),
    #[error("proof bundle hash mismatch (expected {expected}, found {found})")]
    ProofBundleHashMismatch { expected: String, found: String },
    #[error("feature manifest hash mismatch (expected {expected}, found {found})")]
    FeatureManifestHashMismatch { expected: String, found: String },
    #[error(transparent)]
    ManifestIo(#[from] std::io::Error),
    #[error(transparent)]
    CatalogNegotiation(#[from] NegotiationError),
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug)]
pub struct ShutdownManager {
    draining: bool,
    repair_mode: bool,
    last_action: Option<Instant>,
    pending_actions: VecDeque<ShutdownAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownAction {
    TransferLeader { partition_id: String },
    FlushWal,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShutdownError {
    #[error("unexpected shutdown action: expected {expected:?}, observed {observed:?}")]
    UnexpectedAction {
        expected: ShutdownAction,
        observed: ShutdownAction,
    },
}

impl Default for ShutdownManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownManager {
    pub fn new() -> Self {
        Self {
            draining: false,
            repair_mode: false,
            last_action: None,
            pending_actions: VecDeque::new(),
        }
    }

    pub fn begin_shutdown(&mut self, partition_id: impl Into<String>, now: Instant) {
        self.draining = true;
        self.pending_actions.clear();
        self.pending_actions
            .push_back(ShutdownAction::TransferLeader {
                partition_id: partition_id.into(),
            });
        self.pending_actions.push_back(ShutdownAction::FlushWal);
        self.last_action = Some(now);
    }

    pub fn enter_repair_mode(&mut self, now: Instant) {
        self.repair_mode = true;
        self.pending_actions.clear();
        self.last_action = Some(now);
    }

    pub fn next_action(&self) -> Option<&ShutdownAction> {
        self.pending_actions.front()
    }

    pub fn record_action_complete(
        &mut self,
        action: &ShutdownAction,
        now: Instant,
    ) -> Result<(), ShutdownError> {
        match self.pending_actions.front() {
            Some(expected) if expected == action => {
                self.pending_actions.pop_front();
                self.last_action = Some(now);
                Ok(())
            }
            Some(expected) => Err(ShutdownError::UnexpectedAction {
                expected: expected.clone(),
                observed: action.clone(),
            }),
            None => Err(ShutdownError::UnexpectedAction {
                expected: ShutdownAction::FlushWal,
                observed: action.clone(),
            }),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.pending_actions.is_empty()
    }

    pub fn status(&self) -> ShutdownStatus {
        ShutdownStatus {
            draining: self.draining,
            repair_mode: self.repair_mode,
            last_action: self.last_action,
            pending_actions: self.pending_actions.iter().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShutdownStatus {
    pub draining: bool,
    pub repair_mode: bool,
    pub last_action: Option<Instant>,
    pub pending_actions: Vec<ShutdownAction>,
}

#[derive(Debug, Clone)]
pub struct ClusterProfile {
    pub profile_name: String,
    pub flow_profile: FlowProfile,
    pub max_replicas: u32,
}

pub struct ProfileLoader;

impl ProfileLoader {
    pub fn load(values: &HashMap<String, String>) -> Result<ClusterProfile, ProfileError> {
        let profile_name = values
            .get("profile")
            .cloned()
            .ok_or(ProfileError::MissingField("profile"))?;
        let max_replicas = values
            .get("max_replicas")
            .ok_or(ProfileError::MissingField("max_replicas"))?
            .parse::<u32>()
            .map_err(|_| ProfileError::InvalidField("max_replicas"))?;
        let flow_profile = match values
            .get("flow_profile")
            .map(|value| value.as_str())
            .unwrap_or("latency")
        {
            "throughput" => FlowProfile::Throughput,
            "wan" => FlowProfile::Wan,
            _ => FlowProfile::Latency,
        };
        Ok(ClusterProfile {
            profile_name,
            flow_profile,
            max_replicas,
        })
    }
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("invalid field {0}")]
    InvalidField(&'static str),
}
