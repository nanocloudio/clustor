use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Wire catalog version tuple captured during bundle negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogVersion {
    pub major: u8,
    pub minor: u8,
    pub forward_parse_max_minor: u8,
}

impl CatalogVersion {
    pub fn new(major: u8, minor: u8, forward_parse_max_minor: u8) -> Self {
        Self {
            major,
            minor,
            forward_parse_max_minor,
        }
    }
}

/// Reference to the proof bundle described in §0 of the specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleRef {
    pub schema_version: u16,
    pub bundle_sha256: String,
    pub bundle_signature: String,
}

impl ProofBundleRef {
    pub fn new(
        schema_version: u16,
        bundle_sha256: impl Into<String>,
        bundle_signature: impl Into<String>,
    ) -> Self {
        Self {
            schema_version,
            bundle_sha256: bundle_sha256.into(),
            bundle_signature: bundle_signature.into(),
        }
    }

    pub fn signing_message(&self) -> Vec<u8> {
        Self::signing_message_for(self.schema_version, &self.bundle_sha256)
    }

    pub fn signing_message_for(schema_version: u16, bundle_sha256: &str) -> Vec<u8> {
        let mut message = Vec::with_capacity(2 + bundle_sha256.len());
        message.extend_from_slice(&schema_version.to_be_bytes());
        message.extend_from_slice(bundle_sha256.as_bytes());
        message
    }
}

/// SHA-256 digest of a numbered section or appendix heading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionHash {
    pub identifier: String,
    pub heading: String,
    pub sha256: String,
}

/// Digest of the machine-generated bundles referenced by §0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleDigest {
    pub name: String,
    pub path: String,
    pub sha256: String,
}

/// Canonical manifest emitted alongside the wire catalog artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusCoreManifest {
    pub schema_version: u32,
    pub generated_at_ms: u64,
    pub sections: Vec<SectionHash>,
    pub bundles: Vec<BundleDigest>,
    pub catalog: CatalogVersion,
    pub proof_bundle: ProofBundleRef,
    pub feature_manifest_sha256: String,
}

impl ConsensusCoreManifest {
    pub fn write_to(&self, output: impl AsRef<Path>) -> Result<(), ConsensusCoreManifestError> {
        let payload = serde_json::to_vec_pretty(self)?;
        if let Some(parent) = output.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = File::create(output)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConsensusCoreManifestError> {
        let bytes = std::fs::read(path.as_ref())?;
        let manifest: ConsensusCoreManifest = serde_json::from_slice(&bytes)?;
        Ok(manifest)
    }

    pub fn verify_proof_bundle_signature(
        &self,
        public_key_hex: &str,
    ) -> Result<(), ConsensusCoreManifestError> {
        let key_bytes = decode_hex_32(public_key_hex)
            .map_err(|_| ConsensusCoreManifestError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ConsensusCoreManifestError::InvalidPublicKey)?;
        let signature_bytes = decode_hex_64(&self.proof_bundle.bundle_signature)
            .map_err(|_| ConsensusCoreManifestError::InvalidSignatureEncoding)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&self.proof_bundle.signing_message(), &signature)
            .map_err(|_| ConsensusCoreManifestError::SignatureVerificationFailed)?;
        Ok(())
    }

    pub fn load_verified(
        path: impl AsRef<Path>,
        expected_schema_version: u16,
        public_key_hex: &str,
    ) -> Result<Self, ConsensusCoreManifestError> {
        let manifest = ConsensusCoreManifest::load(path)?;
        if manifest.proof_bundle.schema_version != expected_schema_version {
            return Err(ConsensusCoreManifestError::UnsupportedProofBundleSchema {
                expected: expected_schema_version,
                found: manifest.proof_bundle.schema_version,
            });
        }
        manifest.verify_proof_bundle_signature(public_key_hex)?;
        Ok(manifest)
    }
}

/// Builder that derives the manifest from the specification and bundle artifacts.
pub struct ConsensusCoreManifestBuilder {
    spec_path: PathBuf,
    bundles: Vec<BundleArtifact>,
    catalog: CatalogVersion,
    proof_bundle: ProofBundleRef,
    feature_manifest_sha256: Option<String>,
}

impl ConsensusCoreManifestBuilder {
    pub fn new(spec_path: impl Into<PathBuf>) -> Self {
        Self {
            spec_path: spec_path.into(),
            bundles: Vec::new(),
            catalog: CatalogVersion::new(0, 1, 1),
            proof_bundle: ProofBundleRef::new(0, String::new(), String::new()),
            feature_manifest_sha256: None,
        }
    }

    pub fn catalog_version(mut self, version: CatalogVersion) -> Self {
        self.catalog = version;
        self
    }

    pub fn proof_bundle(mut self, proof: ProofBundleRef) -> Self {
        self.proof_bundle = proof;
        self
    }

    pub fn feature_manifest_hash(mut self, hash: impl Into<String>) -> Self {
        self.feature_manifest_sha256 = Some(hash.into());
        self
    }

    pub fn add_bundle(mut self, name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        self.bundles.push(BundleArtifact {
            name: name.into(),
            path: path.into(),
        });
        self
    }

    pub fn generate(self) -> Result<ConsensusCoreManifest, ConsensusCoreManifestError> {
        if !self.spec_path.exists() {
            return Err(ConsensusCoreManifestError::MissingSpec(self.spec_path));
        }
        if self.bundles.is_empty() {
            return Err(ConsensusCoreManifestError::NoBundlesDefined);
        }
        if self.proof_bundle.bundle_sha256.is_empty()
            || self.proof_bundle.bundle_signature.is_empty()
        {
            return Err(ConsensusCoreManifestError::MissingProofBundle);
        }
        let feature_manifest_sha256 = self
            .feature_manifest_sha256
            .clone()
            .ok_or(ConsensusCoreManifestError::MissingFeatureManifestHash)?;
        if feature_manifest_sha256.is_empty() {
            return Err(ConsensusCoreManifestError::MissingFeatureManifestHash);
        }
        let spec_contents = std::fs::read_to_string(&self.spec_path)?;
        let mut sections = collect_section_hashes(&spec_contents);
        if sections.is_empty() {
            return Err(ConsensusCoreManifestError::NoSectionsFound(self.spec_path));
        }
        let bundles = self.compute_bundle_digests()?;
        let bundle_chain = bundles
            .iter()
            .map(|bundle| bundle.sha256.as_str())
            .collect::<Vec<_>>()
            .join(":");
        for section in &mut sections {
            section.sha256 = hash_str(format!("{}:{}", section.heading, bundle_chain));
        }
        let generated_at_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        Ok(ConsensusCoreManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            generated_at_ms,
            sections,
            bundles,
            catalog: self.catalog,
            proof_bundle: self.proof_bundle,
            feature_manifest_sha256,
        })
    }

    pub fn generate_and_write(
        self,
        output: impl AsRef<Path>,
    ) -> Result<ConsensusCoreManifest, ConsensusCoreManifestError> {
        let manifest = self.generate()?;
        manifest.write_to(output)?;
        Ok(manifest)
    }

    fn compute_bundle_digests(&self) -> Result<Vec<BundleDigest>, ConsensusCoreManifestError> {
        let mut digests = Vec::with_capacity(self.bundles.len());
        for artifact in &self.bundles {
            if !artifact.path.exists() {
                return Err(ConsensusCoreManifestError::MissingBundle(
                    artifact.path.clone(),
                ));
            }
            let hash = hash_file(&artifact.path)?;
            digests.push(BundleDigest {
                name: artifact.name.clone(),
                path: artifact.path.to_string_lossy().to_string(),
                sha256: hash,
            });
        }
        Ok(digests)
    }
}

#[derive(Debug, Error)]
pub enum ConsensusCoreManifestError {
    #[error("specification file missing: {0:?}")]
    MissingSpec(PathBuf),
    #[error("bundle artifact missing: {0:?}")]
    MissingBundle(PathBuf),
    #[error("no numbered sections or appendices were found in {0:?}")]
    NoSectionsFound(PathBuf),
    #[error("manifest requires at least one bundle artifact")]
    NoBundlesDefined,
    #[error("proof bundle metadata is incomplete")]
    MissingProofBundle,
    #[error("feature_manifest_sha256 must be provided")]
    MissingFeatureManifestHash,
    #[error("manifest public key must be 32-byte hex")]
    InvalidPublicKey,
    #[error("manifest signature must be 64-byte hex")]
    InvalidSignatureEncoding,
    #[error("manifest proof bundle signature did not verify")]
    SignatureVerificationFailed,
    #[error("manifest proof bundle schema mismatch (expected {expected}, found {found})")]
    UnsupportedProofBundleSchema { expected: u16, found: u16 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Time(#[from] std::time::SystemTimeError),
}

#[derive(Debug, Clone)]
struct BundleArtifact {
    name: String,
    path: PathBuf,
}

fn collect_section_hashes(contents: &str) -> Vec<SectionHash> {
    contents
        .lines()
        .filter_map(|line| parse_heading(line.trim()))
        .collect()
}

fn parse_heading(line: &str) -> Option<SectionHash> {
    if !line.starts_with("##") {
        return None;
    }
    let heading = line.trim_start_matches('#').trim();
    if heading.is_empty() {
        return None;
    }
    if !heading
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
        && !heading.starts_with("Appendix")
    {
        return None;
    }
    let identifier = if heading.starts_with("Appendix") {
        heading
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        heading.split_whitespace().next().unwrap_or(heading).into()
    };
    Some(SectionHash {
        identifier,
        heading: heading.into(),
        sha256: hash_str(heading),
    })
}

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
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

fn hash_str(input: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(input))
}

fn decode_hex_32(input: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(input)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

fn decode_hex_64(input: &str) -> Result<[u8; 64], hex::FromHexError> {
    let bytes = hex::decode(input)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}
