use clustor::spec_fixtures::{ClauseCoverageReport, SpecLint};
use clustor::{
    CatalogVersion, ConsensusCoreManifestBuilder, FeatureManifestBuilder, ProofBundleRef,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const DEFAULT_PROOF_BUNDLE_PATH: &str = "docs/proofs/dev_proof_bundle.bin";
const DEFAULT_RELEASE_AUTOMATION_KEY: &str = "keys/dev_release_automation_ed25519.sk";
const FEATURE_MANIFEST_FILE: &str = "feature_manifest.json";
const SAFETY_KERNEL_MANIFEST_FILE: &str = "safety_kernel_manifest.json";
const CHUNKED_LIST_SCHEMA_FILE: &str = "chunked_list_schema.json";
const PROOF_BUNDLE_SCHEMA_VERSION: u16 = 1;

fn main() -> Result<(), Box<dyn Error>> {
    let spec_path = Path::new("docs/specification.md");
    let artifacts_dir = Path::new("artifacts");
    fs::create_dir_all(artifacts_dir)?;

    let coverage = SpecLint::clause_coverage(spec_path)?;

    emit_wire_catalog(&coverage, artifacts_dir)?;
    emit_chunked_list_schema(&coverage, artifacts_dir)?;
    emit_system_log_catalog(&coverage, artifacts_dir)?;
    emit_metrics_buckets(&coverage, artifacts_dir)?;
    emit_clause_map(&coverage, artifacts_dir)?;
    let signing_key = load_release_signing_key()?;
    let feature_manifest_path = emit_feature_manifest(artifacts_dir, &signing_key)?;
    emit_safety_kernel_manifest(
        spec_path,
        artifacts_dir,
        &feature_manifest_path,
        &signing_key,
    )?;

    println!("Regenerated spec artifacts in {}", artifacts_dir.display());
    Ok(())
}

fn emit_wire_catalog(
    coverage: &ClauseCoverageReport,
    out_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let messages = vec![
        "MembershipChange",
        "MembershipRollback",
        "DurabilityTransition",
        "FenceCommit",
        "DurabilityAck",
        "PreVoteResponse",
        "RoutingEpochMismatch",
        "ModeConflict",
        "ThrottleEnvelope",
        "WhyNotLeader",
        "WhyDiskBlocked",
        "WhySnapshotBlocked",
        "WhyCreditZero",
        "OverrideLedgerEntry",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();
    let path = out_dir.join("wire_catalog.json");
    SpecLint::emit_wire_catalog(coverage, messages, path)?;
    Ok(())
}

fn emit_chunked_list_schema(
    coverage: &ClauseCoverageReport,
    out_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let rules = chunked_list_rules();
    let path = out_dir.join(CHUNKED_LIST_SCHEMA_FILE);
    SpecLint::emit_chunked_list_schema(coverage, rules, path)?;
    Ok(())
}

fn emit_system_log_catalog(
    coverage: &ClauseCoverageReport,
    out_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let entries = vec![
        SystemLogCatalogEntry::new(
            "MembershipChange",
            "0x01",
            vec!["old_members", "new_members", "routing_epoch"],
        ),
        SystemLogCatalogEntry::new(
            "MembershipRollback",
            "0x02",
            vec!["reason", "failing_nodes", "override_ref"],
        ),
        SystemLogCatalogEntry::new(
            "DurabilityTransition",
            "0x03",
            vec![
                "from_mode",
                "to_mode",
                "effective_index",
                "durability_mode_epoch",
            ],
        ),
        SystemLogCatalogEntry::new(
            "FenceCommit",
            "0x04",
            vec!["fence_epoch", "manifest_id", "dr_cluster_id"],
        ),
        SystemLogCatalogEntry::new(
            "DefineActivate",
            "0x05",
            vec!["bundle_id", "barrier_id", "partitions", "readiness_digest"],
        ),
    ];
    let artifact = SystemLogCatalogArtifact {
        schema_version: 1,
        clause_coverage_hash: coverage.clause_coverage_hash.clone(),
        entries,
    };
    write_json(&artifact, out_dir.join("system_log_catalog.json"))
}

fn emit_metrics_buckets(
    coverage: &ClauseCoverageReport,
    out_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let buckets = vec![
        MetricBucket::new(
            "clustor.wal.fsync_latency_ms",
            "ms",
            vec![
                0.25, 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 10.0, 15.0, 20.0, 30.0, 40.0, 60.0, 80.0, 100.0,
            ],
            "WAL fsync latency buckets for strict durability guardrails.",
        ),
        MetricBucket::new(
            "clustor.raft.commit_latency_ms",
            "ms",
            vec![
                0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 10.0, 15.0, 20.0, 30.0, 40.0, 60.0, 80.0, 100.0,
            ],
            "Per-partition Raft commit latency histogram.",
        ),
        MetricBucket::new(
            "clustor.snapshot.transfer_seconds",
            "s",
            vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0],
            "Snapshot transfer duration buckets.",
        ),
        MetricBucket::new(
            "flow.apply_batch_latency_ms",
            "ms",
            vec![0.25, 0.5, 1.0, 2.0, 4.0, 6.0, 8.0, 10.0],
            "Apply pipeline batch latency buckets.",
        ),
    ];
    let artifact = MetricsBucketArtifact {
        schema_version: 1,
        clause_coverage_hash: coverage.clause_coverage_hash.clone(),
        buckets,
    };
    write_json(&artifact, out_dir.join("metrics_buckets.json"))
}

fn emit_clause_map(coverage: &ClauseCoverageReport, out_dir: &Path) -> Result<(), Box<dyn Error>> {
    let clauses = vec![
        ClauseMapEntry::new(
            "§0.3 PreVoteResponse layout",
            "wire.prevote_response_v1",
            "Hex dump verifies the mandatory floor and optional tail byte.",
        ),
        ClauseMapEntry::new(
            "§3.3 ReadIndex proof equality",
            "consistency.read_index_proof_match",
            "Simulator asserts equality between cached CP proof and wal/durability.log.",
        ),
        ClauseMapEntry::new(
            "§6.5 Ledger replay truncation",
            "durability.ledger_replay_strict",
            "Synthetic log ensures truncation stops at the last good record.",
        ),
        ClauseMapEntry::new(
            "§9.2 Segment MAC derivation",
            "integrity.segment_mac_v1",
            "Matches the worked example MAC bytes and rejects byte-order drift.",
        ),
    ];
    let artifact = ClauseMapArtifact {
        schema_version: 1,
        clause_coverage_hash: coverage.clause_coverage_hash.clone(),
        clauses,
    };
    write_json(&artifact, out_dir.join("fixtures.clause_map.json"))
}

fn emit_feature_manifest(
    out_dir: &Path,
    signing_key: &SigningKey,
) -> Result<PathBuf, Box<dyn Error>> {
    let manifest = FeatureManifestBuilder::new()
        .build(signing_key)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    let path = out_dir.join(FEATURE_MANIFEST_FILE);
    manifest
        .write_to(&path)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    Ok(path)
}

fn emit_safety_kernel_manifest(
    spec_path: &Path,
    artifacts_dir: &Path,
    feature_manifest_path: &Path,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn Error>> {
    let proof_bundle_path =
        env::var("SAFETY_KERNEL_PROOF_BUNDLE").unwrap_or_else(|_| DEFAULT_PROOF_BUNDLE_PATH.into());
    let proof_bundle_path = Path::new(&proof_bundle_path);
    if !proof_bundle_path.exists() {
        return Err(format!(
            "proof bundle path {} does not exist",
            proof_bundle_path.display()
        )
        .into());
    }
    let proof_bundle_hash = sha256_file(proof_bundle_path)?;
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(
        PROOF_BUNDLE_SCHEMA_VERSION,
        &proof_bundle_hash,
    ));
    let proof_bundle = ProofBundleRef::new(
        PROOF_BUNDLE_SCHEMA_VERSION,
        proof_bundle_hash,
        hex::encode(signature.to_bytes()),
    );
    let feature_manifest_hash = sha256_file(feature_manifest_path)?;

    let manifest_path = artifacts_dir.join(SAFETY_KERNEL_MANIFEST_FILE);
    let chunked_list_path = artifacts_dir.join(CHUNKED_LIST_SCHEMA_FILE);
    let wire_catalog_path = artifacts_dir.join("wire_catalog.json");
    let system_log_path = artifacts_dir.join("system_log_catalog.json");
    let metrics_path = artifacts_dir.join("metrics_buckets.json");

    let bundles = [
        ("wire_catalog", wire_catalog_path),
        ("chunked_list_schema", chunked_list_path),
        ("system_log_catalog", system_log_path),
        ("metrics_buckets", metrics_path),
    ];

    let builder = bundles.iter().fold(
        ConsensusCoreManifestBuilder::new(spec_path)
            .catalog_version(CatalogVersion::new(0, 1, 1))
            .proof_bundle(proof_bundle)
            .feature_manifest_hash(feature_manifest_hash),
        |builder, (name, path)| builder.add_bundle(*name, path.clone()),
    );

    builder
        .generate_and_write(&manifest_path)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    Ok(())
}

fn load_release_signing_key() -> Result<SigningKey, Box<dyn Error>> {
    let path = env::var("SAFETY_KERNEL_RELEASE_KEY")
        .unwrap_or_else(|_| DEFAULT_RELEASE_AUTOMATION_KEY.into());
    let contents = fs::read_to_string(&path)?;
    let bytes = hex::decode(contents.trim())
        .map_err(|e| format!("failed to decode signing key {}: {e}", path))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("signing key {} must be 32 bytes", path))?;
    Ok(SigningKey::from_bytes(&array))
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let mut file = fs::File::open(path)?;
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

fn chunked_list_rules() -> Vec<String> {
    vec![
        "SnapshotTransfer.chunks",
        "ThrottleEnvelope.events",
        "ProofBundle.entries",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

fn write_json<T: Serialize>(value: &T, path: PathBuf) -> Result<(), Box<dyn Error>> {
    let payload = serde_json::to_vec_pretty(value)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, payload)?;
    Ok(())
}

#[derive(Serialize)]
struct SystemLogCatalogArtifact {
    schema_version: u32,
    clause_coverage_hash: String,
    entries: Vec<SystemLogCatalogEntry>,
}

#[derive(Serialize)]
struct SystemLogCatalogEntry {
    name: &'static str,
    wire_id: &'static str,
    fields: Vec<&'static str>,
}

impl SystemLogCatalogEntry {
    fn new(name: &'static str, wire_id: &'static str, fields: Vec<&'static str>) -> Self {
        Self {
            name,
            wire_id,
            fields,
        }
    }
}

#[derive(Serialize)]
struct MetricsBucketArtifact {
    schema_version: u32,
    clause_coverage_hash: String,
    buckets: Vec<MetricBucket>,
}

#[derive(Serialize)]
struct MetricBucket {
    metric: &'static str,
    unit: &'static str,
    bounds: Vec<f64>,
    notes: &'static str,
}

impl MetricBucket {
    fn new(
        metric: &'static str,
        unit: &'static str,
        bounds: Vec<f64>,
        notes: &'static str,
    ) -> Self {
        Self {
            metric,
            unit,
            bounds,
            notes,
        }
    }
}

#[derive(Serialize)]
struct ClauseMapArtifact {
    schema_version: u32,
    clause_coverage_hash: String,
    clauses: Vec<ClauseMapEntry>,
}

#[derive(Serialize)]
struct ClauseMapEntry {
    clause: &'static str,
    fixture_id: &'static str,
    notes: &'static str,
}

impl ClauseMapEntry {
    fn new(clause: &'static str, fixture_id: &'static str, notes: &'static str) -> Self {
        Self {
            clause,
            fixture_id,
            notes,
        }
    }
}
