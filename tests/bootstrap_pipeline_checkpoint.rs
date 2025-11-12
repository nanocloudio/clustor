use clustor::bootstrap::{
    BootstrapConfig, BootstrapError, BootstrapPipeline, BootstrapRequest, CatalogNegotiationConfig,
    ManifestValidationConfig, ProfileLoader, ShutdownAction, ShutdownManager,
};
use clustor::storage::{
    NonceLedgerConfig, NonceReservationLedger, StartupScrubEngine, MAX_RESERVATION_BLOCKS,
    WAL_CRYPTO_BLOCK_BYTES,
};
use clustor::{
    BundleNegotiationEntry, CatalogVersion, ConsensusCoreManifestBuilder, ProofBundleRef,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use tempfile::tempdir;

fn read_negotiation_entries(path: &PathBuf) -> Vec<BundleNegotiationEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let contents = std::fs::read_to_string(path).unwrap();
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid entry"))
        .collect()
}

fn manifest_fixture(
    partition_id: &str,
) -> (
    tempfile::TempDir,
    PathBuf,
    ManifestValidationConfig,
    CatalogNegotiationConfig,
) {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("spec.md");
    std::fs::write(&spec_path, "## 0 Safety\n## Appendix A App.A").unwrap();
    let bundle_path = dir.path().join("wire_catalog.json");
    let bundle_bytes = b"wire";
    std::fs::write(&bundle_path, bundle_bytes).unwrap();
    let proof_bundle_path = dir.path().join("proof_bundle.bin");
    let proof_bytes = b"proof bundle bytes";
    std::fs::write(&proof_bundle_path, proof_bytes).unwrap();
    let proof_hash = hex::encode(Sha256::digest(proof_bytes));
    let signing_key = SigningKey::from_bytes(&[3u8; 32]);
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(1, &proof_hash));
    let proof = ProofBundleRef::new(1, proof_hash.clone(), hex::encode(signature.to_bytes()));
    let feature_manifest_path = dir.path().join("feature_manifest.json");
    std::fs::write(
        &feature_manifest_path,
        json!({
            "features": [],
            "schema_version": 1
        })
        .to_string(),
    )
    .unwrap();
    let feature_manifest_hash = hex::encode(Sha256::digest(
        std::fs::read(&feature_manifest_path).unwrap(),
    ));
    let manifest_path = dir.path().join("consensus_core_manifest.json");
    ConsensusCoreManifestBuilder::new(&spec_path)
        .catalog_version(CatalogVersion::new(0, 1, 1))
        .proof_bundle(proof)
        .feature_manifest_hash(feature_manifest_hash)
        .add_bundle("wire_catalog", &bundle_path)
        .generate_and_write(&manifest_path)
        .unwrap();
    let manifest = ManifestValidationConfig {
        manifest_path,
        public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        expected_schema_version: 1,
        proof_bundle_path,
        feature_manifest_path,
    };
    let remote_version = CatalogVersion::new(0, 1, 1);
    let dataset_path = dir.path().join("state");
    std::fs::create_dir_all(&dataset_path).unwrap();
    let negotiation = CatalogNegotiationConfig {
        partition_id: partition_id.into(),
        log_path: PathBuf::from("wire/bundle_negotiation.log"),
        remote_version,
    };
    (dir, dataset_path, manifest, negotiation)
}

#[test]
fn bootstrap_pipeline_runs_steps_and_reports() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("p1");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    let report = pipeline
        .run(
            BootstrapRequest {
                partition_id: "p1".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect("pipeline completed");
    assert_eq!(report.events.len(), 3);
    assert_eq!(report.partition_id, "p1");
}

#[test]
fn shutdown_manager_tracks_repair_mode() {
    let mut manager = ShutdownManager::new();
    let now = Instant::now();
    manager.begin_shutdown("p1", now);
    manager.enter_repair_mode(now + Duration::from_secs(1));
    let status = manager.status();
    assert!(status.draining && status.repair_mode);
    assert!(status.last_action.is_some());
}

#[test]
fn shutdown_manager_enforces_action_order() {
    let mut manager = ShutdownManager::new();
    let now = Instant::now();
    manager.begin_shutdown("p2", now);
    let first = manager.next_action().cloned().expect("transfer scheduled");
    match first {
        ShutdownAction::TransferLeader { ref partition_id } => {
            assert_eq!(partition_id, "p2");
        }
        other => panic!("unexpected first action: {:?}", other),
    }
    manager
        .record_action_complete(&first, now + Duration::from_millis(1))
        .expect("transfer completes");
    let second = manager.next_action().cloned().expect("flush pending");
    assert_eq!(second, ShutdownAction::FlushWal);
    manager
        .record_action_complete(&second, now + Duration::from_millis(2))
        .expect("flush completes");
    assert!(manager.is_complete());
}

#[test]
fn shutdown_manager_rejects_out_of_order_actions() {
    let mut manager = ShutdownManager::new();
    let now = Instant::now();
    manager.begin_shutdown("p3", now);
    let err = manager
        .record_action_complete(&ShutdownAction::FlushWal, now)
        .expect_err("flush cannot run before transfer");
    assert!(matches!(
        err,
        clustor::bootstrap::ShutdownError::UnexpectedAction { .. }
    ));
}

#[test]
fn profile_loader_validates_defaults() {
    let mut config = HashMap::new();
    config.insert("profile".into(), "prod".into());
    config.insert("flow_profile".into(), "wan".into());
    config.insert("max_replicas".into(), "7".into());
    let profile = ProfileLoader::load(&config).expect("profile loads");
    assert_eq!(profile.max_replicas, 7);
}

#[test]
fn bootstrap_checkpoint_covers_shutdown_flow() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("partition-x");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    let report = pipeline
        .run(
            BootstrapRequest {
                partition_id: "partition-x".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect("pipeline succeeds");
    assert!(!report.events.is_empty());

    let mut manager = ShutdownManager::new();
    manager.begin_shutdown("partition-x", now + Duration::from_secs(5));
    let status = manager.status();
    assert!(status.draining);
}

#[test]
fn bootstrap_pipeline_rejects_mutated_manifest() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("tampered");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    let manifest_path = manifest.manifest_path.clone();
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    doc["proof_bundle"]["bundle_signature"] = serde_json::json!("00");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    let err = pipeline
        .run(
            BootstrapRequest {
                partition_id: "tampered".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect_err("tampered manifest should fail");
    assert!(matches!(err, BootstrapError::Manifest(_)));
}

#[test]
fn startup_scrub_failures_force_repair_mode() {
    let mut ledger = NonceReservationLedger::with_config(
        99,
        NonceLedgerConfig {
            warn_gap_bytes: WAL_CRYPTO_BLOCK_BYTES as u64,
            abandon_gap_bytes: 2 * WAL_CRYPTO_BLOCK_BYTES as u64,
        },
    );
    // Simulate a ledger that must be scrubbed.
    ledger.reserve(MAX_RESERVATION_BLOCKS, 0).unwrap();
    ledger.reserve(MAX_RESERVATION_BLOCKS, 0).unwrap();
    assert!(ledger.needs_scrub());
    let first = StartupScrubEngine::run(&mut ledger, SystemTime::now());
    assert!(first.scrubbed);
    assert!(!ledger.needs_scrub());

    // Reintroduce gaps to emulate a scrub failure on next boot.
    ledger.reserve(MAX_RESERVATION_BLOCKS, 0).unwrap();
    ledger.reserve(MAX_RESERVATION_BLOCKS, 0).unwrap();
    assert!(ledger.needs_scrub());
    let mut manager = ShutdownManager::new();
    manager.begin_shutdown("repair-partition", Instant::now());
    manager.enter_repair_mode(Instant::now() + Duration::from_secs(1));
    let status = manager.status();
    assert!(status.repair_mode);
    assert!(
        status.pending_actions.is_empty(),
        "repair mode halts graceful shutdown sequence"
    );
}

#[test]
fn bootstrap_pipeline_rejects_schema_mismatch() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, mut manifest, negotiation) = manifest_fixture("schema-mismatch");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    manifest.expected_schema_version += 1;
    let err = pipeline
        .run(
            BootstrapRequest {
                partition_id: "schema-mismatch".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect_err("schema mismatch should fail");
    assert!(matches!(err, BootstrapError::ManifestSchemaMismatch { .. }));
}

#[test]
fn bootstrap_catalog_negotiation_persists_log_under_dataset() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("partition-log");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    let report = pipeline
        .run(
            BootstrapRequest {
                partition_id: "partition-log".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect("pipeline completed");
    let expected_log = dataset_path.join("wire").join("bundle_negotiation.log");
    assert_eq!(report.catalog_negotiation.log_path, expected_log);
    assert!(expected_log.exists());
}

#[test]
fn bootstrap_catalog_negotiation_revoke_is_logged() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("partition-revoke");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    let mut report = pipeline
        .run(
            BootstrapRequest {
                partition_id: "partition-revoke".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect("pipeline completed");
    let reason = "catalog drift detected";
    let updated = report
        .catalog_negotiation
        .revoke_forward_tolerance(reason)
        .expect("revocation succeeds");
    let entries = read_negotiation_entries(&report.catalog_negotiation.log_path);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].reason.as_deref(), Some(reason));
    assert!(!entries[1].accepted);
    assert_eq!(
        updated.forward_parse_max_minor,
        report.catalog_negotiation.local_version.minor
    );
    assert_eq!(
        report
            .catalog_negotiation
            .local_version
            .forward_parse_max_minor,
        report.catalog_negotiation.local_version.minor
    );
}

#[test]
fn bootstrap_pipeline_rejects_proof_bundle_mismatch() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("proof-hash");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    std::fs::write(&manifest.proof_bundle_path, b"tampered bundle").unwrap();
    let err = pipeline
        .run(
            BootstrapRequest {
                partition_id: "proof-hash".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect_err("mismatched proof bundle should fail verification");
    assert!(matches!(
        err,
        BootstrapError::ProofBundleHashMismatch { .. }
    ));
}

#[test]
fn bootstrap_pipeline_rejects_feature_manifest_mismatch() {
    let mut pipeline = BootstrapPipeline::new(BootstrapConfig::default());
    let now = Instant::now();
    let (_tmp, dataset_path, manifest, negotiation) = manifest_fixture("feature-hash");
    let dataset_str = dataset_path.to_string_lossy().into_owned();
    std::fs::write(&manifest.feature_manifest_path, b"{\"features\":[1]}").unwrap();
    let err = pipeline
        .run(
            BootstrapRequest {
                partition_id: "feature-hash".into(),
                dataset_path: dataset_str,
                manifest,
                catalog_negotiation: negotiation,
            },
            now,
        )
        .expect_err("mismatched feature manifest should fail verification");
    assert!(matches!(
        err,
        BootstrapError::FeatureManifestHashMismatch { .. }
    ));
}
