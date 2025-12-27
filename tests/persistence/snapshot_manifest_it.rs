#![cfg(feature = "snapshot-crypto")]

#[path = "../support/persistence/snapshot_export.rs"]
mod snapshot_export;
#[path = "../support/persistence/snapshot_manifest_fixtures.rs"]
mod snapshot_manifest_fixtures;
use super::snapshot_retry::fast_retry_policy;
use clustor::persistence::snapshot::{
    HmacManifestSigner, SnapshotAuthorizer, SnapshotChunkImporter, SnapshotDeltaPolicy,
    SnapshotDeltaPolicyError, SnapshotExportProfile, SnapshotImportError,
    SnapshotImportValidationError, SnapshotImportValidator, SnapshotManifestBuilder,
    SnapshotManifestVerifier,
};
use clustor::storage::{DataEncryptionKey, ManifestAuthorizationLog};
use clustor::ManifestSigner;
use snapshot_export::export_chunks;
use snapshot_manifest_fixtures::{manifest, manifest_from_chunks};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn manifest_builder_generates_stable_hash() {
    let signer = HmacManifestSigner::new(b"secret");
    let chunk = clustor::SnapshotChunk {
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
    let canonical = clustor::snapshot::canonicalize_without_signature(&signed.manifest)
        .expect("canonical manifest");
    assert!(signer.verify(&canonical, &signed.signature));
    assert!(signed.manifest.content_hash.is_some());
}

#[test]
fn snapshot_authorizer_writes_record() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("state");
    let layout = clustor::StorageLayout::new(&data_dir);
    layout.ensure().unwrap();
    let manifest_path = data_dir.join("snapshot").join("manifest.json");
    std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
    std::fs::write(&manifest_path, b"{}").unwrap();
    let log = ManifestAuthorizationLog::new(layout.paths().manifest_authorizations);
    let authorizer = SnapshotAuthorizer::new(log);
    let signer = HmacManifestSigner::new(b"secret");
    let signed = SnapshotManifestBuilder::new("mid")
        .version_id(1)
        .producer("node", "emit")
        .base(1, 10)
        .encryption(2, "salt")
        .add_chunk(clustor::SnapshotChunk {
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
fn manifest_verifier_uses_trust_cache() {
    let signer = HmacManifestSigner::new(b"secret");
    let signed = SnapshotManifestBuilder::new("m1")
        .version_id(5)
        .producer("node", "emit")
        .base(1, 10)
        .encryption(2, "salt")
        .add_chunk(clustor::SnapshotChunk {
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
        clustor::ManifestVerificationError::VersionOutOfRange { .. }
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
        clustor::ManifestVerificationError::SignatureInvalid { .. }
    ));
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
    delta_manifest.snapshot_kind = clustor::SnapshotKind::Delta;
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
    let payload = vec![0xAAu8; 2048];
    let chunks = export_chunks(
        "full-success",
        SnapshotExportProfile::Latency,
        &key,
        &payload,
        512,
    );
    let signer = HmacManifestSigner::new(b"import-flow");
    let full_manifest = manifest_from_chunks(
        "full-success",
        clustor::SnapshotKind::Full,
        None,
        0,
        &chunks,
        &signer,
        key.epoch,
        "salt",
    );

    let importer =
        clustor::SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
    let mut staging = clustor::SnapshotStagingStore::new();
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

    let delta_payload = export_chunks(
        "delta-success",
        SnapshotExportProfile::Latency,
        &key,
        &payload[..1024],
        256,
    );
    let delta_manifest = manifest_from_chunks(
        "delta-success",
        clustor::SnapshotKind::Delta,
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
    let payload = vec![0xBBu8; 1024];
    let chunks = export_chunks(
        "full-orphan",
        SnapshotExportProfile::Latency,
        &key,
        &payload,
        512,
    );
    let signer = HmacManifestSigner::new(b"import-orphan");
    let full_manifest = manifest_from_chunks(
        "full-orphan",
        clustor::SnapshotKind::Full,
        None,
        0,
        &chunks,
        &signer,
        key.epoch,
        "salt",
    );

    let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
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
        clustor::SnapshotKind::Delta,
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
