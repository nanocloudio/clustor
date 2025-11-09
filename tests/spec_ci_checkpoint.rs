use clustor::{
    runtime_terms, CatalogVersion, ConsensusCoreManifest, ConsensusCoreManifestError,
    FeatureGateTelemetry, FeatureManifestBuilder, FixtureBundleGenerator, FixtureEntry,
    MetricsRegistry, ParkedFeatureGate, ProofBundleRef, SpecLint, SpecSelfTestHarness,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{fs, time::SystemTime};
use tempfile::tempdir;

fn emit_manifest_fixture(
    tmp: &tempfile::TempDir,
    signing_key: &SigningKey,
) -> (std::path::PathBuf, String) {
    let wire_path = tmp.path().join("wire_ci.json");
    let chunk_path = tmp.path().join("chunk_ci.json");
    fs::write(&wire_path, b"wire").unwrap();
    fs::write(&chunk_path, b"chunked").unwrap();
    let proof_hash = hex::encode(Sha256::digest(b"proof-ci"));
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(9, &proof_hash));
    let proof_bundle = ProofBundleRef::new(9, proof_hash, hex::encode(signature.to_bytes()));
    let manifest_path = tmp.path().join("ci_manifest.json");
    SpecLint::emit_consensus_core_manifest(
        "docs/specification.md",
        &[
            ("wire_catalog", wire_path.as_path()),
            ("chunked_list_schema", chunk_path.as_path()),
        ],
        CatalogVersion::new(0, 1, 1),
        proof_bundle,
        "feature-hash",
        &manifest_path,
    )
    .expect("manifest emitted");
    let verify_hex = hex::encode(signing_key.verifying_key().to_bytes());
    (manifest_path, verify_hex)
}

#[test]
fn spec_ci_checkpoint_combines_self_test_and_fixtures() {
    let tmp = tempdir().unwrap();
    let self_test_path = tmp.path().join("self_test.json");
    let fixture_path = tmp.path().join("bundle.json");

    let mut registry = MetricsRegistry::new("clustor");
    let harness =
        SpecSelfTestHarness::new().with_test("ci-self-test", "Spec §0", Box::new(|| true));
    harness
        .run(&self_test_path, &mut registry, SystemTime::now())
        .expect("self test passes");

    let entries = vec![FixtureEntry {
        name: "ci-fixture".into(),
        description: "Ensures spec drift is caught".into(),
        payload: serde_json::json!({"field": "value"}),
    }];
    FixtureBundleGenerator::generate(entries, &fixture_path).expect("fixture generated");
    let coverage = SpecLint::clause_coverage("docs/specification.md").expect("coverage");
    let wire_path = tmp.path().join("wire_catalog.json");
    let chunk_path = tmp.path().join("chunked_list_schema.json");
    let wire = SpecLint::emit_wire_catalog(&coverage, vec!["DurabilityAck".into()], &wire_path)
        .expect("wire catalog");
    let chunk =
        SpecLint::emit_chunked_list_schema(&coverage, vec!["ChunkRule".into()], &chunk_path)
            .expect("chunked list");
    assert!(self_test_path.exists() && fixture_path.exists());
    assert_eq!(wire.clause_coverage_hash, coverage.hash());
    assert_eq!(chunk.clause_coverage_hash, coverage.hash());
    let gate_telemetry = FeatureGateTelemetry::new();
    SpecLint::future_gate_coverage("docs/specification.md", gate_telemetry.entries()).unwrap();
    let manifest_path = tmp.path().join("consensus_core_manifest.json");
    let proof_hash = hex::encode(Sha256::digest(b"proof"));
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(7, &proof_hash));
    let proof_bundle = ProofBundleRef::new(7, proof_hash, hex::encode(signature.to_bytes()));
    let bundles = vec![
        ("wire_catalog", wire_path.as_path()),
        ("chunked_list_schema", chunk_path.as_path()),
    ];
    SpecLint::emit_consensus_core_manifest(
        "docs/specification.md",
        &bundles,
        CatalogVersion::new(0, 1, 1),
        proof_bundle,
        "feature-hash",
        &manifest_path,
    )
    .expect("manifest emitted");
    assert!(manifest_path.exists());
}

#[test]
fn spec_ci_checkpoint_records_parked_feature_audit() {
    let builder = FeatureManifestBuilder::new();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let manifest = builder.build(&signing_key).expect("manifest builds");
    let verifying_hex = hex::encode(signing_key.verifying_key().to_bytes());
    std::env::set_var("CLUSTOR_ENABLE_PARKED_FEATURES", "true");
    let mut gate = ParkedFeatureGate::with_manifest(manifest, &verifying_hex).unwrap();
    gate.enforce("leader_leases", "ci-runner", std::time::Instant::now())
        .expect("feature allowed");
    assert_eq!(gate.audit_log().len(), 1);
}

#[test]
fn spec_ci_checkpoint_term_registry_alignment() {
    let expected: Vec<(&str, &str)> = runtime_terms()
        .iter()
        .map(|term| (term.canonical, term.term_id))
        .collect();
    SpecLint::term_registry_check("docs/specification.md", &expected).unwrap();
}

#[test]
fn spec_ci_checkpoint_rejects_mutated_manifest_signature() {
    let tmp = tempdir().unwrap();
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let (manifest_path, verify_hex) = emit_manifest_fixture(&tmp, &signing_key);
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    doc["proof_bundle"]["bundle_signature"] = serde_json::json!("00");
    fs::write(&manifest_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    let err = ConsensusCoreManifest::load_verified(&manifest_path, 9, &verify_hex).unwrap_err();
    assert!(matches!(
        err,
        ConsensusCoreManifestError::InvalidSignatureEncoding
            | ConsensusCoreManifestError::SignatureVerificationFailed
    ));
}

#[test]
fn spec_ci_checkpoint_rejects_mutated_proof_hash() {
    let tmp = tempdir().unwrap();
    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let (manifest_path, verify_hex) = emit_manifest_fixture(&tmp, &signing_key);
    let mut doc: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    doc["proof_bundle"]["bundle_sha256"] = serde_json::json!("deadbeef");
    fs::write(&manifest_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    let err = ConsensusCoreManifest::load_verified(&manifest_path, 9, &verify_hex).unwrap_err();
    assert!(matches!(
        err,
        ConsensusCoreManifestError::SignatureVerificationFailed
    ));
}
