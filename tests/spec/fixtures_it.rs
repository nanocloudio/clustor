use clustor::feature_guard::FeatureGateTelemetry;
use clustor::replication::consensus::manifest::{CatalogVersion, ProofBundleRef};
use clustor::spec::fixtures::{FixtureBundleGenerator, FixtureEntry, FixtureError, SpecLint};
use clustor::ConsensusCoreManifest;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use tempfile::tempdir;

#[test]
fn fixture_bundle_generation_and_lint() {
    let tmp = tempdir().unwrap();
    let bundle_path = tmp.path().join("bundle.json");
    let entries = vec![FixtureEntry {
        name: "appendix-c".into(),
        description: "Snapshot manifest sample".into(),
        payload: serde_json::json!({"term": 7, "index": 42}),
    }];
    let bundle = FixtureBundleGenerator::generate(entries, &bundle_path).unwrap();
    assert!(bundle_path.exists());
    SpecLint::validate_bundle(&bundle, "docs/specification.md").unwrap();
}

#[test]
fn clause_coverage_embeds_into_artifacts() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "clause_tag_coverage = 100%\n\n[Normative] Clause A\n[Operational] Clause B",
    )
    .unwrap();
    let coverage = SpecLint::clause_coverage(&spec_path).expect("coverage");
    let wire_path = tmp.path().join("wire_catalog.json");
    let chunk_path = tmp.path().join("chunked_list_schema.json");
    let wire =
        SpecLint::emit_wire_catalog(&coverage, vec!["DurabilityAck".into()], &wire_path).unwrap();
    let chunk =
        SpecLint::emit_chunked_list_schema(&coverage, vec!["ChunkRule".into()], &chunk_path)
            .unwrap();
    assert_eq!(wire.clause_coverage_hash, coverage.hash());
    assert_eq!(chunk.clause_coverage_hash, coverage.hash());
    assert!(wire_path.exists() && chunk_path.exists());
}

#[test]
fn clause_coverage_requires_tags() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(&spec_path, "[Normative] Clause without coverage flag").unwrap();
    let err = SpecLint::clause_coverage(&spec_path).unwrap_err();
    assert!(matches!(err, FixtureError::CoverageDeclarationMissing));
}

#[test]
fn clause_coverage_rejects_mixed_tags() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "clause_tag_coverage = 100%\n\n[Normative][Operational] Illegal mix\n\n[Operational] ok",
    )
    .unwrap();
    let err = SpecLint::clause_coverage(&spec_path).unwrap_err();
    assert!(matches!(err, FixtureError::MixedClauseTags { .. }));
}

#[test]
fn clause_coverage_enforces_declared_percentage() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "clause_tag_coverage = 75%\n\n[Normative] Tagged paragraph",
    )
    .unwrap();
    let err = SpecLint::clause_coverage(&spec_path).unwrap_err();
    assert!(matches!(
        err,
        FixtureError::ClauseCoverageBelowTarget { .. }
    ));
}

#[test]
fn term_registry_check_validates_known_terms() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "#### 1.3.1 Terminology Normalization\n\
| term_id | Canonical term | Synonyms in docs | Notes |\n\
| --- | --- | --- | --- |\n\
| `TERM-0001` | `Strict` | `Strict durability`, `Strict mode` | Means per-append fdatasync. |\n",
    )
    .unwrap();
    SpecLint::term_registry_check(&spec_path, &[("Strict", "TERM-0001")]).unwrap();
}

#[test]
fn term_registry_check_surfaces_missing_terms() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "#### 1.3.1 Terminology Normalization\n\
| term_id | Canonical term | Synonyms in docs | Notes |\n\
| --- | --- | --- | --- |\n\
| `TERM-0002` | `Group-Fsync` | `Group` | Batching mode |\n",
    )
    .unwrap();
    let err = SpecLint::term_registry_check(&spec_path, &[("Strict", "TERM-0001")]).unwrap_err();
    assert!(matches!(err, FixtureError::TermMissing { .. }));
}

#[test]
fn future_gate_coverage_matches_table() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "### Feature Manifest (FutureGates)\n\
| Feature | Gate flag / CP object | Enablement predicate | Telemetry hook |\n\
| --- | --- | --- | --- |\n\
| Leader leases | feature.leases | predicate | hook |\n\
| PID auto-tuner | flow.pid_auto_tune | predicate | hook |\n\
| Incremental snapshots | snapshot.delta_chain_max | predicate | hook |\n\
| BLAKE3 Merkle leaves | integrity.hash_suite | predicate | hook |\n",
    )
    .unwrap();
    let telemetry = FeatureGateTelemetry::new();
    SpecLint::future_gate_coverage(&spec_path, telemetry.entries()).unwrap();
}

#[test]
fn future_gate_coverage_detects_missing_entries() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "### Feature Manifest (FutureGates)\n\
| Feature | Gate flag / CP object | Enablement predicate | Telemetry hook |\n\
| --- | --- | --- | --- |\n\
| Leader leases | feature.leases | predicate | hook |\n\
| PID auto-tuner | flow.pid_auto_tune | predicate | hook |\n",
    )
    .unwrap();
    let telemetry = FeatureGateTelemetry::new();
    let err = SpecLint::future_gate_coverage(&spec_path, &telemetry.entries()[1..]).unwrap_err();
    assert!(matches!(
        err,
        FixtureError::FutureGateTelemetryMissing { .. }
    ));
}

#[test]
fn consensus_core_manifest_emits_and_verifies() {
    let tmp = tempdir().unwrap();
    let spec_path = tmp.path().join("spec.md");
    std::fs::write(
        &spec_path,
        "## 0 Safety\n## 1 Architecture\n## Appendix A App.A",
    )
    .unwrap();
    let wire_path = tmp.path().join("wire_catalog.json");
    let chunk_path = tmp.path().join("chunked_list_schema.json");
    std::fs::write(&wire_path, b"wire").unwrap();
    std::fs::write(&chunk_path, b"chunked").unwrap();

    let proof_bytes = sha2::Sha256::digest(b"proof");
    let proof_hash = hex::encode(proof_bytes);
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(11, &proof_hash));
    let proof = ProofBundleRef::new(11, proof_hash.clone(), hex::encode(signature.to_bytes()));

    let bundles = vec![
        ("wire_catalog", wire_path.as_path()),
        ("chunked_list_schema", chunk_path.as_path()),
    ];
    let manifest_path = tmp.path().join("consensus_core_manifest.json");
    let manifest = SpecLint::emit_consensus_core_manifest(
        &spec_path,
        &bundles,
        CatalogVersion::new(0, 1, 2),
        proof,
        "feature-hash",
        &manifest_path,
    )
    .expect("manifest emitted");
    assert!(manifest_path.exists());
    assert_eq!(manifest.sections.len(), 3);
    let loaded = ConsensusCoreManifest::load(&manifest_path).expect("manifest loads");
    loaded
        .verify_proof_bundle_signature(&hex::encode(signing_key.verifying_key().to_bytes()))
        .expect("signature verifies");
}
