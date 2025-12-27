use clustor::replication::consensus::{
    CatalogVersion, ConsensusCoreManifest, ConsensusCoreManifestBuilder,
    ConsensusCoreManifestError, ProofBundleRef,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[test]
fn manifest_builder_hashes_sections_and_bundles() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("spec.md");
    let spec_body = r#"
# Clustor Spec
## 0  consensus core
Body
## 1  Architecture
body
## Appendix A App.A – Extras
content
"#;
    std::fs::write(&spec_path, spec_body).unwrap();

    let wire_catalog = dir.path().join("wire_catalog.json");
    let chunked_list = dir.path().join("chunked_list.json");
    std::fs::write(&wire_catalog, b"wire").unwrap();
    std::fs::write(&chunked_list, b"chunked").unwrap();

    let builder = ConsensusCoreManifestBuilder::new(&spec_path)
        .catalog_version(CatalogVersion::new(0, 1, 2))
        .proof_bundle(ProofBundleRef::new(7, "deadbeef", "cafebabe"))
        .feature_manifest_hash("feature-hash")
        .add_bundle("wire_catalog", &wire_catalog)
        .add_bundle("chunked_list_schema", &chunked_list);

    let manifest = builder.generate().expect("manifest builds");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.sections.len(), 3);
    assert_eq!(manifest.bundles.len(), 2);
    assert!(manifest
        .sections
        .iter()
        .all(|section| !section.sha256.is_empty()));
    assert_eq!(manifest.catalog.forward_parse_max_minor, 2);
    assert_eq!(manifest.proof_bundle.schema_version, 7);
}

#[test]
fn manifest_builder_requires_sections_and_bundles() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("spec.md");
    std::fs::write(&spec_path, "# heading only").unwrap();
    let builder = ConsensusCoreManifestBuilder::new(&spec_path)
        .catalog_version(CatalogVersion::new(0, 1, 1))
        .proof_bundle(ProofBundleRef::new(1, "hash", "sig"))
        .feature_manifest_hash("feature-hash");
    let err = builder.generate().unwrap_err();
    assert!(matches!(err, ConsensusCoreManifestError::NoBundlesDefined));
}

#[test]
fn manifest_verifies_ed25519_signature() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("spec.md");
    std::fs::write(&spec_path, "## 0 Safety\n## Appendix A App.A").unwrap();
    let bundle_path = dir.path().join("wire.json");
    let bundle_bytes = b"wire";
    std::fs::write(&bundle_path, bundle_bytes).unwrap();
    let bundle_hash = hex::encode(Sha256::digest(bundle_bytes));
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(5, &bundle_hash));
    let proof = ProofBundleRef::new(5, bundle_hash.clone(), hex::encode(signature.to_bytes()));
    let manifest_path = dir.path().join("manifest.json");
    ConsensusCoreManifestBuilder::new(&spec_path)
        .catalog_version(CatalogVersion::new(0, 1, 2))
        .proof_bundle(proof)
        .feature_manifest_hash("hash")
        .add_bundle("wire_catalog", &bundle_path)
        .generate_and_write(&manifest_path)
        .unwrap();

    let loaded = ConsensusCoreManifest::load(&manifest_path).unwrap();
    loaded
        .verify_proof_bundle_signature(&hex::encode(signing_key.verifying_key().to_bytes()))
        .unwrap();
}

#[test]
fn manifest_signature_failure_surfaces_error() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("spec.md");
    std::fs::write(&spec_path, "## 0 Safety\n## Appendix A").unwrap();
    let bundle_path = dir.path().join("wire.json");
    std::fs::write(&bundle_path, b"wire").unwrap();
    let bundle_hash = hex::encode(Sha256::digest(b"wire"));
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(1, &bundle_hash));
    let proof = ProofBundleRef::new(1, bundle_hash, hex::encode(signature.to_bytes()));
    let manifest_path = dir.path().join("manifest.json");
    ConsensusCoreManifestBuilder::new(&spec_path)
        .catalog_version(CatalogVersion::new(0, 1, 1))
        .proof_bundle(proof)
        .feature_manifest_hash("hash")
        .add_bundle("wire_catalog", &bundle_path)
        .generate_and_write(&manifest_path)
        .unwrap();
    let mut manifest = ConsensusCoreManifest::load(&manifest_path).unwrap();
    manifest.proof_bundle.bundle_signature = "00".repeat(64);
    let err = manifest
        .verify_proof_bundle_signature(&hex::encode(signing_key.verifying_key().to_bytes()))
        .unwrap_err();
    assert!(matches!(
        err,
        ConsensusCoreManifestError::InvalidSignatureEncoding
            | ConsensusCoreManifestError::SignatureVerificationFailed
    ));
}

#[test]
fn load_verified_enforces_schema_and_signature() {
    let dir = tempdir().unwrap();
    let spec_path = dir.path().join("spec.md");
    std::fs::write(&spec_path, "## 0 Safety\n## Appendix A App.A").unwrap();
    let bundle_path = dir.path().join("wire.json");
    std::fs::write(&bundle_path, b"wire").unwrap();
    let bundle_hash = hex::encode(Sha256::digest(b"wire"));
    let signing_key = SigningKey::from_bytes(&[10u8; 32]);
    let signature = signing_key.sign(&ProofBundleRef::signing_message_for(4, &bundle_hash));
    let proof = ProofBundleRef::new(4, bundle_hash.clone(), hex::encode(signature.to_bytes()));
    let manifest_path = dir.path().join("manifest.json");
    ConsensusCoreManifestBuilder::new(&spec_path)
        .catalog_version(CatalogVersion::new(0, 1, 1))
        .proof_bundle(proof)
        .feature_manifest_hash("hash")
        .add_bundle("wire_catalog", &bundle_path)
        .generate_and_write(&manifest_path)
        .unwrap();

    let verify_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let manifest = ConsensusCoreManifest::load_verified(&manifest_path, 4, &verify_hex).unwrap();
    assert_eq!(manifest.proof_bundle.schema_version, 4);

    let err = ConsensusCoreManifest::load_verified(&manifest_path, 5, &verify_hex).unwrap_err();
    assert!(matches!(
        err,
        ConsensusCoreManifestError::UnsupportedProofBundleSchema {
            expected: 5,
            found: 4
        }
    ));
}
