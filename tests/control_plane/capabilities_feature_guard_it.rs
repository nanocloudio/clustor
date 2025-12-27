use clustor::control_plane::capabilities::feature_guard::{
    future_gates, FeatureGateState, FeatureManifest, FeatureManifestBuilder, FeatureManifestError,
    ParkedFeatureGate,
};
use ed25519_dalek::SigningKey;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tempfile::tempdir;

fn sample_manifest() -> (FeatureManifest, String) {
    let builder = FeatureManifestBuilder::new();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let manifest = builder.build(&signing_key).expect("manifest builds");
    let verifying_hex = hex::encode(signing_key.verifying_key().to_bytes());
    (manifest, verifying_hex)
}

#[test]
fn feature_manifest_builder_signs_entries() {
    let (manifest, verifying_hex) = sample_manifest();
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("feature_manifest.json");
    manifest.write_to(&path).unwrap();
    assert!(path.exists());
    let loaded = FeatureManifest::load(&path).expect("manifest loads");
    loaded
        .verify_signature(&verifying_hex)
        .expect("signature verifies");
    let matrix = loaded.capability_matrix().expect("matrix builds");
    assert_eq!(matrix.entries().len(), future_gates().len());
    assert!(matrix
        .entries()
        .iter()
        .all(|entry| entry.gate_state == FeatureGateState::Disabled));
}

#[test]
fn capability_matrix_respects_gate_state_overrides() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let manifest = FeatureManifestBuilder::new()
        .with_gate_state("leader_leases", FeatureGateState::Enabled)
        .build(&signing_key)
        .expect("manifest builds");
    let matrix = manifest.capability_matrix().expect("matrix builds");
    let leader = matrix.entry("leader_leases").expect("leader entry");
    assert_eq!(leader.gate_state, FeatureGateState::Enabled);
}

#[test]
fn capability_matrix_detects_missing_gate() {
    let (mut manifest, _) = sample_manifest();
    manifest.features.pop();
    let err = manifest.capability_matrix().unwrap_err();
    assert!(matches!(err, FeatureManifestError::GateMissing { .. }));
}

#[test]
fn capability_matrix_detects_digest_drift() {
    let (mut manifest, _) = sample_manifest();
    manifest.features[0].predicate_digest = "0xdeadbeef".into();
    let err = manifest.capability_matrix().unwrap_err();
    assert!(matches!(
        err,
        FeatureManifestError::PredicateDigestMismatch { .. }
    ));
}

#[test]
fn gate_blocks_when_env_missing() {
    let _lock = env_lock().lock().unwrap();
    let previous = env::var("CLUSTOR_ENABLE_PARKED_FEATURES").ok();
    env::remove_var("CLUSTOR_ENABLE_PARKED_FEATURES");
    let (manifest, verifying_hex) = sample_manifest();
    let mut gate = ParkedFeatureGate::with_manifest(manifest, &verifying_hex).unwrap();
    assert!(gate
        .enforce("leader_leases", "tester", Instant::now())
        .is_err());
    restore_env(previous);
}

#[test]
fn gate_allows_when_env_enabled() {
    let _lock = env_lock().lock().unwrap();
    let previous = env::var("CLUSTOR_ENABLE_PARKED_FEATURES").ok();
    env::set_var("CLUSTOR_ENABLE_PARKED_FEATURES", "1");
    let (manifest, verifying_hex) = sample_manifest();
    let mut gate = ParkedFeatureGate::with_manifest(manifest, &verifying_hex).unwrap();
    restore_env(previous);
    assert!(gate.allowed_features().unwrap().contains("leader_leases"));
    gate.enforce("leader_leases", "tester", Instant::now())
        .expect("manifest allows feature");
    assert_eq!(gate.audit_log().len(), 1);
}

#[test]
fn gate_blocks_unknown_feature_even_with_manifest() {
    let _lock = env_lock().lock().unwrap();
    let previous = env::var("CLUSTOR_ENABLE_PARKED_FEATURES").ok();
    env::set_var("CLUSTOR_ENABLE_PARKED_FEATURES", "1");
    let (manifest, verifying_hex) = sample_manifest();
    let mut gate = ParkedFeatureGate::with_manifest(manifest, &verifying_hex).unwrap();
    restore_env(previous);
    assert!(gate
        .enforce("unknown_feature", "tester", Instant::now())
        .is_err());
}

#[test]
fn manifest_verification_fails_with_wrong_key() {
    let (manifest, _) = sample_manifest();
    let wrong_key = SigningKey::from_bytes(&[3u8; 32]);
    let wrong_hex = hex::encode(wrong_key.verifying_key().to_bytes());
    let err = manifest
        .verify_signature(&wrong_hex)
        .expect_err("verification should fail");
    assert!(matches!(
        err,
        FeatureManifestError::SignatureVerificationFailed
    ));
}

#[test]
fn gate_rejects_manifest_with_bad_signature() {
    let _lock = env_lock().lock().unwrap();
    let previous = env::var("CLUSTOR_ENABLE_PARKED_FEATURES").ok();
    env::set_var("CLUSTOR_ENABLE_PARKED_FEATURES", "1");
    let (manifest, _) = sample_manifest();
    let wrong_key = SigningKey::from_bytes(&[5u8; 32]);
    let wrong_hex = hex::encode(wrong_key.verifying_key().to_bytes());
    assert!(ParkedFeatureGate::with_manifest(manifest, &wrong_hex).is_err());
    restore_env(previous);
}

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn restore_env(previous: Option<String>) {
    if let Some(value) = previous {
        env::set_var("CLUSTOR_ENABLE_PARKED_FEATURES", value);
    } else {
        env::remove_var("CLUSTOR_ENABLE_PARKED_FEATURES");
    }
}
