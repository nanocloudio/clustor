use clustor::persistence::storage::{
    DefinitionBundle, DefinitionBundleError, DefinitionBundleStore,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn bundle(id: &str, emit: &str, payload: &[u8]) -> DefinitionBundle {
    let digest = format!("0x{}", hex::encode(Sha256::digest(payload)));
    DefinitionBundle {
        bundle_id: id.into(),
        version: 1,
        sha256: digest,
        emit_version: emit.into(),
        definition_blob: payload.to_vec(),
        warmup_recipe: "{}".into(),
        emitted_at_ms: 1_000,
    }
}

#[test]
fn definition_store_stages_and_retains_last_two() {
    let dir = tempdir().unwrap();
    let mut store = DefinitionBundleStore::new(dir.path(), "emit-v1").unwrap();
    store.stage(&bundle("b1", "emit-v1", b"one")).unwrap();
    store.stage(&bundle("b2", "emit-v1", b"two")).unwrap();
    store.stage(&bundle("b3", "emit-v1", b"three")).unwrap();

    assert!(!dir.path().join("b1.blob").exists());
    assert!(dir.path().join("b2.blob").exists());
    assert!(dir.path().join("b3.blob").exists());
    assert_eq!(
        store.retained_bundles(),
        vec!["b2".to_string(), "b3".to_string()]
    );
}

#[test]
fn definition_store_rejects_digest_and_emit_mismatches() {
    let dir = tempdir().unwrap();
    let mut store = DefinitionBundleStore::new(dir.path(), "emit-v1").unwrap();
    let mut wrong_digest = bundle("b1", "emit-v1", b"bytes");
    wrong_digest.sha256 = "0xdead".into();
    assert!(matches!(
        store.stage(&wrong_digest),
        Err(DefinitionBundleError::DigestMismatch { .. })
    ));

    let wrong_emit = bundle("b2", "emit-v2", b"bytes");
    assert!(matches!(
        store.stage(&wrong_emit),
        Err(DefinitionBundleError::EmitVersionMismatch { .. })
    ));
}

#[test]
fn definition_store_rejects_duplicates() {
    let dir = tempdir().unwrap();
    let mut store = DefinitionBundleStore::new(dir.path(), "emit-v1").unwrap();
    let bundle = bundle("b1", "emit-v1", b"bytes");
    store.stage(&bundle).unwrap();
    assert!(matches!(
        store.stage(&bundle),
        Err(DefinitionBundleError::DuplicateBundle { .. })
    ));
}
