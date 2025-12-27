#![cfg(feature = "snapshot-crypto")]

use clustor::DataEncryptionKey;
use clustor::{
    AppendEntriesBatch, CommitEpochEntry, DedupShardDigest, HmacManifestSigner,
    SnapshotAppendEntriesCoordinator, SnapshotChunkExporter, SnapshotDeltaChainState,
    SnapshotDeltaPolicy, SnapshotDeltaPolicyError, SnapshotExportController, SnapshotExportProfile,
    SnapshotImportConfig, SnapshotImportValidationError, SnapshotImportValidator, SnapshotKind,
    SnapshotManifest, SnapshotManifestBuilder, SnapshotManifestVerifier, SnapshotThrottleState,
};
use std::collections::HashMap;
use std::io::Cursor;
use std::time::{Duration, Instant};

const FIXTURE: &str = include_str!("../fixtures/appendix_c_manifest.json");

#[test]
fn appendix_c_manifest_matches_fixture() {
    let key = DataEncryptionKey::new(11, [0xAB; 32]);
    let exporter =
        SnapshotChunkExporter::new(SnapshotExportProfile::Throughput, &key, "fixture-salt");
    let payload = vec![0x5Au8; 512];
    let chunks = exporter
        .export_reader("appendix-c", Cursor::new(payload), 128)
        .unwrap();
    let encryption = exporter.encryption();
    let mut builder = SnapshotManifestBuilder::new("appendix-c")
        .version_id(7)
        .producer("node-a", "emit-v1")
        .base(5, 42)
        .encryption(encryption.dek_epoch, encryption.iv_salt.clone())
        .add_marker("cp-proof:42")
        .ap_pane_digest("0xfeedcafe")
        .add_dedup_shard(DedupShardDigest {
            shard_id: "default".into(),
            ledger_epoch: 3,
            shard_digest: "0x11112222".into(),
        })
        .add_commit_epoch(CommitEpochEntry {
            dimension: "cp".into(),
            epoch: 9,
            checksum: "0xbead".into(),
        });
    for payload in chunks {
        builder = builder.add_chunk(payload.chunk);
    }
    let signer = HmacManifestSigner::new(b"appendix-c-key");
    let signed = builder.finalize(&signer).unwrap();
    let canonical =
        String::from_utf8(signed.canonical_json().expect("canonical manifest bytes")).unwrap();
    assert_eq!(canonical.trim(), FIXTURE.trim());
    assert_eq!(signed.signature.algorithm, "HMAC-SHA256");
    assert!(!signed.signature.value.is_empty());
}

#[test]
fn snapshot_checkpoint_large_import_enforces_throttle() {
    let key = DataEncryptionKey::new(13, [0x11; 32]);
    let exporter =
        SnapshotChunkExporter::new(SnapshotExportProfile::Throughput, &key, "checkpoint-salt");
    let payload = vec![0x42u8; 1024];
    let chunks = exporter
        .export_reader("checkpoint", Cursor::new(payload), 128)
        .unwrap();

    let encryption = exporter.encryption();
    let mut builder = SnapshotManifestBuilder::new("checkpoint")
        .version_id(2)
        .producer("node-z", "emit-v2")
        .base(7, 70)
        .encryption(encryption.dek_epoch, encryption.iv_salt.clone())
        .add_marker("recovery");
    for chunk in &chunks {
        builder = builder.add_chunk(chunk.chunk.clone());
    }
    let signer = HmacManifestSigner::new(b"checkpoint-key");
    let signed = builder.finalize(&signer).unwrap();

    let mut verifier = SnapshotManifestVerifier::new(signer, 1, 10, Duration::from_secs(60));
    verifier
        .verify(&signed, Instant::now())
        .expect("manifest passes verification");

    let config = SnapshotImportConfig::new(1_200)
        .with_resume_ratio(0.5)
        .with_bandwidth(256);
    let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(config);
    let base = Instant::now();
    let mut throttled_events = 0;
    for (idx, chunk) in chunks.iter().enumerate() {
        let now = base + Duration::from_millis((idx as u64) * 5);
        let batch = AppendEntriesBatch::new(&chunk.chunk.chunk_id, chunk.ciphertext.len(), 1);
        let envelope = coordinator.enqueue_at(batch, now).unwrap();
        if matches!(envelope.state, SnapshotThrottleState::Throttled(_)) {
            throttled_events += 1;
        }
    }
    assert!(throttled_events > 0);

    for chunk in &chunks {
        coordinator
            .complete_at(&chunk.chunk.chunk_id, base + Duration::from_secs(2))
            .unwrap();
    }
    let telemetry = coordinator.telemetry();
    assert!(telemetry.throttle_events >= 1);
    assert!(telemetry.resume_events >= 1);
    assert_eq!(coordinator.buffered_bytes(), 0);
}

#[test]
fn snapshot_checkpoint_validates_full_and_delta_chain() {
    let validator = SnapshotImportValidator::new(commit_epochs());
    let mut policy = SnapshotDeltaPolicy::new(3, 10_000, 30_000);
    policy.set_profile_capability(true);
    policy.set_cp_gate(true);

    let full = manifest_with_id("full");
    validator
        .validate_and_record(&full, 0, &mut policy)
        .expect("full manifest allowed");

    let delta = delta_manifest("delta-1", "full", 1);
    validator
        .validate_and_record(&delta, 5_000, &mut policy)
        .expect("delta allowed");

    let telemetry = policy.telemetry();
    assert_eq!(telemetry.state, SnapshotDeltaChainState::Building);
    assert_eq!(telemetry.chain_length, 1);
}

#[test]
fn snapshot_checkpoint_rejects_stale_parent_and_marks_orphaned() {
    let validator = SnapshotImportValidator::new(commit_epochs());
    let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
    policy.set_profile_capability(true);
    policy.set_cp_gate(true);

    let full = manifest_with_id("full");
    validator
        .validate_and_record(&full, 0, &mut policy)
        .expect("full manifest allowed");
    let delta = delta_manifest("delta-1", "full", 1);
    validator
        .validate_and_record(&delta, 5_000, &mut policy)
        .expect("delta allowed");

    let stale = delta_manifest("delta-stale", "unknown-parent", 2);
    let err = validator
        .validate_and_record(&stale, 6_000, &mut policy)
        .expect_err("stale parent must be rejected");
    match err {
        SnapshotImportValidationError::DeltaPolicy(
            SnapshotDeltaPolicyError::DeltaParentMismatch { .. },
        ) => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(policy.telemetry().state, SnapshotDeltaChainState::Orphaned);
}

#[test]
fn snapshot_checkpoint_export_controller_tracks_metrics() {
    let key = DataEncryptionKey::new(9, [0x22; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "telemetry");
    let payload = vec![0xCDu8; 512];
    let chunks = exporter
        .export_reader("fixture", Cursor::new(payload), 128)
        .expect("chunks");
    let now = Instant::now();
    let mut controller = SnapshotExportController::new(256, 400);
    let mut throttled = 0;
    for chunk in &chunks {
        let envelope = controller.enqueue(chunk.chunk.len as usize, now);
        if matches!(envelope.state, SnapshotThrottleState::Throttled(_)) {
            throttled += 1;
        }
        controller.complete(chunk.chunk.len as usize);
    }
    assert!(throttled >= 1);
    let telemetry = controller.telemetry();
    assert_eq!(telemetry.backlog_bytes, 0);
    assert!(telemetry.chunk_rate_bytes_per_sec <= 400);
}

fn commit_epochs() -> HashMap<String, u64> {
    let mut epochs = HashMap::new();
    epochs.insert("cp".into(), 5);
    epochs
}

fn manifest_with_id(id: &str) -> SnapshotManifest {
    let signer = HmacManifestSigner::new(b"checkpoint-manifest");
    SnapshotManifestBuilder::new(id)
        .version_id(1)
        .producer("node-x", "emit-v1")
        .base(3, 30)
        .encryption(2, "salt")
        .ap_pane_digest("0x1111")
        .add_dedup_shard(DedupShardDigest {
            shard_id: "default".into(),
            ledger_epoch: 5,
            shard_digest: "0x2222".into(),
        })
        .add_commit_epoch(CommitEpochEntry {
            dimension: "cp".into(),
            epoch: 5,
            checksum: "0x3333".into(),
        })
        .finalize(&signer)
        .unwrap()
        .manifest
}

fn delta_manifest(id: &str, parent: &str, chain_length: u32) -> SnapshotManifest {
    let mut manifest = manifest_with_id(id);
    manifest.snapshot_kind = SnapshotKind::Delta;
    manifest.delta_parent_manifest_id = Some(parent.into());
    manifest.delta_chain_length = chain_length;
    manifest
}
