#![cfg(feature = "snapshot-crypto")]

use super::snapshot_retry::fast_retry_policy;
use clustor::persistence::snapshot::{
    SnapshotChunkExporter, SnapshotChunkImporter, SnapshotExportController, SnapshotExportProfile,
    SnapshotImportConfig, SnapshotImportError, SnapshotImportNodeBudget, SnapshotImportRetryPolicy,
    SnapshotQueueLimit, SnapshotThrottleReason, SnapshotThrottleState,
};
use clustor::storage::DataEncryptionKey;
use clustor::{SnapshotAppendEntriesCoordinator, SnapshotChunk};
use std::io::Cursor;
use std::time::{Duration, Instant};

#[test]
fn chunk_exporter_encrypts_chunks_with_aead() {
    let key = DataEncryptionKey::new(3, [9u8; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
    let caps = exporter.caps();
    let chunk_size = (caps.max_chunk_bytes / 4) as usize;
    let payload = vec![1u8; chunk_size * 3 + 10];
    let chunks = exporter
        .export_reader("snap", Cursor::new(&payload), chunk_size)
        .unwrap();
    assert_eq!(chunks.len(), 4);

    let importer = SnapshotChunkImporter::new(&key, "salt");
    let mut recovered = Vec::new();
    for payload_chunk in &chunks {
        let bytes = importer
            .import_chunk("snap", payload_chunk)
            .expect("decryptable");
        recovered.extend_from_slice(&bytes);
    }
    assert_eq!(&recovered[..payload.len()], &payload[..]);
}

#[test]
fn chunk_exporter_enforces_chunk_caps() {
    let key = DataEncryptionKey::new(5, [1u8; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
    let invalid_chunk = exporter.caps().max_chunk_bytes as usize + 1;
    let err = exporter
        .export_reader("snap", Cursor::new(vec![0u8; invalid_chunk]), invalid_chunk)
        .unwrap_err();
    assert!(matches!(
        err,
        clustor::SnapshotExportError::ChunkSizeExceeded { .. }
    ));
}

#[test]
fn chunk_exporter_enforces_total_cap() {
    let key = DataEncryptionKey::new(6, [2u8; 32]);
    let caps = clustor::SnapshotExportCaps {
        max_chunk_bytes: 4 * 1024,
        max_total_bytes: 16 * 1024,
        max_chunks: 8,
    };
    let exporter = SnapshotChunkExporter::with_caps(caps, &key, "salt");
    let total = caps.max_total_bytes as usize + 1;
    let err = exporter
        .export_reader(
            "snap",
            Cursor::new(vec![7u8; total]),
            caps.max_chunk_bytes as usize,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        clustor::SnapshotExportError::TotalBytesExceeded
    ));
}

#[test]
fn snapshot_chunk_importer_decrypts_payloads() {
    let key = DataEncryptionKey::new(12, [4u8; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
    let plaintext = vec![0xEEu8; 256];
    let chunks = exporter
        .export_reader("fixture", Cursor::new(plaintext.clone()), 64)
        .expect("chunks");
    let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
    let mut store = clustor::SnapshotStagingStore::new();
    for chunk in &chunks {
        let staged = importer
            .import_chunk("fixture", chunk)
            .expect("chunk decrypts");
        store.stage(&chunk.chunk.chunk_id, staged);
    }
    assert_eq!(store.total_bytes(), plaintext.len());
    assert_eq!(store.chunks().len(), chunks.len());
}

#[test]
fn snapshot_chunk_importer_detects_bad_digest() {
    let key = DataEncryptionKey::new(13, [8u8; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
    let chunks = exporter
        .export_reader("fixture", Cursor::new(vec![0x55u8; 64]), 64)
        .expect("chunks");
    let mut tampered = chunks[0].clone();
    tampered.chunk.digest = "0xdeadbeef".into();
    let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
    let err = importer
        .import_chunk("fixture", &tampered)
        .expect_err("digest mismatch");
    assert!(matches!(err, SnapshotImportError::DigestMismatch { .. }));
}

#[test]
fn snapshot_chunk_importer_rejects_truncated_payload() {
    let key = DataEncryptionKey::new(14, [11u8; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
    let chunks = exporter
        .export_reader("fixture", Cursor::new(vec![0xCDu8; 64]), 32)
        .expect("chunks");
    let mut truncated = chunks[0].clone();
    truncated.ciphertext.truncate(8);
    let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
    let err = importer
        .import_chunk("fixture", &truncated)
        .expect_err("reject truncated chunk");
    assert!(matches!(err, SnapshotImportError::Decrypt { .. }));
}

#[test]
fn importer_respects_retry_policy() {
    let key = DataEncryptionKey::new(1, [7u8; 32]);
    let policy = SnapshotImportRetryPolicy {
        max_retries: 0,
        base_delay: Duration::from_millis(0),
        max_delay: Duration::from_millis(0),
        time_budget: Duration::from_millis(0),
        jitter_fraction: 0.0,
    };
    let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", policy);
    let payload = clustor::SnapshotChunkPayload {
        chunk: SnapshotChunk {
            chunk_id: "chunk-1".into(),
            offset: 0,
            len: 16,
            digest: "deadbeef".into(),
        },
        ciphertext: vec![0u8; 8],
    };
    let err = importer
        .import_chunk("snap-1", &payload)
        .expect_err("import should fail");
    assert!(matches!(err, SnapshotImportError::Decrypt { .. }));
}

#[test]
fn retry_policy_honors_time_budget_deadline() {
    let policy = SnapshotImportRetryPolicy {
        max_retries: 3,
        base_delay: Duration::from_millis(50),
        max_delay: Duration::from_millis(50),
        time_budget: Duration::from_millis(10),
        jitter_fraction: 0.0,
    };
    let retry = policy.to_retry_policy();
    let mut handle = retry.handle_from(Instant::now());
    assert!(handle.next_delay().is_none());
}

#[test]
fn retry_policy_applies_jitter_fraction_bounds() {
    let policy = SnapshotImportRetryPolicy {
        max_retries: 3,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(100),
        time_budget: Duration::from_secs(1),
        jitter_fraction: 0.2,
    };
    let retry = policy.to_retry_policy();
    for _ in 0..8 {
        let mut handle = retry.handle();
        let delay = handle.next_delay().expect("delay");
        assert!(
            delay >= Duration::from_millis(80) && delay <= Duration::from_millis(120),
            "delay {:?} outside jitter bounds",
            delay
        );
    }
}

#[test]
fn snapshot_import_node_budget_limits_usage() {
    let gib = 1024_u64 * 1024 * 1024;
    let mut budget = SnapshotImportNodeBudget::new(64 * gib, 0.1, 32 * gib);
    let limit = budget.limit_bytes();
    assert_eq!(
        limit,
        clustor::SNAPSHOT_IMPORT_NODE_FLOOR_BYTES.min(32 * gib)
    );
    budget.try_reserve(4 * gib).expect("reservation fits");
    let err = budget
        .try_reserve(5 * gib)
        .expect_err("node budget exhausted");
    assert!(matches!(err, SnapshotImportError::NodePressure { .. }));
    budget.release(2 * gib);
    let telemetry = budget.telemetry();
    assert_eq!(telemetry.usage_bytes, 2 * gib);
    assert_eq!(telemetry.peak_usage_bytes, 4 * gib);
    assert_eq!(telemetry.limit_bytes, limit);
}

#[test]
fn snapshot_export_controller_enforces_backlog() {
    let mut controller = SnapshotExportController::new(256, 0);
    let now = Instant::now();
    let open = controller.enqueue(128, now);
    assert!(matches!(open.state, SnapshotThrottleState::Open));
    let throttled = controller.enqueue(200, now);
    assert!(matches!(
        throttled.state,
        SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes { .. })
    ));
    controller.complete(200);
    let recovered = controller.enqueue(64, now + Duration::from_secs(1));
    assert!(matches!(recovered.state, SnapshotThrottleState::Open));
    let telemetry = controller.telemetry();
    assert_eq!(telemetry.backlog_bytes, 192);
}

#[test]
fn snapshot_export_controller_enforces_rate_limit() {
    let mut controller = SnapshotExportController::new(1_024, 300);
    let now = Instant::now();
    let throttled = controller.enqueue(400, now);
    assert!(matches!(
        throttled.state,
        SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit { .. })
    ));
    controller.complete(400);
    let reopened = controller.enqueue(100, now + Duration::from_secs(1));
    assert!(matches!(reopened.state, SnapshotThrottleState::Open));
    let telemetry = controller.telemetry();
    assert!(telemetry.chunk_rate_bytes_per_sec <= 300);
}

#[test]
fn snapshot_append_entries_coordinator_throttles_on_capacity() {
    let mut coordinator = SnapshotAppendEntriesCoordinator::new(256);
    let envelope = coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c1", 128, 1))
        .unwrap();
    assert_eq!(envelope.buffered_bytes, 128);
    assert!(matches!(envelope.state, SnapshotThrottleState::Open));

    let envelope = coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c2", 128, 1))
        .unwrap();
    assert!(matches!(
        envelope.state,
        SnapshotThrottleState::Throttled(SnapshotThrottleReason::SnapshotImport { .. })
    ));
    assert_eq!(coordinator.buffered_bytes(), 256);

    assert_eq!(coordinator.inflight_batches().count(), 2);
    let _ = coordinator.complete("c1").unwrap();
    let final_env = coordinator.complete("c2").unwrap();
    assert!(matches!(final_env.state, SnapshotThrottleState::Open));
}

#[test]
fn snapshot_append_entries_coordinator_errors_on_unknown_chunk() {
    let mut coordinator = SnapshotAppendEntriesCoordinator::new(128);
    coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c1", 64, 1))
        .unwrap();
    let err = coordinator.complete("missing").unwrap_err();
    assert!(matches!(err, SnapshotImportError::UnknownChunk { .. }));
}

#[test]
fn snapshot_append_entries_hysteresis_and_telemetry() {
    let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
        SnapshotImportConfig::new(230).with_resume_ratio(0.5),
    );
    let now = Instant::now();
    coordinator
        .enqueue_at(clustor::AppendEntriesBatch::new("c1", 150, 1), now)
        .unwrap();
    let throttled = coordinator
        .enqueue_at(clustor::AppendEntriesBatch::new("c2", 80, 1), now)
        .unwrap();
    assert!(matches!(
        throttled.state,
        SnapshotThrottleState::Throttled(SnapshotThrottleReason::SnapshotImport { .. })
    ));

    let resumed = coordinator
        .complete_at("c1", now + Duration::from_millis(1))
        .unwrap();
    assert!(matches!(resumed.state, SnapshotThrottleState::Open));
    let telemetry = coordinator.telemetry();
    assert_eq!(telemetry.throttle_events, 1);
    assert_eq!(telemetry.resume_events, 1);
    assert_eq!(telemetry.max_buffered_bytes, 230);
    assert!(matches!(
        telemetry.last_reason,
        Some(SnapshotThrottleReason::SnapshotImport { .. })
    ));
}

#[test]
fn snapshot_append_entries_enforces_entry_limit() {
    let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
        SnapshotImportConfig::new(1_024).with_entry_limit(3),
    );
    coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c1", 64, 1))
        .unwrap();
    coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c2", 64, 1))
        .unwrap();
    let throttle = coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c3", 64, 1))
        .unwrap();
    assert!(matches!(
        throttle.state,
        SnapshotThrottleState::Throttled(SnapshotThrottleReason::SnapshotImport { .. })
    ));
    assert_eq!(coordinator.buffered_entries(), 3);

    coordinator.complete("c1").unwrap();
    let resumed = coordinator.complete("c2").unwrap();
    assert!(matches!(resumed.state, SnapshotThrottleState::Open));
}

#[test]
fn snapshot_append_entries_rate_limit_throttle() {
    let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
        SnapshotImportConfig::new(1024).with_bandwidth(256),
    );
    let now = Instant::now();
    coordinator
        .enqueue_at(clustor::AppendEntriesBatch::new("c1", 128, 1), now)
        .unwrap();
    let envelope = coordinator
        .enqueue_at(clustor::AppendEntriesBatch::new("c2", 200, 1), now)
        .unwrap();
    assert!(matches!(
        envelope.state,
        SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit { .. })
    ));
}

#[test]
fn snapshot_append_entries_queue_limit_errors_when_exceeded() {
    let mut coordinator = SnapshotAppendEntriesCoordinator::new(256);
    coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c1", 200, 1))
        .unwrap();
    let err = coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c2", 100, 1))
        .unwrap_err();
    assert!(matches!(
        err,
        SnapshotImportError::QueueLimit {
            kind: SnapshotQueueLimit::Bytes,
            ..
        }
    ));
}

#[test]
fn snapshot_append_entries_batch_limit_is_enforced() {
    let config = SnapshotImportConfig::new(512).with_batch_limit(1);
    let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(config);
    coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c1", 128, 1))
        .unwrap();
    let err = coordinator
        .enqueue(clustor::AppendEntriesBatch::new("c2", 64, 1))
        .unwrap_err();
    assert!(matches!(
        err,
        SnapshotImportError::QueueLimit {
            kind: SnapshotQueueLimit::Batches,
            ..
        }
    ));
}
