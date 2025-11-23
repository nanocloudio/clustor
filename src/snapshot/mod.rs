mod manifest;
mod pipeline;
mod telemetry;
mod throttle;
mod types;

use types::*;

pub use manifest::*;
pub use pipeline::*;
pub use telemetry::*;
pub use throttle::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::StrictFallbackState;
    use crate::storage::{DataEncryptionKey, ManifestAuthorizationLog, StorageLayout};
    use std::collections::HashMap;
    use std::fs;
    use std::io::Cursor;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn fast_retry_policy() -> SnapshotImportRetryPolicy {
        SnapshotImportRetryPolicy {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            time_budget: Duration::ZERO,
            jitter_fraction: 0.0,
        }
    }

    #[test]
    fn manifest_builder_generates_stable_hash() {
        let signer = HmacManifestSigner::new(b"secret");
        let chunk = SnapshotChunk {
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
        let canonical = super::manifest::canonicalize_without_signature(&signed.manifest).unwrap();
        assert!(signer.verify(&canonical, &signed.signature));
        assert!(signed.manifest.content_hash.is_some());
    }

    #[test]
    fn snapshot_authorizer_writes_record() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("state");
        let layout = StorageLayout::new(&data_dir);
        layout.ensure().unwrap();
        let manifest_path = data_dir.join("snapshot").join("manifest.json");
        fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        fs::write(&manifest_path, b"{}").unwrap();
        let log = ManifestAuthorizationLog::new(layout.paths().manifest_authorizations);
        let authorizer = SnapshotAuthorizer::new(log);
        let signer = HmacManifestSigner::new(b"secret");
        let signed = SnapshotManifestBuilder::new("mid")
            .version_id(1)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(2, "salt")
            .add_chunk(SnapshotChunk {
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
        assert!(matches!(err, SnapshotExportError::ChunkSizeExceeded { .. }));
    }

    #[test]
    fn chunk_exporter_enforces_total_cap() {
        let key = DataEncryptionKey::new(6, [2u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Wan, &key, "salt");
        let caps = exporter.caps();
        let total = caps.max_total_bytes as usize + 1;
        let err = exporter
            .export_reader(
                "snap",
                Cursor::new(vec![7u8; total]),
                caps.max_chunk_bytes as usize,
            )
            .unwrap_err();
        assert!(matches!(err, SnapshotExportError::TotalBytesExceeded));
    }

    #[test]
    fn manifest_verifier_uses_trust_cache() {
        let signer = HmacManifestSigner::new(b"secret");
        let signed = SnapshotManifestBuilder::new("m1")
            .version_id(5)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(2, "salt")
            .add_chunk(SnapshotChunk {
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
            ManifestVerificationError::VersionOutOfRange { .. }
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
            ManifestVerificationError::SignatureInvalid { .. }
        ));
    }

    #[test]
    fn append_entries_coordinator_throttles_on_capacity() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::new(256);
        let envelope = coordinator
            .enqueue(AppendEntriesBatch::new("c1", 128, 1))
            .unwrap();
        assert_eq!(envelope.buffered_bytes, 128);
        assert!(matches!(envelope.state, SnapshotThrottleState::Open));

        let envelope = coordinator
            .enqueue(AppendEntriesBatch::new("c2", 128, 1))
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
    fn append_entries_coordinator_errors_on_unknown_chunk() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::new(128);
        coordinator
            .enqueue(AppendEntriesBatch::new("c1", 64, 1))
            .unwrap();
        let err = coordinator.complete("missing").unwrap_err();
        assert!(matches!(err, SnapshotImportError::UnknownChunk { .. }));
    }

    #[test]
    fn append_entries_hysteresis_and_telemetry() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
            SnapshotImportConfig::new(230).with_resume_ratio(0.5),
        );
        let now = Instant::now();
        coordinator
            .enqueue_at(AppendEntriesBatch::new("c1", 150, 1), now)
            .unwrap();
        let throttled = coordinator
            .enqueue_at(AppendEntriesBatch::new("c2", 80, 1), now)
            .unwrap();
        assert!(matches!(
            throttled.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::SnapshotImport { .. })
        ));

        // Removing 150 bytes drops buffered to 80 which is below resume threshold.
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
    fn append_entries_enforces_entry_limit() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
            SnapshotImportConfig::new(1_024).with_entry_limit(3),
        );
        coordinator
            .enqueue(AppendEntriesBatch::new("c1", 64, 1))
            .unwrap();
        coordinator
            .enqueue(AppendEntriesBatch::new("c2", 64, 1))
            .unwrap();
        let throttle = coordinator
            .enqueue(AppendEntriesBatch::new("c3", 64, 1))
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
    fn append_entries_rate_limit_throttle() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(
            SnapshotImportConfig::new(1024).with_bandwidth(256),
        );
        let now = Instant::now();
        coordinator
            .enqueue_at(AppendEntriesBatch::new("c1", 128, 1), now)
            .unwrap();
        let envelope = coordinator
            .enqueue_at(AppendEntriesBatch::new("c2", 200, 1), now)
            .unwrap();
        assert!(matches!(
            envelope.state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit { .. })
        ));
    }

    #[test]
    fn append_entries_queue_limit_errors_when_exceeded() {
        let mut coordinator = SnapshotAppendEntriesCoordinator::new(256);
        coordinator
            .enqueue(AppendEntriesBatch::new("c1", 200, 1))
            .unwrap();
        let err = coordinator
            .enqueue(AppendEntriesBatch::new("c2", 100, 1))
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
    fn append_entries_batch_limit_is_enforced() {
        let config = SnapshotImportConfig::new(512).with_batch_limit(1);
        let mut coordinator = SnapshotAppendEntriesCoordinator::with_config(config);
        coordinator
            .enqueue(AppendEntriesBatch::new("c1", 128, 1))
            .unwrap();
        let err = coordinator
            .enqueue(AppendEntriesBatch::new("c2", 64, 1))
            .unwrap_err();
        assert!(matches!(
            err,
            SnapshotImportError::QueueLimit {
                kind: SnapshotQueueLimit::Batches,
                ..
            }
        ));
    }

    #[test]
    fn snapshot_import_node_budget_limits_usage() {
        let gib = 1024_u64 * 1024 * 1024;
        let mut budget = SnapshotImportNodeBudget::new(64 * gib, 0.1, 32 * gib);
        let limit = budget.limit_bytes();
        assert_eq!(limit, SNAPSHOT_IMPORT_NODE_FLOOR_BYTES.min(32 * gib));
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
    fn snapshot_chunk_importer_decrypts_payloads() {
        let key = DataEncryptionKey::new(12, [4u8; 32]);
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let plaintext = vec![0xEEu8; 256];
        let chunks = exporter
            .export_reader("fixture", Cursor::new(plaintext.clone()), 64)
            .expect("chunks");
        let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
        let mut store = SnapshotStagingStore::new();
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

    fn readiness() -> SnapshotReadiness {
        SnapshotReadiness {
            manifest_id: "m1".into(),
            base_index: 100,
            content_hash: "0xdeadbeef".into(),
            applied_index_snapshot: 90,
            last_advertised_ready_index: 100,
            manifest_generated_ms: 1_000,
        }
    }

    fn request(snapshot_only: bool, state: StrictFallbackState) -> SnapshotReadRequest {
        SnapshotReadRequest {
            partition_id: "p1".into(),
            read_semantics_snapshot_only: snapshot_only,
            strict_state: state,
            cp_cache_age_ms: 42,
        }
    }

    fn manifest() -> SnapshotManifest {
        let signer = HmacManifestSigner::new(b"manifest");
        SnapshotManifestBuilder::new("m1")
            .version_id(1)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(2, "salt")
            .ap_pane_digest("0x1")
            .add_dedup_shard(DedupShardDigest {
                shard_id: "default".into(),
                ledger_epoch: 1,
                shard_digest: "0xaaa".into(),
            })
            .add_commit_epoch(CommitEpochEntry {
                dimension: "cp".into(),
                epoch: 5,
                checksum: "0xbeef".into(),
            })
            .finalize(&signer)
            .unwrap()
            .manifest
    }

    fn full_delta(id: &str, parent: &str, chain_length: u32) -> SnapshotManifest {
        let mut delta = manifest();
        delta.manifest_id = id.into();
        delta.snapshot_kind = SnapshotKind::Delta;
        delta.delta_parent_manifest_id = Some(parent.into());
        delta.delta_chain_length = chain_length;
        delta
    }

    #[allow(clippy::too_many_arguments)]
    fn manifest_from_chunks(
        manifest_id: &str,
        kind: SnapshotKind,
        parent: Option<&str>,
        chain_length: u32,
        chunks: &[SnapshotChunkPayload],
        signer: &HmacManifestSigner,
        dek_epoch: u32,
        iv_salt: &str,
    ) -> SnapshotManifest {
        let mut builder = SnapshotManifestBuilder::new(manifest_id)
            .version_id(1)
            .producer("node", "emit")
            .base(1, 10)
            .encryption(dek_epoch, iv_salt.to_owned())
            .ap_pane_digest("0x1")
            .add_dedup_shard(DedupShardDigest {
                shard_id: "default".into(),
                ledger_epoch: 1,
                shard_digest: "0xaaa".into(),
            })
            .add_commit_epoch(CommitEpochEntry {
                dimension: "cp".into(),
                epoch: 5,
                checksum: "0xbeef".into(),
            })
            .snapshot_kind(kind);
        if let Some(parent_id) = parent {
            builder = builder.delta_parent(parent_id, chain_length);
        }
        for chunk in chunks {
            builder = builder.add_chunk(chunk.chunk.clone());
        }
        builder.finalize(signer).unwrap().manifest
    }

    #[test]
    fn snapshot_fallback_requires_header() {
        let controller = SnapshotFallbackController::new(readiness());
        let err = controller
            .handle_request(request(false, StrictFallbackState::LocalOnly))
            .unwrap_err();
        assert!(matches!(err, SnapshotReadError::MissingSnapshotOnlyHeader));
    }

    #[test]
    fn snapshot_fallback_requires_allowed_strict_state() {
        let controller = SnapshotFallbackController::new(readiness());
        let err = controller
            .handle_request(request(true, StrictFallbackState::Healthy))
            .unwrap_err();
        assert!(matches!(
            err,
            SnapshotReadError::StrictStateUnavailable { .. }
        ));
    }

    #[test]
    fn snapshot_fallback_enforces_min_ratio() {
        let mut controller = SnapshotFallbackController::new(readiness());
        controller.update_readiness(SnapshotReadiness {
            applied_index_snapshot: 40,
            manifest_generated_ms: readiness().manifest_generated_ms,
            ..readiness()
        });
        let err = controller
            .handle_request(request(true, StrictFallbackState::LocalOnly))
            .unwrap_err();
        assert!(matches!(err, SnapshotReadError::SnapshotOnlyUnavailable));
    }

    #[test]
    fn snapshot_fallback_rejects_when_metrics_absent() {
        let controller = SnapshotFallbackController::new(SnapshotReadiness {
            last_advertised_ready_index: 0,
            applied_index_snapshot: 0,
            ..readiness()
        });
        let err = controller
            .handle_request(request(true, StrictFallbackState::LocalOnly))
            .unwrap_err();
        assert!(matches!(err, SnapshotReadError::SnapshotOnlyUnavailable));
    }

    #[test]
    fn snapshot_fallback_returns_manifest_details() {
        let controller = SnapshotFallbackController::new(readiness());
        let response = controller
            .handle_request(request(true, StrictFallbackState::ProofPublished))
            .expect("fallback succeeds");
        assert_eq!(response.manifest_id, "m1");
        assert_eq!(response.base_index, 100);
        assert!(response.readiness_ratio >= 0.9);
        assert!(response.headers.snapshot_only);
        assert_eq!(response.headers.snapshot_manifest_id, "m1");
        assert_eq!(response.headers.cp_cache_age_ms, 42);
    }

    #[test]
    fn snapshot_trigger_honors_thresholds() {
        let mut trigger = SnapshotTrigger::new(SnapshotTriggerConfig::default());
        let under = trigger.evaluate(SNAPSHOT_LOG_BYTES_TARGET - 1, 0, 1_000);
        assert!(!under.should_trigger);

        let log_trigger = trigger.evaluate(SNAPSHOT_LOG_BYTES_TARGET, 0, 2_000);
        assert!(matches!(
            log_trigger.reason,
            Some(SnapshotTriggerReason::LogBytes)
        ));
        trigger.record_snapshot(2_000);

        let interval_trigger = trigger.evaluate(0, 0, 2_000 + SNAPSHOT_MAX_INTERVAL_MS);
        assert!(matches!(
            interval_trigger.reason,
            Some(SnapshotTriggerReason::Interval)
        ));
        trigger.record_snapshot(3_000);

        let lag_trigger = trigger.evaluate(
            0,
            SNAPSHOT_CATCHUP_THRESHOLD_BYTES,
            3_000 + SNAPSHOT_MAX_INTERVAL_MS / 2,
        );
        assert!(matches!(
            lag_trigger.reason,
            Some(SnapshotTriggerReason::FollowerLag)
        ));
        let telemetry = trigger.telemetry(3_500);
        assert_eq!(
            telemetry.pending_reason,
            Some(SnapshotTriggerReason::FollowerLag)
        );
        assert_eq!(telemetry.last_snapshot_ms, 3_000);
    }

    #[test]
    fn snapshot_fallback_telemetry_tracks_ready_state() {
        let mut controller = SnapshotFallbackController::new(readiness());
        let telemetry = controller.telemetry(2_000);
        assert!(matches!(
            telemetry.snapshot_only_ready_state,
            SnapshotOnlyReadyState::Healthy
        ));
        assert_eq!(telemetry.snapshot_manifest_age_ms, 1_000);

        controller.update_readiness(SnapshotReadiness {
            applied_index_snapshot: 10,
            manifest_generated_ms: 500,
            ..readiness()
        });
        let degraded = controller.telemetry(2_500);
        assert!(matches!(
            degraded.snapshot_only_ready_state,
            SnapshotOnlyReadyState::Degraded
        ));

        controller.record_snapshot_only_result(500, true, 2_500);
        let after_breach = controller.telemetry(2_800);
        assert!(after_breach.snapshot_only_slo_breach_total >= 1);
    }

    #[test]
    fn snapshot_delta_policy_enforces_chain_and_windows() {
        let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);

        let mut full = manifest();
        full.manifest_id = "full".into();
        assert!(matches!(
            policy.record_manifest(&full_delta("d1", "full", 1), 0),
            Err(SnapshotDeltaPolicyError::FullSnapshotUnknown)
        ));

        policy
            .record_manifest(&full, 0)
            .expect("full snapshot allowed");
        let delta = full_delta("d1", "full", 1);
        policy
            .record_manifest(&delta, 5_000)
            .expect("delta allowed");
        assert!(matches!(
            policy.record_manifest(&full_delta("d2", "d1", 2), 20_000),
            Err(SnapshotDeltaPolicyError::DeltaEmitWindowExceeded)
        ));

        policy
            .record_manifest(&full_delta("d2", "d1", 2), 8_000)
            .expect("second delta allowed");
        assert!(matches!(
            policy.record_manifest(&full_delta("overflow", "d2", 3), 9_000),
            Err(SnapshotDeltaPolicyError::DeltaChainExceeded { .. })
        ));

        let mut gated = SnapshotDeltaPolicy::new(1, 10_000, 30_000);
        assert!(matches!(
            gated.record_manifest(&full_delta("d1", "full", 1), 0),
            Err(SnapshotDeltaPolicyError::DeltaDisabled)
        ));
        gated
            .record_manifest(&full, 0)
            .expect("full snapshot allowed");
        assert!(matches!(
            gated.record_manifest(&full_delta("d2", "d1", 1), 1_000),
            Err(SnapshotDeltaPolicyError::DeltaDisabled)
        ));
    }

    #[test]
    fn snapshot_delta_policy_reports_telemetry_states() {
        let mut policy = SnapshotDeltaPolicy::new(2, 10_000, 30_000);
        policy.set_profile_capability(true);
        policy.set_cp_gate(true);
        let mut full = manifest();
        full.manifest_id = "full".into();
        policy
            .record_manifest(&full, 0)
            .expect("full snapshot allowed");
        let telemetry = policy.telemetry();
        assert_eq!(telemetry.state, SnapshotDeltaChainState::Idle);

        let delta = full_delta("d1", "full", 1);
        policy
            .record_manifest(&delta, 1_000)
            .expect("delta allowed");
        let telemetry = policy.telemetry();
        assert_eq!(telemetry.state, SnapshotDeltaChainState::Building);
        assert_eq!(telemetry.chain_length, 1);

        let bad_delta = full_delta("d2", "unknown", 2);
        let err = policy
            .record_manifest(&bad_delta, 1_500)
            .expect_err("stale parent rejected");
        assert!(matches!(
            err,
            SnapshotDeltaPolicyError::DeltaParentMismatch { .. }
        ));
        assert_eq!(policy.telemetry().state, SnapshotDeltaChainState::Orphaned);
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
        delta_manifest.snapshot_kind = SnapshotKind::Delta;
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
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let signer = HmacManifestSigner::new(b"import-flow");
        let payload = vec![0xAAu8; 2048];
        let chunks = exporter
            .export_reader("full-success", Cursor::new(&payload), 512)
            .expect("chunks generated");
        let full_manifest = manifest_from_chunks(
            "full-success",
            SnapshotKind::Full,
            None,
            0,
            &chunks,
            &signer,
            key.epoch,
            "salt",
        );

        let importer = SnapshotChunkImporter::with_retry_policy(&key, "salt", fast_retry_policy());
        let mut staging = SnapshotStagingStore::new();
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

        let delta_payload = exporter
            .export_reader("delta-success", Cursor::new(&payload[..1024]), 256)
            .expect("delta chunks");
        let delta_manifest = manifest_from_chunks(
            "delta-success",
            SnapshotKind::Delta,
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
        let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Latency, &key, "salt");
        let signer = HmacManifestSigner::new(b"import-orphan");
        let payload = vec![0xBBu8; 1024];
        let chunks = exporter
            .export_reader("full-orphan", Cursor::new(&payload), 512)
            .expect("chunks generated");
        let full_manifest = manifest_from_chunks(
            "full-orphan",
            SnapshotKind::Full,
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
            SnapshotKind::Delta,
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
}
