#![allow(dead_code)]

use clustor::feature_guard::{FeatureGateState, FeatureManifestBuilder};
use clustor::lifecycle::activation::{ShadowApplyState, WarmupReadinessRecord};
use clustor::{
    DiskOverrideDevice, DiskOverrideDocument, DiskWriteCacheMode, FeatureCapabilityMatrix,
};
use clustor::{OverrideStatus, QueueFlags, ReadyStateProbe, WarmupReadinessSnapshot};
#[cfg(feature = "snapshot-crypto")]
use clustor::{SnapshotDeltaChainState, SnapshotDeltaChainTelemetry, SnapshotExportTelemetry};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Builds a warmup readiness record for tests.
pub fn readiness_record(partition: &str, warmup_ratio: f64) -> WarmupReadinessRecord {
    WarmupReadinessRecord {
        partition_id: partition.into(),
        bundle_id: "bundle-a".into(),
        shadow_apply_state: ShadowApplyState::Ready,
        shadow_apply_checkpoint_index: 42,
        warmup_ready_ratio: warmup_ratio,
        updated_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    }
}

/// Creates a disk override document with the provided expiration timestamp.
pub fn disk_override(expires_at_ms: &str) -> DiskOverrideDocument {
    DiskOverrideDocument {
        override_id: "disk-1".into(),
        devices: vec![DiskOverrideDevice {
            sys_path: "/sys/block/nvme0n1".into(),
            serial: "nvme-1".into(),
            queue_flags: QueueFlags {
                flush: true,
                fua: true,
            },
            write_cache: DiskWriteCacheMode::WriteThrough,
        }],
        stack_diagram: "dm-crypt -> nvme0n1".into(),
        attested_by: "operator".into(),
        ticket_url: "https://tickets/1".into(),
        expires_at_ms: expires_at_ms.into(),
    }
}

/// Builds a manifest capability matrix and digest for tests.
pub fn build_capability_matrix() -> (FeatureCapabilityMatrix, String) {
    let manifest = FeatureManifestBuilder::new()
        .with_gate_state("leader_leases", FeatureGateState::Enabled)
        .build(&SigningKey::from_bytes(&[11u8; 32]))
        .expect("manifest builds");
    (
        manifest.capability_matrix().expect("matrix"),
        manifest.digest().expect("digest"),
    )
}

/// Constructs a readyz snapshot for the provided readiness record and ratios.
pub fn build_readyz_snapshot(
    record: WarmupReadinessRecord,
    ratios: &HashMap<String, f64>,
    barriers: &HashMap<String, String>,
    _overrides: Vec<OverrideStatus>,
) -> (WarmupReadinessSnapshot, Vec<ReadyStateProbe>) {
    let warmup_snapshot = WarmupReadinessSnapshot {
        records: vec![record],
        publish_period_ms: 1_000,
        skipped_publications_total: 0,
    };
    let probes =
        clustor::map_partition_ratios_with_barriers(&warmup_snapshot.records, ratios, barriers);
    (warmup_snapshot, probes)
}

/// Builds export telemetry for readyz snapshots.
#[cfg(feature = "snapshot-crypto")]
pub fn sample_export_telemetry() -> SnapshotExportTelemetry {
    SnapshotExportTelemetry {
        chunk_rate_bytes_per_sec: 512,
        backlog_bytes: 1_024,
    }
}

/// Builds delta chain telemetry.
#[cfg(feature = "snapshot-crypto")]
pub fn sample_delta_telemetry() -> SnapshotDeltaChainTelemetry {
    SnapshotDeltaChainTelemetry {
        state: SnapshotDeltaChainState::Idle,
        chain_length: 0,
        last_manifest_id: Some("delta-0".into()),
        last_full_snapshot_ms: Some(1_000),
        last_snapshot_ms: Some(2_000),
    }
}
