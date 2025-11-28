use crate::feature_guard::FeatureCapabilityMatrix;
use crate::lifecycle::activation::{
    ActivationDigestError, WarmupReadinessRecord, WarmupReadinessSnapshot,
};
#[cfg(all(test, feature = "snapshot-crypto"))]
use crate::snapshot::{SnapshotDeltaChainTelemetry, SnapshotExportTelemetry};
use std::collections::HashMap;

mod capabilities;
mod overrides;
mod snapshot;
mod why;

pub use capabilities::ReadyzCapabilityRecord;
pub use overrides::{
    DiskOverrideDevice, DiskOverrideDocument, DiskWriteCacheMode, OverrideError, OverrideStatus,
    OverrideType, QueueFlags,
};
pub use snapshot::{
    ReadyStateProbe, ReadyzRecord, ReadyzSnapshot, ReadyzSnapshotBuilder, WarmupSummary,
};
pub use why::{ReadyExplain, ReadyStateHealth};

const READY_PUBLISH_SPEC: &str = "§13.Readyz";

pub fn readyz_from_warmup_snapshot(
    snapshot: &WarmupReadinessSnapshot,
    partition_ratios: &HashMap<String, f64>,
    barrier_assignments: &HashMap<String, String>,
    capability_matrix: &FeatureCapabilityMatrix,
    feature_manifest_digest: impl Into<String>,
    overrides: Vec<OverrideStatus>,
) -> Result<ReadyzSnapshot, ActivationDigestError> {
    let probes = map_partition_ratios_with_barriers(
        &snapshot.records,
        partition_ratios,
        barrier_assignments,
    );
    ReadyzSnapshot::new(
        probes,
        snapshot.publish_period_ms,
        snapshot.skipped_publications_total,
        capability_matrix,
        feature_manifest_digest,
        overrides,
    )
}

pub fn map_partition_ratios(
    readiness: &[WarmupReadinessRecord],
    ratios: &HashMap<String, f64>,
) -> Vec<ReadyStateProbe> {
    let empty = HashMap::new();
    map_partition_ratios_with_barriers(readiness, ratios, &empty)
}

pub fn map_partition_ratios_with_barriers(
    readiness: &[WarmupReadinessRecord],
    ratios: &HashMap<String, f64>,
    barriers: &HashMap<String, String>,
) -> Vec<ReadyStateProbe> {
    readiness
        .iter()
        .map(|record| ReadyStateProbe {
            readiness: record.clone(),
            activation_barrier_id: barriers.get(&record.partition_id).cloned(),
            partition_ready_ratio: ratios.get(&record.partition_id).copied().unwrap_or(0.0),
        })
        .collect()
}

#[cfg(all(test, feature = "snapshot-crypto"))]
mod tests {
    use super::*;
    use crate::feature_guard::{FeatureGateState, FeatureManifestBuilder};
    use crate::lifecycle::activation::{
        ShadowApplyState, WarmupReadinessRecord, WarmupReadinessSnapshot,
    };
    use crate::readyz::{DiskOverrideDevice, DiskOverrideDocument, DiskWriteCacheMode, QueueFlags};
    use crate::snapshot::SnapshotDeltaChainState;
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn readiness_record(partition: &str, warmup_ratio: f64) -> WarmupReadinessRecord {
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

    fn disk_override(expires_at_ms: &str) -> DiskOverrideDocument {
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

    #[test]
    fn snapshot_reports_capabilities_and_overrides() {
        let manifest = FeatureManifestBuilder::new()
            .with_gate_state("leader_leases", FeatureGateState::Enabled)
            .build(&SigningKey::from_bytes(&[11u8; 32]))
            .expect("manifest builds");
        let matrix = manifest.capability_matrix().expect("matrix");
        let manifest_digest = manifest.digest().expect("manifest digest");

        let record = readiness_record("p1", 0.9);
        let ratios = HashMap::from([(String::from("p1"), 0.8)]);
        let doc = disk_override("999999");
        let override_status =
            OverrideStatus::from_disk_override(&doc, 0).expect("override converts");
        let delta = SnapshotDeltaChainTelemetry {
            state: SnapshotDeltaChainState::Idle,
            chain_length: 0,
            last_manifest_id: Some("delta-0".into()),
            last_full_snapshot_ms: Some(1_000),
            last_snapshot_ms: Some(2_000),
        };
        let warmup_snapshot = WarmupReadinessSnapshot {
            records: vec![record.clone()],
            publish_period_ms: 1_000,
            skipped_publications_total: 0,
        };
        let barrier_map = HashMap::from([(String::from("p1"), String::from("barrier-1"))]);
        let snapshot = readyz_from_warmup_snapshot(
            &warmup_snapshot,
            &ratios,
            &barrier_map,
            &matrix,
            manifest_digest.clone(),
            vec![override_status.clone()],
        )
        .expect("readyz snapshot builds")
        .with_export_telemetry(SnapshotExportTelemetry {
            chunk_rate_bytes_per_sec: 512,
            backlog_bytes: 1_024,
        })
        .with_delta_chain(delta.clone());

        assert_eq!(snapshot.capabilities().len(), matrix.entries().len());
        assert_eq!(snapshot.overrides().len(), 1);
        let why = snapshot.why_not_ready("p1").expect("partition captured");
        assert_eq!(why.health, ReadyStateHealth::WarmupPending);
        assert_eq!(why.readiness_digest, snapshot.readiness_digest());
        assert_eq!(why.activation_barrier_id.as_deref(), Some("barrier-1"));
        assert_eq!(snapshot.publish_period_ms(), 1_000);
        assert_eq!(snapshot.skipped_publications_total(), 0);
        assert_eq!(snapshot.feature_manifest_digest(), manifest_digest);
        let warmup = snapshot.warmup_summary();
        assert_eq!(warmup.total, 1);
        assert_eq!(warmup.ready, 0);
        assert!(warmup.ready_fraction() < 0.5);
        assert_eq!(
            snapshot
                .export_telemetry()
                .unwrap()
                .chunk_rate_bytes_per_sec,
            512
        );
        assert_eq!(
            snapshot.delta_chain().unwrap().state,
            SnapshotDeltaChainState::Idle
        );
    }

    #[test]
    fn override_status_reflects_ttl() {
        let doc = disk_override("10");
        let status = OverrideStatus::from_disk_override(&doc, 5).expect("override");
        assert!(status.active);
        let status = OverrideStatus::from_disk_override(&doc, 20).expect("override");
        assert!(!status.active);
    }

    #[test]
    fn override_status_invalid_doc_fails() {
        let mut doc = disk_override("10");
        doc.expires_at_ms = "invalid".into();
        assert!(OverrideStatus::from_disk_override(&doc, 0).is_err());
    }
}
