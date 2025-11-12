use crate::activation::{
    readiness_digest, ShadowApplyState, WarmupReadinessRecord, WarmupReadinessSnapshot,
};
use crate::feature_guard::{FeatureCapabilityMatrix, FeatureGateState};
use crate::overrides::{DiskOverrideDocument, OverrideError};
use crate::snapshot::{SnapshotDeltaChainTelemetry, SnapshotExportTelemetry};
use log::info;
use serde::Serialize;
use std::collections::HashMap;

const READY_PUBLISH_SPEC: &str = "§13.Readyz";

#[derive(Debug, Clone, Serialize)]
pub struct ReadyStateProbe {
    pub readiness: WarmupReadinessRecord,
    pub activation_barrier_id: Option<String>,
    pub partition_ready_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadyzRecord {
    pub partition_id: String,
    pub definition_bundle_id: String,
    pub activation_barrier_id: Option<String>,
    pub shadow_apply_state: ShadowApplyState,
    pub warmup_ready_ratio: f64,
    pub partition_ready_ratio: f64,
    pub readiness_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadyzCapabilityRecord {
    pub feature: &'static str,
    pub slug: &'static str,
    pub gate_state: FeatureGateState,
    pub predicate_digest: String,
    pub gate_state_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OverrideType {
    Disk,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideStatus {
    pub override_id: String,
    pub override_type: OverrideType,
    pub ticket_url: String,
    pub attested_by: String,
    pub expires_at_ms: u64,
    pub active: bool,
}

impl OverrideStatus {
    pub fn from_disk_override(
        document: &DiskOverrideDocument,
        now_ms: u64,
    ) -> Result<Self, OverrideError> {
        let expires_at_ms = document.expiration_epoch_ms()?;
        Ok(Self {
            override_id: document.override_id.clone(),
            override_type: OverrideType::Disk,
            ticket_url: document.ticket_url.clone(),
            attested_by: document.attested_by.clone(),
            expires_at_ms,
            active: expires_at_ms > now_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ReadyStateHealth {
    Healthy,
    WarmupPending,
    PartitionLagging,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadyExplain {
    pub partition_id: String,
    pub definition_bundle_id: String,
    pub activation_barrier_id: Option<String>,
    pub warmup_ready_ratio: f64,
    pub partition_ready_ratio: f64,
    pub readiness_digest: String,
    pub health: ReadyStateHealth,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct WarmupSummary {
    pub total: usize,
    pub ready: usize,
    pub pending: usize,
}

impl WarmupSummary {
    fn from_probes(probes: &[ReadyStateProbe]) -> Self {
        let total = probes.len();
        let ready = probes
            .iter()
            .filter(|probe| probe.readiness.warmup_ready_ratio + f64::EPSILON >= 1.0)
            .count();
        Self {
            total,
            ready,
            pending: total.saturating_sub(ready),
        }
    }

    pub fn ready_fraction(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.ready as f64 / self.total as f64
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadyzSnapshot {
    readiness: Vec<ReadyzRecord>,
    readiness_digest: String,
    publish_period_ms: u64,
    skipped_publications_total: u64,
    capabilities: Vec<ReadyzCapabilityRecord>,
    overrides: Vec<OverrideStatus>,
    export_telemetry: Option<SnapshotExportTelemetry>,
    delta_chain: Option<SnapshotDeltaChainTelemetry>,
    warmup_summary: WarmupSummary,
    feature_manifest_digest: String,
}

impl ReadyzSnapshot {
    pub fn new(
        probes: Vec<ReadyStateProbe>,
        publish_period_ms: u64,
        skipped_publications_total: u64,
        capability_matrix: &FeatureCapabilityMatrix,
        feature_manifest_digest: impl Into<String>,
        overrides: Vec<OverrideStatus>,
    ) -> Self {
        let warmup_summary = WarmupSummary::from_probes(&probes);
        let mut readiness_records: Vec<WarmupReadinessRecord> =
            probes.iter().map(|probe| probe.readiness.clone()).collect();
        readiness_records.sort_by(|a, b| a.partition_id.cmp(&b.partition_id));
        let digest = readiness_digest(&readiness_records);
        let readiness = probes
            .into_iter()
            .map(|probe| ReadyzRecord {
                partition_id: probe.readiness.partition_id.clone(),
                definition_bundle_id: probe.readiness.bundle_id.clone(),
                activation_barrier_id: probe.activation_barrier_id,
                shadow_apply_state: probe.readiness.shadow_apply_state,
                warmup_ready_ratio: probe.readiness.warmup_ready_ratio,
                partition_ready_ratio: probe.partition_ready_ratio.clamp(0.0, 1.0),
                readiness_digest: digest.clone(),
            })
            .collect();
        let capabilities = capability_matrix
            .entries()
            .iter()
            .map(|entry| ReadyzCapabilityRecord {
                feature: entry.feature,
                slug: entry.slug,
                gate_state: entry.gate_state,
                predicate_digest: entry.predicate_digest.clone(),
                gate_state_digest: entry.gate_state_digest.clone(),
            })
            .collect();
        let snapshot = Self {
            readiness,
            readiness_digest: digest,
            publish_period_ms,
            skipped_publications_total,
            capabilities,
            overrides,
            export_telemetry: None,
            delta_chain: None,
            warmup_summary,
            feature_manifest_digest: feature_manifest_digest.into(),
        };
        info!(
            "event=readyz_publish clause={} readiness_digest={} partitions={} warmup_ready={} warmup_total={} skipped_publications_total={}",
            READY_PUBLISH_SPEC,
            snapshot.readiness_digest,
            snapshot.readiness.len(),
            snapshot.warmup_summary.ready,
            snapshot.warmup_summary.total,
            snapshot.skipped_publications_total
        );
        snapshot
    }

    pub fn readiness(&self) -> &[ReadyzRecord] {
        &self.readiness
    }

    pub fn readiness_digest(&self) -> &str {
        &self.readiness_digest
    }

    pub fn capabilities(&self) -> &[ReadyzCapabilityRecord] {
        &self.capabilities
    }

    pub fn overrides(&self) -> &[OverrideStatus] {
        &self.overrides
    }

    pub fn with_export_telemetry(mut self, telemetry: SnapshotExportTelemetry) -> Self {
        self.export_telemetry = Some(telemetry);
        self
    }

    pub fn export_telemetry(&self) -> Option<&SnapshotExportTelemetry> {
        self.export_telemetry.as_ref()
    }

    pub fn with_delta_chain(mut self, telemetry: SnapshotDeltaChainTelemetry) -> Self {
        self.delta_chain = Some(telemetry);
        self
    }

    pub fn delta_chain(&self) -> Option<&SnapshotDeltaChainTelemetry> {
        self.delta_chain.as_ref()
    }

    pub fn warmup_summary(&self) -> WarmupSummary {
        self.warmup_summary
    }

    pub fn feature_manifest_digest(&self) -> &str {
        &self.feature_manifest_digest
    }

    pub fn publish_period_ms(&self) -> u64 {
        self.publish_period_ms
    }

    pub fn skipped_publications_total(&self) -> u64 {
        self.skipped_publications_total
    }

    pub fn why_not_ready(&self, partition_id: &str) -> Option<ReadyExplain> {
        self.readiness
            .iter()
            .find(|record| record.partition_id == partition_id)
            .map(|record| ReadyExplain {
                partition_id: record.partition_id.clone(),
                definition_bundle_id: record.definition_bundle_id.clone(),
                activation_barrier_id: record.activation_barrier_id.clone(),
                warmup_ready_ratio: record.warmup_ready_ratio,
                partition_ready_ratio: record.partition_ready_ratio,
                readiness_digest: record.readiness_digest.clone(),
                health: classify_health(record),
            })
    }
}

fn classify_health(record: &ReadyzRecord) -> ReadyStateHealth {
    if record.warmup_ready_ratio + f64::EPSILON < 1.0 {
        ReadyStateHealth::WarmupPending
    } else if record.partition_ready_ratio + f64::EPSILON < 1.0 {
        ReadyStateHealth::PartitionLagging
    } else {
        ReadyStateHealth::Healthy
    }
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

pub fn readyz_from_warmup_snapshot(
    snapshot: &WarmupReadinessSnapshot,
    partition_ratios: &HashMap<String, f64>,
    barrier_assignments: &HashMap<String, String>,
    capability_matrix: &FeatureCapabilityMatrix,
    feature_manifest_digest: impl Into<String>,
    overrides: Vec<OverrideStatus>,
) -> ReadyzSnapshot {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::{ShadowApplyState, WarmupReadinessRecord, WarmupReadinessSnapshot};
    use crate::feature_guard::FeatureManifestBuilder;
    use crate::overrides::{DiskOverrideDevice, DiskWriteCacheMode, QueueFlags};
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
        let ratios = HashMap::from([("p1".into(), 0.8)]);
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
        let barrier_map = HashMap::from([("p1".into(), "barrier-1".into())]);
        let snapshot = readyz_from_warmup_snapshot(
            &warmup_snapshot,
            &ratios,
            &barrier_map,
            &matrix,
            manifest_digest.clone(),
            vec![override_status.clone()],
        )
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
