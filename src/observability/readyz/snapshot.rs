#[cfg(feature = "admin-http")]
use crate::control_plane::admin::ShrinkPlanStatus;
use crate::feature_guard::FeatureCapabilityMatrix;
use crate::lifecycle::activation::{
    ActivationDigestError, ReadinessDigestBuilder, WarmupReadinessRecord,
};
#[cfg(feature = "snapshot-crypto")]
use crate::snapshot::{SnapshotDeltaChainTelemetry, SnapshotExportTelemetry};
use log::info;
use serde::Serialize;

use super::capabilities::ReadyzCapabilityRecord;
use super::overrides::OverrideStatus;
use super::why::{ReadyExplain, ReadyStateHealth};
use super::READY_PUBLISH_SPEC;

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
    pub shadow_apply_state: crate::lifecycle::activation::ShadowApplyState,
    pub warmup_ready_ratio: f64,
    pub partition_ready_ratio: f64,
    pub readiness_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct WarmupSummary {
    pub total: usize,
    pub ready: usize,
    pub pending: usize,
}

impl Default for WarmupSummary {
    fn default() -> Self {
        Self::new()
    }
}

struct PendingReadyzRecord {
    partition_id: String,
    definition_bundle_id: String,
    activation_barrier_id: Option<String>,
    shadow_apply_state: crate::lifecycle::activation::ShadowApplyState,
    warmup_ready_ratio: f64,
    partition_ready_ratio: f64,
}

pub struct ReadyzSnapshotBuilder {
    publish_period_ms: u64,
    skipped_publications_total: u64,
    capabilities: Vec<ReadyzCapabilityRecord>,
    overrides: Vec<OverrideStatus>,
    feature_manifest_digest: String,
    pending: Vec<PendingReadyzRecord>,
    digest: ReadinessDigestBuilder,
    warmup_summary: WarmupSummary,
}

impl ReadyzSnapshotBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        publish_period_ms: u64,
        skipped_publications_total: u64,
        capability_matrix: &FeatureCapabilityMatrix,
        feature_manifest_digest: impl Into<String>,
        overrides: Vec<OverrideStatus>,
    ) -> Self {
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
        Self {
            publish_period_ms,
            skipped_publications_total,
            capabilities,
            overrides,
            feature_manifest_digest: feature_manifest_digest.into(),
            pending: Vec::new(),
            digest: ReadinessDigestBuilder::new(),
            warmup_summary: WarmupSummary::new(),
        }
    }

    pub fn push(&mut self, probe: ReadyStateProbe) -> Result<(), ActivationDigestError> {
        self.digest.add(&probe.readiness)?;
        self.warmup_summary.record_probe(&probe);
        self.pending.push(PendingReadyzRecord::from_probe(probe));
        Ok(())
    }

    pub fn extend<I>(&mut self, probes: I) -> Result<(), ActivationDigestError>
    where
        I: IntoIterator<Item = ReadyStateProbe>,
    {
        for probe in probes {
            self.push(probe)?;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<ReadyzSnapshot, ActivationDigestError> {
        let digest = self.digest.finish()?;
        let readiness = self
            .pending
            .into_iter()
            .map(|pending| pending.finalize(&digest))
            .collect();
        let snapshot = ReadyzSnapshot {
            readiness,
            readiness_digest: digest.clone(),
            publish_period_ms: self.publish_period_ms,
            skipped_publications_total: self.skipped_publications_total,
            capabilities: self.capabilities,
            overrides: self.overrides,
            #[cfg(feature = "admin-http")]
            shrink_plans: Vec::new(),
            #[cfg(feature = "snapshot-crypto")]
            export_telemetry: None,
            #[cfg(feature = "snapshot-crypto")]
            delta_chain: None,
            warmup_summary: self.warmup_summary,
            feature_manifest_digest: self.feature_manifest_digest,
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
        Ok(snapshot)
    }
}

impl PendingReadyzRecord {
    fn from_probe(probe: ReadyStateProbe) -> Self {
        let ReadyStateProbe {
            readiness,
            activation_barrier_id,
            partition_ready_ratio,
        } = probe;
        let WarmupReadinessRecord {
            partition_id,
            bundle_id,
            shadow_apply_state,
            warmup_ready_ratio,
            ..
        } = readiness;
        Self {
            partition_id,
            definition_bundle_id: bundle_id,
            activation_barrier_id,
            shadow_apply_state,
            warmup_ready_ratio,
            partition_ready_ratio: partition_ready_ratio.clamp(0.0, 1.0),
        }
    }

    fn finalize(self, digest: &str) -> ReadyzRecord {
        ReadyzRecord {
            partition_id: self.partition_id,
            definition_bundle_id: self.definition_bundle_id,
            activation_barrier_id: self.activation_barrier_id,
            shadow_apply_state: self.shadow_apply_state,
            warmup_ready_ratio: self.warmup_ready_ratio,
            partition_ready_ratio: self.partition_ready_ratio,
            readiness_digest: digest.to_string(),
        }
    }
}

impl WarmupSummary {
    pub fn new() -> Self {
        Self {
            total: 0,
            ready: 0,
            pending: 0,
        }
    }

    pub fn record_probe(&mut self, probe: &ReadyStateProbe) {
        self.total += 1;
        if probe.readiness.warmup_ready_ratio + f64::EPSILON >= 1.0 {
            self.ready += 1;
        } else {
            self.pending += 1;
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
    #[cfg(feature = "admin-http")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    shrink_plans: Vec<ShrinkPlanStatus>,
    #[cfg(feature = "snapshot-crypto")]
    export_telemetry: Option<SnapshotExportTelemetry>,
    #[cfg(feature = "snapshot-crypto")]
    delta_chain: Option<SnapshotDeltaChainTelemetry>,
    warmup_summary: WarmupSummary,
    feature_manifest_digest: String,
}

impl ReadyzSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I>(
        probes: I,
        publish_period_ms: u64,
        skipped_publications_total: u64,
        capability_matrix: &FeatureCapabilityMatrix,
        feature_manifest_digest: impl Into<String>,
        overrides: Vec<OverrideStatus>,
    ) -> Result<Self, ActivationDigestError>
    where
        I: IntoIterator<Item = ReadyStateProbe>,
    {
        let mut builder = ReadyzSnapshotBuilder::new(
            publish_period_ms,
            skipped_publications_total,
            capability_matrix,
            feature_manifest_digest,
            overrides,
        );
        builder.extend(probes)?;
        builder.finish()
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

    #[cfg(feature = "admin-http")]
    pub fn shrink_plans(&self) -> &[ShrinkPlanStatus] {
        &self.shrink_plans
    }

    pub fn skipped_publications_total(&self) -> u64 {
        self.skipped_publications_total
    }

    pub fn warmup_summary(&self) -> WarmupSummary {
        self.warmup_summary
    }

    pub fn publish_period_ms(&self) -> u64 {
        self.publish_period_ms
    }

    pub fn feature_manifest_digest(&self) -> &str {
        &self.feature_manifest_digest
    }

    #[cfg(feature = "snapshot-crypto")]
    pub fn with_export_telemetry(mut self, telemetry: SnapshotExportTelemetry) -> Self {
        self.export_telemetry = Some(telemetry);
        self
    }

    #[cfg(feature = "snapshot-crypto")]
    pub fn with_delta_chain(mut self, telemetry: SnapshotDeltaChainTelemetry) -> Self {
        self.delta_chain = Some(telemetry);
        self
    }

    #[cfg(feature = "snapshot-crypto")]
    pub fn export_telemetry(&self) -> Option<&SnapshotExportTelemetry> {
        self.export_telemetry.as_ref()
    }

    #[cfg(feature = "snapshot-crypto")]
    pub fn delta_chain(&self) -> Option<&SnapshotDeltaChainTelemetry> {
        self.delta_chain.as_ref()
    }

    #[cfg(feature = "admin-http")]
    pub fn with_shrink_plans(mut self, plans: Vec<ShrinkPlanStatus>) -> Self {
        self.shrink_plans = plans;
        self
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
