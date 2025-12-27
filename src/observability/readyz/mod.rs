use crate::feature_guard::FeatureCapabilityMatrix;
use crate::lifecycle::activation::{
    ActivationDigestError, WarmupReadinessRecord, WarmupReadinessSnapshot,
};
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
