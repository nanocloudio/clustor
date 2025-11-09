use crate::consensus::DurabilityProof;
use crate::durability::{DurabilityLogEntry, DurabilityLogReplay};
use crate::storage::{WalReplayResult, WalTruncation};
use crate::telemetry::MetricsRegistry;

#[derive(Debug, Clone)]
pub struct RecoveryStatus {
    pub strict_required: bool,
    pub truncation: Option<WalTruncation>,
    pub proof: Option<DurabilityProof>,
}

impl RecoveryStatus {
    pub fn new(wal: &WalReplayResult, durability_entries: &[DurabilityLogEntry]) -> Self {
        Self {
            strict_required: wal.truncation.is_some(),
            truncation: wal.truncation.clone(),
            proof: DurabilityLogReplay::publish_proof(durability_entries),
        }
    }

    pub fn record_metrics(&self, registry: &mut MetricsRegistry) {
        let truncated = self
            .truncation
            .as_ref()
            .map(|summary| summary.truncated_bytes)
            .unwrap_or(0);
        registry.set_gauge("wal.recovery_truncated_bytes", truncated);
    }
}
