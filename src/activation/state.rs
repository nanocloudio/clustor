use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShadowApplyState {
    Pending,
    Replaying,
    Ready,
    Expired,
}

impl ShadowApplyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShadowApplyState::Pending => "Pending",
            ShadowApplyState::Replaying => "Replaying",
            ShadowApplyState::Ready => "Ready",
            ShadowApplyState::Expired => "Expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupReadinessRecord {
    pub partition_id: String,
    pub bundle_id: String,
    pub shadow_apply_state: ShadowApplyState,
    pub shadow_apply_checkpoint_index: u64,
    pub warmup_ready_ratio: f64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct WarmupReadinessSnapshot {
    pub records: Vec<WarmupReadinessRecord>,
    pub publish_period_ms: u64,
    pub skipped_publications_total: u64,
}

impl WarmupReadinessSnapshot {
    pub fn readiness_for(&self, partition_id: &str) -> Option<&WarmupReadinessRecord> {
        self.records
            .iter()
            .find(|record| record.partition_id == partition_id)
    }
}
