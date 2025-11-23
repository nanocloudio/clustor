use serde::Serialize;

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
