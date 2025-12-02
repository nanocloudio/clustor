use crate::replication::flow::FlowThrottleEnvelope;
use serde::{Deserialize, Serialize};

pub const ADMIN_AUDIT_SPEC_CLAUSE: &str = "§12.3";
pub const THROTTLE_SPEC_CLAUSE: &str = "§10.3";
pub const ADMIN_API_SPEC: &str = "§13.AdminAPI";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartitionSpec {
    pub partition_id: String,
    pub replicas: Vec<String>,
    pub routing_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplicaSpec {
    pub replica_id: String,
    pub az: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePartitionRequest {
    pub idempotency_key: String,
    pub partition: PartitionSpec,
    pub replicas: Vec<ReplicaSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreatePartitionResponse {
    pub partition_id: String,
    pub routing_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DurabilityMode {
    Strict,
    Relaxed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetDurabilityModeRequest {
    pub idempotency_key: String,
    pub partition_id: String,
    pub target_mode: DurabilityMode,
    pub expected_mode: DurabilityMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDurabilityModeResponse {
    pub partition_id: String,
    pub applied_mode: DurabilityMode,
    pub durability_mode_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotThrottleRequest {
    pub partition_id: String,
    pub enable: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotThrottleResponse {
    pub partition_id: String,
    pub throttle_state: FlowThrottleEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferLeaderRequest {
    pub idempotency_key: String,
    pub partition_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_replica_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferLeaderResponse {
    pub partition_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_replica_id: Option<String>,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotTriggerRequest {
    pub idempotency_key: String,
    pub partition_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotTriggerResponse {
    pub partition_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThrottleExplainResponse {
    pub partition_id: String,
    pub envelope: FlowThrottleEnvelope,
    pub decision_trace_id: String,
    pub routing_epoch: u64,
    pub spec_clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShrinkPlanState {
    Draft,
    Armed,
    Cancelled,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkTargetPlacement {
    pub prg_id: String,
    pub target_members: Vec<String>,
    pub target_routing_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkPlanStatus {
    pub plan_id: String,
    pub state: ShrinkPlanState,
    pub target_placements: Vec<ShrinkTargetPlacement>,
    pub created_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub armed_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateShrinkPlanRequest {
    pub plan_id: String,
    pub target_placements: Vec<ShrinkTargetPlacement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateShrinkPlanResponse {
    pub plan: ShrinkPlanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmShrinkPlanRequest {
    pub plan_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmShrinkPlanResponse {
    pub plan: ShrinkPlanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelShrinkPlanRequest {
    pub plan_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelShrinkPlanResponse {
    pub plan: ShrinkPlanStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListShrinkPlansResponse {
    pub plans: Vec<ShrinkPlanStatus>,
}
