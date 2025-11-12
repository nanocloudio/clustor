use crate::apply::WhyApply;
use crate::cp::{CpProofCoordinator, CpUnavailableResponse};
use crate::cp_raft::{CpPlacementClient, PlacementRecord};
use crate::flow::{
    CreditHint, FlowThrottleEnvelope, FlowThrottleReason, FlowThrottleState, IngestStatusCode,
};
use crate::security::{BreakGlassToken, RbacManifestCache, SecurityError, SpiffeId};
use crate::system_log::SystemLogEntry;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

const ADMIN_AUDIT_SPEC_CLAUSE: &str = "§12.3";
const THROTTLE_SPEC_CLAUSE: &str = "§10.3";
const ADMIN_API_SPEC: &str = "§13.AdminAPI";

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

#[derive(Debug, Clone)]
struct DurabilityState {
    mode: DurabilityMode,
    epoch: u64,
}

impl DurabilityState {
    fn new() -> Self {
        Self {
            mode: DurabilityMode::Strict,
            epoch: 0,
        }
    }
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

#[derive(Debug, Clone)]
pub struct IdempotencyLedger<T: Clone> {
    entries: HashMap<String, LedgerRecord<T>>,
    retention: Duration,
}

#[derive(Debug, Clone)]
struct LedgerRecord<T: Clone> {
    response: T,
    stored_at: Instant,
}

impl<T: Clone> IdempotencyLedger<T> {
    pub fn new(retention: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            retention,
        }
    }

    pub fn record(&mut self, key: String, response: T, now: Instant) {
        self.entries.insert(
            key,
            LedgerRecord {
                response,
                stored_at: now,
            },
        );
        self.evict(now);
    }

    pub fn get(&mut self, key: &str, now: Instant) -> Option<T> {
        self.evict(now);
        self.entries.get(key).map(|record| record.response.clone())
    }

    fn evict(&mut self, now: Instant) {
        self.entries
            .retain(|_, record| now.saturating_duration_since(record.stored_at) < self.retention);
    }

    pub fn retention(&self) -> Duration {
        self.retention
    }
}

pub struct AdminHandler {
    cp_guard: CpProofCoordinator,
    placements: CpPlacementClient,
    create_partition_ledger: IdempotencyLedger<CreatePartitionResponse>,
    durability_ledger: IdempotencyLedger<SetDurabilityModeResponse>,
    transfer_ledger: IdempotencyLedger<TransferLeaderResponse>,
    snapshot_trigger_ledger: IdempotencyLedger<SnapshotTriggerResponse>,
    durability_modes: HashMap<String, DurabilityState>,
    throttle_state: HashMap<String, FlowThrottleEnvelope>,
    audit_log: Vec<AdminAuditRecord>,
    apply_reports: HashMap<String, WhyApply>,
    durability_log: Vec<SystemLogEntry>,
}

impl AdminHandler {
    pub fn new(
        cp_guard: CpProofCoordinator,
        placements: CpPlacementClient,
        ledger: IdempotencyLedger<CreatePartitionResponse>,
    ) -> Self {
        let retention = ledger.retention();
        Self {
            cp_guard,
            placements,
            create_partition_ledger: ledger,
            durability_ledger: IdempotencyLedger::new(retention),
            transfer_ledger: IdempotencyLedger::new(retention),
            snapshot_trigger_ledger: IdempotencyLedger::new(retention),
            durability_modes: HashMap::new(),
            throttle_state: HashMap::new(),
            audit_log: Vec::new(),
            apply_reports: HashMap::new(),
            durability_log: Vec::new(),
        }
    }

    pub fn handle_create_partition(
        &mut self,
        request: CreatePartitionRequest,
        now: Instant,
    ) -> Result<CreatePartitionResponse, AdminError> {
        self.guard_cp(now)?;
        if let Some(response) = self
            .create_partition_ledger
            .get(&request.idempotency_key, now)
        {
            return Ok(response);
        }
        let record = PlacementRecord {
            partition_id: request.partition.partition_id.clone(),
            routing_epoch: request.partition.routing_epoch + 1,
            lease_epoch: 1,
            members: request
                .replicas
                .iter()
                .map(|replica| replica.replica_id.clone())
                .collect(),
        };
        self.placements.update(record.clone(), now);
        let response = CreatePartitionResponse {
            partition_id: record.partition_id,
            routing_epoch: record.routing_epoch,
        };
        let replica_count = request.replicas.len();
        let idempotency_key = request.idempotency_key.clone();
        self.create_partition_ledger
            .record(request.idempotency_key, response.clone(), now);
        info!(
            "event=admin_create_partition clause={} partition_id={} routing_epoch={} replicas={} ledger_entries={} idempotency_key={}",
            ADMIN_API_SPEC,
            response.partition_id,
            response.routing_epoch,
            replica_count,
            self.create_partition_ledger.entries.len(),
            idempotency_key
        );
        Ok(response)
    }

    pub fn handle_set_durability_mode(
        &mut self,
        request: SetDurabilityModeRequest,
        now: Instant,
    ) -> Result<SetDurabilityModeResponse, AdminError> {
        self.guard_cp(now)?;
        if let Some(cached) = self.durability_ledger.get(&request.idempotency_key, now) {
            return Ok(cached);
        }
        let partition_id = request.partition_id.clone();
        let target_mode = request.target_mode.clone();
        let state = self
            .durability_modes
            .entry(partition_id.clone())
            .or_insert_with(DurabilityState::new);
        if state.mode != request.expected_mode {
            return Err(AdminError::ModeConflict {
                current: state.mode.clone(),
                requested: target_mode,
            });
        }
        if state.mode != target_mode && matches!(target_mode, DurabilityMode::Relaxed) {
            self.cp_guard
                .guard_durability_transition(now)
                .map_err(AdminError::CpUnavailable)?;
        }
        if state.mode != target_mode {
            let previous = state.mode.clone();
            state.epoch = state.epoch.saturating_add(1);
            state.mode = target_mode.clone();
            self.durability_log
                .push(SystemLogEntry::DurabilityTransition {
                    from_mode: format!("{previous:?}"),
                    to_mode: format!("{target_mode:?}"),
                    effective_index: state.epoch,
                    durability_mode_epoch: state.epoch,
                });
        }
        self.audit_log.push(AdminAuditRecord {
            action: "SetDurabilityMode".into(),
            partition_id: partition_id.clone(),
            reason: None,
            recorded_at: now,
            spec_clause: ADMIN_AUDIT_SPEC_CLAUSE.into(),
        });
        let response = SetDurabilityModeResponse {
            partition_id,
            applied_mode: state.mode.clone(),
            durability_mode_epoch: state.epoch,
        };
        self.durability_ledger
            .record(request.idempotency_key, response.clone(), now);
        info!(
            "event=admin_set_durability clause={} partition_id={} target_mode={:?} epoch={}",
            ADMIN_API_SPEC, response.partition_id, target_mode, state.epoch
        );
        Ok(response)
    }

    pub fn handle_snapshot_throttle(
        &mut self,
        request: SnapshotThrottleRequest,
        now: Instant,
    ) -> Result<SnapshotThrottleResponse, AdminError> {
        self.guard_cp(now)?;
        let partition_id = request.partition_id.clone();
        let envelope = if request.enable {
            FlowThrottleEnvelope::new(
                FlowThrottleState::Open,
                CreditHint::Recover,
                IngestStatusCode::Healthy,
            )
        } else {
            FlowThrottleEnvelope::new(
                FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt { byte_credit: 0 }),
                CreditHint::Shed,
                IngestStatusCode::TransientBackpressure,
            )
        };
        self.throttle_state
            .insert(partition_id.clone(), envelope.clone());
        self.audit_log.push(AdminAuditRecord {
            action: "SnapshotThrottle".into(),
            partition_id: partition_id.clone(),
            reason: Some(request.reason),
            recorded_at: now,
            spec_clause: ADMIN_AUDIT_SPEC_CLAUSE.into(),
        });
        info!(
            "event=admin_snapshot_throttle clause={} partition_id={} enable={} throttle_state={:?}",
            THROTTLE_SPEC_CLAUSE, partition_id, request.enable, envelope.state
        );
        Ok(SnapshotThrottleResponse {
            partition_id,
            throttle_state: envelope,
        })
    }

    pub fn handle_transfer_leader(
        &mut self,
        request: TransferLeaderRequest,
        now: Instant,
    ) -> Result<TransferLeaderResponse, AdminError> {
        self.guard_cp(now)?;
        if let Some(cached) = self.transfer_ledger.get(&request.idempotency_key, now) {
            return Ok(cached);
        }
        let partition_id = request.partition_id.clone();
        let placement = self
            .placements
            .placement_snapshot(&partition_id)
            .ok_or(AdminError::UnknownPartition)?;
        if let Some(target) = &request.target_replica_id {
            if !placement
                .record
                .members
                .iter()
                .any(|member| member == target)
            {
                return Err(AdminError::UnknownPartition);
            }
        }
        let response = TransferLeaderResponse {
            partition_id: partition_id.clone(),
            target_replica_id: request.target_replica_id.clone(),
            accepted: true,
            message: Some("transfer scheduled".into()),
        };
        self.audit_log.push(AdminAuditRecord {
            action: "TransferLeader".into(),
            partition_id,
            reason: request.reason.clone(),
            recorded_at: now,
            spec_clause: ADMIN_AUDIT_SPEC_CLAUSE.into(),
        });
        info!(
            "event=admin_transfer_leader clause={} partition_id={} target_replica={:?}",
            ADMIN_API_SPEC, response.partition_id, response.target_replica_id
        );
        self.transfer_ledger
            .record(request.idempotency_key, response.clone(), now);
        Ok(response)
    }

    pub fn handle_snapshot_trigger(
        &mut self,
        request: SnapshotTriggerRequest,
        now: Instant,
    ) -> Result<SnapshotTriggerResponse, AdminError> {
        self.guard_cp(now)?;
        if let Some(cached) = self
            .snapshot_trigger_ledger
            .get(&request.idempotency_key, now)
        {
            return Ok(cached);
        }
        let partition_id = request.partition_id.clone();
        if self.placements.placement_snapshot(&partition_id).is_none() {
            return Err(AdminError::UnknownPartition);
        }
        let response = SnapshotTriggerResponse {
            partition_id: partition_id.clone(),
            accepted: true,
            message: Some(format!("snapshot trigger accepted: {}", request.reason)),
        };
        self.audit_log.push(AdminAuditRecord {
            action: "SnapshotTrigger".into(),
            partition_id,
            reason: Some(request.reason.clone()),
            recorded_at: now,
            spec_clause: ADMIN_AUDIT_SPEC_CLAUSE.into(),
        });
        info!(
            "event=admin_snapshot_trigger clause={} partition_id={} reason={}",
            ADMIN_API_SPEC, response.partition_id, request.reason
        );
        self.snapshot_trigger_ledger
            .record(request.idempotency_key, response.clone(), now);
        Ok(response)
    }

    fn guard_cp(&mut self, now: Instant) -> Result<(), AdminError> {
        self.cp_guard
            .guard_admin(now)
            .map_err(|err| AdminError::CpUnavailable(Box::new(err.response().clone())))
    }

    pub fn explain_throttle(
        &mut self,
        partition_id: &str,
        decision_trace_id: impl Into<String>,
        _now: Instant,
    ) -> Result<ThrottleExplainResponse, AdminError> {
        let placement = self
            .placements
            .placement_snapshot(partition_id)
            .ok_or(AdminError::UnknownPartition)?;
        let envelope =
            self.throttle_state
                .get(partition_id)
                .cloned()
                .unwrap_or(FlowThrottleEnvelope::new(
                    FlowThrottleState::Open,
                    CreditHint::Recover,
                    IngestStatusCode::Healthy,
                ));
        Ok(ThrottleExplainResponse {
            partition_id: partition_id.to_string(),
            envelope,
            decision_trace_id: decision_trace_id.into(),
            routing_epoch: placement.record.routing_epoch,
            spec_clause: THROTTLE_SPEC_CLAUSE.into(),
        })
    }

    pub fn placements(&self) -> &CpPlacementClient {
        &self.placements
    }

    pub fn audit_log(&self) -> &[AdminAuditRecord] {
        &self.audit_log
    }

    pub fn durability_log(&self) -> &[SystemLogEntry] {
        &self.durability_log
    }

    pub fn record_apply_profile_report(
        &mut self,
        partition_id: impl Into<String>,
        report: WhyApply,
    ) {
        let partition_id = partition_id.into();
        info!(
            "event=admin_apply_profile_report clause={} partition_id={} decision_trace_id={}",
            report.spec_clause, partition_id, report.decision_trace_id
        );
        self.apply_reports.insert(partition_id, report);
    }

    pub fn explain_apply_profile(&self, partition_id: &str) -> Result<WhyApply, AdminError> {
        self.apply_reports
            .get(partition_id)
            .cloned()
            .ok_or(AdminError::UnknownPartition)
    }
}

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("partition not registered in placement cache")]
    UnknownPartition,
    #[error("control plane unavailable: {0:?}")]
    CpUnavailable(Box<CpUnavailableResponse>),
    #[error("mode conflict: requested {requested:?} while current is {current:?}")]
    ModeConflict {
        current: DurabilityMode,
        requested: DurabilityMode,
    },
}

#[derive(Debug, Clone)]
pub struct AdminAuditRecord {
    pub action: String,
    pub partition_id: String,
    pub reason: Option<String>,
    pub recorded_at: Instant,
    pub spec_clause: String,
}

#[derive(Debug, Clone)]
pub struct AdminRequestContext {
    pub principal: SpiffeId,
    pub breakglass_token: Option<BreakGlassToken>,
}

impl AdminRequestContext {
    pub fn new(principal: SpiffeId) -> Self {
        Self {
            principal,
            breakglass_token: None,
        }
    }

    pub fn with_breakglass(mut self, token: BreakGlassToken) -> Self {
        self.breakglass_token = Some(token);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCapability {
    CreatePartition,
    SetDurabilityMode,
    SnapshotThrottle,
    TransferLeader,
    TriggerSnapshot,
}

impl AdminCapability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CreatePartition => "CreatePartition",
            Self::SetDurabilityMode => "SetDurabilityMode",
            Self::SnapshotThrottle => "SnapshotThrottle",
            Self::TransferLeader => "TransferLeader",
            Self::TriggerSnapshot => "TriggerSnapshot",
        }
    }
}

pub struct AdminService {
    handler: AdminHandler,
    rbac: RbacManifestCache,
}

impl AdminService {
    pub fn new(handler: AdminHandler, rbac: RbacManifestCache) -> Self {
        Self { handler, rbac }
    }

    pub fn create_partition(
        &mut self,
        ctx: &AdminRequestContext,
        request: CreatePartitionRequest,
        now: Instant,
    ) -> Result<CreatePartitionResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::CreatePartition, now)?;
        validate_create_partition(&request)?;
        self.handler
            .handle_create_partition(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn set_durability_mode(
        &mut self,
        ctx: &AdminRequestContext,
        request: SetDurabilityModeRequest,
        now: Instant,
    ) -> Result<SetDurabilityModeResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::SetDurabilityMode, now)?;
        validate_set_durability_mode(&request)?;
        self.handler
            .handle_set_durability_mode(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn snapshot_throttle(
        &mut self,
        ctx: &AdminRequestContext,
        request: SnapshotThrottleRequest,
        now: Instant,
    ) -> Result<SnapshotThrottleResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::SnapshotThrottle, now)?;
        validate_snapshot_throttle(&request)?;
        self.handler
            .handle_snapshot_throttle(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn transfer_leader(
        &mut self,
        ctx: &AdminRequestContext,
        request: TransferLeaderRequest,
        now: Instant,
    ) -> Result<TransferLeaderResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::TransferLeader, now)?;
        validate_transfer_leader(&request)?;
        self.handler
            .handle_transfer_leader(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn trigger_snapshot(
        &mut self,
        ctx: &AdminRequestContext,
        request: SnapshotTriggerRequest,
        now: Instant,
    ) -> Result<SnapshotTriggerResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::TriggerSnapshot, now)?;
        validate_snapshot_trigger(&request)?;
        self.handler
            .handle_snapshot_trigger(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn explain_throttle(
        &mut self,
        partition_id: &str,
        decision_trace_id: impl Into<String>,
        now: Instant,
    ) -> Result<ThrottleExplainResponse, AdminServiceError> {
        self.handler
            .explain_throttle(partition_id, decision_trace_id, now)
            .map_err(AdminServiceError::from)
    }

    pub fn explain_apply_profile(
        &mut self,
        partition_id: &str,
    ) -> Result<WhyApply, AdminServiceError> {
        self.handler
            .explain_apply_profile(partition_id)
            .map_err(AdminServiceError::from)
    }

    fn authorize(
        &mut self,
        ctx: &AdminRequestContext,
        capability: AdminCapability,
        now: Instant,
    ) -> Result<(), AdminServiceError> {
        let principal = ctx.principal.canonical();
        let resolved_role = match self.rbac.role_for(&ctx.principal, now) {
            Ok(role) => Some(role),
            Err(SecurityError::Unauthorized) => {
                warn!(
                    "event=admin_authorize clause={} capability={} principal={} outcome=principal_unmapped",
                    ADMIN_API_SPEC,
                    capability.as_str(),
                    principal
                );
                None
            }
            Err(err) => {
                warn!(
                    "event=admin_authorize clause={} capability={} principal={} error={:?}",
                    ADMIN_API_SPEC,
                    capability.as_str(),
                    principal,
                    err
                );
                return Err(AdminServiceError::Security(err));
            }
        };

        if let Some(role_name) = resolved_role.as_deref() {
            match self.rbac.authorize(role_name, capability.as_str(), now) {
                Ok(_) => return Ok(()),
                Err(SecurityError::Unauthorized) => {
                    warn!(
                        "event=admin_authorize clause={} capability={} principal={} role={} outcome=unauthorized",
                        ADMIN_API_SPEC,
                        capability.as_str(),
                        principal,
                        role_name
                    );
                }
                Err(err) => return Err(AdminServiceError::Security(err)),
            }
        }

        if let Some(token) = ctx.breakglass_token.clone() {
            match self
                .rbac
                .apply_breakglass(token.clone(), capability.as_str(), now)
            {
                Ok(_) => {
                    info!(
                        "event=admin_breakglass clause={} capability={} principal={} token_id={}",
                        ADMIN_API_SPEC,
                        capability.as_str(),
                        principal,
                        token.token_id
                    );
                    Ok(())
                }
                Err(err) => {
                    warn!(
                        "event=admin_breakglass_failed clause={} capability={} principal={} error={:?}",
                        ADMIN_API_SPEC,
                        capability.as_str(),
                        principal,
                        err
                    );
                    Err(AdminServiceError::from(err))
                }
            }
        } else {
            Err(AdminServiceError::Security(SecurityError::Unauthorized))
        }
    }

    #[cfg(test)]
    pub fn handler_mut(&mut self) -> &mut AdminHandler {
        &mut self.handler
    }
}

#[derive(Debug, Error)]
pub enum AdminServiceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error(transparent)]
    Admin(#[from] AdminError),
    #[error(transparent)]
    Security(#[from] SecurityError),
}

fn validate_create_partition(request: &CreatePartitionRequest) -> Result<(), AdminServiceError> {
    validate_idempotency_key(&request.idempotency_key)?;
    validate_partition_spec(&request.partition)?;
    if request.replicas.is_empty() {
        return Err(AdminServiceError::InvalidRequest(
            "at least one replica is required".into(),
        ));
    }
    for replica in &request.replicas {
        validate_replica_spec(replica)?;
    }
    Ok(())
}

fn validate_set_durability_mode(
    request: &SetDurabilityModeRequest,
) -> Result<(), AdminServiceError> {
    validate_idempotency_key(&request.idempotency_key)?;
    validate_identifier(&request.partition_id, "partition_id", 64)?;
    Ok(())
}

fn validate_snapshot_throttle(request: &SnapshotThrottleRequest) -> Result<(), AdminServiceError> {
    validate_identifier(&request.partition_id, "partition_id", 64)?;
    if request.reason.trim().is_empty() {
        return Err(AdminServiceError::InvalidRequest(
            "reason is required for snapshot throttle".into(),
        ));
    }
    Ok(())
}

fn validate_transfer_leader(request: &TransferLeaderRequest) -> Result<(), AdminServiceError> {
    validate_idempotency_key(&request.idempotency_key)?;
    validate_identifier(&request.partition_id, "partition_id", 64)?;
    if let Some(replica) = &request.target_replica_id {
        validate_identifier(replica, "target_replica_id", 64)?;
    }
    if let Some(reason) = &request.reason {
        if reason.trim().is_empty() {
            return Err(AdminServiceError::InvalidRequest(
                "reason must not be empty when provided".into(),
            ));
        }
    }
    Ok(())
}

fn validate_snapshot_trigger(request: &SnapshotTriggerRequest) -> Result<(), AdminServiceError> {
    validate_idempotency_key(&request.idempotency_key)?;
    validate_identifier(&request.partition_id, "partition_id", 64)?;
    if request.reason.trim().is_empty() {
        return Err(AdminServiceError::InvalidRequest(
            "reason is required for snapshot trigger".into(),
        ));
    }
    Ok(())
}

fn validate_partition_spec(spec: &PartitionSpec) -> Result<(), AdminServiceError> {
    validate_identifier(&spec.partition_id, "partition_id", 64)?;
    if spec.replicas.is_empty() {
        return Err(AdminServiceError::InvalidRequest(
            "partition replicas must be provided".into(),
        ));
    }
    Ok(())
}

fn validate_replica_spec(replica: &ReplicaSpec) -> Result<(), AdminServiceError> {
    validate_identifier(&replica.replica_id, "replica_id", 64)?;
    validate_identifier(&replica.az, "az", 64)?;
    Ok(())
}

fn validate_idempotency_key(key: &str) -> Result<(), AdminServiceError> {
    validate_identifier(key, "idempotency_key", 128)
}

fn validate_identifier(value: &str, field: &str, max_len: usize) -> Result<(), AdminServiceError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AdminServiceError::InvalidRequest(format!(
            "{field} must not be empty"
        )));
    }
    if trimmed.len() > max_len {
        return Err(AdminServiceError::InvalidRequest(format!(
            "{field} must be <= {max_len} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::ApplyProfileReport;
    use crate::consensus::{
        ConsensusCore, ConsensusCoreConfig, DurabilityProof, StrictFallbackState,
    };
    use crate::cp::{CpProofCoordinator, CpUnavailableReason};
    use crate::security::{
        BreakGlassToken, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole, SpiffeId,
    };
    use crate::system_log::SystemLogEntry;
    use std::time::SystemTime;

    #[test]
    fn handler_preserves_idempotency() {
        let placements = CpPlacementClient::new(Duration::from_secs(60));
        let ledger = IdempotencyLedger::new(Duration::from_secs(60));
        let now = Instant::now();
        let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
        cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
        let mut handler = AdminHandler::new(cp, placements, ledger);
        let request = CreatePartitionRequest {
            idempotency_key: "req1".into(),
            partition: PartitionSpec {
                partition_id: "p1".into(),
                replicas: vec!["r1".into()],
                routing_epoch: 0,
            },
            replicas: vec![ReplicaSpec {
                replica_id: "r1".into(),
                az: "us-east-1a".into(),
            }],
        };
        let first = handler
            .handle_create_partition(request.clone(), now)
            .unwrap();
        let replay = handler
            .handle_create_partition(request, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(first, replay);
    }

    #[test]
    fn durability_and_throttle_admin_requests_record_audit() {
        let placements = CpPlacementClient::new(Duration::from_secs(60));
        let ledger = IdempotencyLedger::new(Duration::from_secs(60));
        let now = Instant::now();
        let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
        cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
        let mut handler = AdminHandler::new(cp, placements, ledger);
        handler.placements.update(
            PlacementRecord {
                partition_id: "p1".into(),
                routing_epoch: 7,
                lease_epoch: 1,
                members: vec!["a".into()],
            },
            now,
        );
        let response = handler
            .handle_set_durability_mode(
                SetDurabilityModeRequest {
                    idempotency_key: "dur1".into(),
                    partition_id: "p1".into(),
                    target_mode: DurabilityMode::Relaxed,
                    expected_mode: DurabilityMode::Strict,
                },
                now,
            )
            .unwrap();
        assert_eq!(response.applied_mode, DurabilityMode::Relaxed);
        assert_eq!(response.durability_mode_epoch, 1);
        let throttle = handler
            .handle_snapshot_throttle(
                SnapshotThrottleRequest {
                    partition_id: "p1".into(),
                    enable: false,
                    reason: "checkpoint".into(),
                },
                now,
            )
            .unwrap();
        assert!(matches!(
            throttle.throttle_state.state,
            FlowThrottleState::Throttled(_)
        ));
        let explain = handler.explain_throttle("p1", "trace-1", now).unwrap();
        assert_eq!(explain.routing_epoch, 7);
        assert_eq!(explain.spec_clause, THROTTLE_SPEC_CLAUSE);
        assert_eq!(handler.audit_log().len(), 2);
        assert!(handler
            .audit_log()
            .iter()
            .all(|record| record.spec_clause == ADMIN_AUDIT_SPEC_CLAUSE));
        let log = handler.durability_log();
        assert_eq!(log.len(), 1);
        match &log[0] {
            SystemLogEntry::DurabilityTransition {
                from_mode,
                to_mode,
                durability_mode_epoch,
                ..
            } => {
                assert_eq!(from_mode, "Strict");
                assert_eq!(to_mode, "Relaxed");
                assert_eq!(*durability_mode_epoch, 1);
            }
            other => panic!("unexpected durability log entry: {other:?}"),
        }
    }

    #[test]
    fn explain_apply_profile_returns_report() {
        let placements = CpPlacementClient::new(Duration::from_secs(60));
        let ledger = IdempotencyLedger::new(Duration::from_secs(60));
        let now = Instant::now();
        let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
        cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
        let mut handler = AdminHandler::new(cp, placements, ledger);
        let report = ApplyProfileReport {
            profile_name: "Aggregator".into(),
            aggregator: true,
            p95_batch_ns: 5_000_000,
            p99_batch_ns: 6_500_000,
            max_batch_entries: 2_048,
            max_ack_defer_ms: 750,
            auto_demoted: true,
        };
        let why = WhyApply {
            decision_trace_id: "trace-apply".into(),
            profile: report.clone(),
            guardrail_level: 2.5,
            guardrail_threshold: 5,
            spec_clause: "§6.4".into(),
        };
        handler.record_apply_profile_report("p1", why.clone());
        let explained = handler.explain_apply_profile("p1").unwrap();
        assert_eq!(explained.profile.profile_name, "Aggregator");
        assert!(explained.profile.auto_demoted);
        assert_eq!(explained.decision_trace_id, "trace-apply");
        assert_eq!(explained.spec_clause, "§6.4");
    }

    #[test]
    fn admin_service_validates_requests() {
        let now = Instant::now();
        let (mut service, ctx) = build_service(now, vec!["CreatePartition", "SnapshotThrottle"]);
        let mut request = create_partition_request();
        request.partition.partition_id.clear();
        let err = service
            .create_partition(&ctx, request, now)
            .expect_err("invalid partition id rejected");
        assert!(matches!(err, AdminServiceError::InvalidRequest(_)));

        let mut throttle = SnapshotThrottleRequest {
            partition_id: "".into(),
            enable: true,
            reason: "".into(),
        };
        let err = service
            .snapshot_throttle(&ctx, throttle.clone(), now)
            .expect_err("partition id required");
        assert!(matches!(err, AdminServiceError::InvalidRequest(_)));
        throttle.partition_id = "p1".into();
        let err = service
            .snapshot_throttle(&ctx, throttle, now)
            .expect_err("reason required");
        assert!(matches!(err, AdminServiceError::InvalidRequest(_)));
    }

    #[test]
    fn admin_service_enforces_rbac_and_supports_breakglass() {
        let now = Instant::now();
        let (mut service, ctx) = build_service(now, vec!["SnapshotThrottle"]);
        let request = SetDurabilityModeRequest {
            idempotency_key: "durability-breakglass".into(),
            partition_id: "p1".into(),
            target_mode: DurabilityMode::Relaxed,
            expected_mode: DurabilityMode::Strict,
        };
        let err = service
            .set_durability_mode(&ctx, request.clone(), now)
            .expect_err("missing capability rejected");
        assert!(matches!(
            err,
            AdminServiceError::Security(SecurityError::Unauthorized)
        ));

        let token = BreakGlassToken {
            token_id: "bg-1".into(),
            spiffe_id: SpiffeId::parse(
                "spiffe://example.org/breakglass/DurabilityOverride/operator",
            )
            .unwrap(),
            scope: "DurabilityOverride".into(),
            ticket_url: "https://ticket/1".into(),
            expires_at: now + Duration::from_secs(60),
            issued_at: SystemTime::now(),
        };
        let ctx =
            AdminRequestContext::new(SpiffeId::parse("spiffe://example.org/operator").unwrap())
                .with_breakglass(token);
        service
            .set_durability_mode(&ctx, request, now)
            .expect("breakglass allows execution");
    }

    #[test]
    fn admin_service_rejects_unmapped_principals() {
        let now = Instant::now();
        let (mut service, _) = build_service(now, vec!["CreatePartition"]);
        let ctx =
            AdminRequestContext::new(SpiffeId::parse("spiffe://example.org/observer").unwrap());
        let err = service
            .create_partition(&ctx, create_partition_request(), now)
            .expect_err("unmapped principal rejected");
        assert!(matches!(
            err,
            AdminServiceError::Security(SecurityError::Unauthorized)
        ));
    }

    #[test]
    fn admin_service_blocks_when_rbac_cache_stale() {
        let now = Instant::now();
        let (mut service, ctx) = build_service(now, vec!["CreatePartition"]);
        let future = now + Duration::from_secs(3_601);
        let err = service
            .create_partition(&ctx, create_partition_request(), future)
            .expect_err("stale cache blocks admin APIs");
        assert!(matches!(
            err,
            AdminServiceError::Security(SecurityError::RbacStale)
        ));
    }

    #[test]
    fn admin_service_surfaces_cp_unavailable_errors() {
        let now = Instant::now();
        let (mut service, ctx) = build_service(now, vec!["CreatePartition"]);
        let future = now + Duration::from_secs(601);
        let err = service
            .create_partition(&ctx, create_partition_request(), future)
            .expect_err("cp unavailable surfaces");
        match err {
            AdminServiceError::Admin(AdminError::CpUnavailable(response)) => {
                assert_eq!(response.reason, CpUnavailableReason::CacheExpired);
            }
            other => panic!("expected cp unavailable error, got {other:?}"),
        }
    }

    #[test]
    fn durability_transition_guard_blocks_during_strict_fallback() {
        let now = Instant::now();
        let mut handler = build_handler(now);
        handler
            .cp_guard
            .load_local_ledger(DurabilityProof::new(9, 90), now);
        let request = SetDurabilityModeRequest {
            idempotency_key: "durability-1".into(),
            partition_id: "p1".into(),
            target_mode: DurabilityMode::Relaxed,
            expected_mode: DurabilityMode::Strict,
        };
        let err = handler
            .handle_set_durability_mode(request.clone(), now)
            .expect_err("strict fallback must block group fsync");
        match err {
            AdminError::CpUnavailable(response) => {
                assert_eq!(response.reason, CpUnavailableReason::NeededForReadIndex);
                assert_eq!(response.strict_state, StrictFallbackState::LocalOnly);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        handler
            .cp_guard
            .publish_cp_proof_at(DurabilityProof::new(9, 90), now + Duration::from_millis(1));
        handler
            .handle_set_durability_mode(request, now + Duration::from_millis(2))
            .expect("guard clears once proof published");
    }

    #[test]
    fn set_durability_mode_detects_mode_conflicts() {
        let now = Instant::now();
        let mut handler = build_handler(now);
        handler
            .handle_set_durability_mode(
                SetDurabilityModeRequest {
                    idempotency_key: "durability-1".into(),
                    partition_id: "p1".into(),
                    target_mode: DurabilityMode::Relaxed,
                    expected_mode: DurabilityMode::Strict,
                },
                now,
            )
            .unwrap();
        let err = handler
            .handle_set_durability_mode(
                SetDurabilityModeRequest {
                    idempotency_key: "durability-stale".into(),
                    partition_id: "p1".into(),
                    target_mode: DurabilityMode::Relaxed,
                    expected_mode: DurabilityMode::Strict,
                },
                now + Duration::from_millis(1),
            )
            .expect_err("stale caller receives ModeConflict");
        assert!(matches!(err, AdminError::ModeConflict { .. }));
    }

    fn build_service(now: Instant, capabilities: Vec<&str>) -> (AdminService, AdminRequestContext) {
        let handler = build_handler(now);
        let mut rbac = RbacManifestCache::new(Duration::from_secs(3_600));
        let manifest = RbacManifest {
            roles: vec![RbacRole {
                name: "operator".into(),
                capabilities: capabilities.into_iter().map(|c| c.to_string()).collect(),
            }],
            principals: vec![RbacPrincipal {
                spiffe_id: "spiffe://example.org/operator".into(),
                role: "operator".into(),
            }],
        };
        rbac.load_manifest(manifest, now).unwrap();
        (
            AdminService::new(handler, rbac),
            AdminRequestContext::new(SpiffeId::parse("spiffe://example.org/operator").unwrap()),
        )
    }

    fn build_handler(now: Instant) -> AdminHandler {
        let placements = CpPlacementClient::new(Duration::from_secs(60));
        let ledger = IdempotencyLedger::new(Duration::from_secs(60));
        let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
        cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
        AdminHandler::new(cp, placements, ledger)
    }

    fn create_partition_request() -> CreatePartitionRequest {
        CreatePartitionRequest {
            idempotency_key: "req1".into(),
            partition: PartitionSpec {
                partition_id: "p1".into(),
                replicas: vec!["r1".into()],
                routing_epoch: 0,
            },
            replicas: vec![ReplicaSpec {
                replica_id: "r1".into(),
                az: "us-west-1a".into(),
            }],
        }
    }
}
