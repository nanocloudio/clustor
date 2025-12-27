use super::api::{
    ArmShrinkPlanRequest, ArmShrinkPlanResponse, CancelShrinkPlanRequest, CancelShrinkPlanResponse,
    CreatePartitionRequest, CreatePartitionResponse, CreateShrinkPlanRequest,
    CreateShrinkPlanResponse, ListShrinkPlansResponse, PartitionSpec, ReplicaSpec,
    SetDurabilityModeRequest, SetDurabilityModeResponse, ShrinkTargetPlacement,
    SnapshotThrottleRequest, SnapshotThrottleResponse, SnapshotTriggerRequest,
    SnapshotTriggerResponse, ThrottleExplainResponse, TransferLeaderRequest,
    TransferLeaderResponse, ADMIN_API_SPEC,
};
use super::workflows::AdminHandler;
use super::workflows_error::AdminError;
use crate::replication::apply::WhyApply;
use crate::security::{BreakGlassToken, RbacManifestCache, SecurityError, SpiffeId};
use log::{info, warn};
use std::time::Instant;
use thiserror::Error;

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
    ManageShrinkPlan,
}

impl AdminCapability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CreatePartition => "CreatePartition",
            Self::SetDurabilityMode => "SetDurabilityMode",
            Self::SnapshotThrottle => "SnapshotThrottle",
            Self::TransferLeader => "TransferLeader",
            Self::TriggerSnapshot => "TriggerSnapshot",
            Self::ManageShrinkPlan => "ManageShrinkPlan",
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

    pub fn create_shrink_plan(
        &mut self,
        ctx: &AdminRequestContext,
        request: CreateShrinkPlanRequest,
        now: Instant,
    ) -> Result<CreateShrinkPlanResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::ManageShrinkPlan, now)?;
        validate_create_shrink_plan(&request)?;
        self.handler
            .handle_create_shrink_plan(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn arm_shrink_plan(
        &mut self,
        ctx: &AdminRequestContext,
        request: ArmShrinkPlanRequest,
        now: Instant,
    ) -> Result<ArmShrinkPlanResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::ManageShrinkPlan, now)?;
        validate_plan_id(&request.plan_id)?;
        self.handler
            .handle_arm_shrink_plan(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn cancel_shrink_plan(
        &mut self,
        ctx: &AdminRequestContext,
        request: CancelShrinkPlanRequest,
        now: Instant,
    ) -> Result<CancelShrinkPlanResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::ManageShrinkPlan, now)?;
        validate_plan_id(&request.plan_id)?;
        self.handler
            .handle_cancel_shrink_plan(request, now)
            .map_err(AdminServiceError::from)
    }

    pub fn list_shrink_plans(
        &mut self,
        ctx: &AdminRequestContext,
        now: Instant,
    ) -> Result<ListShrinkPlansResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::ManageShrinkPlan, now)?;
        Ok(self.handler.list_shrink_plans())
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

fn validate_create_shrink_plan(request: &CreateShrinkPlanRequest) -> Result<(), AdminServiceError> {
    validate_plan_id(&request.plan_id)?;
    if request.target_placements.is_empty() {
        return Err(AdminServiceError::InvalidRequest(
            "at least one target placement is required".into(),
        ));
    }
    for target in &request.target_placements {
        validate_shrink_target(target)?;
    }
    Ok(())
}

fn validate_shrink_target(target: &ShrinkTargetPlacement) -> Result<(), AdminServiceError> {
    validate_identifier(&target.prg_id, "prg_id", 64)?;
    if target.target_members.is_empty() {
        return Err(AdminServiceError::InvalidRequest(
            "target_members must not be empty".into(),
        ));
    }
    for member in &target.target_members {
        validate_identifier(member, "target_member", 64)?;
    }
    Ok(())
}

fn validate_plan_id(plan_id: &str) -> Result<(), AdminServiceError> {
    validate_identifier(plan_id, "plan_id", 128)
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
