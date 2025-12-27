use crate::control_plane::core::{CpPlacementClient, CpProofCoordinator, PlacementRecord};
use crate::replication::apply::WhyApply;
use crate::replication::flow::{
    CreditHint, FlowThrottleEnvelope, FlowThrottleReason, FlowThrottleState, IngestStatusCode,
};
use crate::system_log::SystemLogEntry;
use crate::telemetry::MetricsRegistry;
use log::info;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use super::api::{
    ArmShrinkPlanRequest, ArmShrinkPlanResponse, CancelShrinkPlanRequest, CancelShrinkPlanResponse,
    CreatePartitionRequest, CreatePartitionResponse, CreateShrinkPlanRequest,
    CreateShrinkPlanResponse, DurabilityMode, ListShrinkPlansResponse, SetDurabilityModeRequest,
    SetDurabilityModeResponse, ShrinkPlanState, ShrinkPlanStatus, SnapshotThrottleRequest,
    SnapshotThrottleResponse, SnapshotTriggerRequest, SnapshotTriggerResponse,
    ThrottleExplainResponse, TransferLeaderRequest, TransferLeaderResponse, ADMIN_API_SPEC,
    ADMIN_AUDIT_SPEC_CLAUSE, THROTTLE_SPEC_CLAUSE,
};
use super::audit::{AdminAuditRecord, AdminAuditStore};
use super::guard;
use super::workflows_error::AdminError;
use super::workflows_ledger::IdempotencyLedger;
use super::workflows_state::ShrinkPlanTelemetry;
use crate::internal::admin::{DurabilityState, ShrinkPlanRecord, ShrinkTarget};

pub struct AdminHandler {
    cp_guard: CpProofCoordinator,
    placements: CpPlacementClient,
    create_partition_ledger: IdempotencyLedger<CreatePartitionResponse>,
    durability_ledger: IdempotencyLedger<SetDurabilityModeResponse>,
    transfer_ledger: IdempotencyLedger<TransferLeaderResponse>,
    snapshot_trigger_ledger: IdempotencyLedger<SnapshotTriggerResponse>,
    durability_modes: HashMap<String, DurabilityState>,
    throttle_state: HashMap<String, FlowThrottleEnvelope>,
    shrink_plans: HashMap<String, ShrinkPlanRecord>,
    audit_log: AdminAuditStore,
    apply_reports: HashMap<String, WhyApply>,
    durability_log: Vec<SystemLogEntry>,
    clock_base: Instant,
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
            shrink_plans: HashMap::new(),
            audit_log: AdminAuditStore::with_default_capacity(),
            apply_reports: HashMap::new(),
            durability_log: Vec::new(),
            clock_base: Instant::now(),
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
            self.create_partition_ledger.len(),
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
        let (applied_mode, durability_epoch) = {
            let state = self
                .durability_modes
                .entry(partition_id.clone())
                .or_insert_with(DurabilityState::new);
            if state.mode() != request.expected_mode {
                return Err(AdminError::ModeConflict {
                    current: state.mode(),
                    requested: target_mode,
                });
            }
            if state.mode() != target_mode && matches!(target_mode, DurabilityMode::Relaxed) {
                guard::guard_result(self.cp_guard.guard_durability_transition(now))?;
            }
            if state.mode() != target_mode {
                let previous = state.mode();
                state.set_mode(target_mode.clone());
                self.durability_log
                    .push(SystemLogEntry::DurabilityTransition {
                        from_mode: format!("{previous:?}"),
                        to_mode: format!("{target_mode:?}"),
                        effective_index: state.epoch(),
                        durability_mode_epoch: state.epoch(),
                    });
            }
            (state.mode(), state.epoch())
        };
        self.record_audit(AdminAuditRecord {
            action: "SetDurabilityMode".into(),
            partition_id: partition_id.clone(),
            reason: None,
            recorded_at: now,
            spec_clause: ADMIN_AUDIT_SPEC_CLAUSE.into(),
        });
        let response = SetDurabilityModeResponse {
            partition_id,
            applied_mode,
            durability_mode_epoch: durability_epoch,
        };
        self.durability_ledger
            .record(request.idempotency_key, response.clone(), now);
        info!(
            "event=admin_set_durability clause={} partition_id={} target_mode={:?} epoch={}",
            ADMIN_API_SPEC, response.partition_id, target_mode, durability_epoch
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
        self.record_audit(AdminAuditRecord {
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
        self.record_audit(AdminAuditRecord {
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
        self.record_audit(AdminAuditRecord {
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
        guard::guard_result(self.cp_guard.guard_admin(now))
    }

    fn record_audit(&mut self, record: AdminAuditRecord) {
        if let Some(evicted) = self.audit_log.record(record) {
            self.durability_log.push(SystemLogEntry::AdminAuditSpill {
                action: evicted.action,
                partition_id: evicted.partition_id,
                reason: evicted.reason,
            });
        }
    }

    fn timestamp_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.clock_base).as_millis() as u64
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

    pub fn audit_log(&self) -> Vec<AdminAuditRecord> {
        self.audit_log.snapshot()
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

    pub fn handle_create_shrink_plan(
        &mut self,
        request: CreateShrinkPlanRequest,
        now: Instant,
    ) -> Result<CreateShrinkPlanResponse, AdminError> {
        self.guard_cp(now)?;
        if self.shrink_plans.contains_key(&request.plan_id) {
            return Err(AdminError::ShrinkPlanExists {
                plan_id: request.plan_id,
            });
        }
        if request.target_placements.is_empty() {
            return Err(AdminError::InvalidShrinkPlan {
                reason: "at least one target placement is required".into(),
            });
        }
        let created_at_ms = self.timestamp_ms(now);
        let mut targets = Vec::new();
        for target in request.target_placements.iter() {
            let placement = self
                .placements
                .placement_snapshot(&target.prg_id)
                .ok_or(AdminError::UnknownPartition)?;
            if target.target_members.is_empty() {
                return Err(AdminError::InvalidShrinkPlan {
                    reason: format!("target_members empty for {}", target.prg_id),
                });
            }
            let mut seen = HashSet::new();
            let mut members = Vec::new();
            for member in &target.target_members {
                if seen.insert(member.clone()) {
                    members.push(member.clone());
                }
            }
            if members.len() >= placement.record.members.len() {
                return Err(AdminError::InvalidShrinkPlan {
                    reason: format!(
                        "shrink must reduce member count for {} (current {}, target {})",
                        target.prg_id,
                        placement.record.members.len(),
                        members.len()
                    ),
                });
            }
            if !members
                .iter()
                .all(|member| placement.record.members.contains(member))
            {
                return Err(AdminError::InvalidShrinkPlan {
                    reason: format!(
                        "target_members for {} must be subset of current placement",
                        target.prg_id
                    ),
                });
            }
            if target.target_routing_epoch <= placement.record.routing_epoch {
                return Err(AdminError::InvalidShrinkPlan {
                    reason: format!(
                        "target_routing_epoch for {} must be greater than current epoch {}",
                        target.prg_id, placement.record.routing_epoch
                    ),
                });
            }
            targets.push(ShrinkTarget {
                prg_id: target.prg_id.clone(),
                target_members: members,
                target_routing_epoch: target.target_routing_epoch,
            });
        }
        let record = ShrinkPlanRecord::new(request.plan_id.clone(), targets, created_at_ms);
        let status = record.status();
        self.shrink_plans.insert(request.plan_id, record);
        Ok(CreateShrinkPlanResponse { plan: status })
    }

    pub fn handle_arm_shrink_plan(
        &mut self,
        request: ArmShrinkPlanRequest,
        now: Instant,
    ) -> Result<ArmShrinkPlanResponse, AdminError> {
        self.guard_cp(now)?;
        let armed_ts = self.timestamp_ms(now);
        if let Some((plan_id, _)) = self
            .shrink_plans
            .iter()
            .find(|(id, plan)| plan.state == ShrinkPlanState::Armed && **id != request.plan_id)
        {
            return Err(AdminError::ShrinkPlanActive {
                plan_id: plan_id.clone(),
            });
        }
        let plan =
            self.shrink_plans
                .get_mut(&request.plan_id)
                .ok_or(AdminError::ShrinkPlanNotFound {
                    plan_id: request.plan_id.clone(),
                })?;
        if plan.state == ShrinkPlanState::Cancelled {
            return Err(AdminError::ShrinkPlanCancelled {
                plan_id: request.plan_id,
            });
        }
        plan.arm(armed_ts);
        Ok(ArmShrinkPlanResponse {
            plan: plan.status(),
        })
    }

    pub fn handle_cancel_shrink_plan(
        &mut self,
        request: CancelShrinkPlanRequest,
        now: Instant,
    ) -> Result<CancelShrinkPlanResponse, AdminError> {
        self.guard_cp(now)?;
        let ts = self.timestamp_ms(now);
        let plan =
            self.shrink_plans
                .get_mut(&request.plan_id)
                .ok_or(AdminError::ShrinkPlanNotFound {
                    plan_id: request.plan_id.clone(),
                })?;
        plan.cancel(ts);
        Ok(CancelShrinkPlanResponse {
            plan: plan.status(),
        })
    }

    pub fn list_shrink_plans(&self) -> ListShrinkPlansResponse {
        let mut plans: Vec<_> = self
            .shrink_plans
            .values()
            .map(ShrinkPlanRecord::status)
            .collect();
        plans.sort_by(|a, b| a.plan_id.cmp(&b.plan_id));
        ListShrinkPlansResponse { plans }
    }

    pub fn shrink_plan_status(&self) -> Vec<ShrinkPlanStatus> {
        self.list_shrink_plans().plans
    }

    pub fn routing_bundle(&self) -> RoutingPublication {
        let mut placements = self.placements.records();
        let mut applied_plan = None;
        if let Some(plan) = self
            .shrink_plans
            .values()
            .find(|plan| plan.state == ShrinkPlanState::Armed)
        {
            applied_plan = Some(plan.plan_id.clone());
            for target in &plan.targets {
                if let Some(record) = placements.get_mut(&target.prg_id) {
                    record.routing_epoch = target.target_routing_epoch;
                    record.members = target.target_members.clone();
                }
            }
        }
        RoutingPublication {
            placements,
            shrink_plans: self.shrink_plan_status(),
            applied_plan_id: applied_plan,
        }
    }

    pub fn shrink_plan_telemetry(&self) -> ShrinkPlanTelemetry {
        let mut telemetry = ShrinkPlanTelemetry::default();
        for plan in self.shrink_plans.values() {
            telemetry.total += 1;
            match plan.state {
                ShrinkPlanState::Armed => telemetry.armed += 1,
                ShrinkPlanState::Cancelled | ShrinkPlanState::RolledBack => {
                    telemetry.cancelled += 1
                }
                ShrinkPlanState::Draft => {}
            }
        }
        telemetry
    }

    pub fn publish_shrink_plan_metrics(&self, registry: &mut MetricsRegistry) {
        let telemetry = self.shrink_plan_telemetry();
        registry.set_gauge("cp.shrink_plans.total", telemetry.total as u64);
        registry.set_gauge("cp.shrink_plans.armed", telemetry.armed as u64);
        registry.set_gauge("cp.shrink_plans.cancelled", telemetry.cancelled as u64);
    }
}

#[derive(Debug, Clone)]
pub struct RoutingPublication {
    pub placements: HashMap<String, PlacementRecord>,
    pub shrink_plans: Vec<ShrinkPlanStatus>,
    pub applied_plan_id: Option<String>,
}
