use crate::apply::WhyApply;
use crate::cp::{CpProofCoordinator, CpUnavailableResponse};
use crate::cp_raft::{CpPlacementClient, PlacementRecord};
use crate::flow::{FlowThrottleEnvelope, FlowThrottleReason, FlowThrottleState};
use crate::security::{BreakGlassToken, RbacManifestCache, SecurityError};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDurabilityModeRequest {
    pub idempotency_key: String,
    pub partition_id: String,
    pub target_mode: DurabilityMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDurabilityModeResponse {
    pub partition_id: String,
    pub applied_mode: DurabilityMode,
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

#[derive(Debug, Clone, Serialize)]
pub struct ThrottleExplainResponse {
    pub partition_id: String,
    pub envelope: FlowThrottleEnvelope,
    pub decision_trace_id: String,
    pub routing_epoch: u64,
    pub spec_clause: String,
}

#[derive(Debug, Clone)]
pub struct IdempotencyLedger {
    entries: HashMap<String, LedgerRecord>,
    retention: Duration,
}

#[derive(Debug, Clone)]
struct LedgerRecord {
    response: CreatePartitionResponse,
    stored_at: Instant,
}

impl IdempotencyLedger {
    pub fn new(retention: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            retention,
        }
    }

    pub fn record(&mut self, key: String, response: CreatePartitionResponse, now: Instant) {
        self.entries.insert(
            key,
            LedgerRecord {
                response,
                stored_at: now,
            },
        );
        self.evict(now);
    }

    pub fn get(&mut self, key: &str, now: Instant) -> Option<CreatePartitionResponse> {
        self.evict(now);
        self.entries.get(key).map(|record| record.response.clone())
    }

    fn evict(&mut self, now: Instant) {
        self.entries
            .retain(|_, record| now.saturating_duration_since(record.stored_at) < self.retention);
    }
}

pub struct AdminHandler {
    cp_guard: CpProofCoordinator,
    placements: CpPlacementClient,
    ledger: IdempotencyLedger,
    durability_modes: HashMap<String, DurabilityMode>,
    throttle_state: HashMap<String, FlowThrottleEnvelope>,
    audit_log: Vec<AdminAuditRecord>,
    apply_reports: HashMap<String, WhyApply>,
}

impl AdminHandler {
    pub fn new(
        cp_guard: CpProofCoordinator,
        placements: CpPlacementClient,
        ledger: IdempotencyLedger,
    ) -> Self {
        Self {
            cp_guard,
            placements,
            ledger,
            durability_modes: HashMap::new(),
            throttle_state: HashMap::new(),
            audit_log: Vec::new(),
            apply_reports: HashMap::new(),
        }
    }

    pub fn handle_create_partition(
        &mut self,
        request: CreatePartitionRequest,
        now: Instant,
    ) -> Result<CreatePartitionResponse, AdminError> {
        self.guard_cp(now)?;
        if let Some(response) = self.ledger.get(&request.idempotency_key, now) {
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
        self.ledger
            .record(request.idempotency_key, response.clone(), now);
        info!(
            "event=admin_create_partition clause={} partition_id={} routing_epoch={} replicas={} ledger_entries={} idempotency_key={}",
            ADMIN_API_SPEC,
            response.partition_id,
            response.routing_epoch,
            replica_count,
            self.ledger.entries.len(),
            idempotency_key
        );
        Ok(response)
    }

    pub fn handle_update_durability_mode(
        &mut self,
        request: UpdateDurabilityModeRequest,
        now: Instant,
    ) -> Result<UpdateDurabilityModeResponse, AdminError> {
        self.guard_cp(now)?;
        let partition_id = request.partition_id.clone();
        let target_mode = request.target_mode.clone();
        self.durability_modes
            .insert(partition_id.clone(), target_mode.clone());
        self.audit_log.push(AdminAuditRecord {
            action: "UpdateDurabilityMode".into(),
            partition_id: partition_id.clone(),
            reason: None,
            recorded_at: now,
            spec_clause: ADMIN_AUDIT_SPEC_CLAUSE.into(),
        });
        info!(
            "event=admin_update_durability clause={} partition_id={} target_mode={:?}",
            ADMIN_API_SPEC, partition_id, target_mode
        );
        Ok(UpdateDurabilityModeResponse {
            partition_id,
            applied_mode: target_mode,
        })
    }

    pub fn handle_snapshot_throttle(
        &mut self,
        request: SnapshotThrottleRequest,
        now: Instant,
    ) -> Result<SnapshotThrottleResponse, AdminError> {
        self.guard_cp(now)?;
        let partition_id = request.partition_id.clone();
        let envelope = if request.enable {
            FlowThrottleEnvelope {
                state: FlowThrottleState::Open,
            }
        } else {
            FlowThrottleEnvelope {
                state: FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt {
                    byte_credit: 0,
                }),
            }
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
                .unwrap_or(FlowThrottleEnvelope {
                    state: FlowThrottleState::Open,
                });
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
    pub role: String,
    pub breakglass_token: Option<BreakGlassToken>,
}

impl AdminRequestContext {
    pub fn new(role: impl Into<String>) -> Self {
        Self {
            role: role.into(),
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
    UpdateDurabilityMode,
    SnapshotThrottle,
}

impl AdminCapability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CreatePartition => "CreatePartition",
            Self::UpdateDurabilityMode => "UpdateDurabilityMode",
            Self::SnapshotThrottle => "SnapshotThrottle",
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

    pub fn update_durability_mode(
        &mut self,
        ctx: &AdminRequestContext,
        request: UpdateDurabilityModeRequest,
        now: Instant,
    ) -> Result<UpdateDurabilityModeResponse, AdminServiceError> {
        self.authorize(ctx, AdminCapability::UpdateDurabilityMode, now)?;
        validate_update_durability_mode(&request)?;
        self.handler
            .handle_update_durability_mode(request, now)
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
        match self.rbac.authorize(&ctx.role, capability.as_str(), now) {
            Ok(_) => Ok(()),
            Err(SecurityError::Unauthorized) => {
                warn!(
                    "event=admin_authorize clause={} capability={} role={} outcome=unauthorized",
                    ADMIN_API_SPEC,
                    capability.as_str(),
                    ctx.role.as_str(),
                );
                if let Some(token) = ctx.breakglass_token.clone() {
                    match self
                        .rbac
                        .apply_breakglass(token.clone(), capability.as_str(), now)
                    {
                        Ok(_) => {
                            info!(
                                "event=admin_breakglass clause={} capability={} role={} token_id={}",
                                ADMIN_API_SPEC,
                                capability.as_str(),
                                ctx.role,
                                token.token_id
                            );
                            Ok(())
                        }
                        Err(err) => {
                            warn!(
                                "event=admin_breakglass_failed clause={} capability={} role={} error={:?}",
                                ADMIN_API_SPEC,
                                capability.as_str(),
                                ctx.role,
                                err
                            );
                            Err(AdminServiceError::from(err))
                        }
                    }
                } else {
                    Err(AdminServiceError::Security(SecurityError::Unauthorized))
                }
            }
            Err(err) => Err(AdminServiceError::Security(err)),
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

fn validate_update_durability_mode(
    request: &UpdateDurabilityModeRequest,
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
    use crate::consensus::{ConsensusCore, ConsensusCoreConfig, DurabilityProof};
    use crate::cp::{CpProofCoordinator, CpUnavailableReason};
    use crate::security::{BreakGlassToken, RbacManifestCache, SpiffeId};

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
        handler
            .handle_update_durability_mode(
                UpdateDurabilityModeRequest {
                    idempotency_key: "dur1".into(),
                    partition_id: "p1".into(),
                    target_mode: DurabilityMode::Relaxed,
                },
                now,
            )
            .unwrap();
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
        let err = service
            .create_partition(&ctx, create_partition_request(), now)
            .expect_err("missing capability rejected");
        assert!(matches!(
            err,
            AdminServiceError::Security(SecurityError::Unauthorized)
        ));

        let token = BreakGlassToken {
            token_id: "bg-1".into(),
            spiffe_id: SpiffeId::parse("spiffe://example.org/operator").unwrap(),
            scope: "CreatePartition".into(),
            ticket_url: "https://ticket/1".into(),
            expires_at: now + Duration::from_secs(60),
        };
        let ctx = AdminRequestContext::new("operator").with_breakglass(token);
        service
            .create_partition(&ctx, create_partition_request(), now)
            .expect("breakglass allows execution");
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

    fn build_service(now: Instant, capabilities: Vec<&str>) -> (AdminService, AdminRequestContext) {
        let handler = build_handler(now);
        let mut rbac = RbacManifestCache::new(Duration::from_secs(3_600));
        let mut roles = HashMap::new();
        roles.insert(
            "operator".into(),
            capabilities.into_iter().map(|c| c.to_string()).collect(),
        );
        rbac.load_manifest(roles, now);
        (
            AdminService::new(handler, rbac),
            AdminRequestContext::new("operator"),
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
