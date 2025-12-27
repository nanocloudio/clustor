#![cfg(feature = "admin-http")]

use clustor::control_plane::admin::{
    AdminError, AdminHandler, AdminRequestContext, AdminService, AdminServiceError,
    ArmShrinkPlanRequest, CancelShrinkPlanRequest, CreatePartitionRequest, CreateShrinkPlanRequest,
    DurabilityMode, IdempotencyLedger, PartitionSpec, ReplicaSpec, SetDurabilityModeRequest,
    ShrinkPlanState, ShrinkTargetPlacement, SnapshotThrottleRequest, ADMIN_AUDIT_SPEC_CLAUSE,
    THROTTLE_SPEC_CLAUSE,
};
use clustor::control_plane::core::{
    CpPlacementClient, CpProofCoordinator, CpUnavailableReason, PlacementRecord,
};
use clustor::replication::apply::{ApplyProfileReport, WhyApply};
use clustor::replication::consensus::{ConsensusCore, ConsensusCoreConfig, DurabilityProof};
use clustor::replication::flow::FlowThrottleState;
use clustor::security::{
    BreakGlassToken, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole, SecurityError,
    SpiffeId,
};
use clustor::system_log::SystemLogEntry;
use clustor::telemetry::MetricsRegistry;
use std::time::{Duration, Instant, SystemTime};

#[test]
fn handler_preserves_idempotency() {
    let now = Instant::now();
    let mut handler = build_handler(now);
    let request = create_partition_request();
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
    let now = Instant::now();
    let mut handler = handler_with_placements(
        now,
        vec![PlacementRecord {
            partition_id: "p1".into(),
            routing_epoch: 7,
            lease_epoch: 1,
            members: vec!["a".into()],
        }],
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
    let audit = handler.audit_log();
    assert_eq!(audit.len(), 2);
    assert!(audit
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
    let now = Instant::now();
    let mut handler = build_handler(now);
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
        spiffe_id: SpiffeId::parse("spiffe://example.org/breakglass/DurabilityOverride/operator")
            .unwrap(),
        scope: "DurabilityOverride".into(),
        ticket_url: "https://ticket/1".into(),
        expires_at: now + Duration::from_secs(60),
        issued_at: SystemTime::now(),
    };
    let ctx = AdminRequestContext::new(SpiffeId::parse("spiffe://example.org/operator").unwrap())
        .with_breakglass(token);
    service
        .set_durability_mode(&ctx, request, now)
        .expect("breakglass allows execution");
}

#[test]
fn admin_service_rejects_unmapped_principals() {
    let now = Instant::now();
    let (mut service, _) = build_service(now, vec!["CreatePartition"]);
    let ctx = AdminRequestContext::new(SpiffeId::parse("spiffe://example.org/observer").unwrap());
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
    let future = now + Duration::from_secs(7_201);
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
        AdminServiceError::Admin(AdminError::CpUnavailable { response, .. }) => {
            assert_eq!(response.reason, CpUnavailableReason::CacheExpired);
        }
        other => panic!("expected cp unavailable error, got {other:?}"),
    }
}

#[test]
fn durability_transition_guard_blocks_during_strict_fallback() {
    let now = Instant::now();
    let mut handler = handler_in_strict_fallback(now);
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
        AdminError::CpUnavailable { response, .. } => {
            assert_eq!(response.reason, CpUnavailableReason::NeededForReadIndex);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let mut handler = build_handler(now + Duration::from_millis(2));
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

#[test]
fn shrink_plan_requires_arm_and_rolls_back() {
    let now = Instant::now();
    let mut handler = handler_with_placements(
        now,
        vec![PlacementRecord {
            partition_id: "p1".into(),
            routing_epoch: 1,
            lease_epoch: 1,
            members: vec!["a".into(), "b".into(), "c".into()],
        }],
    );
    let created = handler
        .handle_create_shrink_plan(
            CreateShrinkPlanRequest {
                plan_id: "plan-1".into(),
                target_placements: vec![ShrinkTargetPlacement {
                    prg_id: "p1".into(),
                    target_members: vec!["a".into(), "b".into()],
                    target_routing_epoch: 2,
                }],
            },
            now,
        )
        .expect("plan created");
    assert_eq!(created.plan.state, ShrinkPlanState::Draft);
    let initial = handler.routing_bundle();
    assert!(initial.applied_plan_id.is_none());
    assert_eq!(initial.placements["p1"].members.len(), 3);

    handler
        .handle_arm_shrink_plan(
            ArmShrinkPlanRequest {
                plan_id: "plan-1".into(),
            },
            now + Duration::from_millis(1),
        )
        .expect("plan armed");
    let armed = handler.routing_bundle();
    assert_eq!(armed.applied_plan_id.as_deref(), Some("plan-1"));
    assert_eq!(
        armed.placements["p1"].members,
        vec!["a".to_string(), "b".to_string()]
    );
    assert_eq!(armed.placements["p1"].routing_epoch, 2);

    handler
        .handle_cancel_shrink_plan(
            CancelShrinkPlanRequest {
                plan_id: "plan-1".into(),
            },
            now + Duration::from_millis(2),
        )
        .expect("plan cancelled");
    let rolled_back = handler.routing_bundle();
    assert!(rolled_back.applied_plan_id.is_none());
    assert_eq!(rolled_back.placements["p1"].members.len(), 3);
    let status = handler.list_shrink_plans().plans;
    assert_eq!(status.len(), 1);
    assert_eq!(status[0].state, ShrinkPlanState::RolledBack);
}

#[test]
fn shrink_plan_validates_subset_and_reports_telemetry() {
    let now = Instant::now();
    let mut handler = handler_with_placements(
        now,
        vec![PlacementRecord {
            partition_id: "p2".into(),
            routing_epoch: 5,
            lease_epoch: 1,
            members: vec!["x".into(), "y".into(), "z".into()],
        }],
    );
    let err = handler
        .handle_create_shrink_plan(
            CreateShrinkPlanRequest {
                plan_id: "plan-2".into(),
                target_placements: vec![ShrinkTargetPlacement {
                    prg_id: "p2".into(),
                    target_members: vec!["x".into(), "missing".into()],
                    target_routing_epoch: 6,
                }],
            },
            now,
        )
        .expect_err("invalid member rejected");
    assert!(matches!(err, AdminError::InvalidShrinkPlan { .. }));

    handler
        .handle_create_shrink_plan(
            CreateShrinkPlanRequest {
                plan_id: "plan-2".into(),
                target_placements: vec![ShrinkTargetPlacement {
                    prg_id: "p2".into(),
                    target_members: vec!["x".into(), "y".into()],
                    target_routing_epoch: 6,
                }],
            },
            now,
        )
        .expect("second plan created");
    let telemetry = handler.shrink_plan_telemetry();
    assert_eq!(telemetry.total, 1);
    assert_eq!(telemetry.armed, 0);
    assert_eq!(telemetry.cancelled, 0);
    let mut registry = MetricsRegistry::new("clustor");
    handler.publish_shrink_plan_metrics(&mut registry);
    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot.gauges.get("clustor.cp.shrink_plans.total"),
        Some(&1)
    );
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
    handler_with_placements(now, Vec::new())
}

fn handler_with_placements(now: Instant, records: Vec<PlacementRecord>) -> AdminHandler {
    let mut placements = CpPlacementClient::new(Duration::from_secs(60));
    for record in records {
        placements.update(record, now);
    }
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
    AdminHandler::new(cp, placements, ledger)
}

fn handler_in_strict_fallback(now: Instant) -> AdminHandler {
    let placements = CpPlacementClient::new(Duration::from_secs(60));
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    cp.load_local_ledger(DurabilityProof::new(9, 90), now);
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
