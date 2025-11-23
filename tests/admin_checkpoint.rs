#![cfg(feature = "admin-http")]

use clustor::{
    AdminError, AdminHandler, AdminRequestContext, AdminService, AdminServiceError,
    CpPlacementClient, CpProofCoordinator, CpUnavailableReason, CreatePartitionRequest,
    DurabilityMode, DurabilityProof, IdempotencyLedger, PartitionSpec, PlacementRecord,
    RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole, ReplicaSpec,
    SetDurabilityModeRequest, SnapshotTriggerRequest, SpiffeId, TransferLeaderRequest,
};
use clustor::{ConsensusCore, ConsensusCoreConfig};
use std::time::{Duration, Instant};

#[test]
fn admin_checkpoint_handles_partition_lifecycle() {
    let placements = CpPlacementClient::new(Duration::from_secs(60));
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let now = Instant::now();
    let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
    let mut handler = AdminHandler::new(cp, placements, ledger);
    let request = CreatePartitionRequest {
        idempotency_key: "k1".into(),
        partition: PartitionSpec {
            partition_id: "partition-a".into(),
            replicas: vec!["replica-a".into()],
            routing_epoch: 0,
        },
        replicas: vec![ReplicaSpec {
            replica_id: "replica-a".into(),
            az: "us-east-1a".into(),
        }],
    };
    let response = handler
        .handle_create_partition(request.clone(), now)
        .expect("create succeeds");
    assert_eq!(response.partition_id, "partition-a");
    assert_eq!(response.routing_epoch, 1);

    let replay = handler
        .handle_create_partition(request, now + Duration::from_secs(1))
        .expect("idempotent replay succeeds");
    assert_eq!(response, replay);
}

#[test]
fn admin_checkpoint_explains_throttle_and_audit() {
    use clustor::{
        DurabilityMode, PlacementRecord, SetDurabilityModeRequest, SnapshotThrottleRequest,
    };
    let mut placements = CpPlacementClient::new(Duration::from_secs(60));
    let now = Instant::now();
    placements.update(
        PlacementRecord {
            partition_id: "p2".into(),
            routing_epoch: 9,
            lease_epoch: 1,
            members: vec!["x".into()],
        },
        now,
    );
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
    let mut handler = AdminHandler::new(cp, placements, ledger);
    handler
        .handle_set_durability_mode(
            SetDurabilityModeRequest {
                idempotency_key: "durability".into(),
                partition_id: "p2".into(),
                target_mode: DurabilityMode::Strict,
                expected_mode: DurabilityMode::Strict,
            },
            now,
        )
        .unwrap();
    handler
        .handle_snapshot_throttle(
            SnapshotThrottleRequest {
                partition_id: "p2".into(),
                enable: false,
                reason: "cp-outage".into(),
            },
            now,
        )
        .unwrap();
    let explain = handler
        .explain_throttle("p2", "trace-checkpoint", now)
        .expect("explain available");
    assert_eq!(explain.routing_epoch, 9);
    assert_eq!(explain.spec_clause, "§10.3");
    assert_eq!(handler.audit_log().len(), 2);
    assert!(handler
        .audit_log()
        .iter()
        .all(|record| record.spec_clause == "§12.3"));
}

#[test]
fn admin_api_checkpoint_covers_success_and_strict_fallback() {
    let placements = CpPlacementClient::new(Duration::from_secs(60));
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let now = Instant::now();
    let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
    let handler = AdminHandler::new(cp, placements, ledger);
    let mut rbac = RbacManifestCache::new(Duration::from_secs(3_600));
    let manifest = RbacManifest {
        roles: vec![RbacRole {
            name: "operator".into(),
            capabilities: vec![
                "CreatePartition".into(),
                "SetDurabilityMode".into(),
                "SnapshotThrottle".into(),
            ],
        }],
        principals: vec![RbacPrincipal {
            spiffe_id: "spiffe://example.org/operator".into(),
            role: "operator".into(),
        }],
    };
    rbac.load_manifest(manifest, now).unwrap();
    let mut service = AdminService::new(handler, rbac);
    let ctx = AdminRequestContext::new(SpiffeId::parse("spiffe://example.org/operator").unwrap());
    let request = CreatePartitionRequest {
        idempotency_key: "api-success".into(),
        partition: PartitionSpec {
            partition_id: "api-partition".into(),
            replicas: vec!["api-replica".into()],
            routing_epoch: 0,
        },
        replicas: vec![ReplicaSpec {
            replica_id: "api-replica".into(),
            az: "us-west-2a".into(),
        }],
    };
    let response = service
        .create_partition(&ctx, request.clone(), now)
        .expect("admin api succeeds");
    assert_eq!(response.partition_id, "api-partition");
    assert_eq!(response.routing_epoch, 1);

    let future = now + Duration::from_secs(601);
    let mut failure_request = request;
    failure_request.idempotency_key = "api-fail".into();
    let err = service
        .create_partition(&ctx, failure_request, future)
        .expect_err("strict fallback rejection surfaces");
    match err {
        AdminServiceError::Admin(AdminError::CpUnavailable { response, .. }) => {
            assert_eq!(response.reason, CpUnavailableReason::CacheExpired);
        }
        other => panic!("expected CpUnavailable, got {other:?}"),
    }
}

#[test]
fn admin_contracts_cover_durability_mode_conflict_and_idempotency() {
    let mut placements = CpPlacementClient::new(Duration::from_secs(60));
    let now = Instant::now();
    placements.update(
        PlacementRecord {
            partition_id: "p-ctrl".into(),
            routing_epoch: 1,
            lease_epoch: 1,
            members: vec!["leader-a".into()],
        },
        now,
    );
    let (mut service, ctx) = build_admin_service_with_caps(placements, now, &["SetDurabilityMode"]);
    let request = SetDurabilityModeRequest {
        idempotency_key: "dur-1".into(),
        partition_id: "p-ctrl".into(),
        target_mode: DurabilityMode::Relaxed,
        expected_mode: DurabilityMode::Strict,
    };
    let first = service
        .set_durability_mode(&ctx, request.clone(), now)
        .expect("initial transition succeeds");
    let replay = service
        .set_durability_mode(&ctx, request, now + Duration::from_millis(1))
        .expect("idempotent replay returns cached response");
    assert_eq!(first, replay);
    let err = service
        .set_durability_mode(
            &ctx,
            SetDurabilityModeRequest {
                idempotency_key: "dur-stale".into(),
                partition_id: "p-ctrl".into(),
                target_mode: DurabilityMode::Relaxed,
                expected_mode: DurabilityMode::Strict,
            },
            now + Duration::from_millis(2),
        )
        .expect_err("stale caller sees ModeConflict");
    assert!(matches!(
        err,
        AdminServiceError::Admin(AdminError::ModeConflict { .. })
    ));
}

#[test]
fn admin_transfer_leader_is_idempotent() {
    let mut placements = CpPlacementClient::new(Duration::from_secs(60));
    let now = Instant::now();
    placements.update(
        PlacementRecord {
            partition_id: "p-transfer".into(),
            routing_epoch: 3,
            lease_epoch: 1,
            members: vec!["n1".into(), "n2".into(), "n3".into()],
        },
        now,
    );
    let (mut service, ctx) = build_admin_service_with_caps(placements, now, &["TransferLeader"]);
    let request = TransferLeaderRequest {
        idempotency_key: "xfer-1".into(),
        partition_id: "p-transfer".into(),
        target_replica_id: Some("n2".into()),
        reason: Some("maintenance".into()),
    };
    let first = service
        .transfer_leader(&ctx, request.clone(), now)
        .expect("transfer accepted");
    assert!(first.accepted);
    let replay = service
        .transfer_leader(
            &ctx,
            TransferLeaderRequest {
                target_replica_id: Some("n3".into()),
                reason: Some("stale".into()),
                ..request
            },
            now + Duration::from_millis(1),
        )
        .expect("idempotent replay returns cached response");
    assert_eq!(first, replay);
}

#[test]
fn admin_snapshot_trigger_is_idempotent() {
    let mut placements = CpPlacementClient::new(Duration::from_secs(60));
    let now = Instant::now();
    placements.update(
        PlacementRecord {
            partition_id: "p-snap".into(),
            routing_epoch: 5,
            lease_epoch: 1,
            members: vec!["n1".into()],
        },
        now,
    );
    let (mut service, ctx) = build_admin_service_with_caps(placements, now, &["TriggerSnapshot"]);
    let request = SnapshotTriggerRequest {
        idempotency_key: "snap-1".into(),
        partition_id: "p-snap".into(),
        reason: "checkpoint rotation".into(),
    };
    let first = service
        .trigger_snapshot(&ctx, request.clone(), now)
        .expect("snapshot trigger accepted");
    assert!(first.accepted);
    let replay = service
        .trigger_snapshot(
            &ctx,
            SnapshotTriggerRequest {
                reason: "ignored".into(),
                ..request
            },
            now + Duration::from_millis(1),
        )
        .expect("replay returns cached response");
    assert_eq!(first, replay);
}

fn build_admin_service_with_caps(
    placements: CpPlacementClient,
    now: Instant,
    capabilities: &[&str],
) -> (AdminService, AdminRequestContext) {
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let mut cp = CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    cp.publish_cp_proof_at(DurabilityProof::new(1, 1), now);
    let handler = AdminHandler::new(cp, placements, ledger);
    let mut rbac = RbacManifestCache::new(Duration::from_secs(3_600));
    let manifest = RbacManifest {
        roles: vec![RbacRole {
            name: "operator".into(),
            capabilities: capabilities.iter().map(|cap| cap.to_string()).collect(),
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
