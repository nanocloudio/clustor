use clustor::{
    AdminError, AdminHandler, AdminRequestContext, AdminService, AdminServiceError,
    CpPlacementClient, CpProofCoordinator, CpUnavailableReason, CreatePartitionRequest,
    DurabilityProof, IdempotencyLedger, PartitionSpec, RbacManifestCache, ReplicaSpec,
};
use clustor::{ConsensusCore, ConsensusCoreConfig};
use std::collections::HashMap;
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
        DurabilityMode, PlacementRecord, SnapshotThrottleRequest, UpdateDurabilityModeRequest,
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
        .handle_update_durability_mode(
            UpdateDurabilityModeRequest {
                idempotency_key: "durability".into(),
                partition_id: "p2".into(),
                target_mode: DurabilityMode::Strict,
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
    let mut roles = HashMap::new();
    roles.insert(
        "operator".into(),
        vec![
            "CreatePartition".into(),
            "UpdateDurabilityMode".into(),
            "SnapshotThrottle".into(),
        ],
    );
    rbac.load_manifest(roles, now);
    let mut service = AdminService::new(handler, rbac);
    let ctx = AdminRequestContext::new("operator");
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
        AdminServiceError::Admin(AdminError::CpUnavailable(response)) => {
            assert_eq!(response.reason, CpUnavailableReason::CacheExpired);
        }
        other => panic!("expected CpUnavailable, got {other:?}"),
    }
}
