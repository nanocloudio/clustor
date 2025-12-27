#![cfg(all(feature = "net", feature = "admin-http"))]

use super::control_plane_support::admin_service;
use super::http_client::https_request;
use super::loopback_support::next_loopback;
use super::tls_support::{generate_tls_materials, TlsFixtures};
use clustor::admin::{
    AdminHandler, AdminService, CreatePartitionRequest, PartitionSpec, ReplicaSpec,
};
use clustor::consensus::{ConsensusCore, ConsensusCoreConfig};
use clustor::control_plane::core::{CpPlacementClient, CpProofCoordinator, PlacementRecord};
use clustor::net::{AdminHttpServer, AdminHttpServerConfig};
use clustor::{IdempotencyLedger, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
use serde_json::{json, Value};
use std::error::Error;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn admin_http_accepts_partition_requests() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost"],
        "spiffe://test.example/ns/default/sa/admin",
        "spiffe://test.example/ns/default/sa/operator",
    )?;
    let now = Instant::now();
    let operator = client_identity.certificate.spiffe_id.canonical();
    let service = admin_service(now, &operator);
    let bind_addr = next_loopback();
    let mut handle = AdminHttpServer::spawn(
        AdminHttpServerConfig {
            bind: bind_addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        service,
    )?;

    let request = CreatePartitionRequest {
        idempotency_key: "op-1".into(),
        partition: PartitionSpec {
            partition_id: "partition-a".into(),
            replicas: vec!["replica-a".into()],
            routing_epoch: 0,
        },
        replicas: vec![ReplicaSpec {
            replica_id: "replica-a".into(),
            az: "zone-a".into(),
        }],
    };
    let body = serde_json::to_vec(&request)?;
    let response = https_request(
        bind_addr,
        "localhost",
        "POST",
        "/admin/create-partition",
        &body,
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(response.status, 200);
    let parsed: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(parsed["partition_id"], "partition-a");
    assert_eq!(parsed["routing_epoch"], 1);

    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("admin server shutdown");
    Ok(())
}

#[test]
fn admin_http_rejects_unauthorized_principal() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost"],
        "spiffe://test.example/ns/default/sa/admin",
        "spiffe://test.example/ns/default/sa/operator",
    )?;
    let now = Instant::now();
    let service = admin_service(now, "spiffe://test.example/ns/default/sa/other");
    let bind_addr = next_loopback();
    let mut handle = AdminHttpServer::spawn(
        AdminHttpServerConfig {
            bind: bind_addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        service,
    )?;
    let request = CreatePartitionRequest {
        idempotency_key: "op-2".into(),
        partition: PartitionSpec {
            partition_id: "partition-b".into(),
            replicas: vec!["replica-b".into()],
            routing_epoch: 0,
        },
        replicas: vec![ReplicaSpec {
            replica_id: "replica-b".into(),
            az: "zone-b".into(),
        }],
    };
    let body = serde_json::to_vec(&request)?;
    let response = https_request(
        bind_addr,
        "localhost",
        "POST",
        "/admin/create-partition",
        &body,
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(response.status, 403);
    let parsed: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(parsed["error"], "unauthorized");
    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("admin server shutdown");
    Ok(())
}

#[test]
fn admin_http_handles_shrink_plan_flow() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost"],
        "spiffe://test.example/ns/default/sa/admin",
        "spiffe://test.example/ns/default/sa/operator",
    )?;
    let now = Instant::now();
    let operator = client_identity.certificate.spiffe_id.canonical();
    let record = PlacementRecord {
        partition_id: "p-shrink".into(),
        routing_epoch: 1,
        lease_epoch: 1,
        members: vec!["a".into(), "b".into(), "c".into()],
    };
    let service = admin_service_with(now, &operator, |placements| {
        placements.update(record, now);
    });
    let bind_addr = next_loopback();
    let mut handle = AdminHttpServer::spawn(
        AdminHttpServerConfig {
            bind: bind_addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        service,
    )?;

    let create_body = json!({
        "plan_id": "plan-http",
        "target_placements": [{
            "prg_id": "p-shrink",
            "target_members": ["a", "b"],
            "target_routing_epoch": 2
        }]
    })
    .to_string()
    .into_bytes();
    let create = https_request(
        bind_addr,
        "localhost",
        "POST",
        "/admin/shrink-plan",
        &create_body,
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(create.status, 200);
    let resp: Value = serde_json::from_slice(&create.body)?;
    assert_eq!(resp["plan"]["plan_id"], "plan-http");

    let arm_body = json!({ "plan_id": "plan-http" }).to_string().into_bytes();
    let arm = https_request(
        bind_addr,
        "localhost",
        "POST",
        "/admin/shrink-plan/arm",
        &arm_body,
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(arm.status, 200);
    let arm_resp: Value = serde_json::from_slice(&arm.body)?;
    assert_eq!(arm_resp["plan"]["state"], "Armed");

    let list = https_request(
        bind_addr,
        "localhost",
        "GET",
        "/admin/shrink-plan",
        &[],
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(list.status, 200);
    let payload: Value = serde_json::from_slice(&list.body)?;
    assert!(payload["plans"]
        .as_array()
        .expect("plans array")
        .iter()
        .any(|plan| plan["plan_id"] == "plan-http"));

    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("admin server shutdown");
    Ok(())
}

fn admin_service_with(
    now: Instant,
    principal: &str,
    mutate: impl FnOnce(&mut CpPlacementClient),
) -> AdminService {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let cp_guard = CpProofCoordinator::new(kernel);
    let mut placements = CpPlacementClient::new(Duration::from_secs(60));
    mutate(&mut placements);
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let handler = AdminHandler::new(cp_guard, placements, ledger);
    let mut rbac = RbacManifestCache::new(Duration::from_secs(600));
    rbac.load_manifest(
        RbacManifest {
            roles: vec![RbacRole {
                name: "operator".into(),
                capabilities: vec![
                    "CreatePartition".into(),
                    "ManageShrinkPlan".into(),
                    "ArmShrinkPlan".into(),
                    "ListShrinkPlans".into(),
                ],
            }],
            principals: vec![RbacPrincipal {
                spiffe_id: principal.into(),
                role: "operator".into(),
            }],
        },
        now,
    )
    .expect("rbac manifest loads");
    AdminService::new(handler, rbac)
}
