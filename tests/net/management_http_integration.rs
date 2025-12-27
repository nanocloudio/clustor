#![cfg(all(feature = "management", feature = "admin-http", feature = "net"))]

use super::http_client::https_request;
use super::loopback_support::next_loopback;
use super::readyz_support::{sample_readyz_publisher, sample_why_publisher};
use super::tls_support::{generate_tls_materials, TlsFixtures};
use clustor::admin::{
    AdminHandler, AdminService, CreatePartitionRequest, PartitionSpec, ReplicaSpec,
};
use clustor::consensus::{ConsensusCore, ConsensusCoreConfig};
use clustor::control_plane::core::CpProofCoordinator;
use clustor::cp_raft::CpPlacementClient;
use clustor::net::{ManagementHttpServer, ManagementHttpServerConfig};
use clustor::security::{RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
use clustor::IdempotencyLedger;
use serde_json::Value;
use std::error::Error;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn management_server_routes_readyz_and_admin() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost"],
        "spiffe://test.example/ns/default/sa/admin",
        "spiffe://test.example/ns/default/sa/admin",
    )?;

    let readyz = sample_readyz_publisher("partition-a");
    let why = sample_why_publisher("partition-a");
    let admin = build_admin_service(
        Instant::now(),
        &client_identity.certificate.spiffe_id.canonical(),
    );
    let bind_addr = next_loopback();

    let mut handle = ManagementHttpServer::spawn(
        ManagementHttpServerConfig {
            bind: bind_addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
            max_connections: Some(8),
        },
        readyz,
        why,
        admin,
    )?;

    // readyz
    let response = https_request(
        bind_addr,
        "localhost",
        "GET",
        "/readyz",
        &[],
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(response.status, 200);
    let parsed: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(parsed["readiness"][0]["partition_id"], "partition-a");

    // admin
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

    handle.try_shutdown(Duration::from_secs(1))?;
    Ok(())
}

fn build_admin_service(now: Instant, principal: &str) -> AdminService {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let cp_guard = CpProofCoordinator::new(kernel);
    let placements = CpPlacementClient::new(Duration::from_secs(60));
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let handler = AdminHandler::new(cp_guard, placements, ledger);
    let mut rbac = RbacManifestCache::new(Duration::from_secs(600));
    rbac.load_manifest(
        RbacManifest {
            roles: vec![RbacRole {
                name: "operator".into(),
                capabilities: vec!["CreatePartition".into()],
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
