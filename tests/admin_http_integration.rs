#![cfg(all(feature = "net", feature = "admin-http"))]

#[path = "common/http.rs"]
mod http;
#[path = "common/net.rs"]
mod net;

use clustor::admin::{
    AdminHandler, AdminService, CreatePartitionRequest, PartitionSpec, ReplicaSpec,
};
use clustor::consensus::{ConsensusCore, ConsensusCoreConfig};
use clustor::cp::CpProofCoordinator;
use clustor::cp_raft::CpPlacementClient;
use clustor::net::{AdminHttpServer, AdminHttpServerConfig};
use clustor::{IdempotencyLedger, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
use http::https_request;
use net::{generate_tls_materials, next_loopback, TlsFixtures};
use serde_json::Value;
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
    let service = build_admin_service(now, &operator);
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
