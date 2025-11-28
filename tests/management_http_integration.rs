#![cfg(all(feature = "management", feature = "admin-http", feature = "net"))]

#[path = "common/http.rs"]
mod http;
#[path = "common/net.rs"]
mod net;

use clustor::admin::{
    AdminHandler, AdminService, CreatePartitionRequest, PartitionSpec, ReplicaSpec,
};
use clustor::consensus::{ConsensusCore, ConsensusCoreConfig};
use clustor::control_plane::core::CpProofCoordinator;
use clustor::cp_raft::CpPlacementClient;
use clustor::feature_guard::{FeatureGateState, FeatureManifestBuilder};
use clustor::net::{
    ManagementHttpServer, ManagementHttpServerConfig, ReadyzPublisher, WhyPublisher,
};
use clustor::readyz::{ReadyStateProbe, ReadyzSnapshot};
use clustor::security::{RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
use clustor::why::{LocalRole, WhyNotLeader, WhySchemaHeader};
use clustor::{IdempotencyLedger, PartitionQuorumStatus};
use http::https_request;
use net::{generate_tls_materials, next_loopback, TlsFixtures};
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

    let readyz = build_readyz_publisher();
    let why = build_why_publisher();
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

fn build_readyz_publisher() -> ReadyzPublisher {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let manifest = FeatureManifestBuilder::new()
        .with_gate_state("leader_leases", FeatureGateState::Enabled)
        .build(&signing_key)
        .expect("manifest");
    let matrix = manifest.capability_matrix().expect("matrix");
    let record = clustor::lifecycle::activation::WarmupReadinessRecord {
        partition_id: "partition-a".into(),
        bundle_id: "bundle-a".into(),
        shadow_apply_state: clustor::lifecycle::activation::ShadowApplyState::Ready,
        shadow_apply_checkpoint_index: 1,
        warmup_ready_ratio: 1.0,
        updated_at_ms: 0,
    };
    let probe = ReadyStateProbe {
        readiness: record,
        activation_barrier_id: None,
        partition_ready_ratio: 1.0,
    };
    let snapshot = ReadyzSnapshot::new(
        vec![probe],
        1_000,
        0,
        &matrix,
        manifest.digest().expect("manifest digest"),
        Vec::new(),
    )
    .expect("snapshot");
    ReadyzPublisher::new(snapshot)
}

fn build_why_publisher() -> WhyPublisher {
    let publisher = WhyPublisher::default();
    let report = WhyNotLeader {
        header: WhySchemaHeader::new("partition-a", 1, 1, 0),
        leader_id: Some("leader-a".into()),
        local_role: LocalRole::Follower,
        strict_state: clustor::consensus::StrictFallbackState::LocalOnly,
        cp_cache_state: clustor::control_plane::core::CpCacheState::Fresh,
        quorum_status: PartitionQuorumStatus {
            committed_index: 1,
            committed_term: 1,
            quorum_size: 1,
        },
        pending_entries: 0,
        runtime_terms: vec![clustor::terminology::TERM_STRICT],
        strict_fallback_why: None,
        truncated_ids_count: None,
        continuation_token: None,
    };
    publisher.update_not_leader("partition-a", report);
    publisher
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
