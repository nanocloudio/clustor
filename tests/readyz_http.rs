#![cfg(feature = "net")]

#[path = "common/http.rs"]
mod http;
#[path = "common/net.rs"]
mod net;

use clustor::control_plane::core::CpCacheState;
use clustor::lifecycle::activation::{ShadowApplyState, WarmupReadinessRecord};
use clustor::{
    ConsensusCoreStatus, DemotionStatus, FeatureCapabilityMatrix, FeatureManifestBuilder,
};
use clustor::{
    LocalRole, ReadyStateProbe, ReadyzHttpServer, ReadyzHttpServerConfig, ReadyzPublisher,
    ReadyzSnapshot, WhyHttpServer, WhyHttpServerConfig, WhyNotLeader, WhyPublisher,
    WhySchemaHeader,
};
use clustor::{PartitionQuorumStatus, StrictFallbackState};
use ed25519_dalek::SigningKey;
use http::https_request;
use net::{generate_tls_materials, next_loopback, TlsFixtures};
use serde_json::Value;
use std::error::Error;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn readyz_serves_snapshot_and_handles_errors() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let TlsFixtures {
        server,
        client,
        trust,
    } = generate_tls_materials(
        &temp,
        &["localhost"],
        "spiffe://test/ns/default/sa/server",
        "spiffe://test/ns/default/sa/client",
    )?;
    let snapshot = build_readyz_snapshot("alpha");
    let publisher = ReadyzPublisher::new(snapshot);
    let addr = next_loopback();
    let mut handle = ReadyzHttpServer::spawn(
        ReadyzHttpServerConfig {
            bind: addr,
            identity: server.clone(),
            trust_store: trust.clone(),
        },
        publisher,
    )?;
    let response = https_request(addr, "localhost", "GET", "/readyz", &[], &client, &trust)?;
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["readiness"][0]["partition_id"], "alpha");
    let missing = https_request(
        addr,
        "localhost",
        "GET",
        "/readyz/why",
        &[],
        &client,
        &trust,
    )?;
    assert_eq!(missing.status, 400);
    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("readyz shutdown");
    Ok(())
}

#[test]
fn readyz_rejects_foreign_clients() -> Result<(), Box<dyn Error>> {
    let good = TempDir::new()?;
    let bad = TempDir::new()?;
    let good_fixtures = generate_tls_materials(
        &good,
        &["localhost"],
        "spiffe://good/ns/default/sa/server",
        "spiffe://good/ns/default/sa/client",
    )?;
    let bad_fixtures = generate_tls_materials(
        &bad,
        &["localhost"],
        "spiffe://bad/ns/default/sa/server",
        "spiffe://bad/ns/default/sa/client",
    )?;
    let snapshot = build_readyz_snapshot("beta");
    let publisher = ReadyzPublisher::new(snapshot);
    let addr = next_loopback();
    let mut handle = ReadyzHttpServer::spawn(
        ReadyzHttpServerConfig {
            bind: addr,
            identity: good_fixtures.server.clone(),
            trust_store: good_fixtures.trust.clone(),
        },
        publisher,
    )?;
    let err = https_request(
        addr,
        "localhost",
        "GET",
        "/readyz",
        &[],
        &bad_fixtures.client,
        &bad_fixtures.trust,
    );
    assert!(err.is_err(), "foreign client cert should fail");
    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("readyz shutdown");
    Ok(())
}

#[test]
fn why_server_reports_not_leader() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixtures = generate_tls_materials(
        &temp,
        &["localhost"],
        "spiffe://why/ns/default/sa/server",
        "spiffe://why/ns/default/sa/client",
    )?;
    let publisher = build_why_publisher();
    let addr = next_loopback();
    let mut handle = WhyHttpServer::spawn(
        WhyHttpServerConfig {
            bind: addr,
            identity: fixtures.server.clone(),
            trust_store: fixtures.trust.clone(),
        },
        publisher,
    )?;
    let response = https_request(
        addr,
        "localhost",
        "GET",
        "/why/not-leader/alpha",
        &[],
        &fixtures.client,
        &fixtures.trust,
    )?;
    assert_eq!(response.status, 200);
    let missing = https_request(
        addr,
        "localhost",
        "GET",
        "/why/not-leader/missing",
        &[],
        &fixtures.client,
        &fixtures.trust,
    )?;
    assert_eq!(missing.status, 404);
    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("why shutdown");
    Ok(())
}

fn build_readyz_snapshot(partition: &str) -> ReadyzSnapshot {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let manifest = FeatureManifestBuilder::new()
        .build(&signing_key)
        .expect("feature manifest");
    let matrix = FeatureCapabilityMatrix::from_manifest(&manifest).expect("capability matrix");
    let probe = ReadyStateProbe {
        readiness: WarmupReadinessRecord {
            partition_id: partition.into(),
            bundle_id: "bundle-a".into(),
            shadow_apply_state: ShadowApplyState::Pending,
            shadow_apply_checkpoint_index: 0,
            warmup_ready_ratio: 1.0,
            updated_at_ms: 0,
        },
        activation_barrier_id: Some("barrier-a".into()),
        partition_ready_ratio: 1.0,
    };
    ReadyzSnapshot::new(vec![probe], 1_000, 0, &matrix, "digest", Vec::new()).expect("snapshot")
}

fn build_why_publisher() -> WhyPublisher {
    let publisher = WhyPublisher::default();
    let header = WhySchemaHeader::new("alpha", 1, 1, 0);
    let consensus = ConsensusCoreStatus {
        state: StrictFallbackState::Healthy,
        strict_fallback: true,
        pending_entries: 0,
        local_only_duration: None,
        should_alert: false,
        demotion: DemotionStatus::none(),
        last_local_proof: None,
        last_published_proof: None,
        decision_epoch: 0,
        blocking_reason: None,
    };
    let quorum_status = PartitionQuorumStatus {
        committed_index: 0,
        committed_term: 0,
        quorum_size: 1,
    };
    let not_leader = WhyNotLeader::from_status(
        header,
        Some("replica-a".into()),
        LocalRole::Leader,
        CpCacheState::Fresh,
        consensus,
        quorum_status,
        None,
    );
    publisher.update_not_leader("alpha", not_leader);
    publisher
}
