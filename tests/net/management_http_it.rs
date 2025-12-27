#![cfg(all(feature = "net", feature = "admin-http", feature = "management"))]

use super::control_plane_support::admin_service;
use super::http_client::https_request;
use super::loopback_support::next_loopback;
use super::readyz_support::{sample_readyz_publisher, sample_why_publisher};
use super::tls_support::{generate_tls_materials, TlsFixtures};
use clustor::net::management::{ManagementHttpServer, ManagementHttpServerConfig};
use serde_json::Value;
use std::error::Error;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn management_routes_readyz_why_and_admin() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost"],
        "spiffe://mgmt.test/ns/default/sa/server",
        "spiffe://mgmt.test/ns/default/sa/operator",
    )?;
    let readyz = sample_readyz_publisher("alpha");
    let why = sample_why_publisher("alpha");
    let now = Instant::now();
    let operator = client_identity.certificate.spiffe_id.canonical();
    let service = admin_service(now, &operator);
    let addr = next_loopback();
    let mut handle = ManagementHttpServer::spawn(
        ManagementHttpServerConfig {
            bind: addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
            max_connections: Some(8),
        },
        readyz,
        why,
        service,
    )?;

    let readyz_response = https_request(
        addr,
        "localhost",
        "GET",
        "/readyz",
        &[],
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(readyz_response.status, 200);
    let ready_body: Value = serde_json::from_slice(&readyz_response.body)?;
    assert_eq!(
        ready_body["readiness"][0]["partition_id"], "alpha",
        "expected readyz payload"
    );

    let why_response = https_request(
        addr,
        "localhost",
        "GET",
        "/why/not-leader/alpha",
        &[],
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(why_response.status, 200);

    let admin_request = serde_json::json!({
        "idempotency_key": "op-1",
        "partition": {
            "partition_id": "partition-a",
            "replicas": ["replica-a"],
            "routing_epoch": 0
        },
        "replicas": [{
            "replica_id": "replica-a",
            "az": "zone-a"
        }]
    })
    .to_string()
    .into_bytes();
    let admin_response = https_request(
        addr,
        "localhost",
        "POST",
        "/admin/create-partition",
        &admin_request,
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(admin_response.status, 200);

    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("management server shutdown");
    Ok(())
}

#[test]
fn management_unknown_path_returns_404() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost"],
        "spiffe://mgmt.test/ns/default/sa/server",
        "spiffe://mgmt.test/ns/default/sa/operator",
    )?;
    let now = Instant::now();
    let operator = client_identity.certificate.spiffe_id.canonical();
    let readyz = sample_readyz_publisher("alpha");
    let why = sample_why_publisher("alpha");
    let service = admin_service(now, &operator);
    let addr = next_loopback();
    let mut handle = ManagementHttpServer::spawn(
        ManagementHttpServerConfig {
            bind: addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
            max_connections: None,
        },
        readyz,
        why,
        service,
    )?;
    let response = https_request(
        addr,
        "localhost",
        "GET",
        "/not-real",
        &[],
        &client_identity,
        &trust_store,
    )?;
    assert_eq!(response.status, 404);
    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("management server shutdown");
    Ok(())
}
