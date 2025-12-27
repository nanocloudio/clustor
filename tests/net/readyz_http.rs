#![cfg(feature = "net")]

use super::http_client::https_request;
use super::loopback_support::next_loopback;
#[cfg(feature = "snapshot-crypto")]
use super::readyz_blocked::sample_snapshot_blocked_publisher;
use super::readyz_support::{sample_readyz_publisher, sample_why_publisher};
use super::tls_support::{generate_tls_materials, TlsFixtures};
use clustor::{ReadyzHttpServer, ReadyzHttpServerConfig, WhyHttpServer, WhyHttpServerConfig};
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
    let publisher = sample_readyz_publisher("alpha");
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
fn readyz_reports_unknown_path() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixtures = generate_tls_materials(
        &temp,
        &["localhost"],
        "spiffe://readyz/ns/default/sa/server",
        "spiffe://readyz/ns/default/sa/client",
    )?;
    let publisher = sample_readyz_publisher("gamma");
    let addr = next_loopback();
    let mut handle = ReadyzHttpServer::spawn(
        ReadyzHttpServerConfig {
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
        "/readyz/unknown",
        &[],
        &fixtures.client,
        &fixtures.trust,
    )?;
    assert_eq!(response.status, 404);
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["error"], "not found");
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
    let publisher = sample_readyz_publisher("beta");
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
    let publisher = sample_why_publisher("alpha");
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

#[cfg(feature = "snapshot-crypto")]
#[test]
fn why_server_reports_snapshot_blocked() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let fixtures = generate_tls_materials(
        &temp,
        &["localhost"],
        "spiffe://why/ns/default/sa/server",
        "spiffe://why/ns/default/sa/client",
    )?;
    let publisher = sample_snapshot_blocked_publisher("alpha");
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
        "/why/snapshot-blocked/alpha",
        &[],
        &fixtures.client,
        &fixtures.trust,
    )?;
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body)?;
    assert_eq!(body["manifest_id"], "manifest-1");
    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("why shutdown");
    Ok(())
}
