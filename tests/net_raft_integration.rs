#![cfg(feature = "net")]

#[path = "common/net.rs"]
mod common;

use clustor::net::{
    RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkServer, RaftNetworkServerConfig,
};
use clustor::raft::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest};
use clustor::security::MtlsIdentityManager;
use clustor::transport::raft::{RaftRpcHandler, RaftRpcServer};
use common::{generate_tls_materials, next_loopback, TlsFixtures};
use std::error::Error;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[derive(Default)]
struct TestHandler;

impl RaftRpcHandler for TestHandler {
    fn on_request_vote(
        &mut self,
        request: RequestVoteRequest,
    ) -> clustor::raft::RequestVoteResponse {
        clustor::raft::RequestVoteResponse {
            term: request.term,
            granted: true,
            reject_reason: None,
        }
    }

    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
        AppendEntriesResponse {
            term: request.term,
            success: true,
            match_index: request
                .entries
                .last()
                .map(|entry| entry.index)
                .unwrap_or(request.prev_log_index),
            conflict_index: None,
            conflict_term: None,
        }
    }
}

#[test]
fn raft_client_and_server_round_trip_over_tls() -> Result<(), Box<dyn Error>> {
    let certs = TempDir::new()?;
    let TlsFixtures {
        server: server_identity,
        client: client_identity,
        trust: trust_store,
    } = generate_tls_materials(
        &certs,
        &["localhost", "127.0.0.1"],
        "spiffe://test.example/ns/default/sa/server",
        "spiffe://test.example/ns/default/sa/client",
    )?;
    let now = Instant::now();
    let server_mtls = MtlsIdentityManager::new(
        server_identity.certificate.clone(),
        "test.example",
        Duration::from_secs(60),
        now,
    );
    let server = RaftRpcServer::new(server_mtls, TestHandler);
    let bind_addr = next_loopback();
    let mut handle = RaftNetworkServer::spawn(
        RaftNetworkServerConfig {
            bind: bind_addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        server,
    )?;

    let client_mtls = MtlsIdentityManager::new(
        client_identity.certificate.clone(),
        "test.example",
        Duration::from_secs(60),
        now,
    );
    let client = RaftNetworkClient::new(RaftNetworkClientConfig {
        host: bind_addr.ip().to_string(),
        port: bind_addr.port(),
        identity: client_identity.clone(),
        trust_store: trust_store.clone(),
        mtls: client_mtls,
    })?;
    client.refresh_revocation(now);

    let vote = client.request_vote(
        &RequestVoteRequest {
            term: 3,
            candidate_id: "leader-a".into(),
            last_log_index: 42,
            last_log_term: 2,
            pre_vote: false,
        },
        now,
    )?;
    assert!(vote.granted);

    let append =
        client.append_entries(&AppendEntriesRequest::heartbeat(3, "leader-a", 100), now)?;
    assert!(append.success);

    handle
        .try_shutdown(Duration::from_secs(1))
        .expect("raft server shutdown");
    Ok(())
}
