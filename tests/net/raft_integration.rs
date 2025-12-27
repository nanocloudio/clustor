#![cfg(all(feature = "net", feature = "async-net"))]

use super::loopback_support::next_loopback;
use super::tls_support::{generate_tls_materials, TlsFixtures};
use clustor::control_plane::PlacementRecord;
use clustor::net::{
    AsyncRaftNetworkClient, AsyncRaftTransportClientConfig, AsyncRaftTransportClientOptions,
    AsyncRaftTransportPoolManager, AsyncRaftTransportServer, AsyncRaftTransportServerConfig,
    NetError, PeerEndpoint,
};
use clustor::raft::{AppendEntriesRequest, RaftRouting, RequestVoteRequest};
use clustor::security::MtlsIdentityManager;
use clustor::transport::raft::{RaftRpcHandler, RaftRpcServer};
use parking_lot::Mutex as ParkingMutex;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::time::sleep;

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

    fn on_append_entries(
        &mut self,
        request: AppendEntriesRequest,
    ) -> clustor::raft::AppendEntriesResponse {
        clustor::raft::AppendEntriesResponse {
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

#[derive(Clone)]
struct TaggedHandler {
    term: u64,
}

impl RaftRpcHandler for TaggedHandler {
    fn on_request_vote(
        &mut self,
        _request: RequestVoteRequest,
    ) -> clustor::raft::RequestVoteResponse {
        clustor::raft::RequestVoteResponse {
            term: self.term,
            granted: true,
            reject_reason: None,
        }
    }

    fn on_append_entries(
        &mut self,
        _request: AppendEntriesRequest,
    ) -> clustor::raft::AppendEntriesResponse {
        clustor::raft::AppendEntriesResponse {
            term: self.term,
            success: true,
            match_index: 0,
            conflict_index: None,
            conflict_term: None,
        }
    }
}

#[tokio::test]
async fn raft_client_and_server_round_trip_over_tls() -> Result<(), Box<dyn Error>> {
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
    let routing = RaftRouting::alias("partition-test", 1);
    let server = RaftRpcServer::new(server_mtls, TestHandler, routing.clone());
    let bind_addr = next_loopback();
    let mut handle = AsyncRaftTransportServer::spawn(
        AsyncRaftTransportServerConfig {
            bind: bind_addr,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        server,
    )
    .await?;

    let client_mtls = Arc::new(ParkingMutex::new(MtlsIdentityManager::new(
        client_identity.certificate.clone(),
        "test.example",
        Duration::from_secs(60),
        now,
    )));
    let client = AsyncRaftNetworkClient::new(AsyncRaftTransportClientConfig {
        host: bind_addr.ip().to_string(),
        port: bind_addr.port(),
        identity: client_identity.clone(),
        trust_store: trust_store.clone(),
        mtls: client_mtls,
    })?;
    client.refresh_revocation(now).await?;

    let vote = RequestVoteRequest {
        term: 3,
        candidate_id: "leader-a".into(),
        last_log_index: 42,
        last_log_term: 2,
        pre_vote: false,
        routing: routing.clone(),
    };
    let vote_resp = client.request_vote(vote, now).await?;
    assert!(vote_resp.granted);

    let append = client
        .append_entries(
            AppendEntriesRequest::heartbeat(3, "leader-a", 100, routing),
            now,
        )
        .await?;
    assert!(append.success);

    handle.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn raft_pool_migrates_on_routing_epoch_refresh() -> Result<(), Box<dyn Error>> {
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
    let routing_a = RaftRouting::alias("partition-move", 1);
    let routing_b = RaftRouting::alias("partition-move", 2);

    let server_a = RaftRpcServer::new(
        MtlsIdentityManager::new(
            server_identity.certificate.clone(),
            "test.example",
            Duration::from_secs(60),
            now,
        ),
        TaggedHandler { term: 10 },
        routing_a.clone(),
    );
    let bind_a = next_loopback();
    let mut handle_a = AsyncRaftTransportServer::spawn(
        AsyncRaftTransportServerConfig {
            bind: bind_a,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        server_a,
    )
    .await?;

    let server_b = RaftRpcServer::new(
        MtlsIdentityManager::new(
            server_identity.certificate.clone(),
            "test.example",
            Duration::from_secs(60),
            now,
        ),
        TaggedHandler { term: 20 },
        routing_b.clone(),
    );
    let bind_b = next_loopback();
    let mut handle_b = AsyncRaftTransportServer::spawn(
        AsyncRaftTransportServerConfig {
            bind: bind_b,
            identity: server_identity.clone(),
            trust_store: trust_store.clone(),
        },
        server_b,
    )
    .await?;

    let client_mtls = Arc::new(ParkingMutex::new(MtlsIdentityManager::new(
        client_identity.certificate.clone(),
        "test.example",
        Duration::from_secs(60),
        now,
    )));
    let options =
        AsyncRaftTransportClientOptions::default().pool_idle_timeout(Duration::from_millis(50));
    let mut pool =
        AsyncRaftTransportPoolManager::new(client_identity, trust_store, client_mtls, options);
    pool.register_endpoint(
        "node-a",
        PeerEndpoint {
            host: bind_a.ip().to_string(),
            port: bind_a.port(),
        },
    );
    pool.register_endpoint(
        "node-b",
        PeerEndpoint {
            host: bind_b.ip().to_string(),
            port: bind_b.port(),
        },
    );
    pool.reconcile_placements(
        &[PlacementRecord {
            partition_id: "partition-move".into(),
            routing_epoch: 1,
            lease_epoch: 1,
            members: vec!["node-a".into()],
        }],
        now,
    )
    .await?;

    let client_a = pool.client_for("node-a")?.expect("node-a client available");
    let vote_a = RequestVoteRequest {
        term: 1,
        candidate_id: "leader-a".into(),
        last_log_index: 0,
        last_log_term: 0,
        pre_vote: false,
        routing: routing_a.clone(),
    };
    let resp_a = client_a.request_vote(&vote_a).await?;
    assert_eq!(resp_a.term, 10);

    pool.reconcile_placements(
        &[PlacementRecord {
            partition_id: "partition-move".into(),
            routing_epoch: 2,
            lease_epoch: 2,
            members: vec!["node-b".into()],
        }],
        now + Duration::from_millis(5),
    )
    .await?;

    let client_b = pool.client_for("node-b")?.expect("node-b client available");
    let vote_b = RequestVoteRequest {
        term: 2,
        candidate_id: "leader-b".into(),
        last_log_index: 0,
        last_log_term: 0,
        pre_vote: false,
        routing: routing_b.clone(),
    };
    let resp_b = client_b.request_vote(&vote_b).await?;
    assert_eq!(resp_b.term, 20);

    let err = client_a
        .request_vote(&vote_a)
        .await
        .expect_err("draining client rejects new work");
    assert!(matches!(err, NetError::Io(_)));

    sleep(Duration::from_millis(80)).await;
    pool.reconcile_placements(
        &[PlacementRecord {
            partition_id: "partition-move".into(),
            routing_epoch: 2,
            lease_epoch: 2,
            members: vec!["node-b".into()],
        }],
        Instant::now(),
    )
    .await?;
    assert!(pool.client_for("node-a")?.is_none());

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    Ok(())
}
