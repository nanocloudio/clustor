#![cfg(feature = "async-net")]

use clustor::net::{
    load_identity_from_pem, load_trust_store_from_pem, NetError, PeerEndpoint, TlsIdentity,
    TlsTrustStore,
};
use clustor::replication::raft::{
    AppendEntriesRequest, AppendEntriesResponse, RaftRouting, RequestVoteRequest,
    RequestVoteResponse,
};
use clustor::replication::transport::raft::{RaftRpcHandler, RaftRpcServer};
use clustor::security::MtlsIdentityManager;
use clustor::{
    AsyncRaftTransportClient, AsyncRaftTransportClientConfig, AsyncRaftTransportClientOptions,
    AsyncRaftTransportPoolManager, AsyncRaftTransportServer, AsyncRaftTransportServerConfig,
    AsyncRaftTransportServerHandle,
};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use std::convert::TryInto;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio::time::sleep;

fn next_loopback() -> std::net::SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral socket")
        .local_addr()
        .expect("ephemeral addr")
}

fn tls_materials(
    now: Instant,
) -> (
    TlsIdentity,
    TlsTrustStore,
    Arc<parking_lot::Mutex<MtlsIdentityManager>>,
) {
    let dir = TempDir::new().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.subject_alt_names.push(SanType::URI(
        "spiffe://localhost/nodes/1".try_into().unwrap(),
    ));
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let chain_path = dir.path().join("tls-chain.pem");
    let key_path = dir.path().join("tls-key.pem");
    std::fs::write(&chain_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();
    let identity = load_identity_from_pem(&chain_path, &key_path, now).unwrap();
    let trust = load_trust_store_from_pem(&chain_path).unwrap();
    let mtls = Arc::new(parking_lot::Mutex::new(MtlsIdentityManager::new(
        identity.certificate.clone(),
        "localhost",
        Duration::from_secs(60),
        now,
    )));
    (identity, trust, mtls)
}

#[derive(Clone)]
struct FixedHandler {
    term: u64,
    delay: Option<Duration>,
}

impl RaftRpcHandler for FixedHandler {
    fn on_request_vote(&mut self, _request: RequestVoteRequest) -> RequestVoteResponse {
        if let Some(delay) = self.delay {
            std::thread::sleep(delay);
        }
        RequestVoteResponse {
            term: self.term,
            granted: true,
            reject_reason: None,
        }
    }

    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
        if let Some(delay) = self.delay {
            std::thread::sleep(delay);
        }
        AppendEntriesResponse {
            term: self.term,
            success: true,
            match_index: request.prev_log_index,
            conflict_index: None,
            conflict_term: None,
        }
    }
}

async fn spawn_server(
    identity: TlsIdentity,
    trust: TlsTrustStore,
    handler: FixedHandler,
    routing: RaftRouting,
) -> AsyncRaftTransportServerHandle {
    let bind = next_loopback();
    let server_mtls = MtlsIdentityManager::new(
        identity.certificate.clone(),
        "localhost",
        Duration::from_secs(60),
        Instant::now(),
    );
    let server = RaftRpcServer::new(server_mtls, handler, routing);
    AsyncRaftTransportServer::spawn(
        AsyncRaftTransportServerConfig {
            bind,
            identity,
            trust_store: trust,
        },
        server,
    )
    .await
    .expect("async raft server spawn")
}

#[tokio::test]
async fn async_client_server_roundtrip_and_reuse() {
    let now = Instant::now();
    let (identity, trust, mtls) = tls_materials(now);
    let routing = RaftRouting::alias("partition-async", 1);
    let mut server_handle = spawn_server(
        identity.clone(),
        trust.clone(),
        FixedHandler {
            term: 9,
            delay: None,
        },
        routing.clone(),
    )
    .await;

    let client = AsyncRaftTransportClient::new(
        AsyncRaftTransportClientConfig {
            host: server_handle.bind.ip().to_string(),
            port: server_handle.bind.port(),
            identity: identity.clone(),
            trust_store: trust.clone(),
            mtls: mtls.clone(),
        },
        AsyncRaftTransportClientOptions::default()
            .pool_size_per_peer_max(2)
            .pool_warmup(true),
    )
    .expect("client build");

    client.warmup(Instant::now()).await.expect("warmup");

    let vote = RequestVoteRequest {
        term: 1,
        candidate_id: "node-a".into(),
        last_log_index: 0,
        last_log_term: 0,
        pre_vote: false,
        routing: routing.clone(),
    };
    let resp1 = client.request_vote(&vote).await.expect("vote");
    assert!(resp1.granted);
    let resp2 = client.request_vote(&vote).await.expect("vote again");
    assert!(resp2.granted);

    let snapshot = client.pool_snapshot().await;
    assert!(
        snapshot.idle >= 1,
        "expected idle session after reuse, got {:?}",
        snapshot
    );

    server_handle.shutdown().await;
}

#[tokio::test]
async fn async_pool_waits_not_exhausts() {
    let now = Instant::now();
    let (identity, trust, mtls) = tls_materials(now);
    let routing = RaftRouting::alias("partition-async", 1);
    let mut server_handle = spawn_server(
        identity.clone(),
        trust.clone(),
        FixedHandler {
            term: 9,
            delay: Some(Duration::from_millis(50)),
        },
        routing.clone(),
    )
    .await;

    let client = Arc::new(
        AsyncRaftTransportClient::new(
            AsyncRaftTransportClientConfig {
                host: server_handle.bind.ip().to_string(),
                port: server_handle.bind.port(),
                identity: identity.clone(),
                trust_store: trust.clone(),
                mtls: mtls.clone(),
            },
            AsyncRaftTransportClientOptions {
                connect_timeout: Duration::from_secs(5),
                io_timeout: Duration::from_secs(5),
                pool_size_per_peer_max: 1,
                pool_idle_timeout: Duration::from_secs(60),
                pool_warmup: true,
                pool_backoff: Duration::from_millis(50),
                retry_policy: clustor::retry::RetryPolicy::linear(3, Duration::from_millis(50))
                    .with_skip_first_delay(true),
                peer_node_id: None,
                metrics: None,
            },
        )
        .expect("client build"),
    );

    let request = AppendEntriesRequest {
        term: 1,
        leader_id: "leader".into(),
        prev_log_index: 1,
        prev_log_term: 1,
        leader_commit: 1,
        entries: Vec::new(),
        routing: routing.clone(),
    };

    let c1 = client.clone();
    let r1 = request.clone();
    let c2 = client.clone();
    let r2 = request.clone();

    let h1: JoinHandle<Result<AppendEntriesResponse, NetError>> =
        tokio::spawn(async move { c1.append_entries(&r1).await });
    let h2: JoinHandle<Result<AppendEntriesResponse, NetError>> =
        tokio::spawn(async move { c2.append_entries(&r2).await });

    let (res1, res2) = tokio::join!(h1, h2);
    assert!(res1.unwrap().is_ok());
    assert!(res2.unwrap().is_ok());

    server_handle.shutdown().await;
}

#[tokio::test]
async fn async_pool_manager_reconciles_and_drains() {
    let now = Instant::now();
    let (identity, trust, mtls) = tls_materials(now);
    let routing = RaftRouting::alias("partition-async", 1);

    let mut server_a = spawn_server(
        identity.clone(),
        trust.clone(),
        FixedHandler {
            term: 1,
            delay: None,
        },
        routing.clone(),
    )
    .await;
    let mut server_b = spawn_server(
        identity.clone(),
        trust.clone(),
        FixedHandler {
            term: 1,
            delay: None,
        },
        routing.clone(),
    )
    .await;

    let mut manager = AsyncRaftTransportPoolManager::new(
        identity.clone(),
        trust.clone(),
        mtls.clone(),
        AsyncRaftTransportClientOptions::default().pool_idle_timeout(Duration::from_millis(20)),
    );
    manager.register_endpoint(
        "node-a",
        PeerEndpoint {
            host: server_a.bind.ip().to_string(),
            port: server_a.bind.port(),
        },
    );
    manager.register_endpoint(
        "node-b",
        PeerEndpoint {
            host: server_b.bind.ip().to_string(),
            port: server_b.bind.port(),
        },
    );

    manager
        .reconcile_placements(
            &[clustor::control_plane::core::PlacementRecord {
                partition_id: "partition-async".into(),
                routing_epoch: 1,
                lease_epoch: 1,
                members: vec!["node-a".into(), "node-b".into()],
            }],
            now,
        )
        .await
        .expect("reconcile placements");

    assert!(manager.client_for("node-a").unwrap().is_some());
    assert!(manager.client_for("node-b").unwrap().is_some());

    manager
        .reconcile_placements(&[], Instant::now())
        .await
        .expect("reconcile remove");
    sleep(Duration::from_millis(50)).await;
    manager
        .reconcile_placements(&[], Instant::now())
        .await
        .expect("reconcile reap");
    assert!(manager.client_for("node-a").unwrap().is_none());
    assert!(manager.client_for("node-b").unwrap().is_none());

    server_a.shutdown().await;
    server_b.shutdown().await;
}
