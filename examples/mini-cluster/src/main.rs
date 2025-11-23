mod cli;
mod config;
mod http_api;
mod peers;
mod raft;
mod state;
mod storage;
mod tls;

use crate::cli::{init_logging, Cli};
use crate::config::{load_cluster_config, ClusterConfig, NodeConfig};
use crate::http_api::build_router;
use crate::peers::build_peer_map;
use crate::raft::{
    new_durability_ledger, new_election_controller, new_role_state, MiniClusterRaftHandler,
    RaftRuntime,
};
use crate::state::{apply_committed_entries, new_consensus_core, AppState};
use crate::storage::PersistentState;
use crate::tls::{build_http_tls, new_mtls_manager, refresh_server_revocation, REVOCATION_REFRESH_INTERVAL};
use anyhow::{Context, Result};
use clustor::activation::{ShadowApplyState, WarmupReadinessRecord};
use clustor::admin::{AdminHandler, AdminService};
use clustor::cp::CpProofCoordinator;
use clustor::cp_raft::CpPlacementClient;
use clustor::feature_guard::{FeatureGateState, FeatureManifestBuilder};
use clustor::net::{
    load_identity_from_pem, load_trust_store_from_pem, AsyncManagementHttpServer,
    AsyncRaftNetworkServer, ManagementHttpServerConfig, RaftNetworkServerConfig, ReadyzPublisher,
    WhyPublisher,
};
use clustor::readyz::{ReadyStateProbe, ReadyzSnapshot};
use clustor::security::{SecurityError, SpiffeId};
use clustor::why::{LocalRole, WhyNotLeader, WhySchemaHeader};
use clustor::{
    IdempotencyLedger, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole, TlsIdentity,
    TlsTrustStore,
};
use clustor::transport::raft::RaftRpcServer;
use clustor::config_utils::state_dir_for_node;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServerBuilder;
use hyper_util::service::TowerToHyperService;
use log::{info, warn};
use parking_lot::Mutex;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::signal;
use tokio_rustls::TlsAcceptor;
use clap::Parser;
use ed25519_dalek::SigningKey;

#[derive(Clone)]
pub struct NodeState {
    pub app: AppState,
    pub raft: Arc<RaftRuntime>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            warn!("ctrl-c listener error: {err}");
        }
    };
    run_node(cli, ctrl_c).await
}

async fn run_node(cli: Cli, shutdown_signal: impl Future<Output = ()> + Send) -> Result<()> {
    init_logging(cli.log_filter.as_deref());
    let config = load_cluster_config(&cli.config)?;
    let node_cfg = lookup_node(&config, &cli.node)?;
    info!("initializing node {}", node_cfg.id);

    let tls_identity = load_identity_from_pem(&node_cfg.cert, &node_cfg.key, Instant::now())?;
    let trust_store = load_trust_store_from_pem(&config.ca_cert)?;

    let peers = build_peer_map(
        node_cfg,
        &config.nodes,
        &tls_identity,
        &trust_store,
        &config.trust_domain,
    )?;
    let durability_ledger = Arc::new(Mutex::new(new_durability_ledger(&peers, &node_cfg.id)));
    let last_quorum_fsynced = Arc::new(AtomicU64::new(0));
    let consensus_core = new_consensus_core();
    let current_term = Arc::new(AtomicU64::new(1));
    let node_state_dir = state_dir_for_node(&cli.config, &cli.state_dir, &node_cfg.id);
    info!(
        "node {} using state directory {}",
        node_cfg.id,
        node_state_dir.display()
    );
    std::fs::create_dir_all(&node_state_dir)?;
    let storage = PersistentState::open(&node_state_dir)?;
    let recovered_term = storage.current_term();
    current_term.store(recovered_term, Ordering::SeqCst);
    let log = storage.log_handle();
    let existing_entries = storage.entries_from(1);
    let events = Arc::new(Mutex::new(Vec::new()));
    let last_applied = Arc::new(AtomicU64::new(0));
    let leadership_epoch = Arc::new(AtomicU64::new(0));
    apply_committed_entries(&existing_entries, &events, &last_applied);
    info!(
        "node {} recovered {} log entries from {}",
        node_cfg.id,
        existing_entries.len(),
        node_state_dir.join("raft.log").display()
    );
    let mut election_controller = new_election_controller();
    let heartbeat_interval = election_controller.heartbeat_interval();
    let peer_suspect_after = Duration::from_millis(1500).max(heartbeat_interval * 20);
    let peer_down_after = Duration::from_millis(4500).max(heartbeat_interval * 60);
    let role_state =
        new_role_state(current_term.load(Ordering::SeqCst), &mut election_controller, &node_cfg.id);
    if let Some(voted) = storage.voted_for() {
        role_state.lock().voted_for = Some(voted);
    }

    let app_state = AppState {
        node_id: node_cfg.id.clone(),
        events,
        durability_ledger: durability_ledger.clone(),
        last_quorum_fsynced: last_quorum_fsynced.clone(),
        consensus_core: consensus_core.clone(),
        current_term: current_term.clone(),
        leadership_epoch: leadership_epoch.clone(),
        storage: storage.clone(),
        log: log.clone(),
        peers: Arc::new(peers),
        last_applied,
        peer_down_after,
    };

    let runtime = RaftRuntime::new(
        app_state.clone(),
        role_state,
        election_controller,
        heartbeat_interval,
        peer_suspect_after,
        peer_down_after,
    );
    let runtime_handle = runtime.spawn();

    let mut server_mtls = new_mtls_manager(
        &tls_identity,
        &config.trust_domain,
        Duration::from_secs(600),
    );
    server_mtls.rotate(Instant::now()).ok();
    let raft_server = RaftRpcServer::new(server_mtls, MiniClusterRaftHandler::new(runtime.clone()));
    let server_identity_handle = raft_server.identity_handle();

    let raft_bind: SocketAddr = node_cfg.raft_bind.parse()?;
    let mut raft_handle = AsyncRaftNetworkServer::spawn(
        RaftNetworkServerConfig {
            bind: raft_bind,
            identity: tls_identity.clone(),
            trust_store: trust_store.clone(),
        },
        raft_server,
    )
    .await?;

    let server_revocation_task =
        tokio::spawn(refresh_server_revocation(server_identity_handle.clone()));
    let peer_revocation_task = clustor::net::spawn_revocation_refresher(
        app_state
            .peers
            .iter()
            .map(|p| p.client.clone())
            .collect(),
        REVOCATION_REFRESH_INTERVAL,
    );

    let node_state = NodeState {
        app: app_state.clone(),
        raft: runtime.clone(),
    };

    let app = build_router(node_state.clone());

    let http_tls = Arc::new(build_http_tls(&tls_identity)?);
    let tls_acceptor = TlsAcceptor::from(http_tls);
    let http_addr: SocketAddr = node_cfg.http_bind.parse()?;
    info!(
        "node {} listening on https://{} and Raft TLS {}",
        node_cfg.id, node_cfg.http_bind, node_cfg.raft_bind
    );

    let listener = TcpListener::bind(http_addr).await?;
    let node_id = node_cfg.id.clone();
    let mut management_handle =
        start_management_server(node_cfg, &tls_identity, &trust_store, &runtime).await?;

    tokio::pin!(shutdown_signal);
    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let (stream, remote_addr) = match accept_res {
                    Ok(val) => val,
                    Err(err) => {
                        warn!("tcp accept error: {err}");
                        continue;
                    }
                };
                info!("node {} accepted HTTPS connection from {}", node_id, remote_addr);
                let acceptor = tls_acceptor.clone();
                let service = app.clone();
                let node_id_clone = node_id.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(err) => {
                            warn!("TLS handshake failed: {err}");
                            return;
                        }
                    };
                    info!("node {} completed TLS handshake with {}", node_id_clone, remote_addr);
                    let io = TokioIo::new(tls_stream);
                    let hyper_service = TowerToHyperService::new(service);
                    if let Err(err) = HyperServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, hyper_service)
                        .await
                        {
                        warn!("http connection error: {err}");
                    }
                    info!("node {} closed HTTPS session with {}", node_id_clone, remote_addr);
                });
            }
            _ = &mut shutdown_signal => {
                info!("shutdown signal received, shutting down node {}", node_id);
                break;
            }
        }
    }

    runtime_handle.signal_shutdown();
    raft_handle.shutdown().await;
    runtime_handle.shutdown().await;
    if let Some(mut handle) = management_handle.take() {
        handle.shutdown().await;
    }

    server_revocation_task.abort();
    peer_revocation_task.abort();
    let _ = server_revocation_task.await;
    let _ = peer_revocation_task.await;

    info!("node {} shutdown complete", node_id);
    Ok(())
}

fn lookup_node<'a>(config: &'a ClusterConfig, node_id: &str) -> Result<&'a NodeConfig> {
    config
        .nodes
        .iter()
        .find(|node| node.id == node_id)
        .with_context(|| format!("node `{}` not found in config", node_id))
}

async fn start_management_server(
    node_cfg: &NodeConfig,
    identity: &TlsIdentity,
    trust_store: &TlsTrustStore,
    runtime: &Arc<RaftRuntime>,
) -> Result<Option<clustor::net::AsyncManagementHttpServerHandle>> {
    let Some(bind) = node_cfg.management_bind.as_deref() else {
        return Ok(None);
    };
    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid management_bind addr `{bind}`"))?;
    let readyz = build_readyz_publisher(&node_cfg.id);
    let why = build_why_publisher(runtime);
    let admin = build_admin_service(
        Instant::now(),
        &identity.certificate.spiffe_id.canonical(),
    )
    .context("failed to build admin service for management")?;
    let handle = AsyncManagementHttpServer::spawn(
        ManagementHttpServerConfig {
            bind: bind_addr,
            identity: identity.clone(),
            trust_store: trust_store.clone(),
            max_connections: Some(32),
        },
        readyz,
        why,
        admin,
    )
    .await
    .context("failed to start management server")?;
    info!(
        "node {} listening for management API on https://{}",
        node_cfg.id, bind_addr
    );
    Ok(Some(handle))
}

fn build_readyz_publisher(node_id: &str) -> ReadyzPublisher {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let manifest = FeatureManifestBuilder::new()
        .with_gate_state("leader_leases", FeatureGateState::Enabled)
        .build(&signing_key)
        .expect("feature manifest builds");
    let matrix = manifest.capability_matrix().expect("capability matrix");
    let record = WarmupReadinessRecord {
        partition_id: node_id.to_string(),
        bundle_id: "mini-cluster".into(),
        shadow_apply_state: ShadowApplyState::Ready,
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
    .expect("readyz snapshot builds");
    ReadyzPublisher::new(snapshot)
}

fn build_why_publisher(runtime: &Arc<RaftRuntime>) -> WhyPublisher {
    let publisher = WhyPublisher::default();
    let role_guard = runtime.role.lock();
    let local_role = match role_guard.role {
        crate::raft::RaftRole::Leader => LocalRole::Leader,
        crate::raft::RaftRole::Follower => LocalRole::Follower,
        crate::raft::RaftRole::Candidate => LocalRole::Candidate,
    };
    let leader_id = role_guard.leader_id.clone();
    drop(role_guard);
    let quorum_status = clustor::raft::PartitionQuorumStatus {
        committed_index: runtime
            .state
            .last_quorum_fsynced
            .load(Ordering::SeqCst),
        committed_term: runtime.current_term(),
        quorum_size: runtime.state.peers.len(),
    };
    let pending_entries = runtime
        .state
        .log
        .lock()
        .last_index()
        .saturating_sub(runtime.state.last_applied.load(Ordering::SeqCst));
    let strict_state = runtime.state.consensus_core.lock().state();
    let report = WhyNotLeader {
        header: WhySchemaHeader::new(
            &runtime.state.node_id,
            runtime.current_term(),
            0,
            0,
        ),
        leader_id,
        local_role,
        strict_state,
        cp_cache_state: clustor::cp::CpCacheState::Fresh,
        quorum_status,
        pending_entries,
        runtime_terms: vec![clustor::terminology::TERM_STRICT],
        strict_fallback_why: None,
        truncated_ids_count: None,
        continuation_token: None,
    };
    publisher.update_not_leader(&runtime.state.node_id, report);
    publisher
}

fn build_admin_service(now: Instant, principal: &str) -> Result<AdminService, SecurityError> {
    let kernel = clustor::consensus::ConsensusCore::new(
        clustor::consensus::ConsensusCoreConfig::default(),
    );
    let cp_guard = CpProofCoordinator::new(kernel);
    let placements = CpPlacementClient::new(Duration::from_secs(60));
    let ledger = IdempotencyLedger::new(Duration::from_secs(60));
    let handler = AdminHandler::new(cp_guard, placements, ledger);
    let mut rbac = RbacManifestCache::new(Duration::from_secs(600));
    let spiffe = SpiffeId::parse(principal)?;
    rbac.load_manifest(
        RbacManifest {
            roles: vec![RbacRole {
                name: "operator".into(),
                capabilities: vec![
                    "CreatePartition".into(),
                    "SetDurabilityMode".into(),
                    "SnapshotThrottle".into(),
                    "TransferLeader".into(),
                    "TriggerSnapshot".into(),
                ],
            }],
            principals: vec![RbacPrincipal {
                spiffe_id: spiffe.canonical(),
                role: "operator".into(),
            }],
        },
        now,
    )?;
    Ok(AdminService::new(handler, rbac))
}
