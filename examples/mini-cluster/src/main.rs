mod storage;

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use clustor::consensus::{
    ConsensusCore, ConsensusCoreConfig, DurabilityProof, GateOperation, GateViolation,
};
use clustor::durability::{AckRecord, DurabilityLedger, IoMode};
use clustor::net::{
    load_identity_from_pem, load_trust_store_from_pem, RaftNetworkClient, RaftNetworkClientConfig,
    RaftNetworkServer, RaftNetworkServerConfig, TlsIdentity, TlsTrustStore,
};
use clustor::raft::{
    AppendEntriesProcessor, AppendEntriesRequest, AppendEntriesResponse, PartitionQuorumConfig,
    ReplicaId, RequestVoteRequest, RequestVoteResponse,
};
use clustor::security::MtlsIdentityManager;
use clustor::transport::raft::{RaftRpcHandler, RaftRpcServer};
use clustor::{RaftLogEntry, RaftLogStore};
use storage::{AppendedEntry, PersistentState};
use env_logger::Env;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServerBuilder;
use hyper_util::service::TowerToHyperService;
use log::{debug, error, info, warn};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio_rustls::{rustls, TlsAcceptor};

#[derive(Parser, Debug)]
struct Cli {
    /// Path to cluster configuration YAML
    #[arg(long)]
    config: PathBuf,

    /// Node ID to run (e.g. node-a)
    #[arg(long)]
    node: String,

    /// Directory for persisted Raft state (per-node subdirectories are created automatically)
    #[arg(long, default_value = "state")]
    state_dir: PathBuf,

    /// env_logger-style filter string (e.g. "info,clustor=debug"); overrides RUST_LOG/defaults
    #[arg(long)]
    log_filter: Option<String>,
}

const DEFAULT_LOG_FILTER: &str = "info,clustor=info";

#[derive(Debug, Deserialize)]
struct ClusterConfig {
    trust_domain: String,
    ca_cert: PathBuf,
    nodes: Vec<NodeConfig>,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    id: String,
    raft_bind: String,
    http_bind: String,
    cert: PathBuf,
    key: PathBuf,
    peers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EventRecord {
    source: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct EventRequest {
    message: String,
}

#[derive(Serialize)]
struct StatsResponse {
    node_id: String,
    last_applied_index: u64,
    log_tail_index: u64,
    last_quorum_fsynced_index: u64,
    pending_entries: u64,
}

#[derive(Clone)]
struct AppState {
    node_id: String,
    events: Arc<Mutex<Vec<EventRecord>>>,
    durability_ledger: Arc<Mutex<DurabilityLedger>>,
    last_quorum_fsynced: Arc<AtomicU64>,
    consensus_core: Arc<Mutex<ConsensusCore>>,
    current_term: Arc<AtomicU64>,
    storage: PersistentState,
    log: Arc<Mutex<RaftLogStore>>,
    peers: Arc<Vec<PeerInfo>>,
    tls_identity: TlsIdentity,
    trust_store: TlsTrustStore,
    trust_domain: String,
    last_applied: Arc<AtomicU64>,
}

#[derive(Clone)]
struct PeerInfo {
    id: String,
    host: String,
    port: u16,
}

impl AppState {
    fn record_leader_ack(&self, appended: &AppendedEntry) {
        self.record_ack(
            ReplicaId::new(self.node_id.clone()),
            appended.entry.term,
            appended.entry.index,
            appended.segment_seq,
            IoMode::Strict,
        );
    }

    fn record_peer_ack(&self, peer_id: &str, term: u64, match_index: u64) {
        if match_index == 0 {
            return;
        }
        self.record_ack(
            ReplicaId::new(peer_id.to_string()),
            term,
            match_index,
            match_index,
            IoMode::Strict,
        );
    }

    fn record_ack(
        &self,
        replica: ReplicaId,
        term: u64,
        index: u64,
        segment_seq: u64,
        io_mode: IoMode,
    ) {
        let mut ledger = self.durability_ledger.lock();
        match ledger.record_ack(AckRecord {
            replica,
            term,
            index,
            segment_seq,
            io_mode,
        }) {
            Ok(update) => {
                self.last_quorum_fsynced
                    .store(update.quorum_index, Ordering::SeqCst);
                self.reconcile_strict_fallback(update.quorum_index);
            }
            Err(err) => {
                warn!("durability ack rejected: {err}");
            }
        }
    }

    fn on_local_append(&self, entry: &RaftLogEntry) {
        let mut core = self.consensus_core.lock();
        core.enter_strict_fallback(
            DurabilityProof::new(entry.term, entry.index),
            Instant::now(),
        );
        core.register_strict_write();
    }

    fn reconcile_strict_fallback(&self, quorum_index: u64) {
        let log_tail = self.log.lock().last_index();
        let mut core = self.consensus_core.lock();
        if log_tail > quorum_index {
            core.enter_strict_fallback(
                DurabilityProof::new(self.current_term.load(Ordering::SeqCst), quorum_index),
                Instant::now(),
            );
        } else {
            core.mark_healthy();
        }
    }

    fn guard_read(&self) -> Result<(), GateViolation> {
        let mut core = self.consensus_core.lock();
        core.guard(GateOperation::ReadIndex)
    }
}

struct ExampleRaftHandler {
    node_id: String,
    events: Arc<Mutex<Vec<EventRecord>>>,
    log: Arc<Mutex<RaftLogStore>>,
    last_applied: Arc<AtomicU64>,
}

impl ExampleRaftHandler {
    fn new(
        node_id: impl Into<String>,
        events: Arc<Mutex<Vec<EventRecord>>>,
        log: Arc<Mutex<RaftLogStore>>,
        last_applied: Arc<AtomicU64>,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            events,
            log,
            last_applied,
        }
    }
}

impl RaftRpcHandler for ExampleRaftHandler {
    fn on_request_vote(&mut self, request: RequestVoteRequest) -> RequestVoteResponse {
        debug!(
            "node {} received RequestVote from {} (term={}, last_log_index={}, last_log_term={})",
            self.node_id, request.candidate_id, request.term, request.last_log_index, request.last_log_term
        );
        RequestVoteResponse {
            term: request.term,
            granted: true,
            reject_reason: None,
        }
    }

    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
        info!(
            "node {} handling AppendEntries from leader {} (entries={}, prev_log_index={}, leader_commit={})",
            self.node_id,
            request.leader_id,
            request.entries.len(),
            request.prev_log_index,
            request.leader_commit
        );
        let mut log = self.log.lock();
        let mut processor = AppendEntriesProcessor::new(&mut *log);
        let outcome = match processor.apply(&request) {
            Ok(outcome) => outcome,
            Err(err) => {
                error!("append_entries log error: {err}");
                return AppendEntriesResponse {
                    term: request.term,
                    success: false,
                    match_index: 0,
                    conflict_index: None,
                    conflict_term: None,
                };
            }
        };
        drop(log);
        if outcome.success {
            apply_committed_entries(&request.entries, &self.events, &self.last_applied);
        }
        outcome.to_response(request.term)
    }
}

fn init_logging(cli_filter: Option<&str>) {
    let env = Env::default().default_filter_or(DEFAULT_LOG_FILTER);
    let mut builder = env_logger::Builder::from_env(env);
    if let Some(filter) = cli_filter {
        builder.parse_filters(filter);
    }
    builder.format_timestamp_secs();
    builder.format(|buf, record| {
        let ts = buf.timestamp();
        writeln!(
            buf,
            "[{} {:<5} {}] {}",
            ts,
            record.level(),
            record.target(),
            record.args()
        )
    });
    builder.init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.log_filter.as_deref());
    let config = load_cluster_config(&cli.config)?;
    let node_cfg = config
        .nodes
        .iter()
        .find(|node| node.id == cli.node)
        .with_context(|| format!("node `{}` not found in config", cli.node))?;
    info!("initializing node {}", node_cfg.id);

    let tls_identity =
        load_identity_from_pem(&node_cfg.cert, &node_cfg.key, Instant::now())?;
    let trust_store = load_trust_store_from_pem(&config.ca_cert)?;

    let peers = build_peer_map(node_cfg, &config.nodes)?;
    let mut durability_ledger =
        DurabilityLedger::new(PartitionQuorumConfig::new(peers.len() + 1));
    durability_ledger.register_replica(node_cfg.id.clone());
    for peer in &peers {
        durability_ledger.register_replica(peer.id.clone());
    }
    let durability_ledger = Arc::new(Mutex::new(durability_ledger));
    let last_quorum_fsynced = Arc::new(AtomicU64::new(0));
    let consensus_core = Arc::new(Mutex::new(ConsensusCore::new(
        ConsensusCoreConfig::default(),
    )));
    let current_term = Arc::new(AtomicU64::new(1));
    let config_dir = cli
        .config
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let state_root = if cli.state_dir.is_absolute() {
        cli.state_dir.clone()
    } else {
        config_dir.join(&cli.state_dir)
    };
    let node_state_dir = state_root.join(&node_cfg.id);
    info!(
        "node {} using state directory {}",
        node_cfg.id,
        node_state_dir.display()
    );
    std::fs::create_dir_all(&node_state_dir)?;
    let storage = PersistentState::open(&node_state_dir)?;
    let log = storage.log_handle();
    let existing_entries = storage.entries_from(1);
    let events = Arc::new(Mutex::new(Vec::new()));
    let last_applied = Arc::new(AtomicU64::new(0));
    apply_committed_entries(&existing_entries, &events, &last_applied);
    info!(
        "node {} recovered {} log entries from {}",
        node_cfg.id,
        existing_entries.len(),
        node_state_dir.join("raft.log").display()
    );
    let handler = ExampleRaftHandler::new(
        node_cfg.id.clone(),
        events.clone(),
        log.clone(),
        last_applied.clone(),
    );
    let mut server_mtls = new_mtls_manager(
        &tls_identity,
        &config.trust_domain,
        Duration::from_secs(300),
        Duration::from_secs(600),
    );
    server_mtls.rotate(Instant::now()).ok();
    let raft_server = RaftRpcServer::new(server_mtls, handler);

    let raft_bind: SocketAddr = node_cfg.raft_bind.parse()?;
    let _raft_handle = RaftNetworkServer::spawn(
        RaftNetworkServerConfig {
            bind: raft_bind,
            identity: tls_identity.clone(),
            trust_store: trust_store.clone(),
        },
        raft_server,
    )?;

    let state = AppState {
        node_id: node_cfg.id.clone(),
        events,
        durability_ledger: durability_ledger.clone(),
        last_quorum_fsynced: last_quorum_fsynced.clone(),
        consensus_core: consensus_core.clone(),
        current_term: current_term.clone(),
        storage: storage.clone(),
        log: log.clone(),
        peers: Arc::new(peers),
        tls_identity: tls_identity.clone(),
        trust_store: trust_store.clone(),
        trust_domain: config.trust_domain.clone(),
        last_applied,
    };

    let app = Router::new()
        .route("/events", post(handle_post_event))
        .route("/events", get(handle_list_events))
        .route("/stats", get(handle_stats))
        .with_state(state.clone());

    let http_tls = Arc::new(build_http_tls(&tls_identity)?);
    let tls_acceptor = TlsAcceptor::from(http_tls);
    let http_addr: SocketAddr = node_cfg.http_bind.parse()?;
    info!(
        "node {} listening on https://{} and Raft TLS {}",
        node_cfg.id, node_cfg.http_bind, node_cfg.raft_bind
    );

    let listener = TcpListener::bind(http_addr).await?;
    let node_id = node_cfg.id.clone();

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
            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down node {}", node_id);
                break;
            }
        }
    }

    info!("node {} shutdown complete", node_id);
    Ok(())
}

async fn handle_post_event(
    State(state): State<AppState>,
    Json(body): Json<EventRequest>,
) -> Result<Json<EventRecord>, (StatusCode, String)> {
    if body.message.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message must not be empty".into()));
    }

    let record = EventRecord {
        source: state.node_id.clone(),
        message: body.message.clone(),
    };
    info!(
        "node {} accepted local event payload: {}",
        state.node_id, record.message
    );
    let entry = append_local_entry(&state, &record)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;

    if let Err(err) = replicate_to_peers(state.clone(), entry.index).await {
        warn!("replication warning: {err}");
    }
    Ok(Json(record))
}

async fn handle_list_events(
    State(state): State<AppState>,
) -> Result<Json<Vec<EventRecord>>, (StatusCode, String)> {
    state
        .guard_read()
        .map_err(|violation| gate_violation_response(&state.node_id, violation))?;
    let snapshot = state.events.lock().clone();
    Ok(Json(snapshot))
}

async fn handle_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let log_tail = state.log.lock().last_index();
    let quorum = state.last_quorum_fsynced.load(Ordering::SeqCst);
    let stats = StatsResponse {
        node_id: state.node_id.clone(),
        last_applied_index: state.last_applied.load(Ordering::SeqCst),
        log_tail_index: log_tail,
        last_quorum_fsynced_index: quorum,
        pending_entries: log_tail.saturating_sub(quorum),
    };
    Json(stats)
}

async fn replicate_to_peers(state: AppState, start_index: u64) -> Result<(), String> {
    if start_index == 0 {
        debug!("nothing to replicate (start_index=0)");
        return Ok(());
    }
    info!(
        "node {} replicating log index {} to {} peers",
        state.node_id,
        start_index,
        state.peers.len()
    );
    let mut joins: Vec<JoinHandle<Result<(), String>>> = Vec::new();
    for peer in state.peers.iter().cloned() {
        let state_clone = state.clone();
        let handle = tokio::task::spawn_blocking(move || {
            send_to_peer(&state_clone, &peer, start_index)
                .map_err(|err| format!("peer {} error: {err}", peer.id))
        });
        joins.push(handle);
    }
    let mut first_err: Option<String> = None;
    for join in joins {
        match join.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!("replication task error: {err}");
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
            Err(err) => {
                warn!("peer task panic: {err}");
                if first_err.is_none() {
                    first_err = Some(err.to_string());
                }
            }
        }
    }
    if let Some(err) = first_err {
        Err(err)
    } else {
        info!(
            "node {} replicated log index {} to all peers",
            state.node_id, start_index
        );
        Ok(())
    }
}

fn send_to_peer(
    state: &AppState,
    peer: &PeerInfo,
    start_index: u64,
) -> Result<(), clustor::net::NetError> {
    debug!(
        "node {} preparing replication to peer {} @ {}:{} (start_index={})",
        state.node_id, peer.id, peer.host, peer.port, start_index
    );
    let mut mtls = new_mtls_manager(
        &state.tls_identity,
        &state.trust_domain,
        Duration::from_secs(300),
        Duration::from_secs(600),
    );
    mtls.rotate(Instant::now()).ok();
    let mut client = RaftNetworkClient::new(RaftNetworkClientConfig {
        host: peer.host.clone(),
        port: peer.port,
        identity: state.tls_identity.clone(),
        trust_store: state.trust_store.clone(),
        mtls,
    })?;

    let (prev_log_index, prev_log_term, entries, leader_commit) = {
        let log = state.log.lock();
        let prev_index = start_index.saturating_sub(1);
        let prev_term = if prev_index == 0 {
            0
        } else {
            log.term_at(prev_index).unwrap_or(0)
        };
        let entries = log.entries_from(start_index);
        let leader_commit = entries
            .last()
            .map(|entry| entry.index)
            .unwrap_or(prev_index);
        (prev_index, prev_term, entries, leader_commit)
    };

    if entries.is_empty() {
        debug!(
            "node {} no new entries to send to peer {}",
            state.node_id, peer.id
        );
        return Ok(());
    }

    let request = AppendEntriesRequest {
        term: 1,
        leader_id: state.node_id.clone(),
        prev_log_index,
        prev_log_term,
        leader_commit,
        entries,
    };
    info!(
        "node {} connecting to peer {} at {}:{} ({} entries, prev_log_index={}, leader_commit={})",
        state.node_id,
        peer.id,
        peer.host,
        peer.port,
        request.entries.len(),
        request.prev_log_index,
        request.leader_commit
    );
    let response = client.append_entries(&request, Instant::now())?;
    if !response.success {
        warn!(
            "replication rejected by peer {} (conflict_index={:?}, conflict_term={:?})",
            peer.id, response.conflict_index, response.conflict_term
        );
        return Err(clustor::net::NetError::Protocol(format!(
            "append rejected (conflict_index={:?}, conflict_term={:?})",
            response.conflict_index, response.conflict_term
        )));
    }
    state.record_peer_ack(&peer.id, request.term, response.match_index);
    info!(
        "node {} replicated entries [{}..={}] to peer {}",
        state.node_id,
        start_index,
        request
            .entries
            .last()
            .map(|entry| entry.index)
            .unwrap_or(start_index),
        peer.id
    );
    info!(
        "node {} disconnected from peer {} after successful append",
        state.node_id, peer.id
    );
    Ok(())
}

fn build_peer_map(
    node_cfg: &NodeConfig,
    all_nodes: &[NodeConfig],
) -> Result<Vec<PeerInfo>> {
    let index: HashMap<_, _> = all_nodes.iter().map(|n| (&n.id, n)).collect();
    let mut peers = Vec::new();
    for peer_id in &node_cfg.peers {
        let peer_cfg = index
            .get(peer_id)
            .with_context(|| format!("peer `{peer_id}` missing from config"))?;
        let addr: SocketAddr = peer_cfg.raft_bind.parse()?;
        peers.push(PeerInfo {
            id: peer_cfg.id.clone(),
            host: addr.ip().to_string(),
            port: addr.port(),
        });
    }
    Ok(peers)
}

fn gate_violation_response(
    node_id: &str,
    violation: GateViolation,
) -> (StatusCode, String) {
    let reason = match violation {
        GateViolation::ModeConflictStrictFallback => "ModeConflict(strict_fallback)",
        GateViolation::CpUnavailableNeededForReadIndex => {
            "ControlPlaneUnavailable{reason=NeededForReadIndex}"
        }
        GateViolation::CpUnavailableCacheExpired => {
            "ControlPlaneUnavailable{reason=CacheExpired}"
        }
        GateViolation::FollowerCapabilityRevoked => "FollowerCapabilityRevoked",
    };
    warn!(
        "node {} strict fallback gate blocked read: {}",
        node_id, reason
    );
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("strict fallback gate blocked read: {}", reason),
    )
}

fn append_local_entry(state: &AppState, record: &EventRecord) -> Result<RaftLogEntry, String> {
    let payload =
        serde_json::to_vec(record).map_err(|err| format!("encode event payload failed: {err}"))?;
    let appended = state
        .storage
        .append_payload(1, payload)
        .map_err(|err| format!("log append failed: {err}"))?;
    state.on_local_append(&appended.entry);
    state.record_leader_ack(&appended);
    apply_committed_entries(
        &[appended.entry.clone()],
        &state.events,
        &state.last_applied,
    );
    Ok(appended.entry)
}

fn apply_committed_entries(
    entries: &[RaftLogEntry],
    events: &Arc<Mutex<Vec<EventRecord>>>,
    last_applied: &Arc<AtomicU64>,
) {
    if entries.is_empty() {
        return;
    }
    let mut applied = last_applied.load(Ordering::SeqCst);
    let mut new_records = Vec::new();
    for entry in entries {
        if entry.index <= applied {
            continue;
        }
        match serde_json::from_slice::<EventRecord>(&entry.payload) {
            Ok(record) => {
                new_records.push(record);
                applied = entry.index;
            }
            Err(err) => {
                error!(
                    "failed to decode event payload at index {}: {err}",
                    entry.index
                );
            }
        }
    }
    if new_records.is_empty() {
        return;
    }
    let mut guard = events.lock();
    guard.extend(new_records);
    last_applied.store(applied, Ordering::SeqCst);
}

fn new_mtls_manager(
    identity: &TlsIdentity,
    trust_domain: &str,
    dual_validity: Duration,
    revocation_ttl: Duration,
) -> MtlsIdentityManager {
    MtlsIdentityManager::new(
        identity.certificate.clone(),
        trust_domain.to_string(),
        dual_validity,
        revocation_ttl,
        Instant::now(),
    )
}

fn build_http_tls(identity: &TlsIdentity) -> Result<rustls::ServerConfig> {
    let cert_chain = identity.chain.clone();
    let private_key = identity.private_key.clone();
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to build HTTP TLS config")?;
    Ok(config)
}

fn load_cluster_config(path: &Path) -> Result<ClusterConfig> {
    let raw = std::fs::read_to_string(path)?;
    let mut config: ClusterConfig = serde_yaml::from_str(&raw)?;
    // Normalize relative paths to be relative to the config location.
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if config.ca_cert.is_relative() {
        config.ca_cert = base.join(config.ca_cert);
    }
    for node in &mut config.nodes {
        if node.cert.is_relative() {
            node.cert = base.join(&node.cert);
        }
        if node.key.is_relative() {
            node.key = base.join(&node.key);
        }
    }
    Ok(config)
}
