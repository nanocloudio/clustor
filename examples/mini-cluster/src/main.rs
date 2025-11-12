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
    AppendEntriesProcessor, AppendEntriesRequest, AppendEntriesResponse, ElectionController,
    ElectionProfile, PartitionQuorumConfig, ReplicaId, RequestVoteRejectReason,
    RequestVoteRequest, RequestVoteResponse,
};
use clustor::security::{MtlsIdentityManager, RevocationSource};
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
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServerBuilder;
use hyper_util::service::TowerToHyperService;
use log::{debug, error, info, trace, warn};
use rand::Rng;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio::sync::Notify;
use tokio::time::{interval, sleep};
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

const DEFAULT_LOG_FILTER: &str = "info,clustor=info,clustor::net::raft=info";
const REVOCATION_REFRESH_INTERVAL: Duration = Duration::from_secs(240);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RaftRole {
    Leader,
    Follower,
    Candidate,
}

#[derive(Debug)]
struct RoleState {
    role: RaftRole,
    term: u64,
    leader_id: Option<String>,
    voted_for: Option<String>,
    last_leader_contact: Instant,
    election_deadline: Instant,
}

impl RoleState {
    fn new(term: u64, now: Instant, timeout: Duration) -> Self {
        Self {
            role: RaftRole::Follower,
            term,
            leader_id: None,
            voted_for: None,
            last_leader_contact: now,
            election_deadline: now + timeout,
        }
    }

    fn schedule_election(&mut self, now: Instant, timeout: Duration) {
        self.last_leader_contact = now;
        self.election_deadline = now + timeout;
    }
}

#[derive(Clone)]
struct NodeState {
    app: AppState,
    raft: Arc<RaftRuntime>,
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
    last_applied: Arc<AtomicU64>,
    peer_down_after: Duration,
}

#[derive(Clone)]
struct PeerInfo {
    id: String,
    host: String,
    port: u16,
    client: Arc<Mutex<RaftNetworkClient>>,
    health: Arc<PeerHealth>,
}

impl PeerInfo {
    fn refresh_revocation(&self, now: Instant) {
        let mut client = self.client.lock();
        client.refresh_revocation(now);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerStatus {
    Healthy,
    Suspect,
    Down,
}

struct PeerHealthState {
    status: PeerStatus,
    has_success: bool,
    last_success: Instant,
    last_failure: Option<Instant>,
}

struct PeerHealth {
    state: Mutex<PeerHealthState>,
}

impl PeerHealth {
    fn new(now: Instant) -> Self {
        Self {
            state: Mutex::new(PeerHealthState {
                status: PeerStatus::Healthy,
                has_success: false,
                last_success: now,
                last_failure: None,
            }),
        }
    }

    fn record_success(&self, local: &str, peer: &str, now: Instant) {
        let mut state = self.state.lock();
        let previous = state.status;
        let downtime = state.last_failure.map(|ts| now.saturating_duration_since(ts));
        state.status = PeerStatus::Healthy;
        state.has_success = true;
        state.last_success = now;
        state.last_failure = None;
        drop(state);
        if matches!(previous, PeerStatus::Suspect | PeerStatus::Down) {
            if let Some(duration) = downtime {
                info!(
                    "node {} peer {} recovered after {:?}",
                    local, peer, duration
                );
            } else {
                info!("node {} peer {} recovered", local, peer);
            }
        }
    }

    fn record_failure(
        &self,
        local: &str,
        peer: &str,
        now: Instant,
        err: &str,
        down_after: Duration,
    ) {
        let mut state = self.state.lock();
        state.last_failure = Some(now);
        match state.status {
            PeerStatus::Healthy => {
                state.status = PeerStatus::Suspect;
                warn!(
                    "node {} peer {} marked suspect (error={} )",
                    local, peer, err
                );
            }
            PeerStatus::Suspect => {
                if now.duration_since(state.last_success) >= down_after {
                    state.status = PeerStatus::Down;
                    warn!(
                        "node {} peer {} marked down (error={}, last_success {:?} ago)",
                        local,
                        peer,
                        err,
                        now.duration_since(state.last_success)
                    );
                } else {
                    debug!(
                        "node {} peer {} still suspect (error={})",
                        local, peer, err
                    );
                }
            }
            PeerStatus::Down => {
                debug!(
                    "node {} peer {} still down (error={})",
                    local, peer, err
                );
            }
        }
    }

    fn evaluate_timeout(
        &self,
        local: &str,
        peer: &str,
        now: Instant,
        suspect_after: Duration,
        down_after: Duration,
    ) {
        let mut state = self.state.lock();
        if !state.has_success {
            return;
        }
        let since_success = now.duration_since(state.last_success);
        match state.status {
            PeerStatus::Healthy => {
                if since_success >= suspect_after {
                    state.status = PeerStatus::Suspect;
                    warn!(
                        "node {} peer {} marked suspect (no success for {:?})",
                        local, peer, since_success
                    );
                }
            }
            PeerStatus::Suspect => {
                if since_success >= down_after {
                    state.status = PeerStatus::Down;
                    warn!(
                        "node {} peer {} marked down (no success for {:?})",
                        local, peer, since_success
                    );
                }
            }
            PeerStatus::Down => {}
        }
    }

    fn is_healthy(&self) -> bool {
        matches!(self.status(), PeerStatus::Healthy)
    }

    fn status(&self) -> PeerStatus {
        self.state.lock().status
    }
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

struct RaftRuntime {
    node_id: String,
    state: AppState,
    role: Arc<Mutex<RoleState>>,
    election: Mutex<ElectionController>,
    heartbeat_interval: Duration,
    peer_suspect_after: Duration,
    peer_down_after: Duration,
    notify: Arc<Notify>,
    shutdown: Arc<AtomicBool>,
    vote_failure_logged: AtomicBool,
}

struct RaftRuntimeHandle {
    shutdown: Arc<AtomicBool>,
    notify: Arc<Notify>,
    _tasks: Vec<JoinHandle<()>>,
}

impl Drop for RaftRuntimeHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

impl RaftRuntime {
    fn new(
        state: AppState,
        role: Arc<Mutex<RoleState>>,
        election: ElectionController,
        heartbeat_interval: Duration,
        peer_suspect_after: Duration,
        peer_down_after: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_id: state.node_id.clone(),
            state,
            role,
            heartbeat_interval,
            peer_suspect_after,
            peer_down_after,
            election: Mutex::new(election),
            notify: Arc::new(Notify::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            vote_failure_logged: AtomicBool::new(false),
        })
    }

    fn spawn(self: &Arc<Self>) -> RaftRuntimeHandle {
        let heartbeat = tokio::spawn(Self::heartbeat_loop(self.clone()));
        let election = tokio::spawn(Self::election_loop(self.clone()));
        RaftRuntimeHandle {
            shutdown: self.shutdown.clone(),
            notify: self.notify.clone(),
            _tasks: vec![heartbeat, election],
        }
    }

    fn is_leader(&self) -> bool {
        matches!(self.role.lock().role, RaftRole::Leader)
    }

    fn leader_id(&self) -> Option<String> {
        self.role.lock().leader_id.clone()
    }

    fn current_term(&self) -> u64 {
        self.state.current_term.load(Ordering::SeqCst)
    }

    fn wake(&self) {
        self.notify.notify_waiters();
    }

    async fn replicate_from(&self, start_index: u64) -> Result<(), String> {
        if !self.is_leader() {
            return Err("not leader".into());
        }
        if !self.has_leader_quorum() {
            return Err("quorum unavailable".into());
        }
        let commit_index = self.state.last_quorum_fsynced.load(Ordering::SeqCst);
        replicate_to_peers(self.state.clone(), start_index, commit_index).await
    }

    fn handle_request_vote(&self, request: RequestVoteRequest) -> RequestVoteResponse {
        let now = Instant::now();
        let mut current_term = self.current_term();
        if request.term < current_term {
            return RequestVoteResponse {
                term: current_term,
                granted: false,
                reject_reason: Some(RequestVoteRejectReason::TermOutOfDate),
            };
        }
        if request.term > current_term {
            if let Err(err) = self.update_term(request.term) {
                warn!("failed to update term during vote handling: {err}");
            }
            current_term = request.term;
        }

        let (last_index, last_term) = self.log_tail();
        let up_to_date = request.last_log_term > last_term
            || (request.last_log_term == last_term && request.last_log_index >= last_index);
        if !up_to_date {
            return RequestVoteResponse {
                term: current_term,
                granted: false,
                reject_reason: Some(RequestVoteRejectReason::LogBehind),
            };
        }

        {
            let mut role = self.role.lock();
            if let Some(existing) = &role.voted_for {
                if existing != &request.candidate_id {
                    return RequestVoteResponse {
                        term: current_term,
                        granted: false,
                        reject_reason: Some(RequestVoteRejectReason::NotLeaderEligible),
                    };
                }
            } else {
                role.voted_for = Some(request.candidate_id.clone());
            }
            role.role = RaftRole::Follower;
            role.leader_id = None;
        }

        if let Err(err) = self.state.storage.record_vote(Some(&request.candidate_id)) {
            warn!("failed to persist vote: {err}");
        }
        info!(
            "node {} granted vote to {} for term {}",
            self.node_id, request.candidate_id, current_term
        );
        self.schedule_timeout(now);
        RequestVoteResponse {
            term: current_term,
            granted: true,
            reject_reason: None,
        }
    }

    fn handle_append_entries(&self, request: AppendEntriesRequest) -> AppendEntriesResponse {
        let now = Instant::now();
        let current_term = self.current_term();
        if request.term < current_term {
            return AppendEntriesResponse {
                term: current_term,
                success: false,
                match_index: 0,
                conflict_index: Some(request.prev_log_index),
                conflict_term: None,
            };
        }
        if request.term > current_term {
            if let Err(err) = self.update_term(request.term) {
                warn!("failed to update term during append: {err}");
            }
        }
        {
            let mut role = self.role.lock();
            if role.leader_id.as_ref() != Some(&request.leader_id) {
                info!(
                    "node {} now follows leader {} (term={})",
                    self.node_id, request.leader_id, request.term
                );
            }
            role.term = request.term;
            role.role = RaftRole::Follower;
            role.leader_id = Some(request.leader_id.clone());
        }
        self.schedule_timeout(now);

        let mut log = self.state.log.lock();
        let mut processor = AppendEntriesProcessor::new(&mut *log);
        let outcome = match processor.apply(&request) {
            Ok(result) => result,
            Err(err) => {
                error!("append_entries log error: {err}");
                return AppendEntriesResponse {
                    term: self.current_term(),
                    success: false,
                    match_index: 0,
                    conflict_index: None,
                    conflict_term: None,
                };
            }
        };
        let match_index = outcome.match_index;
        drop(log);

        if outcome.success {
            let commit_index = request.leader_commit.min(match_index);
            if commit_index > 0 {
                self.state
                    .last_quorum_fsynced
                    .store(commit_index, Ordering::SeqCst);
                self.state.reconcile_strict_fallback(commit_index);
                let entries_to_apply = {
                    let log = self.state.log.lock();
                    let start = self.state.last_applied.load(Ordering::SeqCst) + 1;
                    log.entries_from(start)
                        .into_iter()
                        .filter(|entry| entry.index <= commit_index)
                        .collect::<Vec<_>>()
                };
                apply_committed_entries(
                    &entries_to_apply,
                    &self.state.events,
                    &self.state.last_applied,
                );
            }
        }

        outcome.to_response(self.current_term())
    }

    fn schedule_timeout(&self, now: Instant) {
        let timeout = {
            let mut controller = self.election.lock();
            controller.next_election_timeout(self.node_id.clone())
        };
        let mut role = self.role.lock();
        role.schedule_election(now, timeout);
        self.notify.notify_waiters();
    }

    fn log_tail(&self) -> (u64, u64) {
        let log = self.state.log.lock();
        let last_index = log.last_index();
        let last_term = if last_index == 0 {
            0
        } else {
            log.term_at(last_index).unwrap_or(0)
        };
        (last_index, last_term)
    }

    pub fn has_leader_quorum(&self) -> bool {
        let total = self.state.peers.len() + 1;
        let majority = total / 2 + 1;
        let healthy_peers = self
            .state
            .peers
            .iter()
            .filter(|peer| peer.health.is_healthy())
            .count();
        1 + healthy_peers >= majority
    }

    fn update_term(&self, term: u64) -> Result<(), String> {
        if term <= self.current_term() {
            return Ok(());
        }
        self.state.storage.set_current_term(term)?;
        self.state.storage.record_vote(None)?;
        self.state.current_term.store(term, Ordering::SeqCst);
        let mut role = self.role.lock();
        role.term = term;
        role.voted_for = None;
        role.role = RaftRole::Follower;
        role.leader_id = None;
        info!(
            "node {} updated local term to {} and reset vote",
            self.node_id, term
        );
        Ok(())
    }

    fn should_start_election(&self, now: Instant) -> bool {
        let role = self.role.lock();
        !matches!(role.role, RaftRole::Leader) && now >= role.election_deadline
    }

    fn time_until_deadline(&self, now: Instant) -> Duration {
        let role = self.role.lock();
        if now >= role.election_deadline {
            Duration::from_millis(0)
        } else {
            role.election_deadline - now
        }
    }

    async fn start_election(self: &Arc<Self>) {
        let now = Instant::now();
        let timeout = {
            let mut controller = self.election.lock();
            controller.next_election_timeout(self.node_id.clone())
        };
        {
            let mut role = self.role.lock();
            if matches!(role.role, RaftRole::Leader) {
                return;
            }
            role.role = RaftRole::Candidate;
            role.term += 1;
            role.voted_for = Some(self.node_id.clone());
            role.leader_id = None;
            role.schedule_election(now, timeout);
        }
        let term = self.role.lock().term;
        if self.vote_failure_logged.load(Ordering::SeqCst) {
            debug!(
                "node {} starting election for term {} (previous attempts failed)",
                self.node_id, term
            );
        } else {
            info!("node {} starting election for term {}", self.node_id, term);
        }
        if let Err(err) = self.state.storage.set_current_term(term) {
            warn!("failed to persist new term {}: {err}", term);
        }
        if let Err(err) = self.state.storage.record_vote(Some(&self.node_id)) {
            warn!("failed to persist self vote: {err}");
        }
        self.state.current_term.store(term, Ordering::SeqCst);
        let (last_index, last_term) = self.log_tail();
        let request = RequestVoteRequest {
            term,
            candidate_id: self.node_id.clone(),
            last_log_index: last_index,
            last_log_term: last_term,
            pre_vote: false,
        };
        let total = self.state.peers.len() + 1;
        let majority = total / 2 + 1;
        let (granted, highest_term) = self.dispatch_request_vote(request).await;
        if highest_term > term {
            if let Err(err) = self.update_term(highest_term) {
                warn!("failed to step down to higher term {}: {err}", highest_term);
            }
            info!(
                "node {} observed higher term {} during election, stepping down",
                self.node_id, highest_term
            );
            return;
        }
        let total_votes = granted + 1; // include self
        let should_become_leader = {
            let role = self.role.lock();
            matches!(role.role, RaftRole::Candidate) && role.term == term && total_votes >= majority
        };
        if should_become_leader {
            self.become_leader(term);
            self.wake();
        }
    }

    async fn dispatch_request_vote(
        &self,
        request: RequestVoteRequest,
    ) -> (usize, u64) {
        let mut highest_term = request.term;
        let mut granted = 0usize;
        let mut jobs = Vec::new();
        for peer in self.state.peers.iter().cloned() {
            let req = request.clone();
            jobs.push(tokio::task::spawn_blocking(move || {
                let mut client = peer.client.lock();
                client.request_vote(&req, Instant::now())
            }));
        }
        for job in jobs {
            match job.await {
                Ok(Ok(response)) => {
                    if response.term > highest_term {
                        highest_term = response.term;
                    }
                    if response.granted {
                        granted += 1;
                    }
                    self.vote_failure_logged.store(false, Ordering::SeqCst);
                }
                Ok(Err(err)) => {
                    self.log_request_vote_error(&err.to_string());
                }
                Err(err) => {
                    self.log_request_vote_error(&err.to_string());
                }
            }
        }
        (granted, highest_term)
    }

    fn become_leader(&self, term: u64) {
        let mut role = self.role.lock();
        role.role = RaftRole::Leader;
        role.term = term;
        role.leader_id = Some(self.node_id.clone());
        role.voted_for = Some(self.node_id.clone());
        role.schedule_election(Instant::now(), self.heartbeat_interval);
        info!(
            "node {} became leader for term {}",
            self.node_id, term
        );
    }

    async fn heartbeat_loop(this: Arc<Self>) {
        loop {
            if this.shutdown.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                _ = sleep(this.heartbeat_interval) => {},
                _ = this.notify.notified() => {},
            }
            if this.shutdown.load(Ordering::SeqCst) {
                break;
            }
            if this.is_leader() {
                let start_index = {
                    let log = this.state.log.lock();
                    log.last_index().saturating_add(1)
                };
                if let Err(err) = this.replicate_from(start_index).await {
                    debug!("heartbeat replication skipped: {err}");
                }
                this.monitor_peer_health();
            }
        }
    }

    async fn election_loop(this: Arc<Self>) {
        loop {
            if this.shutdown.load(Ordering::SeqCst) {
                break;
            }
            let sleep_dur = this.time_until_deadline(Instant::now());
            tokio::select! {
                _ = sleep(sleep_dur) => {},
                _ = this.notify.notified() => {},
            }
            if this.shutdown.load(Ordering::SeqCst) {
                break;
            }
            if this.should_start_election(Instant::now()) {
                this.start_election().await;
            }
        }
    }

    fn monitor_peer_health(&self) {
        let now = Instant::now();
        for peer in self.state.peers.iter() {
            peer.health.evaluate_timeout(
                &self.node_id,
                &peer.id,
                now,
                self.peer_suspect_after,
                self.peer_down_after,
            );
        }
    }
}
 
impl RaftRuntime {
    fn log_request_vote_error(&self, message: &str) {
        if !self
            .vote_failure_logged
            .swap(true, Ordering::SeqCst)
        {
            warn!(
                "node {} unable to reach peer for RequestVote: {} (further failures will be debug-level)",
                self.node_id, message
            );
        } else {
            debug!(
                "node {} RequestVote retry failed: {}",
                self.node_id, message
            );
        }
    }
}

struct MiniClusterRaftHandler {
    runtime: Arc<RaftRuntime>,
}

impl MiniClusterRaftHandler {
    fn new(runtime: Arc<RaftRuntime>) -> Self {
        Self { runtime }
    }
}

impl RaftRpcHandler for MiniClusterRaftHandler {
    fn on_request_vote(&mut self, request: RequestVoteRequest) -> RequestVoteResponse {
        self.runtime.handle_request_vote(request)
    }

    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
        self.runtime.handle_append_entries(request)
    }
}

fn init_logging(cli_filter: Option<&str>) {
    let env = Env::default().default_filter_or(DEFAULT_LOG_FILTER);
    let mut builder = env_logger::Builder::from_env(env);
    builder.parse_filters("clustor::net::raft=info");
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

    let peers = build_peer_map(
        node_cfg,
        &config.nodes,
        &tls_identity,
        &trust_store,
        &config.trust_domain,
    )?;
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
    let recovered_term = storage.current_term();
    current_term.store(recovered_term, Ordering::SeqCst);
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
    let mut election_controller =
        ElectionController::new(ElectionProfile::Latency, rand::thread_rng().gen());
    let heartbeat_interval = election_controller.heartbeat_interval();
    let peer_suspect_after = Duration::from_millis(1500).max(heartbeat_interval * 20);
    let peer_down_after = Duration::from_millis(4500).max(heartbeat_interval * 60);
    let initial_timeout = election_controller.next_election_timeout(node_cfg.id.clone());

    let app_state = AppState {
        node_id: node_cfg.id.clone(),
        events,
        durability_ledger: durability_ledger.clone(),
        last_quorum_fsynced: last_quorum_fsynced.clone(),
        consensus_core: consensus_core.clone(),
        current_term: current_term.clone(),
        storage: storage.clone(),
        log: log.clone(),
        peers: Arc::new(peers),
        last_applied,
        peer_down_after,
    };
    let role_state = Arc::new(Mutex::new(RoleState::new(
        current_term.load(Ordering::SeqCst),
        Instant::now(),
        initial_timeout,
    )));
    if let Some(voted) = storage.voted_for() {
        role_state.lock().voted_for = Some(voted);
    }
    let runtime = RaftRuntime::new(
        app_state.clone(),
        role_state,
        election_controller,
        heartbeat_interval,
        peer_suspect_after,
        peer_down_after,
    );
    let _runtime_handle = runtime.spawn();

    let handler = MiniClusterRaftHandler::new(runtime.clone());
    let mut server_mtls = new_mtls_manager(
        &tls_identity,
        &config.trust_domain,
        Duration::from_secs(300),
        Duration::from_secs(600),
    );
    server_mtls.rotate(Instant::now()).ok();
    let raft_server = RaftRpcServer::new(server_mtls, handler);
    let server_identity_handle = raft_server.identity_handle();

    let raft_bind: SocketAddr = node_cfg.raft_bind.parse()?;
    let _raft_handle = RaftNetworkServer::spawn(
        RaftNetworkServerConfig {
            bind: raft_bind,
            identity: tls_identity.clone(),
            trust_store: trust_store.clone(),
        },
        raft_server,
    )?;

    tokio::spawn(refresh_server_revocation(server_identity_handle.clone()));

    let node_state = NodeState {
        app: app_state.clone(),
        raft: runtime.clone(),
    };

    tokio::spawn(refresh_peer_revocations(app_state.peers.clone()));

    let app = Router::new()
        .route("/events", post(handle_post_event))
        .route("/events", get(handle_list_events))
        .route("/stats", get(handle_stats))
        .with_state(node_state.clone());

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
    State(node): State<NodeState>,
    Json(body): Json<EventRequest>,
) -> Result<Json<EventRecord>, (StatusCode, String)> {
    if body.message.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "message must not be empty".into()));
    }

    if !node.raft.is_leader() {
        let leader = node
            .raft
            .leader_id()
            .unwrap_or_else(|| "unknown".into());
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "node {} is not the leader (current leader: {})",
                node.app.node_id, leader
            ),
        ));
    }
    if !node.raft.has_leader_quorum() {
        return Err(gate_violation_response(
            &node.app.node_id,
            GateViolation::CpUnavailableNeededForReadIndex,
        ));
    }

    let state = node.app.clone();
    let record = EventRecord {
        source: state.node_id.clone(),
        message: body.message.clone(),
    };
    info!(
        "node {} accepted local event payload: {}",
        state.node_id, record.message
    );
    let entry = append_local_entry(&state, &record, node.raft.current_term())
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;

    if let Err(err) = node.raft.replicate_from(entry.index).await {
        warn!("replication warning: {err}");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("replication failed: {err}"),
        ));
    }
    Ok(Json(record))
}

async fn handle_list_events(
    State(node): State<NodeState>,
) -> Result<Json<Vec<EventRecord>>, (StatusCode, String)> {
    let state = node.app.clone();
    state
        .guard_read()
        .map_err(|violation| gate_violation_response(&state.node_id, violation))?;
    if node.raft.is_leader() && !node.raft.has_leader_quorum() {
        return Err(gate_violation_response(
            &state.node_id,
            GateViolation::CpUnavailableNeededForReadIndex,
        ));
    }
    let snapshot = state.events.lock().clone();
    Ok(Json(snapshot))
}

async fn handle_stats(State(node): State<NodeState>) -> Json<StatsResponse> {
    let state = node.app.clone();
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

async fn replicate_to_peers(
    state: AppState,
    start_index: u64,
    leader_commit: u64,
) -> Result<(), String> {
    if start_index == 0 {
        debug!("nothing to replicate (start_index=0)");
        return Ok(());
    }
    let has_entries = {
        let log = state.log.lock();
        log.last_index() >= start_index
    };
    if has_entries {
        info!(
            "node {} replicating log index {} to {} peers",
            state.node_id,
            start_index,
            state.peers.len()
        );
    } else {
        debug!(
            "node {} sending heartbeat to {} peers",
            state.node_id,
            state.peers.len()
        );
    }
    let mut joins: Vec<JoinHandle<Result<(), String>>> = Vec::new();
    for peer in state.peers.iter().cloned() {
        let state_clone = state.clone();
        let peer_clone = peer.clone();
        let commit_index = leader_commit;
        let handle = tokio::task::spawn_blocking(move || {
            let peer_id = peer_clone.id.clone();
            send_to_peer(&state_clone, peer_clone, start_index, commit_index)
                .map_err(|err| format!("peer {} error: {err}", peer_id))
        });
        joins.push(handle);
    }
    let mut first_err: Option<String> = None;
    for join in joins {
        match join.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                debug!("replication task error: {err}");
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
        if has_entries {
            info!(
                "node {} replicated log index {} to all peers",
                state.node_id, start_index
            );
        } else {
            debug!("node {} sent heartbeat to all peers", state.node_id);
        }
        Ok(())
    }
}

fn send_to_peer(
    state: &AppState,
    peer: PeerInfo,
    start_index: u64,
    leader_commit: u64,
) -> Result<(), clustor::net::NetError> {
    debug!(
        "node {} preparing replication to peer {} @ {}:{} (start_index={})",
        state.node_id, peer.id, peer.host, peer.port, start_index
    );
    let (prev_log_index, prev_log_term, entries, log_tail) = {
        let log = state.log.lock();
        let prev_index = start_index.saturating_sub(1);
        let prev_term = if prev_index == 0 {
            0
        } else {
            log.term_at(prev_index).unwrap_or(0)
        };
        let entries = log.entries_from(start_index);
        let tail = log.last_index();
        (prev_index, prev_term, entries, tail)
    };
    let commit_index = leader_commit.min(log_tail);

    let request = AppendEntriesRequest {
        term: state.current_term.load(Ordering::SeqCst),
        leader_id: state.node_id.clone(),
        prev_log_index,
        prev_log_term,
        leader_commit: commit_index,
        entries,
    };
    let heartbeat = request.entries.is_empty();
    if heartbeat {
        debug!(
            "node {} sending heartbeat to peer {} at {}:{} (prev_log_index={}, leader_commit={})",
            state.node_id,
            peer.id,
            peer.host,
            peer.port,
            request.prev_log_index,
            request.leader_commit
        );
    } else {
        debug!(
            "node {} sending {} entries to peer {} @ {}:{} (prev_log_index={}, leader_commit={})",
            state.node_id,
            request.entries.len(),
            peer.id,
            peer.host,
            peer.port,
            request.prev_log_index,
            request.leader_commit
        );
    }
    let mut client = peer.client.lock();
    let response = match client.append_entries(&request, Instant::now()) {
        Ok(resp) => {
            peer.health
                .record_success(&state.node_id, &peer.id, Instant::now());
            resp
        }
        Err(err) => {
            let message = err.to_string();
            debug!(
                "node {} Raft RPC to peer {} failed: {}",
                state.node_id, peer.id, message
            );
            peer.health.record_failure(
                &state.node_id,
                &peer.id,
                Instant::now(),
                &message,
                state.peer_down_after,
            );
            return Err(err);
        }
    };
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
    if !heartbeat {
        debug!(
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
    }
    trace!(
        "node {} completed Raft RPC to peer {}",
        state.node_id, peer.id
    );
    Ok(())
}

fn build_peer_map(
    node_cfg: &NodeConfig,
    all_nodes: &[NodeConfig],
    tls_identity: &TlsIdentity,
    trust_store: &TlsTrustStore,
    trust_domain: &str,
) -> Result<Vec<PeerInfo>> {
    let index: HashMap<_, _> = all_nodes.iter().map(|n| (&n.id, n)).collect();
    let mut peers = Vec::new();
    for peer_id in &node_cfg.peers {
        let peer_cfg = index
            .get(peer_id)
            .with_context(|| format!("peer `{peer_id}` missing from config"))?;
        let addr: SocketAddr = peer_cfg.raft_bind.parse()?;
        let host = addr.ip().to_string();
        let port = addr.port();
        let mut mtls = new_mtls_manager(
            tls_identity,
            trust_domain,
            Duration::from_secs(300),
            Duration::from_secs(600),
        );
        mtls.rotate(Instant::now()).ok();
        let client = RaftNetworkClient::new(RaftNetworkClientConfig {
            host: host.clone(),
            port,
            identity: tls_identity.clone(),
            trust_store: trust_store.clone(),
            mtls,
        })
        .with_context(|| format!("failed to build Raft client for peer {}", peer_cfg.id))?;
        let health = Arc::new(PeerHealth::new(Instant::now()));
        peers.push(PeerInfo {
            id: peer_cfg.id.clone(),
            host,
            port,
            client: Arc::new(Mutex::new(client)),
            health,
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

fn append_local_entry(
    state: &AppState,
    record: &EventRecord,
    term: u64,
) -> Result<RaftLogEntry, String> {
    let payload =
        serde_json::to_vec(record).map_err(|err| format!("encode event payload failed: {err}"))?;
    let appended = state
        .storage
        .append_payload(term, payload)
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

async fn refresh_server_revocation(
    identity: Arc<std::sync::Mutex<MtlsIdentityManager>>,
) {
    let mut ticker = interval(REVOCATION_REFRESH_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        if let Ok(mut guard) = identity.lock() {
            guard.record_revocation_refresh(RevocationSource::Ocsp, now);
            guard.record_revocation_refresh(RevocationSource::Crl, now);
        }
    }
}

async fn refresh_peer_revocations(peers: Arc<Vec<PeerInfo>>) {
    let mut ticker = interval(REVOCATION_REFRESH_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        for peer in peers.iter() {
            peer.refresh_revocation(now);
        }
    }
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
