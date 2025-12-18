use crate::peers::{PeerInfo};
use crate::state::{apply_committed_entries, AppState};
use clustor::raft::{
    AppendEntriesProcessor, AppendEntriesRequest, AppendEntriesResponse, ElectionController,
    ElectionProfile, PartitionQuorumConfig, RequestVoteRejectReason, RequestVoteRequest,
    RequestVoteResponse, RaftRouting,
};
use clustor::transport::raft::RaftRpcHandler;
use log::{debug, error, info, trace, warn};
use parking_lot::Mutex;
use rand::Rng;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::sleep;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaftRole {
    Leader,
    Follower,
    Candidate,
}

#[derive(Debug)]
pub struct RoleState {
    pub role: RaftRole,
    pub term: u64,
    pub leader_id: Option<String>,
    pub voted_for: Option<String>,
    pub last_leader_contact: Instant,
    pub election_deadline: Instant,
}

impl RoleState {
    pub fn new(term: u64, now: Instant, timeout: Duration) -> Self {
        Self {
            role: RaftRole::Follower,
            term,
            leader_id: None,
            voted_for: None,
            last_leader_contact: now,
            election_deadline: now + timeout,
        }
    }

    pub fn schedule_election(&mut self, now: Instant, timeout: Duration) {
        self.last_leader_contact = now;
        self.election_deadline = now + timeout;
    }
}

pub struct RaftRuntime {
    pub node_id: String,
    pub state: AppState,
    pub role: Arc<Mutex<RoleState>>,
    pub election: Mutex<ElectionController>,
    pub heartbeat_interval: Duration,
    pub peer_suspect_after: Duration,
    pub peer_down_after: Duration,
    pub notify: Arc<Notify>,
    pub shutdown: Arc<AtomicBool>,
    vote_failure_logged: AtomicBool,
    leadership_epoch: Arc<AtomicU64>,
}

pub struct RaftRuntimeHandle {
    runtime: Arc<RaftRuntime>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for RaftRuntimeHandle {
    fn drop(&mut self) {
        self.signal_shutdown();
    }
}

impl RaftRuntimeHandle {
    pub fn signal_shutdown(&self) {
        self.runtime.begin_shutdown();
    }

    pub async fn shutdown(mut self) {
        self.signal_shutdown();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl RaftRuntime {
    pub fn new(
        state: AppState,
        role: Arc<Mutex<RoleState>>,
        election: ElectionController,
        heartbeat_interval: Duration,
        peer_suspect_after: Duration,
        peer_down_after: Duration,
    ) -> Arc<Self> {
        let leadership_epoch = state.leadership_epoch.clone();
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
            leadership_epoch,
        })
    }

    pub fn spawn(self: &Arc<Self>) -> RaftRuntimeHandle {
        let heartbeat = tokio::spawn(Self::heartbeat_loop(self.clone()));
        let election = tokio::spawn(Self::election_loop(self.clone()));
        RaftRuntimeHandle {
            runtime: self.clone(),
            tasks: vec![heartbeat, election],
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.leadership_epoch.load(Ordering::SeqCst)
    }

    fn bump_leadership_epoch(&self) {
        self.leadership_epoch.fetch_add(1, Ordering::SeqCst);
    }

    fn mark_not_leader(&self) {
        self.bump_leadership_epoch();
    }

    pub fn begin_shutdown(&self) {
        let already_set = self.shutdown.swap(true, Ordering::SeqCst);
        self.mark_not_leader();
        self.notify.notify_waiters();
        if !already_set {
            for peer in self.state.peers.iter() {
                peer.force_disconnect();
            }
        }
    }

    pub fn is_leader(&self) -> bool {
        matches!(self.role.lock().role, RaftRole::Leader)
    }

    pub fn leader_id(&self) -> Option<String> {
        self.role.lock().leader_id.clone()
    }

    pub fn current_term(&self) -> u64 {
        self.state.current_term.load(Ordering::SeqCst)
    }

    pub fn wake(&self) {
        self.notify.notify_waiters();
    }

    pub async fn replicate_from(&self, start_index: u64) -> Result<(), String> {
        if !self.is_leader() {
            return Err("not leader".into());
        }
        let commit_index = self.state.last_quorum_fsynced.load(Ordering::SeqCst);
        let leader_epoch = self.current_epoch();
        match replicate_to_peers(
            self.state.clone(),
            start_index,
            commit_index,
            leader_epoch,
            self.shutdown.clone(),
            self.peer_suspect_after,
            self.peer_down_after,
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(ReplicationError::LeadershipLost) => Err("leadership changed".into()),
            Err(ReplicationError::Failure(err)) => Err(err),
        }
    }

    pub fn handle_request_vote(&self, request: RequestVoteRequest) -> RequestVoteResponse {
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
            let was_leader = matches!(role.role, RaftRole::Leader | RaftRole::Candidate);
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
            if was_leader {
                self.mark_not_leader();
            }
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

    pub fn handle_append_entries(&self, request: AppendEntriesRequest) -> AppendEntriesResponse {
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
            let was_leader = matches!(role.role, RaftRole::Leader | RaftRole::Candidate);
            if role.leader_id.as_ref() != Some(&request.leader_id) {
                info!(
                    "node {} now follows leader {} (term={})",
                    self.node_id, request.leader_id, request.term
                );
            }
            role.term = request.term;
            role.role = RaftRole::Follower;
            role.leader_id = Some(request.leader_id.clone());
            if was_leader {
                self.mark_not_leader();
            }
        }
        self.schedule_timeout(now);

        let mut log = self.state.log.lock();
        let mut processor = AppendEntriesProcessor::new(&mut log);
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
                    let mut buffer = Vec::new();
                    log.copy_entries_in_range(start, commit_index, &mut buffer);
                    buffer
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
        let was_leader = matches!(role.role, RaftRole::Leader | RaftRole::Candidate);
        role.term = term;
        role.voted_for = None;
        role.role = RaftRole::Follower;
        role.leader_id = None;
        if was_leader {
            self.mark_not_leader();
        }
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
            routing: default_routing(),
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

    async fn dispatch_request_vote(&self, request: RequestVoteRequest) -> (usize, u64) {
        let peer_count = self.state.peers.len();
        if peer_count == 0 {
            return (0, request.term);
        }
        let required = (peer_count + 1).div_ceil(2);
        let mut join_set = JoinSet::new();
        for peer in self.state.peers.iter().cloned() {
            let req = request.clone();
            join_set.spawn(async move { peer.client.request_vote(req, Instant::now()).await });
        }

        let mut highest_term = request.term;
        let mut granted = 0usize;
        let mut remaining = peer_count;
        while let Some(result) = join_set.join_next().await {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }
            match result {
                Ok(Ok(response)) => {
                    remaining -= 1;
                    highest_term = highest_term.max(response.term);
                    if response.granted {
                        granted += 1;
                    }
                    self.vote_failure_logged.store(false, Ordering::SeqCst);
                    if granted >= required || granted + remaining < required {
                        break;
                    }
                }
                Ok(Err(err)) => {
                    remaining -= 1;
                    self.log_request_vote_error(&err.to_string());
                    if granted + remaining < required {
                        break;
                    }
                }
                Err(err) => {
                    remaining -= 1;
                    self.log_request_vote_error(&err.to_string());
                    if granted + remaining < required {
                        break;
                    }
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
        self.bump_leadership_epoch();
        info!("node {} became leader for term {}", self.node_id, term);
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
        if !self.vote_failure_logged.swap(true, Ordering::SeqCst) {
            warn!(
                "node {} unable to reach peer for RequestVote: {} (further failures will be debug-level)",
                self.node_id, message
            );
        } else {
            debug!("node {} RequestVote retry failed: {}", self.node_id, message);
        }
    }
}

pub struct MiniClusterRaftHandler {
    runtime: Arc<RaftRuntime>,
}

impl MiniClusterRaftHandler {
    pub fn new(runtime: Arc<RaftRuntime>) -> Self {
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

pub enum ReplicationError {
    Failure(String),
    LeadershipLost,
}

enum PeerTaskResult {
    Success,
    Failed(String),
    Cancelled,
}

pub async fn replicate_to_peers(
    state: AppState,
    start_index: u64,
    leader_commit: u64,
    leader_epoch: u64,
    shutdown: Arc<AtomicBool>,
    _peer_suspect_after: Duration,
    peer_down_after: Duration,
) -> Result<(), ReplicationError> {
    if start_index == 0 {
        debug!("nothing to replicate (start_index=0)");
        return Ok(());
    }
    let has_entries = {
        let log = state.log.lock();
        log.last_index() >= start_index
    };
    if state.leadership_epoch.load(Ordering::SeqCst) != leader_epoch {
        return Err(ReplicationError::LeadershipLost);
    }
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

    if !has_entries {
        for peer in state.peers.iter().cloned() {
            let state_clone = state.clone();
            let epoch = leader_epoch;
            let shutdown_flag = shutdown.clone();
            tokio::spawn(async move {
                let _ = send_to_peer(
                    &state_clone,
                    peer,
                    start_index,
                    leader_commit,
                    epoch,
                    shutdown_flag,
                    peer_down_after,
                )
                .await;
            });
        }
        return Ok(());
    }

    let required = (state.peers.len() + 1) / 2;
    if required == 0 {
        return Ok(());
    }

    let mut join_set = tokio::task::JoinSet::new();
    for peer in state.peers.iter().cloned() {
        let state_clone = state.clone();
        let commit_index = leader_commit;
        let epoch = leader_epoch;
        let shutdown_flag = shutdown.clone();
        join_set.spawn(async move {
            send_to_peer(
                &state_clone,
                peer,
                start_index,
                commit_index,
                epoch,
                shutdown_flag,
                peer_down_after,
            )
            .await
        });
    }

    let mut successes = 0usize;
    let mut remaining = state.peers.len();
    let mut first_err: Option<String> = None;
    while let Some(result) = join_set.join_next().await {
        if shutdown.load(Ordering::SeqCst) {
            return Err(ReplicationError::LeadershipLost);
        }
        match result {
            Ok(PeerTaskResult::Success) => {
                remaining -= 1;
                successes += 1;
                if successes >= required {
                    info!(
                        "node {} replicated log index {} to quorum ({} acks)",
                        state.node_id,
                        start_index,
                        successes + 1
                    );
                    return Ok(());
                }
            }
            Ok(PeerTaskResult::Failed(err)) => {
                remaining -= 1;
                debug!("replication task error: {err}");
                if first_err.is_none() {
                    first_err = Some(err);
                }
                if successes + remaining < required {
                    break;
                }
            }
            Ok(PeerTaskResult::Cancelled) => {
                return Err(ReplicationError::LeadershipLost);
            }
            Err(err) => {
                remaining -= 1;
                let message = format!("replication task join error: {err}");
                debug!("{message}");
                if first_err.is_none() {
                    first_err = Some(message);
                }
                if successes + remaining < required {
                    break;
                }
            }
        }
    }
    Err(ReplicationError::Failure(
        first_err.unwrap_or_else(|| "quorum not achieved".into()),
    ))
}

async fn send_to_peer(
    state: &AppState,
    peer: PeerInfo,
    start_index: u64,
    leader_commit: u64,
    leader_epoch: u64,
    shutdown: Arc<AtomicBool>,
    peer_down_after: Duration,
) -> PeerTaskResult {
    if state.leadership_epoch.load(Ordering::SeqCst) != leader_epoch {
        return PeerTaskResult::Cancelled;
    }
    debug!(
        "node {} preparing replication to peer {} @ {}:{} (start_index={})",
        state.node_id, peer.id, peer.host, peer.port, start_index
    );
    let leadership_epoch_ref = state.leadership_epoch.clone();
    let shutdown_flag = shutdown.clone();
    let mut next_index = start_index;
    let mut attempts = 0usize;
    let cancel_check = move || {
        shutdown_flag.load(Ordering::SeqCst)
            || leadership_epoch_ref.load(Ordering::SeqCst) != leader_epoch
    };

    while attempts < 64 {
        attempts += 1;
        if state.leadership_epoch.load(Ordering::SeqCst) != leader_epoch {
            return PeerTaskResult::Cancelled;
        }
        let (prev_log_index, prev_log_term, entries, log_tail) = {
            let log = state.log.lock();
            let prev_index = next_index.saturating_sub(1);
            let prev_term = if prev_index == 0 {
                0
            } else {
                log.term_at(prev_index).unwrap_or(0)
            };
            let entries = log.entries_from(next_index);
            let tail = log.last_index();
            (prev_index, prev_term, entries, tail)
        };
        let commit_index = leader_commit.min(log_tail);

        let request_term = state.current_term.load(Ordering::SeqCst);
        let request = AppendEntriesRequest {
            term: request_term,
            leader_id: state.node_id.clone(),
            prev_log_index,
            prev_log_term,
            leader_commit: commit_index,
            entries,
            routing: default_routing(),
        };
        let heartbeat = request.entries.is_empty();
        let last_entry_index = request
            .entries
            .last()
            .map(|entry| entry.index)
            .unwrap_or(next_index);
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
        let response = match peer
            .client
            .append_entries_with_abort(request, Instant::now(), cancel_check.clone())
            .await
        {
            Ok(resp) => {
                if state.leadership_epoch.load(Ordering::SeqCst) == leader_epoch {
                    peer.health
                        .record_success(&state.node_id, &peer.id, Instant::now());
                }
                resp
            }
            Err(err) => {
                if state.leadership_epoch.load(Ordering::SeqCst) != leader_epoch {
                    return PeerTaskResult::Cancelled;
                }
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
                    peer_down_after,
                );
                return PeerTaskResult::Failed(format!("peer {} error: {message}", peer.id));
            }
        };
        if state.leadership_epoch.load(Ordering::SeqCst) != leader_epoch {
            return PeerTaskResult::Cancelled;
        }
        if response.success {
            state.record_peer_ack(&peer.id, request_term, response.match_index);
            if !heartbeat {
                debug!(
                    "node {} replicated entries [{}..={}] to peer {}",
                    state.node_id, next_index, last_entry_index, peer.id
                );
            }
            trace!(
                "node {} completed Raft RPC to peer {}",
                state.node_id, peer.id
            );
            return PeerTaskResult::Success;
        }

        let conflict_index = response
            .conflict_index
            .unwrap_or(prev_log_index.saturating_sub(1))
            .max(1);
        let backoff = if conflict_index < next_index {
            conflict_index
        } else {
            next_index.saturating_sub(1).max(1)
        };
        debug!(
            "node {} replication to peer {} rejected (conflict_index={:?}, conflict_term={:?}); retrying from index {}",
            state.node_id,
            peer.id,
            response.conflict_index,
            response.conflict_term,
            backoff
        );
        if backoff == next_index {
            return PeerTaskResult::Failed(format!(
                "append rejected and unable to back off further (conflict_index={:?}, conflict_term={:?})",
                response.conflict_index, response.conflict_term
            ));
        }
        next_index = backoff;
    }

    PeerTaskResult::Failed("append rejected after too many retries".into())
}

pub fn new_role_state(
    current_term: u64,
    election_controller: &mut ElectionController,
    node_id: &str,
) -> Arc<Mutex<RoleState>> {
    let initial_timeout = election_controller.next_election_timeout(node_id.to_string());
    Arc::new(Mutex::new(RoleState::new(
        current_term,
        Instant::now(),
        initial_timeout,
    )))
}

pub fn new_election_controller() -> ElectionController {
    ElectionController::new(ElectionProfile::Latency, rand::thread_rng().gen())
}

pub fn new_durability_ledger(peers: &[PeerInfo], node_id: &str) -> clustor::durability::DurabilityLedger {
    let mut durability_ledger =
        clustor::durability::DurabilityLedger::new(PartitionQuorumConfig::new(peers.len() + 1));
    durability_ledger.register_replica(node_id.to_string());
    for peer in peers {
        durability_ledger.register_replica(peer.id.clone());
    }
    durability_ledger
}

pub fn default_routing() -> RaftRouting {
    // Mini-cluster runs a single placement group, so keep a static routing epoch.
    RaftRouting::alias("mini-cluster", 1)
}
