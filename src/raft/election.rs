use crate::profile::PartitionProfile;
use crate::raft::rpc::PreVoteResponse;
use crate::raft::{PartitionQuorum, ReplicaId};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const HEARTBEAT_INTERVAL_MS: u64 = 50;
const HIGH_RTT_CONFIRMATIONS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectionProfile {
    Latency,
    Throughput,
    ControlPlane,
    Wan,
}

impl From<PartitionProfile> for ElectionProfile {
    fn from(profile: PartitionProfile) -> Self {
        match profile {
            PartitionProfile::Wan => ElectionProfile::Wan,
            PartitionProfile::Throughput => ElectionProfile::Throughput,
            PartitionProfile::Latency | PartitionProfile::Zfs => ElectionProfile::Latency,
        }
    }
}

impl ElectionProfile {
    pub fn election_window(&self) -> (Duration, Duration) {
        match self {
            ElectionProfile::Latency
            | ElectionProfile::Throughput
            | ElectionProfile::ControlPlane => {
                (Duration::from_millis(150), Duration::from_millis(300))
            }
            ElectionProfile::Wan => (Duration::from_millis(300), Duration::from_millis(600)),
        }
    }

    pub fn high_rtt_threshold_ms(&self) -> u64 {
        match self {
            ElectionProfile::Latency
            | ElectionProfile::Throughput
            | ElectionProfile::ControlPlane => 150,
            ElectionProfile::Wan => 350,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct LatencyState {
    consecutive_high: u32,
    wan_override_next: bool,
    last_rtt_ms: Option<u64>,
}

impl LatencyState {
    fn record_rtt(
        &mut self,
        rtt_ms: u64,
        threshold_ms: u64,
        required_confirmations: u32,
    ) -> HighRttState {
        self.last_rtt_ms = Some(rtt_ms);
        if rtt_ms >= threshold_ms {
            self.consecutive_high = self.consecutive_high.saturating_add(1);
            if self.consecutive_high >= required_confirmations {
                self.wan_override_next = true;
                return HighRttState::Widened;
            }
            HighRttState::Warning
        } else {
            self.consecutive_high = 0;
            self.wan_override_next = false;
            HighRttState::Healthy
        }
    }

    fn take_wan_override(&mut self) -> bool {
        if self.wan_override_next {
            self.wan_override_next = false;
            true
        } else {
            false
        }
    }

    fn force_wan_override(&mut self) {
        self.wan_override_next = true;
    }
}

#[derive(Debug, Clone)]
pub struct ElectionController {
    profile: ElectionProfile,
    rng: ChaCha20Rng,
    latency: HashMap<ReplicaId, LatencyState>,
}

impl ElectionController {
    pub fn for_partition_profile(profile: PartitionProfile, seed: u64) -> Self {
        Self::new(profile.into(), seed)
    }

    pub fn new(profile: ElectionProfile, seed: u64) -> Self {
        Self {
            profile,
            rng: ChaCha20Rng::seed_from_u64(seed),
            latency: HashMap::new(),
        }
    }

    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(HEARTBEAT_INTERVAL_MS)
    }

    pub fn record_heartbeat_rtt(
        &mut self,
        replica: impl Into<ReplicaId>,
        rtt_ms: u64,
    ) -> HighRttState {
        let threshold = self.profile.high_rtt_threshold_ms();
        let state = self.latency.entry(replica.into()).or_default();
        state.record_rtt(rtt_ms, threshold, HIGH_RTT_CONFIRMATIONS)
    }

    pub fn next_election_timeout(&mut self, replica: impl Into<ReplicaId>) -> Duration {
        let replica = replica.into();
        let state = self.latency.entry(replica).or_default();
        let window = if state.take_wan_override() {
            ElectionProfile::Wan.election_window()
        } else {
            self.profile.election_window()
        };
        random_between(&mut self.rng, window.0, window.1)
    }

    pub fn evaluate_pre_vote(
        &self,
        quorum: &PartitionQuorum,
        candidate_term: u64,
        candidate_index: u64,
    ) -> PreVoteDecision {
        if quorum.is_candidate_up_to_date(candidate_term, candidate_index) {
            PreVoteDecision::Granted
        } else {
            PreVoteDecision::Rejected(PreVoteRejectReason::LogBehind)
        }
    }

    pub fn apply_pre_vote_response(
        &mut self,
        replica: impl Into<ReplicaId>,
        response: &PreVoteResponse,
    ) {
        if response.high_rtt.unwrap_or(false) {
            self.latency
                .entry(replica.into())
                .or_default()
                .force_wan_override();
        }
    }

    /// Helper for tests/state machines to construct a `CandidateState` with a randomized timeout.
    pub fn spawn_candidate(
        &mut self,
        candidate_id: impl Into<ReplicaId>,
        term: u64,
        now: Instant,
    ) -> CandidateState {
        let candidate_id = candidate_id.into();
        let timeout = self.next_election_timeout(candidate_id.clone());
        CandidateState::new(candidate_id, term, timeout, now)
    }
}

fn random_between(rng: &mut ChaCha20Rng, min: Duration, max: Duration) -> Duration {
    assert!(max >= min);
    if max == min {
        return min;
    }
    let delta = max - min;
    let jitter = rng.gen_range(0..=delta.as_millis() as u64);
    min + Duration::from_millis(jitter)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighRttState {
    Healthy,
    Warning,
    Widened,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreVoteDecision {
    Granted,
    Rejected(PreVoteRejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreVoteRejectReason {
    LogBehind,
}

#[derive(Debug, Clone)]
pub struct ElectionTimer {
    timeout: Duration,
    deadline: Instant,
}

impl ElectionTimer {
    pub fn new(now: Instant, timeout: Duration) -> Self {
        Self {
            timeout,
            deadline: now + timeout,
        }
    }

    pub fn reset(&mut self, now: Instant, timeout: Duration) {
        self.timeout = timeout;
        self.deadline = now + timeout;
    }

    pub fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

#[derive(Debug, Clone)]
pub struct CandidateState {
    candidate_id: ReplicaId,
    term: u64,
    granted: HashSet<ReplicaId>,
    rejected: HashSet<ReplicaId>,
    timer: ElectionTimer,
}

impl CandidateState {
    pub fn new(
        candidate_id: impl Into<ReplicaId>,
        term: u64,
        timeout: Duration,
        now: Instant,
    ) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            term,
            granted: HashSet::new(),
            rejected: HashSet::new(),
            timer: ElectionTimer::new(now, timeout),
        }
    }

    pub fn candidate_id(&self) -> &ReplicaId {
        &self.candidate_id
    }

    pub fn term(&self) -> u64 {
        self.term
    }

    pub fn record_vote(&mut self, voter: impl Into<ReplicaId>, granted: bool) {
        let voter = voter.into();
        if granted {
            self.granted.insert(voter.clone());
            self.rejected.remove(&voter);
        } else {
            self.rejected.insert(voter.clone());
            self.granted.remove(&voter);
        }
    }

    pub fn votes_granted(&self) -> usize {
        self.granted.len()
    }

    pub fn votes_rejected(&self) -> usize {
        self.rejected.len()
    }

    pub fn quorum_reached(&self, quorum: usize) -> bool {
        self.granted.len() >= quorum
    }

    pub fn timer(&self) -> &ElectionTimer {
        &self.timer
    }

    pub fn timer_mut(&mut self) -> &mut ElectionTimer {
        &mut self.timer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::{
        LeaderStickinessConfig, LeaderStickinessGate, PartitionQuorum, PartitionQuorumConfig,
        StickinessDecision,
    };

    #[test]
    fn election_timeout_respects_profile_range() {
        let mut controller = ElectionController::new(ElectionProfile::Latency, 42);
        controller.record_heartbeat_rtt("a", 20);
        for _ in 0..10 {
            let timeout = controller.next_election_timeout("a");
            assert!(timeout >= Duration::from_millis(150) && timeout <= Duration::from_millis(300));
        }
    }

    #[test]
    fn high_rtt_widens_timeout_once() {
        let mut controller = ElectionController::new(ElectionProfile::Latency, 7);
        for _ in 0..HIGH_RTT_CONFIRMATIONS {
            let state = controller.record_heartbeat_rtt("a", 200);
            assert_ne!(state, HighRttState::Healthy);
        }
        let widened = controller.next_election_timeout("a");
        assert!(widened >= Duration::from_millis(300));
        let reset = controller.next_election_timeout("a");
        assert!(reset < Duration::from_millis(300));
    }

    #[test]
    fn pre_vote_requires_up_to_date_log() {
        let mut quorum = PartitionQuorum::new(PartitionQuorumConfig::new(3));
        for id in ["a", "b", "c"] {
            quorum.register_replica(id);
            quorum.record_match(id, 3, 30).unwrap();
        }
        let controller = ElectionController::new(ElectionProfile::Latency, 9);
        let decision = controller.evaluate_pre_vote(&quorum, 4, 10);
        assert!(matches!(decision, PreVoteDecision::Granted));
        let decision = controller.evaluate_pre_vote(&quorum, 2, 100);
        assert!(matches!(
            decision,
            PreVoteDecision::Rejected(PreVoteRejectReason::LogBehind)
        ));
    }

    #[test]
    fn candidate_state_tracks_votes_and_timeouts() {
        let now = Instant::now();
        let mut candidate = CandidateState::new("leader", 4, Duration::from_millis(200), now);
        candidate.record_vote("f1", true);
        candidate.record_vote("f2", false);
        assert_eq!(candidate.votes_granted(), 1);
        assert_eq!(candidate.votes_rejected(), 1);
        assert!(!candidate.quorum_reached(2));
        candidate.record_vote("f2", true);
        assert_eq!(candidate.votes_granted(), 2);
        assert_eq!(candidate.votes_rejected(), 0);
        assert!(candidate.quorum_reached(2));
        assert!(!candidate.timer().expired(now));
        assert!(
            candidate.timer().remaining(now + Duration::from_millis(50))
                <= Duration::from_millis(150)
        );
        assert!(candidate.timer().expired(now + Duration::from_millis(250)));
    }

    #[test]
    fn partition_profiles_map_to_election_profiles() {
        let mut wan = ElectionController::for_partition_profile(PartitionProfile::Wan, 5);
        for _ in 0..3 {
            let timeout = wan.next_election_timeout("wan");
            assert!(
                timeout >= Duration::from_millis(300) && timeout <= Duration::from_millis(600),
                "WAN timeout {timeout:?} outside expected window"
            );
        }
        let mut zfs = ElectionController::for_partition_profile(PartitionProfile::Zfs, 7);
        for _ in 0..3 {
            let timeout = zfs.next_election_timeout("zfs");
            assert!(
                timeout >= Duration::from_millis(150) && timeout <= Duration::from_millis(300),
                "ZFS timeout {timeout:?} outside latency window"
            );
        }
    }

    #[test]
    fn prevote_high_rtt_forces_wan_window_once() {
        let mut controller = ElectionController::new(ElectionProfile::Latency, 3);
        let response = PreVoteResponse {
            term: 10,
            vote_granted: true,
            high_rtt: Some(true),
        };
        controller.apply_pre_vote_response("peer-1", &response);
        let widened = controller.next_election_timeout("peer-1");
        assert!(
            widened >= Duration::from_millis(300),
            "expected WAN window, got {widened:?}"
        );
        let reset = controller.next_election_timeout("peer-1");
        assert!(
            reset < Duration::from_millis(300),
            "WAN override should last one timeout"
        );
    }

    #[test]
    fn high_rtt_and_stickiness_checkpoint() {
        let mut controller = ElectionController::new(ElectionProfile::Latency, 17);
        for _ in 0..HIGH_RTT_CONFIRMATIONS {
            controller.record_heartbeat_rtt("follower-a", 250);
        }
        let widened = controller.next_election_timeout("follower-a");
        assert!(widened >= Duration::from_millis(300));
        let base = Instant::now();
        let mut gate = LeaderStickinessGate::new(LeaderStickinessConfig::default(), base);
        let mut decision = StickinessDecision::Maintain;
        for offset in 0..3 {
            decision = gate.record_fsync_sample(
                Duration::from_millis(32),
                base + Duration::from_millis(offset),
            );
        }
        assert!(matches!(
            decision,
            StickinessDecision::PendingStepDown { .. }
        ));
        let later = base + Duration::from_millis(1000);
        decision = gate.record_fsync_sample(Duration::from_millis(30), later);
        assert!(matches!(
            decision,
            StickinessDecision::StepDownRequired { .. }
        ));
    }
}
