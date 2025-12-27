use clustor::profile::PartitionProfile;
use clustor::replication::raft::{
    CandidateState, ElectionController, ElectionProfile, HighRttState, LeaderStickinessConfig,
    LeaderStickinessGate, PartitionQuorum, PartitionQuorumConfig, PreVoteDecision,
    PreVoteRejectReason, PreVoteResponse, StickinessDecision,
};
use std::time::{Duration, Instant};

const HIGH_RTT_CONFIRMATIONS: u32 = 3;

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
        candidate.timer().remaining(now + Duration::from_millis(50)) <= Duration::from_millis(150)
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
