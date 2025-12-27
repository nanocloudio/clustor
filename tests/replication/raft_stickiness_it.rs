use clustor::durability::IoMode;
use clustor::replication::raft::stickiness::{
    LeaderStickinessConfig, LeaderStickinessController, LeaderStickinessGate, StickinessDecision,
};
use std::time::{Duration, Instant};

#[test]
fn stickiness_step_down_requires_min_term() {
    let base = Instant::now();
    let mut controller = LeaderStickinessController::new(LeaderStickinessConfig::default(), base);
    let now = base;
    let first = controller.record_fsync_sample(Duration::from_millis(30), now);
    assert!(matches!(first, StickinessDecision::Maintain));
    let second =
        controller.record_fsync_sample(Duration::from_millis(30), now + Duration::from_millis(1));
    assert!(matches!(second, StickinessDecision::Maintain));
    let third =
        controller.record_fsync_sample(Duration::from_millis(30), now + Duration::from_millis(2));
    assert!(matches!(third, StickinessDecision::PendingStepDown { .. }));

    let later = now + Duration::from_millis(1_000);
    let decision = controller.record_fsync_sample(Duration::from_millis(25), later);
    assert!(matches!(
        decision,
        StickinessDecision::StepDownRequired { .. }
    ));
}

#[test]
fn stickiness_recovers_after_low_samples() {
    let base = Instant::now();
    let mut controller = LeaderStickinessController::new(LeaderStickinessConfig::default(), base);
    let start = base + Duration::from_millis(800);
    for i in 0..3 {
        controller.record_fsync_sample(Duration::from_millis(30), start + Duration::from_millis(i));
    }
    for i in 0..5 {
        let decision = controller.record_fsync_sample(
            Duration::from_millis(5),
            start + Duration::from_millis(100 + i as u64),
        );
        if i < 4 {
            assert!(matches!(
                decision,
                StickinessDecision::StepDownRequired { .. }
            ));
        } else {
            assert!(matches!(decision, StickinessDecision::Maintain));
        }
    }
}

#[test]
fn stickiness_gate_forces_strict_mode_when_degraded() {
    let now = Instant::now();
    let mut gate = LeaderStickinessGate::new(LeaderStickinessConfig::default(), now);
    for offset in 0..3 {
        gate.record_fsync_sample(
            Duration::from_millis(30),
            now + Duration::from_millis(offset),
        );
    }
    assert!(gate.degraded());
    assert!(matches!(
        gate.record_fsync_sample(Duration::from_millis(30), now + Duration::from_millis(10)),
        StickinessDecision::PendingStepDown { .. }
    ));
    assert!(matches!(gate.enforce_mode(IoMode::Group), IoMode::Strict));
}

#[test]
fn stickiness_gate_releases_after_recovery() {
    let now = Instant::now();
    let mut gate = LeaderStickinessGate::new(LeaderStickinessConfig::default(), now);
    for offset in 0..3 {
        gate.record_fsync_sample(
            Duration::from_millis(30),
            now + Duration::from_millis(offset),
        );
    }
    assert!(gate.degraded());
    gate.record_fsync_sample(Duration::from_millis(5), now + Duration::from_millis(100));
    for offset in 0..5 {
        gate.record_fsync_sample(
            Duration::from_millis(5),
            now + Duration::from_millis(150 + offset),
        );
    }
    assert!(!gate.degraded());
    assert!(matches!(gate.enforce_mode(IoMode::Group), IoMode::Group));
}
