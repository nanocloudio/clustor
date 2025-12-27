use clustor::replication::membership::{
    CatchUpDecision, CatchUpReason, LearnerCatchUpConfig, LearnerCatchUpEvaluator,
};
use std::time::{Duration, Instant};

#[test]
fn detects_index_gap() {
    let mut evaluator = LearnerCatchUpEvaluator::new(LearnerCatchUpConfig::default());
    let now = Instant::now();
    evaluator.record_progress(10, 1024, now);
    let decision = evaluator.evaluate(11_500, 1024, now + Duration::from_millis(10));
    assert!(matches!(
        decision,
        CatchUpDecision::Lagging {
            reason: CatchUpReason::IndexGap { .. }
        }
    ));
}

#[test]
fn detects_idle_timeout() {
    let mut evaluator = LearnerCatchUpEvaluator::new(LearnerCatchUpConfig {
        max_index_slack: 100,
        max_byte_slack: 1024,
        max_idle_ms: 100,
    });
    let now = Instant::now();
    evaluator.record_progress(10, 10, now);
    let decision = evaluator.evaluate(50, 10, now + Duration::from_millis(200));
    assert!(matches!(
        decision,
        CatchUpDecision::Lagging {
            reason: CatchUpReason::IdleTimeout { .. }
        }
    ));
}
