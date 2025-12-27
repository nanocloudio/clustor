use clustor::apply::{
    AckHandlePolicy, AckHandleSupervisor, ApplyBatch, ApplyBudgetDecision, ApplyEntry,
    ApplyProfile, ApplyRuntime, ApplyScheduler, DedupeCache, DedupeConfig, DedupeToken,
    InMemoryAckHandleMetrics, InMemoryApplyMetrics,
};
use clustor::durability::AckHandle;
use clustor::profile::{PartitionProfile, ProfileCapabilityRegistry};
use std::time::{Duration, Instant};

#[test]
fn apply_checkpoint_budget_backoff_degrades() {
    let profile = ApplyProfile {
        max_batch_ns: 100,
        budget_breach_threshold: 2,
        p99_window: 4,
        ..ApplyProfile::default()
    };
    let metrics = clustor::apply::InMemoryApplyMetrics::default();
    let mut scheduler = ApplyScheduler::new(profile, metrics).unwrap();
    let mut now = Instant::now();
    for ns in [200, 250, 90] {
        scheduler.record_duration(Duration::from_nanos(ns), now);
        now += Duration::from_millis(5);
    }
    let decision = scheduler.record_duration(Duration::from_nanos(220), now);
    assert!(matches!(decision, ApplyBudgetDecision::Degraded { .. }));
}

#[test]
fn apply_checkpoint_ack_handle_timeouts_surface_retryable() {
    let metrics = InMemoryAckHandleMetrics::default();
    let supervisor = AckHandleSupervisor::new(
        AckHandlePolicy {
            max_defer_ms: 1,
            drop_window_ms: 1_000,
            max_consecutive_drops: 3,
            aggregator: false,
        },
        metrics.clone(),
    );
    let handle = supervisor.register(AckHandle::new(1, 1, 2), Instant::now());
    let timeouts = supervisor.tick(Instant::now() + Duration::from_millis(5));
    assert_eq!(timeouts.len(), 1);
    drop(handle);
    assert_eq!(metrics.snapshot().timeouts, 1);
}

#[test]
fn apply_runtime_ack_deadlines_enforced() {
    let profile = ApplyProfile {
        ack_max_defer_ms: 1,
        ..ApplyProfile::default()
    };
    let ack_metrics = InMemoryAckHandleMetrics::default();
    let runtime = ApplyRuntime::new(
        profile,
        InMemoryApplyMetrics::default(),
        ack_metrics.clone(),
    )
    .unwrap();
    let handle = runtime.register_ack_handle(AckHandle::new(1, 1, 2), Instant::now());
    let expired = runtime.tick_ack_deadlines(Instant::now() + Duration::from_millis(5));
    assert_eq!(expired.len(), 1);
    drop(handle);
    assert_eq!(ack_metrics.snapshot().timeouts, 1);
    assert_eq!(runtime.ack_policy().max_defer_ms, 1);
}

#[test]
fn apply_checkpoint_dedupe_cache_replay_prevents_duplicates() {
    let mut cache = DedupeCache::new(DedupeConfig {
        max_entries: 3,
        max_bytes: 64,
    });
    let token = DedupeToken { term: 5, index: 42 };
    assert!(cache.insert(token, 16));
    assert!(cache.contains(&token));
    let snapshot = cache.snapshot();
    let mut replay_cache = DedupeCache::new(DedupeConfig::default());
    replay_cache.replay(snapshot);
    assert!(
        !replay_cache.insert(token, 16),
        "duplicate should be ignored"
    );
}

#[test]
fn apply_checkpoint_queue_backpressure() {
    let profile = ApplyProfile {
        handoff_queue_len: 2,
        ..ApplyProfile::default()
    };
    let metrics = clustor::apply::InMemoryApplyMetrics::default();
    let mut scheduler = ApplyScheduler::new(profile, metrics).unwrap();
    scheduler
        .enqueue(ApplyBatch::new(vec![ApplyEntry { term: 1, index: 1 }]))
        .unwrap();
    scheduler
        .enqueue(ApplyBatch::new(vec![ApplyEntry { term: 1, index: 2 }]))
        .unwrap();
    let overflow = scheduler.enqueue(ApplyBatch::new(vec![ApplyEntry { term: 1, index: 3 }]));
    assert!(overflow.is_err());
}

#[test]
fn apply_checkpoint_aggregator_profile_reports_guardrails() {
    let registry = ProfileCapabilityRegistry::default();
    let profile = ApplyProfile::aggregator(&registry, PartitionProfile::Latency).unwrap();
    let metrics = clustor::apply::InMemoryApplyMetrics::default();
    let mut scheduler = ApplyScheduler::new(profile, metrics.clone()).unwrap();
    let mut now = Instant::now();
    for _ in 0..6 {
        scheduler.record_duration(Duration::from_micros(7_000), now);
        now += Duration::from_millis(10);
    }
    let snapshot = metrics.snapshot();
    assert!(snapshot.aggregator_budget_breaches >= 6);
    assert!(snapshot.aggregator_guardrail_violations >= 1);
    assert!(scheduler.report().auto_demoted);
    let why = scheduler.why_apply("checkpoint-agg");
    assert!(why.guardrail_level >= 1.0);
    assert_eq!(why.profile.profile_name, "Aggregator");
}

#[test]
fn apply_checkpoint_aggregator_guardrail_levels_decay() {
    let registry = ProfileCapabilityRegistry::default();
    let profile = ApplyProfile::aggregator(&registry, PartitionProfile::Latency).unwrap();
    let mut scheduler =
        ApplyScheduler::new(profile, clustor::apply::InMemoryApplyMetrics::default()).unwrap();
    let mut now = Instant::now();
    for _ in 0..5 {
        scheduler.record_duration(Duration::from_micros(7_000), now);
        now += Duration::from_millis(10);
    }
    let initial = scheduler.why_apply("initial");
    assert!(initial.guardrail_level >= 1.0);
    scheduler.record_duration(Duration::from_nanos(500), now + Duration::from_secs(1));
    let later = scheduler.why_apply("later");
    assert!(later.guardrail_level < initial.guardrail_level);
}

#[test]
fn apply_checkpoint_aggregator_profile_stress() {
    let registry = ProfileCapabilityRegistry::default();
    let profile = ApplyProfile::aggregator(&registry, PartitionProfile::Latency).unwrap();
    let metrics = clustor::apply::InMemoryApplyMetrics::default();
    let mut scheduler = ApplyScheduler::new(profile, metrics.clone()).unwrap();
    let mut now = Instant::now();
    for idx in 0..20 {
        let duration = if idx % 3 == 0 {
            Duration::from_micros(8_000)
        } else {
            Duration::from_micros(2_000)
        };
        scheduler.record_duration(duration, now);
        now += Duration::from_millis(5);
    }
    let snapshot = metrics.snapshot();
    assert!(snapshot.guardrail_violations >= 1);
    let why = scheduler.why_apply("stress");
    assert!(why.guardrail_level >= 0.0);
    assert_eq!(why.profile.profile_name, "Aggregator");
}
