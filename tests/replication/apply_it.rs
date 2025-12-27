use clustor::durability::AckHandle;
use clustor::profile::{
    PartitionProfile, ProfileCapabilities, ProfileCapability, ProfileCapabilityError,
    ProfileCapabilityRegistry,
};
use clustor::replication::apply::{
    AckHandleFailureReason, AckHandleMetrics, AckHandlePolicy, AckHandleSupervisor, AckTimeoutInfo,
    ApplyBatch, ApplyBudgetDecision, ApplyEntry, ApplyMetrics, ApplyProfile, ApplyScheduler,
    ApplySchedulerError, DedupeCache, DedupeConfig, DedupeToken, InMemoryAckHandleMetrics,
    InMemoryApplyMetrics, ReplayGuard, TelemetryAckHandleMetrics, TelemetryApplyMetrics,
};
use clustor::telemetry::SharedMetricsRegistry;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[test]
fn enqueue_enforces_limits() {
    let mut scheduler =
        ApplyScheduler::new(ApplyProfile::default(), InMemoryApplyMetrics::default()).unwrap();
    let batch = ApplyBatch::new(vec![ApplyEntry { term: 1, index: 1 }; 16]);
    scheduler.enqueue(batch).unwrap();
    scheduler.dequeue().unwrap();
    let oversized = ApplyBatch::new(vec![ApplyEntry { term: 1, index: 2 }; 600]);
    assert!(matches!(
        scheduler.enqueue(oversized),
        Err(ApplySchedulerError::BatchTooLarge { .. })
    ));
}

#[test]
fn budget_decision_tracks_breaches() {
    let profile = ApplyProfile {
        max_batch_ns: 1_000,
        budget_breach_threshold: 2,
        p99_window: 5,
        ..ApplyProfile::default()
    };
    let mut scheduler = ApplyScheduler::new(profile, InMemoryApplyMetrics::default()).unwrap();
    let mut now = Instant::now();
    for duration_ns in [500, 800, 1200, 1300, 1400] {
        scheduler.record_duration(Duration::from_nanos(duration_ns), now);
        now += Duration::from_millis(10);
    }
    match scheduler.record_duration(Duration::from_nanos(1500), now) {
        ApplyBudgetDecision::Degraded {
            p99_ns,
            consecutive_breaches,
        } => {
            assert!(p99_ns >= 1300);
            assert!(consecutive_breaches >= 2);
        }
        other => panic!("expected degraded decision, got {:?}", other),
    }
}

#[test]
fn queue_alerts_emit_when_near_capacity() {
    let metrics = InMemoryApplyMetrics::default();
    let profile = ApplyProfile {
        handoff_queue_len: 4,
        ..ApplyProfile::default()
    };
    let mut scheduler = ApplyScheduler::new(profile, metrics).unwrap();
    for idx in 0..4 {
        let batch = ApplyBatch::new(vec![ApplyEntry {
            term: 1,
            index: idx,
        }]);
        if idx < 4 {
            let _ = scheduler.enqueue(batch);
        }
    }
    assert!(matches!(
        scheduler.enqueue(ApplyBatch::new(Vec::new())),
        Err(ApplySchedulerError::QueueFull { .. })
    ));
}

#[test]
fn dedupe_cache_enforces_limits_and_replay() {
    let mut cache = DedupeCache::new(DedupeConfig {
        max_entries: 2,
        max_bytes: 48,
    });
    let t1 = DedupeToken { term: 1, index: 10 };
    let t2 = DedupeToken { term: 1, index: 11 };
    let t3 = DedupeToken { term: 1, index: 12 };
    cache.insert(t1, 16);
    cache.insert(t2, 16);
    cache.insert(t3, 16);
    assert!(!cache.contains(&t1));
    cache.prune_below(12);
    assert!(!cache.contains(&t2));
    let snapshot = cache.snapshot();
    let mut replay_cache = DedupeCache::new(DedupeConfig::default());
    replay_cache.replay(snapshot);
    assert!(replay_cache.contains(&t3));
}

#[test]
fn aggregator_profile_requires_capability() {
    let registry = ProfileCapabilityRegistry::default();
    let profile = ApplyProfile::aggregator(&registry, PartitionProfile::Latency).unwrap();
    assert_eq!(profile.max_batch_ns, 6_000_000);
    assert!(profile.aggregator);
    let metrics = InMemoryApplyMetrics::default();
    let mut scheduler = ApplyScheduler::new(profile, metrics.clone()).unwrap();
    let mut now = Instant::now();
    for _ in 0..6 {
        scheduler.record_duration(Duration::from_micros(7_000), now);
        now += Duration::from_millis(10);
    }
    let snapshot = metrics.snapshot();
    assert!(snapshot.aggregator_budget_breaches >= 6);
    assert!(snapshot.aggregator_guardrail_violations >= 1);
    assert!(snapshot.guardrail_violations >= 1);
    let report = scheduler.report();
    assert!(report.auto_demoted);
    assert_eq!(report.max_ack_defer_ms, 750);
    let why = scheduler.why_apply("trace-agg");
    assert_eq!(why.profile.profile_name, "Aggregator");
    assert!(why.guardrail_level >= 1.0);

    let mut map = HashMap::new();
    map.insert(
        PartitionProfile::Throughput,
        ProfileCapabilities::new([ProfileCapability::Aggregator]),
    );
    let restricted = ProfileCapabilityRegistry::with_capabilities(map);
    assert!(matches!(
        ApplyProfile::aggregator(&restricted, PartitionProfile::Latency),
        Err(ProfileCapabilityError::CapabilityForbidden { .. })
    ));
}

#[test]
fn replay_guard_requires_target_index() {
    let mut guard = ReplayGuard::new(15);
    guard.record_apply(10);
    assert!(!guard.is_replay_complete());
    guard.record_apply(16);
    assert!(guard.is_replay_complete());
}

fn sample_ack_handle() -> AckHandle {
    AckHandle::new(1, 1, 2)
}

#[test]
fn ack_handle_times_out_when_deadline_reached() {
    let metrics = InMemoryAckHandleMetrics::default();
    let supervisor = AckHandleSupervisor::new(
        AckHandlePolicy {
            max_defer_ms: 1,
            drop_window_ms: 1000,
            max_consecutive_drops: 3,
            aggregator: false,
        },
        metrics.clone(),
    );
    let handle = supervisor.register(sample_ack_handle(), Instant::now());
    let timeouts = supervisor.tick(Instant::now() + Duration::from_millis(5));
    assert_eq!(timeouts.len(), 1);
    drop(handle);
    assert_eq!(metrics.snapshot().timeouts, 1);
}

#[test]
fn ack_handle_drop_triggers_alert_after_threshold() {
    let metrics = InMemoryAckHandleMetrics::default();
    let supervisor = AckHandleSupervisor::new(
        AckHandlePolicy {
            max_defer_ms: 10,
            drop_window_ms: 1_000,
            max_consecutive_drops: 1,
            aggregator: false,
        },
        metrics.clone(),
    );
    {
        let _handle = supervisor.register(sample_ack_handle(), Instant::now());
    }
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.drop_alerts, 1);
    assert_eq!(snapshot.last_failure, Some(AckHandleFailureReason::Dropped));
}

#[test]
fn ack_handle_guardrail_records_violation() {
    let metrics = InMemoryAckHandleMetrics::default();
    let supervisor = AckHandleSupervisor::new(AckHandlePolicy::aggregator(), metrics.clone());
    let _handle = supervisor.register(sample_ack_handle(), Instant::now());
    supervisor.tick(Instant::now() + Duration::from_millis(800));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.defer_guardrail_violations, 1);
}

#[test]
fn telemetry_apply_metrics_records_counters() {
    let registry = SharedMetricsRegistry::new("clustor");
    let metrics = TelemetryApplyMetrics::new(registry.clone(), true);
    metrics.record_queue_depth(7, 64);
    metrics.record_budget_sample(2_000, 3_000, 2);
    metrics.record_queue_alert();
    metrics.record_guardrail_violation();
    metrics.record_aggregator_budget_breach();
    metrics.record_aggregator_guardrail_violation();
    let snapshot = registry.snapshot().expect("apply metrics snapshot");
    assert_eq!(snapshot.gauges.get("clustor.apply.queue_depth"), Some(&7));
    assert_eq!(
        snapshot
            .gauges
            .get("clustor.apply.batch_budget_threshold_ns"),
        Some(&3_000)
    );
    assert_eq!(
        snapshot
            .counters
            .get("clustor.apply.guardrail_violation_total"),
        Some(&1)
    );
    assert_eq!(
        snapshot
            .counters
            .get("clustor.apply.aggregator_budget_breach_total"),
        Some(&1)
    );
    assert_eq!(
        snapshot
            .counters
            .get("clustor.apply.aggregator_samples_total"),
        Some(&1)
    );
}

#[test]
fn telemetry_ack_handle_metrics_records_counters() {
    let registry = SharedMetricsRegistry::new("clustor");
    let metrics = TelemetryAckHandleMetrics::new(registry.clone());
    metrics.record_completion(11);
    metrics.record_failure(12, &AckHandleFailureReason::Dropped);
    metrics.record_timeout(&AckTimeoutInfo {
        handle_id: 99,
        term: 5,
        index: 8,
    });
    metrics.record_drop_alert();
    metrics.record_defer_guardrail_violation();
    let snapshot = registry.snapshot().expect("ack metrics snapshot");
    assert_eq!(
        snapshot.counters.get("clustor.ack_handle.completed_total"),
        Some(&1)
    );
    assert_eq!(
        snapshot.counters.get("clustor.ack_handle.drop_alert_total"),
        Some(&1)
    );
    assert_eq!(
        snapshot
            .counters
            .get("clustor.ack_handle.defer_guardrail_violation_total"),
        Some(&1)
    );
    assert_eq!(
        snapshot
            .gauges
            .get("clustor.ack_handle.last_timeout.handle_id"),
        Some(&99)
    );
}
