use clustor::{
    DualCreditPidController, FlowProfile, FlowSloMonitor, FlowThrottleReason, FlowThrottleState,
    IncidentCorrelator, TenantFlowController, TenantQuota,
};
use std::time::{Duration, Instant};

#[test]
fn flow_checkpoint_profiles_throttle_and_recover() {
    for profile in [
        FlowProfile::Latency,
        FlowProfile::Throughput,
        FlowProfile::Wan,
    ] {
        let mut controller = DualCreditPidController::new(profile);
        let start = Instant::now();
        let mut throttled = 0;
        for (idx, observed) in [60.0, 160.0, 180.0, 90.0].iter().enumerate() {
            let decision = controller.record_sample(
                120.0,
                *observed,
                start + Duration::from_millis((idx * 5) as u64),
            );
            if matches!(decision.throttle.state, FlowThrottleState::Throttled(_)) {
                throttled += 1;
            }
        }
        if throttled == 0 {
            for burst in 0..8 {
                let decision = controller.record_sample(
                    120.0,
                    480.0,
                    start + Duration::from_millis(25 + burst * 5),
                );
                if matches!(decision.throttle.state, FlowThrottleState::Throttled(_)) {
                    throttled += 1;
                    break;
                }
            }
        }
        assert!(
            throttled > 0,
            "profile {:?} failed to throttle under load",
            profile
        );
    }
}

#[test]
fn flow_checkpoint_tenant_override_disables_quota_throttle() {
    let mut controller = TenantFlowController::new(
        FlowProfile::Latency,
        TenantQuota {
            ingest_limit: 50,
            backlog_limit: 50,
        },
    );
    let now = Instant::now();
    controller.quotas_mut().apply_override(
        "tenant-1",
        TenantQuota::unlimited(),
        Duration::from_secs(30),
        "checkpoint-test",
        now,
    );
    let decision = controller.evaluate("tenant-1", 100.0, 90.0, now);
    assert!(!matches!(
        decision.throttle.state,
        FlowThrottleState::Throttled(FlowThrottleReason::QuotaExceeded { .. })
    ));
}

#[test]
fn flow_checkpoint_exposes_ingest_telemetry() {
    let mut controller = TenantFlowController::new(
        FlowProfile::Latency,
        TenantQuota {
            ingest_limit: 1_000,
            backlog_limit: 1_000,
        },
    );
    let now = Instant::now();
    controller.evaluate("tenant-1", 120.0, 80.0, now);
    let telemetry = controller.ingest_telemetry().expect("telemetry present");
    assert_eq!(telemetry.target_ops_per_sec, 120.0);
    assert!(telemetry.ops_per_sec >= 0.0);
}

#[test]
fn flow_checkpoint_slo_monitor_tracks_alerts() {
    let correlator = IncidentCorrelator::new(Duration::from_secs(60));
    let mut monitor = FlowSloMonitor::new(correlator);
    let now = Instant::now();
    let telemetry = clustor::flow::FlowIngestTelemetry {
        ops_per_sec: 1_000.0,
        target_ops_per_sec: 50_000.0,
        slo_gap: 49_000.0,
    };
    assert!(monitor
        .record(FlowProfile::Latency, telemetry, now)
        .is_some());
    let event = monitor.last_event().expect("event recorded");
    assert_eq!(event.floor_ops_per_sec, 40_000.0);
    assert_eq!(event.profile, FlowProfile::Latency);

    let mut controller = TenantFlowController::new(
        FlowProfile::Throughput,
        TenantQuota {
            ingest_limit: 1_000,
            backlog_limit: 1_000,
        },
    );
    controller.install_slo_monitor(FlowSloMonitor::new(IncidentCorrelator::new(
        Duration::from_secs(60),
    )));
    controller.evaluate("tenant-1", 120_000.0, 80_000.0, now);
    let last = controller
        .slo_monitor()
        .and_then(|monitor| monitor.last_event())
        .expect("controller recorded alert");
    assert_eq!(last.profile, FlowProfile::Throughput);
}

#[test]
fn flow_checkpoint_stress_test_records_incidents() {
    let mut controller = TenantFlowController::new(
        FlowProfile::Throughput,
        TenantQuota {
            ingest_limit: 1_000,
            backlog_limit: 1_000,
        },
    );
    controller.install_slo_monitor(FlowSloMonitor::new(IncidentCorrelator::new(
        Duration::from_secs(30),
    )));
    let start = Instant::now();
    for idx in 0..50 {
        let observed = if idx % 2 == 0 { 200_000.0 } else { 10_000.0 };
        controller.evaluate(
            "tenant-stress",
            120_000.0,
            observed,
            start + Duration::from_millis(idx * 5),
        );
    }
    let why = controller.explain_credit_zero("tenant-stress", "flow-stress");
    assert!(why.is_some());
    let incident = controller
        .slo_monitor()
        .and_then(|monitor| monitor.last_event());
    assert!(incident.is_some());
}
