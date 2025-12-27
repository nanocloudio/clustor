use clustor::observability::telemetry::IncidentCorrelator;
use clustor::replication::flow::{
    CreditHint, DualCreditPidController, FlowIncidentKind, FlowLagClass, FlowProfile,
    FlowSloMonitor, FlowThrottleReason, FlowThrottleState, IngestStatusCode, TenantFlowController,
    TenantQuota, TenantQuotaManager,
};
use clustor::spec::terminology::TERM_STRICT;
use std::time::{Duration, Instant};

#[test]
fn controller_awards_credit_when_under_setpoint() {
    let mut controller = DualCreditPidController::new(FlowProfile::Latency);
    let start = Instant::now();
    let decision = controller.record_sample(100.0, 80.0, start);
    assert!(decision.entry_credits > decision.entry_credit_max / 2);
    let next = controller.record_sample(100.0, 70.0, start + Duration::from_millis(10));
    assert!(next.entry_credits >= decision.entry_credits);
    assert!(matches!(next.throttle.state, FlowThrottleState::Open));
}

#[test]
fn controller_accumulates_backlog_on_overload() {
    let mut controller = DualCreditPidController::new(FlowProfile::Throughput);
    let start = Instant::now();
    let decision = controller.record_sample(100.0, 140.0, start);
    assert!(decision.byte_credits > 0);
    assert!(matches!(
        decision.throttle.state,
        FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt { .. })
    ));
    let later = controller.record_sample(100.0, 160.0, start + Duration::from_millis(5));
    assert!(later.byte_credits >= decision.byte_credits);
    assert!(later.entry_credits <= decision.entry_credits);
}

#[test]
fn pid_simulation_converges_and_clamps_integral() {
    let mut controller = DualCreditPidController::new(FlowProfile::Throughput);
    let start = Instant::now();
    for step in 0..200 {
        let observed = if step < 50 { 100.0 } else { 1_000.0 };
        let decision = controller.record_sample(
            1_000.0,
            observed,
            start + Duration::from_millis((step * 10) as u64),
        );
        assert!(
            decision.entry_credits <= decision.entry_credit_max,
            "entry credits exceeded max"
        );
    }
    let steady = controller.record_sample(1_000.0, 1_000.0, start + Duration::from_secs(5));
    assert!(matches!(steady.throttle.state, FlowThrottleState::Open));
}

#[test]
fn quota_manager_applies_overrides() {
    let mut manager = TenantQuotaManager::new(TenantQuota {
        ingest_limit: 100,
        backlog_limit: 50,
    });
    manager.set_quota(
        "tenant-a",
        TenantQuota {
            ingest_limit: 80,
            backlog_limit: 40,
        },
    );
    let now = Instant::now();
    let override_record = manager.apply_override(
        "tenant-a",
        TenantQuota {
            ingest_limit: 200,
            backlog_limit: 100,
        },
        Duration::from_secs(10),
        "burst",
        now,
    );
    assert_eq!(manager.ledger().len(), 1);
    let (quota, active) = manager.resolve("tenant-a", now + Duration::from_secs(5));
    assert!(active);
    assert_eq!(quota.ingest_limit, override_record.quota.ingest_limit);
    let (quota, active) = manager.resolve("tenant-a", now + Duration::from_secs(20));
    assert!(!active);
    assert_eq!(quota.ingest_limit, 80);
}

#[test]
fn tenant_flow_controller_enforces_quota() {
    let mut controller = TenantFlowController::new(
        FlowProfile::Latency,
        TenantQuota {
            ingest_limit: 50,
            backlog_limit: 50,
        },
    );
    let now = Instant::now();
    let decision = controller.evaluate("tenant-x", 100.0, 10.0, now);
    assert!(matches!(
        decision.throttle.state,
        FlowThrottleState::Throttled(FlowThrottleReason::QuotaExceeded { .. })
    ));
}

#[test]
fn readyz_snapshot_exposes_credit_hint() {
    let mut controller =
        TenantFlowController::new(FlowProfile::Throughput, TenantQuota::unlimited());
    let now = Instant::now();
    controller.evaluate("tenant", 1_000.0, 1_200.0, now);
    let snapshot = controller.readyz_snapshot().expect("readyz");
    assert_eq!(snapshot.profile, FlowProfile::Throughput);
    assert!(matches!(
        snapshot.credit_hint,
        CreditHint::Hold | CreditHint::Shed | CreditHint::Recover
    ));
}

#[test]
fn explain_credit_zero_reports_throttle() {
    let mut controller = TenantFlowController::new(
        FlowProfile::Latency,
        TenantQuota {
            ingest_limit: 50,
            backlog_limit: 50,
        },
    );
    let now = Instant::now();
    controller.evaluate("tenant-x", 100.0, 10.0, now);
    let why = controller
        .explain_credit_zero("tenant-x", "trace-flow")
        .expect("why credit zero");
    assert!(matches!(
        why.throttle.state,
        FlowThrottleState::Throttled(_)
    ));
    assert_eq!(why.decision_trace_id, "trace-flow");
    assert_eq!(why.tenant, "tenant-x");
    assert!(why.runtime_terms.contains(&TERM_STRICT));
    assert!(why.telemetry.target_ops_per_sec > 0.0);
}

#[test]
fn structural_lag_sheds_credits_and_records_incident() {
    let mut controller =
        TenantFlowController::new(FlowProfile::Throughput, TenantQuota::unlimited());
    controller.install_slo_monitor(FlowSloMonitor::new(IncidentCorrelator::new(
        Duration::from_secs(1),
    )));
    let now = Instant::now();
    controller.record_structural_lag(300 * 1024 * 1024, 60_000, now);
    assert!(matches!(controller.lag_class(), FlowLagClass::Structural));
    let event = controller
        .slo_monitor()
        .and_then(|monitor| monitor.last_event())
        .expect("structural incident");
    match &event.kind {
        FlowIncidentKind::StructuralLag { lag_bytes, .. } => {
            assert!(*lag_bytes >= 300 * 1024 * 1024)
        }
        other => panic!("unexpected incident {:?}", other),
    }
    let decision = controller.evaluate("tenant", 1_000.0, 1_200.0, now);
    assert_eq!(
        decision.flow.ingest_status,
        IngestStatusCode::PermanentDurability
    );
    assert!(matches!(decision.flow.credit_hint, CreditHint::Shed));
}

#[test]
fn transient_lag_caps_entry_credits() {
    let mut controller =
        TenantFlowController::new(FlowProfile::Throughput, TenantQuota::unlimited());
    let now = Instant::now();
    controller.record_structural_lag(10 * 1024 * 1024, 5_000, now);
    let decision = controller.evaluate("tenant", 2_000.0, 500.0, now);
    assert!(matches!(controller.lag_class(), FlowLagClass::Transient));
    assert!(decision.flow.entry_credits <= decision.flow.entry_credit_max / 2);
    assert_eq!(decision.flow.ingest_status, IngestStatusCode::Healthy);
}

#[test]
fn device_downgrade_forces_shed_hint() {
    let mut controller = TenantFlowController::new(FlowProfile::Latency, TenantQuota::unlimited());
    let now = Instant::now();
    controller.install_slo_monitor(FlowSloMonitor::new(IncidentCorrelator::new(
        Duration::from_secs(1),
    )));
    controller.record_device_downgrade(true, now);
    let event = controller
        .slo_monitor()
        .and_then(|monitor| monitor.last_event());
    if let Some(record) = event {
        assert!(matches!(record.kind, FlowIncidentKind::DeviceDowngrade));
    }
    let decision = controller.evaluate("tenant", 200.0, 50.0, now);
    assert!(controller.device_degraded());
    assert_eq!(
        decision.flow.ingest_status,
        IngestStatusCode::PermanentDurability
    );
    assert!(matches!(decision.flow.credit_hint, CreditHint::Shed));
}
