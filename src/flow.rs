use crate::profile::PartitionProfile;
use crate::telemetry::{IncidentCorrelator, IncidentDecision};
use crate::terminology::{RuntimeTerm, TERM_STRICT};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FlowProfile {
    #[default]
    Latency,
    Throughput,
    Wan,
}

impl FlowProfile {
    fn params(&self) -> PidParams {
        match self {
            FlowProfile::Latency => PidParams {
                kp: 0.8,
                ki: 0.2,
                kd: 0.05,
                entry_credit_max: 2_048,
                byte_credit_max: 32 * 1024 * 1024,
            },
            FlowProfile::Throughput => PidParams {
                kp: 1.2,
                ki: 0.15,
                kd: 0.1,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
            },
            FlowProfile::Wan => PidParams {
                kp: 0.6,
                ki: 0.1,
                kd: 0.02,
                entry_credit_max: 1_024,
                byte_credit_max: 16 * 1024 * 1024,
            },
        }
    }

    pub fn partition_profile(&self) -> PartitionProfile {
        match self {
            FlowProfile::Latency => PartitionProfile::Latency,
            FlowProfile::Throughput => PartitionProfile::Throughput,
            FlowProfile::Wan => PartitionProfile::Wan,
        }
    }

    pub fn ingest_ops_target(&self) -> Option<f64> {
        self.partition_profile()
            .config()
            .ingest_ops_target
            .map(|value| value as f64)
    }

    pub fn alert_floor_ops_per_sec(&self) -> Option<f64> {
        self.partition_profile()
            .config()
            .throughput_alert_floor
            .map(|value| value as f64)
    }

    pub fn metric_label(&self) -> &'static str {
        match self {
            FlowProfile::Latency => "latency",
            FlowProfile::Throughput => "throughput",
            FlowProfile::Wan => "wan",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PidParams {
    kp: f64,
    ki: f64,
    kd: f64,
    entry_credit_max: i64,
    byte_credit_max: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditHint {
    Recover,
    Hold,
    Shed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestStatusCode {
    Healthy,
    TransientBackpressure,
    PermanentDurability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidAutoTuneState {
    Enabled,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct DualCreditPidController {
    profile: FlowProfile,
    params: PidParams,
    integral: f64,
    last_error: f64,
    last_sample: Option<Instant>,
    entry_credits: i64,
    byte_credits: i64,
    auto_tune_state: PidAutoTuneState,
}

impl DualCreditPidController {
    pub fn new(profile: FlowProfile) -> Self {
        let params = profile.params();
        Self {
            profile,
            params,
            integral: 0.0,
            last_error: 0.0,
            last_sample: None,
            entry_credits: params.entry_credit_max / 2,
            byte_credits: 0,
            auto_tune_state: match profile {
                FlowProfile::Latency => PidAutoTuneState::Disabled,
                _ => PidAutoTuneState::Enabled,
            },
        }
    }

    pub fn profile(&self) -> FlowProfile {
        self.profile
    }

    pub fn record_sample(&mut self, setpoint: f64, observed: f64, now: Instant) -> FlowDecision {
        let dt = self
            .last_sample
            .map(|previous| now.saturating_duration_since(previous).as_secs_f64())
            .unwrap_or(1.0);
        let error = setpoint - observed;
        self.integral += error * dt;
        let derivative = if self.last_sample.is_some() {
            (error - self.last_error) / dt
        } else {
            0.0
        };
        let raw_output =
            self.params.kp * error + self.params.ki * self.integral + self.params.kd * derivative;
        self.last_error = error;
        self.last_sample = Some(now);
        self.apply_output(raw_output);
        let throttle = self.throttle_envelope();
        let ingest_status = self.ingest_status(&throttle);
        FlowDecision {
            entry_credits: self.entry_credits,
            entry_credit_max: self.params.entry_credit_max,
            byte_credits: self.byte_credits,
            byte_credit_max: self.params.byte_credit_max,
            applied_output: raw_output,
            throttle,
            credit_hint: self.credit_hint(),
            ingest_status,
            pid_auto_tune_state: self.auto_tune_state,
        }
    }

    fn apply_output(&mut self, output: f64) {
        let max_delta = (self
            .params
            .entry_credit_max
            .max(self.params.byte_credit_max)) as f64;
        let capped = output.clamp(-max_delta, max_delta);
        if capped >= 0.0 {
            let grant = capped.round() as i64;
            self.entry_credits = (self.entry_credits + grant).min(self.params.entry_credit_max);
            self.byte_credits = (self.byte_credits - grant).max(0);
        } else {
            let debt = (-capped).round() as i64;
            self.byte_credits = (self.byte_credits + debt).min(self.params.byte_credit_max);
            self.entry_credits = (self.entry_credits - debt).max(0);
        }
    }

    fn credit_hint(&self) -> CreditHint {
        let entry_ratio =
            (self.entry_credits as f64 / self.params.entry_credit_max as f64).clamp(0.0, 1.0);
        let byte_availability =
            1.0 - (self.byte_credits as f64 / self.params.byte_credit_max as f64);
        let byte_ratio = byte_availability.clamp(0.0, 1.0);
        if entry_ratio >= 0.75 && byte_ratio >= 0.75 {
            CreditHint::Recover
        } else if entry_ratio >= 0.25 && byte_ratio >= 0.25 {
            CreditHint::Hold
        } else {
            CreditHint::Shed
        }
    }

    fn ingest_status(&self, throttle: &FlowThrottleEnvelope) -> IngestStatusCode {
        match throttle.state {
            FlowThrottleState::Open => IngestStatusCode::Healthy,
            FlowThrottleState::Throttled(_) => IngestStatusCode::TransientBackpressure,
        }
    }

    fn throttle_envelope(&self) -> FlowThrottleEnvelope {
        if self.byte_credits > 0 {
            FlowThrottleEnvelope {
                state: FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt {
                    byte_credit: self.byte_credits,
                }),
            }
        } else if self.entry_credits == 0 {
            FlowThrottleEnvelope {
                state: FlowThrottleState::Throttled(FlowThrottleReason::EntryCreditsDepleted),
            }
        } else {
            FlowThrottleEnvelope {
                state: FlowThrottleState::Open,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FlowDecision {
    pub entry_credits: i64,
    pub entry_credit_max: i64,
    pub byte_credits: i64,
    pub byte_credit_max: i64,
    pub applied_output: f64,
    pub throttle: FlowThrottleEnvelope,
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
    pub pid_auto_tune_state: PidAutoTuneState,
}

#[derive(Debug, Clone)]
pub struct FlowReadyzRecord {
    pub profile: FlowProfile,
    pub pid_auto_tune_state: PidAutoTuneState,
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
    pub entry_credits: i64,
    pub entry_credit_max: i64,
    pub byte_credits: i64,
    pub byte_credit_max: i64,
}

#[derive(Debug, Clone)]
pub struct WhyCreditZero {
    pub tenant: String,
    pub decision_trace_id: String,
    pub throttle: FlowThrottleEnvelope,
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
    pub entry_credits: i64,
    pub entry_credit_max: i64,
    pub byte_credits: i64,
    pub byte_credit_max: i64,
    pub override_active: bool,
    pub slo_event: Option<FlowSloIncidentRecord>,
    pub runtime_terms: Vec<RuntimeTerm>,
    pub telemetry: FlowIngestTelemetry,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowIngestTelemetry {
    pub ops_per_sec: f64,
    pub target_ops_per_sec: f64,
    pub slo_gap: f64,
}

pub trait FlowMetrics: Send + Sync {
    fn record_ingest_ops(&self, telemetry: FlowIngestTelemetry);
}

#[derive(Debug, Clone)]
pub struct FlowSloIncidentRecord {
    pub profile: FlowProfile,
    pub ops_per_sec: f64,
    pub floor_ops_per_sec: f64,
    pub decision: IncidentDecision,
    pub recorded_at: Instant,
}

#[derive(Debug)]
pub struct FlowSloMonitor {
    correlator: IncidentCorrelator,
    floors: HashMap<FlowProfile, f64>,
    last_event: Option<FlowSloIncidentRecord>,
}

impl FlowSloMonitor {
    pub fn new(correlator: IncidentCorrelator) -> Self {
        let mut floors = HashMap::new();
        for profile in [
            FlowProfile::Latency,
            FlowProfile::Throughput,
            FlowProfile::Wan,
        ] {
            if let Some(floor) = profile.alert_floor_ops_per_sec() {
                floors.insert(profile, floor);
            }
        }
        Self {
            correlator,
            floors,
            last_event: None,
        }
    }

    pub fn record(
        &mut self,
        profile: FlowProfile,
        telemetry: FlowIngestTelemetry,
        now: Instant,
    ) -> Option<IncidentDecision> {
        let floor = match self.floors.get(&profile) {
            Some(value) => *value,
            None => return None,
        };
        if telemetry.ops_per_sec + f64::EPSILON >= floor {
            return None;
        }
        let decision = self
            .correlator
            .record(format!("flow.ingest_slo.{}", profile.metric_label()), now);
        self.last_event = Some(FlowSloIncidentRecord {
            profile,
            ops_per_sec: telemetry.ops_per_sec,
            floor_ops_per_sec: floor,
            decision,
            recorded_at: now,
        });
        Some(decision)
    }

    pub fn last_event(&self) -> Option<&FlowSloIncidentRecord> {
        self.last_event.as_ref()
    }

    pub fn floor_for(&self, profile: FlowProfile) -> Option<f64> {
        self.floors.get(&profile).copied()
    }
}

#[derive(Default, Clone)]
pub struct InMemoryFlowMetrics {
    inner: Arc<Mutex<FlowIngestTelemetry>>,
}

impl InMemoryFlowMetrics {
    pub fn snapshot(&self) -> FlowIngestTelemetry {
        *self.inner.lock().unwrap()
    }
}

impl FlowMetrics for InMemoryFlowMetrics {
    fn record_ingest_ops(&self, telemetry: FlowIngestTelemetry) {
        *self.inner.lock().unwrap() = telemetry;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TenantQuota {
    pub ingest_limit: u64,
    pub backlog_limit: u64,
}

impl TenantQuota {
    pub fn unlimited() -> Self {
        Self {
            ingest_limit: u64::MAX,
            backlog_limit: u64::MAX,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuotaOverrideRecord {
    pub tenant: String,
    pub quota: TenantQuota,
    pub expires_at: Instant,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct TenantQuotaManager {
    default: TenantQuota,
    quotas: HashMap<String, TenantQuota>,
    overrides: HashMap<String, QuotaOverrideRecord>,
    ledger: Vec<QuotaOverrideRecord>,
}

impl TenantQuotaManager {
    pub fn new(default: TenantQuota) -> Self {
        Self {
            default,
            quotas: HashMap::new(),
            overrides: HashMap::new(),
            ledger: Vec::new(),
        }
    }

    pub fn set_quota(&mut self, tenant: impl Into<String>, quota: TenantQuota) {
        self.quotas.insert(tenant.into(), quota);
    }

    pub fn apply_override(
        &mut self,
        tenant: impl Into<String>,
        quota: TenantQuota,
        duration: std::time::Duration,
        reason: impl Into<String>,
        now: Instant,
    ) -> QuotaOverrideRecord {
        let tenant = tenant.into();
        let record = QuotaOverrideRecord {
            tenant: tenant.clone(),
            quota,
            expires_at: now + duration,
            reason: reason.into(),
        };
        self.overrides.insert(tenant.clone(), record.clone());
        self.ledger.push(record.clone());
        record
    }

    pub fn resolve(&mut self, tenant: &str, now: Instant) -> (TenantQuota, bool) {
        self.overrides.retain(|_, record| record.expires_at > now);
        if let Some(record) = self.overrides.get(tenant) {
            return (record.quota, true);
        }
        let quota = self.quotas.get(tenant).copied().unwrap_or(self.default);
        (quota, false)
    }

    pub fn ledger(&self) -> &[QuotaOverrideRecord] {
        &self.ledger
    }
}

#[derive(Debug)]
pub struct TenantFlowController<M: FlowMetrics = InMemoryFlowMetrics> {
    controller: DualCreditPidController,
    quotas: TenantQuotaManager,
    metrics: M,
    ingest_telemetry: Option<FlowIngestTelemetry>,
    slo_monitor: Option<FlowSloMonitor>,
    last_flow_decision: Option<FlowDecision>,
    last_tenant_decision: Option<TenantFlowDecision>,
}

impl TenantFlowController<InMemoryFlowMetrics> {
    pub fn new(profile: FlowProfile, default_quota: TenantQuota) -> Self {
        TenantFlowController::with_metrics(profile, default_quota, InMemoryFlowMetrics::default())
    }
}

impl<M: FlowMetrics> TenantFlowController<M> {
    pub fn with_metrics(profile: FlowProfile, default_quota: TenantQuota, metrics: M) -> Self {
        Self {
            controller: DualCreditPidController::new(profile),
            quotas: TenantQuotaManager::new(default_quota),
            metrics,
            ingest_telemetry: None,
            slo_monitor: None,
            last_flow_decision: None,
            last_tenant_decision: None,
        }
    }

    pub fn quotas_mut(&mut self) -> &mut TenantQuotaManager {
        &mut self.quotas
    }

    pub fn install_slo_monitor(&mut self, monitor: FlowSloMonitor) {
        self.slo_monitor = Some(monitor);
    }

    pub fn slo_monitor(&self) -> Option<&FlowSloMonitor> {
        self.slo_monitor.as_ref()
    }

    pub fn evaluate(
        &mut self,
        tenant: &str,
        setpoint: f64,
        observed: f64,
        now: Instant,
    ) -> TenantFlowDecision {
        let flow = self.controller.record_sample(setpoint, observed, now);
        let ops = flow.entry_credits.max(0) as f64;
        let telemetry = FlowIngestTelemetry {
            ops_per_sec: ops,
            target_ops_per_sec: setpoint,
            slo_gap: setpoint - ops,
        };
        self.ingest_telemetry = Some(telemetry);
        self.metrics.record_ingest_ops(telemetry);
        if let Some(monitor) = self.slo_monitor.as_mut() {
            monitor.record(self.controller.profile(), telemetry, now);
        }
        let (quota, override_active) = self.quotas.resolve(tenant, now);
        let mut throttle = flow.throttle.clone();
        if matches!(throttle.state, FlowThrottleState::Open)
            && ((flow.entry_credits as u64) > quota.ingest_limit
                || (flow.byte_credits as u64) > quota.backlog_limit)
        {
            throttle = FlowThrottleEnvelope {
                state: FlowThrottleState::Throttled(FlowThrottleReason::QuotaExceeded {
                    tenant: tenant.to_string(),
                }),
            };
        }
        let decision = TenantFlowDecision {
            flow,
            quota,
            override_active,
            throttle,
        };
        self.last_flow_decision = Some(decision.flow.clone());
        self.last_tenant_decision = Some(decision.clone());
        decision
    }

    pub fn ingest_telemetry(&self) -> Option<FlowIngestTelemetry> {
        self.ingest_telemetry
    }

    pub fn readyz_snapshot(&self) -> Option<FlowReadyzRecord> {
        self.last_flow_decision
            .as_ref()
            .map(|flow| FlowReadyzRecord {
                profile: self.controller.profile(),
                pid_auto_tune_state: flow.pid_auto_tune_state,
                credit_hint: flow.credit_hint,
                ingest_status: flow.ingest_status,
                entry_credits: flow.entry_credits,
                entry_credit_max: flow.entry_credit_max,
                byte_credits: flow.byte_credits,
                byte_credit_max: flow.byte_credit_max,
            })
    }

    pub fn explain_credit_zero(
        &self,
        tenant: &str,
        decision_trace_id: impl Into<String>,
    ) -> Option<WhyCreditZero> {
        let decision = self.last_tenant_decision.as_ref()?;
        if matches!(decision.throttle.state, FlowThrottleState::Open) {
            return None;
        }
        let slo_event = self
            .slo_monitor
            .as_ref()
            .and_then(|monitor| monitor.last_event().cloned());
        Some(WhyCreditZero {
            tenant: tenant.into(),
            decision_trace_id: decision_trace_id.into(),
            throttle: decision.throttle.clone(),
            credit_hint: decision.flow.credit_hint,
            ingest_status: decision.flow.ingest_status,
            entry_credits: decision.flow.entry_credits,
            entry_credit_max: decision.flow.entry_credit_max,
            byte_credits: decision.flow.byte_credits,
            byte_credit_max: decision.flow.byte_credit_max,
            override_active: decision.override_active,
            slo_event,
            runtime_terms: vec![TERM_STRICT],
            telemetry: self.ingest_telemetry.unwrap_or_default(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct TenantFlowDecision {
    pub flow: FlowDecision,
    pub quota: TenantQuota,
    pub override_active: bool,
    pub throttle: FlowThrottleEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowThrottleState {
    Open,
    Throttled(FlowThrottleReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowThrottleReason {
    ByteCreditDebt { byte_credit: i64 },
    EntryCreditsDepleted,
    QuotaExceeded { tenant: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowThrottleEnvelope {
    pub state: FlowThrottleState,
}

impl FlowThrottleEnvelope {
    pub fn explain(&self) -> String {
        match &self.state {
            FlowThrottleState::Open => "flow controller open".to_string(),
            FlowThrottleState::Throttled(reason) => match reason {
                FlowThrottleReason::ByteCreditDebt { byte_credit } => {
                    format!("byte credit debt {} exceeds PID allowance", byte_credit)
                }
                FlowThrottleReason::EntryCreditsDepleted => {
                    "entry credits depleted; throttle applied".to_string()
                }
                FlowThrottleReason::QuotaExceeded { tenant } => {
                    format!("tenant {tenant} exceeded quota; throttle enforced")
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn controller_awards_credit_when_under_setpoint() {
        let mut controller = DualCreditPidController::new(FlowProfile::Latency);
        let start = Instant::now();
        let decision = controller.record_sample(100.0, 80.0, start);
        assert!(decision.entry_credits > controller.params.entry_credit_max / 2);
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
        assert!(controller.entry_credits <= decision.entry_credits);
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
}
