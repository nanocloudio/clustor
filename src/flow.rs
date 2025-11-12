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
                kp: 0.60,
                ki: 0.20,
                kd: 0.10,
                derivative_tau_ms: 300.0,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
                integral_clamp: 2_048.0,
            },
            FlowProfile::Throughput => PidParams {
                kp: 0.50,
                ki: 0.15,
                kd: 0.08,
                derivative_tau_ms: 300.0,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
                integral_clamp: 2_048.0,
            },
            FlowProfile::Wan => PidParams {
                kp: 0.40,
                ki: 0.10,
                kd: 0.05,
                derivative_tau_ms: 450.0,
                entry_credit_max: 4_096,
                byte_credit_max: 64 * 1024 * 1024,
                integral_clamp: 2_048.0,
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
    derivative_tau_ms: f64,
    entry_credit_max: i64,
    byte_credit_max: i64,
    integral_clamp: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditHint {
    Recover,
    Hold,
    Shed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    derivative_state: f64,
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
            derivative_state: 0.0,
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
        self.integral = self
            .integral
            .clamp(-self.params.integral_clamp, self.params.integral_clamp);
        let derivative = self.ema_derivative(error, dt);
        let raw_output =
            self.params.kp * error + self.params.ki * self.integral + self.params.kd * derivative;
        self.last_error = error;
        self.last_sample = Some(now);
        self.apply_output(raw_output);
        let credit_hint = self.credit_hint();
        let throttle_state = self.throttle_state();
        let ingest_status = self.ingest_status(&throttle_state);
        let throttle = FlowThrottleEnvelope::new(throttle_state, credit_hint, ingest_status);
        FlowDecision {
            entry_credits: self.entry_credits,
            entry_credit_max: self.params.entry_credit_max,
            byte_credits: self.byte_credits,
            byte_credit_max: self.params.byte_credit_max,
            applied_output: raw_output,
            throttle,
            credit_hint,
            ingest_status,
            pid_auto_tune_state: self.auto_tune_state,
        }
    }

    fn ema_derivative(&mut self, error: f64, dt: f64) -> f64 {
        if dt <= 0.0 || self.last_sample.is_none() {
            self.derivative_state = 0.0;
            return 0.0;
        }
        let raw = (error - self.last_error) / dt;
        let tau = (self.params.derivative_tau_ms / 1_000.0).max(f64::EPSILON);
        let alpha = dt / (tau + dt);
        self.derivative_state += alpha * (raw - self.derivative_state);
        self.derivative_state
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

    fn ingest_status(&self, state: &FlowThrottleState) -> IngestStatusCode {
        match state {
            FlowThrottleState::Open => IngestStatusCode::Healthy,
            FlowThrottleState::Throttled(_) => IngestStatusCode::TransientBackpressure,
        }
    }

    fn throttle_state(&self) -> FlowThrottleState {
        if self.byte_credits > 0 {
            FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt {
                byte_credit: self.byte_credits,
            })
        } else if self.entry_credits == 0 {
            FlowThrottleState::Throttled(FlowThrottleReason::EntryCreditsDepleted)
        } else {
            FlowThrottleState::Open
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
pub enum FlowIncidentKind {
    IngestFloorBreach {
        ops_per_sec: f64,
        floor_ops_per_sec: f64,
    },
    StructuralLag {
        lag_bytes: u64,
        lag_duration_ms: u64,
    },
    DeviceDowngrade,
}

#[derive(Debug, Clone)]
pub struct FlowSloIncidentRecord {
    pub profile: FlowProfile,
    pub kind: FlowIncidentKind,
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

    pub fn record_ingest_slo(
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
            kind: FlowIncidentKind::IngestFloorBreach {
                ops_per_sec: telemetry.ops_per_sec,
                floor_ops_per_sec: floor,
            },
            decision,
            recorded_at: now,
        });
        Some(decision)
    }

    pub fn record_structural_lag(
        &mut self,
        profile: FlowProfile,
        lag_bytes: u64,
        lag_duration_ms: u64,
        now: Instant,
    ) -> IncidentDecision {
        let decision = self.correlator.record(
            format!("flow.structural_lag.{}", profile.metric_label()),
            now,
        );
        self.last_event = Some(FlowSloIncidentRecord {
            profile,
            kind: FlowIncidentKind::StructuralLag {
                lag_bytes,
                lag_duration_ms,
            },
            decision,
            recorded_at: now,
        });
        decision
    }

    pub fn record_device_downgrade(
        &mut self,
        profile: FlowProfile,
        now: Instant,
    ) -> IncidentDecision {
        let decision = self.correlator.record(
            format!("flow.device_downgrade.{}", profile.metric_label()),
            now,
        );
        self.last_event = Some(FlowSloIncidentRecord {
            profile,
            kind: FlowIncidentKind::DeviceDowngrade,
            decision,
            recorded_at: now,
        });
        decision
    }

    pub fn last_event(&self) -> Option<&FlowSloIncidentRecord> {
        self.last_event.as_ref()
    }

    pub fn floor_for(&self, profile: FlowProfile) -> Option<f64> {
        self.floors.get(&profile).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowLagClass {
    Healthy,
    Transient,
    Structural,
}

#[derive(Debug, Clone)]
struct StructuralLagTracker {
    state: FlowLagClass,
    last_sample: Option<Instant>,
}

impl StructuralLagTracker {
    fn new() -> Self {
        Self {
            state: FlowLagClass::Healthy,
            last_sample: None,
        }
    }

    fn record(&mut self, lag_bytes: u64, lag_duration_ms: u64, now: Instant) -> FlowLagClass {
        let next = Self::classify(lag_bytes, lag_duration_ms);
        self.state = next;
        self.last_sample = Some(now);
        next
    }

    fn state(&self) -> FlowLagClass {
        self.state
    }

    fn classify(lag_bytes: u64, lag_duration_ms: u64) -> FlowLagClass {
        const TRANSIENT_MAX_BYTES: u64 = 64 * 1024 * 1024;
        const STRUCTURAL_HARD_BYTES: u64 = 256 * 1024 * 1024;
        const TRANSIENT_MAX_DURATION_MS: u64 = 30_000;
        if lag_bytes == 0 && lag_duration_ms == 0 {
            FlowLagClass::Healthy
        } else if lag_bytes >= STRUCTURAL_HARD_BYTES
            || lag_bytes > TRANSIENT_MAX_BYTES
            || lag_duration_ms >= TRANSIENT_MAX_DURATION_MS
        {
            FlowLagClass::Structural
        } else {
            FlowLagClass::Transient
        }
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
    lag_tracker: StructuralLagTracker,
    device_degraded: bool,
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
            lag_tracker: StructuralLagTracker::new(),
            device_degraded: false,
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

    pub fn record_structural_lag(
        &mut self,
        lag_bytes: u64,
        lag_duration_ms: u64,
        now: Instant,
    ) -> FlowLagClass {
        let class = self.lag_tracker.record(lag_bytes, lag_duration_ms, now);
        if matches!(class, FlowLagClass::Structural) {
            if let Some(monitor) = self.slo_monitor.as_mut() {
                monitor.record_structural_lag(
                    self.controller.profile(),
                    lag_bytes,
                    lag_duration_ms,
                    now,
                );
            }
        }
        class
    }

    pub fn lag_class(&self) -> FlowLagClass {
        self.lag_tracker.state()
    }

    pub fn record_device_downgrade(&mut self, degraded: bool, now: Instant) {
        if self.device_degraded != degraded {
            self.device_degraded = degraded;
            if degraded {
                if let Some(monitor) = self.slo_monitor.as_mut() {
                    monitor.record_device_downgrade(self.controller.profile(), now);
                }
            }
        }
    }

    pub fn device_degraded(&self) -> bool {
        self.device_degraded
    }

    fn apply_structural_policies(&self, flow: &mut FlowDecision) {
        match self.lag_tracker.state() {
            FlowLagClass::Healthy => {}
            FlowLagClass::Transient => {
                let cap = (self.controller.params.entry_credit_max / 2).max(1);
                flow.entry_credits = flow.entry_credits.min(cap);
                if matches!(flow.credit_hint, CreditHint::Recover) {
                    flow.credit_hint = CreditHint::Hold;
                }
            }
            FlowLagClass::Structural => {
                let cap = (self.controller.params.entry_credit_max / 4).max(1);
                flow.entry_credits = flow.entry_credits.min(cap);
                flow.credit_hint = CreditHint::Shed;
                flow.ingest_status = IngestStatusCode::PermanentDurability;
            }
        }

        if self.device_degraded {
            flow.credit_hint = CreditHint::Shed;
            flow.ingest_status = IngestStatusCode::PermanentDurability;
        }

        flow.throttle = FlowThrottleEnvelope::new(
            flow.throttle.state.clone(),
            flow.credit_hint,
            flow.ingest_status,
        );
    }

    pub fn evaluate(
        &mut self,
        tenant: &str,
        setpoint: f64,
        observed: f64,
        now: Instant,
    ) -> TenantFlowDecision {
        let mut flow = self.controller.record_sample(setpoint, observed, now);
        self.apply_structural_policies(&mut flow);
        let ops = flow.entry_credits.max(0) as f64;
        let telemetry = FlowIngestTelemetry {
            ops_per_sec: ops,
            target_ops_per_sec: setpoint,
            slo_gap: setpoint - ops,
        };
        self.ingest_telemetry = Some(telemetry);
        self.metrics.record_ingest_ops(telemetry);
        if let Some(monitor) = self.slo_monitor.as_mut() {
            monitor.record_ingest_slo(self.controller.profile(), telemetry, now);
        }
        let (quota, override_active) = self.quotas.resolve(tenant, now);
        let mut throttle = flow.throttle.clone();
        if matches!(throttle.state, FlowThrottleState::Open)
            && ((flow.entry_credits as u64) > quota.ingest_limit
                || (flow.byte_credits as u64) > quota.backlog_limit)
        {
            throttle = FlowThrottleEnvelope::new(
                FlowThrottleState::Throttled(FlowThrottleReason::QuotaExceeded {
                    tenant: tenant.to_string(),
                }),
                flow.credit_hint,
                flow.ingest_status,
            );
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
    pub credit_hint: CreditHint,
    pub ingest_status: IngestStatusCode,
}

impl FlowThrottleEnvelope {
    pub fn new(
        state: FlowThrottleState,
        credit_hint: CreditHint,
        ingest_status: IngestStatusCode,
    ) -> Self {
        Self {
            state,
            credit_hint,
            ingest_status,
        }
    }

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
    fn pid_simulation_converges_and_clamps_integral() {
        let mut controller = DualCreditPidController::new(FlowProfile::Throughput);
        let start = Instant::now();
        for step in 0..200 {
            let observed = if step < 50 { 100.0 } else { 1_000.0 };
            controller.record_sample(
                1_000.0,
                observed,
                start + Duration::from_millis((step * 10) as u64),
            );
        }
        assert!(
            controller.integral.abs() <= controller.params.integral_clamp + f64::EPSILON,
            "integral {} exceeded clamp {}",
            controller.integral,
            controller.params.integral_clamp
        );
        assert!(controller.entry_credits <= controller.params.entry_credit_max);
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
            .slo_monitor
            .as_ref()
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
        assert!(decision.flow.entry_credits <= controller.controller.params.entry_credit_max / 2);
        assert_eq!(decision.flow.ingest_status, IngestStatusCode::Healthy);
    }

    #[test]
    fn device_downgrade_forces_shed_hint() {
        let mut controller =
            TenantFlowController::new(FlowProfile::Latency, TenantQuota::unlimited());
        let now = Instant::now();
        controller.install_slo_monitor(FlowSloMonitor::new(IncidentCorrelator::new(
            Duration::from_secs(1),
        )));
        controller.record_device_downgrade(true, now);
        let event = controller
            .slo_monitor
            .as_ref()
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
}
