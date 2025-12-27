mod envelope;
mod pid;
mod profile;

pub use envelope::{
    CreditHint, FlowDecision, FlowReadyzRecord, FlowThrottleEnvelope, FlowThrottleReason,
    FlowThrottleState, IngestStatusCode,
};
pub use pid::{DualCreditPidController, PidAutoTuneState};
pub use profile::FlowProfile;

use crate::telemetry::{IncidentCorrelator, IncidentDecision};
use crate::terminology::{RuntimeTerm, TERM_STRICT};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

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

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowIngestTelemetry {
    pub ops_per_sec: f64,
    pub target_ops_per_sec: f64,
    pub slo_gap: f64,
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

#[derive(Clone)]
pub struct InMemoryFlowMetrics {
    ops_per_sec: Arc<AtomicU64>,
    target_ops_per_sec: Arc<AtomicU64>,
    slo_gap: Arc<AtomicU64>,
}

impl Default for InMemoryFlowMetrics {
    fn default() -> Self {
        Self {
            ops_per_sec: Arc::new(AtomicU64::new(0)),
            target_ops_per_sec: Arc::new(AtomicU64::new(0)),
            slo_gap: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl InMemoryFlowMetrics {
    pub fn snapshot(&self) -> FlowIngestTelemetry {
        FlowIngestTelemetry {
            ops_per_sec: f64::from_bits(self.ops_per_sec.load(Ordering::Relaxed)),
            target_ops_per_sec: f64::from_bits(self.target_ops_per_sec.load(Ordering::Relaxed)),
            slo_gap: f64::from_bits(self.slo_gap.load(Ordering::Relaxed)),
        }
    }
}

impl FlowMetrics for InMemoryFlowMetrics {
    fn record_ingest_ops(&self, telemetry: FlowIngestTelemetry) {
        self.ops_per_sec
            .store(telemetry.ops_per_sec.to_bits(), Ordering::Relaxed);
        self.target_ops_per_sec
            .store(telemetry.target_ops_per_sec.to_bits(), Ordering::Relaxed);
        self.slo_gap
            .store(telemetry.slo_gap.to_bits(), Ordering::Relaxed);
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
