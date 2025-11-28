use crate::telemetry::{SharedMetricsRegistry, TelemetryError};
use log::warn;
use std::sync::{Arc, Mutex, MutexGuard};

use super::ApplyProfile;

pub(crate) fn log_metric_error<T>(context: &str, result: Result<T, TelemetryError>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            warn!(
                "event=telemetry_metric_error context={} error={}",
                context, err
            );
            None
        }
    }
}

pub trait ApplyMetrics: Send + Sync {
    fn record_queue_depth(&self, depth: usize, capacity: usize);
    fn record_budget_sample(&self, p99_ns: u64, threshold_ns: u64, consecutive_breaches: u32);
    fn record_queue_alert(&self);
    fn record_guardrail_violation(&self);
    fn record_aggregator_budget_breach(&self);
    fn record_aggregator_guardrail_violation(&self);
}

#[derive(Default, Clone)]
pub struct InMemoryApplyMetrics {
    inner: Arc<Mutex<InMemoryApplyMetricsSnapshot>>,
}

#[derive(Default, Clone)]
pub struct InMemoryApplyMetricsSnapshot {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub last_p99_ns: u64,
    pub last_threshold_ns: u64,
    pub consecutive_breaches: u32,
    pub queue_alerts: u64,
    pub guardrail_violations: u64,
    pub aggregator_budget_breaches: u64,
    pub aggregator_guardrail_violations: u64,
}

impl InMemoryApplyMetrics {
    pub fn snapshot(&self) -> InMemoryApplyMetricsSnapshot {
        self.lock_inner().clone()
    }

    fn lock_inner(&self) -> MutexGuard<'_, InMemoryApplyMetricsSnapshot> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("event=in_memory_apply_metrics_poisoned; recovering state");
                poisoned.into_inner()
            }
        }
    }
}

impl ApplyMetrics for InMemoryApplyMetrics {
    fn record_queue_depth(&self, depth: usize, capacity: usize) {
        let mut guard = self.lock_inner();
        guard.queue_depth = depth;
        guard.queue_capacity = capacity;
    }

    fn record_budget_sample(&self, p99_ns: u64, threshold_ns: u64, breaches: u32) {
        let mut guard = self.lock_inner();
        guard.last_p99_ns = p99_ns;
        guard.last_threshold_ns = threshold_ns;
        guard.consecutive_breaches = breaches;
    }

    fn record_queue_alert(&self) {
        let mut guard = self.lock_inner();
        guard.queue_alerts += 1;
    }

    fn record_guardrail_violation(&self) {
        let mut guard = self.lock_inner();
        guard.guardrail_violations += 1;
    }

    fn record_aggregator_budget_breach(&self) {
        let mut guard = self.lock_inner();
        guard.aggregator_budget_breaches += 1;
    }

    fn record_aggregator_guardrail_violation(&self) {
        let mut guard = self.lock_inner();
        guard.aggregator_guardrail_violations += 1;
    }
}

#[derive(Clone)]
pub struct TelemetryApplyMetrics {
    registry: SharedMetricsRegistry,
    aggregator: bool,
}

impl TelemetryApplyMetrics {
    pub fn new(registry: SharedMetricsRegistry, aggregator: bool) -> Self {
        Self {
            registry,
            aggregator,
        }
    }

    pub fn for_profile(registry: SharedMetricsRegistry, profile: &ApplyProfile) -> Self {
        Self::new(registry, profile.aggregator)
    }
}

impl ApplyMetrics for TelemetryApplyMetrics {
    fn record_queue_depth(&self, depth: usize, capacity: usize) {
        log_metric_error(
            "apply.queue_depth",
            self.registry.set_gauge("apply.queue_depth", depth as u64),
        );
        log_metric_error(
            "apply.queue_capacity",
            self.registry
                .set_gauge("apply.queue_capacity", capacity as u64),
        );
    }

    fn record_budget_sample(&self, p99_ns: u64, threshold_ns: u64, breaches: u32) {
        log_metric_error(
            "apply.batch_p99_ns",
            self.registry.set_gauge("apply.batch_p99_ns", p99_ns),
        );
        log_metric_error(
            "apply.batch_budget_threshold_ns",
            self.registry
                .set_gauge("apply.batch_budget_threshold_ns", threshold_ns),
        );
        log_metric_error(
            "apply.budget_breach_streak",
            self.registry
                .set_gauge("apply.budget_breach_streak", breaches as u64),
        );
        if self.aggregator {
            log_metric_error(
                "apply.aggregator_samples_total",
                self.registry
                    .inc_counter("apply.aggregator_samples_total", 1),
            );
        }
    }

    fn record_queue_alert(&self) {
        log_metric_error(
            "apply.queue_alert_total",
            self.registry.inc_counter("apply.queue_alert_total", 1),
        );
    }

    fn record_guardrail_violation(&self) {
        log_metric_error(
            "apply.guardrail_violation_total",
            self.registry
                .inc_counter("apply.guardrail_violation_total", 1),
        );
    }

    fn record_aggregator_budget_breach(&self) {
        log_metric_error(
            "apply.aggregator_budget_breach_total",
            self.registry
                .inc_counter("apply.aggregator_budget_breach_total", 1),
        );
    }

    fn record_aggregator_guardrail_violation(&self) {
        log_metric_error(
            "apply.aggregator_guardrail_violation_total",
            self.registry
                .inc_counter("apply.aggregator_guardrail_violation_total", 1),
        );
    }
}
