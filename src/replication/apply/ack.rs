use crate::durability::AckHandle;
use crate::telemetry::SharedMetricsRegistry;
use log::warn;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

use super::metrics::log_metric_error;
use super::profile::ApplyProfile;

#[derive(Debug, Clone)]
pub struct AckHandlePolicy {
    pub max_defer_ms: u64,
    pub drop_window_ms: u64,
    pub max_consecutive_drops: u32,
    pub aggregator: bool,
}

impl Default for AckHandlePolicy {
    fn default() -> Self {
        Self {
            max_defer_ms: 250,
            drop_window_ms: 1_000,
            max_consecutive_drops: 3,
            aggregator: false,
        }
    }
}

impl AckHandlePolicy {
    pub fn aggregator() -> Self {
        Self {
            max_defer_ms: 750,
            drop_window_ms: 1_000,
            max_consecutive_drops: 3,
            aggregator: true,
        }
    }

    pub fn for_profile(profile: &ApplyProfile) -> Self {
        if profile.aggregator {
            Self::aggregator()
        } else {
            Self {
                max_defer_ms: profile.ack_max_defer_ms,
                drop_window_ms: 1_000,
                max_consecutive_drops: 3,
                aggregator: false,
            }
        }
    }
}

pub trait AckHandleMetrics: Send + Sync {
    fn record_completion(&self, id: u64);
    fn record_failure(&self, id: u64, reason: &AckHandleFailureReason);
    fn record_timeout(&self, info: &AckTimeoutInfo);
    fn record_drop_alert(&self);
    fn record_defer_guardrail_violation(&self);
}

#[derive(Default, Clone)]
pub struct InMemoryAckHandleMetrics {
    inner: Arc<Mutex<AckHandleMetricsSnapshot>>,
}

#[derive(Default, Clone)]
pub struct AckHandleMetricsSnapshot {
    pub completed: u64,
    pub failed: u64,
    pub timeouts: u64,
    pub drop_alerts: u64,
    pub last_failure: Option<AckHandleFailureReason>,
    pub defer_guardrail_violations: u64,
}

impl InMemoryAckHandleMetrics {
    pub fn snapshot(&self) -> AckHandleMetricsSnapshot {
        self.lock_inner().clone()
    }

    fn lock_inner(&self) -> MutexGuard<'_, AckHandleMetricsSnapshot> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("event=in_memory_ack_metrics_poisoned; recovering state");
                poisoned.into_inner()
            }
        }
    }
}

impl AckHandleMetrics for InMemoryAckHandleMetrics {
    fn record_completion(&self, _id: u64) {
        let mut guard = self.lock_inner();
        guard.completed += 1;
    }

    fn record_failure(&self, _id: u64, reason: &AckHandleFailureReason) {
        let mut guard = self.lock_inner();
        guard.failed += 1;
        guard.last_failure = Some(reason.clone());
    }

    fn record_timeout(&self, _info: &AckTimeoutInfo) {
        let mut guard = self.lock_inner();
        guard.timeouts += 1;
        guard.last_failure = Some(AckHandleFailureReason::AckTimeout);
    }

    fn record_drop_alert(&self) {
        let mut guard = self.lock_inner();
        guard.drop_alerts += 1;
    }

    fn record_defer_guardrail_violation(&self) {
        let mut guard = self.lock_inner();
        guard.defer_guardrail_violations += 1;
    }
}

#[derive(Clone)]
pub struct TelemetryAckHandleMetrics {
    registry: SharedMetricsRegistry,
}

impl TelemetryAckHandleMetrics {
    pub fn new(registry: SharedMetricsRegistry) -> Self {
        Self { registry }
    }

    fn failure_code(reason: &AckHandleFailureReason) -> u64 {
        match reason {
            AckHandleFailureReason::AckTimeout => 1,
            AckHandleFailureReason::Application(_) => 2,
            AckHandleFailureReason::Dropped => 3,
        }
    }
}

impl AckHandleMetrics for TelemetryAckHandleMetrics {
    fn record_completion(&self, id: u64) {
        log_metric_error(
            "ack_handle.completed_total",
            self.registry.inc_counter("ack_handle.completed_total", 1),
        );
        log_metric_error(
            "ack_handle.last_completed_id",
            self.registry.set_gauge("ack_handle.last_completed_id", id),
        );
    }

    fn record_failure(&self, _id: u64, reason: &AckHandleFailureReason) {
        log_metric_error(
            "ack_handle.failed_total",
            self.registry.inc_counter("ack_handle.failed_total", 1),
        );
        log_metric_error(
            "ack_handle.last_failure_code",
            self.registry
                .set_gauge("ack_handle.last_failure_code", Self::failure_code(reason)),
        );
    }

    fn record_timeout(&self, info: &AckTimeoutInfo) {
        log_metric_error(
            "ack_handle.timeouts_total",
            self.registry.inc_counter("ack_handle.timeouts_total", 1),
        );
        log_metric_error(
            "ack_handle.last_timeout.handle_id",
            self.registry
                .set_gauge("ack_handle.last_timeout.handle_id", info.handle_id),
        );
        log_metric_error(
            "ack_handle.last_timeout.term",
            self.registry
                .set_gauge("ack_handle.last_timeout.term", info.term),
        );
        log_metric_error(
            "ack_handle.last_timeout.index",
            self.registry
                .set_gauge("ack_handle.last_timeout.index", info.index),
        );
    }

    fn record_drop_alert(&self) {
        log_metric_error(
            "ack_handle.drop_alert_total",
            self.registry.inc_counter("ack_handle.drop_alert_total", 1),
        );
    }

    fn record_defer_guardrail_violation(&self) {
        log_metric_error(
            "ack_handle.defer_guardrail_violation_total",
            self.registry
                .inc_counter("ack_handle.defer_guardrail_violation_total", 1),
        );
    }
}

pub struct AckHandleSupervisor<M: AckHandleMetrics = InMemoryAckHandleMetrics> {
    pub(crate) inner: Arc<Mutex<AckHandleSupervisorState<M>>>,
}

pub(crate) struct AckHandleSupervisorState<M: AckHandleMetrics> {
    policy: AckHandlePolicy,
    metrics: Arc<M>,
    next_id: u64,
    handles: HashMap<u64, HandleRecord>,
    drop_events: VecDeque<Instant>,
}

struct HandleRecord {
    ack: AckHandle,
    deadline: Instant,
}

impl<M: AckHandleMetrics> AckHandleSupervisor<M> {
    pub fn new(policy: AckHandlePolicy, metrics: M) -> Self {
        let metrics = Arc::new(metrics);
        Self {
            inner: Arc::new(Mutex::new(AckHandleSupervisorState {
                policy,
                metrics,
                next_id: 0,
                handles: HashMap::new(),
                drop_events: VecDeque::new(),
            })),
        }
    }

    pub fn register(&self, ack: AckHandle, now: Instant) -> ManagedAckHandle<M> {
        let mut guard = lock_supervisor_state(&self.inner);
        let id = guard.next_id;
        guard.next_id += 1;
        let deadline = now + Duration::from_millis(guard.policy.max_defer_ms);
        guard.handles.insert(id, HandleRecord { ack, deadline });
        drop(guard);
        ManagedAckHandle {
            id,
            inner: self.inner.clone(),
            finished: false,
        }
    }

    pub fn tick(&self, now: Instant) -> Vec<AckTimeoutInfo> {
        let (timed_out, metrics, aggregator) = {
            let mut guard = lock_supervisor_state(&self.inner);
            let mut timed_out = Vec::new();
            let mut expired = Vec::new();
            for (id, record) in guard.handles.iter() {
                if record.deadline <= now {
                    let (term, index) = record.ack.target();
                    let info = AckTimeoutInfo {
                        handle_id: *id,
                        term,
                        index,
                    };
                    timed_out.push(info);
                    expired.push(*id);
                }
            }
            for id in expired {
                guard.handles.remove(&id);
            }
            (timed_out, guard.metrics.clone(), guard.policy.aggregator)
        };
        for info in &timed_out {
            metrics.record_timeout(info);
            if aggregator {
                metrics.record_defer_guardrail_violation();
            }
        }
        timed_out
    }

    pub(crate) fn note_drop(&self, id: u64, now: Instant) {
        let action = {
            let mut guard = lock_supervisor_state(&self.inner);
            if guard.handles.remove(&id).is_some() {
                guard.drop_events.push_back(now);
                let window = Duration::from_millis(guard.policy.drop_window_ms);
                while let Some(front) = guard.drop_events.front() {
                    if now.duration_since(*front) > window {
                        guard.drop_events.pop_front();
                    } else {
                        break;
                    }
                }
                let should_alert =
                    guard.drop_events.len() as u32 >= guard.policy.max_consecutive_drops;
                Some((guard.metrics.clone(), should_alert))
            } else {
                None
            }
        };
        if let Some((metrics, should_alert)) = action {
            metrics.record_failure(id, &AckHandleFailureReason::Dropped);
            if should_alert {
                metrics.record_drop_alert();
            }
        }
    }
}

fn lock_supervisor_state<'a, M: AckHandleMetrics>(
    inner: &'a Arc<Mutex<AckHandleSupervisorState<M>>>,
) -> MutexGuard<'a, AckHandleSupervisorState<M>> {
    match inner.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("event=ack_handle_supervisor_poisoned; recovering state");
            poisoned.into_inner()
        }
    }
}

pub struct ManagedAckHandle<M: AckHandleMetrics = InMemoryAckHandleMetrics> {
    pub(crate) id: u64,
    pub(crate) inner: Arc<Mutex<AckHandleSupervisorState<M>>>,
    finished: bool,
}

impl<M: AckHandleMetrics> ManagedAckHandle<M> {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn complete(mut self) -> Result<(), AckHandleError> {
        self.finish_with(AckHandleStatus::Completed)
    }

    pub fn fail(mut self, reason: impl Into<String>) -> Result<(), AckHandleError> {
        self.finish_with(AckHandleStatus::Failed(
            AckHandleFailureReason::Application(reason.into()),
        ))
    }

    fn finish_with(&mut self, status: AckHandleStatus) -> Result<(), AckHandleError> {
        if self.finished {
            return Err(AckHandleError::AlreadyFinished);
        }
        let metrics = {
            let mut guard = lock_supervisor_state(&self.inner);
            guard
                .handles
                .remove(&self.id)
                .map(|_| guard.metrics.clone())
        };
        match metrics {
            Some(metrics) => {
                match &status {
                    AckHandleStatus::Completed => metrics.record_completion(self.id),
                    AckHandleStatus::Failed(reason) => metrics.record_failure(self.id, reason),
                }
                self.finished = true;
                Ok(())
            }
            None => Err(AckHandleError::UnknownHandle),
        }
    }
}

impl<M: AckHandleMetrics> Drop for ManagedAckHandle<M> {
    fn drop(&mut self) {
        if !self.finished {
            let now = Instant::now();
            let supervisor = AckHandleSupervisor {
                inner: self.inner.clone(),
            };
            supervisor.note_drop(self.id, now);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckTimeoutInfo {
    pub handle_id: u64,
    pub term: u64,
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckHandleFailureReason {
    AckTimeout,
    Application(String),
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckHandleStatus {
    Completed,
    Failed(AckHandleFailureReason),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AckHandleError {
    #[error("ack handle already finished")]
    AlreadyFinished,
    #[error("ack handle is no longer tracked")]
    UnknownHandle,
}
