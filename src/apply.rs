use crate::durability::AckHandle;
#[cfg(test)]
use crate::profile::ProfileCapability;
use crate::profile::{PartitionProfile, ProfileCapabilityError, ProfileCapabilityRegistry};
use crate::telemetry::{SharedMetricsRegistry, TelemetryError};
use crate::terminology::TERM_STRICT;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

const DEFAULT_P99_WINDOW: usize = 10_000;
const QUEUE_ALERT_THRESHOLD: f32 = 0.9;
const APPLY_SPEC_CLAUSE: &str = "§6.4";

fn log_metric_error<T>(context: &str, result: Result<T, TelemetryError>) -> Option<T> {
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

#[derive(Debug, Clone)]
pub struct ApplyProfile {
    pub partition_profile: PartitionProfile,
    pub max_batch_ns: u64,
    pub max_batch_entries: usize,
    pub handoff_queue_len: usize,
    pub budget_breach_threshold: u32,
    pub p99_window: usize,
    pub ack_max_defer_ms: u64,
    pub aggregator: bool,
}

impl Default for ApplyProfile {
    fn default() -> Self {
        Self {
            partition_profile: PartitionProfile::Latency,
            max_batch_ns: 2_000_000, // 2 ms
            max_batch_entries: 512,
            handoff_queue_len: 1024,
            budget_breach_threshold: 5,
            p99_window: DEFAULT_P99_WINDOW,
            ack_max_defer_ms: 250,
            aggregator: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ApplyProfileLimits {
    max_batch_ns: u64,
    max_batch_entries: usize,
    ack_max_defer_ms: u64,
}

impl ApplyProfileLimits {
    fn for_profile(profile: PartitionProfile, aggregator: bool) -> Self {
        if aggregator {
            return Self {
                max_batch_ns: 6_000_000,
                max_batch_entries: 2_048,
                ack_max_defer_ms: 750,
            };
        }
        match profile {
            PartitionProfile::Latency | PartitionProfile::Zfs => Self {
                max_batch_ns: 2_000_000,
                max_batch_entries: 512,
                ack_max_defer_ms: 250,
            },
            PartitionProfile::Throughput => Self {
                max_batch_ns: 4_000_000,
                max_batch_entries: 512,
                ack_max_defer_ms: 400,
            },
            PartitionProfile::Wan => Self {
                max_batch_ns: 5_000_000,
                max_batch_entries: 512,
                ack_max_defer_ms: 500,
            },
        }
    }
}

impl ApplyProfile {
    pub fn for_profile(profile: PartitionProfile) -> Self {
        Self {
            partition_profile: profile,
            ..Self::default()
        }
    }

    pub fn with_partition_profile(mut self, profile: PartitionProfile) -> Self {
        self.partition_profile = profile;
        self
    }

    fn limits(&self) -> ApplyProfileLimits {
        ApplyProfileLimits::for_profile(self.partition_profile, self.aggregator)
    }

    pub fn validate(&self) -> Result<(), ApplyProfileError> {
        if self.max_batch_ns == 0 {
            return Err(ApplyProfileError::InvalidMaxBatch);
        }
        if self.max_batch_entries == 0 {
            return Err(ApplyProfileError::InvalidBatchEntries);
        }
        if self.handoff_queue_len == 0 {
            return Err(ApplyProfileError::InvalidQueueDepth);
        }
        if self.p99_window == 0 {
            return Err(ApplyProfileError::InvalidWindow);
        }
        self.validate_limits()
    }

    pub fn aggregator(
        registry: &ProfileCapabilityRegistry,
        profile: PartitionProfile,
    ) -> Result<Self, ProfileCapabilityError> {
        registry.ensure_aggregator_allowed(profile)?;
        Ok(Self {
            partition_profile: profile,
            max_batch_ns: 6_000_000,
            max_batch_entries: 2_048,
            handoff_queue_len: 1_024,
            budget_breach_threshold: 5,
            p99_window: DEFAULT_P99_WINDOW,
            ack_max_defer_ms: 750,
            aggregator: true,
        })
    }

    fn validate_limits(&self) -> Result<(), ApplyProfileError> {
        let limits = self.limits();
        if self.max_batch_ns > limits.max_batch_ns {
            return Err(ApplyProfileError::MaxBatchNsExceedsProfile {
                observed: self.max_batch_ns,
                ceiling: limits.max_batch_ns,
                profile: self.partition_profile,
                aggregator: self.aggregator,
            });
        }
        if self.max_batch_entries > limits.max_batch_entries {
            return Err(ApplyProfileError::MaxBatchEntriesExceedProfile {
                observed: self.max_batch_entries,
                ceiling: limits.max_batch_entries,
                profile: self.partition_profile,
                aggregator: self.aggregator,
            });
        }
        if self.ack_max_defer_ms > limits.ack_max_defer_ms {
            return Err(ApplyProfileError::AckDeferExceedsProfile {
                observed: self.ack_max_defer_ms,
                ceiling: limits.ack_max_defer_ms,
                profile: self.partition_profile,
                aggregator: self.aggregator,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyProfileReport {
    pub profile_name: String,
    pub aggregator: bool,
    pub p95_batch_ns: u64,
    pub p99_batch_ns: u64,
    pub max_batch_entries: usize,
    pub max_ack_defer_ms: u64,
    pub auto_demoted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhyApply {
    pub decision_trace_id: String,
    pub profile: ApplyProfileReport,
    pub guardrail_level: f32,
    pub guardrail_threshold: u32,
    pub spec_clause: String,
}

#[derive(Debug, Error)]
pub enum ApplyProfileError {
    #[error("max batch duration must be non-zero")]
    InvalidMaxBatch,
    #[error("max batch entries must be non-zero")]
    InvalidBatchEntries,
    #[error("handoff queue size must be non-zero")]
    InvalidQueueDepth,
    #[error("p99 window must be non-zero")]
    InvalidWindow,
    #[error(
        "max batch duration {observed}ns exceeds {profile:?} ceiling {ceiling}ns (aggregator={aggregator})"
    )]
    MaxBatchNsExceedsProfile {
        observed: u64,
        ceiling: u64,
        profile: PartitionProfile,
        aggregator: bool,
    },
    #[error(
        "max batch entries {observed} exceeds {profile:?} ceiling {ceiling} (aggregator={aggregator})"
    )]
    MaxBatchEntriesExceedProfile {
        observed: usize,
        ceiling: usize,
        profile: PartitionProfile,
        aggregator: bool,
    },
    #[error(
        "ack defer {observed}ms exceeds {profile:?} ceiling {ceiling}ms (aggregator={aggregator})"
    )]
    AckDeferExceedsProfile {
        observed: u64,
        ceiling: u64,
        profile: PartitionProfile,
        aggregator: bool,
    },
}

#[derive(Debug, Clone)]
pub struct ApplyEntry {
    pub term: u64,
    pub index: u64,
}

#[derive(Debug, Clone)]
pub struct ApplyBatch {
    pub entries: Vec<ApplyEntry>,
    pub enqueued_at: Instant,
}

impl ApplyBatch {
    pub fn new(entries: Vec<ApplyEntry>) -> Self {
        Self {
            entries,
            enqueued_at: Instant::now(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

pub struct ApplyScheduler<M: ApplyMetrics = InMemoryApplyMetrics> {
    profile: ApplyProfile,
    queue: VecDeque<ApplyBatch>,
    metrics: M,
    history: DurationHistory,
    budget_bucket: LeakyBucket,
    last_bucket_level: f32,
    aggregator_auto_demoted: bool,
}

impl<M: ApplyMetrics> ApplyScheduler<M> {
    pub fn new(profile: ApplyProfile, metrics: M) -> Result<Self, ApplyProfileError> {
        profile.validate()?;
        Ok(Self {
            history: DurationHistory::new(profile.p99_window),
            profile,
            queue: VecDeque::new(),
            metrics,
            budget_bucket: LeakyBucket::new(2.0),
            last_bucket_level: 0.0,
            aggregator_auto_demoted: false,
        })
    }

    pub fn enqueue(&mut self, batch: ApplyBatch) -> Result<(), ApplySchedulerError> {
        if batch.len() > self.profile.max_batch_entries {
            return Err(ApplySchedulerError::BatchTooLarge {
                entries: batch.len(),
                limit: self.profile.max_batch_entries,
            });
        }
        if self.queue.len() >= self.profile.handoff_queue_len {
            return Err(ApplySchedulerError::QueueFull {
                capacity: self.profile.handoff_queue_len,
            });
        }
        self.queue.push_back(batch);
        self.metrics
            .record_queue_depth(self.queue.len(), self.profile.handoff_queue_len);
        if (self.queue.len() as f32)
            >= (self.profile.handoff_queue_len as f32 * QUEUE_ALERT_THRESHOLD)
        {
            self.metrics.record_queue_alert();
        }
        Ok(())
    }

    pub fn dequeue(&mut self) -> Option<ApplyBatch> {
        let batch = self.queue.pop_front();
        self.metrics
            .record_queue_depth(self.queue.len(), self.profile.handoff_queue_len);
        batch
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub fn record_duration(&mut self, duration: Duration, now: Instant) -> ApplyBudgetDecision {
        self.history.push(duration);
        let p99_ns = self.history.percentile_ns(0.99);
        let bucket_level = if p99_ns > self.profile.max_batch_ns {
            if self.profile.aggregator {
                self.metrics.record_aggregator_budget_breach();
            }
            self.budget_bucket.add_and_get(1.0, now)
        } else {
            self.budget_bucket.level_after_drain(now)
        };
        let breach_count = bucket_level.ceil() as u32;
        self.last_bucket_level = bucket_level;
        self.metrics
            .record_budget_sample(p99_ns, self.profile.max_batch_ns, breach_count);
        if bucket_level >= self.profile.budget_breach_threshold as f32 {
            self.metrics.record_guardrail_violation();
            if self.profile.aggregator && !self.aggregator_auto_demoted {
                self.aggregator_auto_demoted = true;
                self.metrics.record_aggregator_guardrail_violation();
                warn!(
                    "event=apply_profile_auto_demote clause={} partition_profile={:?} p99_ns={} threshold={} term_id={} aggregator=true",
                    APPLY_SPEC_CLAUSE,
                    self.profile.partition_profile,
                    p99_ns,
                    self.profile.budget_breach_threshold,
                    TERM_STRICT.term_id
                );
            }
            ApplyBudgetDecision::Degraded {
                p99_ns,
                consecutive_breaches: breach_count,
            }
        } else if breach_count > 0 {
            ApplyBudgetDecision::Breaching {
                p99_ns,
                consecutive_breaches: breach_count,
            }
        } else {
            ApplyBudgetDecision::Healthy { p99_ns }
        }
    }

    pub fn report(&self) -> ApplyProfileReport {
        ApplyProfileReport {
            profile_name: if self.profile.aggregator {
                "Aggregator".into()
            } else {
                "Standard".into()
            },
            aggregator: self.profile.aggregator,
            p95_batch_ns: self.history.percentile_ns(0.95),
            p99_batch_ns: self.history.percentile_ns(0.99),
            max_batch_entries: self.profile.max_batch_entries,
            max_ack_defer_ms: self.profile.ack_max_defer_ms,
            auto_demoted: self.aggregator_auto_demoted,
        }
    }

    pub fn why_apply(&self, decision_trace_id: impl Into<String>) -> WhyApply {
        let trace_id = decision_trace_id.into();
        info!(
            "event=apply_profile_report clause={} decision_trace_id={} partition_profile={:?} aggregator={} auto_demoted={}",
            APPLY_SPEC_CLAUSE,
            trace_id,
            self.profile.partition_profile,
            self.profile.aggregator,
            self.aggregator_auto_demoted
        );
        WhyApply {
            decision_trace_id: trace_id,
            profile: self.report(),
            guardrail_level: self.last_bucket_level,
            guardrail_threshold: self.profile.budget_breach_threshold,
            spec_clause: APPLY_SPEC_CLAUSE.into(),
        }
    }
}

pub struct ApplyRuntime<
    M: ApplyMetrics = InMemoryApplyMetrics,
    A: AckHandleMetrics = InMemoryAckHandleMetrics,
> {
    scheduler: ApplyScheduler<M>,
    ack_supervisor: AckHandleSupervisor<A>,
    ack_policy: AckHandlePolicy,
}

impl<M: ApplyMetrics, A: AckHandleMetrics> ApplyRuntime<M, A> {
    pub fn new(
        profile: ApplyProfile,
        apply_metrics: M,
        ack_metrics: A,
    ) -> Result<Self, ApplyProfileError> {
        let ack_policy = AckHandlePolicy::for_profile(&profile);
        let scheduler = ApplyScheduler::new(profile, apply_metrics)?;
        let ack_supervisor = AckHandleSupervisor::new(ack_policy.clone(), ack_metrics);
        Ok(Self {
            scheduler,
            ack_supervisor,
            ack_policy,
        })
    }

    pub fn enqueue_batch(&mut self, batch: ApplyBatch) -> Result<(), ApplySchedulerError> {
        self.scheduler.enqueue(batch)
    }

    pub fn dequeue_batch(&mut self) -> Option<ApplyBatch> {
        self.scheduler.dequeue()
    }

    pub fn queue_len(&self) -> usize {
        self.scheduler.queue_len()
    }

    pub fn record_batch_duration(
        &mut self,
        duration: Duration,
        now: Instant,
    ) -> ApplyBudgetDecision {
        self.scheduler.record_duration(duration, now)
    }

    pub fn register_ack_handle(&self, ack: AckHandle, now: Instant) -> ManagedAckHandle<A> {
        self.ack_supervisor.register(ack, now)
    }

    pub fn tick_ack_deadlines(&self, now: Instant) -> Vec<AckTimeoutInfo> {
        self.ack_supervisor.tick(now)
    }

    pub fn report(&self) -> ApplyProfileReport {
        self.scheduler.report()
    }

    pub fn why_apply(&self, decision_trace_id: impl Into<String>) -> WhyApply {
        self.scheduler.why_apply(decision_trace_id)
    }

    pub fn ack_policy(&self) -> &AckHandlePolicy {
        &self.ack_policy
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplySchedulerError {
    #[error("apply batch has {entries} entries, exceeds limit {limit}")]
    BatchTooLarge { entries: usize, limit: usize },
    #[error("apply queue is full (capacity {capacity})")]
    QueueFull { capacity: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ApplyBudgetDecision {
    Healthy {
        p99_ns: u64,
    },
    Breaching {
        p99_ns: u64,
        consecutive_breaches: u32,
    },
    Degraded {
        p99_ns: u64,
        consecutive_breaches: u32,
    },
}

struct DurationHistory {
    window: usize,
    samples: VecDeque<u64>,
}

impl DurationHistory {
    fn new(window: usize) -> Self {
        Self {
            window,
            samples: VecDeque::with_capacity(window),
        }
    }

    fn push(&mut self, duration: Duration) {
        if self.samples.len() == self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(duration.as_nanos() as u64);
    }

    fn percentile_ns(&self, percentile: f64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut values: Vec<u64> = self.samples.iter().copied().collect();
        values.sort_unstable();
        let rank = ((values.len() as f64 - 1.0) * percentile).round() as usize;
        values[rank]
    }
}

#[derive(Debug, Clone)]
pub struct DedupeConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for DedupeConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
struct LeakyBucket {
    level: f32,
    drain_per_sec: f32,
    last_update: Instant,
}

impl LeakyBucket {
    fn new(drain_per_sec: f32) -> Self {
        Self {
            level: 0.0,
            drain_per_sec,
            last_update: Instant::now(),
        }
    }

    fn add_and_get(&mut self, amount: f32, now: Instant) -> f32 {
        self.drain(now);
        self.level += amount;
        self.level
    }

    fn level_after_drain(&mut self, now: Instant) -> f32 {
        self.drain(now);
        self.level
    }

    fn drain(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_update)
            .as_secs_f32();
        self.level = (self.level - self.drain_per_sec * elapsed).max(0.0);
        self.last_update = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DedupeToken {
    pub term: u64,
    pub index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupeSnapshotEntry {
    pub token: DedupeToken,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupeSnapshot {
    pub entries: Vec<DedupeSnapshotEntry>,
}

pub struct DedupeCache {
    config: DedupeConfig,
    entries: HashMap<DedupeToken, usize>,
    order: VecDeque<DedupeToken>,
    bytes_used: usize,
}

impl DedupeCache {
    pub fn new(config: DedupeConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes_used: 0,
        }
    }

    pub fn contains(&self, token: &DedupeToken) -> bool {
        self.entries.contains_key(token)
    }

    pub fn insert(&mut self, token: DedupeToken, size_bytes: usize) -> bool {
        if self.entries.contains_key(&token) {
            return false;
        }
        self.entries.insert(token, size_bytes);
        self.order.push_back(token);
        self.bytes_used += size_bytes;
        self.evict();
        true
    }

    pub fn prune_below(&mut self, base_index: u64) {
        let mut retained = VecDeque::with_capacity(self.order.len());
        while let Some(token) = self.order.pop_front() {
            if token.index >= base_index {
                retained.push_back(token);
            } else if let Some(size) = self.entries.remove(&token) {
                self.bytes_used = self.bytes_used.saturating_sub(size);
            }
        }
        self.order = retained;
    }

    pub fn snapshot(&self) -> DedupeSnapshot {
        let entries = self
            .order
            .iter()
            .filter_map(|token| {
                self.entries.get(token).map(|size| DedupeSnapshotEntry {
                    token: *token,
                    size_bytes: *size,
                })
            })
            .collect();
        DedupeSnapshot { entries }
    }

    pub fn replay(&mut self, snapshot: DedupeSnapshot) {
        self.clear();
        for entry in snapshot.entries {
            self.insert(entry.token, entry.size_bytes);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes_used = 0;
    }

    fn evict(&mut self) {
        while self.entries.len() > self.config.max_entries
            || self.bytes_used > self.config.max_bytes
        {
            if let Some(oldest) = self.order.pop_front() {
                if let Some(size) = self.entries.remove(&oldest) {
                    self.bytes_used = self.bytes_used.saturating_sub(size);
                }
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplayGuard {
    target_index: u64,
    applied_index: u64,
}

impl ReplayGuard {
    pub fn new(target_index: u64) -> Self {
        Self {
            target_index,
            applied_index: 0,
        }
    }

    pub fn record_apply(&mut self, index: u64) {
        if index > self.applied_index {
            self.applied_index = index;
        }
    }

    pub fn is_replay_complete(&self) -> bool {
        self.applied_index >= self.target_index
    }
}

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
    inner: Arc<Mutex<AckHandleSupervisorState<M>>>,
}

struct AckHandleSupervisorState<M: AckHandleMetrics> {
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

    fn note_drop(&self, id: u64, now: Instant) {
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
    id: u64,
    inner: Arc<Mutex<AckHandleSupervisorState<M>>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileCapabilities;
    use crate::telemetry::SharedMetricsRegistry;

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
}
