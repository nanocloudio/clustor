use crate::durability::AckHandle;
use crate::terminology::TERM_STRICT;
use log::{info, warn};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use thiserror::Error;

use super::ack::{
    AckHandleMetrics, AckHandlePolicy, AckHandleSupervisor, AckTimeoutInfo, ManagedAckHandle,
};
use super::metrics::ApplyMetrics;
use super::profile::{ApplyProfile, ApplyProfileError, ApplyProfileReport, WhyApply};
use super::InMemoryApplyMetrics;

const QUEUE_ALERT_THRESHOLD: f32 = 0.9;
const APPLY_SPEC_CLAUSE: &str = "§6.4";

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
    A: AckHandleMetrics = super::InMemoryAckHandleMetrics,
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
