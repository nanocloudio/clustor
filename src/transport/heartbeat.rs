use crate::raft::ReplicaId;
use crate::telemetry::MetricsRegistry;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const HEARTBEAT_DEFAULT_LAG_MS: u64 = 0;
const MIN_RPC_TIMEOUT_MS: u64 = 100;
const MAX_RPC_TIMEOUT_MS: u64 = 1_000;
const EMA_ALPHA: f64 = 0.2;
const STRUCTURAL_LAG_DURATION_MS: u64 = 30_000;

#[derive(Debug)]
pub struct HeartbeatScheduler {
    interval: Duration,
    followers: HashMap<ReplicaId, FollowerState>,
}

#[derive(Debug, Clone)]
struct FollowerState {
    last_heartbeat: Instant,
    last_ack: Option<Instant>,
    lag_ms: u64,
    ema_rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatCommand {
    pub replica: ReplicaId,
    pub timeout: Duration,
    pub deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LagClass {
    Healthy,
    Transient,
    Structural,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LagStatus {
    pub replica: ReplicaId,
    pub lag_ms: u64,
    pub class: LagClass,
}

impl HeartbeatScheduler {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            followers: HashMap::new(),
        }
    }

    pub fn register(&mut self, replica: impl Into<ReplicaId>, now: Instant) {
        let replica = replica.into();
        self.followers.entry(replica).or_insert(FollowerState {
            last_heartbeat: now - self.interval,
            last_ack: None,
            lag_ms: HEARTBEAT_DEFAULT_LAG_MS,
            ema_rtt_ms: None,
        });
    }

    pub fn unregister(&mut self, replica: &ReplicaId) {
        self.followers.remove(replica);
    }

    pub fn due(&mut self, now: Instant) -> Vec<ReplicaId> {
        let mut due = Vec::new();
        for (replica, state) in self.followers.iter_mut() {
            if now.saturating_duration_since(state.last_heartbeat) >= self.interval {
                state.last_heartbeat = now;
                due.push(replica.clone());
            }
        }
        due
    }

    pub fn poll(&mut self, now: Instant) -> Vec<HeartbeatCommand> {
        self.due(now)
            .into_iter()
            .map(|replica| {
                let timeout = self
                    .followers
                    .get(&replica)
                    .map(|state| self.compute_timeout(state))
                    .unwrap_or_else(|| self.compute_default_timeout());
                HeartbeatCommand {
                    replica,
                    timeout,
                    deadline: now + timeout,
                }
            })
            .collect()
    }

    pub fn record_ack(&mut self, replica: &ReplicaId, now: Instant, lag_ms: u64) {
        if let Some(state) = self.followers.get_mut(replica) {
            state.last_ack = Some(now);
            state.lag_ms = lag_ms;
            let sample = lag_ms.max(1) as f64;
            state.ema_rtt_ms = Some(match state.ema_rtt_ms {
                Some(previous) => previous * (1.0 - EMA_ALPHA) + sample * EMA_ALPHA,
                None => sample,
            });
        }
    }

    pub fn follower_ready_ratio(&self, now: Instant) -> u64 {
        if self.followers.is_empty() {
            return 100;
        }
        let freshness = self.interval * 2;
        let ready = self
            .followers
            .values()
            .filter(|state| {
                state
                    .last_ack
                    .map(|ack| now.saturating_duration_since(ack) <= freshness)
                    .unwrap_or(false)
            })
            .count() as u64;
        ready * 100 / self.followers.len() as u64
    }

    pub fn publish_metrics(&self, metrics: &mut MetricsRegistry, now: Instant) {
        let readiness = self.follower_ready_ratio(now);
        metrics.set_gauge("raft.follower_ready_ratio_percent", readiness);
        let lag_sum: u64 = self.followers.values().map(|state| state.lag_ms).sum();
        metrics.set_gauge(
            "raft.follower_average_lag_ms",
            if self.followers.is_empty() {
                0
            } else {
                lag_sum / self.followers.len() as u64
            },
        );
    }

    pub fn lag_statuses(&self) -> Vec<LagStatus> {
        self.followers
            .iter()
            .map(|(replica, state)| LagStatus {
                replica: replica.clone(),
                lag_ms: state.lag_ms,
                class: classify_lag(state.lag_ms),
            })
            .collect()
    }

    fn compute_timeout(&self, state: &FollowerState) -> Duration {
        let baseline = self.interval.as_millis() as f64;
        let ema = state.ema_rtt_ms.unwrap_or(baseline).max(1.0);
        let doubled = (ema * 2.0).round() as u64;
        Duration::from_millis(doubled.clamp(MIN_RPC_TIMEOUT_MS, MAX_RPC_TIMEOUT_MS))
    }

    fn compute_default_timeout(&self) -> Duration {
        Duration::from_millis(
            (self.interval.as_millis() as u64 * 2).clamp(MIN_RPC_TIMEOUT_MS, MAX_RPC_TIMEOUT_MS),
        )
    }
}

fn classify_lag(lag_ms: u64) -> LagClass {
    if lag_ms == 0 {
        LagClass::Healthy
    } else if lag_ms < STRUCTURAL_LAG_DURATION_MS {
        LagClass::Transient
    } else {
        LagClass::Structural
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::{AppendEntriesRequest, HeartbeatBatcher};

    #[test]
    fn scheduler_tracks_due_followers() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(100));
        sched.register("f1", now);
        sched.register("f2", now);
        assert_eq!(sched.due(now).len(), 2);
        let due = sched.due(now + Duration::from_millis(150));
        assert_eq!(due.len(), 2);
    }

    #[test]
    fn readiness_ratio_reflects_recent_acks() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(100));
        sched.register("f1", now);
        sched.register("f2", now);
        sched.record_ack(&ReplicaId::new("f1"), now, 10);
        assert_eq!(sched.follower_ready_ratio(now), 50);
        assert_eq!(
            sched.follower_ready_ratio(now + Duration::from_millis(300)),
            0
        );
    }

    #[test]
    fn metrics_publish_ready_ratio_and_lag() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(100));
        sched.register("f1", now);
        sched.register("f2", now);
        sched.record_ack(&ReplicaId::new("f1"), now, 20);
        let mut registry = MetricsRegistry::new("clustor");
        sched.publish_metrics(&mut registry, now);
        let snapshot = registry.snapshot();
        assert_eq!(
            snapshot
                .gauges
                .get("clustor.raft.follower_ready_ratio_percent"),
            Some(&50)
        );
        assert_eq!(
            snapshot.gauges.get("clustor.raft.follower_average_lag_ms"),
            Some(&10)
        );
    }

    #[test]
    fn poll_returns_timeout_commands() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(50));
        sched.register("f1", now);
        let commands = sched.poll(now);
        assert_eq!(commands.len(), 1);
        let cmd = &commands[0];
        assert!(cmd.timeout >= Duration::from_millis(MIN_RPC_TIMEOUT_MS));
        assert!(cmd.timeout <= Duration::from_millis(MAX_RPC_TIMEOUT_MS));
        assert!(cmd.deadline >= now + cmd.timeout);
    }

    #[test]
    fn timeout_scales_with_observed_rtt() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(50));
        let replica = ReplicaId::new("f1");
        sched.register(replica.clone(), now);
        let baseline = sched.poll(now);
        let base_timeout = baseline[0].timeout;
        sched.record_ack(&replica, now, 800);
        let updated = sched.poll(now + Duration::from_millis(60));
        assert!(updated[0].timeout >= base_timeout);
    }

    #[test]
    fn lag_statuses_classify_structural_lag() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(50));
        let replica = ReplicaId::new("f1");
        sched.register(replica.clone(), now);
        sched.record_ack(&replica, now, 500);
        let healthy = sched.lag_statuses();
        assert_eq!(healthy[0].class, LagClass::Transient);
        sched.record_ack(&replica, now, STRUCTURAL_LAG_DURATION_MS + 1);
        let structural = sched.lag_statuses();
        assert_eq!(structural[0].class, LagClass::Structural);
    }

    #[test]
    fn async_replication_checkpoint() {
        let now = Instant::now();
        let mut sched = HeartbeatScheduler::new(Duration::from_millis(50));
        for id in ["f1", "f2", "f3"] {
            sched.register(id, now);
        }
        let mut batcher = HeartbeatBatcher::new(2);
        let commands = sched.poll(now);
        assert_eq!(commands.len(), 3);
        let mut flushed_batches = 0;
        for _cmd in commands {
            if let Some(batch) = batcher.enqueue(AppendEntriesRequest::heartbeat(1, "l", 0)) {
                flushed_batches += 1;
                assert_eq!(batch.len(), 2);
            }
        }
        assert_eq!(flushed_batches, 1);
        assert!(sched.poll(now + Duration::from_millis(10)).is_empty());
        assert_eq!(sched.poll(now + Duration::from_millis(55)).len(), 3);
    }
}
