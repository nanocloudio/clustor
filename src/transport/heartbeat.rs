use crate::raft::ReplicaId;
use crate::telemetry::MetricsRegistry;
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
            lag_ms: 0,
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

    pub fn record_ack(&mut self, replica: &ReplicaId, now: Instant, lag_ms: u64) {
        if let Some(state) = self.followers.get_mut(replica) {
            state.last_ack = Some(now);
            state.lag_ms = lag_ms;
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
