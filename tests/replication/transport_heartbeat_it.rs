use clustor::replication::raft::quorum::ReplicaId;
use clustor::replication::raft::{AppendEntriesRequest, HeartbeatBatcher, RaftRouting};
use clustor::replication::transport::heartbeat::{HeartbeatScheduler, LagClass};
use clustor::telemetry::MetricsRegistry;
use std::time::{Duration, Instant};

fn routing(epoch: u64) -> RaftRouting {
    RaftRouting::alias("partition-test", epoch)
}

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
    assert!(cmd.timeout >= Duration::from_millis(100));
    assert!(cmd.timeout <= Duration::from_millis(1_000));
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
    sched.record_ack(&replica, now, 30_000 + 1);
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
        if let Some(batch) = batcher.enqueue(AppendEntriesRequest::heartbeat(1, "l", 0, routing(1)))
        {
            flushed_batches += 1;
            assert_eq!(batch.len(), 2);
        }
    }
    assert_eq!(flushed_batches, 1);
    assert!(sched.poll(now + Duration::from_millis(10)).is_empty());
    assert_eq!(sched.poll(now + Duration::from_millis(55)).len(), 3);
}
