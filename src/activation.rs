use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShadowApplyState {
    Pending,
    Replaying,
    Ready,
    Expired,
}

impl ShadowApplyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShadowApplyState::Pending => "Pending",
            ShadowApplyState::Replaying => "Replaying",
            ShadowApplyState::Ready => "Ready",
            ShadowApplyState::Expired => "Expired",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupReadinessRecord {
    pub partition_id: String,
    pub bundle_id: String,
    pub shadow_apply_state: ShadowApplyState,
    pub shadow_apply_checkpoint_index: u64,
    pub warmup_ready_ratio: f64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct WarmupReadinessSnapshot {
    pub records: Vec<WarmupReadinessRecord>,
    pub publish_period_ms: u64,
    pub skipped_publications_total: u64,
}

impl WarmupReadinessSnapshot {
    pub fn readiness_for(&self, partition_id: &str) -> Option<&WarmupReadinessRecord> {
        self.records
            .iter()
            .find(|record| record.partition_id == partition_id)
    }
}

#[derive(Debug)]
pub struct WarmupReadinessPublisher {
    publish_period_ms: u64,
    skipped_publications_total: u64,
    last_publish_ms: Option<u64>,
    records: HashMap<String, WarmupReadinessRecord>,
}

impl WarmupReadinessPublisher {
    pub fn new(publish_period_ms: u64) -> Self {
        Self {
            publish_period_ms: publish_period_ms.max(1),
            skipped_publications_total: 0,
            last_publish_ms: None,
            records: HashMap::new(),
        }
    }

    pub fn publish_period_ms(&self) -> u64 {
        self.publish_period_ms
    }

    pub fn skipped_publications_total(&self) -> u64 {
        self.skipped_publications_total
    }

    pub fn upsert(&mut self, record: WarmupReadinessRecord) {
        self.records.insert(record.partition_id.clone(), record);
    }

    pub fn snapshot(&mut self, now_ms: u64) -> WarmupReadinessSnapshot {
        if let Some(last) = self.last_publish_ms {
            if now_ms.saturating_sub(last) > self.publish_period_ms.saturating_mul(2) {
                self.skipped_publications_total = self.skipped_publications_total.saturating_add(1);
            }
        }
        self.last_publish_ms = Some(now_ms);
        let mut records: Vec<_> = self.records.values().cloned().collect();
        records.sort_by(|a, b| a.partition_id.cmp(&b.partition_id));
        WarmupReadinessSnapshot {
            records,
            publish_period_ms: self.publish_period_ms,
            skipped_publications_total: self.skipped_publications_total,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActivationBarrier {
    pub barrier_id: String,
    pub bundle_id: String,
    pub partitions: Vec<String>,
    pub readiness_threshold: f64,
    pub warmup_deadline_ms: u64,
    pub readiness_window_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationBarrierState {
    Ready,
    Pending { missing_partitions: Vec<String> },
    Expired,
}

#[derive(Debug, Clone)]
pub struct ActivationBarrierDecision {
    pub barrier_id: String,
    pub bundle_id: String,
    pub state: ActivationBarrierState,
    pub readiness_digest: String,
}

pub struct ActivationBarrierEvaluator;

impl ActivationBarrierEvaluator {
    pub fn evaluate(
        barrier: &ActivationBarrier,
        readiness: &[WarmupReadinessRecord],
        now_ms: u64,
    ) -> ActivationBarrierDecision {
        let relevant = readiness_for_barrier(barrier, readiness);
        let readiness_digest = readiness_digest(&relevant);
        let missing = missing_partitions(barrier, &relevant, now_ms);
        let state = if now_ms > barrier.warmup_deadline_ms {
            ActivationBarrierState::Expired
        } else if missing.is_empty() {
            ActivationBarrierState::Ready
        } else {
            ActivationBarrierState::Pending {
                missing_partitions: missing,
            }
        };
        ActivationBarrierDecision {
            barrier_id: barrier.barrier_id.clone(),
            bundle_id: barrier.bundle_id.clone(),
            state,
            readiness_digest,
        }
    }
}

fn readiness_for_barrier(
    barrier: &ActivationBarrier,
    readiness: &[WarmupReadinessRecord],
) -> Vec<WarmupReadinessRecord> {
    let partitions: HashMap<_, _> = readiness
        .iter()
        .filter(|record| record.bundle_id == barrier.bundle_id)
        .map(|record| (record.partition_id.clone(), record.clone()))
        .collect();
    let mut records = Vec::new();
    for partition in &barrier.partitions {
        if let Some(record) = partitions.get(partition) {
            records.push(record.clone());
        }
    }
    records
}

fn missing_partitions(
    barrier: &ActivationBarrier,
    readiness: &[WarmupReadinessRecord],
    now_ms: u64,
) -> Vec<String> {
    let mut readiness_map: HashMap<_, _> = readiness
        .iter()
        .map(|record| (record.partition_id.clone(), record))
        .collect();
    let mut missing = Vec::new();
    for partition in &barrier.partitions {
        match readiness_map.remove(partition) {
            Some(record) => {
                if record.shadow_apply_state != ShadowApplyState::Ready {
                    missing.push(partition.clone());
                    continue;
                }
                if record.warmup_ready_ratio + f64::EPSILON < barrier.readiness_threshold {
                    missing.push(partition.clone());
                    continue;
                }
                if barrier.readiness_window_ms > 0
                    && now_ms.saturating_sub(record.updated_at_ms) > barrier.readiness_window_ms
                {
                    missing.push(partition.clone());
                }
            }
            None => missing.push(partition.clone()),
        }
    }
    missing.sort();
    missing
}

pub fn readiness_digest(records: &[WarmupReadinessRecord]) -> String {
    if records.is_empty() {
        return "0x0".into();
    }
    let mut encoded = Vec::with_capacity(records.len());
    for record in records {
        let payload = serde_json::json!({
            "partition": record.partition_id,
            "bundle": record.bundle_id,
            "state": record.shadow_apply_state.as_str(),
            "checkpoint": record.shadow_apply_checkpoint_index,
            "ratio": (record.warmup_ready_ratio * 10_000.0).round() as i64,
            "updated_at_ms": record.updated_at_ms,
        });
        encoded.push(serde_json::to_string(&payload).unwrap());
    }
    encoded.sort();
    let joined = encoded.join("|");
    format!("0x{}", hex::encode(Sha256::digest(joined.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn barrier() -> ActivationBarrier {
        ActivationBarrier {
            barrier_id: "barrier-1".into(),
            bundle_id: "bundle-1".into(),
            partitions: vec!["p1".into(), "p2".into()],
            readiness_threshold: 0.8,
            warmup_deadline_ms: 10_000,
            readiness_window_ms: 5_000,
        }
    }

    fn record(partition: &str, ratio: f64, updated_at: u64) -> WarmupReadinessRecord {
        WarmupReadinessRecord {
            partition_id: partition.into(),
            bundle_id: "bundle-1".into(),
            shadow_apply_state: ShadowApplyState::Ready,
            shadow_apply_checkpoint_index: 42,
            warmup_ready_ratio: ratio,
            updated_at_ms: updated_at,
        }
    }

    #[test]
    fn barrier_ready_when_all_partitions_ready() {
        let barrier = barrier();
        let readiness = vec![record("p1", 0.9, 8_000), record("p2", 0.85, 8_500)];
        let decision = ActivationBarrierEvaluator::evaluate(&barrier, &readiness, 9_000);
        assert!(matches!(decision.state, ActivationBarrierState::Ready));
        assert!(decision.readiness_digest.starts_with("0x"));
    }

    #[test]
    fn barrier_pending_when_partition_missing_or_stale() {
        let barrier = barrier();
        let readiness = vec![record("p1", 0.9, 6_500)];
        let decision = ActivationBarrierEvaluator::evaluate(&barrier, &readiness, 7_000);
        match decision.state {
            ActivationBarrierState::Pending { missing_partitions } => {
                assert_eq!(missing_partitions, vec!["p2"])
            }
            other => panic!("unexpected state {other:?}"),
        }
    }

    #[test]
    fn barrier_expires_after_deadline() {
        let barrier = barrier();
        let readiness = vec![record("p1", 0.9, 8_000), record("p2", 0.85, 8_500)];
        let decision = ActivationBarrierEvaluator::evaluate(&barrier, &readiness, 15_000);
        assert!(matches!(decision.state, ActivationBarrierState::Expired));
    }

    #[test]
    fn readiness_publisher_tracks_period_and_skipped_publications() {
        let mut publisher = WarmupReadinessPublisher::new(1_000);
        publisher.upsert(record("p1", 0.9, 1_000));
        let snapshot = publisher.snapshot(1_000);
        assert_eq!(snapshot.publish_period_ms, 1_000);
        assert_eq!(snapshot.skipped_publications_total, 0);
        assert_eq!(snapshot.records.len(), 1);

        // Publish after a large delay to trigger skipped counter.
        publisher.upsert(record("p2", 0.8, 3_000));
        let snapshot = publisher.snapshot(4_500);
        assert_eq!(snapshot.records.len(), 2);
        assert_eq!(snapshot.skipped_publications_total, 1);
        assert!(snapshot.readiness_for("p2").is_some());
    }
}
