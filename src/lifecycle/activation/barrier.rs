use std::collections::HashMap;

use super::digest::{readiness_digest, ActivationDigestError};
use super::state::{ShadowApplyState, WarmupReadinessRecord};

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
    ) -> Result<ActivationBarrierDecision, ActivationDigestError> {
        let relevant = readiness_for_barrier(barrier, readiness);
        let readiness_digest = readiness_digest(&relevant)?;
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
        Ok(ActivationBarrierDecision {
            barrier_id: barrier.barrier_id.clone(),
            bundle_id: barrier.bundle_id.clone(),
            state,
            readiness_digest,
        })
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
