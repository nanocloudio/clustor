use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

const CP_PLACEMENT_SPEC: &str = "§11.ControlPlaneRaft";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRecord {
    pub partition_id: String,
    pub routing_epoch: u64,
    pub lease_epoch: u64,
    pub members: Vec<String>,
}

#[derive(Debug, Clone)]
struct PlacementState {
    record: PlacementRecord,
    last_refresh: Instant,
}

#[derive(Debug)]
pub struct CpPlacementClient {
    placements: HashMap<String, PlacementState>,
    cache_grace: Duration,
}

impl CpPlacementClient {
    pub fn new(cache_grace: Duration) -> Self {
        Self {
            placements: HashMap::new(),
            cache_grace,
        }
    }

    pub fn update(&mut self, record: PlacementRecord, fetched_at: Instant) {
        info!(
            "event=cp_placement_update clause={} partition_id={} routing_epoch={} lease_epoch={} cache_grace_ms={}",
            CP_PLACEMENT_SPEC,
            record.partition_id,
            record.routing_epoch,
            record.lease_epoch,
            self.cache_grace.as_millis()
        );
        self.placements.insert(
            record.partition_id.clone(),
            PlacementState {
                record,
                last_refresh: fetched_at,
            },
        );
    }

    pub fn placement_snapshot(&self, partition_id: &str) -> Option<PlacementSnapshot> {
        self.placements
            .get(partition_id)
            .map(|state| PlacementSnapshot {
                record: state.record.clone(),
                last_refresh: state.last_refresh,
            })
    }

    pub fn validate_routing_epoch(
        &mut self,
        partition_id: &str,
        observed_epoch: u64,
        now: Instant,
    ) -> Result<PlacementSnapshot, RoutingEpochError> {
        let state = self.placements.get(partition_id).ok_or_else(|| {
            warn!(
                "event=cp_placement_guard clause={} outcome=unknown_partition partition_id={}",
                CP_PLACEMENT_SPEC, partition_id
            );
            RoutingEpochError::UnknownPartition {
                partition_id: partition_id.to_string(),
            }
        })?;
        if now.saturating_duration_since(state.last_refresh) > self.cache_grace {
            let age_ms = now
                .saturating_duration_since(state.last_refresh)
                .as_millis();
            warn!(
                "event=cp_placement_guard clause={} outcome=cache_expired partition_id={} age_ms={} cache_grace_ms={}",
                CP_PLACEMENT_SPEC,
                partition_id,
                age_ms,
                self.cache_grace.as_millis()
            );
            return Err(RoutingEpochError::CacheExpired {
                partition_id: partition_id.to_string(),
                last_refresh: state.last_refresh,
            });
        }
        if observed_epoch != state.record.routing_epoch {
            warn!(
                "event=cp_placement_guard clause={} outcome=epoch_mismatch partition_id={} expected={} observed={} lease_epoch={}",
                CP_PLACEMENT_SPEC,
                partition_id,
                state.record.routing_epoch,
                observed_epoch,
                state.record.lease_epoch
            );
            return Err(RoutingEpochError::EpochMismatch {
                partition_id: partition_id.to_string(),
                expected: state.record.routing_epoch,
                observed: observed_epoch,
                lease_epoch: state.record.lease_epoch,
            });
        }
        Ok(PlacementSnapshot {
            record: state.record.clone(),
            last_refresh: state.last_refresh,
        })
    }

    pub fn expire_partition(&mut self, partition_id: &str) {
        let removed = self.placements.remove(partition_id);
        if removed.is_some() {
            info!(
                "event=cp_placement_expire clause={} partition_id={}",
                CP_PLACEMENT_SPEC, partition_id
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementSnapshot {
    pub record: PlacementRecord,
    pub last_refresh: Instant,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingEpochError {
    #[error("partition {partition_id} not found in placement cache")]
    UnknownPartition { partition_id: String },
    #[error("routing epoch mismatch for {partition_id}: observed {observed}, expected {expected}")]
    EpochMismatch {
        partition_id: String,
        expected: u64,
        observed: u64,
        lease_epoch: u64,
    },
    #[error("routing epoch for {partition_id} is stale (last refresh at {last_refresh:?})")]
    CacheExpired {
        partition_id: String,
        last_refresh: Instant,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_routing_epoch_detects_mismatch() {
        let now = Instant::now();
        let mut client = CpPlacementClient::new(Duration::from_secs(5));
        client.update(
            PlacementRecord {
                partition_id: "p1".into(),
                routing_epoch: 10,
                lease_epoch: 7,
                members: vec!["a".into(), "b".into()],
            },
            now,
        );
        let err = client
            .validate_routing_epoch("p1", 9, now)
            .expect_err("mismatch expected");
        assert!(matches!(
            err,
            RoutingEpochError::EpochMismatch {
                partition_id,
                expected: 10,
                observed: 9,
                lease_epoch: 7
            } if partition_id == "p1"
        ));
    }

    #[test]
    fn validate_routing_epoch_detects_expiry() {
        let now = Instant::now();
        let mut client = CpPlacementClient::new(Duration::from_secs(1));
        client.update(
            PlacementRecord {
                partition_id: "p1".into(),
                routing_epoch: 10,
                lease_epoch: 7,
                members: vec![],
            },
            now,
        );
        let err = client
            .validate_routing_epoch("p1", 10, now + Duration::from_secs(5))
            .expect_err("cache should be stale");
        assert!(matches!(err, RoutingEpochError::CacheExpired { .. }));
    }
}
