use clustor::control_plane::core::{CpPlacementClient, PlacementRecord, RoutingEpochError};
use std::time::{Duration, Instant};

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
