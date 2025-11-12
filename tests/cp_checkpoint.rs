use clustor::{
    ConsensusCore, ConsensusCoreConfig, CpCacheState, CpPlacementClient, CpProofCoordinator,
    PlacementRecord, RoutingEpochError,
};
use std::time::{Duration, Instant};

#[test]
fn cp_outage_forces_strict_backpressure() {
    let now = Instant::now();
    let mut placements = CpPlacementClient::new(Duration::from_secs(5));
    placements.update(
        PlacementRecord {
            partition_id: "p1".into(),
            routing_epoch: 5,
            lease_epoch: 2,
            members: vec!["a".into(), "b".into()],
        },
        now,
    );
    placements
        .validate_routing_epoch("p1", 5, now)
        .expect("fresh routing epoch");

    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let mut coordinator = CpProofCoordinator::new(kernel);
    coordinator
        .consensus_core_mut()
        .enter_strict_fallback(clustor::DurabilityProof::new(1, 10), now);
    coordinator.set_cache_state(CpCacheState::Stale { age_ms: 270_000 });

    let err = placements
        .validate_routing_epoch("p1", 5, now + Duration::from_secs(10))
        .expect_err("should be stale");
    assert!(matches!(err, RoutingEpochError::CacheExpired { .. }));
    let read_err = coordinator
        .guard_read_index(now + Duration::from_secs(10))
        .expect_err("strict fallback should block read index");
    assert!(matches!(
        read_err.response().reason,
        clustor::CpUnavailableReason::NeededForReadIndex
    ));
}

#[test]
fn cp_cache_expiry_recovers_after_republish() {
    let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
    let policy = clustor::CpCachePolicy::new(1_000).with_cache_windows(100, 1_000);
    let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
    let now = Instant::now();
    coordinator.publish_cp_proof_at(clustor::DurabilityProof::new(2, 20), now);
    assert!(coordinator
        .guard_read_index(now + Duration::from_millis(500))
        .is_ok());
    let err = coordinator
        .guard_read_index(now + Duration::from_millis(2_000))
        .expect_err("cache expiry should block");
    assert!(matches!(
        err.response().reason,
        clustor::CpUnavailableReason::CacheExpired
    ));
    coordinator.publish_cp_proof_at(
        clustor::DurabilityProof::new(2, 25),
        now + Duration::from_millis(2_500),
    );
    assert!(coordinator
        .guard_read_index(now + Duration::from_millis(2_500))
        .is_ok());
}
