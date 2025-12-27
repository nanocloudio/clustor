use clustor::control_plane::capabilities::profile::{
    PartitionProfile, ProfileCapabilities, ProfileCapability, ProfileCapabilityError,
    ProfileCapabilityRegistry,
};
use clustor::telemetry::MetricsRegistry;
use std::collections::HashMap;
use std::str::FromStr;

#[test]
fn registry_blocks_missing_capability() {
    let mut map = HashMap::new();
    map.insert(
        PartitionProfile::Throughput,
        ProfileCapabilities::new([ProfileCapability::Aggregator]),
    );
    let registry = ProfileCapabilityRegistry::with_capabilities(map);
    registry
        .ensure_aggregator_allowed(PartitionProfile::Throughput)
        .unwrap();
    assert!(matches!(
        registry.ensure_aggregator_allowed(PartitionProfile::Latency),
        Err(ProfileCapabilityError::CapabilityForbidden { .. })
    ));
}

#[test]
fn partition_profile_from_str() {
    assert_eq!(
        PartitionProfile::from_str("Wan").unwrap(),
        PartitionProfile::Wan
    );
    assert!(PartitionProfile::from_str("unknown").is_err());
}

#[test]
fn registry_emits_capability_metrics() {
    let registry = ProfileCapabilityRegistry::default();
    let mut metrics = MetricsRegistry::new("clustor");
    registry.record_metrics(&mut metrics);
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.gauges["clustor.profile.capability.latency.aggregator"],
        1
    );
    assert_eq!(
        snapshot.gauges["clustor.profile.capability.latency.group_fsync"],
        0
    );
    assert_eq!(
        snapshot.gauges["clustor.profile.capability.throughput.group_fsync"],
        1
    );
}
