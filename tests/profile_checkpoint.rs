use clustor::{
    ConsensusCore, ConsensusCoreConfig, CpCachePolicy, CpCacheState, CpProofCoordinator,
    PartitionProfile, ProfileCapability, ProfileCapabilityRegistry,
};

#[test]
fn profile_checkpoint_partition_config_matches_spec() {
    let latency = PartitionProfile::Latency.config();
    assert_eq!(latency.ingest_ops_target, Some(50_000));
    assert_eq!(latency.throughput_alert_floor, Some(40_000));
    assert_eq!(latency.cp_durability_proof_ttl_ms, 43_200_000);

    let throughput = PartitionProfile::Throughput.config();
    assert_eq!(throughput.ingest_ops_target, Some(120_000));
    assert_eq!(throughput.throughput_alert_floor, Some(100_000));
    assert_eq!(throughput.cp_durability_proof_ttl_ms, 86_400_000);

    let wan = PartitionProfile::Wan.config();
    assert_eq!(wan.ingest_ops_target, Some(25_000));
    assert_eq!(wan.throughput_alert_floor, Some(20_000));
    assert_eq!(wan.strict_fallback_local_only_demote_ms, 21_600_000);

    let zfs = PartitionProfile::Zfs.config();
    assert!(zfs.ingest_ops_target.is_none());
    assert!(zfs.throughput_alert_floor.is_none());
}

#[test]
fn profile_checkpoint_consensus_core_uses_profile_windows() {
    let wan = ConsensusCoreConfig::for_profile(PartitionProfile::Wan);
    assert_eq!(wan.local_only_demote_after().as_millis(), 21_600_000u128);
    let latency = ConsensusCoreConfig::for_profile(PartitionProfile::Latency);
    assert_eq!(
        latency.local_only_demote_after().as_millis(),
        14_400_000u128
    );
}

#[test]
fn profile_checkpoint_cache_policy_expires_at_ttl() {
    let mut coordinator =
        CpProofCoordinator::new(ConsensusCore::new(ConsensusCoreConfig::default()));
    let policy = CpCachePolicy::for_profile(PartitionProfile::Throughput);
    assert_eq!(
        coordinator.apply_cache_policy(policy.ttl_ms() - 1, &policy),
        CpCacheState::Fresh
    );
    assert_eq!(
        coordinator.apply_cache_policy(policy.ttl_ms(), &policy),
        CpCacheState::Expired
    );
}

#[test]
fn profile_checkpoint_capability_gates_respect_matrix() {
    let registry = ProfileCapabilityRegistry::default();
    registry
        .guard_operation(
            PartitionProfile::Throughput,
            ProfileCapability::GroupFsync,
            "DurabilityTransition{to=Group}",
        )
        .expect("throughput allows group fsync");
    let group_err = registry
        .guard_operation(
            PartitionProfile::Latency,
            ProfileCapability::GroupFsync,
            "DurabilityTransition{to=Group}",
        )
        .expect_err("latency profile forbids group fsync");
    assert_eq!(group_err.capability, ProfileCapability::GroupFsync);
    assert!(group_err
        .operation
        .contains("DurabilityTransition{to=Group}"));

    let observers_err = registry
        .guard_operation(
            PartitionProfile::Latency,
            ProfileCapability::Observers,
            "EnableObservers",
        )
        .expect_err("latency forbids observers");
    assert_eq!(observers_err.profile, PartitionProfile::Latency);

    registry
        .guard_operation(
            PartitionProfile::Wan,
            ProfileCapability::Blake3HashSuite,
            "SwitchIntegrityHash(blake3)",
        )
        .expect("WAN allows BLAKE3");
    registry
        .guard_operation(
            PartitionProfile::Zfs,
            ProfileCapability::DeltaSnapshots,
            "EnableSnapshotDeltas",
        )
        .expect("ZFS allows delta snapshots");
    let blake_err = registry
        .guard_operation(
            PartitionProfile::Zfs,
            ProfileCapability::Blake3HashSuite,
            "SwitchIntegrityHash(blake3)",
        )
        .expect_err("ZFS forbids BLAKE3");
    assert_eq!(blake_err.capability, ProfileCapability::Blake3HashSuite);
    assert_eq!(blake_err.profile, PartitionProfile::Zfs);
}
