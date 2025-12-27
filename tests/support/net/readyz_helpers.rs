use clustor::control_plane::core::CpCacheState;
use clustor::lifecycle::activation::{ShadowApplyState, WarmupReadinessRecord};
use clustor::{
    ConsensusCoreStatus, DemotionStatus, FeatureCapabilityMatrix, FeatureManifestBuilder,
    LocalRole, PartitionQuorumStatus, ReadyStateProbe, ReadyzPublisher, ReadyzSnapshot,
    StrictFallbackState, WhyNotLeader, WhyPublisher, WhySchemaHeader,
};
use ed25519_dalek::SigningKey;

fn snapshot(partition: &str) -> ReadyzSnapshot {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let manifest = FeatureManifestBuilder::new()
        .build(&signing_key)
        .expect("feature manifest");
    let matrix = FeatureCapabilityMatrix::from_manifest(&manifest).expect("capability matrix");
    let probe = ReadyStateProbe {
        readiness: WarmupReadinessRecord {
            partition_id: partition.into(),
            bundle_id: "bundle-a".into(),
            shadow_apply_state: ShadowApplyState::Pending,
            shadow_apply_checkpoint_index: 0,
            warmup_ready_ratio: 1.0,
            updated_at_ms: 0,
        },
        activation_barrier_id: Some("barrier-a".into()),
        partition_ready_ratio: 1.0,
    };
    ReadyzSnapshot::new(
        vec![probe],
        1_000,
        0,
        &matrix,
        manifest.digest().expect("manifest digest"),
        Vec::new(),
    )
    .expect("readyz snapshot")
}

pub fn sample_readyz_publisher(partition: &str) -> ReadyzPublisher {
    ReadyzPublisher::new(snapshot(partition))
}

pub fn sample_why_publisher(partition: &str) -> WhyPublisher {
    let publisher = WhyPublisher::default();
    let header = WhySchemaHeader::new(partition, 1, 1, 0);
    let consensus = ConsensusCoreStatus {
        state: StrictFallbackState::Healthy,
        strict_fallback: true,
        pending_entries: 0,
        local_only_duration: None,
        should_alert: false,
        demotion: DemotionStatus::none(),
        last_local_proof: None,
        last_published_proof: None,
        decision_epoch: 0,
        blocking_reason: None,
    };
    let quorum_status = PartitionQuorumStatus {
        committed_index: 0,
        committed_term: 0,
        quorum_size: 1,
    };
    let not_leader = WhyNotLeader::from_status(
        header,
        Some("replica-a".into()),
        LocalRole::Leader,
        CpCacheState::Fresh,
        consensus,
        quorum_status,
        None,
    );
    publisher.update_not_leader(partition, not_leader);
    publisher
}
