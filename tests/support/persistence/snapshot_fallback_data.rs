#![cfg(feature = "snapshot-crypto")]

use clustor::consensus::StrictFallbackState;
use clustor::persistence::snapshot::{
    CommitEpochEntry, DedupShardDigest, HmacManifestSigner, SnapshotManifest,
    SnapshotManifestBuilder, SnapshotReadRequest, SnapshotReadiness,
};

pub fn readiness() -> SnapshotReadiness {
    SnapshotReadiness {
        manifest_id: "m1".into(),
        base_index: 100,
        content_hash: "0xdeadbeef".into(),
        applied_index_snapshot: 90,
        last_advertised_ready_index: 100,
        manifest_generated_ms: 1_000,
    }
}

pub fn read_request(snapshot_only: bool, state: StrictFallbackState) -> SnapshotReadRequest {
    SnapshotReadRequest {
        partition_id: "p1".into(),
        read_semantics_snapshot_only: snapshot_only,
        strict_state: state,
        cp_cache_age_ms: 42,
    }
}

pub fn manifest() -> SnapshotManifest {
    let signer = HmacManifestSigner::new(b"manifest");
    SnapshotManifestBuilder::new("m1")
        .version_id(1)
        .producer("node", "emit")
        .base(1, 10)
        .encryption(2, "salt")
        .ap_pane_digest("0x1")
        .add_dedup_shard(DedupShardDigest {
            shard_id: "default".into(),
            ledger_epoch: 1,
            shard_digest: "0xaaa".into(),
        })
        .add_commit_epoch(CommitEpochEntry {
            dimension: "cp".into(),
            epoch: 5,
            checksum: "0xbeef".into(),
        })
        .finalize(&signer)
        .unwrap()
        .manifest
}

pub fn full_delta(id: &str, parent: &str, chain_length: u32) -> SnapshotManifest {
    let mut delta = manifest();
    delta.manifest_id = id.into();
    delta.snapshot_kind = clustor::SnapshotKind::Delta;
    delta.delta_parent_manifest_id = Some(parent.into());
    delta.delta_chain_length = chain_length;
    delta
}
