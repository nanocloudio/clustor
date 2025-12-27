#![cfg(feature = "snapshot-crypto")]

use clustor::persistence::snapshot::{
    CommitEpochEntry, DedupShardDigest, HmacManifestSigner, SnapshotManifest,
    SnapshotManifestBuilder,
};

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

#[allow(clippy::too_many_arguments)]
pub fn manifest_from_chunks(
    manifest_id: &str,
    kind: clustor::SnapshotKind,
    parent: Option<&str>,
    chain_length: u32,
    chunks: &[clustor::SnapshotChunkPayload],
    signer: &HmacManifestSigner,
    dek_epoch: u32,
    iv_salt: &str,
) -> SnapshotManifest {
    let mut builder = SnapshotManifestBuilder::new(manifest_id)
        .version_id(1)
        .producer("node", "emit")
        .base(1, 10)
        .encryption(dek_epoch, iv_salt.to_owned())
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
        .snapshot_kind(kind);
    if let Some(parent_id) = parent {
        builder = builder.delta_parent(parent_id, chain_length);
    }
    for chunk in chunks {
        builder = builder.add_chunk(chunk.chunk.clone());
    }
    builder.finalize(signer).unwrap().manifest
}
