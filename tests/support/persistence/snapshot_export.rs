#![cfg(feature = "snapshot-crypto")]

use clustor::persistence::snapshot::SnapshotExportProfile;
use clustor::storage::DataEncryptionKey;
use std::io::Cursor;

pub fn export_chunks(
    manifest_id: &str,
    profile: SnapshotExportProfile,
    key: &DataEncryptionKey,
    payload: &[u8],
    chunk_size: usize,
) -> Vec<clustor::SnapshotChunkPayload> {
    clustor::SnapshotChunkExporter::new(profile, key, "salt")
        .export_reader(manifest_id, Cursor::new(payload), chunk_size)
        .expect("snapshot chunks")
}
