#![cfg(feature = "snapshot-crypto")]

use clustor::snapshot::{
    HmacManifestSigner, SnapshotAuthorizer, SnapshotChunkExporter, SnapshotChunkImporter,
    SnapshotExportProfile, SnapshotManifestBuilder,
};
use clustor::storage::{DataEncryptionKey, ManifestAuthorizationLog, StorageLayout};
use std::error::Error;
use std::fs;
use std::io::Cursor;
use tempfile::TempDir;

#[test]
fn snapshot_export_import_and_authorize_flow() -> Result<(), Box<dyn Error>> {
    let tmp = TempDir::new()?;
    let data_dir = tmp.path().join("state");
    let layout = StorageLayout::new(&data_dir);
    layout.ensure()?;
    let manifest_dir = layout.paths().snapshot_dir.clone();
    fs::create_dir_all(&manifest_dir)?;
    let manifest_path = manifest_dir.join("manifest.json");
    fs::write(&manifest_path, b"{}")?;

    let key = DataEncryptionKey::new(7, [3u8; 32]);
    let exporter = SnapshotChunkExporter::new(SnapshotExportProfile::Throughput, &key, "salt");
    let payload = vec![42u8; 32 * 1024 + 513];
    let chunks = exporter.export_reader("snap-1", Cursor::new(&payload), 8 * 1024)?;
    assert!(!chunks.is_empty());

    let importer = SnapshotChunkImporter::new(&key, "salt");
    let mut recovered = Vec::new();
    for chunk in &chunks {
        let bytes = importer.import_chunk("snap-1", chunk)?;
        recovered.extend_from_slice(&bytes);
    }
    assert_eq!(&recovered[..payload.len()], &payload[..]);

    let mut builder = SnapshotManifestBuilder::new("snap-1");
    builder = builder
        .version_id(2)
        .producer("node-a", "integration")
        .base(10, payload.len() as u64)
        .encryption(key.epoch, "salt");
    for chunk in &chunks {
        builder = builder.add_chunk(chunk.chunk.clone());
    }
    let signer = HmacManifestSigner::new(b"integration-test-key");
    let signed = builder.finalize(&signer)?;

    let log = ManifestAuthorizationLog::new(layout.paths().manifest_authorizations.clone());
    let authorizer = SnapshotAuthorizer::new(log);
    let record = authorizer.authorize(&manifest_path, &signed, 9, 1_234_567)?;
    assert_eq!(record.manifest_id, "snap-1");
    assert_eq!(record.base_index, signed.manifest.base_index);

    Ok(())
}
