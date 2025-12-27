#![cfg(feature = "snapshot-crypto")]

use clustor::persistence::snapshot::SnapshotReadiness;

pub fn readiness() -> SnapshotReadiness {
    SnapshotReadiness {
        manifest_id: "p1".into(),
        base_index: 100,
        content_hash: "0xabc".into(),
        applied_index_snapshot: 95,
        last_advertised_ready_index: 100,
        manifest_generated_ms: 42,
    }
}
