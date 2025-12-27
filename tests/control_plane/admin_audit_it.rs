#![cfg(feature = "admin-http")]

use clustor::control_plane::admin::{AdminAuditRecord, AdminAuditStore};
use clustor::SystemLogEntry;
use std::time::Instant;

#[test]
fn audit_store_evicts_and_spills_records() {
    let mut log = AdminAuditStore::new(2);
    let mut spill = Vec::new();
    for id in ["a", "b", "c"] {
        let evicted = log.record(AdminAuditRecord {
            action: format!("test-{id}"),
            partition_id: id.into(),
            reason: Some("reason".into()),
            recorded_at: Instant::now(),
            spec_clause: "§1".into(),
        });
        if let Some(record) = evicted {
            spill.push(SystemLogEntry::AdminAuditSpill {
                action: record.action,
                partition_id: record.partition_id,
                reason: record.reason,
            });
        }
    }
    assert_eq!(log.len(), 2);
    assert_eq!(spill.len(), 1);
    assert!(matches!(spill[0], SystemLogEntry::AdminAuditSpill { .. }));
}
