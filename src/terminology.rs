//! Shared runtime terminology references backed by §1.3.1 of the spec.
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuntimeTerm {
    pub canonical: &'static str,
    pub term_id: &'static str,
}

impl RuntimeTerm {
    pub const fn new(canonical: &'static str, term_id: &'static str) -> Self {
        Self { canonical, term_id }
    }
}

pub const TERM_STRICT: RuntimeTerm = RuntimeTerm::new("Strict", "TERM-0001");
pub const TERM_GROUP_FSYNC: RuntimeTerm = RuntimeTerm::new("Group-Fsync", "TERM-0002");
pub const TERM_DURABILITY_RECORD: RuntimeTerm = RuntimeTerm::new("DurabilityRecord", "TERM-0003");
pub const TERM_FOLLOWER_READ_SNAPSHOT: RuntimeTerm =
    RuntimeTerm::new("FollowerReadSnapshot", "TERM-0004");
pub const TERM_LEASE_ENABLE: RuntimeTerm = RuntimeTerm::new("LeaseEnable", "TERM-0005");
pub const TERM_SNAPSHOT_DELTA: RuntimeTerm = RuntimeTerm::new("SnapshotDeltaEnable", "TERM-0006");

pub fn runtime_terms() -> &'static [RuntimeTerm] {
    &[
        TERM_STRICT,
        TERM_GROUP_FSYNC,
        TERM_DURABILITY_RECORD,
        TERM_FOLLOWER_READ_SNAPSHOT,
        TERM_LEASE_ENABLE,
        TERM_SNAPSHOT_DELTA,
    ]
}
