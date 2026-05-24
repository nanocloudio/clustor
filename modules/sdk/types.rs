//! Shared Raft types for all clustor fluxor modules.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface so single-module rustc invocations see unused items"
)]

pub type Term = u64;
pub type Index = u64;
pub type ReplicaId = u8;
pub type Epoch = u32;

pub const MAX_NODES: usize = 7;

/// Replica slot is unused / not configured.
pub const REPLICA_NONE: i8 = -1;

/// Raft roles.
pub const ROLE_FOLLOWER: u8 = 0;
pub const ROLE_CANDIDATE: u8 = 1;
pub const ROLE_LEADER: u8 = 2;

/// Durability modes.
pub const DUR_STRICT: u8 = 0;
pub const DUR_GROUP_FSYNC: u8 = 1;
pub const DUR_RELAXED: u8 = 2;

/// CP cache states.
pub const CP_FRESH: u8 = 0;
pub const CP_CACHED: u8 = 1;
pub const CP_STALE: u8 = 2;
pub const CP_EXPIRED: u8 = 3;

/// Per-replica replication progress (used by commit_tracker, durability_ledger, replicator).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReplicaProgress {
    pub match_index: Index,
    pub match_term: Term,
    pub next_index: Index,
}

impl ReplicaProgress {
    pub const fn zero() -> Self {
        Self {
            match_index: 0,
            match_term: 0,
            next_index: 1,
        }
    }
}

/// Bit width of [`NodeSet`]. Bigger replica counts need a wider
/// bitmask type, not an incremental tweak — bumping past 8 is an
/// ABI change.
pub const NODE_SET_CAPACITY: u8 = 8;

/// Compact bitmask set for up to [`NODE_SET_CAPACITY`] replicas.
///
/// The backing storage is a `u8`, so the valid id range is
/// `0..NODE_SET_CAPACITY`. Out-of-range ids would shift past the
/// type's width (undefined behaviour). All mutators / queries guard
/// against this: `insert` / `remove` are no-ops, `contains` returns
/// `false`. Voter ids beyond [`MAX_NODES`] are caught earlier by the
/// per-module `voter_count` clamp at `module_new` time; this guard
/// is the second line of defence.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NodeSet(pub u8);

impl NodeSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn insert(&mut self, id: ReplicaId) {
        if id < NODE_SET_CAPACITY {
            self.0 |= 1u8 << id;
        }
    }

    pub fn remove(&mut self, id: ReplicaId) {
        if id < NODE_SET_CAPACITY {
            self.0 &= !(1u8 << id);
        }
    }

    pub fn contains(self, id: ReplicaId) -> bool {
        if id >= NODE_SET_CAPACITY {
            return false;
        }
        (self.0 & (1u8 << id)) != 0
    }

    pub fn count(self) -> u8 {
        self.0.count_ones() as u8
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

/// Compute quorum index from a fixed-size progress array.
/// Returns the median match_index among the first `voter_count` slots
/// (i.e. the highest index replicated on a majority).
///
/// `voter_count` is clamped to `MAX_NODES` so a misconfigured module
/// can't trigger a slice panic. Modules should still clamp at
/// `module_new` time; this is the safety net.
pub fn quorum_index(progress: &[Index; MAX_NODES], voter_count: u8) -> Index {
    let n = (voter_count as usize).min(MAX_NODES);
    if n == 0 {
        return 0;
    }
    // Copy to scratch and sort descending.
    let mut scratch = [0u64; MAX_NODES];
    scratch[..n].copy_from_slice(&progress[..n]);
    // Simple insertion sort (n <= 7, always fast).
    for i in 1..n {
        let key = scratch[i];
        let mut j = i;
        while j > 0 && scratch[j - 1] < key {
            scratch[j] = scratch[j - 1];
            j -= 1;
        }
        scratch[j] = key;
    }
    // Quorum position: majority = (n / 2) + 1, index = majority - 1.
    let quorum_pos = n / 2; // e.g. n=3 → pos=1, n=5 → pos=2
    scratch[quorum_pos]
}

/// Compute quorum index across a named voter set. Returns the highest
/// `match_index` value replicated on a majority of the listed
/// replicas. Joint-consensus callers compute this twice (once per
/// configuration) and take the minimum.
pub fn quorum_index_for_set(progress: &[Index; MAX_NODES], voters: NodeSet) -> Index {
    let n = voters.count() as usize;
    if n == 0 {
        return 0;
    }
    let mut scratch = [0u64; MAX_NODES];
    let mut k = 0;
    for (id, &p) in progress.iter().enumerate() {
        if voters.contains(id as ReplicaId) {
            scratch[k] = p;
            k += 1;
        }
    }
    // Sort descending.
    for i in 1..k {
        let key = scratch[i];
        let mut j = i;
        while j > 0 && scratch[j - 1] < key {
            scratch[j] = scratch[j - 1];
            j -= 1;
        }
        scratch[j] = key;
    }
    let quorum_pos = k / 2;
    scratch[quorum_pos]
}
