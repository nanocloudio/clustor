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

/// Per-replica replication progress (used by consensus, durability, replicator).
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
    // NodeSet holds NODE_SET_CAPACITY (8) ids but `progress` has
    // MAX_NODES (7) slots. A member with no progress slot still counts
    // toward the majority denominator, as a permanent zero: otherwise a
    // 4-voter set containing id 7 would take its median over 3 and
    // commit without a true majority.
    let mut scratch = [0u64; NODE_SET_CAPACITY as usize];
    let mut k = 0;
    for id in 0..NODE_SET_CAPACITY {
        if voters.contains(id) {
            scratch[k] = if (id as usize) < MAX_NODES {
                progress[id as usize]
            } else {
                0
            };
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

// ── Site-aware quorum (the multi-site group) ────────────────────────────
//
// A group whose voters span sites (failure domains a whole power, network
// or building loss takes out together) counts a quorum as a majority of
// the voter set that ALSO spans at least `min_sites` distinct sites. The
// majority half is Raft's: any two quorums share a voter, so safety is
// unchanged; the site half only removes quorums, so an entry is committed,
// a leader elected and a ReadIndex confirmed only with copies in
// `min_sites` sites — a committed entry survives the loss of any
// `min_sites - 1` sites whole. `SiteMap::flat()` (every replica in site 0,
// `min_sites` 1) is plain majority, so a graph that declares no sites is
// the group it always was. docs/architecture/multi_site.md is the design.

/// Bits of `SiteMap::sites` per replica: up to 16 sites.
pub const SITE_BITS: u32 = 4;
/// The most distinct sites a map can name.
pub const SITE_MAX: usize = 16;

/// Each replica id's site, `SITE_BITS` per id (id 0 lowest), and the
/// fewest distinct sites a quorum must span.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SiteMap {
    pub sites: u32,
    pub min_sites: u8,
}

/// Why a voter set's placement cannot do what its map asks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SiteFault {
    /// The voters span fewer sites than `min_sites`: no quorum can ever form.
    TooFewSites { spanned: u8, min_sites: u8 },
    /// Losing this site leaves no quorum: the voters left are not a
    /// majority, or span fewer than `min_sites` sites.
    LossOf { site: u8 },
}

impl SiteMap {
    /// Every replica in one site, a quorum a plain majority.
    pub const fn flat() -> Self {
        Self {
            sites: 0,
            min_sites: 1,
        }
    }

    /// The map a graph declares: `sites` packed `SITE_BITS` per replica id,
    /// `min_sites` clamped to at least 1.
    pub const fn new(sites: u32, min_sites: u8) -> Self {
        Self {
            sites,
            min_sites: if min_sites == 0 { 1 } else { min_sites },
        }
    }

    /// Whether this map asks anything beyond a plain majority.
    pub const fn is_flat(self) -> bool {
        self.min_sites <= 1
    }

    /// Replica `id`'s site.
    pub const fn site_of(self, id: ReplicaId) -> u8 {
        if id as u32 >= 32 / SITE_BITS {
            return 0;
        }
        ((self.sites >> (id as u32 * SITE_BITS)) & ((1 << SITE_BITS) - 1)) as u8
    }

    /// The distinct sites the members of `set` sit in.
    pub fn spanned(self, set: NodeSet) -> u8 {
        let mut seen: u16 = 0;
        for id in 0..NODE_SET_CAPACITY {
            if set.contains(id) {
                seen |= 1u16 << self.site_of(id);
            }
        }
        seen.count_ones() as u8
    }

    /// Whether `votes` is a quorum of `voters`: a majority of the set that
    /// spans at least `min_sites` sites.
    pub fn quorum(self, votes: NodeSet, voters: NodeSet) -> bool {
        let inside = NodeSet(votes.0 & voters.0);
        inside.count() > voters.count() / 2 && self.spanned(inside) >= self.min_sites
    }

    /// Whether the group stays live with any one site gone whole: the
    /// voters can form a quorum at all, and with every voter of any one of
    /// their sites removed the rest are still a majority of the set across
    /// `min_sites` sites. A group that passes this survives a site loss
    /// with no reconfiguration; one that fails it (two sites with
    /// `min_sites` 2 — every commit in both, RPO zero) stops committing
    /// until an operator acts.
    pub fn check(self, voters: NodeSet) -> Result<(), SiteFault> {
        let spanned = self.spanned(voters);
        if spanned < self.min_sites {
            return Err(SiteFault::TooFewSites {
                spanned,
                min_sites: self.min_sites,
            });
        }
        let mut done: u16 = 0;
        for id in 0..NODE_SET_CAPACITY {
            if !voters.contains(id) {
                continue;
            }
            let site = self.site_of(id);
            if done & (1u16 << site) != 0 {
                continue;
            }
            done |= 1u16 << site;
            let mut left = voters;
            for j in 0..NODE_SET_CAPACITY {
                if self.site_of(j) == site {
                    left.remove(j);
                }
            }
            if !self.quorum(left, voters) {
                return Err(SiteFault::LossOf { site });
            }
        }
        Ok(())
    }
}

/// The highest index replicated on a quorum of `voters` under `map`: the
/// largest `progress` value whose holders (every voter at or past it) are
/// a majority spanning `map.min_sites` sites. Under a flat map this is
/// `quorum_index_for_set`. A member with no progress slot counts as a
/// permanent zero, as there.
pub fn quorum_index_sited(progress: &[Index; MAX_NODES], voters: NodeSet, map: SiteMap) -> Index {
    if map.is_flat() {
        return quorum_index_for_set(progress, voters);
    }
    let at = |id: u8| -> Index {
        if (id as usize) < MAX_NODES {
            progress[id as usize]
        } else {
            0
        }
    };
    let mut best: Index = 0;
    for c in 0..NODE_SET_CAPACITY {
        if !voters.contains(c) {
            continue;
        }
        let candidate = at(c);
        if candidate <= best {
            continue;
        }
        let mut holders = NodeSet::empty();
        for id in 0..NODE_SET_CAPACITY {
            if voters.contains(id) && at(id) >= candidate {
                holders.insert(id);
            }
        }
        if map.quorum(holders, voters) {
            best = candidate;
        }
    }
    best
}

/// `quorum_index_sited` over the first `voter_count` ids (a group that has
/// seen no voter-set update yet).
pub fn quorum_index_count_sited(
    progress: &[Index; MAX_NODES],
    voter_count: u8,
    map: SiteMap,
) -> Index {
    if map.is_flat() {
        return quorum_index(progress, voter_count);
    }
    let mut voters = NodeSet::empty();
    for id in 0..(voter_count as usize).min(MAX_NODES) {
        voters.insert(id as u8);
    }
    quorum_index_sited(progress, voters, map)
}
