// Slot index and slot set — the bounded bookkeeping every profile-sized
// directory namespace keeps beside its arena.
//
// Pure no_std, zero-alloc, DETERMINISTIC. A registry arena is a fixed array
// of records addressed by slot number. `SlotIndex` maps an opaque
// fixed-width identity (a session id, a flow id, a VIP key, a deadline's
// owner and id) to the slot holding it; `SlotSet` tracks which slots are
// occupied and hands out the lowest free one. Both cost O(1) to O(log N) per
// operation at any occupancy, up to a completely full arena — the profiles
// admit their whole arena, so a structure that degrades near full load
// would degrade exactly where a deployment runs.
//
// Both are derived state: rebuilt from the arena on snapshot restore and
// never serialized. Every query they answer is a pure function of the arena
// they describe, so a replica that rebuilt them from a snapshot answers
// exactly as one that built them by applying the log.

/// FNV-1a 64-bit offset basis and prime (stock parameters, mirrored from
/// `wire.rs` so this file mounts without it).
const FNV1A_64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit hash of a byte slice: the hash `wire.rs` shards routing
/// keys with. A fixed mix, never the language default, so every replica
/// builds the same chains.
#[inline]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h = FNV1A_64_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(FNV1A_64_PRIME);
        i += 1;
    }
    h
}

/// No slot: the end of a chain, or an empty bucket.
const NIL: u32 = u32::MAX;

/// Hash index of `N` entries keyed by `[u8; K]`, one entry per arena slot.
///
/// Separate chaining through the slots themselves: `N` buckets (`N` a power
/// of two), each the head of a chain linked through `next`, and the key of
/// every indexed slot kept in `keys`. At a full arena the load factor is
/// one, where a lookup inspects about 1.5 entries on average — unlike open
/// addressing, whose probe for an absent key degrades to all `N` entries as
/// the table fills. Chain order depends on insertion history, but no answer
/// does: a key is found in its chain or it is absent.
#[repr(C)]
pub struct SlotIndex<const N: usize, const K: usize> {
    heads: [u32; N],
    next: [u32; N],
    keys: [[u8; K]; N],
    pub live: u32,
}

impl<const N: usize, const K: usize> Default for SlotIndex<N, K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const K: usize> SlotIndex<N, K> {
    const SHAPE_OK: () = assert!(
        N.is_power_of_two() && N < NIL as usize,
        "slot index: N must be a power of two below u32::MAX"
    );

    pub const fn new() -> Self {
        let () = Self::SHAPE_OK;
        SlotIndex {
            heads: [NIL; N],
            next: [NIL; N],
            keys: [[0; K]; N],
            live: 0,
        }
    }

    /// Reset in place (a profile-sized index is too large to build on the
    /// stack and copy). Only the bucket heads need clearing: `next` and
    /// `keys` are written before a slot is ever reachable.
    pub fn reset(&mut self) {
        let mut i = 0;
        while i < N {
            self.heads[i] = NIL;
            i += 1;
        }
        self.live = 0;
    }

    #[inline]
    fn bucket(key: &[u8; K]) -> usize {
        (fnv1a_64(key) & (N as u64 - 1)) as usize
    }

    /// Slot holding `key`, if indexed.
    pub fn find(&self, key: &[u8; K]) -> Option<u32> {
        let mut s = self.heads[Self::bucket(key)];
        while s != NIL {
            if self.keys[s as usize] == *key {
                return Some(s);
            }
            s = self.next[s as usize];
        }
        None
    }

    /// Index `key → slot`. The caller guarantees `key` is absent and `slot`
    /// unindexed (a registry looks a key up before admitting it, and
    /// indexes a slot only when it occupies it). False for a slot outside
    /// the arena.
    pub fn insert(&mut self, key: &[u8; K], slot: u32) -> bool {
        if slot as usize >= N {
            return false;
        }
        let b = Self::bucket(key);
        self.keys[slot as usize] = *key;
        self.next[slot as usize] = self.heads[b];
        self.heads[b] = slot;
        self.live += 1;
        true
    }

    /// Remove `key`, returning the slot it indexed.
    pub fn remove(&mut self, key: &[u8; K]) -> Option<u32> {
        let b = Self::bucket(key);
        let mut prev = NIL;
        let mut s = self.heads[b];
        while s != NIL {
            if self.keys[s as usize] == *key {
                let after = self.next[s as usize];
                if prev == NIL {
                    self.heads[b] = after;
                } else {
                    self.next[prev as usize] = after;
                }
                self.next[s as usize] = NIL;
                self.live -= 1;
                return Some(s);
            }
            prev = s;
            s = self.next[s as usize];
        }
        None
    }
}

/// Occupancy of an arena of `N` slots (`N` a power of two), with the lowest
/// free slot found in O(log N). A registry takes `lowest_free`, indexes the
/// record's key, then `mark`s the slot.
///
/// `used` is one byte per slot — compact enough that walking the arena's
/// occupied slots (an export, a recovery pass) scans a dense array instead
/// of striding across records. `full` is a complete binary tree over it:
/// internal node `k` in `1..N` covers the slots below it, set when every one
/// of them is used; the children of node `k ≥ N/2` are slots `2k - N` and
/// `2k + 1 - N`. Allocation takes the lowest free slot, so where a record
/// lands is a function of which slots are occupied — the same on a replica
/// that applied the log and on one that installed a snapshot of it.
#[repr(C)]
pub struct SlotSet<const N: usize> {
    used: [bool; N],
    full: [bool; N],
    pub live: u32,
}

impl<const N: usize> Default for SlotSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SlotSet<N> {
    const SHAPE_OK: () = assert!(
        N.is_power_of_two() && N >= 2 && N < u32::MAX as usize,
        "slot set: N must be a power of two of at least 2"
    );

    pub const fn new() -> Self {
        let () = Self::SHAPE_OK;
        SlotSet {
            used: [false; N],
            full: [false; N],
            live: 0,
        }
    }

    /// Reset in place: every slot free.
    pub fn reset(&mut self) {
        let mut i = 0;
        while i < N {
            self.used[i] = false;
            self.full[i] = false;
            i += 1;
        }
        self.live = 0;
    }

    #[inline]
    pub fn is_used(&self, slot: usize) -> bool {
        slot < N && self.used[slot]
    }

    /// Whether tree position `p` (an internal node in `1..N`, or slot
    /// `p - N` at `N..2N`) covers no free slot.
    #[inline]
    fn covered(&self, p: usize) -> bool {
        if p >= N {
            self.used[p - N]
        } else {
            self.full[p]
        }
    }

    /// Recompute the ancestors of `slot` after its occupancy changed.
    fn update(&mut self, slot: usize) {
        let mut k = (N + slot) / 2;
        while k >= 1 {
            let f = self.covered(2 * k) && self.covered(2 * k + 1);
            if self.full[k] == f {
                break; // nothing above can change either
            }
            self.full[k] = f;
            k /= 2;
        }
    }

    /// The lowest free slot, without taking it.
    pub fn lowest_free(&self) -> Option<usize> {
        if self.full[1] {
            return None;
        }
        let mut p = 1;
        while p < N {
            p = if self.covered(2 * p) {
                2 * p + 1
            } else {
                2 * p
            };
        }
        Some(p - N)
    }

    /// Mark `slot` used (a restore places records where the image says).
    /// False when it is outside the arena or already used.
    pub fn mark(&mut self, slot: usize) -> bool {
        if slot >= N || self.used[slot] {
            return false;
        }
        self.used[slot] = true;
        self.live += 1;
        self.update(slot);
        true
    }

    /// Free `slot`. False when it was not used.
    pub fn free(&mut self, slot: usize) -> bool {
        if slot >= N || !self.used[slot] {
            return false;
        }
        self.used[slot] = false;
        self.live -= 1;
        self.update(slot);
        true
    }

    /// The first used slot at or after `from`.
    pub fn next_used(&self, from: usize) -> Option<usize> {
        let mut i = from;
        while i < N {
            if self.used[i] {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}
