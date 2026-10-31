// Deterministic replicated timing — the state-machine support component
// every replicated consumer state machine embeds.
//
// Pure no_std, zero-alloc, DETERMINISTIC: every mutation is a pure function
// of (state, committed input). No clocks, no randomness, no I/O in this
// file. The consumer state machine embeds `TimingState` so timing and
// consumer state share one apply and snapshot boundary; the module wrapper
// owns wall-clock sampling, leader fencing and proposal of `TimeAdvance` /
// `TimeDrain` entries.
//
// The central invariant: a deadline has no effect because a node's local
// timer elapsed. It has an effect only while applying a committed entry, and
// every replica applies the same bounded set of due deadlines in the same
// canonical order.
//
// `ClockGuard` (bottom of file) is the leader-side wall-clock health check.
// It is NOT part of replicated state — it gates what the leader proposes,
// never what apply does.

use super::slot_index::SlotIndex;

// ── Capacity ────────────────────────────────────────────────────────
//
// Capacity is partitioned per owner, not pooled: one consumer exhausting its
// allocation cannot starve another owner's registrations. Owner namespaces
// are compiled constants, so every replica of a PRG must run the same build
// — which deploying one module artifact per group guarantees.

/// Consumer namespaces the index can host.
pub const TM_MAX_OWNERS: usize = 4;

// Total deadline slots are the `N` of `TimingState<N>`: the embedding
// state machine sizes them from its own profile (the session registry
// asks for two per session — a key TTL and a transfer grant — so a
// profile of 4096 sessions embeds `TimingState<8192>`). The sum of the
// per-owner capacities may not exceed `N`; a TTL command never silently
// clamps at some fixed table size.

/// Opaque deadline identity width.
pub const TM_ID: usize = 16;

/// Maximum due callbacks per applied entry.
/// Sized against the Fluxor step budget: a due pass runs at most this many
/// consumer handlers inline during one apply. Rig-measured per-callback cost
/// must stay under budget for this batch size.
pub const TM_BATCH_MAX: usize = 8;

// ── Deadline and canonical order ────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Deadline {
    pub due_at_ms: u64,
    pub owner: u16,
    pub id: [u8; TM_ID],
    pub generation: u64,
}

impl Deadline {
    pub const fn zero() -> Self {
        Deadline {
            due_at_ms: 0,
            owner: 0,
            id: [0; TM_ID],
            generation: 0,
        }
    }
}

/// Canonical total order: `(due_at_ms, owner, id bytes, generation)`.
/// Equal-time deadlines therefore fire in the same order on every
/// replica. At most one live entry exists per `(owner, id)`, so the order
/// is strict over live entries without the generation; it is included so
/// the order is total over any two deadlines, including two entries of
/// a malformed image.
#[inline]
fn cmp_canonical(a: &Deadline, b: &Deadline) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    match a.due_at_ms.cmp(&b.due_at_ms) {
        Ordering::Equal => {}
        o => return o,
    }
    match a.owner.cmp(&b.owner) {
        Ordering::Equal => {}
        o => return o,
    }
    match a.id.cmp(&b.id) {
        Ordering::Equal => {}
        o => return o,
    }
    a.generation.cmp(&b.generation)
}

// ── Operation results ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterResult {
    /// New index entry created.
    Registered,
    /// Existing `(owner, id)` entry atomically replaced (reschedule /
    /// TTL extension). The new generation must not be older.
    Replaced,
    /// Byte-identical repeat of a live registration (proposer retry);
    /// state unchanged.
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The owner's capacity partition is full. The committed consumer
    /// command must fail without creating its consumer object.
    CapacityExceeded,
    /// Owner outside the configured namespace table.
    BadOwner,
    /// Replacement carried a generation older than the live entry — a stale
    /// writer must never rewind a schedule.
    StaleGeneration,
    /// Generation overflow fails closed; generations never wrap.
    GenerationOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelResult {
    /// Exact `(owner, id, generation)` entry removed.
    Cancelled,
    /// No live entry for `(owner, id)`. The index does not remember fired
    /// deadlines (it must stay bounded), so this covers both already-fired
    /// and never-registered — the consumer derives the richer result from
    /// its own authoritative object.
    NotFound,
    /// Live entry exists but at a different generation; nothing
    /// removed (cancellation is generation-exact).
    StaleGeneration,
}

/// What applying one committed time entry did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeApplied {
    /// Logical time after the entry (unchanged on a rejected
    /// regression — duplicates and regressions stay deterministic
    /// and safe).
    pub logical_now_ms: u64,
    /// Due deadlines handed to consumers by this entry (≤ TM_BATCH_MAX).
    pub fired: u16,
    /// Due work left after the bounded batch, saturating at
    /// [`TM_DUE_DEPTH_MAX`]. Non-zero tells the leader to propose
    /// `TimeDrain` continuation entries; a new leader derives the same
    /// need from this replicated state.
    pub due_remaining: u32,
}

// ── Timing state ────────────────────────────────────────────────────

/// Bytes of a snapshot section header:
/// `[version:u16][live:u32][logical_now_ms:u64][capacity:u32]
/// [caps:u32 × TM_MAX_OWNERS]`.
pub const TM_SNAPSHOT_HDR_LEN: usize = 2 + 4 + 8 + 4 + 4 * TM_MAX_OWNERS;
/// Bytes of one snapshot entry: `[due_at_ms:u64][owner:u16][id:16]
/// [generation:u64]`.
pub const TM_SNAPSHOT_ENTRY_LEN: usize = 8 + 2 + TM_ID + 8;

/// The due backlog [`TimingState::due_depth`] counts up to. Past it the
/// gauge saturates: a backlog that deep already tells the leader to keep
/// proposing `TimeDrain`, and counting further would cost apply time in
/// proportion to the backlog.
pub const TM_DUE_DEPTH_MAX: usize = 256;

/// Index key of a deadline: `[owner:u16 LE][id:16]`.
const TM_KEY: usize = 2 + TM_ID;

/// No node.
const NONE: u32 = u32::MAX;

/// Replicated timing state. Embed in the consumer state machine and
/// snapshot/restore through [`TimingState::snapshot`] /
/// [`TimingState::restore`] as one section of the consumer blob.
///
/// Deadlines live in a fixed arena of `N` nodes, ordered by a binary
/// min-heap in canonical order and found by `(owner, id)` through a
/// [`SlotIndex`]: registering, rescheduling, cancelling and popping are
/// O(log N), and whether anything is due is O(1). The heap's layout is a
/// function of the committed history alone — every operation moves
/// entries by comparing them in canonical order, a strict total order
/// since `(owner, id)` is unique — so every replica holds the same heap,
/// and the snapshot streams it position by position. A restored replica
/// places each entry back at the position it streamed from, so it holds
/// that same heap too. Which arena node backs a position is not part of
/// the state: nodes are never compared, exported or observed.
#[repr(C)]
pub struct TimingState<const N: usize> {
    /// PRG logical time: unsigned milliseconds since the Unix epoch,
    /// monotone and saturating.
    pub logical_now_ms: u64,
    /// Live deadlines (`heap[..live]`).
    pub live: u32,
    /// Per-owner capacity partition (configured, replicated in the
    /// snapshot so restore can reject an incompatible deployment).
    pub caps: [u32; TM_MAX_OWNERS],
    /// Live count per owner.
    pub owner_live: [u32; TM_MAX_OWNERS],
    /// Deadline arena, addressed by node.
    nodes: [Deadline; N],
    /// The min-heap: `heap[p]` is the node at position `p`.
    heap: [u32; N],
    /// Position of each live node in `heap`.
    pos: [u32; N],
    /// Free nodes, a stack (`free[..free_len]`).
    free: [u32; N],
    free_len: u32,
    /// `(owner, id)` → node.
    index: SlotIndex<N, TM_KEY>,
}

impl<const N: usize> TimingState<N> {
    pub const SNAPSHOT_VERSION: u16 = 1;
    pub const SLOT_LEN: usize = TM_SNAPSHOT_ENTRY_LEN;
    pub const SNAPSHOT_HDR_LEN: usize = TM_SNAPSHOT_HDR_LEN;

    /// `caps` must sum to at most `N`; excess is clamped owner-by-owner
    /// (deterministic — config is identical on every replica by
    /// deployment discipline).
    pub const fn clamp_caps(caps: [u32; TM_MAX_OWNERS]) -> [u32; TM_MAX_OWNERS] {
        let mut clamped = caps;
        let mut used: u64 = 0;
        let mut i = 0;
        while i < TM_MAX_OWNERS {
            let room = N as u64 - used;
            if clamped[i] as u64 > room {
                clamped[i] = room as u32;
            }
            used += clamped[i] as u64;
            i += 1;
        }
        clamped
    }

    pub const fn new(caps: [u32; TM_MAX_OWNERS]) -> Self {
        let mut free = [0u32; N];
        let mut i = 0;
        while i < N {
            free[i] = (N - 1 - i) as u32;
            i += 1;
        }
        TimingState {
            logical_now_ms: 0,
            live: 0,
            caps: Self::clamp_caps(caps),
            owner_live: [0; TM_MAX_OWNERS],
            nodes: [Deadline::zero(); N],
            heap: [0; N],
            pos: [NONE; N],
            free,
            free_len: N as u32,
            index: SlotIndex::new(),
        }
    }

    /// Initialise in place: every byte of the state, so it is what makes a
    /// raw state block an index (a profile-sized state is too large to
    /// build on the stack and copy into the module's state block).
    pub fn reset(&mut self, caps: [u32; TM_MAX_OWNERS]) {
        self.logical_now_ms = 0;
        self.caps = Self::clamp_caps(caps);
        let mut i = 0;
        while i < N {
            self.nodes[i] = Deadline::zero();
            self.pos[i] = NONE;
            i += 1;
        }
        self.live = 0;
        self.clear();
    }

    /// Drop every deadline, keeping time and caps. Only live nodes hold
    /// anything, so only they are cleared; the free stack and the index
    /// are rebuilt empty.
    pub fn clear(&mut self) {
        let mut p = 0;
        while p < self.live as usize {
            let node = self.heap[p] as usize;
            self.nodes[node] = Deadline::zero();
            self.pos[node] = NONE;
            p += 1;
        }
        let mut i = 0;
        while i < N {
            self.free[i] = (N - 1 - i) as u32;
            i += 1;
        }
        self.free_len = N as u32;
        self.live = 0;
        self.owner_live = [0; TM_MAX_OWNERS];
        self.index.reset();
    }

    #[inline]
    pub fn logical_now_ms(&self) -> u64 {
        self.logical_now_ms
    }

    fn key(owner: u16, id: &[u8; TM_ID]) -> [u8; TM_KEY] {
        let mut k = [0u8; TM_KEY];
        k[0..2].copy_from_slice(&owner.to_le_bytes());
        k[2..].copy_from_slice(id);
        k
    }

    #[inline]
    fn at(&self, p: usize) -> &Deadline {
        &self.nodes[self.heap[p] as usize]
    }

    #[inline]
    fn less(&self, a: usize, b: usize) -> bool {
        cmp_canonical(self.at(a), self.at(b)) == core::cmp::Ordering::Less
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.pos[self.heap[a] as usize] = a as u32;
        self.pos[self.heap[b] as usize] = b as u32;
    }

    fn sift_up(&mut self, mut p: usize) {
        while p > 0 {
            let parent = (p - 1) / 2;
            if !self.less(p, parent) {
                break;
            }
            self.swap(p, parent);
            p = parent;
        }
    }

    fn sift_down(&mut self, mut p: usize) {
        let live = self.live as usize;
        loop {
            let l = 2 * p + 1;
            if l >= live {
                break;
            }
            let r = l + 1;
            let c = if r < live && self.less(r, l) { r } else { l };
            if !self.less(c, p) {
                break;
            }
            self.swap(p, c);
            p = c;
        }
    }

    /// Restore heap order around position `p` after its entry changed.
    fn settle(&mut self, p: usize) {
        if p > 0 && self.less(p, (p - 1) / 2) {
            self.sift_up(p);
        } else {
            self.sift_down(p);
        }
    }

    /// Add `d` (whose `(owner, id)` is absent) at the end of the heap
    /// without ordering it. False when the arena is full.
    fn push_raw(&mut self, d: Deadline) -> bool {
        if self.free_len == 0 {
            return false;
        }
        self.free_len -= 1;
        let node = self.free[self.free_len as usize];
        let p = self.live as usize;
        self.nodes[node as usize] = d;
        self.heap[p] = node;
        self.pos[node as usize] = p as u32;
        self.live += 1;
        self.owner_live[d.owner as usize] += 1;
        self.index.insert(&Self::key(d.owner, &d.id), node)
    }

    /// Remove the entry at heap position `p`.
    fn remove_at(&mut self, p: usize) -> Deadline {
        let node = self.heap[p];
        let d = self.nodes[node as usize];
        let last = self.live as usize - 1;
        if p != last {
            self.swap(p, last);
        }
        self.live -= 1;
        if p != last {
            self.settle(p);
        }
        let _ = self.index.remove(&Self::key(d.owner, &d.id));
        self.nodes[node as usize] = Deadline::zero();
        self.pos[node as usize] = NONE;
        self.free[self.free_len as usize] = node;
        self.free_len += 1;
        self.owner_live[d.owner as usize] -= 1;
        d
    }

    /// Heap position of `(owner, id)`, if live.
    fn find(&self, owner: u16, id: &[u8; TM_ID]) -> Option<usize> {
        let node = self.index.find(&Self::key(owner, id))?;
        Some(self.pos[node as usize] as usize)
    }

    /// Register or atomically replace a deadline. Called only while applying
    /// a committed consumer command.
    pub fn register(
        &mut self,
        owner: u16,
        id: [u8; TM_ID],
        generation: u64,
        due_at_ms: u64,
    ) -> Result<RegisterResult, RegisterError> {
        if owner as usize >= TM_MAX_OWNERS || self.caps[owner as usize] == 0 {
            return Err(RegisterError::BadOwner);
        }
        if generation == u64::MAX {
            return Err(RegisterError::GenerationOverflow);
        }
        if let Some(p) = self.find(owner, &id) {
            let node = self.heap[p] as usize;
            let cur = self.nodes[node];
            if cur.generation == generation && cur.due_at_ms == due_at_ms {
                return Ok(RegisterResult::Unchanged);
            }
            if generation < cur.generation {
                return Err(RegisterError::StaleGeneration);
            }
            self.nodes[node].generation = generation;
            self.nodes[node].due_at_ms = due_at_ms;
            self.settle(p);
            return Ok(RegisterResult::Replaced);
        }
        if self.owner_live[owner as usize] >= self.caps[owner as usize] {
            return Err(RegisterError::CapacityExceeded);
        }
        let d = Deadline {
            due_at_ms,
            owner,
            id,
            generation,
        };
        if !self.push_raw(d) {
            return Err(RegisterError::CapacityExceeded);
        }
        self.sift_up(self.live as usize - 1);
        Ok(RegisterResult::Registered)
    }

    /// Remove exactly `(owner, id, generation)`. Called only while applying
    /// a committed consumer command.
    pub fn cancel(&mut self, owner: u16, id: &[u8; TM_ID], generation: u64) -> CancelResult {
        if owner as usize >= TM_MAX_OWNERS {
            return CancelResult::NotFound;
        }
        let Some(p) = self.find(owner, id) else {
            return CancelResult::NotFound;
        };
        if self.at(p).generation != generation {
            return CancelResult::StaleGeneration;
        }
        self.remove_at(p);
        CancelResult::Cancelled
    }

    /// Applied rule for `TimeAdvance`: `logical_now = max(logical_now,
    /// proposed)`. A regression or duplicate retains the existing time —
    /// deterministic and safe. Returns true when time moved.
    pub fn advance(&mut self, proposed_time_ms: u64) -> bool {
        if proposed_time_ms > self.logical_now_ms {
            self.logical_now_ms = proposed_time_ms;
            true
        } else {
            false
        }
    }

    /// Whether any deadline is due at the applied logical time.
    #[inline]
    pub fn has_due(&self) -> bool {
        self.live > 0 && self.at(0).due_at_ms <= self.logical_now_ms
    }

    /// Pop the canonically-first due deadline, if any. The caller (the
    /// consumer state machine's bounded due pass) invokes the owning
    /// consumer's due handler inline, at most [`TM_BATCH_MAX`] per
    /// applied entry.
    pub fn pop_due(&mut self) -> Option<Deadline> {
        if !self.has_due() {
            return None;
        }
        Some(self.remove_at(0))
    }

    /// Due entries not yet delivered (the drain backlog), saturating at
    /// [`TM_DUE_DEPTH_MAX`]. The due entries are exactly a subtree at the
    /// heap's root (a node is due only if its parent is), so the count
    /// walks that subtree and nothing below it.
    pub fn due_depth(&self) -> u32 {
        let mut stack = [0u32; TM_DUE_DEPTH_MAX + 2];
        let mut top = 0usize;
        let mut n = 0u32;
        if self.live > 0 {
            stack[0] = 0;
            top = 1;
        }
        while top > 0 && (n as usize) < TM_DUE_DEPTH_MAX {
            top -= 1;
            let p = stack[top] as usize;
            if self.at(p).due_at_ms > self.logical_now_ms {
                continue;
            }
            n += 1;
            let l = 2 * p + 1;
            if l < self.live as usize {
                stack[top] = l as u32;
                top += 1;
            }
            if l + 1 < self.live as usize {
                stack[top] = (l + 1) as u32;
                top += 1;
            }
        }
        n
    }

    /// Earliest pending due time (leader uses it for idle coalescing:
    /// no live deadlines and no pending duration admission → no
    /// `TimeAdvance` proposals).
    pub fn next_due_at(&self) -> Option<u64> {
        if self.live == 0 {
            None
        } else {
            Some(self.at(0).due_at_ms)
        }
    }

    // ── Snapshot section ────────────────────────────────────────────
    //
    // Streamed, versioned: a header then the LIVE entries only, in heap
    // order, so the image scales with what is scheduled rather than with
    // the profile's capacity. Layout (all LE):
    //   header [version:u16][live:u32][logical_now_ms:u64][capacity:u32]
    //          [caps:u32 × TM_MAX_OWNERS]
    //   entry  [due_at_ms:u64][owner:u16][id:16][generation:u64] × live
    // `capacity` is `N`: a replica built with another profile fails the
    // install closed rather than reading a differently sized index.

    /// Bytes the whole section occupies right now.
    pub fn snapshot_len(&self) -> usize {
        Self::SNAPSHOT_HDR_LEN + self.live as usize * Self::SLOT_LEN
    }

    pub fn snapshot_header(&self, dst: &mut [u8]) -> usize {
        if dst.len() < Self::SNAPSHOT_HDR_LEN {
            return 0;
        }
        dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
        dst[2..6].copy_from_slice(&self.live.to_le_bytes());
        dst[6..14].copy_from_slice(&self.logical_now_ms.to_le_bytes());
        dst[14..18].copy_from_slice(&(N as u32).to_le_bytes());
        let mut o = 18;
        let mut i = 0;
        while i < TM_MAX_OWNERS {
            dst[o..o + 4].copy_from_slice(&self.caps[i].to_le_bytes());
            o += 4;
            i += 1;
        }
        Self::SNAPSHOT_HDR_LEN
    }

    /// The entry at heap position `i`; 0 when out of range.
    pub fn snapshot_entry(&self, i: usize, dst: &mut [u8]) -> usize {
        if i >= self.live as usize || dst.len() < Self::SLOT_LEN {
            return 0;
        }
        let d = self.at(i);
        dst[0..8].copy_from_slice(&d.due_at_ms.to_le_bytes());
        dst[8..10].copy_from_slice(&d.owner.to_le_bytes());
        dst[10..10 + TM_ID].copy_from_slice(&d.id);
        dst[26..34].copy_from_slice(&d.generation.to_le_bytes());
        Self::SLOT_LEN
    }

    /// Whole section into `dst` (host convenience over the streamed
    /// form).
    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        let total = self.snapshot_len();
        if dst.len() < total {
            return -1;
        }
        let mut o = self.snapshot_header(dst);
        let mut i = 0;
        while i < self.live as usize {
            o += self.snapshot_entry(i, &mut dst[o..]);
            i += 1;
        }
        total as i32
    }

    fn decode_entry(src: &[u8]) -> Deadline {
        let mut id = [0u8; TM_ID];
        id.copy_from_slice(&src[10..26]);
        Deadline {
            due_at_ms: u64::from_le_bytes([
                src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
            ]),
            owner: u16::from_le_bytes([src[8], src[9]]),
            id,
            generation: u64::from_le_bytes([
                src[26], src[27], src[28], src[29], src[30], src[31], src[32], src[33],
            ]),
        }
    }

    /// Validate a header against this state's configuration: version,
    /// capacity (`N`), per-owner caps, a live count within capacity, and
    /// no logical-time regression against the state being replaced (time
    /// is monotone in log order, so a genuine install never rewinds it —
    /// a rewind is corruption). Returns `(live, logical_now_ms)`.
    pub fn check_header(&self, src: &[u8]) -> Option<(u32, u64)> {
        if src.len() < Self::SNAPSHOT_HDR_LEN {
            return None;
        }
        if u16::from_le_bytes([src[0], src[1]]) != Self::SNAPSHOT_VERSION {
            return None;
        }
        let live = u32::from_le_bytes([src[2], src[3], src[4], src[5]]);
        if live as usize > N {
            return None;
        }
        let logical = u64::from_le_bytes([
            src[6], src[7], src[8], src[9], src[10], src[11], src[12], src[13],
        ]);
        if logical < self.logical_now_ms {
            return None;
        }
        if u32::from_le_bytes([src[14], src[15], src[16], src[17]]) != N as u32 {
            return None;
        }
        let mut o = 18;
        let mut i = 0;
        while i < TM_MAX_OWNERS {
            if u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]]) != self.caps[i] {
                return None;
            }
            o += 4;
            i += 1;
        }
        Some((live, logical))
    }

    /// Streamed install, step 1: adopt a checked header. Clears every
    /// entry; `restore_entry` then appends the `live` entries in order.
    pub fn restore_header(&mut self, src: &[u8]) -> Option<u32> {
        let (live, logical) = self.check_header(src)?;
        self.clear();
        self.logical_now_ms = logical;
        Some(live)
    }

    /// Streamed install, step 2: place the next entry at the next heap
    /// position, returning it. Fails closed on a bad owner, a generation
    /// at the overflow sentinel, an owner over its cap, a repeated
    /// `(owner, id)`, or an entry that does not order after its heap
    /// parent — so an image that installs is a valid heap, the one the
    /// exporter held.
    pub fn restore_entry(&mut self, src: &[u8]) -> Option<Deadline> {
        if src.len() < Self::SLOT_LEN || self.live as usize >= N {
            return None;
        }
        let d = Self::decode_entry(src);
        if d.owner as usize >= TM_MAX_OWNERS || d.generation == u64::MAX {
            return None;
        }
        if self.owner_live[d.owner as usize] >= self.caps[d.owner as usize] {
            return None;
        }
        let p = self.live as usize;
        if p > 0 && cmp_canonical(self.at((p - 1) / 2), &d) != core::cmp::Ordering::Less {
            return None;
        }
        if self.index.find(&Self::key(d.owner, &d.id)).is_some() {
            return None;
        }
        if !self.push_raw(d) {
            return None;
        }
        Some(d)
    }

    /// Whole-section restore (host convenience). Fails closed: a rejected
    /// image leaves the index empty (time keeps the state's own value).
    /// Returns the bytes consumed, or 0 on rejection.
    pub fn restore(&mut self, src: &[u8]) -> usize {
        let Some((live, _)) = self.check_header(src) else {
            return 0;
        };
        let total = Self::SNAPSHOT_HDR_LEN + live as usize * Self::SLOT_LEN;
        if src.len() < total {
            return 0;
        }
        let logical = self.logical_now_ms;
        if self.restore_header(src).is_none() {
            return 0;
        }
        let mut i = 0;
        while i < live as usize {
            let at = Self::SNAPSHOT_HDR_LEN + i * Self::SLOT_LEN;
            if self.restore_entry(&src[at..at + Self::SLOT_LEN]).is_none() {
                self.clear();
                self.logical_now_ms = logical;
                return 0;
            }
            i += 1;
        }
        total
    }
}

// ── Clock guard (leader-side, unreplicated) ─────────────────────────

/// Wall-clock health states. Anything but `Healthy` freezes time
/// production: deadlines become late rather than firing from an
/// untrusted source. Never consulted during apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockHealth {
    Healthy,
    /// The platform returned 0 for wall time (no RTC / undisciplined
    /// source). Fluxor's `TIMER::UNIX_MILLIS` reports 0 without an
    /// RTC — that is an unhealthy source, never a valid epoch instant.
    ZeroSource,
    /// Wall clock moved backward relative to the monotonic clock.
    /// Alarm holds until the wall clock catches back up to the
    /// pre-jump extrapolation.
    BackwardJump,
}

/// Leader-side clock discipline (`clock_guard` from
/// `docs/architecture/replication.md`). Pairs each wall-clock sample with a
/// monotonic sample and checks the deltas agree within `slew_tolerance_ms`.
/// Forward jumps are NOT an alarm: the producer advances logical time in
/// `max_step_ms` clamped steps so due work drains within apply budgets.
#[repr(C)]
pub struct ClockGuard {
    /// Max believable forward movement of logical time per proposed
    /// entry (`logical_time_max_step_ms`).
    pub max_step_ms: u64,
    /// Allowed disagreement between wall and monotonic deltas before
    /// a backward jump alarms.
    pub slew_tolerance_ms: u64,
    /// Highest wall-time extrapolation seen: `unix + (now_mono - mono)`
    /// anchor. 0 = no sample yet.
    anchor_unix_ms: u64,
    anchor_mono_ms: u64,
    pub alarm: ClockHealth,
}

impl ClockGuard {
    pub const fn new(max_step_ms: u64, slew_tolerance_ms: u64) -> Self {
        ClockGuard {
            max_step_ms,
            slew_tolerance_ms,
            anchor_unix_ms: 0,
            anchor_mono_ms: 0,
            alarm: ClockHealth::Healthy,
        }
    }

    /// Feed one paired sample. Returns current health.
    pub fn sample(&mut self, mono_ms: u64, unix_ms: u64) -> ClockHealth {
        if unix_ms == 0 {
            self.alarm = ClockHealth::ZeroSource;
            return self.alarm;
        }
        if self.anchor_unix_ms == 0 {
            self.anchor_unix_ms = unix_ms;
            self.anchor_mono_ms = mono_ms;
            self.alarm = ClockHealth::Healthy;
            return self.alarm;
        }
        let expected = self
            .anchor_unix_ms
            .saturating_add(mono_ms.saturating_sub(self.anchor_mono_ms));
        if unix_ms.saturating_add(self.slew_tolerance_ms) < expected {
            // Backward movement: freeze until the wall clock catches up with
            // the pre-jump extrapolation.
            self.alarm = ClockHealth::BackwardJump;
            return self.alarm;
        }
        // Healthy (a forward jump re-anchors; the producer's step
        // clamp bounds how fast logical time follows it).
        self.anchor_unix_ms = unix_ms;
        self.anchor_mono_ms = mono_ms;
        self.alarm = ClockHealth::Healthy;
        self.alarm
    }

    /// What the leader may propose right now: the sampled wall time,
    /// clamped to `logical + max_step_ms` so a forward jump advances
    /// in bounded steps. Returns None while unhealthy or when the
    /// proposal would not advance logical time.
    pub fn propose_time(&self, logical_now_ms: u64, unix_ms: u64) -> Option<u64> {
        if self.alarm != ClockHealth::Healthy || unix_ms == 0 {
            return None;
        }
        let clamped = if logical_now_ms == 0 {
            // First advance: adopt wall time directly (no meaningful
            // step base yet).
            unix_ms
        } else {
            unix_ms.min(logical_now_ms.saturating_add(self.max_step_ms))
        };
        if clamped > logical_now_ms {
            Some(clamped)
        } else {
            None
        }
    }
}
