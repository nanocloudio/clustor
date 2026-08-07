// Deterministic replicated timing — the state-machine support
// component behind `.context/rfc_deterministic_timing.md`.
//
// Pure no_std, zero-alloc, DETERMINISTIC: every mutation is a pure
// function of (state, committed input). No clocks, no randomness, no
// I/O in this file. The consumer state machine embeds `TimingState`
// so timing and consumer state share one apply and snapshot boundary
// (RFC §4); the module wrapper owns wall-clock sampling, leader
// fencing and proposal of `TimeAdvance` / `TimeDrain` entries.
//
// The central invariant (RFC §0): a deadline has no effect because a
// node's local timer elapsed. It has an effect only while applying a
// committed entry, and every replica applies the same bounded set of
// due deadlines in the same canonical order.
//
// `ClockGuard` (bottom of file) is the leader-side wall-clock health
// check (RFC §5.4). It is NOT part of replicated state — it gates
// what the leader proposes, never what apply does.

// ── Capacity (RFC §6.2) ─────────────────────────────────────────────
//
// Capacity is partitioned per owner, not pooled: one consumer
// exhausting its allocation cannot starve another owner's
// registrations. Owner namespaces are compiled constants for now
// (RFC §22.1); every replica of a PRG must run the same build, which
// the existing module-artifact discipline already guarantees.

/// Consumer namespaces the index can host.
pub const TM_MAX_OWNERS: usize = 4;

/// Total deadline slots (the sum of all per-owner capacities may not
/// exceed this). Fixed so the state and its snapshot have static size.
pub const TM_MAX_DEADLINES: usize = 64;

/// Opaque deadline identity width (RFC §6.1).
pub const TM_ID: usize = 16;

/// Maximum due callbacks per applied entry (RFC §6.2
/// `deadline_batch_max`). Sized against the Fluxor step budget: a due
/// pass runs at most this many consumer handlers inline during one
/// apply. Rig-measured per-callback cost must stay under budget for
/// this batch size (RFC §22.3).
pub const TM_BATCH_MAX: usize = 8;

// ── Deadline and canonical order (RFC §6.1) ─────────────────────────

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
/// replica. At most one live entry exists per `(owner, id)` — the
/// generation component is a vestigial tiebreaker, kept for defense
/// in depth and snapshot-order validation.
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
    /// Replacement carried a generation older than the live entry —
    /// a stale writer must never rewind a schedule (RFC §9.3).
    StaleGeneration,
    /// Generation overflow fails closed; generations never wrap.
    GenerationOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelResult {
    /// Exact `(owner, id, generation)` entry removed.
    Cancelled,
    /// No live entry for `(owner, id)`. The index does not remember
    /// fired deadlines (it must stay bounded), so this covers both
    /// already-fired and never-registered — the consumer derives the
    /// richer result from its own authoritative object (RFC §9.2).
    NotFound,
    /// Live entry exists but at a different generation; nothing
    /// removed (cancellation is generation-exact).
    StaleGeneration,
}

/// What applying one committed time entry did (RFC §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeApplied {
    /// Logical time after the entry (unchanged on a rejected
    /// regression — duplicates and regressions stay deterministic
    /// and safe).
    pub logical_now_ms: u64,
    /// Due deadlines handed to consumers by this entry (≤ TM_BATCH_MAX).
    pub fired: u16,
    /// Due work left after the bounded batch. Non-zero tells the
    /// leader to propose `TimeDrain` continuation entries; a new
    /// leader derives the same need from this replicated state.
    pub due_remaining: u16,
}

// ── Timing state (RFC §6) ───────────────────────────────────────────

/// Replicated timing state. Embed in the consumer state machine and
/// snapshot/restore through [`TimingState::snapshot`] /
/// [`TimingState::restore`] as one section of the consumer blob.
///
/// The index is a fixed-capacity array kept packed and sorted in
/// canonical order — insertion is O(N) shift, the due pass pops from
/// the front, and the snapshot is the array verbatim. N is small and
/// bounded, and the byte image is canonical by construction.
#[repr(C)]
pub struct TimingState {
    /// PRG logical time: unsigned milliseconds since the Unix epoch,
    /// monotone and saturating (RFC §5.1).
    pub logical_now_ms: u64,
    /// Live entries (occupy `slots[..live]` in canonical order).
    pub live: u16,
    /// Per-owner capacity partition (configured, replicated in the
    /// snapshot so restore can reject an incompatible deployment).
    pub caps: [u16; TM_MAX_OWNERS],
    /// Live count per owner (maintained, also derivable from slots).
    pub owner_live: [u16; TM_MAX_OWNERS],
    /// Unused tail slots are always zeroed so the snapshot image is
    /// byte-identical across replicas.
    pub slots: [Deadline; TM_MAX_DEADLINES],
}

impl TimingState {
    /// `caps` must sum to at most [`TM_MAX_DEADLINES`]; excess is
    /// clamped owner-by-owner (deterministic — config is identical on
    /// every replica by deployment discipline).
    pub const fn new(caps: [u16; TM_MAX_OWNERS]) -> Self {
        let mut clamped = caps;
        let mut used: u32 = 0;
        let mut i = 0;
        while i < TM_MAX_OWNERS {
            let room = TM_MAX_DEADLINES as u32 - used;
            if clamped[i] as u32 > room {
                clamped[i] = room as u16;
            }
            used += clamped[i] as u32;
            i += 1;
        }
        TimingState {
            logical_now_ms: 0,
            live: 0,
            caps: clamped,
            owner_live: [0; TM_MAX_OWNERS],
            slots: [Deadline::zero(); TM_MAX_DEADLINES],
        }
    }

    #[inline]
    pub fn logical_now_ms(&self) -> u64 {
        self.logical_now_ms
    }

    fn find(&self, owner: u16, id: &[u8; TM_ID]) -> Option<usize> {
        let mut i = 0;
        while i < self.live as usize {
            if self.slots[i].owner == owner && self.slots[i].id == *id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Position where `d` belongs in canonical order.
    fn insert_pos(&self, d: &Deadline) -> usize {
        let mut i = 0;
        while i < self.live as usize {
            if cmp_canonical(d, &self.slots[i]) == core::cmp::Ordering::Less {
                return i;
            }
            i += 1;
        }
        self.live as usize
    }

    fn remove_at(&mut self, pos: usize) -> Deadline {
        let d = self.slots[pos];
        let mut i = pos;
        while i + 1 < self.live as usize {
            self.slots[i] = self.slots[i + 1];
            i += 1;
        }
        self.live -= 1;
        self.slots[self.live as usize] = Deadline::zero();
        self.owner_live[d.owner as usize] -= 1;
        d
    }

    fn insert_sorted(&mut self, d: Deadline) {
        let pos = self.insert_pos(&d);
        let mut i = self.live as usize;
        while i > pos {
            self.slots[i] = self.slots[i - 1];
            i -= 1;
        }
        self.slots[pos] = d;
        self.live += 1;
        self.owner_live[d.owner as usize] += 1;
    }

    /// Register or atomically replace a deadline (RFC §7, §9.1, §9.3).
    /// Called only while applying a committed consumer command.
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
        if let Some(pos) = self.find(owner, &id) {
            let cur = self.slots[pos];
            if cur.generation == generation && cur.due_at_ms == due_at_ms {
                return Ok(RegisterResult::Unchanged);
            }
            if generation < cur.generation {
                return Err(RegisterError::StaleGeneration);
            }
            self.remove_at(pos);
            self.insert_sorted(Deadline {
                due_at_ms,
                owner,
                id,
                generation,
            });
            return Ok(RegisterResult::Replaced);
        }
        if self.owner_live[owner as usize] >= self.caps[owner as usize] {
            return Err(RegisterError::CapacityExceeded);
        }
        self.insert_sorted(Deadline {
            due_at_ms,
            owner,
            id,
            generation,
        });
        Ok(RegisterResult::Registered)
    }

    /// Remove exactly `(owner, id, generation)` (RFC §9.2). Called
    /// only while applying a committed consumer command.
    pub fn cancel(&mut self, owner: u16, id: &[u8; TM_ID], generation: u64) -> CancelResult {
        if owner as usize >= TM_MAX_OWNERS {
            return CancelResult::NotFound;
        }
        let Some(pos) = self.find(owner, id) else {
            return CancelResult::NotFound;
        };
        if self.slots[pos].generation != generation {
            return CancelResult::StaleGeneration;
        }
        self.remove_at(pos);
        CancelResult::Cancelled
    }

    /// Applied rule for `TimeAdvance` (RFC §5.4, §8):
    /// `logical_now = max(logical_now, proposed)`. A regression or
    /// duplicate retains the existing time — deterministic and safe.
    /// Returns true when time moved.
    pub fn advance(&mut self, proposed_time_ms: u64) -> bool {
        if proposed_time_ms > self.logical_now_ms {
            self.logical_now_ms = proposed_time_ms;
            true
        } else {
            false
        }
    }

    /// Pop the canonically-first due deadline, if any. The caller (the
    /// consumer state machine's bounded due pass) invokes the owning
    /// consumer's due handler inline, at most [`TM_BATCH_MAX`] per
    /// applied entry.
    pub fn pop_due(&mut self) -> Option<Deadline> {
        if self.live == 0 || self.slots[0].due_at_ms > self.logical_now_ms {
            return None;
        }
        Some(self.remove_at(0))
    }

    /// Due entries not yet delivered (the drain backlog, RFC §8).
    pub fn due_depth(&self) -> u16 {
        let mut n = 0u16;
        let mut i = 0;
        while i < self.live as usize {
            if self.slots[i].due_at_ms > self.logical_now_ms {
                break; // sorted: nothing later can be due
            }
            n += 1;
            i += 1;
        }
        n
    }

    /// Earliest pending due time (leader uses it for idle coalescing:
    /// no live deadlines and no pending duration admission → no
    /// `TimeAdvance` proposals, RFC §5.2).
    pub fn next_due_at(&self) -> Option<u64> {
        if self.live == 0 {
            None
        } else {
            Some(self.slots[0].due_at_ms)
        }
    }

    // ── Snapshot section (RFC §12) ──────────────────────────────────
    //
    // Fixed-size, canonical, versioned. Layout (all LE):
    //   [version:u16][live:u16][logical_now_ms:u64]
    //   [caps:u16 × TM_MAX_OWNERS]
    //   [slot × TM_MAX_DEADLINES] where
    //     slot = [due_at_ms:u64][owner:u16][id:16][generation:u64]
    // Unused slots are zero. Fixed size keeps the embedding consumer
    // snapshot statically sized and the byte image replica-identical.

    pub const SNAPSHOT_VERSION: u16 = 1;
    pub const SLOT_LEN: usize = 8 + 2 + TM_ID + 8;
    pub const SNAPSHOT_LEN: usize =
        2 + 2 + 8 + 2 * TM_MAX_OWNERS + TM_MAX_DEADLINES * Self::SLOT_LEN;

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < Self::SNAPSHOT_LEN {
            return -1;
        }
        dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
        dst[2..4].copy_from_slice(&self.live.to_le_bytes());
        dst[4..12].copy_from_slice(&self.logical_now_ms.to_le_bytes());
        let mut o = 12;
        let mut i = 0;
        while i < TM_MAX_OWNERS {
            dst[o..o + 2].copy_from_slice(&self.caps[i].to_le_bytes());
            o += 2;
            i += 1;
        }
        i = 0;
        while i < TM_MAX_DEADLINES {
            let d = &self.slots[i];
            dst[o..o + 8].copy_from_slice(&d.due_at_ms.to_le_bytes());
            dst[o + 8..o + 10].copy_from_slice(&d.owner.to_le_bytes());
            dst[o + 10..o + 10 + TM_ID].copy_from_slice(&d.id);
            dst[o + 26..o + 34].copy_from_slice(&d.generation.to_le_bytes());
            o += Self::SLOT_LEN;
            i += 1;
        }
        Self::SNAPSHOT_LEN as i32
    }

    /// Restore fails closed (returns false, state untouched on the
    /// validation path) on: unknown version, capacity-config mismatch,
    /// over-capacity counts, duplicate `(owner, id)`, non-canonical
    /// order, or a logical-time regression against the state being
    /// replaced (time is monotone in log order, so a genuine install
    /// never rewinds it — a rewind is corruption).
    pub fn restore(&mut self, src: &[u8]) -> bool {
        if src.len() < Self::SNAPSHOT_LEN {
            return false;
        }
        let version = u16::from_le_bytes([src[0], src[1]]);
        if version != Self::SNAPSHOT_VERSION {
            return false;
        }
        let live = u16::from_le_bytes([src[2], src[3]]);
        if live as usize > TM_MAX_DEADLINES {
            return false;
        }
        let logical = u64::from_le_bytes([
            src[4], src[5], src[6], src[7], src[8], src[9], src[10], src[11],
        ]);
        if logical < self.logical_now_ms {
            return false;
        }
        let mut o = 12;
        let mut i = 0;
        while i < TM_MAX_OWNERS {
            let cap = u16::from_le_bytes([src[o], src[o + 1]]);
            if cap != self.caps[i] {
                return false;
            }
            o += 2;
            i += 1;
        }
        let mut slots = [Deadline::zero(); TM_MAX_DEADLINES];
        let mut owner_live = [0u16; TM_MAX_OWNERS];
        i = 0;
        while i < TM_MAX_DEADLINES {
            let due_at_ms = u64::from_le_bytes([
                src[o],
                src[o + 1],
                src[o + 2],
                src[o + 3],
                src[o + 4],
                src[o + 5],
                src[o + 6],
                src[o + 7],
            ]);
            let owner = u16::from_le_bytes([src[o + 8], src[o + 9]]);
            let mut id = [0u8; TM_ID];
            id.copy_from_slice(&src[o + 10..o + 26]);
            let generation = u64::from_le_bytes([
                src[o + 26],
                src[o + 27],
                src[o + 28],
                src[o + 29],
                src[o + 30],
                src[o + 31],
                src[o + 32],
                src[o + 33],
            ]);
            let d = Deadline {
                due_at_ms,
                owner,
                id,
                generation,
            };
            if i < live as usize {
                if owner as usize >= TM_MAX_OWNERS || generation == u64::MAX {
                    return false;
                }
                owner_live[owner as usize] += 1;
                if owner_live[owner as usize] > self.caps[owner as usize] {
                    return false;
                }
                if i > 0 {
                    let prev = &slots[i - 1];
                    // Strictly ascending: also rejects duplicates.
                    if cmp_canonical(prev, &d) != core::cmp::Ordering::Less {
                        return false;
                    }
                    if prev.owner == d.owner && prev.id == d.id {
                        return false;
                    }
                }
                // Duplicate (owner, id) at different due times would
                // pass the adjacent check; scan back for it.
                let mut j = 0;
                while j + 1 < i {
                    if slots[j].owner == d.owner && slots[j].id == d.id {
                        return false;
                    }
                    j += 1;
                }
                slots[i] = d;
            } else if d != Deadline::zero() {
                return false; // tail must be zeroed
            }
            o += Self::SLOT_LEN;
            i += 1;
        }
        self.logical_now_ms = logical;
        self.live = live;
        self.owner_live = owner_live;
        self.slots = slots;
        true
    }
}

// ── Clock guard (leader-side, unreplicated — RFC §5.4) ──────────────

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
/// `docs/architecture/replication.md`). Pairs each wall-clock sample
/// with a monotonic sample and checks the deltas agree within
/// `slew_tolerance_ms`. Forward jumps are NOT an alarm: the producer
/// advances logical time in `max_step_ms` clamped steps so due work
/// drains within apply budgets (RFC §5.4).
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
            // Backward movement: freeze until the wall clock catches
            // up with the pre-jump extrapolation (RFC §5.4).
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
