// Failover registry — the `fo/<operation_id>` namespace of the session
// directory: the replicated compare-and-swap store a failover coordinator
// records each VIP move, release or recovery mark in before its first
// external side effect, and advances only through.
//
// Pure no_std, zero-alloc, DETERMINISTIC: `FailoverRegistry::apply` is a
// pure function of (state, committed command body, digest fn); every
// replica applying the same committed sequence holds byte-identical state.
// No clocks, no randomness, no I/O. The PIC module wrapper
// (`modules/app/session_directory/mod.rs`) hosts it beside the session,
// transport and VIP registries, dispatching on the `"FO"` magic;
// `clustor-common` mounts it for host tests and for Wormhole, whose store
// adapter builds these commands and reads these replies.
//
// The record is Wormhole's §13.5 `FailoverOperation`, the fixed 264-byte
// `WHFO` frame (`wormhole/modules/common/traffic/failover_core.rs`), held
// as its bytes. The registry does not interpret what a record asks for —
// that is the coordinator's — but it owns the rule a record may change by,
// which is the rule `fo_cas_check` states there:
//
// - **a new operation starts at its intent.** The first write of an
//   operation id must be the INTENT phase at phase generation 1; anything
//   else is refused `CONFLICT` and nothing is stored.
// - **a retry is the record.** A byte-identical write of the stored record
//   answers `OK` and changes nothing, so a coordinator that lost the
//   answer resends the same bytes.
// - **one step at a time.** Otherwise the write must be the same operation
//   (every field fixed at intent unchanged), its phase generation must be
//   the stored one plus exactly one, and the phase move must be a legal
//   transition of the record's kind under its fence requirement
//   (`transition_legal`, the same table as Wormhole's
//   `fo_transition_legal`). Anything else is `CONFLICT`, and the reply
//   carries the stored record so the writer follows it.
// - **a frame is checked whole.** Magic, version, reserved bytes, enum
//   ranges and the record's own SHA-256 trailer; a malformed record is
//   `INVALID` and nothing is stored.
// - **replay.** REPLAY changes no record: it is a read through the log, so
//   once it commits, every record a coordinator could have been told about
//   is in this state. The module then streams every live (non-terminal)
//   record to the requester in the order the operations were created
//   (`replay_next`).
// - **bounded retention.** A terminal record (DONE, ABORTED, FAILED,
//   BLOCKED) stays, so a late retry or a re-sent request with the same
//   operation id is answered from it, until the arena is full; then the
//   oldest terminal record gives its slot to a new operation. A full arena
//   of live operations refuses a new one `CAPACITY`, which the store
//   adapter leaves unanswered for the coordinator's own retry.
//
// A proposer routes an operation to its group like any directory key; the
// module's `partition_id` names the group this registry holds.

use super::slot_index::{SlotIndex, SlotSet};

// ── Capacity ────────────────────────────────────────────────────────

/// Profiles: operation records per group. A VIP move is a handful of
/// records per minute at most; the arena bounds live operations plus the
/// terminal history kept for retries.
pub const FO_PROFILE_RP2350: usize = 16;
pub const FO_PROFILE_PI5: usize = 256;
pub const FO_PROFILE_SERVER: usize = 4096;

// ── Record (Wormhole's `FailoverOperation`, failover_core.rs) ───────

pub const FO_RECORD_LEN: usize = 264;
/// Bytes the record's SHA-256 trailer covers.
pub const FO_BODY_LEN: usize = 232;
pub const FO_OP_ID: usize = 16;
pub const FO_MAGIC: [u8; 4] = *b"WHFO";
pub const FO_VERSION: u16 = 1;

/// Record offsets.
const AT_OP_ID: usize = 8;
const AT_KIND: usize = 24;
const AT_FENCE: usize = 25;
const AT_PHASE: usize = 26;
const AT_PHASE_GEN: usize = 104;
const AT_READY: usize = 148;

/// The byte ranges fixed at intent (Wormhole's `same_operation`):
/// operation id, kind, fence; fence provider; actor and target; source
/// fault domain and expected epoch; recovery generation; deadline and
/// allowed interfaces; ready; the four host/boot identities and the
/// policy.
const INTENT_RANGES: [(usize, usize); 10] = [
    (8, 26),    // operation_id, kind, fence
    (31, 32),   // fence_provider
    (32, 84),   // actor, target
    (84, 96),   // source_fault_domain, expected_epoch
    (120, 128), // recovery_generation
    (140, 148), // deadline_ms, allowed_interfaces
    (148, 149), // ready
    (152, 184), // source_host, source_boot
    (184, 216), // dest_host, dest_boot
    (216, 232), // policy
];

/// `FailoverKind`.
pub const FO_KIND_VIP_MOVE: u8 = 1;
pub const FO_KIND_VIP_RELEASE: u8 = 2;
pub const FO_KIND_RECOVERY_MARK: u8 = 3;

/// `FenceRequirement`.
pub const FO_FENCE_NONE: u8 = 0;
pub const FO_FENCE_GRACEFUL: u8 = 1;
pub const FO_FENCE_EXTERNAL: u8 = 2;

/// `FoPhase`.
pub const FO_PH_INTENT: u8 = 0;
pub const FO_PH_DRAINING: u8 = 1;
pub const FO_PH_WITHDRAWN: u8 = 2;
pub const FO_PH_SOURCE_FENCED: u8 = 3;
pub const FO_PH_SOURCE_DISABLED: u8 = 4;
pub const FO_PH_PREPARED: u8 = 5;
pub const FO_PH_FENCE_REQUESTED: u8 = 6;
pub const FO_PH_FENCE_OBSERVED: u8 = 7;
pub const FO_PH_FENCE_CONFIRMED: u8 = 8;
pub const FO_PH_ACTIVATING: u8 = 9;
pub const FO_PH_INSTALLED: u8 = 10;
pub const FO_PH_ADVERTISED: u8 = 11;
pub const FO_PH_ACTIVE: u8 = 12;
pub const FO_PH_RELEASED: u8 = 13;
pub const FO_PH_RECOVERY_MARKED: u8 = 14;
pub const FO_PH_ABORTING: u8 = 15;
pub const FO_PH_DONE: u8 = 16;
pub const FO_PH_ABORTED: u8 = 17;
pub const FO_PH_FAILED: u8 = 18;
pub const FO_PH_BLOCKED: u8 = 19;

pub const fn phase_terminal(p: u8) -> bool {
    matches!(p, FO_PH_DONE | FO_PH_ABORTED | FO_PH_FAILED | FO_PH_BLOCKED)
}

/// Past the unsafe boundary: ACTIVATE may have committed.
pub const fn phase_past_boundary(p: u8) -> bool {
    matches!(
        p,
        FO_PH_ACTIVATING | FO_PH_INSTALLED | FO_PH_ADVERTISED | FO_PH_ACTIVE
    )
}

/// A claim may be outstanding (CLAIM_PREPARE sent, ACTIVATE not yet).
pub const fn phase_claim_window(p: u8) -> bool {
    matches!(
        p,
        FO_PH_PREPARED | FO_PH_FENCE_REQUESTED | FO_PH_FENCE_OBSERVED | FO_PH_FENCE_CONFIRMED
    )
}

/// The next phase on the forward path of `kind` under `fence` from
/// `from` (Wormhole's `fo_successor`).
pub const fn successor(kind: u8, fence: u8, from: u8) -> Option<u8> {
    match kind {
        FO_KIND_RECOVERY_MARK => match from {
            FO_PH_INTENT => Some(FO_PH_RECOVERY_MARKED),
            FO_PH_RECOVERY_MARKED => Some(FO_PH_DONE),
            _ => None,
        },
        FO_KIND_VIP_RELEASE => match from {
            FO_PH_INTENT => Some(FO_PH_DRAINING),
            FO_PH_DRAINING => Some(FO_PH_WITHDRAWN),
            FO_PH_WITHDRAWN => Some(FO_PH_SOURCE_FENCED),
            FO_PH_SOURCE_FENCED => Some(FO_PH_SOURCE_DISABLED),
            FO_PH_SOURCE_DISABLED => Some(FO_PH_RELEASED),
            FO_PH_RELEASED => Some(FO_PH_DONE),
            _ => None,
        },
        FO_KIND_VIP_MOVE => {
            let graceful = fence == FO_FENCE_GRACEFUL;
            let external = fence == FO_FENCE_EXTERNAL;
            match from {
                FO_PH_INTENT if graceful => Some(FO_PH_DRAINING),
                FO_PH_INTENT => Some(FO_PH_PREPARED),
                FO_PH_DRAINING if graceful => Some(FO_PH_WITHDRAWN),
                FO_PH_WITHDRAWN if graceful => Some(FO_PH_SOURCE_FENCED),
                FO_PH_SOURCE_FENCED if graceful => Some(FO_PH_SOURCE_DISABLED),
                FO_PH_SOURCE_DISABLED if graceful => Some(FO_PH_PREPARED),
                FO_PH_PREPARED => Some(FO_PH_FENCE_REQUESTED),
                FO_PH_FENCE_REQUESTED if external => Some(FO_PH_FENCE_OBSERVED),
                FO_PH_FENCE_REQUESTED => Some(FO_PH_ACTIVATING),
                FO_PH_FENCE_OBSERVED if external => Some(FO_PH_FENCE_CONFIRMED),
                FO_PH_FENCE_CONFIRMED if external => Some(FO_PH_ACTIVATING),
                FO_PH_ACTIVATING => Some(FO_PH_INSTALLED),
                FO_PH_INSTALLED => Some(FO_PH_ADVERTISED),
                FO_PH_ADVERTISED => Some(FO_PH_ACTIVE),
                FO_PH_ACTIVE => Some(FO_PH_DONE),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether `from → to` is a legal phase move (Wormhole's
/// `fo_transition_legal`): one step forward, or ABORTING from a phase whose
/// claim can still be aborted, ABORTED from ABORTING or INTENT, FAILED
/// before the boundary, BLOCKED past it (or from ABORTING).
pub const fn transition_legal(kind: u8, fence: u8, from: u8, to: u8) -> bool {
    if phase_terminal(from) {
        return false;
    }
    if let Some(next) = successor(kind, fence, from) {
        if next == to {
            return true;
        }
    }
    match to {
        FO_PH_ABORTING => from == FO_PH_INTENT || phase_claim_window(from),
        FO_PH_ABORTED => from == FO_PH_ABORTING || from == FO_PH_INTENT,
        FO_PH_FAILED => !phase_past_boundary(from),
        FO_PH_BLOCKED => phase_past_boundary(from) || from == FO_PH_ABORTING,
        _ => false,
    }
}

pub type DigestFn = fn(&[u8]) -> [u8; 32];

fn u16_at(src: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([src[o], src[o + 1]])
}

fn u32_at(src: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
}

fn u64_at(src: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[o..o + 8]);
    u64::from_le_bytes(b)
}

/// Whether `rec` is a well-formed `WHFO` record: the frame, the enum
/// ranges and the digest trailer.
pub fn record_valid(rec: &[u8], digest: DigestFn) -> bool {
    rec.len() == FO_RECORD_LEN
        && rec[0..4] == FO_MAGIC
        && u16_at(rec, 4) == FO_VERSION
        && u16_at(rec, 6) == 0
        && rec[149..152] == [0, 0, 0]
        && (FO_KIND_VIP_MOVE..=FO_KIND_RECOVERY_MARK).contains(&rec[AT_KIND])
        && rec[AT_FENCE] <= FO_FENCE_EXTERNAL
        && rec[AT_PHASE] <= FO_PH_BLOCKED
        && rec[AT_READY] <= 1
        && digest(&rec[..FO_BODY_LEN])[..] == rec[FO_BODY_LEN..]
}

/// Whether `b` is the same operation as `a`: every field fixed at intent
/// equal.
pub fn same_operation(a: &[u8; FO_RECORD_LEN], b: &[u8; FO_RECORD_LEN]) -> bool {
    let mut i = 0;
    while i < INTENT_RANGES.len() {
        let (lo, hi) = INTENT_RANGES[i];
        if a[lo..hi] != b[lo..hi] {
            return false;
        }
        i += 1;
    }
    true
}

pub fn record_op_id(rec: &[u8; FO_RECORD_LEN]) -> [u8; FO_OP_ID] {
    let mut id = [0u8; FO_OP_ID];
    id.copy_from_slice(&rec[AT_OP_ID..AT_OP_ID + FO_OP_ID]);
    id
}

pub fn record_phase(rec: &[u8; FO_RECORD_LEN]) -> u8 {
    rec[AT_PHASE]
}

pub fn record_phase_generation(rec: &[u8; FO_RECORD_LEN]) -> u64 {
    u64_at(rec, AT_PHASE_GEN)
}

// ── Commands ────────────────────────────────────────────────────────

/// Compare-and-swap one record: `[op:1][record:264]`.
pub const FO_OP_CAS: u8 = 1;
/// A read through the log, after which the module streams every live
/// record: `[op:1]`.
pub const FO_OP_REPLAY: u8 = 2;

pub const FO_CAS_LEN: usize = 1 + FO_RECORD_LEN;
pub const FO_REPLAY_LEN: usize = 1;
pub const FO_MAX_CMD: usize = FO_CAS_LEN;

pub fn build_cas(dst: &mut [u8], record: &[u8; FO_RECORD_LEN]) -> usize {
    if dst.len() < FO_CAS_LEN {
        return 0;
    }
    dst[0] = FO_OP_CAS;
    dst[1..FO_CAS_LEN].copy_from_slice(record);
    FO_CAS_LEN
}

pub fn build_replay(dst: &mut [u8]) -> usize {
    if dst.is_empty() {
        return 0;
    }
    dst[0] = FO_OP_REPLAY;
    FO_REPLAY_LEN
}

// ── Reply ───────────────────────────────────────────────────────────

/// The proposal is the stored record (newly, or a byte-identical retry).
pub const FO_ST_OK: u8 = 0;
/// Refused; the stored record (if any) follows.
pub const FO_ST_CONFLICT: u8 = 1;
/// A live record streamed after a committed REPLAY.
pub const FO_ST_REPLAY: u8 = 2;
/// Malformed; nothing stored.
pub const FO_ST_INVALID: u8 = 3;
/// A new operation with every slot held by a live one.
pub const FO_ST_CAPACITY: u8 = 4;

/// Encoded reply: `[op:1][status:1][present:1][reserved:1][live:4]
/// [record:264]`. `present` says whether `record` is a stored record;
/// `live` is the count of non-terminal records after the apply (for the
/// end of a replay, the count streamed). The statuses OK, CONFLICT,
/// REPLAY and INVALID are Wormhole's `fo_store` values, so the store
/// adapter forwards them as they are.
pub const FO_REPLY_LEN: usize = 8 + FO_RECORD_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FailoverReply {
    pub op: u8,
    pub status: u8,
    pub present: bool,
    pub live: u32,
    pub record: [u8; FO_RECORD_LEN],
}

impl FailoverReply {
    pub const fn zero() -> Self {
        FailoverReply {
            op: 0,
            status: 0,
            present: false,
            live: 0,
            record: [0; FO_RECORD_LEN],
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < FO_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2] = self.present as u8;
        dst[3] = 0;
        dst[4..8].copy_from_slice(&self.live.to_le_bytes());
        dst[8..FO_REPLY_LEN].copy_from_slice(&self.record);
        FO_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<FailoverReply> {
        if src.len() < FO_REPLY_LEN || src[2] > 1 || src[3] != 0 {
            return None;
        }
        let mut record = [0u8; FO_RECORD_LEN];
        record.copy_from_slice(&src[8..FO_REPLY_LEN]);
        Some(FailoverReply {
            op: src[0],
            status: src[1],
            present: src[2] != 0,
            live: u32_at(src, 4),
            record,
        })
    }
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FoSlot {
    /// Creation order: the registry's `next_seq` when the intent landed.
    /// Zero for a free slot.
    pub seq: u64,
    pub record: [u8; FO_RECORD_LEN],
}

impl FoSlot {
    pub const fn empty() -> Self {
        FoSlot {
            seq: 0,
            record: [0; FO_RECORD_LEN],
        }
    }

    pub fn terminal(&self) -> bool {
        phase_terminal(self.record[AT_PHASE])
    }
}

/// The replicated state machine. `N` is the record arena (a power of two).
#[repr(C)]
pub struct FailoverRegistry<const N: usize> {
    pub slots: [FoSlot; N],
    /// operation id → slot. Derived; rebuilt on restore.
    index: SlotIndex<N, FO_OP_ID>,
    /// Which slots hold a record. Derived; rebuilt on restore.
    occupied: SlotSet<N>,
    pub admitted: u32,
    /// Records held (live and terminal).
    pub count: u32,
    /// Non-terminal records held.
    pub live: u32,
    /// The next operation's creation sequence (from 1).
    pub next_seq: u64,
    pub applied: u64,
}

impl<const N: usize> Default for FailoverRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> FailoverRegistry<N> {
    const PROFILE_OK: () = assert!(
        N.is_power_of_two(),
        "failover profile: N must be a power of two"
    );

    pub const fn new() -> Self {
        let () = Self::PROFILE_OK;
        FailoverRegistry {
            slots: [FoSlot::empty(); N],
            index: SlotIndex::new(),
            occupied: SlotSet::new(),
            admitted: N as u32,
            count: 0,
            live: 0,
            next_seq: 1,
            applied: 0,
        }
    }

    /// Initialise in place, admitting `admitted` records (clamped to `N`):
    /// every byte of the state.
    pub fn reset(&mut self, admitted: u32) {
        let () = Self::PROFILE_OK;
        let mut i = 0;
        while i < N {
            self.slots[i] = FoSlot::empty();
            i += 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.admitted = if admitted as usize > N {
            N as u32
        } else {
            admitted
        };
        self.clear_counters();
    }

    /// Empty an initialised registry, keeping what it admits.
    pub fn clear(&mut self) {
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            self.slots[i] = FoSlot::empty();
            at = i + 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.clear_counters();
    }

    fn clear_counters(&mut self) {
        self.count = 0;
        self.live = 0;
        self.next_seq = 1;
        self.applied = 0;
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    fn find(&self, op: &[u8; FO_OP_ID]) -> Option<usize> {
        self.index.find(op).map(|i| i as usize)
    }

    pub fn lookup(&self, op: &[u8; FO_OP_ID]) -> Option<&[u8; FO_RECORD_LEN]> {
        self.find(op).map(|i| &self.slots[i].record)
    }

    /// The live record created next after `after_seq`: the replay cursor.
    /// `(seq, record)`; None once every live record has been visited.
    pub fn replay_next(&self, after_seq: u64) -> Option<(u64, &[u8; FO_RECORD_LEN])> {
        let mut best: Option<usize> = None;
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            let s = &self.slots[i];
            let earlier = match best {
                Some(b) => s.seq < self.slots[b].seq,
                None => true,
            };
            if s.seq > after_seq && !s.terminal() && earlier {
                best = Some(i);
            }
            at = i + 1;
        }
        best.map(|i| (self.slots[i].seq, &self.slots[i].record))
    }

    /// The slot a new operation takes: the lowest free one while the
    /// admitted count has room, else the oldest terminal record's.
    fn take_slot(&mut self) -> Option<usize> {
        if self.count < self.admitted {
            return self.occupied.lowest_free();
        }
        let mut oldest: Option<usize> = None;
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            let s = &self.slots[i];
            let earlier = match oldest {
                Some(o) => s.seq < self.slots[o].seq,
                None => true,
            };
            if s.terminal() && earlier {
                oldest = Some(i);
            }
            at = i + 1;
        }
        let i = oldest?;
        let op = record_op_id(&self.slots[i].record);
        let _ = self.index.remove(&op);
        self.occupied.free(i);
        self.slots[i] = FoSlot::empty();
        self.count -= 1;
        Some(i)
    }

    fn reply(&self, op: u8, status: u8, record: Option<&[u8; FO_RECORD_LEN]>) -> FailoverReply {
        FailoverReply {
            op,
            status,
            present: record.is_some(),
            live: self.live,
            record: match record {
                Some(r) => *r,
                None => [0; FO_RECORD_LEN],
            },
        }
    }

    /// Apply one committed command body. DETERMINISTIC. Returns the reply
    /// the proposing replica relays.
    pub fn apply(&mut self, body: &[u8], digest: DigestFn) -> FailoverReply {
        self.applied = self.applied.wrapping_add(1);
        let Some(&op) = body.first() else {
            return self.reply(0, FO_ST_INVALID, None);
        };
        match op {
            FO_OP_REPLAY if body.len() == FO_REPLAY_LEN => self.reply(op, FO_ST_OK, None),
            FO_OP_CAS if body.len() == FO_CAS_LEN => self.apply_cas(&body[1..], digest),
            _ => self.reply(op, FO_ST_INVALID, None),
        }
    }

    fn apply_cas(&mut self, rec: &[u8], digest: DigestFn) -> FailoverReply {
        if !record_valid(rec, digest) {
            return self.reply(FO_OP_CAS, FO_ST_INVALID, None);
        }
        let mut proposed = [0u8; FO_RECORD_LEN];
        proposed.copy_from_slice(rec);
        let op_id = record_op_id(&proposed);
        let phase = record_phase(&proposed);
        let generation = record_phase_generation(&proposed);
        let Some(i) = self.find(&op_id) else {
            if phase != FO_PH_INTENT || generation != 1 {
                return self.reply(FO_OP_CAS, FO_ST_CONFLICT, None);
            }
            let Some(i) = self.take_slot() else {
                return self.reply(FO_OP_CAS, FO_ST_CAPACITY, None);
            };
            if !self.index.insert(&op_id, i as u32) {
                return self.reply(FO_OP_CAS, FO_ST_CAPACITY, None);
            }
            self.occupied.mark(i);
            self.slots[i] = FoSlot {
                seq: self.next_seq,
                record: proposed,
            };
            self.next_seq += 1;
            self.count += 1;
            self.live += 1;
            return self.reply(FO_OP_CAS, FO_ST_OK, Some(&proposed));
        };
        let stored = self.slots[i].record;
        if stored == proposed {
            return self.reply(FO_OP_CAS, FO_ST_OK, Some(&stored));
        }
        let from = record_phase(&stored);
        let legal = same_operation(&stored, &proposed)
            && record_phase_generation(&stored).checked_add(1) == Some(generation)
            && transition_legal(stored[AT_KIND], stored[AT_FENCE], from, phase);
        if !legal {
            return self.reply(FO_OP_CAS, FO_ST_CONFLICT, Some(&stored));
        }
        self.slots[i].record = proposed;
        if phase_terminal(phase) {
            self.live -= 1;
        }
        self.reply(FO_OP_CAS, FO_ST_OK, Some(&proposed))
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header [version:u16 = 1][reserved:u16][arena N:u32][admitted:u32]
    //          [record_count:u32][next_seq:u64][applied:u64]
    //   record [slot:u32][seq:u64][record:264] × record_count, in slot
    //          order

    pub const SNAPSHOT_VERSION: u16 = 1;

    pub fn snapshot_len(&self) -> usize {
        FO_SNAP_HDR_LEN + self.count as usize * FO_SNAP_RECORD_LEN
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = FoExportCursor::new();
        let mut o = 0;
        loop {
            let n = self.export_next(&mut cur, &mut dst[o..]);
            if n == 0 {
                break;
            }
            o += n;
        }
        o as i32
    }

    /// Next unit of the streamed export into `dst` (≥ `FO_SNAP_MAX_UNIT`);
    /// 0 once complete.
    pub fn export_next(&self, cur: &mut FoExportCursor, dst: &mut [u8]) -> usize {
        if cur.stage == FO_EXPORT_RECORDS {
            match self.occupied.next_used(cur.pos as usize) {
                Some(i) => cur.pos = i as u32,
                None => cur.stage = FO_EXPORT_DONE,
            }
        }
        if dst.len() < FoInstaller::stage_len(cur.stage) {
            return 0;
        }
        match cur.stage {
            FO_EXPORT_HEADER => {
                dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                dst[2..4].copy_from_slice(&0u16.to_le_bytes());
                dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                dst[8..12].copy_from_slice(&self.admitted.to_le_bytes());
                dst[12..16].copy_from_slice(&self.count.to_le_bytes());
                dst[16..24].copy_from_slice(&self.next_seq.to_le_bytes());
                dst[24..32].copy_from_slice(&self.applied.to_le_bytes());
                cur.stage = FO_EXPORT_RECORDS;
                cur.pos = 0;
                FO_SNAP_HDR_LEN
            }
            FO_EXPORT_RECORDS => {
                let s = &self.slots[cur.pos as usize];
                dst[0..4].copy_from_slice(&cur.pos.to_le_bytes());
                dst[4..12].copy_from_slice(&s.seq.to_le_bytes());
                dst[12..12 + FO_RECORD_LEN].copy_from_slice(&s.record);
                cur.pos += 1;
                FO_SNAP_RECORD_LEN
            }
            _ => 0,
        }
    }

    /// Whole-image restore (host convenience). Fails closed with the
    /// registry cleared.
    pub fn restore(&mut self, src: &[u8], digest: DigestFn) -> bool {
        let mut ins = self.install_begin();
        let mut o = 0;
        while o < src.len() {
            match self.install_feed(&mut ins, &src[o..], digest) {
                Ok(n) if n > 0 => o += n,
                _ => break,
            }
        }
        if o != src.len() {
            ins.failed = true;
        }
        self.install_finish(&mut ins)
    }

    pub fn install_begin(&mut self) -> FoInstaller {
        self.clear();
        FoInstaller::new()
    }

    pub fn install_feed(
        &mut self,
        ins: &mut FoInstaller,
        bytes: &[u8],
        digest: DigestFn,
    ) -> Result<usize, FoInstallRejected> {
        if ins.failed {
            return Err(FoInstallRejected);
        }
        let mut taken = 0;
        while ins.stage != FO_EXPORT_DONE && taken < bytes.len() {
            let want = FoInstaller::stage_len(ins.stage);
            let need = want - ins.carry_len as usize;
            let take = need.min(bytes.len() - taken);
            ins.carry[ins.carry_len as usize..ins.carry_len as usize + take]
                .copy_from_slice(&bytes[taken..taken + take]);
            ins.carry_len += take as u16;
            taken += take;
            if (ins.carry_len as usize) < want {
                break;
            }
            let ok = self.install_unit(ins, digest);
            ins.carry_len = 0;
            if !ok {
                ins.failed = true;
                self.clear();
                return Err(FoInstallRejected);
            }
        }
        Ok(taken)
    }

    fn install_unit(&mut self, ins: &mut FoInstaller, digest: DigestFn) -> bool {
        let unit = ins.carry;
        match ins.stage {
            FO_EXPORT_HEADER => {
                if u16_at(&unit, 0) != Self::SNAPSHOT_VERSION
                    || u16_at(&unit, 2) != 0
                    || u32_at(&unit, 4) != N as u32
                {
                    return false;
                }
                let admitted = u32_at(&unit, 8);
                let count = u32_at(&unit, 12);
                let next_seq = u64_at(&unit, 16);
                if admitted != self.admitted || count > admitted || next_seq == 0 {
                    return false;
                }
                ins.expected = count;
                self.next_seq = next_seq;
                self.applied = u64_at(&unit, 24);
                ins.stage = if count == 0 {
                    FO_EXPORT_DONE
                } else {
                    FO_EXPORT_RECORDS
                };
                true
            }
            FO_EXPORT_RECORDS => {
                let slot = u32_at(&unit, 0) as usize;
                let seq = u64_at(&unit, 4);
                let rec = &unit[12..12 + FO_RECORD_LEN];
                if slot >= N
                    || self.occupied.is_used(slot)
                    || seq == 0
                    || seq >= self.next_seq
                    || !record_valid(rec, digest)
                {
                    return false;
                }
                let mut record = [0u8; FO_RECORD_LEN];
                record.copy_from_slice(rec);
                let op = record_op_id(&record);
                if self.find(&op).is_some() || !self.index.insert(&op, slot as u32) {
                    return false;
                }
                self.occupied.mark(slot);
                self.slots[slot] = FoSlot { seq, record };
                self.count += 1;
                if !self.slots[slot].terminal() {
                    self.live += 1;
                }
                ins.seen += 1;
                if ins.seen == ins.expected {
                    ins.stage = FO_EXPORT_DONE;
                }
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut FoInstaller) -> bool {
        let complete = !ins.failed && ins.stage == FO_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

pub const FO_SNAP_RECORD_LEN: usize = 4 + 8 + FO_RECORD_LEN;
pub const FO_SNAP_HDR_LEN: usize = 32;
pub const FO_SNAP_MAX_UNIT: usize = FO_SNAP_RECORD_LEN;

pub const FO_EXPORT_HEADER: u8 = 0;
pub const FO_EXPORT_RECORDS: u8 = 1;
pub const FO_EXPORT_DONE: u8 = 2;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoInstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FoExportCursor {
    pub stage: u8,
    pub pos: u32,
}

impl Default for FoExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl FoExportCursor {
    pub const fn new() -> Self {
        FoExportCursor {
            stage: FO_EXPORT_HEADER,
            pos: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == FO_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct FoInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    pub expected: u32,
    pub seen: u32,
    pub carry: [u8; FO_SNAP_MAX_UNIT],
}

impl Default for FoInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl FoInstaller {
    pub const fn new() -> Self {
        FoInstaller {
            stage: FO_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            expected: 0,
            seen: 0,
            carry: [0; FO_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == FO_EXPORT_DONE && !self.failed
    }

    /// Bytes one unit of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            FO_EXPORT_HEADER => FO_SNAP_HDR_LEN,
            FO_EXPORT_RECORDS => FO_SNAP_RECORD_LEN,
            _ => 0,
        }
    }
}
