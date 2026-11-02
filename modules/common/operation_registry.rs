// Operation registry — the `op/<operation_id>` namespace of the session
// directory: the replicated compare-and-swap store the coordinators that
// have no VIP-shaped record keep their restart-safe operations in, so every
// drain, ownership transfer and transport migration has one bounded
// operation record. `fo/` holds the traffic fabric's `WHFO` VIP moves; this
// namespace holds the other kinds under one envelope:
//
//   TAKEOVER    a transport-continuity takeover of one protected flow
//               (the fabric's `takeover_core::Takeover`: pair, planned or
//               crash), so a restarted continuity coordinator resumes from
//               the committed step;
//   EVACUATION  a failure-domain evacuation, practice run or restore
//               (`failure_domain_core`'s REQUESTED … COMPLETE);
//   REGION      a region controller's DR operation (`dr_core`'s admit, site
//               loss, regional drain, restore or recovery).
//
// Pure no_std, zero-alloc, DETERMINISTIC: `OperationRegistry::apply` is a
// pure function of (state, committed command body, digest fn); every
// replica applying the same committed sequence holds byte-identical state.
// No clocks, no randomness, no I/O. The PIC module wrapper
// (`modules/app/session_directory/mod.rs`) hosts it beside the other
// registries, dispatching on the `"OP"` magic; `clustor-common` mounts it
// for host tests and for the coordinators' store adapters.
//
// The record is fixed-length (`OP_RECORD_LEN`), sealed by its own SHA-256
// trailer, and held as its bytes:
//
//     0  magic "CLOP"  version u16 = 1  reserved u16
//     8  operation_id [16]
//    24  kind u8  step u8  flags u8  reserved u8
//    28  reserved u32
//    32  phase_generation u64        1 at intent, +1 per accepted write
//    40  intent [120]                fixed at the first write
//   160  progress [64]               free between writes, but see below
//   224  sha256(bytes 0..224) [32]
//
// `step` is the coordinator's own step or state enum, unchanged (the fabric's
// `TkStep`, `fd_state`, `DrStep` values); `intent[0]` names the kind's
// variant (the takeover sequence, the evacuation action, the DR operation
// kind). Clustor interprets only what the rule below needs; the rest of
// intent and progress is the coordinator's (the layouts it is proposed to
// use are in docs/architecture/session_directory.md).
//
// The rule a record may change by:
//
// - **a new operation starts at its intent.** The first write of an
//   operation id must be phase generation 1 at the kind's first step (a
//   takeover's `TrBind` for a pair, `StandbyApplied` for planned and crash;
//   an evacuation's REQUESTED; a DR operation's `Wait`), with no flag set.
// - **a retry is the record.** A byte-identical write answers `OK`.
// - **one step at a time.** Otherwise the write must be the same operation
//   (id, kind and intent unchanged), its phase generation the stored one
//   plus exactly one, from a non-terminal step, along an edge of the kind's
//   table (`step_legal`) — or a progress write that stays on its step.
// - **past the commit point only forward.** A takeover sets `COMMITTED`
//   exactly on the TR MOVE → SR ACTIVATE edge, may never clear it, every
//   step from SR ACTIVATE on requires it, and FALLBACK / FAILED require it
//   clear: once the higher flow epoch has committed there is no declared
//   fallback, only completion. The fence generation and the committed flow
//   epoch in its progress are fixed once set, and a committed record must
//   name both. An evacuation is never ABORTED from MOVING, DRAINING or
//   EVACUATED (an authority move in flight, or done); from RESTORING it
//   may be, which is the fabric's restart rolling a ramp in flight back. It
//   reaches BLOCKED_FENCE only from a phase that moves authority, MOVING
//   or RESTORING. A DR operation's steps only increase.
// - **a frame is checked whole.** Magic, version, reserved bytes, kind,
//   step and variant ranges, flags, and the digest trailer; a malformed
//   record is `INVALID` and nothing is stored.
// - **replay.** REPLAY `[kind]` changes no record: once it commits, the
//   module streams every live record of that kind (0: every kind) in the
//   order the operations were created.
// - **bounded retention.** A terminal record stays, answering retries,
//   until the arena is full; then the oldest terminal record gives its
//   slot to a new operation. A full arena of live operations refuses a new
//   one `CAPACITY`. Retention is what bounds idempotence: once a terminal
//   record has given its slot away, a late duplicate of its intent is a
//   new operation; the epochs a record carries keep such a re-run from
//   acting on authority that has since moved.
// - **bounded work.** Replay and eviction each walk the arena once per
//   record they find (at most 4096 on the server profile, tens of
//   microseconds); the module paces replay at eight records a step. A
//   creation sequence that would pass `u64::MAX` is refused `CAPACITY`.

use super::slot_index::{SlotIndex, SlotSet};

// ── Capacity ────────────────────────────────────────────────────────

/// Profiles: operation records per group. A takeover is one record per
/// protected-flow migration in flight; evacuations and DR operations are
/// rare. The arena bounds live operations plus terminal history kept for
/// retries.
pub const OP_PROFILE_RP2350: usize = 16;
pub const OP_PROFILE_PI5: usize = 256;
pub const OP_PROFILE_SERVER: usize = 4096;

// ── Record ──────────────────────────────────────────────────────────

pub const OP_RECORD_LEN: usize = 256;
/// Bytes the record's SHA-256 trailer covers.
pub const OP_BODY_LEN: usize = 224;
pub const OP_ID: usize = 16;
pub const OP_MAGIC: [u8; 4] = *b"CLOP";
pub const OP_VERSION: u16 = 1;
pub const OP_INTENT_LEN: usize = 120;
pub const OP_PROGRESS_LEN: usize = 64;

/// Record offsets.
pub const OP_AT_ID: usize = 8;
pub const OP_AT_KIND: usize = 24;
pub const OP_AT_STEP: usize = 25;
pub const OP_AT_FLAGS: usize = 26;
pub const OP_AT_GEN: usize = 32;
pub const OP_AT_INTENT: usize = 40;
pub const OP_AT_PROGRESS: usize = 160;

/// Kinds.
pub const OP_KIND_TAKEOVER: u8 = 1;
pub const OP_KIND_EVACUATION: u8 = 2;
pub const OP_KIND_REGION: u8 = 3;

/// `flags`: the takeover's commit point has passed (TR MOVE committed).
pub const OP_FLAG_COMMITTED: u8 = 1;

// Takeover (`intent[0]` = the traffic fabric's `TkKind`; `step` = `TkStep`).
pub const TK_SEQ_PAIR: u8 = 1;
pub const TK_SEQ_PLANNED: u8 = 2;
pub const TK_SEQ_CRASH: u8 = 3;

pub const TK_TR_BIND: u8 = 1;
pub const TK_SR_BIND: u8 = 2;
pub const TK_PAIR_PRIMARY: u8 = 3;
pub const TK_PAIR_STANDBY: u8 = 4;
pub const TK_CUSTODY: u8 = 5;
pub const TK_CHECKPOINT: u8 = 6;
pub const TK_STANDBY_APPLIED: u8 = 7;
pub const TK_MARK_PRIMARY: u8 = 8;
pub const TK_MARK_STANDBY: u8 = 9;
pub const TK_QUIESCE: u8 = 10;
pub const TK_CUT_IMPORTED: u8 = 11;
pub const TK_ARM: u8 = 12;
pub const TK_FENCE_LOCAL: u8 = 13;
pub const TK_FENCE_EXTERNAL: u8 = 14;
pub const TK_SR_FENCE_REQUEST: u8 = 15;
pub const TK_SR_FENCE_CONFIRM: u8 = 16;
pub const TK_COUNTER_FLOOR: u8 = 17;
pub const TK_TR_MOVE: u8 = 18;
pub const TK_SR_ACTIVATE: u8 = 19;
pub const TK_TOMBSTONE: u8 = 20;
pub const TK_ROUTE_MOVE: u8 = 21;
pub const TK_ACTIVATE: u8 = 22;
pub const TK_STABILIZE: u8 = 23;
pub const TK_RETIRE_OLD: u8 = 24;
pub const TK_DONE: u8 = 25;
pub const TK_FALLBACK: u8 = 26;
pub const TK_FAILED: u8 = 27;

/// Takeover progress offsets (within the record): the fence generation
/// the takeover consumed and the flow epoch TR MOVE committed — the
/// per-flow emission token's fields.
pub const TK_AT_FENCE_GEN: usize = OP_AT_PROGRESS + 8;
pub const TK_AT_NEW_TR_EPOCH: usize = OP_AT_PROGRESS + 12;

// Evacuation (`intent[0]` = the traffic fabric's `fd_action`; `step` = `fd_state`).
pub const EV_ACTION_LAST: u8 = 6;
pub const EV_REQUESTED: u8 = 1;
pub const EV_PREFLIGHTED: u8 = 2;
pub const EV_DIALING_OUT: u8 = 3;
pub const EV_MOVING: u8 = 4;
pub const EV_DRAINING: u8 = 5;
pub const EV_EVACUATED: u8 = 6;
pub const EV_OBSERVING: u8 = 7;
pub const EV_RESTORING: u8 = 8;
pub const EV_COMPLETE: u8 = 9;
pub const EV_ABORTED: u8 = 10;
pub const EV_BLOCKED_FENCE: u8 = 11;

// DR operation (`intent[0]` = the traffic fabric's `fx_kind`; `step` = `DrStep`).
pub const RC_KIND_LAST: u8 = 5;
pub const RC_WAIT: u8 = 1;
pub const RC_DONE: u8 = 11;

/// Whether `step` is a terminal step of `kind`.
pub const fn step_terminal(kind: u8, step: u8) -> bool {
    match kind {
        OP_KIND_TAKEOVER => matches!(step, TK_DONE | TK_FALLBACK | TK_FAILED),
        OP_KIND_EVACUATION => matches!(step, EV_COMPLETE | EV_ABORTED | EV_BLOCKED_FENCE),
        OP_KIND_REGION => step == RC_DONE,
        _ => false,
    }
}

const fn step_max(kind: u8) -> u8 {
    match kind {
        OP_KIND_TAKEOVER => TK_FAILED,
        OP_KIND_EVACUATION => EV_BLOCKED_FENCE,
        OP_KIND_REGION => RC_DONE,
        _ => 0,
    }
}

const fn variant_max(kind: u8) -> u8 {
    match kind {
        OP_KIND_TAKEOVER => TK_SEQ_CRASH,
        OP_KIND_EVACUATION => EV_ACTION_LAST,
        OP_KIND_REGION => RC_KIND_LAST,
        _ => 0,
    }
}

/// The step a new operation of `kind` (variant `variant`) is written at.
pub const fn first_step(kind: u8, variant: u8) -> u8 {
    match kind {
        OP_KIND_TAKEOVER => {
            if variant == TK_SEQ_PAIR {
                TK_TR_BIND
            } else {
                TK_STANDBY_APPLIED
            }
        }
        OP_KIND_EVACUATION => EV_REQUESTED,
        OP_KIND_REGION => RC_WAIT,
        _ => 0,
    }
}

/// The takeover's forward path (the traffic fabric's `takeover_core` sequences):
/// whether `to` follows `from` in sequence `seq`.
const fn takeover_next(seq: u8, from: u8, to: u8) -> bool {
    match seq {
        TK_SEQ_PAIR => matches!(
            (from, to),
            (TK_TR_BIND, TK_SR_BIND)
                | (TK_SR_BIND, TK_PAIR_PRIMARY)
                | (TK_PAIR_PRIMARY, TK_PAIR_STANDBY)
                | (TK_PAIR_STANDBY, TK_CUSTODY)
                | (TK_CUSTODY, TK_CHECKPOINT)
                | (TK_CHECKPOINT, TK_STANDBY_APPLIED)
                | (TK_STANDBY_APPLIED, TK_MARK_PRIMARY)
                | (TK_MARK_PRIMARY, TK_MARK_STANDBY)
                | (TK_MARK_STANDBY, TK_DONE)
        ),
        TK_SEQ_PLANNED => matches!(
            (from, to),
            (TK_STANDBY_APPLIED, TK_QUIESCE)
                | (TK_QUIESCE, TK_CUT_IMPORTED)
                | (TK_CUT_IMPORTED, TK_ARM)
                | (TK_ARM, TK_FENCE_LOCAL)
                | (TK_FENCE_LOCAL, TK_SR_FENCE_REQUEST)
                | (TK_SR_FENCE_REQUEST, TK_SR_FENCE_CONFIRM)
                | (TK_SR_FENCE_CONFIRM, TK_COUNTER_FLOOR)
                | (TK_SR_FENCE_CONFIRM, TK_TR_MOVE)
                | (TK_COUNTER_FLOOR, TK_TR_MOVE)
                | (TK_TR_MOVE, TK_SR_ACTIVATE)
                | (TK_SR_ACTIVATE, TK_TOMBSTONE)
                | (TK_TOMBSTONE, TK_ROUTE_MOVE)
                | (TK_ROUTE_MOVE, TK_ACTIVATE)
                | (TK_ACTIVATE, TK_STABILIZE)
                | (TK_STABILIZE, TK_RETIRE_OLD)
                | (TK_RETIRE_OLD, TK_DONE)
        ),
        TK_SEQ_CRASH => matches!(
            (from, to),
            (TK_STANDBY_APPLIED, TK_ARM)
                | (TK_ARM, TK_FENCE_EXTERNAL)
                | (TK_FENCE_EXTERNAL, TK_SR_FENCE_REQUEST)
                | (TK_SR_FENCE_REQUEST, TK_SR_FENCE_CONFIRM)
                | (TK_SR_FENCE_CONFIRM, TK_COUNTER_FLOOR)
                | (TK_SR_FENCE_CONFIRM, TK_TR_MOVE)
                | (TK_COUNTER_FLOOR, TK_TR_MOVE)
                | (TK_TR_MOVE, TK_SR_ACTIVATE)
                | (TK_SR_ACTIVATE, TK_TOMBSTONE)
                | (TK_TOMBSTONE, TK_ROUTE_MOVE)
                | (TK_ROUTE_MOVE, TK_ACTIVATE)
                | (TK_ACTIVATE, TK_DONE)
        ),
        _ => false,
    }
}

/// The evacuation's edges (the traffic fabric's `failure_domain_core`; a writer may
/// persist only the later of two states one call passes through).
const fn evacuation_next(from: u8, to: u8) -> bool {
    match to {
        EV_ABORTED => matches!(
            from,
            EV_REQUESTED | EV_PREFLIGHTED | EV_DIALING_OUT | EV_OBSERVING | EV_RESTORING
        ),
        EV_BLOCKED_FENCE => matches!(from, EV_MOVING | EV_RESTORING),
        _ => matches!(
            (from, to),
            (EV_REQUESTED, EV_PREFLIGHTED)
                | (EV_REQUESTED, EV_DIALING_OUT)
                | (EV_PREFLIGHTED, EV_DIALING_OUT)
                | (EV_DIALING_OUT, EV_MOVING)
                | (EV_DIALING_OUT, EV_DRAINING)
                | (EV_MOVING, EV_DRAINING)
                | (EV_DRAINING, EV_EVACUATED)
                | (EV_DRAINING, EV_OBSERVING)
                | (EV_EVACUATED, EV_OBSERVING)
                | (EV_OBSERVING, EV_RESTORING)
                | (EV_RESTORING, EV_COMPLETE)
        ),
    }
}

/// Whether a write may take a stored record at `from` (flags `f_from`) to
/// `to` (flags `f_to`), for an operation of `kind`, variant `variant`. A
/// write that stays on its step is a progress write: legal from any
/// non-terminal step with the flags unchanged.
pub const fn step_legal(kind: u8, variant: u8, from: u8, to: u8, f_from: u8, f_to: u8) -> bool {
    if step_terminal(kind, from) {
        return false;
    }
    if kind != OP_KIND_TAKEOVER {
        if f_from != 0 || f_to != 0 {
            return false;
        }
        return from == to
            || match kind {
                OP_KIND_EVACUATION => evacuation_next(from, to),
                OP_KIND_REGION => to > from,
                _ => false,
            };
    }
    let was = f_from & OP_FLAG_COMMITTED != 0;
    let now = f_to & OP_FLAG_COMMITTED != 0;
    // The commit point: set exactly as TR MOVE's commit moves the
    // sequence on to SR ACTIVATE, and never cleared.
    if was && !now {
        return false;
    }
    if now != was && !(from == TK_TR_MOVE && to == TK_SR_ACTIVATE) {
        return false;
    }
    if from == TK_TR_MOVE && to == TK_SR_ACTIVATE && !now {
        return false;
    }
    if from == to {
        return true;
    }
    match to {
        TK_FALLBACK | TK_FAILED => !was,
        _ => takeover_next(variant, from, to),
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

/// Whether `rec` is a well-formed record: the frame, the ranges, the flags
/// a kind may carry, a committed takeover naming its fence and epoch, and
/// the digest trailer.
pub fn record_valid(rec: &[u8], digest: DigestFn) -> bool {
    if rec.len() != OP_RECORD_LEN
        || rec[0..4] != OP_MAGIC
        || u16_at(rec, 4) != OP_VERSION
        || u16_at(rec, 6) != 0
        || rec[27] != 0
        || rec[28..32] != [0; 4]
    {
        return false;
    }
    let kind = rec[OP_AT_KIND];
    let step = rec[OP_AT_STEP];
    let flags = rec[OP_AT_FLAGS];
    let variant = rec[OP_AT_INTENT];
    if !(OP_KIND_TAKEOVER..=OP_KIND_REGION).contains(&kind)
        || step == 0
        || step > step_max(kind)
        || variant == 0
        || variant > variant_max(kind)
        || u64_at(rec, OP_AT_GEN) == 0
    {
        return false;
    }
    if kind == OP_KIND_TAKEOVER {
        if flags & !OP_FLAG_COMMITTED != 0 {
            return false;
        }
        if flags & OP_FLAG_COMMITTED != 0
            && (u32_at(rec, TK_AT_FENCE_GEN) == 0 || u32_at(rec, TK_AT_NEW_TR_EPOCH) == 0)
        {
            return false;
        }
    } else if flags != 0 {
        return false;
    }
    digest(&rec[..OP_BODY_LEN])[..] == rec[OP_BODY_LEN..]
}

/// Whether `b` is the same operation as `a`: id, kind and intent equal.
pub fn same_operation(a: &[u8; OP_RECORD_LEN], b: &[u8; OP_RECORD_LEN]) -> bool {
    a[OP_AT_ID..OP_AT_KIND + 1] == b[OP_AT_ID..OP_AT_KIND + 1]
        && a[OP_AT_INTENT..OP_AT_PROGRESS] == b[OP_AT_INTENT..OP_AT_PROGRESS]
}

pub fn record_op_id(rec: &[u8; OP_RECORD_LEN]) -> [u8; OP_ID] {
    let mut id = [0u8; OP_ID];
    id.copy_from_slice(&rec[OP_AT_ID..OP_AT_ID + OP_ID]);
    id
}

pub fn record_kind(rec: &[u8; OP_RECORD_LEN]) -> u8 {
    rec[OP_AT_KIND]
}

pub fn record_step(rec: &[u8; OP_RECORD_LEN]) -> u8 {
    rec[OP_AT_STEP]
}

pub fn record_generation(rec: &[u8; OP_RECORD_LEN]) -> u64 {
    u64_at(rec, OP_AT_GEN)
}

pub fn record_terminal(rec: &[u8; OP_RECORD_LEN]) -> bool {
    step_terminal(rec[OP_AT_KIND], rec[OP_AT_STEP])
}

/// The takeover progress fields that are authority once set: the fence
/// generation consumed and the flow epoch committed. A write may set
/// either from zero, never change one already set.
fn takeover_fixed_kept(a: &[u8; OP_RECORD_LEN], b: &[u8; OP_RECORD_LEN]) -> bool {
    let kept = |o: usize| {
        let was = u32_at(a, o);
        was == 0 || was == u32_at(b, o)
    };
    kept(TK_AT_FENCE_GEN) && kept(TK_AT_NEW_TR_EPOCH)
}

// ── Commands ────────────────────────────────────────────────────────

/// Compare-and-swap one record: `[op:1][record:256]`.
pub const OP_OP_CAS: u8 = 1;
/// A read through the log, after which the module streams every live
/// record of a kind (0: every kind): `[op:1][kind:1]`.
pub const OP_OP_REPLAY: u8 = 2;

pub const OP_CAS_LEN: usize = 1 + OP_RECORD_LEN;
pub const OP_REPLAY_LEN: usize = 2;
pub const OP_MAX_CMD: usize = OP_CAS_LEN;

pub fn build_cas(dst: &mut [u8], record: &[u8; OP_RECORD_LEN]) -> usize {
    if dst.len() < OP_CAS_LEN {
        return 0;
    }
    dst[0] = OP_OP_CAS;
    dst[1..OP_CAS_LEN].copy_from_slice(record);
    OP_CAS_LEN
}

pub fn build_replay(dst: &mut [u8], kind: u8) -> usize {
    if dst.len() < OP_REPLAY_LEN || kind > OP_KIND_REGION {
        return 0;
    }
    dst[0] = OP_OP_REPLAY;
    dst[1] = kind;
    OP_REPLAY_LEN
}

// ── Reply ───────────────────────────────────────────────────────────

/// The proposal is the stored record (newly, or a byte-identical retry).
pub const OP_ST_OK: u8 = 0;
/// Refused; the stored record (if any) follows.
pub const OP_ST_CONFLICT: u8 = 1;
/// A live record streamed after a committed REPLAY.
pub const OP_ST_REPLAY: u8 = 2;
/// Malformed; nothing stored.
pub const OP_ST_INVALID: u8 = 3;
/// A new operation with every slot held by a live one.
pub const OP_ST_CAPACITY: u8 = 4;

/// Encoded reply: `[op:1][status:1][present:1][kind:1][live:4]
/// [record:256]` — `fo/`'s shape, with the reserved byte naming the kind a
/// REPLAY asked for. `present` says whether `record` is a stored record;
/// `live` is the count of non-terminal records after the apply (for the
/// end of a replay, the count streamed). The statuses are `fo/`'s.
pub const OP_REPLY_LEN: usize = 8 + OP_RECORD_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct OperationReply {
    pub op: u8,
    pub status: u8,
    pub present: bool,
    pub kind: u8,
    pub live: u32,
    pub record: [u8; OP_RECORD_LEN],
}

impl OperationReply {
    pub const fn zero() -> Self {
        OperationReply {
            op: 0,
            status: 0,
            present: false,
            kind: 0,
            live: 0,
            record: [0; OP_RECORD_LEN],
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < OP_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2] = self.present as u8;
        dst[3] = self.kind;
        dst[4..8].copy_from_slice(&self.live.to_le_bytes());
        dst[8..OP_REPLY_LEN].copy_from_slice(&self.record);
        OP_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<OperationReply> {
        if src.len() < OP_REPLY_LEN || src[2] > 1 || src[3] > OP_KIND_REGION {
            return None;
        }
        let mut record = [0u8; OP_RECORD_LEN];
        record.copy_from_slice(&src[8..OP_REPLY_LEN]);
        Some(OperationReply {
            op: src[0],
            status: src[1],
            present: src[2] != 0,
            kind: src[3],
            live: u32_at(src, 4),
            record,
        })
    }
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct OpSlot {
    /// Creation order: the registry's `next_seq` when the intent landed.
    /// Zero for a free slot.
    pub seq: u64,
    pub record: [u8; OP_RECORD_LEN],
}

impl OpSlot {
    pub const fn empty() -> Self {
        OpSlot {
            seq: 0,
            record: [0; OP_RECORD_LEN],
        }
    }

    pub fn terminal(&self) -> bool {
        record_terminal(&self.record)
    }
}

/// The replicated state machine. `N` is the record arena (a power of two).
#[repr(C)]
pub struct OperationRegistry<const N: usize> {
    pub slots: [OpSlot; N],
    /// operation id → slot. Derived; rebuilt on restore.
    index: SlotIndex<N, OP_ID>,
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

impl<const N: usize> Default for OperationRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> OperationRegistry<N> {
    const PROFILE_OK: () = assert!(
        N.is_power_of_two(),
        "operation profile: N must be a power of two"
    );

    pub const fn new() -> Self {
        let () = Self::PROFILE_OK;
        OperationRegistry {
            slots: [OpSlot::empty(); N],
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
            self.slots[i] = OpSlot::empty();
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
            self.slots[i] = OpSlot::empty();
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

    fn find(&self, op: &[u8; OP_ID]) -> Option<usize> {
        self.index.find(op).map(|i| i as usize)
    }

    pub fn lookup(&self, op: &[u8; OP_ID]) -> Option<&[u8; OP_RECORD_LEN]> {
        self.find(op).map(|i| &self.slots[i].record)
    }

    /// The live record of `kind` (0: any) created next after `after_seq`:
    /// the replay cursor. `(seq, record)`; None once every such record has
    /// been visited.
    pub fn replay_next(&self, after_seq: u64, kind: u8) -> Option<(u64, &[u8; OP_RECORD_LEN])> {
        let mut best: Option<usize> = None;
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            let s = &self.slots[i];
            let earlier = match best {
                Some(b) => s.seq < self.slots[b].seq,
                None => true,
            };
            let wanted = kind == 0 || record_kind(&s.record) == kind;
            if s.seq > after_seq && !s.terminal() && wanted && earlier {
                best = Some(i);
            }
            at = i + 1;
        }
        best.map(|i| (self.slots[i].seq, &self.slots[i].record))
    }

    /// The slot a new operation takes: the lowest free one while the
    /// admitted count has room, else the oldest terminal record's.
    /// Whether some record already carries creation sequence `seq`: no
    /// two may, or replay, which orders by it, would skip one.
    fn holds_seq(&self, seq: u64) -> bool {
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            if self.slots[i].seq == seq {
                return true;
            }
            at = i + 1;
        }
        false
    }

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
        self.slots[i] = OpSlot::empty();
        self.count -= 1;
        Some(i)
    }

    fn reply(&self, op: u8, status: u8, record: Option<&[u8; OP_RECORD_LEN]>) -> OperationReply {
        OperationReply {
            op,
            status,
            present: record.is_some(),
            kind: record.map_or(0, record_kind),
            live: self.live,
            record: match record {
                Some(r) => *r,
                None => [0; OP_RECORD_LEN],
            },
        }
    }

    /// Apply one committed command body. DETERMINISTIC. Returns the reply
    /// the proposing replica relays.
    pub fn apply(&mut self, body: &[u8], digest: DigestFn) -> OperationReply {
        self.applied = self.applied.wrapping_add(1);
        let Some(&op) = body.first() else {
            return self.reply(0, OP_ST_INVALID, None);
        };
        match op {
            OP_OP_REPLAY if body.len() == OP_REPLAY_LEN && body[1] <= OP_KIND_REGION => {
                let mut r = self.reply(op, OP_ST_OK, None);
                r.kind = body[1];
                r
            }
            OP_OP_CAS if body.len() == OP_CAS_LEN => self.apply_cas(&body[1..], digest),
            _ => self.reply(op, OP_ST_INVALID, None),
        }
    }

    fn apply_cas(&mut self, rec: &[u8], digest: DigestFn) -> OperationReply {
        if !record_valid(rec, digest) {
            return self.reply(OP_OP_CAS, OP_ST_INVALID, None);
        }
        let mut proposed = [0u8; OP_RECORD_LEN];
        proposed.copy_from_slice(rec);
        let op_id = record_op_id(&proposed);
        let kind = record_kind(&proposed);
        let step = record_step(&proposed);
        let generation = record_generation(&proposed);
        let variant = proposed[OP_AT_INTENT];
        let Some(i) = self.find(&op_id) else {
            if generation != 1 || step != first_step(kind, variant) || proposed[OP_AT_FLAGS] != 0 {
                return self.reply(OP_OP_CAS, OP_ST_CONFLICT, None);
            }
            let Some(next_seq) = self.next_seq.checked_add(1) else {
                return self.reply(OP_OP_CAS, OP_ST_CAPACITY, None);
            };
            let Some(i) = self.take_slot() else {
                return self.reply(OP_OP_CAS, OP_ST_CAPACITY, None);
            };
            // `take_slot` answers a slot inside the arena, which the index
            // always takes.
            let _ = self.index.insert(&op_id, i as u32);
            self.occupied.mark(i);
            self.slots[i] = OpSlot {
                seq: self.next_seq,
                record: proposed,
            };
            self.next_seq = next_seq;
            self.count += 1;
            self.live += 1;
            return self.reply(OP_OP_CAS, OP_ST_OK, Some(&proposed));
        };
        let stored = self.slots[i].record;
        if stored == proposed {
            return self.reply(OP_OP_CAS, OP_ST_OK, Some(&stored));
        }
        let legal = same_operation(&stored, &proposed)
            && record_generation(&stored).checked_add(1) == Some(generation)
            && step_legal(
                kind,
                variant,
                record_step(&stored),
                step,
                stored[OP_AT_FLAGS],
                proposed[OP_AT_FLAGS],
            )
            && (kind != OP_KIND_TAKEOVER || takeover_fixed_kept(&stored, &proposed));
        if !legal {
            return self.reply(OP_OP_CAS, OP_ST_CONFLICT, Some(&stored));
        }
        self.slots[i].record = proposed;
        if record_terminal(&proposed) {
            self.live -= 1;
        }
        self.reply(OP_OP_CAS, OP_ST_OK, Some(&proposed))
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header [version:u16 = 1][reserved:u16][arena N:u32][admitted:u32]
    //          [record_count:u32][next_seq:u64][applied:u64]
    //   record [slot:u32][seq:u64][record:256] × record_count, in slot
    //          order

    pub const SNAPSHOT_VERSION: u16 = 1;

    pub fn snapshot_len(&self) -> usize {
        OP_SNAP_HDR_LEN + self.count as usize * OP_SNAP_RECORD_LEN
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = OpExportCursor::new();
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

    /// Next unit of the streamed export into `dst` (≥ `OP_SNAP_MAX_UNIT`);
    /// 0 once complete.
    pub fn export_next(&self, cur: &mut OpExportCursor, dst: &mut [u8]) -> usize {
        if cur.stage == OP_EXPORT_RECORDS {
            match self.occupied.next_used(cur.pos as usize) {
                Some(i) => cur.pos = i as u32,
                None => cur.stage = OP_EXPORT_DONE,
            }
        }
        if dst.len() < OpInstaller::stage_len(cur.stage) {
            return 0;
        }
        match cur.stage {
            OP_EXPORT_HEADER => {
                dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                dst[2..4].copy_from_slice(&0u16.to_le_bytes());
                dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                dst[8..12].copy_from_slice(&self.admitted.to_le_bytes());
                dst[12..16].copy_from_slice(&self.count.to_le_bytes());
                dst[16..24].copy_from_slice(&self.next_seq.to_le_bytes());
                dst[24..32].copy_from_slice(&self.applied.to_le_bytes());
                cur.stage = OP_EXPORT_RECORDS;
                cur.pos = 0;
                OP_SNAP_HDR_LEN
            }
            OP_EXPORT_RECORDS => {
                let s = &self.slots[cur.pos as usize];
                dst[0..4].copy_from_slice(&cur.pos.to_le_bytes());
                dst[4..12].copy_from_slice(&s.seq.to_le_bytes());
                dst[12..12 + OP_RECORD_LEN].copy_from_slice(&s.record);
                cur.pos += 1;
                OP_SNAP_RECORD_LEN
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

    pub fn install_begin(&mut self) -> OpInstaller {
        self.clear();
        OpInstaller::new()
    }

    pub fn install_feed(
        &mut self,
        ins: &mut OpInstaller,
        bytes: &[u8],
        digest: DigestFn,
    ) -> Result<usize, OpInstallRejected> {
        if ins.failed {
            return Err(OpInstallRejected);
        }
        let mut taken = 0;
        while ins.stage != OP_EXPORT_DONE && taken < bytes.len() {
            let want = OpInstaller::stage_len(ins.stage);
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
                return Err(OpInstallRejected);
            }
        }
        Ok(taken)
    }

    fn install_unit(&mut self, ins: &mut OpInstaller, digest: DigestFn) -> bool {
        let unit = ins.carry;
        match ins.stage {
            OP_EXPORT_HEADER => {
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
                    OP_EXPORT_DONE
                } else {
                    OP_EXPORT_RECORDS
                };
                true
            }
            OP_EXPORT_RECORDS => {
                let slot = u32_at(&unit, 0) as usize;
                let seq = u64_at(&unit, 4);
                let rec = &unit[12..12 + OP_RECORD_LEN];
                if slot >= N
                    || self.occupied.is_used(slot)
                    || seq == 0
                    || seq >= self.next_seq
                    || self.holds_seq(seq)
                    || !record_valid(rec, digest)
                {
                    return false;
                }
                let mut record = [0u8; OP_RECORD_LEN];
                record.copy_from_slice(rec);
                let op = record_op_id(&record);
                if self.find(&op).is_some() || !self.index.insert(&op, slot as u32) {
                    return false;
                }
                self.occupied.mark(slot);
                self.slots[slot] = OpSlot { seq, record };
                self.count += 1;
                if !self.slots[slot].terminal() {
                    self.live += 1;
                }
                ins.seen += 1;
                if ins.seen == ins.expected {
                    ins.stage = OP_EXPORT_DONE;
                }
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut OpInstaller) -> bool {
        let complete = !ins.failed && ins.stage == OP_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

pub const OP_SNAP_RECORD_LEN: usize = 4 + 8 + OP_RECORD_LEN;
pub const OP_SNAP_HDR_LEN: usize = 32;
pub const OP_SNAP_MAX_UNIT: usize = OP_SNAP_RECORD_LEN;

pub const OP_EXPORT_HEADER: u8 = 0;
pub const OP_EXPORT_RECORDS: u8 = 1;
pub const OP_EXPORT_DONE: u8 = 2;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpInstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct OpExportCursor {
    pub stage: u8,
    pub pos: u32,
}

impl Default for OpExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl OpExportCursor {
    pub const fn new() -> Self {
        OpExportCursor {
            stage: OP_EXPORT_HEADER,
            pos: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == OP_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OpInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    pub expected: u32,
    pub seen: u32,
    pub carry: [u8; OP_SNAP_MAX_UNIT],
}

impl Default for OpInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl OpInstaller {
    pub const fn new() -> Self {
        OpInstaller {
            stage: OP_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            expected: 0,
            seen: 0,
            carry: [0; OP_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == OP_EXPORT_DONE && !self.failed
    }

    /// Bytes one unit of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            OP_EXPORT_HEADER => OP_SNAP_HDR_LEN,
            OP_EXPORT_RECORDS => OP_SNAP_RECORD_LEN,
            _ => 0,
        }
    }
}
