// Transport registry — the `transport/<flow_id>` namespace of the session
// directory: the replicated state machine that owns a protected
// flow's primary anchor, its ordered standbys, its emitter epoch and the
// mirror horizon its standbys have acknowledged.
//
// Pure no_std, zero-alloc, DETERMINISTIC: `TransportRegistry::apply` is a
// pure function of (state, committed command body); every replica applying
// the same committed sequence holds byte-identical state. No clocks, no
// randomness, no I/O. The PIC module wrapper
// (`modules/app/session_directory/mod.rs`) hosts it beside the session
// registry, dispatching on the `"TR"` magic; `clustor-common` mounts it for
// host tests.
//
// What the registry enforces:
//
// - **one emitter per flow.** A flow has one primary anchor; the `epoch`
//   advances on every binding change (BIND, MOVE, TOMBSTONE), and every
//   command names the epoch it expects, so a stale coordinator is refused
//   `STALE_EPOCH` rather than racing a later one. A cached binding is valid
//   exactly while its epoch is the committed one. The epoch never wraps: a
//   change that would carry it past `u32::MAX` is refused `INVALID`.
// - **promotion only of a committed standby**. MOVE
//   promotes a listed standby whose acknowledged mirror horizon covers the
//   primary's committed horizon; a host that is not a standby is refused
//   `NOT_A_STANDBY`, and a standby whose horizon is behind `MIRROR_BEHIND`.
//   Choosing a healthy but state-empty host is exactly the failure the
//   binding exists to prevent.
// - **monotone mirror horizons.** MIRROR_MARK records `(mirror_epoch,
//   mirror_generation)` for the primary (the committed horizon) or for one
//   standby (what it has acknowledged); each only moves forward.
// - **idempotent operations.** Every command carries `operation_id[16]`.
//   The record remembers its last operation, whole: a byte-identical retry
//   gets the recorded reply back; a different command reusing the id is
//   refused `CONFLICT`. The dedupe window is one operation per flow (and
//   one for the registry-level RECOVERY_MARK), bounded by construction.
// - **tombstones before release.** TOMBSTONE ends emission (a migrated or
//   closed flow); the record stays, refusing everything but RETIRE, which
//   frees the slot. A tombstone keeps the operation-id history of the
//   flow's last transition for the audit horizon the operator chooses.
// - **unsafe-recovery voiding.** RECOVERY_MARK voids every bound flow:
//   MIRROR_MARK and MOVE are refused `RECOVERY_VOID` until a BIND at the
//   committed epoch re-establishes the binding under a new one.
//
// A proposer routes a flow to its group by `wire::shard_for_key` over
// `wire::fnv1a_64(flow_id)` — a virtual shard, fixed for the cluster's
// life, whatever group holds it now — and the module's `partition_id`
// names the group whose shards this registry holds.

use super::slot_index::{SlotIndex, SlotSet};

// ── Capacity ────────────────────────────────────────────────────────

/// Standby anchors one flow lists, in promotion order.
pub const TR_MAX_STANDBYS: usize = 3;

/// Profiles: flows per group (one group's share of a profile's
/// paired-anchor envelope).
pub const TR_PROFILE_RP2350: usize = 64;
pub const TR_PROFILE_PI5: usize = 4096;
pub const TR_PROFILE_SERVER: usize = 65536;

// ── Command opcodes ─────────────────────────────────────────────────

pub const TR_OP_BIND: u8 = 1;
pub const TR_OP_MOVE: u8 = 2;
pub const TR_OP_MIRROR_MARK: u8 = 3;
pub const TR_OP_TOMBSTONE: u8 = 4;
pub const TR_OP_RETIRE: u8 = 5;
pub const TR_OP_RECOVERY_MARK: u8 = 6;

// ── Status codes ────────────────────────────────────────────────────

pub const TR_ST_OK: u8 = 0;
/// Malformed, oversize or semantically impossible input.
pub const TR_ST_INVALID: u8 = 1;
/// Expected epoch is behind (or ahead of) the committed one.
pub const TR_ST_STALE_EPOCH: u8 = 2;
/// Operation id reused by a different command.
pub const TR_ST_CONFLICT: u8 = 3;
pub const TR_ST_UNKNOWN_FLOW: u8 = 4;
pub const TR_ST_NO_CAPACITY: u8 = 5;
/// MOVE names an anchor that is not a listed standby.
pub const TR_ST_NOT_A_STANDBY: u8 = 6;
/// MOVE names a standby whose acknowledged horizon is behind the committed
/// one (RPO-zero takeover would lose state).
pub const TR_ST_MIRROR_BEHIND: u8 = 7;
/// MIRROR_MARK moving a horizon backwards.
pub const TR_ST_MIRROR_REGRESSION: u8 = 8;
/// The flow is tombstoned; only RETIRE applies.
pub const TR_ST_TOMBSTONED: u8 = 9;
/// Voided by unsafe recovery until re-bound.
pub const TR_ST_RECOVERY_VOID: u8 = 10;
/// RECOVERY_MARK with a non-advancing recovery epoch.
pub const TR_ST_RECOVERY_STALE: u8 = 11;

// ── Record states ───────────────────────────────────────────────────

pub const TR_STATE_FREE: u8 = 0;
pub const TR_STATE_BOUND: u8 = 1;
pub const TR_STATE_TOMBSTONE: u8 = 2;

// ── Field sizes / payload layouts ───────────────────────────────────

pub const TR_FLOW_ID: usize = 16;
pub const TR_OP_ID: usize = 16;
pub const TR_ANCHOR_ID: usize = 8;

// Command layouts (after the opcode byte), all LE. Every flow command
// begins `[op_id:16][flow:16][expected_epoch:4]`.
//
//   BIND          [op_id][flow][expected_epoch][primary:8][standby_count:1]
//                 [standbys:8 × 3]
//                   expected_epoch 0 creates the flow at epoch 1; otherwise
//                   it must be the committed epoch and the primary must be
//                   the committed primary (a primary moves by MOVE); the
//                   standby set is replaced and the epoch advances.
//   MOVE          [op_id][flow][expected_epoch][new_primary:8]
//   MIRROR_MARK   [op_id][flow][expected_epoch][anchor:8][mirror_epoch:8]
//                 [mirror_generation:8]
//                   anchor = the primary → the committed horizon; a standby
//                   → that standby's acknowledged horizon.
//   TOMBSTONE     [op_id][flow][expected_epoch]
//   RETIRE        [op_id][flow][expected_epoch]
//   RECOVERY_MARK [op_id][recovery_epoch:4]

pub const TR_COMMON_LEN: usize = 1 + TR_OP_ID + TR_FLOW_ID + 4;
pub const TR_BIND_LEN: usize = TR_COMMON_LEN + TR_ANCHOR_ID + 1 + TR_ANCHOR_ID * TR_MAX_STANDBYS;
pub const TR_MOVE_LEN: usize = TR_COMMON_LEN + TR_ANCHOR_ID;
pub const TR_MIRROR_MARK_LEN: usize = TR_COMMON_LEN + TR_ANCHOR_ID + 8 + 8;
pub const TR_TOMBSTONE_LEN: usize = TR_COMMON_LEN;
pub const TR_RETIRE_LEN: usize = TR_COMMON_LEN;
pub const TR_RECOVERY_MARK_LEN: usize = 1 + TR_OP_ID + 4;
/// Largest command body (BIND).
pub const TR_MAX_CMD: usize = TR_BIND_LEN;

// ── Reply ───────────────────────────────────────────────────────────

/// Encoded reply: `[op:1][status:1][flow:16][epoch:4][mirror_epoch:8]
/// [mirror_generation:8]` — the session reply's shape, so a requester
/// reads committed session and mirror epochs from either namespace the
/// same way. `epoch` is the committed emitter epoch; the mirror pair is
/// the primary's committed horizon (RECOVERY_MARK: voided-flow count and
/// the new recovery epoch).
pub const TR_REPLY_LEN: usize = 1 + 1 + TR_FLOW_ID + 4 + 8 + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TransportReply {
    pub op: u8,
    pub status: u8,
    pub flow_id: [u8; TR_FLOW_ID],
    pub epoch: u32,
    pub mirror_epoch: u64,
    pub mirror_generation: u64,
}

impl TransportReply {
    pub const fn zero() -> Self {
        TransportReply {
            op: 0,
            status: 0,
            flow_id: [0; TR_FLOW_ID],
            epoch: 0,
            mirror_epoch: 0,
            mirror_generation: 0,
        }
    }

    fn fail(op: u8, status: u8) -> Self {
        TransportReply {
            op,
            status,
            ..Self::zero()
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < TR_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2..18].copy_from_slice(&self.flow_id);
        dst[18..22].copy_from_slice(&self.epoch.to_le_bytes());
        dst[22..30].copy_from_slice(&self.mirror_epoch.to_le_bytes());
        dst[30..38].copy_from_slice(&self.mirror_generation.to_le_bytes());
        TR_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<TransportReply> {
        if src.len() < TR_REPLY_LEN {
            return None;
        }
        let mut flow_id = [0u8; TR_FLOW_ID];
        flow_id.copy_from_slice(&src[2..18]);
        Some(TransportReply {
            op: src[0],
            status: src[1],
            flow_id,
            epoch: u32_at(src, 18),
            mirror_epoch: u64_at(src, 22),
            mirror_generation: u64_at(src, 30),
        })
    }
}

fn u32_at(src: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
}

fn u64_at(src: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        src[o],
        src[o + 1],
        src[o + 2],
        src[o + 3],
        src[o + 4],
        src[o + 5],
        src[o + 6],
        src[o + 7],
    ])
}

// ── Command builders (proposer side) ────────────────────────────────

fn put_common(
    dst: &mut [u8],
    op: u8,
    op_id: &[u8; TR_OP_ID],
    flow: &[u8; TR_FLOW_ID],
    expected_epoch: u32,
) -> usize {
    dst[0] = op;
    dst[1..17].copy_from_slice(op_id);
    dst[17..33].copy_from_slice(flow);
    dst[33..37].copy_from_slice(&expected_epoch.to_le_bytes());
    TR_COMMON_LEN
}

pub fn build_bind(
    dst: &mut [u8],
    op_id: &[u8; TR_OP_ID],
    flow: &[u8; TR_FLOW_ID],
    expected_epoch: u32,
    primary: &[u8; TR_ANCHOR_ID],
    standbys: &[[u8; TR_ANCHOR_ID]],
) -> usize {
    if dst.len() < TR_BIND_LEN || standbys.len() > TR_MAX_STANDBYS {
        return 0;
    }
    let mut o = put_common(dst, TR_OP_BIND, op_id, flow, expected_epoch);
    dst[o..o + 8].copy_from_slice(primary);
    o += 8;
    dst[o] = standbys.len() as u8;
    o += 1;
    let mut i = 0;
    while i < TR_MAX_STANDBYS {
        if i < standbys.len() {
            dst[o..o + 8].copy_from_slice(&standbys[i]);
        } else {
            dst[o..o + 8].copy_from_slice(&[0u8; 8]);
        }
        o += 8;
        i += 1;
    }
    TR_BIND_LEN
}

pub fn build_move(
    dst: &mut [u8],
    op_id: &[u8; TR_OP_ID],
    flow: &[u8; TR_FLOW_ID],
    expected_epoch: u32,
    new_primary: &[u8; TR_ANCHOR_ID],
) -> usize {
    if dst.len() < TR_MOVE_LEN {
        return 0;
    }
    let o = put_common(dst, TR_OP_MOVE, op_id, flow, expected_epoch);
    dst[o..o + 8].copy_from_slice(new_primary);
    TR_MOVE_LEN
}

pub fn build_mirror_mark(
    dst: &mut [u8],
    op_id: &[u8; TR_OP_ID],
    flow: &[u8; TR_FLOW_ID],
    expected_epoch: u32,
    anchor: &[u8; TR_ANCHOR_ID],
    mirror_epoch: u64,
    mirror_generation: u64,
) -> usize {
    if dst.len() < TR_MIRROR_MARK_LEN {
        return 0;
    }
    let o = put_common(dst, TR_OP_MIRROR_MARK, op_id, flow, expected_epoch);
    dst[o..o + 8].copy_from_slice(anchor);
    dst[o + 8..o + 16].copy_from_slice(&mirror_epoch.to_le_bytes());
    dst[o + 16..o + 24].copy_from_slice(&mirror_generation.to_le_bytes());
    TR_MIRROR_MARK_LEN
}

pub fn build_tombstone(
    dst: &mut [u8],
    op_id: &[u8; TR_OP_ID],
    flow: &[u8; TR_FLOW_ID],
    expected_epoch: u32,
) -> usize {
    if dst.len() < TR_TOMBSTONE_LEN {
        return 0;
    }
    put_common(dst, TR_OP_TOMBSTONE, op_id, flow, expected_epoch)
}

pub fn build_retire(
    dst: &mut [u8],
    op_id: &[u8; TR_OP_ID],
    flow: &[u8; TR_FLOW_ID],
    expected_epoch: u32,
) -> usize {
    if dst.len() < TR_RETIRE_LEN {
        return 0;
    }
    put_common(dst, TR_OP_RETIRE, op_id, flow, expected_epoch)
}

pub fn build_recovery_mark(dst: &mut [u8], op_id: &[u8; TR_OP_ID], recovery_epoch: u32) -> usize {
    if dst.len() < TR_RECOVERY_MARK_LEN {
        return 0;
    }
    dst[0] = TR_OP_RECOVERY_MARK;
    dst[1..17].copy_from_slice(op_id);
    dst[17..21].copy_from_slice(&recovery_epoch.to_le_bytes());
    TR_RECOVERY_MARK_LEN
}

// ── State ───────────────────────────────────────────────────────────

/// The last operation a record (or the registry) answered: the whole
/// command body, so a retry is recognised by comparing bytes — never by a
/// hash, which a different command could collide with and be answered as
/// if it had applied — and the reply to repeat to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct OpMemo {
    pub present: bool,
    pub cmd_len: u8,
    pub cmd: [u8; TR_MAX_CMD],
    pub reply: TransportReply,
}

impl OpMemo {
    pub const fn empty() -> Self {
        OpMemo {
            present: false,
            cmd_len: 0,
            cmd: [0; TR_MAX_CMD],
            reply: TransportReply::zero(),
        }
    }

    /// `Some(reply)` for a byte-identical retry; `Err(())` for a
    /// conflicting reuse of the operation id; `Ok(None)` for a new
    /// operation. `body` carries its operation id at `[1..17]`.
    fn check(&self, body: &[u8]) -> Result<Option<TransportReply>, ()> {
        if !self.present || self.cmd[1..17] != body[1..17] {
            return Ok(None);
        }
        if self.cmd_len as usize == body.len() && self.cmd[..body.len()] == *body {
            return Ok(Some(self.reply));
        }
        Err(())
    }

    fn record(&mut self, body: &[u8], reply: TransportReply) {
        let n = body.len().min(TR_MAX_CMD);
        self.cmd = [0; TR_MAX_CMD];
        self.cmd[..n].copy_from_slice(&body[..n]);
        self.cmd_len = n as u8;
        self.present = true;
        self.reply = reply;
    }

    /// `[present:1][cmd_len:1][cmd: TR_MAX_CMD][reply: TR_REPLY_LEN]`.
    pub const LEN: usize = 1 + 1 + TR_MAX_CMD + TR_REPLY_LEN;

    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.present as u8;
        dst[1] = self.cmd_len;
        dst[2..2 + TR_MAX_CMD].copy_from_slice(&self.cmd);
        let _ = self
            .reply
            .encode(&mut dst[2 + TR_MAX_CMD..2 + TR_MAX_CMD + TR_REPLY_LEN]);
    }

    fn decode(src: &[u8]) -> Option<OpMemo> {
        if src[0] > 1 || src[1] as usize > TR_MAX_CMD {
            return None;
        }
        let mut cmd = [0u8; TR_MAX_CMD];
        cmd.copy_from_slice(&src[2..2 + TR_MAX_CMD]);
        Some(OpMemo {
            present: src[0] != 0,
            cmd_len: src[1],
            cmd,
            reply: TransportReply::decode(&src[2 + TR_MAX_CMD..2 + TR_MAX_CMD + TR_REPLY_LEN])?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FlowSlot {
    pub state: u8,
    /// Set by RECOVERY_MARK; cleared by a BIND that advances the epoch.
    pub voided: bool,
    pub standby_count: u8,
    pub epoch: u32,
    pub flow_id: [u8; TR_FLOW_ID],
    pub primary: [u8; TR_ANCHOR_ID],
    pub standbys: [[u8; TR_ANCHOR_ID]; TR_MAX_STANDBYS],
    /// The primary's committed horizon.
    pub mirror_epoch: u64,
    pub mirror_generation: u64,
    /// Each standby's acknowledged horizon.
    pub standby_mirror_epoch: [u64; TR_MAX_STANDBYS],
    pub standby_mirror_generation: [u64; TR_MAX_STANDBYS],
    pub last_op: OpMemo,
}

impl FlowSlot {
    pub const fn empty() -> Self {
        FlowSlot {
            state: TR_STATE_FREE,
            voided: false,
            standby_count: 0,
            epoch: 0,
            flow_id: [0; TR_FLOW_ID],
            primary: [0; TR_ANCHOR_ID],
            standbys: [[0; TR_ANCHOR_ID]; TR_MAX_STANDBYS],
            mirror_epoch: 0,
            mirror_generation: 0,
            standby_mirror_epoch: [0; TR_MAX_STANDBYS],
            standby_mirror_generation: [0; TR_MAX_STANDBYS],
            last_op: OpMemo::empty(),
        }
    }

    fn standby_index(&self, anchor: &[u8; TR_ANCHOR_ID]) -> Option<usize> {
        let mut i = 0;
        while i < self.standby_count as usize {
            if self.standbys[i] == *anchor {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Snapshot record layout (fixed `TR_SLOT_SNAP_LEN`):
    ///   [state:1][voided:1][standby_count:1][reserved:1][epoch:4]
    ///   [flow_id:16][primary:8][standbys:8×3][mirror_epoch:8]
    ///   [mirror_generation:8][standby_mirror_epoch:8×3]
    ///   [standby_mirror_generation:8×3][last_op: OpMemo::LEN]
    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.state;
        dst[1] = self.voided as u8;
        dst[2] = self.standby_count;
        dst[3] = 0;
        dst[4..8].copy_from_slice(&self.epoch.to_le_bytes());
        dst[8..24].copy_from_slice(&self.flow_id);
        dst[24..32].copy_from_slice(&self.primary);
        let mut o = 32;
        let mut i = 0;
        while i < TR_MAX_STANDBYS {
            dst[o..o + 8].copy_from_slice(&self.standbys[i]);
            o += 8;
            i += 1;
        }
        dst[o..o + 8].copy_from_slice(&self.mirror_epoch.to_le_bytes());
        dst[o + 8..o + 16].copy_from_slice(&self.mirror_generation.to_le_bytes());
        o += 16;
        i = 0;
        while i < TR_MAX_STANDBYS {
            dst[o..o + 8].copy_from_slice(&self.standby_mirror_epoch[i].to_le_bytes());
            dst[o + 24..o + 32].copy_from_slice(&self.standby_mirror_generation[i].to_le_bytes());
            o += 8;
            i += 1;
        }
        o += 24;
        self.last_op.encode(&mut dst[o..o + OpMemo::LEN]);
    }

    fn decode(src: &[u8]) -> Option<FlowSlot> {
        let mut s = FlowSlot::empty();
        s.state = src[0];
        if s.state > TR_STATE_TOMBSTONE || src[1] > 1 || src[2] as usize > TR_MAX_STANDBYS {
            return None;
        }
        s.voided = src[1] != 0;
        s.standby_count = src[2];
        s.epoch = u32_at(src, 4);
        s.flow_id.copy_from_slice(&src[8..24]);
        s.primary.copy_from_slice(&src[24..32]);
        let mut o = 32;
        let mut i = 0;
        while i < TR_MAX_STANDBYS {
            s.standbys[i].copy_from_slice(&src[o..o + 8]);
            o += 8;
            i += 1;
        }
        s.mirror_epoch = u64_at(src, o);
        s.mirror_generation = u64_at(src, o + 8);
        o += 16;
        i = 0;
        while i < TR_MAX_STANDBYS {
            s.standby_mirror_epoch[i] = u64_at(src, o);
            s.standby_mirror_generation[i] = u64_at(src, o + 24);
            o += 8;
            i += 1;
        }
        o += 24;
        s.last_op = OpMemo::decode(&src[o..o + OpMemo::LEN])?;
        Some(s)
    }
}

/// The replicated state machine. `N` is the flow arena (a power of two).
#[repr(C)]
pub struct TransportRegistry<const N: usize> {
    pub slots: [FlowSlot; N],
    /// flow id → slot. Derived; rebuilt on restore.
    index: SlotIndex<N, TR_FLOW_ID>,
    /// Which slots hold a flow; a new flow takes the lowest free one.
    /// Derived; rebuilt on restore.
    occupied: SlotSet<N>,
    pub admitted: u32,
    pub live: u32,
    pub recovery_epoch: u32,
    pub applied: u64,
    /// Last registry-level operation (RECOVERY_MARK).
    pub last_op: OpMemo,
}

impl<const N: usize> Default for TransportRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TransportRegistry<N> {
    const PROFILE_OK: () = assert!(
        N.is_power_of_two(),
        "transport profile: N must be a power of two"
    );

    pub const fn new() -> Self {
        let () = Self::PROFILE_OK;
        TransportRegistry {
            slots: [FlowSlot::empty(); N],
            index: SlotIndex::new(),
            occupied: SlotSet::new(),
            admitted: N as u32,
            live: 0,
            recovery_epoch: 0,
            applied: 0,
            last_op: OpMemo::empty(),
        }
    }

    /// Initialise in place, admitting `admitted` flows (clamped to `N`):
    /// every byte of the state, so it is what makes a raw state block a
    /// registry.
    pub fn reset(&mut self, admitted: u32) {
        let () = Self::PROFILE_OK;
        let mut i = 0;
        while i < N {
            self.slots[i] = FlowSlot::empty();
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

    /// Empty an initialised registry, keeping what it admits. A free slot
    /// is always `FlowSlot::empty()`, so only the occupied ones are
    /// cleared.
    pub fn clear(&mut self) {
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            self.slots[i] = FlowSlot::empty();
            at = i + 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.clear_counters();
    }

    fn clear_counters(&mut self) {
        self.live = 0;
        self.recovery_epoch = 0;
        self.applied = 0;
        self.last_op = OpMemo::empty();
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    fn find(&self, flow: &[u8; TR_FLOW_ID]) -> Option<usize> {
        self.index.find(flow).map(|i| i as usize)
    }

    /// The slot a new flow takes: the lowest free one, while the admitted
    /// count has room.
    fn find_free(&self) -> Option<usize> {
        if self.live >= self.admitted {
            return None;
        }
        self.occupied.lowest_free()
    }

    pub fn lookup(&self, flow: &[u8; TR_FLOW_ID]) -> Option<&FlowSlot> {
        self.find(flow).map(|i| &self.slots[i])
    }

    fn reply(op: u8, status: u8, slot: &FlowSlot) -> TransportReply {
        TransportReply {
            op,
            status,
            flow_id: slot.flow_id,
            epoch: slot.epoch,
            mirror_epoch: slot.mirror_epoch,
            mirror_generation: slot.mirror_generation,
        }
    }

    fn common(body: &[u8], want: usize) -> Option<([u8; TR_FLOW_ID], u32)> {
        if body.len() < want {
            return None;
        }
        let mut flow = [0u8; TR_FLOW_ID];
        flow.copy_from_slice(&body[17..33]);
        Some((flow, u32_at(body, 33)))
    }

    /// Apply one committed command body. DETERMINISTIC. Returns the reply
    /// the proposing replica relays.
    pub fn apply(&mut self, body: &[u8]) -> TransportReply {
        self.applied = self.applied.wrapping_add(1);
        if body.is_empty() {
            return TransportReply::fail(0, TR_ST_INVALID);
        }
        let op = body[0];
        if op == TR_OP_RECOVERY_MARK {
            return self.apply_recovery_mark(body);
        }
        let want = match op {
            TR_OP_BIND => TR_BIND_LEN,
            TR_OP_MOVE => TR_MOVE_LEN,
            TR_OP_MIRROR_MARK => TR_MIRROR_MARK_LEN,
            TR_OP_TOMBSTONE => TR_TOMBSTONE_LEN,
            TR_OP_RETIRE => TR_RETIRE_LEN,
            _ => return TransportReply::fail(op, TR_ST_INVALID),
        };
        let Some((flow, expected)) = Self::common(body, want) else {
            return TransportReply::fail(op, TR_ST_INVALID);
        };
        let found = self.find(&flow);
        // Idempotence first: a retry of the flow's last operation repeats
        // its reply whatever the state has become since.
        if let Some(i) = found {
            match self.slots[i].last_op.check(body) {
                Ok(Some(r)) => return r,
                Ok(None) => {}
                Err(()) => return Self::reply(op, TR_ST_CONFLICT, &self.slots[i]),
            }
        }
        let reply = match op {
            TR_OP_BIND => self.apply_bind(body, found, &flow, expected),
            _ => {
                let Some(i) = found else {
                    return TransportReply {
                        op,
                        status: TR_ST_UNKNOWN_FLOW,
                        flow_id: flow,
                        ..TransportReply::zero()
                    };
                };
                if self.slots[i].epoch != expected {
                    return Self::reply(op, TR_ST_STALE_EPOCH, &self.slots[i]);
                }
                match op {
                    TR_OP_MOVE => self.apply_move(body, i),
                    TR_OP_MIRROR_MARK => self.apply_mirror_mark(body, i),
                    TR_OP_TOMBSTONE => self.apply_tombstone(i),
                    _ => self.apply_retire(i),
                }
            }
        };
        // Record the operation on the (possibly new) record. A retired
        // flow keeps nothing: its slot is gone.
        if reply.status != TR_ST_UNKNOWN_FLOW {
            if let Some(i) = self.find(&flow) {
                self.slots[i].last_op.record(body, reply);
            }
        }
        reply
    }

    fn apply_bind(
        &mut self,
        body: &[u8],
        found: Option<usize>,
        flow: &[u8; TR_FLOW_ID],
        expected: u32,
    ) -> TransportReply {
        let mut primary = [0u8; TR_ANCHOR_ID];
        primary.copy_from_slice(&body[37..45]);
        let count = body[45] as usize;
        if count > TR_MAX_STANDBYS {
            return TransportReply {
                op: TR_OP_BIND,
                status: TR_ST_INVALID,
                flow_id: *flow,
                ..TransportReply::zero()
            };
        }
        let mut standbys = [[0u8; TR_ANCHOR_ID]; TR_MAX_STANDBYS];
        let mut i = 0;
        while i < count {
            standbys[i].copy_from_slice(&body[46 + i * 8..54 + i * 8]);
            // A standby that is the primary, or listed twice, is not a
            // standby set.
            if standbys[i] == primary {
                return TransportReply {
                    op: TR_OP_BIND,
                    status: TR_ST_INVALID,
                    flow_id: *flow,
                    ..TransportReply::zero()
                };
            }
            let mut j = 0;
            while j < i {
                if standbys[j] == standbys[i] {
                    return TransportReply {
                        op: TR_OP_BIND,
                        status: TR_ST_INVALID,
                        flow_id: *flow,
                        ..TransportReply::zero()
                    };
                }
                j += 1;
            }
            i += 1;
        }
        if let Some(i) = found {
            let slot = &mut self.slots[i];
            if slot.state == TR_STATE_TOMBSTONE {
                return Self::reply(TR_OP_BIND, TR_ST_TOMBSTONED, slot);
            }
            if expected != slot.epoch {
                return Self::reply(TR_OP_BIND, TR_ST_STALE_EPOCH, slot);
            }
            if primary != slot.primary {
                return Self::reply(TR_OP_BIND, TR_ST_INVALID, slot);
            }
            let Some(next) = slot.epoch.checked_add(1) else {
                return Self::reply(TR_OP_BIND, TR_ST_INVALID, slot);
            };
            // Re-binding the standby set: a standby kept in place keeps
            // its acknowledged horizon; a new one starts from nothing.
            let mut ack_e = [0u64; TR_MAX_STANDBYS];
            let mut ack_g = [0u64; TR_MAX_STANDBYS];
            let mut k = 0;
            while k < count {
                if let Some(old) = slot.standby_index(&standbys[k]) {
                    ack_e[k] = slot.standby_mirror_epoch[old];
                    ack_g[k] = slot.standby_mirror_generation[old];
                }
                k += 1;
            }
            slot.standbys = standbys;
            slot.standby_count = count as u8;
            slot.standby_mirror_epoch = ack_e;
            slot.standby_mirror_generation = ack_g;
            slot.epoch = next;
            slot.voided = false;
            return Self::reply(TR_OP_BIND, TR_ST_OK, slot);
        }
        if expected != 0 {
            return TransportReply {
                op: TR_OP_BIND,
                status: TR_ST_STALE_EPOCH,
                flow_id: *flow,
                ..TransportReply::zero()
            };
        }
        let Some(i) = self.find_free() else {
            return TransportReply {
                op: TR_OP_BIND,
                status: TR_ST_NO_CAPACITY,
                flow_id: *flow,
                ..TransportReply::zero()
            };
        };
        if !self.index.insert(flow, i as u32) {
            return TransportReply {
                op: TR_OP_BIND,
                status: TR_ST_NO_CAPACITY,
                flow_id: *flow,
                ..TransportReply::zero()
            };
        }
        self.occupied.mark(i);
        let slot = &mut self.slots[i];
        *slot = FlowSlot::empty();
        slot.state = TR_STATE_BOUND;
        slot.flow_id = *flow;
        slot.primary = primary;
        slot.standbys = standbys;
        slot.standby_count = count as u8;
        slot.epoch = 1;
        self.live += 1;
        Self::reply(TR_OP_BIND, TR_ST_OK, slot)
    }

    fn apply_move(&mut self, body: &[u8], i: usize) -> TransportReply {
        let mut new_primary = [0u8; TR_ANCHOR_ID];
        new_primary.copy_from_slice(&body[37..45]);
        let slot = &mut self.slots[i];
        if slot.state == TR_STATE_TOMBSTONE {
            return Self::reply(TR_OP_MOVE, TR_ST_TOMBSTONED, slot);
        }
        if slot.voided {
            return Self::reply(TR_OP_MOVE, TR_ST_RECOVERY_VOID, slot);
        }
        let Some(k) = slot.standby_index(&new_primary) else {
            return Self::reply(TR_OP_MOVE, TR_ST_NOT_A_STANDBY, slot);
        };
        if (
            slot.standby_mirror_epoch[k],
            slot.standby_mirror_generation[k],
        ) < (slot.mirror_epoch, slot.mirror_generation)
        {
            return Self::reply(TR_OP_MOVE, TR_ST_MIRROR_BEHIND, slot);
        }
        let Some(next) = slot.epoch.checked_add(1) else {
            return Self::reply(TR_OP_MOVE, TR_ST_INVALID, slot);
        };
        // The promoted standby leaves the standby list; the old primary is
        // not a standby (it holds no mirror of the new emitter) — it is
        // re-admitted by a BIND once it has re-mirrored.
        let mut j = k;
        while j + 1 < slot.standby_count as usize {
            slot.standbys[j] = slot.standbys[j + 1];
            slot.standby_mirror_epoch[j] = slot.standby_mirror_epoch[j + 1];
            slot.standby_mirror_generation[j] = slot.standby_mirror_generation[j + 1];
            j += 1;
        }
        let last = slot.standby_count as usize - 1;
        slot.standbys[last] = [0; TR_ANCHOR_ID];
        slot.standby_mirror_epoch[last] = 0;
        slot.standby_mirror_generation[last] = 0;
        slot.standby_count -= 1;
        slot.primary = new_primary;
        slot.epoch = next;
        Self::reply(TR_OP_MOVE, TR_ST_OK, slot)
    }

    fn apply_mirror_mark(&mut self, body: &[u8], i: usize) -> TransportReply {
        let mut anchor = [0u8; TR_ANCHOR_ID];
        anchor.copy_from_slice(&body[37..45]);
        let me = u64_at(body, 45);
        let mg = u64_at(body, 53);
        let slot = &mut self.slots[i];
        if slot.state == TR_STATE_TOMBSTONE {
            return Self::reply(TR_OP_MIRROR_MARK, TR_ST_TOMBSTONED, slot);
        }
        if slot.voided {
            return Self::reply(TR_OP_MIRROR_MARK, TR_ST_RECOVERY_VOID, slot);
        }
        if anchor == slot.primary {
            if (me, mg) < (slot.mirror_epoch, slot.mirror_generation) {
                return Self::reply(TR_OP_MIRROR_MARK, TR_ST_MIRROR_REGRESSION, slot);
            }
            slot.mirror_epoch = me;
            slot.mirror_generation = mg;
            return Self::reply(TR_OP_MIRROR_MARK, TR_ST_OK, slot);
        }
        let Some(k) = slot.standby_index(&anchor) else {
            return Self::reply(TR_OP_MIRROR_MARK, TR_ST_NOT_A_STANDBY, slot);
        };
        if (me, mg)
            < (
                slot.standby_mirror_epoch[k],
                slot.standby_mirror_generation[k],
            )
        {
            return Self::reply(TR_OP_MIRROR_MARK, TR_ST_MIRROR_REGRESSION, slot);
        }
        slot.standby_mirror_epoch[k] = me;
        slot.standby_mirror_generation[k] = mg;
        Self::reply(TR_OP_MIRROR_MARK, TR_ST_OK, slot)
    }

    fn apply_tombstone(&mut self, i: usize) -> TransportReply {
        let slot = &mut self.slots[i];
        if slot.state == TR_STATE_TOMBSTONE {
            return Self::reply(TR_OP_TOMBSTONE, TR_ST_TOMBSTONED, slot);
        }
        let Some(next) = slot.epoch.checked_add(1) else {
            return Self::reply(TR_OP_TOMBSTONE, TR_ST_INVALID, slot);
        };
        slot.state = TR_STATE_TOMBSTONE;
        slot.primary = [0; TR_ANCHOR_ID];
        slot.standbys = [[0; TR_ANCHOR_ID]; TR_MAX_STANDBYS];
        slot.standby_count = 0;
        slot.standby_mirror_epoch = [0; TR_MAX_STANDBYS];
        slot.standby_mirror_generation = [0; TR_MAX_STANDBYS];
        slot.epoch = next;
        Self::reply(TR_OP_TOMBSTONE, TR_ST_OK, slot)
    }

    fn apply_retire(&mut self, i: usize) -> TransportReply {
        if self.slots[i].state != TR_STATE_TOMBSTONE {
            return Self::reply(TR_OP_RETIRE, TR_ST_INVALID, &self.slots[i]);
        }
        let reply = Self::reply(TR_OP_RETIRE, TR_ST_OK, &self.slots[i]);
        let flow = self.slots[i].flow_id;
        let _ = self.index.remove(&flow);
        self.occupied.free(i);
        self.slots[i] = FlowSlot::empty();
        self.live -= 1;
        reply
    }

    fn apply_recovery_mark(&mut self, body: &[u8]) -> TransportReply {
        if body.len() < TR_RECOVERY_MARK_LEN {
            return TransportReply::fail(TR_OP_RECOVERY_MARK, TR_ST_INVALID);
        }
        match self.last_op.check(body) {
            Ok(Some(r)) => return r,
            Ok(None) => {}
            Err(()) => return TransportReply::fail(TR_OP_RECOVERY_MARK, TR_ST_CONFLICT),
        }
        let new_epoch = u32_at(body, 17);
        let reply = if new_epoch <= self.recovery_epoch {
            TransportReply::fail(TR_OP_RECOVERY_MARK, TR_ST_RECOVERY_STALE)
        } else {
            self.recovery_epoch = new_epoch;
            let mut voided = 0u64;
            let mut at = 0;
            while let Some(i) = self.occupied.next_used(at) {
                if self.slots[i].state == TR_STATE_BOUND {
                    self.slots[i].voided = true;
                    voided += 1;
                }
                at = i + 1;
            }
            TransportReply {
                op: TR_OP_RECOVERY_MARK,
                status: TR_ST_OK,
                flow_id: [0; TR_FLOW_ID],
                epoch: new_epoch,
                mirror_epoch: voided,
                mirror_generation: 0,
            }
        };
        self.last_op.record(body, reply);
        reply
    }

    // ── Snapshot (streamed, versioned) ──────────────────────────────
    //
    //   header [version:u16 = 2][reserved:u16][arena N:u32][admitted:u32]
    //          [record_count:u32][recovery_epoch:u32][applied:u64]
    //          [last_op: OpMemo::LEN]
    //   record [slot:u32][FlowSlot: TR_SLOT_SNAP_LEN] × record_count, in
    //          slot order

    pub const SNAPSHOT_VERSION: u16 = 2;

    pub fn snapshot_len(&self) -> usize {
        TR_SNAP_HDR_LEN + self.live as usize * TR_SNAP_RECORD_LEN
    }

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < self.snapshot_len() {
            return -1;
        }
        let mut cur = TrExportCursor::new();
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

    /// Next unit of the streamed export into `dst` (≥ `TR_SNAP_MAX_UNIT`);
    /// 0 once complete.
    pub fn export_next(&self, cur: &mut TrExportCursor, dst: &mut [u8]) -> usize {
        if cur.stage == TR_EXPORT_RECORDS {
            match self.occupied.next_used(cur.pos as usize) {
                Some(i) => cur.pos = i as u32,
                None => cur.stage = TR_EXPORT_DONE,
            }
        }
        if dst.len() < TrInstaller::stage_len(cur.stage) {
            return 0;
        }
        match cur.stage {
            TR_EXPORT_HEADER => {
                dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                dst[2..4].copy_from_slice(&0u16.to_le_bytes());
                dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                dst[8..12].copy_from_slice(&self.admitted.to_le_bytes());
                dst[12..16].copy_from_slice(&self.live.to_le_bytes());
                dst[16..20].copy_from_slice(&self.recovery_epoch.to_le_bytes());
                dst[20..28].copy_from_slice(&self.applied.to_le_bytes());
                self.last_op.encode(&mut dst[28..28 + OpMemo::LEN]);
                cur.stage = TR_EXPORT_RECORDS;
                cur.pos = 0;
                TR_SNAP_HDR_LEN
            }
            TR_EXPORT_RECORDS => {
                dst[0..4].copy_from_slice(&cur.pos.to_le_bytes());
                self.slots[cur.pos as usize].encode(&mut dst[4..4 + TR_SLOT_SNAP_LEN]);
                cur.pos += 1;
                TR_SNAP_RECORD_LEN
            }
            _ => 0,
        }
    }

    /// Whole-image restore (host convenience). Fails closed with the
    /// registry cleared.
    pub fn restore(&mut self, src: &[u8]) -> bool {
        let mut ins = self.install_begin();
        let mut o = 0;
        while o < src.len() {
            match self.install_feed(&mut ins, &src[o..]) {
                Ok(n) if n > 0 => o += n,
                _ => break,
            }
        }
        // Bytes past the image's end are not an image.
        if o != src.len() {
            ins.failed = true;
        }
        self.install_finish(&mut ins)
    }

    pub fn install_begin(&mut self) -> TrInstaller {
        self.clear();
        TrInstaller::new()
    }

    pub fn install_feed(
        &mut self,
        ins: &mut TrInstaller,
        bytes: &[u8],
    ) -> Result<usize, InstallRejected> {
        if ins.failed {
            return Err(InstallRejected);
        }
        let mut taken = 0;
        while ins.stage != TR_EXPORT_DONE && taken < bytes.len() {
            let want = TrInstaller::stage_len(ins.stage);
            let need = want - ins.carry_len as usize;
            let take = need.min(bytes.len() - taken);
            ins.carry[ins.carry_len as usize..ins.carry_len as usize + take]
                .copy_from_slice(&bytes[taken..taken + take]);
            ins.carry_len += take as u16;
            taken += take;
            if (ins.carry_len as usize) < want {
                break;
            }
            let ok = self.install_unit(ins);
            ins.carry_len = 0;
            if !ok {
                ins.failed = true;
                self.clear();
                return Err(InstallRejected);
            }
        }
        Ok(taken)
    }

    fn install_unit(&mut self, ins: &mut TrInstaller) -> bool {
        let unit = ins.carry;
        match ins.stage {
            TR_EXPORT_HEADER => {
                if u16::from_le_bytes([unit[0], unit[1]]) != Self::SNAPSHOT_VERSION
                    || u32_at(&unit, 4) != N as u32
                {
                    return false;
                }
                let admitted = u32_at(&unit, 8);
                let count = u32_at(&unit, 12);
                if admitted != self.admitted || count > admitted {
                    return false;
                }
                let Some(last_op) = OpMemo::decode(&unit[28..28 + OpMemo::LEN]) else {
                    return false;
                };
                ins.expected = count;
                self.recovery_epoch = u32_at(&unit, 16);
                self.applied = u64_at(&unit, 20);
                self.last_op = last_op;
                ins.stage = if count == 0 {
                    TR_EXPORT_DONE
                } else {
                    TR_EXPORT_RECORDS
                };
                true
            }
            TR_EXPORT_RECORDS => {
                let slot = u32_at(&unit, 0) as usize;
                let Some(rec) = FlowSlot::decode(&unit[4..4 + TR_SLOT_SNAP_LEN]) else {
                    return false;
                };
                if slot >= N || rec.state == TR_STATE_FREE || self.occupied.is_used(slot) {
                    return false;
                }
                if self.find(&rec.flow_id).is_some()
                    || !self.index.insert(&rec.flow_id, slot as u32)
                {
                    return false;
                }
                self.occupied.mark(slot);
                self.slots[slot] = rec;
                self.live += 1;
                ins.seen += 1;
                if ins.seen == ins.expected {
                    ins.stage = TR_EXPORT_DONE;
                }
                true
            }
            _ => false,
        }
    }

    pub fn install_finish(&mut self, ins: &mut TrInstaller) -> bool {
        let complete = !ins.failed && ins.stage == TR_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
        }
        complete
    }
}

/// Per-flow snapshot record (see `FlowSlot::encode`): 32 header and
/// identity bytes, 24 of standbys, 16 of the primary's horizon, 48 of the
/// standbys' horizons, then the memo.
pub const TR_SLOT_SNAP_LEN: usize = 120 + OpMemo::LEN;
pub const TR_SNAP_RECORD_LEN: usize = 4 + TR_SLOT_SNAP_LEN;
pub const TR_SNAP_HDR_LEN: usize = 28 + OpMemo::LEN;
pub const TR_SNAP_MAX_UNIT: usize = TR_SNAP_RECORD_LEN;

pub const TR_EXPORT_HEADER: u8 = 0;
pub const TR_EXPORT_RECORDS: u8 = 1;
pub const TR_EXPORT_DONE: u8 = 2;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallRejected;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TrExportCursor {
    pub stage: u8,
    pub pos: u32,
}

impl Default for TrExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl TrExportCursor {
    pub const fn new() -> Self {
        TrExportCursor {
            stage: TR_EXPORT_HEADER,
            pos: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == TR_EXPORT_DONE
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    pub expected: u32,
    pub seen: u32,
    pub carry: [u8; TR_SNAP_MAX_UNIT],
}

impl Default for TrInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl TrInstaller {
    pub const fn new() -> Self {
        TrInstaller {
            stage: TR_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            expected: 0,
            seen: 0,
            carry: [0; TR_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == TR_EXPORT_DONE && !self.failed
    }

    /// Bytes one unit of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            TR_EXPORT_HEADER => TR_SNAP_HDR_LEN,
            TR_EXPORT_RECORDS => TR_SNAP_RECORD_LEN,
            _ => 0,
        }
    }
}
