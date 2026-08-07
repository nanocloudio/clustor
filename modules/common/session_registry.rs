// Session registry — the replicated state machine behind the session
// directory role (fluxor rfc_protocols.md §8.3, §13.7).
//
// Pure no_std, zero-alloc, DETERMINISTIC: `SessionRegistry::apply` is a
// pure function of (state, committed command body). Every replica that
// applies the same committed sequence arrives at byte-identical state —
// the property the whole design leans on. No clocks, no randomness, no
// I/O in this file. The PIC module wrapper
// (`modules/app/session_directory/mod.rs`) owns channels, proposal
// correlation, and telemetry; the cargo crate `clustor-common` mounts
// this file for host tests.
//
// What the registry is, in RFC terms:
//
// - the **single-writer session directory**: one authoritative
//   (anchor, worker) binding per `(session_id, session_epoch)`;
//   competing stale writers are rejected (§8.3).
// - the **reservation authority** for the hot egress counters
//   (§13.7.2, R2): counter blocks are granted monotonically from a
//   per-(session, counter) high-water mark and NEVER re-handed out.
//   The grant reply reaches the proposer only after the command is
//   quorum-committed (the module replies from the committed-entry
//   stream, not from proposal submission) — "quorum-durable before
//   emit" holds by construction.
// - the **receive-window floor** keeper (§13.7.3, R4): the durable
//   rx high-water only moves forward.
// - the **wrapped-key custodian** (§13.7.6, R1): session AEAD keys are
//   stored only as opaque KEK-wrapped blobs this registry cannot read,
//   with quorum wipe on teardown. TTL expiry rides the deterministic
//   replicated timing component (`modules/common/timing.rs`,
//   rfc_deterministic_timing.md): KEY_PUT with a TTL registers a
//   generation-fenced deadline in the embedded `TimingState`; the due
//   handler wipes the key while applying the committed time entry.
//   There is no second authoritative local timer queue (RFC §19.3).
// - the **fence-ordering gate** (§13.7.2a/§13.7.4, R3): an anchor
//   takeover (BIND that changes `anchor_id` on a fence-required
//   session) is refused until an out-of-band emission fence has been
//   recorded as CONFIRMED for that session. The registry cannot cut
//   power itself — enforceability is the fence backend's job (STONITH
//   / fabric egress cutoff; the fluxor rig's `kasa_local` power
//   backend is the reference) — but it enforces the ORDERING: no
//   takeover binding advances past an unconfirmed fence.
// - the **unsafe-recovery marker** (§13.7.6, R2): RECOVERY_MARK voids
//   every session's outstanding reservations and blocks further
//   grants until that session's epoch bumps. This is the consumer-
//   observable form of "unsafe recovery voids outstanding blocks".

use crate::timing::{Deadline, TimingState, TM_BATCH_MAX, TM_MAX_OWNERS};

// ── Capacity ────────────────────────────────────────────────────────

/// Concurrent sessions the registry tracks. Fixed so the state (and
/// its snapshot) has a static size.
pub const SR_MAX_SESSIONS: usize = 64;

/// Hot counters per session (§13.7.1 tier 3): 0 = egress AEAD nonce,
/// 1 = reliable-ordered send index, 2 = outbound datagram sequence.
pub const SR_NUM_COUNTERS: usize = 3;

/// Maximum KEK-wrapped key blob the registry stores (R1). Sized for a
/// 32-byte key + AEAD wrap overhead + key-id/metadata the WRAPPER
/// chose to include; the registry never parses it.
pub const SR_MAX_WRAPPED_KEY: usize = 80;

// ── Command opcodes (first byte of the replicated body) ─────────────

pub const SR_OP_BIND: u8 = 1;
pub const SR_OP_EPOCH_BUMP: u8 = 2;
pub const SR_OP_RESERVE: u8 = 3;
pub const SR_OP_RX_FLOOR: u8 = 4;
pub const SR_OP_KEY_PUT: u8 = 5;
pub const SR_OP_KEY_WIPE: u8 = 6;
pub const SR_OP_FENCE_REQUEST: u8 = 7;
pub const SR_OP_FENCE_CONFIRM: u8 = 8;
pub const SR_OP_UNBIND: u8 = 9;
pub const SR_OP_RECOVERY_MARK: u8 = 10;

// ── Status codes ────────────────────────────────────────────────────

pub const SR_ST_OK: u8 = 0;
/// Stale-epoch / competing-writer rejection (single-writer rule).
pub const SR_ST_STALE_EPOCH: u8 = 1;
pub const SR_ST_UNKNOWN_SESSION: u8 = 2;
pub const SR_ST_NO_CAPACITY: u8 = 3;
pub const SR_ST_MALFORMED: u8 = 4;
/// Grants void after unsafe recovery until the session epoch bumps (R2).
pub const SR_ST_RECOVERY_VOID: u8 = 5;
/// Anchor takeover attempted without a confirmed emission fence (R3).
pub const SR_ST_FENCE_REQUIRED: u8 = 6;
/// Receive-floor regression refused (R4).
pub const SR_ST_FLOOR_REGRESSION: u8 = 7;
/// RECOVERY_MARK with a non-advancing recovery epoch.
pub const SR_ST_RECOVERY_STALE: u8 = 8;
/// KEY_PUT with a TTL could not register its expiry deadline
/// (timing-index capacity or generation overflow). The command fails
/// without storing the key — capacity is checked as part of the same
/// apply operation (rfc_deterministic_timing.md §6.2).
pub const SR_ST_DEADLINE_CAPACITY: u8 = 9;

// ── Deterministic timing (rfc_deterministic_timing.md) ──────────────

/// Owner namespace for session-key TTL deadlines in the embedded
/// timing index. Deadline id = session_id; generation = the slot's
/// `key_gen` at KEY_PUT time.
pub const SR_OWNER_KEY_TTL: u16 = 0;

/// Per-owner deadline capacity partition for this state machine
/// (identical on every replica by deployment discipline; validated on
/// snapshot restore). Owner 0 = key TTLs, sized to the session table.
pub const SR_TIMING_CAPS: [u16; TM_MAX_OWNERS] = [SR_MAX_SESSIONS as u16, 0, 0, 0];

// ── BIND flags ──────────────────────────────────────────────────────

/// Session declares platform-replicated-state migration: anchor
/// takeover requires a confirmed emission fence (R3).
pub const SR_BIND_FENCE_REQUIRED: u8 = 0x01;

// ── Fence states ────────────────────────────────────────────────────

pub const SR_FENCE_NONE: u8 = 0;
pub const SR_FENCE_INITIATED: u8 = 1;
pub const SR_FENCE_CONFIRMED: u8 = 2;

// ── Field sizes / payload layouts ───────────────────────────────────

pub const SR_SESSION_ID: usize = 16;
pub const SR_PEER_ID: usize = 8;

// Command payload layouts (after the opcode byte). All numeric fields
// little-endian; identity fields are opaque byte strings compared raw
// (big-endian canonical form is the producer's concern, as in
// fluxor's SessionCtrlV1).
//
//   BIND          [sid:16][epoch:4][anchor:8][worker:8][flags:1]
//   EPOCH_BUMP    [sid:16][old:4][new:4]
//   RESERVE       [sid:16][epoch:4][counter:1][len:8]
//   RX_FLOOR      [sid:16][epoch:4][floor:8]
//   KEY_PUT       [sid:16][epoch:4][ttl_ms:4][blob_len:2][blob..]
//   KEY_WIPE      [sid:16][epoch:4]
//   FENCE_REQUEST [sid:16][epoch:4][target_anchor:8]
//   FENCE_CONFIRM [sid:16][epoch:4][target_anchor:8]
//   UNBIND        [sid:16][epoch:4]
//   RECOVERY_MARK [recovery_epoch:4]

pub const SR_BIND_LEN: usize = 1 + SR_SESSION_ID + 4 + SR_PEER_ID + SR_PEER_ID + 1;
pub const SR_EPOCH_BUMP_LEN: usize = 1 + SR_SESSION_ID + 4 + 4;
pub const SR_RESERVE_LEN: usize = 1 + SR_SESSION_ID + 4 + 1 + 8;
pub const SR_RX_FLOOR_LEN: usize = 1 + SR_SESSION_ID + 4 + 8;
pub const SR_KEY_PUT_HDR: usize = 1 + SR_SESSION_ID + 4 + 4 + 2;
pub const SR_KEY_WIPE_LEN: usize = 1 + SR_SESSION_ID + 4;
pub const SR_FENCE_LEN: usize = 1 + SR_SESSION_ID + 4 + SR_PEER_ID;
pub const SR_UNBIND_LEN: usize = 1 + SR_SESSION_ID + 4;
pub const SR_RECOVERY_MARK_LEN: usize = 1 + 4;

/// Largest command body (KEY_PUT with a maximal blob).
pub const SR_MAX_CMD: usize = SR_KEY_PUT_HDR + SR_MAX_WRAPPED_KEY;

// ── Reply ───────────────────────────────────────────────────────────

/// Encoded reply layout: `[op:1][status:1][sid:16][epoch:4][a:8][b:8]`.
/// `a`/`b` are op-specific: RESERVE → (block start, block len);
/// RX_FLOOR → (committed floor, 0); RECOVERY_MARK → (voided-session
/// count, new recovery epoch); otherwise zero.
pub const SR_REPLY_LEN: usize = 1 + 1 + SR_SESSION_ID + 4 + 8 + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionReply {
    pub op: u8,
    pub status: u8,
    pub session_id: [u8; SR_SESSION_ID],
    pub epoch: u32,
    pub a: u64,
    pub b: u64,
}

impl SessionReply {
    fn fail(op: u8, status: u8) -> Self {
        SessionReply {
            op,
            status,
            session_id: [0; SR_SESSION_ID],
            epoch: 0,
            a: 0,
            b: 0,
        }
    }

    pub fn encode(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < SR_REPLY_LEN {
            return -1;
        }
        dst[0] = self.op;
        dst[1] = self.status;
        dst[2..18].copy_from_slice(&self.session_id);
        dst[18..22].copy_from_slice(&self.epoch.to_le_bytes());
        dst[22..30].copy_from_slice(&self.a.to_le_bytes());
        dst[30..38].copy_from_slice(&self.b.to_le_bytes());
        SR_REPLY_LEN as i32
    }

    pub fn decode(src: &[u8]) -> Option<SessionReply> {
        if src.len() < SR_REPLY_LEN {
            return None;
        }
        let mut session_id = [0u8; SR_SESSION_ID];
        session_id.copy_from_slice(&src[2..18]);
        Some(SessionReply {
            op: src[0],
            status: src[1],
            session_id,
            epoch: u32::from_le_bytes([src[18], src[19], src[20], src[21]]),
            a: u64::from_le_bytes([
                src[22], src[23], src[24], src[25], src[26], src[27], src[28], src[29],
            ]),
            b: u64::from_le_bytes([
                src[30], src[31], src[32], src[33], src[34], src[35], src[36], src[37],
            ]),
        })
    }
}

// ── Command builders (proposer side) ────────────────────────────────
// Each returns the encoded length, or 0 when `dst` is too small /
// the argument is out of range. The same bytes are the replicated
// entry body the state machine applies.

fn put_common(dst: &mut [u8], op: u8, sid: &[u8; SR_SESSION_ID], epoch: u32) -> usize {
    dst[0] = op;
    dst[1..17].copy_from_slice(sid);
    dst[17..21].copy_from_slice(&epoch.to_le_bytes());
    21
}

pub fn build_bind(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    anchor: &[u8; SR_PEER_ID],
    worker: &[u8; SR_PEER_ID],
    flags: u8,
) -> usize {
    if dst.len() < SR_BIND_LEN {
        return 0;
    }
    let mut o = put_common(dst, SR_OP_BIND, sid, epoch);
    dst[o..o + 8].copy_from_slice(anchor);
    o += 8;
    dst[o..o + 8].copy_from_slice(worker);
    o += 8;
    dst[o] = flags;
    SR_BIND_LEN
}

pub fn build_epoch_bump(dst: &mut [u8], sid: &[u8; SR_SESSION_ID], old: u32, new: u32) -> usize {
    if dst.len() < SR_EPOCH_BUMP_LEN {
        return 0;
    }
    let o = put_common(dst, SR_OP_EPOCH_BUMP, sid, old);
    dst[o..o + 4].copy_from_slice(&new.to_le_bytes());
    SR_EPOCH_BUMP_LEN
}

pub fn build_reserve(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    counter: u8,
    len: u64,
) -> usize {
    if dst.len() < SR_RESERVE_LEN || counter as usize >= SR_NUM_COUNTERS {
        return 0;
    }
    let o = put_common(dst, SR_OP_RESERVE, sid, epoch);
    dst[o] = counter;
    dst[o + 1..o + 9].copy_from_slice(&len.to_le_bytes());
    SR_RESERVE_LEN
}

pub fn build_rx_floor(dst: &mut [u8], sid: &[u8; SR_SESSION_ID], epoch: u32, floor: u64) -> usize {
    if dst.len() < SR_RX_FLOOR_LEN {
        return 0;
    }
    let o = put_common(dst, SR_OP_RX_FLOOR, sid, epoch);
    dst[o..o + 8].copy_from_slice(&floor.to_le_bytes());
    SR_RX_FLOOR_LEN
}

pub fn build_key_put(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    ttl_ms: u32,
    blob: &[u8],
) -> usize {
    let total = SR_KEY_PUT_HDR + blob.len();
    if dst.len() < total || blob.is_empty() || blob.len() > SR_MAX_WRAPPED_KEY {
        return 0;
    }
    let mut o = put_common(dst, SR_OP_KEY_PUT, sid, epoch);
    dst[o..o + 4].copy_from_slice(&ttl_ms.to_le_bytes());
    o += 4;
    dst[o..o + 2].copy_from_slice(&(blob.len() as u16).to_le_bytes());
    o += 2;
    dst[o..o + blob.len()].copy_from_slice(blob);
    total
}

pub fn build_key_wipe(dst: &mut [u8], sid: &[u8; SR_SESSION_ID], epoch: u32) -> usize {
    if dst.len() < SR_KEY_WIPE_LEN {
        return 0;
    }
    put_common(dst, SR_OP_KEY_WIPE, sid, epoch);
    SR_KEY_WIPE_LEN
}

pub fn build_fence(
    dst: &mut [u8],
    op: u8,
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    target_anchor: &[u8; SR_PEER_ID],
) -> usize {
    if dst.len() < SR_FENCE_LEN || (op != SR_OP_FENCE_REQUEST && op != SR_OP_FENCE_CONFIRM) {
        return 0;
    }
    let o = put_common(dst, op, sid, epoch);
    dst[o..o + 8].copy_from_slice(target_anchor);
    SR_FENCE_LEN
}

pub fn build_unbind(dst: &mut [u8], sid: &[u8; SR_SESSION_ID], epoch: u32) -> usize {
    if dst.len() < SR_UNBIND_LEN {
        return 0;
    }
    put_common(dst, SR_OP_UNBIND, sid, epoch);
    SR_UNBIND_LEN
}

pub fn build_recovery_mark(dst: &mut [u8], recovery_epoch: u32) -> usize {
    if dst.len() < SR_RECOVERY_MARK_LEN {
        return 0;
    }
    dst[0] = SR_OP_RECOVERY_MARK;
    dst[1..5].copy_from_slice(&recovery_epoch.to_le_bytes());
    SR_RECOVERY_MARK_LEN
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SessionSlot {
    pub used: bool,
    /// Set by RECOVERY_MARK; cleared by EPOCH_BUMP. While set, RESERVE
    /// is refused (R2: unsafe recovery voids outstanding blocks and
    /// blocks emission until the epoch advances).
    pub voided: bool,
    pub fence_state: u8,
    pub flags: u8,
    pub epoch: u32,
    pub session_id: [u8; SR_SESSION_ID],
    pub anchor_id: [u8; SR_PEER_ID],
    pub worker_id: [u8; SR_PEER_ID],
    /// Anchor the fence was initiated/confirmed against. A takeover
    /// only trusts a fence aimed at the anchor being replaced.
    pub fence_target: [u8; SR_PEER_ID],
    /// Durable receive-window floor (§13.7.3, R4). Forward-only.
    pub rx_floor: u64,
    /// Exclusive high-water of every counter block ever granted.
    pub high_water: [u64; SR_NUM_COUNTERS],
    /// KEK-wrapped key blob (opaque, R1) + declared TTL metadata.
    pub key_len: u16,
    pub key_ttl_ms: u32,
    /// Generation of the key's expiry deadline: bumped by every
    /// KEY_PUT that arms a TTL. A due callback wipes the key only
    /// when its generation still matches (rfc_deterministic_timing.md
    /// §9.3 — an old deadline is a deterministic no-op).
    pub key_gen: u64,
    pub key: [u8; SR_MAX_WRAPPED_KEY],
}

impl SessionSlot {
    pub const fn empty() -> Self {
        SessionSlot {
            used: false,
            voided: false,
            fence_state: SR_FENCE_NONE,
            flags: 0,
            epoch: 0,
            session_id: [0; SR_SESSION_ID],
            anchor_id: [0; SR_PEER_ID],
            worker_id: [0; SR_PEER_ID],
            fence_target: [0; SR_PEER_ID],
            rx_floor: 0,
            high_water: [0; SR_NUM_COUNTERS],
            key_len: 0,
            key_ttl_ms: 0,
            key_gen: 0,
            key: [0; SR_MAX_WRAPPED_KEY],
        }
    }

    /// Zeroize key custody (R1 wipe). Length, TTL, and every blob
    /// byte — the durable substrate must hold nothing after teardown.
    /// `key_gen` survives: it fences deadlines, not custody.
    fn wipe_key(&mut self) {
        self.key_len = 0;
        self.key_ttl_ms = 0;
        self.key = [0; SR_MAX_WRAPPED_KEY];
    }
}

/// The replicated state machine. Embed in the module state; feed every
/// committed entry body (tag header stripped) to `apply` in commit
/// order.
#[repr(C)]
pub struct SessionRegistry {
    pub slots: [SessionSlot; SR_MAX_SESSIONS],
    /// Monotonic unsafe-recovery epoch (R2). Advanced by RECOVERY_MARK.
    pub recovery_epoch: u32,
    /// Applied-command counter (diagnostics / metrics only).
    pub applied: u64,
    /// Embedded deterministic timing state
    /// (rfc_deterministic_timing.md §4: timing and consumer state
    /// share one apply and snapshot boundary).
    pub timing: TimingState,
    /// Due callbacks that performed their domain transition (key
    /// wiped). Replicated so divergence is byte-visible.
    pub deadlines_fired: u32,
    /// Due callbacks that were deterministic no-ops (object gone or
    /// generation mismatch). Replicated so a systematic mismatch is
    /// observable rather than silent (RFC §7).
    pub deadline_noop: u32,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub const fn new() -> Self {
        SessionRegistry {
            slots: [SessionSlot::empty(); SR_MAX_SESSIONS],
            recovery_epoch: 0,
            applied: 0,
            timing: TimingState::new(SR_TIMING_CAPS),
            deadlines_fired: 0,
            deadline_noop: 0,
        }
    }

    fn find(&self, sid: &[u8; SR_SESSION_ID]) -> Option<usize> {
        let mut i = 0;
        while i < SR_MAX_SESSIONS {
            if self.slots[i].used && self.slots[i].session_id == *sid {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn find_free(&self) -> Option<usize> {
        let mut i = 0;
        while i < SR_MAX_SESSIONS {
            if !self.slots[i].used {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Read accessor: current slot for a session (local reads only —
    /// linearizable reads must go through the read-permit path).
    pub fn lookup(&self, sid: &[u8; SR_SESSION_ID]) -> Option<&SessionSlot> {
        self.find(sid).map(|i| &self.slots[i])
    }

    /// Apply one committed command body. DETERMINISTIC — no clocks,
    /// no randomness. Returns the reply the proposing replica relays
    /// to its requester (every replica computes it; only the proposer
    /// has a matching correlation).
    pub fn apply(&mut self, body: &[u8]) -> SessionReply {
        self.applied = self.applied.wrapping_add(1);
        if body.is_empty() {
            return SessionReply::fail(0, SR_ST_MALFORMED);
        }
        let op = body[0];
        let reply = match op {
            SR_OP_BIND => self.apply_bind(body),
            SR_OP_EPOCH_BUMP => self.apply_epoch_bump(body),
            SR_OP_RESERVE => self.apply_reserve(body),
            SR_OP_RX_FLOOR => self.apply_rx_floor(body),
            SR_OP_KEY_PUT => self.apply_key_put(body),
            SR_OP_KEY_WIPE => self.apply_key_wipe(body),
            SR_OP_FENCE_REQUEST | SR_OP_FENCE_CONFIRM => self.apply_fence(body),
            SR_OP_UNBIND => self.apply_unbind(body),
            SR_OP_RECOVERY_MARK => self.apply_recovery_mark(body),
            _ => SessionReply::fail(op, SR_ST_MALFORMED),
        };
        // Post-command due pass (rfc_deterministic_timing.md §7): a
        // command that registered an already-due deadline gets the
        // same bounded pass `TimeAdvance` runs — still a consequence
        // of the committed entry, never of a local timer. Cheap when
        // nothing is due (one sorted-front comparison).
        self.run_due_pass();
        reply
    }

    // ── Deterministic timing (rfc_deterministic_timing.md §7–§8) ────

    /// Bounded due pass: pop at most [`TM_BATCH_MAX`] due deadlines in
    /// canonical order and run each owner's due handler inline.
    fn run_due_pass(&mut self) -> u16 {
        let mut fired = 0u16;
        while (fired as usize) < TM_BATCH_MAX {
            let Some(d) = self.timing.pop_due() else {
                break;
            };
            self.on_deadline_due(d);
            fired += 1;
        }
        fired
    }

    /// Deterministic due handler (RFC §7): mutates replicated state
    /// only. The authoritative object decides the meaning; an absent
    /// object or generation mismatch is a recorded no-op.
    fn on_deadline_due(&mut self, d: Deadline) {
        match d.owner {
            SR_OWNER_KEY_TTL => {
                if let Some(i) = self.find(&d.id) {
                    let slot = &mut self.slots[i];
                    if slot.key_gen == d.generation && slot.key_len > 0 {
                        slot.wipe_key();
                        self.deadlines_fired = self.deadlines_fired.saturating_add(1);
                        return;
                    }
                }
                self.deadline_noop = self.deadline_noop.saturating_add(1);
            }
            _ => {
                self.deadline_noop = self.deadline_noop.saturating_add(1);
            }
        }
    }

    /// Apply a committed `TimeAdvance` entry (RFC §8). Regressions
    /// and duplicates retain the existing logical time — safe and
    /// deterministic. Returns what happened so the module wrapper can
    /// emit metrics and the leader can schedule `TimeDrain`.
    pub fn apply_time_advance(&mut self, proposed_time_ms: u64) -> crate::timing::TimeApplied {
        let _ = self.timing.advance(proposed_time_ms);
        let fired = self.run_due_pass();
        crate::timing::TimeApplied {
            logical_now_ms: self.timing.logical_now_ms(),
            fired,
            due_remaining: self.timing.due_depth(),
        }
    }

    /// Apply a committed `TimeDrain` entry (RFC §8). A drain never
    /// advances time; `through_time_ms` must equal the applied
    /// logical time or the drain is a deterministic no-op — a stale
    /// drain request cannot invent a new time fence.
    pub fn apply_time_drain(&mut self, through_time_ms: u64) -> crate::timing::TimeApplied {
        let fired = if through_time_ms == self.timing.logical_now_ms() {
            self.run_due_pass()
        } else {
            0
        };
        crate::timing::TimeApplied {
            logical_now_ms: self.timing.logical_now_ms(),
            fired,
            due_remaining: self.timing.due_depth(),
        }
    }

    fn common(body: &[u8], want: usize) -> Option<([u8; SR_SESSION_ID], u32)> {
        if body.len() < want {
            return None;
        }
        let mut sid = [0u8; SR_SESSION_ID];
        sid.copy_from_slice(&body[1..17]);
        let epoch = u32::from_le_bytes([body[17], body[18], body[19], body[20]]);
        Some((sid, epoch))
    }

    fn reply_ok(op: u8, sid: &[u8; SR_SESSION_ID], epoch: u32, a: u64, b: u64) -> SessionReply {
        SessionReply {
            op,
            status: SR_ST_OK,
            session_id: *sid,
            epoch,
            a,
            b,
        }
    }

    fn reply_err(op: u8, sid: &[u8; SR_SESSION_ID], epoch: u32, status: u8) -> SessionReply {
        SessionReply {
            op,
            status,
            session_id: *sid,
            epoch,
            a: 0,
            b: 0,
        }
    }

    fn apply_bind(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_BIND_LEN) else {
            return SessionReply::fail(SR_OP_BIND, SR_ST_MALFORMED);
        };
        let mut anchor = [0u8; SR_PEER_ID];
        anchor.copy_from_slice(&body[21..29]);
        let mut worker = [0u8; SR_PEER_ID];
        worker.copy_from_slice(&body[29..37]);
        let flags = body[37];
        if epoch == 0 {
            return Self::reply_err(SR_OP_BIND, &sid, epoch, SR_ST_MALFORMED);
        }

        if let Some(i) = self.find(&sid) {
            let slot = &mut self.slots[i];
            if epoch == slot.epoch && anchor == slot.anchor_id && worker == slot.worker_id {
                // Idempotent re-bind (proposer retry after a lost reply).
                return Self::reply_ok(SR_OP_BIND, &sid, slot.epoch, 0, 0);
            }
            if epoch <= slot.epoch {
                // Single-writer rule (§8.3): a competing writer at the
                // current or an older generation is rejected.
                return Self::reply_err(SR_OP_BIND, &sid, slot.epoch, SR_ST_STALE_EPOCH);
            }
            // Epoch-advancing rebind. An ANCHOR change is a takeover:
            // on a fence-required session it must not proceed until an
            // enforceable fence against the OLD anchor is confirmed
            // (R3; §13.7.4 step 1 — fence CONFIRMED before the epoch
            // advances, which is what lets the VIP move).
            let takeover = anchor != slot.anchor_id;
            if takeover
                && (slot.flags & SR_BIND_FENCE_REQUIRED) != 0
                && !(slot.fence_state == SR_FENCE_CONFIRMED && slot.fence_target == slot.anchor_id)
            {
                return Self::reply_err(SR_OP_BIND, &sid, slot.epoch, SR_ST_FENCE_REQUIRED);
            }
            slot.epoch = epoch;
            slot.anchor_id = anchor;
            slot.worker_id = worker;
            slot.flags = flags;
            // The epoch advanced: recovery-void clears (R2 — the bump
            // is the fence), and the consumed fence resets.
            slot.voided = false;
            slot.fence_state = SR_FENCE_NONE;
            slot.fence_target = [0; SR_PEER_ID];
            return Self::reply_ok(SR_OP_BIND, &sid, epoch, 0, 0);
        }

        let Some(i) = self.find_free() else {
            return Self::reply_err(SR_OP_BIND, &sid, epoch, SR_ST_NO_CAPACITY);
        };
        let slot = &mut self.slots[i];
        *slot = SessionSlot::empty();
        slot.used = true;
        slot.epoch = epoch;
        slot.session_id = sid;
        slot.anchor_id = anchor;
        slot.worker_id = worker;
        slot.flags = flags;
        Self::reply_ok(SR_OP_BIND, &sid, epoch, 0, 0)
    }

    fn apply_epoch_bump(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, old)) = Self::common(body, SR_EPOCH_BUMP_LEN) else {
            return SessionReply::fail(SR_OP_EPOCH_BUMP, SR_ST_MALFORMED);
        };
        let new = u32::from_le_bytes([body[21], body[22], body[23], body[24]]);
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_EPOCH_BUMP, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        let slot = &mut self.slots[i];
        if old != slot.epoch || new <= slot.epoch {
            return Self::reply_err(SR_OP_EPOCH_BUMP, &sid, slot.epoch, SR_ST_STALE_EPOCH);
        }
        slot.epoch = new;
        slot.voided = false; // the bump is what re-arms emission (R2)
        Self::reply_ok(SR_OP_EPOCH_BUMP, &sid, new, 0, 0)
    }

    fn apply_reserve(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_RESERVE_LEN) else {
            return SessionReply::fail(SR_OP_RESERVE, SR_ST_MALFORMED);
        };
        let counter = body[21] as usize;
        let len = u64::from_le_bytes([
            body[22], body[23], body[24], body[25], body[26], body[27], body[28], body[29],
        ]);
        if counter >= SR_NUM_COUNTERS || len == 0 {
            return Self::reply_err(SR_OP_RESERVE, &sid, epoch, SR_ST_MALFORMED);
        }
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_RESERVE, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        let slot = &mut self.slots[i];
        if epoch != slot.epoch {
            // Epoch fencing at block acquisition (§13.7.2): a stale
            // writer — a not-actually-dead old anchor — never gets a
            // fresh block.
            return Self::reply_err(SR_OP_RESERVE, &sid, slot.epoch, SR_ST_STALE_EPOCH);
        }
        if slot.voided {
            // R2: unsafe recovery voided this session's blocks; no
            // grant until the epoch advances.
            return Self::reply_err(SR_OP_RESERVE, &sid, slot.epoch, SR_ST_RECOVERY_VOID);
        }
        let start = slot.high_water[counter];
        let Some(end) = start.checked_add(len) else {
            return Self::reply_err(SR_OP_RESERVE, &sid, slot.epoch, SR_ST_MALFORMED);
        };
        // Identity space is never re-handed out: the high-water only
        // advances, so an abandoned block tail is wasted, not reused.
        slot.high_water[counter] = end;
        Self::reply_ok(SR_OP_RESERVE, &sid, slot.epoch, start, len)
    }

    fn apply_rx_floor(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_RX_FLOOR_LEN) else {
            return SessionReply::fail(SR_OP_RX_FLOOR, SR_ST_MALFORMED);
        };
        let floor = u64::from_le_bytes([
            body[21], body[22], body[23], body[24], body[25], body[26], body[27], body[28],
        ]);
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_RX_FLOOR, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        let slot = &mut self.slots[i];
        if epoch != slot.epoch {
            return Self::reply_err(SR_OP_RX_FLOOR, &sid, slot.epoch, SR_ST_STALE_EPOCH);
        }
        if floor < slot.rx_floor {
            // R4: the receive-window low edge is a hard floor — it
            // never moves backward, so a takeover can never re-admit
            // replays below the last durable checkpoint.
            return Self::reply_err(SR_OP_RX_FLOOR, &sid, slot.epoch, SR_ST_FLOOR_REGRESSION);
        }
        slot.rx_floor = floor;
        Self::reply_ok(SR_OP_RX_FLOOR, &sid, slot.epoch, floor, 0)
    }

    fn apply_key_put(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_KEY_PUT_HDR) else {
            return SessionReply::fail(SR_OP_KEY_PUT, SR_ST_MALFORMED);
        };
        let ttl_ms = u32::from_le_bytes([body[21], body[22], body[23], body[24]]);
        let blob_len = u16::from_le_bytes([body[25], body[26]]) as usize;
        if blob_len == 0 || blob_len > SR_MAX_WRAPPED_KEY || body.len() < SR_KEY_PUT_HDR + blob_len
        {
            return Self::reply_err(SR_OP_KEY_PUT, &sid, epoch, SR_ST_MALFORMED);
        }
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_KEY_PUT, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        if epoch != self.slots[i].epoch {
            let cur = self.slots[i].epoch;
            return Self::reply_err(SR_OP_KEY_PUT, &sid, cur, SR_ST_STALE_EPOCH);
        }
        // TTL expiry rides the replicated timing index. Registration
        // happens BEFORE the key is stored: if the owner's deadline
        // partition is full (or the generation would overflow), the
        // command fails deterministically without creating its
        // consumer object (rfc_deterministic_timing.md §6.2, §9.1).
        if ttl_ms > 0 {
            let gen = self.slots[i].key_gen.wrapping_add(1);
            let due = self.timing.logical_now_ms().saturating_add(ttl_ms as u64);
            match self.timing.register(SR_OWNER_KEY_TTL, sid, gen, due) {
                Ok(_) => self.slots[i].key_gen = gen,
                Err(_) => {
                    let cur = self.slots[i].epoch;
                    return Self::reply_err(SR_OP_KEY_PUT, &sid, cur, SR_ST_DEADLINE_CAPACITY);
                }
            }
        } else {
            // Non-expiring key replaces an expiring one: disarm.
            let gen = self.slots[i].key_gen;
            let _ = self.timing.cancel(SR_OWNER_KEY_TTL, &sid, gen);
        }
        let slot = &mut self.slots[i];
        // R1: the blob is opaque — stored and returned byte-for-byte,
        // never parsed. The KEK lives with the anchors / HSM; this
        // registry (and the WAL under it) cannot read the key.
        slot.wipe_key();
        slot.key_len = blob_len as u16;
        slot.key_ttl_ms = ttl_ms;
        slot.key[..blob_len].copy_from_slice(&body[SR_KEY_PUT_HDR..SR_KEY_PUT_HDR + blob_len]);
        Self::reply_ok(
            SR_OP_KEY_PUT,
            &sid,
            slot.epoch,
            blob_len as u64,
            ttl_ms as u64,
        )
    }

    fn apply_key_wipe(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, _epoch)) = Self::common(body, SR_KEY_WIPE_LEN) else {
            return SessionReply::fail(SR_OP_KEY_WIPE, SR_ST_MALFORMED);
        };
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_KEY_WIPE, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        // Deliberately NOT epoch-gated: a wipe must never be refused
        // as stale — teardown and TTL expiry always win (R1).
        let gen = self.slots[i].key_gen;
        let _ = self.timing.cancel(SR_OWNER_KEY_TTL, &sid, gen);
        let slot = &mut self.slots[i];
        slot.wipe_key();
        Self::reply_ok(SR_OP_KEY_WIPE, &sid, slot.epoch, 0, 0)
    }

    fn apply_fence(&mut self, body: &[u8]) -> SessionReply {
        let op = body[0];
        let Some((sid, epoch)) = Self::common(body, SR_FENCE_LEN) else {
            return SessionReply::fail(op, SR_ST_MALFORMED);
        };
        let mut target = [0u8; SR_PEER_ID];
        target.copy_from_slice(&body[21..29]);
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(op, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        let slot = &mut self.slots[i];
        if epoch != slot.epoch {
            return Self::reply_err(op, &sid, slot.epoch, SR_ST_STALE_EPOCH);
        }
        if op == SR_OP_FENCE_REQUEST {
            slot.fence_state = SR_FENCE_INITIATED;
            slot.fence_target = target;
        } else {
            // CONFIRM only upgrades the fence it was initiated for —
            // a confirmation aimed at a different anchor is malformed
            // orchestration, not a fence.
            if slot.fence_state != SR_FENCE_INITIATED || slot.fence_target != target {
                return Self::reply_err(op, &sid, slot.epoch, SR_ST_MALFORMED);
            }
            slot.fence_state = SR_FENCE_CONFIRMED;
        }
        Self::reply_ok(op, &sid, slot.epoch, slot.fence_state as u64, 0)
    }

    fn apply_unbind(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_UNBIND_LEN) else {
            return SessionReply::fail(SR_OP_UNBIND, SR_ST_MALFORMED);
        };
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_UNBIND, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        if epoch != self.slots[i].epoch {
            let cur = self.slots[i].epoch;
            return Self::reply_err(SR_OP_UNBIND, &sid, cur, SR_ST_STALE_EPOCH);
        }
        // Teardown disarms any pending key-TTL deadline: the slot (the
        // authoritative object) is going away, so the index entry must
        // not linger as a guaranteed no-op.
        let gen = self.slots[i].key_gen;
        let _ = self.timing.cancel(SR_OWNER_KEY_TTL, &sid, gen);
        let slot = &mut self.slots[i];
        // Teardown implies key wipe (R1) and frees the slot. The
        // session's counter high-waters die with it — a REUSED
        // session_id would restart counters at zero, so session_ids
        // must be single-use (fluxor anchors mint anchor_id||counter,
        // which is).
        *slot = SessionSlot::empty();
        Self::reply_ok(SR_OP_UNBIND, &sid, epoch, 0, 0)
    }

    fn apply_recovery_mark(&mut self, body: &[u8]) -> SessionReply {
        if body.len() < SR_RECOVERY_MARK_LEN {
            return SessionReply::fail(SR_OP_RECOVERY_MARK, SR_ST_MALFORMED);
        }
        let new_epoch = u32::from_le_bytes([body[1], body[2], body[3], body[4]]);
        if new_epoch <= self.recovery_epoch {
            return SessionReply::fail(SR_OP_RECOVERY_MARK, SR_ST_RECOVERY_STALE);
        }
        self.recovery_epoch = new_epoch;
        // R2: unsafe recovery voids every outstanding reservation.
        // Emission for each session stays blocked until ITS epoch
        // advances (EPOCH_BUMP or an epoch-advancing BIND).
        let mut voided = 0u64;
        let mut i = 0;
        while i < SR_MAX_SESSIONS {
            if self.slots[i].used {
                self.slots[i].voided = true;
                voided += 1;
            }
            i += 1;
        }
        SessionReply {
            op: SR_OP_RECOVERY_MARK,
            status: SR_ST_OK,
            session_id: [0; SR_SESSION_ID],
            epoch: 0,
            a: voided,
            b: new_epoch as u64,
        }
    }

    // ── Snapshot (state-machine export/install) ─────────────────────

    /// Serialized snapshot size: fixed-layout dump of every slot plus
    /// the registry header and the embedded timing section — one
    /// blob, one applied index (rfc_deterministic_timing.md §12: a
    /// snapshot containing a consumer schedule without its deadline,
    /// or a deadline without its consumer object, is invalid — made
    /// impossible here by construction). Layout (all LE):
    ///   [recovery_epoch:4][applied:8][deadlines_fired:4][deadline_noop:4]
    ///   [timing section: TimingState::SNAPSHOT_LEN (versioned)]
    ///   then per slot:
    ///   [used:1][voided:1][fence_state:1][flags:1][epoch:4]
    ///   [session_id:16][anchor:8][worker:8][fence_target:8]
    ///   [rx_floor:8][high_water:8*3][key_gen:8][key_len:2]
    ///   [key_ttl_ms:4][key:80]
    pub const SNAPSHOT_LEN: usize =
        4 + 8 + 4 + 4 + TimingState::SNAPSHOT_LEN + SR_MAX_SESSIONS * SLOT_SNAP_LEN;

    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        if dst.len() < Self::SNAPSHOT_LEN {
            return -1;
        }
        dst[0..4].copy_from_slice(&self.recovery_epoch.to_le_bytes());
        dst[4..12].copy_from_slice(&self.applied.to_le_bytes());
        dst[12..16].copy_from_slice(&self.deadlines_fired.to_le_bytes());
        dst[16..20].copy_from_slice(&self.deadline_noop.to_le_bytes());
        if self
            .timing
            .snapshot(&mut dst[20..20 + TimingState::SNAPSHOT_LEN])
            < 0
        {
            return -1;
        }
        let mut o = 20 + TimingState::SNAPSHOT_LEN;
        let mut i = 0;
        while i < SR_MAX_SESSIONS {
            let s = &self.slots[i];
            dst[o] = s.used as u8;
            dst[o + 1] = s.voided as u8;
            dst[o + 2] = s.fence_state;
            dst[o + 3] = s.flags;
            dst[o + 4..o + 8].copy_from_slice(&s.epoch.to_le_bytes());
            dst[o + 8..o + 24].copy_from_slice(&s.session_id);
            dst[o + 24..o + 32].copy_from_slice(&s.anchor_id);
            dst[o + 32..o + 40].copy_from_slice(&s.worker_id);
            dst[o + 40..o + 48].copy_from_slice(&s.fence_target);
            dst[o + 48..o + 56].copy_from_slice(&s.rx_floor.to_le_bytes());
            let mut c = 0;
            while c < SR_NUM_COUNTERS {
                dst[o + 56 + c * 8..o + 64 + c * 8].copy_from_slice(&s.high_water[c].to_le_bytes());
                c += 1;
            }
            dst[o + 80..o + 88].copy_from_slice(&s.key_gen.to_le_bytes());
            dst[o + 88..o + 90].copy_from_slice(&s.key_len.to_le_bytes());
            dst[o + 90..o + 94].copy_from_slice(&s.key_ttl_ms.to_le_bytes());
            dst[o + 94..o + 94 + SR_MAX_WRAPPED_KEY].copy_from_slice(&s.key);
            o += SLOT_SNAP_LEN;
            i += 1;
        }
        Self::SNAPSHOT_LEN as i32
    }

    pub fn restore(&mut self, src: &[u8]) -> bool {
        if src.len() < Self::SNAPSHOT_LEN {
            return false;
        }
        // Timing section first: it fails closed (unknown version,
        // capacity mismatch, non-canonical order, time regression)
        // without touching any state, so a rejected install leaves
        // the registry coherent.
        if !self
            .timing
            .restore(&src[20..20 + TimingState::SNAPSHOT_LEN])
        {
            return false;
        }
        self.recovery_epoch = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
        self.applied = u64::from_le_bytes([
            src[4], src[5], src[6], src[7], src[8], src[9], src[10], src[11],
        ]);
        self.deadlines_fired = u32::from_le_bytes([src[12], src[13], src[14], src[15]]);
        self.deadline_noop = u32::from_le_bytes([src[16], src[17], src[18], src[19]]);
        let mut o = 20 + TimingState::SNAPSHOT_LEN;
        let mut i = 0;
        while i < SR_MAX_SESSIONS {
            let s = &mut self.slots[i];
            s.used = src[o] != 0;
            s.voided = src[o + 1] != 0;
            s.fence_state = src[o + 2];
            s.flags = src[o + 3];
            s.epoch = u32::from_le_bytes([src[o + 4], src[o + 5], src[o + 6], src[o + 7]]);
            s.session_id.copy_from_slice(&src[o + 8..o + 24]);
            s.anchor_id.copy_from_slice(&src[o + 24..o + 32]);
            s.worker_id.copy_from_slice(&src[o + 32..o + 40]);
            s.fence_target.copy_from_slice(&src[o + 40..o + 48]);
            s.rx_floor = u64::from_le_bytes([
                src[o + 48],
                src[o + 49],
                src[o + 50],
                src[o + 51],
                src[o + 52],
                src[o + 53],
                src[o + 54],
                src[o + 55],
            ]);
            let mut c = 0;
            while c < SR_NUM_COUNTERS {
                s.high_water[c] = u64::from_le_bytes([
                    src[o + 56 + c * 8],
                    src[o + 57 + c * 8],
                    src[o + 58 + c * 8],
                    src[o + 59 + c * 8],
                    src[o + 60 + c * 8],
                    src[o + 61 + c * 8],
                    src[o + 62 + c * 8],
                    src[o + 63 + c * 8],
                ]);
                c += 1;
            }
            s.key_gen = u64::from_le_bytes([
                src[o + 80],
                src[o + 81],
                src[o + 82],
                src[o + 83],
                src[o + 84],
                src[o + 85],
                src[o + 86],
                src[o + 87],
            ]);
            s.key_len = u16::from_le_bytes([src[o + 88], src[o + 89]]);
            s.key_ttl_ms = u32::from_le_bytes([src[o + 90], src[o + 91], src[o + 92], src[o + 93]]);
            s.key
                .copy_from_slice(&src[o + 94..o + 94 + SR_MAX_WRAPPED_KEY]);
            o += SLOT_SNAP_LEN;
            i += 1;
        }
        true
    }
}

/// Per-slot snapshot record length (see `snapshot` layout comment).
pub const SLOT_SNAP_LEN: usize = 94 + SR_MAX_WRAPPED_KEY;
