// Session registry — the replicated state machine behind the session
// directory role (fluxor).
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
// What the registry is:
//
// - the **single-writer session directory**: one authoritative (anchor,
//   worker) binding per `(session_id, session_epoch)`; competing stale writers
//   are rejected.
// - the **reservation authority** for the hot egress counters, answering
//   fluxor's `session.reservation` capability: blocks are granted
//   monotonically from a per-(session, counter) high-water mark and
//   NEVER re-handed out. The grant reply reaches the proposer only after the
//   command is quorum-committed (the module replies from the committed-entry
//   stream, not from proposal submission) — "quorum-durable before emit" holds
//   by construction. A session that declares the strict crash-continuous
//   profile (`SR_BIND_COUNTER_FLOOR_GATED`) also keeps a per-counter
//   **mirror floor**: the high-water its standby has mirrored, recorded by
//   COUNTER_FLOOR, which a takeover must have advanced to the granted
//   high-water before ACTIVATE succeeds (`SR_ST_RESERVATION_BEHIND`).
// - the **receive-window floor** keeper: the durable rx high-water only
//   moves forward.
// - the **wrapped-key custodian**: session AEAD keys are stored only as
//   opaque KEK-wrapped blobs this registry cannot read, with quorum wipe on
//   teardown. TTL expiry rides the deterministic replicated timing component
//   (`modules/common/timing.rs`): KEY_PUT with a TTL registers a
//   generation-fenced deadline in the embedded `TimingState`; the due handler
//   wipes the key while applying the committed time entry. There is no second
//   authoritative local timer queue. KEY_PUT_BOUND additionally binds the
//   blob to a **custody context digest** — SHA-256 over `(service_id,
//   session_id, epoch, algorithm, use, direction)`, computed by the caller
//   (`key_context_digest` with the SDK's digest) — and a put or a transfer
//   consumption presenting another context is refused
//   (`SR_ST_CONTEXT_MISMATCH`): a key's use is bound to its session,
//   epoch, algorithm, purpose and direction until KEY_WIPE ends it.
// - the **transfer-grant issuer**: GRANT_TRANSFER records the
//   destination `(host, anchor)` and target epoch a key may be re-wrapped
//   for, under a TTL on the timing index; CONSUME_TRANSFER is single-use and
//   must present the grant's destination, epoch and the key's context.
//   RECOVERY_MARK invalidates every outstanding grant.
// - the **fence-ordering gate**: an anchor takeover — ACTIVATE, which
//   moves a fence-required session's `anchor_id` under a strictly higher
//   epoch — is refused until an out-of-band emission fence has been recorded
//   as CONFIRMED against the anchor being replaced, and refused unless it
//   carries the generation that confirmation recorded: the fence agent's
//   custody generation, the one `MSG_ADDR_FENCED` reports and a coordinator
//   carries forward as `fence_gen`. A fence confirmed under an earlier
//   custody therefore never admits a later takeover, and one confirmed fence
//   admits one activation. The registry cannot cut power itself —
//   enforceability is the fence agent's job (a member placed outside the
//   failure domain whose cut is power or the fabric port) — but it enforces
//   the ORDERING: no takeover advances past an unconfirmed fence, and none
//   past a fence that is not the one presented.
// - the **mirror-horizon keeper**: MIRROR_MARK records the committed mirror
//   epoch and generation a session's standby has acknowledged, monotone, and
//   every reply to it exposes them so a coordinator reads committed mirror
//   and session epochs from one authority.
// - the **unsafe-recovery marker**: RECOVERY_MARK voids every session's
//   outstanding reservations and transfer grants and blocks further grants
//   until that session's epoch bumps. This is the consumer-observable form
//   of "unsafe recovery voids outstanding blocks".
//
// Capacity is profile-selected: `SessionRegistry<N, D>` holds an arena of
// `N` session slots and a timing index of `D` deadline slots (two per
// session), both static. The named profiles below are the qualification
// envelopes; a deployment admits at most `admitted ≤ N` sessions and
// reports that as its capability. A session is found by id through a
// chained hash index and a new one takes the lowest free slot through an
// occupancy tree (`slot_index.rs`), so no command walks the arena — except
// RECOVERY_MARK, which voids every session and so visits each live one.

use super::slot_index::{SlotIndex, SlotSet};
use super::timing::{
    Deadline, TimingState, TM_BATCH_MAX, TM_MAX_OWNERS, TM_SNAPSHOT_ENTRY_LEN, TM_SNAPSHOT_HDR_LEN,
};

// ── Capacity profiles ───────────────────────────────────────────────

/// RP2350 agent / tiny relay.
pub const SR_PROFILE_RP2350: usize = 64;
/// Pi 5 edge: the smallest full-feature profile.
pub const SR_PROFILE_PI5: usize = 4096;
/// Server ingress group (a host's anchors are sharded over
/// several groups, this is one group's arena).
pub const SR_PROFILE_SERVER: usize = 65536;

/// Deadline slots a profile embeds: one key TTL plus one transfer grant
/// per session, so neither owner can starve the other.
pub const SR_DEADLINES_RP2350: usize = 128;
pub const SR_DEADLINES_PI5: usize = 8192;
pub const SR_DEADLINES_SERVER: usize = 131072;

pub type SessionRegistryRp2350 = SessionRegistry<SR_PROFILE_RP2350, SR_DEADLINES_RP2350>;
pub type SessionRegistryPi5 = SessionRegistry<SR_PROFILE_PI5, SR_DEADLINES_PI5>;
pub type SessionRegistryServer = SessionRegistry<SR_PROFILE_SERVER, SR_DEADLINES_SERVER>;

/// Hot counters per session: 0 = egress AEAD nonce,
/// 1 = reliable-ordered send index, 2 = outbound datagram sequence.
pub const SR_NUM_COUNTERS: usize = 3;

/// Maximum KEK-wrapped key blob the registry stores. Sized for a
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
/// Fenced anchor takeover: the transport half of the directory role.
pub const SR_OP_ACTIVATE: u8 = 11;
/// Committed mirror horizon `(mirror_epoch, mirror_generation)`, monotone.
pub const SR_OP_MIRROR_MARK: u8 = 12;
/// KEY_PUT bound to a custody-context digest.
pub const SR_OP_KEY_PUT_BOUND: u8 = 13;
/// Issue a destination-bound transfer grant for the session's key.
pub const SR_OP_GRANT_TRANSFER: u8 = 14;
/// Consume (single use) a transfer grant.
pub const SR_OP_CONSUME_TRANSFER: u8 = 15;
/// Advance a counter's mirrored floor (the standby's view of the
/// high-water), monotone.
pub const SR_OP_COUNTER_FLOOR: u8 = 16;

// ── Status codes ────────────────────────────────────────────────────

pub const SR_ST_OK: u8 = 0;
/// Stale-epoch / competing-writer rejection (single-writer rule).
pub const SR_ST_STALE_EPOCH: u8 = 1;
pub const SR_ST_UNKNOWN_SESSION: u8 = 2;
pub const SR_ST_NO_CAPACITY: u8 = 3;
pub const SR_ST_MALFORMED: u8 = 4;
/// Grants void after unsafe recovery until the session epoch bumps.
pub const SR_ST_RECOVERY_VOID: u8 = 5;
/// Anchor takeover attempted without a confirmed emission fence.
pub const SR_ST_FENCE_REQUIRED: u8 = 6;
/// Receive-floor regression refused.
pub const SR_ST_FLOOR_REGRESSION: u8 = 7;
/// RECOVERY_MARK with a non-advancing recovery epoch.
pub const SR_ST_RECOVERY_STALE: u8 = 8;
/// KEY_PUT with a TTL could not register its expiry deadline (timing-index
/// capacity or generation overflow). The command fails without storing the
/// key — capacity is checked as part of the same apply operation.
pub const SR_ST_DEADLINE_CAPACITY: u8 = 9;
/// The fence generation presented on ACTIVATE is not the one FENCE_CONFIRM
/// recorded — a fence from some other custody, not evidence about this host.
pub const SR_ST_FENCE_STALE: u8 = 10;
/// The key custody context presented is not the one the stored key is
/// bound to.
pub const SR_ST_CONTEXT_MISMATCH: u8 = 11;
/// No live transfer grant matches (unknown id, wrong destination or
/// epoch, expired, already consumed, or voided by recovery).
pub const SR_ST_GRANT_INVALID: u8 = 12;
/// A floor-gated takeover whose mirrored counter floor is behind the
/// granted high-water: the standby would re-emit identity space.
pub const SR_ST_RESERVATION_BEHIND: u8 = 13;
/// MIRROR_MARK or COUNTER_FLOOR moving a monotone horizon backwards.
pub const SR_ST_MIRROR_REGRESSION: u8 = 14;

// ── Deterministic timing ────────────────────────────────────────────

/// Owner namespace for session-key TTL deadlines in the embedded
/// timing index. Deadline id = session_id; generation = the slot's
/// `key_gen` at KEY_PUT time.
pub const SR_OWNER_KEY_TTL: u16 = 0;
/// Owner namespace for transfer-grant expiry. Deadline id = session_id;
/// generation = the slot's `grant_gen` at GRANT_TRANSFER time.
pub const SR_OWNER_GRANT_TTL: u16 = 1;

// ── BIND flags ──────────────────────────────────────────────────────

/// Session declares platform-replicated-state migration: anchor
/// takeover requires a confirmed emission fence.
pub const SR_BIND_FENCE_REQUIRED: u8 = 0x01;
/// Session declares the strict crash-continuous profile: ACTIVATE
/// additionally requires every counter's mirrored floor to have reached
/// the granted high-water: the send horizon for reservations.
pub const SR_BIND_COUNTER_FLOOR_GATED: u8 = 0x02;

// ── Fence states ────────────────────────────────────────────────────

pub const SR_FENCE_NONE: u8 = 0;
pub const SR_FENCE_INITIATED: u8 = 1;
pub const SR_FENCE_CONFIRMED: u8 = 2;

// ── Field sizes / payload layouts ───────────────────────────────────

pub const SR_SESSION_ID: usize = 16;
pub const SR_PEER_ID: usize = 8;
pub const SR_HOST_ID: usize = 16;
pub const SR_CONTEXT_DIGEST: usize = 32;

// Command payload layouts (after the opcode byte). All numeric fields
// little-endian; identity fields are opaque byte strings compared raw
// (big-endian canonical form is the producer's concern, as in
// fluxor's SessionCtrlV1).
//
//   BIND             [sid:16][epoch:4][anchor:8][worker:8][flags:1]
//   EPOCH_BUMP       [sid:16][old:4][new:4]
//   RESERVE          [sid:16][epoch:4][counter:1][len:8]
//   RX_FLOOR         [sid:16][epoch:4][floor:8]
//   KEY_PUT          [sid:16][epoch:4][ttl_ms:4][blob_len:2][blob..]
//   KEY_WIPE         [sid:16][epoch:4]
//   FENCE_REQUEST    [sid:16][epoch:4][target_anchor:8]
//   FENCE_CONFIRM    [sid:16][epoch:4][target_anchor:8][fence_gen:4]
//   ACTIVATE         [sid:16][new_epoch:4][new_anchor:8][fence_gen:4]
//   UNBIND           [sid:16][epoch:4]
//   RECOVERY_MARK    [recovery_epoch:4]
//   MIRROR_MARK      [sid:16][epoch:4][mirror_epoch:8][mirror_generation:8]
//   KEY_PUT_BOUND    [sid:16][epoch:4][ttl_ms:4][ctx:32][blob_len:2][blob..]
//   GRANT_TRANSFER   [sid:16][epoch:4][dest_host:16][dest_anchor:8]
//                    [target_epoch:4][ttl_ms:4]
//   CONSUME_TRANSFER [sid:16][epoch:4][grant_id:8][dest_host:16]
//                    [dest_anchor:8][target_epoch:4][ctx:32]
//   COUNTER_FLOOR    [sid:16][epoch:4][counter:1][floor:8]

pub const SR_BIND_LEN: usize = 1 + SR_SESSION_ID + 4 + SR_PEER_ID + SR_PEER_ID + 1;
pub const SR_EPOCH_BUMP_LEN: usize = 1 + SR_SESSION_ID + 4 + 4;
pub const SR_RESERVE_LEN: usize = 1 + SR_SESSION_ID + 4 + 1 + 8;
pub const SR_RX_FLOOR_LEN: usize = 1 + SR_SESSION_ID + 4 + 8;
pub const SR_KEY_PUT_HDR: usize = 1 + SR_SESSION_ID + 4 + 4 + 2;
pub const SR_KEY_WIPE_LEN: usize = 1 + SR_SESSION_ID + 4;
pub const SR_FENCE_LEN: usize = 1 + SR_SESSION_ID + 4 + SR_PEER_ID;
pub const SR_FENCE_CONFIRM_LEN: usize = SR_FENCE_LEN + 4;
pub const SR_ACTIVATE_LEN: usize = 1 + SR_SESSION_ID + 4 + SR_PEER_ID + 4;
pub const SR_UNBIND_LEN: usize = 1 + SR_SESSION_ID + 4;
pub const SR_RECOVERY_MARK_LEN: usize = 1 + 4;
pub const SR_MIRROR_MARK_LEN: usize = 1 + SR_SESSION_ID + 4 + 8 + 8;
pub const SR_KEY_PUT_BOUND_HDR: usize = 1 + SR_SESSION_ID + 4 + 4 + SR_CONTEXT_DIGEST + 2;
pub const SR_GRANT_TRANSFER_LEN: usize = 1 + SR_SESSION_ID + 4 + SR_HOST_ID + SR_PEER_ID + 4 + 4;
pub const SR_CONSUME_TRANSFER_LEN: usize =
    1 + SR_SESSION_ID + 4 + 8 + SR_HOST_ID + SR_PEER_ID + 4 + SR_CONTEXT_DIGEST;
pub const SR_COUNTER_FLOOR_LEN: usize = 1 + SR_SESSION_ID + 4 + 1 + 8;

/// Largest command body (KEY_PUT_BOUND with a maximal blob).
pub const SR_MAX_CMD: usize = SR_KEY_PUT_BOUND_HDR + SR_MAX_WRAPPED_KEY;

// ── Reply ───────────────────────────────────────────────────────────

/// Encoded reply layout: `[op:1][status:1][sid:16][epoch:4][a:8][b:8]`.
/// `a`/`b` are op-specific: BIND → (1 when this advanced an existing
/// binding's epoch, 0 for a first binding or an idempotent retry; 0);
/// RESERVE → (block
/// start, block len); RX_FLOOR → (committed floor, 0); RECOVERY_MARK →
/// (voided-session count, new recovery epoch); FENCE_* → (fence state,
/// generation); ACTIVATE → (the generation consumed, 0); MIRROR_MARK →
/// (committed mirror epoch, committed mirror generation); GRANT_TRANSFER
/// → (grant id, ttl_ms); CONSUME_TRANSFER → (grant id, key length);
/// COUNTER_FLOOR → (committed floor, granted high-water); otherwise zero.
///
/// A RESERVE reply is fluxor's reservation-grant record: the layout above
/// is the one `modules/sdk/contracts/net/session_ctrl.rs` pins (`GRANT_LEN`
/// = 38, `GRANT_OP_RESERVE` = 3 = `SR_OP_RESERVE`, `GRANT_STATUS_OK` = 0 =
/// `SR_ST_OK`), and a transport consuming a grant reads exactly these
/// bytes. Fluxor defines the shape because it
/// is the transport's safety property — no counter value emitted twice
/// under one key — that the record exists to carry. This registry is one
/// authority that can satisfy it.
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

// ── Key custody context ─────────────────────────────────────────────

/// The custody context a wrapped key is bound to: the
/// digest covers `[service_id:16][session_id:16][epoch:4][algorithm:2]
/// [use:1][direction:1]`, so a key for another service, session,
/// epoch, suite, purpose or direction never matches. `digest` is the
/// SDK's SHA-256 (`crypto/sha256.rs::sha256`), passed in so this file
/// stays pure.
pub fn key_context_digest(
    service_id: &[u8; SR_HOST_ID],
    session_id: &[u8; SR_SESSION_ID],
    epoch: u32,
    algorithm: u16,
    key_use: u8,
    direction: u8,
    digest: fn(&[u8]) -> [u8; SR_CONTEXT_DIGEST],
) -> [u8; SR_CONTEXT_DIGEST] {
    let mut m = [0u8; 16 + 16 + 4 + 2 + 1 + 1];
    m[0..16].copy_from_slice(service_id);
    m[16..32].copy_from_slice(session_id);
    m[32..36].copy_from_slice(&epoch.to_le_bytes());
    m[36..38].copy_from_slice(&algorithm.to_le_bytes());
    m[38] = key_use;
    m[39] = direction;
    digest(&m)
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

/// KEY_PUT bound to the custody context `ctx` (see `key_context_digest`).
pub fn build_key_put_bound(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    ttl_ms: u32,
    ctx: &[u8; SR_CONTEXT_DIGEST],
    blob: &[u8],
) -> usize {
    let total = SR_KEY_PUT_BOUND_HDR + blob.len();
    if dst.len() < total || blob.is_empty() || blob.len() > SR_MAX_WRAPPED_KEY {
        return 0;
    }
    let mut o = put_common(dst, SR_OP_KEY_PUT_BOUND, sid, epoch);
    dst[o..o + 4].copy_from_slice(&ttl_ms.to_le_bytes());
    o += 4;
    dst[o..o + SR_CONTEXT_DIGEST].copy_from_slice(ctx);
    o += SR_CONTEXT_DIGEST;
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

pub fn build_fence_request(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    target_anchor: &[u8; SR_PEER_ID],
) -> usize {
    if dst.len() < SR_FENCE_LEN {
        return 0;
    }
    let o = put_common(dst, SR_OP_FENCE_REQUEST, sid, epoch);
    dst[o..o + 8].copy_from_slice(target_anchor);
    SR_FENCE_LEN
}

/// `fence_gen` is the custody generation the fence agent reported on
/// `MSG_ADDR_FENCED`; zero is never a generation and encodes nothing.
pub fn build_fence_confirm(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    target_anchor: &[u8; SR_PEER_ID],
    fence_gen: u32,
) -> usize {
    if dst.len() < SR_FENCE_CONFIRM_LEN || fence_gen == 0 {
        return 0;
    }
    let o = put_common(dst, SR_OP_FENCE_CONFIRM, sid, epoch);
    dst[o..o + 8].copy_from_slice(target_anchor);
    dst[o + 8..o + 12].copy_from_slice(&fence_gen.to_le_bytes());
    SR_FENCE_CONFIRM_LEN
}

/// Move the session's anchor to `new_anchor` under `new_epoch`, presenting
/// the fence generation the coordinator observed confirmed for the anchor
/// being replaced.
pub fn build_activate(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    new_epoch: u32,
    new_anchor: &[u8; SR_PEER_ID],
    fence_gen: u32,
) -> usize {
    if dst.len() < SR_ACTIVATE_LEN {
        return 0;
    }
    let o = put_common(dst, SR_OP_ACTIVATE, sid, new_epoch);
    dst[o..o + 8].copy_from_slice(new_anchor);
    dst[o + 8..o + 12].copy_from_slice(&fence_gen.to_le_bytes());
    SR_ACTIVATE_LEN
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

pub fn build_mirror_mark(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    mirror_epoch: u64,
    mirror_generation: u64,
) -> usize {
    if dst.len() < SR_MIRROR_MARK_LEN {
        return 0;
    }
    let o = put_common(dst, SR_OP_MIRROR_MARK, sid, epoch);
    dst[o..o + 8].copy_from_slice(&mirror_epoch.to_le_bytes());
    dst[o + 8..o + 16].copy_from_slice(&mirror_generation.to_le_bytes());
    SR_MIRROR_MARK_LEN
}

/// Issue a transfer grant: the key may be re-wrapped for `(dest_host,
/// dest_anchor)` to hold under `target_epoch`, within `ttl_ms` of
/// committed logical time (0 = until consumed, unbound or recovered).
pub fn build_grant_transfer(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    dest_host: &[u8; SR_HOST_ID],
    dest_anchor: &[u8; SR_PEER_ID],
    target_epoch: u32,
    ttl_ms: u32,
) -> usize {
    if dst.len() < SR_GRANT_TRANSFER_LEN {
        return 0;
    }
    let mut o = put_common(dst, SR_OP_GRANT_TRANSFER, sid, epoch);
    dst[o..o + 16].copy_from_slice(dest_host);
    o += 16;
    dst[o..o + 8].copy_from_slice(dest_anchor);
    o += 8;
    dst[o..o + 4].copy_from_slice(&target_epoch.to_le_bytes());
    dst[o + 4..o + 8].copy_from_slice(&ttl_ms.to_le_bytes());
    SR_GRANT_TRANSFER_LEN
}

/// A transfer grant as its holder names it on CONSUME_TRANSFER: the id
/// GRANT_TRANSFER replied with, the destination it was issued to and the
/// epoch it targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferGrantRef {
    pub grant_id: u64,
    pub dest_host: [u8; SR_HOST_ID],
    pub dest_anchor: [u8; SR_PEER_ID],
    pub target_epoch: u32,
}

/// Consume a grant, presenting it and the custody context the key is
/// bound to.
pub fn build_consume_transfer(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    grant: &TransferGrantRef,
    ctx: &[u8; SR_CONTEXT_DIGEST],
) -> usize {
    if dst.len() < SR_CONSUME_TRANSFER_LEN {
        return 0;
    }
    let mut o = put_common(dst, SR_OP_CONSUME_TRANSFER, sid, epoch);
    dst[o..o + 8].copy_from_slice(&grant.grant_id.to_le_bytes());
    o += 8;
    dst[o..o + 16].copy_from_slice(&grant.dest_host);
    o += 16;
    dst[o..o + 8].copy_from_slice(&grant.dest_anchor);
    o += 8;
    dst[o..o + 4].copy_from_slice(&grant.target_epoch.to_le_bytes());
    o += 4;
    dst[o..o + SR_CONTEXT_DIGEST].copy_from_slice(ctx);
    SR_CONSUME_TRANSFER_LEN
}

pub fn build_counter_floor(
    dst: &mut [u8],
    sid: &[u8; SR_SESSION_ID],
    epoch: u32,
    counter: u8,
    floor: u64,
) -> usize {
    if dst.len() < SR_COUNTER_FLOOR_LEN || counter as usize >= SR_NUM_COUNTERS {
        return 0;
    }
    let o = put_common(dst, SR_OP_COUNTER_FLOOR, sid, epoch);
    dst[o] = counter;
    dst[o + 1..o + 9].copy_from_slice(&floor.to_le_bytes());
    SR_COUNTER_FLOOR_LEN
}

// ── State ───────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SessionSlot {
    pub used: bool,
    /// Set by RECOVERY_MARK; cleared by EPOCH_BUMP. While set, RESERVE
    /// is refused: unsafe recovery voids outstanding blocks and blocks
    /// emission until the epoch advances.
    pub voided: bool,
    pub fence_state: u8,
    pub flags: u8,
    /// The stored key is bound to `key_ctx`.
    pub key_bound: bool,
    /// A transfer grant is outstanding.
    pub grant_live: bool,
    /// Transient install bookkeeping (which timing owners have restored a
    /// deadline for this slot); never serialized, zero between installs.
    pub restore_marks: u8,
    pub epoch: u32,
    pub session_id: [u8; SR_SESSION_ID],
    pub anchor_id: [u8; SR_PEER_ID],
    pub worker_id: [u8; SR_PEER_ID],
    /// Anchor the fence was initiated/confirmed against. A takeover
    /// only trusts a fence aimed at the anchor being replaced.
    pub fence_target: [u8; SR_PEER_ID],
    /// Custody generation the confirmed fence carries; zero until
    /// FENCE_CONFIRM. ACTIVATE must present exactly this.
    pub fence_gen: u32,
    /// Durable receive-window floor. Forward-only.
    pub rx_floor: u64,
    /// Exclusive high-water of every counter block ever granted.
    pub high_water: [u64; SR_NUM_COUNTERS],
    /// Mirrored floor per counter: the high-water the standby has
    /// acknowledged (COUNTER_FLOOR), forward-only.
    pub floor: [u64; SR_NUM_COUNTERS],
    /// KEK-wrapped key blob (opaque) + declared TTL metadata.
    pub key_len: u16,
    pub key_ttl_ms: u32,
    /// Generation of the key's expiry deadline: bumped by every KEY_PUT that
    /// arms a TTL. A due callback wipes the key only when its generation
    /// still matches.
    pub key_gen: u64,
    pub key: [u8; SR_MAX_WRAPPED_KEY],
    /// Custody-context digest the key is bound to (when `key_bound`).
    pub key_ctx: [u8; SR_CONTEXT_DIGEST],
    /// Committed mirror horizon (MIRROR_MARK), monotone.
    pub mirror_epoch: u64,
    pub mirror_generation: u64,
    /// Outstanding transfer grant (when `grant_live`).
    pub grant_id: u64,
    /// Generation of the grant's expiry deadline (bumped per grant).
    pub grant_gen: u64,
    pub grant_dest_host: [u8; SR_HOST_ID],
    pub grant_dest_anchor: [u8; SR_PEER_ID],
    pub grant_target_epoch: u32,
}

impl SessionSlot {
    pub const fn empty() -> Self {
        SessionSlot {
            used: false,
            voided: false,
            fence_state: SR_FENCE_NONE,
            flags: 0,
            key_bound: false,
            grant_live: false,
            restore_marks: 0,
            epoch: 0,
            session_id: [0; SR_SESSION_ID],
            anchor_id: [0; SR_PEER_ID],
            worker_id: [0; SR_PEER_ID],
            fence_target: [0; SR_PEER_ID],
            fence_gen: 0,
            rx_floor: 0,
            high_water: [0; SR_NUM_COUNTERS],
            floor: [0; SR_NUM_COUNTERS],
            key_len: 0,
            key_ttl_ms: 0,
            key_gen: 0,
            key: [0; SR_MAX_WRAPPED_KEY],
            key_ctx: [0; SR_CONTEXT_DIGEST],
            mirror_epoch: 0,
            mirror_generation: 0,
            grant_id: 0,
            grant_gen: 0,
            grant_dest_host: [0; SR_HOST_ID],
            grant_dest_anchor: [0; SR_PEER_ID],
            grant_target_epoch: 0,
        }
    }

    /// Zeroize key custody. Length, TTL, context binding and
    /// every blob byte — the durable substrate must hold nothing after
    /// teardown. `key_gen` survives: it fences deadlines, not custody.
    fn wipe_key(&mut self) {
        self.key_len = 0;
        self.key_ttl_ms = 0;
        self.key = [0; SR_MAX_WRAPPED_KEY];
        self.key_bound = false;
        self.key_ctx = [0; SR_CONTEXT_DIGEST];
    }

    /// Drop an outstanding grant. `grant_gen` survives to fence its
    /// deadline.
    fn clear_grant(&mut self) {
        self.grant_live = false;
        self.grant_id = 0;
        self.grant_dest_host = [0; SR_HOST_ID];
        self.grant_dest_anchor = [0; SR_PEER_ID];
        self.grant_target_epoch = 0;
    }

    /// Per-slot snapshot record (see `SR_SLOT_SNAP_LEN` layout).
    fn encode(&self, dst: &mut [u8]) {
        dst[0] = self.used as u8;
        dst[1] = self.voided as u8;
        dst[2] = self.fence_state;
        dst[3] = self.flags;
        dst[4] = self.key_bound as u8;
        dst[5] = self.grant_live as u8;
        dst[6] = 0;
        dst[7] = 0;
        dst[8..12].copy_from_slice(&self.epoch.to_le_bytes());
        dst[12..16].copy_from_slice(&self.fence_gen.to_le_bytes());
        dst[16..20].copy_from_slice(&self.grant_target_epoch.to_le_bytes());
        dst[20..24].copy_from_slice(&self.key_ttl_ms.to_le_bytes());
        dst[24..26].copy_from_slice(&self.key_len.to_le_bytes());
        dst[26] = 0;
        dst[27] = 0;
        dst[28..44].copy_from_slice(&self.session_id);
        dst[44..52].copy_from_slice(&self.anchor_id);
        dst[52..60].copy_from_slice(&self.worker_id);
        dst[60..68].copy_from_slice(&self.fence_target);
        dst[68..76].copy_from_slice(&self.grant_dest_anchor);
        dst[76..92].copy_from_slice(&self.grant_dest_host);
        dst[92..100].copy_from_slice(&self.rx_floor.to_le_bytes());
        let mut c = 0;
        while c < SR_NUM_COUNTERS {
            dst[100 + c * 8..108 + c * 8].copy_from_slice(&self.high_water[c].to_le_bytes());
            dst[124 + c * 8..132 + c * 8].copy_from_slice(&self.floor[c].to_le_bytes());
            c += 1;
        }
        dst[148..156].copy_from_slice(&self.key_gen.to_le_bytes());
        dst[156..164].copy_from_slice(&self.mirror_epoch.to_le_bytes());
        dst[164..172].copy_from_slice(&self.mirror_generation.to_le_bytes());
        dst[172..180].copy_from_slice(&self.grant_id.to_le_bytes());
        dst[180..188].copy_from_slice(&self.grant_gen.to_le_bytes());
        dst[188..220].copy_from_slice(&self.key_ctx);
        dst[220..300].copy_from_slice(&self.key);
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

    fn u32_at(src: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([src[o], src[o + 1], src[o + 2], src[o + 3]])
    }

    /// Decode a record; `None` for a flag byte outside {0, 1} or a key
    /// length past the blob.
    fn decode(src: &[u8]) -> Option<SessionSlot> {
        let mut s = SessionSlot::empty();
        if src[0] > 1 || src[1] > 1 || src[4] > 1 || src[5] > 1 {
            return None;
        }
        s.used = src[0] != 0;
        s.voided = src[1] != 0;
        s.fence_state = src[2];
        s.flags = src[3];
        s.key_bound = src[4] != 0;
        s.grant_live = src[5] != 0;
        s.epoch = Self::u32_at(src, 8);
        s.fence_gen = Self::u32_at(src, 12);
        s.grant_target_epoch = Self::u32_at(src, 16);
        s.key_ttl_ms = Self::u32_at(src, 20);
        s.key_len = u16::from_le_bytes([src[24], src[25]]);
        if s.key_len as usize > SR_MAX_WRAPPED_KEY || s.fence_state > SR_FENCE_CONFIRMED {
            return None;
        }
        s.session_id.copy_from_slice(&src[28..44]);
        s.anchor_id.copy_from_slice(&src[44..52]);
        s.worker_id.copy_from_slice(&src[52..60]);
        s.fence_target.copy_from_slice(&src[60..68]);
        s.grant_dest_anchor.copy_from_slice(&src[68..76]);
        s.grant_dest_host.copy_from_slice(&src[76..92]);
        s.rx_floor = Self::u64_at(src, 92);
        let mut c = 0;
        while c < SR_NUM_COUNTERS {
            s.high_water[c] = Self::u64_at(src, 100 + c * 8);
            s.floor[c] = Self::u64_at(src, 124 + c * 8);
            c += 1;
        }
        s.key_gen = Self::u64_at(src, 148);
        s.mirror_epoch = Self::u64_at(src, 156);
        s.mirror_generation = Self::u64_at(src, 164);
        s.grant_id = Self::u64_at(src, 172);
        s.grant_gen = Self::u64_at(src, 180);
        s.key_ctx.copy_from_slice(&src[188..220]);
        s.key.copy_from_slice(&src[220..300]);
        Some(s)
    }
}

/// The replicated state machine. Embed in the module state; feed every
/// committed entry body (tag header stripped) to `apply` in commit
/// order. `N` is the session arena, `D` the deadline index (`≥ 2N`).
#[repr(C)]
pub struct SessionRegistry<const N: usize, const D: usize> {
    pub slots: [SessionSlot; N],
    /// session id → slot. Derived; rebuilt on restore.
    index: SlotIndex<N, SR_SESSION_ID>,
    /// Which slots hold a session; a BIND takes the lowest free one.
    /// Derived; rebuilt on restore.
    occupied: SlotSet<N>,
    /// Sessions this deployment admits (≤ `N`): the profile's claim, and
    /// the capacity reported. Replicated in the snapshot header so every
    /// replica refuses the same BIND.
    pub admitted: u32,
    /// Used slots.
    pub live: u32,
    /// Monotonic unsafe-recovery epoch. Advanced by RECOVERY_MARK.
    pub recovery_epoch: u32,
    /// Applied-command counter (diagnostics / metrics only).
    pub applied: u64,
    /// Embedded deterministic timing state: timing and consumer state
    /// share one apply and snapshot boundary.
    pub timing: TimingState<D>,
    /// Due callbacks that performed their domain transition (key
    /// wiped, grant expired). Replicated so divergence is byte-visible.
    pub deadlines_fired: u32,
    /// Due callbacks that were deterministic no-ops (object gone or
    /// generation mismatch). Replicated so a systematic mismatch is
    /// observable rather than silent.
    pub deadline_noop: u32,
    /// Last transfer-grant id issued (ids are registry-unique, never 0).
    pub next_grant_id: u64,
}

impl<const N: usize, const D: usize> Default for SessionRegistry<N, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const D: usize> SessionRegistry<N, D> {
    /// A profile's timing partition: key TTLs and transfer grants, one
    /// each per session.
    pub const TIMING_CAPS: [u32; TM_MAX_OWNERS] = [N as u32, N as u32, 0, 0];

    /// The arena must index cleanly and the deadline index must hold both
    /// owners' partitions in full — a profile that silently clamped a TTL
    /// partition would refuse KEY_PUTs for sessions it admits.
    const PROFILE_OK: () = assert!(
        N.is_power_of_two() && D >= 2 * N,
        "session profile: N must be a power of two and D >= 2 * N"
    );

    pub const fn new() -> Self {
        let () = Self::PROFILE_OK;
        SessionRegistry {
            slots: [SessionSlot::empty(); N],
            index: SlotIndex::new(),
            occupied: SlotSet::new(),
            admitted: N as u32,
            live: 0,
            recovery_epoch: 0,
            applied: 0,
            timing: TimingState::new(Self::TIMING_CAPS),
            deadlines_fired: 0,
            deadline_noop: 0,
            next_grant_id: 0,
        }
    }

    /// Initialise in place, admitting `admitted` sessions (clamped to
    /// `N`): every byte of the state, so it is what makes a raw state
    /// block a registry. The module's state block is too large for a
    /// profile-sized registry to be built on the stack and copied in.
    pub fn reset(&mut self, admitted: u32) {
        let () = Self::PROFILE_OK;
        let mut i = 0;
        while i < N {
            self.slots[i] = SessionSlot::empty();
            i += 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.admitted = if admitted as usize > N {
            N as u32
        } else {
            admitted
        };
        self.timing.reset(Self::TIMING_CAPS);
        self.clear_counters();
    }

    /// Empty an initialised registry, keeping what it admits and its
    /// logical time. A free slot is always `SessionSlot::empty()`, so only
    /// the occupied ones are cleared.
    pub fn clear(&mut self) {
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            self.slots[i] = SessionSlot::empty();
            at = i + 1;
        }
        self.index.reset();
        self.occupied.reset();
        self.timing.clear();
        self.clear_counters();
    }

    fn clear_counters(&mut self) {
        self.live = 0;
        self.recovery_epoch = 0;
        self.applied = 0;
        self.deadlines_fired = 0;
        self.deadline_noop = 0;
        self.next_grant_id = 0;
    }

    /// Arena size (the profile).
    pub const fn capacity(&self) -> usize {
        N
    }

    fn find(&self, sid: &[u8; SR_SESSION_ID]) -> Option<usize> {
        self.index.find(sid).map(|i| i as usize)
    }

    /// The slot a new session takes: the lowest free one, while the
    /// admitted count has room.
    fn find_free(&self) -> Option<usize> {
        if self.live >= self.admitted {
            return None;
        }
        self.occupied.lowest_free()
    }

    /// Read accessor: current slot for a session (local reads only —
    /// linearizable reads must go through the read-permit path).
    pub fn lookup(&self, sid: &[u8; SR_SESSION_ID]) -> Option<&SessionSlot> {
        self.find(sid).map(|i| &self.slots[i])
    }

    /// Mutable read accessor for host tests that stage a slot's fields
    /// (generation sentinels); production state moves only through
    /// `apply`.
    /// Whether `sid` holds a confirmed fence of exactly `fence_gen` on its
    /// current anchor `anchor`, not yet consumed by an ACTIVATE: what a
    /// fenced transport move of the same flow (session id = flow id) needs
    /// before it may mint the promoted emitter's token.
    pub fn fence_confirmed_on(
        &self,
        sid: &[u8; SR_SESSION_ID],
        anchor: &[u8; SR_PEER_ID],
        fence_gen: u32,
    ) -> bool {
        self.lookup(sid).is_some_and(|s| {
            s.fence_state == SR_FENCE_CONFIRMED
                && s.fence_target == *anchor
                && s.anchor_id == *anchor
                && fence_gen != 0
                && s.fence_gen == fence_gen
        })
    }

    pub fn lookup_mut(&mut self, sid: &[u8; SR_SESSION_ID]) -> Option<&mut SessionSlot> {
        match self.find(sid) {
            Some(i) => Some(&mut self.slots[i]),
            None => None,
        }
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
            SR_OP_KEY_PUT | SR_OP_KEY_PUT_BOUND => self.apply_key_put(body),
            SR_OP_KEY_WIPE => self.apply_key_wipe(body),
            SR_OP_FENCE_REQUEST | SR_OP_FENCE_CONFIRM => self.apply_fence(body),
            SR_OP_UNBIND => self.apply_unbind(body),
            SR_OP_RECOVERY_MARK => self.apply_recovery_mark(body),
            SR_OP_ACTIVATE => self.apply_activate(body),
            SR_OP_MIRROR_MARK => self.apply_mirror_mark(body),
            SR_OP_GRANT_TRANSFER => self.apply_grant_transfer(body),
            SR_OP_CONSUME_TRANSFER => self.apply_consume_transfer(body),
            SR_OP_COUNTER_FLOOR => self.apply_counter_floor(body),
            _ => SessionReply::fail(op, SR_ST_MALFORMED),
        };
        // Post-command due pass: a command that registered an already-due
        // deadline gets the same bounded pass `TimeAdvance` runs — still a
        // consequence of the committed entry, never of a local timer. Cheap
        // when nothing is due (one sorted-front comparison).
        self.run_due_pass();
        reply
    }

    // ── Deterministic timing ────────────────────────────────────────

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

    /// Deterministic due handler: mutates replicated state only. The
    /// authoritative object decides the meaning; an absent object or
    /// generation mismatch is a recorded no-op.
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
            SR_OWNER_GRANT_TTL => {
                if let Some(i) = self.find(&d.id) {
                    let slot = &mut self.slots[i];
                    if slot.grant_gen == d.generation && slot.grant_live {
                        slot.clear_grant();
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

    /// Apply a committed `TimeAdvance` entry. Regressions and duplicates
    /// retain the existing logical time — safe and deterministic. Returns
    /// what happened so the module wrapper can emit metrics and the leader
    /// can schedule `TimeDrain`.
    pub fn apply_time_advance(&mut self, proposed_time_ms: u64) -> super::timing::TimeApplied {
        let _ = self.timing.advance(proposed_time_ms);
        let fired = self.run_due_pass();
        super::timing::TimeApplied {
            logical_now_ms: self.timing.logical_now_ms(),
            fired,
            due_remaining: self.timing.due_depth(),
        }
    }

    /// Apply a committed `TimeDrain` entry. A drain never advances time;
    /// `through_time_ms` must equal the applied logical time or the drain is
    /// a deterministic no-op — a stale drain request cannot invent a new
    /// time fence.
    pub fn apply_time_drain(&mut self, through_time_ms: u64) -> super::timing::TimeApplied {
        let fired = if through_time_ms == self.timing.logical_now_ms() {
            self.run_due_pass()
        } else {
            0
        };
        super::timing::TimeApplied {
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

    /// Locate a bound session and check the command's epoch against it.
    fn slot_at_epoch(
        &self,
        op: u8,
        sid: &[u8; SR_SESSION_ID],
        epoch: u32,
    ) -> Result<usize, SessionReply> {
        let Some(i) = self.find(sid) else {
            return Err(Self::reply_err(op, sid, 0, SR_ST_UNKNOWN_SESSION));
        };
        if epoch != self.slots[i].epoch {
            return Err(Self::reply_err(
                op,
                sid,
                self.slots[i].epoch,
                SR_ST_STALE_EPOCH,
            ));
        }
        Ok(i)
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
                // Single-writer rule: a competing writer at the
                // current or an older generation is rejected.
                return Self::reply_err(SR_OP_BIND, &sid, slot.epoch, SR_ST_STALE_EPOCH);
            }
            // Epoch-advancing rebind. An ANCHOR change is a takeover,
            // and on a fence-required session a takeover is ACTIVATE's
            // alone: it presents the confirmed fence's generation, which
            // a BIND does not carry. The refusal leaves any confirmed
            // fence in place for the ACTIVATE that will use it.
            if anchor != slot.anchor_id && (slot.flags & SR_BIND_FENCE_REQUIRED) != 0 {
                return Self::reply_err(SR_OP_BIND, &sid, slot.epoch, SR_ST_FENCE_REQUIRED);
            }
            slot.epoch = epoch;
            slot.anchor_id = anchor;
            slot.worker_id = worker;
            slot.flags = flags;
            // The epoch advanced: recovery-void clears (the bump
            // is the fence), and any fence in flight resets.
            slot.voided = false;
            slot.fence_state = SR_FENCE_NONE;
            slot.fence_target = [0; SR_PEER_ID];
            slot.fence_gen = 0;
            return Self::reply_ok(SR_OP_BIND, &sid, epoch, 1, 0);
        }

        let Some(i) = self.find_free() else {
            return Self::reply_err(SR_OP_BIND, &sid, epoch, SR_ST_NO_CAPACITY);
        };
        if !self.index.insert(&sid, i as u32) {
            return Self::reply_err(SR_OP_BIND, &sid, epoch, SR_ST_NO_CAPACITY);
        }
        self.occupied.mark(i);
        let slot = &mut self.slots[i];
        *slot = SessionSlot::empty();
        slot.used = true;
        slot.epoch = epoch;
        slot.session_id = sid;
        slot.anchor_id = anchor;
        slot.worker_id = worker;
        slot.flags = flags;
        self.live += 1;
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
        slot.voided = false; // the bump is what re-arms emission
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
        // Epoch fencing at block acquisition: a stale writer — a
        // not-actually-dead old anchor — never gets a fresh block.
        let i = match self.slot_at_epoch(SR_OP_RESERVE, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        let slot = &mut self.slots[i];
        if slot.voided {
            // Unsafe recovery voided this session's blocks; no
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
        let i = match self.slot_at_epoch(SR_OP_RX_FLOOR, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        let slot = &mut self.slots[i];
        if floor < slot.rx_floor {
            // The receive-window low edge is a hard floor — it
            // never moves backward, so a takeover can never re-admit
            // replays below the last durable checkpoint.
            return Self::reply_err(SR_OP_RX_FLOOR, &sid, slot.epoch, SR_ST_FLOOR_REGRESSION);
        }
        slot.rx_floor = floor;
        Self::reply_ok(SR_OP_RX_FLOOR, &sid, slot.epoch, floor, 0)
    }

    /// KEY_PUT and KEY_PUT_BOUND: the bound form carries the custody
    /// context the blob is bound to; a put against a live key bound to
    /// another context is refused.
    fn apply_key_put(&mut self, body: &[u8]) -> SessionReply {
        let op = body[0];
        let bound = op == SR_OP_KEY_PUT_BOUND;
        let hdr = if bound {
            SR_KEY_PUT_BOUND_HDR
        } else {
            SR_KEY_PUT_HDR
        };
        let Some((sid, epoch)) = Self::common(body, hdr) else {
            return SessionReply::fail(op, SR_ST_MALFORMED);
        };
        let ttl_ms = u32::from_le_bytes([body[21], body[22], body[23], body[24]]);
        let mut ctx = [0u8; SR_CONTEXT_DIGEST];
        if bound {
            ctx.copy_from_slice(&body[25..25 + SR_CONTEXT_DIGEST]);
        }
        let blob_len = u16::from_le_bytes([body[hdr - 2], body[hdr - 1]]) as usize;
        if blob_len == 0 || blob_len > SR_MAX_WRAPPED_KEY || body.len() < hdr + blob_len {
            return Self::reply_err(op, &sid, epoch, SR_ST_MALFORMED);
        }
        let i = match self.slot_at_epoch(op, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        // A live key keeps the context it was bound to: a put for another
        // context (or an unbound put over a bound key) is a custody
        // violation, not a replacement. Only KEY_WIPE ends a context. An
        // epoch change does not: the context covers the epoch, so after one
        // the stored key no longer matches the session's own context, and
        // the new holder wipes it before putting a key under its own.
        let held = &self.slots[i];
        if held.key_len > 0 && held.key_bound && (!bound || held.key_ctx != ctx) {
            let cur = self.slots[i].epoch;
            return Self::reply_err(op, &sid, cur, SR_ST_CONTEXT_MISMATCH);
        }
        // TTL expiry rides the replicated timing index. Registration happens
        // BEFORE the key is stored: if the owner's deadline partition is
        // full (or the generation would overflow), the command fails
        // deterministically without creating its consumer object.
        if ttl_ms > 0 {
            let gen = self.slots[i].key_gen.wrapping_add(1);
            let due = self.timing.logical_now_ms().saturating_add(ttl_ms as u64);
            match self.timing.register(SR_OWNER_KEY_TTL, sid, gen, due) {
                Ok(_) => self.slots[i].key_gen = gen,
                Err(_) => {
                    let cur = self.slots[i].epoch;
                    return Self::reply_err(op, &sid, cur, SR_ST_DEADLINE_CAPACITY);
                }
            }
        } else {
            // Non-expiring key replaces an expiring one: disarm.
            let gen = self.slots[i].key_gen;
            let _ = self.timing.cancel(SR_OWNER_KEY_TTL, &sid, gen);
        }
        let slot = &mut self.slots[i];
        // The blob is opaque — stored and returned byte-for-byte, never
        // parsed. The KEK lives with the anchors / HSM; this registry (and
        // the WAL under it) cannot read the key.
        slot.wipe_key();
        slot.key_len = blob_len as u16;
        slot.key_ttl_ms = ttl_ms;
        slot.key[..blob_len].copy_from_slice(&body[hdr..hdr + blob_len]);
        slot.key_bound = bound;
        slot.key_ctx = ctx;
        Self::reply_ok(op, &sid, slot.epoch, blob_len as u64, ttl_ms as u64)
    }

    fn apply_key_wipe(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, _epoch)) = Self::common(body, SR_KEY_WIPE_LEN) else {
            return SessionReply::fail(SR_OP_KEY_WIPE, SR_ST_MALFORMED);
        };
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_KEY_WIPE, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        // Deliberately NOT epoch-gated: a wipe must never be refused
        // as stale — teardown and TTL expiry always win.
        let gen = self.slots[i].key_gen;
        let _ = self.timing.cancel(SR_OWNER_KEY_TTL, &sid, gen);
        let slot = &mut self.slots[i];
        slot.wipe_key();
        Self::reply_ok(SR_OP_KEY_WIPE, &sid, slot.epoch, 0, 0)
    }

    fn apply_fence(&mut self, body: &[u8]) -> SessionReply {
        let op = body[0];
        let want = if op == SR_OP_FENCE_CONFIRM {
            SR_FENCE_CONFIRM_LEN
        } else {
            SR_FENCE_LEN
        };
        let Some((sid, epoch)) = Self::common(body, want) else {
            return SessionReply::fail(op, SR_ST_MALFORMED);
        };
        let mut target = [0u8; SR_PEER_ID];
        target.copy_from_slice(&body[21..29]);
        let i = match self.slot_at_epoch(op, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        let slot = &mut self.slots[i];
        if op == SR_OP_FENCE_REQUEST {
            slot.fence_state = SR_FENCE_INITIATED;
            slot.fence_target = target;
            slot.fence_gen = 0;
        } else {
            // CONFIRM only upgrades the fence it was initiated for —
            // a confirmation aimed at a different anchor is malformed
            // orchestration, not a fence — and it records the agent's
            // custody generation, which is never zero.
            let fence_gen = u32::from_le_bytes([body[29], body[30], body[31], body[32]]);
            if slot.fence_state != SR_FENCE_INITIATED
                || slot.fence_target != target
                || fence_gen == 0
            {
                return Self::reply_err(op, &sid, slot.epoch, SR_ST_MALFORMED);
            }
            slot.fence_state = SR_FENCE_CONFIRMED;
            slot.fence_gen = fence_gen;
        }
        Self::reply_ok(
            op,
            &sid,
            slot.epoch,
            slot.fence_state as u64,
            u64::from(slot.fence_gen),
        )
    }

    /// The fenced takeover: move the anchor under a strictly higher epoch,
    /// admitted only by the confirmed fence whose generation is presented,
    /// and — for a floor-gated session — only once every counter's
    /// mirrored floor has reached the granted high-water.
    fn apply_activate(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, new_epoch)) = Self::common(body, SR_ACTIVATE_LEN) else {
            return SessionReply::fail(SR_OP_ACTIVATE, SR_ST_MALFORMED);
        };
        let mut anchor = [0u8; SR_PEER_ID];
        anchor.copy_from_slice(&body[21..29]);
        let fence_gen = u32::from_le_bytes([body[29], body[30], body[31], body[32]]);
        let Some(i) = self.find(&sid) else {
            return Self::reply_err(SR_OP_ACTIVATE, &sid, 0, SR_ST_UNKNOWN_SESSION);
        };
        let slot = &mut self.slots[i];
        // Only a session that declared the class has a fenced takeover,
        // and a takeover changes the anchor.
        if (slot.flags & SR_BIND_FENCE_REQUIRED) == 0 || anchor == slot.anchor_id {
            return Self::reply_err(SR_OP_ACTIVATE, &sid, slot.epoch, SR_ST_MALFORMED);
        }
        if new_epoch <= slot.epoch {
            return Self::reply_err(SR_OP_ACTIVATE, &sid, slot.epoch, SR_ST_STALE_EPOCH);
        }
        if slot.fence_state != SR_FENCE_CONFIRMED || slot.fence_target != slot.anchor_id {
            return Self::reply_err(SR_OP_ACTIVATE, &sid, slot.epoch, SR_ST_FENCE_REQUIRED);
        }
        if fence_gen == 0 || fence_gen != slot.fence_gen {
            return Self::reply_err(SR_OP_ACTIVATE, &sid, slot.epoch, SR_ST_FENCE_STALE);
        }
        if (slot.flags & SR_BIND_COUNTER_FLOOR_GATED) != 0 {
            // The standby must have mirrored every granted block: a
            // floor behind the high-water is identity space the new
            // emitter does not know was handed out.
            let mut c = 0;
            while c < SR_NUM_COUNTERS {
                if slot.floor[c] < slot.high_water[c] {
                    return Self::reply_err(
                        SR_OP_ACTIVATE,
                        &sid,
                        slot.epoch,
                        SR_ST_RESERVATION_BEHIND,
                    );
                }
                c += 1;
            }
        }
        slot.epoch = new_epoch;
        slot.anchor_id = anchor;
        // The epoch advanced: recovery-void clears, and the fence
        // that admitted this activation is consumed.
        slot.voided = false;
        slot.fence_state = SR_FENCE_NONE;
        slot.fence_target = [0; SR_PEER_ID];
        slot.fence_gen = 0;
        Self::reply_ok(SR_OP_ACTIVATE, &sid, new_epoch, u64::from(fence_gen), 0)
    }

    fn apply_unbind(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_UNBIND_LEN) else {
            return SessionReply::fail(SR_OP_UNBIND, SR_ST_MALFORMED);
        };
        let i = match self.slot_at_epoch(SR_OP_UNBIND, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        // Teardown disarms any pending key-TTL and grant deadlines: the
        // slot (the authoritative object) is going away, so the index
        // entries must not linger as guaranteed no-ops.
        let gen = self.slots[i].key_gen;
        let _ = self.timing.cancel(SR_OWNER_KEY_TTL, &sid, gen);
        let gen = self.slots[i].grant_gen;
        let _ = self.timing.cancel(SR_OWNER_GRANT_TTL, &sid, gen);
        let _ = self.index.remove(&sid);
        self.occupied.free(i);
        // Teardown wipes the key with everything else and frees the slot.
        // The session's counter high-waters die with it — a REUSED
        // session_id would restart counters at zero, so session_ids must
        // be single-use (fluxor anchors mint anchor_id||counter, which
        // is).
        self.slots[i] = SessionSlot::empty();
        self.live -= 1;
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
        // Unsafe recovery voids every outstanding reservation and every
        // outstanding transfer grant: a recovery that lost the log tail
        // must force reconnect, never risk a duplicate key use. Emission
        // for each session stays blocked until ITS epoch advances
        // (EPOCH_BUMP, an epoch-advancing BIND, or ACTIVATE).
        let mut voided = 0u64;
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            self.slots[i].voided = true;
            voided += 1;
            if self.slots[i].grant_live {
                let sid = self.slots[i].session_id;
                let gen = self.slots[i].grant_gen;
                let _ = self.timing.cancel(SR_OWNER_GRANT_TTL, &sid, gen);
                self.slots[i].clear_grant();
            }
            at = i + 1;
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

    /// Committed mirror horizon: `(mirror_epoch, mirror_generation)` is
    /// monotone in lexicographic order; an equal mark is an idempotent
    /// retry, a lower one a regression. The reply exposes the committed
    /// pair.
    fn apply_mirror_mark(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_MIRROR_MARK_LEN) else {
            return SessionReply::fail(SR_OP_MIRROR_MARK, SR_ST_MALFORMED);
        };
        let mirror_epoch = SessionSlot::u64_at(body, 21);
        let mirror_generation = SessionSlot::u64_at(body, 29);
        let i = match self.slot_at_epoch(SR_OP_MIRROR_MARK, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        let slot = &mut self.slots[i];
        if (mirror_epoch, mirror_generation) < (slot.mirror_epoch, slot.mirror_generation) {
            return Self::reply_err(SR_OP_MIRROR_MARK, &sid, slot.epoch, SR_ST_MIRROR_REGRESSION);
        }
        slot.mirror_epoch = mirror_epoch;
        slot.mirror_generation = mirror_generation;
        Self::reply_ok(
            SR_OP_MIRROR_MARK,
            &sid,
            slot.epoch,
            slot.mirror_epoch,
            slot.mirror_generation,
        )
    }

    /// Issue a transfer grant. One grant is outstanding per session; a
    /// new one replaces it (the old id dies). A voided session issues
    /// none until its epoch advances.
    fn apply_grant_transfer(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_GRANT_TRANSFER_LEN) else {
            return SessionReply::fail(SR_OP_GRANT_TRANSFER, SR_ST_MALFORMED);
        };
        let mut dest_host = [0u8; SR_HOST_ID];
        dest_host.copy_from_slice(&body[21..37]);
        let mut dest_anchor = [0u8; SR_PEER_ID];
        dest_anchor.copy_from_slice(&body[37..45]);
        let target_epoch = SessionSlot::u32_at(body, 45);
        let ttl_ms = SessionSlot::u32_at(body, 49);
        let i = match self.slot_at_epoch(SR_OP_GRANT_TRANSFER, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        if self.slots[i].voided {
            let cur = self.slots[i].epoch;
            return Self::reply_err(SR_OP_GRANT_TRANSFER, &sid, cur, SR_ST_RECOVERY_VOID);
        }
        if target_epoch <= epoch {
            // A transfer hands the key to the NEXT holder; the target is a
            // generation the destination will activate under.
            let cur = self.slots[i].epoch;
            return Self::reply_err(SR_OP_GRANT_TRANSFER, &sid, cur, SR_ST_MALFORMED);
        }
        let gen = self.slots[i].grant_gen.wrapping_add(1);
        if ttl_ms > 0 {
            let due = self.timing.logical_now_ms().saturating_add(ttl_ms as u64);
            if self
                .timing
                .register(SR_OWNER_GRANT_TTL, sid, gen, due)
                .is_err()
            {
                let cur = self.slots[i].epoch;
                return Self::reply_err(SR_OP_GRANT_TRANSFER, &sid, cur, SR_ST_DEADLINE_CAPACITY);
            }
        } else {
            let old = self.slots[i].grant_gen;
            let _ = self.timing.cancel(SR_OWNER_GRANT_TTL, &sid, old);
        }
        self.next_grant_id = self.next_grant_id.wrapping_add(1);
        let slot = &mut self.slots[i];
        slot.grant_gen = gen;
        slot.grant_live = true;
        slot.grant_id = self.next_grant_id;
        slot.grant_dest_host = dest_host;
        slot.grant_dest_anchor = dest_anchor;
        slot.grant_target_epoch = target_epoch;
        Self::reply_ok(
            SR_OP_GRANT_TRANSFER,
            &sid,
            slot.epoch,
            slot.grant_id,
            ttl_ms as u64,
        )
    }

    /// Consume a grant, single use: the id, destination and target epoch
    /// must be the grant's, and the custody context the stored key's.
    fn apply_consume_transfer(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_CONSUME_TRANSFER_LEN) else {
            return SessionReply::fail(SR_OP_CONSUME_TRANSFER, SR_ST_MALFORMED);
        };
        let grant_id = SessionSlot::u64_at(body, 21);
        let mut dest_host = [0u8; SR_HOST_ID];
        dest_host.copy_from_slice(&body[29..45]);
        let mut dest_anchor = [0u8; SR_PEER_ID];
        dest_anchor.copy_from_slice(&body[45..53]);
        let target_epoch = SessionSlot::u32_at(body, 53);
        let mut ctx = [0u8; SR_CONTEXT_DIGEST];
        ctx.copy_from_slice(&body[57..89]);
        let i = match self.slot_at_epoch(SR_OP_CONSUME_TRANSFER, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        let cur = self.slots[i].epoch;
        {
            let slot = &self.slots[i];
            if !slot.grant_live
                || slot.grant_id != grant_id
                || slot.grant_dest_host != dest_host
                || slot.grant_dest_anchor != dest_anchor
                || slot.grant_target_epoch != target_epoch
            {
                return Self::reply_err(SR_OP_CONSUME_TRANSFER, &sid, cur, SR_ST_GRANT_INVALID);
            }
            if slot.key_len == 0 || !slot.key_bound || slot.key_ctx != ctx {
                return Self::reply_err(SR_OP_CONSUME_TRANSFER, &sid, cur, SR_ST_CONTEXT_MISMATCH);
            }
        }
        let gen = self.slots[i].grant_gen;
        let _ = self.timing.cancel(SR_OWNER_GRANT_TTL, &sid, gen);
        let slot = &mut self.slots[i];
        slot.clear_grant();
        Self::reply_ok(
            SR_OP_CONSUME_TRANSFER,
            &sid,
            cur,
            grant_id,
            u64::from(slot.key_len),
        )
    }

    /// Advance a counter's mirrored floor. Forward-only; it may not pass
    /// the granted high-water (the standby cannot have mirrored a block
    /// that was never granted). The reply exposes `(floor, high_water)`.
    fn apply_counter_floor(&mut self, body: &[u8]) -> SessionReply {
        let Some((sid, epoch)) = Self::common(body, SR_COUNTER_FLOOR_LEN) else {
            return SessionReply::fail(SR_OP_COUNTER_FLOOR, SR_ST_MALFORMED);
        };
        let counter = body[21] as usize;
        let floor = SessionSlot::u64_at(body, 22);
        if counter >= SR_NUM_COUNTERS {
            return Self::reply_err(SR_OP_COUNTER_FLOOR, &sid, epoch, SR_ST_MALFORMED);
        }
        let i = match self.slot_at_epoch(SR_OP_COUNTER_FLOOR, &sid, epoch) {
            Ok(i) => i,
            Err(r) => return r,
        };
        let slot = &mut self.slots[i];
        if floor < slot.floor[counter] {
            return Self::reply_err(
                SR_OP_COUNTER_FLOOR,
                &sid,
                slot.epoch,
                SR_ST_MIRROR_REGRESSION,
            );
        }
        if floor > slot.high_water[counter] {
            return Self::reply_err(SR_OP_COUNTER_FLOOR, &sid, slot.epoch, SR_ST_MALFORMED);
        }
        slot.floor[counter] = floor;
        Self::reply_ok(
            SR_OP_COUNTER_FLOOR,
            &sid,
            slot.epoch,
            floor,
            slot.high_water[counter],
        )
    }

    // ── Snapshot (state-machine export/install) ─────────────────────
    //
    // Streamed as versioned records, never a whole-arena image: the
    // header names the profile and the record count, each used slot is
    // one record, and the timing section follows (header, then its live
    // entries). A replica of another profile, a count that does not
    // match, a record for a slot already filled or a session already
    // indexed, or a deadline without its consumer object fails the
    // install closed. Layout (all LE):
    //   header [version:u16 = 5][reserved:u16][arena N:u32][deadlines D:u32]
    //          [admitted:u32][record_count:u32][recovery_epoch:u32]
    //          [applied:u64][deadlines_fired:u32][deadline_noop:u32]
    //          [next_grant_id:u64]
    //   record [slot:u32][SessionSlot: SR_SLOT_SNAP_LEN] × record_count,
    //          in slot order
    //   timing TimingState header, then its live entries in heap order
    //
    // An installed snapshot's slot numbering is the exporter's. A session
    // lands in the lowest free slot, a function of which slots are
    // occupied, so every replica places sessions alike and the image is
    // byte-identical across replicas.

    /// The session registry's header leads the session directory's
    /// image, so this versions the image: 3 since the failover-operation
    /// section followed the VIP one; 4 since the region and operation
    /// sections followed it, the transport records carried token fields
    /// and the VIP records their owner width; 5 since the attachment and
    /// reservation sections followed the operation one.
    pub const SNAPSHOT_VERSION: u16 = 5;

    /// Snapshot of the whole state into `dst` (host convenience over the
    /// streamed form). Returns the length, or -1 when `dst` is short.
    pub fn snapshot(&self, dst: &mut [u8]) -> i32 {
        let total = self.snapshot_len();
        if dst.len() < total {
            return -1;
        }
        let mut cur = SrExportCursor::new();
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

    /// Bytes the streamed snapshot occupies right now.
    pub fn snapshot_len(&self) -> usize {
        SR_SNAP_HDR_LEN + self.live as usize * SR_SNAP_RECORD_LEN + self.timing.snapshot_len()
    }

    /// Streamed export: write the next unit (header, one record, timing
    /// header, one timing entry) into `dst` (≥ `SR_SNAP_MAX_UNIT`).
    /// Returns 0 once the image is complete.
    pub fn export_next(&self, cur: &mut SrExportCursor, dst: &mut [u8]) -> usize {
        {
            if cur.stage == SR_EXPORT_RECORDS {
                match self.occupied.next_used(cur.pos as usize) {
                    Some(i) => cur.pos = i as u32,
                    None => cur.stage = SR_EXPORT_TIMING_HDR,
                }
            }
            if cur.stage == SR_EXPORT_TIMING_ENTRIES && cur.pos >= self.timing.live {
                cur.stage = SR_EXPORT_DONE;
            }
            if dst.len() < SrInstaller::stage_len(cur.stage) {
                return 0;
            }
            match cur.stage {
                SR_EXPORT_HEADER => {
                    dst[0..2].copy_from_slice(&Self::SNAPSHOT_VERSION.to_le_bytes());
                    dst[2..4].copy_from_slice(&0u16.to_le_bytes());
                    dst[4..8].copy_from_slice(&(N as u32).to_le_bytes());
                    dst[8..12].copy_from_slice(&(D as u32).to_le_bytes());
                    dst[12..16].copy_from_slice(&self.admitted.to_le_bytes());
                    dst[16..20].copy_from_slice(&self.live.to_le_bytes());
                    dst[20..24].copy_from_slice(&self.recovery_epoch.to_le_bytes());
                    dst[24..32].copy_from_slice(&self.applied.to_le_bytes());
                    dst[32..36].copy_from_slice(&self.deadlines_fired.to_le_bytes());
                    dst[36..40].copy_from_slice(&self.deadline_noop.to_le_bytes());
                    dst[40..48].copy_from_slice(&self.next_grant_id.to_le_bytes());
                    cur.stage = SR_EXPORT_RECORDS;
                    cur.pos = 0;
                    SR_SNAP_HDR_LEN
                }
                SR_EXPORT_RECORDS => {
                    dst[0..4].copy_from_slice(&cur.pos.to_le_bytes());
                    self.slots[cur.pos as usize].encode(&mut dst[4..4 + SR_SLOT_SNAP_LEN]);
                    cur.pos += 1;
                    SR_SNAP_RECORD_LEN
                }
                SR_EXPORT_TIMING_HDR => {
                    cur.stage = SR_EXPORT_TIMING_ENTRIES;
                    cur.pos = 0;
                    self.timing.snapshot_header(dst)
                }
                SR_EXPORT_TIMING_ENTRIES => {
                    let n = self.timing.snapshot_entry(cur.pos as usize, dst);
                    cur.pos += 1;
                    n
                }
                _ => 0,
            }
        }
    }

    /// Whole-image restore (host convenience over the streamed install).
    /// Fails closed: a rejected image leaves the registry EMPTY, as the
    /// streamed install does — the module holds applies until a
    /// snapshot installs. Returns true on success.
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

    /// Streamed install, step 1: clear the registry and start an install.
    /// Logical time survives the clear: it is monotone in log order, and
    /// the timing header check keeps the regression guard against the
    /// state being replaced.
    pub fn install_begin(&mut self) -> SrInstaller {
        self.clear();
        SrInstaller::new()
    }

    /// Streamed install, step 2: feed bytes. Consumes whole units as they
    /// complete (carrying a partial unit across calls) and returns how
    /// many bytes were taken; `Err` fails the install closed (the
    /// registry stays cleared). Bytes past the image's end are left
    /// unconsumed.
    pub fn install_feed(
        &mut self,
        ins: &mut SrInstaller,
        bytes: &[u8],
    ) -> Result<usize, InstallRejected> {
        if ins.failed {
            return Err(InstallRejected);
        }
        let mut taken = 0;
        while ins.stage != SR_EXPORT_DONE && taken < bytes.len() {
            let want = ins.unit_len();
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

    fn install_unit(&mut self, ins: &mut SrInstaller) -> bool {
        let unit = ins.carry;
        match ins.stage {
            SR_EXPORT_HEADER => {
                let src = &unit[..SR_SNAP_HDR_LEN];
                if u16::from_le_bytes([src[0], src[1]]) != Self::SNAPSHOT_VERSION {
                    return false;
                }
                if SessionSlot::u32_at(src, 4) != N as u32
                    || SessionSlot::u32_at(src, 8) != D as u32
                {
                    return false;
                }
                let admitted = SessionSlot::u32_at(src, 12);
                let count = SessionSlot::u32_at(src, 16);
                if admitted != self.admitted || count > admitted {
                    return false;
                }
                ins.expected = count;
                self.recovery_epoch = SessionSlot::u32_at(src, 20);
                self.applied = SessionSlot::u64_at(src, 24);
                self.deadlines_fired = SessionSlot::u32_at(src, 32);
                self.deadline_noop = SessionSlot::u32_at(src, 36);
                self.next_grant_id = SessionSlot::u64_at(src, 40);
                ins.stage = if count == 0 {
                    SR_EXPORT_TIMING_HDR
                } else {
                    SR_EXPORT_RECORDS
                };
                true
            }
            SR_EXPORT_RECORDS => {
                let slot = SessionSlot::u32_at(&unit, 0) as usize;
                let Some(rec) = SessionSlot::decode(&unit[4..4 + SR_SLOT_SNAP_LEN]) else {
                    return false;
                };
                if slot >= N || !rec.used || self.occupied.is_used(slot) {
                    return false;
                }
                if self.find(&rec.session_id).is_some()
                    || !self.index.insert(&rec.session_id, slot as u32)
                {
                    return false;
                }
                self.occupied.mark(slot);
                self.slots[slot] = rec;
                self.live += 1;
                ins.seen += 1;
                if ins.seen == ins.expected {
                    ins.stage = SR_EXPORT_TIMING_HDR;
                }
                true
            }
            SR_EXPORT_TIMING_HDR => {
                let Some(live) = self.timing.restore_header(&unit) else {
                    return false;
                };
                ins.timing_expected = live;
                ins.timing_seen = 0;
                ins.stage = if live == 0 {
                    SR_EXPORT_DONE
                } else {
                    SR_EXPORT_TIMING_ENTRIES
                };
                true
            }
            SR_EXPORT_TIMING_ENTRIES => {
                let Some(d) = self.timing.restore_entry(&unit) else {
                    return false;
                };
                // A deadline without its consumer object, or two for one
                // object, is an invalid image (made impossible by
                // construction on the export side).
                let Some(i) = self.find(&d.id) else {
                    return false;
                };
                let slot = &mut self.slots[i];
                let (bit, ok) = match d.owner {
                    SR_OWNER_KEY_TTL => (1u8, slot.key_len > 0 && slot.key_gen == d.generation),
                    SR_OWNER_GRANT_TTL => (2u8, slot.grant_live && slot.grant_gen == d.generation),
                    _ => (0, false),
                };
                if !ok || slot.restore_marks & bit != 0 {
                    return false;
                }
                slot.restore_marks |= bit;
                ins.timing_seen += 1;
                if ins.timing_seen == ins.timing_expected {
                    ins.stage = SR_EXPORT_DONE;
                }
                true
            }
            _ => false,
        }
    }

    /// Streamed install, step 3: the image must have ended exactly where
    /// its counts said. Clears the transient marks. On failure the
    /// registry is left cleared.
    pub fn install_finish(&mut self, ins: &mut SrInstaller) -> bool {
        let complete = !ins.failed && ins.stage == SR_EXPORT_DONE && ins.carry_len == 0;
        if !complete {
            ins.failed = true;
            self.clear();
            return false;
        }
        let mut at = 0;
        while let Some(i) = self.occupied.next_used(at) {
            self.slots[i].restore_marks = 0;
            at = i + 1;
        }
        true
    }
}

/// Per-slot snapshot record length (see `SessionSlot::encode`).
pub const SR_SLOT_SNAP_LEN: usize = 300;
/// A streamed record: `[slot:u32]` plus the slot record.
pub const SR_SNAP_RECORD_LEN: usize = 4 + SR_SLOT_SNAP_LEN;
/// The registry header of a streamed snapshot.
pub const SR_SNAP_HDR_LEN: usize = 48;
/// Largest unit the exporter writes / the installer carries.
pub const SR_SNAP_MAX_UNIT: usize = SR_SNAP_RECORD_LEN;

pub const SR_EXPORT_HEADER: u8 = 0;
pub const SR_EXPORT_RECORDS: u8 = 1;
pub const SR_EXPORT_TIMING_HDR: u8 = 2;
pub const SR_EXPORT_TIMING_ENTRIES: u8 = 3;
pub const SR_EXPORT_DONE: u8 = 4;

/// A streamed install rejected the image; the registry is left cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallRejected;

/// Position of a streamed export.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SrExportCursor {
    pub stage: u8,
    pub pos: u32,
}

impl Default for SrExportCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl SrExportCursor {
    pub const fn new() -> Self {
        SrExportCursor {
            stage: SR_EXPORT_HEADER,
            pos: 0,
        }
    }

    pub fn done(&self) -> bool {
        self.stage == SR_EXPORT_DONE
    }
}

/// State of a streamed install.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SrInstaller {
    pub stage: u8,
    pub failed: bool,
    pub carry_len: u16,
    pub expected: u32,
    pub seen: u32,
    pub timing_expected: u32,
    pub timing_seen: u32,
    pub carry: [u8; SR_SNAP_MAX_UNIT],
}

impl Default for SrInstaller {
    fn default() -> Self {
        Self::new()
    }
}

impl SrInstaller {
    pub const fn new() -> Self {
        SrInstaller {
            stage: SR_EXPORT_HEADER,
            failed: false,
            carry_len: 0,
            expected: 0,
            seen: 0,
            timing_expected: 0,
            timing_seen: 0,
            carry: [0; SR_SNAP_MAX_UNIT],
        }
    }

    pub fn done(&self) -> bool {
        self.stage == SR_EXPORT_DONE && !self.failed
    }

    /// Bytes the next unit occupies, by stage.
    fn unit_len(&self) -> usize {
        Self::stage_len(self.stage)
    }

    /// Bytes one unit of `stage` occupies.
    pub fn stage_len(stage: u8) -> usize {
        match stage {
            SR_EXPORT_HEADER => SR_SNAP_HDR_LEN,
            SR_EXPORT_RECORDS => SR_SNAP_RECORD_LEN,
            SR_EXPORT_TIMING_HDR => TM_SNAPSHOT_HDR_LEN,
            SR_EXPORT_TIMING_ENTRIES => TM_SNAPSHOT_ENTRY_LEN,
            _ => 0,
        }
    }
}
