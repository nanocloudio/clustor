//! codec — request/response framer and conn_id correlation hub.
//!
//! Inbound: raw client requests delivered by the
//! [`surface`](super::surface) component with a per-message
//! `[conn_id:u8]` prefix (RFC §4.5 / §5.8). Read requests
//! (`MSG_CLIENT_READ_REQUEST`) go tagged to `consensus.read`
//! when the `reads` port is wired, else answer
//! `CLIENT_REJECT_READ_UNSUPPORTED`. Write proposals are stamped with
//! a non-zero `correlation_id` and handed to the
//! [`throttle`](super::throttle) component, which preserves the
//! correlation id through to `consensus.proposals_tagged`.
//!
//! Outbound: every response is returned through the surface with a
//! `[conn_id:u8]` prefix. The correlation tables here turn an
//! internal index/correlation_id back into the conn_id the surface
//! needs to route the response.
//!
//! Correlation-id namespace: dense from 1, bit 63 clear. The
//! operations module's HTTP write bridge owns the bit-63-set half —
//! both feed the same raft proposal stream.
//!
//! Tables (no_std, bounded):
//!   - `corr_ring[corr_id]` → conn_id, set when a proposal is
//!     emitted. Looked up on throttle rejection.
//!   - `idx_ring[(partition, wal_index)]` → conn_id, populated when
//!     `MSG_PROPOSAL_ASSIGNED` arrives from consensus. Looked up on
//!     `MSG_CLIENT_RESPONSE` from consensus.
//!
//! Both rings absorb the typical inflight window between proposal
//! submission and commit. Overflow evicts the oldest entry; the
//! corresponding response is then dropped and counted — fail-open,
//! never misroute.

use super::abi::SyscallTable;
use super::{types, wire, wire_channels};

const CORR_RING: usize = 64;
const IDX_RING: usize = 64;

const LEADER_UNKNOWN: u8 = 0xFF;

/// One resolved outbound wire response. The codec never talks to the
/// surface directly — it returns one of these and the dispatch table
/// hands it to `surface::send_response` (message-shaped seam,
/// standards fluxor-modules.md §8). `buf[0]` carries the conn_id
/// prefix that `send_response` strips into the routing tag.
#[repr(C)]
pub struct Outbound {
    pub msg_type: u8,
    pub len: u8,
    pub buf: [u8; 64],
}

/// One pull off an inbound port: empty, a consumed-but-unroutable
/// frame (counts against the step bound), or a frame to route.
pub enum Pulled {
    Empty,
    Skipped,
    Frame(u8, usize),
}

/// Terminal route for one client request, resolved by [`on_request`].
pub enum Route {
    /// Fully handled inside the codec (read submitted, dropped, …).
    Done,
    /// A wire response (reject) to return through the surface.
    Respond(Outbound),
    /// A tagged proposal for the throttle; `.0` bytes were written to
    /// the caller's proposal buffer.
    Propose(usize),
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CorrEntry {
    corr_id: u64,
    conn_id: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IdxEntry {
    partition_id: u16,
    wal_index: u64,
    conn_id: u8,
}

#[repr(C)]
pub struct Codec {
    pub in_applied: i32,           // in: MSG_CLIENT_RESPONSE / READ_RESPONSE from consensus
    pub in_placement: i32,         // in: PlacementUpdate
    pub in_proposal_assigned: i32, // in: consensus.proposal_assigned
    pub in_leader_state: i32,      // in: consensus.leader_state (MSG_LEADER_HINT)
    pub in_client_requests: i32,   // in: pre-demuxed `[conn_id][body]` client traffic
    pub out_reads: i32,            // out: tagged read submissions to consensus.read

    // Config / params
    pub self_id: u8,
    pub min_epoch: u32,

    // State
    placement_epoch: types::Epoch,
    leader_id: u8, // 0xFF = unknown
    requests_parsed: u32,
    responses_sent: u32,
    reads_rejected: u32,
    not_leader_rejected: u32,
    stale_epoch_rejected: u32,
    corr_misses: u32,
    idx_misses: u32,

    next_corr_id: u64,
    corr_ring: [CorrEntry; CORR_RING],
    corr_head: u16,
    idx_ring: [IdxEntry; IDX_RING],
    idx_head: u16,

    // Scratch
    msg_buf: [u8; 2048],
}

pub unsafe fn init(c: &mut Codec) {
    c.in_applied = -1;
    c.in_placement = -1;
    c.in_proposal_assigned = -1;
    c.in_leader_state = -1;
    c.in_client_requests = -1;
    c.out_reads = -1;
    c.self_id = 0;
    c.min_epoch = 0;
    c.placement_epoch = 0;
    c.leader_id = LEADER_UNKNOWN;
    c.requests_parsed = 0;
    c.responses_sent = 0;
    c.reads_rejected = 0;
    c.not_leader_rejected = 0;
    c.stale_epoch_rejected = 0;
    c.corr_misses = 0;
    c.idx_misses = 0;
    c.next_corr_id = 1; // correlation_id MUST be non-zero
    c.corr_head = 0;
    c.idx_head = 0;
    for slot in c.corr_ring.iter_mut() {
        *slot = CorrEntry { corr_id: 0, conn_id: 0 };
    }
    for slot in c.idx_ring.iter_mut() {
        *slot = IdxEntry { partition_id: 0, wal_index: 0, conn_id: 0 };
    }
}

pub fn work_count(c: &Codec) -> u32 {
    c.requests_parsed.wrapping_add(c.responses_sent)
}

/// Per-step bound: placement/leader drains latest-wins (≤8 each),
/// ≤16 proposal assignments. Apply responses are drained by the
/// dispatch table through [`next_applied`] (≤8/step); request parsing
/// is driven by the dispatch table's request loops (≤8/step each)
/// through [`on_request`].
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(c: &mut Codec, sys: &SyscallTable) {
    drain_placement(c, sys);
    drain_leader_state(c, sys);
    drain_proposal_assigned(c, sys);
}

/// Count one response actually written by the surface on this
/// codec's behalf — the dispatch table reports the send outcome back
/// so `work_count` keeps its meaning.
pub fn note_response_sent(c: &mut Codec) {
    c.responses_sent += 1;
}

unsafe fn drain_placement(c: &mut Codec, sys: &SyscallTable) {
    if c.in_placement < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(c.in_placement, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, c.in_placement, &mut c.msg_buf);
        if msg_type == wire::MSG_PLACEMENT_UPDATE && plen >= 4 {
            c.placement_epoch = u32::from_le_bytes([
                c.msg_buf[0], c.msg_buf[1], c.msg_buf[2], c.msg_buf[3],
            ]);
        }
    }
}

unsafe fn drain_leader_state(c: &mut Codec, sys: &SyscallTable) {
    if c.in_leader_state < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(c.in_leader_state, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, c.in_leader_state, &mut c.msg_buf);
        if msg_type != wire::MSG_LEADER_HINT || (plen as usize) < 1 {
            continue;
        }
        c.leader_id = c.msg_buf[0];
    }
}

unsafe fn drain_proposal_assigned(c: &mut Codec, sys: &SyscallTable) {
    if c.in_proposal_assigned < 0 {
        return;
    }
    for _ in 0..16 {
        let poll = (sys.channel_poll)(c.in_proposal_assigned, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, c.in_proposal_assigned, &mut c.msg_buf);
        if msg_type != wire::MSG_PROPOSAL_ASSIGNED || (plen as usize) < wire::PROPOSAL_ASSIGNED_LEN {
            continue;
        }
        let (corr_id, partition_id, wal_index) = wire::decode_proposal_assigned(&c.msg_buf);
        // Look up the conn_id we recorded when emitting this proposal.
        if let Some(conn_id) = take_corr(c, corr_id) {
            put_idx(c, partition_id, wal_index, conn_id);
        } else {
            c.corr_misses += 1;
        }
    }
}

/// Read one frame off the module's `client_requests` port into
/// `out`. Each frame is a raw `[conn_id:u8][body]` record under
/// `MSG_CLIENT_PROPOSAL` or `MSG_CLIENT_READ_REQUEST` — exactly the
/// shape [`on_request`] takes, from a producer that already owns its
/// connection namespace and has demuxed the request itself. The
/// surface's `requests` port carries peer_router's `MSG_CLIENT_FRAME`
/// envelope instead and is routed by message type there; this path
/// skips the surface entirely and enters the correlation hub
/// directly. Responses return through the same rings and leave on
/// `responses`.
///
/// Consumes at most ONE frame per call so the dispatch table's loop
/// bound counts every read, malformed frames included. Unknown types are treated as
/// proposals — the body is opaque to the substrate, exactly as the
/// surface's default arm does. The dispatch table drives the ≤8/step
/// loop and routes each frame through [`on_request`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Codec` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_client_request(
    c: &mut Codec,
    sys: &SyscallTable,
    out: &mut [u8; 2048],
) -> Pulled {
    if c.in_client_requests < 0 {
        return Pulled::Empty;
    }
    let poll = (sys.channel_poll)(c.in_client_requests, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return Pulled::Empty;
    }
    let (msg_type, plen) =
        wire_channels::channel_read_msg(sys, c.in_client_requests, &mut c.msg_buf);
    let pl = plen as usize;
    if pl == 0 || pl > 2048 {
        return Pulled::Skipped; // need at least the conn_id byte
    }
    out[..pl].copy_from_slice(&c.msg_buf[..pl]);
    let routed_type = match msg_type {
        wire::MSG_CLIENT_PROPOSAL | wire::MSG_CLIENT_READ_REQUEST => msg_type,
        _ => wire::MSG_CLIENT_PROPOSAL,
    };
    Pulled::Frame(routed_type, pl)
}

/// Handle one raw client request `[conn_id:u8][body]` delivered by
/// the dispatch table. Reads are submitted on the codec's own
/// `reads` port; write proposals are tagged into `proposal_out` and
/// returned as [`Route::Propose`] for the dispatch table to hand to
/// the throttle; rejects come back as [`Route::Respond`] for the
/// surface. The codec never touches a sibling component.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Codec` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_request(
    c: &mut Codec,
    sys: &SyscallTable,
    msg_type: u8,
    payload: &[u8],
    proposal_out: &mut [u8; 2048],
) -> Route {
    if payload.is_empty() {
        return Route::Done;
    }
    let conn_id = payload[0];
    let body = &payload[1..];
    let body_len = body.len();

    match msg_type {
        wire::MSG_CLIENT_READ_REQUEST => {
            // Reads bypass throttle and Raft; they go straight to
            // `consensus.read`, where a queue holds them until
            // the ReadIndex linearization point is reached. Reads
            // share the write correlation ring because they flow back
            // as MSG_CLIENT_READ_RESPONSE and look up the same way.
            if c.out_reads < 0 {
                // No read path wired in this graph — keep the
                // explicit READ_UNSUPPORTED behaviour so callers see
                // a structured reject.
                c.reads_rejected += 1;
                return Route::Respond(build_reject_wire(
                    conn_id, wire::CLIENT_REJECT_READ_UNSUPPORTED, 0, 0, 0, 0,
                ));
            }
            if c.leader_id != LEADER_UNKNOWN && c.leader_id != c.self_id {
                // Reads also need a leader (ReadIndex protocol). On a
                // follower, redirect.
                c.not_leader_rejected += 1;
                return Route::Respond(build_reject_wire(
                    conn_id, wire::CLIENT_REJECT_NOT_LEADER, 0, 0, 0, c.leader_id,
                ));
            }
            let corr_id = next_corr_id(c);
            put_corr(c, corr_id, conn_id);
            let total = wire::TAGGED_PROPOSAL_HDR + body_len;
            if total > 2048 {
                return Route::Done;
            }
            let mut framed = [0u8; 2048];
            framed[0..8].copy_from_slice(&corr_id.to_le_bytes());
            framed[8..total].copy_from_slice(&body[..body_len]);
            let poll_out = (sys.channel_poll)(c.out_reads, 0x02);
            if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
                return Route::Done;
            }
            wire_channels::channel_write_msg(sys, c.out_reads, wire::MSG_CLIENT_READ_REQUEST, &framed[..total]);
            c.requests_parsed += 1;
            Route::Done
        }
        // Default: treat as a write proposal.
        _ => {
            // Epoch validation: if the local node has seen a newer
            // placement epoch than the request implies, reject.
            if c.min_epoch != 0 && (c.placement_epoch as u32) < c.min_epoch {
                c.stale_epoch_rejected += 1;
                return Route::Respond(build_reject_wire(
                    conn_id, wire::CLIENT_REJECT_STALE_EPOCH, 0, 0, 0, 0,
                ));
            }
            // Leader-redirect: if we know who the leader is and it
            // isn't us, surface NOT_LEADER with the believed leader_id
            // in the reject envelope.
            if c.leader_id != LEADER_UNKNOWN && c.leader_id != c.self_id {
                c.not_leader_rejected += 1;
                return Route::Respond(build_reject_wire(
                    conn_id, wire::CLIENT_REJECT_NOT_LEADER, 0, 0, 0, c.leader_id,
                ));
            }

            let corr_id = next_corr_id(c);
            put_corr(c, corr_id, conn_id);

            // Tagged proposal `[correlation_id:u64][body]` so the
            // leader can echo MSG_PROPOSAL_ASSIGNED back on
            // consensus.proposal_assigned. Body itself is opaque.
            let total = wire::TAGGED_PROPOSAL_HDR + body_len;
            if total > 2048 {
                return Route::Done;
            }
            proposal_out[0..8].copy_from_slice(&corr_id.to_le_bytes());
            proposal_out[8..total].copy_from_slice(&body[..body_len]);
            c.requests_parsed += 1;
            Route::Propose(total)
        }
    }
}

/// Handle a throttle rejection `[correlation_id][...]` — resolve the
/// conn_id and return the wire-facing reject for the dispatch table
/// to send through the surface. `None` on a correlation miss (the
/// response is dropped and counted — fail-open, never misroute).
pub fn on_reject_internal(c: &mut Codec, env: &[u8]) -> Option<Outbound> {
    let (corr_id, status, retry, entry, byte) = wire::decode_client_reject_internal(env)?;
    let conn_id = match take_corr(c, corr_id) {
        Some(v) => v,
        None => {
            c.corr_misses += 1;
            return None;
        }
    };
    // Throttle rejects don't carry leader_id; the reserved byte is 0
    // for non-NotLeader rejects.
    Some(build_reject_wire(conn_id, status, retry, entry, byte, 0))
}

/// Drain ONE apply-pipeline response off the `applied` port and
/// resolve it to an outbound wire response. `Pulled::Skipped` marks a
/// consumed frame with no route (correlation miss / unknown shape) so
/// the dispatch table's ≤8/step loop counts it. The returned frame's
/// message type and `[conn_id]`-prefixed payload ride in the
/// [`Outbound`]; the dispatch table sends it through the surface.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Codec` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_applied(c: &mut Codec, sys: &SyscallTable) -> Option<Outbound> {
    if c.in_applied < 0 {
        return None;
    }
    let poll = (sys.channel_poll)(c.in_applied, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return None;
    }

    let (msg_type, plen) = wire_channels::channel_read_msg(sys, c.in_applied, &mut c.msg_buf);
    if plen == 0 {
        return None;
    }
    let pl = plen as usize;

    match msg_type {
        wire::MSG_CLIENT_RESPONSE if pl >= 16 => {
            // Internal v2 from consensus:
            // `[partition_id:u16][term:u64][index:u64]`.
            // Legacy v1 is still accepted as `[term:u64][index:u64]`
            // and implies partition 0.
            let (partition_id, term_off) = if pl >= 18 {
                (u16::from_le_bytes([c.msg_buf[0], c.msg_buf[1]]), 2usize)
            } else {
                (0u16, 0usize)
            };
            let mut body = [0u8; 16];
            body.copy_from_slice(&c.msg_buf[term_off..term_off + 16]);
            let index = u64::from_le_bytes([
                body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
            ]);
            let conn_id = match take_idx(c, partition_id, index) {
                Some(v) => v,
                None => {
                    c.idx_misses += 1;
                    return next_applied_skip();
                }
            };
            let mut out = Outbound { msg_type: wire::MSG_CLIENT_RESPONSE, len: 17, buf: [0u8; 64] };
            out.buf[0] = conn_id;
            out.buf[1..17].copy_from_slice(&body);
            Some(out)
        }
        wire::MSG_CLIENT_READ_RESPONSE if pl >= 8 => {
            // `[correlation_id:u64][required_commit:u64]` from
            // consensus. Only the correlation id matters here —
            // reads correlate through the same ring as writes; the
            // codec stamps the id at submission time. The commit
            // index is for consumers wired directly to `applied`
            // that fence their own state machine; the wire client
            // keeps the empty-body contract below.
            let corr_id = u64::from_le_bytes([
                c.msg_buf[0], c.msg_buf[1], c.msg_buf[2], c.msg_buf[3],
                c.msg_buf[4], c.msg_buf[5], c.msg_buf[6], c.msg_buf[7],
            ]);
            let conn_id = match take_corr(c, corr_id) {
                Some(v) => v,
                None => {
                    c.corr_misses += 1;
                    return next_applied_skip();
                }
            };
            // Empty-body read response — the substrate guarantees
            // the linearization point has been reached; the
            // state-machine query is the application's job.
            let mut out =
                Outbound { msg_type: wire::MSG_CLIENT_READ_RESPONSE, len: 1, buf: [0u8; 64] };
            out.buf[0] = conn_id;
            Some(out)
        }
        _ => {
            // Unknown response shape — drop.
            next_applied_skip()
        }
    }
}

/// A consumed-but-unroutable applied frame: burn the loop slot with a
/// zero-length sentinel the dispatch table skips without sending.
fn next_applied_skip() -> Option<Outbound> {
    Some(Outbound { msg_type: 0, len: 0, buf: [0u8; 64] })
}

fn build_reject_wire(
    conn_id: u8,
    status: u8,
    retry_after_ms: u16,
    entry_credits: i16,
    byte_credits: i32,
    reserved: u8,
) -> Outbound {
    let mut env = [0u8; wire::CLIENT_REJECT_WIRE_LEN];
    wire::encode_client_reject_wire(
        &mut env,
        conn_id,
        status,
        reserved,
        retry_after_ms,
        entry_credits,
        byte_credits,
    );
    let mut out =
        Outbound { msg_type: wire::MSG_CLIENT_REJECT, len: wire::CLIENT_REJECT_WIRE_LEN as u8, buf: [0u8; 64] };
    out.buf[..wire::CLIENT_REJECT_WIRE_LEN].copy_from_slice(&env);
    out
}

/// Wire reject for a record whose payload exceeds the proposal cap.
/// No correlation state is involved — the record was never admitted.
pub fn reject_too_large(conn_id: u8) -> Outbound {
    build_reject_wire(conn_id, wire::CLIENT_REJECT_TOO_LARGE, 0, 0, 0, 0)
}

fn next_corr_id(c: &mut Codec) -> u64 {
    let id = c.next_corr_id;
    // correlation_id MUST be non-zero (per wire.rs convention).
    c.next_corr_id = c.next_corr_id.wrapping_add(1);
    if c.next_corr_id == 0 {
        c.next_corr_id = 1;
    }
    id
}

fn put_corr(c: &mut Codec, corr_id: u64, conn_id: u8) {
    let slot = (c.corr_head as usize) % CORR_RING;
    c.corr_ring[slot] = CorrEntry { corr_id, conn_id };
    c.corr_head = c.corr_head.wrapping_add(1);
}

fn take_corr(c: &mut Codec, corr_id: u64) -> Option<u8> {
    for slot in c.corr_ring.iter_mut() {
        if slot.corr_id == corr_id {
            let v = slot.conn_id;
            slot.corr_id = 0; // mark consumed
            return Some(v);
        }
    }
    None
}

fn put_idx(c: &mut Codec, partition_id: u16, wal_index: u64, conn_id: u8) {
    let slot = (c.idx_head as usize) % IDX_RING;
    c.idx_ring[slot] = IdxEntry { partition_id, wal_index, conn_id };
    c.idx_head = c.idx_head.wrapping_add(1);
}

fn take_idx(c: &mut Codec, partition_id: u16, wal_index: u64) -> Option<u8> {
    for slot in c.idx_ring.iter_mut() {
        if slot.wal_index == wal_index && slot.partition_id == partition_id && slot.wal_index != 0 {
            let v = slot.conn_id;
            slot.wal_index = 0;
            return Some(v);
        }
    }
    None
}
