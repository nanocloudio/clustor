//! Client Codec — Request/response framer and conn_id correlation hub.
//!
//! Inbound: raw client requests from `client_surface.client_req`, with
//! per-message `[conn_id:u8]` prefix supplied by client_surface
//! (RFC §4.5 / §5.8). Read requests (`MSG_CLIENT_READ_REQUEST`) are
//! rejected immediately with `CLIENT_REJECT_READ_UNSUPPORTED` until the
//! linearizable-read path lands. Write proposals are stamped with a
//! non-zero `correlation_id` and forwarded as a tagged proposal to
//! `throttle_gate.requests`, which preserves the correlation id through
//! to `raft_engine.proposals_tagged`.
//!
//! Outbound (`responses_out` → `client_surface.client_responses`): every
//! payload is `[conn_id:u8][rest...]`. The correlation tables here are
//! how we turn an internal index/correlation_id back into the conn_id
//! the client_surface needs to route the response.
//!
//! Tables (no_std, bounded):
//!   - `corr_to_conn[corr_id_slot]` → conn_id, set when a proposal is
//!     emitted. Looked up on `MSG_CLIENT_REJECT_INTERNAL` (throttle).
//!   - `idx_to_conn[idx_slot]` → (partition_id, wal_index, conn_id),
//!     populated when `MSG_PROPOSAL_ASSIGNED` arrives from raft_engine.
//!     Looked up on `MSG_CLIENT_RESPONSE` from apply_pipeline.
//!
//! Both rings are sized to absorb the typical inflight window between
//! proposal submission and commit. Overflow evicts the oldest entry;
//! the corresponding response then falls back to last-seen conn_id and
//! is dropped if no fallback exists — fail-open, never misroute.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in deps/fluxor/modules/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../../deps/fluxor/modules/sdk/params.rs");

#[path = "../../sdk/types.rs"]
mod types;

#[path = "../../sdk/wire.rs"]
mod wire;

use types::*;

const CORR_RING: usize = 64;
const IDX_RING: usize = 64;

const LEADER_UNKNOWN: u8 = 0xFF;

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    // Expected client placement epoch. When non-zero, requests whose
    // implicit epoch (currently == `placement_epoch`) is older than
    // this value will be rejected with `CLIENT_REJECT_STALE_EPOCH`.
    // Default 0 keeps the existing accept-everything behaviour for
    // configs that don't yet plumb placement.
    2, min_epoch, u32, 0
        => |s, d, len| { s.min_epoch = p_u32(d, len, 0, 0); };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CorrEntry { corr_id: u64, conn_id: u8 }

#[repr(C)]
#[derive(Clone, Copy)]
struct IdxEntry { partition_id: u16, wal_index: u64, conn_id: u8 }

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels: 5 in, 2 out
    in_raw: i32,                 // in[0]: client_surface.client_req (`[conn_id][body]`)
    in_responses: i32,           // in[1]: apply.applied + throttle.rejected
    in_placement: i32,           // in[2]: PlacementUpdate from placement_router
    in_proposal_assigned: i32,   // in[3]: raft_engine.proposal_assigned
    in_leader_state: i32,        // in[4]: raft_engine.leader_state (MSG_LEADER_HINT)
    out_parsed: i32,             // out[0]: tagged MSG_CLIENT_PROPOSAL to throttle_gate
    out_responses: i32,          // out[1]: framed responses to client_surface
    out_reads: i32,              // out[2]: tagged read submissions to apply_pipeline.read

    // Config / params
    self_id: u8,
    min_epoch: u32,

    // State
    placement_epoch: Epoch,
    leader_id: u8,               // 0xFF = unknown
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

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (deps/fluxor/modules/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }

        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        s.in_raw = in_chan;
        s.out_parsed = out_chan;
        s.in_responses = dev_channel_port(sys, 0, 1);
        s.in_placement = dev_channel_port(sys, 0, 2);
        s.in_proposal_assigned = dev_channel_port(sys, 0, 3);
        s.in_leader_state = dev_channel_port(sys, 0, 4);
        s.out_responses = dev_channel_port(sys, 1, 1);
        s.out_reads = dev_channel_port(sys, 1, 2);

        s.next_corr_id = 1; // correlation_id MUST be non-zero
        s.corr_head = 0;
        s.idx_head = 0;
        s.leader_id = LEADER_UNKNOWN;
        for slot in s.corr_ring.iter_mut() { *slot = CorrEntry { corr_id: 0, conn_id: 0 }; }
        for slot in s.idx_ring.iter_mut() {
            *slot = IdxEntry { partition_id: 0, wal_index: 0, conn_id: 0 };
        }

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        dev_log(sys, 3, b"[codec] init".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (deps/fluxor/modules/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        drain_placement(s, sys);
        drain_leader_state(s, sys);
        drain_proposal_assigned(s, sys);
        parse_requests(s, sys);
        forward_responses(s, sys);

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn drain_placement(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_placement < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_placement, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_placement, &mut s.msg_buf);
        if msg_type == wire::MSG_PLACEMENT_UPDATE && plen >= 4 {
            s.placement_epoch = u32::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            ]);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn drain_leader_state(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_leader_state < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_leader_state, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_leader_state, &mut s.msg_buf);
        if msg_type != wire::MSG_LEADER_HINT || (plen as usize) < 1 { continue; }
        s.leader_id = s.msg_buf[0];
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn drain_proposal_assigned(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_proposal_assigned < 0 { return; }
    for _ in 0..16 {
        let poll = (sys.channel_poll)(s.in_proposal_assigned, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_proposal_assigned, &mut s.msg_buf);
        if msg_type != wire::MSG_PROPOSAL_ASSIGNED || (plen as usize) < wire::PROPOSAL_ASSIGNED_LEN {
            continue;
        }
        let (corr_id, partition_id, wal_index) =
            wire::decode_proposal_assigned(&s.msg_buf);
        // Look up the conn_id we recorded when emitting this proposal.
        if let Some(conn_id) = take_corr(s, corr_id) {
            put_idx(s, partition_id, wal_index, conn_id);
        } else {
            s.corr_misses += 1;
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn parse_requests(s: &mut ModuleState, sys: &SyscallTable) {
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_raw, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_raw, &mut s.msg_buf);
        if plen == 0 { break; }
        let pl = plen as usize;
        // First byte is conn_id (client_surface invariant). Anything
        // shorter is a wiring mistake.
        if pl < 1 { continue; }
        let conn_id = s.msg_buf[0];
        // Copy body to a local scratch buffer so subsequent calls can
        // mutate state without aliasing.
        let body_len = pl - 1;
        let mut body = [0u8; 2048];
        body[..body_len].copy_from_slice(&s.msg_buf[1..pl]);

        match msg_type {
            wire::MSG_CLIENT_READ_REQUEST => {
                // Reads bypass throttle and Raft; they go straight to
                // `apply_pipeline.read`, where a queue holds them
                // until the ReadIndex linearization point is reached.
                // We share the same correlation_id ring used for writes
                // because reads also flow back through `responses` as
                // MSG_CLIENT_READ_RESPONSE and look up the same way.
                if s.out_reads < 0 {
                    // No read path wired in this graph — keep the
                    // explicit READ_UNSUPPORTED behaviour so callers
                    // see a structured reject.
                    emit_reject_wire(
                        s, sys, conn_id,
                        wire::CLIENT_REJECT_READ_UNSUPPORTED,
                        0, 0, 0, 0,
                    );
                    s.reads_rejected += 1;
                    continue;
                }
                if s.leader_id != LEADER_UNKNOWN && s.leader_id != s.self_id {
                    // Reads also need a leader (ReadIndex protocol). On
                    // a follower, redirect.
                    emit_reject_wire(
                        s, sys, conn_id,
                        wire::CLIENT_REJECT_NOT_LEADER,
                        0, 0, 0, s.leader_id,
                    );
                    s.not_leader_rejected += 1;
                    continue;
                }
                let corr_id = next_corr_id(s);
                put_corr(s, corr_id, conn_id);
                let total = wire::TAGGED_PROPOSAL_HDR + body_len;
                if total > 2048 { continue; }
                let mut framed = [0u8; 2048];
                framed[0..8].copy_from_slice(&corr_id.to_le_bytes());
                framed[8..total].copy_from_slice(&body[..body_len]);
                let poll_out = (sys.channel_poll)(s.out_reads, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }
                wire::channel_write_msg(
                    sys, s.out_reads,
                    wire::MSG_CLIENT_READ_REQUEST,
                    &framed[..total],
                );
                s.requests_parsed += 1;
            }
            // Default: treat as a write proposal.
            _ => {
                // Epoch validation: if the local node has seen a newer
                // placement epoch than the request implies, reject.
                if s.min_epoch != 0 && (s.placement_epoch as u32) < s.min_epoch {
                    emit_reject_wire(
                        s, sys, conn_id,
                        wire::CLIENT_REJECT_STALE_EPOCH,
                        0, 0, 0, 0,
                    );
                    s.stale_epoch_rejected += 1;
                    continue;
                }
                // Leader-redirect: if we know who the leader is and it
                // isn't us, surface NOT_LEADER with the believed
                // leader_id in the reject envelope.
                if s.leader_id != LEADER_UNKNOWN && s.leader_id != s.self_id {
                    emit_reject_wire(
                        s, sys, conn_id,
                        wire::CLIENT_REJECT_NOT_LEADER,
                        0, 0, 0, s.leader_id,
                    );
                    s.not_leader_rejected += 1;
                    continue;
                }

                let corr_id = next_corr_id(s);
                put_corr(s, corr_id, conn_id);

                // Emit tagged proposal `[correlation_id:u64][body]` so the
                // leader can echo MSG_PROPOSAL_ASSIGNED back on
                // raft_engine.proposal_assigned. Body itself is opaque.
                let total = wire::TAGGED_PROPOSAL_HDR + body_len;
                if total > 2048 { continue; }
                let mut framed = [0u8; 2048];
                framed[0..8].copy_from_slice(&corr_id.to_le_bytes());
                framed[8..total].copy_from_slice(&body[..body_len]);

                let poll_out = (sys.channel_poll)(s.out_parsed, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }
                wire::channel_write_msg(
                    sys, s.out_parsed,
                    wire::MSG_CLIENT_PROPOSAL,
                    &framed[..total],
                );
                s.requests_parsed += 1;
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn forward_responses(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_responses < 0 { return; }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_responses, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_responses, &mut s.msg_buf);
        if plen == 0 { continue; }
        let pl = plen as usize;

        match msg_type {
            wire::MSG_CLIENT_RESPONSE if pl >= 16 => {
                // Internal v2 from apply_pipeline:
                // `[partition_id:u16][term:u64][index:u64]`.
                // Legacy v1 is still accepted as `[term:u64][index:u64]`
                // and implies partition 0.
                let (partition_id, term_off) = if pl >= 18 { (
                    u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]),
                    2usize,
                ) } else {
                    (0u16, 0usize)
                };
                let mut body = [0u8; 16];
                body.copy_from_slice(&s.msg_buf[term_off..term_off + 16]);
                let index = u64::from_le_bytes([
                    body[8], body[9], body[10], body[11],
                    body[12], body[13], body[14], body[15],
                ]);
                let conn_id = match take_idx(s, partition_id, index) {
                    Some(c) => c,
                    None => { s.idx_misses += 1; continue; }
                };
                emit_response_wire(s, sys, conn_id, &body);
            }
            wire::MSG_CLIENT_REJECT_INTERNAL if pl >= wire::CLIENT_REJECT_INTERNAL_LEN => {
                let (corr_id, status, retry, entry, byte) =
                    match wire::decode_client_reject_internal(&s.msg_buf[..pl]) {
                        Some(t) => t,
                        None => continue,
                    };
                let conn_id = match take_corr(s, corr_id) {
                    Some(c) => c,
                    None => { s.corr_misses += 1; continue; }
                };
                // Throttle rejects don't carry leader_id; the reserved
                // byte is 0 for non-NotLeader rejects.
                emit_reject_wire(s, sys, conn_id, status, retry, entry, byte, 0);
            }
            wire::MSG_CLIENT_READ_RESPONSE if pl >= 8 => {
                // `[correlation_id:u64]` from apply_pipeline. Reads are
                // correlated through the same ring as writes — the
                // codec stamps the correlation_id at submission time.
                let corr_id = u64::from_le_bytes([
                    s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                    s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
                ]);
                let conn_id = match take_corr(s, corr_id) {
                    Some(c) => c,
                    None => { s.corr_misses += 1; continue; }
                };
                // Forward to the wire as an empty-body read response —
                // the substrate guarantees the linearization point has
                // been reached; the state-machine query is the
                // application's job. Wire payload is just `[conn_id]`.
                let body = [conn_id];
                let poll_out = (sys.channel_poll)(s.out_responses, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }
                wire::channel_write_msg(
                    sys, s.out_responses,
                    wire::MSG_CLIENT_READ_RESPONSE, &body,
                );
                s.responses_sent += 1;
            }
            _ => {
                // Unknown response shape — drop. A previous design routed
                // raw MSG_CLIENT_REJECT here; the throttle now uses
                // MSG_CLIENT_REJECT_INTERNAL exclusively.
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn emit_response_wire(s: &mut ModuleState, sys: &SyscallTable, conn_id: u8, body: &[u8]) {
    if s.out_responses < 0 { return; }
    let poll_out = (sys.channel_poll)(s.out_responses, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }
    let total = 1 + body.len();
    if total > 2048 { return; }
    let mut framed = [0u8; 2048];
    framed[0] = conn_id;
    framed[1..total].copy_from_slice(body);
    wire::channel_write_msg(
        sys, s.out_responses, wire::MSG_CLIENT_RESPONSE, &framed[..total],
    );
    s.responses_sent += 1;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn emit_reject_wire(
    s: &mut ModuleState, sys: &SyscallTable,
    conn_id: u8, status: u8, retry_after_ms: u16, entry_credits: i16, byte_credits: i32,
    reserved: u8,
) {
    if s.out_responses < 0 { return; }
    let poll_out = (sys.channel_poll)(s.out_responses, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }
    let mut env = [0u8; wire::CLIENT_REJECT_WIRE_LEN];
    wire::encode_client_reject_wire(
        &mut env, conn_id, status, reserved,
        retry_after_ms, entry_credits, byte_credits,
    );
    wire::channel_write_msg(
        sys, s.out_responses, wire::MSG_CLIENT_REJECT,
        &env[..wire::CLIENT_REJECT_WIRE_LEN],
    );
    s.responses_sent += 1;
}

fn next_corr_id(s: &mut ModuleState) -> u64 {
    let id = s.next_corr_id;
    // correlation_id MUST be non-zero (per wire.rs convention).
    s.next_corr_id = s.next_corr_id.wrapping_add(1);
    if s.next_corr_id == 0 { s.next_corr_id = 1; }
    id
}

fn put_corr(s: &mut ModuleState, corr_id: u64, conn_id: u8) {
    let slot = (s.corr_head as usize) % CORR_RING;
    s.corr_ring[slot] = CorrEntry { corr_id, conn_id };
    s.corr_head = s.corr_head.wrapping_add(1);
}

fn take_corr(s: &mut ModuleState, corr_id: u64) -> Option<u8> {
    for slot in s.corr_ring.iter_mut() {
        if slot.corr_id == corr_id {
            let c = slot.conn_id;
            slot.corr_id = 0; // mark consumed
            return Some(c);
        }
    }
    None
}

fn put_idx(s: &mut ModuleState, partition_id: u16, wal_index: u64, conn_id: u8) {
    let slot = (s.idx_head as usize) % IDX_RING;
    s.idx_ring[slot] = IdxEntry { partition_id, wal_index, conn_id };
    s.idx_head = s.idx_head.wrapping_add(1);
}

fn take_idx(s: &mut ModuleState, partition_id: u16, wal_index: u64) -> Option<u8> {
    for slot in s.idx_ring.iter_mut() {
        if slot.wal_index == wal_index
            && slot.partition_id == partition_id
            && slot.wal_index != 0
        {
            let c = slot.conn_id;
            slot.wal_index = 0;
            return Some(c);
        }
    }
    None
}
