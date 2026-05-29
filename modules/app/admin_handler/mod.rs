//! Admin Handler — Idempotency-keyed admin workflows.
//!
//! Authorised admin commands arrive from `rbac` on `requests`, with the
//! convention `[conn_id:u8][op_code:u8][op_body...]` (per RFC §4.5).
//! Each command is hashed for idempotency.
//!
//! Supported ops are forwarded as a tagged admin envelope
//! `[command_id:u32][op_code:u8][op_body...]` to `raft_engine.admin_proposals`,
//! which applies the op locally and acks via `MSG_ADMIN_APPLIED`. The
//! handler then emits `MSG_ADMIN_RESPONSE([conn_id, status])` back to
//! `client_surface` (§4.5).
//!
//! Supported ops (local-only, no Raft replication):
//!   FREEZE, THAW, TRANSFER_LEADER, DURABILITY_MODE, SNAPSHOT.
//!
//! Still unsupported (require joint consensus or out-of-band integration,
//! tracked in RFC §14):
//!   ADD_VOTER, REMOVE_VOTER, anything else.
//!
//! Idempotency ring is in-memory; persistence across restarts is
//! achieved by replicating admin commands through Raft (RFC §3.1) so
//! the canonical "this command has been applied" record lives in the
//! WAL. The in-memory ring still suppresses rapid retries while the
//! command is in flight; a restart that loses the ring at worst
//! double-applies an idempotent op (FREEZE→FREEZE, etc.) — which is
//! safe by construction for the supported op set.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/params.rs");

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

const IDEMP_SLOTS: usize = 32;
const CMD_RING: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct IdempEntry {
    key_hash: u32,
    timestamp_ms: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdEntry { command_id: u32, conn_id: u8 }

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,     // in[0]: authorized AdminCommand from rbac
    in_applied: i32,      // in[1]: MSG_ADMIN_APPLIED from raft_engine
    out_raft: i32,        // out[0]: admin envelopes to raft_engine.admin_proposals (local-only path)
    out_responses: i32,   // out[1]: MSG_ADMIN_RESPONSE to client_surface
    out_proposal: i32,    // out[2]: ADMIN_MARKER-prefixed MSG_CLIENT_PROPOSAL for replicable ops

    idemp_ttl_ms: u64,
    idemp: [IdempEntry; IDEMP_SLOTS],
    idemp_count: u8,
    commands_processed: u32,

    next_command_id: u32,
    cmd_ring: [CmdEntry; CMD_RING],
    cmd_head: u16,

    msg_buf: [u8; 1024],
}

fn hash_bytes(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 { core::mem::size_of::<ModuleState>() as u32 }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
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
        s.in_requests = in_chan;
        s.out_raft = out_chan;
        s.in_applied = dev_channel_port(sys, 0, 1);
        s.out_responses = dev_channel_port(sys, 1, 1);
        s.out_proposal = dev_channel_port(sys, 1, 2);
        s.idemp_ttl_ms = 3_600_000; // 1 hour
        s.next_command_id = 1;
        s.cmd_head = 0;
        for slot in s.cmd_ring.iter_mut() { *slot = CmdEntry { command_id: 0, conn_id: 0 }; }
        dev_log(sys, 3, b"[admin] init".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        drain_applied(s, sys);
        drain_requests(s, sys, now);

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_applied(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_applied < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_applied, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_applied, &mut s.msg_buf);
        if msg_type != wire::MSG_ADMIN_APPLIED || (plen as usize) < 5 { continue; }
        let command_id = u32::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
        ]);
        let status = s.msg_buf[4];
        if let Some(conn_id) = take_cmd(s, command_id) {
            emit_admin_response(s, sys, conn_id, status);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_requests(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_requests, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
        if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 { continue; }
        let pl = plen as usize;
        if pl < 2 { continue; } // need conn_id + op_code at minimum
        let conn_id = s.msg_buf[0];
        let op_code = s.msg_buf[1];
        // Receipt signal — paired with `[http_adapter] admin op=N
        // conn_id=M`, lets cluster tests assert the POST-→admin
        // path landed without depending on response framing yet.
        let mut log = [0u8; 64];
        let n = format_recv_log(&mut log, op_code, conn_id);
        dev_log(sys, 3, log.as_ptr(), n);
        // Copy command bytes for idempotency hashing + forwarding.
        let cmd_len = pl - 1;
        let mut cmd = [0u8; 1024];
        cmd[..cmd_len].copy_from_slice(&s.msg_buf[1..pl]);
        let key_hash = hash_bytes(&cmd[..cmd_len]);

        // Idempotency check
        let mut dup = false;
        for i in 0..s.idemp_count as usize {
            if s.idemp[i].key_hash == key_hash
                && now.wrapping_sub(s.idemp[i].timestamp_ms) < s.idemp_ttl_ms
            {
                dup = true;
                break;
            }
        }
        if dup {
            emit_admin_response(s, sys, conn_id, wire::ADMIN_STATUS_DUPLICATE);
            continue;
        }

        // Membership ops (ADD_VOTER / REMOVE_VOTER) are intentionally
        // returned as ADMIN_STATUS_UNSUPPORTED for now. The raft_engine
        // joint-consensus state machine is in place (it can apply
        // CONFIG_CHANGE_OP_JOINT/_NEW entries and auto-propose the
        // second half of the transition), but the quorum-tracking
        // surfaces (commit_tracker, durability_ledger) do not yet
        // enforce *union quorum* during the joint phase — both the
        // old and new majorities must accept, and right now they
        // only check the old set. Accepting membership ops without
        // that enforcement risks losing committed entries across a
        // reconfiguration. See RFC §14 for the catch-up + learner +
        // union-quorum work this is gating on. Until that lands the
        // safe answer is "no".
        let supported = matches!(
            op_code,
            wire::ADMIN_OP_FREEZE
                | wire::ADMIN_OP_THAW
                | wire::ADMIN_OP_TRANSFER_LEADER
                | wire::ADMIN_OP_DURABILITY_MODE
                | wire::ADMIN_OP_SNAPSHOT
        );
        if !supported {
            emit_admin_response(s, sys, conn_id, wire::ADMIN_STATUS_UNSUPPORTED);
            continue;
        }

        // Record idempotency
        let slot = (s.idemp_count as usize) % IDEMP_SLOTS;
        s.idemp[slot] = IdempEntry { key_hash, timestamp_ms: now };
        if (s.idemp_count as usize) < IDEMP_SLOTS { s.idemp_count += 1; }

        // Allocate a command_id and remember the conn_id so we can route
        // the eventual MSG_ADMIN_APPLIED back to the right client.
        let command_id = s.next_command_id;
        s.next_command_id = s.next_command_id.wrapping_add(1);
        if s.next_command_id == 0 { s.next_command_id = 1; }
        put_cmd(s, command_id, conn_id);

        // Two paths (RFC §3.1):
        //   FREEZE / THAW / DURABILITY_MODE — replicate through Raft so
        //     every replica's state stays consistent. Send as a
        //     MSG_CLIENT_PROPOSAL with body
        //     `[ADMIN_MARKER:u8][command_id:u32 LE][op_code:u8][op_body]`.
        //   TRANSFER_LEADER / SNAPSHOT — keep the local-only path; both
        //     have per-leader semantics and don't benefit from
        //     replication.
        let replicable = matches!(
            op_code,
            wire::ADMIN_OP_FREEZE
            | wire::ADMIN_OP_THAW
            | wire::ADMIN_OP_DURABILITY_MODE
        );

        if replicable && s.out_proposal >= 0 {
            let mut env = [0u8; 1024];
            env[0] = wire::ADMIN_MARKER;
            env[1..5].copy_from_slice(&command_id.to_le_bytes());
            env[5..5 + cmd_len].copy_from_slice(&cmd[..cmd_len]);
            let total = 5 + cmd_len;
            let poll_out = (sys.channel_poll)(s.out_proposal, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(
                    sys, s.out_proposal, wire::MSG_CLIENT_PROPOSAL, &env[..total],
                );
            }
        } else {
            // Local-only: legacy envelope to raft_engine.admin_proposals.
            // `[command_id:u32 LE][op_code][op_body...]`.
            let mut env = [0u8; 1024];
            env[0..4].copy_from_slice(&command_id.to_le_bytes());
            env[4..4 + cmd_len].copy_from_slice(&cmd[..cmd_len]);
            let total = 4 + cmd_len;
            let poll_out = (sys.channel_poll)(s.out_raft, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(sys, s.out_raft, wire::MSG_ADMIN_COMMAND, &env[..total]);
            }
        }
        s.commands_processed += 1;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_admin_response(s: &mut ModuleState, sys: &SyscallTable, conn_id: u8, status: u8) {
    if s.out_responses < 0 { return; }
    let poll_out = (sys.channel_poll)(s.out_responses, 0x02);
    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
        let resp = [conn_id, status];
        wire_channels::channel_write_msg(sys, s.out_responses, wire::MSG_ADMIN_RESPONSE, &resp);
    }
}

fn put_cmd(s: &mut ModuleState, command_id: u32, conn_id: u8) {
    let slot = (s.cmd_head as usize) % CMD_RING;
    s.cmd_ring[slot] = CmdEntry { command_id, conn_id };
    s.cmd_head = s.cmd_head.wrapping_add(1);
}

fn take_cmd(s: &mut ModuleState, command_id: u32) -> Option<u8> {
    for slot in s.cmd_ring.iter_mut() {
        if slot.command_id == command_id {
            let c = slot.conn_id;
            slot.command_id = 0;
            return Some(c);
        }
    }
    None
}

fn format_recv_log(dst: &mut [u8], op_code: u8, conn_id: u8) -> usize {
    let mut pos = 0usize;
    let head = b"[admin] op=";
    let n = head.len().min(dst.len() - pos);
    dst[pos..pos + n].copy_from_slice(&head[..n]);
    pos += n;
    pos += push_usize(&mut dst[pos..], op_code as usize);
    let mid = b" conn_id=";
    let n = mid.len().min(dst.len() - pos);
    dst[pos..pos + n].copy_from_slice(&mid[..n]);
    pos += n;
    pos += push_usize(&mut dst[pos..], conn_id as usize);
    pos
}

fn push_usize(dst: &mut [u8], mut n: usize) -> usize {
    if n == 0 && !dst.is_empty() {
        dst[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + ((n % 10) as u8);
        n /= 10;
    }
    let take = (tmp.len() - i).min(dst.len());
    dst[..take].copy_from_slice(&tmp[i..i + take]);
    take
}
