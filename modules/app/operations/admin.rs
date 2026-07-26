//! admin — idempotency-keyed admin workflows.
//!
//! Authorized admin commands arrive from the [`rbac`](super::rbac)
//! component (or pre-authorized on the module's `admin_requests`
//! port), with the convention `[conn_id:u8][op_code:u8][op_body...]`
//! (RFC §4.5). Each command is hashed for idempotency.
//!
//! Supported ops are forwarded as a tagged admin envelope
//! `[command_id:u32][op_code:u8][op_body...]` to
//! `consensus.admin_proposals`, which applies the op locally and
//! acks via `MSG_ADMIN_APPLIED`. The component then emits
//! `MSG_ADMIN_RESPONSE([conn_id, status])` on the module's
//! `responses` port (§4.5).
//!
//! Supported ops (local-only, no Raft replication):
//!   FREEZE, THAW, TRANSFER_LEADER, DURABILITY_MODE, SNAPSHOT.
//!
//! Still unsupported (require joint consensus or out-of-band
//! integration, tracked in RFC §14): ADD_VOTER, REMOVE_VOTER,
//! anything else.
//!
//! Idempotency is in-memory and deliberately narrow: it collapses only
//! a *rapid retransmit* — a command identical to the one immediately
//! preceding it within a short in-flight window (`idemp_ttl_ms`). Two
//! genuinely distinct operations (and any alternating sequence such as
//! FREEZE/THAW/FREEZE) each get their own Raft entry. Cross-command and
//! cross-restart idempotency is not this component's job: the canonical
//! "this command has been applied" record lives in the WAL via Raft
//! replication (RFC §3.1), and the supported op set is double-apply-safe
//! by construction (FREEZE→FREEZE, etc.), so a lost in-memory predecessor
//! at worst re-applies an idempotent op.

use super::abi::SyscallTable;
use super::{wire, wire_channels};
use super::{dev_log, dev_report_step_effect, step_effect};

const CMD_RING: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdEntry {
    command_id: u32,
    conn_id: u8,
}

#[repr(C)]
pub struct Admin {
    pub in_applied: i32,   // in: MSG_ADMIN_APPLIED from consensus
    pub in_requests: i32,  // in: pre-authorized AdminCommand (direct inject)
    pub out_raft: i32,     // out: admin envelopes to consensus.admin_proposals (local-only path)
    pub out_responses: i32, // out: MSG_ADMIN_RESPONSE
    pub out_proposal: i32, // out: ADMIN_MARKER-prefixed MSG_CLIENT_PROPOSAL for replicable ops

    // Idempotency collapses only a *rapid retransmit* — a command
    // identical to the one immediately preceding it within the in-flight
    // window. `last_cmd_hash == 0` means "no prior command". A distinct
    // or alternating op is always a fresh command. See the component header.
    idemp_ttl_ms: u64,
    last_cmd_hash: u32,
    last_cmd_ms: u64,
    pub commands_processed: u32,

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

pub unsafe fn init(a: &mut Admin) {
    a.in_applied = -1;
    a.in_requests = -1;
    a.out_raft = -1;
    a.out_responses = -1;
    a.out_proposal = -1;
    // In-flight retransmit window: a duplicate is only collapsed if
    // it lands within this gap of an identical predecessor. Long
    // enough to swallow a client TCP retransmit, short enough that a
    // genuine later op (operator re-issuing the same command) is its
    // own entry.
    a.idemp_ttl_ms = 2_000; // 2 s
    a.last_cmd_hash = 0;
    a.last_cmd_ms = 0;
    a.commands_processed = 0;
    a.next_command_id = 1;
    a.cmd_head = 0;
    for slot in a.cmd_ring.iter_mut() {
        *slot = CmdEntry { command_id: 0, conn_id: 0 };
    }
}

/// Per-step bound: 8 apply acknowledgements + 4 direct-inject
/// commands, plus at most 4 rbac-delivered commands (bounded by
/// rbac's own request loop). Heaviest single item is an FNV-1a hash
/// over ≤1023 bytes.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(a: &mut Admin, sys: &SyscallTable, now: u64) {
    drain_applied(a, sys);
    drain_requests(a, sys, now);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_applied(a: &mut Admin, sys: &SyscallTable) {
    if a.in_applied < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(a.in_applied, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, a.in_applied, &mut a.msg_buf);
        if msg_type != wire::MSG_ADMIN_APPLIED || (plen as usize) < 5 {
            continue;
        }
        let command_id = u32::from_le_bytes([
            a.msg_buf[0], a.msg_buf[1], a.msg_buf[2], a.msg_buf[3],
        ]);
        let status = a.msg_buf[4];
        if let Some(conn_id) = take_cmd(a, command_id) {
            emit_admin_response(a, sys, conn_id, status);
        }
    }
}

/// Drain pre-authorized commands off the `admin_requests` port.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_requests(a: &mut Admin, sys: &SyscallTable, now: u64) {
    if a.in_requests < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(a.in_requests, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, a.in_requests, &mut a.msg_buf);
        if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 {
            continue;
        }
        let pl = plen as usize;
        let mut local = [0u8; 1024];
        local[..pl].copy_from_slice(&a.msg_buf[..pl]);
        on_command(a, sys, now, &local[..pl]);
    }
}

/// Process one authorized admin command envelope
/// `[conn_id:u8][op_code:u8][op_body...]`. This is the single
/// admission point regardless of how the command arrived (rbac
/// delivery or the `admin_requests` port).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_command(a: &mut Admin, sys: &SyscallTable, now: u64, payload: &[u8]) {
    let pl = payload.len();
    if pl < 2 {
        return; // need conn_id + op_code at minimum
    }
    let conn_id = payload[0];
    let op_code = payload[1];
    // Receipt signal — paired with `[http] admin op=N
    // conn_id=M`, the only external proof the POST→admin path
    // landed: admin ops reply 202 immediately (see the http
    // component) and, unlike client proposals, have no async
    // correlation-tracked reply to observe instead.
    let mut log = [0u8; 64];
    let n = format_recv_log(&mut log, op_code, conn_id);
    dev_log(sys, 3, log.as_ptr(), n);
    // Copy command bytes for idempotency hashing + forwarding.
    let cmd_len = pl - 1;
    let mut cmd = [0u8; 1024];
    cmd[..cmd_len].copy_from_slice(&payload[1..pl]);
    let key_hash = hash_bytes(&cmd[..cmd_len]);

    // Client-write bridge (RFC §8): ADMIN_OP_PROPOSE carries opaque
    // application data, not an admin op. Emit it as a RAW (unmarked)
    // MSG_CLIENT_PROPOSAL to raft and return — NO idempotency collapse
    // (distinct client writes may legitimately repeat a body), no admin
    // apply, no admin response. `cmd` is `[op_code][op_body]`, so the
    // proposal body is `cmd[1..]`.
    if op_code == wire::ADMIN_OP_PROPOSE {
        if a.out_proposal >= 0 && cmd_len > 1 {
            let poll_out = (sys.channel_poll)(a.out_proposal, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                let written = wire_channels::channel_write_msg(
                    sys,
                    a.out_proposal,
                    wire::MSG_CLIENT_PROPOSAL,
                    &cmd[1..cmd_len],
                );
                if written > 0 {
                    dev_report_step_effect(sys, step_effect::WORK_DONE);
                }
            }
        }
        return;
    }

    // Idempotency check — collapse only a rapid retransmit: a
    // command identical to its immediate predecessor within the
    // in-flight window. Alternating or otherwise-distinct ops each
    // get their own entry (the alternating freeze/thaw the
    // wal_replay test drives must produce one entry per op).
    let dup = a.last_cmd_hash == key_hash
        && key_hash != 0
        && now.wrapping_sub(a.last_cmd_ms) < a.idemp_ttl_ms;
    if dup {
        emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_DUPLICATE);
        return;
    }

    // Membership ops (ADD_VOTER / REMOVE_VOTER) are intentionally
    // returned as ADMIN_STATUS_UNSUPPORTED for now. The raft
    // joint-consensus state machine is in place (it can apply
    // CONFIG_CHANGE_OP_JOINT/_NEW entries and auto-propose the
    // second half of the transition), but the quorum-tracking
    // surfaces (the commit and ledger components) do not yet
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
        emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_UNSUPPORTED);
        return;
    }

    // Record this command as the predecessor for the next request's
    // retransmit check.
    a.last_cmd_hash = key_hash;
    a.last_cmd_ms = now;

    // Allocate a command_id and remember the conn_id so we can route
    // the eventual MSG_ADMIN_APPLIED back to the right client.
    let command_id = a.next_command_id;
    a.next_command_id = a.next_command_id.wrapping_add(1);
    if a.next_command_id == 0 {
        a.next_command_id = 1;
    }
    put_cmd(a, command_id, conn_id);

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
        wire::ADMIN_OP_FREEZE | wire::ADMIN_OP_THAW | wire::ADMIN_OP_DURABILITY_MODE
    );

    if replicable && a.out_proposal >= 0 {
        let mut env = [0u8; 1024];
        env[0] = wire::ADMIN_MARKER;
        env[1..5].copy_from_slice(&command_id.to_le_bytes());
        env[5..5 + cmd_len].copy_from_slice(&cmd[..cmd_len]);
        let total = 5 + cmd_len;
        let poll_out = (sys.channel_poll)(a.out_proposal, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            wire_channels::channel_write_msg(
                sys,
                a.out_proposal,
                wire::MSG_CLIENT_PROPOSAL,
                &env[..total],
            );
        }
    } else {
        // Local-only: direct envelope to `consensus.admin_proposals`.
        // `[command_id:u32 LE][op_code][op_body...]`.
        let mut env = [0u8; 1024];
        env[0..4].copy_from_slice(&command_id.to_le_bytes());
        env[4..4 + cmd_len].copy_from_slice(&cmd[..cmd_len]);
        let total = 4 + cmd_len;
        let poll_out = (sys.channel_poll)(a.out_raft, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            wire_channels::channel_write_msg(sys, a.out_raft, wire::MSG_ADMIN_COMMAND, &env[..total]);
        }
    }
    a.commands_processed += 1;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn emit_admin_response(a: &mut Admin, sys: &SyscallTable, conn_id: u8, status: u8) {
    if a.out_responses < 0 {
        return;
    }
    let poll_out = (sys.channel_poll)(a.out_responses, 0x02);
    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
        let resp = [conn_id, status];
        wire_channels::channel_write_msg(sys, a.out_responses, wire::MSG_ADMIN_RESPONSE, &resp);
    }
}

fn put_cmd(a: &mut Admin, command_id: u32, conn_id: u8) {
    let slot = (a.cmd_head as usize) % CMD_RING;
    a.cmd_ring[slot] = CmdEntry { command_id, conn_id };
    a.cmd_head = a.cmd_head.wrapping_add(1);
}

fn take_cmd(a: &mut Admin, command_id: u32) -> Option<u8> {
    for slot in a.cmd_ring.iter_mut() {
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

pub(crate) fn push_usize(dst: &mut [u8], mut n: usize) -> usize {
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
