//! admin — idempotency-keyed admin workflows.
//!
//! Authorized admin commands arrive from the [`rbac`](super::rbac) component
//! (or pre-authorized on the module's `admin_requests` port), with the
//! convention `[conn_id:u16 LE][op_code:u8][op_body...]`. Each command is
//! compared byte-for-byte against its immediate predecessor for idempotency.
//!
//! An accepted op takes one of three routes, and the choice is a
//! property of the op rather than of the caller:
//!
//! - **Replicated** — FREEZE, THAW, DURABILITY_MODE. Emitted to
//!   `consensus.proposals` as a `MSG_CLIENT_PROPOSAL` whose body is
//!   `[ADMIN_MAGIC:8][command_id:u32][op_code:u8][op_body...]`, so every
//!   replica applies the same change at the same log position.
//! - **Local** — TRANSFER_LEADER, SNAPSHOT, and the membership ops
//!   ADD_VOTER / REMOVE_VOTER / ADD_LEARNER / REMOVE_LEARNER. Sent as a
//!   tagged envelope `[command_id:u32][op_code:u8][op_body...]` to
//!   `consensus.admin_proposals`. Membership travels this way because
//!   `consensus` turns it into a `CONFIG_CHANGE` entry itself: the
//!   joint-consensus transition is what must be replicated, not the
//!   operator's request for it.
//! - **Controller** — the migration, placement, tenant-quota and
//!   shard-map ops, sent as `MSG_MIGRATION_COMMAND` on `out_migration`.
//!   The state machine's own durable phase record is the source of
//!   truth, so replicating the command as well would be a second
//!   ordering of the same decision. A graph with no controller wired
//!   refuses these rather than accepting a command nothing will run.
//!
//! Either of the first two acks via `MSG_ADMIN_APPLIED`, after which the
//! component emits `MSG_ADMIN_RESPONSE([conn_id:u16 LE][status])` on the
//! module's `responses` port. An op outside the supported set is
//! answered `ADMIN_STATUS_UNSUPPORTED` without being staged.
//!
//! Idempotency is in-memory and deliberately narrow: it collapses only a
//! *rapid retransmit* — a command identical to the one immediately preceding
//! it within a short in-flight window (`idemp_ttl_ms`). Two genuinely
//! distinct operations (and any alternating sequence such as
//! FREEZE/THAW/FREEZE) each get their own Raft entry. Cross-command and
//! cross-restart idempotency is not this component's job: the canonical
//! "this command has been applied" record lives in the WAL via Raft
//! replication, and the supported op set is double-apply-safe by
//! construction (FREEZE→FREEZE, etc.), so a lost in-memory predecessor at
//! worst re-applies an idempotent op.

use super::abi::SyscallTable;
use super::{dev_log, dev_report_step_effect, step_effect};
use super::{wire, wire_channels};

const CMD_RING: usize = 16;

/// Size of every envelope staging buffer in this component (matches
/// the 1 KiB channel-message scratch).
const ENV_BUF: usize = 1024;
/// Longest command (`[op_code][op_body...]`) an admin envelope can
/// carry: the replicated form prepends `ADMIN_MAGIC` (8) +
/// `command_id` (4) inside the same `ENV_BUF`-sized buffer, so the
/// command must leave 12 bytes of header room. Commands past this
/// bound are refused (`ADMIN_STATUS_REJECTED`) — staging one would
/// overrun the envelope buffer.
const CMD_MAX: usize = ENV_BUF - 12;

#[repr(C)]
#[derive(Clone, Copy)]
struct CmdEntry {
    command_id: u32,
    conn_id: u16,
}

#[repr(C)]
pub struct Admin {
    pub in_applied: i32,    // in: MSG_ADMIN_APPLIED from consensus
    pub in_requests: i32,   // in: pre-authorized AdminCommand (direct inject)
    pub out_raft: i32,      // out: admin envelopes to consensus.admin_proposals (local-only path)
    pub out_responses: i32, // out: MSG_ADMIN_RESPONSE
    pub out_proposal: i32,  // out: ADMIN_MAGIC-prefixed MSG_CLIENT_PROPOSAL for replicable ops
    /// out: `MSG_MIGRATION_COMMAND` to the controller that owns the
    /// migration state machine. Optional — a graph without a
    /// controller leaves it unwired and migration ops are refused.
    pub out_migration: i32,

    /// Raft group an admin command targets. One consensus engine hosts
    /// K groups, and every interesting admin op (FREEZE,
    /// TRANSFER_LEADER, the membership ops) is per-group, so the command
    /// names its target. Defaults to 0 — a single-group graph behaves
    /// exactly as before.
    pub target_partition: u16,

    // Idempotency collapses only a *rapid retransmit* — a command
    // identical to the one immediately preceding it within the in-flight
    // window. The predecessor's bytes are retained and compared in
    // full: hash-only equality would answer DUPLICATE to a distinct
    // colliding command and silently never execute it.
    // `last_cmd_len == 0` means "no prior command". A distinct or
    // alternating op is always a fresh command. See the component header.
    idemp_ttl_ms: u64,
    last_cmd_len: u16,
    last_cmd: [u8; CMD_MAX],
    last_cmd_ms: u64,
    pub commands_processed: u32,

    next_command_id: u32,
    cmd_ring: [CmdEntry; CMD_RING],
    cmd_head: u16,

    msg_buf: [u8; 1024],
}

pub unsafe fn init(a: &mut Admin) {
    a.in_applied = -1;
    a.in_requests = -1;
    a.out_raft = -1;
    a.target_partition = 0;
    a.out_responses = -1;
    a.out_proposal = -1;
    a.out_migration = -1;
    // In-flight retransmit window: a duplicate is only collapsed if
    // it lands within this gap of an identical predecessor. Long
    // enough to swallow a client TCP retransmit, short enough that a
    // genuine later op (operator re-issuing the same command) is its
    // own entry.
    a.idemp_ttl_ms = 2_000; // 2 s
    a.last_cmd_len = 0;
    a.last_cmd = [0u8; CMD_MAX];
    a.last_cmd_ms = 0;
    a.commands_processed = 0;
    a.next_command_id = 1;
    a.cmd_head = 0;
    for slot in a.cmd_ring.iter_mut() {
        *slot = CmdEntry {
            command_id: 0,
            conn_id: 0,
        };
    }
}

/// Per-step bound: 8 apply acknowledgements + 4 direct-inject
/// commands, plus at most 4 rbac-delivered commands (bounded by
/// rbac's own request loop). Heaviest single item is a byte compare
/// over ≤`CMD_MAX` bytes.
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
        let Some((msg_type, plen)) = wire_channels::next_msg(sys, a.in_applied, &mut a.msg_buf)
        else {
            break;
        };
        if msg_type != wire::MSG_ADMIN_APPLIED || (plen as usize) < 5 {
            continue;
        }
        let command_id =
            u32::from_le_bytes([a.msg_buf[0], a.msg_buf[1], a.msg_buf[2], a.msg_buf[3]]);
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
        let Some((msg_type, plen)) = wire_channels::next_msg(sys, a.in_requests, &mut a.msg_buf)
        else {
            break;
        };
        if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 {
            continue;
        }
        let pl = plen as usize;
        let mut local = [0u8; ENV_BUF];
        local[..pl].copy_from_slice(&a.msg_buf[..pl]);
        on_command(a, sys, now, &local[..pl]);
    }
}

/// Process one authorized admin command envelope
/// `[conn_id:u16 LE][op_code:u8][op_body...]`. This is the single
/// admission point regardless of how the command arrived (rbac
/// delivery or the `admin_requests` port).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_command(a: &mut Admin, sys: &SyscallTable, now: u64, payload: &[u8]) {
    let pl = payload.len();
    if pl < 3 {
        return; // need conn_id + op_code at minimum
    }
    let conn_id = u16::from_le_bytes([payload[0], payload[1]]);
    let op_code = payload[2];
    // Receipt signal — paired with `[http] admin op=N
    // conn_id=M`, the only external proof the POST→admin path
    // landed: admin ops reply 202 immediately (see the http
    // component) and, unlike client proposals, have no async
    // correlation-tracked reply to observe instead.
    let mut log = [0u8; 64];
    let n = format_recv_log(&mut log, op_code, conn_id);
    dev_log(sys, 3, log.as_ptr(), n);
    // Copy command bytes for the idempotency compare + forwarding.
    let cmd_len = pl - 2;
    let mut cmd = [0u8; ENV_BUF];
    cmd[..cmd_len].copy_from_slice(&payload[2..pl]);

    // Client-write bridge: ADMIN_OP_PROPOSE carries opaque application data,
    // not an admin op. Emit it as a RAW (unmarked) MSG_CLIENT_PROPOSAL to
    // raft and return — NO idempotency collapse (distinct client writes may
    // legitimately repeat a body), no admin apply, no admin response. `cmd`
    // is `[op_code][op_body]`, so the proposal body is `cmd[1..]`.
    if op_code == wire::ADMIN_OP_PROPOSE {
        if a.out_proposal >= 0 && cmd_len > 1 {
            if wire_channels::writable(sys, a.out_proposal) {
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

    // Envelope-size bound: the replicated envelope below prepends 12
    // header bytes to the command inside the same fixed buffer, so a
    // command past `CMD_MAX` cannot be staged — refuse it outright
    // rather than overrun (a panic here kills the whole module).
    if cmd_len > CMD_MAX {
        emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_REJECTED);
        return;
    }

    // Idempotency check — collapse only a rapid retransmit: a
    // command identical (full byte compare, never hash equality) to
    // its immediate predecessor within the in-flight window.
    // Alternating or otherwise-distinct ops each get their own entry
    // (the alternating freeze/thaw the wal_replay test drives must
    // produce one entry per op).
    let dup = a.last_cmd_len as usize == cmd_len
        && a.last_cmd_len != 0
        && a.last_cmd[..cmd_len] == cmd[..cmd_len]
        && now.wrapping_sub(a.last_cmd_ms) < a.idemp_ttl_ms;
    if dup {
        emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_DUPLICATE);
        return;
    }

    // Membership ops are SUPPORTED as of the union-quorum + learner
    // work. The safety argument, in the order the pieces land:
    //
    // 1. UNION QUORUM. During joint consensus an entry counts only once
    //    a majority of BOTH configurations has it — enforced in
    //    `consensus::commit` over match indices AND in
    //    `durability::ledger` over fsync acks, so neither the commit
    //    horizon nor the durability proof can run ahead of the new
    //    configuration. (`tests/union_quorum.rs`)
    //
    // 2. LEARNERS. `ADMIN_OP_ADD_LEARNER` attaches a replica that
    //    receives the log and counts toward nothing, so it can catch up
    //    without being able to stall or skew a quorum.
    //    (`tests/learner_semantics.rs`)
    //
    // 3. PROMOTION GATE. `ADMIN_OP_ADD_VOTER` is refused unless the
    //    target is already a learner whose match index is within
    //    `catchup_lag_max` of the leader's tip. A voter counts from the
    //    moment the change applies, so promoting a cold replica could
    //    make the new majority unmeetable and stall commit — and lose
    //    entries it never held if the leader then failed.
    //
    // 4. ONE CHANGE AT A TIME, enforced in `raft::apply_admin_op`: union
    //    quorum is defined for one pair of configurations, so a second
    //    transition opened mid-flight is rejected rather than queued.
    //
    // Both ops queue a `CONFIG_CHANGE_OP_JOINT` entry; applying it opens
    // joint consensus and auto-queues the matching C_new, so the whole
    // transition travels through the log and every replica replays the
    // same sequence.
    //
    // Catch-up relies on the leader still holding the log the learner
    // needs. Once the log has been compacted past a learner's position
    // the gap is closed by snapshot install instead, which streams to
    // and from the snapshot file and so is bounded by the filesystem
    // rather than by module state.
    let supported = matches!(
        op_code,
        wire::ADMIN_OP_FREEZE
            | wire::ADMIN_OP_THAW
            | wire::ADMIN_OP_TRANSFER_LEADER
            | wire::ADMIN_OP_DURABILITY_MODE
            | wire::ADMIN_OP_SNAPSHOT
            | wire::ADMIN_OP_ADD_LEARNER
            | wire::ADMIN_OP_REMOVE_LEARNER
            | wire::ADMIN_OP_ADD_VOTER
            | wire::ADMIN_OP_REMOVE_VOTER
            | wire::ADMIN_OP_MIGRATE_BEGIN
            | wire::ADMIN_OP_MIGRATE_PHASE_DONE
            | wire::ADMIN_OP_MIGRATE_ABORT
            | wire::ADMIN_OP_PLACEMENT_TOPOLOGY
            | wire::ADMIN_OP_TENANT_QUOTA
            | wire::ADMIN_OP_SHARD_MAP
    );
    if !supported {
        emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_UNSUPPORTED);
        return;
    }

    // Record this command as the predecessor for the next request's
    // retransmit check.
    a.last_cmd_len = cmd_len as u16;
    a.last_cmd[..cmd_len].copy_from_slice(&cmd[..cmd_len]);
    a.last_cmd_ms = now;

    // Allocate a command_id and remember the conn_id so we can route
    // the eventual MSG_ADMIN_APPLIED back to the right client.
    let command_id = a.next_command_id;
    a.next_command_id = a.next_command_id.wrapping_add(1);
    if a.next_command_id == 0 {
        a.next_command_id = 1;
    }
    put_cmd(a, command_id, conn_id);

    // Two paths:
    //   FREEZE / THAW / DURABILITY_MODE — replicate through Raft so
    //     every replica's state stays consistent. Send as a
    //     MSG_CLIENT_PROPOSAL with body
    //     `[ADMIN_MAGIC:8][command_id:u32 LE][op_code:u8][op_body]`.
    //   TRANSFER_LEADER / SNAPSHOT — keep the local-only path; both
    //     have per-leader semantics and don't benefit from
    //     replication.
    // Migration ops go to the controller, not to Raft. The state
    // machine's own phase RECORD is the durable source of truth
    // (MIG-DURABLE), so replicating the COMMAND as well would create a
    // second, redundant ordering of the same decision — and a command
    // that outlived its migration could restart one on replay. This is
    // the same local-only shape TRANSFER_LEADER and SNAPSHOT already
    // use for per-controller semantics.
    if matches!(
        op_code,
        wire::ADMIN_OP_MIGRATE_BEGIN
            | wire::ADMIN_OP_MIGRATE_PHASE_DONE
            | wire::ADMIN_OP_MIGRATE_ABORT
            | wire::ADMIN_OP_PLACEMENT_TOPOLOGY
            | wire::ADMIN_OP_TENANT_QUOTA
            | wire::ADMIN_OP_SHARD_MAP
    ) {
        if a.out_migration < 0 {
            // No controller wired: nothing can own the migration, so
            // refusing is the honest answer rather than accepting a
            // command that will never run.
            emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_UNSUPPORTED);
            return;
        }
        if wire_channels::writable(sys, a.out_migration) {
            wire_channels::channel_write_msg(
                sys,
                a.out_migration,
                wire::MSG_MIGRATION_COMMAND,
                &cmd[..cmd_len],
            );
            emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_OK);
        } else {
            // Back-pressure. The controller decides migrations one at a
            // time; dropping silently would leave the operator believing
            // a migration started.
            emit_admin_response(a, sys, conn_id, wire::ADMIN_STATUS_UNSUPPORTED);
        }
        a.commands_processed += 1;
        return;
    }

    let replicable = matches!(
        op_code,
        wire::ADMIN_OP_FREEZE | wire::ADMIN_OP_THAW | wire::ADMIN_OP_DURABILITY_MODE
    );

    if replicable && a.out_proposal >= 0 {
        let mut env = [0u8; ENV_BUF];
        env[..8].copy_from_slice(&wire::ADMIN_MAGIC);
        env[8..12].copy_from_slice(&command_id.to_le_bytes());
        env[12..12 + cmd_len].copy_from_slice(&cmd[..cmd_len]);
        let total = 12 + cmd_len;
        if wire_channels::writable(sys, a.out_proposal) {
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
        let mut env = [0u8; ENV_BUF];
        env[0..4].copy_from_slice(&command_id.to_le_bytes());
        env[4..4 + cmd_len].copy_from_slice(&cmd[..cmd_len]);
        let total = 4 + cmd_len;
        if wire_channels::writable(sys, a.out_raft) {
            // Partitioned envelope: with one consensus engine hosting K
            // Raft groups, an admin op has to name the group it acts on
            // — FREEZE, TRANSFER_LEADER and the membership ops are all
            // per-group. `target_partition` defaults to 0, which is
            // exactly today's behaviour on a single-group graph; a
            // multi-group admin surface sets it per request.
            //
            // Deliberately ONE target, not a broadcast: a command
            // carries a single `command_id` and gets a single
            // MSG_ADMIN_APPLIED, so fanning one command across K groups
            // would produce K statuses for one id and the correlation
            // upstream would mishandle them. Cluster-wide admin needs a
            // response-aggregation design first.
            wire_channels::channel_write_partitioned(
                sys,
                a.out_raft,
                a.target_partition,
                wire::MSG_ADMIN_COMMAND,
                &env[..total],
            );
        }
    }
    a.commands_processed += 1;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Admin` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn emit_admin_response(a: &mut Admin, sys: &SyscallTable, conn_id: u16, status: u8) {
    if a.out_responses < 0 {
        return;
    }
    if wire_channels::writable(sys, a.out_responses) {
        let cid = conn_id.to_le_bytes();
        let resp = [cid[0], cid[1], status];
        wire_channels::channel_write_msg(sys, a.out_responses, wire::MSG_ADMIN_RESPONSE, &resp);
    }
}

fn put_cmd(a: &mut Admin, command_id: u32, conn_id: u16) {
    let slot = (a.cmd_head as usize) % CMD_RING;
    a.cmd_ring[slot] = CmdEntry {
        command_id,
        conn_id,
    };
    a.cmd_head = a.cmd_head.wrapping_add(1);
}

fn take_cmd(a: &mut Admin, command_id: u32) -> Option<u16> {
    for slot in a.cmd_ring.iter_mut() {
        if slot.command_id == command_id {
            let c = slot.conn_id;
            slot.command_id = 0;
            return Some(c);
        }
    }
    None
}

fn format_recv_log(dst: &mut [u8], op_code: u8, conn_id: u16) -> usize {
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
