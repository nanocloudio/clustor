//! session_directory — the session-directory / reservation-authority
//! role from fluxor's `rfc_protocols.md` (§8.3, §13.7) as a Clustor
//! replicated consumer.
//!
//! The deterministic state machine lives in
//! `modules/common/session_registry.rs` (host-tested by
//! `tests/session_registry.rs`); this module is the wiring:
//!
//! - **Requests** (`MSG_SR_REQUEST`, payload
//!   `[request_id:u64][SR_OP_* command body]`) arrive from anchors /
//!   orchestrators on `requests`. Each is wrapped in a tagged raft
//!   proposal (`replica_facade::build_tagged_proposal`) and written to
//!   `consensus.proposals_tagged` as `MSG_CLIENT_PROPOSAL`.
//! - **Committed entries** arrive back on `committed_entries` in
//!   strict order; every entry is applied to the registry. If the
//!   entry's correlation matches one of OUR pending requests, the
//!   reply (`MSG_SR_REPLY`) goes out on `replies`.
//!
//!   Replying only from the committed-entry stream is the load-bearing
//!   invariant: a reservation grant, an epoch bump, a fence record, or
//!   an auth-relevant write is acknowledged ONLY after it is
//!   quorum-committed — the RFC's R2 "quorum-durable before emit" and
//!   R5 "RPO-zero before acted upon" boundaries live on exactly this
//!   edge. There is no fast-path ack.
//!
//! - **Snapshots**: the registry serializes to a fixed-size blob;
//!   export/install ride the standard `MSG_APP_SNAPSHOT_*` chunk
//!   envelopes (RFC §2.1), chunked at `SNAP_CHUNK` bytes.
//! - **Telemetry**: `MON_SESSION` lines (fluxor
//!   `monitor-protocol.md`) on every continuity-relevant transition —
//!   `reservation_granted`, `epoch_bump`, `fence_initiated` /
//!   `fence_confirmed`, `unsafe_recovery_epoch_void`, `rejected` — so
//!   a failover is legible on the same channel as the rest of the
//!   platform (RFC §10.4).
//!
//! **Fence honesty (R3).** This module records fence state and the
//! registry refuses anchor takeovers until a fence is CONFIRMED, which
//! enforces the §13.7.4 ordering. It cannot make a fence enforceable —
//! that is the fence backend's job (STONITH via a managed PDU, a
//! fabric egress cutoff; the fluxor rig's `kasa_local` power backend
//! is the reference implementation). FENCE_CONFIRM must be proposed
//! only by the agent that actually observed the cutoff.
//!
//! - **Deterministic timing** (rfc_deterministic_timing.md): this
//!   module hosts the leader-fenced time producer for its state
//!   machine. When (and only when) this node is the PRG leader per
//!   `MSG_LEADER_HINT`, its clock guard is healthy, and the timing
//!   index has work (live deadlines / due backlog / a pending
//!   duration admission), it proposes `TimeAdvance` / `TimeDrain`
//!   entries through the ordinary tagged-proposal path. An idle PRG
//!   proposes no time entries (idle coalescing, RFC §5.2). Committed
//!   timing entries come back on `committed_entries` like every other
//!   entry and are applied to the registry's embedded `TimingState` —
//!   deadlines fire ONLY during committed apply, never from a local
//!   timer.
//!
//! # Parameters (TLV v2)
//!
//! | Tag | Name       | Type | Default | Description                              |
//! |-----|------------|------|---------|------------------------------------------|
//! | 1   | replica_id | u8   | 0       | Stamped into correlation ids (uniqueness across proposers). Must equal the node's raft id — the leader fence compares it against MSG_LEADER_HINT. |
//! | 2   | smoke      | u8   | 0       | 1 = propose a BIND + two RESERVEs at boot; the committed grants prove the quorum path end-to-end (e2e assertion hook). 2 = additionally propose a KEY_PUT with a 1500 ms TTL after the grants — its committed expiry proves the deterministic-timing path end-to-end. |
//! | 3   | time_advance_period_ms | u32 | 1000 | Target committed-time cadence while deadlines are pending (RFC §6.2). |
//! | 4   | logical_max_step_ms    | u32 | 60000 | Max forward movement of logical time per proposed entry (forward-jump clamp). |
//! | 5   | clock_slew_tolerance_ms | u32 | 100 | Wall-vs-monotonic disagreement tolerated before the backward-jump alarm. |
//! | 6   | logical_staleness_ms   | u32 | 5000 | Duration-admission freshness bound: a TTL command observed while logical time lags wall time by more than this triggers a time-freshness barrier (admission-time only, RFC §5.2). |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    unreachable_patterns,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; defensive `_ =>` arms are intentional"
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
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;
#[path = "../../common/replica_facade.rs"]
mod replica_facade;
#[path = "../../common/timing.rs"]
mod timing;
#[path = "../../common/session_registry.rs"]
mod session_registry;

use replica_facade::{CommitOrderError, CommittedSubscriber, TAGGED_PROPOSAL_HDR};
use session_registry::*;
use timing::{ClockGuard, ClockHealth};

/// Two-byte prefix on every replicated registry command so registry
/// entries are unambiguous in the shared raft log (admin ops, client
/// KV commands, and future consumers share the same entry stream —
/// an opcode byte alone is not a namespace).
const SR_CMD_MAGIC: [u8; 2] = *b"SR";

/// Pending request table: correlation → request_id. Small — the
/// directory is a control-plane service; a full table backpressures
/// new requests rather than dropping replies.
const MAX_PENDING: usize = 16;

/// Snapshot chunk body size. The registry snapshot is
/// `SessionRegistry::SNAPSHOT_LEN` bytes (~10.4 KiB), so exports run
/// to a dozen chunks.
const SNAP_CHUNK: usize = 1024;

/// Scratch buffer: committed entries carry the command body
/// (SR_CMD_MAGIC + SR_MAX_CMD) under a 16-byte entry header; snapshot
/// chunks are APP_SNAPSHOT_HDR + SNAP_CHUNK.
const MSG_BUF: usize = 2048;

const SMOKE_IDLE: u8 = 0;
const SMOKE_BIND_SENT: u8 = 1;
const SMOKE_RESERVE1_SENT: u8 = 2;
const SMOKE_RESERVE2_SENT: u8 = 3;
const SMOKE_KEY_ARM: u8 = 4;
const SMOKE_KEY_SENT: u8 = 5;
const SMOKE_DONE: u8 = 6;
const SMOKE_OFF: u8 = 0xFF;

/// TTL for the smoke KEY_PUT (smoke = 2): long enough to commit the
/// put before expiry, short enough for an e2e to observe the fire.
const SMOKE_KEY_TTL_MS: u32 = 1500;

/// Smoke-session identity (only used with `smoke = 1`).
const SMOKE_SID: [u8; SR_SESSION_ID] = *b"SMOKE-SESSION-01";
const SMOKE_ANCHOR: [u8; SR_PEER_ID] = *b"SMOKE-A0";
const SMOKE_WORKER: [u8; SR_PEER_ID] = *b"SMOKE-W0";

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    in_entries: i32,          // in[0]: MSG_COMMITTED_ENTRY from consensus
    in_requests: i32,         // in[1]: MSG_SR_REQUEST from anchors/orchestrators
    in_snapshot_chunk: i32,   // in[2]: MSG_APP_SNAPSHOT_CHUNK / RESET (install)
    in_snapshot_request: i32, // in[3]: MSG_APP_SNAPSHOT_REQUEST
    in_proposal_assigned: i32, // in[4]: MSG_PROPOSAL_ASSIGNED from consensus
    in_leader_state: i32,     // in[5]: MSG_LEADER_HINT from consensus
    out_proposals: i32,       // out[0]: MSG_CLIENT_PROPOSAL to consensus.proposals_tagged
    out_replies: i32,         // out[1]: MSG_SR_REPLY to requester
    out_metrics: i32,         // out[2]: MSG_METRICS to operations
    out_snapshot_export: i32, // out[3]: MSG_APP_SNAPSHOT_CHUNK to durability

    // Params
    replica_id: u8,
    smoke: u8,
    smoke_phase: u8,
    _pad0: u8,

    /// The replicated state machine.
    registry: SessionRegistry,

    /// Strict-commit-order subscriber.
    subscriber: CommittedSubscriber,

    /// Correlation allocator: `(replica_id << 56) | counter`.
    corr_counter: u64,

    /// Pending proposals awaiting commit: correlation (allocated at
    /// propose), requester id, and the wal_index raft assigned (0
    /// until the MSG_PROPOSAL_ASSIGNED arrives). The committed entry
    /// whose index equals `pending_idx[i]` is proposal i — raft
    /// strips the tag header before the WAL, so index is the only
    /// sound attribution (content matching would misattribute
    /// byte-identical commands from concurrent proposers, which for
    /// RESERVE means handing two anchors the same counter block).
    pending_corr: [u64; MAX_PENDING],
    pending_req: [u64; MAX_PENDING],
    pending_idx: [u64; MAX_PENDING],
    pending_used: [bool; MAX_PENDING],

    // Counters (metrics)
    requests_in: u32,
    proposals_out: u32,
    replies_out: u32,
    applied_ok: u32,
    applied_rejected: u32,
    stream_gaps: u32,

    // ── Deterministic timing (rfc_deterministic_timing.md) ──────────
    /// Current PRG leader per MSG_LEADER_HINT (0xFF = unknown).
    leader_id: u8,
    /// Node-local pause reason (wire::TIMING_PAUSE_*), metrics/why.
    pause_reason: u8,
    _pad3: [u8; 2],
    // Params (tags 3–6).
    time_advance_period_ms: u32,
    logical_max_step_ms: u32,
    clock_slew_tolerance_ms: u32,
    logical_staleness_ms: u32,
    /// Leader-side wall-clock discipline. Never consulted in apply.
    clock_guard: ClockGuard,
    /// Monotonic throttle stamps for time proposals.
    last_advance_propose_ms: u64,
    last_drain_propose_ms: u64,
    /// Last sampled wall clock (leader only; lag metric).
    last_unix_ms: u64,
    /// Committed timing entries applied (metrics).
    time_advance_applied: u32,
    time_drain_applied: u32,

    /// Cached scheduler index for MON_SESSION emission.
    self_idx: u8,
    _pad1: [u8; 7],
    last_metrics_ms: u64,

    /// Snapshot install cursor (bytes received into snap_buf).
    snap_in_off: u32,
    _pad2: u32,

    msg_buf: [u8; MSG_BUF],
    mon_buf: [u8; 192],
    /// Snapshot staging (install + export walk share it; the two never
    /// overlap — install only happens while catching up, export only
    /// on the snapshot engine's request).
    snap_buf: [u8; SessionRegistry::SNAPSHOT_LEN],
}

mod params_def {
    use super::p_u32;
    use super::p_u8;
    use super::ModuleState;
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;

        1, replica_id, u8, 0
            => |s, d, len| { s.replica_id = p_u8(d, len, 0, 0); };

        2, smoke, u8, 0
            => |s, d, len| { s.smoke = p_u8(d, len, 0, 0); };

        3, time_advance_period_ms, u32, 1000
            => |s, d, len| { s.time_advance_period_ms = p_u32(d, len, 0, 1000); };

        4, logical_max_step_ms, u32, 60000
            => |s, d, len| { s.logical_max_step_ms = p_u32(d, len, 0, 60000); };

        5, clock_slew_tolerance_ms, u32, 100
            => |s, d, len| { s.clock_slew_tolerance_ms = p_u32(d, len, 0, 100); };

        6, logical_staleness_ms, u32, 5000
            => |s, d, len| { s.logical_staleness_ms = p_u32(d, len, 0, 5000); };
    }
}

// ── Proposal path ───────────────────────────────────────────────────

/// Allocate a correlation id unique across proposers: replica_id in
/// the top byte, a monotonic counter below. Correlation 0 is reserved
/// by the facade; the counter starts at 1.
fn next_correlation(s: &mut ModuleState) -> u64 {
    s.corr_counter = s.corr_counter.wrapping_add(1);
    ((s.replica_id as u64) << 56) | (s.corr_counter & 0x00FF_FFFF_FFFF_FFFF)
}

/// Propose a session-registry command. Registers (correlation →
/// request_id) in the pending table so the committed-entry pass can
/// route the reply. Returns false when the pending table or the
/// proposal channel is full.
unsafe fn propose(s: &mut ModuleState, request_id: u64, body: &[u8]) -> bool {
    let sys = &*s.syscalls;
    let Some(slot) = (0..MAX_PENDING).find(|&i| !s.pending_used[i]) else {
        return false;
    };
    let poll = (sys.channel_poll)(s.out_proposals, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let corr = next_correlation(s);
    let mut tagged = [0u8; 2 + SR_MAX_CMD];
    tagged[..2].copy_from_slice(&SR_CMD_MAGIC);
    tagged[2..2 + body.len()].copy_from_slice(body);
    let mut prop = [0u8; TAGGED_PROPOSAL_HDR + 2 + SR_MAX_CMD];
    let n = match replica_facade::build_tagged_proposal(&mut prop, corr, &tagged[..2 + body.len()])
    {
        Ok(n) => n,
        Err(_) => return false,
    };
    let wrote =
        wire_channels::channel_write_msg(sys, s.out_proposals, wire::MSG_CLIENT_PROPOSAL, &prop[..n]);
    if wrote <= 0 {
        return false;
    }
    s.pending_corr[slot] = corr;
    s.pending_req[slot] = request_id;
    s.pending_idx[slot] = 0;
    s.pending_used[slot] = true;
    s.proposals_out = s.proposals_out.saturating_add(1);
    true
}

/// Propose an untracked internal entry (timing). No pending-table
/// registration: time entries need no reply routing — the committed
/// entry itself is the effect. Returns false when the proposal ring
/// has no space (retry next step).
unsafe fn propose_raw(s: &mut ModuleState, body: &[u8]) -> bool {
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.out_proposals, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let corr = next_correlation(s);
    let mut prop = [0u8; TAGGED_PROPOSAL_HDR + wire::TIMING_ENTRY_LEN];
    let n = match replica_facade::build_tagged_proposal(&mut prop, corr, body) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let wrote =
        wire_channels::channel_write_msg(sys, s.out_proposals, wire::MSG_CLIENT_PROPOSAL, &prop[..n]);
    if wrote > 0 {
        s.proposals_out = s.proposals_out.saturating_add(1);
        true
    } else {
        false
    }
}

/// True when this node is the current PRG leader per MSG_LEADER_HINT.
fn is_leader(s: &ModuleState) -> bool {
    s.leader_id != 0xFF && s.leader_id == s.replica_id
}

/// Duration-admission freshness barrier (rfc_deterministic_timing.md
/// §5.2). ADMISSION-TIME ONLY: the check compares the local wall
/// clock against replicated logical time before PROPOSING a duration
/// command; it is never re-evaluated during apply. Returns true when
/// the command may be proposed now (time fresh, or this node is not
/// the leader so the proposal cannot commit anyway); on a stale clock
/// it proposes a TimeAdvance barrier entry first and reports whether
/// the command may follow it in the same submission order.
unsafe fn ensure_time_fresh(s: &mut ModuleState) -> bool {
    let sys = &*s.syscalls;
    if !is_leader(s) {
        return true;
    }
    let logical = s.registry.timing.logical_now_ms();
    let unix = dev_unix_millis(sys);
    if unix == 0 {
        // No trusted wall clock: refuse duration admission (fail
        // closed — a 0 source is never a valid epoch instant).
        return false;
    }
    if unix.saturating_sub(logical) <= s.logical_staleness_ms as u64 {
        return true;
    }
    let mono = dev_millis(sys);
    if s.clock_guard.sample(mono, unix) != ClockHealth::Healthy {
        return false;
    }
    let Some(t) = s.clock_guard.propose_time(logical, unix) else {
        return false;
    };
    let mut body = [0u8; wire::TIMING_ENTRY_LEN];
    let n = wire::encode_time_entry(&mut body, wire::TIMING_OP_ADVANCE, t);
    if n == 0 || !propose_raw(s, &body[..n]) {
        return false;
    }
    // The barrier is in the log ahead of the command; whether it made
    // time FULLY fresh depends on the step clamp — admit only when it
    // did, otherwise the requester retries while catch-up continues.
    unix.saturating_sub(t) <= s.logical_staleness_ms as u64
}

/// Apply one committed timing entry to the embedded state machine.
unsafe fn apply_timing_entry(s: &mut ModuleState, body: &[u8]) {
    let sys = &*s.syscalls;
    let Some((op, time_ms)) = wire::decode_time_entry(body) else {
        // Unknown timing entry versions fail closed (RFC §18).
        dev_log(sys, 2, b"[sess_dir] bad time entry".as_ptr(), 25);
        return;
    };
    let r = if op == wire::TIMING_OP_ADVANCE {
        s.time_advance_applied = s.time_advance_applied.saturating_add(1);
        s.registry.apply_time_advance(time_ms)
    } else {
        s.time_drain_applied = s.time_drain_applied.saturating_add(1);
        s.registry.apply_time_drain(time_ms)
    };
    if r.fired > 0 {
        dev_log(sys, 3, b"[sess_dir] deadline fired".as_ptr(), 25);
    }
}

// ── Telemetry ───────────────────────────────────────────────────────

/// Emit a MON_SESSION line for a committed registry transition.
unsafe fn mon_reply(s: &mut ModuleState, reply: &SessionReply) {
    let sys = &*s.syscalls;
    if s.self_idx == 0xFF {
        let idx = dev_self_index(sys);
        if idx >= 0 {
            s.self_idx = idx as u8;
        }
    }
    let (event, reason): (u8, &[u8]) = if reply.status != SR_ST_OK {
        let reason: &[u8] = match reply.status {
            SR_ST_STALE_EPOCH => b"stale_epoch",
            SR_ST_RECOVERY_VOID => b"recovery_void",
            SR_ST_FENCE_REQUIRED => b"fence_required",
            SR_ST_FLOOR_REGRESSION => b"floor_regression",
            SR_ST_UNKNOWN_SESSION => b"unknown_session",
            SR_ST_NO_CAPACITY => b"no_capacity",
            SR_ST_RECOVERY_STALE => b"recovery_stale",
            _ => b"malformed",
        };
        (MON_EV_REJECTED, reason)
    } else {
        match reply.op {
            SR_OP_BIND => (MON_EV_RELOCATED, b""),
            SR_OP_EPOCH_BUMP => (MON_EV_EPOCH_BUMP, b""),
            SR_OP_RESERVE => (MON_EV_RESERVATION_GRANTED, b""),
            SR_OP_FENCE_REQUEST => (MON_EV_FENCE_INITIATED, b""),
            SR_OP_FENCE_CONFIRM => (MON_EV_FENCE_CONFIRMED, b""),
            SR_OP_UNBIND => (MON_EV_DETACHED, b""),
            SR_OP_RECOVERY_MARK => (MON_EV_UNSAFE_RECOVERY_EPOCH_VOID, b""),
            // KEY_PUT / KEY_WIPE / RX_FLOOR are deliberately silent:
            // key custody must not leak activity patterns to the log,
            // and floor checkpoints are high-rate.
            _ => return,
        }
    };
    let status: &[u8] = if reply.status == SR_ST_OK { b"ok" } else { b"" };
    let mon_ptr = s.mon_buf.as_mut_ptr();
    let _ = dev_mon_session(
        sys,
        s.self_idx,
        event,
        reply.session_id.as_ptr(),
        reply.epoch,
        core::ptr::null(),
        core::ptr::null(),
        reason,
        status,
        mon_ptr,
        192,
    );
}

// ── Module interface ────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
    // SAFETY: per the module ABI, the kernel passes a valid,
    // exclusively-borrowed `state` of at least `module_state_size()`
    // bytes and a live syscall table.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_entries = in_chan;
        s.in_requests = dev_channel_port(sys, 0, 1);
        s.in_snapshot_chunk = dev_channel_port(sys, 0, 2);
        s.in_snapshot_request = dev_channel_port(sys, 0, 3);
        s.in_proposal_assigned = dev_channel_port(sys, 0, 4);
        s.in_leader_state = dev_channel_port(sys, 0, 5);
        s.out_proposals = out_chan;
        s.out_replies = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.out_snapshot_export = dev_channel_port(sys, 1, 3);

        s.replica_id = 0;
        s.smoke = 0;
        s.smoke_phase = SMOKE_IDLE;
        s._pad0 = 0;
        s.registry = SessionRegistry::new();
        s.subscriber = CommittedSubscriber::new(0);
        s.corr_counter = 0;
        s.pending_corr = [0; MAX_PENDING];
        s.pending_req = [0; MAX_PENDING];
        s.pending_idx = [0; MAX_PENDING];
        s.pending_used = [false; MAX_PENDING];
        s.requests_in = 0;
        s.proposals_out = 0;
        s.replies_out = 0;
        s.applied_ok = 0;
        s.applied_rejected = 0;
        s.stream_gaps = 0;
        s.leader_id = 0xFF;
        s.pause_reason = wire::TIMING_PAUSE_NOT_LEADER;
        s._pad3 = [0; 2];
        s.last_advance_propose_ms = 0;
        s.last_drain_propose_ms = 0;
        s.last_unix_ms = 0;
        s.time_advance_applied = 0;
        s.time_drain_applied = 0;
        s.self_idx = 0xFF;
        s._pad1 = [0; 7];
        s.last_metrics_ms = 0;
        s.snap_in_off = 0;
        s._pad2 = 0;

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if s.smoke == 0 {
            s.smoke_phase = SMOKE_OFF;
        }
        s.clock_guard = ClockGuard::new(
            s.logical_max_step_ms as u64,
            s.clock_slew_tolerance_ms as u64,
        );

        dev_log(sys, 3, b"[sess_dir] init".as_ptr(), 15);
        0
    }
}

/// Handle one committed entry. raft strips the tagged-proposal header
/// before the WAL, so `command` is the raw body: registry traffic is
/// `[b"SR"][SR_OP_* command]`; anything else (admin ops, other
/// consumers) is ignored. Every registry entry is applied on every
/// replica; the reply is relayed only by the replica whose pending
/// proposal was assigned exactly this wal index.
unsafe fn apply_committed(s: &mut ModuleState, index: u64, command: &[u8]) {
    // Substrate timing entries (TimeAdvance / TimeDrain) apply to the
    // registry's embedded TimingState on every replica — the ONLY
    // path on which a deadline can fire (rfc_deterministic_timing.md).
    if wire::has_timing_magic(command) {
        apply_timing_entry(s, command);
        return;
    }
    if command.len() <= 2 || command[..2] != SR_CMD_MAGIC {
        return;
    }
    let body = &command[2..];
    let reply = s.registry.apply(body);
    if reply.status == SR_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    mon_reply(s, &reply);

    // Route the reply if this replica proposed the entry at `index`.
    let Some(slot) =
        (0..MAX_PENDING).find(|&i| s.pending_used[i] && s.pending_idx[i] != 0 && s.pending_idx[i] == index)
    else {
        return;
    };
    s.pending_used[slot] = false;
    let request_id = s.pending_req[slot];

    smoke_advance(s, &reply);

    if s.out_replies >= 0 && request_id != 0 {
        let sys = &*s.syscalls;
        let mut out = [0u8; 8 + SR_REPLY_LEN];
        out[..8].copy_from_slice(&request_id.to_le_bytes());
        let _ = reply.encode(&mut out[8..]);
        let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_SR_REPLY, &out);
        if wrote > 0 {
            s.replies_out = s.replies_out.saturating_add(1);
        }
    }
}

/// Smoke sequence: BIND → RESERVE(4096) → RESERVE(4096). The second
/// grant landing at start=4096 in the log is the end-to-end proof
/// that grants are quorum-committed, monotone, and never re-handed
/// out. Requests are self-originated (request_id 0 → no reply frame).
unsafe fn smoke_advance(s: &mut ModuleState, reply: &SessionReply) {
    if s.smoke_phase == SMOKE_OFF || s.smoke_phase == SMOKE_DONE {
        return;
    }
    let sys = &*s.syscalls;
    let mut cmd = [0u8; SR_MAX_CMD];
    match (s.smoke_phase, reply.op, reply.status) {
        (SMOKE_BIND_SENT, SR_OP_BIND, SR_ST_OK) => {
            let n = build_reserve(&mut cmd, &SMOKE_SID, 1, 0, 4096);
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_RESERVE1_SENT;
            }
        }
        (SMOKE_RESERVE1_SENT, SR_OP_RESERVE, SR_ST_OK) => {
            let n = build_reserve(&mut cmd, &SMOKE_SID, 1, 0, 4096);
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_RESERVE2_SENT;
            }
        }
        (SMOKE_RESERVE2_SENT, SR_OP_RESERVE, SR_ST_OK) => {
            if s.smoke >= 2 {
                // Timing smoke: arm a TTL'd key. The proposal happens
                // from the step loop (SMOKE_KEY_ARM) so the freshness
                // barrier can retry until duration admission passes.
                s.smoke_phase = SMOKE_KEY_ARM;
            } else {
                s.smoke_phase = SMOKE_DONE;
                dev_log(sys, 3, b"[sess_dir] smoke complete".as_ptr(), 25);
            }
        }
        (SMOKE_KEY_SENT, SR_OP_KEY_PUT, SR_ST_OK) => {
            s.smoke_phase = SMOKE_DONE;
            dev_log(sys, 3, b"[sess_dir] smoke complete".as_ptr(), 25);
        }
        (_, _, st) if st != SR_ST_OK => {
            // A refused smoke step is a real failure signal; stop.
            s.smoke_phase = SMOKE_DONE;
            dev_log(sys, 1, b"[sess_dir] smoke refused".as_ptr(), 24);
        }
        _ => {}
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI, `state` is valid and exclusively
    // borrowed; the syscall table is live.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 0) Proposal assignments — drained FIRST: raft emits the
        //    assignment (`[correlation:8][partition:2][wal_index:8]`)
        //    at flush time, strictly before the entry can commit, so
        //    processing assignments ahead of committed entries
        //    preserves that order within a step. The wal_index is the
        //    attribution the committed-entry pass matches on.
        if s.in_proposal_assigned >= 0 {
            for _ in 0..8 {
                let poll = (sys.channel_poll)(s.in_proposal_assigned, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 {
                    break;
                }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_proposal_assigned, &mut s.msg_buf);
                if msg_type != wire::MSG_PROPOSAL_ASSIGNED || (plen as usize) < 18 {
                    continue;
                }
                let corr = u64::from_le_bytes([
                    s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                    s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
                ]);
                let wal_index = u64::from_le_bytes([
                    s.msg_buf[10], s.msg_buf[11], s.msg_buf[12], s.msg_buf[13],
                    s.msg_buf[14], s.msg_buf[15], s.msg_buf[16], s.msg_buf[17],
                ]);
                for i in 0..MAX_PENDING {
                    if s.pending_used[i] && s.pending_corr[i] == corr {
                        s.pending_idx[i] = wal_index;
                        break;
                    }
                }
            }
        }

        // 1) Committed entries — apply in strict order, reply on match.
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_entries, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) =
                wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
            if msg_type != wire::MSG_COMMITTED_ENTRY {
                continue;
            }
            let plen = plen as usize;
            match s.subscriber.ingest_committed_entry(&s.msg_buf[..plen]) {
                Ok(entry) => {
                    // Copy the command out of msg_buf so apply can
                    // borrow module state freely.
                    let mut cmd = [0u8; 2 + SR_MAX_CMD];
                    let n = entry.command.len().min(cmd.len());
                    cmd[..n].copy_from_slice(&entry.command[..n]);
                    let index = entry.index;
                    apply_committed(s, index, &cmd[..n]);
                }
                Err(CommitOrderError::GapInPerEntryStream { .. }) => {
                    s.stream_gaps = s.stream_gaps.saturating_add(1);
                    dev_log(sys, 2, b"[sess_dir] gap".as_ptr(), 14);
                    // Recovery is a snapshot install (below).
                }
                Err(_) => {
                    dev_log(sys, 2, b"[sess_dir] bad entry".as_ptr(), 20);
                }
            }
        }

        // 2) Requests — propose each as a tagged raft entry. When the
        //    pending table is full the frame stays in the channel for
        //    the next step; a full proposal ring drops the consumed
        //    request (see the note at the propose() call below).
        if s.in_requests >= 0 {
            for _ in 0..4 {
                let has_free = s.pending_used.iter().any(|u| !u);
                if !has_free {
                    break;
                }
                let poll = (sys.channel_poll)(s.in_requests, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 {
                    break;
                }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
                if msg_type != wire::MSG_SR_REQUEST {
                    continue;
                }
                let plen = plen as usize;
                if plen <= 8 || plen > 8 + SR_MAX_CMD {
                    continue;
                }
                s.requests_in = s.requests_in.saturating_add(1);
                let request_id = u64::from_le_bytes([
                    s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                    s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
                ]);
                let mut body = [0u8; SR_MAX_CMD];
                let blen = plen - 8;
                body[..blen].copy_from_slice(&s.msg_buf[8..plen]);
                // A request that cannot be proposed right now is
                // DROPPED here (we already consumed the frame) — the
                // requester retries on reply timeout. Dropping beats
                // wedging the ring.
                let _ = propose(s, request_id, &body[..blen]);
            }
        }

        // 3) Smoke kick-off: propose the BIND once the proposal ring
        //    is writable (leadership settles behind it; the proposal
        //    simply commits when the group is ready).
        if s.smoke_phase == SMOKE_IDLE {
            let mut cmd = [0u8; SR_MAX_CMD];
            let n = build_bind(
                &mut cmd,
                &SMOKE_SID,
                1,
                &SMOKE_ANCHOR,
                &SMOKE_WORKER,
                SR_BIND_FENCE_REQUIRED,
            );
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_BIND_SENT;
                dev_log(sys, 3, b"[sess_dir] smoke bind sent".as_ptr(), 26);
            }
        }

        // 3.5) Timing smoke: arm the TTL'd key once duration admission
        //      passes the freshness barrier (retries every step).
        if s.smoke_phase == SMOKE_KEY_ARM && ensure_time_fresh(s) {
            let mut cmd = [0u8; SR_MAX_CMD];
            let n = build_key_put(&mut cmd, &SMOKE_SID, 1, SMOKE_KEY_TTL_MS, b"smoke-key");
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_KEY_SENT;
                dev_log(sys, 3, b"[sess_dir] smoke key sent".as_ptr(), 25);
            }
        }

        // 4) Snapshot install (catch-up path).
        if s.in_snapshot_chunk >= 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_snapshot_chunk, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 {
                    break;
                }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_snapshot_chunk, &mut s.msg_buf);
                let pl = plen as usize;
                match msg_type {
                    wire::MSG_APP_SNAPSHOT_RESET => {
                        s.snap_in_off = 0;
                    }
                    wire::MSG_APP_SNAPSHOT_CHUNK => {
                        if let Some((_term, last_idx, off, done, hdr)) =
                            wire::decode_app_snapshot_chunk(&s.msg_buf[..pl])
                        {
                            let body_len = pl - hdr;
                            let off = off as usize;
                            if off == s.snap_in_off as usize
                                && off + body_len <= SessionRegistry::SNAPSHOT_LEN
                            {
                                s.snap_buf[off..off + body_len]
                                    .copy_from_slice(&s.msg_buf[hdr..pl]);
                                s.snap_in_off = (off + body_len) as u32;
                                if done {
                                    if s.snap_in_off as usize
                                        == SessionRegistry::SNAPSHOT_LEN
                                        && s.registry.restore(&s.snap_buf)
                                    {
                                        s.subscriber = CommittedSubscriber::new(last_idx);
                                        dev_log(
                                            sys, 3,
                                            b"[sess_dir] snapshot installed".as_ptr(), 29,
                                        );
                                    } else {
                                        dev_log(
                                            sys, 1,
                                            b"[sess_dir] snapshot corrupt".as_ptr(), 27,
                                        );
                                    }
                                    s.snap_in_off = 0;
                                }
                            } else {
                                // Out-of-order chunk: abandon this install.
                                s.snap_in_off = 0;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 5) Snapshot export on request. The registry state is small
        //    enough to serialize and stream inline in one step.
        if s.in_snapshot_request >= 0 && s.out_snapshot_export >= 0 {
            let poll = (sys.channel_poll)(s.in_snapshot_request, 0x01);
            if poll > 0 && (poll as u32 & 0x01) != 0 {
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_snapshot_request, &mut s.msg_buf);
                if msg_type == wire::MSG_APP_SNAPSHOT_REQUEST && (plen as usize) >= 16 {
                    let (term, last_idx) = wire::decode_term_index(&s.msg_buf);
                    if s.registry.snapshot(&mut s.snap_buf) > 0 {
                        let total = SessionRegistry::SNAPSHOT_LEN;
                        let mut off = 0usize;
                        let mut ok = true;
                        while off < total && ok {
                            let n = SNAP_CHUNK.min(total - off);
                            let done = off + n == total;
                            let mut out = [0u8; wire::APP_SNAPSHOT_HDR + SNAP_CHUNK];
                            let en = wire::encode_app_snapshot_chunk(
                                &mut out,
                                term,
                                last_idx,
                                off as u64,
                                done,
                                &s.snap_buf[off..off + n],
                            );
                            ok = en > 0
                                && wire_channels::channel_write_msg(
                                    sys,
                                    s.out_snapshot_export,
                                    wire::MSG_APP_SNAPSHOT_CHUNK,
                                    &out[..en],
                                ) > 0;
                            off += n;
                        }
                    }
                }
            }
        }

        // 5.5) Leader hints — the fence for the time producer.
        if s.in_leader_state >= 0 {
            for _ in 0..8 {
                let poll = (sys.channel_poll)(s.in_leader_state, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 {
                    break;
                }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_leader_state, &mut s.msg_buf);
                if msg_type == wire::MSG_LEADER_HINT && plen >= 1 {
                    s.leader_id = s.msg_buf[0];
                }
            }
        }

        // 5.6) Deterministic time production (leader-fenced,
        //      rfc_deterministic_timing.md §5, §10). Only the current
        //      leader samples wall time and proposes TimeAdvance /
        //      TimeDrain; an idle index proposes nothing (idle
        //      coalescing); an unhealthy clock makes deadlines late
        //      rather than firing from an untrusted source.
        if !is_leader(s) {
            s.pause_reason = wire::TIMING_PAUSE_NOT_LEADER;
            s.last_unix_ms = 0;
        } else {
            let mono = dev_millis(sys);
            let unix = dev_unix_millis(sys);
            s.last_unix_ms = unix;
            let health = s.clock_guard.sample(mono, unix);
            let logical = s.registry.timing.logical_now_ms();
            if health != ClockHealth::Healthy {
                s.pause_reason = wire::TIMING_PAUSE_CLOCK_ALARM;
            } else if s.registry.timing.due_depth() > 0 {
                // Committed due backlog: continue with drain entries
                // through the already-committed time fence. Advancing
                // pauses so due work stays within apply budgets.
                s.pause_reason = wire::TIMING_PAUSE_DRAIN_BACKLOG;
                if mono.wrapping_sub(s.last_drain_propose_ms) >= 50 {
                    let mut body = [0u8; wire::TIMING_ENTRY_LEN];
                    let n = wire::encode_time_entry(&mut body, wire::TIMING_OP_DRAIN, logical);
                    if n > 0 && propose_raw(s, &body[..n]) {
                        s.last_drain_propose_ms = mono;
                    }
                }
            } else if s.registry.timing.live > 0 {
                s.pause_reason = wire::TIMING_PAUSE_NONE;
                if mono.wrapping_sub(s.last_advance_propose_ms)
                    >= s.time_advance_period_ms as u64
                {
                    if let Some(t) = s.clock_guard.propose_time(logical, unix) {
                        let mut body = [0u8; wire::TIMING_ENTRY_LEN];
                        let n =
                            wire::encode_time_entry(&mut body, wire::TIMING_OP_ADVANCE, t);
                        if n > 0 && propose_raw(s, &body[..n]) {
                            s.last_advance_propose_ms = mono;
                        }
                    }
                }
            } else {
                // No live deadlines: idle tick coalescing (§5.2).
                s.pause_reason = wire::TIMING_PAUSE_IDLE;
            }
        }

        // 6) Heartbeat metrics.
        let now = dev_millis(sys);
        if now.wrapping_sub(s.last_metrics_ms) >= 1000 && s.out_metrics >= 0 {
            s.last_metrics_ms = now;
            let mut buf = [0u8; 32];
            buf[0..8].copy_from_slice(&s.subscriber.cursor().to_le_bytes());
            buf[8..12].copy_from_slice(&s.applied_ok.to_le_bytes());
            buf[12..16].copy_from_slice(&s.applied_rejected.to_le_bytes());
            buf[16..20].copy_from_slice(&s.requests_in.to_le_bytes());
            buf[20..24].copy_from_slice(&s.replies_out.to_le_bytes());
            buf[24..28].copy_from_slice(&s.stream_gaps.to_le_bytes());
            buf[28..32].copy_from_slice(&s.registry.recovery_epoch.to_le_bytes());
            let poll = (sys.channel_poll)(s.out_metrics, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf);
            }

            // Typed timing series for /metrics export
            // (rfc_deterministic_timing.md §16).
            let logical = s.registry.timing.logical_now_ms();
            let lag = if is_leader(s) && s.last_unix_ms > 0 {
                s.last_unix_ms.saturating_sub(logical)
            } else {
                0
            };
            let samples: [(u16, u8, i64); 9] = [
                (
                    wire::metric_ids::TIMING_LOGICAL_TIME_MS,
                    wire::METRIC_KIND_GAUGE,
                    logical as i64,
                ),
                (
                    wire::metric_ids::TIMING_LOGICAL_LAG_MS,
                    wire::METRIC_KIND_GAUGE,
                    lag as i64,
                ),
                (
                    wire::metric_ids::TIMING_ADVANCE_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.time_advance_applied as i64,
                ),
                (
                    wire::metric_ids::TIMING_DRAIN_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.time_drain_applied as i64,
                ),
                (
                    wire::metric_ids::TIMING_DEADLINES_ACTIVE,
                    wire::METRIC_KIND_GAUGE,
                    s.registry.timing.live as i64,
                ),
                (
                    wire::metric_ids::TIMING_DUE_DEPTH,
                    wire::METRIC_KIND_GAUGE,
                    s.registry.timing.due_depth() as i64,
                ),
                (
                    wire::metric_ids::TIMING_FIRED_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.registry.deadlines_fired as i64,
                ),
                (
                    wire::metric_ids::TIMING_NOOP_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.registry.deadline_noop as i64,
                ),
                (
                    wire::metric_ids::TIMING_PAUSE_REASON,
                    wire::METRIC_KIND_GAUGE,
                    s.pause_reason as i64,
                ),
            ];
            for (metric_id, kind, value) in samples {
                let poll = (sys.channel_poll)(s.out_metrics, 0x02);
                if poll <= 0 || (poll as u32 & 0x02) == 0 {
                    break;
                }
                let mut mb = [0u8; wire::METRIC_SAMPLE_LEN];
                wire::encode_metric_sample(
                    &mut mb,
                    wire::SOURCE_ID_TIMING,
                    0,
                    metric_id,
                    kind,
                    value,
                );
                wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &mb);
            }
        }

        0
    }
}

