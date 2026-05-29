//! Raft Engine — Core Raft consensus state machine.
//!
//! Implements leader election (with pre-vote), log replication dispatch,
//! proposal batching, and heartbeat generation. Role-dependent step logic
//! drives the follower/candidate/leader state machine.

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

#[path = "../../common/types.rs"]
mod types;

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use types::*;

const PROPOSAL_BATCH_CAP: usize = 2048;

/// Per-batch correlation slot count. The slot is set non-zero only for
/// proposals that arrived via the tagged port; legacy proposals from the
/// untagged port leave the slot zero and produce no MSG_PROPOSAL_ASSIGNED.
const MAX_BATCH_PROPOSALS: usize = 256;

/// In-flight strict-ReadIndex probes the leader tracks at once. Each
/// probe is consumed in two ticks (broadcast then quorum + reply) so
/// 8 is enough for a per-second read rate well into the thousands.
const MAX_INFLIGHT_PROBES: usize = 8;

/// How long a strict-ReadIndex probe may wait for majority replies
/// before we give up and answer the read with fallback. Sized to the
/// election-timeout floor so a slow follower can't trick us.
const PROBE_TIMEOUT_MS: u64 = 1500;

#[derive(Clone, Copy)]
#[repr(C)]
struct ProbeSlot {
    /// 0 = slot empty.
    probe_id: u64,
    /// The apply_pipeline-side correlation id we'll echo back.
    correlation_id: u64,
    /// commit_index sampled at the moment the probe was issued.
    snapshot_commit: u64,
    /// Term of the probe (so stale replies after a leader change get dropped).
    term: u64,
    /// Replicas that have confirmed our leadership (includes self).
    votes: NodeSet,
    /// Wall-clock deadline; if we don't reach majority by then we
    /// reply with confirmed=0.
    deadline_ms: u64,
}

impl ProbeSlot {
    const fn empty() -> Self {
        Self {
            probe_id: 0,
            correlation_id: 0,
            snapshot_commit: 0,
            term: 0,
            votes: NodeSet::empty(),
            deadline_ms: 0,
        }
    }
}

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, voter_count, u8, 1
        => |s, d, len| { s.voter_count = p_u8(d, len, 0, 1); };

    3, election_timeout_ms, u16, 1000
        => |s, d, len| { s.election_timeout_ms = p_u16(d, len, 0, 1000); };

    4, heartbeat_interval_ms, u16, 150
        => |s, d, len| { s.heartbeat_interval_ms = p_u16(d, len, 0, 150); };

    // Parsed for compatibility with existing configs, but currently
    // forced to 1 in module_new so one proposal maps to one log index.
    // Multi-proposal batching can return once apply responses carry a
    // per-proposal sub-index or correlation id.
    5, proposal_batch_max, u16, 64
        => |s, d, len| { s.proposal_batch_max = p_u16(d, len, 0, 64); };

    6, proposal_batch_timeout_ms, u16, 10
        => |s, d, len| { s.proposal_batch_timeout_ms = p_u16(d, len, 0, 10); };

    // Partition slot for multi-Raft graphs. Default 0 means "single
    // partition / legacy graph"; per-partition instances set this to
    // their slot id and it drives the persistent metadata path
    // (raft/p<id>/meta). See .context/rfc_partition_groups.md.
    7, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };
}

// FS opcodes
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
const FS_SEEK: u32 = 0x0902;

// Metadata file path scheme (RFC partition_groups):
//   single-partition graphs (partition_id = 0):  raft/meta
//   per-partition graphs   (partition_id = N>0): raft/p<NNNN>/meta
// Width is enough for u16; we'll never have more than 65k partitions
// per node and the volatile-FS provider keys files by hash of path.
//
// Format: [term: u64] [voted_for: i8] [last_log_index: u64] [last_log_term: u64] = 25 bytes
/// Layout (28 bytes):
///   `[current_term:u64][voted_for:i8][last_log_index:u64]
///    [last_log_term:u64][current_voters:u8][joint_voters:u8]
///    [joint_active:u8]`
const META_SIZE: usize = 28;
const META_PATH_MAX: usize = 32;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // ── Channels (4 in, 4 out) ──────────────────────────────
    in_rpc: i32,                          // in[0]: RPC from peers (via client_surface)
    in_proposals: i32,                    // in[1]: ClientProposal from throttle_gate (legacy, untagged)
    in_admin: i32,                        // in[2]: AdminCommand from admin_handler
    in_fallback: i32,                     // in[3]: FallbackSignal from cp_proof_cache
    in_proposals_tagged: i32,             // in[4]: ClientProposal with 8-byte correlation_id prefix
    in_proposals_partitioned: i32,        // in[5]: ClientProposal in 5-byte partitioned envelope
    in_proposals_partitioned_tagged: i32, // in[6]: partitioned + correlation_id (from partition_router tagged path)
    in_commit: i32,                       // in[7]: MSG_COMMITTED_BATCH from commit_tracker (leader path)
    in_snapshot_installed: i32,           // in[8]: MSG_SNAPSHOT_INSTALLED from snapshot_engine
    in_read_probe: i32,                   // in[9]: MSG_READ_PROBE_REQ from apply_pipeline
    in_admin_committed: i32,              // in[10]: MSG_ADMIN_COMMITTED from apply_pipeline (§3.1)
    in_wal_flushed: i32,                  // in[11]: MSG_FSYNC_ACK from local wal.flushed (spec §10.4.1)
    out_append: i32,                      // out[0]: AppendEntries to replicator
    out_rpc: i32,                         // out[1]: Vote/Heartbeat RPC to peer_router
    out_log: i32,                         // out[2]: WalEntry to wal
    out_metrics: i32,                     // out[3]: MetricsPayload to telemetry_agg
    out_proposal_assigned: i32,           // out[4]: MSG_PROPOSAL_ASSIGNED back to proposer
    out_log_observe: i32,                 // out[5]: WalEntry fanout to observers (apply_pipeline)
    out_leader_state: i32,                // out[6]: MSG_LEADER_HINT (leader_id, term)
    out_admin_applied: i32,               // out[7]: MSG_ADMIN_APPLIED back to admin_handler
    out_commit_advanced: i32,             // out[8]: MSG_COMMITTED_BATCH for follower commit advances
    out_read_probe_reply: i32,            // out[9]: MSG_READ_PROBE_REPLY to apply_pipeline
    out_wal_compact: i32,                 // out[10]: MSG_WAL_COMPACT_BEFORE to wal after snapshot install
    out_voter_set: i32,                   // out[11]: MSG_VOTER_SET_UPDATE to commit_tracker / durability_ledger

    // ── Partition slot (multi-Raft) ─────────────────────────
    // 0 for single-partition / legacy graphs. Drives META path and
    // is exposed in metrics so cross-partition logs are
    // disambiguable.
    partition_id: u16,

    // ── Raft persistent state ───────────────────────────────
    current_term: Term,
    voted_for: i8,            // -1 = none, 0..6 = replica id
    self_id: ReplicaId,

    // ── Volatile state ──────────────────────────────────────
    role: u8,                 // ROLE_FOLLOWER / CANDIDATE / LEADER
    leader_id: i8,            // -1 = unknown
    voter_count: u8,

    /// Current Raft voter set. Initially populated from
    /// `voter_count` (ids 0..voter_count). Updated as committed
    /// `CONFIG_CHANGE` entries flow through `drain_config_committed`.
    /// See RFC §1.2.
    current_voters: NodeSet,
    /// Joint-consensus transition set. `Some` only while a
    /// `C_old,new` entry has been committed and `C_new` has not yet.
    /// While `Some`, quorum requires majority over BOTH `current`
    /// and `joint` sets.
    joint_voters: NodeSet,
    /// True iff `joint_voters` is the active overlay (so we don't
    /// have to encode "Some via a sentinel" inside a NodeSet bitmask).
    joint_active: bool,
    /// Log index of the most recently committed config-change entry.
    /// Used to suppress duplicate apply on log replay.
    last_config_index: Index,
    /// Set on a leader once a `CONFIG_CHANGE_OP_JOINT` entry commits;
    /// the next `step_leader` tick auto-proposes the matching
    /// `CONFIG_CHANGE_OP_NEW` entry to complete the joint-consensus
    /// transition. Cleared after the proposal is emitted. RFC §1.2.
    pending_new_voters: NodeSet,
    pending_new_voters_set: bool,
    /// Learner mode (RFC §1.2): this replica is not in the current
    /// voter set — typically because a `CONFIG_CHANGE_OP_NEW` committed
    /// that removed `self_id`. While in learner mode the node still
    /// replicates the log and serves reads, but does NOT trigger
    /// election timeouts or grant votes. The flag clears if a later
    /// config change re-adds the node to the voter set.
    learner_mode: bool,

    // ── Election ────────────────────────────────────────────
    election_timeout_ms: u16,
    election_deadline_ms: u64,
    heartbeat_interval_ms: u16,
    last_heartbeat_ms: u64,
    votes_granted: NodeSet,
    votes_rejected: NodeSet,
    pre_vote_active: bool,

    // ── Log tracking ────────────────────────────────────────
    last_log_index: Index,
    last_log_term: Term,
    commit_index: Index,

    /// Replica-local WAL-durable watermark (spec §10.4.1
    /// `local_wal_durable_index`). Tracked from MSG_FSYNC_ACK on the
    /// local `wal.flushed` port. On followers, this value is stamped
    /// into every AppendEntriesResponse so the leader's
    /// `durability_ledger` can compute quorum-fsync durability across
    /// replicas without each follower owning a peer-bound side
    /// channel.
    local_durable_index: Index,

    // ── Proposal batching ───────────────────────────────────
    proposal_batch: [u8; PROPOSAL_BATCH_CAP],
    proposal_batch_len: u16,
    proposal_batch_count: u16,
    proposal_batch_max: u16,
    proposal_batch_start_ms: u64,
    proposal_batch_timeout_ms: u16,

    /// Parallel array indexed [0..proposal_batch_count). 0 means the
    /// proposal was untagged (no MSG_PROPOSAL_ASSIGNED to emit). Non-zero
    /// is the per-proposal correlation_id supplied by the proposer on the
    /// tagged input port.
    correlation_ids: [u64; MAX_BATCH_PROPOSALS],

    // ── Strict fallback ─────────────────────────────────────
    strict_fallback: bool,

    // ── In-flight strict-ReadIndex probes ───────────────────
    probes: [ProbeSlot; MAX_INFLIGHT_PROBES],
    next_probe_id: u64,

    // ── Admin-induced state (RFC §14) ───────────────────────
    /// Set by `ADMIN_OP_FREEZE`; cleared by `ADMIN_OP_THAW`. While
    /// frozen, the proposal-intake paths drop new client proposals
    /// silently (client times out via `client_codec` retry). Existing
    /// in-flight entries continue to replicate.
    frozen: bool,
    /// Cluster-wide durability mode hint (Strict=0 / GroupFsync=1 / Relaxed=2).
    /// Currently informational — not yet plumbed through `commit_tracker`.
    durability_mode: u8,
    /// When non-zero, target of a pending `TimeoutNow` leadership
    /// transfer. The leader emits MSG_TIMEOUT_NOW once it next reaches
    /// the heartbeat path, then clears this slot.
    pending_transfer_to: u8,

    // ── Metrics ─────────────────────────────────────────────
    proposals_received: u32,
    entries_appended: u32,
    elections_started: u32,
    /// Proposals dropped because ADMIN_OP_FREEZE is in effect.
    proposals_dropped_frozen: u32,
    /// Proposals dropped because `strict_fallback` is in effect
    /// (CP-cache lost or expired). Distinct from the frozen counter so
    /// operators can tell admin freeze vs control-plane fallback apart.
    proposals_dropped_strict: u32,
    last_metrics_ms: u64,

    // ── Leader-state hint ───────────────────────────────────
    // Last (leader_id, term) we broadcast on `leader_state`. Re-emit
    // only on change so the channel doesn't burn cycles on steady
    // state. -2 means "never broadcast yet".
    last_hint_leader_id: i8,
    last_hint_term: Term,

    // ── Scratch ─────────────────────────────────────────────
    msg_buf: [u8; 2048],
}

// ── Simple PRNG for election jitter (xorshift32) ────────────
fn xorshift32(state: &mut u32) -> u32 {
    let mut x = *state;
    if x == 0 { x = 0xDEAD_BEEF; }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
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

        // Channel bindings
        s.in_rpc = in_chan;
        s.out_append = out_chan;
        s.in_proposals = dev_channel_port(sys, 0, 1);
        s.in_admin = dev_channel_port(sys, 0, 2);
        s.in_fallback = dev_channel_port(sys, 0, 3);
        s.in_proposals_tagged = dev_channel_port(sys, 0, 4);
        s.in_proposals_partitioned = dev_channel_port(sys, 0, 5);
        s.in_proposals_partitioned_tagged = dev_channel_port(sys, 0, 6);
        s.in_commit = dev_channel_port(sys, 0, 7);
        s.in_snapshot_installed = dev_channel_port(sys, 0, 8);
        s.in_read_probe = dev_channel_port(sys, 0, 9);
        s.in_admin_committed = dev_channel_port(sys, 0, 10);
        s.in_wal_flushed = dev_channel_port(sys, 0, 11);
        s.out_rpc = dev_channel_port(sys, 1, 1);
        s.out_log = dev_channel_port(sys, 1, 2);
        s.out_metrics = dev_channel_port(sys, 1, 3);
        s.out_proposal_assigned = dev_channel_port(sys, 1, 4);
        s.out_log_observe = dev_channel_port(sys, 1, 5);
        s.out_leader_state = dev_channel_port(sys, 1, 6);
        s.out_admin_applied = dev_channel_port(sys, 1, 7);
        s.out_commit_advanced = dev_channel_port(sys, 1, 8);
        s.out_read_probe_reply = dev_channel_port(sys, 1, 9);
        s.out_wal_compact = dev_channel_port(sys, 1, 10);
        s.out_voter_set = dev_channel_port(sys, 1, 11);
        s.probes = [ProbeSlot::empty(); MAX_INFLIGHT_PROBES];
        s.next_probe_id = 1;
        s.current_voters = NodeSet::empty();
        s.joint_voters = NodeSet::empty();
        s.joint_active = false;
        s.last_config_index = 0;
        s.pending_new_voters = NodeSet::empty();
        s.pending_new_voters_set = false;
        s.learner_mode = false;
        s.last_hint_leader_id = -2;
        s.last_hint_term = 0;
        s.frozen = false;
        s.durability_mode = 0;
        s.pending_transfer_to = 0;

        // Defaults + TLV param parsing
        s.voted_for = REPLICA_NONE as i8;
        s.leader_id = REPLICA_NONE as i8;
        s.role = ROLE_FOLLOWER;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // `voter_count` is operator-supplied; clamp here so the
        // initial-voter loop below and every later `quorum_index`
        // path is slice-safe even on a typo'd cluster config.
        if (s.voter_count as usize) > MAX_NODES {
            s.voter_count = MAX_NODES as u8;
        }

        // Until the public response path carries per-proposal sub-indexes,
        // one proposal must map to exactly one log index. Otherwise several
        // correlation_ids can be assigned the same wal_index and client_codec
        // cannot route successful apply responses without ambiguity.
        s.proposal_batch_max = 1;

        // Initial voter set (RFC §1.2). `voter_count` came from
        // parse_tlv just above; seed `current_voters` with ids
        // 0..voter_count. Joint state is inactive at startup; it
        // activates only when a `CONFIG_CHANGE_OP_JOINT` entry
        // commits via `drain_admin_committed`.
        for i in 0..s.voter_count {
            s.current_voters.insert(i);
        }
        // Broadcast initial voter set once everything is wired.
        // (Channels may still be -1 at this point; emit_voter_set
        // tolerates that.)
        // The emission itself happens in the first step() call.

        // Restore persistent state from metadata file
        load_metadata(s, sys);

        // Set initial election deadline
        let now = dev_millis(sys);
        s.election_deadline_ms = now + s.election_timeout_ms as u64;
        s.last_heartbeat_ms = now;

        dev_log(sys, 3, b"[raft] init".as_ptr(), 11);
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

        // 1. Process inbound RPCs (all roles)
        process_rpc(s, sys, now);

        // 2. Process fallback signal
        drain_fallback(s, sys);

        // 3. Process admin commands (local effects only — see RFC §14)
        drain_admin(s, sys, now);

        // 3a. Absorb quorum-commit feedback from commit_tracker so the
        //     leader's heartbeats/AEs carry the right `leader_commit`.
        drain_commit_in(s, sys);

        // 3b. Process snapshot install completions from snapshot_engine.
        drain_snapshot_installed(s, sys);

        // 3c. Drain strict-ReadIndex probe requests from apply_pipeline
        //     and time-out any probes that didn't reach majority.
        drain_read_probes(s, sys, now);
        expire_probes(s, sys, now);

        // 3d. Apply committed admin entries (RFC §3.1). On every
        //     replica, when a Raft-replicated admin entry passes commit,
        //     apply_pipeline echoes the body here and we run the op.
        drain_admin_committed(s, sys);

        // 3e. Track local WAL fsync acks so followers can stamp their
        //     `local_wal_durable_index` into every AppendEntriesResponse
        //     (spec §10.4.1). Cheap drain — leader and follower both
        //     run it but only the follower's value flows over the wire.
        drain_wal_flushed(s, sys);

        // 4. Role-specific logic
        match s.role {
            ROLE_FOLLOWER => step_follower(s, sys, now),
            ROLE_CANDIDATE => step_candidate(s, sys, now),
            ROLE_LEADER => step_leader(s, sys, now),
            _ => {}
        }

        // 5. If we're stepping down via leader transfer, fire TimeoutNow.
        emit_timeout_now_if_pending(s, sys);

        // 6. Emit metrics periodically
        emit_metrics(s, sys, now);

        // 7. Broadcast a leader-state hint on every change so client_codec
        //    can short-circuit non-leader proposals with CLIENT_REJECT_NOT_LEADER.
        emit_leader_hint(s, sys);

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_leader_hint(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_leader_state < 0 { return; }
    if s.leader_id == s.last_hint_leader_id && s.current_term == s.last_hint_term {
        return;
    }
    let poll = (sys.channel_poll)(s.out_leader_state, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 9];
    buf[0] = if s.leader_id < 0 { 0xFFu8 } else { s.leader_id as u8 };
    buf[1..9].copy_from_slice(&s.current_term.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_leader_state, wire::MSG_LEADER_HINT, &buf);
    s.last_hint_leader_id = s.leader_id;
    s.last_hint_term = s.current_term;
}

// ── RPC processing (all roles) ──────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_rpc(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // Process up to 8 RPCs per step to bound step time. Inbound shape is
    // the 5-byte partitioned envelope (`[partition_id:u16 LE][msg_type:u8]
    // [len:u16 LE]`); peer_router fans the channel out to every per-
    // partition raft_engine and each instance filters by its own
    // partition_id, so cross-partition RPCs from peers (and stray
    // client_surface frames stamped with the wrong partition) are dropped
    // here.
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_rpc, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (partition_id, msg_type, plen) =
            wire_channels::channel_read_partitioned(sys, s.in_rpc, &mut s.msg_buf);
        if plen == 0 && msg_type == 0 { break; }
        if partition_id != s.partition_id { continue; }

        match msg_type {
            wire::MSG_REQUEST_VOTE | wire::MSG_PRE_VOTE => {
                dev_log(sys, 3, b"[raft] rv in".as_ptr(), 12);
                handle_vote_request(s, sys, msg_type, plen);
            }
            wire::MSG_REQUEST_VOTE_RESP | wire::MSG_PRE_VOTE_RESP => {
                dev_log(sys, 3, b"[raft] rv resp".as_ptr(), 14);
                handle_vote_response(s, sys, msg_type, plen);
            }
            wire::MSG_APPEND_ENTRIES => {
                handle_append_entries(s, sys, plen, now);
            }
            wire::MSG_APPEND_ENTRIES_RESP => {
                // Handled by replicator, not raft_engine. Shouldn't arrive here
                // but ignore gracefully.
            }
            wire::MSG_TIMEOUT_NOW => {
                handle_timeout_now(s, sys, plen, now);
            }
            wire::MSG_READ_INDEX_PROBE => {
                handle_read_index_probe(s, sys, plen);
            }
            wire::MSG_READ_INDEX_PROBE_RESP => {
                handle_read_index_probe_resp(s, sys, plen);
            }
            _ => {}
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_read_index_probe(s: &mut ModuleState, sys: &SyscallTable, plen: u16) {
    let pl = plen as usize;
    let (probe_id, term) = match wire::decode_read_index_probe(&s.msg_buf[..pl]) {
        Some(v) => v,
        None => return,
    };
    // A follower acknowledges the probe iff the caller's term is at
    // least our own term. If it's higher, we step down — same rule as
    // for AE. A stale probe (term < ours) is dropped silently.
    if term > s.current_term {
        become_follower(s, term);
    }
    if term < s.current_term { return; }
    if s.out_rpc < 0 { return; }
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut resp = [0u8; 17];
    wire::encode_read_index_probe_resp(&mut resp, probe_id, s.current_term, s.self_id);
    let target = if s.leader_id >= 0 { s.leader_id as u8 } else { wire::TARGET_BROADCAST };
    wire_channels::channel_write_routed_partitioned(
        sys, s.out_rpc, target, s.partition_id,
        wire::MSG_READ_INDEX_PROBE_RESP, &resp,
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_read_index_probe_resp(s: &mut ModuleState, sys: &SyscallTable, plen: u16) {
    if s.role != ROLE_LEADER { return; }
    let pl = plen as usize;
    let (probe_id, term, replica) =
        match wire::decode_read_index_probe_resp(&s.msg_buf[..pl]) {
            Some(v) => v,
            None => return,
        };
    if term > s.current_term {
        become_follower(s, term);
        return;
    }
    if (replica as usize) >= MAX_NODES { return; }
    let majority = (s.voter_count / 2) + 1;
    for i in 0..MAX_INFLIGHT_PROBES {
        let probe_id_slot = s.probes[i].probe_id;
        if probe_id_slot == 0 || probe_id_slot != probe_id { continue; }
        if s.probes[i].term != s.current_term { continue; }
        s.probes[i].votes.insert(replica);
        let count = s.probes[i].votes.count();
        if count >= majority {
            let corr = s.probes[i].correlation_id;
            let commit = s.probes[i].snapshot_commit;
            emit_read_probe_reply(s, sys, corr, commit, true);
            s.probes[i] = ProbeSlot::empty();
        }
        return;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_probes(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.in_read_probe < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_read_probe, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_read_probe, &mut s.msg_buf);
        if msg_type != wire::MSG_READ_PROBE_REQ || (plen as usize) < 8 { continue; }
        let correlation_id = u64::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
        ]);
        if correlation_id == 0 { continue; }
        start_probe(s, sys, correlation_id, now);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn start_probe(
    s: &mut ModuleState,
    sys: &SyscallTable,
    correlation_id: u64,
    now: u64,
) {
    // Not the leader: immediately reply with confirmed=0 so the apply
    // pipeline can fall back to rejecting the read.
    if s.role != ROLE_LEADER {
        emit_read_probe_reply(s, sys, correlation_id, 0, false);
        return;
    }
    // Allocate an empty slot.
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in s.probes.iter().enumerate() {
        if slot.probe_id == 0 { slot_idx = Some(i); break; }
    }
    let slot_idx = match slot_idx {
        Some(i) => i,
        None => {
            // Probe table full — reply with confirmed=0, caller retries.
            emit_read_probe_reply(s, sys, correlation_id, 0, false);
            return;
        }
    };
    let probe_id = s.next_probe_id;
    s.next_probe_id = s.next_probe_id.wrapping_add(1).max(1);
    let mut votes = NodeSet::empty();
    votes.insert(s.self_id);

    s.probes[slot_idx] = ProbeSlot {
        probe_id,
        correlation_id,
        snapshot_commit: s.commit_index,
        term: s.current_term,
        votes,
        deadline_ms: now + PROBE_TIMEOUT_MS,
    };

    // Single-node cluster: we already have majority (self).
    let majority = (s.voter_count / 2) + 1;
    if votes.count() >= majority {
        emit_read_probe_reply(s, sys, correlation_id, s.commit_index, true);
        s.probes[slot_idx] = ProbeSlot::empty();
        return;
    }

    // Broadcast the probe to all peers via routed broadcast.
    if s.out_rpc < 0 { return; }
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 16];
    wire::encode_read_index_probe(&mut buf, probe_id, s.current_term);
    wire_channels::channel_write_routed_partitioned(
        sys, s.out_rpc, wire::TARGET_BROADCAST, s.partition_id,
        wire::MSG_READ_INDEX_PROBE, &buf,
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn expire_probes(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    for i in 0..MAX_INFLIGHT_PROBES {
        let slot = s.probes[i];
        if slot.probe_id == 0 { continue; }
        if now >= slot.deadline_ms {
            emit_read_probe_reply(s, sys, slot.correlation_id, 0, false);
            s.probes[i] = ProbeSlot::empty();
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_read_probe_reply(
    s: &ModuleState,
    sys: &SyscallTable,
    correlation_id: u64,
    confirmed_commit: u64,
    confirmed: bool,
) {
    if s.out_read_probe_reply < 0 { return; }
    let poll = (sys.channel_poll)(s.out_read_probe_reply, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 17];
    wire::encode_read_probe_reply(&mut buf, correlation_id, confirmed_commit, confirmed);
    wire_channels::channel_write_msg(
        sys, s.out_read_probe_reply, wire::MSG_READ_PROBE_REPLY, &buf,
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// React to a leader-transfer TimeoutNow: bump term immediately and
/// start an election. Drop stale requests where the sender's term is
/// behind ours.
unsafe fn handle_timeout_now(s: &mut ModuleState, sys: &SyscallTable, plen: u16, now: u64) {
    let plen = plen as usize;
    if plen < 8 { return; }
    let caller_term = u64::from_le_bytes([
        s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
        s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
    ]);
    if caller_term < s.current_term { return; }
    dev_log(sys, 3, b"[raft] timeout_now".as_ptr(), 18);
    // Force-start an election by advancing the deadline into the past
    // and clearing votes. The normal candidate path will pick up.
    s.election_deadline_ms = now;
    s.votes_granted.clear();
    s.votes_rejected.clear();
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Drain admin commands. Each command is
/// `[command_id:u32 LE][op_code:u8][op_body...]`. We apply the side
/// effect locally and emit MSG_ADMIN_APPLIED so admin_handler can route
/// the response back to the originating conn_id.
unsafe fn drain_snapshot_installed(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_snapshot_installed < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_snapshot_installed, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_snapshot_installed, &mut s.msg_buf);
        if msg_type != wire::MSG_SNAPSHOT_INSTALLED { continue; }
        let (term, last_idx, last_term) =
            match wire::decode_snapshot_installed(&s.msg_buf[..plen as usize]) {
                Some(t) => t,
                None => continue,
            };
        // Stale snapshot from an old term: ignore.
        if term < s.current_term { continue; }
        // Already at or past this snapshot point: nothing to do.
        if last_idx <= s.last_log_index { continue; }
        dev_log(sys, 3, b"[raft] snap install".as_ptr(), 19);
        s.last_log_index = last_idx;
        s.last_log_term = last_term;
        if last_idx > s.commit_index {
            s.commit_index = last_idx;
            // Mirror the follower-commit path so apply_pipeline learns
            // about the fast-forward and can drop any pending entries
            // below this index from its observer buffer.
            advance_follower_commit(s, sys, last_idx);
        }
        save_metadata(s, sys);
        // Emit the apply-pipeline reset (§2.3) and the WAL compact-before
        // signal (§2.2). Both are post-snapshot housekeeping; ignore
        // unwired ports.
        emit_apply_reset(s, sys, last_term, last_idx);
        emit_wal_compact_before(s, sys, last_idx);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_apply_reset(s: &ModuleState, sys: &SyscallTable, term: u64, index: u64) {
    if s.out_commit_advanced < 0 { return; }
    let poll = (sys.channel_poll)(s.out_commit_advanced, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 16];
    wire::encode_term_index(&mut buf, term, index);
    wire_channels::channel_write_msg(
        sys, s.out_commit_advanced, wire::MSG_APPLY_PIPELINE_RESET, &buf,
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_wal_compact_before(s: &ModuleState, sys: &SyscallTable, before_index: u64) {
    if s.out_wal_compact < 0 { return; }
    let poll = (sys.channel_poll)(s.out_wal_compact, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let buf = before_index.to_le_bytes();
    wire_channels::channel_write_msg(sys, s.out_wal_compact, wire::MSG_WAL_COMPACT_BEFORE, &buf);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_commit_in(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_commit < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_commit, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_commit, &mut s.msg_buf);
        if msg_type != wire::MSG_COMMITTED_BATCH || (plen as usize) < 16 { continue; }
        let (term, index) = wire::decode_term_index(&s.msg_buf);
        if index > s.commit_index {
            s.commit_index = index;
            if term > s.current_term {
                // Shouldn't happen on the leader path, but stay safe.
                s.current_term = term;
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_wal_flushed(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_wal_flushed < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_wal_flushed, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_wal_flushed, &mut s.msg_buf);
        if msg_type != wire::MSG_FSYNC_ACK || (plen as usize) < 17 { continue; }
        let (_term, index, _replica) = wire::decode_fsync_ack(&s.msg_buf);
        if index > s.local_durable_index {
            s.local_durable_index = index;
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_admin_committed(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_admin_committed < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_admin_committed, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_admin_committed, &mut s.msg_buf);
        let pl = plen as usize;
        match msg_type {
            wire::MSG_ADMIN_COMMITTED => {
                if pl < 5 {
                    continue;
                }
                let command_id = u32::from_le_bytes([
                    s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                ]);
                let op_code = s.msg_buf[4];
                let status = apply_admin_op(
                    s,
                    op_code,
                    &s.msg_buf as *const _ as *const u8,
                    pl,
                );
                emit_admin_applied(s, sys, command_id, status);
            }
            wire::MSG_CONFIG_COMMITTED => {
                apply_config_change(s, sys, pl);
            }
            _ => {}
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn apply_config_change(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    let (op_code, voters_off, voter_count) =
        match wire::decode_config_change(&s.msg_buf[..plen]) {
            Some(v) => v,
            None => return,
        };
    let mut new_set = NodeSet::empty();
    for i in 0..voter_count {
        let id = s.msg_buf[voters_off + i];
        if (id as usize) < MAX_NODES {
            new_set.insert(id);
        }
    }
    match op_code {
        wire::CONFIG_CHANGE_OP_JOINT => {
            // Enter joint state: keep current voters, layer new set
            // as joint. Subsequent quorum checks require both.
            s.joint_voters = new_set;
            s.joint_active = true;
            // RFC §1.2 completeness: the leader queues the C_new
            // proposal so the next `step_leader` tick emits it
            // automatically. Followers ignore this slot — they only
            // see the C_new entry once the leader replicates it.
            if s.role == ROLE_LEADER {
                s.pending_new_voters = new_set;
                s.pending_new_voters_set = true;
            }
        }
        wire::CONFIG_CHANGE_OP_NEW => {
            // Exit joint state: install new voters as current,
            // clear joint overlay. If our own id was removed from the
            // new set, step down to a non-voting follower AND enter
            // learner mode so we don't start elections or grant votes.
            s.current_voters = new_set;
            s.joint_voters = NodeSet::empty();
            s.joint_active = false;
            // Pending was satisfied by the entry we just applied.
            s.pending_new_voters = NodeSet::empty();
            s.pending_new_voters_set = false;
            if !s.current_voters.contains(s.self_id) {
                if s.role == ROLE_LEADER {
                    s.role = ROLE_FOLLOWER;
                    s.leader_id = -1;
                }
                s.learner_mode = true;
                dev_log(sys, 3, b"[raft] removed self".as_ptr(), 19);
            } else {
                // Re-added after a previous removal: clear learner
                // mode so the node re-enters normal election
                // participation on the next tick.
                if s.learner_mode {
                    s.learner_mode = false;
                    dev_log(sys, 3, b"[raft] re-added".as_ptr(), 15);
                }
            }
        }
        _ => return,
    }
    // Push new voter_count to local quorum logic plus downstream
    // (commit_tracker / durability_ledger) so AE-quorum tracking
    // uses the right denominator.
    s.voter_count = s.current_voters.count();
    save_metadata(s, sys);
    emit_voter_set_update(s, sys);
    dev_log(sys, 3, b"[raft] config applied".as_ptr(), 21);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_voter_set_update(s: &ModuleState, sys: &SyscallTable) {
    if s.out_voter_set < 0 {
        return;
    }
    let poll = (sys.channel_poll)(s.out_voter_set, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let mut buf = [0u8; 3];
    wire::encode_voter_set_update(
        &mut buf,
        s.current_voters.0,
        s.joint_voters.0,
        s.joint_active,
    );
    wire_channels::channel_write_msg(sys, s.out_voter_set, wire::MSG_VOTER_SET_UPDATE, &buf);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_admin(s: &mut ModuleState, sys: &SyscallTable, _now: u64) {
    if s.in_admin < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_admin, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_admin, &mut s.msg_buf);
        if msg_type != wire::MSG_ADMIN_COMMAND || (plen as usize) < 5 { continue; }
        let command_id = u32::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
        ]);
        let op_code = s.msg_buf[4];
        let status = apply_admin_op(s, op_code, &s.msg_buf as *const _ as *const u8, plen as usize);
        emit_admin_applied(s, sys, command_id, status);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn apply_admin_op(
    s: &mut ModuleState,
    op_code: u8,
    buf_ptr: *const u8,
    plen: usize,
) -> u8 {
    // Safety: drain_admin owns the buffer for this iteration; this view
    // is read-only.
    let buf = core::slice::from_raw_parts(buf_ptr, plen);
    match op_code {
        wire::ADMIN_OP_FREEZE => { s.frozen = true; wire::ADMIN_STATUS_OK }
        wire::ADMIN_OP_THAW => { s.frozen = false; wire::ADMIN_STATUS_OK }
        wire::ADMIN_OP_TRANSFER_LEADER => {
            // Body: `[target_replica_id:u8]` at offset 5 (after command_id+op_code).
            if plen < 6 { return wire::ADMIN_STATUS_REJECTED; }
            // Only the leader can transfer; followers reject.
            if s.role != ROLE_LEADER { return wire::ADMIN_STATUS_NOT_LEADER; }
            let target = buf[5];
            if target == s.self_id || target as i8 == -1 {
                return wire::ADMIN_STATUS_REJECTED;
            }
            s.pending_transfer_to = target;
            wire::ADMIN_STATUS_OK
        }
        wire::ADMIN_OP_DURABILITY_MODE => {
            if plen < 6 { return wire::ADMIN_STATUS_REJECTED; }
            s.durability_mode = buf[5];
            wire::ADMIN_STATUS_OK
        }
        wire::ADMIN_OP_SNAPSHOT => {
            // We don't directly trigger snapshot_engine here — the
            // existing wal.compaction_signal path already drives it on
            // segment rollover. This op is a no-op acknowledgement
            // until the explicit-snapshot wire is added.
            wire::ADMIN_STATUS_OK
        }
        _ => wire::ADMIN_STATUS_UNSUPPORTED,
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_admin_applied(s: &mut ModuleState, sys: &SyscallTable, command_id: u32, status: u8) {
    if s.out_admin_applied < 0 { return; }
    let poll = (sys.channel_poll)(s.out_admin_applied, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 5];
    buf[0..4].copy_from_slice(&command_id.to_le_bytes());
    buf[4] = status;
    wire_channels::channel_write_msg(sys, s.out_admin_applied, wire::MSG_ADMIN_APPLIED, &buf);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_timeout_now_if_pending(s: &mut ModuleState, sys: &SyscallTable) {
    if s.pending_transfer_to == 0 { return; }
    if s.role != ROLE_LEADER { s.pending_transfer_to = 0; return; }
    if s.out_rpc < 0 { return; }
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let target = s.pending_transfer_to;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&s.current_term.to_le_bytes());
    // Use the partitioned envelope so peer_router can route by partition.
    wire_channels::channel_write_routed_partitioned(
        sys,
        s.out_rpc,
        target,
        s.partition_id,
        wire::MSG_TIMEOUT_NOW,
        &buf,
    );
    dev_log(sys, 3, b"[raft] timeout_now tx".as_ptr(), 21);
    // The transfer attempt is fire-and-forget; if the target doesn't
    // actually take over we keep being leader. The op_response was
    // already acked OK as soon as the local intent was recorded.
    s.pending_transfer_to = 0;
    // Help the transfer succeed by stepping down to follower right
    // after the fire. This makes our re-election delay long enough
    // for the target to start its election first.
    s.role = ROLE_FOLLOWER;
    s.leader_id = target as i8;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_vote_request(s: &mut ModuleState, sys: &SyscallTable, msg_type: u8, plen: u16) {
    if plen < 25 { return; }
    let (term, candidate, last_index, last_term) = wire::decode_vote_request(&s.msg_buf);

    let is_pre_vote = msg_type == wire::MSG_PRE_VOTE;

    // Step down if term is higher (only for real votes, not pre-votes)
    if !is_pre_vote && term > s.current_term {
        become_follower(s, term);
    }

    // Grant conditions:
    // 1. Term >= our term
    // 2. We haven't voted for someone else this term (or it's a pre-vote)
    // 3. Candidate's log is at least as up-to-date as ours
    let term_ok = term >= s.current_term;
    let vote_ok = is_pre_vote
        || s.voted_for == REPLICA_NONE as i8
        || s.voted_for == candidate as i8;
    let log_ok = last_term > s.last_log_term
        || (last_term == s.last_log_term && last_index >= s.last_log_index);

    let granted = term_ok && vote_ok && log_ok;

    if granted && !is_pre_vote {
        s.voted_for = candidate as i8;
        save_metadata(s, sys);
    }

    // Send response routed to the specific candidate
    let resp_type = if is_pre_vote { wire::MSG_PRE_VOTE_RESP } else { wire::MSG_REQUEST_VOTE_RESP };
    let mut resp = [0u8; 10];
    wire::encode_vote_response(&mut resp, s.current_term, granted, s.self_id);

    let poll_out = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(sys, s.out_rpc, candidate, s.partition_id, resp_type, &resp[..10]);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_vote_response(s: &mut ModuleState, _sys: &SyscallTable, msg_type: u8, plen: u16) {
    if s.role != ROLE_CANDIDATE { return; }
    if plen < 10 { return; }

    let (term, granted, voter) = wire::decode_vote_response(&s.msg_buf);

    if term > s.current_term {
        become_follower(s, term);
        return;
    }

    let is_pre_vote_resp = msg_type == wire::MSG_PRE_VOTE_RESP;

    if is_pre_vote_resp != s.pre_vote_active { return; }

    if voter as usize >= MAX_NODES { return; }

    if granted {
        s.votes_granted.insert(voter);
    } else {
        s.votes_rejected.insert(voter);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_append_entries(s: &mut ModuleState, sys: &SyscallTable, plen: u16, now: u64) {
    let pl = plen as usize;
    if pl < wire::AE_HDR_LEN { return; }
    let (term, leader, prev_log_index, prev_log_term, leader_commit, entry_term, entry_index) =
        match wire::decode_append_entries(&s.msg_buf[..pl]) {
            Some(t) => t,
            None => return,
        };

    if term < s.current_term {
        // Reject: stale term. Send response with our term and current
        // last-log so the leader can decide what to do.
        send_append_response(s, sys, false);
        return;
    }

    if term > s.current_term || s.role != ROLE_FOLLOWER {
        become_follower(s, term);
    }
    s.leader_id = leader as i8;
    reset_election_deadline(s, now);

    // Log matching (RFC §5.1). We accept this AE only if its
    // `prev_log_*` agrees with our last committed log position. This
    // catches stale or out-of-order appends. Conflict repair (rolling
    // back our log to an earlier point on mismatch) requires WAL
    // truncation that we don't yet plumb — see RFC §5.1 for the gap.
    if prev_log_index > 0 {
        if prev_log_index != s.last_log_index || prev_log_term != s.last_log_term {
            dev_log(sys, 3, b"[raft] ae mismatch".as_ptr(), 18);
            send_append_response(s, sys, false);
            return;
        }
    } else {
        // prev_log_index == 0 means "append at start of log". Only
        // accept if we ourselves are at an empty log; otherwise the
        // leader is misbehaving or we have stale state.
        if s.last_log_index != 0 {
            send_append_response(s, sys, false);
            return;
        }
    }

    // Accept entry — write to WAL only if the AE carries one.
    if entry_index > 0 {
        let entry_payload_start = wire::AE_HDR_LEN;
        let entry_len = pl.saturating_sub(entry_payload_start);

        let mut wal_buf = [0u8; 2048];
        wire::encode_term_index(&mut wal_buf, entry_term, entry_index);
        let copy_len = entry_len.min(wal_buf.len() - 16);
        if copy_len > 0 {
            wal_buf[16..16 + copy_len]
                .copy_from_slice(&s.msg_buf[entry_payload_start..entry_payload_start + copy_len]);
        }

        let poll = (sys.channel_poll)(s.out_log, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            wire_channels::channel_write_msg(sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf[..16 + copy_len]);
        }

        if s.out_log_observe >= 0 {
            let poll_obs = (sys.channel_poll)(s.out_log_observe, 0x02);
            if poll_obs > 0 && (poll_obs as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(
                    sys, s.out_log_observe, wire::MSG_WAL_ENTRY, &wal_buf[..16 + copy_len],
                );
            }
        }

        s.last_log_index = entry_index;
        s.last_log_term = entry_term;
        s.entries_appended += 1;
    }

    // Follower commit advance: clamp leader_commit to what we actually
    // have. When the follower's commit_index moves, fan it out so the
    // apply pipeline can advance. See RFC §5.1.
    advance_follower_commit(s, sys, leader_commit);

    send_append_response(s, sys, true);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn advance_follower_commit(s: &mut ModuleState, sys: &SyscallTable, leader_commit: u64) {
    let new_commit = leader_commit.min(s.last_log_index);
    if new_commit <= s.commit_index { return; }
    s.commit_index = new_commit;
    if s.out_commit_advanced < 0 { return; }
    let poll = (sys.channel_poll)(s.out_commit_advanced, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 16];
    wire::encode_term_index(&mut buf, s.current_term, new_commit);
    wire_channels::channel_write_msg(sys, s.out_commit_advanced, wire::MSG_COMMITTED_BATCH, &buf);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn send_append_response(s: &ModuleState, sys: &SyscallTable, success: bool) {
    let mut resp = [0u8; wire::AE_RESP_LEN];
    wire::encode_append_entries_resp(
        &mut resp,
        s.current_term,
        s.last_log_index,
        s.self_id,
        success,
        s.local_durable_index,
    );

    // Route back to leader
    let target = if s.leader_id >= 0 { s.leader_id as u8 } else { wire::TARGET_BROADCAST };
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(sys, s.out_rpc, target, s.partition_id, wire::MSG_APPEND_ENTRIES_RESP, &resp);
    }
}

// ── Follower step ───────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_follower(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // Learner-mode followers (self removed from voter set via
    // CONFIG_CHANGE_OP_NEW) MUST NOT start elections. Re-arm the
    // deadline so we don't fire as soon as we exit learner mode.
    if s.learner_mode {
        reset_election_deadline(s, now);
        return;
    }
    if now >= s.election_deadline_ms {
        // Election timeout — start pre-vote
        start_election(s, sys, now, true);
    }
}

// ── Candidate step ──────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_candidate(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    let majority = (s.voter_count / 2) + 1;

    if s.votes_granted.count() >= majority {
        if s.pre_vote_active {
            // Pre-vote succeeded — start real election
            start_election(s, sys, now, false);
        } else {
            // Real vote succeeded — become leader
            become_leader(s, sys, now);
        }
        return;
    }

    // Check election timeout
    if now >= s.election_deadline_ms {
        // Restart election
        start_election(s, sys, now, true);
    }
}

// ── Leader step ─────────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_leader(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // 0. Joint-consensus completeness: if a C_old,new entry has
    //    committed (apply_config_change set `pending_new_voters_set`),
    //    auto-propose the matching C_new entry. We only emit when
    //    the proposal batch is empty so the C_new entry gets its
    //    own clean log slot — important for replication correctness.
    if s.pending_new_voters_set && s.proposal_batch_count == 0 {
        emit_pending_c_new(s, sys, now);
    }

    // 1. Drain proposals into batch
    drain_proposals(s, sys, now);

    // 2. Flush batch if ready
    let batch_elapsed = now.wrapping_sub(s.proposal_batch_start_ms);
    let should_flush = s.proposal_batch_count > 0
        && (s.proposal_batch_count >= s.proposal_batch_max
            || batch_elapsed >= s.proposal_batch_timeout_ms as u64);

    if should_flush {
        flush_proposal_batch(s, sys);
    }

    // 3. Send heartbeats
    if now.wrapping_sub(s.last_heartbeat_ms) >= s.heartbeat_interval_ms as u64 {
        send_heartbeat(s, sys);
        s.last_heartbeat_ms = now;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Append a `CONFIG_CHANGE_OP_NEW` entry into the proposal batch,
/// completing the joint-consensus transition that
/// `apply_config_change` started. Called exclusively from
/// `step_leader` and only when `pending_new_voters_set` is true.
unsafe fn emit_pending_c_new(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // Materialise the new voter id list from the NodeSet bitmask.
    let mut voter_ids = [0u8; MAX_NODES];
    let mut n = 0usize;
    for id in 0..MAX_NODES as u8 {
        if s.pending_new_voters.contains(id) {
            voter_ids[n] = id;
            n += 1;
        }
    }
    let mut body = [0u8; 3 + MAX_NODES];
    let body_len = wire::encode_config_change(
        &mut body,
        wire::CONFIG_CHANGE_OP_NEW,
        &voter_ids[..n],
    );
    if body_len == 0 {
        return;
    }
    // append_to_batch copies from `s.msg_buf[off..off+len]`, so stage
    // the body there. Use an offset past anything drain_proposals
    // might be using; the scratch buffer is 2048 bytes wide so room
    // is plentiful.
    let stage_off = 1024usize;
    s.msg_buf[stage_off..stage_off + body_len].copy_from_slice(&body[..body_len]);
    if append_to_batch(s, sys, stage_off, body_len, 0, now) {
        // Clear the pending slot — flush_proposal_batch will append
        // the C_new entry to the log next time it runs.
        s.pending_new_voters_set = false;
        s.pending_new_voters = NodeSet::empty();
        dev_log(sys, 3, b"[raft] c_new queued".as_ptr(), 19);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_proposals(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // Admin freeze OR strict-fallback: drop every incoming proposal
    // silently. The client path (client_codec → throttle_gate) will
    // not see any feedback, but `client_codec` correlation rings time
    // out on their own and the client eventually retries / surfaces an
    // error. THAW (or a CP-proof recovery for strict_fallback)
    // restores. The two counters are kept distinct in metrics so
    // operators can tell admin-driven from CP-driven gating apart.
    if s.frozen || s.strict_fallback {
        let frozen = s.frozen;
        for chan in [s.in_proposals, s.in_proposals_tagged,
                     s.in_proposals_partitioned, s.in_proposals_partitioned_tagged] {
            if chan < 0 { continue; }
            for _ in 0..16 {
                let poll = (sys.channel_poll)(chan, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let _ = wire_channels::channel_read_msg(sys, chan, &mut s.msg_buf);
                if frozen {
                    s.proposals_dropped_frozen = s.proposals_dropped_frozen.saturating_add(1);
                } else {
                    s.proposals_dropped_strict = s.proposals_dropped_strict.saturating_add(1);
                }
            }
        }
        return;
    }

    // Legacy / untagged proposals (in[1]). The whole payload is the body;
    // the correlation slot stays zero so flush_proposal_batch emits no
    // MSG_PROPOSAL_ASSIGNED for these.
    if s.in_proposals >= 0 {
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_proposals, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_proposals, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }

            if !append_to_batch(s, sys, 0, plen as usize, 0, now) { break; }
        }
    }

    // Tagged proposals (in[4]). Strip the 8-byte correlation_id prefix and
    // store it in the parallel array so the batch flush can emit one
    // MSG_PROPOSAL_ASSIGNED per tagged proposal.
    if s.in_proposals_tagged >= 0 {
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_proposals_tagged, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_proposals_tagged, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL { continue; }
            let plen = plen as usize;
            if plen < wire::TAGGED_PROPOSAL_HDR { continue; }

            let (correlation_id, body_off) = match wire::decode_tagged_proposal(&s.msg_buf[..plen]) {
                Some(v) => v,
                None => continue,
            };
            // correlation_id == 0 is reserved as "untagged"; if a producer
            // sends zero we still batch the body so the proposal isn't
            // lost, but no MSG_PROPOSAL_ASSIGNED will be emitted — same as
            // the legacy path.
            let body_len = plen - body_off;
            if !append_to_batch(s, sys, body_off, body_len, correlation_id, now) { break; }
        }
    }

    // Partitioned proposals (in[5]). 5-byte partitioned envelope from
    // partition_router; payload is the bare proposal body. The
    // partition_id is asserted to match this instance's configured
    // slot — a mismatch means the graph wired the wrong output to
    // this raft.
    if s.in_proposals_partitioned >= 0 {
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_proposals_partitioned, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (partition_id, msg_type, plen) =
                wire_channels::channel_read_partitioned(sys, s.in_proposals_partitioned, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }
            if partition_id != s.partition_id {
                // Misrouted proposal — skip rather than corrupt this
                // partition's log. partition_router contract is
                // "out[i] only ever carries partition_id = i".
                continue;
            }
            if !append_to_batch(s, sys, 0, plen as usize, 0, now) { break; }
        }
    }

    // Partitioned + tagged proposals (in[6]). 5-byte partitioned
    // envelope; payload is `[correlation_id:u64 LE][body]`. Same
    // misroute-rejection semantics as in[5].
    if s.in_proposals_partitioned_tagged >= 0 {
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_proposals_partitioned_tagged, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (partition_id, msg_type, plen) = wire_channels::channel_read_partitioned(
                sys,
                s.in_proposals_partitioned_tagged,
                &mut s.msg_buf,
            );
            if msg_type != wire::MSG_CLIENT_PROPOSAL { continue; }
            let plen = plen as usize;
            if plen < wire::TAGGED_PROPOSAL_HDR { continue; }
            if partition_id != s.partition_id { continue; }

            let (correlation_id, body_off) =
                match wire::decode_tagged_proposal(&s.msg_buf[..plen]) {
                    Some(v) => v,
                    None => continue,
                };
            let body_len = plen - body_off;
            if !append_to_batch(s, sys, body_off, body_len, correlation_id, now) { break; }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Copy `&s.msg_buf[off..off+len]` into the proposal batch and record the
/// correlation_id in the parallel array. Returns false if the batch is
/// full (caller should stop draining).
unsafe fn append_to_batch(
    s: &mut ModuleState,
    sys: &SyscallTable,
    off: usize,
    len: usize,
    correlation_id: u64,
    now: u64,
) -> bool {
    if len == 0 { return true; }
    let space = PROPOSAL_BATCH_CAP - s.proposal_batch_len as usize;
    if len > space { return false; }
    let count = s.proposal_batch_count as usize;
    if count >= MAX_BATCH_PROPOSALS { return false; }

    let start = s.proposal_batch_len as usize;
    s.proposal_batch[start..start + len]
        .copy_from_slice(&s.msg_buf[off..off + len]);
    s.proposal_batch_len += len as u16;
    s.correlation_ids[count] = correlation_id;
    s.proposal_batch_count += 1;
    s.proposals_received += 1;

    if s.proposal_batch_count == 1 {
        s.proposal_batch_start_ms = now;
        dev_log(sys, 3, b"[raft] prop".as_ptr(), 11);
    }
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_proposal_batch(s: &mut ModuleState, sys: &SyscallTable) {
    if s.proposal_batch_count == 0 { return; }

    // Capture the previous log point before advancing. This is the
    // `prev_log_*` tuple the follower must match before accepting the
    // new entry.
    let prev_log_index = s.last_log_index;
    let prev_log_term = if prev_log_index == 0 { 0 } else { s.last_log_term };

    // Advance log
    s.last_log_index += 1;
    s.last_log_term = s.current_term;

    let batch_len = s.proposal_batch_len as usize;

    // Write to WAL (log_append) and fan out to observers (log_observe).
    // Both ports carry the same 16-byte header + body; observers (e.g.
    // apply_pipeline) buffer them keyed by index and emit per-entry
    // committed messages once commit_tracker advances the horizon.
    {
        let mut wal_buf = [0u8; PROPOSAL_BATCH_CAP + 16];
        wire::encode_term_index(&mut wal_buf, s.current_term, s.last_log_index);
        wal_buf[16..16 + batch_len].copy_from_slice(&s.proposal_batch[..batch_len]);

        let poll = (sys.channel_poll)(s.out_log, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            wire_channels::channel_write_msg(sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf[..16 + batch_len]);
        }

        // Fanout: drop silently if observer ring is full — the consumer
        // is non-load-bearing for consensus, so a stuck observer must
        // never block the WAL hot path. Observer modules MUST cope with
        // gaps and recover via the per-entry sequence numbers.
        if s.out_log_observe >= 0 {
            let poll_obs = (sys.channel_poll)(s.out_log_observe, 0x02);
            if poll_obs > 0 && (poll_obs as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(
                    sys,
                    s.out_log_observe,
                    wire::MSG_WAL_ENTRY,
                    &wal_buf[..16 + batch_len],
                );
            }
        }
    }

    // Send to replicator (append_entries) using the extended envelope
    // with prev_log_{index,term} so followers can verify log matching
    // (RFC §5.1). The "prev" for this entry is the index we held
    // BEFORE this flush — `last_log_index - 1` and the term we knew
    // for that index. The leader has just bumped `last_log_*`, so we
    // recover them by subtracting the increment.
    {
        let new_index = s.last_log_index;

        let mut ae_buf = [0u8; PROPOSAL_BATCH_CAP + wire::AE_HDR_LEN];
        let total = wire::encode_append_entries(
            &mut ae_buf,
            s.current_term,
            s.self_id,
            prev_log_index,
            prev_log_term,
            s.commit_index,
            s.current_term,
            new_index,
            &s.proposal_batch[..batch_len],
        );

        let poll = (sys.channel_poll)(s.out_append, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 && total > 0 {
            wire_channels::channel_write_msg(sys, s.out_append, wire::MSG_APPEND_ENTRIES, &ae_buf[..total]);
        }
    }

    s.entries_appended += 1;
    save_metadata(s, sys);
    dev_log(sys, 3, b"[raft] flush".as_ptr(), 12);

    // All proposals in this batch share the same wal_index. Emit one
    // MSG_PROPOSAL_ASSIGNED per tagged proposal so the proposer can bind
    // its correlation_id to the durable log index.
    emit_proposal_assignments(s, sys);

    // Reset batch
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_proposal_assignments(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_proposal_assigned < 0 { return; }
    let count = s.proposal_batch_count as usize;
    let assigned_index = s.last_log_index;
    let pid = s.partition_id;
    for i in 0..count {
        let cid = s.correlation_ids[i];
        s.correlation_ids[i] = 0;
        if cid == 0 { continue; }

        let poll = (sys.channel_poll)(s.out_proposal_assigned, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            // Channel full — drop the assignment. The proposer either
            // falls back to its own heuristic or treats this as a lost
            // correlation. Cannot block here.
            continue;
        }
        let mut buf = [0u8; wire::PROPOSAL_ASSIGNED_LEN];
        wire::encode_proposal_assigned(&mut buf, cid, pid, assigned_index);
        wire_channels::channel_write_msg(sys, s.out_proposal_assigned, wire::MSG_PROPOSAL_ASSIGNED, &buf);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn send_heartbeat(s: &ModuleState, sys: &SyscallTable) {
    // Heartbeats are AppendEntries with an empty body (entry_index = 0).
    // They double as log-matching probes: a follower whose tail
    // disagrees with prev_log_* rejects the AE, prompting the
    // replicator's conflict-repair retry to roll its next_index back.
    let mut hb = [0u8; wire::AE_HDR_LEN];
    let _ = wire::encode_append_entries(
        &mut hb,
        s.current_term,
        s.self_id,
        s.last_log_index,
        s.last_log_term,
        s.commit_index,
        0,
        0,
        &[],
    );

    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(
            sys,
            s.out_rpc,
            wire::TARGET_BROADCAST,
            s.partition_id,
            wire::MSG_APPEND_ENTRIES,
            &hb,
        );
    }
}

// ── Metadata persistence ────────────────────────────────────

/// Build the per-partition metadata path. Returns `(buf, len)`.
///   partition_id == 0 → "raft/meta"          (legacy single-partition)
///   partition_id == N → "raft/p<NNNN>/meta"  (multi-Raft)
fn build_meta_path(partition_id: u16) -> ([u8; META_PATH_MAX], usize) {
    let mut buf = [0u8; META_PATH_MAX];
    if partition_id == 0 {
        let p = b"raft/meta";
        buf[..p.len()].copy_from_slice(p);
        return (buf, p.len());
    }
    // "raft/p" + 4 hex digits + "/meta"
    let prefix = b"raft/p";
    let mut i = 0usize;
    for &b in prefix { buf[i] = b; i += 1; }
    for digit in (0..4).rev() {
        let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        i += 1;
    }
    let suffix = b"/meta";
    for &b in suffix { buf[i] = b; i += 1; }
    (buf, i)
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Load persistent Raft state from raft/[p<id>/]meta.
unsafe fn load_metadata(s: &mut ModuleState, sys: &SyscallTable) {
    let (mut path, plen) = build_meta_path(s.partition_id);
    let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
    if fd < 0 { return; } // no metadata file — fresh start

    let mut buf = [0u8; META_SIZE];
    let n = (sys.provider_call)(fd, FS_READ, buf.as_mut_ptr(), META_SIZE);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);

    if n as usize >= 25 {
        let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        let voted = buf[8] as i8;
        let log_idx = u64::from_le_bytes([buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16]]);
        let log_term = u64::from_le_bytes([buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24]]);
        if term > 0 {
            s.current_term = term;
            s.voted_for = voted;
            s.last_log_index = log_idx;
            s.last_log_term = log_term;
            dev_log(sys, 3, b"[raft] meta ok".as_ptr(), 14);
        }
        // Joint-consensus fields (RFC §1.2) — only present when META
        // was written by a build that included them. Older meta
        // files are accepted unchanged; voter sets fall back to the
        // `voter_count` param defaults seeded in module_new.
        if n as usize >= 28 {
            s.current_voters = NodeSet(buf[25]);
            s.joint_voters = NodeSet(buf[26]);
            s.joint_active = buf[27] != 0;
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Save persistent Raft state to raft/[p<id>/]meta.
unsafe fn save_metadata(s: &ModuleState, sys: &SyscallTable) {
    let (mut path, plen) = build_meta_path(s.partition_id);
    let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
    if fd < 0 { return; } // FS not available

    // Seek to start (overwrite)
    let zero = 0i32.to_le_bytes();
    (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);

    let mut buf = [0u8; META_SIZE];
    buf[0..8].copy_from_slice(&s.current_term.to_le_bytes());
    buf[8] = s.voted_for as u8;
    buf[9..17].copy_from_slice(&s.last_log_index.to_le_bytes());
    buf[17..25].copy_from_slice(&s.last_log_term.to_le_bytes());
    buf[25] = s.current_voters.0;
    buf[26] = s.joint_voters.0;
    buf[27] = s.joint_active as u8;
    (sys.provider_call)(fd, FS_WRITE, buf.as_mut_ptr(), META_SIZE);
    (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
}

// ── State transitions ───────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn become_follower(s: &mut ModuleState, term: Term) {
    s.current_term = term;
    s.role = ROLE_FOLLOWER;
    s.voted_for = REPLICA_NONE as i8;
    s.votes_granted.clear();
    s.votes_rejected.clear();
    s.pre_vote_active = false;
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
    // Drop any pending correlation ids — proposals from a prior term are
    // discarded, so the proposer will time out and retry.
    for i in 0..MAX_BATCH_PROPOSALS { s.correlation_ids[i] = 0; }
    save_metadata(s, &*s.syscalls);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn become_leader(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    s.role = ROLE_LEADER;
    s.leader_id = s.self_id as i8;
    s.votes_granted.clear();
    s.votes_rejected.clear();
    s.pre_vote_active = false;
    s.last_heartbeat_ms = now;
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
    for i in 0..MAX_BATCH_PROPOSALS { s.correlation_ids[i] = 0; }

    dev_log(sys, 3, b"[raft] leader".as_ptr(), 13);

    // Send immediate heartbeat to assert leadership
    send_heartbeat(s, sys);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn start_election(s: &mut ModuleState, sys: &SyscallTable, now: u64, pre_vote: bool) {
    s.pre_vote_active = pre_vote;

    if !pre_vote {
        s.current_term += 1;
        s.voted_for = s.self_id as i8;
        save_metadata(s, sys);
    }

    s.role = ROLE_CANDIDATE;
    s.votes_granted = NodeSet::empty();
    s.votes_rejected = NodeSet::empty();
    s.votes_granted.insert(s.self_id); // vote for self
    s.elections_started += 1;

    // Randomize election timeout with jitter
    let mut seed = (now as u32) ^ ((s.self_id as u32) << 16) ^ 0xCAFE;
    let half_timeout = (s.election_timeout_ms as u32 / 2).max(1);
    let jitter = (xorshift32(&mut seed) & (half_timeout.next_power_of_two() - 1)) as u64;
    s.election_deadline_ms = now + s.election_timeout_ms as u64 + jitter;

    // Check for single-node cluster: already have quorum
    let majority = (s.voter_count / 2) + 1;
    if s.votes_granted.count() >= majority {
        if pre_vote {
            start_election(s, sys, now, false);
        } else {
            become_leader(s, sys, now);
        }
        return;
    }

    // Send vote requests to all peers via routed broadcast
    let msg_type = if pre_vote { wire::MSG_PRE_VOTE } else { wire::MSG_REQUEST_VOTE };
    let mut req = [0u8; 25];
    let req_term = if pre_vote { s.current_term + 1 } else { s.current_term };
    wire::encode_vote_request(&mut req, req_term, s.self_id, s.last_log_index, s.last_log_term);

    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(sys, s.out_rpc, wire::TARGET_BROADCAST, s.partition_id, msg_type, &req[..25]);
    }

    dev_log(sys, 3, b"[raft] elect".as_ptr(), 12);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reset_election_deadline(s: &mut ModuleState, now: u64) {
    let mut seed = (now as u32) ^ 0xBEEF;
    let half_timeout2 = (s.election_timeout_ms as u32 / 2).max(1);
    let jitter = (xorshift32(&mut seed) & (half_timeout2.next_power_of_two() - 1)) as u64;
    s.election_deadline_ms = now + s.election_timeout_ms as u64 + jitter;
}

// ── Fallback signal ─────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_fallback(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_fallback < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_fallback, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_fallback, &mut s.msg_buf);
        if msg_type == wire::MSG_FALLBACK_SIGNAL && plen >= 1 {
            s.strict_fallback = s.msg_buf[0] != 0;
        }
    }
}

// ── Metrics ─────────────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < 1000 { return; }
    s.last_metrics_ms = now;

    // Typed metric samples (RFC §4.3). Replaces the prior packed-into-
    // one-envelope shape so `telemetry_agg` can aggregate without a
    // module-specific parser. Each metric goes out as its own
    // `MSG_METRIC_SAMPLE`; the legacy `MSG_METRICS` envelope is still
    // sent at the end for tools that haven't migrated yet, so this
    // is fully backwards-compatible.
    let mod_id = wire::MODULE_ID_RAFT_ENGINE;
    let pid = s.partition_id;
    let kg = wire::METRIC_KIND_GAUGE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, u8, i64); 9] = [
        (wire::metric_ids::RAFT_ROLE, kg, s.role as i64),
        (wire::metric_ids::RAFT_CURRENT_TERM, kg, s.current_term as i64),
        (wire::metric_ids::RAFT_PROPOSALS_RECEIVED, kc, s.proposals_received as i64),
        (wire::metric_ids::RAFT_ENTRIES_APPENDED, kc, s.entries_appended as i64),
        (wire::metric_ids::RAFT_ELECTIONS_STARTED, kc, s.elections_started as i64),
        (wire::metric_ids::RAFT_PROPOSALS_DROPPED_FROZEN, kc, s.proposals_dropped_frozen as i64),
        (wire::metric_ids::RAFT_PROPOSALS_DROPPED_STRICT, kc, s.proposals_dropped_strict as i64),
        (wire::metric_ids::RAFT_FROZEN_FLAG, kg, s.frozen as i64),
        (wire::metric_ids::RAFT_STRICT_FALLBACK_FLAG, kg, s.strict_fallback as i64),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mod_id, pid, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }

    // Legacy MSG_METRICS shape — still emitted so observers that parse
    // it (test scaffolding, the e2e harness) keep working. Same byte
    // layout as before this RFC §4.3 migration.
    let mut buf = [0u8; 30];
    buf[0] = s.role;
    buf[1..9].copy_from_slice(&s.current_term.to_le_bytes());
    buf[9..13].copy_from_slice(&s.proposals_received.to_le_bytes());
    buf[13..17].copy_from_slice(&s.entries_appended.to_le_bytes());
    buf[17..21].copy_from_slice(&s.elections_started.to_le_bytes());
    buf[21..25].copy_from_slice(&s.proposals_dropped_frozen.to_le_bytes());
    buf[25..29].copy_from_slice(&s.proposals_dropped_strict.to_le_bytes());
    let mut flags = 0u8;
    if s.frozen { flags |= 0x01; }
    if s.strict_fallback { flags |= 0x02; }
    buf[29] = flags;

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..30]);
    }
}
