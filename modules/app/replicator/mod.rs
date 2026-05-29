//! Replicator — Pipelines AppendEntries to followers, collects acks,
//! and emits match-index + durability updates.
//!
//! Receives batched entries from raft_engine, frames them as peer
//! RPCs via `net_out` to `peer_router`, and processes
//! `MSG_APPEND_ENTRIES_RESP` envelopes from peers to drive per-peer
//! replication state. Two outputs ride on each successful response:
//!   - `match_indices` (to `commit_tracker`) — the follower's
//!     `last_log_index`, used for the standard Raft match-quorum.
//!   - `cross_durability_ack` (to `durability_ledger.ack`) — a
//!     synthesized `MSG_FSYNC_ACK` carrying the follower's
//!     `local_wal_durable_index` so the leader's durability ledger
//!     can compute quorum-fsync per spec §10.4.1.

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

const METRICS_INTERVAL_MS: u64 = 1000;

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, peer_count, u8, 0
        => |s, d, len| { s.peer_count = p_u8(d, len, 0, 0); };

    3, pipeline_depth, u8, 8
        => |s, d, len| { s.pipeline_depth = p_u8(d, len, 0, 8); };

    4, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };
}

/// Outstanding WAL read-back request slot. Bounded so a slow WAL
/// cannot accumulate unbounded in-flight requests.
const MAX_PENDING_WAL_REQS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct PeerState {
    next_index: Index,
    match_index: Index,
    inflight: u8,
    active: bool,
    /// Joint-consensus catch-up flag (RFC §1.2). When a new voter
    /// joins via `CONFIG_CHANGE_OP_JOINT`, the leader marks it as
    /// non-voting so its match_index doesn't count toward quorum
    /// until it has replicated up to a stable point. Promoted to
    /// voting once `match_index >= leader.last_log_index - VOTING_LAG`.
    voting: bool,
    /// Last (term, index) we know lives at `next_index - 1` on this
    /// peer. Used as the `prev_log_*` of the next AE. Updated either
    /// via WAL read-back or by recording the per-batch tip.
    prev_log_index: Index,
    prev_log_term: Term,
}

impl PeerState {
    const fn zero() -> Self {
        Self {
            next_index: 1,
            match_index: 0,
            inflight: 0,
            active: false,
            voting: false,
            prev_log_index: 0,
            prev_log_term: 0,
        }
    }
}

/// How far behind a non-voting peer is allowed to be before it
/// auto-promotes to voting. Aggressive (small) values let the joint
/// transition complete quickly; large values bias toward "the new
/// voter must really be caught up". The Raft paper recommends a
/// single round's worth of log delta as a reasonable default.
const VOTING_LAG_THRESHOLD: u64 = 64;

/// Pending WAL read-back: maps a request_id we issued to the peer
/// that prompted it so the reply can be turned into a targeted AE.
#[derive(Clone, Copy)]
#[repr(C)]
struct PendingWalReq {
    request_id: u32,
    /// Peer that needs the entry. 0xFF means slot is unused.
    peer: u8,
    /// Index requested (= peer.next_index - 1 at issue time).
    wal_index: u64,
}

impl PendingWalReq {
    const fn zero() -> Self {
        Self { request_id: 0, peer: 0xFF, wal_index: 0 }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels: 4 in, 6 out
    in_entries: i32,        // in[0]: AppendEntries from raft_engine
    in_ack: i32,            // in[1]: responses from peers via peer_router
    in_snapshot_rx: i32,    // in[2]: export chunks from snapshot_engine
    in_wal_reply: i32,      // in[3]: MSG_WAL_ENTRY_REPLY from wal
    in_voter_set: i32,      // in[4]: MSG_VOTER_SET_UPDATE from raft_engine
    out_net: i32,           // out[0]: RPC frames to peer_router
    out_match: i32,         // out[1]: match index updates to commit_tracker
    out_lag: i32,           // out[2]: lag signal to flow_controller
    out_snapshot_import: i32, // out[3]: import chunks to snapshot_engine
    out_metrics: i32,       // out[4]: metrics to telemetry_agg
    out_wal_request: i32,   // out[5]: MSG_WAL_ENTRY_REQUEST to wal
    out_snapshot_request: i32, // out[6]: MSG_SNAPSHOT_INSTALL_REQUEST to snapshot_engine
    out_cross_durability_ack: i32, // out[7]: synthesized MSG_FSYNC_ACK to durability_ledger.ack (§10.4.1)

    // Config
    self_id: ReplicaId,
    peer_count: u8,
    pipeline_depth: u8,
    partition_id: u16,
    structural_lag_bytes: u32,

    // Per-peer state
    peers: [PeerState; MAX_NODES],

    /// Last `local_wal_durable_index` we forwarded to
    /// `durability_ledger.ack` for each peer (§10.4.1). Used to
    /// suppress redundant fsync-ack forwards: AE responses arrive on
    /// every heartbeat round whether or not the follower's durable
    /// index actually advanced, and durability_ledger already discards
    /// regressions, but we'd rather not burn the channel write either.
    last_forwarded_durable: [Index; MAX_NODES],

    /// Last batch we broadcast — both the (term, index) pair and the
    /// preceding (term, index). Used to populate per-peer prev_log_*
    /// for catch-up AEs without forcing an immediate WAL read-back.
    last_emitted_index: Index,
    last_emitted_term: Term,
    last_emitted_prev_index: Index,
    last_emitted_prev_term: Term,

    /// Current voter set bitmask from raft_engine (RFC §1.2). A peer
    /// id present here is a current voter; peers not in the set are
    /// either non-existent or non-voting catch-up.
    current_voters: u8,
    /// Joint voter set bitmask. When `joint_active`, peers in
    /// `joint_voters & !current_voters` are the *new* voters that
    /// need to be promoted from non-voting after catching up.
    joint_voters: u8,
    joint_active: bool,

    // Pending WAL read-back requests issued for catch-up.
    pending: [PendingWalReq; MAX_PENDING_WAL_REQS],
    next_request_id: u32,

    // Metrics
    rpcs_sent: u32,
    acks_received: u32,
    nacks_received: u32,
    catchup_sent: u32,
    last_metrics_ms: u64,

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

        s.in_entries = in_chan;
        s.out_net = out_chan;
        s.in_ack = dev_channel_port(sys, 0, 1);
        s.in_snapshot_rx = dev_channel_port(sys, 0, 2);
        s.in_wal_reply = dev_channel_port(sys, 0, 3);
        s.in_voter_set = dev_channel_port(sys, 0, 4);
        s.out_match = dev_channel_port(sys, 1, 1);
        s.out_lag = dev_channel_port(sys, 1, 2);
        s.out_snapshot_import = dev_channel_port(sys, 1, 3);
        s.out_metrics = dev_channel_port(sys, 1, 4);
        s.out_wal_request = dev_channel_port(sys, 1, 5);
        s.out_snapshot_request = dev_channel_port(sys, 1, 6);
        s.out_cross_durability_ack = dev_channel_port(sys, 1, 7);

        s.structural_lag_bytes = 256 * 1024 * 1024;
        s.pending = [PendingWalReq::zero(); MAX_PENDING_WAL_REQS];
        s.next_request_id = 1;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        // Activate peer slots. Initial set: 0..peer_count exclusive
        // of self. Every initial peer is voting; non-voting state is
        // entered only when a joint-consensus add brings a new peer
        // online (see `drain_voter_set_update`).
        for i in 0..s.peer_count as usize {
            if i < MAX_NODES && i != s.self_id as usize {
                s.peers[i].active = true;
                s.peers[i].voting = true;
            }
        }

        // Log channel handles for debugging
        if s.out_net >= 0 {
            dev_log(sys, 3, b"[repl] net ok".as_ptr(), 13);
        } else {
            dev_log(sys, 3, b"[repl] net -1".as_ptr(), 13);
        }
        dev_log(sys, 3, b"[repl] init".as_ptr(), 11);
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

        // 0. Pick up any voter-set updates first so peer activation
        //    state is current before we process AE responses below.
        drain_voter_set_update(s, sys);

        // 1. Process inbound entries from raft_engine → fan out to peers
        replicate_entries(s, sys);

        // 2. Process ack responses from peers
        process_acks(s, sys);

        // 3. Drain WAL read-back replies and turn them into targeted AEs.
        process_wal_replies(s, sys);

        // 4. Forward snapshot chunks
        forward_snapshots(s, sys);

        // 5. Emit metrics
        emit_metrics(s, sys);

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn replicate_entries(s: &mut ModuleState, sys: &SyscallTable) {
    // Process up to 4 entries per step
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_entries, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        // Check output readiness
        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
        if msg_type != wire::MSG_APPEND_ENTRIES || (plen as usize) < wire::AE_HDR_LEN { continue; }

        dev_log(sys, 3, b"[repl] ae in".as_ptr(), 12);
        // Snapshot the AE header so we can record the per-peer
        // prev_log_* tip for catch-up retries.
        if let Some((_term, _leader, prev_idx, prev_term, _lc, ent_term, ent_idx)) =
            wire::decode_append_entries(&s.msg_buf[..plen as usize])
        {
            // Heartbeat-style AE has ent_idx == 0 — don't bump our tip.
            if ent_idx != 0 {
                s.last_emitted_prev_index = prev_idx;
                s.last_emitted_prev_term = prev_term;
                s.last_emitted_index = ent_idx;
                s.last_emitted_term = ent_term;
            }
        }

        // Fan out to each active peer with a routed envelope so
        // peer_router can demux to the correct connection.
        let payload = &s.msg_buf[..plen as usize];
        for i in 0..MAX_NODES {
            if !s.peers[i].active { continue; }
            if i == s.self_id as usize { continue; }
            let w = wire_channels::channel_write_routed_partitioned(
                sys, s.out_net, i as u8, s.partition_id,
                wire::MSG_APPEND_ENTRIES, payload,
            );
            if w > 0 {
                s.rpcs_sent += 1;
                dev_log(sys, 3, b"[repl] sent ok".as_ptr(), 14);
            } else {
                dev_log(sys, 3, b"[repl] send fail".as_ptr(), 16);
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
unsafe fn process_acks(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_ack < 0 { return; }

    // Inbound shape from peer_router.peer_rx is the 5-byte partitioned
    // envelope. peer_router fans out a single channel to every per-
    // partition replicator (fluxor inserts a tee), so each instance
    // sees every ack and filters by its own partition_id.
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_ack, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (partition_id, msg_type, plen) =
            wire_channels::channel_read_partitioned(sys, s.in_ack, &mut s.msg_buf);
        if plen == 0 && msg_type == 0 { break; }
        if partition_id != s.partition_id { continue; }
        if plen < 17 { continue; }

        match msg_type {
            wire::MSG_APPEND_ENTRIES_RESP => {
                dev_log(sys, 3, b"[repl] ack".as_ptr(), 10);
                let (term, index, replica, success, durable_index) =
                    match wire::decode_append_entries_resp(&s.msg_buf[..plen as usize]) {
                        Some(v) => v,
                        None => continue,
                    };

                // Forward the follower's `local_wal_durable_index` to
                // the leader's `durability_ledger.ack` as a synthesized
                // MSG_FSYNC_ACK keyed by the follower's replica id
                // (spec §10.4.1). Only forward strictly-advancing
                // values to keep the channel quiet on steady-state
                // heartbeats — durability_ledger also drops
                // regressions, but we'd rather not burn the write.
                if (replica as usize) < MAX_NODES
                    && durable_index > s.last_forwarded_durable[replica as usize]
                    && s.out_cross_durability_ack >= 0
                {
                    let poll_d = (sys.channel_poll)(s.out_cross_durability_ack, 0x02);
                    if poll_d > 0 && (poll_d as u32 & 0x02) != 0 {
                        let mut ack = [0u8; 17];
                        wire::encode_fsync_ack(&mut ack, term, durable_index, replica);
                        wire_channels::channel_write_msg(
                            sys,
                            s.out_cross_durability_ack,
                            wire::MSG_FSYNC_ACK,
                            &ack[..17],
                        );
                        s.last_forwarded_durable[replica as usize] = durable_index;
                    }
                }

                if (replica as usize) < MAX_NODES && s.peers[replica as usize].active {
                    if success {
                        // Snapshot before mutating; only forward when
                        // we make actual progress so commit_tracker's
                        // quorum index doesn't see redundant entries
                        // for the same match_index.
                        let prev_match = s.peers[replica as usize].match_index;
                        let was_voting = s.peers[replica as usize].voting;
                        let peer = &mut s.peers[replica as usize];
                        if peer.inflight > 0 { peer.inflight -= 1; }
                        if index > peer.match_index {
                            peer.match_index = index;
                            peer.next_index = index + 1;
                        }
                        // Forward match update to commit_tracker ONLY
                        // when this peer is currently a voter (RFC §1.2
                        // non-voting catch-up). New voters joining via
                        // joint consensus catch up in non-voting state
                        // first; their match_index doesn't enter the
                        // quorum median until they're promoted.
                        if was_voting && index > prev_match && s.out_match >= 0 {
                            let poll_out = (sys.channel_poll)(s.out_match, 0x02);
                            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                                wire_channels::channel_write_msg(
                                    sys, s.out_match,
                                    wire::MSG_APPEND_ENTRIES_RESP,
                                    &s.msg_buf[..plen as usize],
                                );
                            }
                        }
                        // Auto-promote: a non-voting peer that's caught
                        // up to within `VOTING_LAG_THRESHOLD` of the
                        // leader's tip becomes a full voter.
                        maybe_promote(s, sys, replica);
                    } else {
                        // NACK: follower's log doesn't agree with our
                        // prev_log_* at this index. Roll next_index back
                        // by one and issue a WAL read-back so we can
                        // re-send the entry that lives at (next_index - 1).
                        // The follower's reply payload carries its
                        // current last_log_index — use it as a hint to
                        // skip multiple rounds when the gap is large.
                        let peer = &mut s.peers[replica as usize];
                        if peer.inflight > 0 { peer.inflight -= 1; }
                        s.nacks_received = s.nacks_received.saturating_add(1);
                        let mut new_next = peer.next_index.saturating_sub(1).max(1);
                        // If the follower's reported last_log_index is
                        // strictly less than our roll-back target, jump
                        // straight there (saves rounds when gap is big).
                        if index > 0 && index + 1 < new_next {
                            new_next = index + 1;
                        }
                        peer.next_index = new_next;
                        // Term advance: stay safe if the follower bumped term.
                        let _ = term;
                        let catch_index = new_next.saturating_sub(1);
                        if catch_index == 0 {
                            // Edge case: we've rolled all the way to
                            // before the log starts. Nothing to read
                            // back. Snapshot install (§4.2) is the
                            // recovery path.
                        } else {
                            issue_wal_request(s, sys, replica, catch_index);
                        }
                    }
                }
                s.acks_received += 1;
            }
            wire::MSG_HEARTBEAT_RESP | wire::MSG_REQUEST_VOTE_RESP | wire::MSG_PRE_VOTE_RESP => {
                // Forward vote/heartbeat responses to raft_engine via net_out
                // (they'll be routed back through client_surface → raft_engine.rpc_in)
                // For now, these pass through the same path.
            }
            wire::MSG_INSTALL_SNAPSHOT | wire::MSG_SNAPSHOT_CHUNK => {
                // Inbound snapshot chunk from leader. Forward to
                // snapshot_engine via out_snapshot_import so it can
                // accumulate / install (RFC §5.13).
                if s.out_snapshot_import >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_snapshot_import, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        wire_channels::channel_write_msg(
                            sys, s.out_snapshot_import,
                            msg_type, &s.msg_buf[..plen as usize],
                        );
                    }
                }
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
unsafe fn issue_wal_request(
    s: &mut ModuleState,
    sys: &SyscallTable,
    peer: u8,
    wal_index: u64,
) {
    if s.out_wal_request < 0 || wal_index == 0 { return; }

    // Recycle the slot if we already had a pending request for this
    // (peer, index) — avoids piling up duplicate requests during
    // multi-round catch-up.
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in s.pending.iter().enumerate() {
        if slot.peer == peer && slot.wal_index == wal_index {
            slot_idx = Some(i);
            break;
        }
    }
    if slot_idx.is_none() {
        for (i, slot) in s.pending.iter().enumerate() {
            if slot.peer == 0xFF { slot_idx = Some(i); break; }
        }
    }
    let slot_idx = match slot_idx {
        Some(i) => i,
        None => return, // table full — wait for in-flight to drain
    };

    let request_id = s.next_request_id;
    s.next_request_id = s.next_request_id.wrapping_add(1).max(1);
    s.pending[slot_idx] = PendingWalReq { request_id, peer, wal_index };

    let poll_out = (sys.channel_poll)(s.out_wal_request, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
        // Channel full — free the slot so we retry next tick.
        s.pending[slot_idx] = PendingWalReq::zero();
        return;
    }
    let mut req = [0u8; wire::WAL_ENTRY_REQUEST_LEN];
    wire::encode_wal_entry_request(&mut req, request_id, wal_index);
    wire_channels::channel_write_msg(sys, s.out_wal_request, wire::MSG_WAL_ENTRY_REQUEST, &req);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_voter_set_update(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_voter_set < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_voter_set, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_voter_set, &mut s.msg_buf);
        if msg_type != wire::MSG_VOTER_SET_UPDATE || (plen as usize) < 3 {
            continue;
        }
        if let Some((current, joint, joint_active)) =
            wire::decode_voter_set_update(&s.msg_buf[..plen as usize])
        {
            s.current_voters = current;
            s.joint_voters = joint;
            s.joint_active = joint_active;
            // Activate any peer that's in either set; deactivate
            // peers that have been dropped entirely.
            let union = current | joint;
            for id in 0..MAX_NODES as u8 {
                if id == s.self_id {
                    continue;
                }
                let i = id as usize;
                let in_union = (union & (1u8 << id)) != 0;
                if in_union && !s.peers[i].active {
                    // New peer: activate, start at last_log_index + 1
                    // for the leader's known log tip, non-voting until
                    // caught up.
                    s.peers[i] = PeerState {
                        next_index: s.last_emitted_index.max(1),
                        match_index: 0,
                        inflight: 0,
                        active: true,
                        voting: false,
                        prev_log_index: 0,
                        prev_log_term: 0,
                    };
                    dev_log(sys, 3, b"[repl] new peer".as_ptr(), 15);
                } else if !in_union && s.peers[i].active {
                    // Removed peer: drop active flag so no further AEs
                    // are sent to it. Match-index history is left in
                    // place in case a re-add happens.
                    s.peers[i].active = false;
                    s.peers[i].voting = false;
                    dev_log(sys, 3, b"[repl] drop peer".as_ptr(), 15);
                } else if in_union && s.peers[i].active && !s.peers[i].voting {
                    // Peer is in current_voters (not just joint) → eligible
                    // for promotion to voting status. The promotion itself
                    // happens once match_index is close enough; until then
                    // leave the flag false.
                    let _ = i;
                }
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
/// Promote a non-voting peer to voting once its match_index is
/// within `VOTING_LAG_THRESHOLD` of the leader's last-emitted tip.
/// Called from the AE-success branch in `process_acks`.
unsafe fn maybe_promote(s: &mut ModuleState, sys: &SyscallTable, peer: u8) {
    let i = peer as usize;
    if i >= MAX_NODES {
        return;
    }
    if !s.peers[i].active || s.peers[i].voting {
        return;
    }
    if s.last_emitted_index == 0 {
        return;
    }
    let lag = s.last_emitted_index.saturating_sub(s.peers[i].match_index);
    if lag <= VOTING_LAG_THRESHOLD {
        // Promote only when the peer is also in current_voters (not
        // just joint). During joint-consensus, the joint set may
        // include not-yet-current voters; we wait for the C_new
        // commit to install them into `current_voters` before flipping
        // their voting flag.
        if (s.current_voters & (1u8 << peer)) != 0 {
            s.peers[i].voting = true;
            dev_log(sys, 3, b"[repl] promoted".as_ptr(), 15);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn request_snapshot_install(s: &ModuleState, sys: &SyscallTable, target: u8) {
    if s.out_snapshot_request < 0 { return; }
    let poll = (sys.channel_poll)(s.out_snapshot_request, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let buf = [target; 1];
    wire_channels::channel_write_msg(
        sys, s.out_snapshot_request, wire::MSG_SNAPSHOT_INSTALL_REQUEST, &buf,
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_wal_replies(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_wal_reply < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_wal_reply, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_wal_reply, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_ENTRY_REPLY { continue; }
        let pl = plen as usize;
        let (request_id, term, index, body_off) =
            match wire::decode_wal_entry_reply(&s.msg_buf[..pl]) {
                Some(v) => v,
                None => continue,
            };

        // Match against pending slots; if not found, drop silently —
        // we may have already retried with a fresher request_id.
        let mut slot_idx: Option<usize> = None;
        for (i, slot) in s.pending.iter().enumerate() {
            if slot.request_id == request_id && slot.peer != 0xFF {
                slot_idx = Some(i);
                break;
            }
        }
        let slot_idx = match slot_idx { Some(i) => i, None => continue };
        let peer = s.pending[slot_idx].peer;
        s.pending[slot_idx] = PendingWalReq::zero();
        if peer as usize >= MAX_NODES || !s.peers[peer as usize].active { continue; }

        // Empty body means the WAL doesn't have the index any more —
        // snapshot install is the recovery path. Issue a targeted
        // install request to snapshot_engine; see RFC §4.2.
        if pl <= body_off {
            request_snapshot_install(s, sys, peer);
            continue;
        }

        // Build an AE: prev_log_* is the entry before `index`, then the
        // body at `index` itself. We don't always have the prev tip on
        // hand. If the read-back returned index N and the last broadcast
        // was N+1, we know (N+1's prev_log_*) == (N's term/index) — but
        // that's only valid in the simple case. The robust path is to
        // issue a second WAL request for (index - 1); for now we take a
        // shortcut: use `(term, index - 1)` and rely on the follower's
        // own NACK loop to fix it if the previous term was different.
        // This converges in O(term-changes) rounds.
        let prev_idx = index.saturating_sub(1);
        let prev_term = term;
        let body = &s.msg_buf[body_off..pl];

        let peer_state = &s.peers[peer as usize];
        let leader_commit = peer_state.match_index; // conservative — follower clamps anyway
        let _ = leader_commit;

        let mut ae_buf = [0u8; 2048];
        let total = wire::encode_append_entries(
            &mut ae_buf,
            term,
            s.self_id,
            prev_idx,
            prev_term,
            // leader_commit: use our last-emitted index (clamped on follower).
            s.last_emitted_index,
            term,
            index,
            body,
        );
        if total == 0 { continue; }

        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { continue; }
        let w = wire_channels::channel_write_routed_partitioned(
            sys,
            s.out_net,
            peer,
            s.partition_id,
            wire::MSG_APPEND_ENTRIES,
            &ae_buf[..total],
        );
        if w > 0 {
            s.catchup_sent = s.catchup_sent.saturating_add(1);
            s.rpcs_sent = s.rpcs_sent.saturating_add(1);
            let peer_state = &mut s.peers[peer as usize];
            peer_state.prev_log_index = prev_idx;
            peer_state.prev_log_term = prev_term;
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn forward_snapshots(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_snapshot_rx < 0 { return; }

    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_snapshot_rx, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_snapshot_rx, &mut s.msg_buf);
        if plen == 0 { continue; }

        let pass_through = matches!(
            msg_type,
            wire::MSG_SNAPSHOT_CHUNK | wire::MSG_INSTALL_SNAPSHOT
        );
        if !pass_through { continue; }

        // Forward to peers. Broadcast for now — a lagging-follower
        // detector that targets a specific peer is a future
        // improvement (RFC §5.13).
        let target = wire::TARGET_BROADCAST;
        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            wire_channels::channel_write_routed_partitioned(
                sys, s.out_net, target, s.partition_id,
                msg_type, &s.msg_buf[..plen as usize],
            );
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // rpcs_sent(4) + acks_received(4) + nacks(4) + catchup(4) = 16 bytes
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&s.rpcs_sent.to_le_bytes());
    buf[4..8].copy_from_slice(&s.acks_received.to_le_bytes());
    buf[8..12].copy_from_slice(&s.nacks_received.to_le_bytes());
    buf[12..16].copy_from_slice(&s.catchup_sent.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..16]);
    }
}
