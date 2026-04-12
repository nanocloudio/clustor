//! Raft Engine — Core Raft consensus state machine.
//!
//! Implements leader election (with pre-vote), log replication dispatch,
//! proposal batching, and heartbeat generation. Role-dependent step logic
//! drives the follower/candidate/leader state machine.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/types.rs"]
mod types;

#[path = "../common/wire.rs"]
mod wire;

use types::*;

const PROPOSAL_BATCH_CAP: usize = 2048;

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

    5, proposal_batch_max, u16, 64
        => |s, d, len| { s.proposal_batch_max = p_u16(d, len, 0, 64); };

    6, proposal_batch_timeout_ms, u16, 10
        => |s, d, len| { s.proposal_batch_timeout_ms = p_u16(d, len, 0, 10); };
}

// FS opcodes
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
const FS_SEEK: u32 = 0x0902;

// Metadata file: "raft/meta"
// Format: [term: u64] [voted_for: i8] [last_log_index: u64] [last_log_term: u64] = 25 bytes
const META_PATH: &[u8] = b"raft/meta";
const META_SIZE: usize = 25;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // ── Channels (4 in, 4 out) ──────────────────────────────
    in_rpc: i32,              // in[0]: RPC from peers (via http_surface)
    in_proposals: i32,        // in[1]: ClientProposal from throttle_gate
    in_admin: i32,            // in[2]: AdminCommand from admin_handler
    in_fallback: i32,         // in[3]: FallbackSignal from cp_proof_cache
    out_append: i32,          // out[0]: AppendEntries to replicator
    out_rpc: i32,             // out[1]: Vote/Heartbeat RPC to peer_router
    out_log: i32,             // out[2]: WalEntry to wal
    out_metrics: i32,         // out[3]: MetricsPayload to telemetry_agg

    // ── Raft persistent state ───────────────────────────────
    current_term: Term,
    voted_for: i8,            // -1 = none, 0..6 = replica id
    self_id: ReplicaId,

    // ── Volatile state ──────────────────────────────────────
    role: u8,                 // ROLE_FOLLOWER / CANDIDATE / LEADER
    leader_id: i8,            // -1 = unknown
    voter_count: u8,

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

    // ── Proposal batching ───────────────────────────────────
    proposal_batch: [u8; PROPOSAL_BATCH_CAP],
    proposal_batch_len: u16,
    proposal_batch_count: u16,
    proposal_batch_max: u16,
    proposal_batch_start_ms: u64,
    proposal_batch_timeout_ms: u16,

    // ── Strict fallback ─────────────────────────────────────
    strict_fallback: bool,

    // ── Metrics ─────────────────────────────────────────────
    proposals_received: u32,
    entries_appended: u32,
    elections_started: u32,
    last_metrics_ms: u64,

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
        s.out_rpc = dev_channel_port(sys, 1, 1);
        s.out_log = dev_channel_port(sys, 1, 2);
        s.out_metrics = dev_channel_port(sys, 1, 3);

        // Defaults + TLV param parsing
        s.voted_for = REPLICA_NONE as i8;
        s.leader_id = REPLICA_NONE as i8;
        s.role = ROLE_FOLLOWER;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

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
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // 1. Process inbound RPCs (all roles)
        process_rpc(s, sys, now);

        // 2. Process fallback signal
        drain_fallback(s, sys);

        // 3. Role-specific logic
        match s.role {
            ROLE_FOLLOWER => step_follower(s, sys, now),
            ROLE_CANDIDATE => step_candidate(s, sys, now),
            ROLE_LEADER => step_leader(s, sys, now),
            _ => {}
        }

        // 4. Emit metrics periodically
        emit_metrics(s, sys, now);

        0
    }
}

// ── RPC processing (all roles) ──────────────────────────────

unsafe fn process_rpc(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // Process up to 8 RPCs per step to bound step time
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_rpc, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_rpc, &mut s.msg_buf);
        if plen == 0 { break; }

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
            wire::MSG_HEARTBEAT => {
                handle_heartbeat(s, sys, plen, now);
            }
            wire::MSG_APPEND_ENTRIES_RESP => {
                // Handled by replicator, not raft_engine. Shouldn't arrive here
                // but ignore gracefully.
            }
            _ => {}
        }
    }
}

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
        wire::channel_write_routed(sys, s.out_rpc, candidate, resp_type, &resp[..10]);
    }
}

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

unsafe fn handle_append_entries(s: &mut ModuleState, sys: &SyscallTable, plen: u16, now: u64) {
    if plen < 17 { return; }
    let (term, index, leader) = wire::decode_term_index_replica(&s.msg_buf);

    if term < s.current_term {
        // Reject: stale term. Send response with our term.
        send_append_response(s, sys, false);
        return;
    }

    if term > s.current_term || s.role != ROLE_FOLLOWER {
        become_follower(s, term);
    }
    s.leader_id = leader as i8;
    reset_election_deadline(s, now);

    // Accept entry: write to WAL
    if index > 0 {
        // Forward the full entry to WAL
        let entry_payload_start = 17usize; // after term+index+replica header
        let entry_len = (plen as usize).saturating_sub(entry_payload_start);

        // Build WalEntry: term(8) + index(8) + payload
        let mut wal_buf = [0u8; 256];
        wire::encode_term_index(&mut wal_buf, term, index);
        let copy_len = entry_len.min(wal_buf.len() - 16);
        if copy_len > 0 {
            wal_buf[16..16 + copy_len].copy_from_slice(&s.msg_buf[entry_payload_start..entry_payload_start + copy_len]);
        }

        let poll = (sys.channel_poll)(s.out_log, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            wire::channel_write_msg(sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf[..16 + copy_len]);
        }

        s.last_log_index = index;
        s.last_log_term = term;
        s.entries_appended += 1;
    }

    send_append_response(s, sys, true);
}

unsafe fn handle_heartbeat(s: &mut ModuleState, _sys: &SyscallTable, plen: u16, now: u64) {
    if plen < 17 { return; }
    let (term, _commit_index, leader) = wire::decode_term_index_replica(&s.msg_buf);

    if term > s.current_term || s.role != ROLE_FOLLOWER {
        become_follower(s, term);
    }
    if term >= s.current_term {
        s.leader_id = leader as i8;
        reset_election_deadline(s, now);
    }
}

unsafe fn send_append_response(s: &ModuleState, sys: &SyscallTable, success: bool) {
    let mut resp = [0u8; 17];
    wire::encode_term_index_replica(
        &mut resp,
        s.current_term,
        s.last_log_index,
        s.self_id,
    );
    // Encode success flag: self_id | (success << 7)
    resp[16] = s.self_id | ((success as u8) << 7);

    // Route back to leader
    let target = if s.leader_id >= 0 { s.leader_id as u8 } else { wire::TARGET_BROADCAST };
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire::channel_write_routed(sys, s.out_rpc, target, wire::MSG_APPEND_ENTRIES_RESP, &resp[..17]);
    }
}

// ── Follower step ───────────────────────────────────────────

unsafe fn step_follower(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if now >= s.election_deadline_ms {
        // Election timeout — start pre-vote
        start_election(s, sys, now, true);
    }
}

// ── Candidate step ──────────────────────────────────────────

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

unsafe fn step_leader(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
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

unsafe fn drain_proposals(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.in_proposals < 0 { return; }

    for _ in 0..16 {
        let poll = (sys.channel_poll)(s.in_proposals, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_proposals, &mut s.msg_buf);
        if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }

        let payload_len = plen as usize;
        let space = PROPOSAL_BATCH_CAP - s.proposal_batch_len as usize;
        if payload_len > space { break; } // batch full, back-pressure

        let start = s.proposal_batch_len as usize;
        s.proposal_batch[start..start + payload_len]
            .copy_from_slice(&s.msg_buf[..payload_len]);
        s.proposal_batch_len += payload_len as u16;
        s.proposal_batch_count += 1;
        s.proposals_received += 1;

        if s.proposal_batch_count == 1 {
            s.proposal_batch_start_ms = now;
            dev_log(sys, 3, b"[raft] prop".as_ptr(), 11);
        }
    }
}

unsafe fn flush_proposal_batch(s: &mut ModuleState, sys: &SyscallTable) {
    if s.proposal_batch_count == 0 { return; }

    // Advance log
    s.last_log_index += 1;
    s.last_log_term = s.current_term;

    let batch_len = s.proposal_batch_len as usize;

    // Write to WAL (log_append)
    {
        let mut wal_buf = [0u8; PROPOSAL_BATCH_CAP + 16];
        wire::encode_term_index(&mut wal_buf, s.current_term, s.last_log_index);
        wal_buf[16..16 + batch_len].copy_from_slice(&s.proposal_batch[..batch_len]);

        let poll = (sys.channel_poll)(s.out_log, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            wire::channel_write_msg(sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf[..16 + batch_len]);
        }
    }

    // Send to replicator (append_entries)
    {
        let mut ae_buf = [0u8; PROPOSAL_BATCH_CAP + 17];
        wire::encode_term_index_replica(
            &mut ae_buf,
            s.current_term,
            s.last_log_index,
            s.self_id,
        );
        ae_buf[17..17 + batch_len].copy_from_slice(&s.proposal_batch[..batch_len]);

        let poll = (sys.channel_poll)(s.out_append, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            wire::channel_write_msg(sys, s.out_append, wire::MSG_APPEND_ENTRIES, &ae_buf[..17 + batch_len]);
        }
    }

    s.entries_appended += 1;
    save_metadata(s, sys);
    dev_log(sys, 3, b"[raft] flush".as_ptr(), 12);

    // Reset batch
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
}

unsafe fn send_heartbeat(s: &ModuleState, sys: &SyscallTable) {
    let mut hb = [0u8; 17];
    wire::encode_term_index_replica(&mut hb, s.current_term, s.commit_index, s.self_id);

    // Broadcast heartbeat to all peers via routed envelope
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire::channel_write_routed(sys, s.out_rpc, wire::TARGET_BROADCAST, wire::MSG_HEARTBEAT, &hb[..17]);
    }
}

// ── Metadata persistence ────────────────────────────────────

/// Load persistent Raft state from "raft/meta".
/// Format: [term: u64 LE] [voted_for: i8] = 9 bytes.
unsafe fn load_metadata(s: &mut ModuleState, sys: &SyscallTable) {
    let fd = (sys.dev_call)(-1, FS_OPEN, META_PATH.as_ptr() as *mut u8, META_PATH.len());
    if fd < 0 { return; } // no metadata file — fresh start

    let mut buf = [0u8; META_SIZE];
    let n = (sys.dev_call)(fd, FS_READ, buf.as_mut_ptr(), META_SIZE);
    (sys.dev_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);

    if n as usize >= META_SIZE {
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
    }
}

/// Save persistent Raft state to "raft/meta".
unsafe fn save_metadata(s: &ModuleState, sys: &SyscallTable) {
    let fd = (sys.dev_call)(-1, FS_OPEN, META_PATH.as_ptr() as *mut u8, META_PATH.len());
    if fd < 0 { return; } // FS not available

    // Seek to start (overwrite)
    let zero = 0i32.to_le_bytes();
    (sys.dev_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4);

    let mut buf = [0u8; META_SIZE];
    buf[0..8].copy_from_slice(&s.current_term.to_le_bytes());
    buf[8] = s.voted_for as u8;
    buf[9..17].copy_from_slice(&s.last_log_index.to_le_bytes());
    buf[17..25].copy_from_slice(&s.last_log_term.to_le_bytes());
    (sys.dev_call)(fd, FS_WRITE, buf.as_mut_ptr(), META_SIZE);
    (sys.dev_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    (sys.dev_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
}

// ── State transitions ───────────────────────────────────────

unsafe fn become_follower(s: &mut ModuleState, term: Term) {
    s.current_term = term;
    s.role = ROLE_FOLLOWER;
    s.voted_for = REPLICA_NONE as i8;
    s.votes_granted.clear();
    s.votes_rejected.clear();
    s.pre_vote_active = false;
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
    save_metadata(s, &*s.syscalls);
}

unsafe fn become_leader(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    s.role = ROLE_LEADER;
    s.leader_id = s.self_id as i8;
    s.votes_granted.clear();
    s.votes_rejected.clear();
    s.pre_vote_active = false;
    s.last_heartbeat_ms = now;
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;

    dev_log(sys, 3, b"[raft] leader".as_ptr(), 13);

    // Send immediate heartbeat to assert leadership
    send_heartbeat(s, sys);
}

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
        wire::channel_write_routed(sys, s.out_rpc, wire::TARGET_BROADCAST, msg_type, &req[..25]);
    }

    dev_log(sys, 3, b"[raft] elect".as_ptr(), 12);
}

unsafe fn reset_election_deadline(s: &mut ModuleState, now: u64) {
    let mut seed = (now as u32) ^ 0xBEEF;
    let half_timeout2 = (s.election_timeout_ms as u32 / 2).max(1);
    let jitter = (xorshift32(&mut seed) & (half_timeout2.next_power_of_two() - 1)) as u64;
    s.election_deadline_ms = now + s.election_timeout_ms as u64 + jitter;
}

// ── Fallback signal ─────────────────────────────────────────

unsafe fn drain_fallback(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_fallback < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_fallback, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_fallback, &mut s.msg_buf);
        if msg_type == wire::MSG_FALLBACK_SIGNAL && plen >= 1 {
            s.strict_fallback = s.msg_buf[0] != 0;
        }
    }
}

// ── Metrics ─────────────────────────────────────────────────

unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < 1000 { return; }
    s.last_metrics_ms = now;

    // role(1) + term(8) + proposals(4) + entries(4) + elections(4) = 21
    let mut buf = [0u8; 21];
    buf[0] = s.role;
    buf[1..9].copy_from_slice(&s.current_term.to_le_bytes());
    buf[9..13].copy_from_slice(&s.proposals_received.to_le_bytes());
    buf[13..17].copy_from_slice(&s.entries_appended.to_le_bytes());
    buf[17..21].copy_from_slice(&s.elections_started.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..21]);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
