//! Replicator — Pipelines AppendEntries to followers, collects acks,
//! and emits match index updates.
//!
//! Receives batched entries from raft_engine, frames them as peer RPCs
//! via net_out to peer_router, and processes ack responses to update
//! per-peer replication state.

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

const METRICS_INTERVAL_MS: u64 = 1000;

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, peer_count, u8, 0
        => |s, d, len| { s.peer_count = p_u8(d, len, 0, 0); };

    3, pipeline_depth, u8, 8
        => |s, d, len| { s.pipeline_depth = p_u8(d, len, 0, 8); };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PeerState {
    next_index: Index,
    match_index: Index,
    inflight: u8,
    active: bool,
}

impl PeerState {
    const fn zero() -> Self {
        Self { next_index: 1, match_index: 0, inflight: 0, active: false }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels: 3 in, 5 out
    in_entries: i32,        // in[0]: AppendEntries from raft_engine
    in_ack: i32,            // in[1]: responses from peers via peer_router
    in_snapshot_rx: i32,    // in[2]: export chunks from snapshot_engine
    out_net: i32,           // out[0]: RPC frames to peer_router
    out_match: i32,         // out[1]: match index updates to commit_tracker
    out_lag: i32,           // out[2]: lag signal to flow_controller
    out_snapshot_import: i32, // out[3]: import chunks to snapshot_engine
    out_metrics: i32,       // out[4]: metrics to telemetry_agg

    // Config
    self_id: ReplicaId,
    peer_count: u8,
    pipeline_depth: u8,
    structural_lag_bytes: u32,

    // Per-peer state
    peers: [PeerState; MAX_NODES],

    // Metrics
    rpcs_sent: u32,
    acks_received: u32,
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
        s.out_match = dev_channel_port(sys, 1, 1);
        s.out_lag = dev_channel_port(sys, 1, 2);
        s.out_snapshot_import = dev_channel_port(sys, 1, 3);
        s.out_metrics = dev_channel_port(sys, 1, 4);

        s.structural_lag_bytes = 256 * 1024 * 1024;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        // Activate peer slots
        for i in 0..s.peer_count as usize {
            if i < MAX_NODES && i != s.self_id as usize {
                s.peers[i].active = true;
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
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 1. Process inbound entries from raft_engine → fan out to peers
        replicate_entries(s, sys);

        // 2. Process ack responses from peers
        process_acks(s, sys);

        // 3. Forward snapshot chunks
        forward_snapshots(s, sys);

        // 4. Emit metrics
        emit_metrics(s, sys);

        0
    }
}

unsafe fn replicate_entries(s: &mut ModuleState, sys: &SyscallTable) {
    // Process up to 4 entries per step
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_entries, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        // Check output readiness
        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
        if msg_type != wire::MSG_APPEND_ENTRIES || plen < 17 { continue; }

        dev_log(sys, 3, b"[repl] ae in".as_ptr(), 12);
        // Fan out to each active peer with a routed envelope so
        // peer_router can demux to the correct connection.
        let payload = &s.msg_buf[..plen as usize];
        for i in 0..MAX_NODES {
            if !s.peers[i].active { continue; }
            if i == s.self_id as usize { continue; }
            let w = wire::channel_write_routed(
                sys, s.out_net, i as u8,
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

unsafe fn process_acks(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_ack < 0 { return; }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_ack, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_ack, &mut s.msg_buf);
        if plen < 17 { continue; }

        match msg_type {
            wire::MSG_APPEND_ENTRIES_RESP => {
                dev_log(sys, 3, b"[repl] ack".as_ptr(), 10);
                let (_term, index, replica_byte) = wire::decode_term_index_replica(&s.msg_buf);
                let success = (replica_byte & 0x80) != 0;
                let replica = replica_byte & 0x7F;

                if (replica as usize) < MAX_NODES && s.peers[replica as usize].active {
                    let peer = &mut s.peers[replica as usize];
                    if peer.inflight > 0 { peer.inflight -= 1; }

                    if success && index > peer.match_index {
                        peer.match_index = index;
                        peer.next_index = index + 1;

                        // Forward match update to commit_tracker
                        if s.out_match >= 0 {
                            let poll_out = (sys.channel_poll)(s.out_match, 0x02);
                            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                                wire::channel_write_msg(
                                    sys, s.out_match,
                                    wire::MSG_APPEND_ENTRIES_RESP,
                                    &s.msg_buf[..plen as usize],
                                );
                            }
                        }
                    }
                }
                s.acks_received += 1;
            }
            wire::MSG_HEARTBEAT_RESP | wire::MSG_REQUEST_VOTE_RESP | wire::MSG_PRE_VOTE_RESP => {
                // Forward vote/heartbeat responses to raft_engine via net_out
                // (they'll be routed back through http_surface → raft_engine.rpc_in)
                // For now, these pass through the same path.
            }
            _ => {}
        }
    }
}

unsafe fn forward_snapshots(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_snapshot_rx < 0 { return; }

    let poll = (sys.channel_poll)(s.in_snapshot_rx, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 { return; }

    let (msg_type, plen) = wire::channel_read_msg(sys, s.in_snapshot_rx, &mut s.msg_buf);
    if msg_type == wire::MSG_SNAPSHOT_CHUNK && plen > 0 {
        // Forward export chunks to target peer
        let target = wire::TARGET_BROADCAST; // TODO: track per-peer snapshot target
        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            wire::channel_write_routed(sys, s.out_net, target, wire::MSG_SNAPSHOT_CHUNK, &s.msg_buf[..plen as usize]);
        }
    }
}

unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&s.rpcs_sent.to_le_bytes());
    buf[4..8].copy_from_slice(&s.acks_received.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..8]);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
