//! Client Surface — Client envelope adapter (formerly `http_surface`).
//!
//! Routes inbound Clustor wire envelopes from peer_router to raft_rpc,
//! client_req, or admin_req outputs based on `msg_type`. Aggregates
//! responses from apply_pipeline, admin_handler, and telemetry_agg for
//! output back to peer_router. Despite its former name, this module
//! does NOT parse HTTP — Fluxor foundation `http` is the canonical
//! HTTP module. See `.context/rfc_fluxor_native_module_coherence.md`
//! §4.5 / §10 for the rename rationale.
//!
//! Successful responses and rejections now carry `[conn_id:u8]` through
//! `client_codec`, so the surface does not infer routing from global
//! last-request state.

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

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    // 7 inputs, 3 outputs
    in_requests: i32,         // in[0]: cleartext from peer_router
    in_throttle_status: i32,  // in[1]: ThrottleEnvelope from flow_controller
    in_client_resp: i32,      // in[2]: ClientResponse from apply_pipeline
    in_admin_resp: i32,       // in[3]: AdminResponse from admin_handler/rbac
    in_readyz: i32,           // in[4]: readyz from telemetry_agg
    in_why: i32,              // in[5]: why from telemetry_agg
    in_metrics: i32,          // in[6]: export from telemetry_agg
    out_raft_rpc: i32,        // out[0]: Raft RPC to raft_engine
    out_client_req: i32,      // out[1]: client requests to client_codec
    out_admin_req: i32,       // out[2]: admin requests to rbac
    out_responses: i32,       // out[3]: responses back to peer_router

    requests_routed: u32,
    responses_sent: u32,
    msg_buf: [u8; 2048],
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
        s.out_raft_rpc = out_chan;
        s.in_throttle_status = dev_channel_port(sys, 0, 1);
        s.in_client_resp = dev_channel_port(sys, 0, 2);
        s.in_admin_resp = dev_channel_port(sys, 0, 3);
        s.in_readyz = dev_channel_port(sys, 0, 4);
        s.in_why = dev_channel_port(sys, 0, 5);
        s.in_metrics = dev_channel_port(sys, 0, 6);
        s.out_client_req = dev_channel_port(sys, 1, 1);
        s.out_admin_req = dev_channel_port(sys, 1, 2);
        s.out_responses = dev_channel_port(sys, 1, 3);
        dev_log(sys, 3, b"[client] init".as_ptr(), 13);
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

        // 1. Route inbound requests by message type
        //    peer_router prepends [conn_id: u8] before the wire envelope.
        //    Raw format: [conn_id] [msg_type] [len: u16 LE] [payload]
        for _ in 0..8 {
            let poll = (sys.channel_poll)(s.in_requests, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let n = (sys.channel_read)(s.in_requests, s.msg_buf.as_mut_ptr(), 2048);
            if n < 4 { break; } // need at least conn_id + 3-byte envelope header
            let len = n as usize;

            // Extract conn_id prefix
            let conn_id = s.msg_buf[0];
            // Parse wire envelope from offset 1
            let msg_type = s.msg_buf[1];
            // Debug: log first 6 bytes as hex
            {
                let hex = b"0123456789abcdef";
                let mut dbg = [0u8; 20];
                dbg[0] = b'['; dbg[1] = b'c'; dbg[2] = b']';
                let show = len.min(6);
                for bi in 0..show {
                    dbg[3 + bi*2] = hex[(s.msg_buf[bi] >> 4) as usize];
                    dbg[4 + bi*2] = hex[(s.msg_buf[bi] & 0xF) as usize];
                }
                dev_log(sys, 3, dbg.as_ptr(), 3 + show * 2);
            }
            let payload_len = u16::from_le_bytes([s.msg_buf[2], s.msg_buf[3]]) as usize;
            let payload_start = 4usize; // 1 (conn_id) + 3 (envelope)
            let payload_end = (payload_start + payload_len).min(len);
            let payload = &s.msg_buf[payload_start..payload_end];

            let (out_chan, out_type) = match msg_type {
                wire::MSG_APPEND_ENTRIES | wire::MSG_APPEND_ENTRIES_RESP |
                wire::MSG_REQUEST_VOTE | wire::MSG_REQUEST_VOTE_RESP |
                wire::MSG_PRE_VOTE | wire::MSG_PRE_VOTE_RESP |
                wire::MSG_HEARTBEAT | wire::MSG_HEARTBEAT_RESP => {
                    (s.out_raft_rpc, msg_type)
                }
                wire::MSG_CLIENT_PROPOSAL | wire::MSG_CLIENT_READ_REQUEST => {
                    (s.out_client_req, msg_type)
                }
                wire::MSG_ADMIN_COMMAND => {
                    (s.out_admin_req, msg_type)
                }
                _ => {
                    (s.out_client_req, wire::MSG_CLIENT_PROPOSAL)
                }
            };

            if out_chan >= 0 {
                let poll_out = (sys.channel_poll)(out_chan, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    if out_chan == s.out_raft_rpc {
                        // raft_engine.rpc_in expects 5-byte partitioned
                        // envelopes (step 6b). Client-injected Raft RPCs
                        // are admin-side and don't carry a partition
                        // tag, so we stamp partition_id=0; in multi-
                        // partition deployments those frames will be
                        // dropped by every raft_engine_pN with id != 0.
                        wire_channels::channel_write_partitioned(sys, out_chan, 0, out_type, payload);
                    } else {
                        // Client/admin path: prepend per-message conn_id
                        // so downstream (client_codec, rbac, admin_handler)
                        // can correlate responses back to this connection.
                        // See RFC §4.5 / §5.8.
                        let mut framed = [0u8; 2048];
                        framed[0] = conn_id;
                        let pl = payload.len().min(framed.len() - 1);
                        framed[1..1 + pl].copy_from_slice(&payload[..pl]);
                        wire_channels::channel_write_msg(sys, out_chan, out_type, &framed[..1 + pl]);
                    }
                    s.requests_routed += 1;
                    dev_log(sys, 3, b"[client] route".as_ptr(), 14);
                }
            }
        }

        // 2. Forward response inputs → peer_router via responses_out.
        //    Every response payload now begins with `[conn_id:u8]`;
        //    forward_responses_tagged strips it and uses it as the
        //    per-message routing tag for peer_router (RFC §4.5).
        forward_responses_tagged(sys, s.in_client_resp, s.out_responses, &mut s.msg_buf, &mut s.responses_sent);
        forward_responses_tagged(sys, s.in_admin_resp, s.out_responses, &mut s.msg_buf, &mut s.responses_sent);

        // 3. Drain telemetry/status inputs (these produce diagnostic
        //    responses on /readyz, /why, /metrics endpoints — for now
        //    drain to prevent backpressure; HTTP response framing is
        //    future work)
        drain_input(sys, s.in_throttle_status, &mut s.msg_buf);
        drain_input(sys, s.in_readyz, &mut s.msg_buf);
        drain_input(sys, s.in_why, &mut s.msg_buf);
        drain_input(sys, s.in_metrics, &mut s.msg_buf);

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Forward messages from a response input to the responses_out channel.
/// Expects each payload to start with `[conn_id:u8]` (set by the upstream
/// response producer — `client_codec` for client traffic, `admin_handler`
/// or `rbac` for admin traffic). The conn_id is stripped and used as the
/// routing tag for peer_router.
/// Wire bytes written to `dst`: `[conn_id:u8] [msg_type:u8] [len:u16 LE] [payload-without-conn-id]`.
unsafe fn forward_responses_tagged(
    sys: &SyscallTable, src: i32, dst: i32,
    buf: &mut [u8; 2048], count: &mut u32,
) {
    if src < 0 || dst < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(src, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let poll_out = (sys.channel_poll)(dst, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, src, buf);
        if plen == 0 { break; }
        // Payload must carry at least the conn_id byte. Anything shorter
        // is a wiring mistake — drop it rather than misroute.
        if (plen as usize) < 1 { continue; }

        let conn_id = buf[0];
        let inner_len = plen as usize - 1;
        let total = 1 + wire::ENVELOPE_HDR + inner_len;
        let mut frame = [0u8; 256];
        if total > 256 { continue; }
        frame[0] = conn_id;
        frame[1] = msg_type;
        let lb = (inner_len as u16).to_le_bytes();
        frame[2] = lb[0]; frame[3] = lb[1];
        if inner_len > 0 {
            frame[4..4 + inner_len].copy_from_slice(&buf[1..1 + inner_len]);
        }

        (sys.channel_write)(dst, frame.as_ptr(), total);
        *count += 1;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_input(sys: &SyscallTable, chan: i32, buf: &mut [u8; 2048]) {
    if chan < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let n = (sys.channel_read)(chan, buf.as_mut_ptr(), 2048);
        if n <= 0 { break; }
    }
}
