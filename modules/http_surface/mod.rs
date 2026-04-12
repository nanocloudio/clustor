//! HTTP Surface — Request router and response multiplexer.
//!
//! Routes inbound cleartext from peer_router to raft_rpc, client_req,
//! or admin_req outputs based on message type. Aggregates responses
//! from apply_pipeline, admin_handler, and telemetry for output.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/wire.rs"]
mod wire;

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
    // Track last conn_id for response routing (simple: last-request-wins)
    last_client_conn_id: u8,
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
        dev_log(sys, 3, b"[http] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
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
            s.last_client_conn_id = conn_id;

            // Parse wire envelope from offset 1
            let msg_type = s.msg_buf[1];
            // Debug: log first 6 bytes as hex
            {
                let hex = b"0123456789abcdef";
                let mut dbg = [0u8; 20];
                dbg[0] = b'['; dbg[1] = b'h'; dbg[2] = b']';
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
                wire::MSG_CLIENT_PROPOSAL => {
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
                    wire::channel_write_msg(sys, out_chan, out_type, payload);
                    s.requests_routed += 1;
                    dev_log(sys, 3, b"[http] route".as_ptr(), 12);
                }
            }
        }

        // 2. Forward response inputs → peer_router via responses_out
        //    Prepend last_client_conn_id so peer_router can route back.
        forward_responses_tagged(sys, s.in_client_resp, s.out_responses, s.last_client_conn_id, &mut s.msg_buf, &mut s.responses_sent);
        forward_responses_tagged(sys, s.in_admin_resp, s.out_responses, s.last_client_conn_id, &mut s.msg_buf, &mut s.responses_sent);

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

/// Forward messages from a response input to the responses_out channel,
/// prepending the conn_id so peer_router can route back to the client.
/// Format written: [conn_id: u8] [msg_type: u8] [len: u16 LE] [payload]
unsafe fn forward_responses_tagged(
    sys: &SyscallTable, src: i32, dst: i32, conn_id: u8,
    buf: &mut [u8; 2048], count: &mut u32,
) {
    if src < 0 || dst < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(src, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let poll_out = (sys.channel_poll)(dst, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, src, buf);
        if plen == 0 { break; }

        // Write: [conn_id] [envelope: msg_type + len + payload]
        let pl = plen as usize;
        let total = 1 + wire::ENVELOPE_HDR + pl;
        let mut frame = [0u8; 256];
        if total > 256 { continue; }
        frame[0] = conn_id;
        frame[1] = msg_type;
        let lb = plen.to_le_bytes();
        frame[2] = lb[0]; frame[3] = lb[1];
        if pl > 0 {
            frame[4..4 + pl].copy_from_slice(&buf[..pl]);
        }

        (sys.channel_write)(dst, frame.as_ptr(), total);
        *count += 1;
    }
}

unsafe fn drain_input(sys: &SyscallTable, chan: i32, buf: &mut [u8; 2048]) {
    if chan < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let n = (sys.channel_read)(chan, buf.as_mut_ptr(), 2048);
        if n <= 0 { break; }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
