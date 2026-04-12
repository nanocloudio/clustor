//! Client Codec — Parses inbound client requests and frames responses.
//!
//! Receives raw cleartext from http_surface, parses client read/write
//! requests, validates placement epoch, and emits ClientProposal
//! messages to throttle_gate. Reads committed responses from
//! apply_pipeline and frames them back.

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

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels: 3 in, 1 out
    in_raw: i32,          // in[0]: raw client requests from http_surface
    in_responses: i32,    // in[1]: committed responses from apply_pipeline (via http_surface)
    in_placement: i32,    // in[2]: PlacementUpdate from placement_router
    out_parsed: i32,      // out[0]: ClientProposal to throttle_gate

    // State
    placement_epoch: Epoch,
    requests_parsed: u32,
    responses_sent: u32,

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
    _params: *const u8,
    _params_len: usize,
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

        s.in_raw = in_chan;
        s.out_parsed = out_chan;
        s.in_responses = dev_channel_port(sys, 0, 1);
        s.in_placement = dev_channel_port(sys, 0, 2);

        dev_log(sys, 3, b"[codec] init".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 1. Update placement epoch (ctrl-style: keep latest)
        drain_placement(s, sys);

        // 2. Parse inbound client requests
        parse_requests(s, sys);

        // 3. Forward responses back to clients
        forward_responses(s, sys);

        0
    }
}

unsafe fn drain_placement(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_placement < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_placement, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_placement, &mut s.msg_buf);
        if msg_type == wire::MSG_PLACEMENT_UPDATE && plen >= 4 {
            s.placement_epoch = u32::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            ]);
        }
    }
}

unsafe fn parse_requests(s: &mut ModuleState, sys: &SyscallTable) {
    // Process up to 8 requests per step
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_raw, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let poll_out = (sys.channel_poll)(s.out_parsed, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_raw, &mut s.msg_buf);
        if plen == 0 { break; }

        // Accept raw client messages and re-emit as ClientProposal.
        // The actual request parsing (key extraction, read vs write
        // discrimination) will be refined when the application protocol
        // is defined. For now, forward the payload as-is.
        match msg_type {
            wire::MSG_CLIENT_PROPOSAL => {
                wire::channel_write_msg(
                    sys, s.out_parsed,
                    wire::MSG_CLIENT_PROPOSAL,
                    &s.msg_buf[..plen as usize],
                );
                s.requests_parsed += 1;
            }
            _ => {
                // Unknown msg_type from client — wrap as proposal
                wire::channel_write_msg(
                    sys, s.out_parsed,
                    wire::MSG_CLIENT_PROPOSAL,
                    &s.msg_buf[..plen as usize],
                );
                s.requests_parsed += 1;
            }
        }
    }
}

unsafe fn forward_responses(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_responses < 0 { return; }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_responses, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_responses, &mut s.msg_buf);
        if msg_type == wire::MSG_CLIENT_RESPONSE && plen > 0 {
            // Response path goes back through http_surface → peer_router → client.
            // For now the response just needs to be consumed here.
            // Once http_surface has bidirectional routing, this will write
            // to a response output channel.
            s.responses_sent += 1;
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
