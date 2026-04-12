//! Throttle Gate — Admission control point.
//!
//! Consumes credit tokens from flow_controller and admits or rejects
//! client proposals from client_codec.

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
    in_requests: i32,      // in[0]: ClientProposal from client_codec
    in_credits: i32,       // in[1]: ThrottleCredits from flow_controller
    out_admitted: i32,     // out[0]: admitted ClientProposal to raft_engine
    out_rejected: i32,     // out[1]: rejected → client_codec

    entry_credits: i32,
    byte_credits: i32,
    admitted_count: u32,
    rejected_count: u32,
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
        s.out_admitted = out_chan;
        s.in_credits = dev_channel_port(sys, 0, 1);
        s.out_rejected = dev_channel_port(sys, 1, 1);
        // Start with generous credits until flow_controller takes over
        s.entry_credits = 4096;
        s.byte_credits = 64 * 1024;
        dev_log(sys, 3, b"[gate] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 1. Drain credit updates (keep latest)
        loop {
            let poll = (sys.channel_poll)(s.in_credits, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_credits, &mut s.msg_buf);
            if msg_type == wire::MSG_THROTTLE_CREDITS && plen >= 8 {
                let (entry, byte) = wire::decode_credits(&s.msg_buf);
                s.entry_credits = entry;
                s.byte_credits = byte;
            }
        }

        // 2. Process requests
        for _ in 0..8 {
            let poll = (sys.channel_poll)(s.in_requests, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }

            let payload_len = plen as usize;

            if s.entry_credits > 0 && s.byte_credits >= payload_len as i32 {
                // Admit
                let poll_out = (sys.channel_poll)(s.out_admitted, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    wire::channel_write_msg(sys, s.out_admitted, wire::MSG_CLIENT_PROPOSAL, &s.msg_buf[..payload_len]);
                    s.entry_credits -= 1;
                    s.byte_credits -= payload_len as i32;
                    s.admitted_count += 1;
                }
            } else {
                // Reject with throttle envelope
                if s.out_rejected >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_rejected, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        let mut env = [0u8; 8];
                        wire::encode_credits(&mut env, s.entry_credits, s.byte_credits);
                        wire::channel_write_msg(sys, s.out_rejected, wire::MSG_THROTTLE_ENVELOPE, &env[..8]);
                    }
                }
                s.rejected_count += 1;
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
