//! Throttle Gate — Admission control point.
//!
//! Consumes credit tokens from flow_controller and admits or rejects
//! client proposals from client_codec.

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
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 1. Drain credit updates (keep latest)
        loop {
            let poll = (sys.channel_poll)(s.in_credits, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_credits, &mut s.msg_buf);
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

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }

            let payload_len = plen as usize;

            // Tagged-proposal convention (RFC §5.8): client_codec stamps
            // every proposal with `[correlation_id:u64 LE][body]`. We need
            // the correlation_id so rejections can be mapped back to a
            // conn_id; drop frames that are too short to be tagged.
            if payload_len < wire::TAGGED_PROPOSAL_HDR { continue; }
            let correlation_id = u64::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
            ]);

            if s.entry_credits > 0 && s.byte_credits >= payload_len as i32 {
                // Admit — forward the tagged payload unchanged to
                // raft_engine.proposals_tagged (configured in YAML).
                let poll_out = (sys.channel_poll)(s.out_admitted, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    wire_channels::channel_write_msg(sys, s.out_admitted, wire::MSG_CLIENT_PROPOSAL, &s.msg_buf[..payload_len]);
                    s.entry_credits -= 1;
                    s.byte_credits -= payload_len as i32;
                    s.admitted_count += 1;
                }
            } else {
                // Reject with the internal envelope: `[correlation_id][body]`.
                // client_codec will look up correlation_id → conn_id and
                // emit the wire-facing MSG_CLIENT_REJECT.
                if s.out_rejected >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_rejected, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        let mut env = [0u8; wire::CLIENT_REJECT_INTERNAL_LEN];
                        let retry_ms: u16 = if s.entry_credits > 0 { 5 } else { 50 };
                        let entry_clamped =
                            s.entry_credits.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                        wire::encode_client_reject_internal(
                            &mut env,
                            correlation_id,
                            wire::CLIENT_REJECT_THROTTLED,
                            retry_ms,
                            entry_clamped,
                            s.byte_credits,
                        );
                        wire_channels::channel_write_msg(
                            sys,
                            s.out_rejected,
                            wire::MSG_CLIENT_REJECT_INTERNAL,
                            &env[..wire::CLIENT_REJECT_INTERNAL_LEN],
                        );
                    }
                }
                s.rejected_count += 1;
            }
        }

        0
    }
}
