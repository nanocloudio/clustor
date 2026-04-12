//! Admin Handler — Idempotency-keyed admin workflows.
//!
//! Processes authorized admin commands from RBAC, validates idempotency,
//! and emits Raft proposals for membership/durability/leadership operations.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/wire.rs"]
mod wire;

const IDEMP_SLOTS: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct IdempEntry {
    key_hash: u32,
    timestamp_ms: u64,
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,     // in[0]: authorized AdminCommand from rbac
    out_raft: i32,        // out[0]: admin proposals to raft_engine
    out_responses: i32,   // out[1]: AdminResponse to http_surface

    idemp_ttl_ms: u64,
    idemp: [IdempEntry; IDEMP_SLOTS],
    idemp_count: u8,
    commands_processed: u32,
    msg_buf: [u8; 1024],
}

fn hash_bytes(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
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
        s.out_raft = out_chan;
        s.out_responses = dev_channel_port(sys, 1, 1);
        s.idemp_ttl_ms = 3_600_000; // 1 hour
        dev_log(sys, 3, b"[admin] init".as_ptr(), 12);
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

        for _ in 0..4 {
            let poll = (sys.channel_poll)(s.in_requests, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 { continue; }

            let payload = &s.msg_buf[..plen as usize];
            let key_hash = hash_bytes(payload);

            // Check idempotency
            let mut dup = false;
            for i in 0..s.idemp_count as usize {
                if s.idemp[i].key_hash == key_hash
                    && now.wrapping_sub(s.idemp[i].timestamp_ms) < s.idemp_ttl_ms
                {
                    dup = true;
                    break;
                }
            }

            if dup {
                // Already processed — send cached OK response
                if s.out_responses >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_responses, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        let resp = [0x01u8]; // OK
                        wire::channel_write_msg(sys, s.out_responses, wire::MSG_ADMIN_RESPONSE, &resp);
                    }
                }
                continue;
            }

            // Record in idempotency ledger
            let slot = (s.idemp_count as usize) % IDEMP_SLOTS;
            s.idemp[slot] = IdempEntry { key_hash, timestamp_ms: now };
            if (s.idemp_count as usize) < IDEMP_SLOTS { s.idemp_count += 1; }

            // Forward as Raft admin proposal
            let poll_out = (sys.channel_poll)(s.out_raft, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                wire::channel_write_msg(sys, s.out_raft, wire::MSG_ADMIN_COMMAND, payload);
            }

            s.commands_processed += 1;
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
