//! Read Gate — Issues linearizable read permits based on CP cache state.

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

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_cache: i32,    // in[0]: CacheState from cp_proof_cache
    out_permits: i32, // out[0]: ReadPermit to apply_pipeline
    cache_state: u8,  // CP_FRESH..CP_EXPIRED
    msg_buf: [u8; 32],
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
        s.in_cache = in_chan;
        s.out_permits = out_chan;
        s.cache_state = CP_FRESH; // optimistic until CP tells us otherwise
        dev_log(sys, 3, b"[rgate] init".as_ptr(), 12);
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

        // Drain cache state updates (keep latest)
        loop {
            let poll = (sys.channel_poll)(s.in_cache, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_cache, &mut s.msg_buf);
            if msg_type == wire::MSG_CACHE_STATE && plen >= 1 {
                s.cache_state = wire::decode_cache_state(&s.msg_buf);
            }
        }

        // Only issue read permits when cache is Fresh or Cached
        // (Stale and Expired block linearizable reads)
        if s.cache_state <= CP_CACHED {
            // Emit a standing permit each step so apply_pipeline knows
            // reads are allowed. This is a lightweight signal.
            let poll_out = (sys.channel_poll)(s.out_permits, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                let mut buf = [0u8; 1];
                buf[0] = s.cache_state;
                wire_channels::channel_write_msg(sys, s.out_permits, wire::MSG_READ_PERMIT, &buf[..1]);
            }
        }

        0
    }
}
