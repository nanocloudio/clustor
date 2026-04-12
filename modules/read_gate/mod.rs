//! Read Gate — Issues linearizable read permits based on CP cache state.

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
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Drain cache state updates (keep latest)
        loop {
            let poll = (sys.channel_poll)(s.in_cache, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_cache, &mut s.msg_buf);
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
                wire::channel_write_msg(sys, s.out_permits, wire::MSG_READ_PERMIT, &buf[..1]);
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
