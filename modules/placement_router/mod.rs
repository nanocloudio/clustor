//! Placement Router — Emits epoch-based routing updates.
//!
//! Pure source module. Maintains the current placement epoch and emits
//! PlacementUpdate messages when the epoch changes (driven by admin
//! operations or CP refresh).

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
    out_routing: i32,     // out[0]: PlacementUpdate to client_codec
    current_epoch: u32,
    emitted: bool,
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
    _in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.out_routing = out_chan;
        s.current_epoch = 1;
        dev_log(sys, 3, b"[plac] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // Emit initial placement epoch once
        if !s.emitted {
            let poll = (sys.channel_poll)(s.out_routing, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let buf = s.current_epoch.to_le_bytes();
                wire::channel_write_msg(sys, s.out_routing, wire::MSG_PLACEMENT_UPDATE, &buf);
                s.emitted = true;
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
