//! Placement Router — Emits epoch-based routing updates.
//!
//! Pure source module. Maintains the current placement epoch and emits
//! PlacementUpdate messages when the epoch changes (driven by admin
//! operations or CP refresh).
//!
//! Quantum enhancement: also emits epoch_events (out[1]) for session
//! fencing on rebalance. Optional — Clustor-only graphs leave unwired.

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
    out_routing: i32,       // out[0]: PlacementUpdate to client_codec
    out_epoch_events: i32,  // out[1]: epoch-change events (Quantum enhancement, optional)
    current_epoch: u32,
    prev_epoch: u32,
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
        s.out_routing = out_chan;
        s.out_epoch_events = dev_channel_port(sys, 1, 1);
        s.current_epoch = 1;
        s.prev_epoch = 0;
        dev_log(sys, 3, b"[plac] init".as_ptr(), 11);
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

        // Emit initial placement epoch once
        if !s.emitted {
            let poll = (sys.channel_poll)(s.out_routing, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let buf = s.current_epoch.to_le_bytes();
                wire_channels::channel_write_msg(sys, s.out_routing, wire::MSG_PLACEMENT_UPDATE, &buf);
                s.emitted = true;
            }
        }

        // Quantum enhancement: emit epoch-change events when epoch advances
        if s.current_epoch != s.prev_epoch && s.out_epoch_events >= 0 {
            let poll = (sys.channel_poll)(s.out_epoch_events, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let mut buf = [0u8; 8];
                buf[0..4].copy_from_slice(&s.prev_epoch.to_le_bytes());
                buf[4..8].copy_from_slice(&s.current_epoch.to_le_bytes());
                wire_channels::channel_write_msg(sys, s.out_epoch_events, 0xD4, &buf);
                s.prev_epoch = s.current_epoch;
            }
        }

        0
    }
}
