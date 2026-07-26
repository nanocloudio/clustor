//! Control plane — CP proof source and placement routing.
//!
//! One graph module composed of two source components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`cp`]        — periodic CP proofs, tenant records, capabilities.
//!   - [`placement`] — placement epochs and kpg-keyed epoch events.
//!
//! ## Dispatch table
//!
//! Both components are independent timer-driven sources; the order
//! below is fixed but carries no delivery dependency:
//!
//!   1. `cp`        — refresh-tick proof/tenant/capability emission.
//!   2. `placement` — bootstrap routing update + epoch transitions.

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

mod cp;
mod placement;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    cp: cp::Cp,
    placement: placement::Placement,
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
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        cp::init(&mut s.cp);
        placement::init(&mut s.placement);

        s.cp.out_proof = out_chan; // out[0] proof
        s.cp.out_tenant_records = dev_channel_port(sys, 1, 1);
        s.cp.out_capabilities = dev_channel_port(sys, 1, 2);
        s.placement.out_routing = dev_channel_port(sys, 1, 3);
        s.placement.out_epoch_events = dev_channel_port(sys, 1, 4);

        dev_log(sys, 3, b"[cp] init".as_ptr(), 9);
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
        let now = dev_millis(sys);

        cp::step(&mut s.cp, sys, now);
        placement::step(&mut s.placement, sys);
        0
    }
}
