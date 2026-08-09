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
//!      Bound (`cp::step`): ≤1 proof + ≤1 tenant record + ≤1
//!      capability manifest, on the refresh tick only.
//!   2. `placement` — bootstrap routing update + epoch transitions.
//!      Bound (`placement::step`): ≤1 routing update + ≤1 epoch
//!      event.
//!
//! The dispatch table brackets both component steps with `dev_micros`
//! reads and publishes a per-component step-time histogram each
//! second under the component's source id (`step_accounting`,
//! §8 rule 8) on the optional `metrics` port.

#![cfg_attr(not(feature = "host-test"), no_std)]
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
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;
#[path = "../../common/step_accounting.rs"]
mod step_accounting;

mod cp;
mod placement;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    cp: cp::Cp,
    placement: placement::Placement,

    /// Optional metrics port; carries only the §8 per-component step
    /// accounting (see the manifest's observability note).
    out_metrics: i32,
    /// Per-component step-time histograms (§8 rule 8), owned by the
    /// dispatch table: [cp, placement].
    comp_step: [step_accounting::CompStepHist; 2],
    comp_step_last_ms: u64,
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
        s.out_metrics = dev_channel_port(sys, 1, 5);
        s.comp_step = [step_accounting::CompStepHist::new(); 2];
        s.comp_step_last_ms = 0;

        dev_log(sys, 3, b"[cp] init".as_ptr(), 9);
        dev_log(sys, 3, b"[plac] init".as_ptr(), 11);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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

        let mut t0 = dev_micros(sys);
        cp::step(&mut s.cp, sys, now);
        let t1 = dev_micros(sys);
        s.comp_step[0].record(t1.wrapping_sub(t0));
        t0 = t1;
        placement::step(&mut s.placement, sys);
        s.comp_step[1].record(dev_micros(sys).wrapping_sub(t0));

        // Per-component step accounting (§8 rule 8): publish each
        // component's step-time histogram every second under its own
        // source id (no-op when the metrics port is unwired).
        if now.wrapping_sub(s.comp_step_last_ms) >= 1000 {
            s.comp_step_last_ms = now;
            s.comp_step[0].emit(sys, s.out_metrics, wire::SOURCE_ID_CP, 0);
            s.comp_step[1].emit(sys, s.out_metrics, wire::SOURCE_ID_PLACEMENT, 0);
        }
        0
    }
}
