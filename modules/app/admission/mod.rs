//! Admission — CP proof freshness, read gating and flow control.
//!
//! One graph module composed of three components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`proof_cache`] — CP proof Fresh/Cached/Stale/Expired ladder;
//!     publishes transitions and the strict-fallback signal.
//!   - [`read_gate`]   — standing linearizable-read permits while the
//!     cache is Fresh/Cached.
//!   - [`flow`]        — dual-token PID admission controller driven by
//!     replicator lag; publishes credits + envelope.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else:
//!
//!   1. `proof_cache` — drain proofs, evaluate the ladder; a
//!      transition delivers the new state into `read_gate` same-step.
//!   2. `read_gate`   — standing permit from the freshest state.
//!   3. `flow`        — lag drain, PID tick, credit emit.
//!
//! `proof` and `input` are the same contract on two attach points, as
//! are `cache_state` and `fresh_state` — deployments differ in which
//! name they wire, and both are part of the published surface.

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
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/types.rs"]
mod types;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

mod flow;
mod proof_cache;
mod read_gate;

define_params! {
    ModuleState;

    1, entry_credit_max, u16, 4096
        => |s, d, len| { s.flow.entry_credit_max = p_u16(d, len, 0, 4096) as i32; };

    2, byte_credit_max_kib, u16, 64
        => |s, d, len| {
            s.flow.byte_credit_max = i32::from(p_u16(d, len, 0, 64)) * 1024;
        };

    3, sample_period_ms, u16, 100
        => |s, d, len| { s.flow.sample_period_ms = p_u16(d, len, 0, 100).max(1); };

    // Optional wall-clock admission rate. Zero preserves the legacy absolute
    // pool publication contract; non-zero derives each published grant from
    // actual elapsed milliseconds, so adaptive scheduler cadence cannot alter
    // the configured requests/second.
    4, entry_rate_per_sec, u16, 0
        => |s, d, len| { s.flow.entry_rate_per_sec = p_u16(d, len, 0, 0) as u32; };

    5, fresh_threshold_s, u16, 60
        => |s, d, len| { s.proof_cache.fresh_threshold_ms = p_u16(d, len, 0, 60) as u64 * 1000; };

    6, grace_period_s, u16, 120
        => |s, d, len| { s.proof_cache.grace_period_ms = p_u16(d, len, 0, 120) as u64 * 1000; };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    proof_cache: proof_cache::ProofCache,
    read_gate: read_gate::ReadGate,
    flow: flow::Flow,
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
    params: *const u8,
    params_len: usize,
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

        proof_cache::init(&mut s.proof_cache, sys);
        read_gate::init(&mut s.read_gate);
        flow::init(&mut s.flow);

        // Port handles. Indices follow the manifest declaration order.
        s.proof_cache.in_proof = in_chan; // in[0] proof
        s.proof_cache.in_input = dev_channel_port(sys, 0, 1);
        s.flow.in_lag = dev_channel_port(sys, 0, 2);
        s.proof_cache.out_cache_state = out_chan; // out[0] cache_state
        s.proof_cache.out_fresh_state = dev_channel_port(sys, 1, 1);
        s.proof_cache.out_fallback = dev_channel_port(sys, 1, 2);
        s.read_gate.out_permits = dev_channel_port(sys, 1, 3);
        s.flow.out_credits = dev_channel_port(sys, 1, 4);
        s.flow.out_envelope = dev_channel_port(sys, 1, 5);
        s.flow.out_metrics = dev_channel_port(sys, 1, 6);

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
            flow::arm_pools(&mut s.flow);
        }

        dev_log(sys, 3, b"[proof] init".as_ptr(), 12);
        dev_log(sys, 3, b"[rgate] init".as_ptr(), 12);
        dev_log(sys, 3, b"[flow] init".as_ptr(), 11);
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

        // Dispatch table — see the module header for the ordering
        // contract.
        proof_cache::step(&mut s.proof_cache, &mut s.read_gate, sys, now);
        read_gate::step(&mut s.read_gate, sys);
        flow::step(&mut s.flow, sys, now);
        0
    }
}
