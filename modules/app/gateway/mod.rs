//! Gateway — client envelope routing, framing/correlation and
//! admission.
//!
//! One graph module composed of three components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`surface`]  — demux of peer_router client frames to raft RPC /
//!     client / admin routes; response framing back to peer_router.
//!   - [`codec`]    — request framer and conn_id correlation hub;
//!     stamps correlation ids (dense from 1, bit 63 clear — the
//!     operations module's HTTP bridge owns the bit-63-set half).
//!   - [`throttle`] — credit-based admission; admitted proposals leave
//!     on `proposals_tagged`, rejections return through the codec and
//!     tee on `rejected`.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else:
//!
//!   1. `codec`    — placement/leader/assignment drains; apply
//!      responses route back through the surface.
//!   2. `throttle` — credit drains + admission telemetry.
//!   3. `surface`  — inbound frame routing; client frames flow
//!      surface → codec → throttle same-step, so every consumed frame
//!      has a terminal route (admit, reject, or structured drop) —
//!      the composite never holds a consumed-but-unrouted proposal.
//!   4. `codec` `client_requests` drain — pre-demuxed client traffic
//!      from producers that own their own connection namespace,
//!      entering the correlation hub on the same terms as step 3's
//!      wire frames.

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

mod codec;
mod surface;
mod throttle;

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.codec.self_id = p_u8(d, len, 0, 0); };

    // Expected client placement epoch. When non-zero, requests whose
    // implicit epoch (currently == `placement_epoch`) is older than
    // this value will be rejected with `CLIENT_REJECT_STALE_EPOCH`.
    // Default 0 keeps the existing accept-everything behaviour for
    // configs that don't yet plumb placement.
    2, min_epoch, u32, 0
        => |s, d, len| { s.codec.min_epoch = p_u32(d, len, 0, 0); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    surface: surface::Surface,
    codec: codec::Codec,
    throttle: throttle::Throttle,
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

        surface::init(&mut s.surface);
        codec::init(&mut s.codec);
        throttle::init(&mut s.throttle);

        // Port handles. Indices follow the manifest declaration order.
        s.surface.in_requests = in_chan; // in[0] requests
        s.surface.in_throttle_status = dev_channel_port(sys, 0, 1);
        s.surface.in_admin_resp = dev_channel_port(sys, 0, 2);
        s.surface.in_readyz = dev_channel_port(sys, 0, 3);
        s.surface.in_why = dev_channel_port(sys, 0, 4);
        s.surface.in_metrics = dev_channel_port(sys, 0, 5);
        s.codec.in_applied = dev_channel_port(sys, 0, 6);
        s.codec.in_placement = dev_channel_port(sys, 0, 7);
        s.codec.in_proposal_assigned = dev_channel_port(sys, 0, 8);
        s.codec.in_leader_state = dev_channel_port(sys, 0, 9);
        s.throttle.in_credits = dev_channel_port(sys, 0, 10);
        s.throttle.in_proposals = dev_channel_port(sys, 0, 11);
        s.codec.in_client_requests = dev_channel_port(sys, 0, 12);
        s.surface.out_raft_rpc = out_chan; // out[0] raft_rpc
        s.surface.out_responses = dev_channel_port(sys, 1, 1);
        s.surface.out_admin_req = dev_channel_port(sys, 1, 2);
        s.throttle.out_admitted = dev_channel_port(sys, 1, 3);
        s.throttle.out_rejected = dev_channel_port(sys, 1, 4);
        s.codec.out_reads = dev_channel_port(sys, 1, 5);
        s.throttle.out_metrics = dev_channel_port(sys, 1, 6);

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        dev_log(sys, 3, b"[surface] init".as_ptr(), 14);
        dev_log(sys, 3, b"[codec] init".as_ptr(), 12);
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
        let work_before = surface::work_count(&s.surface)
            .wrapping_add(codec::work_count(&s.codec))
            .wrapping_add(throttle::work_count(&s.throttle));

        // Dispatch table — see the module header for the ordering
        // contract.
        codec::step(&mut s.codec, &mut s.surface, sys);
        throttle::step(&mut s.throttle, &mut s.codec, &mut s.surface, sys);
        surface::step(&mut s.surface, &mut s.codec, &mut s.throttle, sys);
        codec::drain_client_requests(&mut s.codec, &mut s.throttle, &mut s.surface, sys);

        let work_after = surface::work_count(&s.surface)
            .wrapping_add(codec::work_count(&s.codec))
            .wrapping_add(throttle::work_count(&s.throttle));
        if work_after != work_before {
            dev_report_step_effect(sys, step_effect::WORK_DONE);
        }
        0
    }
}
