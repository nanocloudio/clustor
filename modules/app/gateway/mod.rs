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
//! owned HERE and nowhere else. Components never call each other:
//! each returns message-shaped records (verdicts, outbound frames)
//! and the routing between them — codec → throttle admission,
//! throttle-reject → codec → surface, applied → surface — happens in
//! `module_step`'s loops (standards fluxor-modules.md §8):
//!
//!   1. `codec`    — placement/leader/assignment drains; then the
//!      applied-response loop (≤8) resolves conn_ids and sends
//!      through the surface.
//!   2. `throttle` — credit drains; the external-proposals loop
//!      (≤16) admits or walks each reject back through
//!      codec → surface; admission telemetry.
//!   3. `surface`  — inbound frame loop (≤8): raft/admin frames
//!      route on the surface's own ports, client frames flow
//!      codec → throttle same-step, so every consumed frame has a
//!      terminal route (admit, reject, or structured drop) — the
//!      composite never holds a consumed-but-unrouted proposal.
//!      Then admin responses + diagnostic drains.
//!   4. `codec` `client_requests` loop (≤8) — pre-demuxed client
//!      traffic from producers that own their own connection
//!      namespace, entering the correlation hub on the same terms as
//!      step 3's wire frames.
//!
//! The dispatch table brackets each section with `dev_micros` reads
//! and publishes a per-component step-time histogram each second
//! under the component's source id (`step_accounting`, §8 rule 8);
//! a section's routing chains bill the section's driving component.

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

#[path = "../../common/types.rs"]
mod types;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;
#[path = "../../common/step_accounting.rs"]
mod step_accounting;

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

    /// Per-component step-time histograms (§8 rule 8), owned by the
    /// dispatch table: [surface, codec, throttle]. Each dispatch
    /// section is charged to its driving component; a routing chain
    /// crossing components mid-section bills the section owner.
    comp_step: [step_accounting::CompStepHist; 3],
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
        s.surface.in_admin_resp = dev_channel_port(sys, 0, 1);
        s.surface.in_readyz = dev_channel_port(sys, 0, 2);
        s.surface.in_why = dev_channel_port(sys, 0, 3);
        s.surface.in_metrics = dev_channel_port(sys, 0, 4);
        s.codec.in_applied = dev_channel_port(sys, 0, 5);
        s.codec.in_placement = dev_channel_port(sys, 0, 6);
        s.codec.in_proposal_assigned = dev_channel_port(sys, 0, 7);
        s.codec.in_leader_state = dev_channel_port(sys, 0, 8);
        s.throttle.in_credits = dev_channel_port(sys, 0, 9);
        s.throttle.in_proposals = dev_channel_port(sys, 0, 10);
        s.codec.in_client_requests = dev_channel_port(sys, 0, 11);
        s.surface.out_raft_rpc = out_chan; // out[0] raft_rpc
        s.surface.out_responses = dev_channel_port(sys, 1, 1);
        s.surface.out_admin_req = dev_channel_port(sys, 1, 2);
        s.throttle.out_admitted = dev_channel_port(sys, 1, 3);
        s.throttle.out_rejected = dev_channel_port(sys, 1, 4);
        s.codec.out_reads = dev_channel_port(sys, 1, 5);
        s.throttle.out_metrics = dev_channel_port(sys, 1, 6);

        s.comp_step = [step_accounting::CompStepHist::new(); 3];
        s.comp_step_last_ms = 0;

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
        let work_before = surface::work_count(&s.surface)
            .wrapping_add(codec::work_count(&s.codec))
            .wrapping_add(throttle::work_count(&s.throttle));

        // Dispatch table — see the module header for the ordering
        // contract. All cross-component routing lives in these loops.
        let mut frame = [0u8; 2048];

        // 1. codec drains, then the applied-response loop.
        let mut t0 = dev_micros(sys);
        codec::step(&mut s.codec, sys);
        for _ in 0..8 {
            match codec::next_applied(&mut s.codec, sys) {
                None => break,
                Some(out) => {
                    if surface::send_outbound(&mut s.surface, sys, &out) {
                        codec::note_response_sent(&mut s.codec);
                    }
                }
            }
        }

        let t1 = dev_micros(sys);
        s.comp_step[1].record(t1.wrapping_sub(t0));
        t0 = t1;

        // 2. throttle: credits, external proposals, metrics.
        throttle::drain_credits(&mut s.throttle, sys);
        for _ in 0..16 {
            match throttle::next_external(&mut s.throttle, sys, &mut frame) {
                None => break,
                Some(0) => {}
                Some(len) => {
                    if let Some(env) =
                        throttle::on_proposal(&mut s.throttle, sys, &frame[..len])
                    {
                        reject_chain(s, sys, &env);
                    }
                }
            }
        }
        throttle::step_metrics(&mut s.throttle, sys);
        let t1 = dev_micros(sys);
        s.comp_step[2].record(t1.wrapping_sub(t0));
        t0 = t1;

        // 3. surface inbound loop, then its own post-routing work.
        for _ in 0..8 {
            match surface::next_request(&mut s.surface, sys, &mut frame) {
                surface::Inbound::Empty => break,
                surface::Inbound::Handled => {}
                surface::Inbound::Client { msg_type, len } => {
                    route_client(s, sys, msg_type, len, &frame);
                }
                surface::Inbound::Oversize { conn_id } => {
                    let out = codec::reject_too_large(conn_id);
                    if surface::send_outbound(&mut s.surface, sys, &out) {
                        codec::note_response_sent(&mut s.codec);
                    }
                }
            }
        }
        surface::finish_step(&mut s.surface, sys);
        let t1 = dev_micros(sys);
        s.comp_step[0].record(t1.wrapping_sub(t0));
        t0 = t1;

        // 4. pre-demuxed client_requests loop (codec-driven).
        for _ in 0..8 {
            match codec::next_client_request(&mut s.codec, sys, &mut frame) {
                codec::Pulled::Empty => break,
                codec::Pulled::Skipped => {}
                codec::Pulled::Frame(msg_type, len) => {
                    route_client(s, sys, msg_type, len, &frame);
                }
            }
        }

        s.comp_step[1].record(dev_micros(sys).wrapping_sub(t0));

        // Per-component step accounting (§8 rule 8): publish each
        // component's step-time histogram every second under its own
        // source id.
        let now = dev_millis(sys);
        if now.wrapping_sub(s.comp_step_last_ms) >= 1000 {
            s.comp_step_last_ms = now;
            const COMP_IDS: [u8; 3] = [
                wire::SOURCE_ID_SURFACE,
                wire::SOURCE_ID_CODEC,
                wire::SOURCE_ID_THROTTLE,
            ];
            for (h, &id) in s.comp_step.iter().zip(COMP_IDS.iter()) {
                h.emit(sys, s.throttle.out_metrics, id, 0);
            }
        }

        let work_after = surface::work_count(&s.surface)
            .wrapping_add(codec::work_count(&s.codec))
            .wrapping_add(throttle::work_count(&s.throttle));
        if work_after != work_before {
            dev_report_step_effect(sys, step_effect::WORK_DONE);
        }
        0
    }
}

/// Route one client record `[conn_id:u8][body]` through the
/// codec → throttle → codec → surface chain. Cross-component order
/// lives here, in the composition layer, not in any component.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn route_client(
    s: &mut ModuleState,
    sys: &SyscallTable,
    msg_type: u8,
    len: usize,
    frame: &[u8; 2048],
) {
    let mut proposal = [0u8; 2048];
    match codec::on_request(&mut s.codec, sys, msg_type, &frame[..len], &mut proposal) {
        codec::Route::Done => {}
        codec::Route::Respond(out) => {
            if surface::send_outbound(&mut s.surface, sys, &out) {
                codec::note_response_sent(&mut s.codec);
            }
        }
        codec::Route::Propose(plen) => {
            if let Some(env) = throttle::on_proposal(&mut s.throttle, sys, &proposal[..plen]) {
                reject_chain(s, sys, &env);
            }
        }
    }
}

/// Walk one throttle rejection back out: codec resolves the
/// correlation id to a conn_id and frames the wire reject; the
/// surface sends it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn reject_chain(s: &mut ModuleState, sys: &SyscallTable, env: &[u8]) {
    if let Some(out) = codec::on_reject_internal(&mut s.codec, env) {
        if surface::send_outbound(&mut s.surface, sys, &out) {
            codec::note_response_sent(&mut s.codec);
        }
    }
}
