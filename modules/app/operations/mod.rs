//! Operations — admin admission, workflows, telemetry aggregation and
//! the HTTP diagnostic surface.
//!
//! One graph module composed of four components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`rbac`]      — role-based admission for admin commands.
//!   - [`admin`]     — idempotency-keyed admin workflows → raft.
//!   - [`telemetry`] — metrics fan-in, readiness, /metrics export.
//!   - [`http`]      — diagnostic + write-bridge request handling
//!                     (`http` feature). HTTP mechanics live outside
//!                     the module: wave's `http` module (`app`
//!                     variant) parses the wire and delivers
//!                     `HttpRequest` envelopes on `request`; replies
//!                     leave as `HttpResponse` envelopes on
//!                     `response`.
//!
//! Every admin command — wire or HTTP — is admitted through the rbac
//! component; there is no path around it. The `headless` variant
//! carries no HTTP surface at all: the `http` component is compiled
//! out and its ports are absent from the manifest.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else. Components never call each other:
//! each returns message-shaped records (requests, verdicts, staged
//! responses) and the routing between them — request → http,
//! admin envelope → rbac → admin — happens in `module_step`'s loops
//! (standards fluxor-modules.md §8):
//!
//!   1. `telemetry` — drain ingest, recompute readiness, emit tick.
//!      (Heaviest single step on the emit tick: one global + up to 32
//!      per-module histogram scrapes, export ≤ 7400 B.)
//!   2. on an emit tick: refresh the http caches from telemetry's
//!      snapshot values.
//!   3. `rbac`  — identity bindings, then the wire admin-command
//!      loop (≤4): each authorized envelope delivers into `admin`
//!      same-step, here.
//!   4. `admin` — apply acknowledgements, direct-inject commands.
//!   5. `http`  — proposal feedback loops (assignments, the
//!      `/metrics` stream, ≤8 rejections, ≤16 applies, one expiry —
//!      each pull gated on `response` writability), self-telemetry
//!      into `telemetry`.
//!   6. `http` `request` loop (≤8) — wave `HttpRequest` envelopes,
//!      each pull likewise gated on `response` writability; replies
//!      egress on `response`.
//!
//! Per-component step bounds are documented on each component's
//! `step`; the sum stays well inside the runtime step guard.
//!
//! The dispatch table brackets each section with `dev_micros` reads
//! and hands a per-component step-time histogram to the in-module
//! telemetry component each second under the component's source id
//! (`step_accounting`, §8 rule 8); a section's routing chains bill
//! the section's driving component.

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
#[path = "../../common/http_admin.rs"]
mod http_admin;
#[path = "../../common/step_accounting.rs"]
mod step_accounting;

mod admin;
mod rbac;
mod telemetry;

#[cfg(feature = "http")]
mod http;

/// Step-return code classifying this step as bursty work for the
/// scheduler (same contract as wal's STEP_BURST): set when the http
/// component advanced a request, reply or stream slice.
const STEP_BURST: i32 = 2;

define_params! {
    ModuleState;

    1, admin_svid_prefix, blob, 0
        => |s, d, len| {
            let take = (len as usize).min(rbac::SVID_PREFIX_MAX);
            for i in 0..take { s.rbac.admin_prefix[i] = *d.add(i); }
            s.rbac.admin_prefix_len = take as u8;
        };

    2, observer_svid_prefix, blob, 0
        => |s, d, len| {
            let take = (len as usize).min(rbac::SVID_PREFIX_MAX);
            for i in 0..take { s.rbac.observer_prefix[i] = *d.add(i); }
            s.rbac.observer_prefix_len = take as u8;
        };

    3, default_role, u8, rbac::ROLE_OPERATOR
        => |s, d, len| { s.rbac.default_role = p_u8(d, len, 0, rbac::ROLE_OPERATOR); };

    4, emit_interval_ms, u16, 1000
        => |s, d, len| { s.telemetry.emit_interval_ms = p_u16(d, len, 0, 1000) as u64; };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    rbac: rbac::Rbac,
    admin: admin::Admin,
    telemetry: telemetry::Telemetry,
    #[cfg(feature = "http")]
    http: http::Http,

    /// Per-component step-time histograms (§8 rule 8), owned by the
    /// dispatch table: [telemetry, rbac, admin, http]. The headless
    /// variant leaves the http entry idle. Each dispatch section is
    /// charged to its driving component; routing chains bill the
    /// section owner. Delivered message-shaped to the in-module
    /// telemetry component on a 1 s tick.
    comp_step: [step_accounting::CompStepHist; 4],
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

        rbac::init(&mut s.rbac);
        admin::init(&mut s.admin);
        telemetry::init(&mut s.telemetry, sys);
        #[cfg(feature = "http")]
        http::init(&mut s.http);

        // Port handles. Indices follow the manifest declaration order;
        // the headless variant omits the HTTP ports and leaves their
        // indices as holes, so every index below is stable across
        // variants.
        s.rbac.in_requests = in_chan; // in[0] admin_req
        s.rbac.in_identity = dev_channel_port(sys, 0, 1);
        s.admin.in_applied = dev_channel_port(sys, 0, 2);
        s.admin.in_requests = dev_channel_port(sys, 0, 3);
        s.telemetry.in_ingest = dev_channel_port(sys, 0, 4);
        s.admin.out_responses = out_chan; // out[0] responses
        s.rbac.out_denied = dev_channel_port(sys, 1, 1);
        s.rbac.out_audit = dev_channel_port(sys, 1, 2);
        s.admin.out_raft = dev_channel_port(sys, 1, 3);
        s.admin.out_proposal = dev_channel_port(sys, 1, 4);
        s.telemetry.out_readyz = dev_channel_port(sys, 1, 5);
        s.telemetry.out_why = dev_channel_port(sys, 1, 6);
        s.telemetry.out_export = dev_channel_port(sys, 1, 7);
        s.rbac.out_authorized = dev_channel_port(sys, 1, 9);
        #[cfg(feature = "http")]
        {
            s.http.in_proposal_assigned = dev_channel_port(sys, 0, 5);
            s.http.in_applied = dev_channel_port(sys, 0, 6);
            s.http.in_proposal_rejected = dev_channel_port(sys, 0, 7);
            s.http.in_request = dev_channel_port(sys, 0, 8);
            s.http.out_proposal = dev_channel_port(sys, 1, 8);
            s.http.out_response = dev_channel_port(sys, 1, 10);
        }

        s.comp_step = [step_accounting::CompStepHist::new(); 4];
        s.comp_step_last_ms = 0;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        dev_log(sys, 3, b"[rbac] init".as_ptr(), 11);
        dev_log(sys, 3, b"[admin] init".as_ptr(), 12);
        dev_log(sys, 3, b"[tele] init".as_ptr(), 11);
        #[cfg(feature = "http")]
        dev_log(sys, 3, b"[http] init".as_ptr(), 11);
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

        // Dispatch table — see the module header for the ordering
        // contract. All cross-component routing lives in these loops.
        let mut t0 = dev_micros(sys);
        telemetry::step(&mut s.telemetry, sys, now);

        #[cfg(feature = "http")]
        if telemetry::emitted(&s.telemetry) {
            let (ready, export) = telemetry::snapshot(&s.telemetry);
            let timing_pause = telemetry::timing_pause_reason(&s.telemetry);
            http::cache_export(&mut s.http, ready, timing_pause, export);
        }

        let t1 = dev_micros(sys);
        s.comp_step[0].record(t1.wrapping_sub(t0));
        t0 = t1;

        // rbac: identity bindings, then the wire admin-command loop.
        rbac::step(&mut s.rbac, sys);
        let mut env = [0u8; 1024];
        for _ in 0..4 {
            match rbac::next_wire_command(&mut s.rbac, sys, &mut env) {
                rbac::Pulled::Empty => break,
                rbac::Pulled::Skipped => {}
                rbac::Pulled::Command(len) => {
                    route_admin(s, sys, now, rbac::Origin::Wire, len, &env);
                }
            }
        }

        let t1 = dev_micros(sys);
        s.comp_step[1].record(t1.wrapping_sub(t0));
        t0 = t1;

        admin::step(&mut s.admin, sys, now);
        s.comp_step[2].record(dev_micros(sys).wrapping_sub(t0));

        #[cfg(feature = "http")]
        {
            // http: own drains, then the response-producing feedback
            // loops — each pull gated on `response` writability, so
            // feedback is consumed only with somewhere to answer.
            let t0 = dev_micros(sys);
            http::step(&mut s.http, sys);
            for _ in 0..8 {
                if !http::response_writable(&s.http, sys) {
                    break;
                }
                match http::next_rejection(&mut s.http, sys) {
                    http::Feedback::Empty => break,
                    http::Feedback::Handled => {}
                }
            }
            for _ in 0..16 {
                if !http::response_writable(&s.http, sys) {
                    break;
                }
                match http::next_applied(&mut s.http, sys) {
                    http::Feedback::Empty => break,
                    http::Feedback::Handled => {}
                }
            }
            if http::response_writable(&s.http, sys) {
                http::expire_step(&mut s.http, sys, now);
            }
            if let Some(samples) = http::take_metrics(&mut s.http, now) {
                for &(metric_id, kind, value) in samples.iter() {
                    telemetry::on_typed_sample(
                        &mut s.telemetry,
                        wire::SOURCE_ID_HTTP,
                        0,
                        metric_id,
                        kind,
                        value,
                        now,
                    );
                }
            }

            // Requests off the `request` port (wave HttpRequest
            // envelopes). Gated on `response` writability like the
            // feedback loops — a request is never consumed without
            // somewhere to answer, so wave applies the backpressure
            // instead of the reply being dropped.
            //
            // Stale reply state needs no connection-boundary purge
            // here: wave's per-request `stream_id` generation keeps a
            // late answer from matching a recycled conn id, and the
            // 10 s proposal timeout frees the slots.
            let mut ext = http::ExtReq::new();
            for _ in 0..8 {
                if !http::response_writable(&s.http, sys) {
                    break;
                }
                match http::next_external_request(&mut s.http, sys, &mut ext) {
                    http::ExtPulled::Empty => break,
                    http::ExtPulled::Skipped => {}
                    http::ExtPulled::Request => route_http_request(
                        s,
                        sys,
                        now,
                        ext.conn_id,
                        ext.stream_id,
                        ext.method,
                        ext.path_len as usize,
                        ext.body_len as usize,
                        &ext.path,
                        &ext.body,
                    ),
                }
            }

            s.comp_step[3].record(dev_micros(sys).wrapping_sub(t0));
        }

        // Per-component step accounting (§8 rule 8): hand each
        // component's cumulative step-time buckets straight to the
        // in-module telemetry component every second.
        if now.wrapping_sub(s.comp_step_last_ms) >= 1000 {
            s.comp_step_last_ms = now;
            const COMP_IDS: [u8; 4] = [
                wire::SOURCE_ID_TELEMETRY,
                wire::SOURCE_ID_RBAC,
                wire::SOURCE_ID_ADMIN,
                wire::SOURCE_ID_HTTP,
            ];
            let present: usize = if cfg!(feature = "http") { 4 } else { 3 };
            for c in 0..present {
                let cum = s.comp_step[c].cumulative();
                for (i, &v) in cum.iter().enumerate() {
                    telemetry::on_typed_sample(
                        &mut s.telemetry,
                        COMP_IDS[c],
                        0,
                        wire::hist::COMP_STEP_BASE + i as u16,
                        wire::METRIC_KIND_HISTOGRAM,
                        v,
                        now,
                    );
                }
            }
        }

        #[cfg(feature = "http")]
        if http::take_worked(&mut s.http) {
            return STEP_BURST;
        }

        0
    }
}

/// Route one admin envelope through the single admission point:
/// rbac judges, authorized envelopes deliver to `admin`, and the
/// telemetry envelope counter ticks — cross-component order owned
/// here, in the composition layer.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
unsafe fn route_admin(
    s: &mut ModuleState,
    sys: &SyscallTable,
    now: u64,
    origin: rbac::Origin,
    len: usize,
    env: &[u8],
) -> bool {
    let authorized = rbac::evaluate(&mut s.rbac, sys, origin, &env[..len]);
    if authorized {
        admin::on_command(&mut s.admin, sys, now, &env[..len]);
    }
    telemetry::on_legacy_envelope(&mut s.telemetry);
    authorized
}

/// Route one parsed HTTP request through `http::on_request`, then
/// walk its outcome: replies egress inside the call, and admin
/// envelopes run through [`route_admin`] before `http::finish_admin`
/// completes the reply.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and a valid
/// `&SyscallTable` per the module ABI.
#[cfg(feature = "http")]
#[allow(clippy::too_many_arguments, reason = "flat request parts avoid a borrowed struct")]
unsafe fn route_http_request(
    s: &mut ModuleState,
    sys: &SyscallTable,
    now: u64,
    conn_id: u16,
    stream_id: u16,
    method: u8,
    path_len: usize,
    body_len: usize,
    path: &[u8],
    body: &[u8],
) {
    match http::on_request(
        &mut s.http,
        sys,
        conn_id,
        stream_id,
        method,
        &path[..path_len],
        &body[..body_len],
    ) {
        http::ReqOut::Done => {}
        http::ReqOut::Admin { op_code, len } => {
            let mut env = [0u8; 1024];
            let src = http::admin_env(&s.http, len);
            env[..src.len()].copy_from_slice(src);
            let authorized = route_admin(s, sys, now, rbac::Origin::Http, len as usize, &env);
            http::finish_admin(&mut s.http, sys, conn_id, stream_id, op_code, authorized);
        }
    }
}
