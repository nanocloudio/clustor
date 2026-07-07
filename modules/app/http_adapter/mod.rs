//! HTTP adapter — diagnostic surface bridge for `telemetry_agg`.
//!
//! Caches the latest `MSG_READYZ`, `MSG_WHY` and `MSG_METRICS`
//! envelopes from `telemetry_agg` and answers
//! `MSG_HTTP_REQUEST` frames from a downstream HTTP server module
//! (typically Fluxor's `foundation/http`) on the well-known
//! diagnostic paths:
//!
//!   - `GET /readyz`  → 200 if ready, 503 otherwise; body carries the
//!     latest readyz envelope bytes.
//!   - `GET /why`     → 200 with the latest `MSG_WHY` body, or `ok`
//!     if no blocking reason has been reported.
//!   - `GET /metrics` → 200 with the latest export envelope from
//!     `telemetry_agg`. The body is the bytes telemetry_agg emitted
//!     last — see RFC §4.3.
//!
//! Anything else returns 404. The adapter never opens a socket
//! itself — it's purely a clustor-side framer. The upstream HTTP
//! server module owns network framing, TLS, and authentication.
//!
//! See RFC §4.4.

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

#[path = "../../common/http_admin.rs"]
mod http_admin;

/// Bound on the small cached envelopes — `/readyz` and `/why` carry a
/// single status byte, so 1 KiB is ample.
const ENVELOPE_CACHE: usize = 1024;

/// Bound on the cached `/metrics` body. The telemetry_agg export is the
/// largest envelope on this adapter: a binary record stream capped at
/// `SAFE_EXPORT_MAX` (7400 B) by the aggregator so a frame always fits
/// the 8 KiB channel ring. This buffer MUST be >= that cap, or
/// `channel_read_msg` drops every oversized export (its payload-too-large
/// path drains and discards the frame), silently freezing `/metrics` on
/// the last export small enough to fit. 7600 clears the 7400 cap and
/// still keeps the HTTP response frame (3 B envelope + 5 B header +
/// body) under 8 KiB.
const METRICS_CACHE: usize = 7600;

/// Wire frame for a cached HTTP response handed to http_ingress:
/// `conn_id(1) + status(2) + body_len(2) + body`. The body can be the
/// full `/metrics` export, so this is sized to `METRICS_CACHE`. 5 + 7600 +
/// the 3-byte channel envelope = 7608 < CHANNEL_BUFFER_SIZE (8192). Lives on
/// the step stack (64 KB EL0 / 1 MB EL1 on bcm2712, host thread stack on
/// linux), comfortably within budget.
const RESP_FRAME_MAX: usize = 5 + METRICS_CACHE;
// Two bounded phase tables (correlation→connection and index→connection).
// Sized above ingress's 32 live connections so phase handoff and an
// operational probe cannot exhaust the mapping space during a burst.
const HTTP_INFLIGHT: usize = 64;
const HTTP_PROPOSAL_TIMEOUT_MS: u64 = 10_000;
const METRICS_INTERVAL_MS: u64 = 250;

#[derive(Clone, Copy)]
#[repr(C)]
struct CorrSlot {
    correlation_id: u64,
    started_ms: u64,
    conn_id: u8,
}

impl CorrSlot {
    const fn empty() -> Self { Self { correlation_id: 0, started_ms: 0, conn_id: 0 } }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct IndexSlot {
    index: u64,
    started_ms: u64,
    conn_id: u8,
}

impl IndexSlot {
    const fn empty() -> Self { Self { index: 0, started_ms: 0, conn_id: 0 } }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_readyz: i32,         // in[0]: MSG_READYZ from telemetry_agg
    in_why: i32,            // in[1]: MSG_WHY from telemetry_agg
    in_metrics: i32,        // in[2]: MSG_METRICS export from telemetry_agg
    in_request: i32,        // in[3]: MSG_HTTP_REQUEST from foundation/http
    in_proposal_assigned: i32, // in[4]: correlation_id → WAL index from Raft
    in_applied: i32,        // in[5]: per-index apply acknowledgements
    in_proposal_rejected: i32, // in[6]: throttle rejection by correlation id
    out_response: i32,      // out[0]: MSG_HTTP_RESPONSE back to foundation/http
    out_metric_sample: i32, // out[1]: self-telemetry MSG_METRIC_SAMPLE
    out_admin: i32,         // out[2]: MSG_ADMIN_COMMAND → admin_handler.requests
    out_proposal: i32,      // out[3]: tagged proposal → throttle_gate.requests
    out_ready_snapshot: i32, // out[4]: replaceable ready state → http_ingress

    next_correlation_id: u64,
    correlations: [CorrSlot; HTTP_INFLIGHT],
    indices: [IndexSlot; HTTP_INFLIGHT],

    /// Most recent envelope bytes from each cache slot. `*_len = 0`
    /// means "no value seen yet"; respond with a service-degraded
    /// default in that case.
    readyz_buf: [u8; ENVELOPE_CACHE],
    readyz_len: u16,
    ready_snapshot_dirty: bool,
    why_buf: [u8; ENVELOPE_CACHE],
    why_len: u16,
    metrics_buf: [u8; METRICS_CACHE],
    metrics_len: u16,

    requests_handled: u32,
    requests_404: u32,
    inflight_high_water: u8,
    proposal_timeouts: u32,
    commit_timeouts: u32,
    assignments_unmatched: u32,
    assignments_no_slot: u32,
    applies_unmatched: u32,
    proposal_rejections: u32,
    queue_unavailable: u32,
    committed: u32,
    last_metrics_ms: u64,
    /// Count of `POST /admin/<op>` requests rejected because the
    /// downstream `out_admin` channel was unwired, back-pressured, or
    /// the body exceeded the 1 KiB envelope buffer. The HTTP client
    /// sees 503 for each one. Surfaced through the metrics aggregator
    /// so a sustained admin queue stall is operationally visible.
    admin_dropped: u32,
    /// Scratch for draining an envelope off any input channel. Sized to
    /// the largest payload (the `/metrics` export) so `channel_read_msg`
    /// never hits its payload-too-large drop path on a valid frame.
    msg_buf: [u8; METRICS_CACHE],
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
        s.in_readyz = in_chan;
        s.in_why = dev_channel_port(sys, 0, 1);
        s.in_metrics = dev_channel_port(sys, 0, 2);
        s.in_request = dev_channel_port(sys, 0, 3);
        s.in_proposal_assigned = dev_channel_port(sys, 0, 4);
        s.in_applied = dev_channel_port(sys, 0, 5);
        s.in_proposal_rejected = dev_channel_port(sys, 0, 6);
        s.out_response = out_chan;
        s.out_metric_sample = dev_channel_port(sys, 1, 1);
        s.out_admin = dev_channel_port(sys, 1, 2);
        s.out_proposal = dev_channel_port(sys, 1, 3);
        s.out_ready_snapshot = dev_channel_port(sys, 1, 4);
        s.next_correlation_id = 1;
        s.correlations = [CorrSlot::empty(); HTTP_INFLIGHT];
        s.indices = [IndexSlot::empty(); HTTP_INFLIGHT];
        s.readyz_len = 0;
        s.ready_snapshot_dirty = false;
        s.why_len = 0;
        s.metrics_len = 0;
        s.requests_handled = 0;
        s.requests_404 = 0;
        s.inflight_high_water = 0;
        s.proposal_timeouts = 0;
        s.commit_timeouts = 0;
        s.assignments_unmatched = 0;
        s.assignments_no_slot = 0;
        s.applies_unmatched = 0;
        s.proposal_rejections = 0;
        s.queue_unavailable = 0;
        s.committed = 0;
        s.last_metrics_ms = 0;
        s.admin_dropped = 0;
        dev_log(sys, 3, b"[http_adapter] init".as_ptr(), 19);
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
        let handled_before = s.requests_handled;

        cache_latest(s, sys);
        publish_ready_snapshot(s, sys);
        drain_proposal_assignments(s, sys);
        drain_proposal_rejections(s, sys);
        drain_applied(s, sys);
        expire_proposals(s, sys, dev_millis(sys));
        serve_requests(s, sys);
        emit_metrics(s, sys);
        if s.requests_handled != handled_before {
            dev_report_step_effect(sys, step_effect::WORK_DONE);
        }

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Pull the latest body from each diagnostic input. We only keep the
/// most recent envelope per slot; older frames are dropped silently.
unsafe fn cache_latest(s: &mut ModuleState, sys: &SyscallTable) {
    cache_one(s, sys, 0);
    cache_one(s, sys, 1);
    cache_one(s, sys, 2);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn cache_one(s: &mut ModuleState, sys: &SyscallTable, slot: u8) {
    let chan = match slot {
        0 => s.in_readyz,
        1 => s.in_why,
        2 => s.in_metrics,
        _ => return,
    };
    if chan < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, chan, &mut s.msg_buf);
        let pl = plen as usize;
        // Metrics get the large cache; readyz/why are single-byte bodies.
        let take = pl.min(if slot == 2 { METRICS_CACHE } else { ENVELOPE_CACHE });
        let expected = match slot {
            0 => wire::MSG_READYZ,
            1 => wire::MSG_WHY,
            2 => wire::MSG_METRICS,
            _ => continue,
        };
        if msg_type != expected {
            continue;
        }
        match slot {
            0 => {
                s.readyz_buf[..take].copy_from_slice(&s.msg_buf[..take]);
                s.readyz_len = take as u16;
                s.ready_snapshot_dirty = true;
            }
            1 => {
                s.why_buf[..take].copy_from_slice(&s.msg_buf[..take]);
                s.why_len = take as u16;
            }
            2 => {
                s.metrics_buf[..take].copy_from_slice(&s.msg_buf[..take]);
                s.metrics_len = take as u16;
            }
            _ => {}
        }
    }
}

/// Publish replaceable readiness state over the mailbox edge. If the consumer
/// still owns the previous snapshot, retain `dirty` and retry next step; an
/// ordered queue is deliberately unnecessary because only the newest state is
/// observable.
unsafe fn publish_ready_snapshot(s: &mut ModuleState, sys: &SyscallTable) {
    if !s.ready_snapshot_dirty || s.out_ready_snapshot < 0 {
        return;
    }
    let poll = (sys.channel_poll)(s.out_ready_snapshot, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let len = s.readyz_len as usize;
    if wire_channels::channel_write_msg(
        sys,
        s.out_ready_snapshot,
        wire::MSG_HTTP_READY_SNAPSHOT,
        &s.readyz_buf[..len],
    ) > 0
    {
        s.ready_snapshot_dirty = false;
    }
}

unsafe fn drain_proposal_assignments(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_proposal_assigned < 0 { return; }
    for _ in 0..16 {
        let poll = (sys.channel_poll)(s.in_proposal_assigned, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_proposal_assigned, &mut s.msg_buf);
        if msg_type != wire::MSG_PROPOSAL_ASSIGNED
            || (plen as usize) < wire::PROPOSAL_ASSIGNED_LEN
        {
            continue;
        }
        let (correlation_id, _partition_id, index) =
            wire::decode_proposal_assigned(&s.msg_buf);
        let corr_pos = s.correlations.iter().position(|slot| {
            slot.correlation_id == correlation_id && correlation_id != 0
        });
        let idx_pos = s.indices.iter().position(|slot| slot.index == 0);
        match (corr_pos, idx_pos) {
            (Some(c), Some(i)) => {
                let corr = s.correlations[c];
                s.correlations[c] = CorrSlot::empty();
                s.indices[i] = IndexSlot {
                    index,
                    started_ms: corr.started_ms,
                    conn_id: corr.conn_id,
                };
            }
            (None, _) => {
                s.assignments_unmatched = s.assignments_unmatched.saturating_add(1);
            }
            (Some(_), None) => {
                // Keep the correlation resident so its eventual timeout is
                // explicit; the consumed assignment cannot be reconstructed.
                s.assignments_no_slot = s.assignments_no_slot.saturating_add(1);
            }
        }
    }
}

unsafe fn drain_proposal_rejections(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_proposal_rejected < 0 { return; }
    for _ in 0..8 {
        let out = (sys.channel_poll)(s.out_response, 0x02);
        if out <= 0 || (out as u32 & 0x02) == 0 { break; }
        let poll = (sys.channel_poll)(s.in_proposal_rejected, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_proposal_rejected, &mut s.msg_buf);
        if msg_type != wire::MSG_CLIENT_REJECT_INTERNAL { continue; }
        let (correlation_id, _status, _retry, _entries, _bytes) =
            match wire::decode_client_reject_internal(&s.msg_buf[..plen as usize]) {
                Some(v) => v,
                None => continue,
            };
        if let Some(pos) = s.correlations.iter().position(|slot| {
            slot.correlation_id == correlation_id && correlation_id != 0
        }) {
            let conn_id = s.correlations[pos].conn_id;
            s.correlations[pos] = CorrSlot::empty();
            s.proposal_rejections = s.proposal_rejections.saturating_add(1);
            emit_response(s, sys, conn_id, 503, b"proposal rejected");
        }
    }
}

unsafe fn drain_applied(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_applied < 0 { return; }
    for _ in 0..16 {
        let out = (sys.channel_poll)(s.out_response, 0x02);
        if out <= 0 || (out as u32 & 0x02) == 0 { break; }
        let poll = (sys.channel_poll)(s.in_applied, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_applied, &mut s.msg_buf);
        let pl = plen as usize;
        if msg_type != wire::MSG_CLIENT_RESPONSE || pl < 18 { continue; }
        // `[partition:u16][term:u64][index:u64]` — index at offset 10.
        let index_off = 10;
        let index = u64::from_le_bytes([
            s.msg_buf[index_off], s.msg_buf[index_off + 1],
            s.msg_buf[index_off + 2], s.msg_buf[index_off + 3],
            s.msg_buf[index_off + 4], s.msg_buf[index_off + 5],
            s.msg_buf[index_off + 6], s.msg_buf[index_off + 7],
        ]);
        if let Some(pos) = s.indices.iter().position(|slot| slot.index == index) {
            let conn_id = s.indices[pos].conn_id;
            s.indices[pos] = IndexSlot::empty();
            s.committed = s.committed.saturating_add(1);
            emit_response(s, sys, conn_id, 200, b"committed");
        } else {
            s.applies_unmatched = s.applies_unmatched.saturating_add(1);
        }
    }
}

unsafe fn expire_proposals(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    let out = (sys.channel_poll)(s.out_response, 0x02);
    if out <= 0 || (out as u32 & 0x02) == 0 { return; }
    if let Some(pos) = s.correlations.iter().position(|slot| {
        slot.correlation_id != 0
            && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let conn_id = s.correlations[pos].conn_id;
        s.correlations[pos] = CorrSlot::empty();
        s.proposal_timeouts = s.proposal_timeouts.saturating_add(1);
        emit_response(s, sys, conn_id, 503, b"proposal timeout");
        return;
    }
    if let Some(pos) = s.indices.iter().position(|slot| {
        slot.index != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let conn_id = s.indices[pos].conn_id;
        s.indices[pos] = IndexSlot::empty();
        s.commit_timeouts = s.commit_timeouts.saturating_add(1);
        emit_response(s, sys, conn_id, 503, b"commit timeout");
    }
}

unsafe fn emit_http_proposal(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn_id: u8,
    body: &[u8],
) -> bool {
    if s.out_proposal < 0 || body.len() > 1024 { return false; }
    let slot = match s.correlations.iter().position(|slot| slot.correlation_id == 0) {
        Some(v) => v,
        None => return false,
    };
    let poll = (sys.channel_poll)(s.out_proposal, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    let correlation_id = (1u64 << 63) | s.next_correlation_id;
    s.next_correlation_id = s.next_correlation_id.wrapping_add(1).max(1);
    let mut framed = [0u8; 1032];
    framed[..8].copy_from_slice(&correlation_id.to_le_bytes());
    framed[8..8 + body.len()].copy_from_slice(body);
    let written = wire_channels::channel_write_msg(
        sys, s.out_proposal, wire::MSG_CLIENT_PROPOSAL, &framed[..8 + body.len()],
    );
    if written <= 0 { return false; }
    s.correlations[slot] = CorrSlot {
        correlation_id,
        started_ms: dev_millis(sys),
        conn_id,
    };
    let occupied = s.correlations.iter().filter(|v| v.correlation_id != 0).count()
        + s.indices.iter().filter(|v| v.index != 0).count();
    s.inflight_high_water = s.inflight_high_water.max(occupied.min(u8::MAX as usize) as u8);
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn serve_requests(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_request < 0 || s.out_response < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_request, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_request, &mut s.msg_buf);
        if msg_type != wire::MSG_HTTP_REQUEST || plen < 3 {
            continue;
        }
        let pl = plen as usize;
        let conn_id = s.msg_buf[0];
        let _method = s.msg_buf[1];
        let path_len = s.msg_buf[2] as usize;
        if 3 + path_len > pl {
            continue;
        }
        // Copy path out before the response builder borrows msg_buf.
        let mut path_local = [0u8; 64];
        let pl_take = path_len.min(path_local.len());
        path_local[..pl_take].copy_from_slice(&s.msg_buf[3..3 + pl_take]);
        let path = &path_local[..pl_take];

        // POST /admin/<op> takes the admin path: emit
        // `MSG_ADMIN_COMMAND` to admin_handler, reply 202 to the
        // HTTP client immediately. The actual admin reply
        // (`MSG_ADMIN_RESPONSE`) goes to client_surface today;
        // wiring the sync reply back through http_adapter is a
        // follow-up slice.
        // POST /propose — synchronous write bridge. A private correlation id
        // follows the proposal through Raft assignment to its exact WAL index;
        // the HTTP response is emitted only when apply acknowledges that index.
        if _method == b'P' && eq_path(path, b"/propose") {
            let body_off = 3 + path_len;
            let body_len = pl - body_off;
            let mut body_local = [0u8; 1024];
            let take = body_len.min(body_local.len());
            body_local[..take].copy_from_slice(&s.msg_buf[body_off..body_off + take]);
            if !emit_http_proposal(s, sys, conn_id, &body_local[..take]) {
                s.queue_unavailable = s.queue_unavailable.saturating_add(1);
                emit_response(s, sys, conn_id, 503, b"propose queue unavailable");
            }
            s.requests_handled = s.requests_handled.saturating_add(1);
            continue;
        }

        if _method == b'P' && path.starts_with(b"/admin/") {
            let op_name = &path[b"/admin/".len()..];
            // Copy body before re-borrowing msg_buf.
            let body_off = 3 + path_len;
            let body_len = pl - body_off;
            let mut body_local = [0u8; 1024];
            let take = body_len.min(body_local.len());
            body_local[..take].copy_from_slice(&s.msg_buf[body_off..body_off + take]);
            match http_admin::admin_op_code(op_name) {
                Some(op_code) => {
                    // Only claim 202 if the admin envelope actually
                    // made it onto the wire. emit_admin_command
                    // returns false when out_admin is unwired, the
                    // downstream is back-pressured, or the body
                    // overflowed our 1 KiB envelope buffer — all
                    // genuine failures the HTTP caller deserves to
                    // see, not silent successes.
                    if emit_admin_command(s, sys, conn_id, op_code, &body_local[..take]) {
                        // Routing-decision signal, paired with
                        // `[admin] op=N conn_id=M` on the admin_handler
                        // side: the only external proof the POST
                        // actually reached the admin path, since the
                        // 202 below fires immediately and unlike the
                        // client-proposal path (see `CorrSlot`) admin
                        // ops have no async reply to observe instead.
                        let mut log = [0u8; 48];
                        let n = format_admin_route_log(&mut log, op_code, conn_id);
                        dev_log(sys, 3, log.as_ptr(), n);
                        emit_response(s, sys, conn_id, 202, b"accepted");
                    } else {
                        s.admin_dropped = s.admin_dropped.saturating_add(1);
                        emit_response(s, sys, conn_id, 503, b"admin queue unavailable");
                    }
                }
                None => {
                    s.requests_404 = s.requests_404.saturating_add(1);
                    emit_response(s, sys, conn_id, 400, b"unknown admin op");
                }
            }
            s.requests_handled = s.requests_handled.saturating_add(1);
            continue;
        }

        let (status, body): (u16, &[u8]) = if eq_path(path, b"/readyz") {
            // 200 if readyz body's first byte is non-zero; 503 otherwise.
            let ready_byte = if s.readyz_len > 0 { s.readyz_buf[0] } else { 0 };
            let st = if ready_byte != 0 { 200 } else { 503 };
            (st, &s.readyz_buf[..s.readyz_len as usize])
        } else if eq_path(path, b"/why") {
            (200, &s.why_buf[..s.why_len as usize])
        } else if eq_path(path, b"/metrics") {
            (200, &s.metrics_buf[..s.metrics_len as usize])
        } else {
            s.requests_404 = s.requests_404.saturating_add(1);
            (404, b"not found")
        };
        emit_response(s, sys, conn_id, status, body);
        s.requests_handled = s.requests_handled.saturating_add(1);
    }
}

/// Emit absolute counters and current bounded-table occupancy. Telemetry is
/// best-effort and never delays the HTTP transaction path.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metric_sample < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let correlations = s.correlations.iter().filter(|v| v.correlation_id != 0).count() as i64;
    let indices = s.indices.iter().filter(|v| v.index != 0).count() as i64;
    let kg = wire::METRIC_KIND_GAUGE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, u8, i64); 13] = [
        (wire::metric_ids::HTTP_CORRELATIONS_INFLIGHT, kg, correlations),
        (wire::metric_ids::HTTP_INDICES_INFLIGHT, kg, indices),
        (wire::metric_ids::HTTP_INFLIGHT_HIGH_WATER, kg, i64::from(s.inflight_high_water)),
        (wire::metric_ids::HTTP_PROPOSAL_TIMEOUTS, kc, i64::from(s.proposal_timeouts)),
        (wire::metric_ids::HTTP_COMMIT_TIMEOUTS, kc, i64::from(s.commit_timeouts)),
        (wire::metric_ids::HTTP_ASSIGNMENTS_UNMATCHED, kc, i64::from(s.assignments_unmatched)),
        (wire::metric_ids::HTTP_ASSIGNMENTS_NO_SLOT, kc, i64::from(s.assignments_no_slot)),
        (wire::metric_ids::HTTP_APPLIES_UNMATCHED, kc, i64::from(s.applies_unmatched)),
        (wire::metric_ids::HTTP_REJECTIONS, kc, i64::from(s.proposal_rejections)),
        (wire::metric_ids::HTTP_QUEUE_UNAVAILABLE, kc, i64::from(s.queue_unavailable)),
        (wire::metric_ids::HTTP_COMMITTED, kc, i64::from(s.committed)),
        (wire::metric_ids::HTTP_REQUESTS, kc, i64::from(s.requests_handled)),
        (wire::metric_ids::HTTP_REQUESTS_404, kc, i64::from(s.requests_404)),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metric_sample, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(
            &mut buf, wire::MODULE_ID_HTTP_ADAPTER, 0, metric_id, kind, value,
        );
        wire_channels::channel_write_msg(
            sys, s.out_metric_sample, wire::MSG_METRIC_SAMPLE, &buf,
        );
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Emit `MSG_ADMIN_COMMAND([conn_id][op_code][op_body])` on
/// `out_admin` — the wire shape `admin_handler` expects on its
/// `requests` port.
/// Returns `true` iff the admin envelope was successfully written to
/// the downstream channel. False means one of:
///   - `out_admin` is unwired (`< 0`).
///   - The downstream is back-pressured (channel_poll says not-ready).
///   - The body is too large for our envelope buffer.
///
/// The caller is expected to translate `false` into an HTTP 5xx so
/// the client never sees a 202 for an unenqueued command.
unsafe fn emit_admin_command(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn_id: u8,
    op_code: u8,
    body: &[u8],
) -> bool {
    if !http_admin::admin_body_fits(body.len()) {
        return false;
    }
    if s.out_admin < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(s.out_admin, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let mut buf = [0u8; 1024];
    buf[0] = conn_id;
    buf[1] = op_code;
    buf[2..2 + body.len()].copy_from_slice(body);
    wire_channels::channel_write_msg(sys, s.out_admin, wire::MSG_ADMIN_COMMAND, &buf[..2 + body.len()]);
    true
}

/// `[http_adapter] admin op=N conn_id=M` — see the call site's
/// comment for why this stays a log line rather than a metric.
fn format_admin_route_log(dst: &mut [u8], op_code: u8, conn_id: u8) -> usize {
    let mut pos = 0usize;
    let head = b"[http_adapter] admin op=";
    let n = head.len().min(dst.len() - pos);
    dst[pos..pos + n].copy_from_slice(&head[..n]);
    pos += n;
    pos += push_usize(&mut dst[pos..], op_code as usize);
    let mid = b" conn_id=";
    let n = mid.len().min(dst.len() - pos);
    dst[pos..pos + n].copy_from_slice(&mid[..n]);
    pos += n;
    pos += push_usize(&mut dst[pos..], conn_id as usize);
    pos
}

fn push_usize(dst: &mut [u8], mut n: usize) -> usize {
    if n == 0 && !dst.is_empty() {
        dst[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + ((n % 10) as u8);
        n /= 10;
    }
    let take = (tmp.len() - i).min(dst.len());
    dst[..take].copy_from_slice(&tmp[i..i + take]);
    take
}

fn eq_path(path: &[u8], expected: &[u8]) -> bool {
    if path.len() != expected.len() {
        return false;
    }
    for (a, b) in path.iter().zip(expected.iter()) {
        if a != b {
            return false;
        }
    }
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_response(
    s: &ModuleState,
    sys: &SyscallTable,
    conn_id: u8,
    status: u16,
    body: &[u8],
) {
    // Header is conn_id(1) + status(2) + body_len(2); the body can be a full
    // cached envelope — the largest is the `/metrics` export (METRICS_CACHE,
    // up to ~7.4 KiB). The frame must fit one channel message
    // (CHANNEL_BUFFER_SIZE = 8 KiB): 3 B envelope + 5 B header + body stays
    // under 8 KiB because METRICS_CACHE (7600) + 8 < 8192. The frame is built
    // in the state-resident `resp_frame` (not the stack) to keep the per-step
    // stack frame small on embedded targets.
    const RESP_HDR_LEN: usize = 1 + 2 + 2;
    let body_len = body.len().min(METRICS_CACHE);
    let total = RESP_HDR_LEN + body_len;
    let poll = (sys.channel_poll)(s.out_response, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let mut buf = [0u8; RESP_FRAME_MAX];
    buf[0] = conn_id;
    buf[1..3].copy_from_slice(&status.to_le_bytes());
    buf[3..5].copy_from_slice(&(body_len as u16).to_le_bytes());
    if body_len > 0 {
        buf[5..5 + body_len].copy_from_slice(&body[..body_len]);
    }
    wire_channels::channel_write_msg(sys, s.out_response, wire::MSG_HTTP_RESPONSE, &buf[..total]);
}
