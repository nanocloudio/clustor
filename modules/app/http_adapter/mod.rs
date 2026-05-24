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
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in deps/fluxor/modules/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../../deps/fluxor/modules/sdk/params.rs");

#[path = "../../sdk/wire.rs"]
mod wire;

#[path = "../../sdk/http_admin.rs"]
mod http_admin;

/// Bound on cached envelope bodies. /metrics output is the largest;
/// 1 KiB matches the size used elsewhere for telemetry payloads.
const ENVELOPE_CACHE: usize = 1024;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_readyz: i32,         // in[0]: MSG_READYZ from telemetry_agg
    in_why: i32,            // in[1]: MSG_WHY from telemetry_agg
    in_metrics: i32,        // in[2]: MSG_METRICS export from telemetry_agg
    in_request: i32,        // in[3]: MSG_HTTP_REQUEST from foundation/http
    out_response: i32,      // out[0]: MSG_HTTP_RESPONSE back to foundation/http
    out_metric_sample: i32, // out[1]: self-telemetry MSG_METRIC_SAMPLE
    out_admin: i32,         // out[2]: MSG_ADMIN_COMMAND → admin_handler.requests

    /// Most recent envelope bytes from each cache slot. `*_len = 0`
    /// means "no value seen yet"; respond with a service-degraded
    /// default in that case.
    readyz_buf: [u8; ENVELOPE_CACHE],
    readyz_len: u16,
    why_buf: [u8; ENVELOPE_CACHE],
    why_len: u16,
    metrics_buf: [u8; ENVELOPE_CACHE],
    metrics_len: u16,

    requests_handled: u32,
    requests_404: u32,
    /// Count of `POST /admin/<op>` requests rejected because the
    /// downstream `out_admin` channel was unwired, back-pressured, or
    /// the body exceeded the 1 KiB envelope buffer. The HTTP client
    /// sees 503 for each one. Surfaced through the metrics aggregator
    /// so a sustained admin queue stall is operationally visible.
    admin_dropped: u32,
    msg_buf: [u8; 2048],
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
    // SAFETY: per the module ABI (deps/fluxor/modules/sdk/abi.rs),
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
        s.out_response = out_chan;
        s.out_metric_sample = dev_channel_port(sys, 1, 1);
        s.out_admin = dev_channel_port(sys, 1, 2);
        s.readyz_len = 0;
        s.why_len = 0;
        s.metrics_len = 0;
        s.requests_handled = 0;
        s.requests_404 = 0;
        dev_log(sys, 3, b"[http_adapter] init".as_ptr(), 19);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (deps/fluxor/modules/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        cache_latest(s, sys);
        serve_requests(s, sys);

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
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
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
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
        let (msg_type, plen) = wire::channel_read_msg(sys, chan, &mut s.msg_buf);
        let pl = plen as usize;
        let take = pl.min(ENVELOPE_CACHE);
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn serve_requests(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_request < 0 || s.out_response < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_request, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_request, &mut s.msg_buf);
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
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
    wire::channel_write_msg(sys, s.out_admin, wire::MSG_ADMIN_COMMAND, &buf[..2 + body.len()]);
    // `[http_adapter] admin op=N conn_id=M` — receipt signal.
    let mut log = [0u8; 64];
    let n = format_admin_log(&mut log, op_code, conn_id);
    dev_log(sys, 3, log.as_ptr(), n);
    true
}

fn format_admin_log(dst: &mut [u8], op_code: u8, conn_id: u8) -> usize {
    let mut pos = 0usize;
    let head = b"[http_adapter] admin op=";
    let take = head.len().min(dst.len() - pos);
    dst[pos..pos + take].copy_from_slice(&head[..take]);
    pos += take;
    pos += push_usize(&mut dst[pos..], op_code as usize);
    let mid = b" conn_id=";
    let take = mid.len().min(dst.len() - pos);
    dst[pos..pos + take].copy_from_slice(&mid[..take]);
    pos += take;
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
/// routines per the module ABI in `deps/fluxor/modules/sdk/abi.rs`.
unsafe fn emit_response(
    s: &ModuleState,
    sys: &SyscallTable,
    conn_id: u8,
    status: u16,
    body: &[u8],
) {
    let body_len = body.len().min(0xFFFF);
    let total = 1 + 2 + 2 + body_len;
    if total > 2048 {
        return;
    }
    let poll = (sys.channel_poll)(s.out_response, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let mut buf = [0u8; 2048];
    buf[0] = conn_id;
    buf[1..3].copy_from_slice(&status.to_le_bytes());
    buf[3..5].copy_from_slice(&(body_len as u16).to_le_bytes());
    if body_len > 0 {
        buf[5..5 + body_len].copy_from_slice(&body[..body_len]);
    }
    wire::channel_write_msg(sys, s.out_response, wire::MSG_HTTP_RESPONSE, &buf[..total]);
}
