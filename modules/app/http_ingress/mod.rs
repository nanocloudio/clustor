//! HTTP ingress — clustor-side minimal HTTP/1.1 listener.
//!
//! Sits between a second `linux_net` instance (bound to its own
//! TCP port — by convention `peer_router.listen_port + 10000`) and
//! `http_adapter`. The path is:
//!
//!   browser/curl ──tcp──▶ linux_net_http
//!                                │ net_proto NMSG_DATA
//!                                ▼
//!                           http_ingress
//!                                │ MSG_HTTP_REQUEST (0x74)
//!                                │ `[conn_id][method][path_len][path][body]`
//!                                ▼
//!                           http_adapter
//!                                │ MSG_HTTP_RESPONSE (0x75)
//!                                │ `[conn_id][status:u16][body_len:u16][body]`
//!                                ▼
//!                           http_ingress
//!                                │ NCMD_SEND([conn_id][HTTP/1.1 200 OK\r\n...])
//!                                ▼
//!                           linux_net_http
//!                                │ Connection: close
//!                                ▼
//!                            browser/curl
//!
//! Why a clustor-side parser rather than fluxor's `foundation/http`:
//! the `MSG_HTTP_REQUEST` / `MSG_HTTP_RESPONSE` envelopes (msg
//! types 0x74 / 0x75) are a private protocol between this module
//! and `http_adapter`. Keeping the parser here means the
//! foundation HTTP module stays app-agnostic and clustor owns its
//! own diagnostic request/response framing end-to-end.
//!
//! Constraints (minimum viable diagnostic surface):
//!
//!   - GET only. Other methods return 405.
//!   - Headers parsed up to `\r\n\r\n`; body ignored (no Content-Length
//!     handling on the request side — the three diagnostic paths
//!     `/readyz`, `/why`, `/metrics` have no request body).
//!   - One request per connection: every response carries
//!     `Connection: close` and `http_ingress` emits `NCMD_CLOSE`
//!     after the write.
//!   - 4 concurrent connections, 2 KiB receive buffer per connection.
//!
//! Stderr signals emitted by this module (cluster tests assert on
//! these):
//!
//!   `[http_ingress] init listen_port=N`        — bring-up
//!   `[http_ingress] accepted conn_id=N`        — TCP accept
//!   `[http_ingress] request METHOD path conn_id=N` — parsed request
//!   `[http_ingress] closed conn_id=N`          — connection torn down

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

const MAX_CONNS: usize = 4;
const RX_BUF: usize = 2048;
const TX_BUF: usize = 4096;
const MAX_PATH: usize = 64;
/// Maximum request body forwarded to `http_adapter` in the
/// `MSG_HTTP_REQUEST` envelope. Bodies above this are truncated;
/// the diagnostic / admin paths fit comfortably under 1 KiB.
const MAX_BODY: usize = 1024;

// net_proto constants — must match fluxor's `linux_net` / `tls`
// module. Kept in sync with `modules/peer_router/mod.rs`.
const NMSG_ACCEPT: u8 = 0x01;
const NMSG_DATA: u8 = 0x02;
const NMSG_CLOSED: u8 = 0x03;
const NMSG_BOUND: u8 = 0x04;
const NCMD_BIND: u8 = 0x10;
const NCMD_SEND: u8 = 0x11;
const NCMD_CLOSE: u8 = 0x12;

define_params! {
    ModuleState;

    1, listen_port, u16, 9090
        => |s, d, len| { s.listen_port = p_u16(d, len, 0, 9090); };
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Conn {
    active: bool,
    conn_id: u8,
    /// Bytes of the request line + headers received so far.
    /// Reset to 0 once we've emitted MSG_HTTP_REQUEST.
    rx_len: u16,
    /// `true` once we've parsed `\r\n\r\n` and emitted the request
    /// frame; the slot stays alive waiting for the response.
    sent_request: bool,
    rx: [u8; RX_BUF],
}

impl Conn {
    const fn empty() -> Self {
        Self {
            active: false,
            conn_id: 0,
            rx_len: 0,
            sent_request: false,
            rx: [0u8; RX_BUF],
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_net: i32,         // in[0]: net_proto events from linux_net.net_out
    in_response: i32,    // in[1]: MSG_HTTP_RESPONSE from http_adapter.response
    out_net: i32,        // out[0]: net_proto commands to linux_net.net_in
    out_request: i32,    // out[1]: MSG_HTTP_REQUEST to http_adapter.request

    listen_port: u16,
    bound: bool,

    conns: [Conn; MAX_CONNS],
    /// Scratch for the linux_net frame envelope writer.
    net_buf: [u8; TX_BUF],
    /// Scratch for the MSG_HTTP_RESPONSE reader and HTTP/1.1
    /// response-builder.
    resp_buf: [u8; TX_BUF],
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
        s.in_net = in_chan;
        s.out_net = out_chan;
        s.in_response = dev_channel_port(sys, 0, 1);
        s.out_request = dev_channel_port(sys, 1, 1);
        s.listen_port = 9090;
        s.bound = false;
        s.conns = [Conn::empty(); MAX_CONNS];
        s.net_buf = [0u8; TX_BUF];
        s.resp_buf = [0u8; TX_BUF];
        if !params.is_null() && params_len > 0 {
            parse_tlv(s, params, params_len);
        }
        let mut buf = [0u8; 48];
        let n = format_init(&mut buf, s.listen_port);
        dev_log(sys, 3, buf.as_ptr(), n);
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

        if !s.bound {
            try_bind(s, sys);
        }
        drain_net_events(s, sys);
        drain_responses(s, sys);
        0
    }
}

// ── Bind the listen socket ───────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn try_bind(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_net < 0 {
        return;
    }
    let poll = (sys.channel_poll)(s.out_net, POLL_OUT);
    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
        return;
    }
    let pb = s.listen_port.to_le_bytes();
    net_write_frame(
        sys,
        s.out_net,
        NCMD_BIND,
        pb.as_ptr(),
        2,
        s.net_buf.as_mut_ptr(),
        TX_BUF,
    );
    s.bound = true;
}

// ── Inbound: linux_net events and HTTP request parsing ──────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_net_events(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_net < 0 {
        return;
    }
    for _ in 0..16 {
        let poll = (sys.channel_poll)(s.in_net, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let (event, payload_len) =
            net_read_frame(sys, s.in_net, s.net_buf.as_mut_ptr(), TX_BUF);
        if event == 0 {
            break;
        }
        if payload_len < 1 {
            continue;
        }
        let conn_id = s.net_buf[NET_FRAME_HDR];
        match event {
            NMSG_BOUND => {
                // linux_net acknowledged the bind. Nothing to do —
                // we already log on init.
            }
            NMSG_ACCEPT => {
                if let Some(idx) = alloc_conn(s, conn_id) {
                    let _ = idx;
                    let mut buf = [0u8; 48];
                    let n = format_accepted(&mut buf, conn_id);
                    dev_log(sys, 3, buf.as_ptr(), n);
                }
            }
            NMSG_DATA => {
                if payload_len < 2 {
                    continue;
                }
                let data_start = NET_FRAME_HDR + 1;
                let data_len = payload_len - 1;
                ingest_data(s, sys, conn_id, data_start, data_len);
            }
            NMSG_CLOSED => {
                free_conn(s, conn_id);
                let mut buf = [0u8; 48];
                let n = format_closed(&mut buf, conn_id);
                dev_log(sys, 3, buf.as_ptr(), n);
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
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ingest_data(
    s: &mut ModuleState,
    sys: &SyscallTable,
    conn_id: u8,
    data_start: usize,
    data_len: usize,
) {
    // Copy out of net_buf first because resolve_conn re-borrows it.
    let mut chunk = [0u8; RX_BUF];
    let take = data_len.min(RX_BUF);
    chunk[..take].copy_from_slice(&s.net_buf[data_start..data_start + take]);

    let slot = match find_conn(s, conn_id) {
        Some(i) => i,
        None => return,
    };
    if s.conns[slot].sent_request {
        // Awaiting the response — extra inbound bytes are dropped.
        return;
    }
    let conn = &mut s.conns[slot];
    let rx_len = conn.rx_len as usize;
    let copy_n = take.min(RX_BUF - rx_len);
    conn.rx[rx_len..rx_len + copy_n].copy_from_slice(&chunk[..copy_n]);
    conn.rx_len = (rx_len + copy_n) as u16;
    // Look for end-of-headers `\r\n\r\n`. If found, also confirm the
    // body (if Content-Length advertised) has been fully received
    // before emitting; otherwise wait for more data.
    let total = s.conns[slot].rx_len as usize;
    if let Some(headers_end) = find_double_crlf(&s.conns[slot].rx[..total]) {
        let content_length =
            parse_content_length(&s.conns[slot].rx[..headers_end]);
        let need = headers_end + content_length;
        if total >= need {
            emit_request(s, sys, slot, headers_end, content_length);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Emit `MSG_HTTP_REQUEST` for the connection at `slot`. `headers_end`
/// is the index of the byte AFTER the `\r\n\r\n` terminator;
/// `body_len` is the byte count of the request body (typically the
/// parsed `Content-Length`; 0 for GET).
unsafe fn emit_request(
    s: &mut ModuleState,
    sys: &SyscallTable,
    slot: usize,
    headers_end: usize,
    body_len: usize,
) {
    let (conn_id, method_byte, path, path_len) = {
        let conn = &s.conns[slot];
        match parse_request_line(&conn.rx[..headers_end]) {
            Some(parsed) => (conn.conn_id, parsed.0, parsed.1, parsed.2),
            None => {
                // Malformed — send a 400 immediately and bail.
                let body = b"bad request\n";
                send_http_response(s, sys, slot, 400, body);
                return;
            }
        }
    };

    // Build the MSG_HTTP_REQUEST envelope into a stack buffer big
    // enough for header overhead + path + body. The on-wire format
    // is `[conn_id:u8][method:u8][path_len:u8][path][body]`.
    let mut env = [0u8; 1 + 1 + 1 + MAX_PATH + MAX_BODY];
    env[0] = conn_id;
    env[1] = method_byte;
    env[2] = path_len as u8;
    env[3..3 + path_len].copy_from_slice(&path[..path_len]);
    let body_capped = body_len.min(MAX_BODY);
    let body_start = headers_end;
    env[3 + path_len..3 + path_len + body_capped]
        .copy_from_slice(&s.conns[slot].rx[body_start..body_start + body_capped]);
    let total = 3 + path_len + body_capped;
    if s.out_request >= 0 {
        let poll = (sys.channel_poll)(s.out_request, POLL_OUT);
        if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
            wire_channels::channel_write_msg(sys, s.out_request, wire::MSG_HTTP_REQUEST, &env[..total]);
        }
    }
    s.conns[slot].sent_request = true;

    // Log: "[http_ingress] request M /path body=N conn_id=K"
    let mut buf = [0u8; 128];
    let n = format_request_line(
        &mut buf,
        method_byte,
        &path[..path_len],
        body_capped,
        conn_id,
    );
    dev_log(sys, 3, buf.as_ptr(), n);
}

// ── Inbound: http_adapter responses ──────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_responses(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_response < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_response, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_response, &mut s.resp_buf);
        if msg_type != wire::MSG_HTTP_RESPONSE || (plen as usize) < 5 {
            continue;
        }
        let pl = plen as usize;
        let conn_id = s.resp_buf[0];
        let status = u16::from_le_bytes([s.resp_buf[1], s.resp_buf[2]]);
        let body_len = u16::from_le_bytes([s.resp_buf[3], s.resp_buf[4]]) as usize;
        if 5 + body_len > pl {
            continue;
        }
        // Snapshot body into a local buffer; send_http_response will
        // reuse `s.net_buf` to frame the wire response.
        let mut body = [0u8; TX_BUF];
        let take = body_len.min(TX_BUF);
        body[..take].copy_from_slice(&s.resp_buf[5..5 + take]);
        let slot = match find_conn(s, conn_id) {
            Some(i) => i,
            None => continue,
        };
        send_http_response(s, sys, slot, status, &body[..take]);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn send_http_response(
    s: &mut ModuleState,
    sys: &SyscallTable,
    slot: usize,
    status: u16,
    body: &[u8],
) {
    let conn_id = s.conns[slot].conn_id;
    // Frame an HTTP/1.1 response into a stack buffer, then push to
    // linux_net via NCMD_SEND with payload `[conn_id][http_bytes...]`.
    let mut http = [0u8; TX_BUF];
    let n = format_http_response(&mut http, status, body);
    let mut payload = [0u8; TX_BUF];
    payload[0] = conn_id;
    let n_body = n.min(TX_BUF - 1);
    payload[1..1 + n_body].copy_from_slice(&http[..n_body]);
    if s.out_net >= 0 {
        let poll = (sys.channel_poll)(s.out_net, POLL_OUT);
        if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
            net_write_frame(
                sys,
                s.out_net,
                NCMD_SEND,
                payload.as_ptr(),
                1 + n_body,
                s.net_buf.as_mut_ptr(),
                TX_BUF,
            );
            // Connection: close — tell linux_net we're done.
            let close_payload = [conn_id];
            net_write_frame(
                sys,
                s.out_net,
                NCMD_CLOSE,
                close_payload.as_ptr(),
                1,
                s.net_buf.as_mut_ptr(),
                TX_BUF,
            );
        }
    }
    free_conn(s, conn_id);
}

// ── Connection slot bookkeeping ──────────────────────────────

fn alloc_conn(s: &mut ModuleState, conn_id: u8) -> Option<usize> {
    for i in 0..MAX_CONNS {
        if !s.conns[i].active {
            s.conns[i] = Conn::empty();
            s.conns[i].active = true;
            s.conns[i].conn_id = conn_id;
            return Some(i);
        }
    }
    None
}

fn find_conn(s: &ModuleState, conn_id: u8) -> Option<usize> {
    for i in 0..MAX_CONNS {
        if s.conns[i].active && s.conns[i].conn_id == conn_id {
            return Some(i);
        }
    }
    None
}

fn free_conn(s: &mut ModuleState, conn_id: u8) {
    for i in 0..MAX_CONNS {
        if s.conns[i].active && s.conns[i].conn_id == conn_id {
            s.conns[i].active = false;
            return;
        }
    }
}

// ── HTTP/1.1 parsing helpers ─────────────────────────────────

/// Scan the header block for a `Content-Length:` line and parse
/// its decimal value. Case-insensitive on the header name, ignores
/// leading whitespace on the value. Returns 0 if the header isn't
/// present or is malformed — a missing or unparsable header is
/// treated as "no body".
fn parse_content_length(headers: &[u8]) -> usize {
    let needle: &[u8] = b"Content-Length:";
    let n = needle.len();
    let mut i = 0usize;
    while i + n <= headers.len() {
        // Match case-insensitively.
        let mut ok = true;
        for k in 0..n {
            let a = headers[i + k].to_ascii_lowercase();
            let b = needle[k].to_ascii_lowercase();
            if a != b {
                ok = false;
                break;
            }
        }
        if ok && (i == 0 || headers[i - 1] == b'\n') {
            // Read the value up to \r or \n.
            let mut j = i + n;
            while j < headers.len() && (headers[j] == b' ' || headers[j] == b'\t') {
                j += 1;
            }
            let mut val: usize = 0;
            while j < headers.len() {
                let c = headers[j];
                if c == b'\r' || c == b'\n' {
                    break;
                }
                if !c.is_ascii_digit() {
                    return 0;
                }
                val = val.saturating_mul(10).saturating_add((c - b'0') as usize);
                j += 1;
            }
            return val.min(MAX_BODY);
        }
        i += 1;
    }
    0
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 3 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

/// Parse the request line. Returns `(method_byte, path_bytes,
/// path_len)`. `method_byte` is the first byte of the verb (G/P/…),
/// matching http_adapter's expectation.
fn parse_request_line(buf: &[u8]) -> Option<(u8, [u8; MAX_PATH], usize)> {
    // Find first \r\n — end of request line.
    let mut eol = 0;
    while eol + 1 < buf.len() {
        if buf[eol] == b'\r' && buf[eol + 1] == b'\n' {
            break;
        }
        eol += 1;
    }
    if eol == 0 || eol + 1 >= buf.len() {
        return None;
    }
    let line = &buf[..eol];
    // METHOD SP PATH SP HTTP/1.1
    let sp1 = line.iter().position(|&b| b == b' ')?;
    if sp1 == 0 {
        return None;
    }
    let method_byte = line[0];
    let rest = &line[sp1 + 1..];
    let sp2 = rest.iter().position(|&b| b == b' ')?;
    let path = &rest[..sp2];
    if path.is_empty() {
        return None;
    }
    let mut out = [0u8; MAX_PATH];
    let take = path.len().min(MAX_PATH);
    out[..take].copy_from_slice(&path[..take]);
    Some((method_byte, out, take))
}

/// Frame an HTTP/1.1 response into `dst`. Returns bytes written.
fn format_http_response(dst: &mut [u8], status: u16, body: &[u8]) -> usize {
    let reason: &[u8] = match status {
        200 => b"OK",
        400 => b"Bad Request",
        404 => b"Not Found",
        405 => b"Method Not Allowed",
        503 => b"Service Unavailable",
        _ => b"OK",
    };
    let mut out = ByteCursor::new(dst);
    out.push(b"HTTP/1.1 ");
    out.push_u16(status);
    out.push(b" ");
    out.push(reason);
    out.push(b"\r\nContent-Type: text/plain\r\nContent-Length: ");
    out.push_usize(body.len());
    out.push(b"\r\nConnection: close\r\n\r\n");
    out.push(body);
    out.pos
}

// ── log-line formatters ──────────────────────────────────────

fn format_init(dst: &mut [u8], port: u16) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[http_ingress] init listen_port=");
    c.push_u16(port);
    c.pos
}

fn format_accepted(dst: &mut [u8], conn_id: u8) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[http_ingress] accepted conn_id=");
    c.push_usize(conn_id as usize);
    c.pos
}

fn format_closed(dst: &mut [u8], conn_id: u8) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[http_ingress] closed conn_id=");
    c.push_usize(conn_id as usize);
    c.pos
}

fn format_request_line(
    dst: &mut [u8],
    method_byte: u8,
    path: &[u8],
    body_len: usize,
    conn_id: u8,
) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[http_ingress] request ");
    c.push(&[method_byte]);
    c.push(b" ");
    c.push(path);
    c.push(b" body=");
    c.push_usize(body_len);
    c.push(b" conn_id=");
    c.push_usize(conn_id as usize);
    c.pos
}

// Tiny no_std cursor for building short ASCII strings into a fixed
// buffer. Truncates silently if `dst` is too small.
struct ByteCursor<'a> {
    dst: &'a mut [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(dst: &'a mut [u8]) -> Self {
        Self { dst, pos: 0 }
    }
    fn push(&mut self, bytes: &[u8]) {
        let room = self.dst.len().saturating_sub(self.pos);
        let take = bytes.len().min(room);
        self.dst[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
        self.pos += take;
    }
    fn push_u16(&mut self, n: u16) {
        self.push_usize(n as usize);
    }
    fn push_usize(&mut self, mut n: usize) {
        if n == 0 {
            self.push(b"0");
            return;
        }
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + ((n % 10) as u8);
            n /= 10;
        }
        self.push(&tmp[i..]);
    }
}
