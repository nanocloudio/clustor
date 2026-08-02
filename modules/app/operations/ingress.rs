//! ingress — minimal HTTP/1.1 listener.
//!
//! Sits between a `linux_net` instance (bound to its own TCP port —
//! by convention `peer_router.listen_port + 10000`) and the
//! [`http`](super::http) component:
//!
//!   browser/curl ──tcp──▶ linux_net
//!                              │ net_proto NMSG_DATA
//!                              ▼
//!                          ingress ── parsed request ──▶ http
//!                              ▲                          │
//!                              └── response ring ◀────────┘
//!                              │ NCMD_SEND([conn_id][HTTP/1.1 ...])
//!                              ▼
//!                          linux_net ──HTTP/1.1 keep-alive──▶ client
//!
//! Constraints (minimum viable diagnostic surface):
//!
//!   - Headers parsed up to `\r\n\r\n`; request bodies honoured up to
//!     `Content-Length`, capped at `MAX_BODY`.
//!   - Sequential HTTP/1.1 keep-alive. Pipelining is intentionally not
//!     supported: one request may be in flight per connection.
//!   - 32 concurrent connections, 2 KiB receive buffer per connection.
//!
//! `GET /readyz` is short-circuited entirely inside ingress from the
//! readiness byte the dispatch table delivers each telemetry emit
//! tick — the high-rate probe path never touches the request
//! pipeline. This path is intentionally unlogged.
//!
//! Responses from the `http` component arrive on an in-state byte
//! ring with the same framing and all-or-nothing write semantics as
//! a channel: `[conn_id:u8][status:u16 LE][body_len:u16 LE][body]`.
//! The ring drains to the wire at most 8 responses per step, gated on
//! `net_out` writability.
//!
//! Stderr signals emitted by this component (cluster tests assert on
//! these):
//!
//!   `[ingress] init listen_port=N`            — bring-up
//!   `[ingress] accepted conn_id=N`            — TCP accept
//!   `[ingress] request METHOD path conn_id=N` — parsed request
//!   `[ingress] closed conn_id=N`              — connection torn down

use super::abi::SyscallTable;
use super::{admin, http, rbac, telemetry};
use super::{
    dev_log, dev_report_step_effect, net_read_frame, net_write_frame, step_effect, NET_FRAME_HDR,
    POLL_IN, POLL_OUT,
};

/// Concurrent HTTP requests retained while their responses are in
/// flight. Must exceed the bench driver's worker count or load
/// profiles reject connections at the boundary; thirty-two leaves
/// headroom for operational `/metrics` and readiness probes alongside a
/// 16-connection load sweep while keeping the fixed, allocation-free
/// state bounded.
const MAX_CONNS: usize = 32;
const RX_BUF: usize = 2048;
/// Response/TX-path buffer. Must hold the largest response body the
/// http component can return — the `/metrics` export, capped at
/// `telemetry::SAFE_EXPORT_MAX` (7400 B) — plus the HTTP/1.1 status
/// line + headers (~90 B). 7680 covers the cap + headers and keeps
/// the framed net write (3 B net hdr + payload) under the channel
/// ring (8192).
const TX_BUF: usize = 7680;
const MAX_PATH: usize = 64;
/// Maximum request body forwarded to the http component. Bodies above
/// this are truncated; the diagnostic / admin paths fit comfortably
/// under 1 KiB.
const MAX_BODY: usize = 1024;

/// Response ring capacity. Sized to one channel ring so the
/// backpressure envelope matches the port it stands in for: it holds
/// one full `/metrics` response or a burst of small commit acks.
const RESP_RING: usize = 8192;
/// Response record header: `[conn_id:u8][status:u16 LE][len:u16 LE]`.
const RESP_HDR: usize = 5;

// net_proto constants — must match fluxor's `linux_net` / `tls`
// module. Kept in sync with `modules/peer_router/mod.rs`.
const NMSG_ACCEPT: u8 = 0x01;
const NMSG_DATA: u8 = 0x02;
const NMSG_CLOSED: u8 = 0x03;
const NMSG_BOUND: u8 = 0x04;
const NCMD_BIND: u8 = 0x10;
const NCMD_SEND: u8 = 0x11;
const NCMD_CLOSE: u8 = 0x12;

#[repr(C)]
#[derive(Clone, Copy)]
struct Conn {
    active: bool,
    conn_id: u8,
    /// Bytes of the request line + headers received so far.
    /// Reset to 0 once the request has been handed to `http`.
    rx_len: u16,
    /// `true` once we've parsed `\r\n\r\n` and delivered the request;
    /// the slot stays alive waiting for the response.
    sent_request: bool,
    /// Honour an HTTP/1.1 client's explicit `Connection: close` request while
    /// keeping persistent connections as the normal benchmark path.
    close_after_response: bool,
    rx: [u8; RX_BUF],
}

impl Conn {
    const fn empty() -> Self {
        Self {
            active: false,
            conn_id: 0,
            rx_len: 0,
            sent_request: false,
            close_after_response: false,
            rx: [0u8; RX_BUF],
        }
    }
}

#[repr(C)]
pub struct Ingress {
    pub in_net: i32,  // in: net_proto events from linux_net.net_out
    pub out_net: i32, // out: net_proto commands to linux_net.net_in

    pub listen_port: u16,
    bound: bool,
    /// Set when this pass advances an HTTP request or response. Returning
    /// Burst then asks Fluxor's bounded multi-pass scheduler to converge the
    /// downstream/return path without waiting for another cadence interval.
    pub step_work: bool,
    ready_seen: bool,
    ready_byte: u8,

    conns: [Conn; MAX_CONNS],

    /// Response ring: framed records queued by the http component,
    /// drained to the wire below. Same capacity and all-or-nothing
    /// write contract as a channel ring.
    resp_ring: [u8; RESP_RING],
    ring_head: u16,
    ring_used: u16,

    /// Scratch for the linux_net frame envelope writer.
    net_buf: [u8; TX_BUF],
    /// Scratch for un-ringing one response record.
    resp_buf: [u8; TX_BUF],
    /// State-resident hot-path scratch. Keeping these here avoids constructing
    /// and zeroing ~16 KiB of stack arrays for every small HTTP response.
    http_buf: [u8; TX_BUF],
    payload_buf: [u8; TX_BUF],
}

pub unsafe fn init(g: &mut Ingress) {
    g.in_net = -1;
    g.out_net = -1;
    g.listen_port = 9090;
    g.bound = false;
    g.step_work = false;
    g.ready_seen = false;
    g.ready_byte = 0;
    g.conns = [Conn::empty(); MAX_CONNS];
    g.resp_ring = [0u8; RESP_RING];
    g.ring_head = 0;
    g.ring_used = 0;
    g.net_buf = [0u8; TX_BUF];
    g.resp_buf = [0u8; TX_BUF];
    g.http_buf = [0u8; TX_BUF];
    g.payload_buf = [0u8; TX_BUF];
}

/// Deliver the newest readiness byte. Replaceable state — only the
/// latest publication is observable, exactly like the mailbox
/// contract this stands in for.
pub fn deliver_ready(g: &mut Ingress, ready: u8) {
    g.ready_byte = ready;
    g.ready_seen = true;
}

/// Whether the response ring can accept at least one byte — the same
/// contract as poll(OUT) on the channel this ring stands in for
/// (">= 1 byte free"); the actual enqueue is all-or-nothing.
pub fn response_writable(g: &Ingress) -> bool {
    (g.ring_used as usize) < RESP_RING
}

/// Queue one response record. All-or-nothing: a record that does not
/// fit the ring's free space is dropped, mirroring an atomic channel
/// write against a full ring. Returns whether the record was queued.
pub fn queue_response(
    g: &mut Ingress,
    _sys: &SyscallTable,
    conn_id: u8,
    status: u16,
    body: &[u8],
) -> bool {
    let body_len = body.len().min(http::METRICS_CACHE);
    let total = RESP_HDR + body_len;
    if (RESP_RING - g.ring_used as usize) < total {
        return false;
    }
    let mut hdr = [0u8; RESP_HDR];
    hdr[0] = conn_id;
    hdr[1..3].copy_from_slice(&status.to_le_bytes());
    hdr[3..5].copy_from_slice(&(body_len as u16).to_le_bytes());
    ring_write(g, &hdr);
    ring_write(g, &body[..body_len]);
    true
}

fn ring_write(g: &mut Ingress, bytes: &[u8]) {
    let mut w = (g.ring_head as usize + g.ring_used as usize) % RESP_RING;
    for &b in bytes {
        g.resp_ring[w] = b;
        w = (w + 1) % RESP_RING;
    }
    g.ring_used += bytes.len() as u16;
}

fn ring_read(g: &mut Ingress, n: usize, dst: &mut [u8]) {
    let mut r = g.ring_head as usize;
    for slot in dst.iter_mut().take(n) {
        *slot = g.resp_ring[r];
        r = (r + 1) % RESP_RING;
    }
    g.ring_head = r as u16;
    g.ring_used -= n as u16;
}

/// Per-step bound: 16 net events (each at most one request parse +
/// hand-off) + 8 response records drained to the wire, plus the
/// one-shot bind.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(
    g: &mut Ingress,
    h: &mut http::Http,
    rb: &mut rbac::Rbac,
    ad: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
) {
    g.step_work = false;
    if !g.bound {
        try_bind(g, sys);
    }
    drain_net_events(g, h, rb, ad, tele, sys, now);
    drain_responses(g, sys);
}

// ── Bind the listen socket ───────────────────────────────────

unsafe fn try_bind(g: &mut Ingress, sys: &SyscallTable) {
    if g.out_net < 0 {
        return;
    }
    let poll = (sys.channel_poll)(g.out_net, POLL_OUT);
    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
        return;
    }
    let pb = g.listen_port.to_le_bytes();
    net_write_frame(
        sys,
        g.out_net,
        NCMD_BIND,
        pb.as_ptr(),
        2,
        g.net_buf.as_mut_ptr(),
        TX_BUF,
    );
    g.bound = true;
}

// ── Inbound: linux_net events and HTTP request parsing ──────

unsafe fn drain_net_events(
    g: &mut Ingress,
    h: &mut http::Http,
    rb: &mut rbac::Rbac,
    ad: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
) {
    if g.in_net < 0 {
        return;
    }
    for _ in 0..16 {
        let poll = (sys.channel_poll)(g.in_net, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
            break;
        }
        let (event, payload_len) = net_read_frame(sys, g.in_net, g.net_buf.as_mut_ptr(), TX_BUF);
        if event == 0 {
            break;
        }
        if payload_len < 1 {
            continue;
        }
        let conn_id = g.net_buf[NET_FRAME_HDR];
        match event {
            NMSG_BOUND => {
                // linux_net acknowledged the bind. Nothing to do —
                // we already log on init.
            }
            NMSG_ACCEPT => {
                // Per-port filter: ACCEPT carries the parent listener's
                // local_port after the conn_id. On a shared net_out
                // broadcast (multi-anchor graphs) claiming every accept
                // makes this h1 server answer 404s on OTHER protocols'
                // connections — observed polluting an h2/gRPC anchor's
                // port. Only claim conns accepted on OUR listen port;
                // tolerate short frames from older net providers that
                // don't carry the port (single-listener graphs).
                if payload_len >= 3 {
                    let port = u16::from_le_bytes([
                        g.net_buf[NET_FRAME_HDR + 1],
                        g.net_buf[NET_FRAME_HDR + 2],
                    ]);
                    if port != g.listen_port {
                        continue;
                    }
                }
                if alloc_conn(g, conn_id).is_some() {
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
                ingest_data(g, h, rb, ad, tele, sys, now, conn_id, data_start, data_len);
            }
            NMSG_CLOSED => {
                free_conn(g, conn_id);
                let mut buf = [0u8; 48];
                let n = format_closed(&mut buf, conn_id);
                dev_log(sys, 3, buf.as_ptr(), n);
            }
            _ => {}
        }
    }
}

unsafe fn ingest_data(
    g: &mut Ingress,
    h: &mut http::Http,
    rb: &mut rbac::Rbac,
    ad: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
    conn_id: u8,
    data_start: usize,
    data_len: usize,
) {
    let take = data_len.min(RX_BUF);
    let slot = match find_conn(g, conn_id) {
        Some(i) => i,
        None => return,
    };
    if g.conns[slot].sent_request {
        // Awaiting the response — extra inbound bytes are dropped.
        return;
    }
    {
        let rx_len = g.conns[slot].rx_len as usize;
        let copy_n = take.min(RX_BUF - rx_len);
        // Split the borrow: net_buf and conns are disjoint fields.
        let (net_buf, conns) = (&g.net_buf, &mut g.conns);
        conns[slot].rx[rx_len..rx_len + copy_n]
            .copy_from_slice(&net_buf[data_start..data_start + copy_n]);
        conns[slot].rx_len = (rx_len + copy_n) as u16;
    }
    // Look for end-of-headers `\r\n\r\n`. If found, also confirm the
    // body (if Content-Length advertised) has been fully received
    // before delivering; otherwise wait for more data.
    let total = g.conns[slot].rx_len as usize;
    if let Some(headers_end) = find_double_crlf(&g.conns[slot].rx[..total]) {
        let content_length = parse_content_length(&g.conns[slot].rx[..headers_end]);
        let need = headers_end + content_length;
        if total >= need {
            deliver_request(g, h, rb, ad, tele, sys, now, slot, headers_end, content_length);
        }
    }
}

/// Parse and deliver the request at `slot` to the http component.
/// `headers_end` is the index of the byte AFTER the `\r\n\r\n`
/// terminator; `body_len` is the byte count of the request body
/// (typically the parsed `Content-Length`; 0 for GET).
unsafe fn deliver_request(
    g: &mut Ingress,
    h: &mut http::Http,
    rb: &mut rbac::Rbac,
    ad: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
    slot: usize,
    headers_end: usize,
    body_len: usize,
) {
    g.conns[slot].close_after_response =
        requests_connection_close(&g.conns[slot].rx[..headers_end]);
    let (conn_id, method_byte, path, path_len) = {
        let conn = &g.conns[slot];
        match parse_request_line(&conn.rx[..headers_end]) {
            Some(parsed) => (conn.conn_id, parsed.0, parsed.1, parsed.2),
            None => {
                // Malformed — send a 400 immediately and bail.
                send_http_response(g, sys, slot, 400, b"bad request\n");
                return;
            }
        }
    };

    // The readiness byte is replaceable state delivered each telemetry
    // emit tick, so this high-rate diagnostic path completes inside
    // ingress without touching the request pipeline. Intentionally
    // unlogged.
    if method_byte == b'G' && &path[..path_len] == b"/readyz" {
        let body = [g.ready_byte];
        let status = if g.ready_seen && g.ready_byte != 0 { 200 } else { 503 };
        send_http_response(g, sys, slot, status, &body);
        return;
    }

    // Copy the body out of the connection buffer, then hand the parsed
    // request to the http component. Responses come back through the
    // response ring.
    let body_capped = body_len.min(MAX_BODY);
    let mut body_local = [0u8; MAX_BODY];
    body_local[..body_capped]
        .copy_from_slice(&g.conns[slot].rx[headers_end..headers_end + body_capped]);
    g.conns[slot].sent_request = true;
    g.step_work = true;
    dev_report_step_effect(sys, step_effect::WORK_DONE);
    // Ordered POST/admin/proposal requests are low-frequency enough to
    // log per-request (unlike `/readyz` above, which is intentionally
    // silent — see the short-circuit note). This is the only external
    // signal that a request actually reached the request pipeline.
    let mut buf = [0u8; 128];
    let n = format_request_line(&mut buf, method_byte, &path[..path_len], body_capped, conn_id);
    dev_log(sys, 3, buf.as_ptr(), n);
    http::on_request(
        h,
        g,
        rb,
        ad,
        tele,
        sys,
        now,
        conn_id,
        method_byte,
        &path[..path_len],
        &body_local[..body_capped],
    );
}

// ── Outbound: response ring → wire ───────────────────────────

unsafe fn drain_responses(g: &mut Ingress, sys: &SyscallTable) {
    if g.out_net < 0 {
        return;
    }
    for _ in 0..8 {
        if g.ring_used < RESP_HDR as u16 {
            break;
        }
        // Do not consume a response record unless the complete net
        // command has somewhere to go. The write below is atomic.
        let net_poll = (sys.channel_poll)(g.out_net, POLL_OUT);
        if net_poll <= 0 || (net_poll as u32 & POLL_OUT) == 0 {
            break;
        }
        let mut hdr = [0u8; RESP_HDR];
        ring_read(g, RESP_HDR, &mut hdr);
        let conn_id = hdr[0];
        let status = u16::from_le_bytes([hdr[1], hdr[2]]);
        let body_len = u16::from_le_bytes([hdr[3], hdr[4]]) as usize;
        let take = body_len.min(TX_BUF);
        // Un-ring the body into the state-resident staging buffer —
        // no stack arrays on this path.
        {
            let mut r = g.ring_head as usize;
            for i in 0..take {
                g.resp_buf[i] = g.resp_ring[r];
                r = (r + 1) % RESP_RING;
            }
            g.ring_head = r as u16;
            g.ring_used -= take as u16;
        }
        let slot = match find_conn(g, conn_id) {
            Some(i) => i,
            None => continue,
        };
        respond_from_resp_buf(g, sys, slot, status, take);
    }
}

/// Send a response whose body is small enough to stage through the
/// state-resident buffer (all callers respect `TX_BUF`).
unsafe fn send_http_response(
    g: &mut Ingress,
    sys: &SyscallTable,
    slot: usize,
    status: u16,
    body: &[u8],
) {
    let take = body.len().min(TX_BUF);
    g.resp_buf[..take].copy_from_slice(&body[..take]);
    respond_from_resp_buf(g, sys, slot, status, take);
}

/// Frame and send the response whose body sits in `resp_buf[..len]`.
unsafe fn respond_from_resp_buf(
    g: &mut Ingress,
    sys: &SyscallTable,
    slot: usize,
    status: u16,
    len: usize,
) {
    let conn_id = g.conns[slot].conn_id;
    let close = g.conns[slot].close_after_response;
    // Frame an HTTP/1.1 response into state-resident scratch, then push to
    // linux_net via NCMD_SEND with payload `[conn_id][http_bytes...]`.
    // resp_buf and http_buf are disjoint fields, so the split borrow is safe.
    let n = {
        let Ingress { http_buf, resp_buf, .. } = g;
        format_http_response(http_buf, status, &resp_buf[..len], !close)
    };
    g.payload_buf[0] = conn_id;
    let n_body = n.min(TX_BUF - 1);
    {
        let (http_buf, payload_buf) = (&g.http_buf, &mut g.payload_buf);
        payload_buf[1..1 + n_body].copy_from_slice(&http_buf[..n_body]);
    }
    let mut sent = false;
    if g.out_net >= 0 {
        let poll = (sys.channel_poll)(g.out_net, POLL_OUT);
        if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
            sent = net_write_frame(
                sys,
                g.out_net,
                NCMD_SEND,
                g.payload_buf.as_ptr(),
                1 + n_body,
                g.net_buf.as_mut_ptr(),
                TX_BUF,
            ) == NET_FRAME_HDR + 1 + n_body;
        }
    }
    if sent {
        g.step_work = true;
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        if close {
            let close_payload = [conn_id];
            net_write_frame(
                sys,
                g.out_net,
                NCMD_CLOSE,
                close_payload.as_ptr(),
                1,
                g.net_buf.as_mut_ptr(),
                TX_BUF,
            );
            free_conn(g, conn_id);
        } else {
            // Keep the accepted socket and slot, but make it ready for the
            // next sequential request. NMSG_CLOSED remains the teardown path.
            g.conns[slot].rx_len = 0;
            g.conns[slot].sent_request = false;
        }
    }
}

// ── Connection slot bookkeeping ──────────────────────────────

fn alloc_conn(g: &mut Ingress, conn_id: u8) -> Option<usize> {
    for i in 0..MAX_CONNS {
        if !g.conns[i].active {
            g.conns[i] = Conn::empty();
            g.conns[i].active = true;
            g.conns[i].conn_id = conn_id;
            return Some(i);
        }
    }
    None
}

fn find_conn(g: &Ingress, conn_id: u8) -> Option<usize> {
    for i in 0..MAX_CONNS {
        if g.conns[i].active && g.conns[i].conn_id == conn_id {
            return Some(i);
        }
    }
    None
}

fn free_conn(g: &mut Ingress, conn_id: u8) {
    for i in 0..MAX_CONNS {
        if g.conns[i].active && g.conns[i].conn_id == conn_id {
            g.conns[i].active = false;
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

/// Whether the request explicitly asks the server to close after its
/// response. HTTP/1.1 is persistent by default.
fn requests_connection_close(headers: &[u8]) -> bool {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = match line.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => continue,
        };
        if ascii_eq_ignore_case(&line[..colon], b"connection") {
            let mut value = &line[colon + 1..];
            while value.first() == Some(&b' ') || value.first() == Some(&b'\t') {
                value = &value[1..];
            }
            return ascii_eq_ignore_case(value, b"close");
        }
    }
    false
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
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
/// matching the http component's expectation.
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
fn format_http_response(dst: &mut [u8], status: u16, body: &[u8], keep_alive: bool) -> usize {
    let reason: &[u8] = match status {
        200 => b"OK",
        202 => b"Accepted",
        400 => b"Bad Request",
        403 => b"Forbidden",
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
    if keep_alive {
        out.push(b"\r\nConnection: keep-alive\r\n\r\n");
    } else {
        out.push(b"\r\nConnection: close\r\n\r\n");
    }
    out.push(body);
    out.pos
}

// ── log-line formatters ──────────────────────────────────────

pub fn format_init(dst: &mut [u8], port: u16) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[ingress] init listen_port=");
    c.push_u16(port);
    c.pos
}

fn format_accepted(dst: &mut [u8], conn_id: u8) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[ingress] accepted conn_id=");
    c.push_usize(conn_id as usize);
    c.pos
}

fn format_closed(dst: &mut [u8], conn_id: u8) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[ingress] closed conn_id=");
    c.push_usize(conn_id as usize);
    c.pos
}

/// `[ingress] request M /path body=N conn_id=K` — the only
/// external signal that a non-`/readyz` request reached the request
/// pipeline. Never emitted for `/readyz`, which is answered from
/// ingress ready state and is intentionally unlogged per-request.
fn format_request_line(
    dst: &mut [u8],
    method_byte: u8,
    path: &[u8],
    body_len: usize,
    conn_id: u8,
) -> usize {
    let mut c = ByteCursor::new(dst);
    c.push(b"[ingress] request ");
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
