//! http — diagnostic and write-bridge request handling.
//!
//! Serves the well-known diagnostic paths from caches refreshed by
//! the [`telemetry`](super::telemetry) component each emit tick:
//!
//!   - `GET /readyz`  → 200 if ready, 503 otherwise; body carries the
//!     latest readyz byte.
//!   - `GET /why`     → 200 with the latest why body.
//!   - `GET /metrics` → 200 with the latest export payload, served
//!     verbatim — see RFC §4.3.
//!
//! `POST /admin/<op>` is admitted through the [`rbac`](super::rbac)
//! component like every other admin command — HTTP-origin commands
//! evaluate as `default_role` (no peer identity), so a deployment
//! that must not accept HTTP admin sets an observer `default_role`
//! or ships the `headless` variant, which has no HTTP surface at all.
//!
//! `POST /propose` is the synchronous write bridge. A private
//! correlation id (bit 63 set, keeping the namespace disjoint from
//! the codec component's) follows the proposal through Raft assignment to
//! its exact WAL index; the HTTP response is emitted only when apply
//! acknowledges that index.
//!
//! ## Transport
//!
//! This component owns the MEANING of each request and none of the
//! HTTP mechanics. Requests arrive on the `request` port as wave
//! `HttpRequest` envelopes, parsed and framed by wave's `http`
//! module (`app` variant) wired in front of this one; replies leave
//! on `response` as wave `HttpResponse` envelopes and wave puts them
//! back on the wire. Both edges run in mailbox mode (`buffer_group`
//! in the graph), so one channel write is one whole envelope.
//!
//! A response is correlated by `(conn_id, stream_id)` — wave echoes
//! the pair so a deferred `/propose` reply can never land on a
//! client that merely inherited a recycled conn id. The
//! backpressure contract is preserved: the dispatch table gates
//! every pull — requests and proposal feedback alike — on
//! [`response_writable`], so nothing is consumed without somewhere
//! to answer.
//!
//! `/metrics` exceeds one wave send buffer, so it is streamed: the
//! first envelope carries `MORE_BODY`, a `Content-Length` header and
//! the first slice; continuation envelopes carry the rest, advanced
//! by [`step`] as the port drains. One export streams at a time —
//! a concurrent `/metrics` answers 503 until the slot frees.

use super::abi::SyscallTable;
use super::{http_admin, telemetry, wire, wire_channels};
use super::{dev_log, dev_millis, dev_report_step_effect, step_effect};

/// Bound on the small cached envelopes — `/readyz` and `/why` carry a
/// single status byte, so 1 KiB is ample.
const ENVELOPE_CACHE: usize = 1024;

/// Slack the `/metrics` cache keeps above the telemetry export cap.
/// Expressed as a named delta off the one source
/// (`telemetry::SAFE_EXPORT_MAX`) rather than a second literal.
const METRICS_CACHE_SLACK: usize = 200;

/// Bound on the cached `/metrics` body: the telemetry export cap plus
/// slack.
pub const METRICS_CACHE: usize = telemetry::SAFE_EXPORT_MAX + METRICS_CACHE_SLACK;

// Two bounded phase tables (correlation→connection and index→connection).
// Sized above wave's default working set so phase handoff and an
// operational probe cannot exhaust the mapping space during a burst.
const HTTP_INFLIGHT: usize = 64;

/// Wave `HttpRequest` envelope head:
/// `[conn_id:u16][stream_id:u16][method:u8][flags:u8]
/// [path_len:u16][hdr_len:u16][body_len:u16]`, all LE, then the
/// path, the raw header block and the body
/// (wave `modules/foundation/http/server/app.rs`).
const REQ_HDR: usize = 12;
/// Wave `HttpResponse` envelope head:
/// `[conn_id:u16][stream_id:u16][status:u16][flags:u8][ct_len:u8]
/// [hdr_len:u16][body_len:u16]`, then the content type, headers
/// and body.
const RESP_HDR: usize = 12;
/// `flags` bit 0 on both envelopes: the body continues in further
/// envelopes (wave `FLAG_MORE_BODY`).
const FLAG_MORE_BODY: u8 = 0x01;

// Wave's method-byte encoding (`modules/foundation/http/wire.rs`).
// Mirrored rather than imported — the two projects share no source —
// and small enough that drift would fail the e2e admin tests
// immediately. Only POST is gated on: the diagnostic paths match on
// path alone and answer any verb.
const METHOD_POST: u8 = 3;

/// Content type stamped on every reply this component produces.
const CT_TEXT: &[u8] = b"text/plain";

/// Largest single-envelope response body, and the `/metrics` stream
/// slice. Must stay under wave's per-connection send buffer
/// (`SEND_BUF_SIZE` = 4100) with room for the response head, or wave
/// truncates the envelope and closes the connection.
const RESP_SLICE: usize = 3072;

/// Bounds on an externally-parsed request. The body bound matches the
/// 1 KiB admin envelope.
const MAX_EXT_PATH: usize = 64;
const MAX_EXT_BODY: usize = 1024;
/// Largest `request` envelope accepted — wave's `req_out`
/// `max_record`. The excess over path+body bounds is the forwarded
/// header block, which this component skips.
const MAX_EXT_REQUEST: usize = 8192;

/// Correlation-id prefix on a `/propose` frame handed to the gateway.
const CORR_ID_LEN: usize = 8;

const HTTP_PROPOSAL_TIMEOUT_MS: u64 = 10_000;
const METRICS_INTERVAL_MS: u64 = 250;

/// Terminal route for one HTTP request, resolved by [`on_request`].
/// Every reply egresses on `response` inside the producing call;
/// only the admin admission round trip leaves the component.
pub enum ReqOut {
    /// Fully handled (proposal emitted, reply sent, dropped).
    Done,
    /// A `POST /admin/<op>` envelope staged in the admin buffer
    /// ([`admin_env`]); the dispatch table routes it through
    /// rbac → admin and completes the reply via [`finish_admin`].
    Admin { op_code: u8, len: u16 },
}

/// One pull off a proposal-feedback channel: nothing readable, or
/// consumed (matched-and-answered, unmatched, malformed — burns the
/// loop slot either way).
pub enum Feedback {
    Empty,
    Handled,
}

/// The staged admin envelope for a [`ReqOut::Admin`] record.
pub fn admin_env(h: &Http, len: u16) -> &[u8] {
    &h.admin_env[..len as usize]
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CorrSlot {
    correlation_id: u64,
    started_ms: u64,
    conn_id: u16,
    stream_id: u16,
}

impl CorrSlot {
    const fn empty() -> Self {
        Self { correlation_id: 0, started_ms: 0, conn_id: 0, stream_id: 0 }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct IndexSlot {
    index: u64,
    started_ms: u64,
    conn_id: u16,
    stream_id: u16,
}

impl IndexSlot {
    const fn empty() -> Self {
        Self { index: 0, started_ms: 0, conn_id: 0, stream_id: 0 }
    }
}

#[repr(C)]
pub struct Http {
    pub in_proposal_assigned: i32, // in: correlation_id → WAL index from Raft
    pub in_applied: i32,           // in: per-index apply acknowledgements
    pub in_proposal_rejected: i32, // in: throttle rejection by correlation id
    pub in_request: i32,           // in: wave HttpRequest envelopes
    pub out_proposal: i32,         // out: tagged proposal → gateway.proposals
    pub out_response: i32,         // out: wave HttpResponse envelopes

    next_correlation_id: u64,
    correlations: [CorrSlot; HTTP_INFLIGHT],
    indices: [IndexSlot; HTTP_INFLIGHT],

    /// Most recent diagnostic payloads, refreshed from the telemetry
    /// component each emit tick. `*_len = 0` means "no value seen
    /// yet"; respond with a service-degraded default in that case.
    readyz_buf: [u8; ENVELOPE_CACHE],
    readyz_len: u16,
    why_buf: [u8; ENVELOPE_CACHE],
    why_len: u16,
    metrics_buf: [u8; METRICS_CACHE],
    metrics_len: u16,

    /// The in-progress `/metrics` stream: one export at a time.
    /// `st_active` gates [`cache_export`]'s metrics refresh so the
    /// body cannot change length mid-stream.
    st_active: u8,
    st_head_sent: u8,
    st_conn: u16,
    st_stream: u16,
    st_off: u32,

    /// Staging for one inbound `request` envelope and one outbound
    /// `response` envelope. State-resident: both exceed what the
    /// module's step path should put on the stack.
    req_frame: [u8; MAX_EXT_REQUEST],
    resp_frame: [u8; RESP_HDR + 64 + RESP_SLICE],

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
    /// Replies the `response` port refused. Every pull is gated on
    /// [`response_writable`], so this should stay at zero; a rising
    /// count means the response edge is undersized. The client sees
    /// wave's 504.
    responses_dropped: u32,
    last_metrics_ms: u64,
    /// Count of `POST /admin/<op>` requests refused before admission —
    /// rbac denial or a body exceeding the 1 KiB envelope buffer. The
    /// HTTP client sees 403/503 for each one. Surfaced through the
    /// telemetry component so sustained refusal is operationally
    /// visible.
    admin_dropped: u32,
    /// Set when a step advanced a request, reply or stream slice;
    /// consumed by the dispatch table's burst classification.
    worked: u8,
    /// Scratch for draining the proposal-feedback channels (small
    /// fixed-size frames).
    msg_buf: [u8; 256],
    /// Staging for one `POST /admin/<op>` envelope handed to the
    /// dispatch table as [`ReqOut::Admin`].
    admin_env: [u8; 1024],
}

pub unsafe fn init(h: &mut Http) {
    h.in_proposal_assigned = -1;
    h.in_applied = -1;
    h.in_proposal_rejected = -1;
    h.in_request = -1;
    h.out_proposal = -1;
    h.out_response = -1;
    h.next_correlation_id = 1;
    h.correlations = [CorrSlot::empty(); HTTP_INFLIGHT];
    h.indices = [IndexSlot::empty(); HTTP_INFLIGHT];
    h.readyz_len = 0;
    h.why_len = 0;
    h.metrics_len = 0;
    h.st_active = 0;
    h.st_head_sent = 0;
    h.st_conn = 0;
    h.st_stream = 0;
    h.st_off = 0;
    h.requests_handled = 0;
    h.requests_404 = 0;
    h.inflight_high_water = 0;
    h.proposal_timeouts = 0;
    h.commit_timeouts = 0;
    h.assignments_unmatched = 0;
    h.assignments_no_slot = 0;
    h.applies_unmatched = 0;
    h.proposal_rejections = 0;
    h.queue_unavailable = 0;
    h.committed = 0;
    h.responses_dropped = 0;
    h.last_metrics_ms = 0;
    h.admin_dropped = 0;
    h.worked = 0;
    h.admin_env = [0u8; 1024];
}

/// Whether the `response` port can take an envelope right now. The
/// dispatch table gates every feedback pull on this, preserving the
/// rule that feedback is never consumed without somewhere to answer.
pub unsafe fn response_writable(h: &Http, sys: &SyscallTable) -> bool {
    if h.out_response < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(h.out_response, 0x02);
    poll > 0 && (poll as u32 & 0x02) != 0
}

/// Consume the burst flag: whether this component advanced a
/// request, reply or stream slice since the last call.
pub fn take_worked(h: &mut Http) -> bool {
    let w = h.worked != 0;
    h.worked = 0;
    w
}

/// Frame and write ONE wave `HttpResponse` envelope on `response`.
/// All-or-nothing (the port runs in mailbox mode); a refused write
/// counts as a dropped reply — the client surfaces it as wave's 504.
///
/// The body rides as a raw pointer so callers can hand slices of
/// `h`'s own caches (`metrics_buf`, `readyz_buf`) without staging
/// them through a stack buffer first — the frame is composed in the
/// state-resident `resp_frame`.
///
/// # Safety
///
/// `body_ptr..body_ptr+body_len` must be readable and must not alias
/// `h.resp_frame`.
unsafe fn emit_envelope(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u16,
    stream_id: u16,
    status: u16,
    flags: u8,
    ct: &[u8],
    headers: &[u8],
    body_ptr: *const u8,
    body_len: usize,
) -> bool {
    if h.out_response < 0 {
        return false;
    }
    let total = RESP_HDR + ct.len() + headers.len() + body_len;
    if total > h.resp_frame.len() {
        h.responses_dropped = h.responses_dropped.saturating_add(1);
        return false;
    }
    h.resp_frame[0..2].copy_from_slice(&conn_id.to_le_bytes());
    h.resp_frame[2..4].copy_from_slice(&stream_id.to_le_bytes());
    h.resp_frame[4..6].copy_from_slice(&status.to_le_bytes());
    h.resp_frame[6] = flags;
    h.resp_frame[7] = ct.len() as u8;
    h.resp_frame[8..10].copy_from_slice(&(headers.len() as u16).to_le_bytes());
    h.resp_frame[10..12].copy_from_slice(&(body_len as u16).to_le_bytes());
    let mut at = RESP_HDR;
    h.resp_frame[at..at + ct.len()].copy_from_slice(ct);
    at += ct.len();
    h.resp_frame[at..at + headers.len()].copy_from_slice(headers);
    at += headers.len();
    if body_len > 0 {
        core::ptr::copy_nonoverlapping(body_ptr, h.resp_frame.as_mut_ptr().add(at), body_len);
    }
    let wrote = (sys.channel_write)(h.out_response, h.resp_frame.as_ptr(), total);
    if wrote <= 0 {
        h.responses_dropped = h.responses_dropped.saturating_add(1);
        return false;
    }
    h.worked = 1;
    true
}

/// Answer one request with a small (single-envelope) reply.
unsafe fn finish(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u16,
    stream_id: u16,
    status: u16,
    body: &[u8],
) {
    let n = body.len().min(RESP_SLICE);
    emit_envelope(h, sys, conn_id, stream_id, status, 0, CT_TEXT, &[], body.as_ptr(), n);
}

/// One request pulled off the `request` port, handed to the dispatch
/// table for [`on_request`] routing.
#[repr(C)]
pub struct ExtReq {
    pub conn_id: u16,
    pub stream_id: u16,
    pub method: u8,
    pub flags: u8,
    pub path_len: u16,
    pub body_len: u16,
    pub path: [u8; MAX_EXT_PATH],
    pub body: [u8; MAX_EXT_BODY],
}

impl ExtReq {
    pub const fn new() -> Self {
        Self {
            conn_id: 0,
            stream_id: 0,
            method: 0,
            flags: 0,
            path_len: 0,
            body_len: 0,
            path: [0; MAX_EXT_PATH],
            body: [0; MAX_EXT_BODY],
        }
    }
}

/// One pull off the `request` port.
pub enum ExtPulled {
    Empty,
    Skipped,
    Request,
}

/// Read ONE wave `HttpRequest` envelope off the `request` port. The
/// forwarded header block is skipped — every path this component
/// serves is defined by its verb, path and body alone. `Skipped`
/// marks a consumed unusable envelope so the loop bound counts it; a
/// bounds violation the producer would not commit (path or body over
/// this component's caps) is answered rather than dropped.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_external_request(
    h: &mut Http,
    sys: &SyscallTable,
    req: &mut ExtReq,
) -> ExtPulled {
    if h.in_request < 0 {
        return ExtPulled::Empty;
    }
    let poll = (sys.channel_poll)(h.in_request, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return ExtPulled::Empty;
    }
    let n = (sys.channel_read)(h.in_request, h.req_frame.as_mut_ptr(), MAX_EXT_REQUEST);
    if n < REQ_HDR as i32 {
        return ExtPulled::Skipped;
    }
    let buf = &h.req_frame[..n as usize];
    let conn_id = u16::from_le_bytes([buf[0], buf[1]]);
    let stream_id = u16::from_le_bytes([buf[2], buf[3]]);
    let method = buf[4];
    let flags = buf[5];
    let path_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let hdr_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let body_len = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    let need = REQ_HDR
        .saturating_add(path_len)
        .saturating_add(hdr_len)
        .saturating_add(body_len);
    if need > buf.len() {
        return ExtPulled::Skipped; // truncated — a producer framing error
    }
    if path_len > MAX_EXT_PATH {
        // Longer than any path this surface serves.
        h.requests_404 = h.requests_404.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 404, b"not found");
        return ExtPulled::Skipped;
    }
    if body_len > MAX_EXT_BODY || (flags & FLAG_MORE_BODY) != 0 {
        // Over the admin envelope bound, or a streamed request body —
        // nothing here takes one. Refusing beats truncating a
        // proposal. Continuation envelopes for a refused stream
        // parse as requests for unknown paths and answer 404.
        finish(h, sys, conn_id, stream_id, 413, b"body too large");
        return ExtPulled::Skipped;
    }
    let body_off = REQ_HDR + path_len + hdr_len;
    req.conn_id = conn_id;
    req.stream_id = stream_id;
    req.method = method;
    req.flags = flags;
    req.path_len = path_len as u16;
    req.body_len = body_len as u16;
    req.path[..path_len].copy_from_slice(&h.req_frame[REQ_HDR..REQ_HDR + path_len]);
    req.body[..body_len].copy_from_slice(&h.req_frame[body_off..body_off + body_len]);
    ExtPulled::Request
}

/// Refresh the diagnostic caches from the telemetry component's
/// snapshot values. Called by the dispatch table on exactly the steps
/// telemetry emitted, so cache freshness matches the export cadence —
/// the http component never sees the telemetry struct itself. The
/// metrics body is left untouched while a `/metrics` stream is in
/// flight (its declared `Content-Length` must stay true); the next
/// emit tick lands normally.
pub fn cache_export(h: &mut Http, ready: bool, timing_pause: u8, export: &[u8]) {
    h.readyz_buf[0] = ready as u8;
    h.readyz_len = 1;
    // `/why` payload: [version:1][timing_pause_reason] — mirrors the
    // MSG_WHY wire form (see telemetry.rs).
    h.why_buf[0] = 1;
    h.why_buf[1] = timing_pause;
    h.why_len = 2;
    if h.st_active != 0 {
        return;
    }
    let len = export.len().min(METRICS_CACHE);
    if len > 0 {
        h.metrics_buf[..len].copy_from_slice(&export[..len]);
    }
    // An empty export invalidates the cache: `/metrics` then serves
    // an empty body rather than silently replaying stale data.
    h.metrics_len = len as u16;
}

/// Own-state drains: ≤16 proposal assignments, then the in-flight
/// `/metrics` stream. The response-producing feedback loops (≤8
/// rejections, ≤16 applies, one expiry) are driven by the dispatch
/// table through [`next_rejection`] / [`next_applied`] /
/// [`expire_step`], each pull gated there on [`response_writable`] —
/// feedback is never consumed without somewhere to answer. The
/// 250 ms self-metrics tick rides [`take_metrics`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(h: &mut Http, sys: &SyscallTable) {
    drain_proposal_assignments(h, sys);
    stream_step(h, sys);
}

/// Advance the in-flight `/metrics` stream as far as the `response`
/// port allows this step. The head envelope declares the total via
/// `Content-Length` so wave frames the whole transfer and keep-alive
/// survives; continuation envelopes carry body slices only.
unsafe fn stream_step(h: &mut Http, sys: &SyscallTable) {
    while h.st_active != 0 {
        if !response_writable(h, sys) {
            return;
        }
        let total = h.metrics_len as usize;
        if h.st_head_sent == 0 {
            let mut hdrs = [0u8; 32];
            let hn = format_content_length(&mut hdrs, total);
            let n = total.min(RESP_SLICE);
            let body = h.metrics_buf.as_ptr();
            if !emit_envelope(
                h,
                sys,
                h.st_conn,
                h.st_stream,
                200,
                FLAG_MORE_BODY,
                CT_TEXT,
                &hdrs[..hn],
                body,
                n,
            ) {
                return;
            }
            h.st_head_sent = 1;
            h.st_off = n as u32;
        } else {
            let off = h.st_off as usize;
            let rest = total.saturating_sub(off);
            let n = rest.min(RESP_SLICE);
            let flags = if off + n < total { FLAG_MORE_BODY } else { 0 };
            let body = h.metrics_buf.as_ptr().add(off);
            if !emit_envelope(h, sys, h.st_conn, h.st_stream, 200, flags, &[], &[], body, n) {
                return;
            }
            h.st_off = (off + n) as u32;
        }
        if h.st_off as usize >= total {
            h.st_active = 0;
        }
    }
}

unsafe fn drain_proposal_assignments(h: &mut Http, sys: &SyscallTable) {
    if h.in_proposal_assigned < 0 {
        return;
    }
    for _ in 0..16 {
        let poll = (sys.channel_poll)(h.in_proposal_assigned, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, h.in_proposal_assigned, &mut h.msg_buf);
        if msg_type != wire::MSG_PROPOSAL_ASSIGNED
            || (plen as usize) < wire::PROPOSAL_ASSIGNED_LEN
        {
            continue;
        }
        let (correlation_id, _partition_id, index) = wire::decode_proposal_assigned(&h.msg_buf);
        let corr_pos = h
            .correlations
            .iter()
            .position(|slot| slot.correlation_id == correlation_id && correlation_id != 0);
        let idx_pos = h.indices.iter().position(|slot| slot.index == 0);
        match (corr_pos, idx_pos) {
            (Some(c), Some(i)) => {
                let corr = h.correlations[c];
                h.correlations[c] = CorrSlot::empty();
                h.indices[i] = IndexSlot {
                    index,
                    started_ms: corr.started_ms,
                    conn_id: corr.conn_id,
                    stream_id: corr.stream_id,
                };
            }
            (None, _) => {
                h.assignments_unmatched = h.assignments_unmatched.saturating_add(1);
            }
            (Some(_), None) => {
                // Keep the correlation resident so its eventual timeout is
                // explicit; the consumed assignment cannot be reconstructed.
                h.assignments_no_slot = h.assignments_no_slot.saturating_add(1);
            }
        }
    }
}

/// Pull ONE throttle rejection off the `proposal_rejected` port. The
/// dispatch table drives the ≤8/step loop and gates each pull on
/// [`response_writable`] — do not consume a rejection unless the
/// response has somewhere to go.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_rejection(h: &mut Http, sys: &SyscallTable) -> Feedback {
    if h.in_proposal_rejected < 0 {
        return Feedback::Empty;
    }
    let poll = (sys.channel_poll)(h.in_proposal_rejected, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return Feedback::Empty;
    }
    let (msg_type, plen) =
        wire_channels::channel_read_msg(sys, h.in_proposal_rejected, &mut h.msg_buf);
    if msg_type != wire::MSG_CLIENT_REJECT_INTERNAL {
        return Feedback::Handled;
    }
    let (correlation_id, _status, _retry, _entries, _bytes) =
        match wire::decode_client_reject_internal(&h.msg_buf[..plen as usize]) {
            Some(v) => v,
            None => return Feedback::Handled,
        };
    if let Some(pos) = h
        .correlations
        .iter()
        .position(|slot| slot.correlation_id == correlation_id && correlation_id != 0)
    {
        let (conn_id, stream_id) = (h.correlations[pos].conn_id, h.correlations[pos].stream_id);
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_rejections = h.proposal_rejections.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 503, b"proposal rejected");
    }
    Feedback::Handled
}

/// Pull ONE apply acknowledgement off the `applied` port. The
/// dispatch table drives the ≤16/step loop, gating each pull on
/// [`response_writable`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_applied(h: &mut Http, sys: &SyscallTable) -> Feedback {
    if h.in_applied < 0 {
        return Feedback::Empty;
    }
    let poll = (sys.channel_poll)(h.in_applied, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return Feedback::Empty;
    }
    let (msg_type, plen) = wire_channels::channel_read_msg(sys, h.in_applied, &mut h.msg_buf);
    let pl = plen as usize;
    if msg_type != wire::MSG_CLIENT_RESPONSE || pl < 18 {
        return Feedback::Handled;
    }
    // `[partition:u16][term:u64][index:u64]` — index at offset 10.
    let index_off = 10;
    let index = u64::from_le_bytes([
        h.msg_buf[index_off],
        h.msg_buf[index_off + 1],
        h.msg_buf[index_off + 2],
        h.msg_buf[index_off + 3],
        h.msg_buf[index_off + 4],
        h.msg_buf[index_off + 5],
        h.msg_buf[index_off + 6],
        h.msg_buf[index_off + 7],
    ]);
    if let Some(pos) = h.indices.iter().position(|slot| slot.index == index) {
        let (conn_id, stream_id) = (h.indices[pos].conn_id, h.indices[pos].stream_id);
        h.indices[pos] = IndexSlot::empty();
        h.committed = h.committed.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 200, b"committed");
    } else {
        h.applies_unmatched = h.applies_unmatched.saturating_add(1);
    }
    Feedback::Handled
}

/// One expiry check per step (a corr timeout, else an index timeout).
/// The dispatch table gates the call on [`response_writable`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn expire_step(h: &mut Http, sys: &SyscallTable, now: u64) {
    if let Some(pos) = h.correlations.iter().position(|slot| {
        slot.correlation_id != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let (conn_id, stream_id) = (h.correlations[pos].conn_id, h.correlations[pos].stream_id);
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_timeouts = h.proposal_timeouts.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 503, b"proposal timeout");
        return;
    }
    if let Some(pos) = h.indices.iter().position(|slot| {
        slot.index != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let (conn_id, stream_id) = (h.indices[pos].conn_id, h.indices[pos].stream_id);
        h.indices[pos] = IndexSlot::empty();
        h.commit_timeouts = h.commit_timeouts.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 503, b"commit timeout");
    }
}

unsafe fn emit_http_proposal(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u16,
    stream_id: u16,
    body: &[u8],
) -> bool {
    if h.out_proposal < 0 || body.len() > MAX_EXT_BODY {
        return false;
    }
    let slot = match h.correlations.iter().position(|slot| slot.correlation_id == 0) {
        Some(v) => v,
        None => return false,
    };
    let poll = (sys.channel_poll)(h.out_proposal, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    // Bit 63 keeps this namespace disjoint from the codec component's —
    // both feed the throttle intake.
    let correlation_id = (1u64 << 63) | h.next_correlation_id;
    h.next_correlation_id = h.next_correlation_id.wrapping_add(1).max(1);
    let mut framed = [0u8; CORR_ID_LEN + MAX_EXT_BODY];
    framed[..CORR_ID_LEN].copy_from_slice(&correlation_id.to_le_bytes());
    framed[CORR_ID_LEN..CORR_ID_LEN + body.len()].copy_from_slice(body);
    let written = wire_channels::channel_write_msg(
        sys,
        h.out_proposal,
        wire::MSG_CLIENT_PROPOSAL,
        &framed[..CORR_ID_LEN + body.len()],
    );
    if written <= 0 {
        return false;
    }
    h.correlations[slot] = CorrSlot {
        correlation_id,
        started_ms: dev_millis(sys),
        conn_id,
        stream_id,
    };
    let occupied = h.correlations.iter().filter(|v| v.correlation_id != 0).count()
        + h.indices.iter().filter(|v| v.index != 0).count();
    h.inflight_high_water = h.inflight_high_water.max(occupied.min(u8::MAX as usize) as u8);
    true
}

/// Handle one request pulled off the `request` port. Every reply
/// egresses on `response` inside this call except the admin round
/// trip: admin commands come back as [`ReqOut::Admin`] for the
/// rbac → admin route, completed by [`finish_admin`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_request(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u16,
    stream_id: u16,
    method: u8,
    path: &[u8],
    body: &[u8],
) -> ReqOut {
    // POST /propose — synchronous write bridge. The response is
    // deferred until apply acknowledges the assigned WAL index.
    if method == METHOD_POST && path == b"/propose" {
        if !emit_http_proposal(h, sys, conn_id, stream_id, body) {
            h.queue_unavailable = h.queue_unavailable.saturating_add(1);
            finish(h, sys, conn_id, stream_id, 503, b"propose queue unavailable");
        }
        h.requests_handled = h.requests_handled.saturating_add(1);
        h.worked = 1;
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        return ReqOut::Done;
    }

    // POST /admin/<op> — staged for admission through rbac like every
    // admin command; the dispatch table routes the envelope and calls
    // [`finish_admin`] with the verdict. 202 means the command reached
    // the admin component, not that the op succeeded: its real status
    // answers on the module's `responses` port, which HTTP does not
    // surface.
    if method == METHOD_POST && path.starts_with(b"/admin/") {
        let op_name = &path[b"/admin/".len()..];
        let out = match http_admin::admin_op_code(op_name) {
            Some(op_code) => {
                if !http_admin::admin_body_fits(body.len()) {
                    h.admin_dropped = h.admin_dropped.saturating_add(1);
                    finish(h, sys, conn_id, stream_id, 503, b"admin body too large");
                    ReqOut::Done
                } else {
                    // The admin envelope keeps its wire form
                    // (`[conn_id:u8][op_code][body]`); the low conn
                    // byte is a log breadcrumb there, never a reply
                    // route — HTTP replies correlate on the full
                    // `(conn_id, stream_id)` held here.
                    h.admin_env[0] = conn_id as u8;
                    h.admin_env[1] = op_code;
                    h.admin_env[2..2 + body.len()].copy_from_slice(body);
                    ReqOut::Admin { op_code, len: (2 + body.len()) as u16 }
                }
            }
            None => {
                h.requests_404 = h.requests_404.saturating_add(1);
                finish(h, sys, conn_id, stream_id, 400, b"unknown admin op");
                ReqOut::Done
            }
        };
        h.requests_handled = h.requests_handled.saturating_add(1);
        h.worked = 1;
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        return out;
    }

    if path == b"/readyz" {
        // 200 if the cached readyz byte is non-zero; 503 otherwise.
        let ready_byte = if h.readyz_len > 0 { h.readyz_buf[0] } else { 0 };
        let status = if ready_byte != 0 { 200 } else { 503 };
        finish(h, sys, conn_id, stream_id, status, &[ready_byte]);
    } else if path == b"/why" {
        let mut body = [0u8; 2];
        let n = h.why_len as usize;
        body[..n].copy_from_slice(&h.why_buf[..n]);
        finish(h, sys, conn_id, stream_id, 200, &body[..n]);
    } else if path == b"/metrics" {
        if h.st_active != 0 {
            // One export streams at a time; the slot is bounded and
            // the next scrape lands after this one drains.
            finish(h, sys, conn_id, stream_id, 503, b"metrics busy");
        } else if (h.metrics_len as usize) <= RESP_SLICE {
            let n = h.metrics_len as usize;
            let body = h.metrics_buf.as_ptr();
            emit_envelope(h, sys, conn_id, stream_id, 200, 0, CT_TEXT, &[], body, n);
        } else {
            h.st_active = 1;
            h.st_head_sent = 0;
            h.st_conn = conn_id;
            h.st_stream = stream_id;
            h.st_off = 0;
            stream_step(h, sys);
        }
    } else {
        h.requests_404 = h.requests_404.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 404, b"not found");
    }
    h.requests_handled = h.requests_handled.saturating_add(1);
    h.worked = 1;
    dev_report_step_effect(sys, step_effect::WORK_DONE);
    ReqOut::Done
}

/// Complete a `POST /admin/<op>` request after the dispatch table has
/// run the rbac → admin route: 202 when the envelope was authorized
/// and delivered, 403 otherwise.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn finish_admin(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u16,
    stream_id: u16,
    op_code: u8,
    authorized: bool,
) {
    if authorized {
        // Routing-decision signal, paired with `[admin] op=N
        // conn_id=M` on the admin side: the only external proof the
        // POST actually reached the admin path, since the 202 below
        // fires immediately and unlike the client-proposal path (see
        // `CorrSlot`) admin ops have no async reply to observe
        // instead.
        let mut log = [0u8; 48];
        let n = format_admin_route_log(&mut log, op_code, conn_id);
        dev_log(sys, 3, log.as_ptr(), n);
        finish(h, sys, conn_id, stream_id, 202, b"accepted");
    } else {
        h.admin_dropped = h.admin_dropped.saturating_add(1);
        finish(h, sys, conn_id, stream_id, 403, b"forbidden");
    }
}

/// Self-telemetry samples for the telemetry component — absolute
/// counters and current bounded-table occupancy, every 250 ms. The
/// dispatch table feeds the returned samples to
/// `telemetry::on_typed_sample`; `None` off-tick.
pub fn take_metrics(h: &mut Http, now: u64) -> Option<[(u16, u8, i64); 15]> {
    if now.wrapping_sub(h.last_metrics_ms) < METRICS_INTERVAL_MS {
        return None;
    }
    h.last_metrics_ms = now;

    let correlations = h.correlations.iter().filter(|v| v.correlation_id != 0).count() as i64;
    let indices = h.indices.iter().filter(|v| v.index != 0).count() as i64;
    let kg = wire::METRIC_KIND_GAUGE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, u8, i64); 15] = [
        (wire::metric_ids::HTTP_CORRELATIONS_INFLIGHT, kg, correlations),
        (wire::metric_ids::HTTP_INDICES_INFLIGHT, kg, indices),
        (wire::metric_ids::HTTP_INFLIGHT_HIGH_WATER, kg, i64::from(h.inflight_high_water)),
        (wire::metric_ids::HTTP_PROPOSAL_TIMEOUTS, kc, i64::from(h.proposal_timeouts)),
        (wire::metric_ids::HTTP_COMMIT_TIMEOUTS, kc, i64::from(h.commit_timeouts)),
        (wire::metric_ids::HTTP_ASSIGNMENTS_UNMATCHED, kc, i64::from(h.assignments_unmatched)),
        (wire::metric_ids::HTTP_ASSIGNMENTS_NO_SLOT, kc, i64::from(h.assignments_no_slot)),
        (wire::metric_ids::HTTP_APPLIES_UNMATCHED, kc, i64::from(h.applies_unmatched)),
        (wire::metric_ids::HTTP_REJECTIONS, kc, i64::from(h.proposal_rejections)),
        (wire::metric_ids::HTTP_QUEUE_UNAVAILABLE, kc, i64::from(h.queue_unavailable)),
        (wire::metric_ids::HTTP_COMMITTED, kc, i64::from(h.committed)),
        (wire::metric_ids::HTTP_REQUESTS, kc, i64::from(h.requests_handled)),
        (wire::metric_ids::HTTP_REQUESTS_404, kc, i64::from(h.requests_404)),
        (wire::metric_ids::HTTP_RESPONSES_DROPPED, kc, i64::from(h.responses_dropped)),
        (wire::metric_ids::HTTP_ADMIN_DROPPED, kc, i64::from(h.admin_dropped)),
    ];
    Some(samples)
}

/// `Content-Length: N\r\n` into `dst`; wave reads it as the streamed
/// body's declared total and emits the wire header itself.
fn format_content_length(dst: &mut [u8], n: usize) -> usize {
    let head = b"Content-Length: ";
    let mut pos = head.len();
    dst[..pos].copy_from_slice(head);
    pos += push_usize(&mut dst[pos..], n);
    dst[pos] = b'\r';
    dst[pos + 1] = b'\n';
    pos + 2
}

/// `[http] admin op=N conn_id=M` — see the call site's
/// comment for why this stays a log line rather than a metric.
fn format_admin_route_log(dst: &mut [u8], op_code: u8, conn_id: u16) -> usize {
    let mut pos = 0usize;
    let head = b"[http] admin op=";
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
