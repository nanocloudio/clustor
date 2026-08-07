//! http — diagnostic and write-bridge request handling.
//!
//! Serves the well-known diagnostic paths from caches refreshed by
//! the [`telemetry`](super::telemetry) component each emit tick:
//!
//!   - `GET /readyz`  → 200 if ready, 503 otherwise; body carries the
//!     latest readyz byte. (The [`ingress`](super::ingress) component
//!     short-circuits this path from its own ready state — see there.)
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
//! Requests arrive from two sources on identical terms. The
//! [`ingress`](super::ingress) component parses the module's own
//! HTTP/1.1 listener and delivers message-shaped calls; the `request`
//! port carries requests already parsed by a consumer that serves
//! HTTP over its own shared client port. Both enter [`on_request`].
//! Replies go back the way they came — the ingress response ring, or
//! the `response` port — which preserves the backpressure contract:
//! feedback drains below never consume an event they cannot answer.

use super::abi::SyscallTable;
use super::{http_admin, wire, wire_channels};
use super::{dev_log, dev_millis, dev_report_step_effect, step_effect};

/// Bound on the small cached envelopes — `/readyz` and `/why` carry a
/// single status byte, so 1 KiB is ample.
const ENVELOPE_CACHE: usize = 1024;

/// Bound on the cached `/metrics` body: the telemetry export, capped
/// at `telemetry::SAFE_EXPORT_MAX` (7400). 7600 clears the cap and
/// keeps the framed response under the ingress response ring record
/// limit.
pub const METRICS_CACHE: usize = 7600;

// Two bounded phase tables (correlation→connection and index→connection).
// Sized above ingress's 32 live connections so phase handoff and an
// operational probe cannot exhaust the mapping space during a burst.
const HTTP_INFLIGHT: usize = 64;

/// `response` frame header: `[conn_id:u8][status:u16 LE][len:u16 LE]`,
/// mirroring the ingress response ring's record header.
const RESP_BODY: usize = 5;
/// Bounds on an externally-parsed request. The path bound matches the
/// ingress parser's; the body bound matches the 1 KiB admin envelope.
const MAX_EXT_PATH: usize = 64;
const MAX_EXT_BODY: usize = 1024;
/// Largest `request` record accepted: header + path + body, plus slack
/// for the producer's framing.
const MAX_EXT_REQUEST: usize = 3 + MAX_EXT_PATH + MAX_EXT_BODY;
const HTTP_PROPOSAL_TIMEOUT_MS: u64 = 10_000;
const METRICS_INTERVAL_MS: u64 = 250;

/// One response resolved for the ingress listener's response ring.
/// The body is staged in `resp_frame[RESP_BODY..RESP_BODY+len]` —
/// the dispatch table reads it via [`staged_body`] and hands it to
/// `ingress::queue_response`. Replies to `request`-port traffic never
/// appear here: they egress on this component's own `response` port
/// inside the producing call. Consume each record before the next
/// http call — `resp_frame` is a single staging slot.
#[derive(Clone, Copy)]
pub struct Queued {
    pub conn_id: u8,
    pub status: u16,
    pub len: u16,
}

/// One pull off a proposal-feedback channel: nothing readable,
/// consumed-and-finished (ext egress / unmatched / malformed — burns
/// the loop slot), or a listener response to queue.
pub enum Feedback {
    Empty,
    Handled,
    Respond(Queued),
}

/// Terminal route for one HTTP request, resolved by [`on_request`].
pub enum ReqOut {
    /// Fully handled (proposal emitted, ext reply sent, dropped).
    Done,
    /// A listener response to queue on the ingress ring.
    Queue(Queued),
    /// A `POST /admin/<op>` envelope staged in the admin buffer
    /// ([`admin_env`]); the dispatch table routes it through
    /// rbac → admin and completes the reply via [`finish_admin`].
    Admin { op_code: u8, len: u16 },
}

/// The staged response body for a [`Queued`] record.
pub fn staged_body(h: &Http, len: u16) -> &[u8] {
    &h.resp_frame[RESP_BODY..RESP_BODY + len as usize]
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
    conn_id: u8,
}

impl CorrSlot {
    const fn empty() -> Self {
        Self { correlation_id: 0, started_ms: 0, conn_id: 0 }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct IndexSlot {
    index: u64,
    started_ms: u64,
    conn_id: u8,
}

impl IndexSlot {
    const fn empty() -> Self {
        Self { index: 0, started_ms: 0, conn_id: 0 }
    }
}

#[repr(C)]
pub struct Http {
    pub in_proposal_assigned: i32, // in: correlation_id → WAL index from Raft
    pub in_applied: i32,           // in: per-index apply acknowledgements
    pub in_proposal_rejected: i32, // in: throttle rejection by correlation id
    pub in_request: i32,           // in: MSG_HTTP_REQUEST from an external parser
    pub out_proposal: i32,         // out: tagged proposal → gateway.proposals
    pub out_response: i32,         // out: MSG_HTTP_RESPONSE for `in_request` traffic

    /// Which source a live request's `conn_id` came from, one bit per
    /// `conn_id` value — the whole `u8` namespace in 32 bytes.
    ///
    /// A response must go back the way its request came: the ingress
    /// listener's response ring, or the `response` port for requests
    /// that arrived on `request`. A flag bit inside the conn_id would
    /// corrupt the id the external producer expects echoed, and a slot
    /// table would need eviction policy for the deferred `/propose`
    /// path, whose reply can be seconds late. A dense bitmap is O(1),
    /// exactly covers the id space, and can never overflow. The bit is
    /// set when a request arrives on `request` and cleared when its
    /// response is emitted.
    ///
    /// Consequence, and the reason this is documented here: the two
    /// sources share one `conn_id` namespace. A graph that wires both
    /// `net_in` and `request` with overlapping ids gets last-request-
    /// wins for a colliding id. Wire one or the other.
    ext_conns: [u32; 8],

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

    /// Staging for one `response` record. State-resident: the largest
    /// body is the `/metrics` export, far too big for a stack frame
    /// on the module's step path.
    resp_frame: [u8; RESP_BODY + METRICS_CACHE],

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
    /// Count of `POST /admin/<op>` requests refused before admission —
    /// rbac denial or a body exceeding the 1 KiB envelope buffer. The
    /// HTTP client sees 403/503 for each one. Surfaced through the
    /// telemetry component so sustained refusal is operationally
    /// visible.
    admin_dropped: u32,
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
    h.ext_conns = [0u32; 8];
    h.next_correlation_id = 1;
    h.correlations = [CorrSlot::empty(); HTTP_INFLIGHT];
    h.indices = [IndexSlot::empty(); HTTP_INFLIGHT];
    h.readyz_len = 0;
    h.why_len = 0;
    h.metrics_len = 0;
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
    h.last_metrics_ms = 0;
    h.admin_dropped = 0;
    h.admin_env = [0u8; 1024];
}

fn mark_ext(h: &mut Http, conn_id: u8) {
    h.ext_conns[(conn_id >> 5) as usize] |= 1u32 << (conn_id & 31);
}

/// Consume the source flag for `conn_id`. `true` means the request
/// arrived on the `request` port and its reply belongs on `response`.
fn take_ext(h: &mut Http, conn_id: u8) -> bool {
    let word = (conn_id >> 5) as usize;
    let bit = 1u32 << (conn_id & 31);
    let set = (h.ext_conns[word] & bit) != 0;
    h.ext_conns[word] &= !bit;
    set
}

/// Emit the response staged at `resp_frame[RESP_BODY..RESP_BODY+len]`
/// as one `MSG_HTTP_RESPONSE`
/// `[conn_id][status:u16][body_len:u16][body]` on the `response` port.
/// Best-effort and all-or-nothing: an unwired or full port drops the
/// reply, matching the ingress ring's contract.
unsafe fn emit_staged(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u8,
    status: u16,
    len: usize,
) -> bool {
    if h.out_response < 0 {
        return false;
    }
    let poll_out = (sys.channel_poll)(h.out_response, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
        return false;
    }
    h.resp_frame[0] = conn_id;
    h.resp_frame[1..3].copy_from_slice(&status.to_le_bytes());
    h.resp_frame[3..5].copy_from_slice(&(len as u16).to_le_bytes());
    wire_channels::channel_write_msg(
        sys,
        h.out_response,
        wire::MSG_HTTP_RESPONSE,
        &h.resp_frame[..RESP_BODY + len],
    );
    true
}

/// Answer one request on whichever source it arrived from. `body`
/// must not borrow from `h` (diagnostic payloads stage themselves
/// into `resp_frame` at their call site instead). Ext-sourced
/// replies egress here on the component's own `response` port and
/// return `None`; listener replies are staged and returned as a
/// [`Queued`] record for the dispatch table to hand to the ingress
/// response ring.
unsafe fn finish(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u8,
    status: u16,
    body: &[u8],
) -> Option<Queued> {
    let n = body.len().min(METRICS_CACHE);
    h.resp_frame[RESP_BODY..RESP_BODY + n].copy_from_slice(&body[..n]);
    if take_ext(h, conn_id) {
        emit_staged(h, sys, conn_id, status, n);
        None
    } else {
        Some(Queued { conn_id, status, len: n as u16 })
    }
}

/// One externally-parsed request pulled off the `request` port,
/// handed to the dispatch table for [`on_request`] routing.
#[repr(C)]
pub struct ExtReq {
    pub conn_id: u8,
    pub method: u8,
    pub path_len: u8,
    pub body_len: u16,
    pub path: [u8; MAX_EXT_PATH],
    pub body: [u8; MAX_EXT_BODY],
}

impl ExtReq {
    pub const fn new() -> Self {
        Self { conn_id: 0, method: 0, path_len: 0, body_len: 0, path: [0; MAX_EXT_PATH], body: [0; MAX_EXT_BODY] }
    }
}

/// One pull off the `request` port.
pub enum ExtPulled {
    Empty,
    Skipped,
    Request,
}

/// Read ONE frame off the module's `request` port — `MSG_HTTP_REQUEST`
/// `[conn_id][method][path_len][path][body]` parsed by a consumer that
/// serves HTTP over its own shared client port. Frames enter the same
/// [`on_request`] handling the dedicated listener uses (the dispatch
/// table drives the ≤8/step loop, matching the ingress event loop's
/// per-request budget); the source is recorded so the reply egresses
/// on `response`. `Skipped` marks a consumed malformed frame so the
/// loop bound counts it.
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
    let mut buf = [0u8; MAX_EXT_REQUEST];
    let (msg_type, plen) = wire_channels::channel_read_msg(sys, h.in_request, &mut buf);
    if msg_type != wire::MSG_HTTP_REQUEST {
        return ExtPulled::Skipped;
    }
    let pl = plen as usize;
    if pl < 3 {
        return ExtPulled::Skipped; // conn_id + method + path_len
    }
    let conn_id = buf[0];
    let method_byte = buf[1];
    let path_len = (buf[2] as usize).min(MAX_EXT_PATH);
    if 3 + path_len > pl {
        return ExtPulled::Skipped; // truncated path — a producer framing error
    }
    let body_off = 3 + path_len;
    let body_len = (pl - body_off).min(MAX_EXT_BODY);
    mark_ext(h, conn_id);
    req.conn_id = conn_id;
    req.method = method_byte;
    req.path_len = path_len as u8;
    req.body_len = body_len as u16;
    req.path[..path_len].copy_from_slice(&buf[3..3 + path_len]);
    req.body[..body_len].copy_from_slice(&buf[body_off..body_off + body_len]);
    ExtPulled::Request
}

/// Refresh the diagnostic caches from the telemetry component's
/// snapshot values. Called by the dispatch table on exactly the steps
/// telemetry emitted, so cache freshness matches the export cadence —
/// the http component never sees the telemetry struct itself.
pub fn cache_export(h: &mut Http, ready: bool, timing_pause: u8, export: &[u8]) {
    h.readyz_buf[0] = ready as u8;
    h.readyz_len = 1;
    // `/why` payload: [version:1][timing_pause_reason] — mirrors the
    // MSG_WHY wire form (see telemetry.rs).
    h.why_buf[0] = 1;
    h.why_buf[1] = timing_pause;
    h.why_len = 2;
    let len = export.len().min(METRICS_CACHE);
    if len > 0 {
        h.metrics_buf[..len].copy_from_slice(&export[..len]);
        h.metrics_len = len as u16;
    }
}

/// Own-state drains only: ≤16 proposal assignments. The response-
/// producing feedback loops (≤8 rejections, ≤16 applies, one expiry)
/// are driven by the dispatch table through [`next_rejection`] /
/// [`next_applied`] / [`expire_step`], each pull gated there on
/// `ingress::response_writable` exactly as the old in-component loops
/// were — feedback is never consumed without somewhere to answer.
/// The 250 ms self-metrics tick rides [`take_metrics`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(h: &mut Http, sys: &SyscallTable) {
    drain_proposal_assignments(h, sys);
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
/// `ingress::response_writable` — do not consume a rejection unless
/// the response has somewhere to go.
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
        let conn_id = h.correlations[pos].conn_id;
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_rejections = h.proposal_rejections.saturating_add(1);
        return match finish(h, sys, conn_id, 503, b"proposal rejected") {
            Some(q) => Feedback::Respond(q),
            None => Feedback::Handled,
        };
    }
    Feedback::Handled
}

/// Pull ONE apply acknowledgement off the `applied` port. The
/// dispatch table drives the ≤16/step loop, gating each pull on
/// `ingress::response_writable`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_applied(h: &mut Http, sys: &SyscallTable) -> Feedback {
    if h.in_applied < 0 {
        return Feedback::Empty;
    }
    {
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
            h.msg_buf[index_off], h.msg_buf[index_off + 1],
            h.msg_buf[index_off + 2], h.msg_buf[index_off + 3],
            h.msg_buf[index_off + 4], h.msg_buf[index_off + 5],
            h.msg_buf[index_off + 6], h.msg_buf[index_off + 7],
        ]);
        if let Some(pos) = h.indices.iter().position(|slot| slot.index == index) {
            let conn_id = h.indices[pos].conn_id;
            h.indices[pos] = IndexSlot::empty();
            h.committed = h.committed.saturating_add(1);
            match finish(h, sys, conn_id, 200, b"committed") {
                Some(q) => Feedback::Respond(q),
                None => Feedback::Handled,
            }
        } else {
            h.applies_unmatched = h.applies_unmatched.saturating_add(1);
            Feedback::Handled
        }
    }
}

/// One expiry check per step (a corr timeout, else an index timeout —
/// the old scan's exact behaviour). The dispatch table gates the call
/// on `ingress::response_writable`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn expire_step(h: &mut Http, sys: &SyscallTable, now: u64) -> Feedback {
    if let Some(pos) = h.correlations.iter().position(|slot| {
        slot.correlation_id != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let conn_id = h.correlations[pos].conn_id;
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_timeouts = h.proposal_timeouts.saturating_add(1);
        return match finish(h, sys, conn_id, 503, b"proposal timeout") {
            Some(q) => Feedback::Respond(q),
            None => Feedback::Handled,
        };
    }
    if let Some(pos) = h
        .indices
        .iter()
        .position(|slot| slot.index != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS)
    {
        let conn_id = h.indices[pos].conn_id;
        h.indices[pos] = IndexSlot::empty();
        h.commit_timeouts = h.commit_timeouts.saturating_add(1);
        return match finish(h, sys, conn_id, 503, b"commit timeout") {
            Some(q) => Feedback::Respond(q),
            None => Feedback::Handled,
        };
    }
    Feedback::Empty
}

unsafe fn emit_http_proposal(h: &mut Http, sys: &SyscallTable, conn_id: u8, body: &[u8]) -> bool {
    if h.out_proposal < 0 || body.len() > 1024 {
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
    let mut framed = [0u8; 1032];
    framed[..8].copy_from_slice(&correlation_id.to_le_bytes());
    framed[8..8 + body.len()].copy_from_slice(body);
    let written = wire_channels::channel_write_msg(
        sys,
        h.out_proposal,
        wire::MSG_CLIENT_PROPOSAL,
        &framed[..8 + body.len()],
    );
    if written <= 0 {
        return false;
    }
    h.correlations[slot] = CorrSlot {
        correlation_id,
        started_ms: dev_millis(sys),
        conn_id,
    };
    let occupied = h.correlations.iter().filter(|v| v.correlation_id != 0).count()
        + h.indices.iter().filter(|v| v.index != 0).count();
    h.inflight_high_water = h.inflight_high_water.max(occupied.min(u8::MAX as usize) as u8);
    true
}

/// Handle one parsed HTTP request, delivered by the dispatch table
/// (from the ingress listener or the `request` port). `method_byte`
/// is the first byte of the verb (G/P/…); `path`/`body` are the
/// parsed request parts. Listener responses come back as
/// [`ReqOut::Queue`] for the dispatch table to hand to the ingress
/// response ring; admin commands come back as [`ReqOut::Admin`] for
/// the rbac → admin route, completed by [`finish_admin`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_request(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u8,
    method_byte: u8,
    path: &[u8],
    body: &[u8],
) -> ReqOut {
    // POST /propose — synchronous write bridge. The response is
    // deferred until apply acknowledges the assigned WAL index.
    if method_byte == b'P' && path == b"/propose" {
        let mut out = ReqOut::Done;
        if !emit_http_proposal(h, sys, conn_id, body) {
            h.queue_unavailable = h.queue_unavailable.saturating_add(1);
            if let Some(q) = finish(h, sys, conn_id, 503, b"propose queue unavailable") {
                out = ReqOut::Queue(q);
            }
        }
        h.requests_handled = h.requests_handled.saturating_add(1);
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        return out;
    }

    // POST /admin/<op> — staged for admission through rbac like every
    // admin command; the dispatch table routes the envelope and calls
    // [`finish_admin`] with the verdict. 202 means the command reached
    // the admin component; its real status still answers on the
    // module's `responses` port (returning it over HTTP is a
    // follow-up slice).
    if method_byte == b'P' && path.starts_with(b"/admin/") {
        let op_name = &path[b"/admin/".len()..];
        let out = match http_admin::admin_op_code(op_name) {
            Some(op_code) => {
                if !http_admin::admin_body_fits(body.len()) {
                    h.admin_dropped = h.admin_dropped.saturating_add(1);
                    match finish(h, sys, conn_id, 503, b"admin body too large") {
                        Some(q) => ReqOut::Queue(q),
                        None => ReqOut::Done,
                    }
                } else {
                    h.admin_env[0] = conn_id;
                    h.admin_env[1] = op_code;
                    h.admin_env[2..2 + body.len()].copy_from_slice(body);
                    ReqOut::Admin { op_code, len: (2 + body.len()) as u16 }
                }
            }
            None => {
                h.requests_404 = h.requests_404.saturating_add(1);
                match finish(h, sys, conn_id, 400, b"unknown admin op") {
                    Some(q) => ReqOut::Queue(q),
                    None => ReqOut::Done,
                }
            }
        };
        h.requests_handled = h.requests_handled.saturating_add(1);
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        return out;
    }

    // Diagnostic payloads live in `h`'s caches, so they are staged
    // into `resp_frame` (a disjoint field) rather than handed to
    // `respond`, which cannot take a body borrowed from `h`.
    let (status, len): (u16, usize) = if path == b"/readyz" {
        // 200 if the cached readyz byte is non-zero; 503 otherwise.
        let ready_byte = if h.readyz_len > 0 { h.readyz_buf[0] } else { 0 };
        let st = if ready_byte != 0 { 200 } else { 503 };
        let n = h.readyz_len as usize;
        h.resp_frame[RESP_BODY..RESP_BODY + n].copy_from_slice(&h.readyz_buf[..n]);
        (st, n)
    } else if path == b"/why" {
        let n = h.why_len as usize;
        h.resp_frame[RESP_BODY..RESP_BODY + n].copy_from_slice(&h.why_buf[..n]);
        (200, n)
    } else if path == b"/metrics" {
        let n = h.metrics_len as usize;
        h.resp_frame[RESP_BODY..RESP_BODY + n].copy_from_slice(&h.metrics_buf[..n]);
        (200, n)
    } else {
        h.requests_404 = h.requests_404.saturating_add(1);
        let nf: &[u8] = b"not found";
        h.resp_frame[RESP_BODY..RESP_BODY + nf.len()].copy_from_slice(nf);
        (404, nf.len())
    };
    let out = if take_ext(h, conn_id) {
        emit_staged(h, sys, conn_id, status, len);
        ReqOut::Done
    } else {
        ReqOut::Queue(Queued { conn_id, status, len: len as u16 })
    };
    h.requests_handled = h.requests_handled.saturating_add(1);
    dev_report_step_effect(sys, step_effect::WORK_DONE);
    out
}

/// Complete a `POST /admin/<op>` request after the dispatch table has
/// run the rbac → admin route: 202 when the envelope was authorized
/// and delivered, 403 otherwise. Returns the listener response to
/// queue, or `None` for `request`-port traffic (sent here).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn finish_admin(
    h: &mut Http,
    sys: &SyscallTable,
    conn_id: u8,
    op_code: u8,
    authorized: bool,
) -> Option<Queued> {
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
        finish(h, sys, conn_id, 202, b"accepted")
    } else {
        h.admin_dropped = h.admin_dropped.saturating_add(1);
        finish(h, sys, conn_id, 403, b"forbidden")
    }
}

/// Self-telemetry samples for the telemetry component — absolute
/// counters and current bounded-table occupancy, every 250 ms. The
/// dispatch table feeds the returned samples to
/// `telemetry::on_typed_sample`; `None` off-tick.
pub fn take_metrics(h: &mut Http, now: u64) -> Option<[(u16, u8, i64); 13]> {
    if now.wrapping_sub(h.last_metrics_ms) < METRICS_INTERVAL_MS {
        return None;
    }
    h.last_metrics_ms = now;

    let correlations = h.correlations.iter().filter(|v| v.correlation_id != 0).count() as i64;
    let indices = h.indices.iter().filter(|v| v.index != 0).count() as i64;
    let kg = wire::METRIC_KIND_GAUGE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, u8, i64); 13] = [
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
    ];
    Some(samples)
}

/// `[http] admin op=N conn_id=M` — see the call site's
/// comment for why this stays a log line rather than a metric.
fn format_admin_route_log(dst: &mut [u8], op_code: u8, conn_id: u8) -> usize {
    let mut pos = 0usize;
    let head = b"[http] admin op=";
    let n = head.len().min(dst.len() - pos);
    dst[pos..pos + n].copy_from_slice(&head[..n]);
    pos += n;
    pos += super::admin::push_usize(&mut dst[pos..], op_code as usize);
    let mid = b" conn_id=";
    let n = mid.len().min(dst.len() - pos);
    dst[pos..pos + n].copy_from_slice(&mid[..n]);
    pos += n;
    pos += super::admin::push_usize(&mut dst[pos..], conn_id as usize);
    pos
}
