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
use super::{admin, http_admin, ingress, rbac, telemetry, wire, wire_channels};
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

/// Answer one request on whichever source it arrived from. `body` must
/// not borrow from `h`; diagnostic payloads that do are staged into
/// `resp_frame` at their call site instead.
unsafe fn respond(
    h: &mut Http,
    ing: &mut ingress::Ingress,
    sys: &SyscallTable,
    conn_id: u8,
    status: u16,
    body: &[u8],
) -> bool {
    if take_ext(h, conn_id) {
        let n = body.len().min(METRICS_CACHE);
        h.resp_frame[RESP_BODY..RESP_BODY + n].copy_from_slice(&body[..n]);
        emit_staged(h, sys, conn_id, status, n)
    } else {
        ingress::queue_response(ing, sys, conn_id, status, body)
    }
}

/// Drain the module's `request` port — `MSG_HTTP_REQUEST`
/// `[conn_id][method][path_len][path][body]` parsed by a consumer that
/// serves HTTP over its own shared client port. Frames enter the same
/// [`on_request`] handling the dedicated listener uses; the source is
/// recorded so the reply egresses on `response`.
///
/// Per-step bound: ≤8 requests, matching the ingress event loop's
/// per-request budget.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn drain_external_requests(
    h: &mut Http,
    ing: &mut ingress::Ingress,
    rb: &mut rbac::Rbac,
    ad: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
) {
    if h.in_request < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(h.in_request, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let mut buf = [0u8; MAX_EXT_REQUEST];
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, h.in_request, &mut buf);
        if msg_type != wire::MSG_HTTP_REQUEST {
            continue;
        }
        let pl = plen as usize;
        if pl < 3 {
            continue; // conn_id + method + path_len
        }
        let conn_id = buf[0];
        let method_byte = buf[1];
        let path_len = (buf[2] as usize).min(MAX_EXT_PATH);
        if 3 + path_len > pl {
            continue; // truncated path — a producer framing error
        }
        let body_off = 3 + path_len;
        let body_len = (pl - body_off).min(MAX_EXT_BODY);
        mark_ext(h, conn_id);
        // `buf` is a local, so the borrows below are independent of
        // `h` and can be handed straight to the shared handler.
        let (head, tail) = buf.split_at(body_off);
        on_request(
            h,
            ing,
            rb,
            ad,
            tele,
            sys,
            now,
            conn_id,
            method_byte,
            &head[3..3 + path_len],
            &tail[..body_len],
        );
    }
}

/// Refresh the diagnostic caches from the telemetry component. Called
/// by the dispatch table on exactly the steps telemetry emitted, so
/// cache freshness matches the export cadence.
pub fn cache_from(h: &mut Http, t: &telemetry::Telemetry) {
    h.readyz_buf[0] = t.ready as u8;
    h.readyz_len = 1;
    h.why_buf[0] = 0;
    h.why_len = 1;
    let len = (t.export_len as usize).min(METRICS_CACHE);
    if len > 0 {
        h.metrics_buf[..len].copy_from_slice(&t.export_buf[..len]);
        h.metrics_len = len as u16;
    }
}

/// Per-step bound: 16 assignments + 8 rejections + 16 applies + one
/// expiry scan over two 64-slot tables, plus the 250 ms self-metrics
/// tick. Responses go through the ingress ring; every drain below is
/// gated on ring space exactly as it was gated on the response
/// channel, so feedback is never consumed without somewhere to
/// answer.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(
    h: &mut Http,
    ing: &mut ingress::Ingress,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
) {
    drain_proposal_assignments(h, sys);
    drain_proposal_rejections(h, ing, sys);
    drain_applied(h, ing, sys);
    expire_proposals(h, ing, sys, now);
    emit_metrics(h, tele, now);
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

unsafe fn drain_proposal_rejections(h: &mut Http, ing: &mut ingress::Ingress, sys: &SyscallTable) {
    if h.in_proposal_rejected < 0 {
        return;
    }
    for _ in 0..8 {
        // Do not consume a rejection unless the response has somewhere
        // to go.
        if !ingress::response_writable(ing) {
            break;
        }
        let poll = (sys.channel_poll)(h.in_proposal_rejected, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, h.in_proposal_rejected, &mut h.msg_buf);
        if msg_type != wire::MSG_CLIENT_REJECT_INTERNAL {
            continue;
        }
        let (correlation_id, _status, _retry, _entries, _bytes) =
            match wire::decode_client_reject_internal(&h.msg_buf[..plen as usize]) {
                Some(v) => v,
                None => continue,
            };
        if let Some(pos) = h
            .correlations
            .iter()
            .position(|slot| slot.correlation_id == correlation_id && correlation_id != 0)
        {
            let conn_id = h.correlations[pos].conn_id;
            h.correlations[pos] = CorrSlot::empty();
            h.proposal_rejections = h.proposal_rejections.saturating_add(1);
            respond(h, ing, sys, conn_id, 503, b"proposal rejected");
        }
    }
}

unsafe fn drain_applied(h: &mut Http, ing: &mut ingress::Ingress, sys: &SyscallTable) {
    if h.in_applied < 0 {
        return;
    }
    for _ in 0..16 {
        if !ingress::response_writable(ing) {
            break;
        }
        let poll = (sys.channel_poll)(h.in_applied, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, h.in_applied, &mut h.msg_buf);
        let pl = plen as usize;
        if msg_type != wire::MSG_CLIENT_RESPONSE || pl < 18 {
            continue;
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
            respond(h, ing, sys, conn_id, 200, b"committed");
        } else {
            h.applies_unmatched = h.applies_unmatched.saturating_add(1);
        }
    }
}

unsafe fn expire_proposals(h: &mut Http, ing: &mut ingress::Ingress, sys: &SyscallTable, now: u64) {
    if !ingress::response_writable(ing) {
        return;
    }
    if let Some(pos) = h.correlations.iter().position(|slot| {
        slot.correlation_id != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let conn_id = h.correlations[pos].conn_id;
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_timeouts = h.proposal_timeouts.saturating_add(1);
        respond(h, ing, sys, conn_id, 503, b"proposal timeout");
        return;
    }
    if let Some(pos) = h
        .indices
        .iter()
        .position(|slot| slot.index != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS)
    {
        let conn_id = h.indices[pos].conn_id;
        h.indices[pos] = IndexSlot::empty();
        h.commit_timeouts = h.commit_timeouts.saturating_add(1);
        respond(h, ing, sys, conn_id, 503, b"commit timeout");
    }
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

/// Handle one parsed HTTP request, delivered by the ingress
/// component. `method_byte` is the first byte of the verb (G/P/…);
/// `path`/`body` are the parsed request parts. Responses are queued
/// on the ingress response ring.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_request(
    h: &mut Http,
    ing: &mut ingress::Ingress,
    rb: &mut rbac::Rbac,
    ad: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
    conn_id: u8,
    method_byte: u8,
    path: &[u8],
    body: &[u8],
) {
    // POST /propose — synchronous write bridge. The response is
    // deferred until apply acknowledges the assigned WAL index.
    if method_byte == b'P' && path == b"/propose" {
        if !emit_http_proposal(h, sys, conn_id, body) {
            h.queue_unavailable = h.queue_unavailable.saturating_add(1);
            respond(h, ing, sys, conn_id, 503, b"propose queue unavailable");
        }
        h.requests_handled = h.requests_handled.saturating_add(1);
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        return;
    }

    // POST /admin/<op> — admitted through rbac like every admin
    // command. 202 means the command reached the admin component;
    // its real status still answers on the module's `responses`
    // port (returning it over HTTP is a follow-up slice).
    if method_byte == b'P' && path.starts_with(b"/admin/") {
        let op_name = &path[b"/admin/".len()..];
        match http_admin::admin_op_code(op_name) {
            Some(op_code) => {
                if !http_admin::admin_body_fits(body.len()) {
                    h.admin_dropped = h.admin_dropped.saturating_add(1);
                    respond(h, ing, sys, conn_id, 503, b"admin body too large");
                } else {
                    let mut env = [0u8; 1024];
                    env[0] = conn_id;
                    env[1] = op_code;
                    env[2..2 + body.len()].copy_from_slice(body);
                    let authorized = rbac::evaluate(
                        rb,
                        ad,
                        tele,
                        sys,
                        now,
                        rbac::Origin::Http,
                        &env[..2 + body.len()],
                    );
                    if authorized {
                        // Routing-decision signal, paired with
                        // `[admin] op=N conn_id=M` on the admin side:
                        // the only external proof the POST actually
                        // reached the admin path, since the 202 below
                        // fires immediately and unlike the
                        // client-proposal path (see `CorrSlot`) admin
                        // ops have no async reply to observe instead.
                        let mut log = [0u8; 48];
                        let n = format_admin_route_log(&mut log, op_code, conn_id);
                        dev_log(sys, 3, log.as_ptr(), n);
                        respond(h, ing, sys, conn_id, 202, b"accepted");
                    } else {
                        h.admin_dropped = h.admin_dropped.saturating_add(1);
                        respond(h, ing, sys, conn_id, 403, b"forbidden");
                    }
                }
            }
            None => {
                h.requests_404 = h.requests_404.saturating_add(1);
                respond(h, ing, sys, conn_id, 400, b"unknown admin op");
            }
        }
        h.requests_handled = h.requests_handled.saturating_add(1);
        dev_report_step_effect(sys, step_effect::WORK_DONE);
        return;
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
    if take_ext(h, conn_id) {
        emit_staged(h, sys, conn_id, status, len);
    } else {
        ingress::queue_response(ing, sys, conn_id, status, &h.resp_frame[RESP_BODY..RESP_BODY + len]);
    }
    h.requests_handled = h.requests_handled.saturating_add(1);
    dev_report_step_effect(sys, step_effect::WORK_DONE);
}

/// Deliver self-telemetry to the telemetry component. Absolute
/// counters and current bounded-table occupancy, every 250 ms.
fn emit_metrics(h: &mut Http, tele: &mut telemetry::Telemetry, now: u64) {
    if now.wrapping_sub(h.last_metrics_ms) < METRICS_INTERVAL_MS {
        return;
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
    for &(metric_id, kind, value) in samples.iter() {
        telemetry::on_typed_sample(
            tele,
            wire::SOURCE_ID_HTTP,
            0,
            metric_id,
            kind,
            value,
            now,
        );
    }
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
