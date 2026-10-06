//! http — diagnostic and write-bridge request handling.
//!
//! Serves the well-known diagnostic paths from caches refreshed by
//! the [`telemetry`](super::telemetry) component each emit tick:
//!
//!   - `GET /readyz`  → 200 if ready, 503 otherwise; body carries the
//!     latest readyz byte.
//!   - `GET /why`     → 200 with the latest why body.
//!   - `GET /metrics` → 200 with the latest export payload, served
//!     verbatim.
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
//! HTTP mechanics. It is a provider under the SDK exchange contract
//! (`abi::contracts::exchange`): wave's `http` server, wired in front
//! of it, terminates the wire and writes request records on
//! `request_in`; this component answers on `response_out`. Both are
//! framed edges, so one channel record is one whole exchange record.
//!
//! An answer is correlated by the exchange id, which the server
//! chooses and this component echoes verbatim, so a deferred
//! `/propose` answer can never land on a client that merely inherited
//! a recycled connection. Every record this component writes is placed
//! through an [`ExchangeOutbox`]: a record the port has no room for is
//! held and placed on a later step, never dropped, and the dispatch
//! table gates every pull — requests and proposal feedback alike — on
//! [`ready_to_answer`], so nothing is consumed while an earlier record
//! is still owed.
//!
//! Every answer is ONE record: a response HEAD with its body inline
//! and no MORE. The largest is a `/metrics` export, capped by
//! `telemetry::SAFE_EXPORT_MAX` inside what one record carries (a
//! compile-time assertion below holds the two together), so nothing
//! here streams and nothing spends response credit — a HEAD's inline
//! body is not credit-counted. The server derives `Content-Length`
//! from the record. Every answer's content type is `text/plain`.
//!
//! Requests are collected whole by the contract's `Collector`, sized
//! to what this surface serves: up to [`REQ_SLOTS`] exchanges at once,
//! a target of [`MAX_EXT_TARGET`] bytes, a header block of
//! [`MAX_EXT_HEADERS`] and a body of [`MAX_EXT_BODY`]. A body the
//! server has whole rides inline in the HEAD; one announced with MORE
//! is granted the rest of the body bound at once, and the request is
//! handled when its last BODY record lands. Statuses this surface
//! answers on its own account:
//!
//! | Status | When |
//! |--------|------|
//! | 400 | an unknown `/admin/<op>`, or a record out of order for its exchange |
//! | 403 | rbac refused an `/admin/<op>` command |
//! | 404 | no route for the method and target |
//! | 408 | a request body announced with MORE did not finish within [`REQ_BODY_TIMEOUT_MS`] |
//! | 413 | target, headers or body past the bounds above |
//! | 503 | every request slot busy, the propose queue unavailable, a proposal rejected or timed out |
//!
//! A requester ABORT ends its exchange here too: a request being
//! collected is freed, and a deferred `/propose` answer is never
//! written. The header block and the mutual-TLS peer fingerprint are
//! collected and read past — a request here means its verb, target and
//! body.

use super::abi::contracts::exchange::{
    abort, parse_request, response_body_at, seal_response, status, write_abort, write_credit,
    Collector, ExchangeId, Record, Refuse, METHOD_POST, RECORD_MAX,
};
use super::abi::SyscallTable;
use super::ExchangeOutbox;
use super::{dev_log, dev_millis, dev_report_step_effect, step_effect};
use super::{http_admin, telemetry, wire, wire_channels};

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

// Two bounded phase tables (correlation→exchange and index→exchange).
// Sized above wave's default working set so phase handoff and an
// operational probe cannot exhaust the mapping space during a burst.
const HTTP_INFLIGHT: usize = 64;

/// Content type stamped on every answer this component produces.
const CT_TEXT: &[u8] = b"text/plain";

/// Largest answer body one record carries: the record bound less the
/// response HEAD in front of the body.
const RESP_BODY_MAX: usize = RECORD_MAX - response_body_at(CT_TEXT.len());

// The whole `/metrics` cache answers in one record.
const _: () = assert!(METRICS_CACHE <= RESP_BODY_MAX);

/// Exchanges collected at once.
pub const REQ_SLOTS: usize = 4;
/// Largest request target (path and query) this surface takes. Every
/// route is far shorter; the bound is room for a client's query.
pub const MAX_EXT_TARGET: usize = 256;
/// Largest forwarded header block this surface takes. Collected and
/// read past, so it bounds what a client may send rather than what
/// any route reads.
pub const MAX_EXT_HEADERS: usize = 2048;
/// Largest request body: the 1 KiB admin envelope bound, which is also
/// the `/propose` body bound.
pub const MAX_EXT_BODY: usize = 1024;

/// The request collector this surface answers from.
type Requests = Collector<REQ_SLOTS, MAX_EXT_TARGET, MAX_EXT_HEADERS, MAX_EXT_BODY>;

/// How long a request body announced with MORE may stay unfinished.
/// The server aborts a stalled exchange on its own deadline; this
/// frees the slot, and answers, if that abort never arrives.
pub const REQ_BODY_TIMEOUT_MS: u64 = 10_000;

/// Correlation-id prefix on a `/propose` frame handed to the gateway.
const CORR_ID_LEN: usize = 8;

const HTTP_PROPOSAL_TIMEOUT_MS: u64 = 10_000;
const METRICS_INTERVAL_MS: u64 = 250;

/// Terminal route for one HTTP request, resolved by [`on_request`].
/// Every answer egresses on `response_out` inside the producing call;
/// only the admin admission round trip leaves the component.
pub enum ReqOut {
    /// Fully handled (proposal emitted, answer sent).
    Done,
    /// A `POST /admin/<op>` envelope staged in the admin buffer
    /// ([`admin_env`]); the dispatch table routes it through
    /// rbac → admin and completes the answer via [`finish_admin`].
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

/// The exchange a deferred answer is owed to. [`ExchangeId::NONE`] is
/// both an unused slot and one whose requester aborted: the all-zero id
/// names no exchange.
#[derive(Clone, Copy)]
#[repr(C)]
struct CorrSlot {
    correlation_id: u64,
    started_ms: u64,
    id: ExchangeId,
}

impl CorrSlot {
    const fn empty() -> Self {
        Self {
            correlation_id: 0,
            started_ms: 0,
            id: ExchangeId::NONE,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct IndexSlot {
    index: u64,
    started_ms: u64,
    id: ExchangeId,
}

impl IndexSlot {
    const fn empty() -> Self {
        Self {
            index: 0,
            started_ms: 0,
            id: ExchangeId::NONE,
        }
    }
}

/// An exchange whose request body was granted and has not finished
/// arriving: when the grant went out, so a body that never comes is
/// answered rather than held.
#[derive(Clone, Copy)]
#[repr(C)]
struct AwaitBody {
    id: ExchangeId,
    started_ms: u64,
}

impl AwaitBody {
    const fn empty() -> Self {
        Self {
            id: ExchangeId::NONE,
            started_ms: 0,
        }
    }
}

#[repr(C)]
pub struct Http {
    pub in_proposal_assigned: i32, // in: correlation_id → WAL index from Raft
    pub in_applied: i32,           // in: per-index apply acknowledgements
    pub in_proposal_rejected: i32, // in: throttle rejection by correlation id
    pub in_request: i32,           // in: exchange request records (`request_in`)
    pub out_proposal: i32,         // out: tagged proposal → gateway.proposals
    pub out_response: i32,         // out: exchange response records (`response_out`)

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

    /// Requests being collected, and the ones among them whose body is
    /// still arriving.
    requests: Requests,
    awaiting: [AwaitBody; REQ_SLOTS],

    /// Staging for one inbound record and one outbound record.
    /// State-resident: both exceed what the module's step path should
    /// put on the stack. `resp_frame` holds whatever `outbox` owes.
    req_frame: [u8; RECORD_MAX],
    resp_frame: [u8; RECORD_MAX],
    outbox: ExchangeOutbox,

    /// Sequence stamped as the breadcrumb on HTTP-origin admin
    /// envelopes (`[conn_id:u16 LE]`); the exchange id is opaque.
    admin_seq: u16,

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
    /// Answers that could not be composed or found the outbox already
    /// owing a record. Every pull is gated on [`ready_to_answer`] and
    /// every body is bounded inside one record, so this stays at zero;
    /// a rising count is a bug in this component.
    responses_dropped: u32,
    last_metrics_ms: u64,
    /// Count of `POST /admin/<op>` requests refused before admission —
    /// rbac denial or a body exceeding the 1 KiB envelope buffer. The
    /// HTTP client sees 403/503 for each one. Surfaced through the
    /// telemetry component so sustained refusal is operationally
    /// visible.
    admin_dropped: u32,
    /// Requests refused by the collector (busy, too large) or timed
    /// out awaiting their body.
    bodies_refused: u32,
    /// Records naming an exchange this component is not holding.
    records_unmatched: u32,
    /// Set when a step advanced a request or answer; consumed by the
    /// dispatch table's burst classification.
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
    h.requests = Requests::new();
    h.awaiting = [AwaitBody::empty(); REQ_SLOTS];
    h.outbox = ExchangeOutbox::new();
    h.admin_seq = 0;
    h.bodies_refused = 0;
    h.records_unmatched = 0;
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

/// Whether this component may take on work that answers: the
/// `response_out` port is wired and nothing is owed on it. Places a
/// held record first. The dispatch table gates every request and
/// feedback pull on this, so nothing is consumed while an earlier
/// record still waits for room.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn ready_to_answer(h: &mut Http, sys: &SyscallTable) -> bool {
    if h.out_response < 0 {
        return false;
    }
    h.outbox.flush(sys, h.out_response, &h.resp_frame)
}

/// Consume the burst flag: whether this component advanced a
/// request or answer since the last call.
pub fn take_worked(h: &mut Http) -> bool {
    let w = h.worked != 0;
    h.worked = 0;
    w
}

/// Place the `len`-byte record composed in `resp_frame`, or hold it.
unsafe fn place(h: &mut Http, sys: &SyscallTable, len: usize) {
    h.outbox.send(sys, h.out_response, &h.resp_frame, len);
    h.worked = 1;
}

/// Answer `id` with ONE response record: a HEAD carrying the whole
/// body, no MORE. The body is copied into place behind the head the
/// contract's writer seals, so the layout has one author. It rides as
/// a raw pointer because its source is usually another field of `h`
/// (`metrics_buf`, `readyz_buf`) and the record is composed in
/// `h.resp_frame`.
///
/// An exchange whose requester aborted ([`ExchangeId::NONE`]) is owed
/// nothing and gets nothing.
///
/// # Safety
///
/// `body_ptr..body_ptr+body_len` must be readable and must not alias
/// `h.resp_frame`.
unsafe fn emit_response(
    h: &mut Http,
    sys: &SyscallTable,
    id: ExchangeId,
    status: u16,
    body_ptr: *const u8,
    body_len: usize,
) -> bool {
    if h.out_response < 0 || id == ExchangeId::NONE {
        return false;
    }
    // Refused rather than cut short: a body past one record would be a
    // truncated answer. Every caller is bounded below `RESP_BODY_MAX`.
    if body_len > RESP_BODY_MAX || h.outbox.holding() {
        h.responses_dropped = h.responses_dropped.saturating_add(1);
        return false;
    }
    let at = response_body_at(CT_TEXT.len());
    if body_len > 0 {
        core::ptr::copy_nonoverlapping(body_ptr, h.resp_frame.as_mut_ptr().add(at), body_len);
    }
    let Some(len) = seal_response(&id, status, CT_TEXT, body_len, &mut h.resp_frame) else {
        h.responses_dropped = h.responses_dropped.saturating_add(1);
        return false;
    };
    place(h, sys, len);
    true
}

/// Answer one request from a borrowed body.
unsafe fn finish(h: &mut Http, sys: &SyscallTable, id: ExchangeId, status: u16, body: &[u8]) {
    emit_response(h, sys, id, status, body.as_ptr(), body.len());
}

/// One complete request pulled off `request_in`, handed to the
/// dispatch table for [`on_request`] routing.
#[repr(C)]
pub struct ExtReq {
    pub id: ExchangeId,
    pub method: u8,
    pub path_len: u16,
    pub body_len: u16,
    pub path: [u8; MAX_EXT_TARGET],
    pub body: [u8; MAX_EXT_BODY],
}

impl ExtReq {
    pub const fn new() -> Self {
        Self {
            id: ExchangeId::NONE,
            method: 0,
            path_len: 0,
            body_len: 0,
            path: [0; MAX_EXT_TARGET],
            body: [0; MAX_EXT_BODY],
        }
    }
}

/// One pull off `request_in`.
pub enum ExtPulled {
    Empty,
    Skipped,
    Request,
}

/// Read ONE record off `request_in` and, when it completes a request,
/// hand it over in `req`.
///
/// The record goes to the collector, which answers for the contract's
/// mechanics: a HEAD without MORE is a request outright; a HEAD with
/// MORE is granted the rest of the body bound, which is also this
/// surface's consent to it, and the BODY record without MORE completes
/// the request. A request past a bound or past the slots is answered
/// with the collector's status, never dropped.
///
/// `Skipped` marks a record consumed without completing a request, so
/// the caller's loop bound counts it either way. The caller gates this
/// on [`ready_to_answer`]: a pull writes at most one record.
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
    if !wire_channels::readable(sys, h.in_request) {
        return ExtPulled::Empty;
    }
    let n = (sys.channel_read)(h.in_request, h.req_frame.as_mut_ptr(), RECORD_MAX);
    if n <= 0 {
        return ExtPulled::Skipped;
    }
    let n = n as usize;

    // A requester ABORT ends the exchange wherever it is held: the
    // collector frees a request it is collecting, and a deferred
    // answer is never written.
    if let Some(Record::Abort { id, .. }) = parse_request(&h.req_frame[..n]) {
        forget_exchange(h, id);
    }

    let taken = h.requests.accept(&h.req_frame[..n]);
    let grant = h.requests.take_grant();
    let refusal = h.requests.take_refusal();
    match taken {
        Ok(Some(at)) => {
            let Some(r) = h.requests.request(at) else {
                h.requests.release(at);
                return ExtPulled::Skipped;
            };
            // The collector's bounds are this struct's, so both fit.
            req.id = r.id;
            req.method = r.method;
            req.path_len = r.target.len() as u16;
            req.body_len = r.body.len() as u16;
            req.path[..r.target.len()].copy_from_slice(r.target);
            req.body[..r.body.len()].copy_from_slice(r.body);
            h.requests.release(at);
            clear_await(h, req.id);
            ExtPulled::Request
        }
        Ok(None) => {
            if let Some((id, bytes)) = grant {
                await_body(h, id, dev_millis(sys));
                if let Some(len) = write_credit(&id, bytes, &mut h.resp_frame) {
                    place(h, sys, len);
                }
            }
            ExtPulled::Skipped
        }
        Err(_) => {
            match refusal {
                Some((id, why)) => {
                    clear_await(h, id);
                    h.bodies_refused = h.bodies_refused.saturating_add(1);
                    let body: &[u8] = match why {
                        Refuse::Busy => b"request slots busy",
                        Refuse::TooLarge => b"request too large",
                        Refuse::Unexpected => b"bad request",
                    };
                    finish(h, sys, id, why.status(), body);
                }
                // A record naming no exchange this surface holds — a
                // stray body, one past its exchange's end — or one that
                // does not parse: there is nobody to answer.
                None => {
                    h.records_unmatched = h.records_unmatched.saturating_add(1);
                }
            }
            ExtPulled::Skipped
        }
    }
}

/// Note that `id`'s body is being awaited from `now`.
fn await_body(h: &mut Http, id: ExchangeId, now: u64) {
    let at = h
        .awaiting
        .iter()
        .position(|a| a.id == id)
        .or_else(|| h.awaiting.iter().position(|a| a.id == ExchangeId::NONE));
    if let Some(i) = at {
        h.awaiting[i] = AwaitBody {
            id,
            started_ms: now,
        };
    }
}

/// Stop awaiting `id`'s body, if it was.
fn clear_await(h: &mut Http, id: ExchangeId) {
    if id == ExchangeId::NONE {
        return;
    }
    for a in h.awaiting.iter_mut() {
        if a.id == id {
            *a = AwaitBody::empty();
        }
    }
}

/// The requester aborted `id`: nothing further is written for it. A
/// deferred `/propose` keeps its slot until its feedback or deadline
/// comes — the proposal itself is already in flight — but the answer
/// has nowhere to go.
fn forget_exchange(h: &mut Http, id: ExchangeId) {
    if id == ExchangeId::NONE {
        return;
    }
    clear_await(h, id);
    for c in h.correlations.iter_mut() {
        if c.id == id {
            c.id = ExchangeId::NONE;
        }
    }
    for i in h.indices.iter_mut() {
        if i.id == id {
            i.id = ExchangeId::NONE;
        }
    }
}

/// Refresh the diagnostic caches from the telemetry component's
/// snapshot values. Called by the dispatch table on exactly the steps
/// telemetry emitted, so cache freshness matches the export cadence —
/// the http component never sees the telemetry struct itself. A
/// scrape answers from whatever the last tick cached, whole, in one
/// record.
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
    }
    // An empty export invalidates the cache: `/metrics` then serves
    // an empty body rather than silently replaying stale data.
    h.metrics_len = len as u16;
}

/// Own-state drains: ≤16 proposal assignments. The answer-producing feedback loops (≤8
/// rejections, ≤16 applies, one expiry) are driven by the dispatch
/// table through [`next_rejection`] / [`next_applied`] /
/// [`expire_step`], each pull gated there on [`ready_to_answer`] —
/// feedback is never consumed without somewhere to answer. The
/// 250 ms self-metrics tick rides [`take_metrics`].
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
        let Some((msg_type, plen)) =
            wire_channels::next_msg(sys, h.in_proposal_assigned, &mut h.msg_buf)
        else {
            break;
        };
        if msg_type != wire::MSG_PROPOSAL_ASSIGNED {
            continue;
        }
        let Some((correlation_id, _partition_id, index, _term)) =
            wire::decode_proposal_assigned(&h.msg_buf[..plen as usize])
        else {
            continue;
        };
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
                    id: corr.id,
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
/// [`ready_to_answer`] — do not consume a rejection unless the
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
    if !wire_channels::readable(sys, h.in_proposal_rejected) {
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
        let id = h.correlations[pos].id;
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_rejections = h.proposal_rejections.saturating_add(1);
        finish(h, sys, id, 503, b"proposal rejected");
    }
    Feedback::Handled
}

/// Pull ONE apply acknowledgement off the `applied` port. The
/// dispatch table drives the ≤16/step loop, gating each pull on
/// [`ready_to_answer`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_applied(h: &mut Http, sys: &SyscallTable) -> Feedback {
    if h.in_applied < 0 {
        return Feedback::Empty;
    }
    if !wire_channels::readable(sys, h.in_applied) {
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
        let id = h.indices[pos].id;
        h.indices[pos] = IndexSlot::empty();
        h.committed = h.committed.saturating_add(1);
        finish(h, sys, id, 200, b"committed");
    } else {
        h.applies_unmatched = h.applies_unmatched.saturating_add(1);
    }
    Feedback::Handled
}

/// One expiry check per step (a corr timeout, an index timeout, else a
/// request body still arriving).
/// The dispatch table gates the call on [`ready_to_answer`].
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Http` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn expire_step(h: &mut Http, sys: &SyscallTable, now: u64) {
    if let Some(pos) = h.correlations.iter().position(|slot| {
        slot.correlation_id != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let id = h.correlations[pos].id;
        h.correlations[pos] = CorrSlot::empty();
        h.proposal_timeouts = h.proposal_timeouts.saturating_add(1);
        finish(h, sys, id, 503, b"proposal timeout");
        return;
    }
    if let Some(pos) = h.indices.iter().position(|slot| {
        slot.index != 0 && now.wrapping_sub(slot.started_ms) >= HTTP_PROPOSAL_TIMEOUT_MS
    }) {
        let id = h.indices[pos].id;
        h.indices[pos] = IndexSlot::empty();
        h.commit_timeouts = h.commit_timeouts.saturating_add(1);
        finish(h, sys, id, 503, b"commit timeout");
        return;
    }
    if let Some(pos) = h.awaiting.iter().position(|a| {
        a.id != ExchangeId::NONE && now.wrapping_sub(a.started_ms) >= REQ_BODY_TIMEOUT_MS
    }) {
        let id = h.awaiting[pos].id;
        h.awaiting[pos] = AwaitBody::empty();
        // The collector frees an exchange on its ABORT; this one is
        // owed to the collector by this surface's own deadline.
        if let Some(len) = write_abort(&id, abort::STALLED, &mut h.req_frame) {
            let _ = h.requests.accept(&h.req_frame[..len]);
        }
        h.bodies_refused = h.bodies_refused.saturating_add(1);
        finish(h, sys, id, 408, b"request body timeout");
    }
}

unsafe fn emit_http_proposal(
    h: &mut Http,
    sys: &SyscallTable,
    id: ExchangeId,
    body: &[u8],
) -> bool {
    if h.out_proposal < 0 || body.len() > MAX_EXT_BODY {
        return false;
    }
    let slot = match h
        .correlations
        .iter()
        .position(|slot| slot.correlation_id == 0)
    {
        Some(v) => v,
        None => return false,
    };
    if !wire_channels::writable(sys, h.out_proposal) {
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
        id,
    };
    let occupied = h
        .correlations
        .iter()
        .filter(|v| v.correlation_id != 0)
        .count()
        + h.indices.iter().filter(|v| v.index != 0).count();
    h.inflight_high_water = h
        .inflight_high_water
        .max(occupied.min(u8::MAX as usize) as u8);
    true
}

/// Handle one request pulled off `request_in`. Every answer egresses
/// on `response_out` inside this call except the admin round
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
    id: ExchangeId,
    method: u8,
    path: &[u8],
    body: &[u8],
) -> ReqOut {
    // POST /propose — synchronous write bridge. The response is
    // deferred until apply acknowledges the assigned WAL index.
    if method == METHOD_POST && path == b"/propose" {
        if !emit_http_proposal(h, sys, id, body) {
            h.queue_unavailable = h.queue_unavailable.saturating_add(1);
            finish(h, sys, id, 503, b"propose queue unavailable");
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
                    finish(h, sys, id, 503, b"admin body too large");
                    ReqOut::Done
                } else {
                    // The admin envelope keeps its wire form
                    // (`[conn_id:u16 LE][op_code][body]`); for an
                    // HTTP-origin command the conn id is this
                    // surface's admin sequence, a log breadcrumb and
                    // never a reply route — the answer correlates on
                    // the exchange id held by the caller.
                    h.admin_seq = h.admin_seq.wrapping_add(1);
                    h.admin_env[..2].copy_from_slice(&h.admin_seq.to_le_bytes());
                    h.admin_env[2] = op_code;
                    h.admin_env[3..3 + body.len()].copy_from_slice(body);
                    ReqOut::Admin {
                        op_code,
                        len: (3 + body.len()) as u16,
                    }
                }
            }
            None => {
                h.requests_404 = h.requests_404.saturating_add(1);
                finish(h, sys, id, 400, b"unknown admin op");
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
        finish(h, sys, id, status, &[ready_byte]);
    } else if path == b"/why" {
        let mut body = [0u8; 2];
        let n = h.why_len as usize;
        body[..n].copy_from_slice(&h.why_buf[..n]);
        finish(h, sys, id, 200, &body[..n]);
    } else if path == b"/metrics" {
        // The whole export, in one record: `METRICS_CACHE` is sized
        // off the telemetry export cap and asserted inside
        // `RESP_BODY_MAX`, so there is no case here that does not fit.
        let n = h.metrics_len as usize;
        let body = h.metrics_buf.as_ptr();
        emit_response(h, sys, id, 200, body, n);
    } else {
        h.requests_404 = h.requests_404.saturating_add(1);
        finish(h, sys, id, 404, b"not found");
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
    id: ExchangeId,
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
        let n = format_admin_route_log(&mut log, op_code, h.admin_seq);
        dev_log(sys, 3, log.as_ptr(), n);
        finish(h, sys, id, 202, b"accepted");
    } else {
        h.admin_dropped = h.admin_dropped.saturating_add(1);
        finish(h, sys, id, 403, b"forbidden");
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

    let correlations = h
        .correlations
        .iter()
        .filter(|v| v.correlation_id != 0)
        .count() as i64;
    let indices = h.indices.iter().filter(|v| v.index != 0).count() as i64;
    let kg = wire::METRIC_KIND_GAUGE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, u8, i64); 15] = [
        (
            wire::metric_ids::HTTP_CORRELATIONS_INFLIGHT,
            kg,
            correlations,
        ),
        (wire::metric_ids::HTTP_INDICES_INFLIGHT, kg, indices),
        (
            wire::metric_ids::HTTP_INFLIGHT_HIGH_WATER,
            kg,
            i64::from(h.inflight_high_water),
        ),
        (
            wire::metric_ids::HTTP_PROPOSAL_TIMEOUTS,
            kc,
            i64::from(h.proposal_timeouts),
        ),
        (
            wire::metric_ids::HTTP_COMMIT_TIMEOUTS,
            kc,
            i64::from(h.commit_timeouts),
        ),
        (
            wire::metric_ids::HTTP_ASSIGNMENTS_UNMATCHED,
            kc,
            i64::from(h.assignments_unmatched),
        ),
        (
            wire::metric_ids::HTTP_ASSIGNMENTS_NO_SLOT,
            kc,
            i64::from(h.assignments_no_slot),
        ),
        (
            wire::metric_ids::HTTP_APPLIES_UNMATCHED,
            kc,
            i64::from(h.applies_unmatched),
        ),
        (
            wire::metric_ids::HTTP_REJECTIONS,
            kc,
            i64::from(h.proposal_rejections),
        ),
        (
            wire::metric_ids::HTTP_QUEUE_UNAVAILABLE,
            kc,
            i64::from(h.queue_unavailable),
        ),
        (wire::metric_ids::HTTP_COMMITTED, kc, i64::from(h.committed)),
        (
            wire::metric_ids::HTTP_REQUESTS,
            kc,
            i64::from(h.requests_handled),
        ),
        (
            wire::metric_ids::HTTP_REQUESTS_404,
            kc,
            i64::from(h.requests_404),
        ),
        (
            wire::metric_ids::HTTP_RESPONSES_DROPPED,
            kc,
            i64::from(h.responses_dropped),
        ),
        (
            wire::metric_ids::HTTP_ADMIN_DROPPED,
            kc,
            i64::from(h.admin_dropped),
        ),
    ];
    Some(samples)
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
