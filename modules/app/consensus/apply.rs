//! apply — ordered, deduplicated delivery of committed entries to
//! embedded state machines (quantum / lattice / loam) and to any
//! consumer that wires into the per-entry `committed_entries` port.
//! Also hosts the linearizable-read queue described in RFC §4.3.
//!
//! Inputs (seams + channels):
//!   raft's body ring (E5)  — raw appended entries fan-out
//!   horizon latches (E3/E6)— commit horizon advances from commit + raft
//!   reset latch (E6)       — snapshot-install apply reset, consumed FIRST
//!   probe replies (E8)     — strict-ReadIndex confirmations from raft
//!   `read_permits`         — CP-cache freshness signal from admission
//!   `read`                 — tagged read submissions from the codec
//!   entry replies          — WAL gap-refetch replies, delivered by the
//!                            dispatch table's `entry_reply` demux
//!                            (bit-31 request-id half)
//!
//! Outputs:
//!   `applied`              — apply acks (term,index) plus
//!                            MSG_CLIENT_READ_RESPONSE / MSG_CLIENT_REJECT_INTERNAL
//!                            for queued reads that have reached their
//!                            linearization point (or timed out).
//!   `committed_entries`    — per-entry stream `[term][index][body]`
//!   `entry_request`        — WAL gap-refetch requests (bit-31 id space)
//!   probe queue (E7)       — strict-ReadIndex probe requests to raft
//!   admin ring (E9)        — committed admin/config bodies to raft
//!
//! The per-entry stream is what downstream consumers (Loam, Lattice,
//! the example_consumer module, anything using `replica_facade.rs`)
//! subscribe to in order to actually apply commands. Without it, the
//! consumer only knows commit horizons and can't reproduce state.
//!
//! ## Linearizable read semantics
//!
//! When a `MSG_CLIENT_READ_REQUEST` arrives on `read`, the read is
//! enqueued together with the current `commit_horizon` as its required
//! ReadIndex linearization point. A read becomes ready when:
//!   1. `apply_index >= required_commit`, AND
//!   2. We have observed a `MSG_READ_PERMIT` from the read gate within
//!      `READ_PERMIT_TTL_MS` (CP cache is Fresh/Cached).
//! The response body is empty — the substrate guarantees the
//! linearization point has been reached. State-machine consumers
//! consult their replicated state (built from `committed_entries`) and
//! answer the client themselves.
//!
//! If a read is still queued after `READ_TIMEOUT_MS` without becoming
//! ready, we emit `MSG_CLIENT_REJECT_INTERNAL` with
//! `CLIENT_REJECT_FALLBACK`. Bounded queue: oldest read is dropped on
//! overflow with the same fail-open semantics as the entry buffer.
//!
//! Per-step bound (Discipline §5): ≤16 body-ring pops, ≤8 each of
//! refetch replies / permits / submissions / probe replies, one pass
//! over the 16-slot read queue, plus the in-order apply loop bounded
//! by the 64-slot pending buffer.

use super::abi::SyscallTable;
use super::seam::{SeamRing, PROBE_QUEUE_SLOTS};
use super::types::*;
use super::{
    dev_log, dev_micros, dev_millis, dev_report_step_effect, step_effect, wal_frame, wire,
    wire_channels,
};

const DEDUP_SHARDS: usize = 16;

/// Maximum body size held in a pending-entry slot. Derived from the
/// shared frame contract (= the leader's `PROPOSAL_BATCH_CAP`) so any
/// batch raft can flush also fits here unmodified.
const PENDING_BODY_CAP: usize = wal_frame::MAX_ENTRY_BODY;

/// Number of pending entries buffered awaiting commit. Sized to absorb
/// the typical in-flight window between WAL persist and quorum commit.
///
/// The buffer fails CLOSED: when every slot is occupied, `store_pending`
/// refuses the new entry rather than evicting one. That direction is the
/// safe one because a refused entry is still durable in the WAL and the
/// next-needed index is re-read through `request_missing_entry`, whereas
/// an evicted slot ahead of `apply_index` would be a hole nothing asks
/// for again. It is also why this buffer doubles as the retention store
/// for [`emit_committed_entry`]: an entry a destination has not yet
/// taken keeps its slot, so back-pressure travels up the pipeline
/// instead of turning into a lost commit.
///
/// Sized above raft's uncommitted-inflight window (MAX_UNCOMMITTED_INFLIGHT
/// = 48) so a full in-flight backlog never forces a refusal under
/// sustained load.
const PENDING_ENTRY_SLOTS: usize = 64;

/// Bounded linearizable-read queue. Sized to absorb the
/// read-submission window between codec submit and the moment
/// `apply_index` catches the submission's commit horizon.
const PENDING_READ_SLOTS: usize = 16;

/// How long a read may sit without observing a fresh CP permit before
/// it gets rejected with `CLIENT_REJECT_FALLBACK`. 5 s matches the
/// CP-bridge "Fresh" tier refresh budget.
const READ_TIMEOUT_MS: u64 = 5_000;

/// CP permit "freshness" TTL — if we haven't seen a permit in this
/// many ms, treat the cache as stale and refuse new ready-emit.
/// Must span several ticks of the pi5's ~1 s-granular UNIX_MILLIS: on a
/// 1 s-quantised clock a 1 s TTL expires the moment the clock steps,
/// turning fresh permits into spurious read FALLBACK bursts.
const READ_PERMIT_TTL_MS: u64 = 3_000;
const METRICS_INTERVAL_MS: u64 = 1_000;

/// Minimum spacing between re-issues of the SAME missing-index WAL refetch
/// request. One request is outstanding at a time; if its reply is lost or
/// the WAL is momentarily busy we re-ask after this window rather than every
/// step (which would flood `wal.entry_request`). At tick_us=6000 this is
/// ~8 steps — comfortably longer than a WAL serve round-trip.
const ENTRY_REFETCH_RETRY_MS: u64 = 50;

/// Cross-boundary request-id hygiene on the shared `entry_request`
/// fan-in at durability: apply's WAL refetch ids carry bit 31; the
/// replicator owns the bit-31-clear half. Matching is by exact echo,
/// so nothing else changes.
const ENTRY_REQUEST_ID_BIT: u32 = 0x8000_0000;

/// Destinations a committed entry owes before it counts as applied, as
/// bits in [`PendingEntry::delivered`].
///
/// Delivery is tracked per destination, not per entry, for one reason:
/// the retry that a refused write forces must not re-run the writes that
/// already landed. Without these bits an entry whose client ack
/// succeeded and whose observer write was refused would ack twice, and
/// an admin body would be applied twice by raft.
///
/// A destination that is unwired, or that this entry does not concern
/// (the admin seam, for a body carrying no admin/config magic), is
/// marked delivered at the point the entry is classified: there is
/// nobody to owe it to.
const DELIVERED_ACK: u8 = 1 << 0;
const DELIVERED_ADMIN: u8 = 1 << 1;
const DELIVERED_STREAM: u8 = 1 << 2;
const DELIVERED_ALL: u8 = DELIVERED_ACK | DELIVERED_ADMIN | DELIVERED_STREAM;

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingEntry {
    /// 0 = slot empty.
    index: Index,
    term: Term,
    body_len: u16,
    /// `DELIVERED_*` bits already satisfied for this entry. Reset
    /// whenever the slot takes a different entry — including the
    /// same-index replacement a follower truncate-then-append performs,
    /// where the index is unchanged but the body is not.
    delivered: u8,
    body: [u8; PENDING_BODY_CAP],
}

impl PendingEntry {
    const fn empty() -> Self {
        Self {
            index: 0,
            term: 0,
            body_len: 0,
            delivered: 0,
            body: [0u8; PENDING_BODY_CAP],
        }
    }

    fn is_empty(&self) -> bool {
        self.index == 0
    }
}

/// Phase of a pending read:
///   0 = AWAITING_PROBE: probe issued to raft, waiting for reply.
///   1 = ARMED: probe confirmed, `required_commit` set, waiting on
///       `apply_index` to catch up.
///   2 = LEGACY: probe queue full at submission — submission-time
///       `commit_horizon` was used directly. Behaves like phase 1 but
///       never times out waiting for a probe.
const READ_PHASE_AWAITING_PROBE: u8 = 0;
const READ_PHASE_ARMED: u8           = 1;
const READ_PHASE_LEGACY: u8          = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingRead {
    /// 0 = slot empty. Non-zero correlation_id required.
    correlation_id: u64,
    required_commit: Index,
    submitted_ms: u64,
    phase: u8,
}

impl PendingRead {
    const fn empty() -> Self {
        Self {
            correlation_id: 0,
            required_commit: 0,
            submitted_ms: 0,
            phase: READ_PHASE_LEGACY,
        }
    }

    fn is_empty(&self) -> bool {
        self.correlation_id == 0
    }
}

#[repr(C)]
pub struct Apply {
    // ── Channels ──────────────────────────────────────────────
    pub in_read_permits: i32,       // in: ReadPermit from the read gate
    pub in_reads: i32,              // in: MSG_CLIENT_READ_REQUEST from the codec
    pub out_applied: i32,           // out: response stream to the codec
    pub out_committed_entries: i32, // out: per-entry MSG_COMMITTED_ENTRY stream
    pub out_metrics: i32,           // out: MSG_METRIC_SAMPLE (shared module port)
    pub out_entry_request: i32,     // out: MSG_WAL_ENTRY_REQUEST to wal.entry_request (gap refetch)

    // ── Seams (consumed by raft at the top of the next dispatch) ──
    /// E7: strict-ReadIndex probe requests → raft (was
    /// `read_probe_request`). Full queue = degrade-to-LEGACY at the
    /// submission site, exactly the full-channel fallback.
    pub probe_out: [u64; PROBE_QUEUE_SLOTS],
    pub probe_out_count: u8,
    /// E9: committed admin/config bodies → raft (was
    /// `admin_committed`; unwired in every config before — making it
    /// live is the deliberate RFC WS-4 semantic activation).
    ///
    /// A full ring refuses the push, and that refusal RETAINS the entry
    /// rather than dropping it: a committed config change raft never
    /// sees is a voter set that disagrees with the log this node claims
    /// to have applied, and nothing re-derives it. Raft drains this seam
    /// at the top of every dispatch, so the retry lands on the next
    /// step.
    pub admin_out: SeamRing<4096>,

    pub partition_id: u16,

    // ── Gap refetch (apply-side WAL read-back) ────────────────
    /// Index currently being refetched from the WAL (0 = none). At most one
    /// outstanding request; cleared when the matching reply arrives.
    awaiting_entry: Index,
    /// Monotone request id stamped into each MSG_WAL_ENTRY_REQUEST
    /// (bit 31 set at encode — see `ENTRY_REQUEST_ID_BIT`).
    entry_request_id: u32,
    /// `dev_millis` of the last refetch request, for re-issue throttling.
    last_entry_request_ms: u64,
    /// Counter: entries recovered via WAL refetch (APPLY_REFETCHED gauge).
    entries_refetched: u32,

    // ── Commit tracking ───────────────────────────────────────
    apply_index: Index,
    commit_horizon: Index,
    commit_term: Term,
    dedup_shards: [Index; DEDUP_SHARDS],
    entries_applied: u32,
    entries_buffered: u32,
    entries_evicted: u32,
    /// Counter: passes that ended holding a committed entry a
    /// destination refused. NOT a loss count — the entry keeps its slot
    /// and is re-offered next step. A value that climbs steadily means a
    /// consumer is not draining, and `apply_index` is deliberately
    /// frozen behind it; `APPLY_CAUGHT_UP` goes to 0 with it, so the
    /// node reports itself unready rather than diverging quietly.
    delivery_stalls: u32,
    /// `dev_millis` of the last stall warning, for log throttling.
    last_stall_log_ms: u64,

    // ── Metrics ───────────────────────────────────────────────
    last_metrics_ms: u64,
    /// `clustor.flow.apply_batch_latency_ms` cumulative bucket counts
    /// (RFC §4.1): wall time of each horizon-delivery pass that
    /// actually applied ≥1 entry, µs-classified.
    apply_batch_buckets: [u32; wire::hist::APPLY_BATCH_US.len() + 1],

    // ── Pending-entry buffer ──────────────────────────────────
    pending: [PendingEntry; PENDING_ENTRY_SLOTS],

    // ── Read queue ────────────────────────────────────────────
    pending_reads: [PendingRead; PENDING_READ_SLOTS],
    last_permit_ms: u64,
    last_permit_state: u8,
    reads_enqueued: u32,
    reads_completed: u32,
    reads_timed_out: u32,
    reads_evicted: u32,

    // ── Scratch ───────────────────────────────────────────────
    msg_buf: [u8; PENDING_BODY_CAP + 32],
}

/// Initialise every field to its pre-param default. Channel handles
/// and params are assigned by `mod.rs` afterwards; `arm` runs the
/// post-param boot logic.
pub fn init(s: &mut Apply) {
    s.in_read_permits = -1;
    s.in_reads = -1;
    s.out_applied = -1;
    s.out_committed_entries = -1;
    s.out_metrics = -1;
    s.out_entry_request = -1;
    s.probe_out = [0u64; PROBE_QUEUE_SLOTS];
    s.probe_out_count = 0;
    s.admin_out.reset();
    s.partition_id = 0;
    s.awaiting_entry = 0;
    s.entry_request_id = 0;
    s.last_entry_request_ms = 0;
    s.entries_refetched = 0;
    s.apply_index = 0;
    s.commit_horizon = 0;
    s.commit_term = 0;
    s.dedup_shards = [0; DEDUP_SHARDS];
    s.entries_applied = 0;
    s.entries_buffered = 0;
    s.entries_evicted = 0;
    s.delivery_stalls = 0;
    s.last_stall_log_ms = 0;
    s.last_metrics_ms = 0;
    s.apply_batch_buckets = [0u32; wire::hist::APPLY_BATCH_US.len() + 1];
    for slot in s.pending.iter_mut() {
        *slot = PendingEntry::empty();
    }
    for slot in s.pending_reads.iter_mut() {
        *slot = PendingRead::empty();
    }
    s.last_permit_ms = 0;
    s.last_permit_state = 0;
    s.reads_enqueued = 0;
    s.reads_completed = 0;
    s.reads_timed_out = 0;
    s.reads_evicted = 0;
    for b in s.msg_buf.iter_mut() { *b = 0; }
}

/// Post-param boot logic. Called by `mod.rs` after channel handles and
/// params are in place.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn arm(_s: &mut Apply, sys: &SyscallTable) {
    dev_log(sys, 3, b"[apply] init".as_ptr(), 12);
}

/// One apply step. Delivery order (owned by the dispatch table, cited
/// here): the E6 RESET latch is consumed FIRST (ordering reviewed:
/// reset index ≥ any queued horizon at install time), then raft's body
/// ring is drained so the buffer is populated BEFORE the horizon
/// latches are evaluated — the same bodies-before-horizon intra-tick
/// order the channel edges had (avoids spurious WAL refetches), then
/// the read path.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn step(
    s: &mut Apply,
    sys: &SyscallTable,
    now: u64,
    reset: Option<(Term, Index)>,
    raft_horizon: Option<(Term, Index)>,
    commit_horizon: Option<(Term, Index)>,
    bodies: &mut SeamRing<8192>,
    probe_replies: &mut [(u64, u64, u8); PROBE_QUEUE_SLOTS],
    probe_reply_count: &mut u8,
) {
    let work_before = s.entries_applied;

    // 0) E6 RESET first (before any drain).
    if let Some((term, index)) = reset {
        pipeline_reset(s, term, index);
    }

    // 1) Drain the per-entry body ring first so the buffer is
    //    populated before we evaluate commit horizons.
    drain_log_entries(s, sys, bodies);

    // 1b) WAL refetch replies for entries the lossy observer fan-out
    //     dropped were inserted by the dispatch table's entry_reply
    //     demux via `on_entry_reply` (bit-31 request-id half) before
    //     this step; attempt to apply — so progress continues even
    //     when no new commit horizon arrives this step.
    drain_pending_entries(s, sys);

    // 2) Deliver commit-horizon advances (E6 from raft, then E3 from
    //    commit — dispatch order) and emit per-entry committed messages
    //    for any buffered entries the new horizon covers. Time the pass
    //    and fold it into the apply-batch histogram when it actually
    //    applied entries (RFC §4.1).
    let applied_before = s.entries_applied;
    let batch_start = dev_micros(sys);
    if let Some((term, index)) = raft_horizon {
        on_commit_horizon(s, sys, term, index);
    }
    if let Some((term, index)) = commit_horizon {
        on_commit_horizon(s, sys, term, index);
    }
    if s.entries_applied != applied_before {
        let elapsed = dev_micros(sys).wrapping_sub(batch_start);
        let b = wire::hist::bucket(&wire::hist::APPLY_BATCH_US, elapsed);
        s.apply_batch_buckets[b] = s.apply_batch_buckets[b].saturating_add(1);
    }

    // 3) Track CP read permits — used to gate the read queue.
    drain_read_permits(s, sys, now);

    // 4) Accept new linearizable-read submissions from the codec.
    drain_read_submissions(s, sys, now);

    // 4b) Pick up any strict-ReadIndex probe replies that have
    //     arrived from raft and arm or reject the matching
    //     pending read accordingly.
    drain_read_probe_replies(s, sys, probe_replies, probe_reply_count);

    // 5) Drain reads whose linearization point has been reached
    //    (apply_index ≥ required_commit AND CP permit is fresh),
    //    plus reject any that have timed out without freshness.
    drain_pending_reads(s, sys, now);

    // 6) Periodic metrics (RFC §4.1/§4.2).
    emit_metrics(s, sys, now);
    if s.entries_applied != work_before {
        dev_report_step_effect(sys, step_effect::WORK_DONE);
    }
}

/// Deliver one commit-horizon advance (seams E3/E6): per-shard
/// dedup, horizon raise, then the in-order apply pass.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn on_commit_horizon(s: &mut Apply, sys: &SyscallTable, term: Term, index: Index) {
    // Dedup horizon advances per-shard (legacy behaviour preserved).
    let shard = (index as usize) % DEDUP_SHARDS;
    if index <= s.dedup_shards[shard] {
        return;
    }
    s.dedup_shards[shard] = index;

    if index > s.commit_horizon {
        s.commit_horizon = index;
        s.commit_term = term;
    }

    // Emit per-entry messages for any buffered entries that the new
    // horizon now covers (in ascending order; on a gap, refetch the
    // missing index from the WAL rather than stalling).
    drain_pending_entries(s, sys);
}

/// Emit apply counters, the queue-depth gauge, and the apply-batch
/// latency histogram as typed samples (RFC §4.3). Partition-stamped so
/// per-partition apply instances don't collide. Dropped under
/// backpressure — telemetry never stalls the apply path.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut Apply, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // Current queue depth: occupied pending-entry slots (index != 0).
    let mut depth: i64 = 0;
    for e in s.pending.iter() {
        if e.index != 0 { depth += 1; }
    }

    let mid = wire::SOURCE_ID_APPLY;
    let pid = s.partition_id;
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_ENTRIES_APPLIED, wire::METRIC_KIND_COUNTER, i64::from(s.entries_applied));
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_QUEUE_DEPTH, wire::METRIC_KIND_GAUGE, depth);
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_REFETCHED, wire::METRIC_KIND_COUNTER, i64::from(s.entries_refetched));
    // Readiness sub-signal (real /readyz): apply cursor caught up to commit.
    let caught_up = (s.apply_index >= s.commit_horizon) as i64;
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_CAUGHT_UP, wire::METRIC_KIND_GAUGE, caught_up);
    // Drop/eviction counters (observability closeout).
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_ENTRIES_EVICTED, wire::METRIC_KIND_COUNTER, i64::from(s.entries_evicted));
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_READS_EVICTED, wire::METRIC_KIND_COUNTER, i64::from(s.reads_evicted));
    // Backpressure, not loss: passes that ended holding a retained entry.
    emit_sample(s, sys, mid, pid, wire::metric_ids::APPLY_DELIVERY_STALLS, wire::METRIC_KIND_COUNTER, i64::from(s.delivery_stalls));
    // Cumulative bucket counts per the wire contract (wire::hist): emit the
    // running prefix sum so bucket i = count of samples <= bound[i].
    let base = wire::hist::HIST_BASE;
    let mut cum: i64 = 0;
    for i in 0..s.apply_batch_buckets.len() {
        cum += i64::from(s.apply_batch_buckets[i]);
        emit_sample(s, sys, mid, pid, base + i as u16, wire::METRIC_KIND_HISTOGRAM, cum);
    }
}

/// Emit one typed metric sample if `out_metrics` has write space.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_sample(
    s: &Apply,
    sys: &SyscallTable,
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
) {
    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
    wire::encode_metric_sample(&mut buf, module_id, partition_id, metric_id, kind, value);
    wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
}

/// Drain raft's appended-entry body ring (E5). ≤16 per step; a
/// `break` leaves frames IN THE RING for the next step.
///
/// # Safety
///
/// Caller must hold exclusive borrows and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_log_entries(s: &mut Apply, sys: &SyscallTable, bodies: &mut SeamRing<8192>) {
    for _ in 0..16 {
        // Preserve the oldest not-yet-applied entries when the local join
        // buffer is saturated: reading another observer frame here would
        // evict the lowest index, which is exactly the entry strict-order
        // apply needs next.  Leaving the frame in the ring propagates
        // pressure through the graph; if the lossy Raft observer skips a
        // later frame, the WAL refetch path recovers that later gap.
        // The commit horizon is delivered later in this same step and can
        // free slots without a manifest-specific buffer-size assumption.
        if !s.pending.iter().any(PendingEntry::is_empty) {
            drain_pending_entries(s, sys);
            if !s.pending.iter().any(PendingEntry::is_empty) {
                break;
            }
        }
        let (msg_type, plen) = match bodies.pop(&mut s.msg_buf) {
            Some(v) => v,
            None => break,
        };
        if msg_type != wire::MSG_WAL_ENTRY || (plen as usize) < 16 {
            continue;
        }
        let plen = plen as usize;
        let (term, index) = wire::decode_term_index(&s.msg_buf);
        if index == 0 || index <= s.apply_index {
            // Already applied — drop. Followers receiving truncate-replays
            // would re-deliver, but apply_index only moves forward.
            continue;
        }
        let body_len = (plen - 16).min(PENDING_BODY_CAP);
        let _ = store_pending(s, term, index, body_len);
    }
}

/// Snapshot install reset (RFC §2.3). Drop pending observer entries
/// whose index is at or below the snapshot point and fast-forward our
/// own apply_index / commit_horizon to it. Read queue is left intact —
/// strict ReadIndex probe replies (or the legacy commit-horizon path)
/// will arm them against the new horizon.
fn pipeline_reset(s: &mut Apply, term: Term, index: Index) {
    if index <= s.apply_index && index <= s.commit_horizon { return; }
    for slot in s.pending.iter_mut() {
        if !slot.is_empty() && slot.index <= index {
            *slot = PendingEntry::empty();
        }
    }
    if index > s.apply_index { s.apply_index = index; }
    if index > s.commit_horizon { s.commit_horizon = index; s.commit_term = term; }
    // Bump dedup horizons to the new floor so any stale shard slot
    // doesn't pretend we're still behind.
    for shard in s.dedup_shards.iter_mut() {
        if *shard < index { *shard = index; }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` (or shared
/// `&Apply` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn store_pending(
    s: &mut Apply,
    term: Term,
    index: Index,
    body_len: usize,
) -> bool {
    // First pass: same-index replacement (follower truncate-then-append).
    for slot in s.pending.iter_mut() {
        if !slot.is_empty() && slot.index == index {
            slot.term = term;
            slot.body_len = body_len as u16;
            // A different entry now occupies this index, so whatever the
            // previous occupant had already delivered says nothing about
            // this one. Partial delivery of a body that has since been
            // truncated away is not progress to preserve.
            slot.delivered = 0;
            if body_len > 0 {
                slot.body[..body_len].copy_from_slice(&s.msg_buf[16..16 + body_len]);
            }
            return true;
        }
    }
    // Second pass: free slot.
    for slot in s.pending.iter_mut() {
        if slot.is_empty() {
            slot.index = index;
            slot.term = term;
            slot.body_len = body_len as u16;
            slot.delivered = 0;
            if body_len > 0 {
                slot.body[..body_len].copy_from_slice(&s.msg_buf[16..16 + body_len]);
            }
            s.entries_buffered += 1;
            return true;
        }
    }
    // Fail closed: never discard the oldest entry required by strict-order
    // apply. Observer reads normally stop before reaching this branch; WAL
    // replies can race a full buffer, in which case the retry timer will ask
    // for the entry again after committed entries free capacity.
    s.entries_evicted = s.entries_evicted.saturating_add(1);
    false
}

/// Minimum spacing between delivery-stall warnings. A stall re-offers
/// its entry every step, so an unthrottled line would be one per step
/// for as long as a consumer is wedged.
const STALL_LOG_INTERVAL_MS: u64 = 1_000;

/// Record that this pass ended holding an entry a destination refused.
///
/// Counted rather than dropped, and said out loud on a throttle: apply
/// is now deliberately not advancing, and the operator needs to be able
/// to tell that from a quiet cluster. `APPLY_CAUGHT_UP` reports the same
/// condition to `/readyz`; this is the line that names the cause.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn note_delivery_stall(s: &mut Apply, sys: &SyscallTable) {
    s.delivery_stalls = s.delivery_stalls.saturating_add(1);
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_stall_log_ms) < STALL_LOG_INTERVAL_MS {
        return;
    }
    s.last_stall_log_ms = now;
    dev_log(sys, 2, b"[apply] delivery stalled".as_ptr(), 24);
}

/// Apply buffered entries in strict ascending order up to the commit
/// horizon. When the next-needed index (`apply_index + 1`) is missing from
/// the observer buffer — the best-effort body fan-out dropped its
/// body under overdrive — request it back from the durable WAL via
/// `entry_request` instead of stalling forever. The reply lands on
/// `entry_reply`, is reinserted into `pending` by `drain_entry_replies`, and
/// applied on a subsequent pass. Data is never lost (the entry is durable in
/// the WAL); this keeps apply LIVE under commit-outruns-apply overdrive.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_pending_entries(s: &mut Apply, sys: &SyscallTable) {
    loop {
        // No pre-poll of `out_applied` here. `emit_committed_entry`
        // tracks acceptance per destination, so an entry whose ack
        // already landed and whose stream write is still outstanding
        // must not be held back by the ack channel's fill level — and a
        // poll that reports ≥1 byte free never licensed the write
        // anyway.
        let mut victim: Option<usize> = None;
        let mut victim_index: Index = Index::MAX;
        for (i, slot) in s.pending.iter().enumerate() {
            if !slot.is_empty()
                && slot.index > s.apply_index
                && slot.index <= s.commit_horizon
                && slot.index < victim_index
            {
                victim_index = slot.index;
                victim = Some(i);
            }
        }
        match victim {
            // Nothing buffered in (apply_index, commit_horizon] yet we're
            // behind the horizon: the body was dropped on the lossy observer
            // fan-out. Refetch the next-needed index from the durable WAL.
            None => {
                if s.apply_index < s.commit_horizon {
                    request_missing_entry(s, sys, s.apply_index + 1);
                }
                break;
            }
            Some(slot_idx) => {
                if victim_index != s.apply_index + 1 {
                    // Gap: the next-needed index is missing from the buffer.
                    // Refetch it from the WAL; apply resumes once it lands.
                    request_missing_entry(s, sys, s.apply_index + 1);
                    break;
                }
                if !emit_committed_entry(s, sys, slot_idx) {
                    // A destination refused. The entry keeps its slot
                    // and its partial-delivery state, `apply_index`
                    // stays where it is, and the next step re-offers
                    // exactly what is still outstanding. Stopping here
                    // rather than moving to the next index is also what
                    // preserves strict apply order.
                    note_delivery_stall(s, sys);
                    break;
                }
            }
        }
    }
}

/// Ask the WAL for the durable entry at `index` (the missing next-to-apply
/// index). At most one request is outstanding; the same index is re-issued
/// only after `ENTRY_REFETCH_RETRY_MS` so a lost reply self-heals without
/// flooding `wal.entry_request`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn request_missing_entry(s: &mut Apply, sys: &SyscallTable, index: Index) {
    if s.out_entry_request < 0 || index == 0 { return; }
    let now = dev_millis(sys);
    if s.awaiting_entry == index
        && now.wrapping_sub(s.last_entry_request_ms) < ENTRY_REFETCH_RETRY_MS
    {
        return;
    }
    let poll = (sys.channel_poll)(s.out_entry_request, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    s.entry_request_id = s.entry_request_id.wrapping_add(1);
    let mut buf = [0u8; wire::WAL_ENTRY_REQUEST_LEN];
    wire::encode_wal_entry_request(&mut buf, s.entry_request_id | ENTRY_REQUEST_ID_BIT, index);
    let w = wire_channels::channel_write_msg(
        sys, s.out_entry_request, wire::MSG_WAL_ENTRY_REQUEST, &buf,
    );
    if w > 0 {
        s.awaiting_entry = index;
        s.last_entry_request_ms = now;
    }
}

/// Deliver one WAL refetch reply (`MSG_WAL_ENTRY_REPLY`, dispatch-table
/// demux on the shared `entry_reply` fan-in, bit-31 request-id half,
/// ≤8/step) and reinsert its
/// body into the pending buffer so the next apply pass can deliver it.
/// The reply body is the raw proposal body (the WAL stripped the 16-byte
/// term/index header), so it is staged at `msg_buf[16..]` to match
/// `store_pending`'s fixed slice.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn on_entry_reply(s: &mut Apply, _sys: &SyscallTable, msg: &[u8], plen: u16) {
    // Stage the frame in this component's scratch (the demux buffer is
    // shared), mirroring the truncating channel-read contract.
    let plen = (plen as usize).min(s.msg_buf.len()).min(msg.len());
    s.msg_buf[..plen].copy_from_slice(&msg[..plen]);
    let (_req_id, term, index, _prev_term, hdr) =
        match wire::decode_wal_entry_reply(&s.msg_buf[..plen]) {
            Some(v) => v,
            None => return,
        };
    if index == 0 { return; }
    // NOT_FOUND is signalled by term == 0 (the WAL's header-only reply),
    // NOT by an empty body: a leader-election no-op is a real entry with
    // an empty body, and reading it as missing wedges the refetch loop on
    // the first index of every term.
    if term == 0 {
        // NOT_FOUND (below WAL retention) — the gap stands. Leave
        // awaiting_entry SET so request_missing_entry's retry throttle
        // holds the re-request to once per ENTRY_REFETCH_RETRY_MS rather
        // than re-requesting on the very next drain — which would flood
        // wal.entry_request for a permanent gap.
        return;
    }
    // A real entry resolves the outstanding request, so the next gap can
    // be refetched immediately.
    if index == s.awaiting_entry { s.awaiting_entry = 0; }
    if index <= s.apply_index { return; } // already applied
    let body_len = (plen - hdr).min(PENDING_BODY_CAP);
    // Relocate the body from the 20-byte-reply-header offset to offset 16
    // (forward copy, dest < src, so non-overlapping-safe) for store_pending.
    s.msg_buf.copy_within(hdr..hdr + body_len, 16);
    if store_pending(s, term, index, body_len) {
        s.entries_refetched = s.entries_refetched.saturating_add(1);
    }
}

/// Offer one committed entry to every destination it owes — client ack,
/// admin/config fanout, per-entry stream — and retire the slot only once
/// all of them have taken it.
///
/// Returns false, leaving the slot intact and `apply_index` unmoved,
/// while any destination is still refusing. Each destination clears
/// independently via [`PendingEntry::delivered`], so the retry re-offers
/// only what is still outstanding and no destination sees the entry
/// twice.
///
/// ## Why nothing here may be dropped
///
/// This function is the only place a committed entry leaves the apply
/// pipeline. What is not delivered here is not delivered at all: the
/// slot is the last copy, `drain_pending_entries` only ever asks the WAL
/// for `apply_index + 1`, and advancing `apply_index` past an entry is
/// what makes it unaskable-for. Every earlier loss in this pipeline —
/// the lossy body-ring fan-out, a `store_pending` refusal — is survivable
/// precisely because it happens BEFORE the cursor moves, and is repaired
/// by `request_missing_entry`. A loss here has no such repair.
///
/// So each destination is treated as correctness-bearing:
///
/// - the **client ack** is the proposal's only completion signal;
/// - the **admin seam** carries committed config changes, and one raft
///   never sees is a voter set that disagrees with the applied log;
/// - the **per-entry stream** is what every consumer builds replicated
///   state from (see this module's header), and `replica_facade`'s
///   `GapInPerEntryStream` detects such a hole without being able to
///   repair it.
///
/// A destination that is unwired is owed nothing and is marked delivered
/// at once, so an observer-less graph applies at full speed.
///
/// The cost of this is that a consumer which stops draining stalls
/// apply rather than being quietly skipped past. That is the intended
/// direction: `APPLY_CAUGHT_UP` drops to 0, `/readyz` fails, and the
/// node stops claiming to be a replica of a log it is no longer
/// applying.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_committed_entry(s: &mut Apply, sys: &SyscallTable, slot_idx: usize) -> bool {
    // Small fields only — the body stays in its slot rather than being
    // copied through a PENDING_BODY_CAP-sized stack temporary on every
    // applied entry.
    let term = s.pending[slot_idx].term;
    let index = s.pending[slot_idx].index;
    let body_len = s.pending[slot_idx].body_len as usize;

    if s.pending[slot_idx].delivered & DELIVERED_ACK == 0 {
        if s.out_applied < 0 {
            s.pending[slot_idx].delivered |= DELIVERED_ACK;
        } else {
            let mut resp = [0u8; 18];
            resp[0..2].copy_from_slice(&s.partition_id.to_le_bytes());
            wire::encode_term_index(&mut resp[2..18], term, index);
            let w = wire_channels::channel_write_msg(
                sys, s.out_applied, wire::MSG_CLIENT_RESPONSE, &resp,
            );
            if w > 0 {
                s.pending[slot_idx].delivered |= DELIVERED_ACK;
            }
        }
    }

    // Admin-replicated entries (RFC §3.1) start with `ADMIN_MAGIC`.
    // Config-change entries (RFC §1.2) start with `CONFIG_CHANGE_MAGIC`.
    // Both magics are 8 bytes so opaque application payloads cannot
    // collide into them — see `wire::ADMIN_MAGIC`.
    // Both fan out on the admin seam ring back to raft (E9);
    // the distinct msg_type tells the engine which path applies.
    if s.pending[slot_idx].delivered & DELIVERED_ADMIN == 0 {
        // `None` = this entry is not an admin or config change, so the
        // seam is owed nothing by it.
        let owed: Option<(u8, usize)> = if body_len >= 8 {
            let head = &s.pending[slot_idx].body[..body_len];
            if wire::has_admin_magic(head) && body_len >= 13 {
                Some((wire::MSG_ADMIN_COMMITTED, 8))
            } else if wire::has_config_change_magic(head) && body_len >= 10 {
                // Re-emit the body verbatim — the magic stays so
                // raft can validate with `decode_config_change`.
                Some((wire::MSG_CONFIG_COMMITTED, 0))
            } else {
                None
            }
        } else {
            None
        };
        match owed {
            None => s.pending[slot_idx].delivered |= DELIVERED_ADMIN,
            Some((msg_type, from)) => {
                let (pending, admin_out) = (&s.pending[slot_idx], &mut s.admin_out);
                if admin_out.push(msg_type, &pending.body[from..body_len]) {
                    s.pending[slot_idx].delivered |= DELIVERED_ADMIN;
                }
            }
        }
    }

    if s.pending[slot_idx].delivered & DELIVERED_STREAM == 0 {
        if s.out_committed_entries < 0 {
            s.pending[slot_idx].delivered |= DELIVERED_STREAM;
        } else {
            // Reuse msg_buf as the scratch envelope: 16-byte header + body.
            wire::encode_term_index(&mut s.msg_buf, term, index);
            if body_len > 0 {
                let (pending, msg_buf) = (&s.pending[slot_idx], &mut s.msg_buf);
                msg_buf[16..16 + body_len].copy_from_slice(&pending.body[..body_len]);
            }
            // No `channel_poll` pre-check: it reports ≥1 byte free, not
            // room for this frame, so it can neither authorise nor
            // forbid the write. `channel_write_msg` is all-or-nothing
            // and its return value is the only true answer.
            let w = wire_channels::channel_write_msg(
                sys,
                s.out_committed_entries,
                wire::MSG_COMMITTED_ENTRY,
                &s.msg_buf[..16 + body_len],
            );
            if w > 0 {
                s.pending[slot_idx].delivered |= DELIVERED_STREAM;
            }
        }
    }

    if s.pending[slot_idx].delivered != DELIVERED_ALL {
        return false;
    }

    s.apply_index = index;
    s.entries_applied += 1;
    // Apply signal — the only external proof a committed entry
    // actually reached the state machine, distinct from `[wal] entry
    // ok` (durable-but-not-yet-applied) and `[raft] prop` (proposed-
    // but-not-yet-committed). Fires once per applied entry regardless
    // of which downstream ports are wired. Debug level: per-entry
    // hot-path syscall (test harnesses opt in via RUST_LOG=debug).
    dev_log(sys, 4, b"[apply] ok".as_ptr(), 10);
    s.pending[slot_idx] = PendingEntry::empty();
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` (or shared
/// `&Apply` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_permits(s: &mut Apply, sys: &SyscallTable, now: u64) {
    // The read gate emits MSG_READ_PERMIT every step the CP cache is
    // Fresh or Cached, with payload `[cache_state:u8]`. We track the
    // most recent observation; the read-ready check refuses to surface
    // reads that haven't seen a permit within READ_PERMIT_TTL_MS.
    if s.in_read_permits < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_read_permits, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_read_permits, &mut s.msg_buf);
        if msg_type != wire::MSG_READ_PERMIT || (plen as usize) < 1 { continue; }
        s.last_permit_state = s.msg_buf[0];
        s.last_permit_ms = now;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` (or shared
/// `&Apply` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_submissions(s: &mut Apply, sys: &SyscallTable, now: u64) {
    if s.in_reads < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_reads, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_reads, &mut s.msg_buf);
        if msg_type != wire::MSG_CLIENT_READ_REQUEST { continue; }
        if (plen as usize) < wire::TAGGED_PROPOSAL_HDR { continue; }
        let corr_id = u64::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
        ]);
        if corr_id == 0 { continue; }

        // Strict ReadIndex path (RFC §1.3): issue a probe to raft
        // and stash the read in AWAITING_PROBE. The probe round-trip
        // confirms leadership at the moment the read was submitted, so
        // a partitioned former leader can't serve a stale answer.
        //
        // The probe seam (E7) is always wired in-module; a full probe
        // queue degrades to the legacy submission-time commit horizon
        // for this read — the same fallback the full channel produced.
        if issue_read_probe(s, sys, corr_id) {
            enqueue_read(s, sys, corr_id, 0, now, READ_PHASE_AWAITING_PROBE);
        } else {
            // Probe queue full → degrade to legacy for this read.
            enqueue_read(s, sys, corr_id, s.commit_horizon, now, READ_PHASE_LEGACY);
        }
    }
}

/// Queue a strict-ReadIndex probe request for raft (seam E7).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` per the module ABI.
unsafe fn issue_read_probe(s: &mut Apply, _sys: &SyscallTable, correlation_id: u64) -> bool {
    if (s.probe_out_count as usize) >= PROBE_QUEUE_SLOTS { return false; }
    s.probe_out[s.probe_out_count as usize] = correlation_id;
    s.probe_out_count += 1;
    true
}

/// Consume strict-ReadIndex probe replies from raft's reply queue
/// (seam E8). ≤8 per step — the queue is one step deep.
///
/// # Safety
///
/// Caller must hold exclusive borrows and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_probe_replies(
    s: &mut Apply,
    sys: &SyscallTable,
    replies: &mut [(u64, u64, u8); PROBE_QUEUE_SLOTS],
    reply_count: &mut u8,
) {
    let n = (*reply_count as usize).min(PROBE_QUEUE_SLOTS);
    for k in 0..n {
        let (corr_id, confirmed_commit, confirmed_byte) = replies[k];
        let confirmed = confirmed_byte != 0;
        // Find the AWAITING_PROBE slot for this correlation id.
        let mut slot_idx: Option<usize> = None;
        for (i, slot) in s.pending_reads.iter().enumerate() {
            if slot.is_empty() { continue; }
            if slot.correlation_id == corr_id { slot_idx = Some(i); break; }
        }
        let Some(i) = slot_idx else { continue };
        if !confirmed {
            // Probe failed — reject with FALLBACK.
            let corr = s.pending_reads[i].correlation_id;
            let _ = emit_read_reject(s, sys, corr, wire::CLIENT_REJECT_FALLBACK);
            s.pending_reads[i] = PendingRead::empty();
            s.reads_timed_out += 1;
        } else {
            s.pending_reads[i].required_commit = confirmed_commit;
            s.pending_reads[i].phase = READ_PHASE_ARMED;
        }
    }
    *reply_count = 0;
}

unsafe fn enqueue_read(
    s: &mut Apply,
    sys: &SyscallTable,
    correlation_id: u64,
    required_commit: Index,
    submitted_ms: u64,
    phase: u8,
) {
    for slot in s.pending_reads.iter_mut() {
        if slot.is_empty() {
            *slot = PendingRead { correlation_id, required_commit, submitted_ms, phase };
            s.reads_enqueued += 1;
            return;
        }
    }
    // Full — evict the oldest read (smallest submitted_ms) and REJECT
    // it so the submitter can fail closed instead of leaking a stashed
    // read that never resolves (a silent eviction would leave the
    // router's fence slot AWAITING forever). Best-effort: if the reject
    // channel is full the victim still vanishes, but the submitter's
    // own stash deadline covers that residue.
    let mut victim: usize = 0;
    let mut victim_ms = u64::MAX;
    for (i, slot) in s.pending_reads.iter().enumerate() {
        if slot.submitted_ms < victim_ms {
            victim_ms = slot.submitted_ms;
            victim = i;
        }
    }
    let victim_corr = s.pending_reads[victim].correlation_id;
    if victim_corr != 0 {
        let _ = emit_read_reject(s, sys, victim_corr, wire::CLIENT_REJECT_FALLBACK);
    }
    s.pending_reads[victim] = PendingRead { correlation_id, required_commit, submitted_ms, phase };
    s.reads_evicted += 1;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` (or shared
/// `&Apply` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_pending_reads(s: &mut Apply, sys: &SyscallTable, now: u64) {
    if s.out_applied < 0 { return; }
    let permit_fresh = s.last_permit_ms != 0
        && now.wrapping_sub(s.last_permit_ms) <= READ_PERMIT_TTL_MS;

    for i in 0..PENDING_READ_SLOTS {
        let slot = s.pending_reads[i];
        if slot.is_empty() { continue; }

        // Awaiting probe: don't surface yet. The probe-reply path will
        // either arm us or reject. We still observe the read-timeout
        // below so a stuck probe doesn't pile up forever.
        if slot.phase == READ_PHASE_AWAITING_PROBE {
            if now.wrapping_sub(slot.submitted_ms) > READ_TIMEOUT_MS {
                if emit_read_reject(s, sys, slot.correlation_id, wire::CLIENT_REJECT_FALLBACK) {
                    s.pending_reads[i] = PendingRead::empty();
                    s.reads_timed_out += 1;
                }
            }
            continue;
        }

        // Ready: linearization point reached AND CP fresh.
        if permit_fresh && s.apply_index >= slot.required_commit {
            if emit_read_response(s, sys, slot.correlation_id, slot.required_commit) {
                s.pending_reads[i] = PendingRead::empty();
                s.reads_completed += 1;
            }
            continue;
        }

        // Timeout: still waiting after READ_TIMEOUT_MS — reject so the
        // client doesn't hang. CP-fallback is the canonical reason.
        if now.wrapping_sub(slot.submitted_ms) > READ_TIMEOUT_MS {
            if emit_read_reject(s, sys, slot.correlation_id, wire::CLIENT_REJECT_FALLBACK) {
                s.pending_reads[i] = PendingRead::empty();
                s.reads_timed_out += 1;
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` (or shared
/// `&Apply` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_read_response(
    s: &mut Apply,
    sys: &SyscallTable,
    correlation_id: u64,
    required_commit: u64,
) -> bool {
    let poll = (sys.channel_poll)(s.out_applied, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    // `[correlation_id:u64][required_commit:u64]`.
    //
    // The index is what makes this a fence a caller can actually
    // enforce. Consensus releasing the read means CONSENSUS has applied
    // through `required_commit` — it says nothing about the application
    // state machine downstream, which receives committed entries over a
    // channel and applies them on its own schedule. A reader that treats
    // the release alone as permission can therefore query a state
    // machine that has not yet seen the write it is supposed to observe,
    // and read a false absence. Naming the index lets the application
    // hold the read until its own applied position has caught up.
    //
    // The correlation id leads, so a consumer that only routes (the
    // gateway codec) parses the 8-byte prefix and ignores the index.
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&correlation_id.to_le_bytes());
    buf[8..].copy_from_slice(&required_commit.to_le_bytes());
    // The poll above only proves ≥1 byte free; success is the WRITE
    // landing, or the caller retires the read and hangs its client.
    wire_channels::channel_write_msg(sys, s.out_applied, wire::MSG_CLIENT_READ_RESPONSE, &buf) > 0
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Apply` (or shared
/// `&Apply` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_read_reject(s: &mut Apply, sys: &SyscallTable, correlation_id: u64, status: u8) -> bool {
    let poll = (sys.channel_poll)(s.out_applied, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    let mut env = [0u8; wire::CLIENT_REJECT_INTERNAL_LEN];
    wire::encode_client_reject_internal(&mut env, correlation_id, status, 0, 0, 0);
    // See emit_read_response: success is the confirmed write, not the poll.
    wire_channels::channel_write_msg(
        sys, s.out_applied,
        wire::MSG_CLIENT_REJECT_INTERNAL,
        &env[..wire::CLIENT_REJECT_INTERNAL_LEN],
    ) > 0
}
