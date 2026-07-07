//! Apply Pipeline — Ordered, deduplicated delivery of committed entries
//! to embedded state machines (quantum / lattice / loam) and to any
//! consumer that wires into the per-entry `committed_entries` port.
//! Also hosts the linearizable-read queue described in RFC §4.3.
//!
//! Inputs:
//!   in[0]  CommittedBatch       — commit horizon updates from commit_tracker
//!   in[1]  ReadPermit           — CP-cache freshness signal from read_gate
//!   in[2]  WalEntry (observe)   — raw appended entries fan-out from raft_engine
//!   in[3]  ClientReadRequest    — tagged read submissions from client_codec
//!
//! Outputs:
//!   out[0] ClientResponse /     — apply acks (term,index) plus
//!          ClientReadResponse     MSG_CLIENT_READ_RESPONSE / MSG_CLIENT_REJECT_INTERNAL
//!                                 for queued reads that have reached their
//!                                 linearization point (or timed out).
//!   out[1] CommittedEntry       — per-entry stream `[term][index][body]`
//!
//! The per-entry stream is what downstream consumers (Loam, Lattice,
//! the example_consumer module, anything using `replica_facade.rs`)
//! subscribe to in order to actually apply commands. Without it, the
//! consumer only knows commit horizons and can't reproduce state.
//!
//! ## Linearizable read semantics
//!
//! When a `MSG_CLIENT_READ_REQUEST` arrives on `read_in`, the read is
//! enqueued together with the current `commit_horizon` as its required
//! ReadIndex linearization point. A read becomes ready when:
//!   1. `apply_index >= required_commit`, AND
//!   2. We have observed a `MSG_READ_PERMIT` from `read_gate` within
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

#[path = "../../common/types.rs"]
mod types;

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use types::*;

define_params! {
    ModuleState;

    // Partition this apply pipeline belongs to. Stamped into internal
    // MSG_CLIENT_RESPONSE acks so client_codec can correlate
    // `(partition_id, wal_index)` without collisions in multi-partition
    // graphs. Default 0 preserves single-partition configs.
    1, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };
}

const DEDUP_SHARDS: usize = 16;

/// Maximum body size held in a pending-entry slot. Mirrors the leader's
/// `PROPOSAL_BATCH_CAP` so any batch raft_engine can flush also fits
/// here unmodified.
const PENDING_BODY_CAP: usize = 2048;

/// Number of pending entries buffered awaiting commit. Sized to absorb
/// the typical in-flight window between WAL persist and quorum commit.
/// When the buffer is full and a new entry arrives, the oldest
/// un-emitted slot is evicted — observers fail open. The eviction is
/// safe because consumers MUST tolerate gaps and recover from the
/// monotonic index in the per-entry stream.
const PENDING_ENTRY_SLOTS: usize = 32;

/// Bounded linearizable-read queue. Sized to absorb the
/// read-submission window between client_codec submit and the moment
/// `apply_index` catches the submission's commit horizon.
const PENDING_READ_SLOTS: usize = 16;

/// How long a read may sit without observing a fresh CP permit before
/// it gets rejected with `CLIENT_REJECT_FALLBACK`. 5 s matches the
/// CP-bridge "Fresh" tier refresh budget.
const READ_TIMEOUT_MS: u64 = 5_000;

/// CP permit "freshness" TTL — if we haven't seen a permit in this
/// many ms, treat the cache as stale and refuse new ready-emit.
const READ_PERMIT_TTL_MS: u64 = 1_000;
const METRICS_INTERVAL_MS: u64 = 1_000;

/// Minimum spacing between re-issues of the SAME missing-index WAL refetch
/// request. One request is outstanding at a time; if its reply is lost or
/// the WAL is momentarily busy we re-ask after this window rather than every
/// step (which would flood `wal.entry_request`). At tick_us=6000 this is
/// ~8 steps — comfortably longer than a WAL serve round-trip.
const ENTRY_REFETCH_RETRY_MS: u64 = 50;

#[repr(C)]
#[derive(Clone, Copy)]
struct PendingEntry {
    /// 0 = slot empty.
    index: Index,
    term: Term,
    body_len: u16,
    body: [u8; PENDING_BODY_CAP],
}

impl PendingEntry {
    const fn empty() -> Self {
        Self {
            index: 0,
            term: 0,
            body_len: 0,
            body: [0u8; PENDING_BODY_CAP],
        }
    }

    fn is_empty(&self) -> bool {
        self.index == 0
    }
}

/// Phase of a pending read:
///   0 = AWAITING_PROBE: probe issued to raft_engine, waiting for reply.
///   1 = ARMED: probe confirmed, `required_commit` set, waiting on
///       `apply_index` to catch up.
///   2 = LEGACY: no probe path wired — submission-time `commit_horizon`
///       was used directly. Behaves like phase 1 but never times out
///       waiting for a probe.
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
struct ModuleState {
    syscalls: *const SyscallTable,

    // ── Channels (5 in, 3 out) ────────────────────────────────
    in_entries: i32,            // in[0]: CommittedBatch from commit_tracker
    in_read_permits: i32,       // in[1]: ReadPermit from read_gate
    in_log_entries: i32,        // in[2]: WalEntry fan-out from raft_engine.log_observe
    in_reads: i32,              // in[3]: MSG_CLIENT_READ_REQUEST from client_codec
    in_read_probe_reply: i32,   // in[4]: MSG_READ_PROBE_REPLY from raft_engine
    in_entry_reply: i32,        // in[5]: MSG_WAL_ENTRY_REPLY from wal.entry_reply (gap refetch)
    out_applied: i32,           // out[0]: response stream to client_codec
    out_committed_entries: i32, // out[1]: per-entry MSG_COMMITTED_ENTRY stream
    out_read_probe_request: i32,// out[2]: MSG_READ_PROBE_REQ to raft_engine
    out_admin_committed: i32,   // out[3]: MSG_ADMIN_COMMITTED for ADMIN_MARKER bodies
    out_metrics: i32,           // out[4]: MSG_METRIC_SAMPLE to telemetry_agg
    out_entry_request: i32,     // out[5]: MSG_WAL_ENTRY_REQUEST to wal.entry_request (gap refetch)

    partition_id: u16,

    // ── Gap refetch (apply-side WAL read-back) ────────────────
    /// Index currently being refetched from the WAL (0 = none). At most one
    /// outstanding request; cleared when the matching reply arrives.
    awaiting_entry: Index,
    /// Monotone request id stamped into each MSG_WAL_ENTRY_REQUEST.
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

    // ── Metrics ───────────────────────────────────────────────
    last_metrics_ms: u64,
    /// `clustor.flow.apply_batch_latency_ms` cumulative bucket counts
    /// (RFC §4.1): wall time of each `drain_committed_batches` pass that
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
        s.in_entries = in_chan;
        s.out_applied = out_chan;
        s.in_read_permits = dev_channel_port(sys, 0, 1);
        s.in_log_entries = dev_channel_port(sys, 0, 2);
        s.in_reads = dev_channel_port(sys, 0, 3);
        s.in_read_probe_reply = dev_channel_port(sys, 0, 4);
        s.in_entry_reply = dev_channel_port(sys, 0, 5);
        s.out_committed_entries = dev_channel_port(sys, 1, 1);
        s.out_read_probe_request = dev_channel_port(sys, 1, 2);
        s.out_admin_committed = dev_channel_port(sys, 1, 3);
        s.out_metrics = dev_channel_port(sys, 1, 4);
        s.out_entry_request = dev_channel_port(sys, 1, 5);
        s.awaiting_entry = 0;
        s.entry_request_id = 0;
        s.last_entry_request_ms = 0;
        s.entries_refetched = 0;
        s.apply_batch_buckets = [0u32; wire::hist::APPLY_BATCH_US.len() + 1];
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        s.apply_index = 0;
        s.commit_horizon = 0;
        s.commit_term = 0;
        s.last_permit_ms = 0;
        s.last_permit_state = 0;
        for slot in s.pending.iter_mut() {
            *slot = PendingEntry::empty();
        }
        for slot in s.pending_reads.iter_mut() {
            *slot = PendingRead::empty();
        }
        dev_log(sys, 3, b"[apply] init".as_ptr(), 12);
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
        let now = dev_millis(sys);
        let work_before = s.entries_applied;

        // 1) Drain per-entry observer fanout first so the buffer is
        //    populated before we evaluate commit horizons.
        drain_log_entries(s, sys);

        // 1b) Insert any WAL refetch replies for entries the lossy observer
        //     fan-out dropped, then attempt to apply — so progress continues
        //     even when no new commit batch arrives this step.
        drain_entry_replies(s, sys);
        drain_pending_entries(s, sys);

        // 2) Drain commit-horizon updates and emit per-entry committed
        //    messages for any buffered entries with index <= horizon.
        //    Time the pass and fold it into the apply-batch histogram
        //    when it actually applied entries (RFC §4.1).
        let applied_before = s.entries_applied;
        let batch_start = dev_micros(sys);
        drain_committed_batches(s, sys);
        if s.entries_applied != applied_before {
            let elapsed = dev_micros(sys).wrapping_sub(batch_start);
            let b = wire::hist::bucket(&wire::hist::APPLY_BATCH_US, elapsed);
            s.apply_batch_buckets[b] = s.apply_batch_buckets[b].saturating_add(1);
        }

        // 3) Track CP read permits — used to gate the read queue.
        drain_read_permits(s, sys, now);

        // 4) Accept new linearizable-read submissions from client_codec.
        drain_read_submissions(s, sys, now);

        // 4b) Pick up any strict-ReadIndex probe replies that have
        //     arrived from raft_engine and arm or reject the matching
        //     pending read accordingly.
        drain_read_probe_replies(s, sys);

        // 5) Drain reads whose linearization point has been reached
        //    (apply_index ≥ required_commit AND CP permit is fresh),
        //    plus reject any that have timed out without freshness.
        drain_pending_reads(s, sys, now);

        // 6) Periodic metrics (RFC §4.1/§4.2).
        emit_metrics(s, sys, now);
        if s.entries_applied != work_before {
            dev_report_step_effect(sys, step_effect::WORK_DONE);
        }

        0
    }
}

/// Emit apply counters, the queue-depth gauge, and the apply-batch
/// latency histogram as typed samples (RFC §4.3). Partition-stamped so
/// per-partition apply_pipelines don't collide. Dropped under
/// backpressure — telemetry never stalls the apply path.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // Current queue depth: occupied pending-entry slots (index != 0).
    let mut depth: i64 = 0;
    for e in s.pending.iter() {
        if e.index != 0 { depth += 1; }
    }

    let mid = wire::MODULE_ID_APPLY_PIPELINE;
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
    s: &ModuleState,
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_log_entries(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_log_entries < 0 {
        return;
    }
    for _ in 0..16 {
        // Preserve the oldest not-yet-applied entries when the local join
        // buffer is saturated: reading another observer frame here would
        // evict the lowest index, which is exactly the entry strict-order
        // apply needs next.  Leaving the frame on the channel propagates
        // pressure through the graph; if the lossy Raft observer skips a
        // later frame, the WAL refetch path recovers that later gap.
        // The commit input is drained later in this same step and can free
        // slots without a manifest-specific buffer-size assumption.
        if !s.pending.iter().any(PendingEntry::is_empty) {
            drain_pending_entries(s, sys);
            if !s.pending.iter().any(PendingEntry::is_empty) {
                break;
            }
        }
        let poll = (sys.channel_poll)(s.in_log_entries, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_log_entries, &mut s.msg_buf);
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
fn apply_pipeline_reset(s: &mut ModuleState, term: Term, index: Index) {
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
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn store_pending(
    s: &mut ModuleState,
    term: Term,
    index: Index,
    body_len: usize,
) -> bool {
    // First pass: same-index replacement (follower truncate-then-append).
    for slot in s.pending.iter_mut() {
        if !slot.is_empty() && slot.index == index {
            slot.term = term;
            slot.body_len = body_len as u16;
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_committed_batches(s: &mut ModuleState, sys: &SyscallTable) {
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_entries, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
        if (plen as usize) < 16 { continue; }
        if msg_type == wire::MSG_APPLY_PIPELINE_RESET {
            let (term, index) = wire::decode_term_index(&s.msg_buf);
            apply_pipeline_reset(s, term, index);
            continue;
        }
        if msg_type != wire::MSG_COMMITTED_BATCH {
            continue;
        }
        let (term, index) = wire::decode_term_index(&s.msg_buf);

        // Dedup horizon advances per-shard (legacy behaviour preserved).
        let shard = (index as usize) % DEDUP_SHARDS;
        if index <= s.dedup_shards[shard] {
            continue;
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
}

/// Apply buffered entries in strict ascending order up to the commit
/// horizon. When the next-needed index (`apply_index + 1`) is missing from
/// the observer buffer — the best-effort `log_observe` fan-out dropped its
/// body under overdrive — request it back from the durable WAL via
/// `entry_request` instead of stalling forever. The reply lands on
/// `entry_reply`, is reinserted into `pending` by `drain_entry_replies`, and
/// applied on a subsequent pass. Data is never lost (the entry is durable in
/// the WAL); this keeps apply LIVE under commit-outruns-apply overdrive.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_pending_entries(s: &mut ModuleState, sys: &SyscallTable) {
    loop {
        // A committed entry is not retired until its per-index apply
        // acknowledgement can be published. This makes grouped commit
        // advances lossless for synchronous clients: every proposal gets an
        // ack, not only the highest index in a committed batch.
        if s.out_applied >= 0 {
            let poll = (sys.channel_poll)(s.out_applied, 0x02);
            if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        }
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
                emit_committed_entry(s, sys, slot_idx);
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
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn request_missing_entry(s: &mut ModuleState, sys: &SyscallTable, index: Index) {
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
    wire::encode_wal_entry_request(&mut buf, s.entry_request_id, index);
    let w = wire_channels::channel_write_msg(
        sys, s.out_entry_request, wire::MSG_WAL_ENTRY_REQUEST, &buf,
    );
    if w > 0 {
        s.awaiting_entry = index;
        s.last_entry_request_ms = now;
    }
}

/// Consume WAL refetch replies (`MSG_WAL_ENTRY_REPLY`) and reinsert their
/// bodies into the pending buffer so the next apply pass can deliver them.
/// The reply body is the raw proposal body (the WAL stripped the 16-byte
/// term/index header), so it is staged at `msg_buf[16..]` to match
/// `store_pending`'s fixed slice.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_entry_replies(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_entry_reply < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_entry_reply, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_entry_reply, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_ENTRY_REPLY { continue; }
        let plen = plen as usize;
        let (_req_id, term, index, _prev_term, hdr) =
            match wire::decode_wal_entry_reply(&s.msg_buf[..plen]) {
                Some(v) => v,
                None => continue,
            };
        if index == 0 { continue; }
        if plen <= hdr {
            // NOT_FOUND (below WAL retention) — the gap stands. Leave
            // awaiting_entry SET so request_missing_entry's retry throttle
            // holds the re-request to once per ENTRY_REFETCH_RETRY_MS rather
            // than re-requesting on the very next drain — which would flood
            // wal.entry_request for a permanent gap.
            continue;
        }
        // A real entry resolves the outstanding request, so the next gap can
        // be refetched immediately.
        if index == s.awaiting_entry { s.awaiting_entry = 0; }
        if index <= s.apply_index { continue; } // already applied
        let body_len = (plen - hdr).min(PENDING_BODY_CAP);
        // Relocate the body from the 20-byte-reply-header offset to offset 16
        // (forward copy, dest < src, so non-overlapping-safe) for store_pending.
        s.msg_buf.copy_within(hdr..hdr + body_len, 16);
        if store_pending(s, term, index, body_len) {
            s.entries_refetched = s.entries_refetched.saturating_add(1);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_committed_entry(s: &mut ModuleState, sys: &SyscallTable, slot_idx: usize) {
    let slot = s.pending[slot_idx];
    let body_len = slot.body_len as usize;

    // Admin-replicated entries (RFC §3.1) start with `ADMIN_MARKER`.
    // Config-change entries (RFC §1.2) start with `CONFIG_CHANGE_MARKER`.
    // Both fan out on the `admin_committed` port back to raft_engine;
    // the distinct msg_type tells the engine which path applies.
    if body_len >= 1 && s.out_admin_committed >= 0 {
        let marker = slot.body[0];
        if marker == wire::ADMIN_MARKER && body_len >= 6 {
            let poll = (sys.channel_poll)(s.out_admin_committed, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(
                    sys,
                    s.out_admin_committed,
                    wire::MSG_ADMIN_COMMITTED,
                    &slot.body[1..body_len],
                );
            }
        } else if marker == wire::CONFIG_CHANGE_MARKER && body_len >= 3 {
            let poll = (sys.channel_poll)(s.out_admin_committed, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                // Re-emit the body verbatim — the marker stays so
                // raft_engine can validate with `decode_config_change`.
                wire_channels::channel_write_msg(
                    sys,
                    s.out_admin_committed,
                    wire::MSG_CONFIG_COMMITTED,
                    &slot.body[..body_len],
                );
            }
        }
    }

    if s.out_committed_entries >= 0 {
        let poll = (sys.channel_poll)(s.out_committed_entries, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            // Reuse msg_buf as the scratch envelope: 16-byte header + body.
            wire::encode_term_index(&mut s.msg_buf, slot.term, slot.index);
            if body_len > 0 {
                s.msg_buf[16..16 + body_len].copy_from_slice(&slot.body[..body_len]);
            }
            wire_channels::channel_write_msg(
                sys,
                s.out_committed_entries,
                wire::MSG_COMMITTED_ENTRY,
                &s.msg_buf[..16 + body_len],
            );
        }
        // If the channel is full, drop on the floor — fail-open. The
        // entry remains durable in the WAL and the consumer can refetch
        // via a snapshot install when it recovers.
    }

    if s.out_applied >= 0 {
        let mut resp = [0u8; 18];
        resp[0..2].copy_from_slice(&s.partition_id.to_le_bytes());
        wire::encode_term_index(&mut resp[2..18], slot.term, slot.index);
        wire_channels::channel_write_msg(
            sys, s.out_applied, wire::MSG_CLIENT_RESPONSE, &resp,
        );
    }

    s.apply_index = slot.index;
    s.entries_applied += 1;
    // Apply signal — the only external proof a committed entry
    // actually reached the state machine, distinct from `[wal] entry
    // ok` (durable-but-not-yet-applied) and `[raft] prop` (proposed-
    // but-not-yet-committed). Fires once per applied entry regardless
    // of which downstream ports are wired.
    dev_log(sys, 3, b"[apply] ok".as_ptr(), 10);
    s.pending[slot_idx] = PendingEntry::empty();
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_permits(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    // `read_gate` emits MSG_READ_PERMIT every step the CP cache is
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
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_submissions(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
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

        // Strict ReadIndex path (RFC §1.3): issue a probe to raft_engine
        // and stash the read in AWAITING_PROBE. The probe round-trip
        // confirms leadership at the moment the read was submitted, so
        // a partitioned former leader can't serve a stale answer.
        //
        // Falls back to the legacy submission-time commit horizon when
        // the probe ports aren't wired (apply_pipeline configs without
        // a back-edge to raft_engine).
        if s.out_read_probe_request >= 0 && s.in_read_probe_reply >= 0 {
            if issue_read_probe(s, sys, corr_id) {
                enqueue_read(s, sys, corr_id, 0, now, READ_PHASE_AWAITING_PROBE);
            } else {
                // Probe channel full → degrade to legacy for this read.
                enqueue_read(s, sys, corr_id, s.commit_horizon, now, READ_PHASE_LEGACY);
            }
        } else {
            enqueue_read(s, sys, corr_id, s.commit_horizon, now, READ_PHASE_LEGACY);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn issue_read_probe(s: &ModuleState, sys: &SyscallTable, correlation_id: u64) -> bool {
    if s.out_read_probe_request < 0 { return false; }
    let poll = (sys.channel_poll)(s.out_read_probe_request, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    let buf = correlation_id.to_le_bytes();
    let w = wire_channels::channel_write_msg(
        sys, s.out_read_probe_request, wire::MSG_READ_PROBE_REQ, &buf,
    );
    w > 0
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_probe_replies(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_read_probe_reply < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_read_probe_reply, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_read_probe_reply, &mut s.msg_buf);
        if msg_type != wire::MSG_READ_PROBE_REPLY { continue; }
        let (corr_id, confirmed_commit, confirmed) =
            match wire::decode_read_probe_reply(&s.msg_buf[..plen as usize]) {
                Some(v) => v,
                None => continue,
            };
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
}

unsafe fn enqueue_read(
    s: &mut ModuleState,
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
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_pending_reads(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
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
            if emit_read_response(s, sys, slot.correlation_id) {
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
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_read_response(s: &mut ModuleState, sys: &SyscallTable, correlation_id: u64) -> bool {
    let poll = (sys.channel_poll)(s.out_applied, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&correlation_id.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_applied, wire::MSG_CLIENT_READ_RESPONSE, &buf);
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_read_reject(s: &mut ModuleState, sys: &SyscallTable, correlation_id: u64, status: u8) -> bool {
    let poll = (sys.channel_poll)(s.out_applied, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    let mut env = [0u8; wire::CLIENT_REJECT_INTERNAL_LEN];
    wire::encode_client_reject_internal(&mut env, correlation_id, status, 0, 0, 0);
    wire_channels::channel_write_msg(
        sys, s.out_applied,
        wire::MSG_CLIENT_REJECT_INTERNAL,
        &env[..wire::CLIENT_REJECT_INTERNAL_LEN],
    );
    true
}
