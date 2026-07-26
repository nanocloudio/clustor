//! wal — write-ahead log component.
//!
//! Accepts log entries from consensus, frames each as
//! `[len:u32][crc32c:u32][payload]` to a segment file, and emits flushed
//! acks downstream. Replay recomputes the per-entry CRC32C and stops at the
//! first torn/corrupt frame so a partial tail is never replayed as valid.
//!
//! Durability evidence flows two ways: externally on the `flushed`
//! port (raft's own durable-index leg) and in-module to the
//! [`ledger`](super::ledger) component via a monotone latest-wins
//! latch drained by the dispatch table each step. Segment-rotation
//! snapshot triggers reach the [`snapshot`](super::snapshot)
//! component the same way (and externally on `compaction_signal` for
//! downstream coordinators).
//!
//! The `volatile` variant selects the in-memory retention path at
//! compile time (`VOLATILE`): entries are retained in the memory ring
//! for gap refetch and acknowledged immediately — the ack IS the
//! durability point, and the composite structurally cannot emit a
//! quorum durability proof (the ledger component is compiled out).
//! In the `disk` variant the same in-memory path remains the
//! fallback for graphs with no FS provider.

use super::abi::SyscallTable;
use super::collections::Crc32c;
use super::types::{Index, Term};
use super::{
    dev_input_flow_budget, dev_log, dev_micros, dev_millis, dev_report_step_effect,
    fmt_u32_raw, step_effect, wire, wire_channels, POLL_IN, POLL_OUT,
};

/// Compile-time variant selector: the `volatile` variant retains
/// entries in memory by design (never as a fallback).
pub const VOLATILE: bool = cfg!(feature = "volatile");

/// Record the durable high-water for the ledger component. Monotone
/// latest-wins; the dispatch table drains the latch after this
/// component's step.
fn note_ledger_ack(s: &mut Wal, term: Term, index: Index) {
    if index >= s.ledger_ack.1 {
        s.ledger_ack = (term, index);
        s.ledger_dirty = true;
    }
}

/// Record a segment-rotation snapshot trigger for the snapshot
/// component. Latest-wins.
fn note_trigger(s: &mut Wal, term: Term, index: Index) {
    s.snap_trigger = (term, index);
    s.snap_trigger_dirty = true;
}

// Holds a complete maximum-sized four-entry durability group (4 * (8-byte
// frame header + 2064-byte WAL payload) ≈ 8.3 KiB) plus a replay terminator,
// rounded up to a power of two. Sizing this to `group_max_pending=4` is what
// turns the group into one provider write instead of merely grouping its
// fsync.
const WRITE_BUF_SIZE: usize = 16 * 1024;
const METRICS_INTERVAL_MS: u64 = 1000;

/// Max fence-pipelining depth. Bounds the outstanding-fence ring; the effective
/// depth is `min(fence_depth config, FENCE_RING_MAX, nvme ASYNC_BULK_SLOTS)`.
const FENCE_RING_MAX: usize = 8;

/// The MSG_WAL_REPLAY_COMPLETE handshake to raft is re-emitted on this
/// wall-clock cadence (not one-shot): across a cross-domain SPSC bridge
/// the consumer's port may not be live at the instant the WAL first
/// emits, and a lone message written before the first consumer pump can
/// be missed — permanently wedging proposal intake (raft stays
/// `awaiting_replay`). raft ignores duplicates once it has resumed, so
/// re-emitting is idempotent. Bounded by REPLAY_REEMIT_MAX_ATTEMPTS.
const REPLAY_REEMIT_MS: u64 = 20;
const REPLAY_REEMIT_MAX_ATTEMPTS: u32 = 256;

/// Power of two so `index % RING_SIZE` is a cheap mask. Sized to cover
/// the last few seconds of a hot writer without inflating module state.
const ENTRY_RING_SIZE: usize = 256;
const ENTRY_RING_MASK: u64 = (ENTRY_RING_SIZE as u64) - 1;
const MEMORY_ENTRY_BODY_CAP: usize = 2048;

/// WCET/fairness backstop for the transaction-budgeted input pump. The byte
/// grant is the pacing authority; this cap only bounds the number of provider
/// calls when records are very small. Eight records still removes the
/// one-record-per-tick ceiling while keeping a worst-case step auditable.
const MAX_ENTRY_PUMP_RECORDS: usize = 8;

#[derive(Clone, Copy)]
#[repr(C)]
struct EntryLoc {
    /// Log index. 0 means slot is empty.
    index: u64,
    term: u64,
    /// WAL segment file this entry lives in.
    seg_seq: u32,
    /// Byte offset of the entry payload (after the 4-byte length prefix)
    /// within the segment file.
    payload_offset: u32,
    /// Length in bytes of the entry payload (the [term:u64][index:u64][body...]
    /// blob that was written to the file).
    payload_len: u32,
}

impl EntryLoc {
    const fn zero() -> Self {
        Self { index: 0, term: 0, seg_seq: 0, payload_offset: 0, payload_len: 0 }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct MemoryEntry {
    index: u64,
    body_len: u16,
    body: [u8; MEMORY_ENTRY_BODY_CAP],
}

impl MemoryEntry {
    const fn zero() -> Self {
        Self { index: 0, body_len: 0, body: [0; MEMORY_ENTRY_BODY_CAP] }
    }
}

// FS opcodes (from abi::dev_fs)
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
/// Write-side opener. `FS_OPEN` is read-only-if-exists per the FS
/// contract (see `target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs`),
/// so a fresh WAL with no segment file on disk silently degrades to
/// in-memory; segment creation needs the write tier.
const FS_OPEN_CREATE: u32 = 0x0909;
/// Remove a file by path (`modules/sdk/contracts/storage/fs.rs::UNLINK`).
/// Gated on the provider's `caps::UNLINK` bit — see `fs_unlink_supported`.
const FS_UNLINK: u32 = 0x090A;
const FS_PREALLOCATE: u32 = 0x090E;
/// Async durable-write tier (`fs.rs::{WRITE_ASYNC, FSYNC_SUBMIT,
/// FSYNC_POLL}` + `caps::FSYNC_ASYNC`). Used only when the FS provider
/// advertises `FS_CAP_FSYNC_ASYNC`; otherwise the WAL keeps the
/// synchronous FS_WRITE + FS_FSYNC path unchanged.
const FS_WRITE_ASYNC: u32 = 0x090F;
const FS_FSYNC_SUBMIT: u32 = 0x0910;
const FS_FSYNC_POLL: u32 = 0x0911;
const FS_CAP_FSYNC_ASYNC: u32 = 1 << 10;
/// FS capability-discovery opcode + the `UNLINK` bit
/// (`modules/sdk/contracts/storage/fs.rs::{CAPS, caps::UNLINK}`).
const FS_CAPS: u32 = 0x09FF;
const FS_CAP_UNLINK: u32 = 1 << 5;

/// FS E_AGAIN: the FS provider is present but still initialising (e.g. fat32
/// reading the BPB/GPT/root on a cm5 cold boot). Distinct from a hard error
/// (ENODEV/ENOSYS = no provider). On E_AGAIN the WAL WAITS — it holds new
/// entries (raft backpressures) and retries the segment open every step —
/// rather than degrading to in-memory, which would drop durability once the
/// provider came up. Mirrors the kernel `errno::EAGAIN`.
const FS_E_AGAIN: i32 = -11;

const WAL_PATH_MAX: usize = 48;

// Module phases
const PHASE_REPLAY: u8 = 0;
const PHASE_NORMAL: u8 = 1;

/// `module_step` return code for `StepOutcome::Burst` (kernel ABI:
/// 0=Continue, 1=Done, 2=Burst, 3=Ready). Replay returns this from any
/// step that performed an `FS_OPEN` so the scheduler forgives the
/// one-time cold directory-scan penalty (see `step_replay`).
const STEP_BURST: i32 = 2;

/// How many consecutive missing segments the replay scanner
/// tolerates before declaring "no more segments". Replay walks
/// from `replay_seg = 1` and probes each sequence number; a real
/// gap in the segment file set (e.g. seqs 3 and 4 deleted by
/// compaction) shouldn't truncate the rebuilt log. Sixteen
/// consecutive misses cover ordinary post-compaction layouts
/// without making startup unboundedly slow when the WAL is
/// genuinely empty.
const REPLAY_GAP_TOLERANCE: u8 = 16;

#[repr(C)]
pub struct Wal {
    // Channels (composite indices per `mod.rs::module_new`)
    pub in_entries: i32,        // in[0]: WalEntry from consensus
    pub in_entry_request: i32,  // in[1]: MSG_WAL_ENTRY_REQUEST (replicator NACK path)
    pub in_compact_before: i32, // in[2]: MSG_WAL_COMPACT_BEFORE (post-snapshot trim)
    pub out_flushed: i32,       // out[0]: FsyncAck (external consumers; ledger is fed in-module)
    pub out_replay_complete: i32, // out[1]: MSG_WAL_REPLAY_COMPLETE to consensus
    pub out_entry_reply: i32,   // out[2]: MSG_WAL_ENTRY_REPLY back to requester
    pub out_compaction: i32,    // out[3]: SnapshotTrigger for downstream coordinators
    pub out_metrics: i32,       // out[4]: MetricsPayload to operations.telemetry

    // WAL state
    pub partition_id: u16,
    pub self_id: u8,
    current_term: Term,
    current_index: Index,
    segment_seq: u32,
    cursor: u32,            // bytes written in current logical segment
    /// Furthest byte ever written in the CURRENT segment. After a
    /// truncation rewinds `cursor` below this, stale frames live in
    /// `[cursor, seg_high_water)`; until fresh appends overwrite past it,
    /// every append writes a trailing zero-length terminator so replay
    /// stops at the live tail instead of reading the stale suffix. Reset
    /// to 0 on segment rotation. See `MSG_WAL_TRUNCATE_AFTER`.
    seg_high_water: u32,
    pub segment_limit: u32, // from params (default 64 MiB)
    /// Oldest segment_seq still on disk after compaction. Requests for
    /// entries in segments < `oldest_segment_seq` return NOT_FOUND, which
    /// triggers the snapshot-install fallback on the leader.
    oldest_segment_seq: u32,
    pub dek_epoch: u32,
    pub encoding: u8,           // 0=binary

    /// Ring buffer of recent entry locations for random-access lookup
    /// (replicator NACK retry, etc.). `ENTRY_RING_SIZE` covers the
    /// last 256 indices; older indices fall through to a NOT_FOUND
    /// reply and snapshot fallback.
    entry_ring: [EntryLoc; ENTRY_RING_SIZE],
    /// Proposal bodies retained by the explicit no-filesystem fallback.
    /// Uses the same index mask and retention horizon as `entry_ring`, so
    /// apply/replication gap refetch remains correct in ephemeral graphs.
    memory_entries: [MemoryEntry; ENTRY_RING_SIZE],
    entry_ring_max_index: u64,
    entry_ring_min_index: u64,

    // File I/O
    fd: i32,                    // file descriptor for current segment, -1 = not open
    /// Set once `OPEN_CREATE` has failed on the write path so the
    /// `[wal] no fs` in-memory-fallback signal is emitted exactly once,
    /// not per flush. This is the *real* fs-unavailable marker (a fresh
    /// deployment with a writable empty `wal/` never trips it).
    no_fs_logged: bool,
    /// Set once a HARD FS error (not E_AGAIN) has been seen: the provider is
    /// genuinely absent, so the WAL degrades to in-memory permanently. While
    /// this is false and `fd < 0`, the WAL treats the FS as "coming up" and
    /// waits (E_AGAIN-patient) instead of acking entries it can't persist.
    no_fs: bool,
    dbg_last_open_rc: i32,
    dbg_steps: u64,
    input_budget_bytes: u32,
    pump_records: u8,
    path_buf: [u8; WAL_PATH_MAX],
    path_len: u8,

    // Write buffer
    write_buf: [u8; WRITE_BUF_SIZE],
    write_pos: u16,
    /// The staged bytes end in a zero-length replay terminator after a
    /// truncate. Such a batch is flushed immediately and the fd is rewound to
    /// logical `cursor` before fsync/ack.
    staged_terminator: bool,

    // CRC
    crc: Crc32c,

    // Metrics
    entries_written: u32,
    bytes_written: u64,
    /// Durable-write failures (short/failed FS_WRITE, FS_FSYNC error, or
    /// segment open failure). Each one means the entry was NOT acked durable.
    write_errors: u32,
    /// Sticky fail-closed latch. A later high-water ack must never cover a
    /// missing WAL record.
    continuity_fault: bool,
    continuity_errors: u32,
    /// Replay-time CRC32C mismatches (torn / corrupt entries). A mismatch
    /// stops replay of that segment at the bad frame so we never replay
    /// garbage past a torn tail.
    checksum_failures: u32,
    /// Count of `MSG_WAL_TRUNCATE_AFTER` requests applied (Raft conflict
    /// repair discarded a divergent suffix). Diagnostic / regression signal.
    truncations: u32,
    last_metrics_ms: u64,
    /// `clustor.wal.fsync_latency_ms` cumulative bucket counts
    /// (RFC §4.1). One slot per `wire::hist::FSYNC_LATENCY_US` bound
    /// plus a trailing `+Inf` overflow bucket. Measured in µs at each
    /// `FS_FSYNC` call site; emitted as `METRIC_KIND_HISTOGRAM` samples.
    fsync_buckets: [u32; wire::hist::FSYNC_LATENCY_US.len() + 1],

    // Replay state
    phase: u8,              // PHASE_REPLAY or PHASE_NORMAL
    replay_seg: u32,        // current segment being replayed
    replay_fd: i32,         // fd for replay segment, -1 = none
    replay_file_size: u32,  // total bytes in replay segment
    replay_pos: u32,        // current read position
    /// Consecutive `FS_OPEN` failures while scanning for the next
    /// existing segment. Replay walks from `replay_seg = 1` and
    /// tolerates gaps up to `REPLAY_GAP_TOLERANCE`, which lets it
    /// survive both fresh deployments (no segments at all) and
    /// restarts after compaction has deleted leading segments.
    replay_misses: u8,
    /// Lowest segment_seq we successfully opened during this replay
    /// pass; becomes `oldest_segment_seq` on transition to
    /// `PHASE_NORMAL`. Zero until the first successful open.
    replay_first_found: u32,
    /// Highest segment_seq we successfully opened; +1 becomes the
    /// new `segment_seq` for fresh appends after replay. Zero until
    /// the first successful open.
    replay_last_found: u32,

    // Group-fsync batching (active iff fsync_mode == 1).
    pub fsync_mode: u8,
    pub group_window_ms: u16,
    pub group_max_pending: u16,
    pub root_path: u8,
    /// 1 = skip boot replay and start fresh (segment_seq=1), orphaning any
    /// pre-existing segments. For throughput/latency benches (L1/L2) where a
    /// clean slate is wanted and stale segments from prior runs would
    /// otherwise be re-acked into the fresh consensus index space. Leave 0
    /// (default) for crash-recovery (L4) where replay reconstructs state.
    pub skip_replay: u8,
    /// FS `caps::UNLINK` probe cache for compaction's segment deletion:
    /// 0 = unprobed, 1 = supported, 2 = unsupported. See
    /// `fs_unlink_supported`.
    fs_unlink_probe: u8,
    pub fixed_segment: u8,
    fixed_segment_active: bool,
    pub preallocate_settle_ms: u16,
    preallocate_ready_at_ms: u64,
    batch_start_ms: u64,
    pending_count: u16,
    pending_max_index: Index,
    pending_max_term: Term,
    has_batch: bool,
    /// Group-fsync batch has been fsynced to disk but its FsyncAck has NOT
    /// yet been delivered (the `out_flushed` channel was full). The batch is
    /// kept intact so a later step retries the ack WITHOUT re-fsyncing —
    /// otherwise a quiescent writer whose final ack was dropped would never
    /// inform the ledger component and commit would stall (P1: failed WAL I/O
    /// acknowledgements).
    batch_fsynced: bool,

    /// Async durable-write path (enabled iff the FS provider advertises
    /// `FS_CAP_FSYNC_ASYNC`, probed once via `ensure_fs_caps` before the
    /// first durable write). When set, `flush_batch` submits the batch with
    /// `FS_WRITE_ASYNC` and fences with `FS_FSYNC_SUBMIT`/`FS_FSYNC_POLL` —
    /// pipelining durability instead of spin-polling every write.
    fs_async: bool,
    /// A durability fence has been opened for the current batch and is
    /// awaiting completion. While set, staging is held (see
    /// `process_entries`) so the pending ack's coverage cannot drift.
    fence_pending: bool,
    /// The outstanding fence ticket (from `FS_FSYNC_SUBMIT`).
    fence_ticket: u64,
    /// Latched on the first fence failure (submit or poll). A failed fence
    /// is a durability gap, which is FATAL for log integrity: fail-stop —
    /// withhold acks (commit never advances past a non-durable entry), stop
    /// issuing writes, log once. No silent downgrade to the sync path
    /// (which, on a failing device, would fail identically). Recovery is a
    /// node restart, which re-inits the device.
    fence_failed: bool,

    /// Fence-pipelining depth (config param 13, default 1). When >1 the WAL
    /// keeps up to `fence_depth` async fences outstanding at once instead of
    /// waiting for each to complete, decoupling write throughput from fence
    /// (device) latency. Each in-flight fence snapshots its own covered
    /// (ticket, high-water index/term) so later staging can't corrupt an
    /// already-submitted fence's ack coverage. FIFO reap → in-order acks.
    pub fence_depth: u16,
    /// Ring of outstanding fences: (ticket, max_index, max_term). FIFO.
    fence_ring: [(u64, Index, Term); FENCE_RING_MAX],
    fence_ring_head: u8,
    fence_ring_count: u8,

    /// True while the WAL still owes consensus the MSG_WAL_REPLAY_COMPLETE
    /// handshake. Set at module_new; cleared when the port is unwired or after
    /// the bounded re-emit window (see REPLAY_REEMIT_MS). The signal carries
    /// `(current_term, current_index)` — the exact on-disk high-water
    /// reconstructed by replay (or 0/0 for a fresh `skip_replay` start) — so a
    /// recovering raft resumes there rather than at its throttled metadata
    /// hint.
    replay_complete_pending: bool,
    /// Emit attempts so far (bounds the re-emit loop; see
    /// REPLAY_REEMIT_MAX_ATTEMPTS).
    replay_emit_attempts: u32,
    /// Wall-clock ms of the last replay-complete emit (re-emit throttle).
    last_replay_emit_ms: u64,
    /// Diagnostic: high-water emitted in the replay-complete signal (0 until).
    replay_hw_sent: u64,
    /// Diagnostic: count of entries re-emitted during boot replay.
    replayed_count: u32,
    /// Diagnostic: FS_STAT size of the first segment opened during replay.
    replay_first_size: u32,
    /// Diagnostic: entry requests served (hit) vs not-found.
    entryreq_served: u32,
    entryreq_notfound: u32,

    // ── In-module delivery latches (composite seams) ─────────
    /// Highest durable (term, index) this step, for the ledger
    /// component. Monotone latest-wins — the ledger's per-replica
    /// progress only ever advances, so collapsing multiple acks per
    /// step to the max is semantics-preserving.
    pub ledger_ack: (Term, Index),
    pub ledger_dirty: bool,
    /// Latest segment-rotation snapshot trigger, for the snapshot
    /// component. Latest-wins for the same reason.
    pub snap_trigger: (Term, Index),
    pub snap_trigger_dirty: bool,

    // Scratch buffer for reading messages
    msg_buf: [u8; 4096],
}

pub unsafe fn init(s: &mut Wal) {
    s.in_entries = -1;
    s.in_entry_request = -1;
    s.in_compact_before = -1;
    s.out_flushed = -1;
    s.out_compaction = -1;
    s.out_metrics = -1;
    s.out_entry_reply = -1;
    s.out_replay_complete = -1;
    s.partition_id = 0;
    s.self_id = 0;
    s.current_term = 0;
    s.current_index = 0;
    s.cursor = 0;
    s.seg_high_water = 0;
    s.segment_limit = 67_108_864;
    s.dek_epoch = 0;
    s.encoding = 0;
    s.entry_ring_max_index = 0;
    s.entry_ring_min_index = 0;
    s.replay_complete_pending = true;
    s.replay_emit_attempts = 0;
    s.last_replay_emit_ms = 0;
    s.fsync_mode = 0;
    s.group_window_ms = 2;
    s.group_max_pending = 64;
    s.root_path = 0;
    s.skip_replay = 0;
    s.fixed_segment = 0;
    s.preallocate_settle_ms = 0;
    s.fence_depth = 1;
    s.fence_failed = false;
    s.fence_pending = false;
    s.fence_ticket = 0;
    s.fs_async = false;
    s.fence_ring = [(0u64, 0, 0); FENCE_RING_MAX];
    s.fence_ring_head = 0;
    s.fence_ring_count = 0;
    s.replay_hw_sent = 0;
    s.replayed_count = 0;
    s.replay_first_size = 0;
    s.entryreq_served = 0;
    s.entryreq_notfound = 0;
    s.continuity_fault = false;
    s.continuity_errors = 0;
    s.segment_seq = 1;
    s.oldest_segment_seq = 1;
    s.crc = Crc32c::new();
    s.fd = -1;
    s.no_fs_logged = false;
    s.no_fs = false;
    s.dbg_last_open_rc = 1; // sentinel != any real fd/errno so first rc logs
    s.dbg_steps = 0;
    s.input_budget_bytes = 0;
    s.pump_records = 0;
    s.path_len = 0;
    s.write_pos = 0;
    s.staged_terminator = false;
    s.batch_start_ms = 0;
    s.pending_count = 0;
    s.pending_max_index = 0;
    s.pending_max_term = 0;
    s.has_batch = false;
    s.batch_fsynced = false;
    s.entries_written = 0;
    s.bytes_written = 0;
    s.write_errors = 0;
    s.checksum_failures = 0;
    s.truncations = 0;
    s.last_metrics_ms = 0;
    s.fsync_buckets = [0u32; wire::hist::FSYNC_LATENCY_US.len() + 1];
    s.phase = PHASE_REPLAY;
    s.replay_seg = 1;
    s.replay_fd = -1;
    s.replay_file_size = 0;
    s.replay_pos = 0;
    s.replay_misses = 0;
    s.replay_first_found = 0;
    s.replay_last_found = 0;
    s.entry_ring = [EntryLoc::zero(); ENTRY_RING_SIZE];
    s.memory_entries = [MemoryEntry::zero(); ENTRY_RING_SIZE];
    s.ledger_ack = (0, 0);
    s.ledger_dirty = false;
    s.snap_trigger = (0, 0);
    s.snap_trigger_dirty = false;
}

/// Apply post-param bootstrap decisions. Called by the composite once
/// params have landed.
pub fn arm(s: &mut Wal) {
    // Fresh-start mode (benches): bypass replay entirely so stale
    // segments from prior runs aren't re-acked into the fresh index
    // space. New appends start at seq 1; clean_root on the FS side
    // truncates the orphaned root-dir entries on the first create.
    if s.skip_replay != 0 || VOLATILE {
        s.phase = PHASE_NORMAL;
        s.segment_seq = 1;
        s.oldest_segment_seq = 1;
    }
    if VOLATILE {
        // In-memory retention is selected, not a fallback: mark the
        // path up front and never emit the `[wal] no fs` signal.
        s.no_fs = true;
        s.no_fs_logged = true;
    }
}

/// Step the WAL. Return codes follow the kernel step ABI (0=Continue,
/// 2=Burst); the composite propagates Burst. Per-step bounds: replay
/// is one FS open OR one frame; normal mode is the byte-granted input
/// pump (≤8 records), ≤4 control frames, ≤8 gap-refetch serves.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(s: &mut Wal, sys: &SyscallTable) -> i32 {
    s.dbg_steps = s.dbg_steps.wrapping_add(1);

    if s.phase == PHASE_REPLAY {
        // Replay existing WAL segments before accepting new entries.
        return step_replay(s, sys);
    }

    // FS-readiness gate. While the segment isn't open and we haven't
    // decided the FS is genuinely absent, (re)try the open every step.
    // On E_AGAIN (provider still initialising — fat32 reading the BPB on
    // a cm5 cold boot) HOLD: don't drain new entries, so raft backpressures
    // and nothing is acked that can't be persisted. Once the open succeeds
    // (disk) or hard-fails (in-memory), fall through to normal processing.
    if s.fd < 0 && !s.no_fs {
        ensure_segment_open(s, sys);
        if s.fd < 0 && !s.no_fs {
            emit_metrics(s, sys);
            return 0;
        }
        if s.fixed_segment_active {
            // Physical segment reservation is bounded boot/rotation work,
            // but intentionally much larger than a steady-state step.
            // Burst classifies that one-time elapsed interval correctly;
            // no entry has been consumed yet.
            return STEP_BURST;
        }
    }

    // replay_complete is the admission handoff to Raft and therefore the
    // source of /readyz. Keep it closed until post-allocation device work
    // has quiesced; otherwise the first client burst observes the SSD's
    // transient background phase as a 400+ ms queue.
    if s.fixed_segment_active && dev_millis(sys) < s.preallocate_ready_at_ms {
        emit_metrics(s, sys);
        return 0;
    }

    // Hand consensus the exact on-disk high-water reconstructed by
    // replay, only after the write side is ready. Until this lands a
    // recovering/fresh fixed graph holds proposal intake.
    maybe_emit_replay_complete(s, sys);

    // Time-based group flush: a quiescent writer drains its tail
    // batch within group_window_ms even when no new entries arrive.
    // An outstanding async fence is polled every step regardless of the
    // window so a completed batch acks promptly (and staging can resume).
    if s.fs_async && s.fence_depth > 1 {
        // Pipelined mode: reap completed fences (and submit the staged
        // batch) every step, independent of has_batch, so acks flow while
        // more batches are still in flight.
        flush_batch(s, sys);
    } else if s.has_batch {
        let now = dev_millis(sys);
        if s.fence_pending || now.wrapping_sub(s.batch_start_ms) >= s.group_window_ms as u64 {
            flush_batch(s, sys);
        }
    }

    // Normal operation
    // 1. Apply control signals (post-snapshot compaction trim AND Raft
    //    conflict-repair truncation) BEFORE appending. A truncate must
    //    land before any same-step append, else the fresh entry would be
    //    written above the divergent tail and then rewound away.
    drain_compact_before(s, sys);

    // 2. Persist complete records up to the live transaction budget. A
    // classed input derives its grant from the graph and current pacer
    // period; an unclassed legacy graph retains one-record-per-step
    // behaviour. Atomic records may overshoot the byte grant by at most
    // one validated max_record.
    let grant = dev_input_flow_budget(sys, s.in_entries, 0) as u64;
    s.input_budget_bytes = grant.min(u32::MAX as u64) as u32;
    let mut consumed = 0u64;
    let mut records = 0usize;
    while records < MAX_ENTRY_PUMP_RECORDS && (grant == 0 || consumed < grant) {
        let before_entries = s.entries_written;
        let before_bytes = s.bytes_written;
        process_entries(s, sys);
        if s.entries_written == before_entries {
            break;
        }
        records += 1;
        consumed = consumed.saturating_add(
            s.bytes_written.wrapping_sub(before_bytes).saturating_add(8),
        );
        if grant == 0 {
            break;
        }
    }
    s.pump_records = records as u8;
    if records > 0 {
        let poll = (sys.channel_poll)(s.in_entries, POLL_IN);
        let effect = if poll > 0 && (poll as u32 & POLL_IN) != 0 {
            step_effect::RUNNABLE_BACKLOG
        } else {
            step_effect::WORK_DONE
        };
        dev_report_step_effect(sys, effect);
    }

    // 3. Service random-access read-back requests (replicator NACK retry).
    drain_entry_requests(s, sys);

    // 4. Emit metrics periodically
    emit_metrics(s, sys);

    0 // Continue
}

/// Emit the one-shot MSG_WAL_REPLAY_COMPLETE to consensus, carrying the
/// reconstructed on-disk high-water `(current_term, current_index)`. Called
/// only in PHASE_NORMAL. If the port is unwired (non-recovery graph) the
/// pending flag is cleared without emitting; if the channel is momentarily
/// full we keep the flag set and retry next step.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn maybe_emit_replay_complete(s: &mut Wal, sys: &SyscallTable) {
    if !s.replay_complete_pending { return; }
    if s.out_replay_complete < 0 {
        // No consumer wired — nothing to hand off.
        s.replay_complete_pending = false;
        return;
    }
    // Re-emit on a bounded wall-clock cadence rather than one-shot: a lone
    // handshake message can be lost across the cross-domain bridge if the
    // consumer port is not yet live, permanently wedging raft's intake.
    let now = dev_millis(sys);
    if s.replay_emit_attempts > 0
        && now.wrapping_sub(s.last_replay_emit_ms) < REPLAY_REEMIT_MS
    {
        return;
    }
    let poll = (sys.channel_poll)(s.out_replay_complete, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 16];
    wire::encode_term_index(&mut buf, s.current_term, s.current_index);
    let w = wire_channels::channel_write_msg(
        sys, s.out_replay_complete, wire::MSG_WAL_REPLAY_COMPLETE, &buf,
    );
    s.replay_emit_attempts = s.replay_emit_attempts.saturating_add(1);
    if w > 0 {
        s.last_replay_emit_ms = now;
        s.replay_hw_sent = s.current_index;
        if s.replay_emit_attempts == 1 {
            dev_log(sys, 3, b"[wal] replay hw sent".as_ptr(), 20);
        }
    }
    // Stop re-emitting after a bounded window. By this point either raft has
    // resumed (duplicates are harmless — it ignores them) or the edge is
    // broken in a way re-emitting cannot fix; keeping the flag set forever
    // would spin the throttle needlessly.
    if s.replay_emit_attempts >= REPLAY_REEMIT_MAX_ATTEMPTS {
        s.replay_complete_pending = false;
    }
}

// ── Entry-location ring buffer ──────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn record_entry_loc(
    s: &mut Wal,
    index: u64,
    term: u64,
    seg_seq: u32,
    payload_offset: u32,
    payload_len: u32,
) {
    if index == 0 { return; }
    let slot = (index & ENTRY_RING_MASK) as usize;
    s.entry_ring[slot] = EntryLoc { index, term, seg_seq, payload_offset, payload_len };
    if index > s.entry_ring_max_index {
        s.entry_ring_max_index = index;
    }
    let floor = if s.entry_ring_max_index > ENTRY_RING_SIZE as u64 {
        s.entry_ring_max_index - ENTRY_RING_SIZE as u64 + 1
    } else {
        1
    };
    if floor > s.entry_ring_min_index {
        s.entry_ring_min_index = floor;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn lookup_entry_loc(s: &Wal, index: u64) -> Option<EntryLoc> {
    if index == 0 || index > s.entry_ring_max_index { return None; }
    if index < s.entry_ring_min_index { return None; }
    let slot = (index & ENTRY_RING_MASK) as usize;
    let loc = s.entry_ring[slot];
    if loc.index != index { return None; }
    Some(loc)
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_entry_requests(s: &mut Wal, sys: &SyscallTable) {
    if s.in_entry_request < 0 || s.out_entry_reply < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_entry_request, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_entry_request, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_ENTRY_REQUEST { continue; }
        let pl = plen as usize;
        let (request_id, wal_index) = match wire::decode_wal_entry_request(&s.msg_buf[..pl]) {
            Some(v) => v,
            None => continue,
        };
        serve_entry_request(s, sys, request_id, wal_index);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn serve_entry_request(
    s: &mut Wal,
    sys: &SyscallTable,
    request_id: u32,
    wal_index: u64,
) {
    let poll_out = (sys.channel_poll)(s.out_entry_reply, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }

    let loc = match lookup_entry_loc(s, wal_index) {
        Some(l) => l,
        None => {
            // NOT_FOUND — reply with header only, empty body. The leader
            // takes this as a signal to fall through to snapshot install.
            s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
            wire_channels::channel_write_msg(
                sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr,
            );
            return;
        }
    };

    if s.no_fs {
        let slot = (wal_index & ENTRY_RING_MASK) as usize;
        let mem = s.memory_entries[slot];
        if mem.index != wal_index {
            s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
            wire_channels::channel_write_msg(
                sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr,
            );
            return;
        }
        let prev_term = if loc.index > 1 {
            lookup_entry_loc(s, loc.index - 1).map_or(0, |p| p.term)
        } else {
            0
        };
        let body_len = mem.body_len as usize;
        let total = wire::WAL_ENTRY_REPLY_HDR + body_len;
        let mut reply = [0u8; 4096];
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(
            &mut hdr, request_id, loc.term, loc.index, prev_term,
        );
        reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
        reply[wire::WAL_ENTRY_REPLY_HDR..total].copy_from_slice(&mem.body[..body_len]);
        wire_channels::channel_write_msg(
            sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &reply[..total],
        );
        s.entryreq_served = s.entryreq_served.saturating_add(1);
        return;
    }

    // Read the entry body from disk. The body that lands in the WAL is
    // `[term:u64][index:u64][body...]` (16-byte header + body). We pass
    // the whole payload back so the replicator can reconstruct an AE.
    // WAL payload = [term:u64][index:u64][body ≤ PROPOSAL_BATCH_CAP] —
    // up to 2064 bytes, so this buffer must exceed that or a full
    // batch entry falls into the NOT_FOUND branch below, which the
    // replicator reads as needs-snapshot.
    let mut body = [0u8; 4096];
    let payload_len = loc.payload_len as usize;
    if payload_len == 0 || payload_len > body.len() {
        // Defensive: shouldn't happen given the write-path payload cap.
        s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
        wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
        return;
    }

    let read_fd = if loc.seg_seq == s.segment_seq && s.fd >= 0 {
        s.fd
    } else {
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = encode_segment_path(s.partition_id, loc.seg_seq, s.root_path != 0, &mut path);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if fd < 0 {
            s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
            wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
            return;
        }
        fd
    };

    let seek_arg = (loc.payload_offset as i32).to_le_bytes();
    let seek_rc =
        (sys.provider_call)(read_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4);
    let mut ok = seek_rc >= 0;
    if ok {
        let n = (sys.provider_call)(read_fd, FS_READ, body.as_mut_ptr(), payload_len);
        ok = (n as usize) >= payload_len;
    }

    // Restore write-fd position to end-of-segment so the next write
    // appends correctly. We always FS_SEEK to `s.cursor`.
    if read_fd == s.fd {
        let restore = (s.cursor as i32).to_le_bytes();
        (sys.provider_call)(read_fd, FS_SEEK, restore.as_ptr() as *mut u8, 4);
    } else {
        (sys.provider_call)(read_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    }

    if !ok {
        s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
        wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
        return;
    }

    // Body is [term:u64][index:u64][rest...]; strip the 16-byte header
    // when forming the reply so the wire format matches the doc-comment
    // on MSG_WAL_ENTRY_REPLY (`[request_id][term][index][body...]`).
    let rest = if payload_len > 16 { &body[16..payload_len] } else { &[][..] };
    let total = wire::WAL_ENTRY_REPLY_HDR + rest.len();
    let mut reply = [0u8; 4096];
    let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
    // prev_term = term of the entry at index-1, so the replicator builds the
    // catch-up AE with the correct prev_log_term (guessing it triggers a
    // spurious follower truncation at a term boundary). 0 if index<=1 or the
    // predecessor has aged out of the offset ring (then the follower
    // trust-matches if it's committed, else falls through to snapshot).
    let prev_term = if loc.index > 1 {
        lookup_entry_loc(s, loc.index - 1).map_or(0, |p| p.term)
    } else {
        0
    };
    wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, loc.term, loc.index, prev_term);
    reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
    reply[wire::WAL_ENTRY_REPLY_HDR..total].copy_from_slice(rest);
    wire_channels::channel_write_msg(
        sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &reply[..total],
    );
    s.entryreq_served = s.entryreq_served.saturating_add(1);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_compact_before(s: &mut Wal, sys: &SyscallTable) {
    if s.in_compact_before < 0 { return; }

    // A truncate/compaction changes the file cursor and segment topology. Do
    // not let it overtake records that are already accepted into the current
    // durability batch but still live only in `write_buf`.
    let ready = (sys.channel_poll)(s.in_compact_before, 0x01);
    if ready > 0 && (ready as u32 & 0x01) != 0 && s.has_batch {
        flush_batch(s, sys);
        if s.has_batch { return; }
    }

    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_compact_before, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_compact_before, &mut s.msg_buf);
        if (plen as usize) < 8 { continue; }
        let index = u64::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
        ]);
        match msg_type {
            wire::MSG_WAL_COMPACT_BEFORE => compact_before(s, sys, index),
            wire::MSG_WAL_TRUNCATE_AFTER => truncate_after(s, sys, index),
            _ => continue,
        }
    }
}

/// Discard every entry strictly after `keep_through_index` (Raft §5.3
/// conflict repair). Trims the in-memory offset map and, for the live
/// segment, rewinds the write cursor to the end of `keep_through_index`'s
/// frame and writes a zero-length terminator so replay stops at the new
/// tail rather than reading the now-stale suffix. Committed entries are
/// immutable, so raft only ever calls this for an uncommitted tail — the
/// WAL does not (and cannot) re-derive commit_index, it trusts the caller.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines per
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn truncate_after(s: &mut Wal, sys: &SyscallTable, keep_through_index: u64) {
    // Nothing to do if we hold nothing past the keep point.
    if s.current_index <= keep_through_index { return; }

    // The byte offset where the discarded suffix begins. If the keep point
    // is still in our offset ring AND lives in the current segment, rewind
    // to just past its frame; otherwise (keep point compacted out of the
    // ring, or in an older segment) rewind the whole current segment.
    let mut new_cursor: u32 = 0;
    let mut new_term: Term = 0;
    if keep_through_index > 0 {
        if let Some(loc) = lookup_entry_loc(s, keep_through_index) {
            if loc.seg_seq == s.segment_seq {
                new_cursor = loc.payload_offset + loc.payload_len;
            }
            new_term = loc.term;
        }
    }

    // Drop in-memory ring slots above the keep point so lookups and
    // entry-request serves no longer surface the discarded suffix.
    let mut i = keep_through_index + 1;
    while i <= s.entry_ring_max_index {
        let slot = (i & ENTRY_RING_MASK) as usize;
        if s.entry_ring[slot].index == i {
            s.entry_ring[slot].index = 0;
        }
        if s.memory_entries[slot].index == i {
            s.memory_entries[slot].index = 0;
            s.memory_entries[slot].body_len = 0;
        }
        i += 1;
    }
    s.entry_ring_max_index = keep_through_index;

    // Mark the stale region and rewind. The trailing-terminator logic in
    // process_entries keeps replay honest until appends overwrite past it.
    if s.cursor > s.seg_high_water {
        s.seg_high_water = s.cursor;
    }
    s.cursor = new_cursor;
    s.current_index = keep_through_index;
    s.current_term = new_term;
    s.truncations = s.truncations.saturating_add(1);

    // Persist the new tail: seek to the cursor, write a zero-length frame
    // terminator (4 bytes of 0 = entry_len 0, which replay treats as
    // end-of-segment), and fsync so the truncation survives a crash.
    if s.fd >= 0 {
        let seek = (new_cursor as i32).to_le_bytes();
        (sys.provider_call)(s.fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
        let zero = [0u8; 4];
        let w = (sys.provider_call)(s.fd, FS_WRITE, zero.as_ptr() as *mut u8, 4);
        if w == 4 {
            fsync_segment(s, sys);
            // Re-seek to the cursor so the next append overwrites the
            // terminator we just wrote.
            (sys.provider_call)(s.fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
        }
    }
    dev_log(sys, 3, b"[wal] truncate".as_ptr(), 14);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn compact_before(s: &mut Wal, sys: &SyscallTable, before_index: u64) {
    if before_index == 0 { return; }
    // Bump the floor index in the in-memory ring so we stop serving
    // entries below it even if the ring slots still hold them.
    if before_index > s.entry_ring_min_index {
        s.entry_ring_min_index = before_index;
    }
    // Drop segments whose max-index is strictly below the requested
    // floor. The current write segment is exempt — we never delete it
    // while we're still appending to it.
    let mut max_safe_seq_to_drop: u32 = 0;
    for slot in s.entry_ring.iter() {
        if slot.index == 0 { continue; }
        // If the entry is still relevant (>= floor), the segment that
        // holds it stays. We deliberately scan the whole ring rather
        // than rely on segment_seq monotonicity, because a recent
        // entry's segment may equal an older entry's segment.
        if slot.index < before_index && slot.seg_seq < s.segment_seq {
            if slot.seg_seq > max_safe_seq_to_drop {
                max_safe_seq_to_drop = slot.seg_seq;
            }
        }
    }
    if max_safe_seq_to_drop == 0 { return; }
    // Delete segments [oldest_segment_seq .. max_safe_seq_to_drop] from
    // disk via FS_UNLINK where the provider supports it (probed once via
    // FS_CAPS — linux and fat32 both advertise `caps::UNLINK`; fat32's
    // unlink tombstones the dirent synchronously and reclaims the cluster
    // chain lazily in its own steps). On a provider without the cap — or
    // on a per-file error — the floor still advances and the file is
    // merely orphaned (the pre-unlink posture): compaction correctness
    // never depends on physical deletion, only replay/entry-serving does.
    while s.oldest_segment_seq <= max_safe_seq_to_drop
        && s.oldest_segment_seq < s.segment_seq
    {
        if fs_unlink_supported(s, sys) {
            let mut path = [0u8; WAL_PATH_MAX];
            let plen = encode_segment_path(s.partition_id, s.oldest_segment_seq, s.root_path != 0, &mut path);
            let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
            if rc == 0 {
                dev_log(sys, 3, b"[wal] compacted".as_ptr(), 15);
            } else {
                // ENOENT is expected after skip_replay orphaned a prior
                // run's numbering, or when an operator GC'd out-of-band.
                dev_log(sys, 3, b"[wal] compact orphan".as_ptr(), 20);
            }
        } else {
            dev_log(sys, 3, b"[wal] compacted".as_ptr(), 15);
        }
        s.oldest_segment_seq += 1;
    }
}

/// Lazily probe the FS provider's capability bitmap for `UNLINK` support.
/// Cached after the first successful probe (`0` = unprobed, `1` = yes,
/// `2` = no); a failed CAPS call (provider still initialising) stays
/// unprobed and retries on the next compaction rather than caching a
/// transient error as "unsupported".
unsafe fn fs_unlink_supported(s: &mut Wal, sys: &SyscallTable) -> bool {
    ensure_fs_caps(s, sys);
    s.fs_unlink_probe == 1
}

/// One-shot FS capability probe. Reads the provider's CAPS bitmap once
/// and caches both the `UNLINK` disposition (`fs_unlink_probe`) and
/// whether the async durable-write tier is available (`fs_async`). A
/// failed CAPS call (provider still initialising) leaves everything
/// unprobed and retries next call. Called at the top of `flush_batch`
/// so `fs_async` is set before the first durable write is issued.
unsafe fn ensure_fs_caps(s: &mut Wal, sys: &SyscallTable) {
    if s.fs_unlink_probe != 0 {
        return;
    }
    let mut caps = [0u8; 4];
    let rc = (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4);
    if rc == 4 {
        let bits = u32::from_le_bytes(caps);
        s.fs_unlink_probe = if bits & FS_CAP_UNLINK != 0 { 1 } else { 2 };
        s.fs_async = bits & FS_CAP_FSYNC_ASYNC != 0;
    }
}

// ── Replay phase ────────────────────────────────────────────
//
// On startup, scans for existing WAL segment files and re-emits
// their entries through the flushed output. This allows the
// downstream pipeline (ledger → commit) to
// reconstruct committed state.
//
// Processes one chunk per step (bounded work per tick).

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_replay(s: &mut Wal, sys: &SyscallTable) -> i32 {
    // Try to open the current replay segment.
    //
    // Replay walks forward from `replay_seg = 1` probing for
    // segment files. `FS_OPEN` is read-only-if-exists per the
    // Linux FS provider, so a missing file returns negative. A
    // single miss does NOT end replay — we tolerate up to
    // `REPLAY_GAP_TOLERANCE` consecutive misses, which lets us
    // survive both fresh deployments (zero segments → bounded
    // scan terminates cleanly) and restarts after compaction has
    // deleted leading segments (gaps in the seq range).
    //
    // A successful open with size > 0 resets the miss counter and
    // records the seq in `replay_first_found` / `replay_last_found`
    // so the transition to PHASE_NORMAL can set `oldest_segment_seq`
    // and `segment_seq` to the right values for ongoing operation.
    // Size 0 still terminates replay (an empty segment is the
    // tombstone an in-flight rotation may leave behind).
    if s.replay_fd < 0 {
        build_segment_path(s, s.replay_seg);
        let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), s.path_len as usize);
        if fd == FS_E_AGAIN {
            // FS provider still initialising (fat32 reading the BPB on a cm5
            // cold boot). Do NOT count this as a missing segment — that would
            // skip real segments and lose committed state on recovery. Wait
            // and retry the same seq next step.
            return 0;
        }
        if fd < 0 {
            // Missing segment — count it and either advance or
            // declare replay done depending on the miss tally.
            s.replay_misses = s.replay_misses.saturating_add(1);
            if s.replay_misses < REPLAY_GAP_TOLERANCE {
                // Skip and try the next seq on the following tick.
                // Bounded work per tick (one open).
                s.replay_seg = s.replay_seg.saturating_add(1);
                // Burst: this FS_OPEN may have paid the one-time cold
                // directory-scan penalty (a first-touch read of a
                // bloated/cold root-dir cluster on this NVMe runs tens of
                // ms — measured 38 ms). Returning Burst makes the scheduler
                // re-arm with the 8× burst budget for the *next* step and,
                // critically, discard this step's elapsed without checking
                // it against the normal deadline — so a legitimate one-time
                // boot scan never faults the module. Replay is bounded
                // (terminates when segments are exhausted), so this is a
                // headroom grant, not unbounded work. See RFC §14 item 3b.
                return STEP_BURST;
            }
            // Bound reached: replay is done. Finding no segments here
            // is NOT proof the filesystem is unavailable — a fresh
            // deployment has an empty (but perfectly writable) `wal/`.
            // Whether the FS is actually missing is only known on the
            // write path (`ensure_segment_open`), which emits
            // `[wal] no fs` if `OPEN_CREATE` fails. So replay just
            // reports completion either way and lets the writer make
            // the fallback call.
            dev_log(sys, 3, b"[wal] replay done".as_ptr(), 17);
            if s.replay_last_found == 0 {
                // No segments found: start writes at seq 1.
                s.segment_seq = 1;
                s.oldest_segment_seq = 1;
            } else {
                s.segment_seq = s.replay_last_found.saturating_add(1);
                s.oldest_segment_seq = s.replay_first_found;
            }
            s.phase = PHASE_NORMAL;
            // Burst (forgive any cold-scan this open paid); harmlessly
            // re-steps once into PHASE_NORMAL, which returns Continue.
            return STEP_BURST;
        }

        // Check file size — an empty segment is the tombstone an
        // in-flight rotation may leave behind. Treat it the same
        // way we treat a final miss: terminate replay here.
        // FS_STAT writes [size:u32 LE][mtime:u32 LE] into the supplied buffer.
        let mut stat_buf = [0u8; 8];
        let stat_rc = (sys.provider_call)(fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        let size = if stat_rc < 0 { 0 } else {
            u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
        };
        if size == 0 {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            dev_log(sys, 3, b"[wal] replay done".as_ptr(), 17);
            s.phase = PHASE_NORMAL;
            if s.replay_last_found == 0 {
                // Empty very first segment file: start at seq 1.
                s.segment_seq = 1;
                s.oldest_segment_seq = 1;
            } else {
                s.segment_seq = s.replay_last_found.saturating_add(1);
                s.oldest_segment_seq = s.replay_first_found;
            }
            // Burst (forgive any cold-scan this open paid).
            return STEP_BURST;
        }

        // Real segment data found — reset the gap counter and
        // record the seq for the post-replay bounds.
        s.replay_misses = 0;
        if s.replay_first_found == 0 {
            s.replay_first_found = s.replay_seg;
            s.replay_first_size = size;
        }
        s.replay_last_found = s.replay_seg;

        s.replay_fd = fd;
        s.replay_file_size = size;
        s.replay_pos = 0;
        dev_log(sys, 3, b"[wal] replay seg".as_ptr(), 16);
        // The FS_OPEN above may have paid the one-time cold directory-scan
        // penalty (tens of ms). Forgive it via Burst and read entries on
        // subsequent (warm, fast) steps rather than falling through here —
        // this keeps per-entry replay paced one-per-step (no over-drain of
        // the downstream ack channel) while the cold open never faults.
        return STEP_BURST;
    }

    // Read one framed entry: [entry_len: u32 LE] [crc32c: u32 LE] [entry_data]
    const FRAME_HDR: u32 = 8;
    let remaining = s.replay_file_size - s.replay_pos;
    if remaining < FRAME_HDR {
        // Not enough data for a frame header — segment done
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Read the 8-byte header (length + CRC32C)
    let mut hdr = [0u8; FRAME_HDR as usize];
    let n = (sys.provider_call)(s.replay_fd, FS_READ, hdr.as_mut_ptr(), FRAME_HDR as usize);
    if n < FRAME_HDR as i32 {
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }
    s.replay_pos += FRAME_HDR;

    let entry_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let stored_crc = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    if entry_len == 0 || entry_len > 2048 || (entry_len as u32) > (s.replay_file_size - s.replay_pos) {
        // Invalid / impossible length — a torn header. Stop replay for this
        // segment at the last good entry.
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Read entry data
    let entry_payload_offset = s.replay_pos;
    let n2 = (sys.provider_call)(s.replay_fd, FS_READ, s.msg_buf.as_mut_ptr(), entry_len);
    if (n2 as usize) < entry_len {
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }
    s.replay_pos += entry_len as u32;

    // Integrity check: recompute the payload CRC32C and compare. A mismatch
    // means a torn or corrupt payload — stop replay here (the durable prefix
    // up to this frame is the recoverable log) rather than replaying garbage.
    let actual_crc = {
        let mut c = Crc32c::new();
        c.update(&s.msg_buf[..entry_len]);
        c.finalize()
    };
    if actual_crc != stored_crc {
        s.checksum_failures = s.checksum_failures.saturating_add(1);
        dev_log(sys, 3, b"[wal] replay CRC FAIL".as_ptr(), 21);
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Parse: first 16 bytes are term(8) + index(8)
    if entry_len >= 16 {
        let (term, index) = wire::decode_term_index(&s.msg_buf);

        if index > s.current_index {
            s.current_index = index;
            s.current_term = term;
        }
        record_entry_loc(s, index, term, s.replay_seg, entry_payload_offset, entry_len as u32);
        note_ledger_ack(s, term, index);

        // Re-emit as FsyncAck — entry is already durable on disk
        let poll = (sys.channel_poll)(s.out_flushed, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            let mut ack = [0u8; 17];
            wire::encode_fsync_ack(&mut ack, term, index, s.self_id);
            wire_channels::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack[..17]);
            dev_log(sys, 3, b"[wal] replayed".as_ptr(), 14);
        }

        s.entries_written += 1;
        s.replayed_count += 1;
    }

    0
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn build_segment_path(s: &mut Wal, seq: u32) {
    let n = encode_segment_path(s.partition_id, seq, s.root_path != 0, &mut s.path_buf);
    s.path_len = n as u8;
}

/// Free function: write the segment path for `(partition_id, seq)`
/// into `out` and return the length written. Used by both the
/// stateful `build_segment_path` (above) and by random-access
/// readers that need a local path buffer.
///
/// Layout: `wal/p<NNNN>_seg_<NNNNNNNN>` — single-directory, every
/// partition's segments live alongside each other under one
/// `wal/` directory. The partition prefix is always present
/// (`p0000` for single-partition deployments) so the directory
/// contains one consistent filename shape and operators see at a
/// glance which partition a segment belongs to.
///
/// Operator requirement: `wal/` must exist and be writable in the
/// process working directory. The Linux FS provider's
/// `OPEN_CREATE` opcode creates files but does not `mkdir`
/// parents (there is no `FS_MKDIR` opcode today). The single-
/// directory layout means a single `mkdir wal` (or a symlink to
/// the operator's preferred path, e.g. `ln -s /var/lib/quantum/wal
/// wal`) suffices for any partition count. See
/// `modules/app/durability/manifest.toml` for the wider deployment note.
fn encode_segment_path(partition_id: u16, seq: u32, root: bool, out: &mut [u8]) -> usize {
    let cap = out.len();
    let mut i = 0usize;
    if root {
        // 8.3-conforming, root-relative: "<p:1hex><seq:7hex>.WAL" (≤12 chars).
        // Bare-metal FAT32 has no mkdir (so no `wal/` parent) and rejects
        // names longer than 8.3. 1 partition nibble + 7 seq nibbles covers
        // 16 partitions × 268M segments — ample for any real log.
        let p = (partition_id & 0xF) as u8;
        out[i] = if p < 10 { b'0' + p } else { b'a' + p - 10 }; i += 1;
        for digit in (0..7).rev() {
            let nibble = ((seq >> (digit * 4)) & 0xF) as u8;
            let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            if i < cap { out[i] = ch; i += 1; }
        }
        for &b in b".WAL" {
            if i < cap { out[i] = b; i += 1; }
        }
        return i;
    }
    for &b in b"wal/p" {
        if i < cap { out[i] = b; i += 1; }
    }
    for digit in (0..4).rev() {
        let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        if i < cap { out[i] = ch; i += 1; }
    }
    for &b in b"_seg_" {
        if i < cap { out[i] = b; i += 1; }
    }
    for digit in (0..8).rev() {
        let nibble = ((seq >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        if i < cap { out[i] = ch; i += 1; }
    }
    i
}

// ── Normal operation ────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_entries(s: &mut Wal, sys: &SyscallTable) {
    // Once continuity is lost, consuming later records cannot repair it: Raft
    // no longer retains the missing proposal body. Leave the input full so
    // backpressure propagates, and never acknowledge a high-water across the
    // hole.
    if s.continuity_fault { return; }

    // An async durability fence is outstanding for the current batch. Do NOT
    // stage new records: they would advance `pending_max_index` past what the
    // fence covers, so the pending FsyncAck would falsely claim them durable.
    // The record waits in the input channel (backpressure) until the fence
    // resolves and the batch resets; `flush_batch` keeps polling it each step.
    //
    // Pipelined mode (`fence_depth > 1`) lifts this: each in-flight fence
    // snapshots its own covered high-water into `fence_ring`, so staging past
    // an outstanding fence is safe. Backpressure only when the ring is full.
    if s.fence_failed { return; } // latched fail-stop: hold intake, no acks
    if s.fs_async && s.fence_depth > 1 {
        let depth = (s.fence_depth as usize).min(FENCE_RING_MAX);
        if (s.fence_ring_count as usize) >= depth { return; }
    } else if s.fence_pending {
        return;
    }

    // Check input readiness
    let poll_in = (sys.channel_poll)(s.in_entries, 0x01);
    if poll_in <= 0 || (poll_in as u32 & 0x01) == 0 { return; }

    // Output back-pressure: only block when out_flushed is wired AND
    // currently not writable. An unwired output (`out_flushed < 0`,
    // e.g. a partitioned graph that hasn't built the per-partition
    // commit pipeline yet) shouldn't gate disk durability — the WAL's
    // job is to write entries, the FsyncAck is a downstream
    // optimisation. Skipping the ack is fine; skipping the write
    // would silently drop committed log entries.
    if s.out_flushed >= 0 {
        let poll_out = (sys.channel_poll)(s.out_flushed, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }
    }

    // Read entry
    let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
    if msg_type != wire::MSG_WAL_ENTRY || plen < 16 { return; }

    let (term, index) = wire::decode_term_index(&s.msg_buf);
    let payload_len = plen as usize;

    let expected = s.current_index.saturating_add(1);
    if index != expected {
        // Commit only the valid contiguous prefix already staged, then latch
        // closed. This record is deliberately not reflected in cursor/index.
        if s.has_batch {
            flush_batch(s, sys);
        }
        s.continuity_errors = s.continuity_errors.saturating_add(1);
        s.continuity_fault = true;
        dev_log(sys, 3, b"[wal] continuity FAIL".as_ptr(), 21);
        return;
    }

    // Frame: [entry_len: u32 LE] [crc32c: u32 LE] [entry_data]. The CRC32C
    // covers the payload bytes so replay can distinguish a torn/corrupt
    // payload from a valid entry (RFC §5: "the current replay framing cannot
    // reliably distinguish a torn payload from a valid entry"). Track the
    // payload offset (after the 8-byte header) so MSG_WAL_ENTRY_REQUEST can
    // read it back. In group mode the FS_FSYNC is deferred to flush_batch —
    // emitting the ack before that fsync would signal durability that doesn't
    // yet hold on disk.
    const FRAME_HDR: u32 = 8;
    let entry_payload_offset = s.cursor.saturating_add(FRAME_HDR);
    ensure_segment_open(s, sys);
    if s.fd < 0 {
        if s.no_fs {
            // Explicit ephemeral mode: retain the recent proposal body for
            // the same random-access gap-refetch contract as the disk path,
            // then acknowledge immediately (there is no durability barrier).
            let body_len = payload_len.saturating_sub(16).min(MEMORY_ENTRY_BODY_CAP);
            let slot = (index & ENTRY_RING_MASK) as usize;
            s.memory_entries[slot].index = index;
            s.memory_entries[slot].body_len = body_len as u16;
            if body_len > 0 {
                s.memory_entries[slot].body[..body_len]
                    .copy_from_slice(&s.msg_buf[16..16 + body_len]);
            }
            s.current_term = term;
            s.current_index = index;
            s.cursor = s.cursor.saturating_add(FRAME_HDR + payload_len as u32);
            s.entries_written = s.entries_written.saturating_add(1);
            s.bytes_written = s.bytes_written.saturating_add(payload_len as u64);
            record_entry_loc(s, index, term, 0, 0, payload_len as u32);
            note_ledger_ack(s, term, index);
            if s.out_flushed >= 0 {
                let mut ack_buf = [0u8; 17];
                wire::encode_fsync_ack(&mut ack_buf, term, index, s.self_id);
                wire_channels::channel_write_msg(
                    sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf,
                );
                // Ephemeral mode has no fsync barrier — the ack above
                // IS the durability point (there is no disk state to
                // wait on). Same external signal as the disk path in
                // `flush_batch`.
                dev_log(sys, 3, b"[wal] entry ok".as_ptr(), 14);
            }
            return;
        }
        // A configured filesystem exists but the segment could not be opened:
        // fail closed rather than acknowledging data that was not persisted.
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 3, b"[wal] entry FAIL no-fd".as_ptr(), 22);
        return;
    }
    // Stage a complete record contiguously so group mode coalesces
    // several records into ONE provider write as well as one fsync,
    // rather than issuing separate header and body writes per entry.
    let crc = {
        let mut c = Crc32c::new();
        c.update(&s.msg_buf[..payload_len]);
        c.finalize()
    };
    let frame_len = FRAME_HDR as usize + payload_len;
    if frame_len > WRITE_BUF_SIZE { return; }
    if s.write_pos as usize + frame_len > WRITE_BUF_SIZE {
        flush_batch(s, sys);
        if s.has_batch { return; }
    }
    let pos = s.write_pos as usize;
    s.write_buf[pos..pos + 4].copy_from_slice(&(payload_len as u32).to_le_bytes());
    s.write_buf[pos + 4..pos + 8].copy_from_slice(&crc.to_le_bytes());
    s.write_buf[pos + 8..pos + frame_len].copy_from_slice(&s.msg_buf[..payload_len]);
    s.write_pos = (pos + frame_len) as u16;

    s.current_term = term;
    s.current_index = index;
    s.cursor += FRAME_HDR + payload_len as u32;
    s.entries_written += 1;
    s.bytes_written += payload_len as u64;
    record_entry_loc(s, index, term, s.segment_seq, entry_payload_offset, payload_len as u32);

    if !s.has_batch {
        s.batch_start_ms = dev_millis(sys);
        s.has_batch = true;
    }
    s.batch_fsynced = false;
    if index >= s.pending_max_index {
        s.pending_max_index = index;
        s.pending_max_term = term;
    }
    s.pending_count = s.pending_count.saturating_add(1);

    // Per-append staging signal, mode-exclusive: `fsync_mode == 0`
    // (per-entry) always flushes this same append immediately below,
    // so "staged" and "durable" coincide — log `entry ok`. Group
    // mode (`fsync_mode == 1`) may hold this entry in the pending
    // batch for a while, so "staged" is a distinct, weaker claim —
    // log `entry queued`; durability gets its own signal
    // (`[wal] group fsync`) from `flush_batch` once the batch
    // actually lands.
    if s.fsync_mode == 0 {
        dev_log(sys, 3, b"[wal] entry ok".as_ptr(), 14);
    } else {
        dev_log(sys, 3, b"[wal] entry queued".as_ptr(), 18);
    }

    // A truncate leaves stale bytes beyond the logical tail. Append a replay
    // terminator to this staged write and flush it immediately; flush_batch
    // restores the fd to `cursor` before the durability barrier.
    if s.cursor < s.seg_high_water {
        if s.write_pos as usize + 4 <= WRITE_BUF_SIZE {
            let p = s.write_pos as usize;
            s.write_buf[p..p + 4].fill(0);
            s.write_pos += 4;
            s.staged_terminator = true;
        }
    } else {
        s.seg_high_water = s.cursor;
    }

    if s.fsync_mode == 0
        || s.pending_count >= s.group_max_pending
        || s.staged_terminator
    {
        flush_batch(s, sys);
    }

    // Segment rotation must flush any pending batch first so the ack
    // is ordered relative to the close.
    if s.cursor >= s.segment_limit {
        if s.has_batch {
            flush_batch(s, sys);
            if s.has_batch { return; }
        }
        flush_block(s, sys);
        fsync_segment(s, sys);
        close_segment(s, sys);

        note_trigger(s, s.current_term, s.current_index);
        if s.out_compaction >= 0 {
            let mut trig = [0u8; 16];
            wire::encode_term_index(&mut trig, s.current_term, s.current_index);
            wire_channels::channel_write_msg(sys, s.out_compaction, wire::MSG_SNAPSHOT_TRIGGER, &trig[..16]);
        }
        s.segment_seq += 1;
        s.cursor = 0;
        s.seg_high_water = 0;
        s.crc.reset();
    }
}

/// Fence-pipelined flush (config `fence_depth > 1`, async FS only).
///
/// Two phases per call:
///   1. Reap completed fences from the head of `fence_ring` (FIFO). Each
///      fence carries the (term, index) high-water it covers; on `durable`
///      we emit that MSG_FSYNC_ACK. A fenced-write failure is FATAL (withhold
///      the ack; commit never advances past a non-durable entry). If the ack
///      channel is full we stop and retry next step (the fence stays queued).
///   2. If a batch is staged and the ring has room (< effective depth), write
///      it (FS_WRITE_ASYNC) and open a new fence (FS_FSYNC_SUBMIT), snapshotting
///      the current cumulative high-water into the ring slot so subsequent
///      staging can't corrupt this fence's coverage.
///
/// Durability invariant preserved: an entry is acked only after its write is
/// on stable media, and acks are strictly in raft-log order (FIFO reap of a
/// monotonic, cumulative fence sequence). The write/seek/terminator logic
/// mirrors the single-fence `flush_batch` body exactly.
///
/// # Safety
/// As `flush_batch`: exclusive `&mut Wal` + a live `&SyscallTable`.
unsafe fn flush_batch_pipelined(s: &mut Wal, sys: &SyscallTable) {
    // ── 1. Reap completed fences (oldest first → in-order acks). ──
    while s.fence_ring_count > 0 {
        let (ticket, max_index, max_term) = s.fence_ring[s.fence_ring_head as usize];
        let mut tb = ticket.to_le_bytes();
        let rc = (sys.provider_call)(s.fd, FS_FSYNC_POLL, tb.as_mut_ptr(), 8);
        if rc == 1 {
            break; // oldest fence still in flight; nothing newer can be acked
        }
        if rc != 0 {
            // A fenced write FAILED — durability gap. Latch fail-stop (see
            // `fence_failed`); the flush entry point holds all further work.
            s.fence_failed = true;
            s.write_errors = s.write_errors.saturating_add(1);
            dev_log(sys, 1, b"[wal] FATAL async durable-write failed".as_ptr(), 38);
            return;
        }
        // Durable — deliver to the ledger component, then emit this
        // fence's FsyncAck (retry next step if channel full).
        note_ledger_ack(s, max_term, max_index);
        if s.out_flushed >= 0 {
            let poll_out = (sys.channel_poll)(s.out_flushed, POLL_OUT);
            if poll_out <= 0 || (poll_out as u32 & POLL_OUT) == 0 {
                return; // ack channel full — keep the fence queued, retry later
            }
            let mut ack_buf = [0u8; 17];
            wire::encode_fsync_ack(&mut ack_buf, max_term, max_index, s.self_id);
            wire_channels::channel_write_msg(
                sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17],
            );
        }
        s.fence_ring_head = ((s.fence_ring_head as usize + 1) % FENCE_RING_MAX) as u8;
        s.fence_ring_count -= 1;
    }

    // ── 2. Submit a new fence for the staged batch if the ring has room. ──
    if !s.has_batch {
        return;
    }
    let depth = (s.fence_depth as usize).min(FENCE_RING_MAX);
    if (s.fence_ring_count as usize) >= depth {
        return; // fence ring full → backpressure; batch stays staged
    }

    // Fixed-segment replay terminator (mirrors the single-fence body).
    if s.fixed_segment_active && !s.staged_terminator {
        if s.write_pos as usize + 4 > WRITE_BUF_SIZE {
            s.write_errors = s.write_errors.saturating_add(1);
            dev_log(sys, 3, b"[wal] terminator overflow".as_ptr(), 25);
            return;
        }
        let p = s.write_pos as usize;
        s.write_buf[p..p + 4].fill(0);
        s.write_pos += 4;
        s.staged_terminator = true;
    }

    if s.write_pos > 0 {
        let staged_len = s.write_pos as usize;
        let terminator_len = if s.staged_terminator { 4usize } else { 0usize };
        let logical_len = staged_len.saturating_sub(terminator_len);
        let batch_start = s.cursor.saturating_sub(logical_len as u32);
        let seek_arg = (batch_start as i32).to_le_bytes();
        let seek_rc =
            (sys.provider_call)(s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, seek_arg.len());
        if seek_rc < 0 {
            s.write_errors = s.write_errors.saturating_add(1);
            dev_log(sys, 3, b"[wal] group seek FAIL".as_ptr(), 21);
            return;
        }
        let written =
            (sys.provider_call)(s.fd, FS_WRITE_ASYNC, s.write_buf.as_mut_ptr(), staged_len);
        if written == FS_E_AGAIN || (written >= 0 && (written as usize) < staged_len) {
            // Backpressure (nvme async ring full). Rewind, keep the batch staged,
            // retry next step. Nothing acked → no durability impact.
            (sys.provider_call)(s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, seek_arg.len());
            return;
        }
        if written < 0 {
            (sys.provider_call)(s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, seek_arg.len());
            s.write_errors = s.write_errors.saturating_add(1);
            dev_log(sys, 1, b"[wal] FATAL group write failed".as_ptr(), 30);
            return;
        }
        if s.staged_terminator {
            let logical_end = (s.cursor as i32).to_le_bytes();
            let seek_rc = (sys.provider_call)(
                s.fd, FS_SEEK, logical_end.as_ptr() as *mut u8, logical_end.len(),
            );
            if seek_rc < 0 {
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 3, b"[wal] restore seek FAIL".as_ptr(), 23);
                return;
            }
        }
        s.write_pos = 0;
        s.staged_terminator = false;
    }

    // Open the durability fence covering everything written so far.
    let mut tb = [0u8; 8];
    let rc = (sys.provider_call)(s.fd, FS_FSYNC_SUBMIT, tb.as_mut_ptr(), 8);
    if rc == FS_E_AGAIN {
        // Scratch-flush ring-full backpressure; the batch write already landed
        // (write_pos == 0). Retry the fence next step — the cumulative next
        // fence still covers these records, so no ack is lost.
        return;
    }
    if rc != 0 {
        s.fence_failed = true;
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 1, b"[wal] FATAL fence submit failed".as_ptr(), 31);
        return;
    }
    let ticket = u64::from_le_bytes(tb);
    let tail = (s.fence_ring_head as usize + s.fence_ring_count as usize) % FENCE_RING_MAX;
    s.fence_ring[tail] = (ticket, s.pending_max_index, s.pending_max_term);
    s.fence_ring_count += 1;
    // Batch consumed — clear so process_entries stages the next one.
    s.has_batch = false;
    s.pending_count = 0;
    s.batch_fsynced = false;
}

/// Fsync the segment and emit one MSG_FSYNC_ACK for the batch high-water
/// (term, index). No-op on an empty batch.
///
/// The batch is only cleared once its ack is actually delivered (or there is
/// no `out_flushed` consumer). If the channel is full, the fsync still
/// happened — we mark `batch_fsynced` and keep the high-water so a later step
/// retries the ack without paying a second fsync. Dropping it here would stall
/// commit for a writer that then goes quiescent (the next ack can't subsume a
/// skipped one if there is no next ack). P1: failed WAL I/O acknowledgements.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_batch(s: &mut Wal, sys: &SyscallTable) {
    // Probe the FS provider's async durable-write capability once, before the
    // first write is issued, so `fs_async` reflects the backend.
    ensure_fs_caps(s, sys);

    // A fence failure is a durability gap — latched fail-stop. No further
    // writes, fences, or acks; only a restart recovers (see `fence_failed`).
    if s.fence_failed { return; }

    // Fence-pipelined async path (config `fence_depth > 1`): keeps multiple
    // fences outstanding so throughput is device-bandwidth-bound rather than
    // 1/fence-latency. Runs every step (reaps even with no staged batch).
    if s.fs_async && s.fence_depth > 1 {
        flush_batch_pipelined(s, sys);
        return;
    }

    if !s.has_batch { return; }

    if !s.batch_fsynced {
        // ── Async fence poll ──────────────────────────────────────────
        // If a non-blocking durability fence is outstanding, poll it. This
        // is the seam that lets the fsync leave the scheduler step: the
        // write was submitted earlier; here we only observe completion.
        if s.fence_pending {
            let mut tb = s.fence_ticket.to_le_bytes();
            let rc = (sys.provider_call)(s.fd, FS_FSYNC_POLL, tb.as_mut_ptr(), 8);
            if rc == 1 {
                // Still pending — the batch is not yet durable this step.
                return;
            }
            if rc == 0 {
                // Durable: every fenced write is on non-volatile media.
                s.fence_pending = false;
                s.batch_fsynced = true;
                // fall through to emit the FsyncAck
            } else {
                // A fenced write FAILED — durability gap. Latch fail-stop
                // (see `fence_failed`): withhold the ack and keep the fence
                // outstanding so we do not re-write and mask it.
                s.fence_failed = true;
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 1, b"[wal] FATAL async durable-write failed".as_ptr(), 38);
                return;
            }
        }

        if !s.batch_fsynced {
            // A fixed-capacity segment has no useful EOF: its directory size was
            // persisted once at creation. Make the current live tail explicit in
            // the same provider write as the records. Replay stops on this zero
            // length even though STAT reports the full segment capacity.
            if s.fixed_segment_active && !s.staged_terminator {
                if s.write_pos as usize + 4 > WRITE_BUF_SIZE {
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 3, b"[wal] terminator overflow".as_ptr(), 25);
                    return;
                }
                let p = s.write_pos as usize;
                s.write_buf[p..p + 4].fill(0);
                s.write_pos += 4;
                s.staged_terminator = true;
            }
            // `cursor` tracks the logical end of the staged records, while the
            // optional four-byte replay terminator is deliberately outside that
            // logical range. Seek explicitly because an entry-refetch read may
            // have moved the shared descriptor since this batch was staged.
            if s.write_pos > 0 {
                let staged_len = s.write_pos as usize;
                let terminator_len = if s.staged_terminator { 4usize } else { 0usize };
                let logical_len = staged_len.saturating_sub(terminator_len);
                let batch_start = s.cursor.saturating_sub(logical_len as u32);
                let seek_arg = (batch_start as i32).to_le_bytes();
                let seek_rc = (sys.provider_call)(
                    s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, seek_arg.len(),
                );
                if seek_rc < 0 {
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 3, b"[wal] group seek FAIL".as_ptr(), 21);
                    return;
                }

                // Async mode submits via FS_WRITE_ASYNC (pipelined, copied
                // into device DMA slots so `write_buf` is free on return);
                // durability is proven later by the FSYNC_SUBMIT/POLL fence.
                let write_op = if s.fs_async { FS_WRITE_ASYNC } else { FS_WRITE };
                let written = (sys.provider_call)(
                    s.fd, write_op, s.write_buf.as_mut_ptr(), staged_len,
                );
                if written == FS_E_AGAIN || (written >= 0 && (written as usize) < staged_len) {
                    // BACKPRESSURE (async ring full mid-batch), NOT an error.
                    // Rewind and retry the whole batch next step; in-flight
                    // writes drain within a step or two. The batch stays
                    // staged (`write_pos` not reset). No error count, no
                    // durability impact — nothing was acked.
                    (sys.provider_call)(
                        s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, seek_arg.len(),
                    );
                    return;
                }
                if written < 0 {
                    // A genuine write error. Rewind, count, and surface it.
                    (sys.provider_call)(
                        s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, seek_arg.len(),
                    );
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 1, b"[wal] FATAL group write failed".as_ptr(), 30);
                    return;
                }

                if s.staged_terminator {
                    let logical_end = (s.cursor as i32).to_le_bytes();
                    let seek_rc = (sys.provider_call)(
                        s.fd, FS_SEEK, logical_end.as_ptr() as *mut u8, logical_end.len(),
                    );
                    if seek_rc < 0 {
                        s.write_errors = s.write_errors.saturating_add(1);
                        dev_log(sys, 3, b"[wal] restore seek FAIL".as_ptr(), 23);
                        return;
                    }
                }

                s.write_pos = 0;
                s.staged_terminator = false;
            }

            // ── Durability fence ──────────────────────────────────────
            if s.fs_async {
                // Open a non-blocking fence and hand off; the ack is emitted
                // on a later step once the poll (above) reports durable.
                let mut tb = [0u8; 8];
                let rc = (sys.provider_call)(s.fd, FS_FSYNC_SUBMIT, tb.as_mut_ptr(), 8);
                if rc == 0 {
                    s.fence_ticket = u64::from_le_bytes(tb);
                    s.fence_pending = true;
                    return;
                }
                if rc == FS_E_AGAIN {
                    // The final scratch flush hit ring-full backpressure — no
                    // fence opened. Retry the fence next step (the write above
                    // already succeeded; write_pos is 0 so we re-enter here).
                    return;
                }
                // A genuine error opening the fence — latch fail-stop and
                // withhold the ack (see `fence_failed`).
                s.fence_failed = true;
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 1, b"[wal] FATAL fence submit failed".as_ptr(), 31);
                return;
            }

            if fsync_segment(s, sys) != 0 {
                // Deferred group fsync failed — the batch is NOT durable. Withhold
                // the FsyncAck (commit must not advance past it) and keep the batch
                // intact so a later flush retries instead of losing durability.
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 3, b"[wal] group fsync FAIL".as_ptr(), 22);
                return;
            }
            s.batch_fsynced = true;
        }
    }

    note_ledger_ack(s, s.pending_max_term, s.pending_max_index);
    if s.out_flushed >= 0 {
        let poll_out = (sys.channel_poll)(s.out_flushed, POLL_OUT);
        if poll_out <= 0 || (poll_out as u32 & POLL_OUT) == 0 {
            // Channel full: the batch is durable but unacked. Keep it and retry
            // the ack on a later step (next entry or the time-based flush).
            dev_log(sys, 3, b"[wal] group ack deferred".as_ptr(), 24);
            return;
        }
        let mut ack_buf = [0u8; 17];
        wire::encode_fsync_ack(
            &mut ack_buf, s.pending_max_term, s.pending_max_index, s.self_id,
        );
        wire_channels::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17]);
        // Batch-durability signal, group mode only: per-entry mode
        // (`fsync_mode == 0`) also flows through this function (every
        // append flushes its own singleton batch immediately — see
        // the call site's condition), but its durability signal is
        // already `[wal] entry ok` at stage time, which coincides
        // exactly since the batch never holds more than that one
        // entry. Logging `group fsync` there too would be redundant
        // and would break the per-entry/group dichotomy the wal
        // group-fsync test suite asserts on.
        if s.fsync_mode != 0 {
            dev_log(sys, 3, b"[wal] group fsync".as_ptr(), 17);
        }
    }

    s.has_batch = false;
    s.batch_fsynced = false;
    s.fence_pending = false;
    s.pending_count = 0;
    s.pending_max_index = 0;
    s.pending_max_term = 0;
    s.batch_start_ms = 0;
}

/// Open or create the current WAL segment file. Replay (read-only)
/// still uses `FS_OPEN` so it can detect "no more segments" via
/// ENODEV; the write side needs the create tier.
///
/// fd < 0 means FS unavailable (e.g. bare-metal without a mounted
/// filesystem) — module degrades to in-memory only.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ensure_segment_open(s: &mut Wal, sys: &SyscallTable) {
    if s.fd >= 0 { return; }
    if VOLATILE {
        // The volatile variant selects in-memory retention by design —
        // never a fallback, so no `[wal] no fs` signal.
        s.no_fs = true;
        return;
    }
    build_segment_path(s, s.segment_seq);
    s.fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), s.path_len as usize);
    if s.fd >= 0 && s.fixed_segment != 0 {
        // Reserve four bytes beyond the configured record limit for the live
        // tail terminator. PREALLOCATE persists physical capacity + fixed file
        // size and leaves the descriptor at offset zero.
        let capacity = s.segment_limit.saturating_add(4);
        let cap = capacity.to_le_bytes();
        let prc = (sys.provider_call)(
            s.fd, FS_PREALLOCATE, cap.as_ptr() as *mut u8, cap.len(),
        );
        if prc == 0 {
            // Establish a durable empty-log terminator before admission. A
            // crash after preallocation but before the first client append
            // must replay zero entries, never stale preallocated data.
            let zero = [0u8; 4];
            let w = (sys.provider_call)(s.fd, FS_WRITE, zero.as_ptr() as *mut u8, zero.len());
            let seek = 0i32.to_le_bytes();
            let sr = (sys.provider_call)(s.fd, FS_SEEK, seek.as_ptr() as *mut u8, seek.len());
            let fr = (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
            if w == 4 && sr == 0 && fr == 0 {
                s.fixed_segment_active = true;
                s.preallocate_ready_at_ms = dev_millis(sys)
                    .saturating_add(s.preallocate_settle_ms as u64);
            } else {
                (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                s.fd = -1;
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 3, b"[wal] prealloc init FAIL".as_ptr(), 24);
                return;
            }
        }
        // ENOSYS/unsupported is an intentional compatibility fallback: this
        // descriptor remains a normal EOF-sized append file.
    }
    // DIAG: surface the create rc (E_AGAIN=-11 = fat32 not ready, retry;
    // a hard negative = no/failed FS provider; >=0 = disk-backed).
    if s.fd != s.dbg_last_open_rc {
        s.dbg_last_open_rc = s.fd;
        let mut m = [0u8; 32]; let p = m.as_mut_ptr();
        let tag = b"[wal] open rc="; core::ptr::copy_nonoverlapping(tag.as_ptr(), p, tag.len());
        let neg = s.fd < 0;
        let mut q = tag.len();
        if neg { *p.add(q) = b'-'; q += 1; }
        q += fmt_u32_raw(p.add(q), (s.fd as i64).unsigned_abs() as u32);
        dev_log(sys, 3, p, q);
    }
    if s.fd >= 0 || s.fd == FS_E_AGAIN {
        // Disk-backed, or the provider is initialising (retry next step).
        return;
    }
    // Hard error (no FS provider / missing parent): degrade to in-memory
    // permanently and emit the fallback signal once.
    s.no_fs = true;
    if !s.no_fs_logged {
        s.no_fs_logged = true;
        dev_log(sys, 3, b"[wal] no fs".as_ptr(), 11);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_block(s: &mut Wal, sys: &SyscallTable) {
    if s.write_pos == 0 { return; }

    ensure_segment_open(s, sys);

    if s.fd >= 0 {
        let len = s.write_pos as usize;
        (sys.provider_call)(s.fd, FS_WRITE, s.write_buf.as_mut_ptr(), len);
    }

    s.write_pos = 0;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Fsync the current segment file, timing the call and folding the
/// elapsed µs into the `clustor.wal.fsync_latency_ms` histogram
/// (RFC §4.1). All durable-write fsync sites route through here so the
/// histogram covers both strict per-entry and group-deferred fsyncs.
///
/// Returns 0 on success, the provider's negative errno on failure, or -1 when
/// there is no open segment. A failed fsync is NOT folded into the latency
/// histogram (it isn't a real durability measurement); callers must treat a
/// non-zero return as "not durable" and withhold the FsyncAck.
unsafe fn fsync_segment(s: &mut Wal, sys: &SyscallTable) -> i32 {
    if s.fd < 0 { return -1; }
    let start = dev_micros(sys);
    let rc = (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
    if rc != 0 { return rc; }
    let elapsed = dev_micros(sys).wrapping_sub(start);
    let b = wire::hist::bucket(&wire::hist::FSYNC_LATENCY_US, elapsed);
    s.fsync_buckets[b] = s.fsync_buckets[b].saturating_add(1);
    0
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Close current segment and prepare for rotation.
unsafe fn close_segment(s: &mut Wal, sys: &SyscallTable) {
    if s.fd >= 0 {
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
    s.fixed_segment_active = false;
    s.preallocate_ready_at_ms = 0;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_metrics(s: &mut Wal, sys: &SyscallTable) {
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // `[wal] hb` — steady-state liveness on the foundation-module
    // heartbeat cadence. Survives log_net's history-skip (drain_net
    // seeds TAIL_NET=HEAD on first call), which discards init-time
    // one-shot markers. Fires regardless of out_metrics wiring.
    let mut hb = [0u8; 96];
    let mut pos = 0usize;
    pos += emit_field(hb.as_mut_ptr(), pos, b"[wal] hb mode=", s.fsync_mode as u32);
    // Durability state, on the heartbeat rather than only in the
    // one-shot `open rc=` line: 1 = a real segment descriptor is open
    // (disk-backed), 0 = not (provider still initialising, or the
    // in-memory retention path). An observer that attaches after boot
    // — the UDP log monitor does exactly that, and rig pass rules may
    // only key on recurring signals (`standards/rig.md`) — otherwise
    // has no way to tell a disk-durable node from an ephemeral one.
    // The same fact is a gauge (`WAL_OPEN_RC`) for /metrics consumers.
    pos += emit_field(hb.as_mut_ptr(), pos, b" fs=", (s.fd >= 0) as u32);
    pos += emit_field(hb.as_mut_ptr(), pos, b" seg=", s.segment_seq);
    pos += emit_field(hb.as_mut_ptr(), pos, b" entries=", s.entries_written);
    pos += emit_field(hb.as_mut_ptr(), pos, b" batch=", s.has_batch as u32);
    pos += emit_field(hb.as_mut_ptr(), pos, b" pending=", s.pending_count as u32);
    dev_log(sys, 3, hb.as_ptr(), pos);

    if s.out_metrics < 0 { return; }

    // Typed metric samples (RFC §4.3): scalar counters/gauges plus the
    // fsync-latency histogram. Each sample is its own MSG_METRIC_SAMPLE
    // so the telemetry component aggregates without a per-module parser. The
    // legacy MSG_METRICS envelope is still emitted below for observers
    // that parse it.
    let mid = wire::SOURCE_ID_WAL;
    let pid = s.partition_id;
    let kc = wire::METRIC_KIND_COUNTER;
    let kg = wire::METRIC_KIND_GAUGE;
    let kh = wire::METRIC_KIND_HISTOGRAM;
    let scalars: [(u16, u8, i64); 17] = [
        (wire::metric_ids::WAL_ENTRIES_WRITTEN, kc, i64::from(s.entries_written)),
        (wire::metric_ids::WAL_WRITE_ERRORS, kc, i64::from(s.write_errors)),
        (wire::metric_ids::WAL_CHECKSUM_FAILURES, kc, i64::from(s.checksum_failures)),
        (wire::metric_ids::WAL_TRUNCATIONS, kc, i64::from(s.truncations)),
        (wire::metric_ids::WAL_BYTES_WRITTEN, kc, s.bytes_written as i64),
        (wire::metric_ids::WAL_SEGMENT_SEQ, kg, i64::from(s.segment_seq)),
        // §4.2 saturation gauge: entries written but not yet group-fsynced.
        (wire::metric_ids::WAL_PENDING_DEPTH, kg, i64::from(s.pending_count)),
        // Diagnostic: last FS_OPEN_CREATE rc (>=0 disk, <0 in-memory fallback).
        (wire::metric_ids::WAL_OPEN_RC, kg, i64::from(s.dbg_last_open_rc)),
        (wire::metric_ids::WAL_STEPS, kc, s.dbg_steps as i64),
        (wire::metric_ids::WAL_REPLAY_HW, kg, s.replay_hw_sent as i64),
        (wire::metric_ids::WAL_REPLAYED, kc, i64::from(s.replayed_count)),
        (wire::metric_ids::WAL_REPLAY_FSIZE, kg, i64::from(s.replay_first_size)),
        (wire::metric_ids::WAL_ENTRYREQ_SERVED, kc, i64::from(s.entryreq_served)),
        (wire::metric_ids::WAL_ENTRYREQ_NOTFOUND, kc, i64::from(s.entryreq_notfound)),
        (wire::metric_ids::WAL_INPUT_BUDGET_BYTES, kg, i64::from(s.input_budget_bytes)),
        (wire::metric_ids::WAL_PUMP_RECORDS, kg, i64::from(s.pump_records)),
        (wire::metric_ids::WAL_CONTINUITY_ERRORS, kc, i64::from(s.continuity_errors)),
    ];
    for &(metric_id, kind, value) in scalars.iter() {
        emit_sample(s, sys, mid, pid, metric_id, kind, value);
    }
    // Cumulative bucket counts per the wire contract (wire::hist): bucket i
    // carries the count of samples <= bound[i], so emit the running prefix sum.
    let base = wire::hist::HIST_BASE;
    let mut cum: i64 = 0;
    for i in 0..s.fsync_buckets.len() {
        cum += i64::from(s.fsync_buckets[i]);
        emit_sample(s, sys, mid, pid, base + i as u16, kh, cum);
    }

    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&s.entries_written.to_le_bytes());
    buf[4..12].copy_from_slice(&s.bytes_written.to_le_bytes());
    buf[12..16].copy_from_slice(&s.segment_seq.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..16]);
    }
}

/// Emit one typed metric sample on `out_metrics` if the channel has
/// write space. Drops the sample under backpressure — telemetry is
/// never allowed to stall the WAL hot path (standards §8).
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_sample(
    s: &Wal,
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

/// Append `tag` followed by `val`'s decimal representation at
/// `buf[start..]`. Returns the number of bytes written.
///
/// # Safety
///
/// `buf` must have room for `tag.len() + 10` bytes starting at `start`.
unsafe fn emit_field(buf: *mut u8, start: usize, tag: &[u8], val: u32) -> usize {
    core::ptr::copy_nonoverlapping(tag.as_ptr(), buf.add(start), tag.len());
    tag.len() + fmt_u32_raw(buf.add(start + tag.len()), val)
}
