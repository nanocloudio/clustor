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
use super::wal_frame;
use super::{
    dev_input_flow_budget, dev_log, dev_micros, dev_millis, dev_report_step_effect,
    fmt_u32_raw, step_effect, wire, wire_channels, POLL_IN, POLL_OUT,
};

/// Frame header size, as `u32` for the cursor/offset arithmetic in
/// this file. The canonical constant (and the full frame contract
/// shared with `clustor_cli`'s `wal-scan`) is `common/wal_frame.rs`.
const FRAME_HDR: u32 = wal_frame::FRAME_HDR as u32;

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

/// Slots in the index->offset map (`entry_ring`). Deliberately separate
/// from `ENTRY_RING_SIZE`, which also sizes `memory_entries` — those
/// carry full 2 KiB bodies, so the two cannot share a bound.
///
/// On restart, apply restarts at index 0 and refetches every entry;
/// any index below `entry_ring_min_index` misses the map. Locations
/// are 32 B, so 8192 slots cost ~256 KiB and cover realistic recovery
/// windows between snapshots.
///
/// The bound is NOT a hard recovery ceiling: a request below the ring
/// floor falls back to a bounded forward scan of the on-disk segments
/// (`step_entry_scan`), which locates the record by walking frames
/// from the oldest durable segment. Only indices whose segment was
/// compacted away are truly unservable (`[wal] entry req unservable`)
/// — for those, snapshot install is the only way back.
const ENTRY_LOC_RING_SIZE: usize = 8192;
const ENTRY_LOC_RING_MASK: u64 = (ENTRY_LOC_RING_SIZE as u64) - 1;
const MEMORY_ENTRY_BODY_CAP: usize = 2048;

/// Per-step record budget for the below-floor segment scan. Each
/// record costs one `FS_SEEK` + two small `FS_READ`s (frame header +
/// term/index prefix), so 16 records ≈ 48 provider calls — bounded,
/// auditable step work in the same spirit as `MAX_ENTRY_PUMP_RECORDS`.
/// The scan cursor persists across steps (and across served requests,
/// so sequential recovery refetches resume in O(1) instead of
/// rescanning from the segment start).
const SCAN_RECORDS_PER_STEP: usize = 16;

/// WCET/fairness backstop for the transaction-budgeted input pump. The byte
/// grant is the pacing authority; this cap only bounds the number of provider
/// calls when records are very small. Eight records still removes the
/// one-record-per-tick ceiling while keeping a worst-case step auditable.
const MAX_ENTRY_PUMP_RECORDS: usize = 8;

/// Pump cap when every record pays a SYNCHRONOUS fsync (`fsync_mode ==
/// 0` on a provider without the async fence tier). Eight × the ~250 µs
/// device fsync floor is ~2 ms — exactly the step-guard kill threshold —
/// so per-entry-sync mode halves the batch to keep headroom.
const MAX_SYNC_FSYNC_RECORDS: usize = 4;

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
/// Directory create (single-level, EEXIST-idempotent on the linux
/// provider; bare-metal FAT32 answers a clean ENOSYS). Used once per
/// boot to self-heal a missing `wal/` parent in dir-mode layouts.
///
/// Deliberately NOT gated on `caps::MKDIR` the way `FS_UNLINK` is
/// (`fs_unlink_supported`): this fires at most once per boot, only
/// after an open has already hard-failed, and the retried open — not
/// the mkdir's return — decides the outcome. A caps probe would cost
/// the same round-trip it saves.
const FS_MKDIR: u32 = 0x090B;
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
/// reading the BPB/GPT/root on a pi5 cold boot). Distinct from a hard error
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

/// Frames replayed per step once a segment is open. Each frame costs
/// two FS_READs plus a CRC over ≤2 KiB, so four keeps the step inside
/// the guard while still draining a multi-hundred-thousand-frame
/// segment in reasonable wall-clock.
const REPLAY_FRAMES_PER_STEP: usize = 4;

/// Physical segment deletions per step. FS_UNLINK is synchronous
/// (fat32 tombstones the dirent in-call), so a deep post-snapshot trim
/// is paced across steps by `continue_compaction` instead of unlinking
/// the whole droppable range inside one step.
const COMPACT_UNLINKS_PER_STEP: usize = 4;

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
    /// (replicator NACK retry, apply gap refetch, crash recovery).
    /// `ENTRY_LOC_RING_SIZE` covers the last 8192 indices; older
    /// indices fall through to a NOT_FOUND reply and snapshot fallback.
    entry_ring: [EntryLoc; ENTRY_LOC_RING_SIZE],
    /// Proposal bodies retained by the explicit no-filesystem fallback.
    /// Bodies are 2 KiB each, so this keeps the smaller
    /// `ENTRY_RING_SIZE` bound: in ephemeral graphs only the last 256
    /// indices are refetchable; older ones answer NOT_FOUND even when
    /// their location slot is still live.
    memory_entries: [MemoryEntry; ENTRY_RING_SIZE],
    entry_ring_max_index: u64,
    entry_ring_min_index: u64,

    // File I/O
    fd: i32,                    // file descriptor for current segment, -1 = not open
    /// One-shot guard for the `[wal] open fail` hard-error log.
    no_fs_logged: bool,
    /// In-memory retention marker. Set ONLY by the `volatile` build
    /// variant (where it is the declared, honest mode). A disk build
    /// never sets it: a hard open error fail-closes (stash +
    /// `write_errors`, retry next step) so raft backpressures instead
    /// of the WAL acking entries it can't persist — a disk graph must
    /// never silently certify durability it doesn't have. While
    /// `fd < 0` the WAL treats the FS as "coming up" (E_AGAIN-patient)
    /// or broken (hard error), and waits either way.
    no_fs: bool,
    /// One-shot guard for the dir-mode `wal/` parent self-heal: nothing
    /// creates `wal/` outside the test harness, and the provider maps
    /// every open failure to one errno, so a missing parent is
    /// indistinguishable from a dead disk until mkdir+retry has been
    /// tried once.
    mkdir_attempted: bool,
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
    /// A record consumed from `in_entries` that could not be staged this step
    /// (write buffer undrainable, segment unopenable). `msg_buf` still holds
    /// it; length in bytes, 0 = none. Re-driven at the top of the next
    /// `process_entries` BEFORE any new channel read, so a transient staging
    /// failure can never punch a hole in the index sequence.
    stashed_len: u16,
    /// Times a record was stashed rather than dropped. Non-zero is healthy
    /// backpressure (the WAL is the bottleneck), not a fault signal.
    stashed_holds: u32,
    /// The (expected, got) index pair at the FIRST continuity break. Exposed
    /// as metrics because the pair is the whole diagnosis: a `got` far above
    /// `expected` means records were lost upstream; `got` below means a
    /// replay/rewind delivered an old index.
    fault_expected: u64,
    fault_got: u64,
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
    /// The persisted-floor sidecar (`persist_segment_floor`) was
    /// consulted at replay start (one-shot). Without it, replay probes
    /// from seq 1 and a long-lived log whose leading segments were
    /// compacted past `REPLAY_GAP_TOLERANCE` would be orphaned wholesale.
    replay_floor_checked: bool,
    /// Latched when replay hits a mid-log fault (CRC mismatch, torn
    /// frame, short read, or an index gap across segments). From then
    /// on later segments are walked for their seq numbers only — no
    /// entry is acked or recorded — so a durable high-water can never
    /// be asserted across a hole (the pre-fault prefix is the log).
    replay_tainted: bool,

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
    /// Diagnostic: entry requests served via the below-floor segment scan.
    entryreq_scan_served: u32,

    // ── Below-floor segment-scan fallback ─────────────────────
    // A request for an index that has aged out of `entry_ring` is served
    // by walking the on-disk segment frames forward from the oldest
    // durable segment (mirroring `step_replay`'s framing walk), bounded
    // to `SCAN_RECORDS_PER_STEP` records per step. One request at a
    // time; concurrent below-floor requests for a different index get
    // no reply and lean on the requester's re-issue throttle (apply's
    // ENTRY_REFETCH_RETRY_MS / the replicator's NACK retry).
    /// A scan target is pending (`scan_target` valid).
    scan_active: bool,
    /// Target located (`scan_loc` valid); the reply is pending delivery.
    scan_found: bool,
    /// Request id to echo in the scan-served reply.
    scan_request_id: u32,
    /// Index being scanned for (0 = none).
    scan_target: u64,
    /// Segment currently being walked.
    scan_seg: u32,
    /// Read-only fd on `scan_seg` (-1 = none). Kept open across steps
    /// and across served requests as a warm cursor. Never `s.fd`.
    scan_fd: i32,
    scan_pos: u32,
    scan_file_size: u32,
    /// Consecutive missing-segment opens (gap tolerance, as replay).
    scan_misses: u8,
    /// Index/term of the last record the cursor walked past — the warm-
    /// cursor key (a new target > `scan_last_index` resumes here) and
    /// the `prev_term` source for sequential serves.
    scan_last_index: u64,
    scan_last_term: u64,
    /// Term of the record at `scan_target - 1`, captured while walking.
    scan_prev_term: u64,
    /// Location of the found target (valid while `scan_found`).
    scan_loc: EntryLoc,
    /// Indices below this were compacted away (`MSG_WAL_COMPACT_BEFORE`)
    /// — legitimately unservable; requests fail loudly instead of
    /// scanning. Distinct from `entry_ring_min_index`, which also rises
    /// as the ring wraps (still servable from disk).
    compact_floor: u64,
    /// One-shot latch for the loud unservable-(compacted)-index log.
    entryreq_unservable_logged: bool,
    /// Highest segment seq compaction still owes physical deletion for
    /// (0 = none pending). Unlinks are paced `COMPACT_UNLINKS_PER_STEP`
    /// per step by `continue_compaction` so a deep trim can't blow the
    /// step budget on synchronous FS_UNLINK calls.
    compact_pending_to: u32,
    /// Floor value (new `oldest_segment_seq`) already persisted to the
    /// sidecar file; deletion never runs ahead of a durable floor, so a
    /// crash mid-compaction can't strand replay behind the gap tolerance.
    floor_persisted: u32,

    // ── In-module delivery latches (composite seams) ─────────
    /// Highest durable (term, index) this step, for the ledger
    /// component. Monotone latest-wins — the ledger's per-replica
    /// progress only ever advances, so collapsing multiple acks per
    /// step to the max is semantics-preserving.
    /// One-shot latch for the informative below-ring-floor diagnostic
    /// (`entry req below floor: seg scan` — see `begin_entry_scan`).
    pub entryreq_floor_logged: bool,
    /// Durable high-water frozen at replay completion, and its term.
    /// Distinct from `current_index`, which advances on STAGED writes.
    pub replay_recovered_index: Index,
    pub replay_recovered_term: Term,
    /// One-shot: the recovered high-water is acked to the ledger once.
    pub replay_ledger_seeded: bool,
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
    s.entryreq_scan_served = 0;
    s.scan_active = false;
    s.scan_found = false;
    s.scan_request_id = 0;
    s.scan_target = 0;
    s.scan_seg = 0;
    s.scan_fd = -1;
    s.scan_pos = 0;
    s.scan_file_size = 0;
    s.scan_misses = 0;
    s.scan_last_index = 0;
    s.scan_last_term = 0;
    s.scan_prev_term = 0;
    s.scan_loc = EntryLoc::zero();
    s.compact_floor = 0;
    s.entryreq_unservable_logged = false;
    s.continuity_fault = false;
    s.continuity_errors = 0;
    s.stashed_len = 0;
    s.stashed_holds = 0;
    s.fault_expected = 0;
    s.fault_got = 0;
    s.segment_seq = 1;
    s.oldest_segment_seq = 1;
    s.crc = Crc32c::new();
    s.fd = -1;
    s.no_fs_logged = false;
    s.no_fs = false;
    s.mkdir_attempted = false;
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
    s.replay_floor_checked = false;
    s.replay_tainted = false;
    s.compact_pending_to = 0;
    s.floor_persisted = 0;
    s.entry_ring = [EntryLoc::zero(); ENTRY_LOC_RING_SIZE];
    s.memory_entries = [MemoryEntry::zero(); ENTRY_RING_SIZE];
    s.entryreq_floor_logged = false;
    s.replay_recovered_index = 0;
    s.replay_recovered_term = 0;
    s.replay_ledger_seeded = false;
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
        // In-memory retention is the variant's declared mode, not a
        // fallback: mark the path up front. The disk build's
        // `[wal] open fail` signal is unreachable here by
        // construction (`ensure_segment_open` returns early).
        s.no_fs = true;
    }
}

/// Step the WAL. Return codes follow the kernel step ABI (0=Continue,
/// 2=Burst); the composite propagates Burst. Per-step bounds: replay
/// is one FS open OR one frame; normal mode is the byte-granted input
/// pump (≤8 records), ≤4 control frames, ≤8 gap-refetch serves, plus
/// at most one cold segment open (which in dir mode may add a one-shot
/// `FS_MKDIR` and a single retried open before it concludes anything).
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

    // FS-readiness gate. While the segment isn't open, (re)try the open
    // every step and HOLD: don't drain new entries, so raft
    // backpressures and nothing is acked that can't be persisted. This
    // covers both E_AGAIN (provider still initialising — fat32 reading
    // the BPB on a pi5 cold boot) and hard failures (broken path/disk;
    // `[wal] open fail` + write_errors say so). A disk build never
    // falls through to in-memory operation — that is the `volatile`
    // variant's declared mode (`no_fs`, set at arm), never a fallback.
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
    let pump_cap = if s.fsync_mode == 0 && !s.fs_async {
        MAX_SYNC_FSYNC_RECORDS
    } else {
        MAX_ENTRY_PUMP_RECORDS
    };
    while records < pump_cap && (grant == 0 || consumed < grant) {
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

    // 3. Service random-access read-back requests (replicator NACK retry),
    //    then advance the bounded below-floor segment scan (if pending).
    drain_entry_requests(s, sys);
    step_entry_scan(s, sys);

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
    // Re-seed the ledger with the locally recovered durable high-water.
    // The ledger only advances through `on_ack`, which fires on the fsync
    // of a NEW write; replay produces no such ack, so without this seed a
    // recovered node's ledger sits at 0 and raft's uncommitted-inflight
    // gate holds proposal intake closed forever. Asserting this replica's
    // own durable index is exactly what a DurabilityAck means, so quorum
    // semantics are unchanged; `note_ledger_ack` is monotone, so a
    // duplicate seed is harmless.
    if !s.replay_ledger_seeded && s.replay_recovered_index > 0 {
        s.replay_ledger_seeded = true;
        note_ledger_ack(s, s.replay_recovered_term, s.replay_recovered_index);
    }
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
    let slot = (index & ENTRY_LOC_RING_MASK) as usize;
    s.entry_ring[slot] = EntryLoc { index, term, seg_seq, payload_offset, payload_len };
    if index > s.entry_ring_max_index {
        s.entry_ring_max_index = index;
    }
    let floor = if s.entry_ring_max_index > ENTRY_LOC_RING_SIZE as u64 {
        s.entry_ring_max_index - ENTRY_LOC_RING_SIZE as u64 + 1
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
    let slot = (index & ENTRY_LOC_RING_MASK) as usize;
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
            // Below-floor miss: the index aged out of the location ring
            // (see ENTRY_LOC_RING_SIZE) but its record is still in a
            // durable segment unless compaction deleted it. Serve it via
            // the bounded forward segment scan instead of NOT_FOUND —
            // crash recovery refetches the WHOLE log through this path,
            // and a NOT_FOUND there permanently wedges the rebuild
            // (there is no snapshot to fall through to).
            if wal_index > 0
                && wal_index < s.entry_ring_min_index
                && wal_index >= s.compact_floor
                && !s.no_fs
                && !VOLATILE
            {
                // No reply yet — the scan answers on a later step; the
                // requester's re-issue throttle covers a dropped attach.
                begin_entry_scan(s, sys, request_id, wal_index);
                return;
            }
            // NOT_FOUND — reply with header only, empty body. The leader
            // takes this as a signal to fall through to snapshot install.
            s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
            // Truly unservable below-floor index: compacted away (or the
            // in-memory path, which retains nothing older than the body
            // ring). Fail loudly — snapshot install is the only way back.
            if wal_index < s.entry_ring_min_index && !s.entryreq_unservable_logged {
                s.entryreq_unservable_logged = true;
                dev_log(sys, 2, b"[wal] entry req unservable (compacted)".as_ptr(), 38);
            }
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

    // Read the entry body from disk and pass the whole payload back so
    // the replicator can reconstruct an AE. A WAL payload is
    // `[term:u64][index:u64][body]` capped at `wal_frame::MAX_ENTRY_LEN`,
    // so both buffers clear it comfortably.
    let mut body = [0u8; 4096];
    let payload_len = loc.payload_len as usize;
    // The reply is `WAL_ENTRY_REPLY_HDR + (payload_len - 16)` bytes and
    // is staged in a 4096-byte buffer, so bound the payload by what the
    // REPLY can hold, not just by `body` — the slice write below has no
    // panic path to fall back on.
    let payload_max = body.len().min(4096 + 16 - wire::WAL_ENTRY_REPLY_HDR);
    if payload_len < 16 || payload_len > payload_max {
        // Defensive: shouldn't happen given the write-path payload cap.
        s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
        wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
        return;
    }

    // If the frame is still in the staged batch (its location was recorded
    // at stage time, before any provider write), serve it straight from
    // `write_buf`: the on-disk bytes for that region are undefined — EOF-
    // short on a growing file, preallocated garbage on a fixed one.
    let staged_logical =
        (s.write_pos as usize).saturating_sub(if s.staged_terminator { 4 } else { 0 });
    if loc.seg_seq == s.segment_seq && staged_logical > 0 {
        let batch_start = s.cursor.saturating_sub(staged_logical as u32);
        let frame_start = loc.payload_offset.saturating_sub(FRAME_HDR);
        if frame_start >= batch_start {
            let off = (frame_start - batch_start) as usize + FRAME_HDR as usize;
            if off + payload_len > staged_logical {
                // Recorded as staged but outside the staged range —
                // inconsistent bookkeeping; NOT_FOUND beats serving garbage.
                s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
                let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
                wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
                wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
                return;
            }
            let rest_len = payload_len.saturating_sub(16);
            let total = wire::WAL_ENTRY_REPLY_HDR + rest_len;
            let prev_term = if loc.index > 1 {
                lookup_entry_loc(s, loc.index - 1).map_or(0, |p| p.term)
            } else {
                0
            };
            let mut reply = [0u8; 4096];
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, loc.term, loc.index, prev_term);
            reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
            if rest_len > 0 {
                // copy_nonoverlapping: the slice lengths are equal by
                // construction (rest_len = payload_len - 16) but not
                // provably so to rustc — copy_from_slice would link in a
                // len-mismatch panic path, which PIC modules cannot carry.
                core::ptr::copy_nonoverlapping(
                    s.write_buf.as_ptr().add(off + 16),
                    reply.as_mut_ptr().add(wire::WAL_ENTRY_REPLY_HDR),
                    rest_len,
                );
            }
            wire_channels::channel_write_msg(
                sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &reply[..total],
            );
            s.entryreq_served = s.entryreq_served.saturating_add(1);
            return;
        }
    }

    // Under the async write tier there is no read-your-writes until the
    // fence completes, so a submitted-but-not-durable frame reads back as
    // undefined bytes, fails the CRC check below, and escalates to a
    // snapshot install for an entry that becomes servable one fence
    // round-trip later. Don't reply at all — the requester's retry
    // throttle re-asks after the fence lands.
    if loc.seg_seq == s.segment_seq && !s.no_fs && wal_index > s.ledger_ack.1 {
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

    // Read the frame header with the payload and re-verify the stored
    // CRC32C before shipping: read-back feeds followers, so an unchecked
    // corrupt sector propagates cluster-wide as a valid entry.
    let hdr_off = loc.payload_offset.saturating_sub(FRAME_HDR);
    let seek_arg = (hdr_off as i32).to_le_bytes();
    let seek_rc =
        (sys.provider_call)(read_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4);
    let mut ok = seek_rc >= 0;
    let mut frame_hdr = [0u8; FRAME_HDR as usize];
    if ok {
        let n = (sys.provider_call)(read_fd, FS_READ, frame_hdr.as_mut_ptr(), FRAME_HDR as usize);
        ok = n >= FRAME_HDR as i32;
    }
    if ok {
        let n = (sys.provider_call)(read_fd, FS_READ, body.as_mut_ptr(), payload_len);
        ok = (n as usize) >= payload_len;
    }
    if ok {
        let (entry_len32, stored_crc) = wal_frame::parse_header(&frame_hdr);
        let actual_crc = {
            let mut c = Crc32c::new();
            c.update(&body[..payload_len]);
            c.finalize()
        };
        if entry_len32 as usize != payload_len || actual_crc != stored_crc {
            s.checksum_failures = s.checksum_failures.saturating_add(1);
            dev_log(sys, 2, b"[wal] serve CRC FAIL".as_ptr(), 20);
            ok = false;
        }
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

// ── Below-floor segment-scan fallback ───────────────────────
//
// Serves entry requests whose index has aged out of `entry_ring` by
// walking the on-disk segment frames forward from the oldest durable
// segment — the same `[len][crc][payload]` walk `step_replay` does,
// but skipping payloads (seek) instead of reading them. Work is
// bounded per step (`SCAN_RECORDS_PER_STEP` records, or one segment
// open) and the cursor resumes across steps. After a serve, the
// cursor stays warm so sequential refetches (crash recovery walks
// index 1,2,3…) continue in O(1) per entry.

/// Attach a below-floor request to the scan slot. One target at a
/// time: a request for a different index while a scan is active is
/// dropped without a reply — apply re-asks the same index after
/// `ENTRY_REFETCH_RETRY_MS` and the replicator's NACK path re-issues
/// likewise, so a dropped attach only costs one retry interval.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn begin_entry_scan(s: &mut Wal, sys: &SyscallTable, request_id: u32, wal_index: u64) {
    // The located-but-undelivered reply matches: just refresh the id.
    if s.scan_found {
        if s.scan_loc.index == wal_index {
            s.scan_request_id = request_id;
        }
        return;
    }
    if s.scan_active {
        if s.scan_target == wal_index {
            s.scan_request_id = request_id;
        }
        return; // busy with a different target — requester retries
    }
    // Warm-cursor continuation: the durable log is walked in ascending
    // index order (appends are contiguous; truncation invalidates the
    // cursor — see `truncate_after`), so a target past the last record
    // the cursor walked resumes mid-segment instead of rescanning.
    let warm = s.scan_fd >= 0 && s.scan_last_index > 0 && wal_index > s.scan_last_index;
    if !warm {
        reset_scan_cursor(s, sys);
        s.scan_seg = s.oldest_segment_seq;
    }
    s.scan_prev_term = if warm && s.scan_last_index + 1 == wal_index {
        s.scan_last_term
    } else {
        0
    };
    s.scan_target = wal_index;
    s.scan_request_id = request_id;
    s.scan_active = true;
    // Informative one-shot: below-floor requests are being served via
    // the segment scan. The loud path is `entry req unservable`.
    if !s.entryreq_floor_logged {
        s.entryreq_floor_logged = true;
        dev_log(sys, 3, b"[wal] entry req below floor: seg scan".as_ptr(), 37);
    }
}

/// Drop any scan fd and forget the warm cursor. Does NOT touch the
/// pending target/reply flags — callers decide those.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn reset_scan_cursor(s: &mut Wal, sys: &SyscallTable) {
    if s.scan_fd >= 0 {
        (sys.provider_call)(s.scan_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.scan_fd = -1;
    }
    s.scan_pos = 0;
    s.scan_file_size = 0;
    s.scan_misses = 0;
    s.scan_last_index = 0;
    s.scan_last_term = 0;
}

/// Terminate the active scan as unservable: the walk proved the index
/// is not in any durable segment (compacted away, or a gap). Replies
/// NOT_FOUND (header-only) so the requester falls through to its
/// snapshot path, and logs the hard failure once.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn fail_entry_scan(s: &mut Wal, sys: &SyscallTable) {
    let request_id = s.scan_request_id;
    let wal_index = s.scan_target;
    s.scan_active = false;
    s.scan_found = false;
    s.scan_target = 0;
    s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
    if !s.entryreq_unservable_logged {
        s.entryreq_unservable_logged = true;
        dev_log(sys, 2, b"[wal] entry req unservable (compacted)".as_ptr(), 38);
    }
    let poll_out = (sys.channel_poll)(s.out_entry_reply, POLL_OUT);
    if poll_out > 0 && (poll_out as u32 & POLL_OUT) != 0 {
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
        wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
    }
    // Channel full: the NOT_FOUND is dropped; the requester's retry
    // re-attaches and fails again (idempotent, still loud-once).
}

/// Advance the below-floor scan by one bounded step: either one
/// segment open (mirroring replay's one-open-per-step pacing) or up
/// to `SCAN_RECORDS_PER_STEP` frame skips. Serves the reply the
/// moment the target record is located.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_entry_scan(s: &mut Wal, sys: &SyscallTable) {
    if s.scan_found {
        deliver_scan_reply(s, sys);
        return;
    }
    if !s.scan_active { return; }

    // Open the segment under the cursor. One provider open per step —
    // a cold open can pay the directory-scan penalty (see step_replay).
    if s.scan_fd < 0 {
        if s.scan_seg > s.segment_seq {
            // Walked past the live segment without finding the index.
            fail_entry_scan(s, sys);
            return;
        }
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = encode_segment_path(s.partition_id, s.scan_seg, s.root_path != 0, &mut path);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if fd == FS_E_AGAIN { return; } // provider initialising — retry
        if fd < 0 {
            // Missing segment: tolerate gaps exactly like replay.
            s.scan_misses = s.scan_misses.saturating_add(1);
            if s.scan_misses >= REPLAY_GAP_TOLERANCE {
                fail_entry_scan(s, sys);
                return;
            }
            s.scan_seg = s.scan_seg.saturating_add(1);
            return;
        }
        let mut stat_buf = [0u8; 8];
        let stat_rc = (sys.provider_call)(fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        let size = if stat_rc < 0 { 0 } else {
            u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
        };
        if size == 0 {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.scan_seg = s.scan_seg.saturating_add(1);
            return;
        }
        s.scan_misses = 0;
        s.scan_fd = fd;
        s.scan_file_size = size;
        s.scan_pos = 0;
        return; // bounded: the open was this step's work
    }

    // Walk frames: [entry_len:u32][crc32c:u32][payload], where payload
    // begins [term:u64][index:u64]. Read the 24-byte prefix, then seek
    // past the payload — never read bodies we are only skipping.
    let mut records = 0usize;
    while records < SCAN_RECORDS_PER_STEP {
        let remaining = s.scan_file_size.saturating_sub(s.scan_pos);
        if remaining < FRAME_HDR {
            // Segment exhausted — move to the next one.
            (sys.provider_call)(s.scan_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.scan_fd = -1;
            s.scan_seg = s.scan_seg.saturating_add(1);
            return;
        }
        let seek_arg = (s.scan_pos as i32).to_le_bytes();
        if (sys.provider_call)(s.scan_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4) < 0 {
            fail_entry_scan(s, sys);
            reset_scan_cursor(s, sys);
            return;
        }
        let mut hdr = [0u8; FRAME_HDR as usize];
        let n = (sys.provider_call)(s.scan_fd, FS_READ, hdr.as_mut_ptr(), FRAME_HDR as usize);
        if n < FRAME_HDR as i32 {
            (sys.provider_call)(s.scan_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.scan_fd = -1;
            s.scan_seg = s.scan_seg.saturating_add(1);
            return;
        }
        let (entry_len, _) = wal_frame::parse_header(&hdr);
        if wal_frame::len_invalid(
            entry_len,
            u64::from(s.scan_file_size.saturating_sub(s.scan_pos + FRAME_HDR)),
        ) {
            // Terminator or torn frame — end of this segment's live data
            // (same stop rule as replay).
            (sys.provider_call)(s.scan_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.scan_fd = -1;
            s.scan_seg = s.scan_seg.saturating_add(1);
            return;
        }
        let payload_offset = s.scan_pos + FRAME_HDR;
        if entry_len >= 16 {
            let mut ti = [0u8; 16];
            let n2 = (sys.provider_call)(s.scan_fd, FS_READ, ti.as_mut_ptr(), 16);
            if n2 < 16 {
                fail_entry_scan(s, sys);
                reset_scan_cursor(s, sys);
                return;
            }
            let (term, index) = wire::decode_term_index(&ti);
            if index == s.scan_target {
                s.scan_loc = EntryLoc {
                    index,
                    term,
                    seg_seq: s.scan_seg,
                    payload_offset,
                    payload_len: entry_len,
                };
                s.scan_found = true;
                s.scan_active = false;
                deliver_scan_reply(s, sys);
                return;
            }
            if index > s.scan_target {
                // Passed the slot without finding it: the record is not
                // in the durable log (leading segments compacted away).
                // The cursor stays warm for later, higher targets.
                fail_entry_scan(s, sys);
                return;
            }
            if index + 1 == s.scan_target {
                s.scan_prev_term = term;
            }
            if index > 0 {
                s.scan_last_index = index;
                s.scan_last_term = term;
            }
        }
        s.scan_pos = payload_offset + entry_len;
        records += 1;
    }
}

/// Emit the reply for a scan-located record: read the payload from the
/// scan fd and send it in the same wire shape as the ring-served path.
/// Retries next step if the reply channel is full. On success the
/// cursor advances past the record so a follow-up sequential request
/// resumes without rescanning.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn deliver_scan_reply(s: &mut Wal, sys: &SyscallTable) {
    if !s.scan_found { return; }
    if s.out_entry_reply < 0 {
        s.scan_found = false;
        s.scan_target = 0;
        return;
    }
    let poll_out = (sys.channel_poll)(s.out_entry_reply, POLL_OUT);
    if poll_out <= 0 || (poll_out as u32 & POLL_OUT) == 0 { return; } // retry next step

    let loc = s.scan_loc;
    let payload_len = loc.payload_len as usize;
    let mut body = [0u8; 4096];
    let mut ok = s.scan_fd >= 0 && payload_len > 0 && payload_len <= body.len();
    // Verify the stored CRC32C before shipping — scan-served bytes feed
    // followers just like ring-served ones.
    let mut frame_hdr = [0u8; FRAME_HDR as usize];
    if ok {
        let hdr_off = loc.payload_offset.saturating_sub(FRAME_HDR);
        let seek_arg = (hdr_off as i32).to_le_bytes();
        ok = (sys.provider_call)(s.scan_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4) >= 0;
    }
    if ok {
        let n = (sys.provider_call)(s.scan_fd, FS_READ, frame_hdr.as_mut_ptr(), FRAME_HDR as usize);
        ok = n >= FRAME_HDR as i32;
    }
    if ok {
        let n = (sys.provider_call)(s.scan_fd, FS_READ, body.as_mut_ptr(), payload_len);
        ok = (n as usize) >= payload_len;
    }
    if ok {
        let (entry_len32, stored_crc) = wal_frame::parse_header(&frame_hdr);
        let actual_crc = {
            let mut c = Crc32c::new();
            c.update(&body[..payload_len]);
            c.finalize()
        };
        if entry_len32 as usize != payload_len || actual_crc != stored_crc {
            s.checksum_failures = s.checksum_failures.saturating_add(1);
            dev_log(sys, 2, b"[wal] serve CRC FAIL".as_ptr(), 20);
            ok = false;
        }
    }
    if !ok {
        // The segment vanished (or shrank) under the cursor — most
        // plausibly compaction. Fail loudly like any unservable index.
        s.scan_target = loc.index;
        s.scan_found = false;
        s.scan_active = true; // fail_entry_scan clears these
        fail_entry_scan(s, sys);
        reset_scan_cursor(s, sys);
        return;
    }

    // Reply wire shape matches the ring-served path: strip the 16-byte
    // [term][index] payload prefix; prev_term was captured while the
    // scan walked the preceding record.
    let rest = if payload_len > 16 { &body[16..payload_len] } else { &[][..] };
    let total = wire::WAL_ENTRY_REPLY_HDR + rest.len();
    let mut reply = [0u8; 4096];
    let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
    wire::encode_wal_entry_reply_hdr(
        &mut hdr, s.scan_request_id, loc.term, loc.index, s.scan_prev_term,
    );
    reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
    reply[wire::WAL_ENTRY_REPLY_HDR..total].copy_from_slice(rest);
    wire_channels::channel_write_msg(
        sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &reply[..total],
    );
    s.entryreq_served = s.entryreq_served.saturating_add(1);
    s.entryreq_scan_served = s.entryreq_scan_served.saturating_add(1);
    s.scan_found = false;
    s.scan_target = 0;
    // Warm the cursor past the served record for sequential refetches.
    s.scan_last_index = loc.index;
    s.scan_last_term = loc.term;
    s.scan_prev_term = 0;
    s.scan_pos = loc.payload_offset + loc.payload_len;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_compact_before(s: &mut Wal, sys: &SyscallTable) {
    if s.in_compact_before < 0 { return; }

    // Continue any unlink work a previous compaction left pending
    // (paced COMPACT_UNLINKS_PER_STEP per step).
    continue_compaction(s, sys);

    // A truncate/compaction changes the file cursor and segment topology. Do
    // not let it overtake records that are already accepted into the current
    // durability batch but still live only in `write_buf` — NOR records whose
    // async write/fence is still in flight: a fence completing after a
    // truncation would ack the discarded suffix, and the in-flight write
    // races the rewound region. Wait until the pipeline is empty.
    let ready = (sys.channel_poll)(s.in_compact_before, 0x01);
    if ready > 0
        && (ready as u32 & 0x01) != 0
        && (s.has_batch || s.fence_pending || s.fence_ring_count > 0)
    {
        flush_batch(s, sys);
        if s.has_batch || s.fence_pending || s.fence_ring_count > 0 { return; }
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

    // Locate the keep point. `keep == 0` discards the whole log (no frame
    // to rewind to). Otherwise the offset ring must still hold the keep
    // entry: raft only truncates its uncommitted tail, bounded by the
    // in-flight window (≪ ENTRY_LOC_RING_SIZE). A miss means upstream
    // state corruption — fail-stop rather than guess a rewind point, since
    // a wrong one leaves the suffix on disk for replay to resurrect.
    let mut keep_seg: u32 = 0;
    let mut new_cursor: u32 = 0;
    let mut new_term: Term = 0;
    if keep_through_index > 0 {
        match lookup_entry_loc(s, keep_through_index) {
            Some(loc) => {
                keep_seg = loc.seg_seq;
                new_cursor = loc.payload_offset + loc.payload_len;
                new_term = loc.term;
            }
            None => {
                s.fence_failed = true;
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 1, b"[wal] FATAL truncate unlocatable".as_ptr(), 31);
                return;
            }
        }
    }

    // Drop in-memory ring slots above the keep point so lookups and
    // entry-request serves no longer surface the discarded suffix. The
    // per-index walk is clamped to one ring revolution: past that, slots
    // repeat and a full-array sweep is both cheaper and complete.
    if s.entry_ring_max_index > keep_through_index {
        let span = s.entry_ring_max_index - keep_through_index;
        if span >= ENTRY_LOC_RING_SIZE as u64 {
            for slot in s.entry_ring.iter_mut() {
                if slot.index > keep_through_index { slot.index = 0; }
            }
        } else {
            let mut i = keep_through_index + 1;
            while i <= s.entry_ring_max_index {
                let loc_slot = (i & ENTRY_LOC_RING_MASK) as usize;
                if s.entry_ring[loc_slot].index == i {
                    s.entry_ring[loc_slot].index = 0;
                }
                i += 1;
            }
        }
        if span >= ENTRY_RING_SIZE as u64 {
            for m in s.memory_entries.iter_mut() {
                if m.index > keep_through_index {
                    m.index = 0;
                    m.body_len = 0;
                }
            }
        } else {
            let mut i = keep_through_index + 1;
            while i <= s.entry_ring_max_index {
                let slot = (i & ENTRY_RING_MASK) as usize;
                if s.memory_entries[slot].index == i {
                    s.memory_entries[slot].index = 0;
                    s.memory_entries[slot].body_len = 0;
                }
                i += 1;
            }
        }
    }
    s.entry_ring_max_index = keep_through_index;

    s.current_index = keep_through_index;
    s.current_term = new_term;
    s.truncations = s.truncations.saturating_add(1);

    // Truncation rewrites the tail under the scan's ascending-order
    // assumption. Drop the warm cursor; an in-flight scan for a target
    // above the keep point is for a discarded entry (drop it without a
    // reply — the requester's next attempt resolves against the new
    // ring state), one at-or-below restarts from the oldest segment.
    s.scan_found = false;
    reset_scan_cursor(s, sys);
    if s.scan_active {
        if s.scan_target > keep_through_index {
            s.scan_active = false;
            s.scan_target = 0;
        } else {
            s.scan_seg = s.oldest_segment_seq;
        }
    }

    if keep_through_index == 0 || keep_seg != s.segment_seq {
        // The discarded suffix spans segment files beyond the current
        // one — a rewind of the current segment alone would leave the
        // suffix on disk for replay to resurrect.
        truncate_cross_segment(s, sys, keep_seg, new_cursor);
        dev_log(sys, 3, b"[wal] truncate".as_ptr(), 14);
        return;
    }

    // Keep point lives in the current segment: mark the stale region and
    // rewind. The trailing-terminator logic in process_entries keeps
    // replay honest until appends overwrite past it.
    if s.cursor > s.seg_high_water {
        s.seg_high_water = s.cursor;
    }
    s.cursor = new_cursor;

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

/// Cross-segment truncation: the keep point lives in an older segment
/// (`keep_seg`), or the whole log is discarded (`keep_seg == 0`). The
/// terminator must land in the keep segment itself and every segment
/// file above it must be made replay-inert, else a crash after this
/// conflict repair resurrects the discarded suffix at replay. The
/// suffix is raft's uncommitted tail (≤ the in-flight window), so the
/// loops here are bounded by that, not by the log size.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn truncate_cross_segment(s: &mut Wal, sys: &SyscallTable, keep_seg: u32, new_cursor: u32) {
    if s.fd >= 0 {
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
    let old_seq = s.segment_seq;

    if keep_seg == 0 {
        // Whole-log discard: invalidate every segment and continue in a
        // FRESH file at the next seq — never reuse a stale file in place.
        let mut seq = s.oldest_segment_seq;
        while seq <= old_seq {
            invalidate_segment(s, sys, seq);
            seq = seq.saturating_add(1);
        }
        s.segment_seq = old_seq.saturating_add(1);
        // Every prior segment is gone: the floor must follow the fresh
        // seq, or compaction and the below-floor scan keep addressing
        // files that no longer exist.
        s.oldest_segment_seq = s.segment_seq;
        if s.scan_active { s.scan_seg = s.oldest_segment_seq; }
        s.cursor = 0;
        s.seg_high_water = 0;
        s.fixed_segment_active = false;
        return;
    }

    // Re-open the keep segment for writing, learn its physical extent
    // (the stale-suffix high-water), and persist the terminator at the
    // new tail before anything is deleted.
    let mut path = [0u8; WAL_PATH_MAX];
    let plen = encode_segment_path(s.partition_id, keep_seg, s.root_path != 0, &mut path);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
    if fd < 0 {
        // Can't place the terminator — the discarded suffix would replay
        // as valid after a crash. Fail-stop (see `fence_failed`).
        s.fence_failed = true;
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 1, b"[wal] FATAL truncate reopen".as_ptr(), 27);
        return;
    }
    let mut stat_buf = [0u8; 8];
    let stat_rc = (sys.provider_call)(fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
    let size = if stat_rc < 0 { 0 } else {
        u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
    };
    let seek = (new_cursor as i32).to_le_bytes();
    let sr = (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
    let zero = [0u8; 4];
    let w = (sys.provider_call)(fd, FS_WRITE, zero.as_ptr() as *mut u8, 4);
    let fr = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    if sr < 0 || w != 4 || fr != 0 {
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fence_failed = true;
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 1, b"[wal] FATAL truncate term write".as_ptr(), 30);
        return;
    }
    // Next append overwrites the terminator we just wrote.
    (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);

    // Only now delete/neutralise the fully-discarded segments above.
    let mut seq = keep_seg.saturating_add(1);
    while seq <= old_seq {
        invalidate_segment(s, sys, seq);
        seq = seq.saturating_add(1);
    }

    s.fd = fd;
    s.segment_seq = keep_seg;
    s.cursor = new_cursor;
    s.seg_high_water = size.max(new_cursor);
}

/// Make a discarded segment file replay-inert: unlink it where the
/// provider supports it; otherwise (or on unlink failure) overwrite its
/// first frame header with a zero-length terminator so replay stops at
/// offset 0 even though the file still exists.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn invalidate_segment(s: &mut Wal, sys: &SyscallTable, seq: u32) {
    let mut path = [0u8; WAL_PATH_MAX];
    let plen = encode_segment_path(s.partition_id, seq, s.root_path != 0, &mut path);
    if fs_unlink_supported(s, sys) {
        let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
        if rc == 0 { return; }
    }
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
    if fd < 0 { return; } // never existed (or FS gone) — nothing to neutralise
    let seek = 0i32.to_le_bytes();
    let sr = (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
    let zero = [0u8; 4];
    let w = (sys.provider_call)(fd, FS_WRITE, zero.as_ptr() as *mut u8, 4);
    let fr = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    if sr < 0 || w != 4 || fr != 0 {
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 3, b"[wal] invalidate FAIL".as_ptr(), 21);
    }
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
    // Record the compaction floor so below-floor requests for indices
    // this trim covers fail fast (loudly) instead of scanning segments
    // that are about to be (or already were) deleted.
    if before_index > s.compact_floor {
        s.compact_floor = before_index;
    }
    // An active scan for a now-compacted target is unservable.
    if s.scan_active && s.scan_target < before_index {
        fail_entry_scan(s, sys);
    }
    // Drop segments whose max-index is strictly below the requested
    // floor. The current write segment is exempt — we never delete it
    // while we're still appending to it.
    //
    // A segment is safe to drop ONLY if EVERY entry it holds is below
    // the floor. The boundary segment — where the floor falls
    // mid-segment — also holds the first entries of the live tail, so
    // dropping it for its reclaimable half destroys acked, committed,
    // unsnapshotted state. Find the lowest segment holding any
    // at-or-above-floor entry; only segments strictly below BOTH that
    // and the live one may be dropped.
    let mut max_below: u32 = 0;
    let mut min_keep_seq: u32 = u32::MAX;
    for slot in s.entry_ring.iter() {
        if slot.index == 0 { continue; }
        if slot.index < before_index {
            if slot.seg_seq > max_below {
                max_below = slot.seg_seq;
            }
        } else if slot.seg_seq < min_keep_seq {
            min_keep_seq = slot.seg_seq;
        }
    }
    let mut max_safe_seq_to_drop = max_below.min(s.segment_seq.saturating_sub(1));
    if min_keep_seq != u32::MAX && max_safe_seq_to_drop >= min_keep_seq {
        max_safe_seq_to_drop = min_keep_seq.saturating_sub(1);
    }
    if max_safe_seq_to_drop == 0 { return; }
    // Segments are about to be deleted: the scan cursor (and any
    // located-but-undelivered reply) may reference one of them. Drop
    // the cursor and re-point it at the post-trim oldest segment; an
    // in-flight scan for a surviving target restarts from there.
    s.scan_found = false;
    reset_scan_cursor(s, sys);
    // Record the deletion target; `continue_compaction` (called every
    // step) persists the floor first and then unlinks a few segments per
    // step, so a deep trim never blows the step budget on synchronous
    // FS_UNLINK calls.
    if max_safe_seq_to_drop > s.compact_pending_to {
        s.compact_pending_to = max_safe_seq_to_drop;
    }
    continue_compaction(s, sys);
}

/// Paced physical side of compaction. Two invariants:
///
/// 1. The floor sidecar is durably persisted BEFORE the first unlink, so
///    replay can always find the surviving log even when the trim removes
///    more leading segments than `REPLAY_GAP_TOLERANCE` covers. A failed
///    persist just defers deletion to the next step — correctness never
///    depends on physical deletion.
/// 2. At most `COMPACT_UNLINKS_PER_STEP` segments per step (fat32's
///    unlink tombstones the dirent synchronously). Without the UNLINK
///    cap, or on a per-file error, the floor still advances and the file
///    is merely orphaned.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn continue_compaction(s: &mut Wal, sys: &SyscallTable) {
    if s.compact_pending_to == 0 { return; }
    if s.oldest_segment_seq > s.compact_pending_to
        || s.oldest_segment_seq >= s.segment_seq
    {
        s.compact_pending_to = 0;
        return;
    }
    let new_oldest = s.compact_pending_to.saturating_add(1).min(s.segment_seq);
    if !persist_segment_floor(s, sys, new_oldest) {
        return; // retry next step; nothing deleted until the floor is durable
    }
    let mut unlinks = 0usize;
    while s.oldest_segment_seq <= s.compact_pending_to
        && s.oldest_segment_seq < s.segment_seq
        && unlinks < COMPACT_UNLINKS_PER_STEP
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
        unlinks += 1;
        s.oldest_segment_seq += 1;
    }
    if s.oldest_segment_seq > s.compact_pending_to
        || s.oldest_segment_seq >= s.segment_seq
    {
        s.compact_pending_to = 0;
    }
    // Restart any surviving in-flight scan at the new oldest segment.
    if s.scan_seg < s.oldest_segment_seq {
        s.scan_seg = s.oldest_segment_seq;
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
// On startup, scans for existing WAL segment files and re-emits their
// entries through the flushed output so the downstream pipeline
// (ledger → commit) reconstructs committed state.
//
// Bounded per tick: one segment open, or up to
// `REPLAY_FRAMES_PER_STEP` frames from an already-open segment.

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
        // Consult the persisted segment floor once per replay pass. A
        // long-lived log compacts more leading segments away than
        // REPLAY_GAP_TOLERANCE covers, so probing blindly from seq 1
        // exhausts the miss budget before reaching the survivors and
        // orphans the whole durable log. Missing sidecar = fresh
        // deployment or pre-floor layout: probe from seq 1.
        if !s.replay_floor_checked {
            let mut path = [0u8; WAL_PATH_MAX];
            let plen = encode_floor_path(s.partition_id, s.root_path != 0, &mut path);
            let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
            if fd == FS_E_AGAIN { return 0; } // provider initialising — retry
            if fd >= 0 {
                let mut val = [0u8; 4];
                let n = (sys.provider_call)(fd, FS_READ, val.as_mut_ptr(), 4);
                (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
                if n == 4 {
                    let floor = u32::from_le_bytes(val);
                    if floor > s.replay_seg { s.replay_seg = floor; }
                    s.floor_persisted = floor;
                    dev_log(sys, 3, b"[wal] replay floor".as_ptr(), 18);
                }
            }
            s.replay_floor_checked = true;
            // The open may have paid the cold directory-scan penalty.
            return STEP_BURST;
        }
        build_segment_path(s, s.replay_seg);
        let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), s.path_len as usize);
        if fd == FS_E_AGAIN {
            // FS provider still initialising (fat32 reading the BPB on a pi5
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
                // A first-touch FS_OPEN against a cold root-dir cluster on
                // this NVMe runs tens of ms — far past the step deadline.
                // Burst discards this step's elapsed instead of checking it,
                // and re-arms the next step with the 8× budget. Replay is
                // bounded, so this is headroom, not unbounded work.
                return STEP_BURST;
            }
            // Bound reached: replay is done. Finding no segments here
            // is NOT proof the filesystem is unavailable — a fresh
            // deployment has an empty (but perfectly writable) `wal/`.
            // Whether the FS is actually missing is only known on the
            // write path (`ensure_segment_open`), which self-heals
            // the parent and then fails closed with `[wal] open fail`
            // if `OPEN_CREATE` still fails. So replay just reports
            // completion either way and lets the writer make the call.
            // Freeze the durable high-water reconstructed by replay.
            // Everything up to here is ON DISK; `current_index` keeps
            // moving as new entries are STAGED, so it must never be
            // used to assert durability.
            s.replay_recovered_index = s.current_index;
            s.replay_recovered_term = s.current_term;
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
            // Freeze the durable high-water reconstructed by replay.
            s.replay_recovered_index = s.current_index;
            s.replay_recovered_term = s.current_term;
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

        if s.replay_tainted {
            // Past a mid-log fault the prefix already replayed IS the
            // recoverable log. Later segments are walked only so
            // `segment_seq` lands past every existing file (fresh appends
            // must never land in a stale segment) — their entries are
            // never read, acked, or recorded.
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.replay_seg = s.replay_seg.saturating_add(1);
            return STEP_BURST;
        }

        s.replay_fd = fd;
        s.replay_file_size = size;
        s.replay_pos = 0;
        dev_log(sys, 3, b"[wal] replay seg".as_ptr(), 16);
        // The FS_OPEN above may have paid the cold directory-scan penalty
        // (tens of ms). Forgive it via Burst and read frames on subsequent
        // warm steps rather than falling through here.
        return STEP_BURST;
    }

    // Read framed entries: [entry_len: u32 LE] [crc32c: u32 LE] [entry_data].
    // Up to REPLAY_FRAMES_PER_STEP per step (warm reads — the cold open
    // already got its Burst); any segment transition or fault ends the step.
    let mut frames = 0usize;
    while frames < REPLAY_FRAMES_PER_STEP {
        frames += 1;
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
            // Short read despite `remaining >= FRAME_HDR`: a device fault,
            // not a clean end. Taint so no later segment is acked over it.
            s.replay_tainted = true;
            (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.replay_fd = -1;
            s.replay_seg += 1;
            return 0;
        }
        s.replay_pos += FRAME_HDR;

        let (entry_len32, stored_crc) = wal_frame::parse_header(&hdr);
        let entry_len = entry_len32 as usize;
        if wal_frame::len_invalid(entry_len32, u64::from(s.replay_file_size - s.replay_pos)) {
            // Stop this segment at the last good entry. A zero-length
            // frame is the live-tail terminator — a clean per-segment stop
            // (fixed segments end every rotated segment with one) — so it
            // does not taint. A nonzero-but-impossible length is a torn
            // header, which does.
            if entry_len32 != 0 { s.replay_tainted = true; }
            (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.replay_fd = -1;
            s.replay_seg += 1;
            return 0;
        }

        // Read entry data
        let entry_payload_offset = s.replay_pos;
        let n2 = (sys.provider_call)(s.replay_fd, FS_READ, s.msg_buf.as_mut_ptr(), entry_len);
        if (n2 as usize) < entry_len {
            s.replay_tainted = true;
            (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.replay_fd = -1;
            s.replay_seg += 1;
            return 0;
        }
        s.replay_pos += entry_len as u32;

        // Integrity check: recompute the payload CRC32C and compare. A
        // mismatch means a torn or corrupt payload — stop replay here (the
        // durable prefix up to this frame is the recoverable log) rather
        // than replaying garbage, and taint the rest of the walk.
        let actual_crc = {
            let mut c = Crc32c::new();
            c.update(&s.msg_buf[..entry_len]);
            c.finalize()
        };
        if actual_crc != stored_crc {
            s.checksum_failures = s.checksum_failures.saturating_add(1);
            s.replay_tainted = true;
            dev_log(sys, 3, b"[wal] replay CRC FAIL".as_ptr(), 21);
            (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.replay_fd = -1;
            s.replay_seg += 1;
            return 0;
        }

        // Parse: first 16 bytes are term(8) + index(8)
        if entry_len >= 16 {
            let (term, index) = wire::decode_term_index(&s.msg_buf);

            // An index jump means the records between the last replayed
            // entry and this one are gone. Acking across that hole would
            // assert a durable high-water over missing records, which is
            // unrepairable once commit passes it. Stop; the prefix is the
            // log.
            if s.current_index != 0 && index > s.current_index.saturating_add(1) {
                s.continuity_errors = s.continuity_errors.saturating_add(1);
                s.replay_tainted = true;
                dev_log(sys, 1, b"[wal] replay gap".as_ptr(), 16);
                (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
                s.replay_fd = -1;
                s.replay_seg += 1;
                return 0;
            }

            if index > s.current_index {
                s.current_index = index;
                s.current_term = term;
            }
            record_entry_loc(s, index, term, s.replay_seg, entry_payload_offset, entry_len as u32);
            note_ledger_ack(s, term, index);

            // Re-emit as FsyncAck — entry is already durable on disk.
            // Best-effort: the ledger latch above carries the high-water
            // even when the external ack channel is momentarily full.
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
/// The `wal/` parent is self-healed at first open (`FS_MKDIR`, once
/// per boot) when absent, so a fresh working directory needs no
/// manual `mkdir`. An operator who wants the segments elsewhere
/// pre-creates a symlink (e.g. `ln -s /var/lib/quantum/wal wal`);
/// the single-directory layout serves any partition count. See
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

/// Write the segment-floor sidecar path for `partition_id` into `out`
/// and return the length. Non-root: `wal/p<NNNN>_floor`. Root (8.3
/// bare-metal FAT32): `<p:1hex>FLOOR.WAL` — six-char basename, so it
/// can never collide with the eight-hex-digit segment names.
fn encode_floor_path(partition_id: u16, root: bool, out: &mut [u8]) -> usize {
    let cap = out.len();
    let mut i = 0usize;
    if root {
        let p = (partition_id & 0xF) as u8;
        out[i] = if p < 10 { b'0' + p } else { b'a' + p - 10 };
        i += 1;
        for &b in b"FLOOR.WAL" {
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
    for &b in b"_floor" {
        if i < cap { out[i] = b; i += 1; }
    }
    i
}

/// Durably persist `new_oldest` (the segment seq replay must start
/// probing from) to the floor sidecar. Returns true on success. Called
/// BEFORE compaction unlinks anything: physical deletion never runs
/// ahead of a durable floor, so replay can always find the log even
/// when more than `REPLAY_GAP_TOLERANCE` leading segments are gone.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn persist_segment_floor(s: &mut Wal, sys: &SyscallTable, new_oldest: u32) -> bool {
    if s.floor_persisted >= new_oldest { return true; }
    let mut path = [0u8; WAL_PATH_MAX];
    let plen = encode_floor_path(s.partition_id, s.root_path != 0, &mut path);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
    if fd < 0 { return false; }
    let val = new_oldest.to_le_bytes();
    let w = (sys.provider_call)(fd, FS_WRITE, val.as_ptr() as *mut u8, 4);
    let fr = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    if w == 4 && fr == 0 {
        s.floor_persisted = new_oldest;
        true
    } else {
        false
    }
}

// ── Normal operation ────────────────────────────────────────

/// Tell raft which index this WAL will accept next, so it can resync its tip
/// instead of diverging silently. Best-effort: a full output channel just
/// means the next `recover_continuity` pass re-sends it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid `&SyscallTable`
/// per the module ABI.
unsafe fn emit_wal_reject(s: &mut Wal, sys: &SyscallTable, expected: u64) {
    if s.out_flushed < 0 {
        return;
    }
    let poll = (sys.channel_poll)(s.out_flushed, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    let mut buf = [0u8; 8];
    wire::encode_wal_reject(&mut buf, expected);
    wire_channels::channel_write_msg(sys, s.out_flushed, wire::MSG_WAL_REJECT, &buf);
}

unsafe fn process_entries(s: &mut Wal, sys: &SyscallTable) {
    // Continuity is fail-closed but RECOVERABLE. On a hole the WAL must NOT
    // stop draining: raft reads a full input channel as transient WAL-busy and
    // latches `flush_deferred`, which suspends intake with no error anywhere.
    // Instead it emits `MSG_WAL_REJECT` (the index it wants next) and keeps
    // discarding until raft replays from `expected`. Discarded records are
    // uncommitted by construction — never acked, so no quorum counted them
    // durable. `current_index` never advances across the hole, so no
    // high-water is ever acked across one.

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

    // Read entry — unless `msg_buf` still holds one we consumed but could not
    // stage last step (see the stash points below). Re-driving it here is what
    // makes the consume-then-fail paths lossless.
    let plen: u16 = if s.stashed_len > 0 {
        let n = s.stashed_len;
        s.stashed_len = 0;
        n
    } else {
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_ENTRY || plen < 16 { return; }
        plen
    };

    let (term, index) = wire::decode_term_index(&s.msg_buf);
    let payload_len = plen as usize;

    let expected = s.current_index.saturating_add(1);
    if index != expected {
        // Commit only the valid contiguous prefix already staged, then latch
        // closed. This record is deliberately not reflected in cursor/index,
        // so `current_index` never crosses the hole and no high-water is ever
        // acked across it.
        if s.has_batch {
            flush_batch(s, sys);
        }
        if !s.continuity_fault {
            // Count the BREAK, not every record discarded behind it — the
            // counter stays "how many times continuity was lost".
            s.continuity_errors = s.continuity_errors.saturating_add(1);
            s.continuity_fault = true;
            s.fault_expected = expected;
            s.fault_got = index;
            dev_log(sys, 1, b"[wal] continuity FAIL".as_ptr(), 21);
        }
        // Re-assert on every discard: a reject dropped by a momentarily full
        // output channel must not strand raft waiting for a resync hint.
        emit_wal_reject(s, sys, expected);
        return;
    }
    if s.continuity_fault {
        // Raft resynced to our tip and replayed from the right index.
        s.continuity_fault = false;
        dev_log(sys, 3, b"[wal] continuity resync".as_ptr(), 23);
    }

    // Frame: [entry_len: u32 LE] [crc32c: u32 LE] [entry_data]. The CRC32C
    // covers the payload bytes so replay can tell a torn payload from a
    // valid entry. The payload offset (after the 8-byte header) is tracked
    // so MSG_WAL_ENTRY_REQUEST can read it back. In group mode the FS_FSYNC
    // is deferred to flush_batch — acking before that fsync would claim
    // durability that doesn't yet hold on disk.

    // A fixed segment's physical capacity is exactly `segment_limit + 4`
    // (records + live-tail terminator), so rotate BEFORE a frame that would
    // cross the limit: an overshooting append short-writes and the flush
    // retries the same overshooting batch forever. EOF-sized segments keep
    // the grow-then-rotate path below.
    if s.fixed_segment_active
        && s.cursor > 0
        && s.cursor
            .saturating_add(FRAME_HDR + payload_len as u32)
            .saturating_add(4)
            > s.segment_limit
    {
        if s.has_batch {
            flush_batch(s, sys);
            if s.has_batch {
                // Batch undrainable this step — the record is already out
                // of the channel; stash and re-drive next step.
                s.stashed_len = plen;
                s.stashed_holds = s.stashed_holds.saturating_add(1);
                return;
            }
        }
        rotate_segment(s, sys);
    }

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
        // STASH it — this record is already out of the channel, and dropping
        // it would leave a hole that surfaces later as a continuity fault on
        // the NEXT record (which is then unrepairable once commit passes it).
        s.stashed_len = plen as u16;
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
    if frame_len > WRITE_BUF_SIZE {
        // Unstageable at any time (record larger than the whole write buffer).
        // Not a transient condition, so do NOT stash — that would spin. This
        // is a hard mis-sizing; fail closed and let the continuity fault
        // report it rather than silently losing the entry.
        s.write_errors = s.write_errors.saturating_add(1);
        return;
    }
    if s.write_pos as usize + frame_len > WRITE_BUF_SIZE {
        flush_batch(s, sys);
        if s.has_batch {
            // The buffer could not be drained this step (fsync in flight, ack
            // channel full, segment rolling). This record is already out of
            // the channel — stash and re-drive it next step. Dropping it
            // would leave `current_index` un-advanced, so the next record
            // arrives as `current_index + 2` and latches a continuity fault.
            s.stashed_len = plen as u16;
            s.stashed_holds = s.stashed_holds.saturating_add(1);
            return;
        }
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
        rotate_segment(s, sys);
    }
}

/// Close the current segment and advance to the next seq. The caller
/// must have drained any staged batch first (acks are ordered relative
/// to the close).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn rotate_segment(s: &mut Wal, sys: &SyscallTable) {
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
        // Group mode only. Per-entry mode flushes a singleton batch per
        // append, so its durability signal is already `[wal] entry ok` at
        // stage time; the test suite keys on that dichotomy.
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
/// A persistent `fd < 0` means the FS is initialising (E_AGAIN) or
/// broken (hard error, after the one-shot `wal/` self-heal): the
/// caller's readiness gate holds entry intake either way.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ensure_segment_open(s: &mut Wal, sys: &SyscallTable) {
    if s.fd >= 0 { return; }
    if VOLATILE {
        // The volatile variant selects in-memory retention by
        // design, never as a fallback, so no failure signal.
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
    if s.fd >= 0 && !s.fixed_segment_active {
        // A pre-existing file at this seq (skip_replay orphan, reuse on a
        // provider without UNLINK) may hold stale frames beyond our write
        // cursor. Learn its size so that region is treated like a
        // post-truncate suffix — every append stages a trailing terminator
        // until fresh writes overwrite past it, else replay reads our
        // fresh frames and continues straight into the stale ones.
        let mut stat_buf = [0u8; 8];
        let rc = (sys.provider_call)(s.fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        if rc >= 0 {
            let size = u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]]);
            if size > s.seg_high_water {
                s.seg_high_water = size;
            }
        }
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
    // Hard error. The provider maps every open failure to one errno, so
    // a missing `wal/` parent (nothing creates it outside the test
    // harness) is indistinguishable from a dead disk — self-heal the
    // parent once and retry before concluding anything.
    if s.root_path == 0 && !s.mkdir_attempted {
        s.mkdir_attempted = true;
        let mut dir = [0u8; 4];
        dir[..3].copy_from_slice(b"wal");
        let _ = (sys.provider_call)(-1, FS_MKDIR, dir.as_mut_ptr(), 3);
        dev_log(sys, 3, b"[wal] mkdir wal".as_ptr(), 15);
        s.fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), s.path_len as usize);
        if s.fd >= 0 || s.fd == FS_E_AGAIN {
            return; // healed, or the provider is still settling
        }
    }
    // Hard failure in a DISK build: fail closed, loudly. `fd` stays -1,
    // appends stash with `write_errors` and are never acked, raft
    // backpressures, and the open retries every step — the graph holds
    // rather than certifying durability it doesn't have. (In-memory
    // operation is the `volatile` variant's declared mode, never a
    // fallback.)
    // Count the TRANSITION into hard failure, not every retry: the
    // open is re-attempted each step while the path stays broken, and
    // a per-step increment would bury the per-entry durable-write
    // failures this counter exists to surface.
    if !s.no_fs_logged {
        s.no_fs_logged = true;
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 1, b"[wal] open fail".as_ptr(), 15);
    }
}

/// The WAL's current `(term, index)` high-water — the same value a
/// rotation trigger would carry. The dispatch table hands it to the
/// snapshot component so a demand-triggered snapshot (install request
/// with no snapshot taken yet) captures at the same point a rotation
/// capture would.
pub fn high_water(s: &Wal) -> (Term, Index) {
    (s.current_term, s.current_index)
}

/// Seam delivery from the snapshot component: a peer snapshot was
/// accepted at `(term, index)`. The subsumed prefix will never arrive
/// on `entries`, so fast-forward the append contract — otherwise the
/// first post-install append (`index + 1`) collides with the
/// continuity gate's `current_index + 1` and latches a fault whose
/// reject would roll raft's freshly installed tip straight back.
///
/// Entries at or below `index` are no longer locally servable
/// (compaction semantics — raft's post-install `compact_before`
/// carries the same floor); the ledger learns the installed
/// high-water as durable, matching the durable artefact the install
/// path just wrote (or, with no FS, the in-memory image the install
/// IS on this graph).
///
/// Disk note: a later boot replays the on-disk prefix and stops at
/// the index gap this jump leaves ("[wal] replay gap") — recovery
/// then resumes from the durable prefix and the cluster re-installs,
/// which is conservative, loud, and preferred over serving a log
/// with a silent hole.
pub fn on_snapshot_installed(s: &mut Wal, term: Term, index: Index) {
    if index <= s.current_index {
        return;
    }
    s.current_term = term;
    s.current_index = index;
    if index.saturating_add(1) > s.entry_ring_min_index {
        s.entry_ring_min_index = index.saturating_add(1);
    }
    note_ledger_ack(s, term, index);
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

/// Fsync the current segment file, timing the call and folding the
/// elapsed µs into the `clustor.wal.fsync_latency_ms` histogram. All
/// durable-write fsync sites route through here so the histogram covers
/// both strict per-entry and group-deferred fsyncs.
///
/// Returns 0 on success, the provider's negative errno on failure, or -1 when
/// there is no open segment. A failed fsync is NOT folded into the latency
/// histogram (it isn't a real durability measurement); callers must treat a
/// non-zero return as "not durable" and withhold the FsyncAck.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
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

/// Close the current segment and prepare for rotation.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
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
    // Durability state on the heartbeat, not only in the one-shot
    // `open rc=` line: 1 = a real segment descriptor is open
    // (disk-backed), 0 = not. Rig pass rules may only key on recurring
    // signals (`standards/rig.md`), and the UDP log monitor attaches
    // after boot, so a one-shot marker is invisible to both.
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
    let scalars: [(u16, u8, i64); 21] = [
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
        (wire::metric_ids::WAL_STASHED_HOLDS, kc, i64::from(s.stashed_holds)),
        (wire::metric_ids::WAL_CURRENT_INDEX, kg, s.current_index as i64),
        (wire::metric_ids::WAL_FAULT_EXPECTED, kg, s.fault_expected as i64),
        (wire::metric_ids::WAL_FAULT_GOT, kg, s.fault_got as i64),
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
