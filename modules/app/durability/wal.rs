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

use super::{fs_step, sealed};
#[path = "wal_seal.rs"]
pub mod wal_seal;
use super::{
    dev_input_flow_budget, dev_log, dev_micros, dev_millis, dev_report_step_effect, fmt_u32_raw,
    step_effect, wire, wire_channels, POLL_IN, POLL_OUT,
};
use fs_step::{later, Io};

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

/// Retention window of the volatile variant, in slots: how far back a
/// refetch can reach in memory. Power of two, so both ring masks below
/// reduce an index to a slot with a single `&`.
///
/// This is the one number that sets a volatile replica's memory cost.
/// It sizes `memory_entries`, whose slots carry full bodies at
/// `MemoryEntry` = 2064 B apiece — 516 KiB at 256 slots, which is most
/// of `Wal`. It also sizes `entry_ring` on a volatile build, for the
/// reason given there.
const VOLATILE_RETENTION_SLOTS: usize = 256;

/// Length of `memory_entries`: the retention window on a volatile
/// build, one slot on a disk build.
///
/// The array is written on exactly one path — the `no_fs` branch of
/// `append_entry` — and `no_fs` is set only by the volatile variant
/// (`arm`, `ensure_segment_open`); a disk build never sets it, because
/// a hard open error there fail-closes rather than degrading to memory.
/// A disk build therefore never populates a slot, and the two paths
/// that read them see only zeroes: the `no_fs`-gated serve, which it
/// never enters, and `publish_truncation`'s sweep, which finds every
/// `index` still 0 and clears nothing. At 2064 B a slot, carrying the
/// full window on that build would cost a disk replica 514 KiB of
/// module state no code path can reach. See `memory_slot` for the
/// accessor that keeps the two sizings honest.
const MEMORY_RING_SIZE: usize = if VOLATILE {
    VOLATILE_RETENTION_SLOTS
} else {
    1
};
const MEMORY_RING_MASK: u64 = (MEMORY_RING_SIZE as u64) - 1;

/// Per-body cap, taken from the graph-wide entry-body cap rather than
/// restated here. `wal_frame::MAX_ENTRY_BODY` is what raft's proposal
/// buffer and the `entry_reply` port's `max_record` are both sized
/// against; a local literal would pin this ring to one number while
/// those move, silently truncating every retained body.
const MEMORY_ENTRY_BODY_CAP: usize = wal_frame::MAX_ENTRY_BODY;

/// Slots in the index->offset map (`entry_ring`). Separate from the
/// body ring: locations are 32 B, so a disk build affords far more of
/// them than it could afford bodies.
///
/// On restart, apply restarts at index 0 and refetches every entry;
/// any index below `entry_ring_min_index` misses the map. 8192 slots
/// cost ~256 KiB and cover realistic recovery windows between
/// snapshots.
///
/// On a DISK build the bound is NOT a hard recovery ceiling: a request
/// below the ring floor falls back to a bounded forward scan of the
/// on-disk segments (`step_entry_scan`), which locates the record by
/// walking frames from the oldest durable segment. Only indices whose
/// segment was compacted away are truly unservable
/// (`[wal] entry req unservable`) — for those, snapshot install is the
/// only way back.
///
/// A VOLATILE build has no segments to scan (`step_entry_scan` is
/// gated off there) and cannot serve any index whose BODY has aged out,
/// so a location slot outliving its body could never resolve to a
/// servable reply. The map is therefore sized to the body ring on that
/// build: 248 KiB less module state, and the two floors coincide, which
/// makes `entry_ring_min_index` the single honest retention edge rather
/// than one that under-reports what is actually servable.
const ENTRY_LOC_RING_SIZE: usize = if VOLATILE {
    VOLATILE_RETENTION_SLOTS
} else {
    8192
};
const ENTRY_LOC_RING_MASK: u64 = (ENTRY_LOC_RING_SIZE as u64) - 1;

/// Term boundaries kept: the first index of each of this many recent
/// terms. A term changes only at an election, so the table answers the
/// term of any index since the oldest boundary it holds, however far
/// that index has fallen behind the location ring — which is what an
/// install clamped to a lagging commit index needs.
const TERM_BOUNDARIES: usize = 32;

/// The first index the log holds at `term`.
#[derive(Clone, Copy)]
#[repr(C)]
struct TermBoundary {
    index: u64,
    term: u64,
}

/// Segment starts kept: the first index of each of this many recent
/// segment files. A walk for an index below the location ring opens
/// the segment that holds it instead of the oldest one, so locating
/// an old entry — a lagging refetch, or a truncation whose keep point
/// has left the ring — costs one segment, not the whole retained log.
const SEGMENT_STARTS: usize = 64;

/// The first index written to segment `seq`.
#[derive(Clone, Copy)]
#[repr(C)]
struct SegmentStart {
    first_index: u64,
    seq: u32,
}

/// Footprint budget for `Wal`, enforced at compile time.
///
/// `Wal` is by far the largest component in the durability composite,
/// so it is what decides whether a constrained target fits. The kernel
/// allocates module state from `module_state_size()`, not from BSS, so
/// nothing in the linker output flags a regression here — an extra ring
/// or a widened `MemoryEntry` costs half a megabyte of RAM per replica,
/// silently. These bounds sit a little above the actual sizes (disk
/// 285_664 B, volatile 558_032 B) so ordinary field additions pass,
/// while re-inflating a ring — the only change big enough to matter —
/// fails the build.
const WAL_FOOTPRINT_BUDGET: usize = if VOLATILE { 600 * 1024 } else { 320 * 1024 };
const _: () = assert!(
    core::mem::size_of::<Wal>() <= WAL_FOOTPRINT_BUDGET,
    "Wal exceeds its footprint budget — see WAL_FOOTPRINT_BUDGET",
);

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
        Self {
            index: 0,
            term: 0,
            seg_seq: 0,
            payload_offset: 0,
            payload_len: 0,
        }
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
        Self {
            index: 0,
            body_len: 0,
            body: [0; MEMORY_ENTRY_BODY_CAP],
        }
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
/// Durable publication of a parent-directory entry
/// (`modules/sdk/contracts/storage/fs.rs::{FSYNC_NAME, caps::FSYNC_NAME}`).
/// `FS_FSYNC` covers a segment's bytes through its descriptor; it does
/// NOT make the name that finds the segment survive a power cut. Both
/// fences are required before a segment file counts as durable.
const FS_FSYNC_NAME: u32 = 0x0912;
const FS_CAP_FSYNC_NAME: u32 = 1 << 11;
/// FS capability-discovery opcode + the `UNLINK` bit
/// (`modules/sdk/contracts/storage/fs.rs::{CAPS, caps::UNLINK}`).
const FS_CAPS: u32 = 0x09FF;
const FS_CAP_UNLINK: u32 = 1 << 5;
/// FS ENOSYS: the provider implements no such opcode. Distinct from an
/// allocation or device failure, which must never be reinterpreted as
/// "this backend does not offer the feature".
const FS_E_NOSYS: i32 = -38;
/// FS ENOENT: the named file is not there. The read-only opener
/// (`FS_OPEN`) answers this for a name that does not exist, which is how
/// an absent segment is told apart from a provider that is refusing.
const FS_E_NOENT: i32 = -2;

/// `name_fence` postures. `AUTO` publishes names through
/// `FS_FSYNC_NAME` when the provider advertises `caps::FSYNC_NAME` and
/// meters every unfenced publication when it does not. `STRICT` refuses
/// to publish a name the provider cannot fence, so a segment is never
/// admitted on a backend that cannot prove the name reaches media.
const NAME_FENCE_AUTO: u8 = 0;
const NAME_FENCE_STRICT: u8 = 1;

/// `name_fence_probe` / `WAL_NAME_FENCE` dispositions.
const NAME_FENCE_UNPROBED: u8 = 0;
const NAME_FENCE_PRESENT: u8 = 1;
const NAME_FENCE_ABSENT: u8 = 2;

/// `WAL_SEGMENT_MODE` values — see the metric's own documentation.
const SEGMENT_MODE_DYNAMIC: i64 = 0;
const SEGMENT_MODE_FIXED: i64 = 1;
const SEGMENT_MODE_FALLBACK: i64 = 2;

/// FS E_AGAIN / E_INPROGRESS are never failures here. Every fs call is
/// non-blocking (`fs_step`): `EAGAIN` means nothing moved — the provider is
/// still mounting, a bounded resource is full, or the data is not cached
/// yet — and `EINPROGRESS` means a multi-step operation was taken and is
/// decided on a later ask of the byte-identical request. Every sequence
/// below keeps its in-flight request in `Wal` and resumes it on a later
/// step; while a durable write is undecided the WAL holds new entries (raft
/// backpressures) rather than degrading to in-memory, which would drop
/// durability once the provider came up.
const FS_E_INPROGRESS: i32 = fs_step::E_INPROGRESS;

/// How a resumable fs sequence stands after one step's asks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Finished, and what it was asked to make true is true.
    Done,
    /// Still in flight: its request is kept and resumed on a later step.
    Later,
    /// A real failure (already counted and logged where it was seen).
    Fail,
}

// Segment-admission phases (`open_phase`): the sequence that turns a
// segment path into an admitted, name-fenced descriptor.
const OPEN_IDLE: u8 = 0;
const OPEN_CREATE: u8 = 1;
const OPEN_MKDIR: u8 = 2;
const OPEN_PREALLOC: u8 = 3;
const OPEN_TERM: u8 = 4;
const OPEN_REWIND: u8 = 5;
const OPEN_FSYNC: u8 = 6;
const OPEN_NAME: u8 = 7;
const OPEN_STAT: u8 = 8;

// In-segment truncation phases (`tc_phase`).
const TC_SEEK: u8 = 0;
const TC_WRITE: u8 = 1;
const TC_FSYNC: u8 = 2;

// Cross-segment truncation: preparing the keep segment (`retire_prep`).
const PREP_OPEN: u8 = 0;
const PREP_STAT: u8 = 1;
const PREP_SEEK: u8 = 2;
const PREP_WRITE: u8 = 3;
const PREP_FSYNC: u8 = 4;
const PREP_NAME: u8 = 5;
const PREP_DONE: u8 = 6;

// Segment invalidation phases (`rm_phase`).
const RM_START: u8 = 0;
const RM_UNLINK: u8 = 1;
const RM_UNAME: u8 = 2;
const RM_PROBE: u8 = 3;
const RM_CREATE: u8 = 4;
const RM_SEEK: u8 = 5;
const RM_WRITE: u8 = 6;
const RM_FSYNC: u8 = 7;
const RM_CNAME: u8 = 8;

// Compaction unlink phases (`cp_phase`).
const CP_UNLINK: u8 = 0;
const CP_NAME: u8 = 1;

// Floor-sidecar persist phases (`sc_phase`).
const SC_IDLE: u8 = 0;
const SC_OPEN: u8 = 1;
const SC_WRITE: u8 = 2;
const SC_FSYNC: u8 = 3;
const SC_NAME: u8 = 4;

// Read-back serve phases (`sv_phase`).
const SV_OPEN: u8 = 0;
const SV_SEEK: u8 = 1;
const SV_READ: u8 = 2;
const SV_REPLY: u8 = 3;

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

/// Per-kpg retention-floor table capacity. A downstream consumer emits
/// one `MSG_COMPACTION_FLOOR` per active kpg it cares about, however it
/// arrives at that floor. 32 slots covers any realistic per-partition
/// kpg count; on overflow the engine fails closed (see
/// `retention_floor_overflow`) — evicting a slot would silently widen
/// the compaction window past a live floor, and fail-open would do the
/// same for the unrecorded one.
const RETENTION_FLOOR_SLOTS: usize = 32;

/// Empty-slot sentinel for the retention-floor table. `0xFFFF` is
/// wire-reserved as "never a real kpg id" so this value can mark vacant
/// slots without colliding with `kpg_id = 0`.
const FLOOR_SLOT_EMPTY: u16 = u16::MAX;

#[derive(Clone, Copy)]
#[repr(C)]
struct RetentionFloorSlot {
    kpg_id: u16,
    floor_revision: u64,
}

impl RetentionFloorSlot {
    const fn empty() -> Self {
        Self {
            kpg_id: FLOOR_SLOT_EMPTY,
            floor_revision: 0,
        }
    }
}

#[repr(C)]
pub struct Wal {
    // Channels (composite indices per `mod.rs::module_new`)
    pub in_entries: i32, // in[0]: WalEntry from consensus
    /// Voter-set update lifted off the entry stream for the dispatch
    /// table to hand to `ledger` (components never call each other —
    /// see the module header). Mirrors raft's `voter_out` latch.
    /// Latest-wins: only the newest configuration matters.
    pub voter_out: Option<(u8, u8, bool, u8)>,
    /// Per-slot inboxes. The module reads each shared channel once and
    /// routes by the partitioned envelope's id; this slot drains only
    /// its own. Without this a slot's destructive read would consume —
    /// and discard — frames addressed to its siblings.
    pub inbox_entries: super::inbox::Inbox,
    pub inbox_entry_req: super::inbox::Inbox,
    pub in_entry_request: i32, // in[1]: MSG_WAL_ENTRY_REQUEST (replicator NACK path)
    pub in_compact_before: i32, // in[2]: MSG_WAL_COMPACT_BEFORE (post-snapshot trim)
    /// in[7]: `MSG_COMPACTION_FLOOR` from the application — the lowest
    /// index it can still ask this log for (a Kafka retention window).
    pub in_retention_floor: i32,
    pub inbox_retention: super::inbox::Inbox,
    /// Application retention floors, per kpg. A floor bounds segment
    /// RETIREMENT, not the snapshot: a snapshot is state and is always
    /// safe to take, while the entries below it are content a consumer
    /// may still read from disk. Linear scans — small enough that the
    /// scan fits in one tick.
    retention_floors: [RetentionFloorSlot; RETENTION_FLOOR_SLOTS],
    /// Sticky bit set when a floor arrived for a kpg the table could not
    /// hold. Compaction fails closed (retires nothing) while set: the
    /// picture of what is still needed is incomplete. Recovery is an
    /// operator restart with a larger `RETENTION_FLOOR_SLOTS`.
    retention_floor_overflow: bool,
    /// Consensus's own floor: the slowest voter's match index, carried
    /// as `MSG_COMPACTION_FLOOR` on `compact_before`. Retiring below it
    /// would strand a follower that still needs those entries. Latest
    /// wins; `None` until the first one arrives.
    match_floor: Option<u64>,
    /// The snapshot component's transfer floor (seam, set each step): a
    /// peer being caught up by a portable copy replays the log from the
    /// copy's position, which must outlive the transfer.
    pub xfer_floor: Option<u64>,
    /// Compactions whose trim point a floor pulled down. Rising means
    /// retention (or a lagging voter) is what bounds disk, not the
    /// snapshot cadence.
    compact_floored: u32,
    pub out_flushed: i32, // out[0]: FsyncAck (external consumers; ledger is fed in-module)
    pub out_replay_complete: i32, // out[1]: MSG_WAL_REPLAY_COMPLETE to consensus
    pub out_entry_reply: i32, // out[2]: MSG_WAL_ENTRY_REPLY back to requester
    /// Cold-read request/reply: a SECOND, independent entry read-back
    /// path for consumers that address the log by content rather than by
    /// replication position — today, a Kafka Fetch whose offset has aged
    /// out of the in-memory ring but whose record is still in the WAL.
    ///
    /// Its own channel pair rather than sharing `entry_request`: that one
    /// is the crash-recovery refetch path, its `request_id` space is
    /// fully allocated (bit 31 splits `replicator` from `apply`), and a
    /// client-driven read has no business sharing a queue with log
    /// rebuild.
    pub in_cold_read: i32,
    pub out_cold_reply: i32,
    /// Per-slot inbox for `in_cold_read`, filled by the module's intake
    /// demux from the partitioned envelope.
    pub inbox_cold_read: super::inbox::Inbox,
    /// Cold reads served and refused, for the operator view: refusals
    /// rising means consumers are falling further behind than the log
    /// can still locate.
    pub cold_served: u32,
    pub cold_notfound: u32,
    pub out_compaction: i32, // out[3]: SnapshotTrigger for downstream coordinators
    pub out_metrics: i32,    // out[4]: MetricsPayload to operations.telemetry

    // WAL state
    pub partition_id: u16,
    pub self_id: u8,
    current_term: Term,
    current_index: Index,
    segment_seq: u32,
    cursor: u32, // bytes written in current logical segment
    /// Furthest byte ever written in the CURRENT segment. After a
    /// truncation rewinds `cursor` below this, stale frames live in
    /// `[cursor, seg_high_water)`; until fresh appends overwrite past it,
    /// every append writes a trailing zero-length terminator so replay
    /// stops at the live tail instead of reading the stale suffix. Reset
    /// to 0 on segment rotation. See `MSG_WAL_TRUNCATE_AFTER`.
    seg_high_water: u32,
    pub segment_limit: u32, // from params (default 64 MiB)
    /// Segment rotations this boot — on `[wal] hb` with the limit and the
    /// cursor, so a segment that never rotates is read, not inferred.
    pub rotations: u32,
    /// Oldest segment_seq still on disk after compaction. Requests for
    /// entries in segments < `oldest_segment_seq` return NOT_FOUND, which
    /// triggers the snapshot-install fallback on the leader.
    oldest_segment_seq: u32,
    pub dek_epoch: u32,
    pub encoding: u8, // 0=binary

    /// Ring buffer of recent entry locations for random-access lookup
    /// (replicator NACK retry, apply gap refetch, crash recovery).
    /// `ENTRY_LOC_RING_SIZE` covers the last 8192 indices on a disk
    /// build and the retention window on a volatile one; older indices
    /// fall through to a NOT_FOUND reply and snapshot fallback.
    entry_ring: [EntryLoc; ENTRY_LOC_RING_SIZE],
    /// Proposal bodies retained by the volatile variant's declared
    /// in-memory mode. Bodies are 2 KiB each, so this is the ring that
    /// sets `Wal`'s footprint: only the last `VOLATILE_RETENTION_SLOTS`
    /// indices are refetchable, and older ones answer NOT_FOUND (which
    /// escalates to snapshot install). A disk build never sets `no_fs`
    /// and so never populates a slot, which is why `MEMORY_RING_SIZE`
    /// is one slot there.
    memory_entries: [MemoryEntry; MEMORY_RING_SIZE],
    entry_ring_max_index: u64,
    entry_ring_min_index: u64,
    /// The first index of each recent term, ascending, newest last
    /// (see `TERM_BOUNDARIES`). Seeded by replay, extended on append,
    /// trimmed with a suffix discard, restarted by a snapshot install.
    term_bounds: [TermBoundary; TERM_BOUNDARIES],
    term_bounds_len: u8,
    /// The first index of each recent segment, ascending by both seq
    /// and index, newest last (see `SEGMENT_STARTS`). Seeded by replay,
    /// extended by the first append into a rotated segment, trimmed
    /// with a suffix discard.
    seg_starts: [SegmentStart; SEGMENT_STARTS],
    seg_starts_len: u8,
    /// The last index an entry request asked for (telemetry).
    last_req_index: u64,

    // File I/O
    fd: i32, // file descriptor for current segment, -1 = not open
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
    /// Count of truncation requests refused because the new tail could
    /// not be made durable. Nothing was published for these: the
    /// high-water is unchanged and the requester keeps its old tip.
    truncate_failures: u32,
    /// A truncation ack the output channel could not take yet. The ack
    /// is what releases the requester's held tip, so it is parked and
    /// retried rather than dropped.
    trunc_ack_pending: bool,
    trunc_ack_index: Index,
    trunc_ack_req: u32,
    trunc_ack_durable: bool,
    /// A truncation is mid-retirement: the discarded segment range is
    /// being made inert `COMPACT_UNLINKS_PER_STEP` at a time, and the
    /// write state it will publish is parked in the other `retire_*`
    /// fields. While this is set nothing opens a segment, stages a
    /// record, or reads another control frame — the WAL's descriptor
    /// and segment sequence are not valid to write through yet.
    retire_active: bool,
    /// Next segment sequence to retire, and the last of the range
    /// (inclusive). `retire_from > retire_through` means the range is
    /// inert and the truncation may publish.
    retire_from: u32,
    retire_through: u32,
    /// At least one segment of the range is already inert, so the
    /// request is no longer a clean repeat of an untouched log.
    retire_partial: bool,
    /// Write state the truncation publishes once the range is inert:
    /// descriptor, sequence, cursor, and physical extent.
    retire_fd: i32,
    retire_seq: u32,
    retire_cursor: u32,
    retire_high_water: u32,
    /// The whole log is discarded: the published sequence is a FRESH
    /// file and the compaction floor follows it.
    retire_fresh: bool,
    /// The request this retirement answers.
    retire_keep_index: Index,
    retire_keep_term: Term,
    retire_req: u32,
    last_metrics_ms: u64,
    /// `clustor.wal.fsync_latency_ms` cumulative bucket counts. One slot per
    /// `wire::hist::FSYNC_LATENCY_US` bound plus a trailing `+Inf` overflow
    /// bucket. Measured in µs at each `FS_FSYNC` call site; emitted as
    /// `METRIC_KIND_HISTOGRAM` samples.
    /// Read by mod.rs's kernel-ring emit as well as the MSG_METRIC_SAMPLE
    /// export below — one array, two wires.
    pub fsync_buckets: [u32; wire::hist::FSYNC_LATENCY_US.len() + 1],

    // Replay state
    phase: u8,             // PHASE_REPLAY or PHASE_NORMAL
    replay_seg: u32,       // current segment being replayed
    replay_fd: i32,        // fd for replay segment, -1 = none
    replay_file_size: u32, // total bytes in replay segment
    replay_pos: u32,       // current read position
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
    /// FS `caps::FSYNC_NAME` probe cache: `NAME_FENCE_UNPROBED`,
    /// `NAME_FENCE_PRESENT`, `NAME_FENCE_ABSENT`. Shares the one-shot
    /// CAPS read with `fs_unlink_probe`.
    name_fence_probe: u8,
    /// `NAME_FENCE_AUTO` or `NAME_FENCE_STRICT` (config param 15).
    pub name_fence: u8,
    /// Counter behind `WAL_NAME_UNFENCED`: segment names minted or
    /// retired on a provider with no `caps::FSYNC_NAME`.
    name_unfenced: u32,
    /// One-shot guard for the `write_errors` step in
    /// `ensure_segment_open`'s name-fence refusal path. The open is
    /// re-attempted every step while the descriptor is refused, so the
    /// counter records the TRANSITION into refusal — a per-step
    /// increment would bury the per-entry durable-write failures it
    /// exists to surface.
    name_fence_refused: bool,
    /// One-shot guards for the two name-fence diagnostics. Both
    /// conditions recur on every publication attempt and both are
    /// already exported as gauges (`WAL_NAME_FENCE`,
    /// `WAL_NAME_UNFENCED`), so the log records the transition only.
    name_fence_absent_logged: bool,
    name_fence_fail_logged: bool,
    pub fixed_segment: u8,
    fixed_segment_active: bool,
    /// Set once `PREALLOCATE` has answered `ENOSYS` for this provider:
    /// fixed segments were requested, the backend has no such opcode,
    /// and every segment is a normal dynamically grown file. Reported
    /// as `SEGMENT_MODE_FALLBACK` so protected operation and
    /// compatibility operation are distinguishable from outside.
    preallocate_unsupported: bool,
    /// The errno of the most recent `PREALLOCATE` refusal that was NOT
    /// `ENOSYS` (allocation or device failure), or 0. Reported as
    /// `WAL_PREALLOCATE_ERRNO`.
    preallocate_errno: i32,
    /// Counter behind `WAL_PREALLOCATE_FAILURES`.
    preallocate_failures: u32,
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
    /// Serves refused because the segment would not open (telemetry).
    entryreq_open_fail: u32,
    /// The read fd an entry serve holds open on a SEALED segment, and
    /// that segment. A catch-up asks for a segment's entries one by one,
    /// and on a FAT32 root every open is a directory scan that can answer
    /// `E_AGAIN`, so opening per entry caps a catch-up at the scan rate
    /// and refuses some serves outright. The live segment is never held
    /// (its size grows under the writer); a retired segment drops its fd
    /// before the unlink.
    serve_fd: i32,
    serve_seg: u32,
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
    /// The scan is locating a truncation's keep point (see
    /// `begin_truncate_locate`): its hit resumes the truncation and is
    /// never delivered as an entry reply, and its miss refuses the
    /// truncation.
    scan_for_truncate: bool,
    /// A truncation is parked on the scan: the keep point left the
    /// location ring and is being located on disk. The control channel
    /// is not drained past it, so later requests keep their order.
    trunc_locating: bool,
    trunc_locate_keep: u64,
    trunc_locate_req: u32,
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
    /// Segment replay starts from, persisted beside the floor: the one
    /// holding the latest durable snapshot's index. Segments between the
    /// floor and it are retained content — a Kafka window a consumer may
    /// still read from disk — but raft rebuilds its log only from the
    /// snapshot on, so boot replay skips them and the cold-read scan
    /// serves them on demand. Without this, boot cost would scale with
    /// the retention window rather than with the log above the snapshot.
    replay_start_persisted: u32,
    /// First index replay recorded, so the ring's floor can be raised to
    /// it when replay started above the segment floor: indexes below it
    /// are on disk but not in the ring, and the scan must serve them.
    replay_first_index: u64,

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

    /// Sealed frames, the nonce-domain allocator and key
    /// epochs. Inert when the `aead` parameter is 0.
    pub seal: wal_seal::WalSeal,
    /// The group's configuration, followed from the config entries this
    /// log takes, and whether it moved since the dispatch table last
    /// handed it to the snapshot component.
    pub cfg: wire::CfgTrack,
    pub cfg_dirty: bool,
    /// One whole sealed frame read back for serving or scanning, and the
    /// reply composed over it. In state rather than on the stack, so the
    /// sealed read paths add no page-sized frame of their own.
    seal_frame: [u8; SEALED_FRAME_MAX],

    // ── Non-blocking fs: requests in flight ───────────────────
    //
    // No fs call waits on the device, so every multi-call sequence keeps
    // its request here and resumes it on a later step (see `fs_step`).
    /// An `FS_FSYNC` on `fd` was asked and has not been decided. Until it
    /// is, nothing writes through `fd`: a re-ask is byte-identical to the
    /// first ask, so its decision covers only the bytes written before it,
    /// and a write in between would be acknowledged by a fence that never
    /// covered it. Staging holds meanwhile.
    sync_pending: bool,
    /// When the pending fsync was first asked (µs), for the histogram.
    sync_start_us: u64,
    /// Bytes at the front of the staged batch the provider has already
    /// accepted. A short write advances this, and the rest is resumed
    /// after it on a later step.
    flush_moved: u16,
    /// A rotation is under way: the old segment's fsync awaits its
    /// decision. Staging holds until the next segment is the live one.
    rotating: bool,
    /// Segment admission (`OPEN_*` phases): the descriptor being admitted
    /// is held here, never in `fd`, until the name fence admits it.
    open_phase: u8,
    open_fd: i32,
    open_moved: u8,
    /// The last `FS_OPEN_CREATE` answer, for the `[wal] open rc=` line.
    open_rc: i32,
    /// This boot minted the `wal/` directory (`FS_MKDIR` answered 0) and
    /// its name is not fenced yet: nothing inside it is admitted, adopted
    /// or acknowledged until it is (`fence_wal_dir`).
    dir_unfenced: bool,
    /// An in-segment truncation is being persisted (`TC_*` phases): its
    /// keep point, rewound cursor, term and request.
    tc_active: bool,
    tc_phase: u8,
    tc_moved: u8,
    tc_cursor: u32,
    tc_keep: u64,
    tc_term: Term,
    tc_req: u32,
    /// Cross-segment truncation: how far the keep segment's terminator
    /// has got (`PREP_*`), and bytes of it written.
    retire_prep: u8,
    retire_moved: u8,
    /// Segment invalidation in flight (`RM_*`): its segment, phase, the
    /// terminator descriptor, and whether the unlink was taken.
    rm_seq: u32,
    rm_phase: u8,
    rm_fd: i32,
    rm_moved: u8,
    rm_unlinked: bool,
    rm_taken: bool,
    /// Compaction's unlink of `oldest_segment_seq` in flight (`CP_*`).
    cp_phase: u8,
    cp_taken: bool,
    /// Floor-sidecar persist in flight (`SC_*`), the values it writes, and
    /// the values wanted next.
    sc_phase: u8,
    sc_fd: i32,
    sc_moved: u8,
    sc_floor: u32,
    sc_start: u32,
    floor_wanted: u32,
    start_wanted: u32,
    /// Replay's read of the floor sidecar: descriptor, bytes, buffer.
    floor_rd_fd: i32,
    floor_rd_got: u8,
    floor_rd_buf: [u8; 8],
    /// Replay's open segment has been sized (`FS_STAT` answered).
    replay_sized: bool,
    /// Bytes of the current replay frame read so far, and its header.
    replay_got: u32,
    replay_hdr: [u8; 8],
    /// The scan's open segment has been sized.
    scan_sized: bool,
    /// Bytes of the current scan record's prefix read so far, and the
    /// prefix (`[len][crc][term][index]`).
    scan_got: u32,
    scan_hdr: [u8; 24],
    /// Delivery of a scan-located record: seeked, and bytes read.
    dlv_seeked: bool,
    dlv_got: u32,
    /// One read-back serve in flight (`SV_*`): the request it answers,
    /// where the frame is, the descriptor read through (`sv_own` = a
    /// per-serve descriptor closed when the serve ends), and bytes read.
    sv_active: bool,
    sv_phase: u8,
    sv_sealed: bool,
    sv_own: bool,
    sv_fd: i32,
    sv_request_id: u32,
    sv_index: u64,
    sv_chan: i32,
    sv_loc: EntryLoc,
    sv_got: u32,
    /// The serve answers a cold read (counted when it answers).
    sv_cold: bool,
    /// The serve's frame, apart from `seal_frame` (the scan's): both may
    /// be part-read across steps at once.
    serve_buf: [u8; SEALED_FRAME_MAX],

    // Scratch buffer for reading messages
    msg_buf: [u8; 4096],
}

/// Largest stored sealed frame: the largest entry plus the v1 overhead.
const SEALED_FRAME_MAX: usize = wal_frame::MAX_ENTRY_LEN + sealed::WAL_OVERHEAD;

/// Write a frame to a consensus-facing channel in the 5-byte
/// partitioned envelope, stamped with this WAL's partition.
///
/// One durability instance hosts K groups, so the consumer cannot infer
/// the partition from the wiring and has to be told — which is what the
/// partitioned envelope is for. A non-partitioned graph uses the same
/// 5-byte form with `partition_id = 0`, so there is one code path.
///
/// # Safety
/// Caller must supply a valid `&SyscallTable` per the module ABI.
#[inline]
unsafe fn write_part(s: &Wal, sys: &SyscallTable, chan: i32, msg_type: u8, payload: &[u8]) -> i32 {
    wire_channels::channel_write_partitioned(sys, chan, s.partition_id, msg_type, payload)
}

pub unsafe fn init(s: &mut Wal) {
    s.voter_out = None;
    s.inbox_entries = super::inbox::Inbox::new();
    s.inbox_entry_req = super::inbox::Inbox::new();
    s.inbox_cold_read = super::inbox::Inbox::new();
    s.inbox_retention = super::inbox::Inbox::new();
    s.in_retention_floor = -1;
    s.retention_floors = [RetentionFloorSlot::empty(); RETENTION_FLOOR_SLOTS];
    s.retention_floor_overflow = false;
    s.match_floor = None;
    s.xfer_floor = None;
    s.compact_floored = 0;
    s.in_entries = -1;
    s.in_entry_request = -1;
    s.in_compact_before = -1;
    s.out_flushed = -1;
    s.out_compaction = -1;
    s.out_metrics = -1;
    s.out_entry_reply = -1;
    s.in_cold_read = -1;
    s.out_cold_reply = -1;
    s.cold_served = 0;
    s.cold_notfound = 0;
    s.out_replay_complete = -1;
    s.partition_id = 0;
    s.self_id = 0;
    s.current_term = 0;
    s.current_index = 0;
    s.cursor = 0;
    s.seg_high_water = 0;
    s.segment_limit = 67_108_864;
    s.rotations = 0;
    s.dek_epoch = 0;
    s.encoding = 0;
    s.entry_ring_max_index = 0;
    s.entry_ring_min_index = 0;
    s.term_bounds = [TermBoundary { index: 0, term: 0 }; TERM_BOUNDARIES];
    s.term_bounds_len = 0;
    s.seg_starts = [SegmentStart {
        first_index: 0,
        seq: 0,
    }; SEGMENT_STARTS];
    s.seg_starts_len = 0;
    s.last_req_index = 0;
    s.truncate_failures = 0;
    s.trunc_ack_pending = false;
    s.trunc_ack_index = 0;
    s.trunc_ack_req = 0;
    s.trunc_ack_durable = false;
    s.retire_active = false;
    s.retire_from = 0;
    s.retire_through = 0;
    s.retire_partial = false;
    s.retire_fd = -1;
    s.retire_seq = 0;
    s.retire_cursor = 0;
    s.retire_high_water = 0;
    s.retire_fresh = false;
    s.retire_keep_index = 0;
    s.retire_keep_term = 0;
    s.retire_req = 0;
    s.replay_complete_pending = true;
    s.replay_emit_attempts = 0;
    s.last_replay_emit_ms = 0;
    s.fsync_mode = 0;
    s.group_window_ms = 2;
    s.group_max_pending = 64;
    s.root_path = 0;
    s.skip_replay = 0;
    s.fixed_segment = 0;
    s.preallocate_unsupported = false;
    s.preallocate_errno = 0;
    s.preallocate_failures = 0;
    // One CAPS read fills `fs_unlink_probe`, `name_fence_probe` and
    // `fs_async` together, so the two dispositions must start unprobed
    // in step (`ensure_fs_caps` gates on `fs_unlink_probe`).
    s.fs_unlink_probe = 0;
    s.name_fence_probe = NAME_FENCE_UNPROBED;
    s.name_fence = NAME_FENCE_AUTO;
    s.name_unfenced = 0;
    s.name_fence_refused = false;
    s.name_fence_absent_logged = false;
    s.name_fence_fail_logged = false;
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
    s.entryreq_open_fail = 0;
    s.serve_fd = -1;
    s.serve_seg = 0;
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
    s.scan_for_truncate = false;
    s.trunc_locating = false;
    s.trunc_locate_keep = 0;
    s.trunc_locate_req = 0;
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
    s.replay_start_persisted = 0;
    s.replay_first_index = 0;
    s.entry_ring = [EntryLoc::zero(); ENTRY_LOC_RING_SIZE];
    s.memory_entries = [MemoryEntry::zero(); MEMORY_RING_SIZE];
    s.entryreq_floor_logged = false;
    s.replay_recovered_index = 0;
    s.replay_recovered_term = 0;
    s.replay_ledger_seeded = false;
    s.ledger_ack = (0, 0);
    s.ledger_dirty = false;
    s.snap_trigger = (0, 0);
    s.snap_trigger_dirty = false;
    wal_seal::init(&mut s.seal);
    s.cfg = wire::NO_CFG_TRACK;
    s.cfg_dirty = false;
    s.seal_frame = [0; SEALED_FRAME_MAX];
    s.sync_pending = false;
    s.sync_start_us = 0;
    s.flush_moved = 0;
    s.rotating = false;
    s.open_phase = OPEN_IDLE;
    s.open_fd = -1;
    s.open_moved = 0;
    s.open_rc = 1;
    s.dir_unfenced = false;
    s.tc_active = false;
    s.tc_phase = TC_SEEK;
    s.tc_moved = 0;
    s.tc_cursor = 0;
    s.tc_keep = 0;
    s.tc_term = 0;
    s.tc_req = 0;
    s.retire_prep = PREP_DONE;
    s.retire_moved = 0;
    s.rm_seq = 0;
    s.rm_phase = RM_START;
    s.rm_fd = -1;
    s.rm_moved = 0;
    s.rm_unlinked = false;
    s.rm_taken = false;
    s.cp_phase = CP_UNLINK;
    s.cp_taken = false;
    s.sc_phase = SC_IDLE;
    s.sc_fd = -1;
    s.sc_moved = 0;
    s.sc_floor = 0;
    s.sc_start = 0;
    s.floor_wanted = 0;
    s.start_wanted = 0;
    s.floor_rd_fd = -1;
    s.floor_rd_got = 0;
    s.floor_rd_buf = [0; 8];
    s.replay_sized = false;
    s.replay_got = 0;
    s.replay_hdr = [0; 8];
    s.scan_sized = false;
    s.scan_got = 0;
    s.scan_hdr = [0; 24];
    s.dlv_seeked = false;
    s.dlv_got = 0;
    s.sv_active = false;
    s.sv_phase = SV_OPEN;
    s.sv_sealed = false;
    s.sv_own = false;
    s.sv_fd = -1;
    s.sv_request_id = 0;
    s.sv_index = 0;
    s.sv_chan = -1;
    s.sv_loc = EntryLoc::zero();
    s.sv_got = 0;
    s.sv_cold = false;
    s.serve_buf = [0; SEALED_FRAME_MAX];
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
/// pump (≤8 records), ≤4 control frames — at most one of which
/// truncates, since a truncation leaving an ack or a segment range
/// outstanding ends the drain — ≤8 gap-refetch serves, plus at most
/// one cold segment open (which in dir mode may add a one-shot
/// `FS_MKDIR` and a single retried open before it concludes
/// anything). Physical segment removal, whether from compaction or
/// from a truncation's retirement, is paced at
/// `COMPACT_UNLINKS_PER_STEP` files per step; a step that removed any
/// returns Burst, since each removal is a synchronous unlink plus a
/// directory fence.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
#[inline(always)]
pub unsafe fn step(s: &mut Wal, sys: &SyscallTable) -> i32 {
    s.dbg_steps = s.dbg_steps.wrapping_add(1);

    // A sealed WAL reads nothing and writes nothing until its allocator
    // state and current master are in hand — and nothing ever again once
    // it has failed closed.
    if wal_seal::enabled(s) {
        if let Some(rc) = wal_seal::boot_step(s, sys) {
            emit_metrics(s, sys);
            return rc;
        }
    }

    if s.phase == PHASE_REPLAY {
        // Replay existing WAL segments before accepting new entries.
        return step_replay(s, sys);
    }

    // A truncation mid-retirement owns the write state: its descriptor
    // and segment sequence are parked in the `retire_*` fields and
    // `s.fd` is withheld, so opening a segment here would create a fresh
    // file at a sequence the retirement is about to remove and append to
    // it at a cursor that belongs to another file. Drive the retirement
    // and nothing else until the discarded range is inert.
    if s.retire_active {
        let worked = continue_retirement(s, sys);
        flush_truncate_ack(s, sys);
        emit_metrics(s, sys);
        return if worked { STEP_BURST } else { 0 };
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
        // A flush already under way — a write part-accepted, a fence or an
        // fsync awaiting its decision — is resumed every step, not when
        // the group window next comes round.
        if flush_in_flight(s) || now.wrapping_sub(s.batch_start_ms) >= s.group_window_ms as u64 {
            flush_batch(s, sys);
        }
    }
    // Rotate a full segment once it is quiescent, independent of an
    // append. The append path checks the limit only right after it
    // appended, while the batch it just staged is still outstanding, and
    // on a device whose flushes are asynchronous that is always the case:
    // the check never fires, the segment grows without bound, and the
    // snapshot a rotation triggers never lands. Quiescent means nothing
    // in flight: no staged batch, no fence awaited, no fence ticket
    // outstanding against this segment (a ticket is valid only on the
    // descriptor that produced it, and only until that descriptor
    // closes). A rotation already under way is resumed.
    if s.rotating || (s.fd >= 0 && s.cursor >= s.segment_limit && quiescent(s)) {
        rotate_segment(s, sys);
    }

    // Normal operation
    // 1. Apply control signals (post-snapshot compaction trim AND Raft
    //    conflict-repair truncation) BEFORE appending. A truncate must
    //    land before any same-step append, else the fresh entry would be
    //    written above the divergent tail and then rewound away.
    let mut retired = drain_compact_before(s, sys);
    if wal_seal::maybe_retire(s, sys) {
        retired = true;
    }

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
        consumed =
            consumed.saturating_add(s.bytes_written.wrapping_sub(before_bytes).saturating_add(8));
        if grant == 0 {
            break;
        }
    }
    s.pump_records = records as u8;
    if records > 0 {
        let effect = if !s.inbox_entries.is_empty() {
            step_effect::RUNNABLE_BACKLOG
        } else {
            step_effect::WORK_DONE
        };
        dev_report_step_effect(sys, effect);
    }

    // 3. Service random-access read-back requests (replicator NACK retry),
    //    then advance the bounded below-floor segment scan (if pending).
    drain_entry_requests(s, sys);
    // Cold reads AFTER replication read-back: a lagging consumer must
    // never delay the path a rebuilding replica depends on.
    drain_cold_reads(s, sys);
    step_entry_scan(s, sys);

    // 4. Emit metrics periodically
    emit_metrics(s, sys);

    // Physical segment removal is synchronous provider work (unlink +
    // directory fence per file), well above a steady-state step even at
    // the paced budget. Burst classifies that interval correctly.
    if retired {
        STEP_BURST
    } else {
        0
    }
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
    if !s.replay_complete_pending {
        return;
    }
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
    if s.replay_emit_attempts > 0 && now.wrapping_sub(s.last_replay_emit_ms) < REPLAY_REEMIT_MS {
        return;
    }
    if !wire_channels::writable(sys, s.out_replay_complete) {
        return;
    }
    let mut buf = [0u8; 16];
    wire::encode_term_index(&mut buf, s.current_term, s.current_index);
    let w = write_part(
        s,
        sys,
        s.out_replay_complete,
        wire::MSG_WAL_REPLAY_COMPLETE,
        &buf,
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

/// Slot for `index` in the retained-body ring (`memory_entries`).
///
/// On a volatile build this is the usual power-of-two mask over
/// `VOLATILE_RETENTION_SLOTS`. On a disk build the ring is one
/// slot and the mask is 0, so every index aliases to it — sound because
/// nothing populates that slot on a disk build (`no_fs`, the only write
/// path's gate, is never set), leaving the alias to name a permanently
/// empty entry that no lookup can match.
#[inline]
fn memory_slot(index: u64) -> usize {
    (index & MEMORY_RING_MASK) as usize
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// An entry the log has taken at `index`, its `[term][index][body]` at
/// `msg_buf[from..from + len]`: a config entry moves the configuration.
fn note_config(s: &mut Wal, index: u64, from: usize, len: usize) {
    let Some(src) = s.msg_buf.get(from + 16..from + len) else {
        return;
    };
    if !wire::has_config_change_magic(src) {
        return;
    }
    let mut body = [0u8; wire::CONFIG_CHANGE_HDR + wire::MEMBERSHIP_IDS as usize];
    let n = src.len().min(body.len());
    body[..n].copy_from_slice(&src[..n]);
    s.cfg.note(index, &body[..n]);
    s.cfg_dirty = true;
}

/// The configuration is `m` as of `index` (the group's initial one, at
/// index 0).
pub fn set_membership(s: &mut Wal, index: u64, m: wire::Membership) {
    s.cfg.set(index, m);
    s.cfg_dirty = true;
}

unsafe fn record_entry_loc(
    s: &mut Wal,
    index: u64,
    term: u64,
    seg_seq: u32,
    payload_offset: u32,
    payload_len: u32,
) {
    if index == 0 {
        return;
    }
    note_term_boundary(s, index, term);
    note_segment_start(s, seg_seq, index);
    let slot = (index & ENTRY_LOC_RING_MASK) as usize;
    s.entry_ring[slot] = EntryLoc {
        index,
        term,
        seg_seq,
        payload_offset,
        payload_len,
    };
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

/// The term of the entry at `index`, while the location ring still
/// covers it. The composite resolves a lagging follower's install
/// against this: a manifest shipped at the leader's commit index must
/// carry that entry's term, or the follower's log matching fails at the
/// very next append.
pub fn term_at(s: &Wal, index: u64) -> Option<u64> {
    if index == 0 || index > s.current_index {
        return None;
    }
    if index >= s.entry_ring_min_index && index <= s.entry_ring_max_index {
        let loc = s.entry_ring[(index & ENTRY_LOC_RING_MASK) as usize];
        if loc.index == index {
            return Some(loc.term);
        }
    }
    // Older than the ring: the term of the latest boundary at or below
    // it, if the table reaches back that far.
    let n = s.term_bounds_len as usize;
    let mut i = n;
    while i > 0 {
        i -= 1;
        let b = s.term_bounds[i];
        if b.index <= index {
            return Some(b.term);
        }
    }
    None
}

/// Record `index` as a term boundary when its term differs from the
/// log's last. Entries arrive in index order on both append and replay,
/// so the table stays ascending; a full table lets the oldest go.
fn note_term_boundary(s: &mut Wal, index: u64, term: u64) {
    let n = s.term_bounds_len as usize;
    if n > 0 && s.term_bounds[n - 1].term == term {
        return;
    }
    if n == TERM_BOUNDARIES {
        s.term_bounds.copy_within(1.., 0);
        s.term_bounds[TERM_BOUNDARIES - 1] = TermBoundary { index, term };
        return;
    }
    s.term_bounds[n] = TermBoundary { index, term };
    s.term_bounds_len = (n + 1) as u8;
}

/// Forget boundaries above `keep_through`: a discarded suffix takes its
/// terms with it, and whatever is appended there next records its own.
fn trim_term_boundaries(s: &mut Wal, keep_through: u64) {
    let mut n = s.term_bounds_len as usize;
    while n > 0 && s.term_bounds[n - 1].index > keep_through {
        n -= 1;
    }
    s.term_bounds_len = n as u8;
}

/// Record `index` as the first entry of segment `seq` when the segment
/// differs from the last recorded. Entries arrive in index order, and
/// segment sequences rise with them, so the table stays ascending on
/// both; a full table lets the oldest go. The in-memory posture has no
/// segment files and records nothing.
fn note_segment_start(s: &mut Wal, seq: u32, index: u64) {
    if seq == 0 {
        return;
    }
    let n = s.seg_starts_len as usize;
    if n > 0 && s.seg_starts[n - 1].seq == seq {
        return;
    }
    if n == SEGMENT_STARTS {
        s.seg_starts.copy_within(1.., 0);
        s.seg_starts[SEGMENT_STARTS - 1] = SegmentStart {
            first_index: index,
            seq,
        };
        return;
    }
    s.seg_starts[n] = SegmentStart {
        first_index: index,
        seq,
    };
    s.seg_starts_len = (n + 1) as u8;
}

/// Forget the starts of segments a suffix discard retires: every
/// segment whose first entry is above `keep_through`.
fn trim_segment_starts(s: &mut Wal, keep_through: u64) {
    let mut n = s.seg_starts_len as usize;
    while n > 0 && s.seg_starts[n - 1].first_index > keep_through {
        n -= 1;
    }
    s.seg_starts_len = n as u8;
}

/// The segment a forward walk for `index` starts in: the newest
/// segment that began at or below it, never below the retained floor.
/// An index older than every recorded start walks from the floor.
fn segment_for(s: &Wal, index: u64) -> u32 {
    let mut i = s.seg_starts_len as usize;
    while i > 0 {
        i -= 1;
        let start = s.seg_starts[i];
        if start.first_index <= index {
            return start.seq.max(s.oldest_segment_seq);
        }
    }
    s.oldest_segment_seq
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn lookup_entry_loc(s: &Wal, index: u64) -> Option<EntryLoc> {
    if index == 0 || index > s.entry_ring_max_index {
        return None;
    }
    if index < s.entry_ring_min_index {
        return None;
    }
    let slot = (index & ENTRY_LOC_RING_MASK) as usize;
    let loc = s.entry_ring[slot];
    if loc.index != index {
        return None;
    }
    Some(loc)
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_entry_requests(s: &mut Wal, sys: &SyscallTable) {
    // A read-back still reading its frame is resumed first, and no other
    // request is taken until it has answered: its descriptor and buffer
    // are in use, and a request popped now would have nowhere to wait.
    if s.sv_active {
        continue_serve(s, sys);
        if s.sv_active {
            return;
        }
    }
    if s.in_entry_request < 0 || s.out_entry_reply < 0 {
        return;
    }
    for _ in 0..8 {
        if s.sv_active {
            break;
        }
        let Some((msg_type, plen)) = s.inbox_entry_req.next(sys, &mut s.msg_buf) else {
            break;
        };
        if msg_type != wire::MSG_WAL_ENTRY_REQUEST {
            continue;
        }
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
/// Serve one WAL entry read-back on `reply_chan`.
///
/// `allow_scan` gates the bounded forward segment scan for an index that
/// has aged out of the location ring. Crash recovery refetches the WHOLE
/// log through this path and a NOT_FOUND there permanently wedges the
/// rebuild, so the replication caller passes `true`. The COLD-READ
/// caller passes `false`: a Kafka consumer that cannot be served from
/// the ring is answered NOT_FOUND and falls back to
/// OFFSET_OUT_OF_RANGE, which is exactly today's behaviour — strictly
/// better than putting a client-driven scan on the same machinery the
/// log rebuild depends on.
unsafe fn serve_entry_request_on(
    s: &mut Wal,
    sys: &SyscallTable,
    request_id: u32,
    wal_index: u64,
    reply_chan: i32,
    allow_scan: bool,
) {
    // Dispatched here, above either path's frame: the unsealed serve
    // stages page-sized buffers on the stack that the sealed one does not
    // need, and nesting one inside the other would add them up.
    let Some(loc) = locate_for_serve(s, sys, request_id, wal_index, reply_chan, allow_scan) else {
        return;
    };
    if wal_seal::enabled(s) {
        serve_sealed(s, sys, loc, request_id, wal_index, reply_chan);
    } else {
        serve_clear(s, sys, loc, request_id, wal_index, reply_chan);
    }
}

/// The location of `wal_index` for a read-back on `reply_chan`, or
/// `None` once the request has been answered (NOT_FOUND), handed to the
/// below-floor scan, or left for a retry because the channel is full.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn locate_for_serve(
    s: &mut Wal,
    sys: &SyscallTable,
    request_id: u32,
    wal_index: u64,
    reply_chan: i32,
    allow_scan: bool,
) -> Option<EntryLoc> {
    s.last_req_index = wal_index;
    if reply_chan < 0 || !wire_channels::writable(sys, reply_chan) {
        return None;
    }
    match lookup_entry_loc(s, wal_index) {
        Some(l) => Some(l),
        None => {
            // Below-floor miss: the index aged out of the location ring
            // (see ENTRY_LOC_RING_SIZE) but its record is still in a
            // durable segment unless compaction deleted it. Serve it via
            // the bounded forward segment scan instead of NOT_FOUND —
            // crash recovery refetches the WHOLE log through this path,
            // and a NOT_FOUND there permanently wedges the rebuild
            // (there is no snapshot to fall through to).
            if allow_scan
                && wal_index > 0
                && wal_index < s.entry_ring_min_index
                && wal_index >= s.compact_floor
                && !s.no_fs
                && !VOLATILE
            {
                // No reply yet — the scan answers on a later step; the
                // requester's re-issue throttle covers a dropped attach.
                begin_entry_scan(s, sys, request_id, wal_index);
                return None;
            }
            // NOT_FOUND — reply with header only, empty body. The leader
            // takes this as a signal to fall through to snapshot install.
            s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
            // Truly unservable below-floor index: compacted away (or the
            // in-memory path, which retains nothing older than the body
            // ring). Fail loudly — snapshot install is the only way back.
            if wal_index < s.entry_ring_min_index && !s.entryreq_unservable_logged {
                s.entryreq_unservable_logged = true;
                dev_log(
                    sys,
                    2,
                    b"[wal] entry req unservable (compacted)".as_ptr(),
                    38,
                );
            }
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
            write_part(s, sys, reply_chan, wire::MSG_WAL_ENTRY_REPLY, &hdr);
            None
        }
    }
}

/// The unsealed read-back of an entry located at `loc`.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn serve_clear(
    s: &mut Wal,
    sys: &SyscallTable,
    loc: EntryLoc,
    request_id: u32,
    wal_index: u64,
    reply_chan: i32,
) {
    if s.no_fs {
        let slot = memory_slot(wal_index);
        let mem = s.memory_entries[slot];
        if mem.index != wal_index {
            s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
            write_part(s, sys, reply_chan, wire::MSG_WAL_ENTRY_REPLY, &hdr);
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
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, loc.term, loc.index, prev_term);
        reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
        reply[wire::WAL_ENTRY_REPLY_HDR..total].copy_from_slice(&mem.body[..body_len]);
        write_part(
            s,
            sys,
            reply_chan,
            wire::MSG_WAL_ENTRY_REPLY,
            &reply[..total],
        );
        s.entryreq_served = s.entryreq_served.saturating_add(1);
        return;
    }

    // Read the entry body from disk and pass the whole payload back so
    // the replicator can reconstruct an AE. A WAL payload is
    // `[term:u64][index:u64][body]` capped at `wal_frame::MAX_ENTRY_LEN`,
    // so both buffers clear it comfortably.
    let payload_len = loc.payload_len as usize;
    // The reply is `WAL_ENTRY_REPLY_HDR + (payload_len - 16)` bytes and
    // is staged in a 4096-byte buffer, so bound the payload by what the
    // REPLY can hold — the slice write has no panic path to fall back on.
    // Bound by the frame contract, not by the staging buffer. The reply
    // buffer is 4096, so a buffer-derived bound
    // would admit payloads up to 4084 — past `wal_frame::MAX_ENTRY_LEN`
    // (2064, what the write path can produce and what replay accepts)
    // and past what the `entry_reply` port's `max_record` (2079 =
    // envelope + reply header + `MAX_ENTRY_BODY`) can carry. A payload
    // in that range builds a well-formed reply that `channel_write_msg`
    // then refuses, which drops the refetch silently and stalls the
    // requester until its retry throttle re-asks. Rejecting here makes
    // it a counted NOT_FOUND that escalates to snapshot install.
    let payload_max = wal_frame::MAX_ENTRY_LEN.min(SEALED_FRAME_MAX - FRAME_HDR as usize);
    if payload_len < 16 || payload_len > payload_max {
        // Defensive: shouldn't happen given the write-path payload cap.
        s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
        write_part(s, sys, reply_chan, wire::MSG_WAL_ENTRY_REPLY, &hdr);
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
                write_part(s, sys, reply_chan, wire::MSG_WAL_ENTRY_REPLY, &hdr);
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
            write_part(
                s,
                sys,
                reply_chan,
                wire::MSG_WAL_ENTRY_REPLY,
                &reply[..total],
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

    // A serve reads through a fd of its own, the live segment included.
    // Reading through the writer's fd seeks it across its own write-back
    // sector, and a frame's trailing bytes can then be read before they
    // land. A sealed segment's fd is kept for the next serve; the live
    // segment's is opened and closed per serve. The open, seek and read
    // are resumed across steps (`continue_serve`) until they answer.
    begin_serve(s, sys, loc, request_id, wal_index, reply_chan, false);
}

/// Start the one read-back serve: the frame of `loc` read through its
/// own descriptor and answered on `chan` once whole.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn begin_serve(
    s: &mut Wal,
    sys: &SyscallTable,
    loc: EntryLoc,
    request_id: u32,
    wal_index: u64,
    chan: i32,
    sealed_frame: bool,
) {
    s.sv_active = true;
    s.sv_phase = SV_OPEN;
    s.sv_sealed = sealed_frame;
    s.sv_own = false;
    s.sv_fd = -1;
    s.sv_request_id = request_id;
    s.sv_index = wal_index;
    s.sv_chan = chan;
    s.sv_loc = loc;
    s.sv_got = 0;
    s.sv_cold = false;
    continue_serve(s, sys);
}

/// End the serve: close its per-serve descriptor and free the slot.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn end_serve(s: &mut Wal, sys: &SyscallTable) {
    if s.sv_own && s.sv_fd >= 0 {
        (sys.provider_call)(s.sv_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    }
    s.sv_fd = -1;
    s.sv_own = false;
    s.sv_active = false;
    s.sv_cold = false;
}

/// The serve could not be had: answer NOT_FOUND (the requester escalates
/// to snapshot install) and free the slot.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn serve_not_found(s: &mut Wal, sys: &SyscallTable) {
    let cold = s.sv_cold;
    let (id, idx, chan) = (s.sv_request_id, s.sv_index, s.sv_chan);
    end_serve(s, sys);
    reply_not_found(s, sys, id, idx, chan);
    if cold {
        s.cold_notfound = s.cold_notfound.wrapping_add(1);
    }
}

/// Resume the read-back serve: open (or reuse) the segment's read
/// descriptor, seek to the frame, read it whole into `serve_buf` across as
/// many steps as the provider needs, then verify and answer. An `EAGAIN`
/// or a short read is never a NOT_FOUND: the serve waits for the bytes.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn continue_serve(s: &mut Wal, sys: &SyscallTable) {
    if !s.sv_active {
        return;
    }
    let loc = s.sv_loc;
    let (lead, flen) = if s.sv_sealed {
        (
            sealed::WAL_HDR_LEN as u32,
            sealed::wal_frame_len(loc.payload_len as usize),
        )
    } else {
        (FRAME_HDR, FRAME_HDR as usize + loc.payload_len as usize)
    };
    if flen > SEALED_FRAME_MAX {
        serve_not_found(s, sys);
        return;
    }
    if s.sv_phase == SV_OPEN {
        let sealed_seg = loc.seg_seq != s.segment_seq;
        if sealed_seg && s.serve_fd >= 0 && s.serve_seg == loc.seg_seq {
            s.sv_fd = s.serve_fd;
            s.sv_own = false;
        } else {
            if s.serve_fd >= 0 {
                (sys.provider_call)(s.serve_fd, FS_CLOSE, core::ptr::null_mut(), 0);
                s.serve_fd = -1;
            }
            let mut path = [0u8; WAL_PATH_MAX];
            let plen =
                encode_segment_path(s.partition_id, loc.seg_seq, s.root_path != 0, &mut path);
            let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
            if later(fd) {
                return; // the open is asked again next step
            }
            if fd < 0 {
                s.entryreq_open_fail = s.entryreq_open_fail.saturating_add(1);
                // The first few: which segment, and the provider's answer.
                if s.entryreq_open_fail <= 3 {
                    let mut line = [0u8; 120];
                    let mut p = 0usize;
                    p += emit_field(
                        line.as_mut_ptr(),
                        p,
                        b"[wal] serve open FAIL idx=",
                        s.sv_index as u32,
                    );
                    p += emit_field(line.as_mut_ptr(), p, b" seg=", loc.seg_seq);
                    p += emit_field(line.as_mut_ptr(), p, b" rc=-", fd.unsigned_abs());
                    p += emit_field(line.as_mut_ptr(), p, b" live_seg=", s.segment_seq);
                    p += emit_field(line.as_mut_ptr(), p, b" oldest=", s.oldest_segment_seq);
                    dev_log(sys, 2, line.as_ptr(), p);
                }
                serve_not_found(s, sys);
                return;
            }
            if sealed_seg {
                s.serve_fd = fd;
                s.serve_seg = loc.seg_seq;
                s.sv_own = false;
            } else {
                s.sv_own = true;
            }
            s.sv_fd = fd;
        }
        s.sv_phase = SV_SEEK;
    }
    if s.sv_phase == SV_SEEK {
        let off = loc.payload_offset.saturating_sub(lead);
        let seek_arg = (off as i32).to_le_bytes();
        let rc = (sys.provider_call)(s.sv_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4);
        if later(rc) {
            return;
        }
        if rc < 0 {
            serve_not_found(s, sys);
            return;
        }
        s.sv_got = 0;
        s.sv_phase = SV_READ;
    }
    if s.sv_phase == SV_READ {
        let mut got = s.sv_got as usize;
        let io = fs_step::read_into(
            sys.provider_call,
            s.sv_fd,
            s.serve_buf.as_mut_ptr(),
            flen,
            &mut got,
        );
        s.sv_got = got as u32;
        match io {
            Io::Later => return,
            Io::Done => s.sv_phase = SV_REPLY,
            Io::End | Io::Fail(_) => {
                serve_not_found(s, sys);
                return;
            }
        }
    }
    // SV_REPLY: the frame is whole. Held until the reply channel can
    // take it.
    let chan = s.sv_chan;
    if chan < 0 || !wire_channels::writable(sys, chan) {
        return;
    }
    if s.sv_own && s.sv_fd >= 0 {
        (sys.provider_call)(s.sv_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.sv_fd = -1;
        s.sv_own = false;
    }
    let before = s.entryreq_served;
    let cold = s.sv_cold;
    if s.sv_sealed {
        let prev_term = if loc.index > 1 {
            lookup_entry_loc(s, loc.index - 1).map_or(0, |p| p.term)
        } else {
            0
        };
        if open_for_serve(s, sys, &loc, flen, false) {
            send_sealed_reply(s, sys, &loc, s.sv_request_id, prev_term, chan, false);
            s.entryreq_served = s.entryreq_served.saturating_add(1);
        } else {
            reply_not_found(s, sys, s.sv_request_id, s.sv_index, chan);
        }
    } else {
        reply_clear_frame(s, sys, &loc, s.sv_request_id, s.sv_index, chan);
    }
    end_serve(s, sys);
    if cold {
        if s.entryreq_served != before {
            s.cold_served = s.cold_served.wrapping_add(1);
        } else {
            s.cold_notfound = s.cold_notfound.wrapping_add(1);
        }
    }
}

/// Verify an unsealed frame read whole into `serve_buf` (header, then
/// payload) and answer with it. Read-back feeds followers, so the stored
/// CRC32C is re-verified before shipping: an unchecked corrupt sector
/// propagates cluster-wide as a valid entry.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn reply_clear_frame(
    s: &mut Wal,
    sys: &SyscallTable,
    loc: &EntryLoc,
    request_id: u32,
    wal_index: u64,
    reply_chan: i32,
) {
    let payload_len = loc.payload_len as usize;
    let hdr_len = FRAME_HDR as usize;
    let mut frame_hdr = [0u8; FRAME_HDR as usize];
    frame_hdr.copy_from_slice(&s.serve_buf[..FRAME_HDR as usize]);
    let (entry_len32, stored_crc) = wal_frame::parse_header(&frame_hdr);
    let Some(body) = s.serve_buf.get(hdr_len..hdr_len + payload_len) else {
        reply_not_found(s, sys, request_id, wal_index, reply_chan);
        return;
    };
    let actual_crc = {
        let mut c = Crc32c::new();
        c.update(body);
        c.finalize()
    };
    if entry_len32 as usize != payload_len || actual_crc != stored_crc {
        s.checksum_failures = s.checksum_failures.saturating_add(1);
        dev_log(sys, 2, b"[wal] serve CRC FAIL".as_ptr(), 20);
        // The first few, in detail: what was asked, what the frame
        // header said, and what the bytes hashed to.
        if s.checksum_failures <= 3 {
            let mut line = [0u8; 160];
            let mut p = 0usize;
            p += emit_field(
                line.as_mut_ptr(),
                p,
                b"[wal] serve detail idx=",
                wal_index as u32,
            );
            p += emit_field(line.as_mut_ptr(), p, b" seg=", loc.seg_seq);
            p += emit_field(
                line.as_mut_ptr(),
                p,
                b" off=",
                loc.payload_offset.saturating_sub(FRAME_HDR),
            );
            p += emit_field(line.as_mut_ptr(), p, b" want=", payload_len as u32);
            p += emit_field(line.as_mut_ptr(), p, b" hdr_len=", entry_len32);
            p += emit_field(line.as_mut_ptr(), p, b" crc_stored=", stored_crc);
            p += emit_field(line.as_mut_ptr(), p, b" crc_read=", actual_crc);
            p += emit_field(line.as_mut_ptr(), p, b" cur=", s.cursor);
            dev_log(sys, 2, line.as_ptr(), p);
        }
        reply_not_found(s, sys, request_id, wal_index, reply_chan);
        return;
    }

    // Body is [term:u64][index:u64][rest...]; strip the 16-byte header
    // when forming the reply so the wire format matches the doc-comment
    // on MSG_WAL_ENTRY_REPLY (`[request_id][term][index][body...]`).
    let rest_len = payload_len.saturating_sub(16);
    let total = wire::WAL_ENTRY_REPLY_HDR + rest_len;
    let mut reply = [0u8; 4096];
    if total > reply.len() {
        reply_not_found(s, sys, request_id, wal_index, reply_chan);
        return;
    }
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
    if rest_len > 0 {
        // copy_nonoverlapping: the lengths are equal by construction but
        // not provably so to rustc, and a PIC module carries no panic path.
        core::ptr::copy_nonoverlapping(
            s.serve_buf.as_ptr().add(hdr_len + 16),
            reply.as_mut_ptr().add(wire::WAL_ENTRY_REPLY_HDR),
            rest_len,
        );
    }
    write_part(
        s,
        sys,
        reply_chan,
        wire::MSG_WAL_ENTRY_REPLY,
        &reply[..total],
    );
    s.entryreq_served = s.entryreq_served.saturating_add(1);
}

/// Drain cold-read requests. Same wire shape as the replication
/// read-back, its own channels, and NO forward segment scan — an index
/// the location ring has forgotten is answered NOT_FOUND and the caller
/// falls back to the error it would have returned anyway.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn drain_cold_reads(s: &mut Wal, sys: &SyscallTable) {
    if s.in_cold_read < 0 || s.out_cold_reply < 0 {
        return;
    }
    if s.sv_active {
        continue_serve(s, sys);
        if s.sv_active {
            return;
        }
    }
    // Bounded per step, like every other drain here: a consumer that has
    // fallen a long way behind must not be able to spend the whole tick.
    for _ in 0..4 {
        if s.sv_active {
            break;
        }
        // Pre-routed by the intake demux: only this partition's requests.
        let Some((msg_type, plen)) = s.inbox_cold_read.next(sys, &mut s.msg_buf) else {
            break;
        };
        if msg_type != wire::MSG_WAL_ENTRY_REQUEST {
            continue;
        }
        let Some((request_id, wal_index)) =
            wire::decode_wal_entry_request(&s.msg_buf[..plen as usize])
        else {
            continue;
        };
        let before = s.entryreq_served;
        serve_entry_request_on(s, sys, request_id, wal_index, s.out_cold_reply, false);
        if s.sv_active {
            // Still reading its frame: counted when it answers.
            s.sv_cold = true;
            break;
        }
        if s.entryreq_served != before {
            s.cold_served = s.cold_served.wrapping_add(1);
        } else {
            s.cold_notfound = s.cold_notfound.wrapping_add(1);
        }
    }
}

/// Replication read-back: the original entry-request path, unchanged.
unsafe fn serve_entry_request(s: &mut Wal, sys: &SyscallTable, request_id: u32, wal_index: u64) {
    serve_entry_request_on(s, sys, request_id, wal_index, s.out_entry_reply, true);
}

/// Header-only NOT_FOUND reply: the requester escalates to snapshot
/// install.
///
/// # Safety
/// Caller must supply a valid `&SyscallTable` per the module ABI.
#[inline(never)]
unsafe fn reply_not_found(
    s: &mut Wal,
    sys: &SyscallTable,
    request_id: u32,
    wal_index: u64,
    chan: i32,
) {
    s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
    let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
    wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
    write_part(s, sys, chan, wire::MSG_WAL_ENTRY_REPLY, &hdr);
}

/// Copy the whole stored frame of `loc` into `serve_buf` from the staged
/// batch, when it has not reached the device yet. Returns the frame's
/// stored length, `Some(0)` when the frame is on the device (the serve
/// reads it from there), or `None` when it cannot be had.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn staged_sealed_frame(s: &mut Wal, loc: &EntryLoc) -> Option<usize> {
    let c = loc.payload_len as usize;
    let flen = sealed::wal_frame_len(c);
    if c > wal_frame::MAX_ENTRY_LEN || flen > SEALED_FRAME_MAX {
        return None;
    }
    let frame_start = loc.payload_offset.checked_sub(sealed::WAL_HDR_LEN as u32)?;
    let staged_logical =
        (s.write_pos as usize).saturating_sub(if s.staged_terminator { 4 } else { 0 });
    if loc.seg_seq == s.segment_seq && staged_logical > 0 {
        let batch_start = s.cursor.saturating_sub(staged_logical as u32);
        if frame_start >= batch_start {
            let off = (frame_start - batch_start) as usize;
            if off + flen > staged_logical {
                return None;
            }
            core::ptr::copy_nonoverlapping(
                s.write_buf.as_ptr().add(off),
                s.serve_buf.as_mut_ptr(),
                flen,
            );
            return Some(flen);
        }
    }
    Some(0)
}

/// Authenticate a stored frame in place — the serve's (`serve_buf`) or
/// the scan's (`seal_frame`, when `scan`). Only a frame whose tag
/// verifies is served: read-back feeds followers, and a replica must not
/// ship what it cannot vouch for.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn open_for_serve(
    s: &mut Wal,
    sys: &SyscallTable,
    loc: &EntryLoc,
    flen: usize,
    scan: bool,
) -> bool {
    let who = wal_seal::who(s);
    let Some(frame) = (if scan {
        s.seal_frame.get_mut(..flen)
    } else {
        s.serve_buf.get_mut(..flen)
    }) else {
        return false;
    };
    let opened = wal_seal::open_stored(&mut s.seal, who, sys, loc.seg_seq, frame);
    let c = loc.payload_len as usize;
    match opened {
        wal_seal::Opened::Ok { ct_len } if ct_len as usize == c && c >= 16 => true,
        other => {
            wal_seal::serve_verdict(s, sys, other);
            false
        }
    }
}

/// Send the entry opened in place (`serve_buf`, or `seal_frame` when
/// `scan`) as a read-back reply. The reply is composed in place: its
/// header overwrites the frame header and the term/index prologue just
/// ahead of the entry body, so no second page-sized buffer sits on this
/// path's stack.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
#[inline(never)]
unsafe fn send_sealed_reply(
    s: &mut Wal,
    sys: &SyscallTable,
    loc: &EntryLoc,
    request_id: u32,
    prev_term: u64,
    chan: i32,
    scan: bool,
) {
    let body = sealed::WAL_HDR_LEN + 16;
    let start = body - wire::WAL_ENTRY_REPLY_HDR;
    let end = sealed::WAL_HDR_LEN + loc.payload_len as usize;
    let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
    wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, loc.term, loc.index, prev_term);
    let buf: &mut [u8; SEALED_FRAME_MAX] = if scan {
        &mut s.seal_frame
    } else {
        &mut s.serve_buf
    };
    buf[start..body].copy_from_slice(&hdr);
    let Some(msg) = buf.get(start..end) else {
        return;
    };
    wire_channels::channel_write_partitioned(
        sys,
        chan,
        s.partition_id,
        wire::MSG_WAL_ENTRY_REPLY,
        msg,
    );
}

/// The sealed twin of the ring-served read-back.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn serve_sealed(
    s: &mut Wal,
    sys: &SyscallTable,
    loc: EntryLoc,
    request_id: u32,
    wal_index: u64,
    reply_chan: i32,
) {
    let staged = loc.seg_seq == s.segment_seq
        && s.write_pos > 0
        && loc.payload_offset
            >= s.cursor.saturating_sub(
                (s.write_pos as u32).saturating_sub(if s.staged_terminator { 4 } else { 0 }),
            );
    // As unsealed: a written-but-unfenced frame reads back undefined
    // until its fence lands; the requester's retry throttle re-asks.
    if !staged && loc.seg_seq == s.segment_seq && wal_index > s.ledger_ack.1 {
        return;
    }
    match staged_sealed_frame(s, &loc) {
        None => reply_not_found(s, sys, request_id, wal_index, reply_chan),
        // On the device: read it through the serve's own descriptor.
        Some(0) => begin_serve(s, sys, loc, request_id, wal_index, reply_chan, true),
        Some(flen) => {
            let prev_term = if loc.index > 1 {
                lookup_entry_loc(s, loc.index - 1).map_or(0, |p| p.term)
            } else {
                0
            };
            if open_for_serve(s, sys, &loc, flen, false) {
                send_sealed_reply(s, sys, &loc, request_id, prev_term, reply_chan, false);
                s.entryreq_served = s.entryreq_served.saturating_add(1);
            } else {
                reply_not_found(s, sys, request_id, wal_index, reply_chan);
            }
        }
    }
}

/// Close the scan's segment and move the cursor to the next one.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn scan_next_segment(s: &mut Wal, sys: &SyscallTable) {
    if s.scan_fd >= 0 {
        (sys.provider_call)(s.scan_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    }
    s.scan_fd = -1;
    s.scan_sized = false;
    s.scan_got = 0;
    s.scan_seg = s.scan_seg.saturating_add(1);
}

/// The sealed twin of the scan's frame walk: a sealed frame keeps term
/// and index inside its ciphertext, so each record is read whole and
/// authenticated before its index can be believed. A record the
/// provider has part-delivered is resumed at `scan_got` next step.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn scan_sealed_records(s: &mut Wal, sys: &SyscallTable) {
    let mut records = 0usize;
    while records < SCAN_RECORDS_PER_STEP {
        let remaining = s.scan_file_size.saturating_sub(s.scan_pos) as usize;
        if s.scan_got == 0 {
            if remaining < sealed::WAL_PREFIX_LEN {
                scan_next_segment(s, sys);
                return;
            }
            let seek = (s.scan_pos as i32).to_le_bytes();
            let rc = (sys.provider_call)(s.scan_fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
            if later(rc) {
                return;
            }
            if rc < 0 {
                fail_entry_scan(s, sys);
                reset_scan_cursor(s, sys);
                return;
            }
        }
        if (s.scan_got as usize) < sealed::WAL_PREFIX_LEN {
            let mut got = s.scan_got as usize;
            let io = fs_step::read_into(
                sys.provider_call,
                s.scan_fd,
                s.seal_frame.as_mut_ptr(),
                sealed::WAL_PREFIX_LEN,
                &mut got,
            );
            s.scan_got = got as u32;
            match io {
                Io::Later => return,
                Io::Done => {}
                Io::End | Io::Fail(_) => {
                    scan_next_segment(s, sys);
                    return;
                }
            }
        }
        let frame_len = match sealed::wal_parse_prefix(
            &s.seal_frame[..sealed::WAL_PREFIX_LEN],
            wal_frame::MAX_ENTRY_LEN,
        ) {
            sealed::WalPrefix::Frame { frame_len } => frame_len as usize,
            _ => {
                scan_next_segment(s, sys);
                return;
            }
        };
        let flen = sealed::WAL_PREFIX_LEN + frame_len;
        if frame_len > remaining.saturating_sub(sealed::WAL_PREFIX_LEN) || flen > SEALED_FRAME_MAX {
            scan_next_segment(s, sys);
            return;
        }
        let mut got = s.scan_got as usize;
        let io = fs_step::read_into(
            sys.provider_call,
            s.scan_fd,
            s.seal_frame.as_mut_ptr(),
            flen,
            &mut got,
        );
        s.scan_got = got as u32;
        match io {
            Io::Later => return,
            Io::Done => {}
            Io::End | Io::Fail(_) => {
                fail_entry_scan(s, sys);
                reset_scan_cursor(s, sys);
                return;
            }
        }
        s.scan_got = 0;
        let who = wal_seal::who(s);
        let seg = s.scan_seg;
        let opened = wal_seal::open_stored(&mut s.seal, who, sys, seg, &mut s.seal_frame[..flen]);
        let ct_len = match opened {
            wal_seal::Opened::Ok { ct_len } if ct_len >= 16 => ct_len,
            wal_seal::Opened::Torn => {
                // Same stop rule as replay: the segment's live data ends.
                s.checksum_failures = s.checksum_failures.saturating_add(1);
                scan_next_segment(s, sys);
                return;
            }
            other => {
                wal_seal::serve_verdict(s, sys, other);
                fail_entry_scan(s, sys);
                reset_scan_cursor(s, sys);
                return;
            }
        };
        let Some((term, index)) =
            wire::decode_term_index(&s.seal_frame[sealed::WAL_HDR_LEN..sealed::WAL_HDR_LEN + 16])
        else {
            fail_entry_scan(s, sys);
            reset_scan_cursor(s, sys);
            return;
        };
        let payload_offset = s.scan_pos + sealed::WAL_HDR_LEN as u32;
        if index == s.scan_target {
            s.scan_loc = EntryLoc {
                index,
                term,
                seg_seq: s.scan_seg,
                payload_offset,
                payload_len: ct_len,
            };
            // Delivered by the caller once this walk's frame is gone.
            s.scan_found = true;
            s.scan_active = false;
            s.dlv_seeked = false;
            s.dlv_got = 0;
            return;
        }
        if index > s.scan_target {
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
        s.scan_pos += flen as u32;
        records += 1;
    }
}

/// Seek to and read the scan-located frame (`want` bytes from `at`) into
/// `seal_frame`, resumably. `Io::Done` once it is whole.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn read_located(s: &mut Wal, sys: &SyscallTable, at: u32, want: usize) -> Io {
    if s.scan_fd < 0 || want > SEALED_FRAME_MAX {
        return Io::Fail(-1);
    }
    if !s.dlv_seeked {
        let seek = (at as i32).to_le_bytes();
        let rc = (sys.provider_call)(s.scan_fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
        if later(rc) {
            return Io::Later;
        }
        if rc < 0 {
            return Io::Fail(rc);
        }
        s.dlv_seeked = true;
        s.dlv_got = 0;
    }
    let mut got = s.dlv_got as usize;
    let io = fs_step::read_into(
        sys.provider_call,
        s.scan_fd,
        s.seal_frame.as_mut_ptr(),
        want,
        &mut got,
    );
    s.dlv_got = got as u32;
    io
}

/// The sealed twin of `deliver_scan_reply`'s read and verify.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn deliver_scan_reply_sealed(s: &mut Wal, sys: &SyscallTable) {
    if !s.scan_found {
        return;
    }
    if s.out_entry_reply < 0 {
        s.scan_found = false;
        s.scan_target = 0;
        return;
    }
    if !wire_channels::writable(sys, s.out_entry_reply) {
        return;
    }
    let loc = s.scan_loc;
    let c = loc.payload_len as usize;
    let flen = sealed::wal_frame_len(c);
    let frame_start = loc
        .payload_offset
        .saturating_sub(sealed::WAL_HDR_LEN as u32);
    let io = if c <= wal_frame::MAX_ENTRY_LEN {
        read_located(s, sys, frame_start, flen)
    } else {
        Io::Fail(-1)
    };
    if io == Io::Later {
        return; // the rest of the frame is read next step
    }
    s.dlv_seeked = false;
    s.dlv_got = 0;
    let sent = io == Io::Done && open_for_serve(s, sys, &loc, flen, true);
    if !sent {
        s.scan_target = loc.index;
        s.scan_found = false;
        s.scan_active = true;
        fail_entry_scan(s, sys);
        reset_scan_cursor(s, sys);
        return;
    }
    let chan = s.out_entry_reply;
    send_sealed_reply(
        s,
        sys,
        &loc,
        s.scan_request_id,
        s.scan_prev_term,
        chan,
        true,
    );
    s.entryreq_served = s.entryreq_served.saturating_add(1);
    s.entryreq_scan_served = s.entryreq_scan_served.saturating_add(1);
    s.scan_found = false;
    s.scan_target = 0;
    s.scan_last_index = loc.index;
    s.scan_last_term = loc.term;
    s.scan_prev_term = 0;
    s.scan_pos = frame_start + flen as u32;
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
        s.scan_seg = segment_for(s, wal_index);
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
        dev_log(
            sys,
            3,
            b"[wal] entry req below floor: seg scan".as_ptr(),
            37,
        );
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
    s.scan_sized = false;
    s.scan_got = 0;
    s.dlv_seeked = false;
    s.dlv_got = 0;
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
    if s.scan_for_truncate {
        // The walk proved the keep point is in no durable segment: the
        // log does not hold the entry the requester keeps, and no
        // rewind point can be guessed.
        s.scan_active = false;
        s.scan_found = false;
        s.scan_target = 0;
        s.scan_for_truncate = false;
        s.trunc_locating = false;
        refuse_truncate_unlocatable(s, sys, s.trunc_locate_keep, s.trunc_locate_req);
        return;
    }
    let request_id = s.scan_request_id;
    let wal_index = s.scan_target;
    s.scan_active = false;
    s.scan_found = false;
    s.scan_target = 0;
    s.entryreq_notfound = s.entryreq_notfound.saturating_add(1);
    if !s.entryreq_unservable_logged {
        s.entryreq_unservable_logged = true;
        dev_log(
            sys,
            2,
            b"[wal] entry req unservable (compacted)".as_ptr(),
            38,
        );
    }
    if wire_channels::writable(sys, s.out_entry_reply) {
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index, 0);
        write_part(s, sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
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
        deliver_scan(s, sys);
        return;
    }
    if !s.scan_active {
        return;
    }

    // Open the segment under the cursor. One provider open per step —
    // a cold open can pay the directory-scan penalty (see step_replay).
    // An open or a size not answered yet is asked again next step; only
    // an answered miss counts against the gap tolerance.
    if s.scan_fd < 0 {
        if s.scan_seg > s.segment_seq {
            // Walked past the live segment without finding the index.
            fail_entry_scan(s, sys);
            return;
        }
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = encode_segment_path(s.partition_id, s.scan_seg, s.root_path != 0, &mut path);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if later(fd) {
            return;
        } // provider initialising, or the directory not cached — retry
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
        s.scan_fd = fd;
        s.scan_sized = false;
        s.scan_got = 0;
    }
    if !s.scan_sized {
        let mut stat_buf = [0u8; 8];
        let stat_rc = (sys.provider_call)(s.scan_fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        if later(stat_rc) {
            return;
        }
        let size = if stat_rc < 0 {
            0
        } else {
            u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
        };
        if size == 0 {
            scan_next_segment(s, sys);
            return;
        }
        s.scan_misses = 0;
        s.scan_sized = true;
        s.scan_file_size = size;
        s.scan_pos = 0;
        s.scan_got = 0;
        return; // bounded: the open was this step's work
    }

    if wal_seal::enabled(s) {
        scan_sealed_records(s, sys);
        if s.scan_found {
            deliver_scan(s, sys);
        }
        return;
    }

    // Walk frames: [entry_len:u32][crc32c:u32][payload], where payload
    // begins [term:u64][index:u64]. Read the 24-byte prefix, then seek
    // past the payload — never read bodies we are only skipping. A
    // prefix the provider has part-delivered is resumed at `scan_got`.
    let mut records = 0usize;
    while records < SCAN_RECORDS_PER_STEP {
        let remaining = s.scan_file_size.saturating_sub(s.scan_pos);
        if s.scan_got == 0 {
            if remaining < FRAME_HDR {
                // Segment exhausted — move to the next one.
                scan_next_segment(s, sys);
                return;
            }
            let seek_arg = (s.scan_pos as i32).to_le_bytes();
            let rc = (sys.provider_call)(s.scan_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4);
            if later(rc) {
                return;
            }
            if rc < 0 {
                fail_entry_scan(s, sys);
                reset_scan_cursor(s, sys);
                return;
            }
        }
        if s.scan_got < FRAME_HDR {
            let mut got = s.scan_got as usize;
            let io = fs_step::read_into(
                sys.provider_call,
                s.scan_fd,
                s.scan_hdr.as_mut_ptr(),
                FRAME_HDR as usize,
                &mut got,
            );
            s.scan_got = got as u32;
            match io {
                Io::Later => return,
                Io::Done => {}
                Io::End | Io::Fail(_) => {
                    scan_next_segment(s, sys);
                    return;
                }
            }
        }
        let mut hdr = [0u8; FRAME_HDR as usize];
        hdr.copy_from_slice(&s.scan_hdr[..FRAME_HDR as usize]);
        let (entry_len, _) = wal_frame::parse_header(&hdr);
        if wal_frame::len_invalid(
            entry_len,
            u64::from(s.scan_file_size.saturating_sub(s.scan_pos + FRAME_HDR)),
        ) {
            // Terminator or torn frame — end of this segment's live data
            // (same stop rule as replay).
            scan_next_segment(s, sys);
            return;
        }
        let payload_offset = s.scan_pos + FRAME_HDR;
        if entry_len >= 16 {
            let mut got = s.scan_got as usize;
            let io = fs_step::read_into(
                sys.provider_call,
                s.scan_fd,
                s.scan_hdr.as_mut_ptr(),
                FRAME_HDR as usize + 16,
                &mut got,
            );
            s.scan_got = got as u32;
            match io {
                Io::Later => return,
                Io::Done => {}
                Io::End | Io::Fail(_) => {
                    fail_entry_scan(s, sys);
                    reset_scan_cursor(s, sys);
                    return;
                }
            }
            let mut ti = [0u8; 16];
            ti.copy_from_slice(&s.scan_hdr[FRAME_HDR as usize..FRAME_HDR as usize + 16]);
            let Some((term, index)) = wire::decode_term_index(&ti) else {
                fail_entry_scan(s, sys);
                reset_scan_cursor(s, sys);
                return;
            };
            if index == s.scan_target {
                s.scan_loc = EntryLoc {
                    index,
                    term,
                    seg_seq: s.scan_seg,
                    payload_offset,
                    payload_len: entry_len,
                };
                s.scan_got = 0;
                s.scan_found = true;
                s.scan_active = false;
                s.dlv_seeked = false;
                s.dlv_got = 0;
                deliver_scan(s, sys);
                return;
            }
            if index > s.scan_target {
                // Passed the slot without finding it: the record is not
                // in the durable log (leading segments compacted away).
                // The cursor stays warm for later, higher targets.
                s.scan_got = 0;
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
        s.scan_got = 0;
        s.scan_pos = payload_offset + entry_len;
        records += 1;
    }
}

/// Deliver a scan-located record's reply by the path that matches the
/// WAL's frames, chosen above either path's frame (see
/// `serve_entry_request_on`).
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn deliver_scan(s: &mut Wal, sys: &SyscallTable) {
    if s.scan_for_truncate {
        // The hit is a keep point; the control drain resumes the
        // truncation with it (see `resume_truncate`).
        return;
    }
    if wal_seal::enabled(s) {
        deliver_scan_reply_sealed(s, sys);
    } else {
        deliver_scan_reply(s, sys);
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
#[inline(never)]
unsafe fn deliver_scan_reply(s: &mut Wal, sys: &SyscallTable) {
    if !s.scan_found {
        return;
    }
    if s.out_entry_reply < 0 {
        s.scan_found = false;
        s.scan_target = 0;
        return;
    }
    if !wire_channels::writable(sys, s.out_entry_reply) {
        return;
    } // retry next step

    let loc = s.scan_loc;
    let payload_len = loc.payload_len as usize;
    let hdr_off = loc.payload_offset.saturating_sub(FRAME_HDR);
    let want = FRAME_HDR as usize + payload_len;
    // Verify the stored CRC32C before shipping — scan-served bytes feed
    // followers just like ring-served ones. The frame (header + payload)
    // is read whole into `seal_frame`, resumed across steps until it is.
    let io = if payload_len > 0 && payload_len <= wal_frame::MAX_ENTRY_LEN {
        read_located(s, sys, hdr_off, want)
    } else {
        Io::Fail(-1)
    };
    if io == Io::Later {
        return;
    }
    s.dlv_seeked = false;
    s.dlv_got = 0;
    let mut ok = io == Io::Done;
    if ok {
        let mut frame_hdr = [0u8; FRAME_HDR as usize];
        frame_hdr.copy_from_slice(&s.seal_frame[..FRAME_HDR as usize]);
        let (entry_len32, stored_crc) = wal_frame::parse_header(&frame_hdr);
        let actual_crc = match s.seal_frame.get(FRAME_HDR as usize..want) {
            Some(body) => {
                let mut c = Crc32c::new();
                c.update(body);
                c.finalize()
            }
            None => !stored_crc,
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
    let rest_len = payload_len.saturating_sub(16);
    let total = wire::WAL_ENTRY_REPLY_HDR + rest_len;
    let mut reply = [0u8; 4096];
    if total > reply.len() {
        return;
    }
    let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
    wire::encode_wal_entry_reply_hdr(
        &mut hdr,
        s.scan_request_id,
        loc.term,
        loc.index,
        s.scan_prev_term,
    );
    reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
    if rest_len > 0 {
        core::ptr::copy_nonoverlapping(
            s.seal_frame.as_ptr().add(FRAME_HDR as usize + 16),
            reply.as_mut_ptr().add(wire::WAL_ENTRY_REPLY_HDR),
            rest_len,
        );
    }
    write_part(
        s,
        sys,
        s.out_entry_reply,
        wire::MSG_WAL_ENTRY_REPLY,
        &reply[..total],
    );
    s.entryreq_served = s.entryreq_served.saturating_add(1);
    s.entryreq_scan_served = s.entryreq_scan_served.saturating_add(1);
    s.scan_found = false;
    s.scan_target = 0;
    // Warm the cursor past the served record for sequential refetches.
    s.scan_last_index = loc.index;
    s.scan_last_term = loc.term;
    s.scan_prev_term = 0;
    s.scan_pos = loc.payload_offset + loc.payload_len + wal_seal::payload_trail(s);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_compact_before(s: &mut Wal, sys: &SyscallTable) -> bool {
    // An ack the output channel could not take is retried before
    // anything else: the requester holds its old tip until it arrives,
    // so a dropped ack is a wedge, not a lost notification.
    flush_truncate_ack(s, sys);
    // Floors before trims: a floor declared this step bounds a trim
    // requested this step.
    drain_retention_floors(s, sys);
    // The floor sidecar's persist is resumed whatever arrives: a replay
    // start a trim asked for is persisted even if no further trim comes.
    sidecar_step(s, sys);
    if s.in_compact_before < 0 {
        return false;
    }
    // A truncation persisting its terminator owns the control channel and
    // the live descriptor: resume it, and drain nothing behind it until
    // it has answered.
    if s.tc_active {
        continue_truncate(s, sys);
        if s.tc_active {
            return false;
        }
    }
    // Control work rewinds or retires segments, so it waits for the live
    // segment to be admitted: an admission still in flight holds its own
    // descriptor that a truncation could not see.
    if s.fd < 0 && !s.no_fs {
        return continue_compaction(s, sys);
    }
    // A truncation parked on the segment walk owns the control channel:
    // nothing behind it is drained, and no compaction retires files the
    // walk may be in, until the walk answers. Its hit resumes the
    // truncation under the same in-flight gate as a fresh request.
    if s.trunc_locating {
        if !(s.scan_found && s.scan_for_truncate) {
            return false;
        }
        if !quiescent(s) {
            flush_batch(s, sys);
            if !quiescent(s) {
                return false;
            }
        }
        return resume_truncate(s, sys);
    }

    // Continue any unlink work a previous compaction left pending
    // (paced COMPACT_UNLINKS_PER_STEP per step).
    let mut retired = continue_compaction(s, sys);

    // A truncate/compaction changes the file cursor and segment topology. Do
    // not let it overtake records that are already accepted into the current
    // durability batch but still live only in `write_buf` — NOR records whose
    // async write/fence is still in flight: a fence completing after a
    // truncation would ack the discarded suffix, and the in-flight write
    // races the rewound region. Wait until the pipeline is empty.
    if wire_channels::readable(sys, s.in_compact_before) && (!quiescent(s) || s.rotating) {
        flush_batch(s, sys);
        if !quiescent(s) || s.rotating {
            return retired;
        }
    }

    for _ in 0..4 {
        let Some((msg_type, plen)) =
            wire_channels::next_msg(sys, s.in_compact_before, &mut s.msg_buf)
        else {
            break;
        };
        if (plen as usize) < 8 {
            continue;
        }
        let index = u64::from_le_bytes([
            s.msg_buf[0],
            s.msg_buf[1],
            s.msg_buf[2],
            s.msg_buf[3],
            s.msg_buf[4],
            s.msg_buf[5],
            s.msg_buf[6],
            s.msg_buf[7],
        ]);
        match msg_type {
            wire::MSG_WAL_COMPACT_BEFORE => compact_before(s, sys, index),
            wire::MSG_COMPACTION_FLOOR => {
                // `[kpg_id:u16][floor:u64]`: consensus's min-match floor
                // for this group. The kpg id is the partition, which is
                // this slot by construction; the value is what matters.
                if (plen as usize) >= 10 {
                    let floor = u64::from_le_bytes([
                        s.msg_buf[2],
                        s.msg_buf[3],
                        s.msg_buf[4],
                        s.msg_buf[5],
                        s.msg_buf[6],
                        s.msg_buf[7],
                        s.msg_buf[8],
                        s.msg_buf[9],
                    ]);
                    s.match_floor = Some(floor);
                }
            }
            wire::MSG_WAL_TRUNCATE_AFTER => {
                let req_id = match wire::decode_wal_truncate_after(&s.msg_buf[..plen as usize]) {
                    Some((_, id)) => id,
                    None => continue,
                };
                if truncate_after(s, sys, index, req_id) {
                    retired = true;
                }
                // One truncation may leave state the next one in this
                // drain would destroy: an ack the channel could not take
                // yet (the park slot holds exactly one answer), a
                // segment range still being retired (whose write state
                // is parked, not published), or a keep point still
                // being located on disk. End the drain and let a later
                // step resume — the frames stay queued.
                if s.trunc_ack_pending || s.retire_active || s.trunc_locating || s.tc_active {
                    break;
                }
            }
            _ => continue,
        }
    }
    retired
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
unsafe fn truncate_after(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_through_index: u64,
    req_id: u32,
) -> bool {
    // Already at or below the keep point. Either there was never
    // anything to discard, or this repeats a truncation that already
    // completed and whose ack was lost. Both are success — re-ack, or
    // the requester holds its old tip forever.
    if s.current_index <= keep_through_index {
        send_truncate_ack(s, sys, keep_through_index, req_id, true);
        return false;
    }

    // Locate the keep point. `keep == 0` discards the whole log (no frame
    // to rewind to). Otherwise the location ring answers while it still
    // covers the keep entry; an entry below the ring is still in a
    // durable segment, and the paced segment walk locates it across
    // steps with the truncation parked on it. A miss anywhere else — a
    // gap inside the ring, an index below the compaction floor, or the
    // in-memory posture, whose ring is its whole retention — means the
    // log does not hold the entry the requester keeps: refuse rather
    // than guess a rewind point, since a wrong one leaves the suffix on
    // disk for replay to resurrect.
    if keep_through_index == 0 {
        return truncate_at(s, sys, 0, 0, 0, keep_through_index, req_id);
    }
    match lookup_entry_loc(s, keep_through_index) {
        Some(loc) => truncate_at(
            s,
            sys,
            loc.seg_seq,
            loc.payload_offset + loc.payload_len + wal_seal::payload_trail(s),
            loc.term,
            keep_through_index,
            req_id,
        ),
        None => {
            if keep_through_index < s.entry_ring_min_index
                && keep_through_index >= s.compact_floor
                && !s.no_fs
                && !VOLATILE
            {
                begin_truncate_locate(s, sys, keep_through_index, req_id);
            } else {
                refuse_truncate_unlocatable(s, sys, keep_through_index, req_id);
            }
            false
        }
    }
}

/// Park a truncation on the segment walk: the keep point has left the
/// location ring, so its frame is located on disk the way a below-floor
/// entry request is. The walk preempts any entry request on it (the
/// requester re-asks), and the control channel is not drained past the
/// truncation until the walk answers. Raft holds its tip meanwhile; the
/// hold is bounded only by the correlated ack, so a long walk delays
/// repair without abandoning it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn begin_truncate_locate(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_through_index: u64,
    req_id: u32,
) {
    s.scan_found = false;
    s.scan_active = false;
    s.scan_target = 0;
    begin_entry_scan(s, sys, req_id, keep_through_index);
    s.scan_for_truncate = true;
    s.trunc_locating = true;
    s.trunc_locate_keep = keep_through_index;
    s.trunc_locate_req = req_id;
    dev_log(sys, 3, b"[wal] truncate locate".as_ptr(), 21);
}

/// Resume a parked truncation with the keep frame the walk located.
/// The walk's descriptor is dropped first: the keep segment is
/// reopened for writing by the truncation itself. Returns whether any
/// segment was retired here.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn resume_truncate(s: &mut Wal, sys: &SyscallTable) -> bool {
    let loc = s.scan_loc;
    let keep_through_index = s.trunc_locate_keep;
    let req_id = s.trunc_locate_req;
    s.scan_found = false;
    s.scan_target = 0;
    s.scan_for_truncate = false;
    s.trunc_locating = false;
    reset_scan_cursor(s, sys);
    if s.current_index <= keep_through_index {
        send_truncate_ack(s, sys, keep_through_index, req_id, true);
        return false;
    }
    truncate_at(
        s,
        sys,
        loc.seg_seq,
        loc.payload_offset + loc.payload_len + wal_seal::payload_trail(s),
        loc.term,
        keep_through_index,
        req_id,
    )
}

/// Refuse a truncation whose keep entry the log does not hold, and
/// latch fail-stop: the requester keeps an entry this log never had,
/// which no rewind point can reconcile.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn refuse_truncate_unlocatable(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_through_index: u64,
    req_id: u32,
) {
    s.fence_failed = true;
    s.write_errors = s.write_errors.saturating_add(1);
    dev_log(sys, 1, b"[wal] FATAL truncate unlocatable".as_ptr(), 32);
    send_truncate_ack(s, sys, keep_through_index, req_id, false);
}

/// Persist and publish a truncation whose keep frame is known: the
/// segment it ends in (`keep_seg`, 0 for a whole-log discard), the
/// cursor just past it, and its term.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn truncate_at(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_seg: u32,
    new_cursor: u32,
    new_term: Term,
    keep_through_index: u64,
    req_id: u32,
) -> bool {
    // ── Persist the new tail BEFORE publishing it ───────────────
    // The high-water, the offset rings and the scan cursor stay as the
    // requester last saw them until the new tail is on stable storage.
    // Within the current segment that is one terminator plus its fsync,
    // so a failure is a clean repeat. Across segments it also means
    // every discarded segment file is inert; that range is paced across
    // steps, and the descriptor, sequence and cursor the truncation
    // will publish are parked in the `retire_*` fields until it is, so
    // nothing observes a half-retired log as the live one.
    if keep_through_index == 0 || keep_seg != s.segment_seq {
        // The discarded suffix spans segment files beyond the current
        // one — a rewind of the current segment alone would leave the
        // suffix on disk for replay to resurrect.
        return begin_cross_segment_truncate(
            s,
            sys,
            keep_seg,
            new_cursor,
            keep_through_index,
            new_term,
            req_id,
        );
    }
    // Within the current segment: a terminator at the new tail, then its
    // fsync. Both may be decided on later steps; the truncation is held in
    // `tc_*` and resumed (`continue_truncate`) until they are, and nothing
    // is staged or drained past it meanwhile.
    s.tc_active = true;
    s.tc_phase = TC_SEEK;
    s.tc_moved = 0;
    s.tc_cursor = new_cursor;
    s.tc_keep = keep_through_index;
    s.tc_term = new_term;
    s.tc_req = req_id;
    continue_truncate(s, sys);
    false
}

/// Resume an in-segment truncation: persist its terminator, then publish
/// it — or refuse it, untouched, if the terminator cannot be made
/// durable. Leaves `tc_active` set while a step is still undecided.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn continue_truncate(s: &mut Wal, sys: &SyscallTable) {
    if !s.tc_active {
        return;
    }
    match truncate_current_segment(s, sys, s.tc_cursor) {
        Step::Later => {}
        Step::Fail => {
            s.tc_active = false;
            s.truncate_failures = s.truncate_failures.saturating_add(1);
            dev_log(sys, 1, b"[wal] truncate not durable".as_ptr(), 26);
            send_truncate_ack(s, sys, s.tc_keep, s.tc_req, false);
        }
        Step::Done => {
            s.tc_active = false;
            publish_truncation(s, sys, s.tc_keep, s.tc_term, s.tc_req);
        }
    }
}

/// Publish a truncation whose new tail is durable: drop the discarded
/// suffix from the in-memory rings, move the high-water back to the keep
/// point, repoint the scan cursor, and ack.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn publish_truncation(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_through_index: u64,
    new_term: Term,
    req_id: u32,
) {
    // Drop in-memory ring slots above the keep point so lookups and
    // entry-request serves no longer surface the discarded suffix. The
    // per-index walk is clamped to one ring revolution: past that, slots
    // repeat and a full-array sweep is both cheaper and complete.
    trim_term_boundaries(s, keep_through_index);
    trim_segment_starts(s, keep_through_index);
    if s.entry_ring_max_index > keep_through_index {
        let span = s.entry_ring_max_index - keep_through_index;
        if span >= ENTRY_LOC_RING_SIZE as u64 {
            for slot in s.entry_ring.iter_mut() {
                if slot.index > keep_through_index {
                    slot.index = 0;
                }
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
        if span >= MEMORY_RING_SIZE as u64 {
            for m in s.memory_entries.iter_mut() {
                if m.index > keep_through_index {
                    m.index = 0;
                    m.body_len = 0;
                }
            }
        } else {
            let mut i = keep_through_index + 1;
            while i <= s.entry_ring_max_index {
                let slot = memory_slot(i);
                if s.memory_entries[slot].index == i {
                    s.memory_entries[slot].index = 0;
                    s.memory_entries[slot].body_len = 0;
                }
                i += 1;
            }
        }
    }
    s.entry_ring_max_index = keep_through_index;
    // A keep point below the ring's floor leaves the ring empty, every
    // slot swept above. The floor follows the tail, so the replacement
    // suffix is ring-served from its first entry instead of walked
    // until the log regrows past the old floor.
    if s.entry_ring_min_index > keep_through_index.saturating_add(1) {
        s.entry_ring_min_index = keep_through_index.saturating_add(1);
    }
    s.cfg.truncate(keep_through_index);
    s.cfg_dirty = true;

    s.current_index = keep_through_index;
    s.current_term = new_term;
    s.truncations = s.truncations.saturating_add(1);
    // The replacement suffix reuses indices and offsets the discarded one
    // held: it is sealed under a new incarnation, never the old one's.
    wal_seal::close_incarnation(s, sys);

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
            s.scan_seg = segment_for(s, s.scan_target);
        }
    }

    dev_log(sys, 3, b"[wal] truncate".as_ptr(), 14);
    send_truncate_ack(s, sys, keep_through_index, req_id, true);
}

/// Persist the new tail inside the CURRENT segment: seek to the keep
/// point, write a zero-length frame terminator (4 bytes of 0, which
/// replay treats as end-of-segment), and fsync. `Done` once the
/// truncation is on stable storage; `Later` while a step awaits its
/// decision (the phase is kept in `tc_phase` and resumed); `Fail` when it
/// cannot be made durable. The cursor moves only on `Done`, so a failed
/// attempt is a clean repeat.
///
/// The in-memory retention posture (`no_fs`) has no on-disk suffix that
/// replay could resurrect: there is nothing to persist and nothing to
/// fail. A missing descriptor in any other posture is the opposite — a
/// disk segment whose suffix is untouched — so it refuses.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn truncate_current_segment(s: &mut Wal, sys: &SyscallTable, new_cursor: u32) -> Step {
    if s.no_fs {
        if s.cursor > s.seg_high_water {
            s.seg_high_water = s.cursor;
        }
        s.cursor = new_cursor;
        return Step::Done;
    }
    if s.fd < 0 {
        // A disk segment with no descriptor: the open failed, is still
        // settling, or the descriptor is parked by a retirement. The
        // suffix is untouched on media either way.
        s.write_errors = s.write_errors.saturating_add(1);
        return Step::Fail;
    }
    if s.tc_phase == TC_SEEK {
        let seek = (new_cursor as i32).to_le_bytes();
        let rc = (sys.provider_call)(s.fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
        if later(rc) {
            return Step::Later;
        }
        if rc < 0 {
            s.write_errors = s.write_errors.saturating_add(1);
            return Step::Fail;
        }
        s.tc_moved = 0;
        s.tc_phase = TC_WRITE;
    }
    if s.tc_phase == TC_WRITE {
        let zero = [0u8; 4];
        let mut moved = s.tc_moved as usize;
        let io = fs_step::write_from(
            sys.provider_call,
            FS_WRITE,
            s.fd,
            zero.as_ptr(),
            4,
            &mut moved,
        );
        s.tc_moved = moved as u8;
        match io {
            Io::Later => return Step::Later,
            Io::Fail(_) | Io::End => {
                s.write_errors = s.write_errors.saturating_add(1);
                return Step::Fail;
            }
            Io::Done => s.tc_phase = TC_FSYNC,
        }
    }
    match sync_fd(s, sys) {
        Step::Later => return Step::Later,
        Step::Fail => {
            s.write_errors = s.write_errors.saturating_add(1);
            return Step::Fail;
        }
        Step::Done => {}
    }
    // The next append seeks to the cursor itself and overwrites the
    // terminator just written.
    if s.cursor > s.seg_high_water {
        s.seg_high_water = s.cursor;
    }
    s.cursor = new_cursor;
    Step::Done
}

/// Answer a truncation request. The ack is the ONLY thing that lets the
/// requester rewind its tip, so a channel that cannot take it right now
/// parks the answer for `flush_truncate_ack` rather than dropping it.
/// There is one park slot, so a caller that leaves an answer parked must
/// not process another truncation until it is delivered.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn send_truncate_ack(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_through_index: u64,
    req_id: u32,
    durable: bool,
) {
    s.trunc_ack_pending = true;
    s.trunc_ack_index = keep_through_index;
    s.trunc_ack_req = req_id;
    s.trunc_ack_durable = durable;
    flush_truncate_ack(s, sys);
}

/// Deliver a parked truncation ack if the output channel can take it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn flush_truncate_ack(s: &mut Wal, sys: &SyscallTable) {
    if !s.trunc_ack_pending {
        return;
    }
    if s.out_flushed < 0 {
        // No path back to the requester: it never entered the pending
        // state on this graph (truncation is opt-in via wiring), so
        // there is nobody to answer.
        s.trunc_ack_pending = false;
        return;
    }
    if !wire_channels::writable(sys, s.out_flushed) {
        return;
    }
    let mut buf = [0u8; wire::WAL_TRUNCATE_ACK_LEN];
    wire::encode_wal_truncate_ack(
        &mut buf,
        s.trunc_ack_index,
        s.trunc_ack_req,
        s.trunc_ack_durable,
    );
    if write_part(s, sys, s.out_flushed, wire::MSG_WAL_TRUNCATE_ACK, &buf) > 0 {
        s.trunc_ack_pending = false;
    }
}

/// Begin a cross-segment truncation: the keep point lives in an older
/// segment (`keep_seg`), or the whole log is discarded (`keep_seg ==
/// 0`). The terminator lands in the keep segment itself, and every
/// segment file above it must be made replay-inert, else a crash after
/// this conflict repair resurrects the discarded suffix at replay.
///
/// The keep segment's terminator (`retire_prep`) and the retirement of
/// the range are both paced by `continue_retirement`, so this returns
/// with the write state parked rather than published: `s.fd` stays
/// withheld and `s.segment_seq`/`s.cursor` keep addressing the
/// pre-truncation segment, which nothing may write through while
/// `retire_active` holds. Returns whether any segment was retired here.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn begin_cross_segment_truncate(
    s: &mut Wal,
    sys: &SyscallTable,
    keep_seg: u32,
    new_cursor: u32,
    keep_through_index: u64,
    new_term: Term,
    req_id: u32,
) -> bool {
    // The live segment is quiescent (every batch fenced, no ticket
    // outstanding), so nothing its close would drop is owed durability.
    if s.fd >= 0 {
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
    let old_seq = s.segment_seq;

    if keep_seg == 0 {
        // Whole-log discard: every segment is retired and appends
        // continue in a FRESH file at the next seq — never a stale file
        // reused in place.
        s.retire_fd = -1;
        s.retire_seq = old_seq.saturating_add(1);
        s.retire_cursor = 0;
        s.retire_high_water = 0;
        s.retire_fresh = true;
        s.retire_from = s.oldest_segment_seq;
        s.retire_through = old_seq;
        s.retire_prep = PREP_DONE;
    } else {
        // Re-open the keep segment for writing, learn its physical
        // extent (the stale-suffix high-water), and persist the
        // terminator at the new tail before anything is deleted.
        s.retire_fd = -1;
        s.retire_seq = keep_seg;
        s.retire_cursor = new_cursor;
        s.retire_high_water = new_cursor;
        s.retire_fresh = false;
        s.retire_from = keep_seg.saturating_add(1);
        s.retire_through = old_seq;
        s.retire_prep = PREP_OPEN;
        s.retire_moved = 0;
    }

    s.retire_active = true;
    s.retire_partial = false;
    s.retire_keep_index = keep_through_index;
    s.retire_keep_term = new_term;
    s.retire_req = req_id;
    continue_retirement(s, sys)
}

/// The keep segment could not take its terminator: the discarded suffix
/// would replay as valid after a crash. Fail-stop (see `fence_failed`)
/// and refuse the truncation; nothing of the range was retired.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn refuse_retire_prep(s: &mut Wal, sys: &SyscallTable, what: &[u8]) {
    if s.retire_fd >= 0 {
        (sys.provider_call)(s.retire_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.retire_fd = -1;
    }
    s.retire_active = false;
    s.retire_prep = PREP_DONE;
    s.fence_failed = true;
    s.write_errors = s.write_errors.saturating_add(1);
    dev_log(sys, 1, what.as_ptr(), what.len());
    s.truncate_failures = s.truncate_failures.saturating_add(1);
    dev_log(sys, 1, b"[wal] truncate not durable".as_ptr(), 26);
    send_truncate_ack(s, sys, s.retire_keep_index, s.retire_req, false);
}

/// Persist the terminator at a cross-segment truncation's keep point:
/// reopen the keep segment, learn its extent, write the terminator,
/// fsync it, fence its name. Each phase's request is re-asked unchanged
/// until decided. `Done` once the keep segment's new tail is durable.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn continue_retire_prep(s: &mut Wal, sys: &SyscallTable) -> Step {
    loop {
        match s.retire_prep {
            PREP_OPEN => {
                let mut path = [0u8; WAL_PATH_MAX];
                let plen =
                    encode_segment_path(s.partition_id, s.retire_seq, s.root_path != 0, &mut path);
                let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
                if later(fd) {
                    return Step::Later;
                }
                if fd < 0 {
                    refuse_retire_prep(s, sys, b"[wal] FATAL truncate reopen");
                    return Step::Fail;
                }
                s.retire_fd = fd;
                s.retire_prep = PREP_STAT;
            }
            PREP_STAT => {
                let mut stat_buf = [0u8; 8];
                let rc = (sys.provider_call)(s.retire_fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
                if later(rc) {
                    return Step::Later;
                }
                let size = if rc < 0 {
                    0
                } else {
                    u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
                };
                s.retire_high_water = size.max(s.retire_cursor);
                s.retire_prep = PREP_SEEK;
            }
            PREP_SEEK => {
                let seek = (s.retire_cursor as i32).to_le_bytes();
                let rc = (sys.provider_call)(s.retire_fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
                if later(rc) {
                    return Step::Later;
                }
                if rc < 0 {
                    refuse_retire_prep(s, sys, b"[wal] FATAL truncate term write");
                    return Step::Fail;
                }
                s.retire_moved = 0;
                s.retire_prep = PREP_WRITE;
            }
            PREP_WRITE => {
                let zero = [0u8; 4];
                let mut moved = s.retire_moved as usize;
                let io = fs_step::write_from(
                    sys.provider_call,
                    FS_WRITE,
                    s.retire_fd,
                    zero.as_ptr(),
                    4,
                    &mut moved,
                );
                s.retire_moved = moved as u8;
                match io {
                    Io::Later => return Step::Later,
                    Io::Done => s.retire_prep = PREP_FSYNC,
                    Io::Fail(_) | Io::End => {
                        refuse_retire_prep(s, sys, b"[wal] FATAL truncate term write");
                        return Step::Fail;
                    }
                }
            }
            PREP_FSYNC => {
                let rc = (sys.provider_call)(s.retire_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if later(rc) {
                    return Step::Later;
                }
                if rc != 0 {
                    refuse_retire_prep(s, sys, b"[wal] FATAL truncate term write");
                    return Step::Fail;
                }
                s.retire_prep = PREP_NAME;
            }
            PREP_NAME => {
                let mut path = [0u8; WAL_PATH_MAX];
                let plen =
                    encode_segment_path(s.partition_id, s.retire_seq, s.root_path != 0, &mut path);
                match publish_name(s, sys, &mut path, plen) {
                    Step::Later => return Step::Later,
                    Step::Fail => {
                        refuse_retire_prep(s, sys, b"[wal] FATAL truncate term write");
                        return Step::Fail;
                    }
                    // The next append seeks to the cursor itself and
                    // overwrites the terminator just written.
                    Step::Done => s.retire_prep = PREP_DONE,
                }
            }
            _ => return Step::Done,
        }
    }
}

/// Paced physical side of a truncation's segment retirement, mirroring
/// `continue_compaction`: at most `COMPACT_UNLINKS_PER_STEP` files per
/// step, each an UNLINK plus a directory fence (or the open/terminate/
/// fence fallback), each resumed across steps until its provider calls
/// are decided.
///
/// The write state parked by `begin_cross_segment_truncate` is handed
/// back — and the truncation published and acked — only once the keep
/// segment's terminator is durable and the whole range is inert: a
/// segment that survives replays the very suffix the truncation removed.
///
/// A segment that cannot be retired ends the attempt if nothing in the
/// range has gone yet: the log is untouched, so the request is refused
/// and a retry is a clean repeat. Once part of the range is inert a
/// clean repeat no longer exists — the retirement stays armed and
/// retries that segment every step, and `fence_failed` fail-stops new
/// appends because the on-disk log now has a hole above the keep point
/// that only a completed retirement or a restart resolves.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn continue_retirement(s: &mut Wal, sys: &SyscallTable) -> bool {
    if !s.retire_active {
        return false;
    }
    if s.retire_prep != PREP_DONE && continue_retire_prep(s, sys) != Step::Done {
        return false;
    }
    let mut retired = 0usize;
    while s.retire_from <= s.retire_through && retired < COMPACT_UNLINKS_PER_STEP {
        match invalidate_segment(s, sys, s.retire_from) {
            Step::Later => return retired > 0,
            Step::Fail => {
                if s.retire_partial {
                    s.fence_failed = true;
                    return retired > 0;
                }
                // Nothing retired: hand the pre-truncation state back
                // untouched and refuse.
                if s.retire_fd >= 0 {
                    (sys.provider_call)(s.retire_fd, FS_CLOSE, core::ptr::null_mut(), 0);
                    s.retire_fd = -1;
                }
                s.retire_active = false;
                s.truncate_failures = s.truncate_failures.saturating_add(1);
                dev_log(sys, 1, b"[wal] truncate not durable".as_ptr(), 26);
                send_truncate_ack(s, sys, s.retire_keep_index, s.retire_req, false);
                return false;
            }
            Step::Done => {}
        }
        s.retire_partial = true;
        s.retire_from = s.retire_from.saturating_add(1);
        retired += 1;
    }
    if s.retire_from <= s.retire_through {
        return retired > 0; // more of the range next step
    }

    // The range is inert: adopt the parked write state and publish.
    s.fd = s.retire_fd;
    s.segment_seq = s.retire_seq;
    s.cursor = s.retire_cursor;
    s.seg_high_water = s.retire_high_water;
    if s.retire_fresh {
        // Every prior segment is gone: the floor must follow the fresh
        // seq, or compaction and the below-floor scan keep addressing
        // files that no longer exist.
        s.oldest_segment_seq = s.segment_seq;
        s.fixed_segment_active = false;
    }
    s.retire_fd = -1;
    s.retire_active = false;
    s.retire_partial = false;
    publish_truncation(
        s,
        sys,
        s.retire_keep_index,
        s.retire_keep_term,
        s.retire_req,
    );
    retired > 0
}

/// Make a discarded segment file replay-inert: unlink it where the
/// provider supports it; otherwise (or on unlink failure) overwrite its
/// first frame header with a zero-length terminator so replay stops at
/// offset 0 even though the file still exists.
///
/// Close the held serve-path read fd if it is on segment `seq`, which is
/// about to be unlinked or rewritten. A serve reading through it is
/// abandoned without a reply (the requester re-asks): the descriptor
/// number may be handed out again once closed.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drop_serve_fd(s: &mut Wal, sys: &SyscallTable, seq: u32) {
    if s.sv_active && s.sv_loc.seg_seq == seq {
        end_serve(s, sys);
    }
    if s.serve_fd >= 0 && s.serve_seg == seq {
        (sys.provider_call)(s.serve_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.serve_fd = -1;
    }
}

/// Reset the segment-invalidation machine.
fn rm_reset(s: &mut Wal) {
    s.rm_phase = RM_START;
    s.rm_fd = -1;
    s.rm_moved = 0;
    s.rm_unlinked = false;
    s.rm_taken = false;
}

/// Close the invalidation's terminator descriptor, if open.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn rm_close(s: &mut Wal, sys: &SyscallTable) {
    if s.rm_fd >= 0 {
        (sys.provider_call)(s.rm_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.rm_fd = -1;
    }
}

/// The invalidation of `rm_seq` failed: count, log, reset.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn rm_fail(s: &mut Wal, sys: &SyscallTable) -> Step {
    rm_close(s, sys);
    rm_reset(s);
    s.write_errors = s.write_errors.saturating_add(1);
    dev_log(sys, 3, b"[wal] invalidate FAIL".as_ptr(), 21);
    Step::Fail
}

/// Retirement is only complete once the REMOVAL of the name is itself
/// durable: an unlink whose directory entry stays in a volatile cache
/// resurrects the segment after a power cut, and the discarded suffix
/// replays as valid. So the unlink is followed by the same name fence
/// that publishes a creation, and a segment whose removal cannot be
/// fenced falls through to the terminator path rather than being
/// reported retired.
///
/// A step machine over `rm_*`: each request is re-asked unchanged until
/// the provider decides it. An `UNLINK` that was taken (`EINPROGRESS`)
/// and whose decision the provider then dropped answers `ENOENT` when
/// re-asked — the removal it started has happened, and that is read as
/// the unlink succeeding, not as an absent segment. `Done` once segment
/// `seq` is inert by a durable name operation.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn invalidate_segment(s: &mut Wal, sys: &SyscallTable, seq: u32) -> Step {
    if s.rm_seq != seq || s.rm_phase == RM_START {
        rm_close(s, sys);
        rm_reset(s);
        s.rm_seq = seq;
        drop_serve_fd(s, sys, seq);
        if !ensure_fs_caps(s, sys) {
            return Step::Later;
        }
        s.rm_phase = if fs_unlink_supported(s, sys) {
            RM_UNLINK
        } else {
            RM_PROBE
        };
    }
    let mut path = [0u8; WAL_PATH_MAX];
    let plen = encode_segment_path(s.partition_id, seq, s.root_path != 0, &mut path);
    loop {
        match s.rm_phase {
            RM_UNLINK => {
                let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
                if rc == FS_E_INPROGRESS {
                    s.rm_taken = true;
                }
                if later(rc) {
                    return Step::Later;
                }
                s.rm_phase = if rc == 0 || (rc == FS_E_NOENT && s.rm_taken) {
                    RM_UNAME
                } else {
                    RM_PROBE
                };
            }
            RM_UNAME => match publish_name(s, sys, &mut path, plen) {
                Step::Later => return Step::Later,
                Step::Done => {
                    rm_reset(s);
                    return Step::Done;
                }
                Step::Fail => {
                    // Gone from the live namespace, but the removal is
                    // not fenced: the name can come back. Mint it again
                    // below so what comes back is inert.
                    s.rm_unlinked = true;
                    s.rm_phase = RM_PROBE;
                }
            },
            RM_PROBE => {
                // A name that is not there is already inert — unless this
                // machine is what removed it. Probe with the read-only
                // opener, which answers ENOENT rather than minting the
                // file, so that a refusal from the write tier below can be
                // read as what it is: a failing FS, not an absent segment.
                // Retirement answers a durability question, and a dying
                // provider must not be able to report every segment
                // retired.
                let probe = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
                if later(probe) {
                    return Step::Later;
                }
                if probe >= 0 {
                    (sys.provider_call)(probe, FS_CLOSE, core::ptr::null_mut(), 0);
                } else if probe == FS_E_NOENT && !s.rm_unlinked {
                    rm_reset(s);
                    return Step::Done;
                }
                s.rm_phase = RM_CREATE;
            }
            RM_CREATE => {
                let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
                if later(fd) {
                    return Step::Later;
                }
                if fd < 0 {
                    return rm_fail(s, sys);
                }
                s.rm_fd = fd;
                s.rm_phase = RM_SEEK;
            }
            RM_SEEK => {
                let seek = 0i32.to_le_bytes();
                let rc = (sys.provider_call)(s.rm_fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
                if later(rc) {
                    return Step::Later;
                }
                if rc < 0 {
                    return rm_fail(s, sys);
                }
                s.rm_moved = 0;
                s.rm_phase = RM_WRITE;
            }
            RM_WRITE => {
                let zero = [0u8; 4];
                let mut moved = s.rm_moved as usize;
                let io = fs_step::write_from(
                    sys.provider_call,
                    FS_WRITE,
                    s.rm_fd,
                    zero.as_ptr(),
                    4,
                    &mut moved,
                );
                s.rm_moved = moved as u8;
                match io {
                    Io::Later => return Step::Later,
                    Io::Done => s.rm_phase = RM_FSYNC,
                    Io::Fail(_) | Io::End => return rm_fail(s, sys),
                }
            }
            RM_FSYNC => {
                // The terminator's durability is fenced BEFORE the close:
                // CLOSE never waits and reports no write-back failure.
                let rc = (sys.provider_call)(s.rm_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if later(rc) {
                    return Step::Later;
                }
                if rc != 0 {
                    return rm_fail(s, sys);
                }
                rm_close(s, sys);
                s.rm_phase = RM_CNAME;
            }
            RM_CNAME => {
                // The open-create may have minted this name (unlink
                // succeeded, its fence did not; or the file was already
                // gone). Publishing it costs one directory fence and makes
                // the inert file itself durable.
                match publish_name(s, sys, &mut path, plen) {
                    Step::Later => return Step::Later,
                    Step::Done => {
                        rm_reset(s);
                        return Step::Done;
                    }
                    Step::Fail => {
                        rm_reset(s);
                        s.write_errors = s.write_errors.saturating_add(1);
                        return Step::Fail;
                    }
                }
            }
            _ => {
                rm_reset(s);
                return Step::Later;
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` (or shared
/// `&Wal` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn compact_before(s: &mut Wal, sys: &SyscallTable, before_index: u64) {
    if before_index == 0 {
        return;
    }
    // Everything up to the snapshot's index is committed: its config
    // entries are the base now.
    if before_index <= s.current_index {
        s.cfg.fold_through(before_index);
    }
    // `before_index` is the snapshot's index. Whatever the floors keep
    // below it, replay after a restart can start at the segment that
    // holds it: the snapshot covers the state, and the older segments
    // are content the scan path reads on demand.
    if let Some(loc) = lookup_entry_loc(s, before_index) {
        persist_replay_start(s, sys, loc.seg_seq);
    }
    // The floors bound the trim, not the snapshot that requested it.
    // Entries at or above the lowest floor are still wanted — by a
    // consumer inside its retention window, or by a voter that has not
    // matched them — so the trim point comes down to the floor and the
    // snapshot above it stands.
    let before_index = match retention_floor_index(s) {
        Some(floor) if floor < before_index => {
            s.compact_floored = s.compact_floored.wrapping_add(1);
            floor
        }
        _ => before_index,
    };
    if before_index == 0 {
        return;
    }
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
        if slot.index == 0 {
            continue;
        }
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
    if max_safe_seq_to_drop == 0 {
        return;
    }
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

/// Drain application retention floors from this slot's inbox.
///
/// Wire shape (10 bytes): `[kpg_id:u16 LE][floor_revision:u64 LE]`,
/// declared by `wire::MSG_COMPACTION_FLOOR`. Idempotent: a floor
/// re-sent unchanged updates a slot in place.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn drain_retention_floors(s: &mut Wal, sys: &SyscallTable) {
    if s.in_retention_floor < 0 {
        return;
    }
    for _ in 0..4 {
        let Some((msg_type, plen)) = s.inbox_retention.next(sys, &mut s.msg_buf) else {
            break;
        };
        if msg_type != wire::MSG_COMPACTION_FLOOR || (plen as usize) < 10 {
            continue;
        }
        let kpg_id = u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]);
        // The wire reserves `0xFFFF` as "never a real kpg id"; it is
        // also this table's empty-slot sentinel. Drop loudly.
        if kpg_id == FLOOR_SLOT_EMPTY {
            dev_log(sys, 3, b"[wal] kpg sentinel".as_ptr(), 18);
            continue;
        }
        let floor_revision = u64::from_le_bytes([
            s.msg_buf[2],
            s.msg_buf[3],
            s.msg_buf[4],
            s.msg_buf[5],
            s.msg_buf[6],
            s.msg_buf[7],
            s.msg_buf[8],
            s.msg_buf[9],
        ]);
        upsert_retention_floor(s, sys, kpg_id, floor_revision);
    }
}

/// Insert or update the floor for `kpg_id`. Table full → latch the
/// sticky overflow flag (compaction retires nothing until restart) and
/// say so, rather than evicting a floor and retiring what it guards.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn upsert_retention_floor(
    s: &mut Wal,
    sys: &SyscallTable,
    kpg_id: u16,
    floor_revision: u64,
) {
    for slot in &mut s.retention_floors {
        if slot.kpg_id == kpg_id {
            slot.floor_revision = floor_revision;
            return;
        }
    }
    for slot in &mut s.retention_floors {
        if slot.kpg_id == FLOOR_SLOT_EMPTY {
            slot.kpg_id = kpg_id;
            slot.floor_revision = floor_revision;
            // First floor for this kpg. Low volume by construction — a
            // publisher re-sends only when its floor MOVES — and it is
            // the only external evidence that an application's retention
            // window bounds compaction here, rather than being computed
            // and dropped somewhere on the way.
            let mut line = [0u8; 64];
            let mut pos = emit_field(
                line.as_mut_ptr(),
                0,
                b"[wal] floor p=",
                u32::from(s.partition_id),
            );
            pos += emit_field(line.as_mut_ptr(), pos, b" kpg=", u32::from(kpg_id));
            pos += emit_field(
                line.as_mut_ptr(),
                pos,
                b" idx=",
                floor_revision.min(u64::from(u32::MAX)) as u32,
            );
            dev_log(sys, 3, line.as_ptr(), pos);
            return;
        }
    }
    s.retention_floor_overflow = true;
    dev_log(sys, 3, b"[wal] floor full".as_ptr(), 16);
}

/// The lowest index any floor still wants kept, or `None` when no
/// floor has been declared (nothing bounds compaction but the
/// snapshot). An overflowed table answers 0: nothing may be retired
/// when the set of floors is known to be incomplete.
fn retention_floor_index(s: &Wal) -> Option<u64> {
    if s.retention_floor_overflow {
        return Some(0);
    }
    let mut lowest = match (s.match_floor, s.xfer_floor) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    for slot in &s.retention_floors {
        if slot.kpg_id == FLOOR_SLOT_EMPTY {
            continue;
        }
        lowest = Some(match lowest {
            Some(cur) if cur <= slot.floor_revision => cur,
            _ => slot.floor_revision,
        });
    }
    lowest
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
/// Each removal is fenced like every other, so the REMOVAL of the name
/// is durable and not merely queued in a directory cache. A refused
/// fence orphans the file rather than failing the trim: the persisted
/// floor already keeps replay above a name that comes back.
///
/// Returns whether any segment was unlinked, so the caller can classify
/// the step's elapsed time.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn continue_compaction(s: &mut Wal, sys: &SyscallTable) -> bool {
    if s.compact_pending_to == 0 {
        return false;
    }
    if s.oldest_segment_seq > s.compact_pending_to || s.oldest_segment_seq >= s.segment_seq {
        s.compact_pending_to = 0;
        return false;
    }
    let new_oldest = s.compact_pending_to.saturating_add(1).min(s.segment_seq);
    if !persist_segment_floor(s, sys, new_oldest) {
        return false; // resumed next step; nothing deleted until the floor is durable
    }
    if !ensure_fs_caps(s, sys) {
        return false;
    }
    let mut unlinks = 0usize;
    while s.oldest_segment_seq <= s.compact_pending_to
        && s.oldest_segment_seq < s.segment_seq
        && unlinks < COMPACT_UNLINKS_PER_STEP
    {
        if fs_unlink_supported(s, sys) {
            let mut path = [0u8; WAL_PATH_MAX];
            let plen = encode_segment_path(
                s.partition_id,
                s.oldest_segment_seq,
                s.root_path != 0,
                &mut path,
            );
            if s.cp_phase == CP_UNLINK {
                if !s.cp_taken {
                    drop_serve_fd(s, sys, s.oldest_segment_seq);
                }
                let rc = (sys.provider_call)(-1, FS_UNLINK, path.as_mut_ptr(), plen);
                if rc == FS_E_INPROGRESS {
                    s.cp_taken = true;
                }
                if later(rc) {
                    return unlinks > 0; // the same unlink is asked again next step
                }
                // A taken unlink whose decision was dropped answers ENOENT
                // when re-asked: its removal happened.
                if rc == 0 || (rc == FS_E_NOENT && s.cp_taken) {
                    s.cp_phase = CP_NAME;
                } else {
                    // ENOENT is expected after skip_replay orphaned a prior
                    // run's numbering, or when an operator GC'd out-of-band.
                    dev_log(sys, 3, b"[wal] compact orphan".as_ptr(), 20);
                }
            }
            if s.cp_phase == CP_NAME {
                match publish_name(s, sys, &mut path, plen) {
                    Step::Later => return unlinks > 0,
                    Step::Done => dev_log(sys, 3, b"[wal] compacted".as_ptr(), 15),
                    Step::Fail => dev_log(sys, 3, b"[wal] compact name unfenced".as_ptr(), 27),
                }
            }
        } else {
            dev_log(sys, 3, b"[wal] compacted".as_ptr(), 15);
        }
        s.cp_phase = CP_UNLINK;
        s.cp_taken = false;
        unlinks += 1;
        s.oldest_segment_seq += 1;
    }
    if s.oldest_segment_seq > s.compact_pending_to || s.oldest_segment_seq >= s.segment_seq {
        s.compact_pending_to = 0;
    }
    // Restart any surviving in-flight scan at the new oldest segment.
    if s.scan_seg < s.oldest_segment_seq {
        s.scan_seg = s.oldest_segment_seq;
    }
    unlinks > 0
}

/// Lazily probe the FS provider's capability bitmap for `UNLINK` support.
/// Cached after the first answered probe (`0` = unprobed, `1` = yes,
/// `2` = no); a CAPS call the provider cannot answer yet (`EAGAIN` while
/// it mounts) stays unprobed and retries rather than caching a transient
/// answer as "unsupported". Callers that need to know check
/// `ensure_fs_caps` first.
unsafe fn fs_unlink_supported(s: &mut Wal, sys: &SyscallTable) -> bool {
    ensure_fs_caps(s, sys);
    s.fs_unlink_probe == 1
}

/// One-shot FS capability probe. Reads the provider's CAPS bitmap once
/// and caches the `UNLINK` disposition (`fs_unlink_probe`), the
/// name-publication disposition (`name_fence_probe`), and whether the
/// async durable-write tier is available (`fs_async`). Returns whether the
/// bitmap is known. `EAGAIN` (the provider is still attaching its volume,
/// and a capability can depend on the volume) leaves everything unprobed
/// and is asked again later — it is never latched as "absent". Any other
/// failure is a provider that cannot describe itself; it is latched as
/// offering nothing optional, which is what an unprobed provider was
/// already treated as. Called at the top of `flush_batch` so `fs_async`
/// is set before the first durable write is issued.
unsafe fn ensure_fs_caps(s: &mut Wal, sys: &SyscallTable) -> bool {
    if s.fs_unlink_probe != 0 {
        return true;
    }
    let mut caps = [0u8; 4];
    let rc = (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4);
    if later(rc) {
        return false;
    }
    let bits = if rc == 4 { u32::from_le_bytes(caps) } else { 0 };
    s.fs_unlink_probe = if bits & FS_CAP_UNLINK != 0 { 1 } else { 2 };
    s.fs_async = bits & FS_CAP_FSYNC_ASYNC != 0;
    s.name_fence_probe = if bits & FS_CAP_FSYNC_NAME != 0 {
        NAME_FENCE_PRESENT
    } else {
        NAME_FENCE_ABSENT
    };
    true
}

/// Fence the `wal/` directory's own name when this boot minted it
/// (`FS_MKDIR` answered 0): a directory created by `MKDIR` is no more
/// durable than a file created by `OPEN_CREATE` until `FS_FSYNC_NAME`
/// covers it, and every segment, the floor sidecar and the seal state
/// live inside it. `Done` once nothing is owed.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn fence_wal_dir(s: &mut Wal, sys: &SyscallTable) -> Step {
    if !s.dir_unfenced {
        return Step::Done;
    }
    let mut dir = [0u8; 4];
    dir[..3].copy_from_slice(b"wal");
    let st = publish_name(s, sys, &mut dir, 3);
    if st == Step::Done {
        s.dir_unfenced = false;
    }
    st
}

/// Publish the parent-directory entry for `path` — the fence that makes
/// a segment file discoverable after a power cut. `FS_FSYNC` on the
/// descriptor covers the bytes only.
///
/// `Done` when the name may be treated as durable: `FS_FSYNC_NAME`
/// answered 0. `Later` when the provider has not decided yet (or cannot
/// answer CAPS yet): the caller asks again, with the same path, on a later
/// step. A provider without `caps::FSYNC_NAME` cannot prove that, so:
///
///   - `NAME_FENCE_STRICT` answers `Fail` — the caller refuses the
///     publication rather than certifying a name it cannot fence.
///   - `NAME_FENCE_AUTO` answers `Done` and counts the publication in
///     `WAL_NAME_UNFENCED`, so the weaker posture is visible rather
///     than assumed.
///
/// A provider that advertises the capability and then fails the call is
/// always a durability failure, in both postures.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn publish_name(s: &mut Wal, sys: &SyscallTable, path: &mut [u8], plen: usize) -> Step {
    if !ensure_fs_caps(s, sys) {
        return Step::Later;
    }
    if s.name_fence_probe != NAME_FENCE_PRESENT {
        if s.name_fence == NAME_FENCE_STRICT {
            // A backend that has no such opcode has none on any later
            // attempt either, and every refused publication retries. The
            // disposition is exported as `WAL_NAME_FENCE`, so the log
            // records the standing condition once, informationally.
            if !s.name_fence_absent_logged {
                s.name_fence_absent_logged = true;
                dev_log(sys, 2, b"[wal] no name fence".as_ptr(), 19);
            }
            return Step::Fail;
        }
        s.name_unfenced = s.name_unfenced.saturating_add(1);
        return Step::Done;
    }
    let rc = (sys.provider_call)(-1, FS_FSYNC_NAME, path.as_mut_ptr(), plen);
    if later(rc) {
        return Step::Later;
    }
    if rc == 0 {
        return Step::Done;
    }
    // The provider advertised the capability and then refused the call:
    // a genuine durability failure, in both postures. Loud once — it
    // recurs on every publication while the device is in this state.
    if !s.name_fence_fail_logged {
        s.name_fence_fail_logged = true;
        dev_log(sys, 1, b"[wal] name fence FAIL".as_ptr(), 21);
    }
    Step::Fail
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
    //
    // Every call here is non-blocking: an open, a size, or a frame that
    // has not answered yet is resumed where it stopped next step — an
    // `EAGAIN` is never read as a missing segment (that would skip real
    // segments and lose committed state on recovery) nor a short frame
    // as a torn one.
    if s.replay_fd < 0 {
        // Consult the persisted segment floor once per replay pass. A
        // long-lived log compacts more leading segments away than
        // REPLAY_GAP_TOLERANCE covers, so probing blindly from seq 1
        // exhausts the miss budget before reaching the survivors and
        // orphans the whole durable log. Missing sidecar = fresh
        // deployment or pre-floor layout: probe from seq 1.
        if !s.replay_floor_checked {
            return read_replay_floor(s, sys);
        }
        build_segment_path(s, s.replay_seg);
        let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), s.path_len as usize);
        if later(fd) {
            // FS provider still initialising (fat32 reading the BPB on a pi5
            // cold boot), or the directory not cached yet. Do NOT count this
            // as a missing segment. Wait and retry the same seq next step.
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
            settle_after_replay(s);
            s.phase = PHASE_NORMAL;
            // Burst (forgive any cold-scan this open paid); harmlessly
            // re-steps once into PHASE_NORMAL, which returns Continue.
            return STEP_BURST;
        }
        s.replay_fd = fd;
        s.replay_sized = false;
        s.replay_got = 0;
    }

    if !s.replay_sized {
        // Check file size — an empty segment is the tombstone an
        // in-flight rotation may leave behind. Treat it the same
        // way we treat a final miss: terminate replay here.
        // FS_STAT writes [size:u32 LE][mtime:u32 LE] into the supplied buffer.
        let mut stat_buf = [0u8; 8];
        let stat_rc = (sys.provider_call)(s.replay_fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        if later(stat_rc) {
            return 0; // the same descriptor is sized next step
        }
        let size = if stat_rc < 0 {
            0
        } else {
            u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
        };
        if size == 0 {
            close_replay_fd(s, sys);
            // Freeze the durable high-water reconstructed by replay.
            s.replay_recovered_index = s.current_index;
            s.replay_recovered_term = s.current_term;
            dev_log(sys, 3, b"[wal] replay done".as_ptr(), 17);
            s.phase = PHASE_NORMAL;
            settle_after_replay(s);
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

        if wal_seal::enabled(s) && !wal_seal::on_replay_segment(s, sys) {
            close_replay_fd(s, sys);
            return 0;
        }

        if s.replay_tainted {
            // Past a mid-log fault the prefix already replayed IS the
            // recoverable log. Later segments are walked only so
            // `segment_seq` lands past every existing file (fresh appends
            // must never land in a stale segment) — their entries are
            // never read, acked, or recorded.
            close_replay_fd(s, sys);
            s.replay_seg = s.replay_seg.saturating_add(1);
            return STEP_BURST;
        }

        s.replay_sized = true;
        s.replay_file_size = size;
        s.replay_pos = 0;
        s.replay_got = 0;
        dev_log(sys, 3, b"[wal] replay seg".as_ptr(), 16);
        // The FS_OPEN above may have paid the cold directory-scan penalty
        // (tens of ms). Forgive it via Burst and read frames on subsequent
        // warm steps rather than falling through here.
        return STEP_BURST;
    }

    if wal_seal::enabled(s) {
        return wal_seal::replay_frames(s, sys, REPLAY_FRAMES_PER_STEP);
    }

    // Read framed entries: [entry_len: u32 LE] [crc32c: u32 LE] [entry_data].
    // Up to REPLAY_FRAMES_PER_STEP per step (warm reads — the cold open
    // already got its Burst); any segment transition or fault ends the step.
    // A frame the provider has only part-delivered is resumed at
    // `replay_got` next step: the descriptor's offset already sits there.
    let mut frames = 0usize;
    while frames < REPLAY_FRAMES_PER_STEP {
        // Every replayed entry is re-acked to consensus, and the ack is
        // how a restarted node learns the terms of the log it holds — a
        // missing one leaves an index it cannot judge. Wait for room
        // before consuming the frame rather than replaying past an ack
        // the channel could not take.
        if s.out_flushed >= 0 && !wire_channels::writable(sys, s.out_flushed) {
            return 0;
        }
        frames += 1;
        let remaining = s.replay_file_size.saturating_sub(s.replay_pos);
        if s.replay_got == 0 && remaining < FRAME_HDR {
            // Not enough data for a frame header — segment done
            end_replay_segment(s, sys, false);
            return 0;
        }

        // Read the 8-byte header (length + CRC32C)
        if s.replay_got < FRAME_HDR {
            let mut got = s.replay_got as usize;
            let io = fs_step::read_into(
                sys.provider_call,
                s.replay_fd,
                s.replay_hdr.as_mut_ptr(),
                FRAME_HDR as usize,
                &mut got,
            );
            s.replay_got = got as u32;
            match io {
                Io::Later => return 0,
                Io::Done => {}
                Io::End | Io::Fail(_) => {
                    // Short read despite `remaining >= FRAME_HDR`: a device
                    // fault, not a clean end. Taint so no later segment is
                    // acked over it.
                    end_replay_segment(s, sys, true);
                    return 0;
                }
            }
        }

        let (entry_len32, stored_crc) = wal_frame::parse_header(&s.replay_hdr);
        let entry_len = entry_len32 as usize;
        if wal_frame::len_invalid(
            entry_len32,
            u64::from(s.replay_file_size.saturating_sub(s.replay_pos + FRAME_HDR)),
        ) {
            // Stop this segment at the last good entry. A zero-length
            // frame is the live-tail terminator — a clean per-segment stop
            // (fixed segments end every rotated segment with one) — so it
            // does not taint. A nonzero-but-impossible length is a torn
            // header, which does.
            end_replay_segment(s, sys, entry_len32 != 0);
            return 0;
        }

        // Read entry data
        let mut got = (s.replay_got - FRAME_HDR) as usize;
        let io = fs_step::read_into(
            sys.provider_call,
            s.replay_fd,
            s.msg_buf.as_mut_ptr(),
            entry_len,
            &mut got,
        );
        s.replay_got = FRAME_HDR + got as u32;
        match io {
            Io::Later => return 0,
            Io::Done => {}
            Io::End | Io::Fail(_) => {
                end_replay_segment(s, sys, true);
                return 0;
            }
        }
        let entry_payload_offset = s.replay_pos + FRAME_HDR;
        s.replay_pos += FRAME_HDR + entry_len as u32;
        s.replay_got = 0;

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
            dev_log(sys, 3, b"[wal] replay CRC FAIL".as_ptr(), 21);
            end_replay_segment(s, sys, true);
            return 0;
        }

        // Parse: first 16 bytes are term(8) + index(8)
        if let Some((term, index)) = wire::decode_term_index(&s.msg_buf[..entry_len]) {
            // An index jump means the records between the last replayed
            // entry and this one are gone. Acking across that hole would
            // assert a durable high-water over missing records, which is
            // unrepairable once commit passes it. Stop; the prefix is the
            // log.
            if s.current_index != 0 && index > s.current_index.saturating_add(1) {
                s.continuity_errors = s.continuity_errors.saturating_add(1);
                dev_log(sys, 1, b"[wal] replay gap".as_ptr(), 16);
                end_replay_segment(s, sys, true);
                return 0;
            }

            if index > s.current_index {
                s.current_index = index;
                s.current_term = term;
            }
            if s.replay_first_index == 0 {
                s.replay_first_index = index;
            }
            record_entry_loc(
                s,
                index,
                term,
                s.replay_seg,
                entry_payload_offset,
                entry_len as u32,
            );
            note_config(s, index, 0, entry_len);
            note_ledger_ack(s, term, index);

            // Re-emit as FsyncAck — entry is already durable on disk.
            // Room was checked before the frame was consumed; the ledger
            // latch above carries the high-water regardless.
            if s.out_flushed >= 0 {
                let mut ack = [0u8; 17];
                wire::encode_fsync_ack(&mut ack, term, index, s.self_id);
                write_part(s, sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack[..17]);
                dev_log(sys, 3, b"[wal] replayed".as_ptr(), 14);
            }

            s.entries_written += 1;
            s.replayed_count += 1;
        }
    }

    0
}

/// Close the replay descriptor (a read-only one: nothing it carried is
/// owed durability).
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn close_replay_fd(s: &mut Wal, sys: &SyscallTable) {
    if s.replay_fd >= 0 {
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    }
    s.replay_fd = -1;
    s.replay_sized = false;
    s.replay_got = 0;
}

/// End replay of the open segment and move to the next seq. `torn` marks
/// the walk tainted so no later segment is acknowledged over the hole.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn end_replay_segment(s: &mut Wal, sys: &SyscallTable, torn: bool) {
    if torn {
        s.replay_tainted = true;
    }
    close_replay_fd(s, sys);
    s.replay_seg += 1;
}

/// Read the persisted segment floor once per replay pass, resumably: the
/// open and the read are each re-asked until answered, and only an
/// answered absence counts as "no sidecar".
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn read_replay_floor(s: &mut Wal, sys: &SyscallTable) -> i32 {
    if s.floor_rd_fd < 0 {
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = encode_floor_path(s.partition_id, s.root_path != 0, &mut path);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if later(fd) {
            return 0; // provider initialising — retry
        }
        if fd < 0 {
            s.replay_floor_checked = true;
            // The open may have paid the cold directory-scan penalty.
            return STEP_BURST;
        }
        s.floor_rd_fd = fd;
        s.floor_rd_got = 0;
    }
    // `[floor:u32][replay_start:u32]`; a 4-byte file from an earlier
    // layout carries the floor alone.
    let mut got = s.floor_rd_got as usize;
    let io = fs_step::read_into(
        sys.provider_call,
        s.floor_rd_fd,
        s.floor_rd_buf.as_mut_ptr(),
        8,
        &mut got,
    );
    s.floor_rd_got = got as u8;
    if io == Io::Later {
        return 0;
    }
    (sys.provider_call)(s.floor_rd_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    s.floor_rd_fd = -1;
    let n = if matches!(io, Io::Fail(_)) { 0 } else { got };
    let val = s.floor_rd_buf;
    if n >= 4 {
        let floor = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
        if floor > s.replay_seg {
            s.replay_seg = floor;
        }
        s.floor_persisted = floor;
        dev_log(sys, 3, b"[wal] replay floor".as_ptr(), 18);
    }
    if n >= 8 {
        let start = u32::from_le_bytes([val[4], val[5], val[6], val[7]]);
        if start > s.replay_seg {
            s.replay_seg = start;
            dev_log(sys, 3, b"[wal] replay from snapshot".as_ptr(), 26);
        }
        s.replay_start_persisted = start;
    }
    s.replay_floor_checked = true;
    STEP_BURST
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
/// pre-creates a symlink in the working directory (`ln -s
/// <somewhere> wal`); the single-directory layout serves any
/// partition count. See
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
        out[i] = if p < 10 { b'0' + p } else { b'a' + p - 10 };
        i += 1;
        for digit in (0..7).rev() {
            let nibble = ((seq >> (digit * 4)) & 0xF) as u8;
            let ch = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            if i < cap {
                out[i] = ch;
                i += 1;
            }
        }
        for &b in b".WAL" {
            if i < cap {
                out[i] = b;
                i += 1;
            }
        }
        return i;
    }
    for &b in b"wal/p" {
        if i < cap {
            out[i] = b;
            i += 1;
        }
    }
    for digit in (0..4).rev() {
        let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        if i < cap {
            out[i] = ch;
            i += 1;
        }
    }
    for &b in b"_seg_" {
        if i < cap {
            out[i] = b;
            i += 1;
        }
    }
    for digit in (0..8).rev() {
        let nibble = ((seq >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        if i < cap {
            out[i] = ch;
            i += 1;
        }
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
            if i < cap {
                out[i] = b;
                i += 1;
            }
        }
        return i;
    }
    for &b in b"wal/p" {
        if i < cap {
            out[i] = b;
            i += 1;
        }
    }
    for digit in (0..4).rev() {
        let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        if i < cap {
            out[i] = ch;
            i += 1;
        }
    }
    for &b in b"_floor" {
        if i < cap {
            out[i] = b;
            i += 1;
        }
    }
    i
}

/// Durably persist `new_oldest` (the segment seq replay must start
/// probing from) to the floor sidecar. Returns true once it is durable.
/// Called BEFORE compaction unlinks anything: physical deletion never
/// runs ahead of a durable floor, so replay can always find the log even
/// when more than `REPLAY_GAP_TOLERANCE` leading segments are gone.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn persist_segment_floor(s: &mut Wal, sys: &SyscallTable, new_oldest: u32) -> bool {
    if s.floor_persisted >= new_oldest {
        return true;
    }
    if new_oldest > s.floor_wanted {
        s.floor_wanted = new_oldest;
    }
    sidecar_step(s, sys);
    s.floor_persisted >= new_oldest
}

/// Record that replay may start at `seg` — the segment holding the
/// latest durable snapshot's index. Monotone, and persisted by
/// `sidecar_step` (resumed every step); a refused write is retried by the
/// next snapshot's trim request.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn persist_replay_start(s: &mut Wal, sys: &SyscallTable, seg: u32) {
    if seg <= s.replay_start_persisted {
        return;
    }
    if seg > s.start_wanted {
        s.start_wanted = seg;
    }
    sidecar_step(s, sys);
}

/// Close the sidecar descriptor and return the machine to idle.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn sidecar_reset(s: &mut Wal, sys: &SyscallTable) {
    if s.sc_fd >= 0 {
        (sys.provider_call)(s.sc_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.sc_fd = -1;
    }
    s.sc_phase = SC_IDLE;
    s.sc_moved = 0;
}

/// Write the sidecar `[floor:u32][replay_start:u32]` durably and publish
/// its name, as a step machine over `sc_*`: the values are fixed when a
/// write starts, every request is re-asked unchanged until decided, and
/// both values are adopted only once the name fence answers. A wish that
/// moves while a write is in flight is written by the next one.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn sidecar_step(s: &mut Wal, sys: &SyscallTable) {
    if s.sc_phase == SC_IDLE {
        let floor = s.floor_wanted.max(s.floor_persisted);
        // Replay never starts below the floor: a start the trim overtakes
        // moves up with it.
        let start = s.start_wanted.max(s.replay_start_persisted).max(floor);
        if floor == s.floor_persisted && start == s.replay_start_persisted {
            return;
        }
        s.sc_floor = floor;
        s.sc_start = start;
        s.sc_moved = 0;
        s.sc_phase = SC_OPEN;
    }
    let mut path = [0u8; WAL_PATH_MAX];
    let plen = encode_floor_path(s.partition_id, s.root_path != 0, &mut path);
    loop {
        match s.sc_phase {
            SC_OPEN => {
                let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
                if later(fd) {
                    return;
                }
                if fd < 0 {
                    sidecar_refused(s, sys);
                    return;
                }
                s.sc_fd = fd;
                s.sc_phase = SC_WRITE;
            }
            SC_WRITE => {
                let mut val = [0u8; 8];
                val[..4].copy_from_slice(&s.sc_floor.to_le_bytes());
                val[4..].copy_from_slice(&s.sc_start.to_le_bytes());
                let mut moved = s.sc_moved as usize;
                let io = fs_step::write_from(
                    sys.provider_call,
                    FS_WRITE,
                    s.sc_fd,
                    val.as_ptr(),
                    8,
                    &mut moved,
                );
                s.sc_moved = moved as u8;
                match io {
                    Io::Later => return,
                    Io::Done => s.sc_phase = SC_FSYNC,
                    Io::Fail(_) | Io::End => {
                        sidecar_refused(s, sys);
                        return;
                    }
                }
            }
            SC_FSYNC => {
                // Fenced before the close: CLOSE reports no write-back.
                let rc = (sys.provider_call)(s.sc_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if later(rc) {
                    return;
                }
                if rc != 0 {
                    sidecar_refused(s, sys);
                    return;
                }
                (sys.provider_call)(s.sc_fd, FS_CLOSE, core::ptr::null_mut(), 0);
                s.sc_fd = -1;
                s.sc_phase = SC_NAME;
            }
            SC_NAME => match fence_wal_dir(s, sys) {
                Step::Done => match publish_name(s, sys, &mut path, plen) {
                    Step::Later => return,
                    Step::Fail => {
                        sidecar_refused(s, sys);
                        return;
                    }
                    Step::Done => {
                        s.floor_persisted = s.sc_floor;
                        s.replay_start_persisted = s.sc_start;
                        sidecar_reset(s, sys);
                        return;
                    }
                },
                Step::Later => return,
                Step::Fail => {
                    sidecar_refused(s, sys);
                    return;
                }
            },
            _ => {
                sidecar_reset(s, sys);
                return;
            }
        }
    }
}

/// A sidecar write was refused. The floor stays wanted (compaction
/// retries it, and deletes nothing meanwhile); the replay-start wish is
/// dropped until the next snapshot's trim asks again.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn sidecar_refused(s: &mut Wal, sys: &SyscallTable) {
    sidecar_reset(s, sys);
    s.start_wanted = s.replay_start_persisted;
}

/// Set the segment bounds once replay has walked what it needs. The
/// oldest segment on disk is the persisted floor when replay started
/// above it — the segments between are retained content the scan
/// serves — else the first segment replay found; and in the former case
/// the ring's floor rises to the first replayed index, so a request
/// below it goes to the scan rather than reading as "not in the ring,
/// so compacted".
fn settle_after_replay(s: &mut Wal) {
    wal_seal::after_replay(s);
    if s.replay_last_found == 0 {
        s.segment_seq = 1;
        s.oldest_segment_seq = 1;
        return;
    }
    s.segment_seq = s.replay_last_found.saturating_add(1);
    if s.floor_persisted > 0 && s.floor_persisted < s.replay_first_found {
        s.oldest_segment_seq = s.floor_persisted;
        if s.replay_first_index > s.entry_ring_min_index {
            s.entry_ring_min_index = s.replay_first_index;
        }
    } else {
        s.oldest_segment_seq = s.replay_first_found;
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
    if !wire_channels::writable(sys, s.out_flushed) {
        return;
    }
    let mut buf = [0u8; 8];
    wire::encode_wal_reject(&mut buf, expected);
    write_part(s, sys, s.out_flushed, wire::MSG_WAL_REJECT, &buf);
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
    if s.fence_failed {
        return;
    } // latched fail-stop: hold intake, no acks
      // A sequence that owns the live descriptor is resumed before anything
      // is staged: a rotation awaiting its fsync (the next record belongs in
      // the NEXT segment), a truncation persisting its terminator (the
      // cursor is about to move), or a staged replay terminator not yet
      // written (a record staged behind it would sit after the terminator).
    if s.rotating || s.tc_active || s.staged_terminator {
        return;
    }
    // A full segment takes nothing more: its pipeline drains, and it is
    // closed only once no fence ticket is outstanding against it (a
    // ticket dies with its descriptor). Holding intake for that one drain
    // is what keeps a segment bounded under sustained pipelined load —
    // staging past the limit would keep a fence in flight forever, and
    // the segment would never be quiescent enough to rotate.
    if s.fd >= 0 && s.cursor >= s.segment_limit && !rotate_before_append(s, sys) {
        return;
    }
    if s.fs_async && s.fence_depth > 1 {
        let depth = (s.fence_depth as usize).min(FENCE_RING_MAX);
        if (s.fence_ring_count as usize) >= depth {
            return;
        }
    } else if s.fence_pending || s.sync_pending {
        // The batch's fence (async) or fsync (sync) is undecided: a record
        // staged now would raise `pending_max_index` past what it covers.
        return;
    }

    // Check input readiness. The frames live in THIS slot's inbox, not
    // on the channel — the module's intake demux drains the channel
    // into per-slot inboxes before any slot steps, so gating on the
    // channel here would see it already empty and never pop the inbox.
    if s.stashed_len == 0 && s.inbox_entries.is_empty() {
        return;
    }

    // Output back-pressure: only block when out_flushed is wired AND
    // currently not writable. An unwired output (`out_flushed < 0`,
    // e.g. a partitioned graph that hasn't built the per-partition
    // commit pipeline yet) shouldn't gate disk durability — the WAL's
    // job is to write entries, the FsyncAck is a downstream
    // optimisation. Skipping the ack is fine; skipping the write
    // would silently drop committed log entries.
    if s.out_flushed >= 0 && !wire_channels::writable(sys, s.out_flushed) {
        return;
    }

    // Read entry — unless `msg_buf` still holds one we consumed but could not
    // stage last step (see the stash points below). Re-driving it here is what
    // makes the consume-then-fail paths lossless.
    let plen: u16 = if s.stashed_len > 0 {
        let n = s.stashed_len;
        s.stashed_len = 0;
        n
    } else {
        // Pre-routed by the module's intake demux into THIS slot's
        // inbox, so nothing here belongs to another group.
        let Some((msg_type, plen)) = s.inbox_entries.next(sys, &mut s.msg_buf) else {
            return;
        };
        // The entry stream is multiplexed: raft also publishes voter-set
        // updates here so the ledger's union-quorum tally sees a
        // configuration change in FIFO order with the entries whose
        // acks it governs. Lift it to the latch and yield the step —
        // the next step reads the following entry.
        if msg_type == wire::MSG_VOTER_SET_UPDATE {
            if let Some(v) = wire::decode_voter_set_update(&s.msg_buf[..plen as usize]) {
                s.voter_out = Some((v.0, v.1, v.2, v.3));
            }
            return;
        }
        if msg_type != wire::MSG_WAL_ENTRY {
            return;
        }
        plen
    };

    let payload_len = plen as usize;
    // Slice to the declared payload: `msg_buf` outlives each message,
    // so a short frame must not read the last one's tail.
    let Some((term, index)) = wire::decode_term_index(&s.msg_buf[..payload_len]) else {
        return;
    };

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
    let frame_len = wal_seal::frame_len(s, payload_len);
    if s.fixed_segment_active
        && s.cursor > 0
        && s.cursor.saturating_add(frame_len as u32).saturating_add(4) > s.segment_limit
        && !rotate_before_append(s, sys)
    {
        // The segment cannot be closed this step — a batch or a fence is
        // still in flight, or the rotation's fsync is undecided. The record
        // is already out of the channel; stash and re-drive next step.
        s.stashed_len = plen;
        s.stashed_holds = s.stashed_holds.saturating_add(1);
        return;
    }

    // A new key epoch starts at a segment boundary: close the current
    // segment first, so no segment holds frames of two epochs by
    // rotation (a truncation back into an older segment still can).
    if wal_seal::boundary_wanted(s) && s.cursor > 0 && !rotate_before_append(s, sys) {
        s.stashed_len = plen;
        s.stashed_holds = s.stashed_holds.saturating_add(1);
        return;
    }

    let entry_payload_offset = s.cursor.saturating_add(wal_seal::payload_lead(s));
    ensure_segment_open(s, sys);
    if s.fd < 0 {
        if s.no_fs {
            // Explicit ephemeral mode: retain the recent proposal body for
            // the same random-access gap-refetch contract as the disk path,
            // then acknowledge immediately (there is no durability barrier).
            let body_len = payload_len.saturating_sub(16).min(MEMORY_ENTRY_BODY_CAP);
            let slot = memory_slot(index);
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
            note_config(s, index, 0, payload_len);
            note_ledger_ack(s, term, index);
            if s.out_flushed >= 0 {
                let mut ack_buf = [0u8; 17];
                wire::encode_fsync_ack(&mut ack_buf, term, index, s.self_id);
                write_part(s, sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf);
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
    if wal_seal::enabled(s) {
        // Sealed once, here: the staged bytes are what every write and
        // retry of this record sends, so a retry after an unknown outcome
        // repeats the identical ciphertext under the identical nonce.
        let ready = wal_seal::ensure_writable(s, sys);
        if ready != Step::Done || !wal_seal::seal_into(s, sys, pos, payload_len) {
            s.stashed_len = plen;
            s.stashed_holds = s.stashed_holds.saturating_add(1);
            // An allocator-state write still undecided is a hold, not an
            // error: the record is re-driven once it is adopted.
            if ready != Step::Later {
                s.write_errors = s.write_errors.saturating_add(1);
            }
            return;
        }
    } else {
        let crc = {
            let mut c = Crc32c::new();
            c.update(&s.msg_buf[..payload_len]);
            c.finalize()
        };
        s.write_buf[pos..pos + 4].copy_from_slice(&(payload_len as u32).to_le_bytes());
        s.write_buf[pos + 4..pos + 8].copy_from_slice(&crc.to_le_bytes());
        s.write_buf[pos + 8..pos + 8 + payload_len].copy_from_slice(&s.msg_buf[..payload_len]);
    }
    s.write_pos = (pos + frame_len) as u16;

    s.current_term = term;
    s.current_index = index;
    s.cursor += frame_len as u32;
    s.entries_written += 1;
    s.bytes_written += payload_len as u64;
    record_entry_loc(
        s,
        index,
        term,
        s.segment_seq,
        entry_payload_offset,
        payload_len as u32,
    );
    note_config(s, index, 0, payload_len);

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

    if s.fsync_mode == 0 || s.pending_count >= s.group_max_pending || s.staged_terminator {
        flush_batch(s, sys);
    }

    // Segment rotation must flush any pending batch first so the ack
    // is ordered relative to the close. A segment that is not quiescent
    // yet is rotated by the step once it is (see `step`).
    if s.cursor >= s.segment_limit {
        let _ = rotate_before_append(s, sys);
    }
}

/// Nothing is in flight against the live segment: no staged batch, no
/// part-written batch, no fence or fsync undecided, no fence ticket
/// outstanding, no truncation persisting. Only then may it be closed —
/// a fence ticket dies with its descriptor.
fn quiescent(s: &Wal) -> bool {
    !s.has_batch
        && s.write_pos == 0
        && !s.fence_pending
        && s.fence_ring_count == 0
        && !s.sync_pending
        && !s.tc_active
}

/// A flush is part-way through: bytes part-accepted, a terminator staged
/// for a write not yet complete, or a fence or fsync undecided. The step
/// resumes it every step rather than at the next group window.
fn flush_in_flight(s: &Wal) -> bool {
    s.fence_pending || s.sync_pending || s.flush_moved > 0 || s.staged_terminator
}

/// Drain what is in flight and close the live segment so the next
/// append lands in a fresh one. True once the rotation is complete;
/// false while the batch, a fence, or the rotation's own fsync is still
/// undecided (the caller holds its record and the step resumes this).
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn rotate_before_append(s: &mut Wal, sys: &SyscallTable) -> bool {
    if s.rotating {
        return rotate_segment(s, sys);
    }
    if !quiescent(s) {
        flush_batch(s, sys);
        if !quiescent(s) {
            return false;
        }
    }
    rotate_segment(s, sys)
}

/// Close the current segment and advance to the next seq. The caller
/// must have drained any staged batch first (acks are ordered relative
/// to the close).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
///
/// Resumable: the old segment's fsync may be decided on a later step,
/// and until it is `rotating` holds staging (the next record belongs to
/// the next segment) and the step resumes this. Returns whether the
/// rotation is complete. Every acknowledged batch was already fenced, so
/// the fsync here only settles whatever reached the descriptor since;
/// its failure is counted, and the close goes ahead as it always has.
unsafe fn rotate_segment(s: &mut Wal, sys: &SyscallTable) -> bool {
    s.rotating = true;
    if s.fd >= 0 {
        match sync_fd(s, sys) {
            Step::Later => return false,
            Step::Fail => {
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 3, b"[wal] rotate fsync FAIL".as_ptr(), 23);
            }
            Step::Done => {}
        }
    }
    s.rotating = false;
    s.rotations = s.rotations.saturating_add(1);
    close_segment(s, sys);
    wal_seal::close_incarnation(s, sys);

    note_trigger(s, s.current_term, s.current_index);
    if s.out_compaction >= 0 {
        let mut trig = [0u8; 16];
        wire::encode_term_index(&mut trig, s.current_term, s.current_index);
        wire_channels::channel_write_msg(
            sys,
            s.out_compaction,
            wire::MSG_SNAPSHOT_TRIGGER,
            &trig[..16],
        );
    }
    s.segment_seq += 1;
    s.cursor = 0;
    s.seg_high_water = 0;
    s.crc.reset();
    true
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
        if rc == 1 || later(rc) {
            break; // oldest fence still in flight; nothing newer can be acked
        }
        if rc != 0 {
            // A fenced write FAILED — durability gap. Latch fail-stop (see
            // `fence_failed`); the flush entry point holds all further work.
            s.fence_failed = true;
            s.write_errors = s.write_errors.saturating_add(1);
            dev_log(
                sys,
                1,
                b"[wal] FATAL async durable-write failed".as_ptr(),
                38,
            );
            return;
        }
        // Durable — deliver to the ledger component, then emit this
        // fence's FsyncAck (retry next step if channel full).
        note_ledger_ack(s, max_term, max_index);
        if s.out_flushed >= 0 {
            if !wire_channels::writable(sys, s.out_flushed) {
                return; // ack channel full — keep the fence queued, retry later
            }
            let mut ack_buf = [0u8; 17];
            wire::encode_fsync_ack(&mut ack_buf, max_term, max_index, s.self_id);
            write_part(s, sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17]);
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

    if s.write_pos > 0 && write_staged(s, sys, FS_WRITE_ASYNC) != Step::Done {
        return;
    }

    // Open the durability fence covering everything written so far.
    let mut tb = [0u8; 8];
    let rc = (sys.provider_call)(s.fd, FS_FSYNC_SUBMIT, tb.as_mut_ptr(), 8);
    if later(rc) {
        // No fence slot free (or nothing could be opened without waiting):
        // no fence exists. The batch's bytes are already written
        // (write_pos == 0); retry the fence next step. The next fence is
        // cumulative, so it still covers these records and no ack is lost.
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
    // first write is issued, so `fs_async` reflects the backend. Until the
    // provider can answer (it is still mounting) nothing is written: a batch
    // started on one tier must finish on it.
    if !ensure_fs_caps(s, sys) {
        return;
    }

    // A fence failure is a durability gap — latched fail-stop. No further
    // writes, fences, or acks; only a restart recovers (see `fence_failed`).
    if s.fence_failed {
        return;
    }

    // Fence-pipelined async path (config `fence_depth > 1`): keeps multiple
    // fences outstanding so throughput is device-bandwidth-bound rather than
    // 1/fence-latency. Runs every step (reaps even with no staged batch).
    if s.fs_async && s.fence_depth > 1 {
        flush_batch_pipelined(s, sys);
        return;
    }

    if !s.has_batch {
        return;
    }

    if !s.batch_fsynced {
        // ── Async fence poll ──────────────────────────────────────────
        // If a non-blocking durability fence is outstanding, poll it. This
        // is the seam that lets the fsync leave the scheduler step: the
        // write was submitted earlier; here we only observe completion.
        if s.fence_pending {
            let mut tb = s.fence_ticket.to_le_bytes();
            let rc = (sys.provider_call)(s.fd, FS_FSYNC_POLL, tb.as_mut_ptr(), 8);
            if rc == 1 || later(rc) {
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
                dev_log(
                    sys,
                    1,
                    b"[wal] FATAL async durable-write failed".as_ptr(),
                    38,
                );
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
            // Async mode submits via FS_WRITE_ASYNC (pipelined, copied into
            // device DMA slots so `write_buf` is free on return); durability
            // is proven later by the FSYNC_SUBMIT/POLL fence. While an fsync
            // is undecided nothing is staged, so `write_pos` is 0 and this
            // is skipped: no byte reaches the descriptor between a fence's
            // ask and its decision.
            if s.write_pos > 0 {
                let write_op = if s.fs_async { FS_WRITE_ASYNC } else { FS_WRITE };
                if write_staged(s, sys, write_op) != Step::Done {
                    return;
                }
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
                if later(rc) {
                    // No fence slot free (or none could be opened without
                    // waiting) — no fence exists. Retry the fence next step
                    // (the write above already succeeded; write_pos is 0 so
                    // we re-enter here).
                    return;
                }
                // A genuine error opening the fence — latch fail-stop and
                // withhold the ack (see `fence_failed`).
                s.fence_failed = true;
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 1, b"[wal] FATAL fence submit failed".as_ptr(), 31);
                return;
            }

            match sync_fd(s, sys) {
                // Taken, not decided: re-asked, byte-identical, next step.
                // Staging holds meanwhile (`sync_pending`).
                Step::Later => return,
                Step::Fail => {
                    // Deferred group fsync failed — the batch is NOT durable.
                    // Withhold the FsyncAck (commit must not advance past it)
                    // and keep the batch so a later flush asks a fresh fsync
                    // instead of losing durability.
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 3, b"[wal] group fsync FAIL".as_ptr(), 22);
                    return;
                }
                Step::Done => {}
            }
            s.batch_fsynced = true;
        }
    }

    note_ledger_ack(s, s.pending_max_term, s.pending_max_index);
    if s.out_flushed >= 0 {
        if !wire_channels::writable(sys, s.out_flushed) {
            // Channel full: the batch is durable but unacked. Keep it and retry
            // the ack on a later step (next entry or the time-based flush).
            dev_log(sys, 3, b"[wal] group ack deferred".as_ptr(), 24);
            return;
        }
        let mut ack_buf = [0u8; 17];
        wire::encode_fsync_ack(
            &mut ack_buf,
            s.pending_max_term,
            s.pending_max_index,
            s.self_id,
        );
        write_part(s, sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17]);
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
/// A persistent `fd < 0` means the FS is initialising, the admission is
/// still in flight (an open, preallocation, terminator fsync or name
/// fence awaiting its decision), the path is broken (hard error, after
/// the one-shot `wal/` self-heal), or the descriptor was refused after
/// opening because a guarantee the graph asked for could not be had
/// (fixed capacity, or a fenced name). The caller's readiness gate holds
/// entry intake in every case.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ensure_segment_open(s: &mut Wal, sys: &SyscallTable) {
    if s.fd >= 0 {
        return;
    }
    if VOLATILE {
        // The volatile variant selects in-memory retention by
        // design, never as a fallback, so no failure signal.
        s.no_fs = true;
        return;
    }
    if s.open_phase == OPEN_IDLE {
        build_segment_path(s, s.segment_seq);
        s.open_phase = OPEN_CREATE;
    }
    let outcome = open_segment_attempt(s, sys);
    // DIAG: surface the create rc (E_AGAIN=-11 = fat32 not ready, retry;
    // a hard negative = no/failed FS provider; >=0 = disk-backed).
    let shown = if s.fd >= 0 { s.fd } else { s.open_rc };
    if shown != s.dbg_last_open_rc {
        s.dbg_last_open_rc = shown;
        let mut m = [0u8; 32];
        let p = m.as_mut_ptr();
        let tag = b"[wal] open rc=";
        core::ptr::copy_nonoverlapping(tag.as_ptr(), p, tag.len());
        let neg = shown < 0;
        let mut q = tag.len();
        if neg {
            *p.add(q) = b'-';
            q += 1;
        }
        q += fmt_u32_raw(p.add(q), (shown as i64).unsigned_abs() as u32);
        dev_log(sys, 3, p, q);
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
    // failures this counter exists to surface. A descriptor refused
    // AFTER opening was already counted at its refusal site.
    if matches!(outcome, OpenOutcome::OpenFailed) && !s.no_fs_logged {
        s.no_fs_logged = true;
        s.write_errors = s.write_errors.saturating_add(1);
        dev_log(sys, 1, b"[wal] open fail".as_ptr(), 15);
    }
}

/// How one segment-open attempt ended. The distinction the caller needs
/// is whether the PATH failed (a missing parent is worth one self-heal)
/// or the descriptor was refused after opening, where the path is fine
/// and the guarantee is not.
enum OpenOutcome {
    /// `s.fd` holds an admitted descriptor.
    Admitted,
    /// The provider is still initialising, or a step of the admission
    /// awaits its decision; it resumes where it stopped next step.
    Settling,
    /// The open itself failed.
    OpenFailed,
    /// Opened, then refused: preallocation or the name fence. Already
    /// counted and logged at the refusal site.
    Refused,
}

/// Drop a descriptor whose admission was refused, and start the next
/// attempt from the open.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn refuse_open(s: &mut Wal, sys: &SyscallTable) -> OpenOutcome {
    if s.open_fd >= 0 {
        (sys.provider_call)(s.open_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.open_fd = -1;
    }
    s.open_phase = OPEN_IDLE;
    s.fixed_segment_active = false;
    OpenOutcome::Refused
}

/// Drive the admission of `path_buf` as the live segment through its
/// phases: create, reserve fixed capacity where that is configured (with
/// a durable empty-log terminator), fence the name, learn the stale
/// extent. Each phase's request is re-asked, unchanged, until the
/// provider decides it; the descriptor is held in `open_fd` and reaches
/// `s.fd` only when admitted.
///
/// The name fence is the single admission point: the bytes of a fresh
/// segment are reachable by no durable name until its parent-directory
/// entry is published, so a descriptor that cannot be fenced under the
/// strict posture is never handed back, however it was opened.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn open_segment_attempt(s: &mut Wal, sys: &SyscallTable) -> OpenOutcome {
    loop {
        match s.open_phase {
            OPEN_CREATE => {
                let fd = (sys.provider_call)(
                    -1,
                    FS_OPEN_CREATE,
                    s.path_buf.as_mut_ptr(),
                    s.path_len as usize,
                );
                s.open_rc = fd;
                if later(fd) {
                    return OpenOutcome::Settling;
                }
                if fd < 0 {
                    // The provider maps every open failure to one errno, so
                    // a missing `wal/` parent (nothing creates it outside
                    // the test harness) is indistinguishable from a dead
                    // disk — self-heal the parent once and retry. The retry
                    // re-enters the SAME admission, so the preallocation
                    // tier and the name fence gate a self-healed descriptor
                    // exactly as they gate a first-try one.
                    if s.root_path == 0 && !s.mkdir_attempted {
                        s.mkdir_attempted = true;
                        s.open_phase = OPEN_MKDIR;
                        continue;
                    }
                    s.open_phase = OPEN_IDLE;
                    return OpenOutcome::OpenFailed;
                }
                s.open_fd = fd;
                s.open_moved = 0;
                s.open_phase = if s.fixed_segment != 0 {
                    OPEN_PREALLOC
                } else {
                    OPEN_NAME
                };
            }
            OPEN_MKDIR => {
                let mut dir = [0u8; 4];
                dir[..3].copy_from_slice(b"wal");
                let rc = (sys.provider_call)(-1, FS_MKDIR, dir.as_mut_ptr(), 3);
                if later(rc) {
                    return OpenOutcome::Settling;
                }
                // The retried open, not the mkdir's answer, decides. A
                // directory this call minted is a name like any other: it is
                // fenced before a segment inside it is admitted (`OPEN_NAME`).
                if rc == 0 {
                    s.dir_unfenced = true;
                }
                dev_log(sys, 3, b"[wal] mkdir wal".as_ptr(), 15);
                s.open_phase = OPEN_CREATE;
            }
            OPEN_PREALLOC => {
                // Reserve four bytes beyond the configured record limit for
                // the live tail terminator. PREALLOCATE persists physical
                // capacity + fixed file size and leaves the descriptor at
                // offset zero.
                let capacity = s.segment_limit.saturating_add(4);
                let cap = capacity.to_le_bytes();
                let prc =
                    (sys.provider_call)(s.open_fd, FS_PREALLOCATE, cap.as_ptr() as *mut u8, 4);
                if later(prc) {
                    // Provider still initialising, or the reservation is
                    // taken and undecided: the same request is asked again
                    // next step. Admitting the segment now would fix the
                    // mode before the backend could answer.
                    return OpenOutcome::Settling;
                }
                if prc == 0 {
                    // Establish a durable empty-log terminator before
                    // admission. A crash after preallocation but before the
                    // first client append must replay zero entries, never
                    // stale preallocated data.
                    s.open_moved = 0;
                    s.open_phase = OPEN_TERM;
                } else if prc == FS_E_NOSYS {
                    // The backend has no such opcode. Fixed segments are a
                    // protection this provider cannot offer, so the
                    // descriptor remains a normal EOF-sized append file — a
                    // compatibility mode, reported as SEGMENT_MODE_FALLBACK
                    // so it is never mistaken for protected operation.
                    // ENOSYS alone selects this: the open above already
                    // bound a provider, so any other error is that provider
                    // or its device failing, and downgrading the durability
                    // mode on a fault would answer a broken store by
                    // quietly asking less of it.
                    if !s.preallocate_unsupported {
                        s.preallocate_unsupported = true;
                        dev_log(sys, 3, b"[wal] prealloc unsupported".as_ptr(), 26);
                    }
                    s.open_phase = OPEN_NAME;
                } else {
                    // ENOSPC, EIO, ENODEV, or any other refusal from a
                    // provider that DOES implement the opcode — the open
                    // above proves one is bound. A full disk or a failing
                    // device is a failure of this segment, not a licence to
                    // write it in a different mode: refuse admission and
                    // surface the errno.
                    s.preallocate_errno = prc;
                    s.preallocate_failures = s.preallocate_failures.saturating_add(1);
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 1, b"[wal] prealloc FAIL".as_ptr(), 19);
                    return refuse_open(s, sys);
                }
            }
            OPEN_TERM => {
                let zero = [0u8; 4];
                let mut moved = s.open_moved as usize;
                let io = fs_step::write_from(
                    sys.provider_call,
                    FS_WRITE,
                    s.open_fd,
                    zero.as_ptr(),
                    4,
                    &mut moved,
                );
                s.open_moved = moved as u8;
                match io {
                    Io::Later => return OpenOutcome::Settling,
                    Io::Done => s.open_phase = OPEN_REWIND,
                    Io::Fail(_) | Io::End => {
                        s.write_errors = s.write_errors.saturating_add(1);
                        dev_log(sys, 3, b"[wal] prealloc init FAIL".as_ptr(), 24);
                        return refuse_open(s, sys);
                    }
                }
            }
            OPEN_REWIND => {
                let seek = 0i32.to_le_bytes();
                let sr = (sys.provider_call)(s.open_fd, FS_SEEK, seek.as_ptr() as *mut u8, 4);
                if later(sr) {
                    return OpenOutcome::Settling;
                }
                if sr < 0 {
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 3, b"[wal] prealloc init FAIL".as_ptr(), 24);
                    return refuse_open(s, sys);
                }
                s.open_phase = OPEN_FSYNC;
            }
            OPEN_FSYNC => {
                let fr = (sys.provider_call)(s.open_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if later(fr) {
                    return OpenOutcome::Settling;
                }
                if fr != 0 {
                    s.write_errors = s.write_errors.saturating_add(1);
                    dev_log(sys, 3, b"[wal] prealloc init FAIL".as_ptr(), 24);
                    return refuse_open(s, sys);
                }
                s.fixed_segment_active = true;
                s.preallocate_ready_at_ms =
                    dev_millis(sys).saturating_add(s.preallocate_settle_ms as u64);
                s.open_phase = OPEN_NAME;
            }
            OPEN_NAME => {
                // The parent first: a segment's entry is reachable after a
                // power cut only if the `wal/` directory holding it is.
                match fence_wal_dir(s, sys) {
                    Step::Done => {}
                    Step::Later => return OpenOutcome::Settling,
                    Step::Fail => {
                        if !s.name_fence_refused {
                            s.name_fence_refused = true;
                            s.write_errors = s.write_errors.saturating_add(1);
                        }
                        return refuse_open(s, sys);
                    }
                }
                let mut path = [0u8; WAL_PATH_MAX];
                let plen = s.path_len as usize;
                path[..plen].copy_from_slice(&s.path_buf[..plen]);
                match publish_name(s, sys, &mut path, plen) {
                    Step::Later => return OpenOutcome::Settling,
                    Step::Fail => {
                        // The open is retried every step while the fence
                        // refuses, so count the transition into refusal, not
                        // each attempt.
                        if !s.name_fence_refused {
                            s.name_fence_refused = true;
                            s.write_errors = s.write_errors.saturating_add(1);
                        }
                        return refuse_open(s, sys);
                    }
                    Step::Done => {
                        s.open_phase = if s.fixed_segment_active {
                            OPEN_IDLE
                        } else {
                            OPEN_STAT
                        };
                        if s.open_phase == OPEN_IDLE {
                            s.fd = s.open_fd;
                            s.open_fd = -1;
                            return OpenOutcome::Admitted;
                        }
                    }
                }
            }
            OPEN_STAT => {
                // A pre-existing file at this seq (skip_replay orphan, reuse
                // on a provider without UNLINK) may hold stale frames beyond
                // our write cursor. Learn its size so that region is treated
                // like a post-truncate suffix — every append stages a
                // trailing terminator until fresh writes overwrite past it,
                // else replay reads our fresh frames and continues straight
                // into the stale ones.
                let mut stat_buf = [0u8; 8];
                let rc = (sys.provider_call)(s.open_fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
                if later(rc) {
                    return OpenOutcome::Settling;
                }
                if rc >= 0 {
                    let size =
                        u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]]);
                    if size > s.seg_high_water {
                        s.seg_high_water = size;
                    }
                }
                s.fd = s.open_fd;
                s.open_fd = -1;
                s.open_phase = OPEN_IDLE;
                return OpenOutcome::Admitted;
            }
            _ => {
                s.open_phase = OPEN_IDLE;
                return OpenOutcome::Settling;
            }
        }
    }
}

/// Which segment mode this WAL actually achieved, as reported by
/// `WAL_SEGMENT_MODE`. Protected fixed-capacity operation and the
/// compatibility fallback are distinct values, so an operator can tell
/// a node that has the protection from one that merely asked for it.
fn segment_mode(s: &Wal) -> i64 {
    if s.fixed_segment == 0 {
        SEGMENT_MODE_DYNAMIC
    } else if s.preallocate_unsupported {
        SEGMENT_MODE_FALLBACK
    } else {
        SEGMENT_MODE_FIXED
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

/// Whether this WAL writes sealed frames.
pub fn sealed(s: &Wal) -> bool {
    wal_seal::enabled(s)
}

/// The key epoch new sealed records use; 0 until the sealed WAL is
/// ready, and always 0 unsealed.
pub fn key_epoch(s: &Wal) -> u32 {
    if wal_seal::enabled(s) && s.seal.phase == wal_seal::PHASE_READY {
        s.seal.epoch
    } else {
        0
    }
}

/// Ask for a new key epoch, taken at the next segment boundary.
pub fn request_key_rotation(s: &mut Wal) {
    wal_seal::request_rotation(s);
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
pub fn on_snapshot_installed(s: &mut Wal, term: Term, index: Index, m: wire::Membership) {
    if index <= s.current_index {
        return;
    }
    set_membership(s, index, m);
    s.current_term = term;
    s.current_index = index;
    if index.saturating_add(1) > s.entry_ring_min_index {
        s.entry_ring_min_index = index.saturating_add(1);
    }
    // The snapshot's last entry is the only term boundary the log knows.
    s.term_bounds[0] = TermBoundary { index, term };
    s.term_bounds_len = 1;
    note_ledger_ack(s, term, index);
}

/// Write the staged batch (`write_buf[..write_pos]`) at its place in the
/// live segment, resuming after the prefix the provider already accepted
/// (`flush_moved`). `Done` once every staged byte is the provider's; the
/// batch's bytes are then volatile until a fence covers them.
///
/// `cursor` tracks the logical end of the staged records, while the
/// optional four-byte replay terminator is deliberately outside that
/// logical range. Every write seeks explicitly first — no reader shares
/// this descriptor, and nothing assumes its offset between steps — so a
/// resumed write lands exactly after what already moved.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
unsafe fn write_staged(s: &mut Wal, sys: &SyscallTable, op: u32) -> Step {
    let staged_len = s.write_pos as usize;
    let terminator_len = if s.staged_terminator { 4usize } else { 0usize };
    let logical_len = staged_len.saturating_sub(terminator_len);
    let batch_start = s.cursor.saturating_sub(logical_len as u32);
    let mut moved = (s.flush_moved as usize).min(staged_len);
    if moved < staged_len {
        let seek_arg = (batch_start.wrapping_add(moved as u32) as i32).to_le_bytes();
        let seek_rc = (sys.provider_call)(s.fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4);
        if later(seek_rc) {
            return Step::Later;
        }
        if seek_rc < 0 {
            s.write_errors = s.write_errors.saturating_add(1);
            dev_log(sys, 3, b"[wal] group seek FAIL".as_ptr(), 21);
            return Step::Fail;
        }
        let io = fs_step::write_from(
            sys.provider_call,
            op,
            s.fd,
            s.write_buf.as_ptr(),
            staged_len,
            &mut moved,
        );
        s.flush_moved = moved as u16;
        match io {
            // BACKPRESSURE (async ring full, cache full), NOT an error. The
            // accepted prefix belongs to the provider; the rest is resumed
            // after it on a later step. No error count, no durability
            // impact — nothing was acked.
            Io::Later => return Step::Later,
            Io::Fail(_) | Io::End => {
                // A genuine write error: count and surface it. What moved
                // stays moved; a later flush resumes after it.
                s.write_errors = s.write_errors.saturating_add(1);
                dev_log(sys, 1, b"[wal] FATAL group write failed".as_ptr(), 30);
                return Step::Fail;
            }
            Io::Done => {}
        }
    }
    s.write_pos = 0;
    s.flush_moved = 0;
    s.staged_terminator = false;
    Step::Done
}

/// Fsync the live segment and fold the time from first ask to decision
/// into the `clustor.wal.fsync_latency_ms` histogram. Every fsync of the
/// live descriptor routes through here, so the histogram covers strict
/// per-entry, group-deferred, truncation and rotation fsyncs alike.
///
/// The fsync is non-blocking: `Later` keeps `sync_pending` set, and the
/// caller re-asks the byte-identical request on a later step. Until it is
/// decided nothing writes through `fd` (see `sync_pending`). `Done` only
/// on the provider's 0 — the descriptor's bytes and size are durable. A
/// failure is not folded into the histogram (it isn't a durability
/// measurement), and callers withhold whatever the fsync gated.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn sync_fd(s: &mut Wal, sys: &SyscallTable) -> Step {
    if s.fd < 0 {
        s.sync_pending = false;
        return Step::Fail;
    }
    if !s.sync_pending {
        s.sync_start_us = dev_micros(sys);
    }
    let rc = (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
    if later(rc) {
        s.sync_pending = true;
        return Step::Later;
    }
    s.sync_pending = false;
    if rc != 0 {
        return Step::Fail;
    }
    let elapsed = dev_micros(sys).wrapping_sub(s.sync_start_us);
    let b = wire::hist::bucket(&wire::hist::FSYNC_LATENCY_US, elapsed);
    s.fsync_buckets[b] = s.fsync_buckets[b].saturating_add(1);
    Step::Done
}

/// Close the current segment and prepare for rotation.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Wal` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn close_segment(s: &mut Wal, sys: &SyscallTable) {
    if s.fd >= 0 {
        // CLOSE never waits and reports no write-back: everything this
        // descriptor carried that durability rests on was fenced first.
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
    s.sync_pending = false;
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
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS {
        return;
    }
    s.last_metrics_ms = now;

    // `[wal] hb` — steady-state liveness on the foundation-module
    // heartbeat cadence. Survives log_net's history-skip (drain_net
    // seeds TAIL_NET=HEAD on first call), which discards init-time
    // one-shot markers. Fires regardless of out_metrics wiring.
    let mut hb = [0u8; 160];
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
    // The rotation question, answered rather than inferred: the limit the
    // params gave, where the cursor stands, how often this boot rotated.
    pos += emit_field(hb.as_mut_ptr(), pos, b" lim=", s.segment_limit);
    pos += emit_field(hb.as_mut_ptr(), pos, b" cur=", s.cursor);
    pos += emit_field(hb.as_mut_ptr(), pos, b" rot=", s.rotations);
    dev_log(sys, 3, hb.as_ptr(), pos);

    // The below-floor entry scan (cold reads that serve apply and the
    // replicator from disk): a scan that never finds, or never replies,
    // stops every apply behind it, and downstream that reads only as
    // silence.
    let mut sc = [0u8; 224];
    let mut sp = 0usize;
    sp += emit_field(
        sc.as_mut_ptr(),
        sp,
        b"[wal] scan act=",
        s.scan_active as u32,
    );
    sp += emit_field(sc.as_mut_ptr(), sp, b" found=", s.scan_found as u32);
    sp += emit_field(sc.as_mut_ptr(), sp, b" tgt=", s.scan_target as u32);
    sp += emit_field(sc.as_mut_ptr(), sp, b" seg=", s.scan_seg);
    sp += emit_field(sc.as_mut_ptr(), sp, b" oldest=", s.oldest_segment_seq);
    sp += emit_field(sc.as_mut_ptr(), sp, b" walked=", s.scan_last_index as u32);
    sp += emit_field(sc.as_mut_ptr(), sp, b" nf=", s.entryreq_notfound);
    sp += emit_field(sc.as_mut_ptr(), sp, b" nf_open=", s.entryreq_open_fail);
    sp += emit_field(
        sc.as_mut_ptr(),
        sp,
        b" ring_min=",
        s.entry_ring_min_index as u32,
    );
    sp += emit_field(
        sc.as_mut_ptr(),
        sp,
        b" rep_first=",
        s.replay_first_index as u32,
    );
    sp += emit_field(sc.as_mut_ptr(), sp, b" floor=", s.compact_floor as u32);
    // The last index asked for, the log's own position, the ring's reach,
    // and what the ring holds in that index's slot: a miss at or above
    // the floor is otherwise unexplainable from outside.
    let req = s.last_req_index;
    sp += emit_field(sc.as_mut_ptr(), sp, b" req=", req as u32);
    sp += emit_field(sc.as_mut_ptr(), sp, b" cur=", s.current_index as u32);
    sp += emit_field(
        sc.as_mut_ptr(),
        sp,
        b" rmax=",
        s.entry_ring_max_index as u32,
    );
    let held = s.entry_ring[(req & ENTRY_LOC_RING_MASK) as usize].index;
    sp += emit_field(sc.as_mut_ptr(), sp, b" slot=", held as u32);
    dev_log(sys, 3, sc.as_ptr(), sp);

    if s.out_metrics < 0 {
        return;
    }

    // Typed metric samples: scalar counters/gauges plus the fsync-latency
    // histogram. Each sample is its own MSG_METRIC_SAMPLE so the telemetry
    // component aggregates without a per-module parser. The legacy
    // MSG_METRICS envelope is still emitted below for observers that parse
    // it.
    let mid = wire::SOURCE_ID_WAL;
    let pid = s.partition_id;
    let kc = wire::METRIC_KIND_COUNTER;
    let kg = wire::METRIC_KIND_GAUGE;
    let kh = wire::METRIC_KIND_HISTOGRAM;
    let scalars: [(u16, u8, i64); 28] = [
        (
            wire::metric_ids::WAL_ENTRIES_WRITTEN,
            kc,
            i64::from(s.entries_written),
        ),
        (
            wire::metric_ids::WAL_WRITE_ERRORS,
            kc,
            i64::from(s.write_errors),
        ),
        (
            wire::metric_ids::WAL_CHECKSUM_FAILURES,
            kc,
            i64::from(s.checksum_failures),
        ),
        (
            wire::metric_ids::WAL_TRUNCATIONS,
            kc,
            i64::from(s.truncations),
        ),
        (
            wire::metric_ids::WAL_BYTES_WRITTEN,
            kc,
            s.bytes_written as i64,
        ),
        (
            wire::metric_ids::WAL_SEGMENT_SEQ,
            kg,
            i64::from(s.segment_seq),
        ),
        // saturation gauge: entries written but not yet group-fsynced.
        (
            wire::metric_ids::WAL_PENDING_DEPTH,
            kg,
            i64::from(s.pending_count),
        ),
        // Diagnostic: last FS_OPEN_CREATE rc (>=0 disk, <0 in-memory fallback).
        (
            wire::metric_ids::WAL_OPEN_RC,
            kg,
            i64::from(s.dbg_last_open_rc),
        ),
        (wire::metric_ids::WAL_STEPS, kc, s.dbg_steps as i64),
        (wire::metric_ids::WAL_REPLAY_HW, kg, s.replay_hw_sent as i64),
        (
            wire::metric_ids::WAL_REPLAYED,
            kc,
            i64::from(s.replayed_count),
        ),
        (
            wire::metric_ids::WAL_REPLAY_FSIZE,
            kg,
            i64::from(s.replay_first_size),
        ),
        (
            wire::metric_ids::WAL_ENTRYREQ_SERVED,
            kc,
            i64::from(s.entryreq_served),
        ),
        (
            wire::metric_ids::WAL_ENTRYREQ_NOTFOUND,
            kc,
            i64::from(s.entryreq_notfound),
        ),
        (
            wire::metric_ids::WAL_INPUT_BUDGET_BYTES,
            kg,
            i64::from(s.input_budget_bytes),
        ),
        (
            wire::metric_ids::WAL_PUMP_RECORDS,
            kg,
            i64::from(s.pump_records),
        ),
        (
            wire::metric_ids::WAL_CONTINUITY_ERRORS,
            kc,
            i64::from(s.continuity_errors),
        ),
        (
            wire::metric_ids::WAL_STASHED_HOLDS,
            kc,
            i64::from(s.stashed_holds),
        ),
        (
            wire::metric_ids::WAL_CURRENT_INDEX,
            kg,
            s.current_index as i64,
        ),
        (
            wire::metric_ids::WAL_FAULT_EXPECTED,
            kg,
            s.fault_expected as i64,
        ),
        (wire::metric_ids::WAL_FAULT_GOT, kg, s.fault_got as i64),
        (
            wire::metric_ids::WAL_TRUNCATE_FAILURES,
            kc,
            s.truncate_failures as i64,
        ),
        (wire::metric_ids::WAL_SEGMENT_MODE, kg, segment_mode(s)),
        (
            wire::metric_ids::WAL_PREALLOCATE_FAILURES,
            kc,
            i64::from(s.preallocate_failures),
        ),
        (
            wire::metric_ids::WAL_PREALLOCATE_ERRNO,
            kg,
            i64::from(s.preallocate_errno),
        ),
        (
            wire::metric_ids::WAL_NAME_FENCE,
            kg,
            i64::from(s.name_fence_probe),
        ),
        (
            wire::metric_ids::WAL_NAME_UNFENCED,
            kc,
            i64::from(s.name_unfenced),
        ),
        (
            wire::metric_ids::WAL_COMPACT_FLOORED,
            kc,
            i64::from(s.compact_floored),
        ),
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

    if wire_channels::writable(sys, s.out_metrics) {
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
    if !wire_channels::writable(sys, s.out_metrics) {
        return;
    }
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
