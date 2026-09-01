//! snapshot — per-partition snapshot manifest persistence and
//! transfer.
//!
//! Triggers arrive from the [`wal`](super::wal) component (delivered
//! in-module at segment rotation) and from the external `trigger`
//! port (admin ops, downstream coordinators). The DEK epoch is owned
//! by the [`keys`](super::keys) component and handed in each step.
//! Everything else — durable formats, chunked install transfer, the
//! app snapshot round-trip — is documented on the struct below.
//!
//! Snapshot files:
//!   partition_id == 0  →  `wal/p0000_snap_<NNNNNNNN>.bin`
//!   partition_id == N  →  `wal/p<NNNN>_snap_<NNNNNNNN>.bin`
//!   root_path == 1     →  `<p:1hex><idx:7hex>.SNP` at the FS root.

use super::abi::SyscallTable;
use super::collections::Crc32c;
use super::types::{Index, Term};
use super::{dev_log, dev_millis, wire, wire_channels};

const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
/// Write-side opener. `FS_OPEN` is read-only-if-exists per the FS
/// contract (see `target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs`);
/// snapshot manifests are created from scratch, so persistence needs
/// the write tier.
const FS_OPEN_CREATE: u32 = 0x0909;
/// Remove a file by path (`modules/sdk/contracts/storage/fs.rs::UNLINK`).
/// Used to retire the previous snapshot file once a newer one is durable;
/// gated on the provider's `caps::UNLINK` bit (see `fs_unlink_supported`).
const FS_UNLINK: u32 = 0x090A;
/// FS capability-discovery opcode + the `UNLINK` bit
/// (`modules/sdk/contracts/storage/fs.rs::{CAPS, caps::UNLINK}`).
const FS_CAPS: u32 = 0x09FF;
const FS_CAP_UNLINK: u32 = 1 << 5;
/// Durable publication of a parent-directory entry
/// (`modules/sdk/contracts/storage/fs.rs::{FSYNC_NAME, caps::FSYNC_NAME}`).
/// A snapshot artefact and its pointer slots are recovery roots: their
/// bytes being durable is worthless if the name that finds them is not.
const FS_FSYNC_NAME: u32 = 0x0912;
const FS_CAP_FSYNC_NAME: u32 = 1 << 11;

/// `name_fence` postures — see `durability/mod.rs` param 15.
const NAME_FENCE_STRICT: u8 = 1;

/// `name_fence_probe` / `SNAP_NAME_FENCE` dispositions.
const NAME_FENCE_UNPROBED: u8 = 0;
const NAME_FENCE_PRESENT: u8 = 1;
const NAME_FENCE_ABSENT: u8 = 2;
/// FS E_AGAIN: the provider exists but is still initialising (fat32
/// reading the BPB/GPT/root on a cold boot). Distinct from ENODEV/ENOSYS
/// ("no provider"): an E_AGAIN persist failure must NOT be treated as the
/// in-memory-graph case, or we'd signal an install (and let raft compact
/// the WAL) against a manifest that never landed.
const FS_E_AGAIN: i32 = -11;

// ── Boot-restore phases ───────────────────────────────────────────────
/// Read the pointer sidecar naming the durable local snapshot.
const BOOT_PTR: u8 = 0;
/// Load + CRC-validate the snapshot file the pointer names.
const BOOT_LOAD: u8 = 1;
/// Replay the app body to the state machine (RESET + chunks).
const BOOT_EMIT: u8 = 2;
/// Tell consensus the snapshot base exists (`MSG_SNAPSHOT_INSTALLED`):
/// the wal tail starts ABOVE the snapshot index, and without the base
/// marker raft sees a log with no floor and never elects.
const BOOT_SIGNAL: u8 = 3;
/// Restore finished (or nothing to restore) — wal replay may proceed.
const BOOT_DONE: u8 = 4;
/// "No FS provider at all" errnos (ENODEV / ENOSYS). ONLY these justify
/// the in-memory-graph install path: any other open/write failure (EIO,
/// ENOSPC, E_AGAIN…) means an FS exists but the artefact did not land,
/// and signalling an install would let raft compact the WAL against a
/// snapshot that is not on disk.
const FS_E_NODEV: i32 = -19;
const FS_E_NOSYS: i32 = -38;

/// `module_step` return code for `StepOutcome::Burst` (kernel ABI:
/// 0=Continue, 1=Done, 2=Burst, 3=Ready). Returned from a step that
/// performed a synchronous disk op (snapshot persist, chunk ingest,
/// boot restore): a cold first-touch FS_OPEN_CREATE/write on this NVMe
/// runs tens to >100 ms and would trip the step guard. Burst discards
/// the step's elapsed instead of checking it, then re-arms with the 8×
/// budget. Work per step is bounded (≤4 triggers), so this is a
/// headroom grant, not unbounded I/O.
const STEP_BURST: i32 = 2;

const SNAP_PATH_MAX: usize = 64;

/// Number of snapshot-pointer slots. Each slot is a SEPARATE FILE, so
/// the two records never share a read-modify-write unit: a publish
/// rewrites one file's data cluster and a torn sector there damages
/// that slot alone. Two records inside one file would share the unit
/// and tear together.
///
/// That covers the records, not the namespace. On FAT32 both directory
/// entries may sit in one directory sector, so creating the second slot
/// mutates a sector the first entry already occupies.
/// `materialize_snap_ptr_slots` therefore creates and sizes BOTH files
/// and fences BOTH names before any non-neutral generation is adopted,
/// so that mutation happens while there is nothing to lose. Afterwards
/// a publish rewrites the same 32 bytes in place, leaving the size and
/// cluster chain unchanged and the directory sector untouched.
const SNAP_PTR_SLOTS: usize = 2;
/// Pointer candidates BOOT_LOAD may try: both slots plus the flat
/// record.
const SNAP_PTR_CANDIDATES: usize = SNAP_PTR_SLOTS + 1;

/// Pointer slot magic and format id.
const MAGIC_SNAP_PTR: u32 = 0x5254_5053; // "SPTR" little-endian as bytes
const SNAP_PTR_FORMAT_ID: u16 = 1;

/// Pointer slot size.
///
/// Layout (32 bytes):
///   `[magic:u32][format:u16][pad:u16][generation:u64][index:u64]
///    [reserved:4][crc32c:u32]`
///
/// The CRC covers bytes `0..28`. `pad` and `reserved` are written zero
/// and covered by the CRC, so a decoder finding them non-zero under a
/// known `format` id refuses the record; a future field claims them
/// behind a new format id rather than by reinterpreting a zero.
const SNAP_PTR_SIZE: usize = 32;
const SNAP_PTR_CRC_OFF: usize = 28;
/// Flat pointer: a bare 8-byte index with no magic, generation or
/// CRC. Tried last at boot, so a store holding this shape still
/// resolves its snapshot.
const SNAP_PTR_FLAT_SIZE: usize = 8;

const MAGIC_SNAP: u32 = 0x534E_4150; // "SNAP" little-endian as bytes

/// Durable snapshot file layout (crash-atomic without an FS rename, which the
/// FS contract does not expose):
///   `[MAGIC_SNAP:u32][partition:u16][rsvd:u16][term:u64][last_idx:u64]`
///   `[last_term:u64][dek_epoch:u32][body_len:u32]` = `SNAP_HDR_LEN` bytes,
///   then `body[body_len]`, then `[body_crc32c:u32][END_MAGIC:u32]`.
/// Written sequentially in one pass with a SINGLE trailing fsync, so a torn
/// or interrupted write never leaves a readable trailer — `load_snapshot`
/// rejects any file whose `END_MAGIC` or CRC doesn't check out and the node
/// falls back to its log. Snapshot filenames are index-keyed and indices are
/// monotonic, so a fresh install never overwrites a shorter valid file.
const SNAP_HDR_LEN: usize = 40;
const SNAP_TRAILER_LEN: usize = 8;
/// Read granularity for the finalise-time CRC pass and the boot-time
/// integrity check. A stack buffer, not module state — snapshot bodies
/// are streamed, never held.
const SNAP_VERIFY_CHUNK: usize = 1024;
const END_MAGIC_SNAP: u32 = 0x534E_4445; // "ENDS"

/// Largest chunk we emit on the wire. Bounded so a single envelope
/// fits inside MAX_PAYLOAD (64 KiB - 1) with room for the
/// `MSG_INSTALL_SNAPSHOT` 33-byte header.
const MAX_CHUNK_BODY: usize = 4 * 1024;

/// How many steps we'll wait for an app snapshot body before giving up
/// on the capture. At the rig's 1 ms tick this is ~2 s — long enough
/// for a worker busy draining a commit batch, short enough that a
/// wedged app only costs one rotation's snapshot.
const APP_CAPTURE_TIMEOUT_TICKS: u32 = 2000;

const METRICS_INTERVAL_MS: u64 = 1000;

#[repr(C)]
pub struct Snapshot {
    /// Per-slot inboxes for the consensus-facing inputs. Filled by the
    /// durability module's intake demux; one instance serves K groups,
    /// so each of these edges names its group.
    pub inbox_import: super::inbox::Inbox,
    pub inbox_install_req: super::inbox::Inbox,
    pub in_import: i32, // in[4]: import chunks from replicator (InstallSnapshot RPC)
    pub in_trigger: i32, // in[5]: external SnapshotTrigger (wal rotation arrives in-module)
    pub in_install_request: i32, // in[6]: MSG_SNAPSHOT_INSTALL_REQUEST from replicator
    pub out_export: i32, // out[6]: export chunks to replicator (peer transfer)
    pub out_manifest: i32, // out[7]: manifest auth to peer_router (deferred)
    pub out_metrics: i32, // shares the wal's out[4] metrics port (see mod.rs)
    pub out_installed: i32, // out[8]: MSG_SNAPSHOT_INSTALLED to consensus

    // Most recent snapshot (term, index) we persisted. Used to answer
    // on-demand install requests from `replicator`.
    last_snapshot_term: u64,
    last_snapshot_index: u64,

    /// Seam latch → wal (monotone latest-wins, drained by the dispatch
    /// table): `(last_included_term, last_included_index)` of an
    /// accepted peer install, so the wal fast-forwards its append
    /// contract past the prefix the snapshot subsumes.
    pub wal_fast_forward: (u64, u64),
    pub wal_fast_forward_dirty: bool,

    /// Seam ← wal (latest-wins): the wal's `(term, index)` high-water,
    /// delivered by the dispatch table each step via
    /// [`on_wal_high_water`]. The capture point for a demand-triggered
    /// snapshot.
    wal_high_water: (Term, Index),

    /// Boot-restore state machine (`BOOT_*`). At boot the persisted
    /// local snapshot (pointer sidecar → snapshot file) is loaded and
    /// its app body replayed to the state machine BEFORE the wal
    /// component replays its (possibly compacted) tail — otherwise the
    /// app rebuilds only the tail and everything below the snapshot is
    /// silently missing. `mod.rs` holds `wal::step` until this reports
    /// done.
    boot_phase: u8,
    /// Snapshot index named by the pointer slot currently being tried
    /// (BOOT_PTR → BOOT_LOAD).
    boot_ptr_index: u64,
    /// Candidate snapshot indices collected at BOOT_PTR, ordered by
    /// pointer generation (newest first, the flat pointer last). BOOT_LOAD
    /// walks them in order: a pointer is only believed once the snapshot
    /// artefact it names is present and passes its own CRC, so a pointer that
    /// survived a crash its snapshot did not never becomes the recovery root.
    boot_ptr_candidates: [u64; SNAP_PTR_CANDIDATES],
    /// Number of populated entries in `boot_ptr_candidates`.
    boot_ptr_count: u8,
    /// Next candidate BOOT_LOAD will try.
    boot_ptr_next: u8,
    /// Pointer slot (0/1) holding the highest valid generation. The next
    /// publish targets the other slot.
    /// Both pointer slot files exist at full size with their names
    /// fenced, so every later publish is a pure in-place data
    /// overwrite. See `materialize_snap_ptr_slots`.
    snap_ptr_slots_materialized: bool,
    snap_ptr_slot: u8,
    /// Generation of the record in `snap_ptr_slot`.
    snap_ptr_generation: u64,

    pub partition_id: u16,
    /// Param `root_path`: 1 = 8.3 snapshot names at the FS root (bare-metal
    /// FAT32); 0 = `wal/p<NNNN>_snap_<NNNNNNNN>.bin` (linux layout).
    pub root_path: u8,
    /// FS `caps::UNLINK` probe cache for previous-snapshot retirement:
    /// 0 = unprobed, 1 = supported, 2 = unsupported. See
    /// `fs_unlink_supported`.
    fs_unlink_probe: u8,
    /// FS `caps::FSYNC_NAME` probe cache: `NAME_FENCE_UNPROBED`,
    /// `NAME_FENCE_PRESENT`, `NAME_FENCE_ABSENT`.
    name_fence_probe: u8,
    /// Param `name_fence` (0 = auto, 1 = strict), fanned in from the
    /// composite so segments, snapshots and pointer slots share one
    /// posture.
    pub name_fence: u8,
    /// Counter behind `SNAP_NAME_UNFENCED`.
    name_unfenced: u32,

    // State
    pub dek_epoch: u32,
    snapshots_taken: u32,
    chunks_imported: u32,
    /// Snapshot triggers we declined: a capture already in flight, an
    /// app body that failed to land. The trigger itself is dropped and
    /// the leader's next rotation re-fires it.
    triggers_deferred: u32,
    /// Total snapshot body bytes durably written to disk (across installs).
    snap_bytes_written: u64,
    /// Count of durable-install failures (OPEN_CREATE failed, short write, or
    /// fsync error). Non-zero means a received snapshot was NOT installed —
    /// the install signal is withheld so consensus never trusts a torn body.
    install_failures: u32,

    // Metrics
    last_metrics_ms: u64,
    /// Monotonic ms when the current install's first chunk arrived;
    /// used to time `clustor.snapshot.transfer_seconds`.
    install_start_ms: u64,
    /// `clustor.snapshot.transfer_seconds` cumulative bucket counts: wall
    /// time from first install chunk to `done`, ms-classified against
    /// `wire::hist::SNAPSHOT_MS`.
    transfer_buckets: [u32; wire::hist::SNAPSHOT_MS.len() + 1],

    // In-flight install state (single-stream, fail-open if interleaved):
    in_progress_term: u64,
    in_progress_last_idx: u64,
    in_progress_last_term: u64,
    in_progress_active: bool,
    /// Next expected offset for the in-progress install. A chunk
    /// arriving with a different offset signals reordering or loss;
    /// we discard the install attempt and wait for the leader to
    /// re-send from offset 0.
    in_progress_offset: u64,
    /// Body length of the snapshot most recently written or read. The
    /// BODY ITSELF is never held in module state — it streams to and
    /// from the snapshot file, so its size is bounded by the
    /// filesystem. This is only the length the app-restore stream and
    /// the "is there a body to replay" checks need.
    body_len: u32,

    // ── Streaming snapshot writer ──────────────────────────────────
    //
    // Bodies stream straight to file rather than accumulating in module
    // state. A resident staging buffer would cap an installed snapshot at
    // its own size, and that cap becomes a cap on how far behind a replica
    // can fall and still be caught up by install.
    //
    // The one wrinkle is the CRC: it covers `header || body`, but
    // `body_len` is a header field not known until the last chunk
    // arrives. Rather than change the on-disk format or make every
    // producer declare its length up front, the finaliser seeks back,
    // writes the true header, then reads the body back once to compute
    // the CRC. That read is sequential over a file written moments
    // earlier, and snapshots are infrequent; it buys ONE code path
    // shared by the install and local-capture producers, with no format
    // change and no wire change.
    /// True when the in-flight install has a real FS provider behind
    /// it. An in-memory graph installs the (term, index) with no
    /// artefact; anything else must reach disk before the install is
    /// signalled.
    install_had_fs: bool,
    /// Open write fd of a snapshot being streamed, or -1.
    wfd: i32,
    /// Bytes of body written so far through `snap_append`.
    wbody: u32,
    /// Identity of the snapshot being streamed, for the final header.
    wterm: Term,
    windex: Index,
    wlast_term: Term,

    // ── App state-machine snapshot round-trip ─────────────────────
    /// Port to the application state machine (request + restore) and
    /// the port its encoded body comes back on. Both -1 when the graph
    /// has no app snapshot provider, in which case snapshots stay
    /// manifest-only and this whole path is inert.
    pub out_app_ctl: i32,
    pub in_app_body: i32,
    /// A capture has been requested and we're waiting for the body.
    /// Triggers arriving meanwhile are dropped (the next rotation
    /// re-fires), so this never queues.
    app_capture_pending: bool,
    /// Ticks since the request went out — bounds the wait so a wedged
    /// or silent app can't block snapshotting forever.
    app_capture_ticks: u32,
    app_bodies_received: u32,
    app_captures_timed_out: u32,
    /// Body staged for the next install emit. Owned by state (not a
    /// borrow of msg_buf) so `finalize_snapshot` can take `&mut s`.
    /// True when the in-flight capture has a real FS provider behind it.
    capture_had_fs: bool,
    app_body_len: u32,

    // Scratch
    path_buf: [u8; SNAP_PATH_MAX],
    msg_buf: [u8; 8192],
}

pub unsafe fn init(s: &mut Snapshot) {
    s.inbox_import = super::inbox::Inbox::new();
    s.inbox_install_req = super::inbox::Inbox::new();
    s.in_import = -1;
    s.in_trigger = -1;
    s.in_install_request = -1;
    s.out_export = -1;
    s.out_manifest = -1;
    s.out_metrics = -1;
    s.out_installed = -1;
    s.in_app_body = -1;
    s.out_app_ctl = -1;
    s.last_snapshot_term = 0;
    s.last_snapshot_index = 0;
    s.wal_fast_forward = (0, 0);
    s.wal_fast_forward_dirty = false;
    s.wal_high_water = (0, 0);
    s.boot_phase = BOOT_PTR;
    s.boot_ptr_index = 0;
    s.boot_ptr_candidates = [0; SNAP_PTR_CANDIDATES];
    s.boot_ptr_count = 0;
    s.boot_ptr_next = 0;
    s.snap_ptr_slots_materialized = false;
    s.snap_ptr_slot = 0;
    s.snap_ptr_generation = 0;
    s.partition_id = 0;
    s.root_path = 0;
    s.fs_unlink_probe = 0;
    s.name_fence_probe = NAME_FENCE_UNPROBED;
    s.name_fence = 0;
    s.name_unfenced = 0;
    s.dek_epoch = 0;
    s.snapshots_taken = 0;
    s.chunks_imported = 0;
    s.triggers_deferred = 0;
    s.snap_bytes_written = 0;
    s.install_failures = 0;
    s.last_metrics_ms = 0;
    s.install_start_ms = 0;
    s.transfer_buckets = [0u32; wire::hist::SNAPSHOT_MS.len() + 1];
    s.in_progress_term = 0;
    s.in_progress_last_idx = 0;
    s.in_progress_last_term = 0;
    s.in_progress_active = false;
    s.in_progress_offset = 0;
    s.body_len = 0;
    s.install_had_fs = false;
    s.capture_had_fs = false;
    s.wfd = -1;
    s.wbody = 0;
    s.wterm = 0;
    s.windex = 0;
    s.wlast_term = 0;
    s.app_capture_pending = false;
    s.app_capture_ticks = 0;
    s.app_bodies_received = 0;
    s.app_captures_timed_out = 0;
    s.app_body_len = 0;
}

/// Deliver the wal component's current `(term, index)` high-water.
/// Message-shaped seam (§8 rule 2): the same payload a rotation
/// trigger carries, in the same direction, so `snapshot` keeps its
/// port-only `step` signature and stays liftable into a standalone
/// module without edits inside the component.
pub fn on_wal_high_water(s: &mut Snapshot, term: Term, index: Index) {
    s.wal_high_water = (term, index);
}

/// Handle one snapshot trigger at `(term, index)` — the single
/// admission point for triggers regardless of origin (the wal
/// component's segment rotation, or the external `trigger` port).
/// Returns whether the step performed a synchronous disk op.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_trigger(s: &mut Snapshot, sys: &SyscallTable, term: Term, index: Index) -> bool {
    // No retention gate here. A snapshot is the STATE at `index` and
    // is always safe to take; what a retention floor protects is the
    // ENTRIES below it, and those are retired by the wal's segment
    // compaction, which is where the floor is applied
    // (`wal::compact_before`). Gating the snapshot instead held raft's
    // compaction point back to the application's retention window —
    // days of log to replay at boot for a broker with a Kafka
    // retention policy.
    // With an app state machine wired, the snapshot is only
    // meaningful once we hold its state. Ask for a capture and stop
    // here; the body's own (term, index) — which may have advanced
    // past this trigger — drives finalisation in the app-body path.
    // BOTH capture ports must be wired: with `out_app_ctl` alone the
    // request can never be answered and `app_capture_pending` never
    // clears (the timeout lives on the reply drain), deferring every
    // future snapshot forever.
    if s.out_app_ctl >= 0 && s.in_app_body < 0 {
        dev_log(sys, 2, b"[snap] app body port unwired".as_ptr(), 28);
    }
    if s.out_app_ctl >= 0 && s.in_app_body >= 0 {
        if s.app_capture_pending {
            // One capture in flight at a time; the next rotation
            // re-fires this trigger.
            s.triggers_deferred = s.triggers_deferred.saturating_add(1);
            return false;
        }
        if request_app_capture(s, sys, term, index) {
            s.app_capture_pending = true;
            s.app_capture_ticks = 0;
        }
        return false;
    }
    // No app provider on this graph — manifest-only snapshot.
    s.app_body_len = 0;
    finalize_local_snapshot(s, sys, term, index);
    true
}

/// Per-step bound: ≤4 frames per input family (retention floors,
/// external triggers, install requests, import chunks) + at most one
/// app-body chunk + at most one demand-triggered capture. Returns
/// whether this step performed a synchronous disk op whose cold
/// first-touch can exceed the step deadline (the module returns Burst
/// for it — see the composite dispatch).
///
/// The wal's current high-water is delivered beforehand by
/// [`on_wal_high_water`]; it is the capture point for a
/// demand-triggered snapshot, exactly what a rotation trigger would
/// carry.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(s: &mut Snapshot, sys: &SyscallTable) -> bool {
    let (hw_term, hw_index) = s.wal_high_water;
    let mut cold_fs = false;

    // 1. External snapshot triggers.
    if s.in_trigger >= 0 {
        for _ in 0..4 {
            let Some((msg_type, plen)) = wire_channels::next_msg(sys, s.in_trigger, &mut s.msg_buf)
            else {
                break;
            };
            let trig = if msg_type == wire::MSG_SNAPSHOT_TRIGGER {
                wire::decode_term_index(&s.msg_buf[..plen as usize])
            } else {
                None
            };
            if let Some((term, index)) = trig {
                if on_trigger(s, sys, term, index) {
                    cold_fs = true;
                }
            }
        }
    }

    // 2b. On-demand install requests from replicator. When a
    //     follower's next_index falls below our WAL retention floor,
    //     the replicator hits a NOT_FOUND WAL reply and asks us to
    //     re-broadcast the most recent snapshot.
    //
    //     A request arriving BEFORE any snapshot exists triggers a
    //     capture on demand at the wal high-water. Without this, a
    //     graph whose snapshot cadence has not fired yet (rotation
    //     triggers at segment_bytes of appends; a volatile wal in
    //     particular never rotates) leaves every install request
    //     unread and the lagging follower livelocks on NOT_FOUND
    //     refetches forever.
    if s.in_install_request >= 0 {
        let mut demand_trigger = false;
        for _ in 0..4 {
            let Some((msg_type, plen)) = s.inbox_install_req.next(sys, &mut s.msg_buf) else {
                break;
            };
            if msg_type != wire::MSG_SNAPSHOT_INSTALL_REQUEST || (plen as usize) < 1 {
                continue;
            }
            if s.last_snapshot_index > 0 {
                // The install is broadcast, not routed: the request's
                // target byte is decoded but unused until a routed
                // snapshot port exists.
                emit_install_chunk(s, sys, s.last_snapshot_term, s.last_snapshot_index);
            } else {
                demand_trigger = true;
            }
        }
        // At most one demand capture per step, and none while an app
        // capture is already in flight (requests re-arrive every
        // follower renudge; funnelling them all into on_trigger would
        // spam triggers_deferred without adding work).
        if demand_trigger && !s.app_capture_pending && hw_index > 0 {
            // Debug, not info: install requests re-arrive on every
            // follower renudge, and a blocked retention floor or a
            // refused app capture leaves this branch re-entered.
            dev_log(sys, 4, b"[snap] demand trigger".as_ptr(), 21);
            if on_trigger(s, sys, hw_term, hw_index) {
                cold_fs = true;
            }
            // Manifest-only graphs finalise synchronously: the NEXT
            // request (the follower re-requests on a steady cadence)
            // is served from `last_snapshot_index`. App-state graphs
            // finalise via the app-body path above.
        }
    }

    // 2c. App state-machine snapshot bodies. The body's
    //     own (term, index) is authoritative — the app may have
    //     applied past the trigger that prompted the capture.
    if s.in_app_body >= 0 && s.app_capture_pending {
        if wire_channels::readable(sys, s.in_app_body) {
            let (msg_type, plen) =
                wire_channels::channel_read_msg(sys, s.in_app_body, &mut s.msg_buf);
            let pl = plen as usize;
            let chunk = if msg_type == wire::MSG_APP_SNAPSHOT_CHUNK && pl >= wire::APP_SNAPSHOT_HDR
            {
                wire::decode_term_index(&s.msg_buf[..pl])
            } else {
                None
            };
            if let Some((term, index)) = chunk {
                let offset = u64::from_le_bytes([
                    s.msg_buf[16],
                    s.msg_buf[17],
                    s.msg_buf[18],
                    s.msg_buf[19],
                    s.msg_buf[20],
                    s.msg_buf[21],
                    s.msg_buf[22],
                    s.msg_buf[23],
                ]) as usize;
                let done = s.msg_buf[24] != 0;
                let body_len = pl - wire::APP_SNAPSHOT_HDR;
                // Strict in-order accumulation; a gap or an oversized
                // body aborts the capture and the next rotation
                // re-requests.
                // Strict in-order accumulation, streamed straight to
                // the snapshot file: a captured body is bounded by the
                // filesystem, not by module state. An install in flight
                // owns the single write fd, so a capture that collides
                // with one is abandoned and the next rotation re-fires.
                let expected = s.app_body_len as usize;
                let start_ok = if offset == 0 {
                    if s.in_progress_active {
                        false
                    } else {
                        let (started, had_fs) = snap_begin(s, sys, term, index, term);
                        s.capture_had_fs = had_fs;
                        started || !had_fs
                    }
                } else {
                    s.wfd >= 0 || !s.capture_had_fs
                };
                if offset != expected || !start_ok {
                    snap_abort(s, sys);
                    s.app_body_len = 0;
                    s.app_capture_pending = false;
                    s.app_capture_ticks = 0;
                    s.triggers_deferred = s.triggers_deferred.saturating_add(1);
                } else {
                    let mut ok = true;
                    if body_len > 0 && s.capture_had_fs {
                        let src = s.msg_buf.as_mut_ptr().add(wire::APP_SNAPSHOT_HDR);
                        ok = snap_append(s, sys, src, body_len);
                    }
                    if !ok {
                        s.app_body_len = 0;
                        s.app_capture_pending = false;
                        s.app_capture_ticks = 0;
                        s.triggers_deferred = s.triggers_deferred.saturating_add(1);
                    } else {
                        s.app_body_len = (offset + body_len) as u32;
                        if done {
                            s.app_bodies_received = s.app_bodies_received.saturating_add(1);
                            s.app_capture_pending = false;
                            s.app_capture_ticks = 0;
                            cold_fs = true; // finalise persists the manifest
                            finalize_local_snapshot(s, sys, term, index);
                            s.app_body_len = 0;
                        }
                    }
                }
            }
        } else {
            // Bound the wait: a silent app (encode failed, or the
            // state outgrew its export budget) must not wedge
            // snapshotting for good.
            s.app_capture_ticks = s.app_capture_ticks.saturating_add(1);
            if s.app_capture_ticks > APP_CAPTURE_TIMEOUT_TICKS {
                s.app_capture_pending = false;
                s.app_capture_ticks = 0;
                s.app_captures_timed_out = s.app_captures_timed_out.saturating_add(1);
                dev_log(sys, 3, b"[snap] app timeout".as_ptr(), 18);
            }
        }
    }

    // 3. Drain incoming chunks (InstallSnapshot RPC from leader).
    if s.in_import >= 0 {
        for _ in 0..4 {
            let Some((msg_type, plen)) = s.inbox_import.next(sys, &mut s.msg_buf) else {
                break;
            };
            if plen == 0 {
                continue;
            }
            let pl = plen as usize;
            match msg_type {
                wire::MSG_INSTALL_SNAPSHOT => {
                    ingest_install_chunk(s, sys, pl);
                    cold_fs = true; // chunk ingest persists to disk
                }
                wire::MSG_SNAPSHOT_CHUNK => {
                    // Legacy untyped chunk — count for backward
                    // compatibility with older test fixtures, no
                    // install side effect.
                    s.chunks_imported += 1;
                }
                _ => {}
            }
        }
    }

    // 4. Periodic metrics.
    emit_metrics(s, sys);

    cold_fs
}

/// Emit snapshot counters and the transfer-time histogram as typed samples.
/// Partition-stamped. Dropped under backpressure.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut Snapshot, sys: &SyscallTable) {
    if s.out_metrics < 0 {
        return;
    }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS {
        return;
    }
    s.last_metrics_ms = now;

    let mid = wire::SOURCE_ID_SNAPSHOT;
    let pid = s.partition_id;
    let kc = wire::METRIC_KIND_COUNTER;
    // The name-fence disposition is a state, not a count.
    emit_sample(
        s,
        sys,
        mid,
        pid,
        wire::metric_ids::SNAP_NAME_FENCE,
        wire::METRIC_KIND_GAUGE,
        i64::from(s.name_fence_probe),
    );
    let scalars: [(u16, i64); 8] = [
        (
            wire::metric_ids::SNAP_SNAPSHOTS_TAKEN,
            i64::from(s.snapshots_taken),
        ),
        (
            wire::metric_ids::SNAP_CHUNKS_IMPORTED,
            i64::from(s.chunks_imported),
        ),
        (
            wire::metric_ids::SNAP_TRIGGERS_DEFERRED,
            i64::from(s.triggers_deferred),
        ),
        (
            wire::metric_ids::SNAP_BYTES_WRITTEN,
            s.snap_bytes_written as i64,
        ),
        (
            wire::metric_ids::SNAP_INSTALL_FAILURES,
            i64::from(s.install_failures),
        ),
        (
            wire::metric_ids::SNAP_APP_BODIES_RECEIVED,
            i64::from(s.app_bodies_received),
        ),
        (
            wire::metric_ids::SNAP_APP_CAPTURES_TIMED_OUT,
            i64::from(s.app_captures_timed_out),
        ),
        (
            wire::metric_ids::SNAP_NAME_UNFENCED,
            i64::from(s.name_unfenced),
        ),
    ];
    for &(metric_id, value) in scalars.iter() {
        emit_sample(s, sys, mid, pid, metric_id, kc, value);
    }
    // Cumulative bucket counts per the wire contract (wire::hist): emit the
    // running prefix sum so bucket i = count of samples <= bound[i].
    let base = wire::hist::HIST_BASE;
    let mut cum: i64 = 0;
    for i in 0..s.transfer_buckets.len() {
        cum += i64::from(s.transfer_buckets[i]);
        emit_sample(
            s,
            sys,
            mid,
            pid,
            base + i as u16,
            wire::METRIC_KIND_HISTOGRAM,
            cum,
        );
    }
}

/// Emit one typed metric sample if `out_metrics` has write space.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_sample(
    s: &Snapshot,
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

/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` (or shared
/// `&Snapshot` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ingest_install_chunk(s: &mut Snapshot, sys: &SyscallTable, plen: usize) {
    let (term, last_idx, last_term, offset, done, hdr_len) =
        match wire::decode_install_snapshot(&s.msg_buf[..plen]) {
            Some(t) => t,
            None => return,
        };
    let body_len = plen.saturating_sub(hdr_len);

    // Reset on first chunk (offset == 0) or when (term, last_idx) change
    // versus the install we were accumulating.
    let restart = offset == 0
        || !s.in_progress_active
        || s.in_progress_term != term
        || s.in_progress_last_idx != last_idx;
    if restart {
        s.in_progress_term = term;
        s.in_progress_last_idx = last_idx;
        s.in_progress_last_term = last_term;
        s.in_progress_offset = 0;
        s.body_len = 0;
        s.install_start_ms = dev_millis(sys);
        // Open the target file now and stream every chunk into it. The
        // body is never accumulated in module state, so an installed
        // snapshot is bounded by the filesystem rather than by a 16 KiB
        // buffer — which is what bounded how far a learner could fall
        // behind and still catch up.
        //
        // No early record beyond this: the durable-install gate (body +
        // boot pointer) lives on `done`, and the file is not published
        // under its final name until `snap_finish`, so a partial stream
        // never shadows the artefact the boot restore reads.
        let (started, had_fs) = snap_begin(s, sys, term, last_idx, last_term);
        s.install_had_fs = had_fs;
        if !started && had_fs {
            // FS present but the open failed (provider still
            // initialising, ENOSPC, …). Leave the install inactive; the
            // leader re-sends from offset 0.
            s.in_progress_active = false;
            dev_log(sys, 3, b"[snap] open fail".as_ptr(), 16);
            return;
        }
        s.in_progress_active = true;
    }

    // Offset gating: drop misordered chunks. The leader is expected to
    // re-send from offset 0 if it sees us stalled.
    if offset != s.in_progress_offset {
        dev_log(sys, 3, b"[snap] off skew".as_ptr(), 15);
        return;
    }

    // Stream the chunk straight to the file. A short write aborts the
    // install (snap_append closes the fd); the leader re-sends from
    // offset 0 and `restart` opens a fresh file.
    if body_len > 0 && s.install_had_fs {
        let src = s.msg_buf.as_mut_ptr().add(hdr_len);
        if !snap_append(s, sys, src, body_len) {
            dev_log(sys, 3, b"[snap] append fail".as_ptr(), 18);
            s.in_progress_active = false;
            return;
        }
        s.body_len += body_len as u32;
    } else if body_len > 0 {
        // No FS provider: nothing to write, but the (term, index) is
        // still a valid install for an in-memory graph.
        s.body_len += body_len as u32;
    }
    s.in_progress_offset = offset + body_len as u64;
    s.chunks_imported += 1;

    if done {
        // Finalise: durably write the accumulated body to disk
        // (crash-atomically — see write_snapshot_durable) BEFORE telling
        // raft the snapshot is installed. The install signal is what lets a
        // follower advance its state to last_idx and compact its log, so it
        // must not be emitted until the body survives a crash. A torn/failed
        // write withholds the signal; the leader re-sends from offset 0.
        let had_fs = s.install_had_fs;
        let durable = had_fs && snap_finish(s, sys);
        // Boot pointer: an installed snapshot that boot can't find is
        // as good as lost once raft compacts behind it (same gate as
        // the local-rotation publish).
        let durable = durable && (!had_fs || persist_snap_pointer(s, sys, s.in_progress_last_idx));

        // `had_fs == false` means no FS provider (in-memory graph): no
        // durable artefact is possible, but the (term, index) is still a
        // valid install there. With an FS present, only signal on a
        // confirmed durable write.
        // Hand the state-machine body to the app BEFORE signalling the
        // install. The install signal is what lets raft compact its log
        // to last_idx; if the app never received the state it could
        // then never catch up. A refused hand-off (channel full)
        // withholds the signal and the leader re-sends from offset 0.
        let mut app_restored = true;
        if s.out_app_ctl >= 0 && s.body_len > 0 {
            app_restored = emit_app_restore(s, sys, s.in_progress_term, s.in_progress_last_idx);
        }

        if app_restored && (durable || !had_fs) && s.out_installed >= 0 {
            if wire_channels::writable(sys, s.out_installed) {
                let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
                wire::encode_snapshot_installed(
                    &mut buf,
                    s.in_progress_term,
                    s.in_progress_last_idx,
                    s.in_progress_last_term,
                );
                write_installed(s, sys, wire::MSG_SNAPSHOT_INSTALLED, &buf);
                let prev_index = s.last_snapshot_index;
                s.last_snapshot_term = s.in_progress_term;
                s.last_snapshot_index = s.in_progress_last_idx;
                // Seam latch → wal: the installed prefix will never
                // arrive on `entries`, so the wal must fast-forward its
                // append contract to `last_idx` or the very next
                // post-install append (`last_idx + 1` against an
                // expected `current_index + 1`) latches a continuity
                // fault. Monotone latest-wins; drained by the dispatch
                // table after this component's step.
                s.wal_fast_forward = (s.in_progress_last_term, s.in_progress_last_idx);
                s.wal_fast_forward_dirty = true;
                dev_log(sys, 3, b"[snap] installed".as_ptr(), 16);
                // Exactly-one-snapshot steady state (mirrors the local
                // trigger path): retire the superseded snapshot file only
                // when this install confirmed durable on a real FS.
                if durable {
                    unlink_prev_snapshot(s, sys, prev_index, s.last_snapshot_index);
                }
            }
        }
        // Fold the install duration into the transfer histogram.
        let elapsed_ms = dev_millis(sys).wrapping_sub(s.install_start_ms);
        let b = wire::hist::bucket(&wire::hist::SNAPSHOT_MS, elapsed_ms);
        s.transfer_buckets[b] = s.transfer_buckets[b].saturating_add(1);
        s.in_progress_active = false;
        s.body_len = 0;
        s.in_progress_offset = 0;
    }
}

/// Finalise a locally-taken snapshot at `(term, index)`, shipping
/// whatever body the capture streamed into the snapshot file
/// (empty = manifest-only).
///
/// Shared by the trigger path (no app provider — empty body) and the
/// app-body path, so both orders of
/// operations stay identical: persist, signal raft, retire the
/// superseded manifest, then ship to peers.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn finalize_local_snapshot(s: &mut Snapshot, sys: &SyscallTable, term: Term, index: Index) {
    let prev_index = s.last_snapshot_index;
    // Persist the app BODY with the snapshot, not a bare manifest: the
    // boot restore replays exactly this body to the state machine
    // before the (compacted) wal tail — a body-less manifest would let
    // raft compact the log below state nothing can ever rebuild.
    // Two callers reach here. The app-capture path has already streamed
    // the body into an open file, so this only closes it out. The
    // manifest-only path (no app state machine on this graph) has no
    // stream in flight, so open one now for an empty body. Both end at
    // the same writer, so both emit byte-identical artefacts.
    if s.wfd < 0 {
        let (started, had_fs) = snap_begin(s, sys, term, index, term);
        s.capture_had_fs = had_fs;
        if !started && had_fs {
            dev_log(sys, 3, b"[snap] open fail".as_ptr(), 16);
            return;
        }
    }
    let had_fs = s.capture_had_fs;
    let blen = s.app_body_len;
    let durable = had_fs && snap_finish(s, sys);
    if !had_fs {
        // No FS provider: nothing durable is possible, and the caller's
        // `!had_fs` path applies.
        s.body_len = blen;
    }
    if !durable && had_fs {
        // FS present but the snapshot didn't land (provider
        // initialising, ENOSPC, short write…). Drop it — the next
        // rotation re-fires. Signalling an install here would let raft
        // compact WAL segments against a snapshot that isn't on disk.
        return;
    }
    if had_fs && !persist_snap_pointer(s, sys, index) {
        // Snapshot durable but the boot pointer isn't: unfindable at
        // boot. Withhold the install signal; the next rotation retries
        // the whole publish.
        dev_log(sys, 3, b"[snap] ptr fail".as_ptr(), 15);
        return;
    }
    dev_log(sys, 3, b"[snap] manifest".as_ptr(), 15);
    s.last_snapshot_term = term;
    s.last_snapshot_index = index;
    // Tell raft the local snapshot is durable so it advances the WAL
    // compaction floor (the leader-local leg of
    // `drain_snapshot_installed` — without this signal a leader never
    // retires segments). Same durable-or-no-FS gate as the import
    // path; skipped when the port is unwired or briefly full (the next
    // trigger re-signals).
    if s.out_installed >= 0 {
        if wire_channels::writable(sys, s.out_installed) {
            let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
            wire::encode_snapshot_installed(&mut buf, term, index, term);
            write_installed(s, sys, wire::MSG_SNAPSHOT_INSTALLED, &buf);
        }
    }
    // Tell the app the snapshot at `index` is now DURABLE, on the same
    // control channel that carries REQUEST/RESET. An app worker gates its
    // GC floor on this: local export completion is NOT proof of durability,
    // and advancing the floor onto a not-yet-durable snapshot lets a crash
    // force WAL replay to read compacted-away state. Gated on `had_fs` —
    // which here implies `durable` (the `!durable && had_fs` early-return
    // fired otherwise; `!had_fs` is an in-memory graph with nothing durable
    // to acknowledge). Skipped when the port is unwired or briefly full;
    // the next rotation re-signals, and the worker's floor simply lags.
    if had_fs && s.out_app_ctl >= 0 && wire_channels::writable(sys, s.out_app_ctl) {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&term.to_le_bytes());
        buf[8..].copy_from_slice(&index.to_le_bytes());
        wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_DURABLE, &buf);
    }
    // Exactly-one-snapshot steady state: retire the previous manifest
    // only after the new one is durable.
    if durable {
        unlink_prev_snapshot(s, sys, prev_index, index);
    }
    emit_install_staged(s, sys, term, index);
    s.snapshots_taken += 1;
}

/// Ask the app state machine to capture its state now. `(term, index)`
/// is a hint about the position we'd like; the app answers with its
/// own applied position, which is authoritative.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn request_app_capture(
    s: &mut Snapshot,
    sys: &SyscallTable,
    term: Term,
    index: Index,
) -> bool {
    if s.out_app_ctl < 0 {
        return false;
    }
    if !wire_channels::writable(sys, s.out_app_ctl) {
        return false;
    }
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&term.to_le_bytes());
    buf[8..].copy_from_slice(&index.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_REQUEST, &buf);
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` (or shared
/// `&Snapshot` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Re-broadcast the most recent snapshot as a manifest-only
/// InstallSnapshot: peers learn the `(term, index)` and trust their own
/// log/WAL for the rest. Body-carrying installs go out through
/// `emit_install_staged`.
unsafe fn emit_install_chunk(s: &mut Snapshot, sys: &SyscallTable, term: Term, index: Index) {
    emit_install_body(s, sys, term, index, &[]);
}

/// Deliver an installed snapshot to the app state machine: a
/// `MSG_APP_SNAPSHOT_RESET` (discard current state) followed by the body as
/// a `MSG_APP_SNAPSHOT_CHUNK` stream.
///
/// Returns false if the hand-off could not be completed, in which case
/// the caller MUST withhold the install signal — otherwise raft would
/// compact past state the app never received.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn emit_app_restore(s: &mut Snapshot, sys: &SyscallTable, term: Term, index: Index) -> bool {
    if s.out_app_ctl < 0 {
        return false;
    }
    let total = s.body_len as usize;
    // The body lives in the snapshot FILE, not in module state, so it is
    // read back a chunk at a time as it is handed over. Opened per
    // attempt: a refused chunk aborts the whole restore and the caller
    // retries from offset 0, so there is no partial stream to resume.
    let fd = if total > 0 {
        snap_open_body(s, sys, index, 0)
    } else {
        -1
    };
    if total > 0 && fd < 0 {
        return false;
    }
    // RESET first: the app discards state up front, so a stream that
    // dies mid-way leaves it empty (catch-up from leader) rather than
    // half-old/half-new.
    if !wire_channels::writable(sys, s.out_app_ctl) {
        if fd >= 0 {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        }
        return false;
    }
    let mut hdr = [0u8; 16];
    hdr[..8].copy_from_slice(&term.to_le_bytes());
    hdr[8..].copy_from_slice(&index.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_RESET, &hdr);

    let mut sent = 0usize;
    loop {
        let chunk = (total - sent).min(MAX_CHUNK_BODY);
        let done = sent + chunk == total;
        if !wire_channels::writable(sys, s.out_app_ctl) {
            if fd >= 0 {
                (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            }
            return false;
        }
        let mut buf = [0u8; wire::APP_SNAPSHOT_HDR + MAX_CHUNK_BODY];
        buf[..8].copy_from_slice(&term.to_le_bytes());
        buf[8..16].copy_from_slice(&index.to_le_bytes());
        buf[16..24].copy_from_slice(&(sent as u64).to_le_bytes());
        buf[24] = u8::from(done);
        if chunk > 0 {
            let dst = buf.as_mut_ptr().add(wire::APP_SNAPSHOT_HDR);
            if (sys.provider_call)(fd, FS_READ, dst, chunk) != chunk as i32 {
                (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
                return false;
            }
        }
        wire_channels::channel_write_msg(
            sys,
            s.out_app_ctl,
            wire::MSG_APP_SNAPSHOT_CHUNK,
            &buf[..wire::APP_SNAPSHOT_HDR + chunk],
        );
        sent += chunk;
        if done {
            if fd >= 0 {
                (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            }
            return true;
        }
    }
}

/// Emit an InstallSnapshot RPC carrying the body staged in
/// the snapshot file's body, chunked to `MAX_CHUNK_BODY`.
///
/// Separate from `emit_install_body` because the body lives in state:
/// passing it as a slice would alias the `&mut Snapshot` the
/// chunking loop needs.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn emit_install_staged(s: &mut Snapshot, sys: &SyscallTable, term: Term, index: Index) {
    let total = s.body_len as usize;
    if total == 0 {
        emit_install_body(s, sys, term, index, &[]);
        return;
    }
    if s.out_export < 0 {
        return;
    }
    // Read the body back from the snapshot file rather than from a
    // resident buffer, so what a leader can send a follower is bounded
    // by the filesystem and not by module state.
    let fd = snap_open_body(s, sys, index, 0);
    if fd < 0 {
        return;
    }
    let mut offset: u64 = 0;
    let mut sent = 0usize;
    while sent < total {
        let chunk = (total - sent).min(MAX_CHUNK_BODY);
        let done = sent + chunk == total;
        if !wire_channels::writable(sys, s.out_export) {
            // Channel saturated — the trigger path retries on the next
            // rotation or an explicit ADMIN_OP_SNAPSHOT.
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            return;
        }
        let mut buf = [0u8; wire::INSTALL_SNAPSHOT_HDR + MAX_CHUNK_BODY];
        let dst = buf.as_mut_ptr().add(wire::INSTALL_SNAPSHOT_HDR);
        if (sys.provider_call)(fd, FS_READ, dst, chunk) != chunk as i32 {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            return;
        }
        // Header is written in place ahead of the body already staged at
        // INSTALL_SNAPSHOT_HDR, so the frame is composed with one copy.
        let mut hdr = [0u8; wire::INSTALL_SNAPSHOT_HDR];
        let n = wire::encode_install_snapshot(&mut hdr, term, index, term, offset, done, &[]);
        if n == 0 {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            return;
        }
        buf[..wire::INSTALL_SNAPSHOT_HDR].copy_from_slice(&hdr);
        wire_channels::channel_write_msg(
            sys,
            s.out_export,
            wire::MSG_INSTALL_SNAPSHOT,
            &buf[..wire::INSTALL_SNAPSHOT_HDR + chunk],
        );
        offset += chunk as u64;
        sent += chunk;
    }
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` (or shared
/// `&Snapshot` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_install_body(
    s: &mut Snapshot,
    sys: &SyscallTable,
    term: Term,
    index: Index,
    body: &[u8],
) {
    if s.out_export < 0 {
        return;
    }
    let total = body.len();
    if total == 0 {
        // Manifest-only install: still send one chunk so the follower
        // can update its (term, index) bookkeeping.
        if !wire_channels::writable(sys, s.out_export) {
            return;
        }
        let mut buf = [0u8; wire::INSTALL_SNAPSHOT_HDR];
        let n = wire::encode_install_snapshot(&mut buf, term, index, term, 0, true, &[]);
        if n > 0 {
            wire_channels::channel_write_msg(
                sys,
                s.out_export,
                wire::MSG_INSTALL_SNAPSHOT,
                &buf[..n],
            );
        }
        return;
    }

    let mut offset: u64 = 0;
    let mut remaining = total;
    while remaining > 0 {
        let chunk = remaining.min(MAX_CHUNK_BODY);
        let start = total - remaining;
        let done = chunk == remaining;
        if !wire_channels::writable(sys, s.out_export) {
            // Channel saturated. We bail — the trigger path will retry
            // on the next segment rollover or explicit ADMIN_OP_SNAPSHOT.
            return;
        }
        let mut buf = [0u8; wire::INSTALL_SNAPSHOT_HDR + MAX_CHUNK_BODY];
        let n = wire::encode_install_snapshot(
            &mut buf,
            term,
            index,
            term,
            offset,
            done,
            &body[start..start + chunk],
        );
        if n == 0 {
            return;
        }
        wire_channels::channel_write_msg(sys, s.out_export, wire::MSG_INSTALL_SNAPSHOT, &buf[..n]);
        offset += chunk as u64;
        remaining -= chunk;
    }
}

/// Path of pointer slot `slot`. The two slots are distinct files so a
/// failure in one cannot reach the other.
///   root mode: `<p>SNAPPT<slot>.SNP` (8.3-legal: 8-char stem)
///   dir mode:  `wal/p<NNNN>_snapptr<slot>.bin`
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot`.
unsafe fn build_snap_ptr_slot_path(s: &mut Snapshot, slot: u8) -> usize {
    let len = build_snap_pointer_path(s);
    let digit = b'0' + (slot & 1);
    if s.root_path != 0 {
        // "<p>SNAPPTR.SNP" → "<p>SNAPPT<slot>.SNP": replace the 'R', so
        // the stem stays 8 characters.
        s.path_buf[7] = digit;
        return len;
    }
    // "..._snapptr.bin" → "..._snapptr<slot>.bin": insert before ".bin".
    let dot = len - 4;
    let mut i = len;
    while i > dot {
        s.path_buf[i] = s.path_buf[i - 1];
        i -= 1;
    }
    s.path_buf[dot] = digit;
    len + 1
}

/// Encode a pointer slot record and seal it with its CRC.
fn encode_snap_ptr(buf: &mut [u8; SNAP_PTR_SIZE], generation: u64, index: Index) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    buf[0..4].copy_from_slice(&MAGIC_SNAP_PTR.to_le_bytes());
    buf[4..6].copy_from_slice(&SNAP_PTR_FORMAT_ID.to_le_bytes());
    buf[8..16].copy_from_slice(&generation.to_le_bytes());
    buf[16..24].copy_from_slice(&index.to_le_bytes());
    let mut c = Crc32c::new();
    c.update(&buf[..SNAP_PTR_CRC_OFF]);
    buf[SNAP_PTR_CRC_OFF..SNAP_PTR_SIZE].copy_from_slice(&c.finalize().to_le_bytes());
}

/// Decode a pointer slot into `(generation, index)`. `None` for anything
/// whose magic, format id, or CRC does not check out — a torn write, an
/// unwritten slot, and a foreign file are all refused alike.
fn decode_snap_ptr(buf: &[u8]) -> Option<(u64, Index)> {
    if buf.len() < SNAP_PTR_SIZE {
        return None;
    }
    if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != MAGIC_SNAP_PTR {
        return None;
    }
    if u16::from_le_bytes([buf[4], buf[5]]) != SNAP_PTR_FORMAT_ID {
        return None;
    }
    let mut c = Crc32c::new();
    c.update(&buf[..SNAP_PTR_CRC_OFF]);
    let want = u32::from_le_bytes([
        buf[SNAP_PTR_CRC_OFF],
        buf[SNAP_PTR_CRC_OFF + 1],
        buf[SNAP_PTR_CRC_OFF + 2],
        buf[SNAP_PTR_CRC_OFF + 3],
    ]);
    if c.finalize() != want {
        return None;
    }
    Some((
        u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]),
        u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]),
    ))
}

/// Fixed-name pointer sidecar naming the current durable local
/// snapshot's index. Boot follows it to the snapshot file; without it
/// the index-named file is unfindable (the FS surface has no listing).
/// This builds the base name; `build_snap_ptr_slot_path` derives the
/// per-slot names from it, and the base name itself carries the flat
/// record.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot`.
unsafe fn build_snap_pointer_path(s: &mut Snapshot) -> usize {
    let mut i = 0usize;
    if s.root_path != 0 {
        // 8.3 root layout, mirroring `build_snapshot_path`:
        // "<p:1hex>SNAPPTR.SNP".
        let p = (s.partition_id & 0xF) as u8;
        s.path_buf[i] = if p < 10 { b'0' + p } else { b'a' + p - 10 };
        i += 1;
        for &b in b"SNAPPTR.SNP" {
            s.path_buf[i] = b;
            i += 1;
        }
        return i;
    }
    for &b in b"wal/p" {
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = b;
            i += 1;
        }
    }
    for digit in (0..4).rev() {
        let nibble = ((s.partition_id >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = ch;
            i += 1;
        }
    }
    for &b in b"_snapptr.bin" {
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = b;
            i += 1;
        }
    }
    i
}

/// Bring BOTH pointer slot files into existence, at full size, with
/// both names fenced — before any non-neutral generation is adopted.
///
/// Two files make the RECORDS independent; they do not make the NAMES
/// independent. On FAT32 a directory entry is 32 bytes inside a
/// 512-byte directory sector, and two entries in one directory
/// routinely share one, so minting the second name mutates a sector the
/// first name already occupies. Creating each slot at its first publish
/// puts that mutation after generation 1 is adopted and is the only
/// pointer the node has — the worst possible moment. Doing it here puts
/// it where nothing has been adopted yet, and from the first adopted
/// generation onward every publish overwrites `SNAP_PTR_SIZE` bytes in
/// a file that already has its size and its cluster chain, leaving the
/// directory untouched.
///
/// An existing slot is read first and left alone if it is already full
/// size: a node upgrading into this scheme must not have its recovered
/// pointer zeroed. A fresh slot gets all zeroes, which `decode_snap_ptr`
/// rejects, so it is "nothing yet" rather than a competing record.
///
/// Returns false only on a real FS failure; a device with no FS at all
/// is handled by the caller's `FS_E_NODEV` / `FS_E_NOSYS` path.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn materialize_snap_ptr_slots(s: &mut Snapshot, sys: &SyscallTable) -> bool {
    if s.snap_ptr_slots_materialized {
        return true;
    }
    for slot in 0..SNAP_PTR_SLOTS as u8 {
        let plen = build_snap_ptr_slot_path(s, slot);
        let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), plen);
        if fd < 0 {
            return fd == FS_E_NODEV || fd == FS_E_NOSYS;
        }
        // A short read is the test for "not yet sized": a file created
        // a moment ago reads 0, one written by a previous boot reads
        // SNAP_PTR_SIZE and keeps whatever record it holds.
        let seek = 0i32.to_le_bytes();
        let mut probe = [0u8; SNAP_PTR_SIZE];
        let sized = (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4) >= 0
            && (sys.provider_call)(fd, FS_READ, probe.as_mut_ptr(), SNAP_PTR_SIZE)
                == SNAP_PTR_SIZE as i32;
        if !sized {
            let mut neutral = [0u8; SNAP_PTR_SIZE];
            let ok = (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4) >= 0
                && (sys.provider_call)(fd, FS_WRITE, neutral.as_mut_ptr(), SNAP_PTR_SIZE)
                    == SNAP_PTR_SIZE as i32
                && (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) == 0;
            if !ok {
                (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
                return false;
            }
        }
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        // `path_buf` still holds this slot's path.
        if !publish_name(s, sys, plen) {
            return false;
        }
    }
    s.snap_ptr_slots_materialized = true;
    true
}

/// Persist the pointer sidecar for `index`. Returns durable-or-no-fs
/// like the other persists; the caller gates the install signal on it —
/// a snapshot whose pointer never landed is unfindable at boot, and
/// letting raft compact against it would strand the state below it.
unsafe fn persist_snap_pointer(s: &mut Snapshot, sys: &SyscallTable, index: Index) -> bool {
    // Both names and both sizes are settled before anything is adopted,
    // so no publish below ever mutates the directory.
    if !materialize_snap_ptr_slots(s, sys) {
        return false;
    }
    // Target the INACTIVE slot: the record boot would follow today is
    // never the one being overwritten, so no failure between here and
    // the fsync can leave the node without a usable pointer.
    let slot = 1 - (s.snap_ptr_slot & 1);
    let generation = s.snap_ptr_generation.wrapping_add(1);
    let plen = build_snap_ptr_slot_path(s, slot);
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), plen);
    if fd < 0 {
        return fd == FS_E_NODEV || fd == FS_E_NOSYS;
    }
    let mut buf = [0u8; SNAP_PTR_SIZE];
    encode_snap_ptr(&mut buf, generation, index);
    let w = (sys.provider_call)(fd, FS_WRITE, buf.as_mut_ptr(), SNAP_PTR_SIZE);
    let f = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    if w != SNAP_PTR_SIZE as i32 || f != 0 {
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return false;
    }
    // Read the slot back and re-validate before adopting the new
    // generation. The read is served through the descriptor that just
    // wrote, so it proves the provider holds the bytes it accepted —
    // a short or mis-encoded write is caught here; the fsync above is
    // what carries them to media.
    let seek = 0i32.to_le_bytes();
    let mut check = [0u8; SNAP_PTR_SIZE];
    let ok = (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4) >= 0
        && (sys.provider_call)(fd, FS_READ, check.as_mut_ptr(), SNAP_PTR_SIZE)
            == SNAP_PTR_SIZE as i32
        && decode_snap_ptr(&check) == Some((generation, index));
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    if !ok {
        return false;
    }
    // The name was fenced at materialisation, before anything was
    // adopted, and this publish changed neither the size nor the
    // cluster chain — so the directory entry is exactly as it was and
    // needs no second fence.
    s.snap_ptr_slot = slot;
    s.snap_ptr_generation = generation;
    true
}

/// Collect the pointer candidates at boot: both slots ordered by
/// generation (newest first), then the flat record. Returns `true`
/// when the FS provider is still initialising and the caller must
/// retry on a later step.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn collect_snap_ptr_candidates(s: &mut Snapshot, sys: &SyscallTable) -> bool {
    let mut found: [(u64, Index); SNAP_PTR_SLOTS] = [(0, 0); SNAP_PTR_SLOTS];
    let mut count = 0usize;
    for slot in 0..SNAP_PTR_SLOTS as u8 {
        let plen = build_snap_ptr_slot_path(s, slot);
        let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), plen);
        if fd == FS_E_AGAIN {
            return true;
        }
        if fd < 0 {
            continue;
        }
        let mut buf = [0u8; SNAP_PTR_SIZE];
        let n = (sys.provider_call)(fd, FS_READ, buf.as_mut_ptr(), SNAP_PTR_SIZE);
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        if n != SNAP_PTR_SIZE as i32 {
            continue;
        }
        if let Some((generation, index)) = decode_snap_ptr(&buf) {
            found[count] = (generation, index);
            count += 1;
            if generation > s.snap_ptr_generation {
                s.snap_ptr_generation = generation;
                s.snap_ptr_slot = slot;
            }
        }
    }
    // Newest generation first (at most two entries).
    if count == SNAP_PTR_SLOTS && found[1].0 > found[0].0 {
        found.swap(0, 1);
    }
    s.boot_ptr_count = 0;
    s.boot_ptr_next = 0;
    for entry in found.iter().take(count) {
        s.boot_ptr_candidates[s.boot_ptr_count as usize] = entry.1;
        s.boot_ptr_count += 1;
    }

    // The single unchecksummed record, as the last resort.
    let plen = build_snap_pointer_path(s);
    let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), plen);
    if fd == FS_E_AGAIN {
        return s.boot_ptr_count == 0;
    }
    if fd >= 0 {
        let mut val = [0u8; SNAP_PTR_FLAT_SIZE];
        let n = (sys.provider_call)(fd, FS_READ, val.as_mut_ptr(), SNAP_PTR_FLAT_SIZE);
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        if n == SNAP_PTR_FLAT_SIZE as i32 {
            let index = u64::from_le_bytes(val);
            let dup = s
                .boot_ptr_candidates
                .iter()
                .take(s.boot_ptr_count as usize)
                .any(|c| *c == index);
            if !dup {
                s.boot_ptr_candidates[s.boot_ptr_count as usize] = index;
                s.boot_ptr_count += 1;
            }
        } else {
            dev_log(sys, 3, b"[snap] boot ptr torn".as_ptr(), 20);
        }
    }
    false
}

/// Advance to the next pointer candidate, or finish the boot restore
/// when every candidate has been refused. A pointer is believed only
/// once the snapshot it names has been opened and validated, so nothing
/// downstream — retirement, compaction, the install signal — can rely on
/// a root that is not actually on disk.
fn next_boot_candidate(s: &mut Snapshot) {
    s.boot_ptr_next += 1;
    if s.boot_ptr_next < s.boot_ptr_count {
        s.boot_ptr_index = s.boot_ptr_candidates[s.boot_ptr_next as usize];
    } else {
        s.boot_ptr_index = 0;
        s.boot_phase = BOOT_DONE;
    }
}

/// Drive the boot restore one bounded slice per step. Returns true
/// once done (successfully, or with nothing to restore) — `mod.rs`
/// holds `wal::step` (and with it the whole replay → raft-resume
/// handoff) until then, so the app receives the snapshot body BEFORE
/// the wal tail replays on top of it.
///
/// Every arm that issues a provider call yields the step (returns
/// false) even when the restore is finished: a cold first-touch
/// `FS_OPEN` runs tens of ms here, and the caller classifies a
/// still-running restore as Burst so the step guard forgives it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn boot_restore(s: &mut Snapshot, sys: &SyscallTable) -> bool {
    match s.boot_phase {
        BOOT_PTR => {
            if collect_snap_ptr_candidates(s, sys) {
                return false; // provider initialising — retry next step
            }
            if s.boot_ptr_count == 0 {
                // No pointer: fresh deployment, in-memory graph, or a
                // pre-pointer layout. Nothing to restore.
                s.boot_phase = BOOT_DONE;
                return false;
            }
            s.boot_ptr_index = s.boot_ptr_candidates[0];
            s.boot_phase = BOOT_LOAD;
            false
        }
        BOOT_LOAD => {
            let plen = build_snapshot_path(s, s.boot_ptr_index);
            let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), plen);
            if fd == FS_E_AGAIN {
                return false;
            }
            if fd < 0 {
                // Pointer names a file that is gone. Fall through to the
                // next candidate: an older pointer whose snapshot IS
                // present is a valid recovery root, and only when every
                // candidate fails is there nothing to restore. The wal
                // then replays whatever it still holds; state below the
                // vanished snapshot is LOST and the log says so rather
                // than guessing.
                dev_log(sys, 3, b"[snap] boot missing".as_ptr(), 19);
                next_boot_candidate(s);
                return false;
            }
            let mut hdr = [0u8; SNAP_HDR_LEN];
            let mut ok = (sys.provider_call)(fd, FS_READ, hdr.as_mut_ptr(), SNAP_HDR_LEN)
                == SNAP_HDR_LEN as i32
                && u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) == MAGIC_SNAP
                && u16::from_le_bytes([hdr[4], hdr[5]]) == s.partition_id;
            let body_len = if ok {
                u32::from_le_bytes([hdr[36], hdr[37], hdr[38], hdr[39]]) as usize
            } else {
                0
            };
            // Verify the body by streaming it, so boot is not bounded
            // by a buffer either: the body is replayed to the app from
            // the file later (BOOT_EMIT), and nothing needs it resident.
            let mut c = Crc32c::new();
            c.update(&hdr);
            if ok && body_len > 0 {
                let mut read = 0usize;
                let mut vbuf = [0u8; SNAP_VERIFY_CHUNK];
                while ok && read < body_len {
                    let want = (body_len - read).min(SNAP_VERIFY_CHUNK);
                    ok = (sys.provider_call)(fd, FS_READ, vbuf.as_mut_ptr(), want) == want as i32;
                    if ok {
                        c.update(&vbuf[..want]);
                        read += want;
                    }
                }
            }
            if ok {
                let mut trailer = [0u8; SNAP_TRAILER_LEN];
                ok = (sys.provider_call)(fd, FS_READ, trailer.as_mut_ptr(), SNAP_TRAILER_LEN)
                    == SNAP_TRAILER_LEN as i32
                    && u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]])
                        == END_MAGIC_SNAP
                    && c.finalize()
                        == u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
            }
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            if !ok {
                // Fail CLOSED on a torn/corrupt snapshot: never replay a
                // bad body, and never let a pointer to one become the
                // recovery root. Try the next candidate instead.
                dev_log(sys, 3, b"[snap] boot corrupt".as_ptr(), 19);
                s.body_len = 0;
                next_boot_candidate(s);
                return false;
            }
            s.last_snapshot_term = u64::from_le_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]);
            s.last_snapshot_index = u64::from_le_bytes([
                hdr[16], hdr[17], hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
            ]);
            s.body_len = body_len as u32;
            s.boot_phase = if s.out_app_ctl >= 0 && body_len > 0 {
                BOOT_EMIT
            } else {
                BOOT_SIGNAL
            };
            false
        }
        BOOT_EMIT => {
            if emit_app_restore(s, sys, s.last_snapshot_term, s.last_snapshot_index) {
                dev_log(sys, 3, b"[snap] boot restored".as_ptr(), 20);
                s.boot_phase = BOOT_SIGNAL;
            }
            false // channel not ready / partial — re-send next step
        }
        BOOT_SIGNAL => {
            // Consensus must learn the snapshot base BEFORE the wal
            // tail replays: its entries start above the snapshot index,
            // and a log with no base never elects.
            if s.out_installed < 0 {
                s.boot_phase = BOOT_DONE;
                return true;
            }
            let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
            wire::encode_snapshot_installed(
                &mut buf,
                s.last_snapshot_term,
                s.last_snapshot_index,
                s.last_snapshot_term,
            );
            // The phase advances only on a CONFIRMED write. A poll saying
            // ">=1 byte free" is not room for this frame, and BOOT_DONE is
            // a one-way door: nothing re-sends this. A node whose base
            // term/index never reached raft comes up believing its log
            // starts at 0 while its state is at the snapshot index.
            let n = write_installed(s, sys, wire::MSG_SNAPSHOT_INSTALLED, &buf);
            if n <= 0 {
                return false; // channel full or frame too large — retry next step
            }
            s.boot_phase = BOOT_DONE;
            true
        }
        _ => true,
    }
}

/// Build the snapshot path: `wal/p<NNNN>_snap_<NNNNNNNN>.bin`.
///
/// All partitions share the one `wal/` directory; the partition_id is
/// stamped into the filename rather than a per-partition subdirectory,
/// mirroring `wal::encode_segment_path`. `OPEN_CREATE` creates files
/// but does not `mkdir` parents, so the flat layout is what makes the
/// artefact appear on disk given a single operator-created `wal/`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot`.
unsafe fn build_snapshot_path(s: &mut Snapshot, index: Index) -> usize {
    let mut i = 0usize;
    if s.root_path != 0 {
        // 8.3-conforming, root-relative: "<p:1hex><idx:7hex>.SNP" (≤12
        // chars). Bare-metal FAT32 has no mkdir (so no `wal/` parent) and
        // rejects names longer than 8.3. Mirrors the wal module's
        // `encode_segment_path` root layout ("<p:1hex><seq:7hex>.WAL") —
        // the distinct extension keeps segments and snapshots separable
        // in a flat root dir.
        let p = (s.partition_id & 0xF) as u8;
        s.path_buf[i] = if p < 10 { b'0' + p } else { b'a' + p - 10 };
        i += 1;
        let low = index as u32;
        for digit in (0..7).rev() {
            let nibble = ((low >> (digit * 4)) & 0xF) as u8;
            let ch = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            s.path_buf[i] = ch;
            i += 1;
        }
        for &b in b".SNP" {
            s.path_buf[i] = b;
            i += 1;
        }
        return i;
    }
    for &b in b"wal/p" {
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = b;
            i += 1;
        }
    }
    for digit in (0..4).rev() {
        let nibble = ((s.partition_id >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = ch;
            i += 1;
        }
    }
    for &b in b"_snap_" {
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = b;
            i += 1;
        }
    }
    // 8-hex-digit suffix from the low 32 bits of index (matches
    // wal/seg_<NNNNNNNN> width; sufficient for the foreseeable index
    // range, and ops can join the high bits from the manifest body).
    let low = index as u32;
    for digit in (0..8).rev() {
        let nibble = ((low >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = ch;
            i += 1;
        }
    }
    for &b in b".bin" {
        if i < SNAP_PATH_MAX {
            s.path_buf[i] = b;
            i += 1;
        }
    }
    i
}

/// Lazily probe the FS provider's capability bitmap for `UNLINK` support
/// (same shape as `wal::fs_unlink_supported`). A failed CAPS call stays
/// unprobed and retries later rather than caching a transient error.
unsafe fn fs_unlink_supported(s: &mut Snapshot, sys: &SyscallTable) -> bool {
    ensure_fs_caps(s, sys);
    s.fs_unlink_probe == 1
}

/// One-shot FS capability probe, caching the `UNLINK` and `FSYNC_NAME`
/// dispositions together. A failed CAPS call leaves both unprobed and
/// retries later rather than caching a transient error as "unsupported".
unsafe fn ensure_fs_caps(s: &mut Snapshot, sys: &SyscallTable) {
    if s.fs_unlink_probe != 0 {
        return;
    }
    let mut caps = [0u8; 4];
    let rc = (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4);
    if rc == 4 {
        let bits = u32::from_le_bytes(caps);
        s.fs_unlink_probe = if bits & FS_CAP_UNLINK != 0 { 1 } else { 2 };
        s.name_fence_probe = if bits & FS_CAP_FSYNC_NAME != 0 {
            NAME_FENCE_PRESENT
        } else {
            NAME_FENCE_ABSENT
        };
    }
}

/// Publish the parent-directory entry for the path currently staged in
/// `path_buf` — the fence that makes a snapshot artefact, a pointer
/// slot, or a retirement survive a power cut. Same posture rules as the
/// WAL's `publish_name`: strict refuses what the provider cannot fence,
/// auto meters it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn publish_name(s: &mut Snapshot, sys: &SyscallTable, plen: usize) -> bool {
    ensure_fs_caps(s, sys);
    if s.name_fence_probe != NAME_FENCE_PRESENT {
        if s.name_fence == NAME_FENCE_STRICT {
            dev_log(sys, 1, b"[snap] no name fence".as_ptr(), 20);
            return false;
        }
        s.name_unfenced = s.name_unfenced.saturating_add(1);
        return true;
    }
    let rc = (sys.provider_call)(-1, FS_FSYNC_NAME, s.path_buf.as_mut_ptr(), plen);
    if rc == 0 {
        return true;
    }
    dev_log(sys, 1, b"[snap] name fence FAIL".as_ptr(), 22);
    false
}

/// Retire the previous snapshot file after a NEWER one is durable, so the
/// disk holds exactly one snapshot artefact per partition in steady state
/// instead of accumulating one per WAL rotation. Best-effort: a missing
/// file (operator GC, skip_replay renumbering) or a provider without
/// `caps::UNLINK` leaves the old file orphaned — never an error, the new
/// snapshot's durability is already established by the caller.
unsafe fn unlink_prev_snapshot(
    s: &mut Snapshot,
    sys: &SyscallTable,
    prev_index: Index,
    new_index: Index,
) {
    if prev_index == 0 || prev_index == new_index {
        return;
    }
    if !fs_unlink_supported(s, sys) {
        return;
    }
    let plen = build_snapshot_path(s, prev_index);
    if plen == 0 {
        return;
    }
    if (sys.provider_call)(-1, FS_UNLINK, s.path_buf.as_mut_ptr(), plen) == 0
        && publish_name(s, sys, plen)
    {
        // Retirement is complete only once the REMOVAL of the name is
        // durable: an unlink left in a volatile directory cache
        // resurrects the retired snapshot after a power cut.
        dev_log(sys, 3, b"[snap] retired".as_ptr(), 14);
    }
}

/// Open the snapshot file for `index` positioned `at` bytes into its
/// body. Returns a read fd, or -1.
///
/// Snapshot bodies are never resident, so every consumer — the app
/// restore, the export to a follower, the boot-time verify — reads them
/// back from the file through this.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn snap_open_body(s: &mut Snapshot, sys: &SyscallTable, index: Index, at: usize) -> i32 {
    let plen = build_snapshot_path(s, index);
    if plen == 0 {
        return -1;
    }
    let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), plen);
    if fd < 0 {
        return -1;
    }
    let off = ((SNAP_HDR_LEN + at) as i32).to_le_bytes();
    if (sys.provider_call)(fd, FS_SEEK, off.as_ptr() as *mut u8, 4) < 0 {
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return -1;
    }
    fd
}

/// Write to the consensus-facing install channel in the 5-byte partitioned
/// envelope, stamped with this snapshot component's partition. Mirrors
/// `wal::write_part`: one durability instance hosts K groups, so the
/// consumer cannot infer the partition from the wiring and the producer
/// states it.
///
/// # Safety
/// Caller must supply a valid `&SyscallTable` per the module ABI.
#[inline]
unsafe fn write_installed(s: &Snapshot, sys: &SyscallTable, msg_type: u8, payload: &[u8]) -> i32 {
    wire_channels::channel_write_partitioned(
        sys,
        s.out_installed,
        s.partition_id,
        msg_type,
        payload,
    )
}

/// Build the 40-byte snapshot header for `body_len` bytes of body.
fn snap_header(
    s: &Snapshot,
    term: Term,
    last_idx: Index,
    last_term: Term,
    body_len: u32,
) -> [u8; SNAP_HDR_LEN] {
    let mut hdr = [0u8; SNAP_HDR_LEN];
    hdr[0..4].copy_from_slice(&MAGIC_SNAP.to_le_bytes());
    hdr[4..6].copy_from_slice(&s.partition_id.to_le_bytes());
    // 6..8 reserved
    hdr[8..16].copy_from_slice(&term.to_le_bytes());
    hdr[16..24].copy_from_slice(&last_idx.to_le_bytes());
    hdr[24..32].copy_from_slice(&last_term.to_le_bytes());
    hdr[32..36].copy_from_slice(&s.dek_epoch.to_le_bytes());
    hdr[36..40].copy_from_slice(&body_len.to_le_bytes());
    hdr
}

/// Open a snapshot file and write a placeholder header, ready for
/// `snap_append`. Returns `(started, had_fs)` with the same
/// had_fs contract as the old `write_snapshot_durable`: false means no
/// FS provider at all (an in-memory graph), which is not a failure.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn snap_begin(
    s: &mut Snapshot,
    sys: &SyscallTable,
    term: Term,
    last_idx: Index,
    last_term: Term,
) -> (bool, bool) {
    snap_abort(s, sys);
    let plen = build_snapshot_path(s, last_idx);
    if plen == 0 {
        return (false, false);
    }
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), plen);
    if fd < 0 {
        // Genuinely no FS provider (in-memory graph): nothing to durably
        // install. ANY other error (E_AGAIN during a fat32 cold boot,
        // EIO, ENOSPC, missing parent dir) reports had_fs=true so the
        // caller withholds its install signal and the source retries.
        return (false, fd != FS_E_NODEV && fd != FS_E_NOSYS);
    }
    // Placeholder header: body_len is not known until the last chunk.
    // `snap_finish` seeks back and rewrites it.
    let mut hdr = snap_header(s, term, last_idx, last_term, 0);
    let ok =
        (sys.provider_call)(fd, FS_WRITE, hdr.as_mut_ptr(), SNAP_HDR_LEN) == SNAP_HDR_LEN as i32;
    if !ok {
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        return (false, true);
    }
    s.wfd = fd;
    s.wbody = 0;
    s.wterm = term;
    s.windex = last_idx;
    s.wlast_term = last_term;
    (true, true)
}

/// Append body bytes to the snapshot being streamed.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot`, supply a valid
/// `&SyscallTable`, and `src` must be readable for `len` bytes.
unsafe fn snap_append(s: &mut Snapshot, sys: &SyscallTable, src: *mut u8, len: usize) -> bool {
    if s.wfd < 0 {
        return false;
    }
    if len == 0 {
        return true;
    }
    if (sys.provider_call)(s.wfd, FS_WRITE, src, len) != len as i32 {
        snap_abort(s, sys);
        return false;
    }
    s.wbody = s.wbody.saturating_add(len as u32);
    true
}

/// Close and discard a snapshot being streamed. Idempotent.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn snap_abort(s: &mut Snapshot, sys: &SyscallTable) {
    if s.wfd >= 0 {
        (sys.provider_call)(s.wfd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.wfd = -1;
    }
    s.wbody = 0;
}

/// Finalise a streamed snapshot: rewrite the header with the true body
/// length, compute the `header || body` CRC by reading the body back,
/// append the trailer, fsync, close, and publish the name.
///
/// The read-back is what lets the body stream without being buffered:
/// the CRC's first input is a header field that only the last chunk
/// determines. Reading a file written moments ago is cheap next to
/// holding every snapshot body in module state.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn snap_finish(s: &mut Snapshot, sys: &SyscallTable) -> bool {
    if s.wfd < 0 {
        return false;
    }
    let fd = s.wfd;
    let body_len = s.wbody;
    let mut hdr = snap_header(s, s.wterm, s.windex, s.wlast_term, body_len);

    // 1. True header at offset 0.
    let zero = 0i32.to_le_bytes();
    let mut ok = (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4) >= 0
        && (sys.provider_call)(fd, FS_WRITE, hdr.as_mut_ptr(), SNAP_HDR_LEN) == SNAP_HDR_LEN as i32;

    // 2. CRC over header || body, reading the body back in chunks.
    let mut crc = Crc32c::new();
    crc.update(&hdr);
    if ok && body_len > 0 {
        let start = (SNAP_HDR_LEN as i32).to_le_bytes();
        ok = (sys.provider_call)(fd, FS_SEEK, start.as_ptr() as *mut u8, 4) >= 0;
        let mut read = 0u32;
        let mut buf = [0u8; SNAP_VERIFY_CHUNK];
        while ok && read < body_len {
            let want = ((body_len - read) as usize).min(SNAP_VERIFY_CHUNK);
            ok = (sys.provider_call)(fd, FS_READ, buf.as_mut_ptr(), want) == want as i32;
            if ok {
                crc.update(&buf[..want]);
                read += want as u32;
            }
        }
    }

    // 3. Trailer at the end, then one trailing fsync makes the whole
    //    file durable atomically.
    if ok {
        let end = ((SNAP_HDR_LEN as u32 + body_len) as i32).to_le_bytes();
        ok = (sys.provider_call)(fd, FS_SEEK, end.as_ptr() as *mut u8, 4) >= 0;
    }
    if ok {
        let mut trailer = [0u8; SNAP_TRAILER_LEN];
        trailer[0..4].copy_from_slice(&crc.finalize().to_le_bytes());
        trailer[4..8].copy_from_slice(&END_MAGIC_SNAP.to_le_bytes());
        ok = (sys.provider_call)(fd, FS_WRITE, trailer.as_mut_ptr(), SNAP_TRAILER_LEN)
            == SNAP_TRAILER_LEN as i32;
    }
    if ok {
        ok = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) == 0;
    }
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    s.wfd = -1;

    if ok {
        // The artefact is self-describing (magic + CRC + END_MAGIC), so
        // it is published under its final name rather than renamed into
        // place. That name is only durable once its parent-directory
        // entry is fenced.
        let plen = build_snapshot_path(s, s.windex);
        ok = plen > 0 && publish_name(s, sys, plen);
    }
    if ok {
        s.body_len = body_len;
        s.snap_bytes_written = s.snap_bytes_written.saturating_add(body_len as u64);
        dev_log(sys, 3, b"[snap] durable".as_ptr(), 14);
    } else {
        s.install_failures = s.install_failures.saturating_add(1);
        dev_log(sys, 3, b"[snap] durable FAIL".as_ptr(), 19);
    }
    s.wbody = 0;
    ok
}
