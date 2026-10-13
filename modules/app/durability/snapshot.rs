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
use super::{dev_log, dev_millis, fmt_u32_raw, wire, wire_channels};
use crate::abi::contracts::key_vault as kv;

#[path = "../../common/sealed_record.rs"]
mod sealed;

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
///   `[last_term:u64][dek_epoch:u32][body_len:u32]`
///   `[membership:3 = voters, joint, learners][rsvd:5]` = `SNAP_HDR_LEN` bytes,
///   then `body[body_len]`, then `[body_crc32c:u32][END_MAGIC:u32]`.
/// Written sequentially in one pass with a SINGLE trailing fsync, so a torn
/// or interrupted write never leaves a readable trailer — `load_snapshot`
/// rejects any file whose `END_MAGIC` or CRC doesn't check out and the node
/// falls back to its log. Snapshot filenames are index-keyed and indices are
/// monotonic, so a fresh install never overwrites a shorter valid file.
pub const SNAP_HDR_LEN: usize = 48;
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

/// Plaintext one sealed chunk carries: the transfer chunk size, so a
/// sealed body reads back in exactly the pieces an unsealed one does.
const SEAL_CHUNK_PLAIN: usize = MAX_CHUNK_BODY;
/// One whole sealed chunk: header, plaintext capacity, tag.
const SEAL_BUF: usize = sealed::SNAP_HDR_LEN + SEAL_CHUNK_PLAIN + sealed::TAG_LEN;

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

    // Most recent snapshot (term, index) we persisted, and the
    // configuration as of its index. Used to answer on-demand install
    // requests from `replicator`.
    last_snapshot_term: u64,
    last_snapshot_index: u64,
    last_snapshot_membership: wire::Membership,

    /// Seam ← wal (latest-wins, delivered by the dispatch table when it
    /// moves): the configuration as the log has it, so a snapshot taken
    /// at any index records the configuration as of that index.
    pub cfg: wire::CfgTrack,

    /// Seam latch → wal (monotone latest-wins, drained by the dispatch
    /// table): `(last_included_term, last_included_index, configuration)`
    /// of an accepted peer install, so the wal fast-forwards its append
    /// contract past the prefix the snapshot subsumes and takes the
    /// snapshot's configuration as its own.
    pub wal_fast_forward: (u64, u64, wire::Membership),
    pub wal_fast_forward_dirty: bool,
    /// Seam latch → wal: the configuration a snapshot restored at boot
    /// records, as of its index — the log below it may be gone.
    pub wal_membership: Option<(u64, wire::Membership)>,

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
    /// Kernel-ring twin (`SNAPSHOT_RING_US`, 16 buckets, µs — see wire::hist).
    pub ring_transfer_buckets: [u64; wire::hist::SNAPSHOT_RING_US.len() + 1],

    // In-flight install state (single-stream, fail-open if interleaved):
    in_progress_term: u64,
    in_progress_last_idx: u64,
    in_progress_last_term: u64,
    /// The configuration the install being received carries.
    in_progress_membership: wire::Membership,
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
    /// Identity of the snapshot being streamed, for the final header,
    /// and the configuration as of its index.
    wterm: Term,
    windex: Index,
    wlast_term: Term,
    wmembership: wire::Membership,

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
    /// The capture path, counted at each link so a snapshot that never
    /// lands can be placed: triggers that reached `on_trigger`, capture
    /// requests written to the app, requests the control channel refused
    /// (not writable). Reported on `[snap] hb`.
    triggers_seen: u32,
    app_captures_requested: u32,
    app_captures_unwritable: u32,
    last_hb_ms: u64,
    /// A lagging follower's install waiting on the composite: the
    /// leader's commit index from the request, below this component's
    /// manifest, so the install must be shipped at that index with the
    /// term the WAL holds there. 0 = none pending. Latest wins; one per
    /// step is served.
    install_wanted: u64,
    /// Installs the composite could not resolve: the commit index had
    /// left the WAL's location ring. Counted on `[snap] hb`; the
    /// replicator re-raises the request.
    installs_unresolved: u32,
    /// Body staged for the next install emit. Owned by state (not a
    /// borrow of msg_buf) so `finalize_snapshot` can take `&mut s`.
    /// True when the in-flight capture has a real FS provider behind it.
    capture_had_fs: bool,
    app_body_len: u32,

    // ── Chunk-sealed snapshot bodies ─────────────────────────────
    //
    // With `seal_suite` non-zero a snapshot body is stored as v1 `FXSC`
    // chunks under a key derived from the group's master
    // for the epoch in force, with a fresh 128-bit generation per
    // snapshot. The file header, CRC trailer and every read-back stream
    // keep their unsealed shape: the header's `body_len` counts stored
    // bytes, and the stream above sees the same bytes in the same
    // `MAX_CHUNK_BODY` pieces. Peers receive logical chunks over the
    // transport and seal them under their own key.
    /// v1 suite id, 0 = unsealed. Fanned in from the wal.
    pub seal_suite: u16,
    pub seal_cluster: [u8; sealed::CLUSTER_LEN],
    /// This replica's id: the "source replica" of the chunks it seals.
    pub self_id: u8,
    /// Lowest key epoch among the sealed snapshot files that may still
    /// be on disk (0 = none): its master must outlive them.
    sealed_epoch: u32,
    /// The stream being written: its key, epoch, generation, next chunk
    /// index, plaintext staged toward the next chunk, and stored bytes.
    wkey: i32,
    wepoch: u32,
    wgen: [u8; sealed::GENERATION_LEN],
    wchunk: u64,
    wfill: u32,
    wstored: u32,
    /// Epoch of the file `snap_finish` last made durable.
    done_epoch: u32,
    /// A sealed snapshot failed authentication: boot does not proceed.
    seal_fault: bool,
    pub seal_failures: u32,
    /// Scratch for one sealed chunk (in state: bodies stream).
    seal_buf: [u8; SEAL_BUF],

    // ── Portable transfer to a peer (leader) ─────────────────────
    //
    // A lagging peer's install is the app's PORTABLE copy of its state,
    // asked for on demand (`MSG_APP_SNAPSHOT_EXPORT_REQUEST`) and relayed
    // chunk for frame as it streams back — never this node's stored
    // body, which for a disk-backed store certifies only this node's own
    // files. One transfer at a time; another peer's request is answered
    // when its hold re-raises it.
    xfer_phase: u8,
    xfer_target: u8,
    xfer_id: u32,
    xfer_leader_term: u64,
    xfer_ticks: u32,
    xfer_expect_off: u64,
    /// The log position the copy in flight is labelled with: the wal keeps
    /// what follows it (the peer replays from there) while the transfer
    /// runs and for `XFER_HOLD_MS` after.
    xfer_floor_index: u64,
    xfer_floor_until_ms: u64,
    /// The peer a copy last went to, and until when its requests are not
    /// answered again: it is installing that copy, and its hold re-raises
    /// the request long before the install lands. Answering would start a
    /// new stream, whose first frame aborts the install under way.
    xfer_sent_target: u8,
    xfer_sent_until_ms: u64,
    xfers_started: u32,
    xfers_completed: u32,
    xfers_abandoned: u32,
    /// A composed `MSG_INSTALL_SNAPSHOT_TO` the export port had no room
    /// for (`xfer_held_len` bytes): written before anything more is read.
    xfer_held_len: u16,
    xfer_frame: [u8; 1 + wire::INSTALL_SNAPSHOT_HDR + wire::XFER_CHUNK_BODY],

    // ── Resumable hand-off to the app (follower install, boot) ───
    //
    // The body is handed over from the file a step at a time, resuming
    // where the channel stopped taking it, so its size is bounded by the
    // filesystem and not by one channel's room. A peer install is told to
    // raft only once the app acknowledges it (`app_install_ack`) — before
    // that, raft must not move past state the app does not hold.
    pub in_app_ack: i32,
    rs_phase: u8,
    rs_install: bool,
    rs_reset_sent: bool,
    rs_last_done: bool,
    rs_held_sealed: bool,
    rs_term: Term,
    rs_index: Index,
    rs_total: u64,
    rs_off: u64,
    rs_fd: i32,
    rs_ticks: u32,
    rs_held: u16,
    rs_reader: ChunkReader,
    rs_buf: [u8; wire::APP_SNAPSHOT_HDR + MAX_CHUNK_BODY],
    /// The peer install the restore will signal when it lands.
    pi_term: Term,
    pi_index: Index,
    pi_last_term: Term,
    pi_membership: wire::Membership,
    pi_durable: bool,
    pi_signal_owed: bool,
    installs_awaiting_app: u32,

    // Scratch
    path_buf: [u8; SNAP_PATH_MAX],
    msg_buf: [u8; 8192],
}

const XFER_IDLE: u8 = 0;
const XFER_ASKED: u8 = 1;
const XFER_RELAYING: u8 = 2;
/// Steps a transfer may go without the app producing or the link taking
/// a frame before it is abandoned (the peer re-raises its request).
const XFER_STALL_TICKS: u32 = 30_000;
/// How long after a transfer's last frame the wal still keeps the log the
/// peer replays from the copy's position.
const XFER_HOLD_MS: u64 = 120_000;
/// How long a peer that was sent a copy has to install it before its
/// request is answered with another.
const XFER_INSTALL_MS: u64 = 60_000;

const RS_IDLE: u8 = 0;
const RS_SENDING: u8 = 1;
const RS_AWAIT_ACK: u8 = 2;
const RS_DONE: u8 = 3;
const RS_FAILED: u8 = 4;
/// Steps a peer install waits for the app's acknowledgement.
const RS_ACK_TICKS: u32 = 120_000;

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
    s.wal_fast_forward = (0, 0, wire::Membership::default());
    s.wal_membership = None;
    s.last_snapshot_membership = wire::Membership::default();
    s.cfg = wire::NO_CFG_TRACK;
    s.in_progress_membership = wire::Membership::default();
    s.wmembership = wire::Membership::default();
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
    s.ring_transfer_buckets = [0u64; wire::hist::SNAPSHOT_RING_US.len() + 1];
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
    s.triggers_seen = 0;
    s.app_captures_requested = 0;
    s.app_captures_unwritable = 0;
    s.last_hb_ms = 0;
    s.install_wanted = 0;
    s.installs_unresolved = 0;
    s.app_body_len = 0;
    s.seal_suite = 0;
    s.seal_cluster = [0; sealed::CLUSTER_LEN];
    s.self_id = 0;
    s.sealed_epoch = 0;
    s.wkey = -1;
    s.wepoch = 0;
    s.wgen = [0; sealed::GENERATION_LEN];
    s.wchunk = 0;
    s.wfill = 0;
    s.wstored = 0;
    s.done_epoch = 0;
    s.seal_fault = false;
    s.seal_failures = 0;
    s.seal_buf = [0; SEAL_BUF];
    s.xfer_phase = XFER_IDLE;
    s.xfer_target = 0;
    s.xfer_id = 0;
    s.xfer_leader_term = 0;
    s.xfer_ticks = 0;
    s.xfer_expect_off = 0;
    s.xfer_floor_index = 0;
    s.xfer_floor_until_ms = 0;
    s.xfer_sent_target = 0;
    s.xfer_sent_until_ms = 0;
    s.xfers_started = 0;
    s.xfers_completed = 0;
    s.xfers_abandoned = 0;
    s.xfer_held_len = 0;
    s.in_app_ack = -1;
    s.rs_phase = RS_IDLE;
    s.rs_install = false;
    s.rs_fd = -1;
    s.rs_held = 0;
    s.rs_reader = ChunkReader::new(0, 0, wire::Membership::default());
    s.pi_signal_owed = false;
    s.installs_awaiting_app = 0;
}

/// The wal position a transfer in flight (or just finished) still needs
/// kept: the peer replays the log from the copy's position.
pub fn xfer_floor(s: &Snapshot, now_ms: u64) -> Option<u64> {
    if s.xfer_floor_index == 0 {
        return None;
    }
    if s.xfer_phase != XFER_IDLE || now_ms < s.xfer_floor_until_ms {
        Some(s.xfer_floor_index)
    } else {
        None
    }
}

/// Lowest key epoch a sealed snapshot on disk may still name (0 when
/// none): the wal keeps that epoch's master alive.
pub fn sealed_epoch(s: &Snapshot) -> u32 {
    s.sealed_epoch
}

#[inline]
fn sealing(s: &Snapshot) -> bool {
    s.seal_suite != 0
}

fn seal_identity(s: &Snapshot) -> sealed::Identity {
    sealed::Identity {
        cluster: s.seal_cluster,
        partition: u64::from(s.partition_id),
        replica: u64::from(s.self_id),
    }
}

/// The chunk key for a snapshot of `generation` under `epoch`. The
/// master is the wal's (same label, same owner): opened, never
/// destroyed here.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
unsafe fn snap_key(
    s: &Snapshot,
    sys: &SyscallTable,
    epoch: u32,
    generation: &[u8; sealed::GENERATION_LEN],
) -> i32 {
    let Some(vsuite) = sealed::vault_suite(s.seal_suite) else {
        return -22;
    };
    let mut label = [0u8; sealed::MASTER_LABEL_CAP];
    let n = sealed::master_label(s.partition_id, s.self_id, epoch, &mut label);
    let master = sealed::open_master(sys, &label[..n], false);
    if master < 0 {
        return master;
    }
    let ctx = sealed::snap_context(&seal_identity(s), generation, epoch);
    sealed::derive(
        sys,
        master,
        vsuite,
        kv::usage::SEAL | kv::usage::OPEN,
        sealed::SNAP_LABEL,
        &ctx,
    )
}

/// Seal the staged plaintext as the stream's next chunk and write it.
///
/// # Safety
/// Exclusive `&mut Snapshot`; `sys` must reach live kernel routines.
unsafe fn seal_chunk_out(s: &mut Snapshot, sys: &SyscallTable, flags: u8) -> bool {
    let c = s.wfill as usize;
    let binding = sealed::SnapBinding {
        generation: s.wgen,
        last_term: s.wterm,
        last_index: s.windex,
        membership: s.wmembership.encode(),
        epoch: s.wepoch,
    };
    let aad = sealed::snap_aad(&seal_identity(s), &binding, s.wchunk, flags, c as u32);
    let nonce = sealed::snap_nonce(s.wchunk);
    sealed::snap_write_header(
        &mut s.seal_buf,
        s.wepoch,
        &s.wgen,
        s.wchunk,
        flags,
        c as u32,
    );
    let base = s.seal_buf.as_mut_ptr();
    let rc = sealed::aead(
        sys,
        s.wkey,
        true,
        &nonce,
        &aad,
        base.add(sealed::SNAP_HDR_LEN),
        c,
        base.add(sealed::SNAP_HDR_LEN + c),
    );
    if rc != sealed::Aead::Ok {
        s.seal_failures = s.seal_failures.saturating_add(1);
        return false;
    }
    let total = sealed::SNAP_OVERHEAD + c;
    if (sys.provider_call)(s.wfd, FS_WRITE, base, total) != total as i32 {
        return false;
    }
    s.wchunk += 1;
    s.wfill = 0;
    s.wstored = s.wstored.saturating_add(total as u32);
    true
}

/// A reader over a sealed body: the binding its first chunk fixes and
/// the key it derived.
#[derive(Clone, Copy)]
struct ChunkReader {
    key: i32,
    binding: sealed::SnapBinding,
    next: u64,
    done: bool,
}

/// Why a sealed body could not be read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChunkErr {
    /// Short read or malformed header: the file is not whole.
    Io,
    /// A chunk that does not authenticate, or out of place.
    Auth,
    /// Its epoch's master is not in the vault.
    Key,
}

impl ChunkReader {
    fn new(term: Term, index: Index, membership: wire::Membership) -> Self {
        Self {
            key: -1,
            binding: sealed::SnapBinding {
                generation: [0; sealed::GENERATION_LEN],
                last_term: term,
                last_index: index,
                membership: membership.encode(),
                epoch: 0,
            },
            next: 0,
            done: false,
        }
    }
}

/// Read and open the next chunk from `fd` into `seal_buf`. Returns the
/// plaintext length (at `seal_buf[40..]`).
///
/// # Safety
/// Exclusive `&mut Snapshot`; `sys` must reach live kernel routines.
unsafe fn read_chunk(
    s: &mut Snapshot,
    sys: &SyscallTable,
    fd: i32,
    r: &mut ChunkReader,
) -> Result<usize, ChunkErr> {
    let hl = sealed::SNAP_HDR_LEN;
    if (sys.provider_call)(fd, FS_READ, s.seal_buf.as_mut_ptr(), hl) != hl as i32 {
        return Err(ChunkErr::Io);
    }
    let Some(h) = sealed::snap_parse_header(&s.seal_buf[..hl], SEAL_CHUNK_PLAIN) else {
        return Err(ChunkErr::Io);
    };
    let c = h.ct_len as usize;
    let rest = c + sealed::TAG_LEN;
    if (sys.provider_call)(fd, FS_READ, s.seal_buf.as_mut_ptr().add(hl), rest) != rest as i32 {
        return Err(ChunkErr::Io);
    }
    if r.next == 0 {
        r.binding.generation = h.generation;
        r.binding.epoch = h.epoch;
        r.key = snap_key(s, sys, h.epoch, &h.generation);
        if r.key < 0 {
            return Err(ChunkErr::Key);
        }
    }
    if h.chunk_index != r.next || h.generation != r.binding.generation || h.epoch != r.binding.epoch
    {
        return Err(ChunkErr::Auth);
    }
    let aad = sealed::snap_aad(
        &seal_identity(s),
        &r.binding,
        h.chunk_index,
        h.flags,
        c as u32,
    );
    let nonce = sealed::snap_nonce(h.chunk_index);
    let base = s.seal_buf.as_mut_ptr();
    match sealed::aead(
        sys,
        r.key,
        false,
        &nonce,
        &aad,
        base.add(hl),
        c,
        base.add(hl + c),
    ) {
        sealed::Aead::Ok => {}
        sealed::Aead::AuthFailed => return Err(ChunkErr::Auth),
        sealed::Aead::Refused(_) => return Err(ChunkErr::Key),
    }
    r.next += 1;
    r.done = h.flags & sealed::SNAP_FLAG_FINAL != 0;
    Ok(c)
}

/// Authenticate a whole sealed body of `stored` bytes starting at the
/// file's current position: every chunk in order, the last one final,
/// nothing after it. Returns the plaintext length.
///
/// # Safety
/// Exclusive `&mut Snapshot`; `sys` must reach live kernel routines.
unsafe fn verify_sealed_body(
    s: &mut Snapshot,
    sys: &SyscallTable,
    fd: i32,
    stored: usize,
    term: Term,
    index: Index,
    membership: wire::Membership,
) -> Result<u32, ChunkErr> {
    let mut r = ChunkReader::new(term, index, membership);
    let mut consumed = 0usize;
    let mut logical = 0u32;
    while !r.done {
        if consumed >= stored {
            sealed::destroy(sys, r.key);
            return Err(ChunkErr::Auth);
        }
        let got = read_chunk(s, sys, fd, &mut r);
        let c = match got {
            Ok(c) => c,
            Err(e) => {
                sealed::destroy(sys, r.key);
                return Err(e);
            }
        };
        consumed += sealed::SNAP_OVERHEAD + c;
        logical = logical.saturating_add(c as u32);
    }
    sealed::destroy(sys, r.key);
    if consumed != stored {
        return Err(ChunkErr::Auth);
    }
    Ok(logical)
}

/// Deliver the wal component's current `(term, index)` high-water.
/// Message-shaped seam (§8 rule 2): the same payload a rotation
/// trigger carries, in the same direction, so `snapshot` keeps its
/// port-only `step` signature and stays liftable into a standalone
/// module without edits inside the component.
pub fn on_wal_high_water(s: &mut Snapshot, term: Term, index: Index) {
    s.wal_high_water = (term, index);
}

/// One ` tag=value` field of the heartbeat; returns the new write position.
/// Panic-free: a field that would not fit is left out.
fn hb_field(buf: &mut [u8], at: usize, tag: &[u8], val: u32) -> usize {
    if at + tag.len() + 10 > buf.len() {
        return at;
    }
    buf[at..at + tag.len()].copy_from_slice(tag);
    let p = at + tag.len();
    // SAFETY: `fmt_u32_raw` writes at most 10 digits, and the bound
    // above left room for them past `p` inside `buf`.
    p + unsafe { fmt_u32_raw(buf.as_mut_ptr().add(p), val) }
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
    s.triggers_seen = s.triggers_seen.saturating_add(1);
    // A body being handed to the app (an install, a boot restore) owns the
    // control channel and the sealing buffer until it lands; the next
    // rotation re-fires this trigger.
    if s.rs_phase != RS_IDLE || s.pi_signal_owed {
        s.triggers_deferred = s.triggers_deferred.saturating_add(1);
        return false;
    }
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
    // `[snap] hb` — the capture path's links as counts, on the same
    // cadence as `[wal] hb`, so a snapshot that never lands is placed
    // from a capture rather than reasoned about: triggers reaching this
    // component, requests written to the app, requests its channel
    // refused, bodies back, timeouts, deferred triggers, snapshots
    // taken, and the last durable index.
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_hb_ms) >= 5000 {
        s.last_hb_ms = now;
        // Sequential fields, not a table of literals: an array of byte
        // slices is never relocated in a PIC module.
        let mut hb = [0u8; 192];
        let mut p = 0usize;
        p = hb_field(&mut hb, p, b"[snap] hb trig=", s.triggers_seen);
        p = hb_field(&mut hb, p, b" req=", s.app_captures_requested);
        p = hb_field(&mut hb, p, b" unwr=", s.app_captures_unwritable);
        p = hb_field(&mut hb, p, b" pend=", s.app_capture_pending as u32);
        p = hb_field(&mut hb, p, b" bodies=", s.app_bodies_received);
        p = hb_field(&mut hb, p, b" tmo=", s.app_captures_timed_out);
        p = hb_field(&mut hb, p, b" def=", s.triggers_deferred);
        p = hb_field(&mut hb, p, b" taken=", s.snapshots_taken);
        p = hb_field(&mut hb, p, b" last=", s.last_snapshot_index as u32);
        p = hb_field(&mut hb, p, b" hw=", hw_index as u32);
        p = hb_field(&mut hb, p, b" unres=", s.installs_unresolved);
        dev_log(sys, 3, hb.as_ptr(), p);
    }

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
            if msg_type != wire::MSG_SNAPSHOT_INSTALL_REQUEST {
                continue;
            }
            let Some((target, commit)) =
                wire::decode_snapshot_install_request(&s.msg_buf[..plen as usize])
            else {
                continue;
            };
            // With an app state machine the install is its portable copy,
            // asked for now; never this node's stored body (a disk store's
            // is a marker only this node can adopt) nor a bare manifest
            // (which a peer would adopt with no state behind it).
            if s.out_app_ctl >= 0 && s.in_app_body >= 0 {
                let leader_term =
                    wire::decode_snapshot_install_request_term(&s.msg_buf[..plen as usize]);
                xfer_ask(s, sys, target, commit, leader_term);
                continue;
            }
            if s.last_snapshot_index == 0 {
                demand_trigger = true;
            } else if s.last_snapshot_index <= commit {
                // The snapshot is committed, by its index: ship it as it
                // stands. (The install is broadcast, not routed: the
                // request's target is unused until a routed snapshot port
                // exists.)
                emit_install_chunk(s, sys, s.last_snapshot_term, s.last_snapshot_index);
            } else {
                // The manifest marks a rotation point past the leader's
                // commit. The follower would adopt it as committed, so the
                // install is shipped at the commit index instead — with the
                // term the WAL holds there, which the composite resolves
                // ([`resolve_install`]).
                s.install_wanted = commit;
            }
        }
        // At most one demand capture per step, and none while an app
        // capture is already in flight (each lagging follower re-raises
        // its request once per hold; funnelling them all into
        // on_trigger would spam triggers_deferred without adding work).
        if demand_trigger && !s.app_capture_pending && hw_index > 0 {
            // Debug, not info: a blocked retention floor or a refused
            // app capture leaves this branch re-entered on every
            // re-raised request.
            dev_log(sys, 4, b"[snap] demand trigger".as_ptr(), 21);
            if on_trigger(s, sys, hw_term, hw_index) {
                cold_fs = true;
            }
            // Manifest-only graphs finalise synchronously: the NEXT
            // request (re-raised when the follower's hold expires) is
            // served from `last_snapshot_index`. App-state graphs
            // finalise via the app-body path above.
        }
    }

    // 2c. App state-machine snapshot bodies. The body's
    //     own (term, index) is authoritative — the app may have
    //     applied past the trigger that prompted the capture.
    //     The same port carries a portable export's chunks, relayed to
    //     the peer that asked; a frame the export port has not taken
    //     holds everything behind it.
    if s.in_app_body >= 0 && s.xfer_held_len > 0 {
        xfer_flush(s, sys);
    }
    if s.in_app_body >= 0 && s.xfer_phase != XFER_IDLE {
        s.xfer_ticks = s.xfer_ticks.saturating_add(1);
        if s.xfer_ticks > XFER_STALL_TICKS {
            xfer_abandon(s, sys);
        }
    }
    if s.in_app_body >= 0
        && (s.app_capture_pending || s.xfer_phase != XFER_IDLE)
        && s.xfer_held_len == 0
    {
        if wire_channels::readable(sys, s.in_app_body) {
            let (msg_type, plen) =
                wire_channels::channel_read_msg(sys, s.in_app_body, &mut s.msg_buf);
            let pl = plen as usize;
            if msg_type == wire::MSG_APP_SNAPSHOT_EXPORT_CHUNK {
                xfer_relay(s, sys, pl);
            }
            let chunk = if s.app_capture_pending
                && msg_type == wire::MSG_APP_SNAPSHOT_CHUNK
                && pl >= wire::APP_SNAPSHOT_HDR
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
                        let m = s.cfg.at(index);
                        let (started, had_fs) = snap_begin(s, sys, term, index, term, m);
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
        } else if s.app_capture_pending {
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
                _ => {}
            }
        }
    }

    // 3b. The app's acknowledgements of installs it holds, and the
    //     hand-off of an installed body a step at a time.
    drain_app_acks(s, sys);
    if s.rs_phase != RS_IDLE && s.rs_install {
        restore_step(s, sys);
        match s.rs_phase {
            RS_DONE => {
                s.rs_phase = RS_IDLE;
                s.pi_signal_owed = true;
            }
            RS_FAILED => {
                s.rs_phase = RS_IDLE;
                s.install_failures = s.install_failures.saturating_add(1);
                dev_log(sys, 1, b"[snap] install not held by app".as_ptr(), 30);
            }
            _ => {}
        }
    }
    if s.pi_signal_owed {
        signal_peer_install(s, sys);
    }

    // 4. Periodic metrics.
    emit_metrics(s, sys);

    cold_fs
}

/// Ship the install a lagging follower is waiting on when the manifest
/// ran ahead of the leader's commit: at the commit index, with the term
/// `term_at` reports for it. The composite calls this after [`step`]
/// with the WAL's lookup, which holds a term for every index its
/// location ring covers. An index the ring no longer covers cannot be
/// shipped with a true term; it is counted and the request is left for
/// the replicator to re-raise, by when commit will have moved.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Snapshot` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn resolve_install<F: Fn(Index) -> Option<Term>>(
    s: &mut Snapshot,
    sys: &SyscallTable,
    term_at: F,
) {
    let commit = s.install_wanted;
    if commit == 0 {
        return;
    }
    s.install_wanted = 0;
    if s.last_snapshot_index <= commit {
        emit_install_chunk(s, sys, s.last_snapshot_term, s.last_snapshot_index);
        return;
    }
    match term_at(commit) {
        Some(term) => emit_install_chunk(s, sys, term, commit),
        None => {
            s.installs_unresolved = s.installs_unresolved.saturating_add(1);
            if s.installs_unresolved == 1 {
                dev_log(sys, 2, b"[snap] install unresolved".as_ptr(), 25);
            }
        }
    }
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
    let (term, last_idx, last_term, offset, done, membership, hdr_len) =
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
        // A new install supersedes the one still being handed to the app.
        if s.rs_install && s.rs_phase != RS_IDLE {
            restore_close(s, sys);
            s.rs_phase = RS_IDLE;
        }
        s.pi_signal_owed = false;
        s.in_progress_term = term;
        s.in_progress_last_idx = last_idx;
        s.in_progress_last_term = last_term;
        s.in_progress_membership = membership;
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
        let (started, had_fs) = snap_begin(s, sys, term, last_idx, last_term, membership);
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
        //
        // A body is handed to the app before raft hears of the install —
        // the signal is what lets raft move its log past the snapshot, and
        // past state the app never received it could never catch up. The
        // hand-off is resumable (`restore_step`), and with the app's
        // acknowledgement wired the signal waits for it.
        if durable || !had_fs {
            s.pi_term = s.in_progress_term;
            s.pi_index = s.in_progress_last_idx;
            s.pi_last_term = s.in_progress_last_term;
            s.pi_membership = s.in_progress_membership;
            s.pi_durable = durable;
            let carries_state = s.out_app_ctl >= 0 && s.body_len > 0;
            if s.out_app_ctl >= 0 && !carries_state {
                // A bare manifest where an app holds the state: adopted,
                // it would put raft past state the app never received.
                // Refused; the leader's next answer carries the state.
                s.install_failures = s.install_failures.saturating_add(1);
                dev_log(sys, 1, b"[snap] stateless install refused".as_ptr(), 32);
            } else if carries_state {
                restore_begin(
                    s,
                    s.in_progress_term,
                    s.in_progress_last_idx,
                    u64::from(s.body_len),
                    true,
                );
                s.installs_awaiting_app = s.installs_awaiting_app.saturating_add(1);
            } else {
                s.pi_signal_owed = true;
                signal_peer_install(s, sys);
            }
        }
        // Fold the install duration into the transfer histogram.
        let elapsed_ms = dev_millis(sys).wrapping_sub(s.install_start_ms);
        let b = wire::hist::bucket(&wire::hist::SNAPSHOT_MS, elapsed_ms);
        s.transfer_buckets[b] = s.transfer_buckets[b].saturating_add(1);
        let rb = wire::hist::bucket(
            &wire::hist::SNAPSHOT_RING_US,
            elapsed_ms.saturating_mul(1_000),
        );
        s.ring_transfer_buckets[rb] = s.ring_transfer_buckets[rb].wrapping_add(1);
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
        let m = s.cfg.at(index);
        let (started, had_fs) = snap_begin(s, sys, term, index, term, m);
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
    s.last_snapshot_membership = s.wmembership;
    // Tell raft the local snapshot is durable so it advances the WAL
    // compaction floor (the leader-local leg of
    // `drain_snapshot_installed` — without this signal a leader never
    // retires segments). Same durable-or-no-FS gate as the import
    // path; skipped when the port is unwired or briefly full (the next
    // trigger re-signals).
    if s.out_installed >= 0 {
        if wire_channels::writable(sys, s.out_installed) {
            let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
            wire::encode_snapshot_installed(&mut buf, term, index, term, s.wmembership, blen > 0);
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
    // A manifest-only graph pushes its snapshot to peers as before. With
    // an app state machine a peer is caught up by a portable transfer it
    // asks for (`xfer_ask`): this node's body may certify only its own
    // store (a disk store's marker), and broadcast it would rewind a peer.
    if s.out_app_ctl < 0 {
        export_staged(s, sys, term, index);
    }
    s.snapshots_taken += 1;
}

/// Ask the app for a portable copy for `target` (one transfer at a time;
/// a request for the transfer under way, or for another peer meanwhile,
/// is answered by the hold re-raising it).
unsafe fn xfer_ask(
    s: &mut Snapshot,
    sys: &SyscallTable,
    target: u8,
    commit: Index,
    leader_term: Term,
) {
    if s.xfer_phase != XFER_IDLE {
        return;
    }
    if target == s.xfer_sent_target && dev_millis(sys) < s.xfer_sent_until_ms {
        return;
    }
    let id = s.xfer_id.wrapping_add(1) & 0x00FF_FFFF;
    let mut buf = [0u8; 20];
    buf[..8].copy_from_slice(&leader_term.to_le_bytes());
    buf[8..16].copy_from_slice(&commit.to_le_bytes());
    buf[16..20].copy_from_slice(&id.to_le_bytes());
    if wire_channels::channel_write_msg(
        sys,
        s.out_app_ctl,
        wire::MSG_APP_SNAPSHOT_EXPORT_REQUEST,
        &buf,
    ) <= 0
    {
        return;
    }
    s.xfer_id = id;
    s.xfer_phase = XFER_ASKED;
    s.xfer_target = target;
    s.xfer_leader_term = leader_term;
    s.xfer_ticks = 0;
    s.xfer_expect_off = 0;
    s.xfers_started = s.xfers_started.saturating_add(1);
    dev_log(sys, 3, b"[snap] xfer asked".as_ptr(), 17);
}

/// Relay one export chunk (in `msg_buf`, `pl` bytes) to the transfer's
/// peer as an install frame, under the leader's term.
unsafe fn xfer_relay(s: &mut Snapshot, sys: &SyscallTable, pl: usize) {
    if s.xfer_phase == XFER_IDLE || pl < wire::APP_SNAPSHOT_HDR {
        return;
    }
    let Some((term, index)) = wire::decode_term_index(&s.msg_buf[..pl]) else {
        return;
    };
    let mut o = [0u8; 8];
    o.copy_from_slice(&s.msg_buf[16..24]);
    let offset = u64::from_le_bytes(o);
    let done = s.msg_buf[24] != 0;
    let id = u32::from_le_bytes([s.msg_buf[25], s.msg_buf[26], s.msg_buf[27], 0]);
    if id != s.xfer_id {
        return; // a superseded export's tail
    }
    let body_len = pl - wire::APP_SNAPSHOT_HDR;
    if offset != s.xfer_expect_off || body_len > wire::XFER_CHUNK_BODY {
        xfer_abandon(s, sys);
        return;
    }
    let leader_term = if s.xfer_leader_term != 0 {
        s.xfer_leader_term
    } else {
        term
    };
    let membership = membership_of(s, index);
    let mut hdr = [0u8; wire::INSTALL_SNAPSHOT_HDR];
    if wire::encode_install_snapshot(
        &mut hdr,
        leader_term,
        index,
        term,
        offset,
        done,
        membership,
        &[],
    ) == 0
    {
        xfer_abandon(s, sys);
        return;
    }
    s.xfer_frame[0] = s.xfer_target;
    s.xfer_frame[1..1 + wire::INSTALL_SNAPSHOT_HDR].copy_from_slice(&hdr);
    let at = 1 + wire::INSTALL_SNAPSHOT_HDR;
    let mut i = 0usize;
    while i < body_len {
        s.xfer_frame[at + i] = s.msg_buf[wire::APP_SNAPSHOT_HDR + i];
        i += 1;
    }
    s.xfer_held_len = (at + body_len) as u16;
    s.xfer_phase = XFER_RELAYING;
    s.xfer_floor_index = index;
    s.xfer_floor_until_ms = dev_millis(sys).saturating_add(XFER_HOLD_MS);
    s.xfer_expect_off = offset + body_len as u64;
    s.xfer_ticks = 0;
    if done {
        // The stream is whole once this frame goes; the floor holds on.
        s.xfer_phase = XFER_IDLE;
        s.xfers_completed = s.xfers_completed.saturating_add(1);
        s.xfer_sent_target = s.xfer_target;
        s.xfer_sent_until_ms = dev_millis(sys).saturating_add(XFER_INSTALL_MS);
        dev_log(sys, 3, b"[snap] xfer sent".as_ptr(), 16);
    }
    xfer_flush(s, sys);
}

/// Write the held install frame, if the export port takes it now.
unsafe fn xfer_flush(s: &mut Snapshot, sys: &SyscallTable) {
    let n = s.xfer_held_len as usize;
    if n == 0 || s.out_export < 0 {
        s.xfer_held_len = 0;
        return;
    }
    if wire_channels::channel_write_msg(
        sys,
        s.out_export,
        wire::MSG_INSTALL_SNAPSHOT_TO,
        &s.xfer_frame[..n],
    ) > 0
    {
        s.xfer_held_len = 0;
        s.xfer_ticks = 0;
    }
}

/// Give the transfer up: its peer's hold re-raises the request and a new
/// copy is asked for. The app's export, still running, is superseded by
/// that next ask (or ends on its own idle bound).
unsafe fn xfer_abandon(s: &mut Snapshot, sys: &SyscallTable) {
    s.xfer_phase = XFER_IDLE;
    s.xfer_sent_until_ms = 0;
    s.xfer_held_len = 0;
    s.xfers_abandoned = s.xfers_abandoned.saturating_add(1);
    dev_log(sys, 2, b"[snap] xfer abandoned".as_ptr(), 21);
}

/// Begin handing the body of the snapshot at `index` to the app.
unsafe fn restore_begin(s: &mut Snapshot, term: Term, index: Index, total: u64, install: bool) {
    s.rs_phase = RS_SENDING;
    s.rs_install = install;
    s.rs_term = term;
    s.rs_index = index;
    s.rs_total = total;
    s.rs_off = 0;
    s.rs_reset_sent = false;
    s.rs_last_done = false;
    s.rs_held = 0;
    s.rs_ticks = 0;
    s.rs_fd = -1;
    s.rs_reader = ChunkReader::new(term, index, membership_of(s, index));
}

/// Close the restore's file and key.
unsafe fn restore_close(s: &mut Snapshot, sys: &SyscallTable) {
    if s.rs_fd >= 0 {
        (sys.provider_call)(s.rs_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.rs_fd = -1;
    }
    if s.rs_reader.key >= 0 {
        sealed::destroy(sys, s.rs_reader.key);
        s.rs_reader.key = -1;
    }
    s.rs_held = 0;
}

/// One step of the hand-off: the RESET, then the body a chunk at a time
/// for as long as the control channel takes it, resuming where it
/// stopped. Then, for a peer install with the acknowledgement wired, the
/// wait for it. Leaves `rs_phase` at `RS_DONE` or `RS_FAILED` when over.
unsafe fn restore_step(s: &mut Snapshot, sys: &SyscallTable) {
    if s.rs_phase == RS_AWAIT_ACK {
        s.rs_ticks = s.rs_ticks.saturating_add(1);
        if s.rs_ticks > RS_ACK_TICKS {
            s.rs_phase = RS_FAILED;
        }
        return;
    }
    if s.rs_phase != RS_SENDING || s.out_app_ctl < 0 {
        return;
    }
    if !s.rs_reset_sent {
        let mut hdr = [0u8; 16];
        hdr[..8].copy_from_slice(&s.rs_term.to_le_bytes());
        hdr[8..].copy_from_slice(&s.rs_index.to_le_bytes());
        if wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_RESET, &hdr)
            <= 0
        {
            return;
        }
        s.rs_reset_sent = true;
    }
    if s.rs_fd < 0 && s.rs_total > 0 {
        s.rs_fd = snap_open_body(s, sys, s.rs_index, 0);
        if s.rs_fd < 0 {
            s.rs_phase = RS_FAILED;
            return;
        }
    }
    let sealed_body = sealing(s) && s.rs_total > 0;
    for _ in 0..8 {
        if s.rs_held > 0 {
            let n = s.rs_held as usize;
            let w = if s.rs_held_sealed {
                let start = sealed::SNAP_HDR_LEN - wire::APP_SNAPSHOT_HDR;
                wire_channels::channel_write_msg(
                    sys,
                    s.out_app_ctl,
                    wire::MSG_APP_SNAPSHOT_CHUNK,
                    &s.seal_buf[start..start + n],
                )
            } else {
                wire_channels::channel_write_msg(
                    sys,
                    s.out_app_ctl,
                    wire::MSG_APP_SNAPSHOT_CHUNK,
                    &s.rs_buf[..n],
                )
            };
            if w <= 0 {
                return; // the channel is full: the same chunk next step
            }
            s.rs_held = 0;
            if s.rs_last_done {
                restore_close(s, sys);
                s.rs_phase = if s.rs_install && s.in_app_ack >= 0 {
                    RS_AWAIT_ACK
                } else {
                    RS_DONE
                };
                s.rs_ticks = 0;
                return;
            }
        }
        // Compose the next chunk.
        let c = if sealed_body {
            let mut r = s.rs_reader;
            let got = read_chunk(s, sys, s.rs_fd, &mut r);
            s.rs_reader = r;
            match got {
                Ok(c) => c,
                Err(_) => {
                    s.seal_failures = s.seal_failures.saturating_add(1);
                    restore_close(s, sys);
                    s.rs_phase = RS_FAILED;
                    return;
                }
            }
        } else {
            let c = (s.rs_total - s.rs_off).min(MAX_CHUNK_BODY as u64) as usize;
            if c > 0 {
                let dst = s.rs_buf.as_mut_ptr().add(wire::APP_SNAPSHOT_HDR);
                if (sys.provider_call)(s.rs_fd, FS_READ, dst, c) != c as i32 {
                    restore_close(s, sys);
                    s.rs_phase = RS_FAILED;
                    return;
                }
            }
            c
        };
        if sealed_body && c == 0 {
            if s.rs_reader.done && s.rs_off != s.rs_total {
                restore_close(s, sys);
                s.rs_phase = RS_FAILED;
                return;
            }
            continue;
        }
        if s.rs_off + c as u64 > s.rs_total {
            restore_close(s, sys);
            s.rs_phase = RS_FAILED;
            return;
        }
        let done = s.rs_off + c as u64 == s.rs_total;
        let mut h = [0u8; wire::APP_SNAPSHOT_HDR];
        h[..8].copy_from_slice(&s.rs_term.to_le_bytes());
        h[8..16].copy_from_slice(&s.rs_index.to_le_bytes());
        h[16..24].copy_from_slice(&s.rs_off.to_le_bytes());
        h[24] = u8::from(done);
        if sealed_body {
            let start = sealed::SNAP_HDR_LEN - wire::APP_SNAPSHOT_HDR;
            s.seal_buf[start..sealed::SNAP_HDR_LEN].copy_from_slice(&h);
        } else {
            s.rs_buf[..wire::APP_SNAPSHOT_HDR].copy_from_slice(&h);
        }
        s.rs_held_sealed = sealed_body;
        s.rs_held = (wire::APP_SNAPSHOT_HDR + c) as u16;
        s.rs_off += c as u64;
        s.rs_last_done = done;
    }
}

/// The app's install acknowledgements: the one naming the restore's index
/// completes it.
unsafe fn drain_app_acks(s: &mut Snapshot, sys: &SyscallTable) {
    if s.in_app_ack < 0 {
        return;
    }
    for _ in 0..4 {
        if !wire_channels::readable(sys, s.in_app_ack) {
            return;
        }
        let mut buf = [0u8; 32];
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_app_ack, &mut buf);
        if msg_type != wire::MSG_APP_SNAPSHOT_INSTALLED || (plen as usize) < 10 {
            continue;
        }
        if u16::from_le_bytes([buf[0], buf[1]]) != s.partition_id {
            continue;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[2..10]);
        let index = u64::from_le_bytes(b);
        if s.rs_phase == RS_AWAIT_ACK && s.rs_install && index == s.rs_index {
            s.rs_phase = RS_DONE;
        }
    }
}

/// Tell raft a peer install landed (owed until its port takes it): the
/// state is the app's and the snapshot durable, so raft may base its log
/// on it; the wal fast-forwards past the prefix it subsumes.
unsafe fn signal_peer_install(s: &mut Snapshot, sys: &SyscallTable) {
    if s.out_installed < 0 {
        s.pi_signal_owed = false;
        return;
    }
    let carries_state = s.out_app_ctl >= 0 && s.rs_total > 0 && s.rs_index == s.pi_index;
    let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
    wire::encode_snapshot_installed(
        &mut buf,
        s.pi_term,
        s.pi_index,
        s.pi_last_term,
        s.pi_membership,
        carries_state,
    );
    if write_installed(s, sys, wire::MSG_SNAPSHOT_INSTALLED, &buf) <= 0 {
        return;
    }
    s.pi_signal_owed = false;
    let prev_index = s.last_snapshot_index;
    s.last_snapshot_term = s.pi_term;
    s.last_snapshot_index = s.pi_index;
    s.last_snapshot_membership = s.pi_membership;
    // Seam latch → wal: the installed prefix will never arrive on
    // `entries`, so the wal fast-forwards its append contract to the
    // install's index (or the next append latches a continuity fault).
    s.wal_fast_forward = (s.pi_last_term, s.pi_index, s.pi_membership);
    s.wal_fast_forward_dirty = true;
    dev_log(sys, 3, b"[snap] installed".as_ptr(), 16);
    // Exactly-one-snapshot steady state: retire the superseded snapshot
    // file only when this install confirmed durable on a real FS.
    if s.pi_durable {
        unlink_prev_snapshot(s, sys, prev_index, s.pi_index);
    }
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
        s.app_captures_unwritable = s.app_captures_unwritable.saturating_add(1);
        return false;
    }
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&term.to_le_bytes());
    buf[8..].copy_from_slice(&index.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_REQUEST, &buf);
    s.app_captures_requested = s.app_captures_requested.saturating_add(1);
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
#[inline(never)]
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
        let n = wire::encode_install_snapshot(
            &mut hdr,
            term,
            index,
            term,
            offset,
            done,
            membership_of(s, index),
            &[],
        );
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

/// Ship the retained snapshot to peers, by the path that matches how it
/// is stored.
///
/// # Safety
/// Exclusive `&mut Snapshot`; `sys` must reach live kernel routines.
unsafe fn export_staged(s: &mut Snapshot, sys: &SyscallTable, term: Term, index: Index) {
    if sealing(s) && s.body_len > 0 {
        if s.out_export >= 0 {
            emit_sealed_body(s, sys, term, index, s.out_export, false);
        }
    } else {
        emit_install_staged(s, sys, term, index);
    }
}

/// Stream a sealed body as logical chunks: to the app (`restore`: a
/// RESET, then `MSG_APP_SNAPSHOT_CHUNK`s) or to peers (InstallSnapshot).
/// Each chunk is opened and authenticated before its plaintext leaves:
/// the receiver seals what it keeps under its own key. The pieces,
/// offsets and final flags are exactly the unsealed stream's. Each
/// message is composed in place in `seal_buf`, its header written over
/// the chunk header just ahead of the plaintext. Returns whether the
/// whole body went out.
///
/// # Safety
/// Exclusive `&mut Snapshot`; `sys` must reach live kernel routines.
#[inline(never)]
unsafe fn emit_sealed_body(
    s: &mut Snapshot,
    sys: &SyscallTable,
    term: Term,
    index: Index,
    chan: i32,
    restore: bool,
) -> bool {
    let total = s.body_len as usize;
    let fd = snap_open_body(s, sys, index, 0);
    if fd < 0 {
        return false;
    }
    if restore {
        if !wire_channels::writable(sys, chan) {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            return false;
        }
        let mut hdr = [0u8; 16];
        hdr[..8].copy_from_slice(&term.to_le_bytes());
        hdr[8..].copy_from_slice(&index.to_le_bytes());
        wire_channels::channel_write_msg(sys, chan, wire::MSG_APP_SNAPSHOT_RESET, &hdr);
    }
    let body = sealed::SNAP_HDR_LEN;
    let mut r = ChunkReader::new(term, index, membership_of(s, index));
    let mut sent = 0usize;
    let mut whole = false;
    while !r.done {
        let c = match read_chunk(s, sys, fd, &mut r) {
            Ok(c) => c,
            Err(_) => {
                s.seal_failures = s.seal_failures.saturating_add(1);
                dev_log(sys, 1, b"[snap] seal read FAIL".as_ptr(), 21);
                break;
            }
        };
        if c == 0 {
            whole = r.done && sent == total;
            continue;
        }
        if sent + c > total || !wire_channels::writable(sys, chan) {
            break;
        }
        let done = sent + c == total;
        let (msg, start) = if restore {
            let start = body - wire::APP_SNAPSHOT_HDR;
            let h = &mut s.seal_buf[start..body];
            h[..8].copy_from_slice(&term.to_le_bytes());
            h[8..16].copy_from_slice(&index.to_le_bytes());
            h[16..24].copy_from_slice(&(sent as u64).to_le_bytes());
            h[24] = u8::from(done);
            h[25..].fill(0);
            (wire::MSG_APP_SNAPSHOT_CHUNK, start)
        } else {
            let start = body - wire::INSTALL_SNAPSHOT_HDR;
            let mut hdr = [0u8; wire::INSTALL_SNAPSHOT_HDR];
            if wire::encode_install_snapshot(
                &mut hdr,
                term,
                index,
                term,
                sent as u64,
                done,
                membership_of(s, index),
                &[],
            ) == 0
            {
                break;
            }
            s.seal_buf[start..body].copy_from_slice(&hdr);
            (wire::MSG_INSTALL_SNAPSHOT, start)
        };
        wire_channels::channel_write_msg(sys, chan, msg, &s.seal_buf[start..body + c]);
        sent += c;
        whole = r.done && sent == total;
    }
    sealed::destroy(sys, r.key);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    whole
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
        let n = wire::encode_install_snapshot(
            &mut buf,
            term,
            index,
            term,
            0,
            true,
            membership_of(s, index),
            &[],
        );
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
            membership_of(s, index),
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
    if s.seal_fault {
        // A sealed snapshot failed authentication: nothing below it may
        // be rebuilt from this replica's media.
        return false;
    }
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
            // Sealed, a body whose CRC holds must also authenticate, chunk
            // by chunk, before anything in it — or its header's term and
            // index — reaches the state machine or consensus. The CRC is
            // judged first: a torn file is a crash's leftovers, while a
            // whole one that does not authenticate is tampering or the
            // wrong key, and fails the replica closed.
            let mut logical = body_len as u32;
            if ok && sealing(s) {
                let term = u64::from_le_bytes([
                    hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
                ]);
                let index = u64::from_le_bytes([
                    hdr[16], hdr[17], hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
                ]);
                let start = (SNAP_HDR_LEN as i32).to_le_bytes();
                let verdict = if (sys.provider_call)(fd, FS_SEEK, start.as_ptr() as *mut u8, 4) < 0
                {
                    Err(ChunkErr::Io)
                } else {
                    let m = wire::Membership::decode(&hdr[40..43]).unwrap_or_default();
                    verify_sealed_body(s, sys, fd, body_len, term, index, m)
                };
                match verdict {
                    Ok(n) => {
                        logical = n;
                        let epoch = u32::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35]]);
                        s.sealed_epoch = epoch;
                        s.done_epoch = epoch;
                    }
                    Err(e) => {
                        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
                        s.seal_failures = s.seal_failures.saturating_add(1);
                        if !s.seal_fault {
                            s.seal_fault = true;
                            if e == ChunkErr::Key {
                                dev_log(sys, 1, b"[snap] seal: key epoch unavailable".as_ptr(), 34);
                            } else {
                                dev_log(sys, 1, b"[snap] seal tag FAIL".as_ptr(), 20);
                            }
                        }
                        return false;
                    }
                }
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
            s.last_snapshot_membership = wire::Membership::decode(&hdr[40..43]).unwrap_or_default();
            // The log below the snapshot may be gone: the configuration
            // the wal replays on top of is the snapshot's.
            s.wal_membership = Some((s.last_snapshot_index, s.last_snapshot_membership));
            s.body_len = logical;
            s.boot_phase = if s.out_app_ctl >= 0 && logical > 0 {
                BOOT_EMIT
            } else {
                BOOT_SIGNAL
            };
            false
        }
        BOOT_EMIT => {
            // The body is handed over resumably: one larger than the
            // control channel's room (a portable install's) lands over
            // several steps, and the app reads it once it is serving.
            if s.rs_phase == RS_IDLE {
                restore_begin(
                    s,
                    s.last_snapshot_term,
                    s.last_snapshot_index,
                    u64::from(s.body_len),
                    false,
                );
            }
            restore_step(s, sys);
            match s.rs_phase {
                RS_DONE => {
                    s.rs_phase = RS_IDLE;
                    dev_log(sys, 3, b"[snap] boot restored".as_ptr(), 20);
                    s.boot_phase = BOOT_SIGNAL;
                }
                RS_FAILED => {
                    // Started over from the RESET next step.
                    s.rs_phase = RS_IDLE;
                }
                _ => {}
            }
            false
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
                s.last_snapshot_membership,
                s.out_app_ctl >= 0 && s.body_len > 0,
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
        if sealing(s) && s.done_epoch != 0 {
            s.sealed_epoch = s.done_epoch;
        }
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

/// The configuration a snapshot at `index` records: the one being
/// written, the last one published, or (taking one now) the log's.
fn membership_of(s: &Snapshot, index: Index) -> wire::Membership {
    if index == s.windex {
        s.wmembership
    } else if index == s.last_snapshot_index {
        s.last_snapshot_membership
    } else {
        s.cfg.at(index)
    }
}

/// Build the snapshot header for `body_len` bytes of body.
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
    // Sealed, the epoch is the one the stream's chunks were sealed under,
    // fixed when it began.
    let epoch = if sealing(s) { s.wepoch } else { s.dek_epoch };
    hdr[32..36].copy_from_slice(&epoch.to_le_bytes());
    hdr[36..40].copy_from_slice(&body_len.to_le_bytes());
    hdr[40..43].copy_from_slice(&s.wmembership.encode());
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
    membership: wire::Membership,
) -> (bool, bool) {
    snap_abort(s, sys);
    s.wmembership = membership;
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
    if sealing(s) {
        // A fresh generation, the epoch in force, and the chunk key under
        // both. No epoch yet (the wal has not established one) or no key
        // refuses the stream: the caller withholds its install signal.
        s.wepoch = s.dek_epoch;
        s.wterm = term;
        s.windex = last_idx;
        let ok = s.wepoch != 0 && sealed::random_fill(sys, &mut s.wgen);
        s.wkey = if ok {
            snap_key(s, sys, s.wepoch, &s.wgen)
        } else {
            -1
        };
        if s.wkey < 0 {
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            s.seal_failures = s.seal_failures.saturating_add(1);
            dev_log(sys, 2, b"[snap] seal key unavailable".as_ptr(), 27);
            return (false, true);
        }
        s.wchunk = 0;
        s.wfill = 0;
        s.wstored = 0;
    }
    // Placeholder header: body_len is not known until the last chunk.
    // `snap_finish` seeks back and rewrites it.
    let mut hdr = snap_header(s, term, last_idx, last_term, 0);
    let ok =
        (sys.provider_call)(fd, FS_WRITE, hdr.as_mut_ptr(), SNAP_HDR_LEN) == SNAP_HDR_LEN as i32;
    if !ok {
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        sealed::destroy(sys, s.wkey);
        s.wkey = -1;
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
    if sealing(s) {
        // Stage toward whole `SEAL_CHUNK_PLAIN` chunks; the remainder is
        // sealed as the final chunk by `snap_finish`.
        let mut done = 0usize;
        while done < len {
            let room = SEAL_CHUNK_PLAIN - s.wfill as usize;
            let take = (len - done).min(room);
            core::ptr::copy_nonoverlapping(
                src.add(done),
                s.seal_buf
                    .as_mut_ptr()
                    .add(sealed::SNAP_HDR_LEN + s.wfill as usize),
                take,
            );
            s.wfill += take as u32;
            done += take;
            if s.wfill as usize == SEAL_CHUNK_PLAIN && !seal_chunk_out(s, sys, 0) {
                snap_abort(s, sys);
                return false;
            }
        }
        s.wbody = s.wbody.saturating_add(len as u32);
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
    if s.wkey >= 0 {
        sealed::destroy(sys, s.wkey);
        s.wkey = -1;
    }
    s.wfill = 0;
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
    let logical = s.wbody;
    // Sealed, the body ends with the chunk carrying the final flag: the
    // staged remainder, possibly empty, so every sealed body has an
    // authenticated end.
    let mut ok = !sealing(s) || seal_chunk_out(s, sys, sealed::SNAP_FLAG_FINAL);
    if s.wkey >= 0 {
        sealed::destroy(sys, s.wkey);
        s.wkey = -1;
    }
    let body_len = if sealing(s) { s.wstored } else { logical };
    let mut hdr = snap_header(s, s.wterm, s.windex, s.wlast_term, body_len);

    // 1. True header at offset 0.
    let zero = 0i32.to_le_bytes();
    ok = ok
        && (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4) >= 0
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
        s.body_len = logical;
        s.snap_bytes_written = s.snap_bytes_written.saturating_add(logical as u64);
        if sealing(s) {
            // The previous file may survive until it is retired: keep the
            // lower of the two epochs live until then.
            s.done_epoch = s.wepoch;
            if s.sealed_epoch == 0 || s.wepoch < s.sealed_epoch {
                s.sealed_epoch = s.wepoch;
            }
        }
        dev_log(sys, 3, b"[snap] durable".as_ptr(), 14);
    } else {
        s.install_failures = s.install_failures.saturating_add(1);
        dev_log(sys, 3, b"[snap] durable FAIL".as_ptr(), 19);
    }
    s.wbody = 0;
    ok
}
