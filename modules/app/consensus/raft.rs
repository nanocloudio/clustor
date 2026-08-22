//! raft — core Raft consensus state machine component.
//!
//! Implements leader election (with pre-vote), log replication dispatch,
//! proposal batching, and heartbeat generation. Role-dependent step logic
//! drives the follower/candidate/leader state machine. Persists
//! term/vote/durable-index metadata into two generational CRC-sealed
//! slots (`RAFT<pppp>.M<slot>` on bare-metal FAT32, `raft/meta<slot>`
//! otherwise) via the FS contract.
//!
//! Seams (owned here, drained by the dispatch table in `mod.rs`):
//! AppendEntries outbox ring → replicator; log-body outbox ring →
//! apply; commit-horizon in-latch from commit; apply-horizon/reset
//! out-latches → apply; read-probe reply queue → apply; voter-set
//! latch → commit + replicator; §5.4.2 term-fence latch → commit. Probe
//! requests and committed admin entries are consumed from apply's queues
//! at the top of this step; a deposed-leader term hint arrives from the
//! replicator via `on_peer_term`.
//!
//! Per-step bound (Discipline §5): ≤8 RPCs, ≤4 each of admin /
//! snapshot-installed / probe / admin-committed / replay drains, ≤8
//! WAL-flushed acks, ≤4×16 proposal reads, plus O(1) role logic.
//! Metadata persistence is bounded per DRAINED RPC, not per step: a
//! vote grant or a term adoption writes one 64-byte slot record
//! (seek+write+fsync+seek+read) each, so a step draining 8 vote
//! requests can issue 8 — plus, once per slot, the name fence, and once
//! per boot in dir mode an `FS_MKDIR` and one retried open. Any step
//! that touched metadata is reported Burst (`meta_fs_step`), which is
//! what keeps the guard honest rather than the count.

use super::abi::SyscallTable;
use super::collections::Crc32c;
use super::seam::{HorizonLatch, SeamRing, PROBE_QUEUE_SLOTS};
use super::types::*;
use super::{
    dev_log, dev_micros, dev_millis, dev_report_step_effect, step_effect, wal_frame, wire,
    wire_channels,
};

/// One coalesced batch = one WAL entry body. Derived from the shared
/// frame contract so the write path can never exceed what replay
/// accepts (`wal_frame::MAX_ENTRY_LEN = ENTRY_PROLOGUE + MAX_ENTRY_BODY`).
const PROPOSAL_BATCH_CAP: usize = wal_frame::MAX_ENTRY_BODY;

/// Per-batch correlation slot count. The slot is set non-zero only for
/// proposals that arrived via the tagged port; legacy proposals from the
/// untagged port leave the slot zero and produce no MSG_PROPOSAL_ASSIGNED.
const MAX_BATCH_PROPOSALS: usize = 256;

/// In-flight strict-ReadIndex probes the leader tracks at once. With N
/// mixed-load client connections each holding one fence, concurrent
/// probes ≈ connection count, so the table must exceed the typical
/// connection count or newcomers get rejected at the boundary. Slots
/// are 48 bytes; 32 is cheap.
const MAX_INFLIGHT_PROBES: usize = 32;

/// How long a strict-ReadIndex probe may wait for majority replies
/// before we give up and answer the read with fallback. Sized to the
/// election-timeout floor so a slow follower can't trick us.
const PROBE_TIMEOUT_MS: u64 = 1500;
/// Durability-backpressure window (RFC §13/§14). The leader stops pulling
/// new proposals once its log runs this many entries ahead of `commit_index`
/// (i.e. ahead of quorum-durable state).
///
/// The channel alone gives no backpressure here: in WAL group-fsync mode
/// the WAL absorbs writes faster than they commit, so the raft→wal channel
/// never fills and raft races ahead, overflowing the `log_observe` fanout
/// and apply's body buffer until it evicts un-applied entries.
///
/// Bounds: must stay ≤ apply's `PENDING_ENTRY_SLOTS` (64) so a full backlog
/// never forces an eviction, and within `TAIL_TERM_RING` / `COMMIT_TS_RING`
/// (64). Little's Law sizing: sustained throughput ≈ window / commit
/// latency; 48 is the knee for the Pi 5 NVMe path — deep enough to hide
/// fsync latency behind the WAL's pipelined durability fences (wal
/// `fence_depth`), past which the device's serial fsync-barrier rate
/// (~1000/s) dominates and a wider window only adds latency. Uncommitted
/// entries are WAL-fsynced-before-ack, so the window trades memory, not
/// durability.
const MAX_UNCOMMITTED_INFLIGHT: u64 = 48;

/// How far `last_log_index` may run ahead of `local_durable_index` — i.e. how
/// many appends may sit in the WAL's input channel unacknowledged — before we
/// stop accepting more. Bounds the log-vs-WAL divergence that
/// `channel_write_msg` success cannot detect (see the durability bound in
/// `handle_append_entries`). Generous enough not to throttle healthy
/// pipelining on a disk-backed WAL, small enough that a stalled WAL is caught
/// long before the divergence covers committed entries.
const MAX_WAL_UNACKED: u64 = 256;

/// How many election timeouts a conflict-repair truncation may stay
/// unacknowledged before the request is abandoned. The hold NACKs every
/// AppendEntries, refuses candidacy and suspends the no-op, so a WAL that
/// never answers — a latched failure, an unopenable segment, a graph with
/// only one direction of the pair wired — would otherwise take the node
/// out of replication for good. Wide enough that ordinary fsync latency
/// and a re-sent request never reach it.
const TRUNCATE_HOLD_TIMEOUTS: u64 = 3;

/// Recent (index → term) ring for follower-side log matching and Raft §5.3
/// conflict repair. Only the *uncommitted* tail can ever diverge (committed
/// entries are immutable and identical cluster-wide), and that tail is
/// bounded by `MAX_UNCOMMITTED_INFLIGHT`, so a small power-of-two ring covers
/// every index a conflict check can legitimately target. Indices at/below
/// `commit_index` are trusted to match without a ring hit.
const TAIL_TERM_RING: usize = 64;
const TAIL_TERM_MASK: u64 = (TAIL_TERM_RING as u64) - 1;

#[derive(Clone, Copy)]
#[repr(C)]
struct TailTerm {
    /// 0 means the slot is empty.
    index: Index,
    term: Term,
}

/// Slots in the append→commit timestamp ring (RFC §4.1 commit latency).
/// Sized to cover in-flight uncommitted entries on the leader; a wrap
/// before commit just drops that sample (the equality check guards it).
const COMMIT_TS_RING: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
struct ProbeSlot {
    /// 0 = slot empty.
    probe_id: u64,
    /// The apply-side correlation id we'll echo back.
    correlation_id: u64,
    /// commit_index sampled at the moment the probe was issued.
    snapshot_commit: u64,
    /// Term of the probe (so stale replies after a leader change get dropped).
    term: u64,
    /// Replicas that have confirmed our leadership (includes self).
    votes: NodeSet,
    /// Wall-clock deadline; if we don't reach majority by then we
    /// reply with confirmed=0.
    deadline_ms: u64,
    /// The peer broadcast actually landed on `out_rpc`. Without this,
    /// a probe whose broadcast hit backpressure becomes a zombie slot
    /// (occupied, nothing in flight, guaranteed timeout-reject);
    /// `expire_probes` re-attempts unsent broadcasts each step.
    broadcast_sent: bool,
}

impl ProbeSlot {
    const fn empty() -> Self {
        Self {
            probe_id: 0,
            correlation_id: 0,
            snapshot_commit: 0,
            term: 0,
            votes: NodeSet::empty(),
            deadline_ms: 0,
            broadcast_sent: false,
        }
    }
}

// FS opcodes
const FS_OPEN: u32 = 0x0900;
/// Write-side opener: creates the file if absent (FS_OPEN is read-only-
/// if-exists). Required for the root-level metadata file on bare-metal
/// FAT32, which has no mkdir for the default `raft/meta` parent.
const FS_OPEN_CREATE: u32 = 0x0909;
/// FS E_AGAIN: provider present but still initialising (fat32 reading the BPB
/// on a pi5 cold boot). `load_metadata` must retry rather than treat this as
/// "no metadata" — otherwise a recovering node restarts fresh.
const FS_E_AGAIN: i32 = -11;
const FS_READ: u32 = 0x0901;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
const FS_SEEK: u32 = 0x0902;
/// Directory create (single-level, EEXIST-idempotent on the linux
/// provider; bare-metal FAT32 answers ENOSYS). Used once per boot to
/// self-heal a missing `raft/` parent in dir-mode persistence.
const FS_MKDIR: u32 = 0x090B;
/// Durable publication of a parent-directory entry
/// (`modules/sdk/contracts/storage/fs.rs::{FSYNC_NAME, caps::FSYNC_NAME}`).
/// `FS_FSYNC` makes a slot's bytes durable through its descriptor; the
/// name that lets the next boot open the slot at all is a separate
/// fence, and it is the one that matters on first creation.
const FS_FSYNC_NAME: u32 = 0x0912;
const FS_CAPS: u32 = 0x09FF;
const FS_CAP_FSYNC_NAME: u32 = 1 << 11;

/// `name_fence` postures — 0 = auto (fence where the provider
/// advertises `caps::FSYNC_NAME`, meter the publications it cannot
/// fence), 1 = strict (refuse to create a slot whose name the provider
/// cannot fence).
const NAME_FENCE_STRICT: u8 = 1;

/// `name_fence_probe` / `RAFT_NAME_FENCE` dispositions.
const NAME_FENCE_UNPROBED: u8 = 0;
const NAME_FENCE_PRESENT: u8 = 1;
const NAME_FENCE_ABSENT: u8 = 2;

/// Outcome of a metadata persist attempt. Voting-relevant callers gate
/// on `Persisted`; `Transient` (FS provider initialising) carries no
/// error accounting; `Failed` counts into `meta_write_errors` and
/// invalidates the cached fd so the next attempt reopens.
#[derive(Clone, Copy, PartialEq)]
enum PersistOutcome {
    Persisted,
    Transient,
    Failed,
}

// Metadata file path scheme (RFC partition_groups):
//   single-partition graphs (partition_id = 0):  raft/meta
//   per-partition graphs   (partition_id = N>0): raft/p<NNNN>/meta
// Width is enough for u16; we'll never have more than 65k partitions
// per node and the volatile-FS provider keys files by hash of path.
//
/// Number of metadata slots. Each slot is a SEPARATE FILE so that the
/// two records never share a read-modify-write unit: a persist rewrites
/// one file's data cluster, and a torn or lost sector there damages
/// that slot alone. Two records packed into one file share that unit
/// and fail together — one failure unit wearing two names, not
/// redundancy.
///
/// The records are only half of it: the namespace that finds them has
/// its own failure unit. On FAT32 a directory entry is 32 bytes inside
/// a 512-byte directory sector, and two entries in one directory
/// routinely share one — so minting the second name mutates a sector
/// the first name already occupies.
///
/// `materialize_meta_slots` therefore creates BOTH files, sizes both,
/// and fences both names before any non-neutral generation is adopted.
/// That is what makes the pair independent from the first adopted
/// generation onward: every later persist seeks to 0 and overwrites
/// fixed-size data in a file that already has its size and its cluster
/// chain, so no publication ever touches the directory again. Doing it
/// lazily instead would put the second name's creation AFTER the first
/// generation was adopted and durable, which is precisely when there is
/// something to lose.
const META_SLOTS: usize = 2;

/// Slot record magic and format id.
const META_MAGIC: u32 = 0x4D54_4652;
const META_FORMAT_ID: u16 = 1;

/// Slot record size.
///
/// Layout (64 bytes):
///   `[magic:u32][format:u16][pad:u16][generation:u64][term:u64]
///    [voted_for:i8][current_voters:u8][joint_voters:u8][joint_active:u8]
///    [durable_index:u64][durable_term:u64][reserved:16][crc32c:u32]`
///
/// The CRC covers bytes `0..60`. A record is accepted only with the
/// right magic, the right format id, and a matching CRC.
const META_SLOT_SIZE: usize = 64;
const META_CRC_OFF: usize = 60;

/// Flat record: one unchecksummed record written in place, with no
/// magic, generation or CRC. Read once at boot when neither slot
/// validates, so a node whose store holds this shape still recovers
/// its term and vote rather than restarting at term 0.
///
/// Layout (28 bytes):
///   `[current_term:u64][voted_for:i8][last_log_index:u64]
///    [last_log_term:u64][current_voters:u8][joint_voters:u8]
///    [joint_active:u8]`
///
/// Only the election-safety fields are read out of it — the term, the
/// vote, and the voter set when the record carries one. Its two log
/// bytes pair a durable index with the tip term, which describe
/// different entries, so nothing seeds the log tip from them.
const META_FLAT_SIZE: usize = 28;
/// Shortest accepted flat record: enough bytes to be the shape above
/// rather than a fragment of something else. The three voter-set bytes
/// are optional.
const META_FLAT_MIN: usize = 25;
const META_PATH_MAX: usize = 32;
/// Persist metadata on the durable-ack path at most once per this many
/// durable-index advances (a crash loses at most this much of the durable
/// *hint*; the WAL replay re-derives the exact durable index on recovery).
const META_PERSIST_STRIDE: Index = 64;

#[repr(C)]
pub struct Raft {
    // ── Channels ────────────────────────────────────────────
    pub in_rpc: i32,                          // in[0]: RPC from peers (via peer_router)
    pub in_proposals: i32,                    // in[1]: ClientProposal (legacy, untagged)
    pub in_admin: i32,                        // in[2]: AdminCommand from operations
    pub in_proposals_tagged: i32,             // in[3]: ClientProposal with 8-byte correlation_id prefix
    pub in_proposals_partitioned: i32,        // in[4]: ClientProposal in 5-byte partitioned envelope
    pub in_proposals_partitioned_tagged: i32, // in[5]: partitioned + correlation_id
    pub in_snapshot_installed: i32,           // in[6]: MSG_SNAPSHOT_INSTALLED from durability
    pub in_wal_flushed: i32,                  // in[7]: MSG_FSYNC_ACK from local wal.flushed (spec §10.4.1)
    pub in_wal_replay_complete: i32,          // in[8]: MSG_WAL_REPLAY_COMPLETE (recovery resume)
    pub out_rpc: i32,                         // out[0]: Vote/Heartbeat RPC to peer_router
    pub out_log: i32,                         // out[2]: WalEntry to wal
    pub out_metrics: i32,                     // out[3]: MetricsPayload (shared module port)
    pub out_proposal_assigned: i32,           // out[4]: MSG_PROPOSAL_ASSIGNED back to proposer
    pub out_leader_state: i32,                // out[5]: MSG_LEADER_HINT (leader_id, term)
    pub out_admin_applied: i32,               // out[6]: MSG_ADMIN_APPLIED back to operations
    pub out_wal_compact: i32,                 // out[7]: MSG_WAL_COMPACT_BEFORE to wal

    // ── Seams (drained by the mod.rs dispatch table) ────────
    /// E1: AppendEntries outbox → replicator.
    /// All-or-nothing push; a full ring drops the frame whole — the
    /// heartbeat / catch-up paths re-cover it.
    pub outbox_ae: SeamRing<8192>,
    /// E5: appended-entry body fanout → apply.
    /// Fail-open drop-on-full preserved.
    pub outbox_bodies: SeamRing<8192>,
    /// E3: quorum commit horizon from commit. Consumed by
    /// `drain_commit_in` — next step relative to commit's raise
    /// (one-tick feedback).
    pub commit_in: HorizonLatch,
    /// E6: apply-horizon advance → apply. Always deliverable.
    pub apply_horizon_out: HorizonLatch,
    /// E6 RESET: snapshot-install apply reset → apply. Latched
    /// `(term, index)`; consumed at the top of apply's step.
    pub apply_reset_out: Option<(Term, Index)>,
    /// E8: strict-ReadIndex probe replies → apply.
    /// `(correlation_id, confirmed_commit, confirmed)`; a full queue
    /// drops the reply — the client retry path re-covers it.
    pub probe_reply_out: [(u64, u64, u8); PROBE_QUEUE_SLOTS],
    pub probe_reply_count: u8,
    /// E10: voter-set update → commit + replicator (was
    /// `out_voter_set`). `(current, joint, joint_active)` bitmasks,
    /// delivered in the same step the config change applies.
    pub voter_out: Option<(u8, u8, u8)>,

    // ── Partition slot (multi-Raft) ─────────────────────────
    // 0 for single-partition graphs. Drives META path and is exposed
    // in metrics so cross-partition logs are disambiguable.
    pub partition_id: u16,

    // ── Raft persistent state ───────────────────────────────
    current_term: Term,
    voted_for: i8,            // -1 = none, 0..6 = replica id
    pub self_id: ReplicaId,

    // ── Volatile state ──────────────────────────────────────
    role: u8,                 // ROLE_FOLLOWER / CANDIDATE / LEADER
    leader_id: i8,            // -1 = unknown
    pub voter_count: u8,

    /// Current Raft voter set. Initially populated from
    /// `voter_count` (ids 0..voter_count). Updated as committed
    /// `CONFIG_CHANGE` entries flow through `drain_admin_committed`.
    /// See RFC §1.2.
    current_voters: NodeSet,
    /// Joint-consensus transition set. `Some` only while a
    /// `C_old,new` entry has been committed and `C_new` has not yet.
    /// While `Some`, quorum requires majority over BOTH `current`
    /// and `joint` sets.
    joint_voters: NodeSet,
    /// True iff `joint_voters` is the active overlay (so we don't
    /// have to encode "Some via a sentinel" inside a NodeSet bitmask).
    joint_active: bool,
    /// A freshly-elected leader owes the log a current-term no-op entry
    /// (Raft §5.4.2): prior-term entries must never be committed by
    /// counting replicas directly, and the no-op is what lets them
    /// commit transitively. Set in `become_leader`, cleared once
    /// `append_noop` lands the entry in the WAL.
    noop_pending: bool,
    /// E12 seam: (term, first index of that term) for the commit
    /// component's §5.4.2 gate. Latched by `append_noop`; drained by the
    /// dispatch table into `commit::on_term_fence`.
    pub commit_fence_out: Option<(Term, Index)>,
    /// Set on a leader once a `CONFIG_CHANGE_OP_JOINT` entry commits;
    /// the next `step_leader` tick auto-proposes the matching
    /// `CONFIG_CHANGE_OP_NEW` entry to complete the joint-consensus
    /// transition. Cleared after the proposal is emitted. RFC §1.2.
    pending_new_voters: NodeSet,
    pending_new_voters_set: bool,
    /// Learner mode (RFC §1.2): this replica is not in the current
    /// voter set — typically because a `CONFIG_CHANGE_OP_NEW` committed
    /// that removed `self_id`. While in learner mode the node still
    /// replicates the log and serves reads, but does NOT trigger
    /// election timeouts or grant votes. The flag clears if a later
    /// config change re-adds the node to the voter set.
    learner_mode: bool,

    // ── Election ────────────────────────────────────────────
    pub election_timeout_ms: u16,
    election_deadline_ms: u64,
    pub heartbeat_interval_ms: u16,
    last_heartbeat_ms: u64,
    votes_granted: NodeSet,
    votes_rejected: NodeSet,
    pre_vote_active: bool,

    // ── Log tracking ────────────────────────────────────────
    last_log_index: Index,
    last_log_term: Term,
    commit_index: Index,
    /// Recent (index → term) ring (see `TAIL_TERM_RING`). Written whenever
    /// `last_log_index` advances (leader flush, follower accept); read by the
    /// follower log-match / conflict-repair path. Zero-initialised (empty).
    tail_terms: [TailTerm; TAIL_TERM_RING],
    /// Count of Raft §5.3 conflict-repair truncations this node has driven
    /// (divergent suffix discarded). Emitted as `raft.log_truncations`.
    log_truncations: u32,

    // ── Pending WAL truncation (Raft §5.3 conflict repair) ──
    /// A truncation the WAL has been asked for but has NOT yet reported
    /// durable. The tip is NOT rewound while this is set: until the
    /// correlated ack arrives, this node still holds the old suffix, so
    /// it must not accept a replacement one, must not stand for
    /// election on a tip it has agreed to discard, and must not let a
    /// repeated or newer AppendEntries overtake the request.
    truncate_pending: bool,
    /// Keep-through index of the pending request.
    truncate_keep: Index,
    /// Correlation id of the pending request. Only an ack carrying this
    /// id and this keep index releases the rewind.
    truncate_req_id: u32,
    /// Monotone source for `truncate_req_id`.
    truncate_req_seq: u32,
    /// Wall-clock bound on the pending request (`TRUNCATE_HOLD_TIMEOUTS`
    /// election timeouts). Past it the request is abandoned and the node
    /// returns to the conservative posture: the log is left whole and the
    /// leader is NACKed into retrying.
    truncate_deadline_ms: u64,
    /// The request could not be written to the control channel (full,
    /// short write, or a hard error). It is re-emitted every step until
    /// it lands: a dropped emit must never silently permit the rewind.
    truncate_emit_pending: bool,
    /// A `MSG_WAL_COMPACT_BEFORE` the control channel has not taken yet
    /// (`0` = none). Edge-triggered — it is raised once, by a snapshot
    /// install or a local snapshot, and nothing raises it again until
    /// the NEXT snapshot. A dropped one therefore leaves the WAL holding
    /// every retired segment until then, so it is retried each step
    /// instead. Highest index wins: the floor is monotone, so a later
    /// signal supersedes an earlier one that has not landed.
    compact_before_pending: u64,
    /// A committed admin op whose `MSG_ADMIN_APPLIED` status the channel
    /// has not taken yet. The op is already applied by the time the ack
    /// is written, so this is not re-applied — it is re-ANNOUNCED, and
    /// `drain_admin_committed` refuses to pop the next admin record
    /// while it is set, which is what keeps the seam's own retention
    /// from being undone by a lost status.
    admin_ack_pending: bool,
    admin_ack_id: u32,
    admin_ack_status: u8,
    /// The pending request reached the WAL's control channel at least
    /// once. Until it has, the WAL cannot have begun retiring anything
    /// for it and the hold may be released; once it has, only a
    /// correlated ack may release it — the WAL's retirement runs across
    /// many steps, so silence is indistinguishable from work in
    /// progress.
    truncate_delivered: bool,
    /// Truncation requests the WAL refused as not durable. Diagnostic.
    truncate_nacks: u32,
    /// AppendEntries held (`busy` NACK) because a truncation was still
    /// unacknowledged. Diagnostic.
    truncate_holds: u32,
    /// WAL continuity rejections repaired (`MSG_WAL_REJECT` → tip rollback).
    /// Emitted as `raft.wal_resyncs`; steady state 0.
    wal_resyncs: u32,
    /// Appends held because our log was already `MAX_WAL_UNACKED` ahead of
    /// `local_durable_index`. Non-zero means the WAL is the bottleneck and
    /// backpressure is doing its job — not an error.
    wal_unacked_holds: u32,
    /// AppendEntries refused because `entry_index != last_log_index + 1` while
    /// `prev_log_*` matched — a leader shipping a mis-sequenced entry. Steady
    /// state 0; non-zero means log repair ran instead of a WAL hole.
    ae_noncontiguous: u32,

    /// Replica-local WAL-durable watermark (spec §10.4.1
    /// `local_wal_durable_index`). Tracked from MSG_FSYNC_ACK on the
    /// local `wal.flushed` port. On followers, this value is stamped
    /// into every AppendEntriesResponse so the leader's
    /// durability ledger can compute quorum-fsync durability across
    /// replicas without each follower owning a peer-bound side
    /// channel.
    local_durable_index: Index,
    /// Term of the entry AT `local_durable_index`, taken from the WAL's
    /// own fsync ack / replay high-water. The metadata record must pair
    /// the durable index with THIS term: `last_log_term` describes the
    /// volatile tip, which can be newer than anything on disk, and a
    /// record claiming (durable index, newer term) over-states how
    /// up-to-date the recovered log is in an election.
    local_durable_term: Term,

    // ── Persistent metadata (term/vote/durable index) ───────
    /// 1 = persist metadata to a ROOT-level 8.3 file (`RAFT<pppp>.MET`)
    /// via FS_OPEN_CREATE, mirroring `wal.root_path`. Required on bare-metal
    /// FAT32 (no mkdir, so the `raft/meta` path can't be created). Default 0
    /// keeps the `raft/meta` layout for the linux volatile-FS provider.
    pub meta_root_path: u8,
    /// Cached fd per metadata slot (both path modes): opened once with
    /// FS_OPEN_CREATE and reused for every persist, so a save never pays
    /// a cold dir-scan re-open. -1 = not yet opened. Invalidated (closed
    /// and reset to -1) on any write/fsync failure so a transiently
    /// broken path never permanently disenfranchises the node.
    meta_fds: [i32; META_SLOTS],
    /// Slot index (0/1) holding the record with the highest valid
    /// generation. The next persist targets the OTHER slot, so a torn
    /// write can never damage the record recovery would fall back to.
    meta_slot: u8,
    /// Generation of the record in `meta_slot`. Monotone; boot picks the
    /// highest generation that validates.
    meta_generation: u64,
    /// 0 = no metadata persistence at all (the declared volatile
    /// posture: no load, no saves, boot vote hold-off + term floor
    /// instead). 1 (default) = persist via the FS contract.
    pub persist_meta: u8,
    /// Hard metadata persist failures (counter; metric
    /// RAFT_META_WRITE_ERRORS). Transient E_AGAIN outcomes are not
    /// counted.
    meta_write_errors: u32,
    /// One-shot guard for the `[raft] meta write fail` log.
    meta_fail_logged: bool,
    /// One-shot guard for the dir-mode `raft/` parent self-heal.
    meta_mkdir_attempted: bool,
    /// One-shot guard for the `[raft] no name fence` log: the condition
    /// is permanent for the life of the provider and recurs on every
    /// persist attempt.
    name_fence_logged: bool,
    /// One-shot guard for the `[raft] name fence FAIL` log.
    name_fence_fail_logged: bool,
    /// Counter behind `RAFT_NAME_UNFENCED`: slot names published without
    /// a fence because the provider does not advertise the capability.
    /// Zero under the strict posture, which refuses instead.
    name_unfenced: u32,
    /// FS `caps::FSYNC_NAME` probe cache: `NAME_FENCE_UNPROBED`,
    /// `NAME_FENCE_PRESENT`, `NAME_FENCE_ABSENT`.
    name_fence_probe: u8,
    /// Param `name_fence` (0 = auto, 1 = strict).
    pub name_fence: u8,
    /// Per-slot record of whether this boot has already fenced that
    /// slot's directory entry. A slot file is created once and
    /// overwritten in place thereafter, so the fence is paid on the
    /// creation that mints the name, not on every persist.
    meta_name_published: [bool; META_SLOTS],
    /// Both slot files exist at full size with their names fenced, so
    /// every later persist is a pure in-place data overwrite. See
    /// `materialize_meta_slots` for why this must be true before the
    /// first generation is adopted.
    meta_slots_materialized: bool,
    /// Error-side backoff: steps remaining during which the throttled
    /// durable-hint persist is skipped after a hard failure. The
    /// vote/election persist sites always attempt regardless.
    meta_backoff_steps: u16,
    /// Volatile posture only: wall-clock until which real vote grants
    /// and real election starts are held off after boot (0 = inactive).
    holdoff_until_ms: u64,
    /// One-shot guard for the `[raft] holdoff over` log.
    holdoff_over_logged: bool,
    /// Volatile posture only: highest term observed in AppendEntries
    /// traffic since boot. Real vote grants require a term strictly
    /// above this floor — a restarted memoryless node that has heard
    /// the current leader can never re-vote in that leader's election.
    vote_floor_term: Term,
    /// Highest `local_durable_index` already persisted to the metadata file.
    /// Throttles the durable-path persist so we don't fsync metadata on every
    /// single durable-index advance (which would double the WAL fsync load).
    meta_persisted_durable: Index,
    /// Set true by load_metadata on a recovery boot (persisted durable index
    /// > 0). On the first step after the WAL hands over its high-water, raft
    /// raises the apply horizon to the recovered durable base so apply seeds
    /// its horizon there — otherwise it would gap (expecting index 1 while
    /// the WAL replay re-acks committed entries at the recovered base) and
    /// never apply post-recovery commits. Cleared once the raise lands.
    /// (The recovery floor here is the durable index; a state machine with a
    /// persisted *applied* snapshot index would seed from that instead.)
    pending_recovery_reset: bool,
    /// True while the boot-time metadata load is still waiting on the FS
    /// provider (FS_OPEN returned E_AGAIN at module_new — fat32 not ready
    /// yet). The step retries `load_metadata` until it resolves, or a
    /// recovering node restarts fresh instead of picking up its persisted
    /// term/vote/durable-index.
    meta_load_pending: bool,
    /// Recovery intake hold. Set at init whenever the dedicated
    /// `wal_replay_complete` edge is wired (a disk-recovery graph) —
    /// deliberately INDEPENDENT of the persisted meta hint, which can read
    /// back as 0 (throttled / early-save) and must not be the thing that
    /// decides whether to wait. While true, `step_leader` does NOT drain
    /// proposals — raft must not append new entries before it learns the
    /// WAL's true on-disk high-water, or they collide with the index space
    /// the WAL is still re-acking from replay. Cleared when
    /// `drain_wal_replay_complete` receives that high-water and resumes
    /// `last_log_index` there (the WAL's replayed high-water is
    /// AUTHORITATIVE, overriding the meta hint). See
    /// `wire::MSG_WAL_REPLAY_COMPLETE`.
    awaiting_replay: bool,
    /// Diagnostic: the WAL replay high-water raft last resumed at (0 if none).
    replay_hw_received: Index,
    /// Diagnostic: the log index raft loaded from RAFT0000.MET at boot
    /// (0 = none / fresh). Exposes whether the persisted hint is present.
    meta_hint_loaded: Index,

    // ── Proposal batching ───────────────────────────────────
    proposal_batch: [u8; PROPOSAL_BATCH_CAP],
    proposal_batch_len: u16,
    proposal_batch_count: u16,
    pub proposal_batch_max: u16,
    proposal_batch_start_ms: u64,
    pub proposal_batch_timeout_ms: u16,

    /// Durability backpressure (RFC §13/§14). Set true when
    /// `flush_proposal_batch` could not write to `out_log` (the WAL is
    /// mid-fsync or overloaded). While true, the batch is held pending —
    /// `last_log_index` is NOT advanced, so raft's log never diverges from
    /// the WAL — and proposal intake is suspended (`drain_proposals`
    /// returns early), leaving proposals queued in their input channels so
    /// the upstream proposer backpressures rather than loses them. Cleared
    /// on the next successful flush, and on every role transition (the
    /// batch it describes is discarded there).
    flush_deferred: bool,
    /// Count of flush deferrals — emitted as RAFT_FLUSHES_DEFERRED.
    flushes_deferred: u32,

    /// Parallel array indexed [0..proposal_batch_count). 0 means the
    /// proposal was untagged (no MSG_PROPOSAL_ASSIGNED to emit). Non-zero
    /// is the per-proposal correlation_id supplied by the proposer on the
    /// tagged input port.
    correlation_ids: [u64; MAX_BATCH_PROPOSALS],

    // ── Strict fallback ─────────────────────────────────────
    strict_fallback: bool,

    // ── In-flight strict-ReadIndex probes ───────────────────
    probes: [ProbeSlot; MAX_INFLIGHT_PROBES],
    next_probe_id: u64,

    // ── Admin-induced state (RFC §14) ───────────────────────
    /// Set by `ADMIN_OP_FREEZE`; cleared by `ADMIN_OP_THAW`. While
    /// frozen, the proposal-intake paths drop new client proposals
    /// silently (client times out via the codec retry). Existing
    /// in-flight entries continue to replicate.
    frozen: bool,

    /// Set when this step performed a synchronous metadata FS write
    /// (vote/term persist). The composite returns Burst for such a step:
    /// the write is bounded and one-shot per election event, and charging
    /// it against the normal step deadline reads as a scheduler budget
    /// overrun that delays heartbeats into a spurious election. Same
    /// classification wal uses for its cold-FS path.
    pub meta_fs_step: bool,
    /// Cluster-wide durability mode hint (Strict=0 / GroupFsync=1 / Relaxed=2).
    /// Currently informational — not yet plumbed through the commit component.
    durability_mode: u8,
    /// When non-zero, target of a pending `TimeoutNow` leadership
    /// transfer. The leader emits MSG_TIMEOUT_NOW once it next reaches
    /// the heartbeat path, then clears this slot.
    pending_transfer_to: u8,

    // ── Metrics ─────────────────────────────────────────────
    proposals_received: u32,
    entries_appended: u32,
    elections_started: u32,
    /// Proposals dropped because ADMIN_OP_FREEZE is in effect.
    proposals_dropped_frozen: u32,
    /// Proposals dropped because `strict_fallback` is in effect
    /// (CP-cache lost or expired). Distinct from the frozen counter so
    /// operators can tell admin freeze vs control-plane fallback apart.
    proposals_dropped_strict: u32,
    last_metrics_ms: u64,
    /// Append→commit timestamp ring for `clustor.raft.commit_latency_ms`
    /// (RFC §4.1). Keyed by `log_index % COMMIT_TS_RING`; the parallel
    /// `commit_ts_us` array holds the leader-local `dev_micros` stamp
    /// taken when the entry was appended. On commit-advance the matching
    /// slot's age is folded into `commit_latency_buckets` and cleared.
    commit_ts_index: [Index; COMMIT_TS_RING],
    commit_ts_us: [u64; COMMIT_TS_RING],
    commit_latency_buckets: [u32; wire::hist::COMMIT_LATENCY_US.len() + 1],

    // ── Leader-state hint ───────────────────────────────────
    // Last (leader_id, term) we broadcast on `leader_state`. Re-emit
    // only on change so the channel doesn't burn cycles on steady
    // state. -2 means "never broadcast yet".
    last_hint_leader_id: i8,
    last_hint_term: Term,

    // ── Scratch ─────────────────────────────────────────────
    msg_buf: [u8; 4096],
}

// ── Simple PRNG for election jitter (xorshift32) ────────────
fn xorshift32(state: &mut u32) -> u32 {
    let mut x = *state;
    if x == 0 { x = 0xDEAD_BEEF; }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

/// Initialise every field to its pre-param default. Channel handles
/// and params are assigned by `mod.rs` afterwards; `arm` runs the
/// post-param boot logic.
pub fn init(s: &mut Raft) {
    s.in_rpc = -1;
    s.in_proposals = -1;
    s.in_admin = -1;
    s.in_proposals_tagged = -1;
    s.in_proposals_partitioned = -1;
    s.in_proposals_partitioned_tagged = -1;
    s.in_snapshot_installed = -1;
    s.in_wal_flushed = -1;
    s.in_wal_replay_complete = -1;
    s.out_rpc = -1;
    s.out_log = -1;
    s.out_metrics = -1;
    s.out_proposal_assigned = -1;
    s.out_leader_state = -1;
    s.out_admin_applied = -1;
    s.out_wal_compact = -1;

    s.outbox_ae.reset();
    s.outbox_bodies.reset();
    s.commit_in = HorizonLatch::new();
    s.apply_horizon_out = HorizonLatch::new();
    s.apply_reset_out = None;
    s.probe_reply_out = [(0u64, 0u64, 0u8); PROBE_QUEUE_SLOTS];
    s.probe_reply_count = 0;
    s.voter_out = None;

    s.partition_id = 0;
    s.current_term = 0;
    s.self_id = 0;
    s.role = ROLE_FOLLOWER;
    s.leader_id = REPLICA_NONE as i8;
    s.voter_count = 1;
    s.probes = [ProbeSlot::empty(); MAX_INFLIGHT_PROBES];
    s.next_probe_id = 1;
    s.current_voters = NodeSet::empty();
    s.joint_voters = NodeSet::empty();
    s.joint_active = false;
    s.noop_pending = false;
    s.commit_fence_out = None;
    s.pending_new_voters = NodeSet::empty();
    s.pending_new_voters_set = false;
    s.learner_mode = false;
    s.election_timeout_ms = 1000;
    s.election_deadline_ms = 0;
    s.heartbeat_interval_ms = 150;
    s.last_heartbeat_ms = 0;
    s.votes_granted = NodeSet::empty();
    s.votes_rejected = NodeSet::empty();
    s.pre_vote_active = false;
    s.last_log_index = 0;
    s.last_log_term = 0;
    s.commit_index = 0;
    s.tail_terms = [TailTerm { index: 0, term: 0 }; TAIL_TERM_RING];
    s.log_truncations = 0;
    s.truncate_pending = false;
    s.truncate_keep = 0;
    s.truncate_req_id = 0;
    s.truncate_req_seq = 0;
    s.truncate_deadline_ms = 0;
    s.truncate_emit_pending = false;
    s.compact_before_pending = 0;
    s.admin_ack_pending = false;
    s.admin_ack_id = 0;
    s.admin_ack_status = 0;
    s.truncate_delivered = false;
    s.truncate_nacks = 0;
    s.truncate_holds = 0;
    s.wal_resyncs = 0;
    s.wal_unacked_holds = 0;
    s.ae_noncontiguous = 0;
    s.local_durable_index = 0;
    s.local_durable_term = 0;
    s.meta_root_path = 0;
    s.meta_fds = [-1; META_SLOTS];
    s.meta_slot = 0;
    s.meta_generation = 0;
    s.persist_meta = 1;
    s.meta_write_errors = 0;
    s.meta_fail_logged = false;
    s.meta_mkdir_attempted = false;
    s.name_fence_logged = false;
    s.name_fence_fail_logged = false;
    s.name_unfenced = 0;
    s.name_fence_probe = NAME_FENCE_UNPROBED;
    // Matches the declared param default: an unconfigured graph waits on
    // the capability rather than publishing a name it cannot fence.
    s.name_fence = NAME_FENCE_STRICT;
    s.meta_name_published = [false; META_SLOTS];
    s.meta_slots_materialized = false;
    s.meta_backoff_steps = 0;
    s.holdoff_until_ms = 0;
    s.holdoff_over_logged = true;
    s.vote_floor_term = 0;
    s.meta_persisted_durable = 0;
    s.pending_recovery_reset = false;
    s.meta_load_pending = false;
    s.awaiting_replay = false;
    s.replay_hw_received = 0;
    s.meta_hint_loaded = 0;
    s.proposal_batch = [0u8; PROPOSAL_BATCH_CAP];
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
    s.proposal_batch_max = 1;
    s.proposal_batch_start_ms = 0;
    s.proposal_batch_timeout_ms = 10;
    s.flush_deferred = false;
    s.flushes_deferred = 0;
    s.correlation_ids = [0u64; MAX_BATCH_PROPOSALS];
    s.strict_fallback = false;
    s.voted_for = REPLICA_NONE as i8;
    s.frozen = false;
    s.meta_fs_step = false;
    s.durability_mode = 0;
    s.pending_transfer_to = 0;
    s.proposals_received = 0;
    s.entries_appended = 0;
    s.elections_started = 0;
    s.proposals_dropped_frozen = 0;
    s.proposals_dropped_strict = 0;
    s.last_metrics_ms = 0;
    s.commit_ts_index = [0; COMMIT_TS_RING];
    s.commit_ts_us = [0; COMMIT_TS_RING];
    s.commit_latency_buckets = [0u32; wire::hist::COMMIT_LATENCY_US.len() + 1];
    s.last_hint_leader_id = -2;
    s.last_hint_term = 0;
    for b in s.msg_buf.iter_mut() { *b = 0; }
}

/// Post-param boot logic: clamps, initial voter seed, recovery hold,
/// metadata load, election deadline. Called by `mod.rs` after channel
/// handles and params are in place.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn arm(s: &mut Raft, sys: &SyscallTable) {
    // `voter_count` is operator-supplied; clamp both ends. Above
    // MAX_NODES the initial-voter loop and every later `quorum_index`
    // would index out of range; at 0 the voter set is empty and no
    // quorum — election, ReadIndex or commit — can ever be reached.
    if (s.voter_count as usize) > MAX_NODES {
        s.voter_count = MAX_NODES as u8;
    }
    if s.voter_count == 0 {
        s.voter_count = 1;
    }

    // Group commit is config-gated via `proposal_batch_max` (see the
    // param table for the consumer contract N>1 imposes). Clamp to the
    // correlation-slot capacity so a batch always fits downstream; 0 is
    // meaningless and reads as "no batching".
    if s.proposal_batch_max == 0 {
        s.proposal_batch_max = 1;
    }
    if s.proposal_batch_max as usize > MAX_BATCH_PROPOSALS {
        s.proposal_batch_max = MAX_BATCH_PROPOSALS as u16;
    }

    // Initial voter set (RFC §1.2). `voter_count` came from
    // the param table; seed `current_voters` with ids
    // 0..voter_count. Joint state is inactive at startup; it
    // activates only when a `CONFIG_CHANGE_OP_JOINT` entry
    // commits via `drain_admin_committed`.
    for i in 0..s.voter_count {
        s.current_voters.insert(i);
    }
    // A replica outside its own voter set can never assemble a quorum
    // (its ballot and its match index are both discounted). That is a
    // config error, not a state this node can recover from — say so.
    if !s.current_voters.contains(s.self_id) {
        dev_log(sys, 1, b"[raft] self not in voter set".as_ptr(), 28);
    }
    // Broadcast initial voter set once everything is wired.
    // The emission itself happens in the first step() call.

    // Hold proposal intake from boot whenever the recovery edge is wired,
    // so raft never appends before the WAL hands over its authoritative
    // on-disk high-water. Independent of the meta hint (which can be 0).
    s.awaiting_replay = s.in_wal_replay_complete >= 0;

    let now = dev_millis(sys);

    if s.persist_meta == 0 {
        // Declared volatile posture: no metadata file exists or is
        // wanted — no load, no retry hold. A memoryless node cannot
        // know whether it voted in an election still in flight across
        // its restart, so real votes and real elections are held off
        // for one full election timeout after boot. A single-voter set
        // has no second voter to double-vote with: skip the hold-off
        // so a restarted single-node graph resumes immediately.
        let single_voter = s.current_voters.count() == 1
            && s.current_voters.contains(s.self_id)
            && !s.joint_active;
        if !single_voter {
            s.holdoff_until_ms = now + s.election_timeout_ms as u64;
            s.holdoff_over_logged = false;
            dev_log(sys, 3, b"[raft] holdoff".as_ptr(), 14);
        }
    } else {
        // Restore persistent state from the metadata slots. At cold boot
        // the FS provider may not be ready (E_AGAIN); the load reports
        // that and the step retries until it resolves. Waiting is not a
        // layout question — both path modes have slots to read, and a
        // graph that persists nothing took the branch above — so an
        // inconclusive answer holds in either. Booting fresh instead
        // would discard a term and vote that are still on disk.
        s.meta_load_pending = load_metadata(s, sys);
    }

    // Set initial election deadline, jittered per node: an unjittered
    // first deadline synchronises the first election wave whenever a
    // whole cluster (re)boots together.
    let mut seed = (now as u32) ^ ((s.self_id as u32) << 16) ^ 0xBEEF;
    let half_timeout = (s.election_timeout_ms as u32 / 2).max(1);
    let jitter = (xorshift32(&mut seed) & (half_timeout.next_power_of_two() - 1)) as u64;
    s.election_deadline_ms = now + s.election_timeout_ms as u64 + jitter;
    s.last_heartbeat_ms = now;

    dev_log(sys, 3, b"[raft] init".as_ptr(), 11);
}

/// Current leadership state, for the dispatch table's E11 delivery
/// to the replicator (the in-module form of the `leader_state` hint
/// raft already publishes externally).
pub fn is_leader(s: &Raft) -> bool {
    s.role == ROLE_LEADER
}

/// The local log tip (`last_log_index`), for the dispatch table's
/// relaxed-mode self-match seed into commit: with no durability
/// barrier, "self has the entry" is exactly "self appended the entry".
pub fn log_tip(s: &Raft) -> Index {
    s.last_log_index
}

/// Leadership snapshot for the replicator's E11 hint: (is_leader,
/// current_term, commit_index). Catch-up AEs must carry the LEADER's
/// term, not a read-back entry's term, and `commit_index` is the only
/// value `leader_commit` may carry.
pub fn leader_hint(s: &Raft) -> (bool, Term, Index) {
    (s.role == ROLE_LEADER, s.current_term, s.commit_index)
}

/// Deliver a higher term observed by the replicator in an
/// AppendEntriesResponse (E13). Raft §5.1: a server seeing a larger term
/// reverts to follower — otherwise a deposed leader that can still reach
/// followers, but not the new leader, stays "leader" forever and
/// black-holes proposals.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_peer_term(s: &mut Raft, sys: &SyscallTable, term: Term) {
    if term > s.current_term {
        dev_log(sys, 2, b"[raft] deposed by resp term".as_ptr(), 27);
        become_follower(s, sys, term);
    }
}

/// One raft step. `admin_in` and `probes_in` are apply-owned seams
/// (E9 committed admin/config ring, E7 probe-request queue) consumed
/// here at the top of the dispatch — one step after apply filled them,
/// preserving the channel edges' next-step timing.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn step(
    s: &mut Raft,
    sys: &SyscallTable,
    now: u64,
    admin_in: &mut SeamRing<4096>,
    probes_in: &mut [u64; PROBE_QUEUE_SLOTS],
    probes_count: &mut u8,
) {
    let work_before = s.proposals_received.wrapping_add(s.entries_appended);

    // 0a. Boot-time metadata load retry. At cold boot the fat32 provider
    //     isn't ready when module_new ran (FS_OPEN -> E_AGAIN), so retry
    //     each step until the FS resolves.
    if s.meta_load_pending {
        s.meta_load_pending = load_metadata(s, sys);
        // Until the persisted state is in hand, hold the whole step: no
        // elections, no append/intake. Otherwise raft assigns FRESH log
        // indices that collide when the loaded last_log_index lands. The FS
        // resolves within a few steps of cold boot; a fresh deploy (no meta
        // file) resolves immediately.
        if s.meta_load_pending {
            return;
        }
    }

    // 0. Recovery seeding: fast-forward apply to the recovery BASE so it
    //    resumes applying post-recovery commits instead of gapping from
    //    apply_index=0. The base is the FIXED recovered high-water
    //    (`replay_hw_received` for the WAL-handshake path, or the
    //    persisted hint `last_log_index` for the legacy no-edge path)
    //    — NOT the live `last_log_index`, which would drift forward once
    //    intake resumes and make apply skip freshly-appended bodies.
    //    Crucially, on the WAL-handshake path we keep `awaiting_replay`
    //    set until THIS raise, so no new entry is appended before apply
    //    has been seeded to the base; that keeps the post-recovery body
    //    stream gap-free in order. The horizon latch is always
    //    deliverable, so it collapses to
    //    one raise.
    if s.pending_recovery_reset {
        let high_water = if s.replay_hw_received > 0 {
            s.replay_hw_received
        } else {
            s.last_log_index
        };
        // Crash recovery is NOT a snapshot install: the committed
        // entries up to `high_water` still live in the WAL and their
        // bodies must be REPLAYED into the (volatile) apply consumers,
        // not skipped. So we advance apply's commit_horizon to
        // `high_water` with a normal horizon raise (which leaves
        // its apply_index at the recovery floor — 0, or a snapshot
        // index if one was installed first); its refetch loop then
        // pulls each body back from the WAL and applies it in order.
        // Using the apply RESET latch here (snapshot semantics)
        // would jump apply_index past the bodies and the state machine
        // would never see the recovered entries.
        s.apply_horizon_out.raise(s.last_log_term, high_water);
        s.pending_recovery_reset = false;
        // Horizon is seeded — now it is safe to accept new proposals.
        s.awaiting_replay = false;
    }

    // 0b. Metadata persist-error backoff drains one step at a time
    //     (consulted only by the throttled durable-hint save).
    if s.meta_backoff_steps > 0 {
        s.meta_backoff_steps -= 1;
    }

    // 0c. Volatile posture: one-shot marker when the boot vote
    //     hold-off window ends, so the window is externally visible.
    if !s.holdoff_over_logged && now >= s.holdoff_until_ms {
        s.holdoff_over_logged = true;
        dev_log(sys, 3, b"[raft] holdoff over".as_ptr(), 19);
    }

    // 1. Process inbound RPCs (all roles)
    process_rpc(s, sys, now);

    // 2. The fallback signal is delivered by the dispatch table's
    //    cp_state demux via `on_fallback` before this step runs.

    // 3. Process admin commands (local effects only — see RFC §14)
    drain_admin(s, sys, now);

    // 3a. Absorb quorum-commit feedback from the commit component so the
    //     leader's heartbeats/AEs carry the right `leader_commit`.
    drain_commit_in(s, sys);

    // 3b. Process snapshot install completions from the snapshot side.
    drain_snapshot_installed(s, sys);

    // 3c. Drain strict-ReadIndex probe requests from apply
    //     and time-out any probes that didn't reach majority.
    drain_read_probes(s, sys, probes_in, probes_count, now);
    expire_probes(s, sys, now);

    // 3d. Apply committed admin entries (RFC §3.1). On every
    //     replica, when a Raft-replicated admin entry passes commit,
    //     apply echoes the body here and we run the op.
    drain_admin_committed(s, sys, admin_in);

    // 3e. Track local WAL fsync acks so followers can stamp their
    //     `local_wal_durable_index` into every AppendEntriesResponse
    //     (spec §10.4.1). Cheap drain — leader and follower both
    //     run it but only the follower's value flows over the wire.
    drain_wal_flushed(s, sys);

    // 3f. Boot-time recovery resume: if the WAL has finished replay and
    //     handed us its exact on-disk high-water, resume `last_log_index`
    //     there (overriding the stale persisted hint), re-seed
    //     apply, and release the proposal-intake hold.
    drain_wal_replay_complete(s, sys);

    // 3g. Re-send a truncation request the control channel could not
    //     take. Backpressure must delay the truncation, never cancel
    //     it: the tip stays held until the WAL answers, so a request
    //     that quietly stopped being re-sent would hold this node out
    //     of the log-repair path indefinitely.
    //
    //     A request that never reached the channel expires, because the
    //     WAL provably never saw it. One that did is held until the WAL
    //     answers, however long that takes: its retirement runs over
    //     many steps, so silence there means "in progress" just as
    //     readily as "lost", and resuming on a timer would let this node
    //     campaign on a suffix the WAL is in the middle of removing.
    if s.truncate_pending {
        if now >= s.truncate_deadline_ms && !s.truncate_delivered {
            abandon_truncate(s, sys);
        } else if s.truncate_emit_pending {
            emit_wal_truncate_after(s, sys);
        }
    }
    // Re-offer a compact-before the control channel refused. Nothing
    // else will raise it again before the next snapshot, so this is its
    // only route back.
    flush_wal_compact_before(s, sys);

    // 4. Role-specific logic
    match s.role {
        ROLE_FOLLOWER => step_follower(s, sys, now),
        ROLE_CANDIDATE => step_candidate(s, sys, now),
        ROLE_LEADER => step_leader(s, sys, now),
        _ => {}
    }

    // 5. If we're stepping down via leader transfer, fire TimeoutNow.
    emit_timeout_now_if_pending(s, sys);

    // 6. Emit metrics periodically
    emit_metrics(s, sys, now);

    // 7. Broadcast a leader-state hint on every change so the codec
    //    can short-circuit non-leader proposals with CLIENT_REJECT_NOT_LEADER.
    emit_leader_hint(s, sys);
    if s.proposals_received.wrapping_add(s.entries_appended) != work_before {
        let poll = (sys.channel_poll)(s.in_proposals_tagged, 0x01);
        let effect = if poll > 0 && (poll as u32 & 0x01) != 0 {
            step_effect::RUNNABLE_BACKLOG
        } else {
            step_effect::WORK_DONE
        };
        dev_report_step_effect(sys, effect);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// The change latch moves only on a confirmed write. This is emitted
/// ONLY when `(leader_id, term)` differs from the last one latched, so a
/// hint recorded as sent but never written is never re-offered — every
/// consumer of `MSG_LEADER_HINT` would keep routing to the previous
/// leader for the whole of this term, and nothing would correct it until
/// the next leadership change.
unsafe fn emit_leader_hint(s: &mut Raft, sys: &SyscallTable) {
    if s.out_leader_state < 0 { return; }
    if s.leader_id == s.last_hint_leader_id && s.current_term == s.last_hint_term {
        return;
    }
    let mut buf = [0u8; 9];
    buf[0] = if s.leader_id < 0 { 0xFFu8 } else { s.leader_id as u8 };
    buf[1..9].copy_from_slice(&s.current_term.to_le_bytes());
    // No poll pre-check: it reports >=1 byte free, not room for this
    // frame. A refused write leaves the latch alone, so the next step
    // re-offers the same hint.
    let n = wire_channels::channel_write_msg(
        sys, s.out_leader_state, wire::MSG_LEADER_HINT, &buf,
    );
    if n > 0 {
        s.last_hint_leader_id = s.leader_id;
        s.last_hint_term = s.current_term;
    }
}

// ── RPC processing (all roles) ──────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_rpc(s: &mut Raft, sys: &SyscallTable, now: u64) {
    // Process up to 8 RPCs per step to bound step time. Inbound shape is
    // the 5-byte partitioned envelope (`[partition_id:u16 LE][msg_type:u8]
    // [len:u16 LE]`); peer_router fans the channel out to every per-
    // partition consensus instance and each instance filters by its own
    // partition_id, so cross-partition RPCs from peers (and stray
    // client frames stamped with the wrong partition) are dropped
    // here.
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_rpc, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (partition_id, msg_type, plen) =
            wire_channels::channel_read_partitioned(sys, s.in_rpc, &mut s.msg_buf);
        if plen == 0 && msg_type == 0 { break; }
        if partition_id != s.partition_id { continue; }

        match msg_type {
            wire::MSG_REQUEST_VOTE | wire::MSG_PRE_VOTE => {
                dev_log(sys, 3, b"[raft] rv in".as_ptr(), 12);
                handle_vote_request(s, sys, msg_type, plen);
            }
            wire::MSG_REQUEST_VOTE_RESP | wire::MSG_PRE_VOTE_RESP => {
                dev_log(sys, 3, b"[raft] rv resp".as_ptr(), 14);
                handle_vote_response(s, sys, msg_type, plen);
            }
            wire::MSG_APPEND_ENTRIES => {
                handle_append_entries(s, sys, plen, now);
            }
            wire::MSG_APPEND_ENTRIES_RESP => {
                // Handled by the replicator component, not raft. Shouldn't
                // arrive here but ignore gracefully.
            }
            wire::MSG_TIMEOUT_NOW => {
                handle_timeout_now(s, sys, plen, now);
            }
            wire::MSG_READ_INDEX_PROBE => {
                handle_read_index_probe(s, sys, plen);
            }
            wire::MSG_READ_INDEX_PROBE_RESP => {
                handle_read_index_probe_resp(s, sys, plen);
            }
            _ => {}
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_read_index_probe(s: &mut Raft, sys: &SyscallTable, plen: u16) {
    let pl = plen as usize;
    let (probe_id, term) = match wire::decode_read_index_probe(&s.msg_buf[..pl]) {
        Some(v) => v,
        None => return,
    };
    // A follower acknowledges the probe iff the caller's term is at
    // least our own term. If it's higher, we step down — same rule as
    // for AE. A stale probe (term < ours) is dropped silently.
    if term > s.current_term {
        become_follower(s, sys, term);
    }
    if term < s.current_term { return; }
    if s.out_rpc < 0 { return; }
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut resp = [0u8; 17];
    wire::encode_read_index_probe_resp(&mut resp, probe_id, s.current_term, s.self_id);
    let target = if s.leader_id >= 0 { s.leader_id as u8 } else { wire::TARGET_BROADCAST };
    wire_channels::channel_write_routed_partitioned(
        sys, s.out_rpc, target, s.partition_id,
        wire::MSG_READ_INDEX_PROBE_RESP, &resp,
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_read_index_probe_resp(s: &mut Raft, sys: &SyscallTable, plen: u16) {
    if s.role != ROLE_LEADER { return; }
    let pl = plen as usize;
    let (probe_id, term, replica) =
        match wire::decode_read_index_probe_resp(&s.msg_buf[..pl]) {
            Some(v) => v,
            None => return,
        };
    if term > s.current_term {
        become_follower(s, sys, term);
        return;
    }
    if (replica as usize) >= MAX_NODES { return; }
    // Same ballot rule as elections: only active voters confirm a
    // ReadIndex fence (and both sets must confirm while joint).
    if !s.current_voters.contains(replica)
        && !(s.joint_active && s.joint_voters.contains(replica))
    {
        return;
    }
    for i in 0..MAX_INFLIGHT_PROBES {
        let probe_id_slot = s.probes[i].probe_id;
        if probe_id_slot == 0 || probe_id_slot != probe_id { continue; }
        if s.probes[i].term != s.current_term { continue; }
        s.probes[i].votes.insert(replica);
        if set_majority(s.probes[i].votes, s.current_voters, s.joint_voters, s.joint_active) {
            let corr = s.probes[i].correlation_id;
            let commit = s.probes[i].snapshot_commit;
            emit_read_probe_reply(s, sys, corr, commit, true);
            s.probes[i] = ProbeSlot::empty();
        }
        return;
    }
}

/// Drain strict-ReadIndex probe requests from apply's probe queue
/// (seam E7), ≤4 per step.
///
/// # Safety
///
/// Caller must hold exclusive borrows and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_read_probes(
    s: &mut Raft,
    sys: &SyscallTable,
    probes_in: &mut [u64; PROBE_QUEUE_SLOTS],
    probes_count: &mut u8,
    now: u64,
) {
    for _ in 0..4 {
        if *probes_count == 0 { break; }
        let correlation_id = probes_in[0];
        let n = *probes_count as usize;
        for i in 1..n {
            probes_in[i - 1] = probes_in[i];
        }
        *probes_count -= 1;
        if correlation_id == 0 { continue; }
        start_probe(s, sys, correlation_id, now);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn start_probe(
    s: &mut Raft,
    sys: &SyscallTable,
    correlation_id: u64,
    now: u64,
) {
    // Not the leader: immediately reply with confirmed=0 so the apply
    // pipeline can fall back to rejecting the read.
    if s.role != ROLE_LEADER {
        dev_log(sys, 3, b"[raft] probe nolead".as_ptr(), 19);
        emit_read_probe_reply(s, sys, correlation_id, 0, false);
        return;
    }
    // Allocate an empty slot.
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in s.probes.iter().enumerate() {
        if slot.probe_id == 0 { slot_idx = Some(i); break; }
    }
    let slot_idx = match slot_idx {
        Some(i) => i,
        None => {
            // Probe table full — reply with confirmed=0, caller retries.
            dev_log(sys, 3, b"[raft] probe full".as_ptr(), 17);
            emit_read_probe_reply(s, sys, correlation_id, 0, false);
            return;
        }
    };
    let probe_id = s.next_probe_id;
    s.next_probe_id = s.next_probe_id.wrapping_add(1).max(1);
    let mut votes = NodeSet::empty();
    votes.insert(s.self_id);

    s.probes[slot_idx] = ProbeSlot {
        probe_id,
        correlation_id,
        snapshot_commit: s.commit_index,
        term: s.current_term,
        votes,
        deadline_ms: now + PROBE_TIMEOUT_MS,
        broadcast_sent: false,
    };

    // Single-node cluster: we already have majority (self).
    if set_majority(votes, s.current_voters, s.joint_voters, s.joint_active) {
        emit_read_probe_reply(s, sys, correlation_id, s.commit_index, true);
        s.probes[slot_idx] = ProbeSlot::empty();
        return;
    }

    // Broadcast the probe to all peers. On backpressure the slot stays
    // `broadcast_sent = false` and `expire_probes` retries every step
    // until it lands or the deadline rejects it — never a zombie.
    broadcast_probe(s, sys, slot_idx);
}

/// Attempt the routed peer broadcast for probe slot `i`; marks the slot
/// sent on success. Safe to call repeatedly.
unsafe fn broadcast_probe(s: &mut Raft, sys: &SyscallTable, i: usize) -> bool {
    if s.out_rpc < 0 { return false; }
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    let mut buf = [0u8; 16];
    wire::encode_read_index_probe(&mut buf, s.probes[i].probe_id, s.probes[i].term);
    let n = wire_channels::channel_write_routed_partitioned(
        sys, s.out_rpc, wire::TARGET_BROADCAST, s.partition_id,
        wire::MSG_READ_INDEX_PROBE, &buf,
    );
    if n > 0 {
        s.probes[i].broadcast_sent = true;
        true
    } else {
        false
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn expire_probes(s: &mut Raft, sys: &SyscallTable, now: u64) {
    for i in 0..MAX_INFLIGHT_PROBES {
        let slot = s.probes[i];
        if slot.probe_id == 0 { continue; }
        if now >= slot.deadline_ms {
            emit_read_probe_reply(s, sys, slot.correlation_id, 0, false);
            s.probes[i] = ProbeSlot::empty();
            continue;
        }
        // Backpressured-at-issue broadcasts retry until they land
        // (see ProbeSlot::broadcast_sent).
        if !slot.broadcast_sent {
            broadcast_probe(s, sys, i);
        }
    }
}

/// Queue a probe reply for apply (seam E8).
/// A full queue silently drops the reply.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` per the module ABI.
unsafe fn emit_read_probe_reply(
    s: &mut Raft,
    _sys: &SyscallTable,
    correlation_id: u64,
    confirmed_commit: u64,
    confirmed: bool,
) {
    if (s.probe_reply_count as usize) >= PROBE_QUEUE_SLOTS { return; }
    s.probe_reply_out[s.probe_reply_count as usize] =
        (correlation_id, confirmed_commit, confirmed as u8);
    s.probe_reply_count += 1;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// React to a leader-transfer TimeoutNow: bump term immediately and
/// start an election. Drop stale requests where the sender's term is
/// behind ours.
unsafe fn handle_timeout_now(s: &mut Raft, sys: &SyscallTable, plen: u16, now: u64) {
    let plen = plen as usize;
    if plen < 8 { return; }
    let caller_term = u64::from_le_bytes([
        s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
        s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
    ]);
    if caller_term < s.current_term { return; }
    // A transfer cannot make an unrecovered tip safe to campaign on.
    // Refused here as well as in `start_election` so the deadline is
    // never pulled into the past on this node's behalf: leaving it
    // where it is means the ordinary timeout applies once the WAL has
    // answered, instead of an election firing the moment it does.
    if replay_hold(s) {
        dev_log(sys, 2, b"[raft] timeout_now held".as_ptr(), 23);
        return;
    }
    dev_log(sys, 3, b"[raft] timeout_now".as_ptr(), 18);
    // Force-start an election by advancing the deadline into the past
    // and clearing votes. The normal candidate path will pick up.
    s.election_deadline_ms = now;
    s.votes_granted.clear();
    s.votes_rejected.clear();
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_snapshot_installed(s: &mut Raft, sys: &SyscallTable) {
    if s.in_snapshot_installed < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_snapshot_installed, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_snapshot_installed, &mut s.msg_buf);
        if msg_type != wire::MSG_SNAPSHOT_INSTALLED { continue; }
        let (term, last_idx, last_term) =
            match wire::decode_snapshot_installed(&s.msg_buf[..plen as usize]) {
                Some(t) => t,
                None => continue,
            };
        // Stale snapshot from an old term: ignore.
        if term < s.current_term { continue; }
        // At or past this snapshot point already → this is a LOCAL
        // snapshot of our own log (the leader/steady-state path: wal's
        // rotation trigger → snapshot component → installed_local), not a
        // peer install. No state fast-forward is owed — the log already
        // covers the snapshot — but the WAL compaction floor is: without
        // this leg a leader never retires segments (the follower-install
        // path below is unreachable for own-log snapshots, so `[wal]
        // compacted` never fired on a leader). Clamp the floor to
        // `commit_index`: the trigger carries the rotation-time APPEND
        // high-water, and an uncommitted suffix can still be truncated by
        // conflict repair (§5.3) — compaction must never outrun commit.
        // `compact_before` is idempotent/monotonic, so duplicate or
        // out-of-order installs are harmless here.
        if last_idx <= s.last_log_index {
            let floor = if last_idx < s.commit_index { last_idx } else { s.commit_index };
            if floor > 0 {
                dev_log(sys, 3, b"[raft] snap local".as_ptr(), 17);
                emit_wal_compact_before(s, sys, floor);
            }
            continue;
        }
        dev_log(sys, 3, b"[raft] snap install".as_ptr(), 19);
        s.last_log_index = last_idx;
        s.last_log_term = last_term;
        // The snapshot subsumes every entry up to `last_idx`; the local
        // WAL never held them and can never ack them. Without this
        // fast-forward the unacked-window gate (MAX_WAL_UNACKED)
        // compares a post-install log tip against a durable index of 0
        // and answers `busy` to every catch-up append forever — a
        // rebuilt follower would install the image and then never
        // resume the replication stream.
        if last_idx > s.local_durable_index {
            s.local_durable_index = last_idx;
            s.local_durable_term = last_term;
        }
        if last_idx > s.commit_index {
            // Mirror the follower-commit path so apply learns about the
            // fast-forward. advance_follower_commit must observe the OLD
            // commit_index (its monotone guard returns early otherwise)
            // — it performs the `commit_index = last_idx` update itself.
            advance_follower_commit(s, sys, last_idx);
        }
        save_metadata(s, sys);
        // Emit the apply-pipeline reset (§2.3) and the WAL compact-before
        // signal (§2.2). Both are post-snapshot housekeeping; ignore
        // unwired ports.
        emit_apply_reset(s, sys, last_term, last_idx);
        emit_wal_compact_before(s, sys, last_idx);
    }
}

/// E6 RESET seam (was MSG_APPLY_PIPELINE_RESET on `commit_advanced`):
/// latch the snapshot-install reset for apply, which consumes it at
/// the top of its step. Always deliverable.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` per the module ABI.
unsafe fn emit_apply_reset(s: &mut Raft, _sys: &SyscallTable, term: u64, index: u64) {
    s.apply_reset_out = Some((term, index));
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_wal_compact_before(s: &mut Raft, sys: &SyscallTable, before_index: u64) {
    if s.out_wal_compact < 0 { return; }
    if before_index > s.compact_before_pending {
        s.compact_before_pending = before_index;
    }
    flush_wal_compact_before(s, sys);
}

/// Re-offer the outstanding compact-before signal. Called every step so
/// a refused one is not lost until the next snapshot happens to raise
/// another.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn flush_wal_compact_before(s: &mut Raft, sys: &SyscallTable) {
    if s.compact_before_pending == 0 || s.out_wal_compact < 0 { return; }
    let buf = s.compact_before_pending.to_le_bytes();
    let n = wire_channels::channel_write_msg(
        sys, s.out_wal_compact, wire::MSG_WAL_COMPACT_BEFORE, &buf,
    );
    if n > 0 {
        s.compact_before_pending = 0;
    }
}

/// Ask the WAL to discard every entry strictly after `truncate_keep`
/// (Raft §5.3). Rides the shared `wal.compact_before` control channel.
///
/// This is a REQUEST, not an effect: the tip is rewound only when the
/// correlated `MSG_WAL_TRUNCATE_ACK` reports the new tail durable. A
/// channel that cannot take the frame, or takes only part of it, leaves
/// `truncate_emit_pending` set so the next step re-sends — the request
/// is never silently dropped, because dropping it while the tip stayed
/// rewound is exactly how a node accepts a replacement suffix the WAL
/// never made room for.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and a `&SyscallTable` whose
/// function pointers reach live kernel routines per the module ABI.
unsafe fn emit_wal_truncate_after(s: &mut Raft, sys: &SyscallTable) {
    if !s.truncate_pending || s.out_wal_compact < 0 { return; }
    let poll = (sys.channel_poll)(s.out_wal_compact, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        s.truncate_emit_pending = true;
        return;
    }
    let mut buf = [0u8; wire::WAL_TRUNCATE_AFTER_LEN];
    wire::encode_wal_truncate_after(&mut buf, s.truncate_keep, s.truncate_req_id);
    let n = wire_channels::channel_write_msg(
        sys,
        s.out_wal_compact,
        wire::MSG_WAL_TRUNCATE_AFTER,
        &buf,
    );
    s.truncate_emit_pending = n <= 0;
    if n > 0 {
        s.truncate_delivered = true;
    }
}

/// Give up on a truncation the control channel never accepted. Only
/// callable while the request is undelivered, which is what makes it
/// safe: the WAL never received this request id, so it cannot be
/// retiring anything for it, and both sides still hold the same suffix.
/// The log keeps that suffix, so the only thing this node can honestly
/// do with the leader's replacement entries is refuse them — which the
/// ordinary log-match NACK does once the hold is gone. Counted as a
/// refusal (`RAFT_TRUNCATE_NACKS`): the new tail was never persisted.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn abandon_truncate(s: &mut Raft, sys: &SyscallTable) {
    s.truncate_pending = false;
    s.truncate_emit_pending = false;
    s.truncate_nacks = s.truncate_nacks.saturating_add(1);
    dev_log(sys, 2, b"[raft] truncate abandon".as_ptr(), 23);
}

/// Apply a correlated truncation ack. Only an ack naming the pending
/// request's id AND keep index releases the rewind; a stale or
/// mismatched ack is ignored, so a repeated or reordered answer can
/// never authorise a truncation that was not the one still in flight.
///
/// A `durable = false` answer means the WAL published nothing: the old
/// suffix is still on disk and still ours, so the request stays pending
/// and is re-sent.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn apply_truncate_ack(
    s: &mut Raft,
    sys: &SyscallTable,
    keep_through: Index,
    req_id: u32,
    durable: bool,
) {
    if !s.truncate_pending
        || req_id != s.truncate_req_id
        || keep_through != s.truncate_keep
    {
        return;
    }
    if !durable {
        s.truncate_nacks = s.truncate_nacks.saturating_add(1);
        s.truncate_emit_pending = true;
        dev_log(sys, 2, b"[raft] truncate nack".as_ptr(), 20);
        return;
    }
    s.truncate_pending = false;
    s.truncate_emit_pending = false;
    // Ordering: every fsync ack for an entry this truncation discards
    // was written to `wal.flushed` ahead of the truncate ack and is
    // consumed by the same FIFO drain, so none can land after the clamp
    // below and undo it. The manifest's `wal_flushed` port records why
    // the two must never be split onto separate edges.
    //
    // The durable watermark counts entries the WAL fsynced, committed or
    // not, so it can sit above the entries this truncation discarded.
    // Left there it would be stamped into every AppendEntriesResponse (the
    // leader credits durability for entries that are gone) and written
    // into the metadata record (the next boot stands for election on a log
    // it does not hold), so it comes down with the tip. The paired term is
    // the one held AT the new tail; unknown reads as 0 rather than
    // inheriting the discarded suffix's term.
    if s.local_durable_index > keep_through {
        s.local_durable_index = keep_through;
        s.local_durable_term = ring_term_at(s, keep_through).unwrap_or(0);
        // The throttled durable-hint persist fires only once the watermark
        // runs a stride ahead of what is on disk; without this the record
        // keeps naming a discarded entry until the log grows back past it.
        if s.meta_persisted_durable > keep_through {
            s.meta_persisted_durable = keep_through;
        }
    }
    if s.last_log_index <= keep_through {
        return;
    }
    // Evict the now-stale ring slots in (keep_through, last_log_index].
    let mut i = keep_through + 1;
    let bound = keep_through + TAIL_TERM_RING as u64 + 1;
    while i <= s.last_log_index && i <= bound {
        let slot = (i & TAIL_TERM_MASK) as usize;
        if s.tail_terms[slot].index == i {
            s.tail_terms[slot].index = 0;
        }
        i += 1;
    }
    s.last_log_index = keep_through;
    s.last_log_term = ring_term_at(s, keep_through).unwrap_or(s.last_log_term);
    s.log_truncations = s.log_truncations.saturating_add(1);
    dev_log(sys, 3, b"[raft] log truncate".as_ptr(), 19);
}

/// Record the term we hold at `index` in the tail ring (called whenever
/// `last_log_index` advances).
#[inline]
fn record_tail_term(s: &mut Raft, index: Index, term: Term) {
    if index == 0 { return; }
    let slot = (index & TAIL_TERM_MASK) as usize;
    s.tail_terms[slot] = TailTerm { index, term };
}

/// Term stored at `index` in the tail ring, if still resident. `None` means
/// the index is not in the ring window (too old / never seen).
#[inline]
fn ring_term_at(s: &Raft, index: Index) -> Option<Term> {
    if index == 0 { return Some(0); }
    let slot = (index & TAIL_TERM_MASK) as usize;
    let t = s.tail_terms[slot];
    if t.index == index { Some(t.term) } else { None }
}

/// True iff our log holds an entry at `index` whose term equals `term`.
/// Index 0 (before the log) and committed indices match by definition —
/// committed entries are immutable and identical across the cluster, so a
/// disagreement there is impossible in correct Raft.
#[inline]
fn log_term_matches(s: &Raft, index: Index, term: Term) -> bool {
    if index == 0 || index <= s.commit_index {
        return true;
    }
    ring_term_at(s, index) == Some(term)
}

/// Discard the divergent suffix: keep entries through `keep_through`, drop the
/// rest from both our log pointers and the WAL. Refuses to touch committed
/// state (a defensive no-op — callers never request it).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and a `&SyscallTable`
/// whose function pointers reach live kernel routines per the module ABI.
unsafe fn truncate_log_after(s: &mut Raft, sys: &SyscallTable, keep_through: Index, now: u64) {
    if s.last_log_index <= keep_through {
        return;
    }
    // SAFETY INVARIANT: committed entries are immutable. Never truncate at or
    // below commit_index. The log-match checks only ever flag conflicts in the
    // uncommitted tail, so this clamp should be unreachable — it exists so a
    // future caller bug degrades to "do nothing" rather than data loss.
    if keep_through < s.commit_index {
        return;
    }
    // If the WAL truncate request or the ack path is unwired (single-node
    // graphs, or a config that hasn't added the edges), we MUST NOT roll our
    // in-memory log back: doing so without the WAL also discarding the suffix
    // would let the WAL replay both the stale and the re-sent entry, and
    // without the ack edge there is no way to learn that it did. Degrade to
    // the conservative behaviour — leave the log as-is; the caller still
    // NACKs and the leader retries (the pre-conflict-repair path). Truncation
    // is opt-in via wiring.
    if s.out_wal_compact < 0 || s.in_wal_flushed < 0 {
        return;
    }
    s.truncate_keep = keep_through;
    s.truncate_req_seq = s.truncate_req_seq.wrapping_add(1);
    s.truncate_req_id = s.truncate_req_seq;
    s.truncate_pending = true;
    s.truncate_emit_pending = false;
    s.truncate_delivered = false;
    // Bound the wait for the channel to accept the request. The hold
    // itself is not bounded: once the WAL has the request, only its
    // correlated ack releases the tip.
    s.truncate_deadline_ms = now + TRUNCATE_HOLD_TIMEOUTS * s.election_timeout_ms as u64;
    emit_wal_truncate_after(s, sys);
}

/// Consume the quorum-commit horizon latch from the commit component
/// (seam E3). commit dispatches after raft, so this consumes the
/// previous step's raise — one tick of feedback spacing.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_commit_in(s: &mut Raft, sys: &SyscallTable) {
    if !s.commit_in.dirty { return; }
    s.commit_in.dirty = false;
    let term = s.commit_in.term;
    let index = s.commit_in.index;
    if index > s.commit_index {
        let prev = s.commit_index;
        s.commit_index = index;
        // Fold the append→commit age of EVERY entry in this newly-committed
        // range, not just the batch high-water — a group fsync commits many
        // entries at once, so recording only `index` biases the latency
        // histogram (RFC §4.1). Bounded to the ring depth: only the most
        // recent COMMIT_TS_RING stamps survive, so entries below that
        // window have no live timestamp and are skipped.
        let ring_lo = index.saturating_sub(COMMIT_TS_RING as Index - 1);
        let lo = if prev + 1 > ring_lo { prev + 1 } else { ring_lo };
        let now = dev_micros(sys);
        let mut e = lo;
        while e <= index {
            let ts_slot = (e as usize) % COMMIT_TS_RING;
            if s.commit_ts_index[ts_slot] == e {
                let lat = now.wrapping_sub(s.commit_ts_us[ts_slot]);
                let b = wire::hist::bucket(&wire::hist::COMMIT_LATENCY_US, lat);
                s.commit_latency_buckets[b] = s.commit_latency_buckets[b].saturating_add(1);
                s.commit_ts_index[ts_slot] = 0;
            }
            e += 1;
        }
        if term > s.current_term {
            // Shouldn't happen on the leader path — but a higher term
            // must be adopted through the persistence path (term + vote
            // clear + metadata save), never as a bare in-memory bump: an
            // unpersisted term bump lets this node re-vote in the old
            // term after a restart.
            become_follower(s, sys, term);
        }
    }
}

/// Roll our log tip back to what the WAL actually holds after a continuity
/// rejection (`MSG_WAL_REJECT`, payload = the index the WAL wants next).
///
/// This repairs the divergence rather than papering over it. The discarded
/// tail is uncommitted BY CONSTRUCTION: the WAL never acked those indices, so
/// they were never quorum-durable and no `commit_index` can cover them. A
/// follower re-derives them from the leader's next AppendEntries; a leader
/// re-proposes them. The `keep_through < commit_index` clamp below is the
/// safety net — if it ever fires, the invariant is already broken upstream and
/// refusing to truncate is the conservative choice.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared `&Raft` where the
/// signature uses one) and supply a valid `&SyscallTable` whose function
/// pointers reach live kernel routines per the module ABI.
unsafe fn resync_to_wal(s: &mut Raft, sys: &SyscallTable, expected_index: Index) {
    let keep_through = expected_index.saturating_sub(1);
    if keep_through >= s.last_log_index {
        // Nothing to roll back — the reject raced a truncation that already
        // brought us to (or below) the WAL's tip.
        s.flush_deferred = false;
        return;
    }
    // DELIBERATELY NOT a log rollback. Apply has already consumed the
    // entries above the WAL's tip, so rewinding re-delivers them, and
    // evicting the tail-ring slots makes `log_term_matches` disown entries
    // the leader still holds (AE-conflict storms on healthy nodes).
    //
    // The divergence is prevented at its source — the boot-handshake gate in
    // `handle_append_entries` and the `MAX_WAL_UNACKED` bound — so nothing
    // legitimate reaches here. If it does, the node stalls LOUDLY: counted
    // and logged. Clearing the stale deferral keeps intake from wedging
    // behind a flag whose batch is gone.
    s.flush_deferred = false;
    s.wal_resyncs = s.wal_resyncs.saturating_add(1);
    dev_log(sys, 1, b"[raft] wal divergence".as_ptr(), 21);
}

unsafe fn drain_wal_flushed(s: &mut Raft, sys: &SyscallTable) {
    if s.in_wal_flushed < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_wal_flushed, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_wal_flushed, &mut s.msg_buf);
        if msg_type == wire::MSG_WAL_REJECT {
            // The WAL refused our append as discontinuous: our log claims
            // entries it never persisted. A successful `channel_write_msg`
            // only proved the frame reached its input channel, never that it
            // was accepted, so this is the ONLY authoritative signal that our
            // tip is a fiction. Resync down to what the WAL actually holds and
            // replay from there.
            if let Some(expected) = wire::decode_wal_reject(&s.msg_buf[..plen.max(0) as usize]) {
                resync_to_wal(s, sys, expected);
            }
            continue;
        }
        if msg_type == wire::MSG_WAL_TRUNCATE_ACK {
            if let Some((keep, req_id, durable)) =
                wire::decode_wal_truncate_ack(&s.msg_buf[..plen.max(0) as usize])
            {
                apply_truncate_ack(s, sys, keep, req_id, durable);
            }
            continue;
        }
        if msg_type != wire::MSG_FSYNC_ACK || (plen as usize) < 17 { continue; }
        // The ack's term is the term of the entry AT `index`. It is the
        // only source that pairs the two, and the metadata record needs
        // exactly that pair.
        let (ack_term, index, _replica) = wire::decode_fsync_ack(&s.msg_buf);
        if index > s.local_durable_index {
            s.local_durable_index = index;
            s.local_durable_term = ack_term;
        }
    }
    // Persist the advanced durable watermark (term/vote/durable index) on the
    // fsync-ack path — but throttled, so we don't add a metadata fsync per
    // entry (which would double the WAL's fsync load and skew throughput).
    // term/vote changes persist eagerly at their own call sites; this only
    // catches durable-index growth. META_PERSIST_STRIDE bounds how much
    // durable progress a crash can lose from the metadata hint (replay
    // re-derives the exact index from the WAL regardless).
    if s.persist_meta != 0
        && s.meta_root_path != 0
        && s.meta_backoff_steps == 0
        && s.local_durable_index >= s.meta_persisted_durable.wrapping_add(META_PERSIST_STRIDE)
    {
        save_metadata(s, sys);
    }
}

/// Consume the WAL's one-shot replay-complete signal. The WAL's reconstructed
/// on-disk high-water is the AUTHORITATIVE recovery point — the persisted
/// metadata `last_log_index` is only a throttled hint that can either lag the
/// true high-water (META_PERSIST_STRIDE rounds down) or, if a crash lost
/// un-replayable tail entries, over-count it. So on a genuine recovery boot
/// (`awaiting_replay`) `last_log_index` resumes exactly at the high-water,
/// apply is re-seeded to that base via the recovery-reset path, and the
/// proposal-intake hold is released so post-recovery traffic continues the
/// recovered index space instead of colliding with it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_wal_replay_complete(s: &mut Raft, sys: &SyscallTable) {
    if s.in_wal_replay_complete < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_wal_replay_complete, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_wal_replay_complete, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_REPLAY_COMPLETE || (plen as usize) < 16 { continue; }
        let (hw_term, high_water) = wire::decode_term_index(&s.msg_buf);
        // Only a genuine recovery boot acts on the high-water. A
        // non-recovery graph (fresh WAL emitting hw=0) must not rewind a
        // log raft is legitimately growing — so we gate on `awaiting_replay`,
        // which `load_metadata` set iff we loaded a persisted durable index.
        if s.awaiting_replay {
            s.last_log_index = high_water;
            s.last_log_term = hw_term;
            record_tail_term(s, high_water, hw_term);
            s.local_durable_index = high_water;
            s.local_durable_term = hw_term;
            s.meta_persisted_durable = high_water;
            s.replay_hw_received = high_water;
            // Re-seed apply to the recovered base via the step-0
            // path. The intake hold (`awaiting_replay`) stays SET until
            // that raise is emitted — only then does step-0 clear it — so raft
            // never appends a new entry before apply has been seeded to the
            // base. (For high_water == 0, a fresh skip_replay WAL, there is
            // nothing to seed: release intake immediately.)
            if high_water > 0 {
                s.pending_recovery_reset = true;
            } else {
                s.awaiting_replay = false;
            }
            dev_log(sys, 3, b"[raft] replay resume".as_ptr(), 20);
        }
    }
}

/// Apply committed admin/config entries from apply's seam ring (E9).
/// ≤4 per step.
///
/// # Safety
///
/// Caller must hold exclusive borrows and supply a valid
/// `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_admin_committed(s: &mut Raft, sys: &SyscallTable, admin_in: &mut SeamRing<4096>) {
    for _ in 0..4 {
        // An unannounced result blocks the drain. The ring holds the
        // records behind it, so nothing is lost by waiting, whereas
        // popping past would overwrite the pending status with the next
        // one and leave the first command with no outcome at all.
        if !flush_admin_applied(s, sys) {
            return;
        }
        let (msg_type, plen) = match admin_in.pop(&mut s.msg_buf) {
            Some(v) => v,
            None => break,
        };
        let pl = plen as usize;
        match msg_type {
            wire::MSG_ADMIN_COMMITTED => {
                if pl < 5 {
                    continue;
                }
                let command_id = u32::from_le_bytes([
                    s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                ]);
                let op_code = s.msg_buf[4];
                let status = apply_admin_op(
                    s,
                    op_code,
                    &s.msg_buf as *const _ as *const u8,
                    pl,
                );
                emit_admin_applied(s, sys, command_id, status);
            }
            wire::MSG_CONFIG_COMMITTED => {
                apply_config_change(s, sys, pl);
            }
            _ => {}
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn apply_config_change(s: &mut Raft, sys: &SyscallTable, plen: usize) {
    let (op_code, voters_off, voter_count) =
        match wire::decode_config_change(&s.msg_buf[..plen]) {
            Some(v) => v,
            None => return,
        };
    let mut new_set = NodeSet::empty();
    for i in 0..voter_count {
        let id = s.msg_buf[voters_off + i];
        if (id as usize) < MAX_NODES {
            new_set.insert(id);
        }
    }
    match op_code {
        wire::CONFIG_CHANGE_OP_JOINT => {
            // Replay dedup: applying the same joint entry twice (log
            // replay, duplicate committed-entry delivery) must not
            // re-queue a duplicate C_new proposal.
            if s.joint_active && s.joint_voters.0 == new_set.0 {
                return;
            }
            // Enter joint state: keep current voters, layer new set
            // as joint. Subsequent quorum checks require both.
            s.joint_voters = new_set;
            s.joint_active = true;
            // RFC §1.2 completeness: the leader queues the C_new
            // proposal so the next `step_leader` tick emits it
            // automatically. Followers ignore this slot — they only
            // see the C_new entry once the leader replicates it.
            if s.role == ROLE_LEADER {
                s.pending_new_voters = new_set;
                s.pending_new_voters_set = true;
            }
        }
        wire::CONFIG_CHANGE_OP_NEW => {
            // Replay dedup: an identical C_new against an already-exited
            // joint state is a replayed entry — idempotent, skip.
            if !s.joint_active && s.current_voters.0 == new_set.0 {
                return;
            }
            // Exit joint state: install new voters as current,
            // clear joint overlay. If our own id was removed from the
            // new set, step down to a non-voting follower AND enter
            // learner mode so we don't start elections or grant votes.
            s.current_voters = new_set;
            s.joint_voters = NodeSet::empty();
            s.joint_active = false;
            // Pending was satisfied by the entry we just applied.
            s.pending_new_voters = NodeSet::empty();
            s.pending_new_voters_set = false;
            if !s.current_voters.contains(s.self_id) {
                if s.role == ROLE_LEADER {
                    s.role = ROLE_FOLLOWER;
                    s.leader_id = -1;
                }
                s.learner_mode = true;
                dev_log(sys, 3, b"[raft] removed self".as_ptr(), 19);
            } else {
                // Re-added after a previous removal: clear learner
                // mode so the node re-enters normal election
                // participation on the next tick.
                if s.learner_mode {
                    s.learner_mode = false;
                    dev_log(sys, 3, b"[raft] re-added".as_ptr(), 15);
                }
            }
        }
        _ => return,
    }
    // Push new voter_count to local quorum logic plus downstream
    // (commit + replicator via the voter-set latch) so AE-quorum
    // tracking uses the right denominator.
    s.voter_count = s.current_voters.count();
    save_metadata(s, sys);
    emit_voter_set_update(s, sys);
    dev_log(sys, 3, b"[raft] config applied".as_ptr(), 21);
}

/// E10 seam: latch the voter-set update for same-step delivery to
/// commit + replicator by the dispatch table — every consumer sees
/// the update on the same tick.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` per the module ABI.
unsafe fn emit_voter_set_update(s: &mut Raft, _sys: &SyscallTable) {
    s.voter_out = Some((s.current_voters.0, s.joint_voters.0, s.joint_active as u8));
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_admin(s: &mut Raft, sys: &SyscallTable, _now: u64) {
    if s.in_admin < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_admin, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_admin, &mut s.msg_buf);
        if msg_type != wire::MSG_ADMIN_COMMAND || (plen as usize) < 5 { continue; }
        let command_id = u32::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
        ]);
        let op_code = s.msg_buf[4];
        let status = apply_admin_op(s, op_code, &s.msg_buf as *const _ as *const u8, plen as usize);
        emit_admin_applied(s, sys, command_id, status);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn apply_admin_op(
    s: &mut Raft,
    op_code: u8,
    buf_ptr: *const u8,
    plen: usize,
) -> u8 {
    // Safety: drain_admin owns the buffer for this iteration; this view
    // is read-only.
    let buf = core::slice::from_raw_parts(buf_ptr, plen);
    match op_code {
        wire::ADMIN_OP_FREEZE => { s.frozen = true; wire::ADMIN_STATUS_OK }
        wire::ADMIN_OP_THAW => { s.frozen = false; wire::ADMIN_STATUS_OK }
        wire::ADMIN_OP_TRANSFER_LEADER => {
            // Body: `[target_replica_id:u8]` at offset 5 (after command_id+op_code).
            if plen < 6 { return wire::ADMIN_STATUS_REJECTED; }
            // Only the leader can transfer; followers reject.
            if s.role != ROLE_LEADER { return wire::ADMIN_STATUS_NOT_LEADER; }
            let target = buf[5];
            if target == s.self_id || target as i8 == -1 {
                return wire::ADMIN_STATUS_REJECTED;
            }
            s.pending_transfer_to = target;
            wire::ADMIN_STATUS_OK
        }
        wire::ADMIN_OP_DURABILITY_MODE => {
            if plen < 6 { return wire::ADMIN_STATUS_REJECTED; }
            s.durability_mode = buf[5];
            wire::ADMIN_STATUS_OK
        }
        wire::ADMIN_OP_SNAPSHOT => {
            // We don't directly trigger the snapshot component here — the
            // existing wal.compaction_signal path already drives it on
            // segment rollover. This op is a no-op acknowledgement
            // until the explicit-snapshot wire is added.
            wire::ADMIN_STATUS_OK
        }
        _ => wire::ADMIN_STATUS_UNSUPPORTED,
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_admin_applied(s: &mut Raft, sys: &SyscallTable, command_id: u32, status: u8) {
    if s.out_admin_applied < 0 { return; }
    s.admin_ack_pending = true;
    s.admin_ack_id = command_id;
    s.admin_ack_status = status;
    let _ = flush_admin_applied(s, sys);
}

/// Re-offer the outstanding admin status, reporting whether nothing is
/// owed. The op it names has already been applied, so this announces a
/// result rather than causing one; losing it would leave an operator's
/// command with no outcome at all while its effect stood.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn flush_admin_applied(s: &mut Raft, sys: &SyscallTable) -> bool {
    if !s.admin_ack_pending { return true; }
    if s.out_admin_applied < 0 {
        s.admin_ack_pending = false;
        return true;
    }
    let mut buf = [0u8; 5];
    buf[0..4].copy_from_slice(&s.admin_ack_id.to_le_bytes());
    buf[4] = s.admin_ack_status;
    let n = wire_channels::channel_write_msg(
        sys, s.out_admin_applied, wire::MSG_ADMIN_APPLIED, &buf,
    );
    if n > 0 {
        s.admin_ack_pending = false;
    }
    !s.admin_ack_pending
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_timeout_now_if_pending(s: &mut Raft, sys: &SyscallTable) {
    if s.pending_transfer_to == 0 { return; }
    if s.role != ROLE_LEADER { s.pending_transfer_to = 0; return; }
    if s.out_rpc < 0 { return; }
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let target = s.pending_transfer_to;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&s.current_term.to_le_bytes());
    // Use the partitioned envelope so peer_router can route by partition.
    wire_channels::channel_write_routed_partitioned(
        sys,
        s.out_rpc,
        target,
        s.partition_id,
        wire::MSG_TIMEOUT_NOW,
        &buf,
    );
    dev_log(sys, 3, b"[raft] timeout_now tx".as_ptr(), 21);
    // The transfer attempt is fire-and-forget; if the target doesn't
    // actually take over we keep being leader. The op_response was
    // already acked OK as soon as the local intent was recorded.
    s.pending_transfer_to = 0;
    // Help the transfer succeed by stepping down to follower right
    // after the fire. This makes our re-election delay long enough
    // for the target to start its election first.
    s.role = ROLE_FOLLOWER;
    s.leader_id = target as i8;
}

/// True while this node does not yet know where its own log ends.
///
/// Between boot and the WAL's `replay_complete`, `last_log_index` /
/// `last_log_term` hold the PERSISTED HINT, which is a lower bound and
/// nothing more: the hint is written on a throttle and records the
/// durable watermark, so the WAL can hold committed entries well above
/// it. Every ballot in Raft is decided by comparing logs, and a
/// comparison made against an understated tip is not conservative — it
/// is wrong in the unsafe direction:
///
/// - GRANTING on it elects a candidate whose log is genuinely shorter
///   than ours, and the entries between the hint and our real tip —
///   committed entries — are then overwritten. That is a Leader
///   Completeness violation, the one Raft property with no recovery.
/// - CAMPAIGNING on it advertises a tip below our own, so we can win an
///   election we should have lost, with the same outcome.
///
/// Term observation and heartbeat handling stay open, because neither
/// depends on the tip: a higher term must be adopted whenever it is
/// heard, and `handle_append_entries` already answers `busy` so the
/// leader simply retries. What closes is every path whose correctness
/// rests on the log comparison.
///
/// The hold is only as long as the WAL takes to hand over its
/// high-water — milliseconds — and is armed only where the recovery
/// edge is wired (see `s.awaiting_replay`).
fn replay_hold(s: &Raft) -> bool {
    s.awaiting_replay
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_vote_request(s: &mut Raft, sys: &SyscallTable, msg_type: u8, plen: u16) {
    if plen < 25 { return; }
    let (term, candidate, last_index, last_term) = wire::decode_vote_request(&s.msg_buf);

    let is_pre_vote = msg_type == wire::MSG_PRE_VOTE;

    // Step down if term is higher (only for real votes, not pre-votes).
    // IN MEMORY only: the persisted record is written exactly once
    // below, folded with the grant decision, so this path never costs
    // two metadata round-trips and never persists a state it later
    // amends.
    let term_advanced = !is_pre_vote && term > s.current_term;
    if term_advanced {
        become_follower_mem(s, term);
    }

    // Grant conditions:
    // 1. Term >= our term
    // 2. We haven't voted for someone else this term (or it's a pre-vote)
    // 3. Candidate's log is at least as up-to-date as ours
    // 4. We are a voter: learners (removed from the voter set) MUST NOT
    //    grant — an ex-voter's vote counted toward a majority is exactly
    //    how a post-downsize cluster elects two leaders.
    let term_ok = term >= s.current_term;
    let vote_ok = is_pre_vote
        || s.voted_for == REPLICA_NONE as i8
        || s.voted_for == candidate as i8;
    let log_ok = last_term > s.last_log_term
        || (last_term == s.last_log_term && last_index >= s.last_log_index);

    let mut granted = term_ok && vote_ok && log_ok && !s.learner_mode;

    // Log comparison is only as good as our knowledge of our own log.
    // See `replay_hold`: until the WAL reports its high-water, `log_ok`
    // was computed against a lower bound, so a candidate that is
    // genuinely behind us can look ahead of us. Refuse both real votes
    // and PRE-votes — a pre-vote granted on the same bad comparison is
    // what tells the candidate its real election will succeed.
    //
    // The response still goes out, carrying our term: a candidate
    // learning it is behind is useful, and a silent drop would only
    // stall the election it is entitled to lose.
    if replay_hold(s) {
        granted = false;
    }

    // Volatile posture mitigations for real votes: no grants inside the
    // boot hold-off window (this node may have voted in an election
    // still in flight across its restart), and none in any term at or
    // below the highest term heard from a leader since boot.
    if granted && !is_pre_vote && s.persist_meta == 0 {
        let now = dev_millis(sys);
        if now < s.holdoff_until_ms || term <= s.vote_floor_term {
            granted = false;
        }
    }

    // Write-then-adopt: persist the prospective record, and only on
    // success adopt the vote in memory and answer `granted`. On
    // failure the grant is withheld and NOTHING was mutated by the
    // grant path — no rollback exists or is needed. A failed persist
    // after a term advance leaves the term adopted in memory (the
    // become_follower liveness exception) with the vote unset.
    if !is_pre_vote && (granted || term_advanced) {
        let vote = if granted { candidate as i8 } else { s.voted_for };
        let current = s.current_term;
        match persist_meta_record(s, sys, current, vote) {
            PersistOutcome::Persisted => {
                if granted {
                    s.voted_for = candidate as i8;
                }
            }
            _ => {
                granted = false;
            }
        }
    }

    // Send response routed to the specific candidate
    let resp_type = if is_pre_vote { wire::MSG_PRE_VOTE_RESP } else { wire::MSG_REQUEST_VOTE_RESP };
    let mut resp = [0u8; 10];
    wire::encode_vote_response(&mut resp, s.current_term, granted, s.self_id);

    let poll_out = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(sys, s.out_rpc, candidate, s.partition_id, resp_type, &resp[..10]);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_vote_response(s: &mut Raft, sys: &SyscallTable, msg_type: u8, plen: u16) {
    if s.role != ROLE_CANDIDATE { return; }
    if plen < 10 { return; }

    let (term, granted, voter) = wire::decode_vote_response(&s.msg_buf);

    if term > s.current_term {
        become_follower(s, sys, term);
        return;
    }

    let is_pre_vote_resp = msg_type == wire::MSG_PRE_VOTE_RESP;

    if is_pre_vote_resp != s.pre_vote_active { return; }

    // A real grant is only valid for the election it answered: the granter
    // adopts our term before responding, so its response echoes it. A
    // response at any other term is a delayed grant from another election,
    // and counting it lets two candidates assemble "majorities" sharing a
    // voter. Pre-vote responses carry the granter's own (unbumped) term, so
    // they are exempt — a stale one can at worst trigger a real,
    // term-checked election.
    if !is_pre_vote_resp && term != s.current_term { return; }

    if voter as usize >= MAX_NODES { return; }

    // Only ballots from the active voter set(s) count: a learner or an
    // ex-voter that missed its revoke must not move the tally.
    if !s.current_voters.contains(voter)
        && !(s.joint_active && s.joint_voters.contains(voter))
    {
        return;
    }

    if granted {
        s.votes_granted.insert(voter);
    } else {
        s.votes_rejected.insert(voter);
    }
}

/// Quorum rule shared by elections and ReadIndex probes: `votes` ∩
/// current voter set must reach a majority of it, and — while a joint
/// config is active — a majority of the joint set too. Election-side
/// mirror of commit's dual-median rule: a joint-phase leader must win
/// both configs (RFC §1.2).
fn set_majority(votes: NodeSet, current: NodeSet, joint: NodeSet, joint_active: bool) -> bool {
    let cur_needed = (current.count() / 2) + 1;
    if NodeSet(votes.0 & current.0).count() < cur_needed { return false; }
    if joint_active && joint.count() > 0 {
        let joint_needed = (joint.count() / 2) + 1;
        if NodeSet(votes.0 & joint.0).count() < joint_needed { return false; }
    }
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_append_entries(s: &mut Raft, sys: &SyscallTable, plen: u16, now: u64) {
    let pl = plen as usize;
    if pl < wire::AE_HDR_LEN { return; }
    let (term, leader, prev_log_index, prev_log_term, leader_commit, entry_term, entry_index) =
        match wire::decode_append_entries(&s.msg_buf[..pl]) {
            Some(t) => t,
            None => {
                dev_log(sys, 3, b"[raft] ae decode-fail".as_ptr(), 21);
                return;
            }
        };

    if term < s.current_term {
        // Reject: stale term. Send response with our term and current
        // last-log so the leader can decide what to do.
        send_append_response(s, sys, false, false);
        return;
    }

    // Volatile posture: remember the highest term seen from a leader —
    // real vote grants require a term strictly above this floor.
    if s.persist_meta == 0 && term > s.vote_floor_term {
        s.vote_floor_term = term;
    }

    if term > s.current_term {
        become_follower(s, sys, term);
    } else if s.role != ROLE_FOLLOWER {
        // Keep `voted_for`: the vote belongs to the TERM, not the role,
        // and the persisted record is unchanged — so no metadata write.
        step_down_same_term(s);
    }
    s.leader_id = leader as i8;
    reset_election_deadline(s, now);

    // Boot handshake gate — the follower half of the rule `step_leader`
    // already enforces (`!s.awaiting_replay`). Until the WAL hands us its
    // on-disk high-water we do not know where our log actually ends, so
    // appending now and rewinding to `replay_hw` a moment later leaves raft
    // and the WAL permanently disagreeing, and the resulting continuity
    // fault is unrepairable once commit passes it.
    //
    // `busy` (not a log mismatch): the leader retries this same entry once we
    // are ready, rather than rolling next_index back into needless repair.
    if s.awaiting_replay {
        send_append_response(s, sys, false, true);
        return;
    }

    // Pending-truncation gate. Until the WAL reports the discarded
    // suffix gone from stable storage, this node still holds it: a
    // replacement entry appended now would sit above a suffix the WAL
    // can still replay, and an ack of it would be quorum evidence for a
    // log the disk does not have. `busy` (not a log mismatch): the
    // leader retries the same entry once the truncation lands, rather
    // than rolling next_index back into needless repair.
    if s.truncate_pending {
        s.truncate_holds = s.truncate_holds.saturating_add(1);
        send_append_response(s, sys, false, true);
        return;
    }

    // ── Log matching + conflict repair (Raft §5.3) ──────────────
    // (1) Gap: we don't hold an entry as far as prev_log_index. NACK; the
    //     response carries our last_log_index so the leader (replicator)
    //     backs next_index up to it instead of decrementing one at a time.
    if prev_log_index > s.last_log_index {
        dev_log(sys, 3, b"[raft] ae gap".as_ptr(), 13);
        send_append_response(s, sys, false, false);
        return;
    }
    // (2) Term conflict at prev_log_index: our entry there disagrees with the
    //     leader's. Discard everything from prev_log_index onward (uncommitted
    //     by construction — see `log_term_matches`) and NACK so the leader
    //     backs up and resends from an agreed point.
    if !log_term_matches(s, prev_log_index, prev_log_term) {
        truncate_log_after(s, sys, prev_log_index.saturating_sub(1), now);
        dev_log(sys, 3, b"[raft] ae conflict".as_ptr(), 18);
        send_append_response(s, sys, false, false);
        return;
    }

    // prev_log_* agrees. Accept the carried entry, if any.
    if entry_index > 0 {
        // If we already hold an entry at this index, it is either identical
        // (idempotent retransmit — do NOT re-append, that would duplicate it
        // in the WAL) or divergent (truncate + NACK so the leader resends it
        // on a later AE, after the WAL has applied the truncate — the resend
        // and the truncate must not race within one WAL step).
        if entry_index <= s.last_log_index {
            if log_term_matches(s, entry_index, entry_term) {
                advance_follower_commit(s, sys, leader_commit);
                // Ack AT the retransmitted index, not our tip: this AE
                // verified the log only up to `entry_index`, and a tip
                // that still carries an old-term divergent suffix must
                // not be quorum-counted off the back of it.
                send_append_response_at(s, sys, true, false, entry_index);
                return;
            }
            truncate_log_after(s, sys, entry_index.saturating_sub(1), now);
            dev_log(sys, 3, b"[raft] ae conflict".as_ptr(), 18);
            send_append_response(s, sys, false, false);
            return;
        }

        // Durability bound (the other half of RFC §13/§14's fail-closed
        // contract). `channel_write_msg` succeeding below proves only that the
        // frame entered the WAL's input channel — never that the WAL ACCEPTED
        // it. Unbounded, our log runs arbitrarily far ahead of what is
        // persisted, and once commit passes that point the divergence covers
        // acknowledged entries and no rollback can repair it.
        //
        // Hold intake once we are too far ahead of our own durable index and
        // answer `busy`: the leader retries this same entry rather than
        // rolling next_index back into needless log repair.
        if s.last_log_index.saturating_sub(s.local_durable_index) >= MAX_WAL_UNACKED {
            s.wal_unacked_holds = s.wal_unacked_holds.saturating_add(1);
            send_append_response(s, sys, false, true);
            return;
        }

        // Clean append. The checks above validate `prev_log_*` only — nothing
        // there constrains `entry_index`, so contiguity is enforced here. A
        // leader whose per-peer `prev_log_index` bookkeeping disagrees with
        // the entry it ships (the replicator derives it from two sources: WAL
        // read-back and the per-batch tip) can present prev_log_index == our
        // tip together with an entry_index that skips; writing that punches a
        // hole in both our log and the WAL, unrepairable once commit passes
        // it.
        //
        // NACK instead. The response carries our real `last_log_index`, which
        // is what the leader needs to reset `next_index` and resend from the
        // right place — ordinary Raft log repair, no hole.
        if entry_index != s.last_log_index.saturating_add(1) {
            s.ae_noncontiguous = s.ae_noncontiguous.saturating_add(1);
            dev_log(sys, 3, b"[raft] ae noncontiguous".as_ptr(), 23);
            send_append_response(s, sys, false, false);
            return;
        }

        let entry_payload_start = wire::AE_HDR_LEN;
        let entry_len = pl.saturating_sub(entry_payload_start);

        // An entry body over the shared frame cap can never be stored
        // faithfully — truncating it here would ACK success while our
        // applied state silently diverges from the leader's. NACK with
        // `busy=false` instead: structurally invalid, not backpressure.
        if entry_len > wal_frame::MAX_ENTRY_BODY {
            s.ae_noncontiguous = s.ae_noncontiguous.saturating_add(1);
            dev_log(sys, 3, b"[raft] ae oversize entry".as_ptr(), 24);
            send_append_response(s, sys, false, false);
            return;
        }

        let mut wal_buf = [0u8; wal_frame::MAX_ENTRY_LEN];
        wire::encode_term_index(&mut wal_buf, entry_term, entry_index);
        let copy_len = entry_len;
        if copy_len > 0 {
            wal_buf[16..16 + copy_len]
                .copy_from_slice(&s.msg_buf[entry_payload_start..entry_payload_start + copy_len]);
        }

        // Fail closed on the follower too (RFC §13/§14): attempt the WAL
        // write first and only advance `last_log_index` if the whole entry
        // landed. `channel_write_msg` is a single atomic frame write, so a
        // `<= 0` return means the channel was full and NOTHING was written
        // — do NOT advance (else our log would claim an entry the WAL never
        // persisted and diverge). Respond with failure so the leader
        // retries this AE once our WAL drains; normal Raft log-repair,
        // driven by local durability backpressure instead of a log mismatch.
        let written =
            wire_channels::channel_write_msg(sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf[..16 + copy_len]);
        if written <= 0 {
            s.flushes_deferred = s.flushes_deferred.saturating_add(1);
            // Local WAL backpressure, NOT a log mismatch: signal `busy` so the
            // leader retries this same entry once our WAL drains instead of
            // rolling next_index back (which would trigger needless log repair).
            send_append_response(s, sys, false, true);
            return;
        }

        // E5 seam: fan the accepted body out to
        // apply's body ring. Fail-open drop-on-full preserved.
        let _ = s.outbox_bodies.push(wire::MSG_WAL_ENTRY, &wal_buf[..16 + copy_len]);

        s.last_log_index = entry_index;
        s.last_log_term = entry_term;
        record_tail_term(s, entry_index, entry_term);
        s.entries_appended += 1;
    }

    // Follower commit advance: clamp leader_commit to what we actually
    // have. When the follower's commit_index moves, fan it out so the
    // apply pipeline can advance. See RFC §5.1.
    advance_follower_commit(s, sys, leader_commit);

    send_append_response(s, sys, true, false);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn advance_follower_commit(s: &mut Raft, _sys: &SyscallTable, leader_commit: u64) {
    let new_commit = leader_commit.min(s.last_log_index);
    if new_commit <= s.commit_index { return; }
    s.commit_index = new_commit;
    // E6 seam (was MSG_COMMITTED_BATCH on `commit_advanced`): raise the
    // apply-horizon latch — always deliverable, no writability gate.
    s.apply_horizon_out.raise(s.current_term, new_commit);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn send_append_response(s: &Raft, sys: &SyscallTable, success: bool, busy: bool) {
    send_append_response_at(s, sys, success, busy, s.last_log_index);
}

/// As `send_append_response`, but reporting an explicit index — used by
/// the idempotent-retransmit ACK, whose verification covers only the
/// retransmitted entry, not the whole tip.
///
/// # Safety
///
/// As `send_append_response`.
unsafe fn send_append_response_at(
    s: &Raft,
    sys: &SyscallTable,
    success: bool,
    busy: bool,
    ack_index: Index,
) {
    let mut resp = [0u8; wire::AE_RESP_LEN];
    wire::encode_append_entries_resp(
        &mut resp,
        s.current_term,
        ack_index,
        s.self_id,
        success,
        s.local_durable_index,
        busy,
    );

    // Route back to leader
    let target = if s.leader_id >= 0 { s.leader_id as u8 } else { wire::TARGET_BROADCAST };
    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(sys, s.out_rpc, target, s.partition_id, wire::MSG_APPEND_ENTRIES_RESP, &resp);
    }
}

// ── Follower step ───────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_follower(s: &mut Raft, sys: &SyscallTable, now: u64) {
    // Learner-mode followers (self removed from voter set via
    // CONFIG_CHANGE_OP_NEW) MUST NOT start elections. Re-arm the
    // deadline so we don't fire as soon as we exit learner mode.
    if s.learner_mode {
        reset_election_deadline(s, now);
        return;
    }
    if now >= s.election_deadline_ms {
        // Election timeout — start pre-vote
        start_election(s, sys, now, true);
    }
}

// ── Candidate step ──────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_candidate(s: &mut Raft, sys: &SyscallTable, now: u64) {
    if set_majority(s.votes_granted, s.current_voters, s.joint_voters, s.joint_active) {
        if s.pre_vote_active {
            // Pre-vote succeeded — start real election
            start_election(s, sys, now, false);
        } else {
            // Real vote succeeded — become leader
            become_leader(s, sys, now);
        }
        return;
    }

    // Check election timeout
    if now >= s.election_deadline_ms {
        // Restart election
        start_election(s, sys, now, true);
    }
}

// ── Leader step ─────────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_leader(s: &mut Raft, sys: &SyscallTable, now: u64) {
    // 0. Joint-consensus completeness: if a C_old,new entry has
    //    committed (apply_config_change set `pending_new_voters_set`),
    //    auto-propose the matching C_new entry. We only emit when
    //    the proposal batch is empty so the C_new entry gets its
    //    own clean log slot — important for replication correctness.
    if s.pending_new_voters_set && s.proposal_batch_count == 0 {
        emit_pending_c_new(s, sys, now);
    }

    // 0b. Current-term no-op (§5.4.2). Must precede proposal intake so
    //     the fence index lands as the first entry of this term; a full
    //     WAL channel just retries next tick (`noop_pending` stays set).
    if s.noop_pending
        && !s.awaiting_replay
        && !s.truncate_pending
        && s.proposal_batch_count == 0
        && !s.flush_deferred
    {
        append_noop(s, sys);
    }

    // 1. Drain proposals into batch — gated by two durability-backpressure
    //    conditions (RFC §13/§14):
    //    (a) not holding a WAL-deferred batch (`flush_deferred`): a prior
    //        flush couldn't write to `out_log`; reading more would coalesce
    //        onto the held index or drop it.
    //    (b) the uncommitted-inflight window is under `MAX_UNCOMMITTED_INFLIGHT`:
    //        the log must not run too far ahead of quorum-durable
    //        `commit_index`, or the WAL group-fsync path lets raft race past
    //        what commits, overflowing the observer fanout / apply buffer.
    //    When either gate is closed, proposals stay queued in their input
    //    channels and the upstream proposer (throttle / injector)
    //    backpressures — a plateau at commit throughput, not a cliff.
    //    (c) not holding for boot-time recovery resume (`awaiting_replay`):
    //        until the WAL hands us its exact on-disk high-water we'd append
    //        at a STALE persisted hint and collide with the replayed index
    //        space. Proposals stay queued upstream until the signal lands.
    //    (d) no unacknowledged truncation (`truncate_pending`): the tip is
    //        still the pre-truncation one and the WAL is about to shorten
    //        the segment under it, so a new entry would be appended into
    //        the region being discarded.
    let inflight = s.last_log_index.saturating_sub(s.commit_index);
    if !s.flush_deferred
        && !s.awaiting_replay
        && !s.truncate_pending
        && inflight < MAX_UNCOMMITTED_INFLIGHT
    {
        drain_proposals(s, sys, now);
    }

    // 2. Flush batch if ready. A deferred batch is always "ready" — it
    //    retries the WAL write every tick until `out_log` has space.
    let batch_elapsed = now.wrapping_sub(s.proposal_batch_start_ms);
    let should_flush = s.proposal_batch_count > 0
        && (s.flush_deferred
            || s.proposal_batch_count >= s.proposal_batch_max
            || batch_elapsed >= s.proposal_batch_timeout_ms as u64);

    if should_flush {
        flush_proposal_batch(s, sys);
    }

    // 3. Send heartbeats
    if now.wrapping_sub(s.last_heartbeat_ms) >= s.heartbeat_interval_ms as u64 {
        send_heartbeat(s, sys);
        s.last_heartbeat_ms = now;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Append a `CONFIG_CHANGE_OP_NEW` entry into the proposal batch,
/// completing the joint-consensus transition that
/// `apply_config_change` started. Called exclusively from
/// `step_leader` and only when `pending_new_voters_set` is true.
unsafe fn emit_pending_c_new(s: &mut Raft, sys: &SyscallTable, now: u64) {
    // Materialise the new voter id list from the NodeSet bitmask.
    let mut voter_ids = [0u8; MAX_NODES];
    let mut n = 0usize;
    for id in 0..MAX_NODES as u8 {
        if s.pending_new_voters.contains(id) {
            voter_ids[n] = id;
            n += 1;
        }
    }
    let mut body = [0u8; 3 + MAX_NODES];
    let body_len = wire::encode_config_change(
        &mut body,
        wire::CONFIG_CHANGE_OP_NEW,
        &voter_ids[..n],
    );
    if body_len == 0 {
        return;
    }
    // append_to_batch copies from `s.msg_buf[off..off+len]`, so stage
    // the body there. Use an offset past anything drain_proposals
    // might be using; the scratch buffer is 2048 bytes wide so room
    // is plentiful.
    let stage_off = 1024usize;
    s.msg_buf[stage_off..stage_off + body_len].copy_from_slice(&body[..body_len]);
    if append_to_batch(s, sys, stage_off, body_len, 0, now) {
        // Clear the pending slot — flush_proposal_batch will append
        // the C_new entry to the log next time it runs.
        s.pending_new_voters_set = false;
        s.pending_new_voters = NodeSet::empty();
        dev_log(sys, 3, b"[raft] c_new queued".as_ptr(), 19);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_proposals(s: &mut Raft, sys: &SyscallTable, now: u64) {
    // Admin freeze OR strict-fallback: drop every incoming proposal
    // silently. The client path (codec → throttle) will
    // not see any feedback, but the codec correlation rings time
    // out on their own and the client eventually retries / surfaces an
    // error. THAW (or a CP-proof recovery for strict_fallback)
    // restores. The two counters are kept distinct in metrics so
    // operators can tell admin-driven from CP-driven gating apart.
    if s.frozen || s.strict_fallback {
        let frozen = s.frozen;
        for chan in [s.in_proposals, s.in_proposals_tagged,
                     s.in_proposals_partitioned, s.in_proposals_partitioned_tagged] {
            if chan < 0 { continue; }
            for _ in 0..16 {
                let poll = (sys.channel_poll)(chan, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) = wire_channels::channel_read_msg(sys, chan, &mut s.msg_buf);
                // Replicable admin envelopes (ADMIN_MAGIC-prefixed, spec
                // §3.1) are exempt from the FREEZE gate: freeze blocks
                // client writes, and the THAW that lifts it rides this
                // very path — dropping it would make freeze permanent by
                // construction. They arrive untagged only, and remain
                // subject to the durability backpressure gates. The
                // strict-fallback gate is not exempted: its recovery is a
                // CP-proof refresh, not an admin entry.
                if frozen
                    && !s.strict_fallback
                    && chan == s.in_proposals
                    && msg_type == wire::MSG_CLIENT_PROPOSAL
                    && plen >= 8
                    && wire::has_admin_magic(&s.msg_buf[..plen as usize])
                    && !s.flush_deferred
                    && s.last_log_index.saturating_sub(s.commit_index) < MAX_UNCOMMITTED_INFLIGHT
                {
                    if append_to_batch(s, sys, 0, plen as usize, 0, now) {
                        continue;
                    }
                }
                if frozen {
                    s.proposals_dropped_frozen = s.proposals_dropped_frozen.saturating_add(1);
                } else {
                    s.proposals_dropped_strict = s.proposals_dropped_strict.saturating_add(1);
                }
            }
        }
        return;
    }

    // Legacy / untagged proposals (in[1]). The whole payload is the body;
    // the correlation slot stays zero so flush_proposal_batch emits no
    // MSG_PROPOSAL_ASSIGNED for these.
    if s.in_proposals >= 0 {
        for _ in 0..16 {
            // Stop pulling proposals the moment either durability-backpressure
            // gate closes (RFC §13/§14): a deferred WAL flush, or the
            // uncommitted-inflight window reaching its cap. Checking inside the
            // loop (not just once per step) bounds the per-step append burst —
            // without it a single drain pass can append dozens of entries past
            // the cap before the next check, overrunning the observer fanout /
            // apply buffer and re-triggering the cliff.
            if s.flush_deferred
                || s.last_log_index.saturating_sub(s.commit_index) >= MAX_UNCOMMITTED_INFLIGHT
            {
                return;
            }
            let poll = (sys.channel_poll)(s.in_proposals, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_proposals, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }

            if !append_to_batch(s, sys, 0, plen as usize, 0, now) { break; }
        }
    }

    // Tagged proposals (in[4]). Strip the 8-byte correlation_id prefix and
    // store it in the parallel array so the batch flush can emit one
    // MSG_PROPOSAL_ASSIGNED per tagged proposal.
    if s.in_proposals_tagged >= 0 {
        for _ in 0..16 {
            if s.flush_deferred
                || s.last_log_index.saturating_sub(s.commit_index) >= MAX_UNCOMMITTED_INFLIGHT
            {
                return;
            }
            let poll = (sys.channel_poll)(s.in_proposals_tagged, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_proposals_tagged, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL { continue; }
            let plen = plen as usize;
            if plen < wire::TAGGED_PROPOSAL_HDR { continue; }

            let (correlation_id, body_off) = match wire::decode_tagged_proposal(&s.msg_buf[..plen]) {
                Some(v) => v,
                None => continue,
            };
            // correlation_id == 0 is reserved as "untagged"; if a producer
            // sends zero we still batch the body so the proposal isn't
            // lost, but no MSG_PROPOSAL_ASSIGNED will be emitted — same as
            // the legacy path.
            let body_len = plen - body_off;
            if !append_to_batch(s, sys, body_off, body_len, correlation_id, now) { break; }
        }
    }

    // Partitioned proposals (in[5]). 5-byte partitioned envelope from
    // the partition-routing path; payload is the bare proposal body. The
    // partition_id is asserted to match this instance's configured
    // slot — a mismatch means the graph wired the wrong output to
    // this raft.
    if s.in_proposals_partitioned >= 0 {
        for _ in 0..16 {
            if s.flush_deferred
                || s.last_log_index.saturating_sub(s.commit_index) >= MAX_UNCOMMITTED_INFLIGHT
            {
                return;
            }
            let poll = (sys.channel_poll)(s.in_proposals_partitioned, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (partition_id, msg_type, plen) =
                wire_channels::channel_read_partitioned(sys, s.in_proposals_partitioned, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }
            if partition_id != s.partition_id {
                // Misrouted proposal — skip rather than corrupt this
                // partition's log. The partition-routing contract is
                // "out[i] only ever carries partition_id = i".
                continue;
            }
            if !append_to_batch(s, sys, 0, plen as usize, 0, now) { break; }
        }
    }

    // Partitioned + tagged proposals (in[6]). 5-byte partitioned
    // envelope; payload is `[correlation_id:u64 LE][body]`. Same
    // misroute-rejection semantics as in[5].
    if s.in_proposals_partitioned_tagged >= 0 {
        for _ in 0..16 {
            if s.flush_deferred
                || s.last_log_index.saturating_sub(s.commit_index) >= MAX_UNCOMMITTED_INFLIGHT
            {
                return;
            }
            let poll = (sys.channel_poll)(s.in_proposals_partitioned_tagged, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (partition_id, msg_type, plen) = wire_channels::channel_read_partitioned(
                sys,
                s.in_proposals_partitioned_tagged,
                &mut s.msg_buf,
            );
            if msg_type != wire::MSG_CLIENT_PROPOSAL { continue; }
            let plen = plen as usize;
            if plen < wire::TAGGED_PROPOSAL_HDR { continue; }
            if partition_id != s.partition_id { continue; }

            let (correlation_id, body_off) =
                match wire::decode_tagged_proposal(&s.msg_buf[..plen]) {
                    Some(v) => v,
                    None => continue,
                };
            let body_len = plen - body_off;
            if !append_to_batch(s, sys, body_off, body_len, correlation_id, now) { break; }
        }
    }
}

/// Copy `&s.msg_buf[off..off+len]` into the proposal batch and record the
/// correlation_id in the parallel array. Flushes immediately once the
/// batch reaches `proposal_batch_max`, so the operator-configured cap
/// holds inside a single drain pass: two proposals drained back-to-back
/// past the cap would otherwise share a WAL index and collide in the
/// per-proposal `correlation_id → wal_index` mapping apply hands to the
/// codec. The time-based flush stays with `step_leader`'s `should_flush`.
///
/// Returns false only when the batch buffer is byte-full or the hard
/// `MAX_BATCH_PROPOSALS` slot cap is reached — callers stop draining and
/// let the next tick try again.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn append_to_batch(
    s: &mut Raft,
    sys: &SyscallTable,
    off: usize,
    len: usize,
    correlation_id: u64,
    now: u64,
) -> bool {
    if len == 0 { return true; }
    let space = PROPOSAL_BATCH_CAP - s.proposal_batch_len as usize;
    if len > space { return false; }
    let count = s.proposal_batch_count as usize;
    if count >= MAX_BATCH_PROPOSALS { return false; }

    let start = s.proposal_batch_len as usize;
    s.proposal_batch[start..start + len]
        .copy_from_slice(&s.msg_buf[off..off + len]);
    s.proposal_batch_len += len as u16;
    s.correlation_ids[count] = correlation_id;
    s.proposal_batch_count += 1;
    s.proposals_received += 1;
    // Acceptance signal — single choke point for all four proposal
    // ingress paths (untagged/tagged/partitioned/partitioned+tagged)
    // in `drain_proposals`. Fires once the proposal is genuinely
    // batched, not merely received off the channel. Debug level: this
    // is a per-proposal hot-path syscall (and a per-message UDP frame
    // on the bare-metal rig) — at info it throttles the very intake
    // path it instruments once rates pass a few hundred per second.
    dev_log(sys, 4, b"[raft] prop".as_ptr(), 11);

    if s.proposal_batch_count == 1 {
        s.proposal_batch_start_ms = now;
    }

    // Honour the count-based flush cap inside the drain pass.
    // `proposal_batch_max == 1` (the default; see the param table) makes
    // every proposal its own log index. Higher caps still batch up to
    // that limit, then flush so the next append starts a fresh entry.
    if s.proposal_batch_count >= s.proposal_batch_max {
        flush_proposal_batch(s, sys);
    }
    true
}

/// Append the freshly-elected leader's current-term no-op entry
/// (§5.4.2): a 16-byte term/index prologue with an empty body. Follows
/// `flush_proposal_batch`'s fail-closed WAL ordering — the log advance
/// happens only after the WAL accepts the entry — and ships the same
/// AE/observer fanout, so followers receive it like any other entry. On
/// success, latches the (term, first-index-of-term) fence for commit.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn append_noop(s: &mut Raft, sys: &SyscallTable) {
    let prev_log_index = s.last_log_index;
    let prev_log_term = if prev_log_index == 0 { 0 } else { s.last_log_term };
    let new_index = s.last_log_index + 1;

    let mut wal_buf = [0u8; 16];
    wire::encode_term_index(&mut wal_buf, s.current_term, new_index);
    let written =
        wire_channels::channel_write_msg(sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf);
    if written <= 0 {
        return; // WAL busy — `noop_pending` stays set, retry next tick
    }

    s.last_log_index = new_index;
    s.last_log_term = s.current_term;
    record_tail_term(s, new_index, s.current_term);

    // Observer fanout (E5) — drop-on-full, as flush_proposal_batch.
    let _ = s.outbox_bodies.push(wire::MSG_WAL_ENTRY, &wal_buf);

    // Replicator fanout (E1): empty-body AE at the new tip.
    {
        let mut ae_buf = [0u8; wire::AE_HDR_LEN];
        let total = wire::encode_append_entries(
            &mut ae_buf,
            s.current_term,
            s.self_id,
            prev_log_index,
            prev_log_term,
            s.commit_index,
            s.current_term,
            new_index,
            &[],
        );
        if total > 0 {
            let _ = s.outbox_ae.push(wire::MSG_APPEND_ENTRIES, &ae_buf[..total]);
        }
    }

    s.entries_appended += 1;
    s.commit_fence_out = Some((s.current_term, new_index));
    s.noop_pending = false;
    dev_log(sys, 3, b"[raft] noop".as_ptr(), 11);
}

/// Flush the coalesced proposal batch as one WAL entry, then fan it out
/// to the replicator (E1) and apply's observer ring (E5).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_proposal_batch(s: &mut Raft, sys: &SyscallTable) {
    if s.proposal_batch_count == 0 { return; }

    // ── Durability backpressure: fail closed (RFC §13/§14) ──────────
    // `last_log_index` must never advance past what the WAL accepts, so the
    // frame for the NEXT index is written FIRST and the index advance is
    // gated on that write. `channel_write_msg` is a single atomic frame
    // write (`wire_channels::write_framed`), so `<= 0` means the channel is
    // full and NOTHING was written — hold the batch and retry next tick.
    // `step_leader` suspends intake while `flush_deferred` is set, so the
    // proposals that would have filled this batch stay queued upstream
    // (proposer backpressure) rather than being dropped.
    let prev_log_index = s.last_log_index;
    let prev_log_term = if prev_log_index == 0 { 0 } else { s.last_log_term };
    let new_index = s.last_log_index + 1;
    let batch_len = s.proposal_batch_len as usize;

    let mut wal_buf = [0u8; PROPOSAL_BATCH_CAP + 16];
    wire::encode_term_index(&mut wal_buf, s.current_term, new_index);
    wal_buf[16..16 + batch_len].copy_from_slice(&s.proposal_batch[..batch_len]);

    let written = wire_channels::channel_write_msg(
        sys, s.out_log, wire::MSG_WAL_ENTRY, &wal_buf[..16 + batch_len],
    );
    if written <= 0 {
        if !s.flush_deferred {
            s.flush_deferred = true;
            s.flushes_deferred = s.flushes_deferred.saturating_add(1);
            dev_log(sys, 3, b"[raft] wal full".as_ptr(), 15);
        }
        return;
    }
    s.flush_deferred = false;

    // The WAL write landed — commit the log advance.
    s.last_log_index = new_index;
    s.last_log_term = s.current_term;
    record_tail_term(s, new_index, s.current_term);

    // Stamp the append time for this index so commit-advance can fold
    // its age into clustor.raft.commit_latency_ms (RFC §4.1).
    let ts_slot = (s.last_log_index as usize) % COMMIT_TS_RING;
    s.commit_ts_index[ts_slot] = s.last_log_index;
    s.commit_ts_us[ts_slot] = dev_micros(sys);

    // Fan out the same entry to observers (E5 seam).
    // Same 16-byte header + body; the apply component buffers them keyed
    // by index and emits per-entry committed messages once the commit
    // horizon advances.
    {
        // Fanout: drop silently if observer ring is full — the consumer
        // is non-load-bearing for consensus, so a stuck observer must
        // never block the WAL hot path. Observer consumers MUST cope with
        // gaps and recover via the per-entry sequence numbers.
        let _ = s.outbox_bodies.push(wire::MSG_WAL_ENTRY, &wal_buf[..16 + batch_len]);
    }

    // Send to replicator (E1 seam) using the
    // extended envelope with prev_log_{index,term} so followers can
    // verify log matching (RFC §5.1). The "prev" for this entry is the
    // index we held BEFORE this flush — `last_log_index - 1` and the
    // term we knew for that index. The leader has just bumped
    // `last_log_*`, so we recover them by subtracting the increment.
    {
        let mut ae_buf = [0u8; PROPOSAL_BATCH_CAP + wire::AE_HDR_LEN];
        let total = wire::encode_append_entries(
            &mut ae_buf,
            s.current_term,
            s.self_id,
            prev_log_index,
            prev_log_term,
            s.commit_index,
            s.current_term,
            new_index,
            &s.proposal_batch[..batch_len],
        );

        // Fire and forget: a full ring drops the frame whole — the
        // heartbeat / catch-up read-back paths re-cover a dropped AE.
        if total > 0 {
            let _ = s.outbox_ae.push(wire::MSG_APPEND_ENTRIES, &ae_buf[..total]);
        }
    }

    s.entries_appended += 1;
    // Metadata is deliberately NOT persisted here. Raft's durable state is
    // `currentTerm`/`votedFor` (persisted at the election/vote sites) plus
    // the log itself, which is the WAL; `last_log_index`/`last_log_term` are
    // derived from the log and reconstructed on recovery. A per-append
    // persist would also cost a synchronous FS round-trip inside the append
    // hot path, well past raft's step guard.
    // All proposals in this batch share the same wal_index. Emit one
    // MSG_PROPOSAL_ASSIGNED per tagged proposal so the proposer can bind
    // its correlation_id to the durable log index.
    emit_proposal_assignments(s, sys);

    // Reset batch
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_proposal_assignments(s: &mut Raft, sys: &SyscallTable) {
    if s.out_proposal_assigned < 0 { return; }
    let count = s.proposal_batch_count as usize;
    let assigned_index = s.last_log_index;
    let pid = s.partition_id;
    for i in 0..count {
        let cid = s.correlation_ids[i];
        s.correlation_ids[i] = 0;
        if cid == 0 { continue; }

        let poll = (sys.channel_poll)(s.out_proposal_assigned, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            // Channel full — drop the assignment. The proposer either
            // falls back to its own heuristic or treats this as a lost
            // correlation. Cannot block here.
            continue;
        }
        let mut buf = [0u8; wire::PROPOSAL_ASSIGNED_LEN];
        wire::encode_proposal_assigned(&mut buf, cid, pid, assigned_index);
        wire_channels::channel_write_msg(sys, s.out_proposal_assigned, wire::MSG_PROPOSAL_ASSIGNED, &buf);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn send_heartbeat(s: &Raft, sys: &SyscallTable) {
    // Heartbeats are AppendEntries with an empty body (entry_index = 0).
    // They double as log-matching probes: a follower whose tail
    // disagrees with prev_log_* rejects the AE, prompting the
    // replicator's conflict-repair retry to roll its next_index back.
    let mut hb = [0u8; wire::AE_HDR_LEN];
    let _ = wire::encode_append_entries(
        &mut hb,
        s.current_term,
        s.self_id,
        s.last_log_index,
        s.last_log_term,
        s.commit_index,
        0,
        0,
        &[],
    );

    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(
            sys,
            s.out_rpc,
            wire::TARGET_BROADCAST,
            s.partition_id,
            wire::MSG_APPEND_ENTRIES,
            &hb,
        );
    }
}

// ── Metadata persistence ────────────────────────────────────

/// Build the per-partition metadata path. Returns `(buf, len)`.
///   partition_id == 0 → "raft/meta"          (legacy single-partition)
///   partition_id == N → "raft/p<NNNN>/meta"  (multi-Raft)
fn build_meta_path(partition_id: u16) -> ([u8; META_PATH_MAX], usize) {
    build_meta_path_ex(partition_id, false)
}

/// Build the path of metadata slot `slot` (0/1). The two slots are
/// distinct files so that a failure in one cannot reach the other.
///   root mode: `RAFT<pppp>.M<slot>` (8.3-legal: 8-char stem, 2-char ext)
///   dir mode:  `raft/meta<slot>` / `raft/p<NNNN>/meta<slot>`
fn build_meta_slot_path(partition_id: u16, root: bool, slot: u8) -> ([u8; META_PATH_MAX], usize) {
    let (mut buf, mut len) = build_meta_path_ex(partition_id, root);
    let digit = b'0' + (slot & 1);
    if root {
        // Replace the ".MET" extension with ".M<slot>".
        len -= 2;
        buf[len] = digit;
        return (buf, len + 1);
    }
    buf[len] = digit;
    (buf, len + 1)
}

/// Metadata record contents, independent of the on-disk encoding.
#[derive(Clone, Copy)]
struct MetaRecord {
    generation: u64,
    term: Term,
    voted_for: i8,
    durable_index: Index,
    durable_term: Term,
    current_voters: u8,
    joint_voters: u8,
    joint_active: bool,
}

/// Encode a slot record into `buf` and seal it with its CRC.
fn encode_meta_slot(buf: &mut [u8; META_SLOT_SIZE], rec: &MetaRecord) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    buf[0..4].copy_from_slice(&META_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&META_FORMAT_ID.to_le_bytes());
    buf[8..16].copy_from_slice(&rec.generation.to_le_bytes());
    buf[16..24].copy_from_slice(&rec.term.to_le_bytes());
    buf[24] = rec.voted_for as u8;
    buf[25] = rec.current_voters;
    buf[26] = rec.joint_voters;
    buf[27] = rec.joint_active as u8;
    buf[28..36].copy_from_slice(&rec.durable_index.to_le_bytes());
    buf[36..44].copy_from_slice(&rec.durable_term.to_le_bytes());
    let mut crc = Crc32c::new();
    crc.update(&buf[..META_CRC_OFF]);
    let sum = crc.finalize();
    buf[META_CRC_OFF..META_SLOT_SIZE].copy_from_slice(&sum.to_le_bytes());
}

/// Decode a slot record. `None` for anything that is not a complete,
/// current-format, CRC-intact record — a torn write, a never-written
/// slot, and a foreign file are all indistinguishable and all refused.
fn decode_meta_slot(buf: &[u8]) -> Option<MetaRecord> {
    if buf.len() < META_SLOT_SIZE {
        return None;
    }
    if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != META_MAGIC {
        return None;
    }
    if u16::from_le_bytes([buf[4], buf[5]]) != META_FORMAT_ID {
        return None;
    }
    let mut crc = Crc32c::new();
    crc.update(&buf[..META_CRC_OFF]);
    let want = u32::from_le_bytes([
        buf[META_CRC_OFF],
        buf[META_CRC_OFF + 1],
        buf[META_CRC_OFF + 2],
        buf[META_CRC_OFF + 3],
    ]);
    if crc.finalize() != want {
        return None;
    }
    Some(MetaRecord {
        generation: u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]),
        term: u64::from_le_bytes([
            buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
        ]),
        voted_for: buf[24] as i8,
        current_voters: buf[25],
        joint_voters: buf[26],
        joint_active: buf[27] != 0,
        durable_index: u64::from_le_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]),
        durable_term: u64::from_le_bytes([
            buf[36], buf[37], buf[38], buf[39], buf[40], buf[41], buf[42], buf[43],
        ]),
    })
}

/// Build the metadata path. When `root` is set, emit a ROOT-level 8.3
/// name (`RAFT<pppp>.MET`, e.g. `RAFT0000.MET`) — FAT32 has no mkdir, so
/// the `raft/` parent of the default path can't be created. The 8-char
/// stem (`RAFT` + 4 hex partition digits) + 3-char extension is 8.3-legal.
fn build_meta_path_ex(partition_id: u16, root: bool) -> ([u8; META_PATH_MAX], usize) {
    let mut buf = [0u8; META_PATH_MAX];
    if root {
        let mut i = 0usize;
        for &b in b"RAFT" { buf[i] = b; i += 1; }
        for digit in (0..4).rev() {
            let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
            buf[i] = if nibble < 10 { b'0' + nibble } else { b'A' + nibble - 10 };
            i += 1;
        }
        for &b in b".MET" { buf[i] = b; i += 1; }
        return (buf, i);
    }
    if partition_id == 0 {
        let p = b"raft/meta";
        buf[..p.len()].copy_from_slice(p);
        return (buf, p.len());
    }
    // "raft/p" + 4 hex digits + "/meta"
    let prefix = b"raft/p";
    let mut i = 0usize;
    for &b in prefix { buf[i] = b; i += 1; }
    for digit in (0..4).rev() {
        let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        i += 1;
    }
    let suffix = b"/meta";
    for &b in suffix { buf[i] = b; i += 1; }
    (buf, i)
}

/// Load persistent Raft state from `raft/[p<id>/]meta`.
///
/// Returns `true` if the FS provider is still initialising (FS_OPEN returned
/// E_AGAIN) and the caller must RETRY on a later step: at cold boot the fat32
/// provider isn't ready when `module_new` runs, and a one-shot load would
/// miss the metadata and restart the node fresh. Returns `false` once the
/// load resolves (loaded, or the file genuinely doesn't exist = fresh
/// deploy).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn load_metadata(s: &mut Raft, sys: &SyscallTable) -> bool {
    s.meta_fs_step = true;
    let root = s.meta_root_path != 0;

    // Read both slots and keep the highest generation that validates.
    // A slot that is missing, short, torn, or foreign simply does not
    // compete — recovery never adopts an unverified record.
    // Generation 0 is never written, so it is a safe "nothing yet" floor.
    let mut best: Option<(u8, MetaRecord)> = None;
    let mut best_gen: u64 = 0;
    let mut retry = false;
    for slot in 0..META_SLOTS as u8 {
        let (mut path, plen) = build_meta_slot_path(s.partition_id, root, slot);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if fd == FS_E_AGAIN {
            retry = true;
            continue;
        }
        if fd < 0 {
            continue;
        }
        let mut buf = [0u8; META_SLOT_SIZE];
        let n = (sys.provider_call)(fd, FS_READ, buf.as_mut_ptr(), META_SLOT_SIZE);
        (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
        if n != META_SLOT_SIZE as i32 {
            continue;
        }
        if let Some(rec) = decode_meta_slot(&buf) {
            if rec.generation > best_gen {
                best_gen = rec.generation;
                best = Some((slot, rec));
            }
        }
    }
    // One inconclusive slot is enough to defer the whole load: the slot
    // that did not answer may hold the HIGHER generation, and resolving on
    // the other one would adopt an older term and vote — a node that
    // re-votes in a term it has already voted in.
    if retry {
        return true; // FS provider initialising — retry later
    }

    let rec = match best {
        Some((slot, rec)) => {
            s.meta_slot = slot;
            s.meta_generation = rec.generation;
            rec
        }
        None => match load_flat_metadata(s, sys, root) {
            FlatLoad::Retry => return true,
            FlatLoad::None => return false,
            FlatLoad::Record(rec) => rec,
        },
    };

    {
        let term = rec.term;
        let voted = rec.voted_for;
        let log_idx = rec.durable_index;
        let log_term = rec.durable_term;
        if term > 0 {
            s.current_term = term;
            s.voted_for = voted;
            // `log_idx` is the persisted DURABLE watermark (see save_metadata),
            // paired with the term of the entry AT that index.
            // Seed both the log index and the durable index from it so a
            // recovered node resumes at the on-disk durable point and replay
            // re-acks from there rather than re-proposing into a fresh space.
            s.last_log_index = log_idx;
            s.last_log_term = log_term;
            s.local_durable_index = log_idx;
            s.local_durable_term = log_term;
            s.meta_persisted_durable = log_idx;
            s.meta_hint_loaded = log_idx;
            // Recovery seeding. The persisted `log_idx` is only a THROTTLED
            // durable hint (META_PERSIST_STRIDE) that can lag — or, after a
            // crash that lost un-replayable tail entries, over-count — the
            // WAL's true replayed high-water. So when the dedicated
            // `wal_replay_complete` edge is wired, the intake hold is already
            // armed (in arm) and the WAL's high-water drives the
            // resume + apply-reset — we do NOTHING here. Only the legacy
            // graph (no edge) falls back to seeding apply from the
            // (stale) hint via the recovery-reset path.
            if log_idx > 0 && s.in_wal_replay_complete < 0 {
                s.pending_recovery_reset = true;
            }
            dev_log(sys, 3, b"[raft] meta ok".as_ptr(), 14);
        }
        // Joint-consensus fields (RFC §1.2). A zero `current_voters`
        // is NOT a valid persisted set — it is a record whose voter
        // bytes were never written — and adopting it would leave every
        // quorum test (elections, ReadIndex, commit) permanently
        // unsatisfiable. Keep the `voter_count` defaults seeded in
        // `arm` in that case.
        if rec.current_voters != 0 {
            s.current_voters = NodeSet(rec.current_voters);
            s.joint_voters = NodeSet(rec.joint_voters);
            s.joint_active = rec.joint_active;
        }
    }
    false // resolved (loaded or empty) — no retry needed
}

/// Outcome of the flat-record read.
enum FlatLoad {
    /// FS provider still initialising — the caller retries on a later step.
    Retry,
    /// No flat record: a fresh deploy, or a store already holding
    /// slot records.
    None,
    Record(MetaRecord),
}

/// Read a flat record. Called only when neither slot validates, so a
/// store holding this shape yields its term and vote instead of the
/// node starting fresh.
///
/// The record's log fields pair a durable index with the volatile tip
/// term, so they do not describe one entry and no claim about the log
/// can rest on them: the returned record carries a zero log position and
/// the WAL's replayed high-water is the only thing that resumes the tip.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn load_flat_metadata(s: &mut Raft, sys: &SyscallTable, root: bool) -> FlatLoad {
    let (mut path, plen) = build_meta_path_ex(s.partition_id, root);
    let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
    if fd == FS_E_AGAIN {
        return FlatLoad::Retry;
    }
    if fd < 0 {
        return FlatLoad::None;
    }
    let mut buf = [0u8; META_FLAT_SIZE];
    let n = (sys.provider_call)(fd, FS_READ, buf.as_mut_ptr(), META_FLAT_SIZE);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    // Compared as a SIGNED count: a provider still initialising answers
    // E_AGAIN here as well as at the open, and every other negative return
    // is a failed read, not a record. Widening either to `usize` first
    // turns them into a huge length that passes the floor and hands the
    // caller a zeroed buffer as persisted state.
    if n == FS_E_AGAIN {
        return FlatLoad::Retry;
    }
    // The flat shape has exactly two defined lengths: 25 bytes without
    // the voter-set trailer, or the full 28 with it. Nothing checksums
    // this record, so a length the format never writes is not a record
    // to interpret — it is the residue of a write that failed partway,
    // and its term and vote may be ones the writer went on to refuse.
    // Refuse the whole thing rather than adopt fields that happen to
    // look complete.
    if n != META_FLAT_MIN as i32 && n != META_FLAT_SIZE as i32 {
        if n > 0 {
            dev_log(sys, 2, b"[raft] meta flat partial".as_ptr(), 24);
        }
        return FlatLoad::None;
    }
    let has_voters = n == META_FLAT_SIZE as i32 && buf[25] != 0;
    dev_log(sys, 3, b"[raft] meta flat".as_ptr(), 16);
    FlatLoad::Record(MetaRecord {
        generation: 0,
        term: u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]),
        voted_for: buf[8] as i8,
        durable_index: 0,
        durable_term: 0,
        current_voters: if has_voters { buf[25] } else { 0 },
        joint_voters: if has_voters { buf[26] } else { 0 },
        joint_active: has_voters && buf[27] != 0,
    })
}

/// Hard-failure accounting for a metadata persist: counter, one-shot
/// log, fd invalidation (so the next attempt reopens), and the
/// error-side backoff consulted by the throttled durable-hint save.
///
/// Invalidating the fd also re-arms `materialize_meta_slots`, which
/// owns the only open path: the next attempt runs it again, reopens
/// what was closed, finds the file already at full size and leaves its
/// record untouched. Leaving the flag set would strand the persist on a
/// closed descriptor for good.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn mark_meta_failure(s: &mut Raft, sys: &SyscallTable, slot: u8) -> PersistOutcome {
    let idx = (slot & 1) as usize;
    if s.meta_fds[idx] >= 0 {
        (sys.provider_call)(s.meta_fds[idx], FS_CLOSE, core::ptr::null_mut(), 0);
        s.meta_fds[idx] = -1;
    }
    s.meta_slots_materialized = false;
    s.meta_write_errors = s.meta_write_errors.saturating_add(1);
    s.meta_backoff_steps = 200;
    if !s.meta_fail_logged {
        s.meta_fail_logged = true;
        dev_log(sys, 1, b"[raft] meta write fail".as_ptr(), 22);
    }
    PersistOutcome::Failed
}

/// One-shot dir-mode self-heal: create the `raft/` parent chain (and
/// the per-partition subdirectory) via FS_MKDIR. Single-level and
/// EEXIST-idempotent on the linux provider; bare-metal FAT32 answers a
/// clean ENOSYS, but root-path mode never reaches here anyway.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn meta_mkdir_parents(s: &mut Raft, sys: &SyscallTable) {
    let mut root = [0u8; 4];
    root[..4].copy_from_slice(b"raft");
    let _ = (sys.provider_call)(-1, FS_MKDIR, root.as_mut_ptr(), 4);
    if s.partition_id != 0 {
        // "raft/p<NNNN>" — the parent of the per-partition meta file.
        let (mut path, plen) = build_meta_path(s.partition_id);
        // Strip the trailing "/meta" (5 bytes) to get the directory.
        let dir_len = plen - 5;
        let _ = (sys.provider_call)(-1, FS_MKDIR, path.as_mut_ptr(), dir_len);
    }
    dev_log(sys, 3, b"[raft] mkdir raft".as_ptr(), 17);
}

/// Fill `name_fence_probe` from the provider's capability word (once
/// per boot; a provider that cannot answer the probe stays unprobed and
/// is treated as lacking the capability).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn probe_name_fence(s: &mut Raft, sys: &SyscallTable) {
    if s.name_fence_probe != NAME_FENCE_UNPROBED {
        return;
    }
    let mut caps = [0u8; 4];
    if (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4) == 4 {
        let bits = u32::from_le_bytes(caps);
        s.name_fence_probe = if bits & FS_CAP_FSYNC_NAME != 0 {
            NAME_FENCE_PRESENT
        } else {
            NAME_FENCE_ABSENT
        };
    }
}

/// True when a slot name may be minted under the current posture.
/// Strict on a provider with no `caps::FSYNC_NAME` answers false, and
/// the caller refuses BEFORE the open: a persist that fails at the
/// fence has already fsynced a record carrying a generation and a vote
/// this node never adopted, which the next boot would then recover.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn name_fence_permits_create(s: &mut Raft, sys: &SyscallTable) -> bool {
    probe_name_fence(s, sys);
    if s.name_fence_probe == NAME_FENCE_PRESENT || s.name_fence != NAME_FENCE_STRICT {
        return true;
    }
    if !s.name_fence_logged {
        s.name_fence_logged = true;
        dev_log(sys, 2, b"[raft] no name fence".as_ptr(), 20);
    }
    false
}

/// Publish the parent-directory entry naming a metadata slot.
///
/// `FS_FSYNC` on the slot's descriptor covers its 64 bytes; it does not
/// make the name durable, and a slot whose name is lost is a node that
/// boots with no term and no vote — the exact state the two-generation
/// layout exists to prevent. The fence is therefore part of creating
/// the slot, not a tidy-up after it.
///
/// Returns `true` when the name may be treated as durable. A provider
/// without `caps::FSYNC_NAME` cannot prove that: the strict posture
/// refuses (the persist fails, and the caller withholds the vote or
/// election that gated on it), while the auto posture proceeds and
/// leaves the disposition visible in `RAFT_NAME_FENCE`.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn publish_meta_name(
    s: &mut Raft,
    sys: &SyscallTable,
    path: &mut [u8],
    plen: usize,
) -> bool {
    if !name_fence_permits_create(s, sys) {
        return false;
    }
    if s.name_fence_probe != NAME_FENCE_PRESENT {
        // Auto posture: the name goes out unfenced, and saying so is the
        // whole of what this posture offers over strict.
        s.name_unfenced = s.name_unfenced.saturating_add(1);
        return true;
    }
    let rc = (sys.provider_call)(-1, FS_FSYNC_NAME, path.as_mut_ptr(), plen);
    if rc == 0 {
        return true;
    }
    // The provider advertised the capability and then failed the call:
    // a real fault in the store, not a posture the operator chose.
    if !s.name_fence_fail_logged {
        s.name_fence_fail_logged = true;
        dev_log(sys, 1, b"[raft] name fence FAIL".as_ptr(), 22);
    }
    false
}

/// Bring BOTH slot files into existence, at full size, with both names
/// fenced — before any non-neutral generation is adopted.
///
/// ## Why this is not the same as creating each slot when it is first
/// written
///
/// Two files make the RECORDS independent: a persist rewrites one
/// file's data and a torn sector there reaches that slot alone. It does
/// not make the NAMES independent. On FAT32 a directory entry is 32
/// bytes inside a 512-byte directory sector, and two entries in one
/// directory routinely share a sector — so adding the second name is a
/// mutation of a sector the first name already lives in.
///
/// Creating lazily puts that mutation in the worst possible place. Slot
/// A is created and adopted at the first persist; slot B's name is
/// minted at the SECOND persist — by which time generation 1 is
/// adopted, durable, and the only thing recovery has. A node
/// interrupted there can lose both names together and come back with no
/// metadata at all, having previously reported a vote as durable.
///
/// Doing it here moves the whole namespace mutation to a point where
/// there is provably nothing to lose: no generation has been adopted,
/// so an interruption costs a node that had not yet voted. From the
/// first adopted generation onward the directory is never touched
/// again — each persist seeks to 0 and overwrites `META_SLOT_SIZE`
/// bytes in a file that already has that size and that cluster chain.
///
/// The neutral record written into a fresh slot is all zeroes: the
/// magic check in `decode_meta_slot` rejects it, so a slot in this
/// state is "nothing yet" to recovery rather than a competing record.
/// An existing slot is READ first and left alone if it is already full
/// size — an upgrading node must not have its recovered state zeroed.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn materialize_meta_slots(s: &mut Raft, sys: &SyscallTable) -> PersistOutcome {
    if s.meta_slots_materialized {
        return PersistOutcome::Persisted;
    }
    for slot in 0..META_SLOTS as u8 {
        let idx = slot as usize;
        // Same refusal as the persist path, for the same reason: under
        // the strict posture a name that cannot be fenced is never
        // minted, and the refusal comes before any FS work.
        if !s.meta_name_published[idx] && !name_fence_permits_create(s, sys) {
            return mark_meta_failure(s, sys, slot);
        }
        if s.meta_fds[idx] < 0 {
            let (mut path, plen) =
                build_meta_slot_path(s.partition_id, s.meta_root_path != 0, slot);
            let mut opened = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
            if opened == FS_E_AGAIN {
                return PersistOutcome::Transient; // provider initialising
            }
            if opened < 0 && s.meta_root_path == 0 && !s.meta_mkdir_attempted {
                s.meta_mkdir_attempted = true;
                meta_mkdir_parents(s, sys);
                opened = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
                if opened == FS_E_AGAIN {
                    return PersistOutcome::Transient;
                }
            }
            if opened < 0 {
                return mark_meta_failure(s, sys, slot);
            }
            s.meta_fds[idx] = opened;
        }
        let fd = s.meta_fds[idx];

        // Size it, but only if it is not already sized. A short read is
        // the test: a file this node created a moment ago reads 0, one
        // written by a previous boot reads META_SLOT_SIZE and keeps
        // whatever record it holds.
        let zero = 0i32.to_le_bytes();
        if (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4) < 0 {
            return mark_meta_failure(s, sys, slot);
        }
        let mut probe = [0u8; META_SLOT_SIZE];
        let have = (sys.provider_call)(fd, FS_READ, probe.as_mut_ptr(), META_SLOT_SIZE);
        if have != META_SLOT_SIZE as i32 {
            if (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4) < 0 {
                return mark_meta_failure(s, sys, slot);
            }
            let mut neutral = [0u8; META_SLOT_SIZE];
            if (sys.provider_call)(fd, FS_WRITE, neutral.as_mut_ptr(), META_SLOT_SIZE)
                != META_SLOT_SIZE as i32
            {
                return mark_meta_failure(s, sys, slot);
            }
            if (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) < 0 {
                return mark_meta_failure(s, sys, slot);
            }
        }

        // Fence the name now — the point of the exercise is that the
        // directory is settled before anything depends on it.
        if !s.meta_name_published[idx] {
            let (mut path, plen) =
                build_meta_slot_path(s.partition_id, s.meta_root_path != 0, slot);
            if !publish_meta_name(s, sys, &mut path, plen) {
                return mark_meta_failure(s, sys, slot);
            }
            s.meta_name_published[idx] = true;
        }
    }
    s.meta_slots_materialized = true;
    PersistOutcome::Persisted
}

/// Persist the Raft metadata record with an EXPLICIT `(term, voted_for)`
/// pair — the write-then-adopt primitive. Voting-relevant callers
/// persist the prospective record first and mutate in-memory state only
/// on `Persisted`; there is no rollback logic anywhere because nothing
/// is adopted before the record is durable.
///
/// The persisted `last_log_index` slot carries the DURABLE watermark
/// (`local_durable_index`), not the volatile appended index, so a
/// recovered node never claims durability it didn't have on disk.
///
/// In the `persist_meta: 0` posture this is a no-op returning
/// `Persisted`: nothing is supposed to persist, and the posture's own
/// safety mitigations (hold-off, term floor) live at the grant sites.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn persist_meta_record(
    s: &mut Raft,
    sys: &SyscallTable,
    term: Term,
    voted_for: i8,
) -> PersistOutcome {
    if s.persist_meta == 0 {
        return PersistOutcome::Persisted;
    }
    s.meta_fs_step = true;
    // Both names and both file sizes are settled before the first
    // adopted generation, so from here on the directory is never
    // touched again — see `materialize_meta_slots`. The fds it opened
    // are cached, so each persist is just seek+write+fsync with no cold
    // dir-scan re-open.
    match materialize_meta_slots(s, sys) {
        PersistOutcome::Persisted => {}
        other => return other,
    }
    // Target the INACTIVE slot. The active slot — the one recovery
    // would choose today — is never touched, so a failure anywhere
    // between here and the fsync leaves it whole and readable.
    let slot = 1 - (s.meta_slot & 1);
    let idx = slot as usize;
    let fd = s.meta_fds[idx];

    // Seek to start (overwrite)
    let zero = 0i32.to_le_bytes();
    if (sys.provider_call)(fd, FS_SEEK, zero.as_ptr() as *mut u8, 4) < 0 {
        return mark_meta_failure(s, sys, slot);
    }

    let durable = s.local_durable_index;
    let generation = s.meta_generation.wrapping_add(1);
    let mut buf = [0u8; META_SLOT_SIZE];
    encode_meta_slot(
        &mut buf,
        &MetaRecord {
            generation,
            term,
            voted_for,
            durable_index: durable,
            // Paired with the durable index by the WAL's own ack — NOT
            // `last_log_term`, which describes the volatile tip.
            durable_term: s.local_durable_term,
            current_voters: s.current_voters.0,
            joint_voters: s.joint_voters.0,
            joint_active: s.joint_active,
        },
    );
    if (sys.provider_call)(fd, FS_WRITE, buf.as_mut_ptr(), META_SLOT_SIZE) != META_SLOT_SIZE as i32
    {
        return mark_meta_failure(s, sys, slot);
    }
    if (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) < 0 {
        return mark_meta_failure(s, sys, slot);
    }

    // Read the slot back and compare it byte for byte before adopting
    // the new generation. The read goes through the same descriptor and
    // may well be served from the provider's cache, so it proves the
    // bytes reached the provider whole — a short or partial write is
    // caught here — while the FSYNC above is what carries them to media.
    let seek = 0i32.to_le_bytes();
    if (sys.provider_call)(fd, FS_SEEK, seek.as_ptr() as *mut u8, 4) < 0 {
        return mark_meta_failure(s, sys, slot);
    }
    let mut check = [0u8; META_SLOT_SIZE];
    if (sys.provider_call)(fd, FS_READ, check.as_mut_ptr(), META_SLOT_SIZE) != META_SLOT_SIZE as i32
    {
        return mark_meta_failure(s, sys, slot);
    }
    if check != buf {
        return mark_meta_failure(s, sys, slot);
    }

    // The name was fenced at materialisation, before anything was
    // adopted. Kept as a guard rather than deleted: if a future change
    // ever reaches this point with an unpublished name, the record must
    // not be adopted under a directory entry that may not survive.
    if !s.meta_name_published[idx] {
        return mark_meta_failure(s, sys, slot);
    }

    // Adopt: from here recovery chooses this slot.
    s.meta_slot = slot;
    s.meta_generation = generation;
    s.meta_persisted_durable = durable;
    PersistOutcome::Persisted
}

/// Persist the CURRENT in-memory `(term, voted_for)` — for call sites
/// where the record content is already adopted (durable-hint advance,
/// voter-set changes, snapshot fast-forward, higher-term adoption's
/// liveness exception). Failures are counted inside; callers that must
/// gate externally visible effects use `persist_meta_record` directly.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn save_metadata(s: &mut Raft, sys: &SyscallTable) -> PersistOutcome {
    let term = s.current_term;
    let voted = s.voted_for;
    persist_meta_record(s, sys, term, voted)
}

// ── State transitions ───────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn become_follower(s: &mut Raft, sys: &SyscallTable, term: Term) {
    become_follower_mem(s, term);
    // Liveness exception to write-then-adopt: refusing to observe a
    // higher term would wedge the cluster, so the adoption stands even
    // if the persist fails (counted inside). Safety holds because the
    // `(term, voted_for)` record is atomic and both voting sites gate
    // on their own persist — an unpersisted term can never pair with a
    // persisted vote at that term.
    save_metadata(s, sys);
}

/// In-memory follower transition: term adoption, vote clear, candidacy
/// and batch state reset — with NO metadata write. Callers that need
/// the record persisted do it themselves (`become_follower` for the
/// adopt-then-count liveness path; `handle_vote_request` folds the
/// adoption into its single grant-gated persist).
fn become_follower_mem(s: &mut Raft, term: Term) {
    s.current_term = term;
    s.role = ROLE_FOLLOWER;
    s.voted_for = REPLICA_NONE as i8;
    s.votes_granted.clear();
    s.votes_rejected.clear();
    s.pre_vote_active = false;
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
    // `flush_deferred` means "holding a batch the WAL refused", and the only
    // code that clears it sits past `flush_proposal_batch`'s `count == 0`
    // early return. Left set over a discarded batch it suspends intake
    // permanently, so it must be cleared with the batch it describes.
    s.flush_deferred = false;
    // Drop any pending correlation ids — proposals from a prior term are
    // discarded, so the proposer will time out and retry.
    for i in 0..MAX_BATCH_PROPOSALS { s.correlation_ids[i] = 0; }
}

/// Same-term step-down (a candidate observing the term's elected
/// leader). The vote belongs to the TERM and is kept; the persisted
/// `(term, vote)` record is therefore UNCHANGED and no metadata write
/// happens. Clearing the vote here and restoring it in a second write
/// would leave a window whose crash erases a granted vote from disk,
/// and the restarted node could then vote twice in one term.
fn step_down_same_term(s: &mut Raft) {
    let voted = s.voted_for;
    let term = s.current_term;
    become_follower_mem(s, term);
    s.voted_for = voted;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn become_leader(s: &mut Raft, sys: &SyscallTable, now: u64) {
    // Unreachable while `start_election` holds — candidacy cannot begin
    // during replay — and checked anyway, because this is the step that
    // makes an understated log authoritative for the whole cluster. A
    // future path to office that forgets the hold fails closed here
    // instead of taking office on a tip this node has not recovered.
    if replay_hold(s) {
        return;
    }
    s.role = ROLE_LEADER;
    s.leader_id = s.self_id as i8;
    s.votes_granted.clear();
    s.votes_rejected.clear();
    s.pre_vote_active = false;
    s.last_heartbeat_ms = now;
    s.proposal_batch_len = 0;
    s.proposal_batch_count = 0;
    // See `become_follower`: the discarded batch takes its deferral flag with
    // it, or leadership starts with intake permanently suspended.
    s.flush_deferred = false;
    for i in 0..MAX_BATCH_PROPOSALS { s.correlation_ids[i] = 0; }

    dev_log(sys, 3, b"[raft] leader".as_ptr(), 13);

    // Owe the log a current-term no-op (Raft §5.4.2): committing it is
    // the only safe way prior-term entries become committed.
    //
    // Arm the commit fence NOW, index unknown (0), so nothing commits by
    // counting between taking office and the no-op landing; `append_noop`
    // resolves it to the real index. Only with `out_log` wired: a graph
    // with no WAL edge can never land the no-op, so arming there would
    // block commit forever.
    s.noop_pending = true;
    if s.out_log >= 0 {
        s.commit_fence_out = Some((s.current_term, 0));
    }

    // Send immediate heartbeat to assert leadership
    send_heartbeat(s, sys);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn start_election(s: &mut Raft, sys: &SyscallTable, now: u64, pre_vote: bool) {
    // No candidacy on a tip this node has already agreed to discard:
    // the vote request would advertise a log the WAL is in the middle
    // of shortening, and winning on it is how a stale suffix becomes
    // the cluster's. Applies to pre-votes too — a pre-vote won on that
    // tip converts straight into the real election.
    if s.truncate_pending {
        s.election_deadline_ms = now + s.election_timeout_ms as u64;
        return;
    }
    // No candidacy on a tip we have not yet recovered. See
    // `replay_hold`: the vote request would advertise the persisted
    // hint, which is at or below our real tip, and an election won on
    // an understated log is how this node's own committed tail gets
    // overwritten by the leader it just elected.
    //
    // Gated here rather than only at the timeout site so it also covers
    // the pre-vote→real conversion, the single-node fast path below,
    // and a TimeoutNow-driven start. The deadline re-arms; the WAL
    // answers in milliseconds and the next timeout proceeds normally.
    if replay_hold(s) {
        s.election_deadline_ms = now + s.election_timeout_ms as u64;
        return;
    }
    if !pre_vote {
        // Volatile posture: no REAL elections inside the boot hold-off.
        // Gated here — not just at the timeout site — so the
        // pre-vote→real conversion and the single-node fast path are
        // covered too. The deadline re-arms; the node retries after
        // the window.
        if s.persist_meta == 0 && now < s.holdoff_until_ms {
            s.election_deadline_ms = s.holdoff_until_ms + s.election_timeout_ms as u64;
            return;
        }
        // Write-then-adopt: persist the prospective `(term+1, self)`
        // self-vote FIRST; only on success bump the in-memory term and
        // take candidacy. On failure nothing changed — no term
        // inflation leaks through response terms to depose healthy
        // leaders — and the re-armed deadline retries later.
        let prospective = s.current_term + 1;
        let self_vote = s.self_id as i8;
        match persist_meta_record(s, sys, prospective, self_vote) {
            PersistOutcome::Persisted => {
                s.current_term = prospective;
                s.voted_for = self_vote;
            }
            _ => {
                s.election_deadline_ms = now + s.election_timeout_ms as u64;
                return;
            }
        }
    }
    s.pre_vote_active = pre_vote;

    s.role = ROLE_CANDIDATE;
    s.votes_granted = NodeSet::empty();
    s.votes_rejected = NodeSet::empty();
    s.votes_granted.insert(s.self_id); // vote for self
    s.elections_started += 1;

    // Randomize election timeout with jitter
    let mut seed = (now as u32) ^ ((s.self_id as u32) << 16) ^ 0xCAFE;
    let half_timeout = (s.election_timeout_ms as u32 / 2).max(1);
    let jitter = (xorshift32(&mut seed) & (half_timeout.next_power_of_two() - 1)) as u64;
    s.election_deadline_ms = now + s.election_timeout_ms as u64 + jitter;

    // Check for single-node cluster: already have quorum
    if set_majority(s.votes_granted, s.current_voters, s.joint_voters, s.joint_active) {
        if pre_vote {
            start_election(s, sys, now, false);
        } else {
            become_leader(s, sys, now);
        }
        return;
    }

    // Send vote requests to all peers via routed broadcast
    let msg_type = if pre_vote { wire::MSG_PRE_VOTE } else { wire::MSG_REQUEST_VOTE };
    let mut req = [0u8; 25];
    let req_term = if pre_vote { s.current_term + 1 } else { s.current_term };
    wire::encode_vote_request(&mut req, req_term, s.self_id, s.last_log_index, s.last_log_term);

    let poll = (sys.channel_poll)(s.out_rpc, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_routed_partitioned(sys, s.out_rpc, wire::TARGET_BROADCAST, s.partition_id, msg_type, &req[..25]);
    }

    dev_log(sys, 3, b"[raft] elect".as_ptr(), 12);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reset_election_deadline(s: &mut Raft, now: u64) {
    // Fold self_id into the seed: co-timed followers (heartbeat-
    // synchronised deadlines) must not draw correlated jitter, or a
    // leader loss degenerates into repeated split votes.
    let mut seed = (now as u32) ^ ((s.self_id as u32) << 16) ^ 0xBEEF;
    let half_timeout2 = (s.election_timeout_ms as u32 / 2).max(1);
    let jitter = (xorshift32(&mut seed) & (half_timeout2.next_power_of_two() - 1)) as u64;
    s.election_deadline_ms = now + s.election_timeout_ms as u64 + jitter;
}

// ── Fallback signal ─────────────────────────────────────────

/// Deliver one MSG_FALLBACK_SIGNAL frame from the shared `cp_state`
/// fan-in (dispatch-table demux). Sets `strict_fallback` from the
/// byte.
pub fn on_fallback(s: &mut Raft, msg: &[u8], plen: u16) {
    if plen >= 1 {
        s.strict_fallback = msg[0] != 0;
    }
}

// ── Metrics ─────────────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut Raft` (or shared
/// `&Raft` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_metrics(s: &mut Raft, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < 1000 { return; }
    s.last_metrics_ms = now;

    // Typed metric samples (RFC §4.3). Replaces the prior packed-into-
    // one-envelope shape so the telemetry component can aggregate without
    // a module-specific parser. Each metric goes out as its own
    // `MSG_METRIC_SAMPLE`; the legacy `MSG_METRICS` envelope is still
    // sent at the end for tools that haven't migrated yet, so this
    // is fully backwards-compatible.
    let mod_id = wire::SOURCE_ID_RAFT;
    let pid = s.partition_id;
    let kg = wire::METRIC_KIND_GAUGE;
    let kc = wire::METRIC_KIND_COUNTER;
    // Readiness sub-signal (RFC: real /readyz): boot replay done, metadata
    // loaded, and consensus established (we lead, or we know the leader).
    // A node holding an unacknowledged truncation NACKs every
    // AppendEntries, so it is not carrying replication and must not
    // advertise that it is.
    let raft_ready = (!s.awaiting_replay
        && !s.meta_load_pending
        && !s.truncate_pending
        && (s.role == ROLE_LEADER || s.leader_id >= 0)) as i64;
    let samples: [(u16, u8, i64); 26] = [
        // RAFT_READY leads the array: the emit loop stops at a full
        // metrics channel, so readiness must be the last casualty under
        // backpressure, not the first.
        (wire::metric_ids::RAFT_READY, kg, raft_ready),
        (wire::metric_ids::RAFT_LAST_LOG_INDEX, kg, s.last_log_index as i64),
        (wire::metric_ids::RAFT_COMMIT_INDEX, kg, s.commit_index as i64),
        (wire::metric_ids::RAFT_ROLE, kg, s.role as i64),
        (wire::metric_ids::RAFT_CURRENT_TERM, kg, s.current_term as i64),
        (wire::metric_ids::RAFT_PROPOSALS_RECEIVED, kc, s.proposals_received as i64),
        (wire::metric_ids::RAFT_ENTRIES_APPENDED, kc, s.entries_appended as i64),
        (wire::metric_ids::RAFT_ELECTIONS_STARTED, kc, s.elections_started as i64),
        (wire::metric_ids::RAFT_PROPOSALS_DROPPED_FROZEN, kc, s.proposals_dropped_frozen as i64),
        (wire::metric_ids::RAFT_PROPOSALS_DROPPED_STRICT, kc, s.proposals_dropped_strict as i64),
        (wire::metric_ids::RAFT_FROZEN_FLAG, kg, s.frozen as i64),
        (wire::metric_ids::RAFT_STRICT_FALLBACK_FLAG, kg, s.strict_fallback as i64),
        (wire::metric_ids::RAFT_FLUSHES_DEFERRED, kc, s.flushes_deferred as i64),
        (
            wire::metric_ids::RAFT_UNCOMMITTED_INFLIGHT,
            kg,
            s.last_log_index.saturating_sub(s.commit_index) as i64,
        ),
        (wire::metric_ids::RAFT_AWAITING_REPLAY, kg, s.awaiting_replay as i64),
        (wire::metric_ids::RAFT_REPLAY_HW, kg, s.replay_hw_received as i64),
        (wire::metric_ids::RAFT_META_HINT, kg, s.meta_hint_loaded as i64),
        (wire::metric_ids::RAFT_LOG_TRUNCATIONS, kc, s.log_truncations as i64),
        (wire::metric_ids::RAFT_WAL_RESYNCS, kc, s.wal_resyncs as i64),
        (wire::metric_ids::RAFT_WAL_UNACKED_HOLDS, kc, s.wal_unacked_holds as i64),
        (wire::metric_ids::RAFT_AE_NONCONTIGUOUS, kc, s.ae_noncontiguous as i64),
        (wire::metric_ids::RAFT_META_WRITE_ERRORS, kc, s.meta_write_errors as i64),
        (wire::metric_ids::RAFT_NAME_FENCE, kg, i64::from(s.name_fence_probe)),
        (wire::metric_ids::RAFT_NAME_UNFENCED, kc, s.name_unfenced as i64),
        (wire::metric_ids::RAFT_TRUNCATE_HOLDS, kc, s.truncate_holds as i64),
        (wire::metric_ids::RAFT_TRUNCATE_NACKS, kc, s.truncate_nacks as i64),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mod_id, pid, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }

    // commit_latency_ms histogram buckets (RFC §4.1), kind=histogram.
    // Cumulative per the wire contract (wire::hist): bucket i carries the
    // count of samples <= bound[i], so emit the running prefix sum.
    let base = wire::hist::HIST_BASE;
    let mut cum: i64 = 0;
    for i in 0..s.commit_latency_buckets.len() {
        cum += i64::from(s.commit_latency_buckets[i]);
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mod_id, pid, base + i as u16, wire::METRIC_KIND_HISTOGRAM, cum);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }

    // Legacy MSG_METRICS shape — still emitted so observers that parse
    // it (test scaffolding, the e2e harness) keep working. Same byte
    // layout per RFC §4.3.
    let mut buf = [0u8; 30];
    buf[0] = s.role;
    buf[1..9].copy_from_slice(&s.current_term.to_le_bytes());
    buf[9..13].copy_from_slice(&s.proposals_received.to_le_bytes());
    buf[13..17].copy_from_slice(&s.entries_appended.to_le_bytes());
    buf[17..21].copy_from_slice(&s.elections_started.to_le_bytes());
    buf[21..25].copy_from_slice(&s.proposals_dropped_frozen.to_le_bytes());
    buf[25..29].copy_from_slice(&s.proposals_dropped_strict.to_le_bytes());
    let mut flags = 0u8;
    if s.frozen { flags |= 0x01; }
    if s.strict_fallback { flags |= 0x02; }
    buf[29] = flags;

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..30]);
    }
}
