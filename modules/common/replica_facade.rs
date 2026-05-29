//! Consumer-facing replica-group facade for Clustor's module graph.
//!
//! ## What this file is
//!
//! Loam, Lattice, and future replicated consumers all integrate with a Clustor
//! replica group through the same set of channel ports on the consensus graph
//! (`raft_engine.proposals_tagged`, `raft_engine.proposal_assigned`,
//! `commit_tracker.committed`, `snapshot_engine.import/export`, etc.). The
//! wire envelopes are defined in `modules/common/wire.rs`; the per-message
//! payload layouts are defined in the producing module.
//!
//! This file is the *typed Rust surface* over that contract. It is pulled in
//! by each consumer's fluxor module via the standard pattern
//!
//! ```ignore
//! #[path = "../common/replica_facade.rs"]
//! mod replica_facade;
//! ```
//!
//! and by host-side `cargo test` integration tests the same way. It is
//! **pure logic** — no `unsafe`, no `SyscallTable` calls — so the same
//! types compile under `no_std` for the embedded module build and under
//! `std` for cargo tests.
//!
//! ## Semantic contract
//!
//! Mirrors the high-level `ReplicaGroup` trait described in
//! `docs/architecture/consumer_facade.md`:
//!
//! - `build_tagged_proposal` encodes a `MSG_CLIENT_PROPOSAL` body bound to a
//!   non-zero `correlation_id`. The caller sends it on
//!   `raft_engine.proposals_tagged` (or its partitioned form). Bodies above
//!   [`MAX_COMMAND_BYTES`] are rejected with [`ProposeError::CommandTooLarge`]
//!   and never reach the WAL.
//! - [`InflightTable`] tracks the round trip `register` → `MSG_PROPOSAL_ASSIGNED`
//!   (`record_assignment`) → `MSG_COMMITTED_BATCH` (`record_commit`) →
//!   `take_committed`. The caller drains [`CommitAck`]s once they're durable.
//! - [`CommittedSubscriber`] consumes `MSG_COMMITTED_BATCH` payloads and
//!   enforces monotonic commit-order delivery. Same code path on a
//!   single-replica group and on a 5-replica group; the commit horizon
//!   advances as soon as the local durability ledger acks.
//! - [`SnapshotInstaller`] / [`SnapshotExporter`] frame snapshot chunks for
//!   `snapshot_engine.import_chunks` / `snapshot_engine.export_chunks` and
//!   verify the trailing manifest matches the advertised commit index.
//! - [`MembershipView`] and [`ReadGateInputs`] are read-only state accessors
//!   the consumer maintains by watching telemetry / cache-state channels.
//!
//! ## Invariants
//!
//! - **Opaque commands.** Clustor never inspects the body bytes. Consumers
//!   own the schema; the facade only enforces the size cap.
//! - **Topology-invariant.** A single-replica graph and a multi-replica
//!   graph travel the same code path through this facade; the only
//!   difference is when commits actually arrive (immediately after local
//!   durability vs. after quorum durability).
//! - **Bounded command size.** [`MAX_COMMAND_BYTES`] = 4096 bytes by default.
//!   Bulk content (object bodies, EC shards, cache contents) must travel
//!   out-of-band — Clustor orders identity-bearing metadata, not payloads.
//! - **No new public state.** The facade is a pure helper; it does not add
//!   control-plane state, change Raft semantics, alter durability, or
//!   widen the read-gate predicate.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface so single-module rustc invocations see unused items"
)]

// ── Public surface constants ───────────────────────────────────────────────

/// Maximum size of an opaque command body proposed through Clustor.
///
/// Replicated metadata decisions stay well below this; bulk content
/// (object bodies, EC shards) must travel out-of-band. Consumers
/// hitting this cap should reshape their command, not raise the cap.
pub const MAX_COMMAND_BYTES: usize = 4096;

/// Tagged-proposal correlation prefix size (matches
/// `wire::TAGGED_PROPOSAL_HDR`).
pub const TAGGED_PROPOSAL_HDR: usize = 8;

/// MSG_PROPOSAL_ASSIGNED payload size (matches
/// `wire::PROPOSAL_ASSIGNED_LEN`): correlation_id(8) + partition_id(2)
/// + wal_index(8).
pub const PROPOSAL_ASSIGNED_LEN: usize = 18;

/// MSG_COMMITTED_BATCH payload size: term(8) + index(8).
pub const COMMITTED_BATCH_LEN: usize = 16;

/// MSG_COMMITTED_ENTRY header size: term(8) + index(8). The body
/// follows immediately and can be 0..MAX_COMMAND_BYTES + tagged-prefix
/// (for proposal batches the per-entry envelope carries the coalesced
/// batch body produced by `raft_engine.flush_proposal_batch`).
pub const COMMITTED_ENTRY_HDR: usize = 16;

/// MSG_SNAPSHOT_CHUNK envelope prefix size: seq(4) + len(4).
pub const SNAPSHOT_CHUNK_HDR: usize = 8;

/// MSG_SNAPSHOT_MANIFEST length (matches `snapshot_engine`'s record).
pub const SNAPSHOT_MANIFEST_LEN: usize = 32;

/// Snapshot manifest magic: ASCII "SNAP" little-endian.
pub const SNAPSHOT_MAGIC: u32 = 0x534E_4150;

/// CP cache states (mirror of `modules/common/types.rs::CP_*`).
pub const CACHE_FRESH: u8 = 0;
pub const CACHE_CACHED: u8 = 1;
pub const CACHE_STALE: u8 = 2;
pub const CACHE_EXPIRED: u8 = 3;

/// Maximum replicas a single partition can hold. Matches
/// `modules/common/types.rs::MAX_NODES`.
pub const MAX_NODES: usize = 7;

/// Default in-flight proposal capacity. Consumers needing more
/// concurrent in-flight proposals instantiate `InflightTable<N>`
/// with a larger `N`.
pub const DEFAULT_INFLIGHT_CAPACITY: usize = 64;

// ── Public surface types ───────────────────────────────────────────────────

/// Outcome of a committed proposal: the Raft term at which the entry
/// committed and the assigned log index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitAck {
    pub term: u64,
    pub index: u64,
}

/// Decoded MSG_COMMITTED_ENTRY payload: the term + index at which the
/// entry committed, plus the opaque body bytes the proposer originally
/// submitted. Emitted on `apply_pipeline.committed_entries` in strict
/// commit-index order. Consumers wired only to `commit_tracker.committed`
/// see horizon-only updates and never receive a `CommittedEntry`; for
/// those, see [`CommittedSubscriber::ingest_committed_batch`] which
/// returns a [`CommitAck`] watermark instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedEntry<'a> {
    pub term: u64,
    pub index: u64,
    /// Opaque command bytes — Clustor never inspects these. A
    /// consumer's deterministic handler is invoked with this slice.
    pub command: &'a [u8],
}

impl<'a> CommittedEntry<'a> {
    /// Decode a `MSG_COMMITTED_ENTRY` payload (`[term:u64 LE][index:u64
    /// LE][body...]`). Returns `None` if the payload is shorter than
    /// the 16-byte header.
    pub fn decode(payload: &'a [u8]) -> Option<Self> {
        if payload.len() < COMMITTED_ENTRY_HDR {
            return None;
        }
        let term = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let index = u64::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);
        Some(Self {
            term,
            index,
            command: &payload[COMMITTED_ENTRY_HDR..],
        })
    }
}

/// Error returned by [`build_tagged_proposal`] and `InflightTable::register`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposeError {
    /// Body exceeds [`MAX_COMMAND_BYTES`]. The proposal MUST NOT be
    /// retried; the consumer must reshape its command. Clustor never
    /// sees the body.
    CommandTooLarge { len: usize, max: usize },
    /// Caller passed an empty body. Treated as a misuse; an empty
    /// proposal cannot carry meaning and is rejected at the boundary.
    EmptyCommand,
    /// Caller passed a zero `correlation_id`; the leader treats zero
    /// as "untagged" and won't emit MSG_PROPOSAL_ASSIGNED. Reserved.
    ReservedCorrelationId,
    /// The proposer's local in-flight table is full. The caller MUST
    /// drain commit acks before issuing more proposals.
    InflightTableFull { capacity: usize },
    /// Provided encode buffer too small to hold the encoded payload.
    EncodeBufferTooSmall { needed: usize, actual: usize },
    /// This replica is not the leader, so a proposal cannot be made
    /// from here. Caller should forward to [`MembershipView::leader`]
    /// or wait for the next leader-elected signal. Surfaced by
    /// higher-level wrappers; the bare encode path does not emit this.
    NotLeader,
}

/// Error returned by [`CommittedSubscriber::ingest_committed_batch`]
/// and [`CommittedSubscriber::ingest_committed_entry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOrderError {
    /// Observed index regressed below the subscriber's cursor. This
    /// indicates a misrouted message or a buggy producer; the
    /// consumer MUST drop the batch and SHOULD raise a telemetry
    /// incident — re-applying earlier indexes violates the
    /// deterministic-handler contract.
    NonMonotonicIndex { cursor: u64, observed: u64 },
    /// Payload shorter than [`COMMITTED_BATCH_LEN`] (for horizon
    /// batches) or [`COMMITTED_ENTRY_HDR`] (for per-entry envelopes).
    MalformedBatch { len: usize },
    /// A per-entry committed envelope arrived with an index that
    /// skipped past `cursor + 1`. The consumer SHOULD react by
    /// requesting a snapshot install — the apply_pipeline observer
    /// ring evicted entries before the consumer could read them.
    /// `expected` is `cursor + 1`; `observed` is the missing index.
    GapInPerEntryStream { expected: u64, observed: u64 },
}

/// Returned by a consumer's per-entry handler. A non-success result
/// MUST cause the consumer to halt and surface the error — applying
/// out of order would break the deterministic-handler invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// The handler observed an inconsistency between the command body
    /// and its own state. The consumer SHOULD treat this as
    /// unrecoverable and surface to its operator.
    StateInconsistency,
    /// The handler ran out of capacity (memory, file descriptors,
    /// etc.). The consumer SHOULD apply backpressure upstream.
    ResourceExhausted,
    /// The handler explicitly rejected the entry as invalid — same
    /// semantics as `StateInconsistency`, broken out so consumers can
    /// distinguish "I'm broken" from "the data is broken".
    InvalidCommand,
}

/// Error returned by snapshot helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Chunk sequence number arrived out of order. Snapshot install
    /// MUST be retried from the beginning; the partial state in the
    /// installer is discarded.
    ChunkOutOfOrder { expected: u32, observed: u32 },
    /// Manifest record was missing or shorter than [`SNAPSHOT_MANIFEST_LEN`].
    ManifestMissing { len: usize },
    /// Manifest magic, partition_id, or commit index did not match
    /// the expected value advertised to the installer.
    ManifestMismatch,
    /// Payload framing was malformed (length prefix lies, seq prefix
    /// short, or a chunk was offered after the manifest finalized).
    InvalidPayload,
    /// Encode buffer too small for the manifest or chunk payload.
    EncodeBufferTooSmall { needed: usize, actual: usize },
    /// A chunk was offered after the manifest finalized; or a
    /// manifest is being built before any chunks were emitted.
    SnapshotAlreadyFinalized,
}

// ── Tagged proposal encoding ───────────────────────────────────────────────

/// Build a tagged-proposal payload (`[correlation_id:u64 LE][body]`) into
/// `dst`, returning the encoded length. The caller wraps the result in the
/// standard `MSG_CLIENT_PROPOSAL` envelope (3-byte) or its partitioned
/// variant (5-byte) before writing to the channel.
///
/// Enforces:
///
/// - `body.len() <= MAX_COMMAND_BYTES` (Clustor orders metadata, not bulk).
/// - `body` non-empty.
/// - `correlation_id != 0` (zero is reserved as "untagged" by the leader).
/// - `dst.len() >= 8 + body.len()`.
///
/// Returns the consumed byte count on success; an error otherwise. The
/// command body is NEVER inspected — Clustor is opaque to its bytes.
pub fn build_tagged_proposal(
    dst: &mut [u8],
    correlation_id: u64,
    body: &[u8],
) -> Result<usize, ProposeError> {
    if body.is_empty() {
        return Err(ProposeError::EmptyCommand);
    }
    if body.len() > MAX_COMMAND_BYTES {
        return Err(ProposeError::CommandTooLarge {
            len: body.len(),
            max: MAX_COMMAND_BYTES,
        });
    }
    if correlation_id == 0 {
        return Err(ProposeError::ReservedCorrelationId);
    }
    let needed = TAGGED_PROPOSAL_HDR + body.len();
    if dst.len() < needed {
        return Err(ProposeError::EncodeBufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0..8].copy_from_slice(&correlation_id.to_le_bytes());
    dst[8..needed].copy_from_slice(body);
    Ok(needed)
}

/// Decode a `MSG_PROPOSAL_ASSIGNED` payload. Returns `Some((correlation_id,
/// partition_id, wal_index))` if the payload is well-formed; `None`
/// otherwise. Mirrors `wire::decode_proposal_assigned` but does not pull
/// in the SyscallTable.
pub fn decode_proposal_assigned(payload: &[u8]) -> Option<(u64, u16, u64)> {
    if payload.len() < PROPOSAL_ASSIGNED_LEN {
        return None;
    }
    let correlation_id = u64::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);
    let partition_id = u16::from_le_bytes([payload[8], payload[9]]);
    let wal_index = u64::from_le_bytes([
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
        payload[16],
        payload[17],
    ]);
    Some((correlation_id, partition_id, wal_index))
}

// ── In-flight correlation table ────────────────────────────────────────────

/// Lifecycle of a proposal in [`InflightTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InflightState {
    /// `register` called; awaiting `MSG_PROPOSAL_ASSIGNED`.
    Pending,
    /// `MSG_PROPOSAL_ASSIGNED` observed; awaiting commit.
    Assigned,
    /// Commit horizon advanced past `assigned_index`; ready to drain.
    Committed,
}

const STATE_PENDING: u8 = 0;
const STATE_ASSIGNED: u8 = 1;
const STATE_COMMITTED: u8 = 2;

#[derive(Clone, Copy)]
struct InflightSlot {
    /// 0 means the slot is empty.
    correlation_id: u64,
    assigned_index: u64,
    assigned_term: u64,
    state: u8,
}

impl InflightSlot {
    const fn empty() -> Self {
        Self {
            correlation_id: 0,
            assigned_index: 0,
            assigned_term: 0,
            state: STATE_PENDING,
        }
    }
}

/// Fixed-capacity correlation table. Mirrors the in-flight set a
/// consumer maintains while waiting for its tagged proposals to commit.
///
/// `N` is the maximum number of concurrent in-flight proposals. Picking
/// `N` involves a memory / parallelism trade-off: each slot is 24 bytes,
/// and the table size is the most concurrent commits a consumer can wait
/// on between calls to [`InflightTable::take_committed`]. Default to
/// [`DEFAULT_INFLIGHT_CAPACITY`] for most workloads.
pub struct InflightTable<const N: usize> {
    slots: [InflightSlot; N],
}

impl<const N: usize> InflightTable<N> {
    /// Create an empty in-flight table.
    pub const fn new() -> Self {
        Self {
            slots: [InflightSlot::empty(); N],
        }
    }

    /// Maximum number of concurrent in-flight proposals.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Current number of populated slots (any state).
    pub fn len(&self) -> usize {
        let mut n = 0;
        for s in &self.slots {
            if s.correlation_id != 0 {
                n += 1;
            }
        }
        n
    }

    /// True if no slots are populated.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reserve a slot for a tagged proposal. Idempotent for the same
    /// `correlation_id`. Returns [`ProposeError::InflightTableFull`] if
    /// no slot is free and [`ProposeError::ReservedCorrelationId`] if
    /// `correlation_id` is 0.
    pub fn register(&mut self, correlation_id: u64) -> Result<(), ProposeError> {
        if correlation_id == 0 {
            return Err(ProposeError::ReservedCorrelationId);
        }
        for s in &self.slots {
            if s.correlation_id == correlation_id {
                return Ok(());
            }
        }
        for s in self.slots.iter_mut() {
            if s.correlation_id == 0 {
                s.correlation_id = correlation_id;
                s.assigned_index = 0;
                s.assigned_term = 0;
                s.state = STATE_PENDING;
                return Ok(());
            }
        }
        Err(ProposeError::InflightTableFull { capacity: N })
    }

    /// Bind a previously registered correlation to its `wal_index`.
    /// Returns `Some(wal_index)` if the assignment was recorded, `None`
    /// if no matching slot existed (likely a duplicate
    /// `MSG_PROPOSAL_ASSIGNED` after a retry).
    pub fn record_assignment(&mut self, correlation_id: u64, wal_index: u64) -> Option<u64> {
        for s in self.slots.iter_mut() {
            if s.correlation_id == correlation_id && s.state == STATE_PENDING {
                s.assigned_index = wal_index;
                s.state = STATE_ASSIGNED;
                return Some(wal_index);
            }
        }
        None
    }

    /// Promote every assigned slot whose `assigned_index <= committed_index`
    /// to `Committed`, storing `committed_term`. Returns the count of
    /// newly committed slots.
    pub fn record_commit(&mut self, committed_term: u64, committed_index: u64) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.correlation_id != 0
                && s.state == STATE_ASSIGNED
                && s.assigned_index <= committed_index
            {
                s.assigned_term = committed_term;
                s.state = STATE_COMMITTED;
                n += 1;
            }
        }
        n
    }

    /// Drain the next committed slot, freeing it. Returns
    /// `Some((correlation_id, CommitAck))` if a committed slot was
    /// available, `None` otherwise. Order is implementation-defined
    /// (slot-scan order), NOT commit order — consumers that need
    /// commit-ordered acks should use [`CommittedSubscriber`] directly.
    pub fn take_committed(&mut self) -> Option<(u64, CommitAck)> {
        for s in self.slots.iter_mut() {
            if s.correlation_id != 0 && s.state == STATE_COMMITTED {
                let result = (
                    s.correlation_id,
                    CommitAck {
                        term: s.assigned_term,
                        index: s.assigned_index,
                    },
                );
                *s = InflightSlot::empty();
                return Some(result);
            }
        }
        None
    }

    /// Inspect the current state of a correlation. Returns `(state, term,
    /// index)` — term/index are 0 until the assignment lands.
    pub fn lookup(&self, correlation_id: u64) -> Option<(InflightState, u64, u64)> {
        for s in &self.slots {
            if s.correlation_id == correlation_id {
                let state = match s.state {
                    STATE_PENDING => InflightState::Pending,
                    STATE_ASSIGNED => InflightState::Assigned,
                    _ => InflightState::Committed,
                };
                return Some((state, s.assigned_term, s.assigned_index));
            }
        }
        None
    }

    /// Cancel a single inflight. Returns `true` if a slot was freed.
    /// Use when the caller observed a leader change before the
    /// proposal was assigned (so the proposal was discarded).
    pub fn cancel(&mut self, correlation_id: u64) -> bool {
        for s in self.slots.iter_mut() {
            if s.correlation_id == correlation_id {
                *s = InflightSlot::empty();
                return true;
            }
        }
        false
    }

    /// Cancel all inflights. Returns the count freed. Use after the
    /// consumer observes a term jump on the leader — the prior term's
    /// pending proposals were dropped by the new leader.
    pub fn cancel_all(&mut self) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.correlation_id != 0 {
                *s = InflightSlot::empty();
                n += 1;
            }
        }
        n
    }
}

impl<const N: usize> Default for InflightTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Committed subscriber ───────────────────────────────────────────────────

/// Consumes `MSG_COMMITTED_BATCH` payloads (16 bytes, `[term:u64][index:u64]`)
/// and enforces monotonic commit-order delivery. `commit_tracker.committed`
/// emits the *current commit horizon*, not per-entry envelopes — so this
/// subscriber tracks the watermark, not individual entries.
///
/// Same code path on single-replica and multi-replica clusters.
pub struct CommittedSubscriber {
    cursor: u64,
    last_term: u64,
    advanced_count: u64,
}

impl CommittedSubscriber {
    /// Build a subscriber that has already observed everything up to
    /// `start_after_index` (use 0 on fresh startup).
    pub const fn new(start_after_index: u64) -> Self {
        Self {
            cursor: start_after_index,
            last_term: 0,
            advanced_count: 0,
        }
    }

    /// Ingest a `MSG_COMMITTED_BATCH` payload. Returns the [`CommitAck`]
    /// reported by `commit_tracker`. If the horizon advanced strictly
    /// past the cursor, the advance is recorded; if it equals the cursor
    /// (idempotent retransmit) the call is a no-op. A horizon that
    /// regresses BELOW the cursor returns
    /// [`CommitOrderError::NonMonotonicIndex`] and the cursor is NOT
    /// updated.
    pub fn ingest_committed_batch(
        &mut self,
        payload: &[u8],
    ) -> Result<CommitAck, CommitOrderError> {
        if payload.len() < COMMITTED_BATCH_LEN {
            return Err(CommitOrderError::MalformedBatch { len: payload.len() });
        }
        let term = u64::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
            payload[7],
        ]);
        let index = u64::from_le_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);
        if index < self.cursor {
            return Err(CommitOrderError::NonMonotonicIndex {
                cursor: self.cursor,
                observed: index,
            });
        }
        if index > self.cursor {
            self.advanced_count += index - self.cursor;
            self.cursor = index;
        }
        self.last_term = term;
        Ok(CommitAck { term, index })
    }

    /// Highest commit index this subscriber has observed.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Term of the most recently observed batch.
    pub fn last_term(&self) -> u64 {
        self.last_term
    }

    /// Cumulative count of entries the cursor has advanced past.
    pub fn delivered(&self) -> u64 {
        self.advanced_count
    }

    /// Ingest a `MSG_COMMITTED_ENTRY` payload (per-entry envelope from
    /// `apply_pipeline.committed_entries`). Decodes into a borrowed
    /// [`CommittedEntry`] view of the payload and advances the cursor.
    ///
    /// Per-entry stream invariants enforced here:
    ///
    /// - `payload.len() >= COMMITTED_ENTRY_HDR` (returns
    ///   [`CommitOrderError::MalformedBatch`] otherwise).
    /// - `index > cursor` (strictly monotonic). A duplicate index
    ///   returns [`CommitOrderError::NonMonotonicIndex`] — the
    ///   consumer's deterministic handler MUST NOT see the same entry
    ///   twice.
    /// - `index == cursor + 1` (no gaps). The apply_pipeline observer
    ///   ring is bounded and evicts oldest entries under sustained
    ///   backpressure; if the consumer falls behind it may observe a
    ///   gap. Gaps return [`CommitOrderError::GapInPerEntryStream`]
    ///   and the consumer MUST recover via snapshot install
    ///   ([`SnapshotInstaller`]).
    ///
    /// On success the cursor advances to `index` and `last_term` to
    /// the entry's term. The returned [`CommittedEntry`] borrows from
    /// `payload`, so the caller can hand it to a deterministic handler
    /// without copying the body.
    pub fn ingest_committed_entry<'a>(
        &mut self,
        payload: &'a [u8],
    ) -> Result<CommittedEntry<'a>, CommitOrderError> {
        let Some(entry) = CommittedEntry::decode(payload) else {
            return Err(CommitOrderError::MalformedBatch { len: payload.len() });
        };
        if entry.index <= self.cursor {
            return Err(CommitOrderError::NonMonotonicIndex {
                cursor: self.cursor,
                observed: entry.index,
            });
        }
        let expected = self.cursor + 1;
        if entry.index != expected {
            return Err(CommitOrderError::GapInPerEntryStream {
                expected,
                observed: entry.index,
            });
        }
        self.cursor = entry.index;
        self.last_term = entry.term;
        self.advanced_count += 1;
        Ok(entry)
    }

    /// Reset the cursor to `index` after a snapshot install. The
    /// caller MUST have populated its local state to match this
    /// snapshot before calling — subsequent
    /// [`CommittedSubscriber::ingest_committed_entry`] calls will
    /// require an entry at `index + 1`.
    pub fn reset_to(&mut self, index: u64, term: u64) {
        self.cursor = index;
        self.last_term = term;
    }
}

// ── Snapshot install / export ──────────────────────────────────────────────

/// Stateful installer for follower catch-up. Verifies chunk ordering
/// and that the trailing manifest matches the advertised commit index.
///
/// The consumer:
///   1. Constructs the installer with the snapshot's target commit index.
///   2. Calls [`SnapshotInstaller::ingest_chunk`] for each
///      `MSG_SNAPSHOT_CHUNK` payload, applying the returned slice to
///      its local state.
///   3. Calls [`SnapshotInstaller::finalize`] with the trailing
///      `MSG_SNAPSHOT_MANIFEST` payload. The returned [`CommitAck`] is
///      the commit horizon the consumer's commit subscriber may now
///      jump to.
pub struct SnapshotInstaller {
    expected_index: u64,
    expected_partition: u16,
    next_chunk_seq: u32,
    bytes_received: u64,
    finalized: bool,
}

impl SnapshotInstaller {
    /// Build an installer expecting a snapshot anchored at
    /// `expected_index` for partition `partition_id` (0 for legacy
    /// single-partition graphs).
    pub const fn new(partition_id: u16, expected_index: u64) -> Self {
        Self {
            expected_index,
            expected_partition: partition_id,
            next_chunk_seq: 0,
            bytes_received: 0,
            finalized: false,
        }
    }

    /// Ingest the next chunk. Returns the unwrapped body bytes (caller
    /// applies them to its local state machine / WAL).
    ///
    /// Wire shape: `[seq:u32 LE][len:u32 LE][bytes:len]`.
    pub fn ingest_chunk<'a>(&mut self, payload: &'a [u8]) -> Result<&'a [u8], SnapshotError> {
        if self.finalized {
            return Err(SnapshotError::SnapshotAlreadyFinalized);
        }
        if payload.len() < SNAPSHOT_CHUNK_HDR {
            return Err(SnapshotError::InvalidPayload);
        }
        let seq = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let len = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
        if seq != self.next_chunk_seq {
            return Err(SnapshotError::ChunkOutOfOrder {
                expected: self.next_chunk_seq,
                observed: seq,
            });
        }
        if SNAPSHOT_CHUNK_HDR + len > payload.len() {
            return Err(SnapshotError::InvalidPayload);
        }
        self.next_chunk_seq = self.next_chunk_seq.saturating_add(1);
        self.bytes_received += len as u64;
        Ok(&payload[SNAPSHOT_CHUNK_HDR..SNAPSHOT_CHUNK_HDR + len])
    }

    /// Finalize the install with the trailing manifest payload.
    /// Verifies magic, partition_id, and commit-index match what the
    /// installer expects; returns the [`CommitAck`] the consumer may
    /// now seed its commit cursor with.
    pub fn finalize(&mut self, manifest: &[u8]) -> Result<CommitAck, SnapshotError> {
        if manifest.len() < SNAPSHOT_MANIFEST_LEN {
            return Err(SnapshotError::ManifestMissing {
                len: manifest.len(),
            });
        }
        let magic = u32::from_le_bytes([manifest[0], manifest[1], manifest[2], manifest[3]]);
        if magic != SNAPSHOT_MAGIC {
            return Err(SnapshotError::ManifestMismatch);
        }
        let partition_id = u16::from_le_bytes([manifest[4], manifest[5]]);
        if partition_id != self.expected_partition {
            return Err(SnapshotError::ManifestMismatch);
        }
        let term = u64::from_le_bytes([
            manifest[8],
            manifest[9],
            manifest[10],
            manifest[11],
            manifest[12],
            manifest[13],
            manifest[14],
            manifest[15],
        ]);
        let index = u64::from_le_bytes([
            manifest[16],
            manifest[17],
            manifest[18],
            manifest[19],
            manifest[20],
            manifest[21],
            manifest[22],
            manifest[23],
        ]);
        if index != self.expected_index {
            return Err(SnapshotError::ManifestMismatch);
        }
        self.finalized = true;
        Ok(CommitAck { term, index })
    }

    pub fn finalized(&self) -> bool {
        self.finalized
    }
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }
    pub fn chunks_received(&self) -> u32 {
        self.next_chunk_seq
    }
}

/// Stateful exporter that frames snapshot chunks for a peer. Used by
/// the leader / snapshot_engine when it answers a follower's snapshot
/// install request.
pub struct SnapshotExporter {
    partition_id: u16,
    target_index: u64,
    next_chunk_seq: u32,
    bytes_emitted: u64,
    completed: bool,
}

impl SnapshotExporter {
    pub const fn new(partition_id: u16, target_index: u64) -> Self {
        Self {
            partition_id,
            target_index,
            next_chunk_seq: 0,
            bytes_emitted: 0,
            completed: false,
        }
    }

    /// Encode the next chunk into `dst`. Returns the number of bytes
    /// written. The caller wraps in a `MSG_SNAPSHOT_CHUNK` envelope.
    pub fn build_chunk(&mut self, dst: &mut [u8], bytes: &[u8]) -> Result<usize, SnapshotError> {
        if self.completed {
            return Err(SnapshotError::SnapshotAlreadyFinalized);
        }
        let needed = SNAPSHOT_CHUNK_HDR + bytes.len();
        if dst.len() < needed {
            return Err(SnapshotError::EncodeBufferTooSmall {
                needed,
                actual: dst.len(),
            });
        }
        dst[0..4].copy_from_slice(&self.next_chunk_seq.to_le_bytes());
        dst[4..8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        dst[8..needed].copy_from_slice(bytes);
        self.next_chunk_seq = self.next_chunk_seq.saturating_add(1);
        self.bytes_emitted += bytes.len() as u64;
        Ok(needed)
    }

    /// Encode the trailing manifest into `dst`. Finalizes the
    /// exporter so subsequent chunk calls error.
    pub fn build_manifest(
        &mut self,
        dst: &mut [u8],
        term: u64,
        dek_epoch: u32,
    ) -> Result<usize, SnapshotError> {
        if dst.len() < SNAPSHOT_MANIFEST_LEN {
            return Err(SnapshotError::EncodeBufferTooSmall {
                needed: SNAPSHOT_MANIFEST_LEN,
                actual: dst.len(),
            });
        }
        dst[0..4].copy_from_slice(&SNAPSHOT_MAGIC.to_le_bytes());
        dst[4..6].copy_from_slice(&self.partition_id.to_le_bytes());
        dst[6..8].copy_from_slice(&0u16.to_le_bytes()); // reserved
        dst[8..16].copy_from_slice(&term.to_le_bytes());
        dst[16..24].copy_from_slice(&self.target_index.to_le_bytes());
        dst[24..28].copy_from_slice(&dek_epoch.to_le_bytes());
        dst[28..32].copy_from_slice(&0u32.to_le_bytes()); // reserved
        self.completed = true;
        Ok(SNAPSHOT_MANIFEST_LEN)
    }

    pub fn completed(&self) -> bool {
        self.completed
    }
    pub fn bytes_emitted(&self) -> u64 {
        self.bytes_emitted
    }
    pub fn chunks_emitted(&self) -> u32 {
        self.next_chunk_seq
    }
}

// ── Membership view ────────────────────────────────────────────────────────

/// Read-only view of the replica group from the consumer's perspective.
/// The consumer maintains this by watching telemetry / leader-changed
/// signals (currently emitted by `raft_engine.metrics`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MembershipView {
    leader_id: i8,
    voter_count: u8,
    self_id: u8,
}

impl MembershipView {
    pub const fn new(self_id: u8, voter_count: u8) -> Self {
        Self {
            leader_id: -1,
            voter_count,
            self_id,
        }
    }

    pub fn set_leader(&mut self, leader: Option<u8>) {
        self.leader_id = match leader {
            Some(v) => v as i8,
            None => -1,
        };
    }

    pub fn leader(&self) -> Option<u8> {
        if self.leader_id < 0 {
            None
        } else {
            Some(self.leader_id as u8)
        }
    }

    pub fn voter_count(&self) -> u8 {
        self.voter_count
    }

    pub fn self_id(&self) -> u8 {
        self.self_id
    }

    pub fn is_leader(&self) -> bool {
        self.leader_id == self.self_id as i8
    }

    /// Quorum size for the configured voter count.
    pub fn quorum_size(&self) -> u8 {
        (self.voter_count / 2) + 1
    }

    /// Single-replica groups behave as "always leader, always quorum"
    /// for the caller's purposes. A single-replica graph still walks
    /// the entire facade contract; this helper just makes that obvious.
    pub fn is_single_replica(&self) -> bool {
        self.voter_count == 1
    }
}

// ── Read-gate inputs ───────────────────────────────────────────────────────

/// Inputs the read-gate evaluator needs to decide whether a consistent
/// read can be served. Mirrors the structure consumed by
/// `read_gate.permits` — the consumer maintains the same fields locally
/// and asks the gate before answering a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadGateInputs {
    /// CP cache state observed from `cp_proof_cache.cache_state`
    /// (`CACHE_FRESH` / `CACHE_CACHED` / `CACHE_STALE` / `CACHE_EXPIRED`).
    pub cache_state: u8,
    /// `commit_tracker`'s most recent commit horizon.
    pub raft_commit_index: u64,
    /// Local durability ledger's last fsynced index.
    pub durable_index: u64,
    /// True when the runtime has been told to fall back to Strict
    /// mode (e.g. via `cp_proof_cache.strict_fallback`). Blocks reads.
    pub strict_fallback: bool,
}

impl ReadGateInputs {
    pub const fn new() -> Self {
        Self {
            cache_state: CACHE_EXPIRED,
            raft_commit_index: 0,
            durable_index: 0,
            strict_fallback: false,
        }
    }

    /// Predicate matching `read_gate.mod.rs` plus the durability-equality
    /// clause: a linearizable read is admitted only when the CP cache is
    /// Fresh-or-Cached, no strict-fallback signal is active, and the
    /// commit index equals the durable index.
    pub fn can_read(&self) -> bool {
        !self.strict_fallback
            && self.cache_state <= CACHE_CACHED
            && self.raft_commit_index == self.durable_index
    }
}

impl Default for ReadGateInputs {
    fn default() -> Self {
        Self::new()
    }
}

// ── Unit tests (host-side, run with `cargo test`) ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_committed_batch(term: u64, index: u64) -> [u8; COMMITTED_BATCH_LEN] {
        let mut buf = [0u8; COMMITTED_BATCH_LEN];
        buf[0..8].copy_from_slice(&term.to_le_bytes());
        buf[8..16].copy_from_slice(&index.to_le_bytes());
        buf
    }

    fn make_committed_entry(term: u64, index: u64, body: &[u8]) -> [u8; 128] {
        let mut buf = [0u8; 128];
        buf[0..8].copy_from_slice(&term.to_le_bytes());
        buf[8..16].copy_from_slice(&index.to_le_bytes());
        assert!(body.len() <= buf.len() - COMMITTED_ENTRY_HDR);
        buf[COMMITTED_ENTRY_HDR..COMMITTED_ENTRY_HDR + body.len()].copy_from_slice(body);
        buf
    }

    fn make_proposal_assigned(
        correlation_id: u64,
        partition_id: u16,
        wal_index: u64,
    ) -> [u8; PROPOSAL_ASSIGNED_LEN] {
        let mut buf = [0u8; PROPOSAL_ASSIGNED_LEN];
        buf[0..8].copy_from_slice(&correlation_id.to_le_bytes());
        buf[8..10].copy_from_slice(&partition_id.to_le_bytes());
        buf[10..18].copy_from_slice(&wal_index.to_le_bytes());
        buf
    }

    #[test]
    fn build_tagged_proposal_round_trips() {
        let body = b"set foo=bar";
        let mut buf = [0u8; 32];
        let len = build_tagged_proposal(&mut buf, 0xCAFE, body).unwrap();
        assert_eq!(len, TAGGED_PROPOSAL_HDR + body.len());
        let cid = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(cid, 0xCAFE);
        assert_eq!(&buf[8..len], body);
    }

    #[test]
    fn build_tagged_proposal_rejects_empty() {
        let mut buf = [0u8; 32];
        assert_eq!(
            build_tagged_proposal(&mut buf, 1, b""),
            Err(ProposeError::EmptyCommand)
        );
    }

    #[test]
    fn build_tagged_proposal_rejects_zero_correlation_id() {
        let mut buf = [0u8; 32];
        assert_eq!(
            build_tagged_proposal(&mut buf, 0, b"x"),
            Err(ProposeError::ReservedCorrelationId)
        );
    }

    #[test]
    fn build_tagged_proposal_rejects_oversize() {
        // Oversized command MUST be rejected and MUST NOT touch the buffer.
        let body = [0xAAu8; MAX_COMMAND_BYTES + 1];
        let mut buf = [0u8; MAX_COMMAND_BYTES + TAGGED_PROPOSAL_HDR + 16];
        let err = build_tagged_proposal(&mut buf, 1, &body).unwrap_err();
        match err {
            ProposeError::CommandTooLarge { len, max } => {
                assert_eq!(len, MAX_COMMAND_BYTES + 1);
                assert_eq!(max, MAX_COMMAND_BYTES);
            }
            other => panic!("expected CommandTooLarge, got {:?}", other),
        }
        // Buffer must not have been written past the header — first
        // byte stays zero (we never wrote the correlation_id either).
        assert_eq!(&buf[..16], &[0u8; 16]);
    }

    #[test]
    fn build_tagged_proposal_rejects_short_buffer() {
        let body = b"hello";
        let mut buf = [0u8; 8]; // only header, no body room
        let err = build_tagged_proposal(&mut buf, 1, body).unwrap_err();
        assert!(matches!(
            err,
            ProposeError::EncodeBufferTooSmall {
                needed: 13,
                actual: 8
            }
        ));
    }

    #[test]
    fn build_tagged_proposal_accepts_max_size() {
        let body = [0xAAu8; MAX_COMMAND_BYTES];
        let mut buf = [0u8; MAX_COMMAND_BYTES + TAGGED_PROPOSAL_HDR];
        let len = build_tagged_proposal(&mut buf, 7, &body).unwrap();
        assert_eq!(len, TAGGED_PROPOSAL_HDR + MAX_COMMAND_BYTES);
    }

    #[test]
    fn inflight_table_round_trip() {
        let mut table: InflightTable<4> = InflightTable::new();
        assert!(table.is_empty());
        table.register(11).unwrap();
        table.register(22).unwrap();
        assert_eq!(table.len(), 2);

        // Idempotent re-register is a no-op.
        table.register(11).unwrap();
        assert_eq!(table.len(), 2);

        // Lookup before assignment
        let (state, t, i) = table.lookup(11).unwrap();
        assert_eq!(state, InflightState::Pending);
        assert_eq!((t, i), (0, 0));

        // Record assignment for 11.
        assert_eq!(table.record_assignment(11, 100), Some(100));
        let (state, t, i) = table.lookup(11).unwrap();
        assert_eq!(state, InflightState::Assigned);
        assert_eq!((t, i), (0, 100));

        // Record assignment for 22.
        assert_eq!(table.record_assignment(22, 101), Some(101));

        // Commit advance to 100 only promotes 11.
        assert_eq!(table.record_commit(5, 100), 1);
        let (state, _, _) = table.lookup(11).unwrap();
        assert_eq!(state, InflightState::Committed);
        let (state, _, _) = table.lookup(22).unwrap();
        assert_eq!(state, InflightState::Assigned);

        // Drain 11.
        let (cid, ack) = table.take_committed().unwrap();
        assert_eq!(cid, 11);
        assert_eq!(
            ack,
            CommitAck {
                term: 5,
                index: 100
            }
        );
        assert!(table.lookup(11).is_none());
        assert_eq!(table.len(), 1);

        // Commit advance past 101 promotes 22.
        assert_eq!(table.record_commit(5, 200), 1);
        let (cid, ack) = table.take_committed().unwrap();
        assert_eq!(cid, 22);
        assert_eq!(
            ack,
            CommitAck {
                term: 5,
                index: 101
            }
        );
        assert!(table.is_empty());
    }

    #[test]
    fn inflight_table_full_returns_error() {
        let mut table: InflightTable<2> = InflightTable::new();
        table.register(1).unwrap();
        table.register(2).unwrap();
        let err = table.register(3).unwrap_err();
        assert_eq!(err, ProposeError::InflightTableFull { capacity: 2 });
    }

    #[test]
    fn inflight_table_rejects_zero_correlation() {
        let mut table: InflightTable<2> = InflightTable::new();
        assert_eq!(table.register(0), Err(ProposeError::ReservedCorrelationId));
    }

    #[test]
    fn inflight_table_cancel_all_after_term_change() {
        let mut table: InflightTable<4> = InflightTable::new();
        table.register(11).unwrap();
        table.register(22).unwrap();
        table.record_assignment(11, 100);
        assert_eq!(table.cancel_all(), 2);
        assert!(table.is_empty());
    }

    #[test]
    fn record_assignment_ignores_unknown_correlation() {
        let mut table: InflightTable<4> = InflightTable::new();
        // Late MSG_PROPOSAL_ASSIGNED for a correlation we never
        // registered (e.g. cancelled after a leader change). The
        // table refuses silently — None means "drop the assignment".
        assert!(table.record_assignment(999, 42).is_none());
    }

    #[test]
    fn decode_proposal_assigned_matches_wire() {
        let buf = make_proposal_assigned(0x1234, 7, 0xABCD);
        let (cid, partition, idx) = decode_proposal_assigned(&buf).unwrap();
        assert_eq!(cid, 0x1234);
        assert_eq!(partition, 7);
        assert_eq!(idx, 0xABCD);
    }

    #[test]
    fn decode_proposal_assigned_rejects_short() {
        assert!(decode_proposal_assigned(&[0u8; 10]).is_none());
    }

    #[test]
    fn committed_subscriber_strict_order() {
        let mut sub = CommittedSubscriber::new(0);
        let ack = sub
            .ingest_committed_batch(&make_committed_batch(3, 5))
            .unwrap();
        assert_eq!(ack, CommitAck { term: 3, index: 5 });
        assert_eq!(sub.cursor(), 5);
        assert_eq!(sub.delivered(), 5);

        // Idempotent retransmit at same horizon — must succeed and not
        // advance the delivered count.
        let ack = sub
            .ingest_committed_batch(&make_committed_batch(3, 5))
            .unwrap();
        assert_eq!(ack, CommitAck { term: 3, index: 5 });
        assert_eq!(sub.delivered(), 5);

        // Forward advance, term may change (new term took over).
        let ack = sub
            .ingest_committed_batch(&make_committed_batch(4, 8))
            .unwrap();
        assert_eq!(ack, CommitAck { term: 4, index: 8 });
        assert_eq!(sub.cursor(), 8);
        assert_eq!(sub.delivered(), 8);
        assert_eq!(sub.last_term(), 4);
    }

    #[test]
    fn committed_subscriber_rejects_regress() {
        let mut sub = CommittedSubscriber::new(0);
        sub.ingest_committed_batch(&make_committed_batch(3, 5))
            .unwrap();
        let err = sub
            .ingest_committed_batch(&make_committed_batch(3, 4))
            .unwrap_err();
        assert_eq!(
            err,
            CommitOrderError::NonMonotonicIndex {
                cursor: 5,
                observed: 4
            }
        );
        // Cursor unchanged after rejection.
        assert_eq!(sub.cursor(), 5);
    }

    #[test]
    fn committed_subscriber_rejects_malformed() {
        let mut sub = CommittedSubscriber::new(0);
        let err = sub.ingest_committed_batch(&[0u8; 8]).unwrap_err();
        assert_eq!(err, CommitOrderError::MalformedBatch { len: 8 });
    }

    #[test]
    fn snapshot_round_trip_via_exporter_and_installer() {
        // Build a 3-chunk snapshot, ship it through, install on the receiver.
        let mut exporter = SnapshotExporter::new(0, 200);
        let body_a = b"chunk-A-bytes";
        let body_b = b"chunk-B-bytes-longer";
        let body_c = b"C";

        let mut chunk_buf = [0u8; 64];
        let la = exporter.build_chunk(&mut chunk_buf, body_a).unwrap();
        let chunk_a = chunk_buf[..la].to_vec();
        let lb = exporter.build_chunk(&mut chunk_buf, body_b).unwrap();
        let chunk_b = chunk_buf[..lb].to_vec();
        let lc = exporter.build_chunk(&mut chunk_buf, body_c).unwrap();
        let chunk_c = chunk_buf[..lc].to_vec();

        let mut manifest_buf = [0u8; SNAPSHOT_MANIFEST_LEN];
        let lm = exporter
            .build_manifest(&mut manifest_buf, /* term */ 9, /* dek_epoch */ 2)
            .unwrap();
        assert_eq!(lm, SNAPSHOT_MANIFEST_LEN);
        assert!(exporter.completed());

        // Installer expects partition 0 at index 200.
        let mut installer = SnapshotInstaller::new(0, 200);
        let a = installer.ingest_chunk(&chunk_a).unwrap();
        assert_eq!(a, body_a);
        let b = installer.ingest_chunk(&chunk_b).unwrap();
        assert_eq!(b, body_b);
        let c = installer.ingest_chunk(&chunk_c).unwrap();
        assert_eq!(c, body_c);
        let ack = installer.finalize(&manifest_buf).unwrap();
        assert_eq!(
            ack,
            CommitAck {
                term: 9,
                index: 200
            }
        );
        assert!(installer.finalized());
        assert_eq!(installer.chunks_received(), 3);
    }

    #[test]
    fn snapshot_installer_rejects_out_of_order() {
        let mut installer = SnapshotInstaller::new(0, 100);
        let mut buf = [0u8; 32];
        // Chunk seq 0
        let mut exporter = SnapshotExporter::new(0, 100);
        let l0 = exporter.build_chunk(&mut buf, b"a").unwrap();
        let c0 = buf[..l0].to_vec();
        let l1 = exporter.build_chunk(&mut buf, b"b").unwrap();
        let c1 = buf[..l1].to_vec();

        // Skip chunk 0, send chunk 1 first — must fail.
        let err = installer.ingest_chunk(&c1).unwrap_err();
        assert_eq!(
            err,
            SnapshotError::ChunkOutOfOrder {
                expected: 0,
                observed: 1
            }
        );

        // After failure, sending chunk 0 still succeeds (recovery is
        // up to the consumer; the installer holds no error state).
        installer.ingest_chunk(&c0).unwrap();
    }

    #[test]
    fn snapshot_installer_rejects_partition_mismatch() {
        // Exporter on partition 7, installer expecting partition 0.
        let mut exporter = SnapshotExporter::new(7, 50);
        let mut buf = [0u8; 32];
        let _ = exporter.build_chunk(&mut buf, b"x").unwrap();
        let mut mbuf = [0u8; SNAPSHOT_MANIFEST_LEN];
        exporter.build_manifest(&mut mbuf, 1, 0).unwrap();

        let mut installer = SnapshotInstaller::new(0, 50);
        let err = installer.finalize(&mbuf).unwrap_err();
        assert_eq!(err, SnapshotError::ManifestMismatch);
    }

    #[test]
    fn snapshot_installer_rejects_commit_index_mismatch() {
        let mut exporter = SnapshotExporter::new(0, 99);
        let mut mbuf = [0u8; SNAPSHOT_MANIFEST_LEN];
        exporter.build_manifest(&mut mbuf, 1, 0).unwrap();
        let mut installer = SnapshotInstaller::new(0, 100);
        assert_eq!(
            installer.finalize(&mbuf).unwrap_err(),
            SnapshotError::ManifestMismatch
        );
    }

    #[test]
    fn snapshot_installer_rejects_chunk_after_finalize() {
        let mut exporter = SnapshotExporter::new(0, 5);
        let mut buf = [0u8; 32];
        let lc = exporter.build_chunk(&mut buf, b"x").unwrap();
        let chunk = buf[..lc].to_vec();
        let mut mbuf = [0u8; SNAPSHOT_MANIFEST_LEN];
        exporter.build_manifest(&mut mbuf, 1, 0).unwrap();

        let mut installer = SnapshotInstaller::new(0, 5);
        installer.ingest_chunk(&chunk).unwrap();
        installer.finalize(&mbuf).unwrap();
        let err = installer.ingest_chunk(&chunk).unwrap_err();
        assert_eq!(err, SnapshotError::SnapshotAlreadyFinalized);
    }

    #[test]
    fn membership_view_basics() {
        let mut m = MembershipView::new(1, 3);
        assert_eq!(m.leader(), None);
        assert_eq!(m.voter_count(), 3);
        assert_eq!(m.self_id(), 1);
        assert!(!m.is_leader());
        assert_eq!(m.quorum_size(), 2);
        assert!(!m.is_single_replica());

        m.set_leader(Some(1));
        assert_eq!(m.leader(), Some(1));
        assert!(m.is_leader());

        m.set_leader(None);
        assert_eq!(m.leader(), None);
    }

    #[test]
    fn membership_view_single_replica() {
        let m = MembershipView::new(0, 1);
        assert!(m.is_single_replica());
        assert_eq!(m.quorum_size(), 1);
    }

    #[test]
    fn read_gate_predicate_truth_table() {
        let mut inputs = ReadGateInputs::new();
        // Defaults: cache_state=EXPIRED, strict_fallback=false, indices 0.
        // EXPIRED >= STALE → not readable.
        assert!(!inputs.can_read());

        inputs.cache_state = CACHE_FRESH;
        inputs.raft_commit_index = 10;
        inputs.durable_index = 10;
        assert!(inputs.can_read());

        // Commit ahead of durable → blocked.
        inputs.raft_commit_index = 11;
        assert!(!inputs.can_read());

        // Equal again → allowed.
        inputs.durable_index = 11;
        assert!(inputs.can_read());

        // Strict fallback overrides cache state.
        inputs.strict_fallback = true;
        assert!(!inputs.can_read());
        inputs.strict_fallback = false;

        // Stale cache → blocked.
        inputs.cache_state = CACHE_STALE;
        assert!(!inputs.can_read());

        // Cached cache state still passes.
        inputs.cache_state = CACHE_CACHED;
        assert!(inputs.can_read());
    }

    /// End-to-end: simulate a single-replica proposal that commits via
    /// the local durability path. Same code path as a multi-replica
    /// commit — only the timing of `record_commit` differs.
    #[test]
    fn single_replica_propose_commit_round_trip() {
        let membership = MembershipView::new(0, 1);
        assert!(membership.is_single_replica());

        let mut inflight: InflightTable<{ DEFAULT_INFLIGHT_CAPACITY }> = InflightTable::new();
        let mut subscriber = CommittedSubscriber::new(0);

        // 1) Consumer issues a tagged proposal.
        let body = b"single-replica-set foo=bar";
        let mut buf = [0u8; MAX_COMMAND_BYTES + TAGGED_PROPOSAL_HDR];
        let _ = build_tagged_proposal(&mut buf, 0xABCD, body).unwrap();
        inflight.register(0xABCD).unwrap();

        // 2) raft_engine assigns wal_index=1 and emits MSG_PROPOSAL_ASSIGNED.
        let assigned = make_proposal_assigned(0xABCD, 0, 1);
        let (cid, _pid, wal_index) = decode_proposal_assigned(&assigned).unwrap();
        assert_eq!(cid, 0xABCD);
        inflight.record_assignment(cid, wal_index);

        // 3) Local durability_ledger acks; commit_tracker advances to 1.
        let batch = make_committed_batch(1, 1);
        let ack = subscriber.ingest_committed_batch(&batch).unwrap();
        assert_eq!(ack, CommitAck { term: 1, index: 1 });

        // 4) Consumer wakes inflight on commit horizon and drains.
        inflight.record_commit(ack.term, ack.index);
        let (drained_cid, drained_ack) = inflight.take_committed().unwrap();
        assert_eq!(drained_cid, 0xABCD);
        assert_eq!(drained_ack, ack);
        assert!(inflight.is_empty());
        // Same flow would work on a 3-replica cluster — only step (3)
        // would wait for quorum durability instead of local durability.
    }

    /// Multi-proposal commit-order test. Mirrors "subscribe_committed
    /// fires in strict commit-order on every replica" from the user's
    /// test list: the subscriber observes monotonically advancing
    /// commit indexes and the inflight table only releases acks for
    /// proposals whose assigned_index is <= the current commit horizon.
    #[test]
    fn subscribe_committed_fires_in_order() {
        let mut inflight: InflightTable<4> = InflightTable::new();
        let mut sub = CommittedSubscriber::new(0);

        // Three concurrent in-flight proposals.
        inflight.register(0xA1).unwrap();
        inflight.register(0xA2).unwrap();
        inflight.register(0xA3).unwrap();
        inflight.record_assignment(0xA1, 10);
        inflight.record_assignment(0xA2, 11);
        inflight.record_assignment(0xA3, 12);

        // commit_tracker emits horizon=10 first.
        sub.ingest_committed_batch(&make_committed_batch(1, 10))
            .unwrap();
        inflight.record_commit(1, 10);
        assert_eq!(inflight.take_committed().map(|(c, _)| c), Some(0xA1));
        // Only A1 is committed; A2/A3 still Assigned.
        assert_eq!(
            inflight.lookup(0xA2).map(|(s, _, _)| s),
            Some(InflightState::Assigned)
        );

        // Horizon advances to 12 — A2 and A3 both become committable.
        sub.ingest_committed_batch(&make_committed_batch(1, 12))
            .unwrap();
        assert_eq!(inflight.record_commit(1, 12), 2);

        // Both drain (slot-scan order; correlation_ids can come out in
        // either order, what matters is they're both released).
        let first = inflight.take_committed().unwrap();
        let second = inflight.take_committed().unwrap();
        let mut got = [first.0, second.0];
        got.sort();
        assert_eq!(got, [0xA2, 0xA3]);
        assert!(inflight.is_empty());

        // Cursor reflects the final horizon.
        assert_eq!(sub.cursor(), 12);
    }

    // ── Per-entry stream (MSG_COMMITTED_ENTRY) ────────────────────────────

    #[test]
    fn committed_entry_decode_roundtrip() {
        let body = b"set foo=bar";
        let mut buf = [0u8; 128];
        buf[0..8].copy_from_slice(&7u64.to_le_bytes());
        buf[8..16].copy_from_slice(&42u64.to_le_bytes());
        buf[16..16 + body.len()].copy_from_slice(body);
        let entry = CommittedEntry::decode(&buf[..16 + body.len()]).unwrap();
        assert_eq!(entry.term, 7);
        assert_eq!(entry.index, 42);
        assert_eq!(entry.command, body);
    }

    #[test]
    fn committed_entry_decode_rejects_short() {
        assert!(CommittedEntry::decode(&[0u8; 8]).is_none());
    }

    #[test]
    fn subscriber_ingest_per_entry_in_order() {
        let mut sub = CommittedSubscriber::new(0);
        let body1 = b"a";
        let body2 = b"bb";
        let body3 = b"ccc";

        let buf1 = make_committed_entry(1, 1, body1);
        let entry = sub
            .ingest_committed_entry(&buf1[..16 + body1.len()])
            .unwrap();
        assert_eq!(
            (entry.term, entry.index, entry.command),
            (1, 1, body1.as_slice())
        );
        assert_eq!(sub.cursor(), 1);
        assert_eq!(sub.delivered(), 1);

        let buf2 = make_committed_entry(1, 2, body2);
        let entry = sub
            .ingest_committed_entry(&buf2[..16 + body2.len()])
            .unwrap();
        assert_eq!(entry.index, 2);
        assert_eq!(entry.command, body2.as_slice());

        let buf3 = make_committed_entry(2, 3, body3);
        let entry = sub
            .ingest_committed_entry(&buf3[..16 + body3.len()])
            .unwrap();
        assert_eq!(
            (entry.term, entry.index, entry.command),
            (2, 3, body3.as_slice())
        );
        assert_eq!(sub.last_term(), 2);
        assert_eq!(sub.cursor(), 3);
        assert_eq!(sub.delivered(), 3);
    }

    #[test]
    fn subscriber_per_entry_rejects_duplicate() {
        let mut sub = CommittedSubscriber::new(0);
        let buf = make_committed_entry(1, 1, b"x");
        sub.ingest_committed_entry(&buf[..17]).unwrap();
        let err = sub.ingest_committed_entry(&buf[..17]).unwrap_err();
        assert_eq!(
            err,
            CommitOrderError::NonMonotonicIndex {
                cursor: 1,
                observed: 1
            }
        );
        assert_eq!(sub.cursor(), 1, "duplicate MUST NOT advance cursor");
    }

    #[test]
    fn subscriber_per_entry_rejects_gap() {
        let mut sub = CommittedSubscriber::new(0);
        let buf = make_committed_entry(1, 1, b"x");
        sub.ingest_committed_entry(&buf[..17]).unwrap();
        // Skip index 2 — apply_pipeline ring evicted it.
        let buf3 = make_committed_entry(1, 3, b"x");
        let err = sub.ingest_committed_entry(&buf3[..17]).unwrap_err();
        assert_eq!(
            err,
            CommitOrderError::GapInPerEntryStream {
                expected: 2,
                observed: 3
            }
        );
        assert_eq!(sub.cursor(), 1);
    }

    #[test]
    fn subscriber_reset_to_after_snapshot() {
        let mut sub = CommittedSubscriber::new(0);
        // Process two entries then a snapshot fast-forwards us.
        let b1 = make_committed_entry(1, 1, b"a");
        let b2 = make_committed_entry(1, 2, b"b");
        sub.ingest_committed_entry(&b1[..17]).unwrap();
        sub.ingest_committed_entry(&b2[..17]).unwrap();

        // Snapshot installs at index 100.
        sub.reset_to(100, 5);
        assert_eq!(sub.cursor(), 100);
        assert_eq!(sub.last_term(), 5);

        // Next entry must be 101.
        let bad = make_committed_entry(5, 200, b"x");
        assert_eq!(
            sub.ingest_committed_entry(&bad[..17]).unwrap_err(),
            CommitOrderError::GapInPerEntryStream {
                expected: 101,
                observed: 200
            }
        );
        let ok = make_committed_entry(5, 101, b"x");
        sub.ingest_committed_entry(&ok[..17]).unwrap();
        assert_eq!(sub.cursor(), 101);
    }

    #[test]
    fn subscriber_per_entry_rejects_malformed() {
        let mut sub = CommittedSubscriber::new(0);
        let err = sub.ingest_committed_entry(&[0u8; 8]).unwrap_err();
        assert_eq!(err, CommitOrderError::MalformedBatch { len: 8 });
    }

    #[test]
    fn subscriber_per_entry_works_with_empty_body() {
        // A no-op proposal (e.g. a Raft term-stabilising entry) has a
        // 16-byte payload — header only, no body. The subscriber must
        // accept it; the consumer's handler decides what to do.
        let mut sub = CommittedSubscriber::new(0);
        let buf = make_committed_entry(1, 1, b"");
        let entry = sub.ingest_committed_entry(&buf[..16]).unwrap();
        assert_eq!(entry.command, &[][..]);
        assert_eq!(sub.cursor(), 1);
    }

    /// End-to-end: a small inflight + per-entry pipeline that mimics
    /// what a Loam / Lattice module would do at runtime.
    #[test]
    fn end_to_end_propose_assign_apply_per_entry() {
        let mut inflight: InflightTable<4> = InflightTable::new();
        let mut sub = CommittedSubscriber::new(0);

        // Propose two tagged commands.
        inflight.register(0x11).unwrap();
        inflight.register(0x22).unwrap();
        let assign_a = make_proposal_assigned(0x11, 0, 1);
        let assign_b = make_proposal_assigned(0x22, 0, 2);
        let (cid_a, _, idx_a) = decode_proposal_assigned(&assign_a).unwrap();
        let (cid_b, _, idx_b) = decode_proposal_assigned(&assign_b).unwrap();
        inflight.record_assignment(cid_a, idx_a);
        inflight.record_assignment(cid_b, idx_b);

        // Per-entry stream delivers the commands in commit order.
        let body_a = b"PUT key=foo val=1";
        let body_b = b"DELETE key=foo";
        let env_a = make_committed_entry(3, 1, body_a);
        let env_b = make_committed_entry(3, 2, body_b);

        let entry = sub
            .ingest_committed_entry(&env_a[..16 + body_a.len()])
            .unwrap();
        assert_eq!(entry.command, body_a);
        inflight.record_commit(entry.term, entry.index);
        let drained = inflight.take_committed().unwrap();
        assert_eq!(drained, (0x11, CommitAck { term: 3, index: 1 }));

        let entry = sub
            .ingest_committed_entry(&env_b[..16 + body_b.len()])
            .unwrap();
        assert_eq!(entry.command, body_b);
        inflight.record_commit(entry.term, entry.index);
        let drained = inflight.take_committed().unwrap();
        assert_eq!(drained, (0x22, CommitAck { term: 3, index: 2 }));

        assert_eq!(sub.cursor(), 2);
        assert!(inflight.is_empty());
    }
}
