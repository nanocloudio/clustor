//! Consumer-facing replica-group facade for Clustor's module graph.
//!
//! ## What this file is
//!
//! Loam, Lattice, and future replicated consumers all integrate with a Clustor
//! replica group through the same set of channel ports on the consensus graph
//! (`consensus.proposals_tagged`, `consensus.proposal_assigned`,
//! `consensus.committed_entries`, `durability.import/export`, etc.). The
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
//!   `consensus.proposals_tagged` (or its partitioned form). Bodies above
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
//!   `durability.import_chunks` / `durability.export_chunks` and
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
/// `wire::PROPOSAL_ASSIGNED_LEN`): `[correlation_id:u64]
/// [partition_id:u16][wal_index:u64][term:u64]`.
pub const PROPOSAL_ASSIGNED_LEN: usize = 26;

/// MSG_COMMITTED_BATCH payload size: term(8) + index(8).
pub const COMMITTED_BATCH_LEN: usize = 16;

/// MSG_COMMITTED_ENTRY header size: term(8) + index(8). The body
/// follows immediately and can be 0..MAX_COMMAND_BYTES + tagged-prefix
/// (for proposal batches the per-entry envelope carries the coalesced
/// batch body produced by `consensus.flush_proposal_batch`).
/// `MSG_COMMITTED_ENTRY` header: `[partition_id:u16][term:u64][index:u64]`.
///
/// This file is `#[path]`-included into contexts that do NOT have `wire`
/// in scope (the benches, for one), so it cannot re-export the constant
/// and must keep its own. That duplication is exactly what let the two
/// drift when the partition id was added — only the writer changed, and
/// this decoder then read `index` across the shifted boundary, which
/// made `session_directory` reject every entry.
///
/// `tests/facade.rs::facade_constants_match_wire` asserts the two are
/// equal, so drift now fails a test instead of corrupting a stream.
pub const COMMITTED_ENTRY_HDR: usize = 18;

/// MSG_SNAPSHOT_CHUNK envelope prefix size: seq(4) + len(4).
pub const SNAPSHOT_CHUNK_HDR: usize = 8;

/// MSG_SNAPSHOT_MANIFEST length (matches `durability`'s record).
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

// ── Channel envelope ───────────────────────────────────────────────────────
//
// Every message on a Clustor channel carries a 3-byte envelope ahead of its
// payload. A consumer attaches to byte-stream channels, so it needs both to
// frame what it writes and to reassemble what it reads across arbitrary read
// boundaries. These are the only envelope facts a consumer depends on; the
// full `MSG_*` registry in `wire.rs` stays internal to the substrate.

/// Envelope header size: `[msg_type:u8][payload_len:u16 LE]`.
pub const ENVELOPE_HDR: usize = 3;

/// Largest payload one envelope carries.
pub const MAX_PAYLOAD: usize = 0xFFFF;

/// Envelope type for an opaque command offered to the replica group.
///
/// Written to `consensus.proposals` when the consumer carries its own
/// correlation inside the command body, or — wrapping a
/// [`build_tagged_proposal`] payload — to `consensus.proposals_tagged` when
/// it wants Clustor to correlate on its behalf.
pub const MSG_CLIENT_PROPOSAL: u8 = 0x10;

/// Envelope type of the per-entry committed stream on
/// `consensus.committed_entries`. The payload is
/// `[term:u64 LE][index:u64 LE][body]` — see [`CommittedEntry::decode`].
pub const MSG_COMMITTED_ENTRY: u8 = 0x24;

/// Frame `payload` into `dst` as `[msg_type][len:u16 LE][payload]`,
/// returning the total bytes written.
///
/// Envelope and payload are composed into one buffer so the caller issues a
/// single channel write. That is what keeps a frame atomic against a reader
/// reassembling the stream.
pub fn frame(dst: &mut [u8], msg_type: u8, payload: &[u8]) -> Result<usize, ProposeError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(ProposeError::CommandTooLarge {
            len: payload.len(),
            max: MAX_PAYLOAD,
        });
    }
    let needed = ENVELOPE_HDR + payload.len();
    if dst.len() < needed {
        return Err(ProposeError::EncodeBufferTooSmall {
            needed,
            actual: dst.len(),
        });
    }
    dst[0] = msg_type;
    dst[1..3].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    dst[ENVELOPE_HDR..needed].copy_from_slice(payload);
    Ok(needed)
}

/// Split one complete frame off the front of `buf`.
///
/// Returns `(msg_type, payload, consumed)`. Returns `None` when `buf` holds
/// less than a whole frame, in which case the caller retains the bytes and
/// retries after its next read. Consumers drain in a loop, then compact the
/// unconsumed remainder to the front of their reassembly buffer.
pub fn next_frame(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.len() < ENVELOPE_HDR {
        return None;
    }
    let msg_type = buf[0];
    let payload_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
    let total = ENVELOPE_HDR + payload_len;
    if buf.len() < total {
        return None;
    }
    Some((msg_type, &buf[ENVELOPE_HDR..total], total))
}

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
/// submitted. Emitted on `consensus.committed_entries` in strict
/// commit-index order. Consumers that ingest only MSG_COMMITTED_BATCH
/// horizon updates never receive a `CommittedEntry`; for
/// those, see [`CommittedSubscriber::ingest_committed_batch`] which
/// returns a [`CommitAck`] watermark instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedEntry<'a> {
    /// Which raft group produced this entry. One engine hosts K groups
    /// whose indexes each start at 1, so a cursor is only meaningful
    /// per partition.
    pub partition_id: u16,
    pub term: u64,
    pub index: u64,
    /// Opaque command bytes — Clustor never inspects these. A
    /// consumer's deterministic handler is invoked with this slice.
    pub command: &'a [u8],
}

impl<'a> CommittedEntry<'a> {
    /// Decode a `MSG_COMMITTED_ENTRY` payload
    /// (`[partition_id:u16 LE][term:u64 LE][index:u64 LE][body...]`).
    /// Returns `None` if the payload is shorter than the header.
    pub fn decode(payload: &'a [u8]) -> Option<Self> {
        if payload.len() < COMMITTED_ENTRY_HDR {
            return None;
        }
        let partition_id = u16::from_le_bytes([payload[0], payload[1]]);
        let term = u64::from_le_bytes([
            payload[2], payload[3], payload[4], payload[5], payload[6], payload[7], payload[8],
            payload[9],
        ]);
        let index = u64::from_le_bytes([
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16],
            payload[17],
        ]);
        Some(Self {
            partition_id,
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
    /// requesting a snapshot install — the consensus observer
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
/// partition_id, wal_index, term))` if the payload is well-formed; `None`
/// otherwise. Mirrors `wire::decode_proposal_assigned` but does not pull
/// in the SyscallTable.
pub fn decode_proposal_assigned(payload: &[u8]) -> Option<(u64, u16, u64, u64)> {
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
    let term = u64::from_le_bytes([
        payload[18],
        payload[19],
        payload[20],
        payload[21],
        payload[22],
        payload[23],
        payload[24],
        payload[25],
    ]);
    Some((correlation_id, partition_id, wal_index, term))
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
    /// Another term's entry committed at `assigned_index`: the proposal
    /// never will. Drained by [`InflightTable::take_superseded`].
    Superseded,
}

const STATE_PENDING: u8 = 0;
const STATE_ASSIGNED: u8 = 1;
const STATE_COMMITTED: u8 = 2;
const STATE_SUPERSEDED: u8 = 3;

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

    /// Bind a previously registered correlation to its entry, `wal_index`
    /// in `term`. Returns `Some(wal_index)` if the assignment was
    /// recorded, `None` if no matching slot existed (likely a duplicate
    /// `MSG_PROPOSAL_ASSIGNED` after a retry).
    pub fn record_assignment(
        &mut self,
        correlation_id: u64,
        wal_index: u64,
        term: u64,
    ) -> Option<u64> {
        for s in self.slots.iter_mut() {
            if s.correlation_id == correlation_id && s.state == STATE_PENDING {
                s.assigned_index = wal_index;
                s.assigned_term = term;
                s.state = STATE_ASSIGNED;
                return Some(wal_index);
            }
        }
        None
    }

    /// The entry at `committed_index`, appended in `committed_term`, has
    /// committed. Every assigned slot of the same term at or below that
    /// index is committed with it: one leader assigns a term's entries,
    /// and two logs that agree on an entry agree on everything before it.
    /// A slot of another term at exactly that index was superseded — the
    /// position went to another leader's entry. A slot of another term
    /// below it is left for the commit of its own entry (or of a later
    /// one in its term). Returns the count of newly committed slots.
    pub fn record_commit(&mut self, committed_term: u64, committed_index: u64) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.correlation_id == 0 || s.state != STATE_ASSIGNED {
                continue;
            }
            if s.assigned_term == committed_term && s.assigned_index <= committed_index {
                s.state = STATE_COMMITTED;
                n += 1;
            } else if s.assigned_index == committed_index {
                s.state = STATE_SUPERSEDED;
            }
        }
        n
    }

    /// Drain the next superseded slot, freeing it: its correlation id,
    /// for the caller to answer (and resubmit if it chooses).
    pub fn take_superseded(&mut self) -> Option<u64> {
        for s in self.slots.iter_mut() {
            if s.correlation_id != 0 && s.state == STATE_SUPERSEDED {
                let id = s.correlation_id;
                *s = InflightSlot::empty();
                return Some(id);
            }
        }
        None
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
                    STATE_COMMITTED => InflightState::Committed,
                    _ => InflightState::Superseded,
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

    /// Cancel all inflights. Returns the count freed. For a consumer that
    /// gives up on every proposal at a term jump rather than waiting for
    /// each to commit or be superseded.
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
/// and enforces monotonic commit-order delivery. MSG_COMMITTED_BATCH
/// carries the *current commit horizon*, not per-entry envelopes — so this
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
    /// reported by `consensus`. If the horizon advanced strictly
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
    /// `consensus.committed_entries`). Decodes into a borrowed
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
    /// - `index == cursor + 1` (no gaps). Gaps return
    ///   [`CommitOrderError::GapInPerEntryStream`] and the consumer
    ///   MUST recover via snapshot install ([`SnapshotInstaller`]).
    ///
    ///   Falling behind is NOT one of the ways to reach this error.
    ///   `consensus.committed_entries` is lossless under backpressure:
    ///   a refused write retains the entry and holds the producer's
    ///   `apply_index` behind it, so a slow consumer stalls its
    ///   producer instead of being skipped past. The check stands as a
    ///   defence against a consumer rebound to a different producer,
    ///   or against a regression in that contract — it should never
    ///   fire because of load.
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
/// the leader / durability when it answers a follower's snapshot
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
/// signals (currently emitted by `consensus.metrics`).
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
/// `admission.permits` — the consumer maintains the same fields locally
/// and asks the gate before answering a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadGateInputs {
    /// CP cache state observed from `admission.cache_state`
    /// (`CACHE_FRESH` / `CACHE_CACHED` / `CACHE_STALE` / `CACHE_EXPIRED`).
    pub cache_state: u8,
    /// `consensus`'s most recent commit horizon.
    pub raft_commit_index: u64,
    /// Local durability ledger's last fsynced index.
    pub durable_index: u64,
    /// True when the runtime has been told to fall back to Strict
    /// mode (e.g. via `admission.strict_fallback`). Blocks reads.
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
