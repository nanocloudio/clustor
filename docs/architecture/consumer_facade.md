# Consumer Facade (`replica_facade`)

The module graph at [modules.md](modules.md)
expresses clustor as a set of cooperative modules connected by
mailbox channels. Downstream consumers — Loam, Lattice, future
siblings — attach their own fluxor module to a small set of those
ports and exchange messages using the wire envelopes defined in
`modules/common/wire.rs`.

This document is the contract for that attachment surface.

The typed Rust helper that implements the encoding and lifecycle
bookkeeping lives at `modules/common/replica_facade.rs`. Consumer
modules include it the same way they include `wire.rs` and `types.rs`:

```rust
#[path = "../common/replica_facade.rs"]
mod replica_facade;
```

The file is `#![allow(dead_code)]` and pure logic — no `unsafe`, no
`SyscallTable` use — so it compiles under both the embedded `no_std`
module build and the host-side `cargo test` build. Integration tests
at `tests/facade.rs` exercise the same file unchanged.

## Table of Contents

1. [Semantic contract](#semantic-contract)
2. [Bounded, opaque commands](#bounded-opaque-commands)
3. [Propose lifecycle](#propose-lifecycle)
4. [Per-entry committed stream](#per-entry-committed-stream)
5. [Membership and topology invariance](#membership-and-topology-invariance)
6. [Leader change](#leader-change)
7. [Snapshot install and export](#snapshot-install-and-export)
8. [Read-gate inputs](#read-gate-inputs)
9. [Invariants and out-of-scope](#invariants-and-out-of-scope)
10. [Test surface](#test-surface)
11. [Per-entry stream configuration](#per-entry-stream-configuration)

---

## Semantic contract

Conceptually the facade implements the following trait shape:

```rust
pub trait ReplicaGroup {
    fn propose(&self, command: Vec<u8>)
        -> impl Future<Output = Result<CommitAck, ProposeError>>;
    fn subscribe_committed(
        &self,
        handler: Box<dyn Fn(CommittedEntry) -> Result<(), ApplyError> + Send + Sync>,
    );
    fn install_snapshot(
        &self,
        chunks: impl Stream<Item = SnapshotChunk>,
        manifest: SnapshotManifest,
    ) -> impl Future<Output = Result<(), SnapshotError>>;
    fn export_snapshot(&self, at_index: u64)
        -> impl Stream<Item = Result<SnapshotChunk, SnapshotError>>;
    fn members(&self) -> Vec<ReplicaId>;
    fn leader(&self) -> Option<ReplicaId>;
    fn read_gate_inputs(&self) -> ReadGateInputs;
}
```

The implementation expresses each method as a
channel-driven exchange. Each consumer module owns its own
`InflightTable`, `CommittedSubscriber`,
`SnapshotInstaller` / `SnapshotExporter`, `MembershipView`, and
`ReadGateInputs`. The helpers in
`modules/common/replica_facade.rs` define the encode/decode and
bookkeeping that step-mode poll loops use.

There is no `Future`-typed return value — work completes when the
consumer's step observes the matching wire message — but the
**semantic** contract holds:

- `propose(command)` returns on commit, where "commit" means
  "the consumer observed a `MSG_COMMITTED_BATCH` whose
  `index ≥ assigned_index`".
- For a single-replica group, commit is reached as soon as local
  durability acks. For an N-replica group, commit is reached when
  quorum durability acks. **Same code path** in the consumer.
- `subscribe_committed` delivers strictly in commit order on every
  replica.
- Snapshot install is atomic: chunk receipt is observable, but the
  consumer's commit cursor only jumps after
  `SnapshotInstaller::finalize` returns success.
- `read_gate_inputs` reflects the consumer's most recent view of
  the CP cache state and durability / commit indexes.

---

## Bounded, opaque commands

The maximum opaque command size is `MAX_COMMAND_BYTES = 4096` bytes,
enforced by `replica_facade::build_tagged_proposal`. Bodies above
this cap are rejected at the consumer boundary; oversized commands
never reach `raft_engine`'s proposal port.

The cap is intentionally small — clustor orders identity-bearing
metadata, never bulk content. Object bodies, EC shards, cache
contents, and other bulk data travel out-of-band. (Cross-reference:
Loam's BODY-OUT-OF-RAFT invariant.)

Empty commands and `correlation_id == 0` are rejected. Zero is
reserved by `raft_engine` as the "untagged" marker that suppresses
`MSG_PROPOSAL_ASSIGNED` emission.

Command bytes are opaque to clustor. `raft_engine`, `wal`,
`commit_tracker`, and `apply_pipeline` do not inspect, parse, or
schema-validate command bodies. Consumers own their own command
schema.

---

## Propose lifecycle

A tagged proposal walks through four states across two channels.

### 1) Build

The consumer calls `build_tagged_proposal(buf, correlation_id, body)`
to encode an `8-byte correlation_id || body` payload. The payload
is wrapped in `MSG_CLIENT_PROPOSAL` (3-byte envelope) or its
partitioned variant (5-byte) and written to
`raft_engine.proposals_tagged` (or `proposals_partitioned_tagged`).

The consumer also calls `InflightTable::register(correlation_id)`
so the result can be matched later. Capacity exhaustion returns
`ProposeError::InflightTableFull { capacity }` and the consumer
drains commit acks before issuing more proposals.

### 2) Assign

When the leader flushes a batch, it emits
`MSG_PROPOSAL_ASSIGNED { correlation_id, partition_id, wal_index }`
on `proposal_assigned`. The consumer matches against its inflight
table via `InflightTable::record_assignment(correlation_id, wal_index)`.
An assignment for an unknown `correlation_id` (e.g. cancelled after
a leader change) is silently dropped.

### 3) Commit

`commit_tracker.committed` emits
`MSG_COMMITTED_BATCH { term, index }` whenever its commit horizon
advances. The consumer feeds it to
`CommittedSubscriber::ingest_committed_batch`, which enforces
monotonic ordering, then calls
`InflightTable::record_commit(term, index)` to promote any
in-flight whose `assigned_index ≤ index` to `Committed`.

### 4) Drain

The consumer calls `InflightTable::take_committed()` in a loop to
release the resulting `(correlation_id, CommitAck)` pairs to its
own API surface.

---

## Per-entry committed stream

`MSG_COMMITTED_BATCH` is a horizon update — it carries only
`(term, index)` and never the command bytes. A consumer that needs
to **apply** entries deterministically (i.e. transform local state
by interpreting the command) wires its own input to
`apply_pipeline.committed_entries`, which emits
`MSG_COMMITTED_ENTRY { term, index, body }` per committed entry in
strict commit-index order.

The fanout chain:

```
raft_engine.log_observe ──► apply_pipeline.log_entries
                                        │
                            commit_tracker.committed ──► apply_pipeline.entries
                                        │
                            apply_pipeline.committed_entries ──► consumer
```

`raft_engine` writes every appended entry to **both** `log_append`
(to WAL, durability-load-bearing) and `log_observe` (fanout to
observers, non-load-bearing). `apply_pipeline` buffers up to
`PENDING_ENTRY_SLOTS = 32` entries by index and drains them onto
`committed_entries` once the commit horizon advances past their
index.

Backpressure on the observer ring fails open: under sustained
back-pressure the oldest un-emitted slot is evicted, the consumer
observes a gap, and recovery is via snapshot install
(`SnapshotInstaller::reset_to`).

### Per-entry ingest contract

Consumers use `CommittedSubscriber::ingest_committed_entry(payload)`
(NOT `ingest_committed_batch`) when wired to `committed_entries`.
The per-entry method enforces:

- `index == cursor + 1` — no gaps. Gaps return
  `CommitOrderError::GapInPerEntryStream`.
- `index > cursor` — no duplicates. Duplicates return
  `CommitOrderError::NonMonotonicIndex`.
- `payload.len() >= COMMITTED_ENTRY_HDR` — malformed envelopes are
  rejected.

### Choosing a delivery mode

| Delivery | Channel | Use case |
|---|---|---|
| Horizon-only | `commit_tracker.committed` (`MSG_COMMITTED_BATCH`) | Consumer only needs commit watermarks (e.g. ack-on-commit RPCs) |
| Per-entry | `apply_pipeline.committed_entries` (`MSG_COMMITTED_ENTRY`) | Consumer applies bodies to a state machine |

A consumer may wire both. `CommittedSubscriber` permits interleaved
calls to `ingest_committed_batch` and `ingest_committed_entry`,
with the cursor advancing monotonically across both call paths.

---

## Membership and topology invariance

`MembershipView::voter_count` and `MembershipView::self_id` are
static configuration. `MembershipView::leader` is mutated by the
consumer when it observes a leader-changed signal (e.g. a new term
in `raft_engine.metrics`). `members()` returns the configured voter
set; dynamic membership reconfiguration is out of scope for this
surface.

**A single-replica graph (`voter_count == 1`) walks the same facade
contract as a multi-replica graph.** The commit horizon advances
faster, but `propose → assign → commit → drain` is the same code
path. Consumer code does not branch on cluster size.
(Cross-reference: Loam's TOPOLOGY-INVARIANT.)

---

## Leader change

When a consumer observes a term jump on its leader (via
`raft_engine.metrics`), the safe protocol is:

1. Call `InflightTable::cancel_all()` to drop the entire pending
   set.
2. Re-propose with fresh `correlation_id`s if the consumer is the
   originator.
3. Drop any late `MSG_PROPOSAL_ASSIGNED` arriving after the cancel.
   `record_assignment` returns `None` for unknown correlations and
   takes no other action.

This protocol is conservative. Some of the assigned-but-not-committed
proposals may have actually been replicated by the new leader. The
cost of re-proposing them is a duplicate entry the consumer's own
dedup logic filters; the cost of returning a stale `CommitAck` to a
caller is a correctness violation. The facade favours conservative
cancellation.

---

## Snapshot install and export

### Exporter

`SnapshotExporter::new(partition_id, target_index)` is constructed
by the serving replica when a follower requests a snapshot. The
exporter emits zero or more `MSG_SNAPSHOT_CHUNK` payloads
(`[seq:u32 LE][len:u32 LE][bytes:len]`) followed by exactly one
`MSG_SNAPSHOT_MANIFEST` of length `SNAPSHOT_MANIFEST_LEN = 32`.

### Installer

`SnapshotInstaller::new(partition_id, expected_index)` is
constructed by the receiving follower. Chunks arrive in sequence
order starting at `seq = 0`; a gap or reorder yields
`SnapshotError::ChunkOutOfOrder { expected, observed }` and the
follower restarts the install from scratch. The trailing manifest's
magic, `partition_id`, and `commit_index` match the installer's
expectations; a mismatch yields `SnapshotError::ManifestMismatch`.
On success `finalize` returns a `CommitAck` the follower seeds into
its `CommittedSubscriber`.

### Manifest record layout (32 bytes)

```
[0..4]   = 0x534E_4150 ("SNAP") little-endian
[4..6]   = partition_id LE
[6..8]   = reserved = 0
[8..16]  = term LE
[16..24] = commit_index LE
[24..28] = dek_epoch LE
[28..32] = reserved = 0
```

---

## Read-gate inputs

`ReadGateInputs` mirrors the inputs `read_gate` consumes. Consumers
populate the four fields from the following sources:

| Field | Source |
|---|---|
| `cache_state` | Most recent `MSG_CACHE_STATE` from `cp_proof_cache` (`CACHE_FRESH` / `CACHE_CACHED` / `CACHE_STALE` / `CACHE_EXPIRED`) |
| `raft_commit_index` | The consumer's `CommittedSubscriber::cursor()` |
| `durable_index` | Most recent `MSG_DURABILITY_PROOF` index from `durability_ledger` |
| `strict_fallback` | Latched true on `MSG_FALLBACK_SIGNAL` |

`ReadGateInputs::can_read()` returns the read-gate verdict:

```
can_read = !strict_fallback
        && cache_state <= CACHE_CACHED
        && raft_commit_index == durable_index
```

This is the same predicate `read_gate` evaluates locally. The
duplicate copy in the consumer lets reads be admitted without a
cross-core permit round-trip when the consumer is co-located on the
same core as `read_gate`.

---

## Invariants and out-of-scope

- The facade adds no control-plane state, no new wire envelopes, and
  no new Raft semantics. It is strictly a typed encode/decode plus
  state-bookkeeping layer over the existing module graph.
- Dynamic membership reconfiguration
  (`add_replica` / `remove_replica`) is **out of scope**.
  `MembershipView::members()` is read-only for this contract; a
  future surface will gate joint-consensus transitions.
- Bulk data transfer is **out of scope**. The
  `MAX_COMMAND_BYTES = 4096` cap is enforced and consumers partition
  bulk payloads out-of-band.

---

## Test surface

- **Host-side `cargo test`** covers the encode/decode and
  state-machine layers (`tests/facade.rs` plus the inline
  `#[cfg(test)]` module in `modules/common/replica_facade.rs`,
  49+ tests). This is the primary regression net for per-entry
  ordering, inflight correlation, snapshot framing, and bounded-size
  invariants.
- **Real fluxor module integration** is proved by
  `modules/example_consumer/`, a minimal `no_std` module that
  `#[path]`-includes `replica_facade.rs` and wires to
  `apply_pipeline.committed_entries`. `make modules` rebuilds it
  alongside every clustor module on every CI run — the gate that
  catches `no_std` regressions in the facade or in the per-entry
  emitter.
- **End-to-end multi-node scenarios** — 3-replica propose with all
  members acking, 3-replica propose with one member offline,
  propose-fails-when-quorum-unreachable, leader-change replay,
  follower snapshot install, oversized-command rejection, read-gate
  index tracking — live in the Rust harness at `tests/cluster.rs`.
  Each scenario spawns real `fluxor-linux` instances via
  `std::process::Command` and asserts against logs, `/readyz`, and
  `/metrics`. Long-term tooling for clustor is Rust-only — no
  Python harness in `tests/` or `make ci`.

---

## Per-entry stream configuration

To receive `MSG_COMMITTED_ENTRY` on the consumer side, the
deployment graph wires two edges:

```yaml
- from: raft_engine.log_observe
  to: apply_pipeline.log_entries
  edge_class: cross_core

- from: apply_pipeline.committed_entries
  to: <consumer-module>.committed_entries
  edge_class: cross_core
```

Without the first edge, `apply_pipeline` never sees the entry
bodies and `committed_entries` stays silent. Without the second,
the fanout has no destination. Both edges are optional from the
consensus core's standpoint — omitting them does not affect quorum,
durability, or read-gate behaviour. `configs/clustor.yaml` wires
the first edge into `apply_pipeline.log_entries` by default; the
second is consumer-specific and lives in the downstream graph
(see `modules/example_consumer/manifest.toml` for the port shape).
