# Substrate Capability Surface

The exact set of signals a replicated-state-machine consumer relies
on for durability, replication, and reconstruction. Anything not
enumerated here is a **capability leak** — a hidden assumption that
would break the moment the substrate is swapped for a different
implementation (a single-node WAL, a managed-Raft service, a test
harness mock).

This document is the normative contract. Clustor is the canonical
provider today; the typed Rust helpers a consumer compiles against
live at [`../../modules/common/replica_facade.rs`](../../modules/common/replica_facade.rs)
and the prose contract for those helpers is
[consumer_facade.md](consumer_facade.md). This document is the
narrower, implementation-agnostic peer of those — it speaks in
primitives, not types.

If a consumer module reaches beyond this surface — or this document
ever drifts from what implementations actually emit — one of them
gets updated, never silently both.

## Design intent

The consumer/substrate boundary is shaped to satisfy four
properties simultaneously:

1. **Replayable.** A restarting node, given the substrate's
   committed log (or a snapshot + tail), reconstructs the same
   apply-derived state it had before the crash.
2. **Replicable.** A follower receiving committed entries arrives
   at the same state as the leader without ever observing client
   proposals.
3. **Substitutable.** A single-node deployment can replace clustor
   with a local WAL implementing this surface — no consumer module
   change. See [§Single-node stand-in](#single-node-stand-in).
4. **Narrow.** Every primitive listed below is load-bearing.
   Adding one must change at least one consumer module's behaviour
   or it doesn't belong here.

## Surface

Seven primitives. The shapes here are the contract; the wire-level
byte encodings live in [`../../modules/common/wire.rs`](../../modules/common/wire.rs)
and are stable once shipped (see
[architecture/compatibility.md](compatibility.md) for the
versioning rules).

### 1. `proposals` (untagged)

**Direction.** Consumer → substrate.
**Shape.** Opaque body bytes. Wire opcode `MSG_CLIENT_PROPOSAL`.
The substrate treats the body as opaque and replicates / commits
it verbatim.
**Used by.** Any fire-and-forget consumer op — admin signals,
keep-alives, anything whose protocol-level ACK is not gated on
durability.
**Substrate guarantees.** If accepted, the body reaches every
node's committed-entry stream in commit order. No durability ack
to the proposer (it didn't ask for one).

### 2. `proposals_tagged` (tagged)

**Direction.** Consumer → substrate.
**Shape.** `[correlation_id:u64 LE][body]`. Wire opcode
`MSG_CLIENT_PROPOSAL` on a distinct input port.
`correlation_id` is consumer-allocated, nonzero, unique per
outstanding proposal.
**Used by.** Ops whose protocol-level ACK is gated on durability.
**Substrate guarantees.** Same as `proposals` for the `[body]`
part, plus a `proposal_assigned` echo (§3) and an eventual
`quorum_durable` notice (§5) keyed by `correlation_id`.

### 3. `proposal_assigned` (early-ack echo)

**Direction.** Substrate → consumer.
**Shape.** `MSG_PROPOSAL_ASSIGNED`,
`[correlation_id:u64 LE][partition_id:u16 LE][wal_index:u64 LE]`
— `PROPOSAL_ASSIGNED_LEN = 18` bytes.
**Used by.** Consumer-side correlation tables binding
`correlation_id` → consumer-private metadata (session slot, packet
id, op type) before durability lands.
**Substrate guarantees.** Emitted exactly once per tagged proposal
that was accepted into the local WAL — *before* commit, *before*
quorum durability. The `(partition_id, wal_index)` tuple is the
canonical key for the proposal until it commits; downstream
durability matching (§5) keys on this tuple, not on `wal_index`
alone — a single consumer process may host replicas of multiple
partitions.

### 4. `committed_entries` (per-entry stream)

**Direction.** Substrate → consumer.
**Shape.** `MSG_COMMITTED_ENTRY` envelopes with body
`[term:u64 LE][index:u64 LE][entry_body]`.
**Used by.** The single source of truth for durable state
mutations on the consumer side.
**Substrate guarantees:**
- Monotone by `index`, gap-free across snapshot boundaries.
- Delivered in commit order; an entry is never re-delivered on
  the leader unless the apply reset (§7) precedes it.
- `entry_body` is byte-identical to the body the proposer
  submitted (or `[correlation_id][body]` for tagged proposals
  — consumers strip the correlation prefix using the same wire
  layout they encoded with).

### 5. `quorum_durable` (durability notifier)

**Direction.** Substrate → consumer.
**Shape.** `MSG_DURABILITY_PROOF`,
`[partition_id:u16 LE][term:u64 LE][index:u64 LE][replica_id:u8]`
— `DURABILITY_PROOF_LEN = 19` bytes.
**Used by.** Consumer-side ack emission for tagged proposals.
**Substrate guarantees.** Emitted exactly when an entry has
reached quorum durability across the replica set. This is what
makes the **ACK-DURABILITY invariant** load-bearing — there is no
path from "WAL written locally" to "consumer emits protocol ACK"
that skips this signal. Any consumer that elides the wait and
acks earlier breaks the substitutability claim (a substrate
guaranteeing only `local-fsync` durability would silently regress).

### 6. Snapshot install / export

**Direction.** Bidirectional via substrate-invoked callbacks on
the consumer module.
**Shape.** Consumer-owned opaque payload. The substrate
transfers the bytes across the wire and commits them; it does not
interpret them.
**Used by.** Cold-start state reconstruction, follower catch-up,
and any newly-placed replica that needs to skip log replay.
**Substrate guarantees:**
- **Export hook** fires when the substrate decides to take a
  snapshot. The consumer returns a self-describing payload
  covering all apply-derived state.
- **Install hook** fires when the substrate has received a
  snapshot (from peer or disk). The consumer re-creates state
  from the payload, then receives the apply reset (§7)
  with the new apply index, then resumes consuming
  `committed_entries` from `reset_index + 1`.
- Snapshot ordering is consistent with the committed-entry
  stream: a snapshot at index N reflects exactly the state a
  consumer would have after applying entries 0..=N.

### 7. Apply reset

**Direction.** Substrate → consumer.
**Shape.** The apply-reset envelope (opcode `0x2B` in
[`../../modules/common/wire.rs`](../../modules/common/wire.rs)) with
body `[term:u64 LE][index:u64 LE]` — same body shape as
`MSG_COMMITTED_BATCH`, distinct opcode.
**Used by.** Every apply-derived arena in the consumer.
**Substrate guarantees.** Emitted when the substrate's notion of
"next apply index" has rewound — snapshot install, leader-
driven log truncation, or any other event that invalidates
already-applied state. After this signal, every consumer module
must:

1. Discard all apply-derived state with `apply_index > reset_index`.
2. Re-emit state from the new snapshot if one is being installed.
3. Resume consuming `committed_entries` starting at `reset_index + 1`.

This is **not** a "best effort" advisory. A consumer that doesn't
honour the reset can diverge from the substrate's view of
replicated state and will produce subtly wrong acks and fanouts
after the next leader change.

## What is NOT in the surface

The following signals are visible to consumer modules in a typical
deployment graph but MUST NOT be the source of truth for any state
the consumer claims durability for. They are **operational**
signals — useful for admission control, backpressure, and
diagnostics, never for replicated state.

- `MSG_THROTTLE_CREDITS`, `MSG_BP_SIGNAL` — admission-side
  backpressure. Used only on the ingress path. Followers do not
  observe these and do not need them.
- `MSG_LAG_SIGNAL` — flow-control hint emitted by consumers,
  consumed by routers. Not authoritative state.
- `MSG_CP_PROOF`, `MSG_CACHE_STATE`, `MSG_FALLBACK_SIGNAL`,
  `MSG_EPOCH_EVENT` — control-plane freshness signals from
  `control_plane` and `admission`. These gate read responses and
  fence in-flight state on epoch flips, but they carry no durable
  payload — see [consumer_facade.md §Read-gate inputs](consumer_facade.md#read-gate-inputs)
  for the predicate consumers evaluate against them.
- `MSG_PLACEMENT_UPDATE` — operational; consumed by routing
  modules. Routing state itself is replicated through the
  committed-entry stream like any other apply-derived state.

The test: if removing a signal changes which response a client
sees, it belongs in the seven primitives above. If it changes
*when* a response is sent or *how fast* a request is admitted, it
is an operational signal and does not belong here.

## Single-node stand-in

A "no replication" stand-in substrate (for embedded use, dev
rigs, or test harnesses) implements the seven primitives as
follows:

| Primitive | Stand-in behaviour |
|---|---|
| `proposals` | Append body to local WAL, fsync, emit on `committed_entries` immediately. |
| `proposals_tagged` | Same as above, plus immediate `proposal_assigned` echo and immediate `quorum_durable`. |
| `proposal_assigned` | `partition_id = 0`, `wal_index = local WAL offset`. |
| `committed_entries` | Pass-through from the local WAL append, in WAL order. |
| `quorum_durable` | Fired the moment the WAL fsync returns (local fsync *is* the durability for a single-node deployment). |
| Snapshot hooks | Read / write a single file at a configured path. |
| Apply reset | Fired on cold start after snapshot install. |

A consumer binary that runs against a 3-replica clustor cluster
runs against this stand-in unchanged — only the YAML wiring
differs. That is the substitutability contract this surface
exists to defend.

## Versioning

The surface above is **v1**. Additions are allowed; removals and
shape changes require a version bump and a documented upgrade
path. The surface version is independent of:

- The wire-protocol version (per-opcode envelope shapes, see
  [wire.md](wire.md)).
- Any consumer's internal payload version byte (a consumer that
  versions its `entry_body` opaquely is invisible to the surface).

A provider advertises which surface version it implements; a
consumer manifest declares which surface version it requires. The
`fluxor` build resolver fails fast when these disagree, the same
way it fails on an ABI mismatch (see
[`../../fluxor.toml`](../../fluxor.toml) `[required]` block).

## Consumer pointers

Every consumer module that consumes a primitive carries a
`// see docs/architecture/substrate_capability_surface.md §N`
comment at the use site, so a reader chasing one signal's contract
lands here directly. The mapping for in-tree consumers:

| Primitive | Where it's consumed in clustor |
|---|---|
| `proposals` | `gateway`'s codec component (untagged op intake) |
| `proposals_tagged` | `gateway`'s codec component (correlation-bound intake) |
| `proposal_assigned` | `gateway`'s codec component, `replica_facade::InflightTable` |
| `committed_entries` | `consensus.committed_entries` → downstream consumer modules |
| `quorum_durable` | `durability`'s ledger component → `consensus`'s commit component → consumer ack paths |
| Snapshot hooks | `durability`'s snapshot component (orchestration); consumer modules implement the install/export callbacks |
| Apply reset | Every apply-derived arena in the consumer |

Downstream projects (Lattice, Loam, Quantum, Chronicle, …) carry
their own mapping table inside whichever doc anchors their adapter
layer.

## See also

- [consumer_facade.md](consumer_facade.md) — typed Rust helpers
  (`build_tagged_proposal`, `InflightTable`, `CommittedSubscriber`,
  `SnapshotInstaller` / `SnapshotExporter`, `MembershipView`,
  `ReadGateInputs`) that implement the consumer side of this
  surface.
- [replication.md](replication.md) — how the substrate produces
  the guarantees above (elections, AE flow, durable watermarks,
  read gate, compaction).
- [wire.md](wire.md) — opcode catalog and byte layouts for every
  `MSG_*` referenced here.
- [../proposal_correlation.md](../proposal_correlation.md) — the
  protocol that binds primitives 2 and 3 together.
