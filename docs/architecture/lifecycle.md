# Replica Lifecycle

The phases a replica moves through over its lifetime: boot restore,
WAL replay, durability modes, strict fallback, snapshots, admin
operations, and membership. The replication-loop algorithms are in
[replication.md](replication.md).

## Table of Contents

1. [Boot and WAL replay](#boot-and-wal-replay)
2. [Durability modes](#durability-modes)
3. [Group-fsync batching](#group-fsync-batching)
4. [Strict fallback and the read gate](#strict-fallback-and-the-read-gate)
5. [Leader and follower lifecycle](#leader-and-follower-lifecycle)
6. [Admin operations](#admin-operations)
7. [Snapshot lifecycle](#snapshot-lifecycle)
8. [Membership changes and joint consensus](#membership-changes-and-joint-consensus)

---

<a id="startup-scrub-and-quarantine"></a>
## Boot and WAL replay

Boot runs in two stages: snapshot restore, then WAL replay.

**Snapshot restore** (`modules/app/durability/snapshot.rs`) reads the
pointer sidecar naming the durable local snapshot, loads and
CRC-validates the file it names, replays the application body to the
state machine (a reset followed by chunks), and signals
`MSG_SNAPSHOT_INSTALLED` to consensus so raft knows the log has a
floor. A file whose end magic or CRC does not check out is rejected
and the node falls back to its log. Snapshot files are written in one
sequential pass with a single trailing fsync, so a torn write never
leaves a readable trailer.

**WAL replay** (`modules/app/durability/wal.rs`) walks segment files
forward from the persisted segment-floor sidecar (or from sequence 1
when none exists), tolerating a bounded number of missing sequence
numbers so compaction gaps and fresh deployments both terminate the
scan cleanly. Within a segment it verifies each frame's CRC32C against
the shared frame contract (`modules/common/wal_frame.rs`) and stops at
the first torn or corrupt frame; everything before it is the durable
prefix. The write path later rewinds onto that tail and stages a
zero-length terminator, so stale bytes beyond it are never replayed as
valid. Startup verification is exactly this per-frame CRC walk — there
is no separate scrub pass, no index files to rebuild, and no
quarantine state. A `dek_epoch: u32` is stamped into snapshot headers
and rotated weekly by the keys component
(`modules/app/durability/keys.rs`), but nothing encrypts yet.

When replay finishes, the WAL freezes the recovered durable
high-water, seeds the durability ledger with it (replay produces no
fsync acks, and without the seed a recovered node's quorum tracking
would sit at zero), and emits `MSG_WAL_REPLAY_COMPLETE` carrying the
recovered `(term, index)`. This is the **boot handoff**: raft holds
proposal intake closed and answers AppendEntries with `busy` until the
signal lands, because appending at a stale persisted index hint would
collide with the replayed index space. The signal is re-emitted on a
bounded cadence in case the first frame is lost while the consumer
port is still coming up. The graphs wire it on a dedicated edge
(`durability.replay_complete → consensus.wal_replay_complete`) — the
comment in the deployment graph records why it must never be
multiplexed onto `wal.flushed`, which also fans out durability
acknowledgements.

Raft persists its own metadata (current term, vote, durable-index
hint) in `RAFT<pppp>.MET` on bare-metal FAT32 or `raft/meta`
otherwise, written before votes and term changes take effect.

---

<a id="durability-modes-and-io-writer-states"></a>
## Durability modes

Three modes, defined in `modules/common/types.rs` and selected by the
consensus module's `durability_mode` parameter (enum `strict=0`,
`group_fsync=1`, `relaxed=2`; default group_fsync):

- **strict** and **group_fsync** — the commit index is clamped to the
  quorum-durable index: an entry commits only once a quorum of
  replicas has fsynced it. The two differ on the WAL side, not the
  commit side (see the batching section below).
- **relaxed** — the clamp is dropped and the quorum match index
  commits directly. Acknowledged writes are replicated but not
  necessarily on stable storage anywhere; a simultaneous crash of a
  quorum can lose them. Volatile and benchmark graphs use this.

The WAL's write behaviour is a separate parameter, `fsync_mode`
(`modules/app/durability/wal.rs`): `0` fsyncs every entry before it is
acknowledged durable; `1` enables group-fsync batching.

<a id="3-monotone-epoch-enforcement"></a>
Mode changes ride `ADMIN_OP_DURABILITY_MODE`, which is replicated
through raft as an admin-magic proposal and applied at commit on every
replica; the raft component records the applied mode, while the commit
tracker's operating mode and the WAL's `fsync_mode` come from module
parameters fixed at composition time. There is no durability-mode
epoch, no mode-conflict RPC, and no io_uring writer-state machinery.
Independently of the configured mode, strict fallback (below) forces
the commit tracker's *effective* mode to strict.

---

## Group-fsync batching

With `fsync_mode = 1`, appended entries accumulate in a pending batch
and are flushed when any of three conditions is met: the batch reaches
`group_max_pending` entries (default 64), the batch age reaches
`group_window_ms` (default 2 ms; the flush timer runs even when no new
entries arrive, so a quiescent writer drains its tail), or a
truncation terminator has been staged. Segment rotation always flushes
first so acknowledgements stay ordered relative to the close.

On filesystem providers with the async durable-write tier, flushes are
fence-pipelined: up to `fence_depth` fsync fences stay outstanding at
once, each carrying the `(term, index)` high-water it covers, and
fences are reaped strictly in order so durability acknowledgements are
emitted in raft-log order. A failed fenced write latches a fail-stop
flag: the acknowledgement is withheld and no further writes proceed,
so the commit index can never advance past a non-durable entry. Each
completed fsync delivers the covered high-water to the in-module
durability ledger and emits `MSG_FSYNC_ACK` on the `flushed` port.

---

## Strict fallback and the read gate

`strict_fallback` is a flag, not a state machine. The admission
module's proof cache classifies control-plane proof age into Fresh,
Cached, Stale, and Expired; the flag is set exactly when the cache
state is Stale or Expired (`modules/app/consensus/commit.rs`), and the
proof cache broadcasts the same transition as `MSG_FALLBACK_SIGNAL`.

Its effects while set:

- The commit tracker's effective durability mode becomes strict, so
  commit is gated on quorum fsync regardless of the configured mode.
- The read-gate component stops emitting read permits, so linearizable
  reads time out and are rejected with `CLIENT_REJECT_FALLBACK`
  (see [replication.md](replication.md#read-gate-predicate)).
- Raft drops incoming client proposals, counted separately from
  freeze-driven drops so operators can tell the two gates apart.

The flag clears when a fresh control-plane proof returns the cache to
Fresh or Cached. There are no named fallback sub-states, no demotion
timers, no recampaign backoff, and no vote annotations — elections
proceed normally while the flag is set.

---

## Leader and follower lifecycle

Roles follow standard Raft: follower, candidate (pre-vote first, then
a real election), leader. Election timing, vote rules, the
current-term no-op fence, and conflict repair are described in
[replication.md](replication.md#elections-and-pre-vote).

Two flags modify a node's participation:

- **Learner mode** — set when a committed configuration change removes
  the node from the voter set. A learner never starts elections and
  never grants votes, but keeps replicating so it can rejoin promptly
  if re-added.
- **Frozen** — set by `ADMIN_OP_FREEZE`. Client proposals are dropped;
  admin-magic envelopes are exempt so the `THAW` that lifts the freeze
  can itself commit.

Followers never serve linearizable reads; the ReadIndex path answers
only on the leader, and there is no follower-read capability grant.

---

## Admin operations

Admin commands enter through the operations module
(`modules/app/operations/admin.rs`): HTTP `POST /admin/<op>` is
admitted by the rbac component and handed to the admin component as
`[conn_id][op_code][op_body]`. A command byte-identical to its
immediate predecessor within a 2 s window is collapsed as
`ADMIN_STATUS_DUPLICATE`; that in-memory retransmit dedup is the only
idempotency window, and the supported op set is double-apply-safe by
construction.

Supported ops and their routes:

| Op | Route | Effect |
|---|---|---|
| `FREEZE` / `THAW` | Replicated (admin-magic proposal, applied at commit) | Sets / clears the proposal-drop flag on every replica |
| `DURABILITY_MODE` | Replicated | Records the requested mode (see [Durability modes](#durability-modes)) |
| `TRANSFER_LEADER` | Local-only envelope to consensus | Leader sends `MSG_TIMEOUT_NOW` to the target and steps down; rejected on followers |
| `SNAPSHOT` | Local-only | Acknowledged, currently a no-op: snapshots are driven by segment rotation and the external trigger port, not by this op |
| `ADD_VOTER` / `REMOVE_VOTER` | — | `ADMIN_STATUS_UNSUPPORTED` (see membership below) |

Application replies ride `MSG_ADMIN_APPLIED` back through the admin
component, which answers the originating connection with
`MSG_ADMIN_RESPONSE`.

---

## Snapshot lifecycle

Snapshots are per-partition and manifest-plus-body
(`modules/app/durability/snapshot.rs`).

**Triggers.** The WAL fires a trigger at every segment rotation; an
external `trigger` port accepts `MSG_SNAPSHOT_TRIGGER` from admin
tooling or coordinators; and the replicator requests a re-broadcast
(`MSG_SNAPSHOT_INSTALL_REQUEST`) when a follower's `next_index` falls
below the leader's WAL retention floor. Every trigger passes the
retention-floor gate: a snapshot at index *n* implies compaction below
*n*, so any registered consumer floor still below *n* defers the
trigger.

**Capture.** With an application state machine wired, the engine
requests a state export (`MSG_APP_SNAPSHOT_REQUEST`) and accumulates
the body chunks strictly in order; the body's own `(term, index)` is
authoritative, since the application may have applied past the
trigger. A silent application is bounded by a capture timeout so a
wedged consumer costs one rotation's snapshot, not all of them.

**Persist.** The snapshot file carries a magic header, `(term, index)`
metadata, the `dek_epoch`, the body, a body CRC32C, and an end magic —
written sequentially with one trailing fsync, so it is crash-atomic
without a rename. Filenames are index-keyed and monotone. The manifest
authorisation port (`durability.manifest_auth`) broadcasts the durable
manifest to peers.

**Install transfer.** Leaders stream `MSG_INSTALL_SNAPSHOT` chunks —
a 33-byte header `[term][last_included_index][last_included_term]
[offset][done]` followed by up to 4 KiB of data — which the follower
accumulates strictly in order; a gap or oversize aborts the attempt
and waits for the leader to restart it. On `done`, the follower
durably persists the snapshot before signalling
`MSG_SNAPSHOT_INSTALLED`; a failed persist withholds the signal so
consensus never trusts a torn body. On receiving the signal, raft
fast-forwards its log state to the snapshot point, resets the apply
pipeline, and emits the WAL compaction floor
([replication.md](replication.md#compaction)). There are no bandwidth
budgets, size targets, or manifest signing.

---

## Membership changes and joint consensus

> **Status note.** The current substrate has the joint state machine
> in `consensus`'s raft component (`CONFIG_CHANGE_OP_JOINT`/`_NEW`,
> voter-set overlay, auto-`C_new` on commit) and joint-aware quorum
> logic in its commit component — the voter-set update is delivered
> between them inside the module, in the same step raft applies the
> configuration change. One downstream piece is unfinished: the ledger
> component of `durability` does not consume `MSG_VOTER_SET_UPDATE`
> and uses the fixed-`voter_count` quorum median, so union quorum is
> not enforced on the durability side during the joint phase.
>
> The admin component of `operations` accordingly returns
> `ADMIN_STATUS_UNSUPPORTED` for `ADD_VOTER` / `REMOVE_VOTER`. The
> safe gate stays closed until union quorum reaches the ledger.

What the implemented state machine does when a configuration entry
commits (`modules/app/consensus/raft.rs`):

- **`CONFIG_CHANGE_OP_JOINT`** enters the joint phase: the current
  voter set is kept and the new set is layered as a joint overlay.
  From that step on, elections, ReadIndex probes, and the commit
  tracker's quorum all require majorities of **both** sets (the commit
  tracker takes the minimum of the two medians). The leader
  automatically queues the matching `C_new` entry, which is emitted in
  its own clean log slot on a subsequent tick.
- **`CONFIG_CHANGE_OP_NEW`** exits the joint phase: the new set
  becomes current and the overlay clears. A node absent from the new
  set steps down if it was leader and enters learner mode — no
  elections, no vote grants — and leaves learner mode again if a later
  change re-adds it. Both ops deduplicate replayed entries.

Vote responses and probe confirmations from nodes outside the active
voter set(s) never move a tally — the guard against an ex-voter's
ballot electing a second leader after a downsize. There is no
preflight validation, learner catch-up protocol, finalise window, or
rollback entry; the admin gate stays closed until the durability
ledger is joint-aware.
