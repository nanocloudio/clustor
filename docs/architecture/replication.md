# Replication and Read Safety

The replication loop as implemented — elections, log replication and
conflict repair, the quorum-fsync durability path, the read gate, flow
control, and compaction. [lifecycle.md](lifecycle.md) covers the states
a replica passes through; [concepts.md](concepts.md) defines the
vocabulary; [wire.md](wire.md) defines the byte shapes. Everything
here is grounded in the `consensus`, `durability`, and `admission` sources.

## Table of Contents

1. [Elections and pre-vote](#elections-and-pre-vote)
2. [Log replication and conflict repair](#log-replication-and-conflict-repair)
3. [Durability and the quorum-fsync path](#durability-and-the-quorum-fsync-path)
4. [Agreement without durability](#agreement-without-durability)
5. [ACK contract](#ack-contract)
6. [Read gate predicate](#read-gate-predicate)
7. [Flow control](#flow-control)
8. [Compaction](#compaction)

---

## Elections and pre-vote

The election timeout is a single configured value, `election_timeout_ms`
(default 1000 ms), not a range. Each deadline re-arm adds random jitter
of up to roughly half the timeout, drawn from a xorshift generator
seeded with the node's `self_id` so co-timed followers never draw
correlated jitter. Heartbeats fire every `heartbeat_interval_ms`
(default 150 ms); the shipped configs set 150. Both parameters live in
`modules/app/consensus/mod.rs`.

When a follower's deadline expires it starts a **pre-vote** round: it
becomes a candidate but does not bump `current_term` or persist a vote.
Pre-vote requests carry `current_term + 1`; peers answer without
adopting the term or recording a ballot, granting whenever the
candidate's log is at least as up to date as their own. Only when the
pre-vote gathers a majority does the candidate start the real election
— incrementing the term, voting for itself, and persisting
`(current_term, voted_for)` to the raft metadata file before any
request leaves the node.

Vote-grant rules (`raft::handle_vote_request`): the request's term must
be at least the local term, the node must not have voted for someone
else this term (pre-votes are exempt), the candidate's log must be at
least as up to date, and the granter must be a voter — a node in
learner mode never grants. Real-vote responses count only when they
echo the candidate's exact term, and only ballots from the active voter
set (both sets while a joint configuration is active) move the tally.

On winning, the leader appends a current-term no-op entry and arms a
**term fence** in the commit tracker: until the no-op itself has
quorum, the commit index may not advance by counting replicas —
prior-term entries commit only transitively (the Raft figure-8 rule).
It also sends an immediate heartbeat.

`ADMIN_OP_TRANSFER_LEADER` is honoured by sending `MSG_TIMEOUT_NOW` to
the target replica and stepping down to follower, giving the target a
head start on its election. There is no lease mechanism, no leader
stickiness timer, and no RTT-adaptive timeout: leadership changes are
driven entirely by election timeouts, higher terms, and explicit
transfer.

---

## Log replication and conflict repair

Leaders coalesce client proposals into batches of at most
`MAX_ENTRY_BODY` (2048) bytes — one batch becomes one WAL entry. Two
backpressure gates hold proposal intake: the log may not run more than
48 entries ahead of the commit index (`MAX_UNCOMMITTED_INFLIGHT`), and
not more than 256 entries ahead of the node's own durable index
(`MAX_WAL_UNACKED`). When either gate closes, proposals queue upstream
in their channels and the admission throttle backpressures.

The replicator ships one entry per AppendEntries RPC, each carrying
`(prev_log_index, prev_log_term)` for log matching. Followers apply
the frame in strict order:

1. **Stale term** — reject.
2. **Gap** (`prev_log_index > last_log_index`) — NACK; the response
   carries the follower's real `last_log_index` so the leader backs
   `next_index` up in one step instead of decrementing.
3. **Term conflict at `prev_log_index`** — truncate the local log back
   to `prev_log_index − 1` and NACK. Truncation is forwarded to the
   WAL as `MSG_WAL_TRUNCATE_AFTER`; the WAL rewinds its write cursor to
   the end of the kept entry's frame and writes a zero-length
   terminator so replay never resurrects the discarded suffix
   (`modules/app/durability/wal.rs`).
4. **Retransmit** of an index already held with a matching term —
   acknowledged at that index without re-appending.
5. **Clean append** — contiguity is enforced (`entry_index` must be
   exactly `last_log_index + 1`), oversize bodies are rejected, and
   the entry is written to the WAL channel before the follower's log
   state advances. If the WAL channel is full the follower answers
   `busy`, and the leader retries the same entry rather than entering
   log repair.

Only the uncommitted tail can diverge, so followers keep a small
(index → term) ring for conflict checks; indices at or below the
commit index are trusted to match.

Followers that miss entry bodies (post-restart, or a fan-out gap)
refetch them from the WAL by index over the
`entry_request`/`entry_reply` channel pair. Each in-flight refetch
keeps a stable `request_id` until its reply arrives or a TTL expires —
the table is keyed by `(peer, index)` and capped, so retries never
invalidate a reply already in transit.

---

<a id="ledger-ordering-and-replay"></a>
## Durability and the quorum-fsync path

Ground truth for durability is the WAL frame contract
(`modules/common/wal_frame.rs`): each entry is stored as
`[entry_len: u32 LE][crc32c: u32 LE][payload]`, where the CRC32C
(Castagnoli) covers the payload only, the payload begins with a
16-byte `[term][index]` prologue, and the body after the prologue is
capped at 2048 bytes. A frame whose length field is zero, over the
cap, or running past the readable region is torn; replay stops at the
first torn or corrupt frame and everything before it is the durable
prefix. There is no sidecar durability log and no per-entry durability
record — the WAL frames plus the acknowledgement flow below are the
whole mechanism.

The flow, leader side:

1. The WAL persists the entry (per-entry fsync, or group-fsync
   batching — see [lifecycle.md](lifecycle.md#durability-modes)) and,
   once the covering fsync completes, reports its durable high-water:
   in-module to the durability ledger, and to consensus on the
   `flushed` port so the node tracks its own
   `local_wal_durable_index`.
2. Followers stamp their `local_wal_durable_index` into every
   AppendEntriesResponse. The leader's replicator forwards each
   advance as a synthesised `MSG_FSYNC_ACK` to the durability module's
   `ack` port.
3. The **ledger** (`modules/app/durability/ledger.rs`) is an in-memory
   quorum tracker: a per-replica array of durable indices. When any
   slot advances it recomputes the quorum-durable index (the median
   over the voter count) and, on an advance, emits
   `MSG_DURABILITY_PROOF` — a leader-side artefact, since followers
   only ever see their own slot move.
4. The commit tracker (`modules/app/consensus/commit.rs`) consumes the
   proof as its `durable_index` and computes the commit index as
   `min(quorum match index, durable_index)` in the strict and
   group_fsync modes. In relaxed mode the durable-index clamp is
   dropped and the quorum match index commits directly; because the
   leader's own slot in the match array is otherwise fed by durability
   proofs, relaxed mode seeds it from the leader's log tip each step:
   with no barrier to wait for, "self has the entry" is exactly "self
   appended the entry". The current-term fence from the election no-op
   applies in every mode.

<a id="commit-visibility-modes"></a>
There are no named commit-visibility modes: what a read can observe is
fixed by the durability mode's commit gating above, and linearizable
reads are additionally fenced by the read gate below.

The ledger pairs each proof's index with a term bound derived from the
supporting replicas' ack terms, so a proof never names a term ahead of
its index. A proof that cannot be delivered because the channel is
momentarily full is latched and retried every step — deferred, never
dropped.

---

<a id="agreement-without-durability"></a>
## Agreement without durability

Raft gives two separable guarantees: **agreement** (a single leader,
one ordered log, entries applied identically on every replica) and
**durability** (agreed state survives restarts). Everything above this
section builds the second on top of the first; the first also stands
alone, and clustor composes it as a declared posture rather than a
degraded mode.

An agreement-only node combines three settings:

- the durability module's `volatile` variant: entry retention is
  in-memory, the ledger component is compiled out, and the `ack` /
  `quorum_durable` ports are structurally absent, so the composition
  *cannot* emit a durability proof (a graph that expects one fails
  validation rather than running against fabricated acks);
- the consensus module's `durability_mode: relaxed`: commit is the
  quorum match index, with the leader's own match seeded from its log
  tip (there is no barrier to wait for);
- the consensus module's `persist_meta: none`: no term/vote metadata
  is read or written; the FS contract goes unused.

What the composition guarantees: **committed means replicated in
memory on a quorum of live voters.** Consequences, stated plainly:

- A single node that restarts rejoins with the same identity and an
  empty log, and is rebuilt from the cluster. The in-memory log serves
  random-access refetch only for the most recent 256 entry bodies; a
  replica further behind (a restarted node is the extreme case) is
  caught up by snapshot install, so agreement-only graphs must wire
  the consensus snapshot-request edge to the durability module's
  install input.
- A node with no stable term or vote could, in principle, vote twice
  in an election that spans its restart. Two mitigations narrow the
  window: for one election timeout after boot the node grants no real
  votes and starts no elections (skipped when it is the only voter;
  pre-vote traffic, which confers no quorum right, is unaffected), and
  it refuses grants in any term at or below the highest term it has
  heard from a leader since boot. These are mitigations, not proofs;
  the provable form, rejoining as a non-voting learner and being
  re-admitted through a membership change, is a design target, not
  wired.
- Simultaneous restart of a quorum of voters can elect an empty-log
  leader and discard all prior committed state, even when a
  surviving minority node still holds every entry. Such a survivor
  holds applied state the new cluster will never re-issue and must be
  restarted as well. Membership changes are forgotten along with the
  log, so a removed node that restarts believes its configured voter
  set again: live nodes discount its ballots, but restarted nodes
  cannot.

Three invariants hold across the layers: acknowledgements on
`flushed` mean replicated-volatile, the readiness signal carries no
durability claim, and a disk composition never falls back to memory.
A hard storage failure there holds the log (appends go unacknowledged
and the proposer backpressures) instead of acknowledging what was
never persisted.

---

## ACK contract

A client acknowledgement is emitted only after the entry's index has
passed the commit tracker — which, in the strict and group_fsync
modes, requires both a replication quorum (match indices) and a
durability quorum (fsync acknowledgements) at or past the entry. An
acknowledged write therefore survives any single-node loss and is
physically fsynced on a quorum of replicas. In relaxed mode the
durability half of the gate is waived and the acknowledgement promises
replication only.

The current-term fence preserves the standard Raft rule: a fresh
leader acknowledges nothing until an entry of its own term has
committed, so majority-replicated entries inherited from a predecessor
are never counted directly.

There is no client-supplied idempotency key. The only idempotency
window in the system is the admin path's retransmit dedup: an admin
command byte-identical to its immediate predecessor within a 2 s
window is answered `ADMIN_STATUS_DUPLICATE` without a second apply
(`modules/app/operations/admin.rs`). Ordinary client writes that are
retried produce distinct entries; deduplication is the consumer's
responsibility.

---

## Read gate predicate

Linearizable reads are served through a strict ReadIndex path plus a
control-plane freshness permit.

**ReadIndex probes.** A read submission (`MSG_CLIENT_READ_REQUEST`)
causes the apply component to issue a probe request to raft (seam E7).
The leader snapshots its commit index, then broadcasts
`MSG_READ_INDEX_PROBE` to its peers; each peer answers
`MSG_READ_INDEX_PROBE_RESP` if the probe's term is at least its own
(stepping down if higher). When a majority of the active voter set —
both sets while a joint configuration is active — confirms, raft
replies to apply with the snapshotted commit index as the read's
linearization point. This confirms leadership at submission time, so a
partitioned former leader cannot serve a stale answer. A probe that
fails to reach majority within 1500 ms, or that lands on a non-leader,
is answered unconfirmed and the read is rejected with
`CLIENT_REJECT_FALLBACK`. On a single-node cluster the leader is its
own majority and confirms immediately. If the probe queue is full the
read degrades to the legacy gate: the commit horizon captured at
submission time.

**Permits.** The admission module's proof cache classifies
control-plane proof age into Fresh / Cached / Stale / Expired
(`modules/app/admission/proof_cache.rs`). While the state is Fresh or
Cached, the read-gate component emits a standing `MSG_READ_PERMIT`
each step (`modules/app/admission/read_gate.rs`); Stale and Expired
stop the flow and simultaneously raise the strict-fallback signal (see
[lifecycle.md](lifecycle.md#strict-fallback-and-the-read-gate)).

A queued read becomes ready when the apply index has reached its
confirmed commit index **and** a permit has been observed within the
last 3 s. Reads still queued after 5 s are rejected with
`CLIENT_REJECT_FALLBACK`. The response body is empty — the substrate
guarantees only that the linearization point was reached; state-machine
consumers answer from their replicated state. Library consumers mirror
the same predicate via `ReadGateInputs::can_read` in
`modules/common/replica_facade.rs`: no strict fallback, cache Fresh or
Cached, and commit index equal to durable index.

---

## Flow control

Admission runs a dual-token PID controller
(`modules/app/admission/flow.rs`) with a 100 ms sample period and one
gain set: kp = 0.60, ki = 0.20, kd = 0.10 (Q16.16 fixed point, with an
anti-windup clamp on the integral term). There are no per-profile gain
tables. Two credit pools feed the gateway's throttle:
`entry_credit_max = 4096` entries and `byte_credit_max = 64 KiB`.

Two operating modes:

- **Rate-based** (`entry_rate_per_sec > 0`): each sample converts the
  wall-clock rate into an absolute entry grant (with sub-token carry so
  the long-run rate is exact), adjusted by the PID output; byte credits
  are held at capacity. The throughput configs use this as the
  governing limiter.
- **Absolute-pool** (default): the PID output adjusts both pools
  directly, bytes scaled 16× from entries.

The controller's error input is a lag signal drained from the
`lag` port. The replicator reserves the matching output but does not
currently emit `MSG_LAG_SIGNAL`, so in the shipped graphs the error
term stays at zero and the pools hold at their caps; effective
admission control comes from the rate limiter plus raft's
uncommitted-inflight and WAL-unacked gates.

---

<a id="compaction-floor"></a>
## Compaction

Compaction is snapshot-driven. On each WAL segment rotation the WAL
emits `MSG_SNAPSHOT_TRIGGER` at the rotation-time high-water. The
snapshot engine gates the trigger on its retention-floor table — the
commit tracker publishes `min(match index over the active voter set)`
as `MSG_COMPACTION_FLOOR`, so a snapshot (and therefore compaction)
never outruns what the slowest live voter has replicated. Once a
snapshot is durably installed, `MSG_SNAPSHOT_INSTALLED` reaches raft,
which emits `MSG_WAL_COMPACT_BEFORE` clamped to the commit index.

The WAL applies the floor conservatively
(`modules/app/durability/wal.rs`): only whole segments every one of
whose entries lies below the floor are deleted, the boundary segment
is always kept, and the live write segment is never touched. The
segment floor is durably persisted to a sidecar file **before** the
first unlink, so replay after a crash mid-compaction still finds the
surviving log; unlinks are paced a few per step. There is no separate
compaction-floor computation beyond this — the retention floor, the
commit clamp, and the whole-segment rule are the entire policy.
