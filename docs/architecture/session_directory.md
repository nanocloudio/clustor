# Session Directory — the reservation authority

The `session_directory` module is a durable single-writer service
for session continuity: the authority that migratable sessions
depend on for takeover safety (vocabulary in
`fluxor/docs/architecture/protocol_surfaces.md`).

It is an ordinary Clustor replicated consumer — the same
seven-primitive facade `example_consumer` demonstrates — with a real
state machine behind it.

Two kinds of client reach it. An **anchor** speaks fluxor's
SessionCtrlV1 — the contract every `session.directory` provider
answers — on `ctrl_in` / `ctrl_out`: ATTACH binds a session at a
generation, EPOCH_BUMP advances it, DETACH releases it, and a committed
binding is followed by a reservation grant in the contract's record.
An **orchestrator** speaks the registry's own command set on
`requests` / `replies` (`MSG_SR_REQUEST`, `[request_id][SR_OP_* body]`):
reservations for other counters, key custody, receive-window floors,
fence request and confirmation, the fenced takeover, recovery marks.
Both are the same replicated log; the contract is the wire an anchor
sees, so a graph places this directory or any other provider of the
capability interchangeably.

The log reaches the module on `committed_entries` in one of two
shapes, declared by `forwarded_stream`. Wired straight from consensus
it is the group's whole log, contiguous, and a gap is a fault recovered
by snapshot install. Behind a forwarder — a graph whose one consumer of
the committed stream passes this directory's entries on, as Quantum's
session processor does — it is a selection of that log, this
directory's entries in order, and an index jump is the forwarder's
omission of other consumers' entries; the cursor follows it, and a lost
entry of the directory's own shows as an unanswered proposal reclaimed
by the pending TTL. `partition_id` names the group whose log this is: an
engine hosting several groups writes them all to one stream, each
numbered from 1, and only this group's entries apply here.

## Pieces

| Piece | Path | Role |
|---|---|---|
| State machine | `modules/common/session_registry.rs` | Deterministic `apply(committed body) → reply`; pure no_std. |
| Module | `modules/app/session_directory/` | Channels, proposal correlation, reply routing, snapshots, telemetry. |
| Contract face | `modules/common/session_directory_face.rs` | An anchor's SessionCtrlV1 verbs (HELLO / ATTACH / EPOCH_BUMP / DETACH on `ctrl_in`) mapped onto registry commands, and committed replies mapped back onto the contract's frames (ATTACHED / EPOCH_CONFIRMED / DETACHED / ERROR, then the reservation grant) on `ctrl_out`. |
| Deployment | the substrate graph plus this module wired as a consumer | Boots a real group; grants are quorum-committed and monotone end to end. |

## What the registry enforces

- **Single-writer bindings.** One authoritative `(anchor, worker)`
  binding per `(session_id, session_epoch)`. A competing BIND at the
  current or an older epoch is rejected `stale_epoch`; identical
  re-binds are idempotent (proposer retry).
- **Counter-block grants.** `RESERVE` hands out
  `[high_water, high_water + len)` per `(session, counter)` for the
  three hot egress counters (AEAD nonce, reliable-ordered send index,
  datagram sequence). The high-water only advances — identity space is
  **never re-handed out**; an abandoned block tail is wasted, not
  reused. Stale-epoch requesters get nothing.
- **Receive-window floor.** `RX_FLOOR` checkpoints only move forward;
  a takeover can never lower the replay-window low edge below the
  last durable checkpoint.
- **Wrapped-key custody.** `KEY_PUT` stores an opaque KEK-wrapped
  blob (≤ 80 bytes) the registry never parses — the KEK lives with
  the anchors / HSM, so the directory, the WAL under it, and every
  replica hold ciphertext only. `KEY_WIPE` (TTL expiry, never
  epoch-refused) and `UNBIND` (teardown) zeroize every custody byte.
  TTL is metadata; expiry is enforced by a *replicated* wipe so
  determinism holds.
- **Fence ordering.** A takeover — `ACTIVATE`, which moves a
  session's `anchor_id` under a strictly higher epoch — is refused
  `fence_required` until `FENCE_CONFIRM` has landed **for the anchor
  being replaced** (`FENCE_REQUEST` alone is not enough: initiated ≠
  confirmed, and moving the VIP on an unconfirmed kill is exactly the
  split-brain this ordering forbids), and refused `fence_stale` unless
  it carries the **generation** that confirmation recorded. The
  generation is the out-of-band fence agent's custody generation — what
  `MSG_ADDR_FENCED` reports and a failover coordinator carries forward
  as `fence_gen` — so a fence confirmed under an earlier custody never
  admits a later takeover. One confirmed fence admits one activation;
  the consumed fence resets. A `BIND` that changes the anchor on a
  session flagged `SR_BIND_FENCE_REQUIRED` presents no generation and
  is refused outright; its anchor moves only by `ACTIVATE`. The
  registry enforces the *ordering*; making the fence *enforceable* is
  the fence agent's job (a member placed on another node whose cut is
  power or the fabric port — fluxor's reference agent opens the rig's
  plug).
- **Unsafe-recovery voiding.** `RECOVERY_MARK`
  (operator/orchestrator-proposed after any forced quorum recovery —
  force-new-cluster, quorum reduction) advances a monotone
  `recovery_epoch` and voids every session's outstanding reservations:
  `RESERVE` answers `recovery_void` until that session's epoch
  advances. A recovery that lost the grant-log tail can therefore
  never lead to a re-emitted `(key, nonce)`.

## The ack boundary

The module replies to a request **only from the committed-entry
stream**: request → tagged proposal → WAL fsync → quorum commit →
`consensus.committed_entries` → `registry.apply` → reply. There is
no fast-path ack, so anything acknowledged through this module —
a counter-block grant, an auth-relevant `KEY_*`/`BIND` transition — is
quorum-durable first: nothing is emitted before it is quorum-durable,
and nothing is acted upon that a recovery could lose. The boundary is
held structurally.

Reply attribution is by **assigned wal index**, not content:
`consensus` strips the tagged-proposal header before the WAL and
reports `correlation → wal_index` on `proposal_assigned`. Content
matching would misattribute byte-identical commands from concurrent
proposers — for `RESERVE` that means two anchors believing they own the
same block, which is precisely the catastrophe the authority exists to
prevent.

Registry commands are namespaced in the shared raft log by a 2-byte
`"SR"` magic prefix, so admin ops and other consumers' entries are
ignored structurally rather than by lucky opcode disjointness.

## Deterministic timing

This module also hosts the leader-fenced time producer for
deterministic replicated timing. When (and only when) this node is
the group leader per `MSG_LEADER_HINT`, its `ClockGuard` is healthy,
and the timing index has work, the step loop proposes
`TimeAdvance` / `TimeDrain` entries through the ordinary
tagged-proposal path (`modules/common/timing.rs`; entry bodies are
prefixed with `wire::TIMING_MAGIC` so they share the raft log without
colliding with `"SR"` commands). An idle group proposes nothing.

Committed timing entries come back on `committed_entries` like every
other entry and apply to the registry's embedded `TimingState` on
every replica. Deadlines fire only during committed apply, never from
a local timer — a `KEY_PUT` with a TTL registers a generation-fenced
deadline, and the due callback performs the replicated `KEY_WIPE`, so
expiry stays deterministic across the group.

## Wire

- `MSG_SR_REQUEST` (0x90): `[request_id:u64 LE][SR_OP_* body]` — from
  anchors/orchestrators (remote channels in deployment).
- `MSG_SR_REPLY` (0x91): `[request_id:u64 LE][SessionReply:38]` — only
  after commit.
- Command layouts, status codes, and the snapshot format are specified
  in `modules/common/session_registry.rs`.

## Telemetry

Every continuity-relevant committed transition emits a fluxor
`MON_SESSION` line (`fluxor/docs/architecture/monitor-protocol.md`):
`relocated` (bind), `epoch_bump`, `reservation_granted`,
`fence_initiated` / `fence_confirmed`, `unsafe_recovery_epoch_void`,
`detached` (unbind), and `rejected` with the refusal reason
(`stale_epoch`, `fence_required`, `recovery_void`,
`floor_regression`, …). Key custody and rx-floor traffic is
deliberately silent.

## Capabilities

`session.directory`, `session.reservation`, `security.key_wrap`,
`durable.rpo_zero` — the providers fluxor's `continuity:` block
validator requires for a migratable replicated-state declaration
(`fluxor/docs/architecture/capability_surface.md`). Capabilities name
structure; the safety behaviour above is a property of the state
machine, and the failover timing budget is only measurable against a
deployed client.

## Sizing

`SR_MAX_SESSIONS = 64` sessions × `SR_NUM_COUNTERS = 3` counters, one
raft entry per grant. Block size `N` is the caller's declared
trade-off: larger blocks amortise the quorum round-trip and survive
directory outages longer, at the cost of a wider failover counter gap
and a longer divergence window. Anchors should refill ahead of
exhaustion (fluxor's `nonce_reservation` core's `needs_refill`) so
the round-trip stays off the emit path.

## What is deliberately out of scope here

- The **anchor side**: fluxor's
  `modules/sdk/cores/nonce_reservation.rs` consumes the grants;
  protocol anchors composing it are application work in downstream
  repositories.
- The **fence agent**: the out-of-band member that performs the cut
  and reports the custody generation `FENCE_CONFIRM` records.
- **Automatic unsafe-recovery detection** — the substrate has no
  force-new-cluster marker today; `RECOVERY_MARK` is the explicit,
  auditable operator hook. If the substrate grows a first-class unsafe
  recovery signal, wiring it to propose the mark automatically is the
  natural follow-up.
