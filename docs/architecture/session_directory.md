# Session Directory — the reservation authority

The `session_directory` module is a durable single-writer service
for session continuity: the authority that migratable sessions
depend on for takeover safety (vocabulary in
`fluxor/docs/architecture/protocol_surfaces.md`).

It is an ordinary Clustor replicated consumer — the same
seven-primitive facade `example_consumer` demonstrates — with a real
state machine behind it.

## Pieces

| Piece | Path | Role |
|---|---|---|
| State machine | `modules/common/session_registry.rs` | Deterministic `apply(committed body) → reply`; pure no_std. |
| Module | `modules/app/session_directory/` | Channels, proposal correlation, reply routing, snapshots, telemetry. |
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
- **Fence ordering.** A takeover — a BIND that changes `anchor_id` on
  a session flagged `SR_BIND_FENCE_REQUIRED` — is refused
  `fence_required` until `FENCE_CONFIRM` has landed **for the anchor
  being replaced** (`FENCE_REQUEST` alone is not enough: initiated ≠
  confirmed, and moving the VIP on an unconfirmed kill is exactly the
  split-brain this ordering forbids). The registry enforces the
  *ordering*; making the fence *enforceable* is the deployment's
  fence backend (STONITH via managed PDU / fabric egress cutoff —
  the fluxor rig's `kasa_local` power backend is the reference).
  `FENCE_CONFIRM` must be proposed only by the agent that observed
  the cutoff. This module therefore does NOT declare fluxor's
  `fence.enforceable` capability; the fence agent does.
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
- A **fence backend** (deployment infrastructure).
- **Automatic unsafe-recovery detection** — the substrate has no
  force-new-cluster marker today; `RECOVERY_MARK` is the explicit,
  auditable operator hook. If the substrate grows a first-class unsafe
  recovery signal, wiring it to propose the mark automatically is the
  natural follow-up.
