# Session Directory — the reservation authority

The `session_directory` module implements the **session directory /
reservation authority** role from fluxor's protocol-surfaces RFC
(`fluxor/.context/rfc_protocols.md` §8.3, §13.7; vocabulary in
`fluxor/docs/architecture/protocol_surfaces.md`): the durable
single-writer service that platform-replicated-state
`transport_migratable` sessions depend on for takeover safety.

It is an ordinary Clustor replicated consumer — the same seven-primitive
facade `example_consumer` demonstrates — with a real state machine
behind it.

## Pieces

| Piece | Path | Role |
|---|---|---|
| State machine | `modules/common/session_registry.rs` | Deterministic `apply(committed body) → reply`; pure no_std, host-tested. |
| Module | `modules/app/session_directory/` | Channels, proposal correlation, reply routing, snapshots, telemetry. |
| Gate tests | `tests/session_registry.rs` | State-machine form of the RFC §18 R1–R5 verification gates. |
| E2E | `tests/session_directory_e2e.rs` + `configs/session-directory.yaml` | Boots a real group; proves grants are quorum-committed and monotone end to end. |

## What the registry enforces

- **Single-writer bindings (§8.3).** One authoritative
  `(anchor, worker)` binding per `(session_id, session_epoch)`.
  A competing BIND at the current or an older epoch is rejected
  `stale_epoch`; identical re-binds are idempotent (proposer retry).
- **Counter-block grants (§13.7.2, R2).** `RESERVE` hands out
  `[high_water, high_water + len)` per `(session, counter)` for the
  three hot egress counters (AEAD nonce, reliable-ordered send index,
  datagram sequence). The high-water only advances — identity space is
  **never re-handed out**; an abandoned block tail is wasted, not
  reused. Stale-epoch requesters get nothing.
- **Receive-window floor (§13.7.3, R4).** `RX_FLOOR` checkpoints only
  move forward; a takeover can never lower the replay-window low edge
  below the last durable checkpoint.
- **Wrapped-key custody (§13.7.6, R1).** `KEY_PUT` stores an opaque
  KEK-wrapped blob (≤ 80 bytes) the registry never parses — the KEK
  lives with the anchors / HSM, so the directory, the WAL under it,
  and every replica hold ciphertext only. `KEY_WIPE` (TTL expiry,
  never epoch-refused) and `UNBIND` (teardown) zeroize every custody
  byte. TTL is metadata; expiry is enforced by a *replicated* wipe so
  determinism holds.
- **Fence ordering (§13.7.2a / §13.7.4, R3).** A takeover — a BIND
  that changes `anchor_id` on a session flagged
  `SR_BIND_FENCE_REQUIRED` — is refused `fence_required` until
  `FENCE_CONFIRM` has landed **for the anchor being replaced**
  (`FENCE_REQUEST` alone is not enough: initiated ≠ confirmed, and
  moving the VIP on an unconfirmed kill is the split-brain §13.7.2a
  forbids). The registry enforces the *ordering*; making the fence
  *enforceable* is the deployment's fence backend (STONITH via managed
  PDU / fabric egress cutoff — the fluxor rig's `kasa_local` power
  backend is the reference). `FENCE_CONFIRM` must be proposed only by
  the agent that observed the cutoff. This module therefore does NOT
  declare fluxor's `fence.enforceable` capability; the fence agent
  does.
- **Unsafe-recovery voiding (§13.7.6, R2).** `RECOVERY_MARK`
  (operator/orchestrator-proposed after any forced quorum recovery —
  force-new-cluster, quorum reduction) advances a monotone
  `recovery_epoch` and voids every session's outstanding reservations:
  `RESERVE` answers `recovery_void` until that session's epoch
  advances. A recovery that lost the grant-log tail can therefore
  never lead to a re-emitted `(key, nonce)`.

## The ack boundary (R2 + R5)

The module replies to a request **only from the committed-entry
stream**: request → tagged proposal → WAL fsync → quorum commit →
`consensus.committed_entries` → `registry.apply` → reply. There is
no fast-path ack, so anything acknowledged through this module —
a counter-block grant, an auth-relevant `KEY_*`/`BIND` transition — is
quorum-durable first. That is the RFC's "quorum-durable before emit"
(R2) and "RPO-zero before acted upon" (R5) boundary, held structurally.

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

## Wire

- `MSG_SR_REQUEST` (0x90): `[request_id:u64 LE][SR_OP_* body]` — from
  anchors/orchestrators (remote channels in deployment).
- `MSG_SR_REPLY` (0x91): `[request_id:u64 LE][SessionReply:38]` — only
  after commit.
- Command layouts, status codes, and the snapshot format are specified
  in `modules/common/session_registry.rs`.

## Telemetry

Every continuity-relevant committed transition emits a fluxor
`MON_SESSION` line (`fluxor/docs/architecture/monitor-protocol.md`,
including the §Failover records vocabulary): `relocated` (bind),
`epoch_bump`, `reservation_granted`, `fence_initiated` /
`fence_confirmed`, `unsafe_recovery_epoch_void`, `detached` (unbind),
and `rejected` with the refusal reason (`stale_epoch`,
`fence_required`, `recovery_void`, `floor_regression`, …). Key custody
and rx-floor traffic is deliberately silent.

## Capabilities (fluxor `capability_surface.md`)

`session.directory`, `session.reservation`, `security.key_wrap`,
`durable.rpo_zero` — the providers fluxor's `continuity:` block
validator requires for a `transport_migratable /
platform_replicated_state` declaration (§7.3). Capabilities name
structure; the R1–R5 behaviour is proven by `tests/session_registry.rs`
and the e2e run, and the failover timing budget (§12.4) only by
measurement against a deployed client.

## Sizing and §13.7.7

`SR_MAX_SESSIONS = 64` sessions × `SR_NUM_COUNTERS = 3` counters, one
raft entry per grant. Block size `N` is the caller's declared
trade-off (RFC §13.7.7): larger blocks amortise the quorum round-trip
and survive directory outages longer, at the cost of a wider failover
counter gap and a longer §13.7.2a divergence window. Anchors should
refill ahead of exhaustion (fluxor's `nonce_reservation` core's
`needs_refill`) so the round-trip stays off the emit path.

## What is deliberately out of scope here

- The **anchor side** (fluxor `modules/sdk/cores/nonce_reservation.rs`
  consumes the grants; the RakNet/Bedrock anchor composing it is app
  work in the `chunk` repo per RFC §8.1).
- A **fence backend** (deployment infrastructure).
- **Automatic unsafe-recovery detection** — the substrate has no
  force-new-cluster marker today; `RECOVERY_MARK` is the explicit,
  auditable operator hook. If the substrate grows a first-class unsafe
  recovery signal, wiring it to propose the mark automatically is the
  natural follow-up.
