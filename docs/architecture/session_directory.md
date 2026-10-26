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
fence request and confirmation, the fenced takeover, mirror horizons,
transfer grants, recovery marks. Both are the same replicated log; the
contract is the wire an anchor sees, so a graph places this directory
or any other provider of the capability interchangeably.

The same ports and log carry two more namespaces, each its own
deterministic state machine told apart by message id and
by the two-byte magic on the replicated body: `transport/<flow_id>`
(`MSG_TR_REQUEST` / `MSG_TR_REPLY`, magic `"TR"`), which owns a
protected flow's primary and standby anchors, emitter epoch and mirror
horizon; and `vip/<service_address>` (`MSG_VB_REQUEST` /
`MSG_VB_REPLY`, magic `"VB"`), which owns a service address's exclusive
owner or active owner set and mints the emission tokens that prove it.

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
| Session state machine | `modules/common/session_registry.rs` | `session/<session_id>`: deterministic `apply(committed body) → reply`; pure no_std, profile-sized. |
| Transport state machine | `modules/common/transport_registry.rs` | `transport/<flow_id>`: primary / standbys / emitter epoch / mirror horizons; idempotent operation ids. |
| VIP state machine | `modules/common/vip_registry.rs` | `vip/<service_address>`: the binding phase sequence, fence ordering, emission tokens. |
| Slot index | `modules/common/slot_index.rs` | `SlotIndex`, a chained hash index (FNV-1a) from identity to arena slot, and `SlotSet`, slot occupancy with the lowest free slot in O(log N): the bookkeeping every namespace keeps beside its arena. |
| Timing | `modules/common/timing.rs` | `TimingState<N>`: the profile-sized deterministic deadline index (a min-heap in canonical order) the session registry embeds. |
| Module | `modules/app/session_directory/` | Channels, proposal correlation, reply routing, streamed snapshots, telemetry, the VIP seed, the capacity profile. |
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
  `recovery_epoch`, voids every session's outstanding reservations and
  invalidates every outstanding transfer grant: `RESERVE` and
  `GRANT_TRANSFER` answer `recovery_void` until that session's epoch
  advances. A recovery that lost the grant-log tail can therefore
  never lead to a re-emitted `(key, nonce)` or a duplicate key use.
- **Mirror horizon.** `MIRROR_MARK` records the committed
  `(mirror_epoch, mirror_generation)` a session's standby has
  acknowledged, monotone in lexicographic order; its reply exposes the
  pair in `a` / `b`, so a coordinator reads committed mirror and session
  epochs from one authority.
- **Custody context.** `KEY_PUT_BOUND` binds the wrapped
  blob to the SHA-256 digest of `(service_id, session_id, epoch,
  algorithm, use, direction)` (`key_context_digest`; the module computes
  it with the SDK's digest, the core takes the 32 bytes). A put or a
  transfer consumption under another context is refused
  `context_mismatch` while the key lives. Only `KEY_WIPE` ends the
  context: after an epoch change the stored key no longer matches the
  session's own context, so the new holder wipes it before putting its
  own.
- **Transfer grants.** `GRANT_TRANSFER` records the
  destination `(host, anchor)` and target epoch the key may be re-wrapped
  for, under a TTL on the timing index, and replies with a
  registry-unique grant id. `CONSUME_TRANSFER` is single-use: it must
  present the grant's id, destination and target epoch and the key's
  context (`grant_invalid` / `context_mismatch` otherwise). One grant is
  outstanding per session; a new one replaces it.
- **Reservation floor.** A session declaring
  `SR_BIND_COUNTER_FLOOR_GATED` keeps a per-counter mirrored floor
  (`COUNTER_FLOOR`, forward-only, never past the granted high-water):
  `ACTIVATE` is refused `reservation_behind` until every counter's floor
  has reached its high-water, so the new emitter never re-emits identity
  space its standby did not mirror.

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
magic prefix — `"SR"` sessions, `"TR"` flows, `"VB"` VIP bindings — so
admin ops and other consumers' entries are ignored structurally rather
than by lucky opcode disjointness, and each namespace's reply goes out
as its own message id from the same pending table.

## Profiles

Capacity is profile-selected. The arenas are static,
sized per `[[variant]]` of the module — `rp2350` (the default: 64
sessions, 64 flows, 16 VIP bindings), `pi5` (4096 / 4096 / 1024),
`server` (65536 / 65536 / 16384) — and the `profile` parameter names the
capacity a deployment admits and reports (`admitted ≤ arena`). A profile
larger than the variant's arena refuses to start: a build admitting less
than the named profile cannot claim it. The registries are
`SessionRegistry<N, D>` (D deadline slots, two per session: a key TTL
and a transfer grant), `TransportRegistry<N>` and `VipRegistry<N>`.

A profile admits its whole arena, so every structure stays bounded at a
full one. Each registry finds a record by identity through a chained hash
index over FNV-1a (the hash `wire.rs` shards with — never the language
default), constant-time on average at any occupancy, and places a new
record in the lowest free slot through an occupancy tree in O(log N);
both are derived state, rebuilt on restore. The deadline index is a
min-heap: registering, cancelling and firing a deadline are O(log N).
Two operations walk an arena, both rare and bounded by it: a
`RECOVERY_MARK`, which voids every live record, and the clear that begins
a snapshot install, which touches each occupied slot.

A VIP record lives as long as its group: a released binding keeps its
`vip_epoch`, so a stale coordinator's command for an old epoch is still
refused. The VIP arena therefore bounds the distinct addresses a group
ever claims, not only the ones it holds.

A proposer routes a session or flow to its group by `wire::shard_for_key`
over its identity's FNV-1a hash: a virtual shard of the fixed 2^18 space,
whatever group holds it now. `partition_id` names the group whose shards
this directory holds.

## Transport namespace

`transport/<flow_id>` (`modules/common/transport_registry.rs`) holds, per
`flow_id[16]`, the primary anchor, up to three ordered standbys, the
emitter `epoch`, the primary's committed mirror horizon
`(mirror_epoch, mirror_generation)` and each standby's acknowledged
horizon. Every command carries `operation_id[16]`, the flow and the
epoch it expects; the epoch never wraps, and a change that would carry it
past `u32::MAX` is refused `invalid`:

| Command | Payload after `[op][op_id:16][flow:16][expected_epoch:4]` | Effect |
|---|---|---|
| `BIND` (1) | `[primary:8][standby_count:1][standbys:8×3]` | `expected_epoch` 0 creates at epoch 1; otherwise re-binds the standby set under the committed primary and advances the epoch. |
| `MOVE` (2) | `[new_primary:8]` | Promotes a listed standby whose acknowledged horizon covers the committed one (`not_a_standby`, `mirror_behind`); epoch advances; the old primary is not silently a standby. |
| `MIRROR_MARK` (3) | `[anchor:8][mirror_epoch:8][mirror_generation:8]` | The primary's committed horizon or a standby's acknowledgement; monotone (`mirror_regression`). |
| `TOMBSTONE` (4) | — | Ends emission; the record stays, taking only `RETIRE`. |
| `RETIRE` (5) | — | Frees a tombstoned slot. |
| `RECOVERY_MARK` (6) | `[op_id:16][recovery_epoch:4]` | Voids every bound flow until a `BIND` at the committed epoch re-binds it. |

Replies are the session reply's 38-byte shape:
`[op][status][flow:16][epoch:4][mirror_epoch:8][mirror_generation:8]`.
A byte-identical retry of a record's last operation repeats its recorded
reply; a different command under the same id is `conflict`. The record
keeps that last command whole and compares bytes, so no other command can
pass for a retry. The dedupe window is one operation per flow, bounded by
construction.

## VIP namespace and emission tokens

`vip/<service_address>` (`modules/common/vip_registry.rs`) keeps one
record per `(service_id, address_family, prefix, prefix_len)` with
`vip_epoch`, the phase, mode, owner hosts with their boot
incarnations, prepared hosts, confirmed fences, advertisement policy
and the recovery generation. Phases move forward one step at a time —
`UNASSIGNED → PREPARING_NEW → FENCING_OLD → OWNER_COMMITTED →
ADDRESS_INSTALLED → ADVERTISED → ACTIVE → DRAINING → WITHDRAWN →
EMISSION_DISABLED → RELEASED` — and `ABORT` is accepted only before
`OWNER_COMMITTED`, returning to the phase the record held when the claim
was made. Every command carries `operation_id[16]`, the key and
`expected_epoch` (u64), idempotent and conflict-checked as above:

| Command | Payload after `[op][op_id:16][key:34][expected_epoch:8]` | Effect |
|---|---|---|
| `CLAIM_PREPARE` (1) | `[mode:1][host:16][boot:16][policy:16][allowed_interfaces:4]` | New `vip_epoch`; from an unowned record or as a takeover of an owned one (its owners become the previous owners to fence; an active/active add fences nobody; an `EMISSION_DISABLED` predecessor is its own acknowledgement). |
| `ABORT` (2) | — | Before commit only. |
| `FENCE_REQUEST` (3) | `[host:16]` | → `FENCING_OLD` (zero host when nothing is to fence). |
| `FENCE_CONFIRM` (4) | `[host:16][fence_gen:4]` | Records the fence agent's custody generation for a previous owner (or, in an `ACTIVE` active/active set, a current owner being removed). |
| `ACTIVATE` (5) | `[ready_graph:1]` | → `OWNER_COMMITTED`: every previous owner fenced (`blocked_fence`), the graph attested (`not_ready`), the registry seeded; bumps `authority_generation`, mints the token. |
| `INSTALLED` (6) / `ADVERTISED` (7) / `ACTIVE` (8) | — | One step each. |
| `WITHDRAW` (9) / `DISABLE` (10) / `RELEASE` (11) | `[host:16]` | `ACTIVE → DRAINING → WITHDRAWN`, `→ EMISSION_DISABLED`, `→ RELEASED` (owners cleared); `RELEASE` naming a fenced owner of an `ACTIVE` active/active set removes just that host. |
| `RECOVERY_MARK` (12) | `[op_id:16][generation:8]` | Bumps `unsafe_recovery_generation`; a fence in flight returns to `PREPARING_NEW`; every committed binding is void until re-claimed and re-fenced. The reply's `vip_epoch` is the count of bindings voided. |
| `SEED` (13) | `[op_id:16][seed:32]` | Once per group: the capability seed. |

The reply is `[op][status][phase][mode][owner_count][token_present]
[key:34][vip_epoch:8][authority_generation:8]
[unsafe_recovery_generation:8][token:110]`; statuses are the `VB_ST_*`
set (`OK`, `INVALID`, `STALE_EPOCH`, `FUTURE_EPOCH`, `CONFLICT`,
`CAPACITY`, `NOT_READY`, `BLOCKED_FENCE`, `UNSUPPORTED_STATE`,
`INVARIANT_FAILURE`, `UNKNOWN_BINDING`, `RECOVERY_VOID`,
`RECOVERY_STALE`, …).

An **emission token** is `[service_id:16][family:1][prefix_len:1]
[prefix:16][owner_host:16][boot_incarnation:16][vip_epoch:8]
[authority_generation:8][unsafe_recovery_generation:8]
[allowed_interfaces:4][capability:16]`, the capability being the first
16 bytes of SHA-256 over the registry's seed followed by the token's
fields. Both are fixed-length, so no extension of a valid input is a
valid input, and the keyed digest is a sound MAC. A token is an opaque,
generation-checked capability: `verify_emission_token` (what a Fluxor
`ip` / NIC provider or `route_announcer` asks before sourcing an address
or originating a prefix) fails closed on a recovery generation or vip
epoch behind the registry's, an authority generation that is not the
current one, a host or boot incarnation that is not a current owner's, a
voided binding, owners that may not emit, or a capability that does not
recompute (compared in constant time). Owners may emit from the commit
that made them owners until `DISABLE`; a takeover claim leaves them that
authority until its own commit, unless it was made after they disabled
emission. That exception is what lets a claim over an
`EMISSION_DISABLED` predecessor skip the fence: the predecessor cannot
regain authority. The seed is replicated state, so every replica mints
and verifies the same tokens: the module's leader proposes it once per
group from the kernel CSPRNG (`SEED`), and until it commits `ACTIVATE`
answers `not_ready` everywhere. A token is a pure function of that
state: `emission_token` re-derives the current one for any owner on any
replica, a restart loses nothing, and a cached token stops verifying the
moment authority moves past it.

## Streamed snapshot

Every registry streams its snapshot as versioned records rather than a
whole-arena image: a header naming the version, the arena, the admitted
count and the record count, then one record per live slot carrying its
slot number (placement is replicated state, so images are byte-identical
across replicas), then — for the session registry — the timing
section's header and live entries. Restore validates the version, the
profile, every count and every cross-reference (a deadline without its
consumer object, two records for one slot or one identity) and fails
closed, leaving the registry empty. The module stages one chunk plus one
unit (`SNAP_CHUNK` + the largest record), independent of the profile;
the timing section streams the deadline heap position by position, and a
restored replica places each entry back where it streamed from, so it
holds the exporter's heap;
an export spans steps and holds committed applies until it completes,
so the image is one index's state; a begun or failed install holds
applies until an install succeeds. The image's sections are the session
registry, then the transport registry, then the VIP registry.

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
- `MSG_TR_REQUEST` (0x92) / `MSG_TR_REPLY` (0x93): the same envelopes
  for `TR_OP_*` bodies and the 38-byte `TransportReply`.
- `MSG_VB_REQUEST` (0x94) / `MSG_VB_REPLY` (0x95): the same envelopes
  for `VB_OP_*` bodies and the `VipReply` (with the token).
- Command layouts, status codes, and the snapshot formats are specified
  in `modules/common/session_registry.rs`,
  `modules/common/transport_registry.rs` and
  `modules/common/vip_registry.rs`.

The session command set, for reference (payloads after the opcode byte,
LE; `[sid:16][epoch:4]` first unless noted):

| Command | Payload | Reply `a` / `b` |
|---|---|---|
| `BIND` (1) | `[anchor:8][worker:8][flags:1]` | 1 when an existing binding advanced / 0 |
| `EPOCH_BUMP` (2) | `[old:4][new:4]` | — |
| `RESERVE` (3) | `[counter:1][len:8]` | block start / len (fluxor's grant record) |
| `RX_FLOOR` (4) | `[floor:8]` | committed floor / — |
| `KEY_PUT` (5) | `[ttl_ms:4][blob_len:2][blob]` | blob len / ttl |
| `KEY_WIPE` (6) | — | — |
| `FENCE_REQUEST` (7) / `FENCE_CONFIRM` (8) | `[target_anchor:8]` (+ `[fence_gen:4]`) | fence state / generation |
| `UNBIND` (9) | — | — |
| `RECOVERY_MARK` (10) | `[recovery_epoch:4]` (no sid) | voided count / new epoch |
| `ACTIVATE` (11) | `[new_anchor:8][fence_gen:4]` (`epoch` = new epoch) | generation consumed / — |
| `MIRROR_MARK` (12) | `[mirror_epoch:8][mirror_generation:8]` | committed mirror epoch / generation |
| `KEY_PUT_BOUND` (13) | `[ttl_ms:4][ctx:32][blob_len:2][blob]` | blob len / ttl |
| `GRANT_TRANSFER` (14) | `[dest_host:16][dest_anchor:8][target_epoch:4][ttl_ms:4]` | grant id / ttl |
| `CONSUME_TRANSFER` (15) | `[grant_id:8][dest_host:16][dest_anchor:8][target_epoch:4][ctx:32]` | grant id / key len |
| `COUNTER_FLOOR` (16) | `[counter:1][floor:8]` | floor / high-water |

`BIND` flags: `SR_BIND_FENCE_REQUIRED` (0x01), `SR_BIND_COUNTER_FLOOR_GATED`
(0x02).

## Telemetry

Every continuity-relevant committed transition emits a fluxor
`MON_SESSION` line (`fluxor/docs/architecture/monitor-protocol.md`):
`attached` (a first bind), `relocated` (a bind that advanced the
epoch), `epoch_bump`, `reservation_granted`, `fence_initiated` /
`fence_confirmed`, `vip_moved` (a fenced session `ACTIVATE`, and a
committed VIP `ACTIVATE` keyed by service id and vip epoch),
`unsafe_recovery_epoch_void`, `detached` (unbind), and `rejected` with
a refused session command's reason (`stale_epoch`, `fence_required`, `fence_stale`,
`recovery_void`, `floor_regression`, `context_mismatch`,
`grant_invalid`, `reservation_behind`, `mirror_regression`,
`deadline_capacity`, …). Key custody and transfer-grant traffic is
deliberately silent, so the log carries no pattern of key activity;
rx-floor, mirror and counter-floor checkpoints are silent because they
are high-rate.

## Capabilities

`session.directory`, `session.reservation`, `security.key_wrap`,
`durable.rpo_zero` — the providers fluxor's `continuity:` block
validator requires for a migratable replicated-state declaration
(`fluxor/docs/architecture/capability_surface.md`). Capabilities name
structure; the safety behaviour above is a property of the state
machine, and the failover timing budget is only measurable against a
deployed client.

## Sizing

The profile's sessions × `SR_NUM_COUNTERS = 3` counters, one raft entry
per grant (see *Profiles*; the ceilings are in the limit register). Block size `N` is the caller's declared
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
- **Automatic unsafe-recovery detection** — the substrate raises no
  force-new-cluster signal, so `RECOVERY_MARK` is the explicit, auditable
  operator hook. A substrate signal for unsafe recovery would be wired to
  propose the mark.
