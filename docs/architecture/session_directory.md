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
owner or active owner set and mints the emission tokens that prove it;
and `fo/<operation_id>` (`MSG_FO_REQUEST` / `MSG_FO_REPLY`, magic
`"FO"`), the compare-and-swap store a failover coordinator records each
VIP move, release or recovery mark in before acting on it; `rg/<service>`
(`MSG_RG_REQUEST` / `MSG_RG_REPLY`, magic `"RG"`), the global tier's
region owner sets with their DR generation and regional invalidation;
and `op/<operation_id>` (`MSG_OP_REQUEST` / `MSG_OP_REPLY`, magic
`"OP"`), the compare-and-swap store of takeover, evacuation and DR
operation records; `att/<attachment_id>` (`MSG_AT_REQUEST` /
`MSG_AT_REPLY`, magic `"AT"`), private attachments' generations and their
services' revocation boundaries; and `rs/` (`MSG_RS_REQUEST` /
`MSG_RS_REPLY`, magic `"RS"`), egress block and address reservations.
Token checks add one more magic, `"CK"`: a barrier entry with no body
that changes no state (see the flow token below). A forwarder passes
these on with the directory's other entries.

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
| VIP state machine | `modules/common/vip_registry.rs` | `vip/<service_address>`: the binding phase sequence, fence ordering, emission tokens; owner sets as wide as the profile. |
| Failover-operation store | `modules/common/failover_registry.rs` | `fo/<operation_id>`: the traffic fabric's `WHFO` VIP-move records, compare-and-swap. |
| Region state machine | `modules/common/region_registry.rs` | `rg/<service>`: the VIP state machine with regions as owners, DR generations, regional invalidation. |
| Operation store | `modules/common/operation_registry.rs` | `op/<operation_id>`: takeover, evacuation and DR operation records (`CLOP`), compare-and-swap. |
| Attachment boundaries | `modules/common/attachment_registry.rs` | `att/<attachment_id>`: attachment generations, service revocation boundaries. |
| Reservations | `modules/common/reservation_registry.rs` | `rs/`: egress blocks per gateway boot incarnation, address ranges with quarantine; horizons in committed time. |
| Slot index | `modules/common/slot_index.rs` | `SlotIndex`, a chained hash index (FNV-1a) from identity to arena slot, and `SlotSet`, slot occupancy with the lowest free slot in O(log N): the bookkeeping every namespace keeps beside its arena. |
| Timing | `modules/common/timing.rs` | `TimingState<N>`: the profile-sized deterministic deadline index (a min-heap in canonical order) the session registry embeds. |
| Module | `modules/app/session_directory/` | Channels, proposal correlation, reply routing, streamed snapshots, telemetry, the VIP seed, the capacity profile. |
| Contract face | `modules/common/session_directory_face.rs` | An anchor's SessionCtrlV1 verbs (HELLO / ATTACH / EPOCH_BUMP / DETACH on `ctrl_in`) mapped onto registry commands, and committed replies mapped back onto the contract's frames (ATTACHED / EPOCH_CONFIRMED / DETACHED / ERROR, then the reservation grant) on `ctrl_out`. |
| Deployment | the substrate graph plus this module wired as a consumer | Boots a real group; grants are quorum-committed and monotone end to end. |
| Stack | `packaging/stack/clustor-directory.yaml` | `clustor-directory`: a one-voter group with this module as its consumer, published so another project's graph includes it whole and reaches only `requests` / `replies` (and `net_in` / `net_out` for the peer router's socket). |

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
  never lead to a re-emitted `(key, nonce)` or a duplicate key use. It
  also clears every fence in flight: a takeover after a recovery fences
  afresh, and a fenced transport move needs a fence confirmed since.
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
magic prefix — `"SR"` sessions, `"TR"` flows, `"VB"` VIP bindings, `"FO"`
failover operations, `"RG"` region owner sets, `"OP"` operation records,
`"AT"` attachment boundaries, `"RS"` reservations, and `"CK"` for a
token check's barrier — so admin ops and other consumers' entries are
ignored structurally rather than by lucky opcode disjointness, and each
namespace's reply goes out as its own message id from the same pending
table (a check's verdict from a table of its own).

## Profiles

Capacity is profile-selected. The arenas are static,
sized per `[[variant]]` of the module — `rp2350` (the default: 64
sessions, 64 flows, 16 VIP bindings), `pi5` (4096 / 4096 / 1024),
`server` (65536 / 65536 / 16384) — and the `profile` parameter names the
capacity a deployment admits and reports (`admitted ≤ arena`). A profile
larger than the variant's arena refuses to start: a build admitting less
than the named profile cannot claim it. The registries are
`SessionRegistry<N, D>` (D deadline slots, two per session: a key TTL
and a transfer grant), `TransportRegistry<N>`, `VipRegistry<N, O>`,
`FailoverRegistry<N>`, `RegionRegistry<N, O>`, `OperationRegistry<N>`,
`AttachmentRegistry<N, S>` (S services) and `ReservationRegistry<B, A>`
(B egress block records, A address records).

`O` is an owner width: the hosts one active/active set admits, a
compile-time size like the arena — 8 / 16 / 32 for `vip/`
(`VB_OWNERS_*`), 8 / 16 / 64 regions for `rg/` over 4 / 64 / 1024
services (`RG_*`). Every binding reserves `O` rows of host tables, so a
wider set is bought with memory (the limit register has the bytes), and
the record format does not change with it: a binding's image is a head
unit and `O` fixed-size rows, and the header records `O`. Its
consequences for compatibility:

- **The width is part of the image.** A replica refuses an image of
  another width, exactly as it refuses one of another arena, so a group's
  replicas run one variant.
  Changing a deployment's variant is a re-image (a fresh group, or every
  replica restarted from a log replay), never a rolling restart.
- **Epochs are unaffected.** `vip_epoch`, the authority generation and
  the recovery generation mean what they meant; a wider set just admits
  more joins before `CAPACITY`. Tokens name no width, and a token minted
  by a narrower build verifies against the same state.
- **Sharding instead of width.** Past `VB_OWNERS_MAX` (64), or where the
  arena cannot pay for the rows, a service's addresses split across
  bindings (one prefix per binding, each its own owner set), or the
  global tier steers flows across cells (`rg/`, each cell's set within
  its width). The width bounds one binding, not a service.

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

| `MOVE_FENCED` (7) | `[new_primary:8][fence_gen:4]` | `MOVE`, naming the fence generation (≠ 0) that ended the old emitter's authority: the promoted anchor's per-flow emission token is minted. |

Replies are the session reply's 38-byte shape:
`[op][status][flow:16][epoch:4][mirror_epoch:8][mirror_generation:8]`,
and on the wire every one is followed by a token trailer
`[token_present:1][reserved:3][FlowToken:48]` (`TR_WIRE_REPLY_LEN` = 90
bytes), so a reader of the 38-byte reply alone reads its first 38 bytes
as that reply.
A byte-identical retry of a record's last operation repeats its recorded
reply; a different command under the same id is `conflict`. The record
keeps that last command whole and compares bytes, so no other command can
pass for a retry. The dedupe window is one operation per flow, bounded by
construction.

### Per-flow emission tokens

The authority, not the coordinator, mints the token a promoted standby
presents before it may emit. `MOVE_FENCED` commits
`MOVE`'s promotion and records the fence generation it names (the
custody generation the session namespace's `FENCE_CONFIRM` carried); the
`FlowToken` is then derived from replicated state:

    [flow_id:16][epoch:4][anchor:8][fence_gen:4][capability:16]
    capability = SHA-256(seed ‖ "TRFLOW01" ‖ flow_id ‖ epoch ‖ anchor ‖ fence_gen)[..16]

— the fields of the traffic fabric's `cc_emission_token(flow_id, new_epoch,
anchor, fence_gen)` in its order, keyed by the group's capability seed
(the VIP registry's, replicated once by `SEED`; an unseeded group mints
nothing). The module puts the token in the `MOVE_FENCED` reply's trailer;
any replica re-derives it (`flow_token`) and a provider asks
`verify_flow_token` before enabling emission.

That question goes to the directory. A Fluxor continuity provider's token
check (`MSG_TOKEN_CHECK` 0xC2, `[token:48]`, on its `auth_req`) and an
address provider's check before it arms under `arm_authority`
(`MSG_ARM_AUTH_CHECK` 0x7A, the VIP emission token as its auth) arrive on
the module's `checks` port and are answered on `replies`:
`[token][verdict]` (0xC3) and `[addr][generation][sha256(auth)][verdict]`
(0x7B), the verdict 0 or `0x80 |` the registry's refusal. A check is
linearizable. The replica that takes one proposes a barrier, a `"CK"`
entry, and holds the check until its applied state reaches that entry.
Raft appends the barrier behind every entry committed before the check
arrived, so the answer reflects each of them: a token that a committed
move has ended never verifies, on any replica, however far behind it
ran. A check costs one commit of latency. Checks wait in a table of
their own (`MAX_CHECKS`), never behind registry commands; a check no
slot can take stays in the channel, and one whose barrier has not
applied within 5 seconds (the longest a Fluxor provider waits) is dropped
unanswered, which the provider reads as a refusal. The check refuses an
unseeded group, another anchor, epoch or fence generation, another
boot's arm, an address outside the token's prefix (the provider does
not parse the token, so this is the only place the address is checked
against it), and an auth longer than Fluxor's `ARM_AUTH_MAX` — that one
at once, with no barrier, since no state could admit it.
`TransportRegistry::answer_token_check` and `VipRegistry::answer_arm_check`
are the answers (`tests/flow_token.rs`, `tests/vip_registry.rs`).

The fence generation is not taken on trust. The module applies transport
commands through `apply_fenced`, and a new `MOVE_FENCED` commits only if
the session namespace's record of the flow (session id = flow id,
the traffic fabric's convention) holds a confirmed fence of exactly that generation
on the emitter being replaced, not yet consumed by the takeover's
`ACTIVATE` (`SessionRegistry::fence_confirmed_on`); otherwise it is
`unauthorized` (12), recorded like any refusal. Both namespaces are
replicated state applied in log order in the same module, so every
replica reads the same session record at that position and decides alike.
The takeover's order — `FENCE_CONFIRM`, then `MOVE_FENCED`, then the
session `ACTIVATE` that consumes the fence — is what the check needs; a
retry of a committed move is answered from its memo before the check, so
the consumed fence is not asked for again. A host `TransportRegistry`
applied with plain `apply` (no session namespace beside it) takes the
generation as named. A token verifies while its
anchor is the primary under the move that minted it: a re-`BIND` of the
standby set keeps it (the emitter did not change); a later `MOVE`,
`TOMBSTONE` or `RECOVERY_MARK` ends it for good, and a re-admission after
recovery needs a new fenced move. A retried `MOVE_FENCED` repeats its
recorded reply and carries the token only while the flow is still at the
epoch it committed. A plain `MOVE` mints nothing. A fence confirmed before
an unsafe-recovery mark admits no `MOVE_FENCED` after it: the session
namespace's `RECOVERY_MARK` clears every fence in flight.

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
| `RECOVERY_MARK` (12) | `[op_id:16][generation:8]` | Bumps `unsafe_recovery_generation`; a claim in flight returns to `PREPARING_NEW` with its fences voided and every current owner of the record to fence (an active/active add becomes a replacement; its `ABORT` leaves the record void); every committed binding is void until re-claimed and re-fenced. The reply's `vip_epoch` is the count of committed bindings voided. |
| `SEED` (13) | `[op_id:16][seed:32]` | Once per group: the capability seed. |
| `TOKEN_REISSUE` (14) | `[host:16][boot:16]` | A read in log order, changing nothing and recording no operation: the token `emission_token` derives for `host` now, when the epoch is the binding's, `host` is a committed owner under `boot`, the owners may emit, no confirmed fence names `host` and the binding's authority is current (`recovery_void` otherwise). |

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
answers `not_ready` everywhere. The leader proposes it the moment it
leads, not after a start-up delay: first a barrier (an empty entry) in
its own term, then, once that barrier has applied and the registry is
still unseeded, the `SEED` (`vip_registry::SeedPacer`). The barrier is
what keeps the `SEED` single: once an entry of the new term has applied,
no `SEED` an earlier leader left in the log can still commit behind it,
so a new leader either finds the group seeded or proposes the only one.
A barrier or `SEED` raft never places is proposed again from a fresh
barrier after `VB_SEED_RETRY_MS` (1 s); a new term starts the round
over. On a three-replica group on loopback the `SEED` applies on every
replica some tens of milliseconds after the election, so a consumer
needs no settle delay before its first `ACTIVATE` beyond waiting for a
leader (a `not_ready` answer is retried like any other). A second
committed `SEED`, should one ever race, is refused `conflict` on every
replica and the first stands. A token is a pure function of that
state: `emission_token` re-derives the current one for any owner on any
replica, a restart loses nothing, and a cached token stops verifying the
moment authority moves past it.

`TOKEN_REISSUE` is how an owner reads that token back over the wire. Every
`ACTIVATE` advances the binding's authority generation, and in an
active/active set the owners already in it did not propose the join that
advanced it, so the `ACTIVATE` reply carrying the new generation never
reaches them. The read is committed through the log rather than answered
from a local replica, so it is ordered after the join it follows and a
lagging follower cannot hand back an older generation. It answers only a
committed owner that may emit, under the boot incarnation it was admitted
with (a rebooted host re-claims), not named by a confirmed fence, on a
binding whose authority is current: voided by `RECOVERY_MARK` or committed
under an older recovery generation, it answers `recovery_void`. The token
it returns names the binding's current generations, so it stops verifying
at the next authority move like any other. A claim over an
`EMISSION_DISABLED` active/active set replaces the set rather than joining
it, so a disabled owner is never re-admitted by another host's commit.

## Failover-operation namespace

`fo/<operation_id>` (`modules/common/failover_registry.rs`) holds one
traffic-fabric `FailoverOperation` per operation id: the fixed 264-byte `WHFO`
record, kept as its
bytes. Clustor does not act on what a record asks
for; it owns the rule a record may change by, which is the rule
the producer's `fo_cas_check` states:

| Command | Body | Effect |
|---|---|---|
| `CAS` (1) | `[record:264]` | A new operation id is stored only as INTENT at phase generation 1. A byte-identical write of the stored record is `OK`. Otherwise the write must leave every field fixed at intent unchanged, advance the phase generation by exactly one, and make a legal transition of the record's kind under its fence requirement (the forward path, ABORTING inside a claim window, FAILED before the unsafe boundary, BLOCKED past it); anything else is `CONFLICT` carrying the stored record. A malformed frame (magic, version, reserved bytes, enum ranges, a target the traffic fabric's `VipTarget::decode` would refuse, its own SHA-256 trailer) is `INVALID`. |
| `REPLAY` (2) | — | A read through the log: changes nothing. Once it commits, the replica that proposed it streams every live (non-terminal) record to the requester, in creation order, as `REPLAY` replies, then an end-of-replay reply (op `REPLAY`, status `OK`, the count). |

The reply is `[op:1][status:1][present:1][reserved:1][live:4][record:264]`;
the statuses `OK` (0), `CONFLICT` (1), `REPLAY` (2) and `INVALID` (3) are
the traffic fabric's store answers, and `CAPACITY` (4) refuses a new operation
when every slot holds a live one. A terminal record stays, so a late
retry or a re-sent request with the same operation id is answered from
it, until a new operation needs its slot (the oldest terminal record
gives way first). Retention is what bounds that idempotence: a duplicate
of an evicted operation's intent is a new operation, and the epochs the
record carries keep it from acting on authority that has since moved. A
replay committed while another streams waits for it to end; a snapshot
install stops both unended, and the requester resends.

## Region namespace (the global tier)

`rg/<service>` (`modules/common/region_registry.rs`) is the low-rate
global group's state ([multi_site.md](multi_site.md)): each service's
region owner set, its DR generation and regional invalidation. The owner set is the `vip/` state
machine, regions as owners, so every `VB_OP_*` command is accepted in its
`vip/` layout (a region controller built on the VIP builders drives `rg/`
unchanged), keyed by the service's global key, and answered with the
`VipReply` it already reads followed by `[dr_generation:8]
[invalidated_readiness:8]` (`RG_REPLY_LEN`). A region owner's boot
incarnation is `[tag:8][readiness_generation:u64 LE]`.

- **DR generation.** Each binding counts its committed owner-set changes
  — an `ACTIVATE`, a `RELEASE` that removes a region or ends the set, a
  `RECOVERY_MARK` that voids it, an `ABORT` that leaves a recovered
  claim's record void, an `INVALIDATE` that newly voids one of its
  regions' owners. A retry, a refusal, a claim, a phase step, a mark that
  finds the binding void already and an invalidation that reaches no owner
  not already void count nothing. It is replicated state: a restarted
  controller reads the group's count, and every reply carries the
  binding's current one.
- **`INVALIDATE` (32)** `[op_id:16][region:16][readiness:8]`: the
  region's authority is void at or below `readiness` across every binding
  — its tokens stop verifying (`RG_ST_INVALIDATED`, 32), `TOKEN_REISSUE`
  returns none, an `ACTIVATE` that would commit it and a claim naming it
  at or below that readiness are refused — until a claim under a newer
  readiness generation. Per region the readiness only advances
  (`recovery_stale`); the operation id is idempotent like `RECOVERY_MARK`'s.
  The owner stays in the set until a fenced `RELEASE` or a replacing
  claim removes it: invalidation never stands in for a fence.
- **Seed.** The namespace mints under a seed derived from the group's
  (SHA-256 over a domain tag and the VIP seed), adopted when the
  directory's VIP `SEED` commits; `SEED` itself is not accepted here.

## Operation namespace

`op/<operation_id>` (`modules/common/operation_registry.rs`) is the
restart-safe operation record for the coordinators that have no
VIP-shaped one: a transport-continuity takeover (the traffic fabric's
`takeover_core`), a failure-domain evacuation (`failure_domain_core`) and
a region controller's DR operation (`dr_core`). One 256-byte `CLOP`
record per operation id, sealed by its own SHA-256 trailer:

    0   magic "CLOP"  version u16 = 1  reserved u16
    8   operation_id [16]
    24  kind u8  step u8  flags u8  reserved u8     kind: 1 TAKEOVER,
    28  reserved u32                                2 EVACUATION, 3 REGION
    32  phase_generation u64
    40  intent [120]       fixed at the first write; intent[0] = variant
    160 progress [64]      free between writes
    224 sha256(0..224) [32]

`step` is the coordinator's own enum value (`TkStep`, `fd_state`,
`DrStep`); `intent[0]` its variant (`TkKind`, `fd_action`, `fx_kind`).
`CAS` (1) `[record]` and `REPLAY` (2) `[kind]` (0: every kind) behave as
`fo/`'s, with the same reply shape (its reserved byte naming the kind)
and statuses, the same creation-order replay and retention. The rule:

| Kind | First write | Edges | Never |
|---|---|---|---|
| TAKEOVER | `TrBind` (pair) or `StandbyApplied` (planned, crash), flags 0 | `takeover_core`'s sequences, `CounterFloor` optional; a progress write on any non-terminal step | `COMMITTED` set anywhere but `TrMove → SrActivate`, or cleared; `Fallback` / `Failed` once committed; a fence generation or committed epoch changed once set; a committed record without both |
| EVACUATION | `REQUESTED` | REQUESTED → PREFLIGHTED / DIALING_OUT → MOVING / DRAINING → EVACUATED / OBSERVING → RESTORING → COMPLETE (a writer may persist only the later of two states one call passes) | ABORTED from MOVING, DRAINING or EVACUATED; BLOCKED_FENCE except from MOVING or RESTORING |
| REGION | `Wait` | any later step; `Done` (11) terminal | a step decrease; any flag |

The proposed layouts of intent and progress, so a coordinator encodes its
state mechanically (Clustor reads only the bytes the rule names):

- **TAKEOVER** intent: `[kind][mode][ingress][transport][fallback]
  [counter_gated][reserved:2][flow_id:16][service_id:16]
  [primary_anchor:8][standby_anchor:8][primary_host:16]
  [standby_host:16][sr_epoch:4][reserved:4][mirror_generation:8]
  [stability_ms:8][budget_ms:8]`; progress: `[why][outcome][counter]
  [reserved][tr_epoch:4][fence_gen:4][new_tr_epoch:4][new_sr_epoch:4]
  [fence_attempts:4][elapsed_ms:8][step_elapsed_ms:8][floors:8×3]`
  (`fence_gen` and `new_tr_epoch` are the ones the rule fixes; with
  `flow_id` they are the per-flow token's fields).
- **EVACUATION** intent: `[action][level][reserved:2][domain:4]
  [operation fields of the `FdIntent`]`; progress: the reason, the
  dial generation, moves done and failed, the baseline readiness.
- **REGION** intent: `[fx_kind][dr_mode][reserved:2][region:4]
  [target:4][reserved:4][service_id:16][op_seq:8][epoch_before:8]
  [authority_before:8][dr_before:8][recovery_generation:8]`; progress:
  the outcome, the last request id and command step, the fence
  generation.

## Attachment namespace

`att/<attachment_id>` (`modules/common/attachment_registry.rs`) commits
what the traffic fabric's private-service broker admits a connection under
(`attachment_core::AttachmentBoundary`): each attachment's generation and
each service's revocation generation.

| Command | Body after `[op]` | Effect |
|---|---|---|
| `COMMIT` (1) | `[op_id:16][attachment_id:16][producer_tenant:16][service_id:16][generation:8]` | The attachment's generation, strictly above the committed one (`stale` otherwise; a new attachment starts at any generation ≥ 1). The attachment is bound at its first commit to its service, created at revocation generation 1; naming another is `conflict`. |
| `REVOKE` (2) | `[op_id:16][producer_tenant:16][service_id:16][revocation_generation:8]` | Advances the service's boundary, strictly; every grant under an older one stops admitting new connections. |
| `READ` (3) | `[attachment_id:16]` | The boundary at this log position; changes nothing. |

The reply (`AT_REPLY_LEN` = 72) is `[op][status][reserved:2][covered:4]
[attachment_id:16][producer_tenant:16][service_id:16]
[attachment_generation:8][revocation_generation:8]` — the boundary in its
last 16 bytes; `covered` counts the service's attachments. Statuses: `ok`
(0), `invalid` (1), `stale` (2), `conflict` (3), `unknown` (4),
`capacity` (5). Each record keeps its last command whole for retries.
Records live as long as the group, so a generation never restarts lower
under a reused identity.

## Reservation namespace

`rs/` (`modules/common/reservation_registry.rs`) holds the strict
reservations that must never be issued twice, without per-flow churn
through consensus. Horizons are counted in the directory's committed
logical time (`timing.rs`), read at the entry's log position, so every
replica ends a horizon at the same entry. A command carrying one
(`RETIRE_BOOT`, `ADDR_RELEASE`) is admitted only behind the time-freshness
barrier a duration gets, and while a horizon is pending the leader keeps
proposing time, as it does for live deadlines; committed time may still
lag wall time by up to `logical_staleness_ms` at admission, so horizons
are declared with that margin.

| Command | Body after `[op][op_id:16]` | Effect |
|---|---|---|
| `RESERVE` (1) | `[identity:16][protocol:1][gateway:16][boot:8][pool_blocks:4]` | The lowest block of the pool that is free, released, or retired past its horizon, to `(gateway, boot)`; `exhausted` when none is, `retired` when the incarnation was. A block keeps the operation id and pool size of the grant that took it, so a retry is that grant: repeated while it stands, `conflict` (nothing granted) once the block was released, moved or retired. A zero operation id is `invalid`. the traffic fabric's `BlockAuthority::reserve`. |
| `RELEASE` (2) | `[identity:16][protocol:1][block:4][gateway:16][boot:8]` | Frees the block; only its holder may (`not_holder`). |
| `RETIRE_BOOT` (3) | `[gateway:16][boot:8][horizon_ms:8]` | The incarnation is gone: each block it holds is grantable once `horizon_ms` of committed time has passed, and the incarnation is remembered as retired (the last as many as the block arena holds), granted nothing again. The one block command that walks the arena. |
| `MOVE` (4) | `[identity:16][protocol:1][block:4][from_gateway:16][from_boot:8][to_gateway:16][to_boot:8]` | Hands a block to another incarnation for continuity (`retired` if that one was); `until` in the reply is the previous holder's horizon, the quarantine `adopt_block` honours. |
| `ADDR_RESERVE` (5) | `[record_id:16][tenant:16][family:1][len:1][prefix:16][parent:16]` | Holds a canonical range for a tenant unless a held range, or a quarantined one inside its horizon, of the family overlaps it (`overlap`, with `until`; never whose) — its own ancestors excepted. `parent` all zero: a top-level range (a BYOIP import). Otherwise the range is carved from that record (a VIP or sub-prefix of the import): see below. A record's parent is fixed for its life; re-reserving it under another is `conflict`. |
| `ADDR_RELEASE` (6) | `[record_id:16][horizon_ms:8]` | Quarantines the range for `horizon_ms`; reusable after. A record with a held child is not released (`conflict`): children first. |

An address manager holds each tenant's whole imported prefix as a
top-level record, so two managers of the group never admit overlapping
imports, and holds what it carves from one as a child naming that
record. A child's parent must be a record of the registry (`unknown`
otherwise) that is held, of the same family, containing the child
(`len` no shorter, prefix within), with an ancestor chain no longer
than `RS_ADDR_DEPTH_MAX` (4) — otherwise `invalid`. A child may overlap
its ancestor chain and nothing else live: a sibling, another import, a
quarantined range inside its horizon are `overlap` as for any range, and
a top-level range overlapping anything live, someone's child included,
is `overlap`. A child may be held for any tenant: `rs/` is not the
authorization layer — the manager that holds the parent carves it. These
parent refusals, and `ADDR_RELEASE`'s `conflict` under a held child,
leave the record's operation memo as it was, so the same operation
succeeds once the parent or children are in place; a quarantined child
does not hold its parent. A record some other record names as parent
never gives its slot away (its children go first), so a parent
reference always names a record.

The reply (`RS_REPLY_LEN` = 72) is `[op][status][kind][state][block:4]
[count:4][reserved:4][generation:8][until:8][holder:16][holder_boot:8]
[subject:16]`. Statuses: `ok` (0), `invalid` (1), `conflict` (2),
`exhausted` (3), `not_holder` (4), `overlap` (5), `capacity` (6),
`unknown` (7), `retired` (8). Every grant, move and re-reservation
advances the record's generation, which never wraps (`invalid` at
`u64::MAX`). A block record lives as long as its pool; an address record
whose quarantine has passed gives its slot to a new one when the arena is
full.

## Streamed snapshot

Every registry streams its snapshot as versioned records rather than a
whole-arena image: a header naming the version, the arena, the admitted
count and the record count, then one record per live slot carrying its
slot number (placement is replicated state, so images are byte-identical
across replicas), then — for the session registry — the timing
section's header and live entries. Restore validates the version, the
profile, every count and every cross-reference (a deadline without its
consumer object, two records for one slot or one identity, an address
record whose parent is not a record of the image, does not contain it,
is quarantined under a held child or sits past `RS_ADDR_DEPTH_MAX`) and fails
closed, leaving the registry empty. The module stages one chunk plus one
unit (`SNAP_CHUNK` + the largest record), independent of the profile;
the timing section streams the deadline heap position by position, and a
restored replica places each entry back where it streamed from, so it
holds the exporter's heap;
an export spans steps and holds committed applies until it completes,
so the image is one index's state; a begun or failed install holds
applies until an install succeeds. The image's sections are the session
registry, then the transport registry, then the VIP registry, then the
failover-operation store (each record with its creation sequence, so a
restored replica replays in the exporter's order), then the region
registry (its header, its VIP image, a DR generation per binding, the
invalidation table), then the operation store (with creation sequences,
as `fo/`), then the attachment boundaries (services, then attachments),
then the reservations (blocks, then address records, then the retired
incarnations). The session registry's header leads the image, and
each section's header carries version 1; an image of any other version
is refused. The format has one version: a layout change rewrites it in
place, so a group's replicas run one build and are upgraded together
(or re-imaged).

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
  for `TR_OP_*` bodies and the 38-byte `TransportReply` with its 52-byte
  token trailer.
- `MSG_VB_REQUEST` (0x94) / `MSG_VB_REPLY` (0x95): the same envelopes
  for `VB_OP_*` bodies and the `VipReply` (with the token).
- `MSG_FO_REQUEST` (0x96) / `MSG_FO_REPLY` (0x97): the same envelopes
  for `FO_OP_*` bodies and the 272-byte `FailoverReply`.
- `MSG_RG_REQUEST` (0x98) / `MSG_RG_REPLY` (0x99): `VB_OP_*` and
  `RG_OP_INVALIDATE` bodies and the `RgReply`.
- `MSG_OP_REQUEST` (0x9A) / `MSG_OP_REPLY` (0x9B): `OP_OP_*` bodies and
  the 264-byte `OperationReply`; after a committed REPLAY, one reply per
  live record of the kind, then the end of the replay.
- `MSG_AT_REQUEST` (0x9C) / `MSG_AT_REPLY` (0x9D): `AT_OP_*` bodies and
  the 72-byte `AttachmentReply`.
- `MSG_RS_REQUEST` (0x9E) / `MSG_RS_REPLY` (0x9F): `RS_OP_*` bodies and
  the 72-byte `ReservationReply`.
- Command layouts, status codes, and the snapshot formats are specified
  in `modules/common/session_registry.rs`,
  `modules/common/transport_registry.rs`,
  `modules/common/vip_registry.rs`,
  `modules/common/failover_registry.rs`,
  `modules/common/region_registry.rs`,
  `modules/common/operation_registry.rs`,
  `modules/common/attachment_registry.rs` and
  `modules/common/reservation_registry.rs`.

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

## Tiers and sites

A directory serves one tier (`scope`, docs/architecture/multi_site.md):
`all` (the default — one region, no global tier), `cell` (everything but
`rg/`) or `global` (`rg/`, and `op/` REGION and EVACUATION records). A
request in a namespace the other tier owns is answered, before it is
proposed, with `MSG_DIR_OUT_OF_SCOPE` (0xA0) `[request_id:8][request
msg:1][reason:1]` — reason 1 the namespace, 2 an `op/` record of a kind the
other tier owns — so a session's state never enters a log whose voters
span sites (`modules/common/directory_scope.rs`). The global tier runs on a
multi-site group, its quorum a majority across `min_sites` sites
(`consensus` `site_map`, `min_sites`); `smoke: 3` is the
site-loss smoke, a regional INVALIDATE committed one readiness higher
every 300 ms by the leader and logged by every replica that applies it
(`tests/site_loss_e2e.rs`).

## Fronts: the broker and egress surfaces

The namespaces a broker or an egress gateway stands on are reached
through `directory_front` (`modules/app/directory_front/`), one instance
per namespace: `namespace: rs` for egress block and address-range
reservations (an egress gateway's block authority, a tenant's ranges),
`namespace: att` for attachment boundaries (the private-service broker's
admission generations), `namespace: op` for operation records, with
`op_kind: evacuation` for a failure-domain controller's. The consumer
writes the namespace's request frames under its own request ids on
`request_in` and reads the committed replies back under them on
`answer_out`; the front owns everything between:

- each request goes to `requests` under an id of the front's own
  (`tag << 32 | counter`, the tag drawn once per start), so a reply to an
  earlier life's request or to another requester on the shared `replies`
  port is skipped (`foreign`);
- a request unanswered `retry_ms` (default 2000) after its last send is
  sent again — the same command, whose operation id makes it a retry the
  registry answers from the grant or record it made;
- an `op/` REPLAY's streamed records pass through as they arrive (each
  restarting its retry clock) and the REPLAY completes on its own reply;
- a request of another namespace, an `op/` record or REPLAY of another
  kind, or a malformed one is refused there, counted, and answered at once
  as `MSG_DIR_OUT_OF_SCOPE` `[consumer id][request msg][reason]` (1
  another namespace, 2 another kind, 3 malformed), as a directory of the
  other tier answers; `retry_ms` 0 is refused at init, since every resend
  is a log entry;
- at most eight requests are in flight; a ninth waits in `request_in`.

It answers nothing from state of its own and holds no record past its
reply. `tests/directory_front.rs` drives its core
(`modules/common/directory_front_core.rs`) against the real `rs/`, `att/`
and `op/` registries.

## Including the directory in another graph

`packaging/stack/clustor-directory.yaml` publishes the directory as the
`clustor-directory` stack (Fluxor's `docs/architecture/stacks.md`: a
published stack is included by name once pinned, or by path):
`peer_router`, `gateway`,
`consensus`, `durability`, `control_plane`, `admission` and `operations`
as a one-voter group whose peer router names itself, and this module as
its consumer, wired exactly as `configs/session-directory.yaml` wires
them (without the diagnostic HTTP surface). Its exports are the
directory's `requests`, `replies` and `checks` and the peer router's `net_in` /
`net_out`, which the includer wires to the platform's `linux_net`; its
params are `self_id`, `listen_port` (required) and the boot `smoke`. A
graph that needs a directory beside its own modules — a traffic fabric's
`continuity_coordinator`, whose transport and session requests and the
`MOVE_FENCED` reply with its `FlowToken` trailer go to it — includes the
stack and wires two edges; the reply boundary (committed and applied
before any reply) is the same one, because it is the same module on the
same log.

`tests/session_directory_e2e.rs`
(`the_included_directory_stack_commits_its_grants_and_its_time`) boots
`configs/session-directory-stack.yaml`, a graph holding nothing but the
included stack and its two socket edges, and proves the group elects
itself and the included directory's grants and committed expiry land as
in Clustor's own graph. A multi-voter directory stays Clustor's own
graphs (`session-directory-3node.yaml`): a stack cannot carry its peers'
addresses as one list param, and the single-voter shape is what a graph
that needs a local directory takes.

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
