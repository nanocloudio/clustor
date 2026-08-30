# Limit register

The inventory of clustor's deliberate finite bounds: a capacity or semantic
ceiling found in source but absent here is a bug. Every checkable
row's `Symbol` must exist in its `Source` file as a `const` whose
value matches `Value`; a ceiling changed in source without updating
this register is a defect. A `Value` of `—` marks a row that is
documented but not value-checkable (the constant is not written as a
plain integer).

`Capacity` bounds retained work or state, `shape` bounds one message or
record, `semantic` changes the guarantee when exhausted, and `pacing` only
limits work per step. Backpressure bounds are registered because they define
the maximum admitted concurrency and dominate throughput/latency. A ring that
overwrites or drops is not pacing: it is a lossy capacity boundary.

### What is not a row

A constant qualifies when reaching it changes observable behaviour —
something is refused, evicted, dropped, deferred, or answered
differently. Four families of constant do not, and are deliberately
absent so that "absent here is a bug" stays a checkable claim:

- **Wire and on-disk record widths.** `AE_HDR_LEN`, `DURABILITY_PROOF_LEN`,
  `META_SLOT_SIZE`, `SNAP_HDR_LEN` and their kin define a layout; they are
  not ceilings anything can reach. The formats are specified in
  [wire.md](wire.md) and the frame contract in `modules/common/wal_frame.rs`.
- **Caps defined in terms of a registered one.** A constant written as
  an expression over a registered symbol tracks it in source, so a
  second row would create two places to update and one to forget. The
  registered symbol is the row; the derivation belongs in its Reason.
  Current cases: `PENDING_BODY_CAP`, `PROPOSAL_BATCH_CAP`,
  `MEMORY_ENTRY_BODY_CAP`, `PROPOSAL_BUF` and `MSG_BUF` are each
  `wal_frame::MAX_ENTRY_BODY`; `CMD_MAX` derives from `ENV_BUF`,
  `EXPORT_BUDGET` from `SAFE_EXPORT_MAX`, `SEND_STAGE_MAX` from
  `ROUTE_FRAME_MAX`, and `SR_MAX_CMD` from `SR_MAX_WRAPPED_KEY`.
- **Striping and resolution factors.** `DEDUP_SHARDS` picks which of 16
  high-water slots an index consults. Nothing is exhausted at 16; a
  different value changes collision behaviour, not a guarantee.
- **Opcodes, protocol ids, state tags and timing intervals.**

Modules outside the replicated substrate — the `consensus_bench` and
`nvme_bench` drivers, `clustor_cli`, `example_consumer` — are also out of
scope. Their bounds are measurement apparatus, not deployment envelope.

## Deliberate caps

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| App-snapshot body (capture + install accumulation, boot restore) | `MAX_SNAPSHOT_BODY` | modules/app/durability/snapshot.rs | 16384 | Policy: bounds the memory-store worst case (see below). |
| Snapshot chunk per channel frame | `MAX_CHUNK_BODY` | modules/app/durability/snapshot.rs | 4096 | Wire pacing: one install-transfer chunk per frame; totals are unbounded because the stream is chunked. |
| Retention-floor table (distinct consumer ids) | `RETENTION_FLOOR_SLOTS` | modules/app/durability/snapshot.rs | 32 | Fail-closed: overflow sets a sticky flag and the compaction trigger stops advancing. |
| Command body through the replica facade | `MAX_COMMAND_BYTES` | modules/common/replica_facade.rs | 4096 | Policy: clustor orders metadata, not bulk; larger bodies are refused with `ProposeError::CommandTooLarge` (see interaction note below). |
| WAL entry body | `MAX_ENTRY_BODY` | modules/common/wal_frame.rs | 2048 | Frame contract: an oversize AppendEntries entry is refused as structurally invalid, and replay treats a larger length as a torn frame. |
| Channel envelope payload | `MAX_PAYLOAD` | modules/common/wire.rs | — | The envelope's u16 length field caps payloads at 0xFFFF; every encoder refuses rather than truncates. |
| Replicas per partition | `MAX_NODES` | modules/common/types.rs | 7 | Topology policy: `voter_count` is clamped at init and higher replica ids are dropped. |
| Follower log-matching term ring | `TAIL_TERM_RING` | modules/app/consensus/raft.rs | 64 | Capacity: recent `(index → term)` for follower-side log matching and Raft §5.3 conflict repair. Only the uncommitted tail can diverge, and it is bounded by `MAX_UNCOMMITTED_INFLIGHT` (48), so the ring covers every index a conflict check can legitimately target; indices at or below `commit_index` are trusted without a ring hit. It must stay above the uncommitted window — the two move together. |
| Commit-latency timestamp ring | `COMMIT_TS_RING` | modules/app/consensus/raft.rs | 64 | Capacity, observability only: append→commit timestamps for the commit-latency histogram. A wrap before commit drops that sample; an equality check keeps a wrapped slot from being attributed to the wrong entry. |
| Leader ReadIndex probes in flight | `MAX_INFLIGHT_PROBES` | modules/app/consensus/raft.rs | 32 | A full probe table answers unconfirmed, and the read is rejected to the caller for retry. |
| Pending linearizable reads at apply | `PENDING_READ_SLOTS` | modules/app/consensus/apply.rs | 16 | A full queue evicts the oldest read with an explicit client reject, so the submitter fails closed. |
| Pending committed-entry bodies at apply | `PENDING_ENTRY_SLOTS` | modules/app/consensus/apply.rs | 64 | Capacity/backpressure: sized above the 48-entry uncommitted window so committed bodies are not evicted before apply. Changing either side requires a joint review. |
| Coalesced proposals per WAL entry | `MAX_BATCH_PROPOSALS` | modules/app/consensus/raft.rs | 256 | Shape/pacing: caps correlation records in one proposal batch; remaining proposals wait for another step. The byte cap normally binds first. |
| Uncommitted leader entries | `MAX_UNCOMMITTED_INFLIGHT` | modules/app/consensus/raft.rs | — | Typed value 48. Raft stops pulling proposals until commit advances; this is the principal quorum-latency throughput window. It must stay at or below apply and tail-ring capacity. |
| WAL-unacknowledged entries | `MAX_WAL_UNACKED` | modules/app/consensus/raft.rs | — | Typed value 256. Raft stops admission when the WAL falls behind; a stalled WAL becomes backpressure rather than unbounded divergence. |
| Pending WAL requests in replicator | `MAX_PENDING_WAL_REQS` | modules/app/consensus/replicator.rs | 16 | Backpressures further work while WAL request/reply state is occupied. |
| ReadIndex seam queue | `PROBE_QUEUE_SLOTS` | modules/app/consensus/seam.rs | 8 | A full Raft reply queue currently drops the confirmation silently. This is a correctness-sensitive lossy boundary and should become retained backpressure or an explicit reject. |
| Client correlation ids in flight | `CORR_RING` | modules/app/gateway/codec.rs | 64 | Lossy capacity: correlation ids held between proposal submission and commit. Overflow evicts the oldest entry; that client's response is then dropped and counted. Fail-open by design — a dropped response never becomes a misrouted one. |
| Assigned-index → connection map | `IDX_RING` | modules/app/gateway/codec.rs | 64 | Lossy capacity: `wal_index → conn_id` for committed proposals, same eviction and drop-not-misroute contract as `CORR_RING`. |
| Admin commands awaiting their applied record | `CMD_RING` | modules/app/operations/admin.rs | 16 | Lossy capacity: in-memory predecessors for admin ops in flight through replication. The supported op set is double-apply-safe by construction (FREEZE→FREEZE, etc.), so a lost predecessor at worst re-applies an idempotent op. |
| Peer key fingerprint | `PEER_FP_MAX` | modules/app/peer_router/mod.rs | 32 | Shape: longest key fingerprint `MSG_PEER_IDENTITY` carries (SHA-256). |
| Peer/client connection staging | `BUF_SIZE` | modules/app/peer_router/mod.rs | 8192 | Shape: per-connection staging, pinned to fluxor's `CHANNEL_BUFFER_SIZE` — nothing larger can transit a channel. Undersizing this drops frames silently at every hop (`channel_read_msg` discards oversized payloads, encoders return 0): followers wedge on the replication path and clients time out on the response path. |
| `/metrics` export staging | `EXPORT_BUF_LEN` | modules/app/operations/telemetry.rs | 8192 | Capacity: one full channel ring. `SAFE_EXPORT_MAX` is the byte budget actually applied when building the payload, so an export always fits one atomic frame. |
| WAL replay-complete handshake attempts | `REPLAY_REEMIT_MAX_ATTEMPTS` | modules/app/durability/wal.rs | — | Semantic; typed value 256. `MSG_WAL_REPLAY_COMPLETE` is re-emitted on a cadence rather than once, because a lone message written before raft's first pump can be missed across the SPSC bridge. raft ignores duplicates, so re-emission is idempotent — but after the last attempt the handshake stops, and a raft that still has not consumed it stays `awaiting_replay` with proposal intake wedged. |
| WAL replay segment-gap tolerance | `REPLAY_GAP_TOLERANCE` | modules/app/durability/wal.rs | — | Semantic; typed value 16. Consecutive missing segment sequence numbers replay probes before declaring the log ended, which bounds startup cost on an empty WAL. It covers INTERIOR gaps left by compaction. The leading-gap case — a long-lived log whose first surviving segment sits far past seq 1 — is not left to this budget: replay consults the persisted floor sidecar once per pass and starts from it, because exhausting the miss budget before reaching the survivors would orphan the whole durable log. |
| App-snapshot capture wait | `APP_CAPTURE_TIMEOUT_TICKS` | modules/app/durability/snapshot.rs | — | Semantic; typed value 2000 (~2 s at the rig's 1 ms tick). On expiry the capture is abandoned and counted in `app_captures_timed_out`, so a wedged app costs one rotation's snapshot rather than stalling the snapshot engine. |
| Admin envelope staging | `ENV_BUF` | modules/app/operations/admin.rs | 1024 | Shape: every envelope staging buffer in the admin component, matching the 1 KiB channel-message scratch. The longest command it can carry is `CMD_MAX = ENV_BUF - 12`, because the replicated form prepends `ADMIN_MAGIC` (8) and `command_id` (4) inside the same buffer. |
| HTTP request body accepted | `MAX_EXT_BODY` | modules/app/operations/http.rs | 1024 | A larger forwarded body is answered 413, never truncated. Wire-side body/connection bounds are wave's (`max_body_kib`, per-target slot tables). |
| HTTP request path accepted | `MAX_EXT_PATH` | modules/app/operations/http.rs | 64 | A longer path is answered 404 — nothing this surface serves is longer. |
| Complete HTTP request staging | `MAX_EXT_REQUEST` | modules/app/operations/http.rs | 8192 | Bounds the assembled external request/envelope. Requests that do not fit are refused rather than partially interpreted. |
| Single-envelope response body / `/metrics` stream slice | `RESP_SLICE` | modules/app/operations/http.rs | 3072 | Sized under wave's per-connection send buffer; larger bodies stream via MORE_BODY. |
| Concurrent HTTP `/propose` requests | `HTTP_INFLIGHT` | modules/app/operations/http.rs | 64 | Slot exhaustion answers 503 "propose queue unavailable". |
| Admin op body via HTTP | `ADMIN_BODY_MAX` | modules/common/http_admin.rs | 1022 | An oversize admin POST is answered 503 before any work is staged. |
| Volatile WAL retention window | `VOLATILE_RETENTION_SLOTS` | modules/app/durability/wal.rs | 256 | Lossy capacity: how far back a volatile replica can serve a random-access refetch. Sizes both WAL rings on that variant, so it is also the knob that sets its module-state cost (2064 B per slot). An index below the floor answers NOT_FOUND and escalates to snapshot install. |
| Retained proposal bodies | `MEMORY_RING_SIZE` | modules/app/durability/wal.rs | — | Variant-dependent: `VOLATILE_RETENTION_SLOTS` on a volatile build, 1 on a disk build, which never populates the ring (`no_fs`, its only write gate, is never set there). |
| WAL entry-location map | `ENTRY_LOC_RING_SIZE` | modules/app/durability/wal.rs | — | Variant-dependent lossy capacity: 8192 on a disk build, `VOLATILE_RETENTION_SLOTS` on a volatile one. On disk an index below the floor still resolves through a bounded segment scan, so the bound is not a recovery ceiling; on volatile there are no segments to scan and the floor is the retention edge. |
| WAL staged write batch | `WRITE_BUF_SIZE` | modules/app/durability/wal.rs | 16384 | Capacity, sized to hold `group_max_pending=4` full frames so a group becomes one provider write rather than merely a grouped fsync. A frame that does not fit the REMAINING space flushes the batch first, and is stashed for the next step if the flush cannot drain. A frame larger than the whole buffer is a hard mis-sizing: it is refused and counted in `write_errors` rather than stashed, because retrying it would spin. `MAX_ENTRY_LEN` (2064) keeps that branch unreachable in a correctly composed graph. |
| `Wal` module-state footprint | `WAL_FOOTPRINT_BUDGET` | modules/app/durability/wal.rs | — | Variant-dependent compile-time assertion, not a runtime ceiling: 320 KiB on a disk build, 600 KiB on a volatile one, each a little above the actual size. Module state comes from `module_state_size()` rather than BSS, so a ring re-inflated past the budget fails the build instead of silently costing every replica half a megabyte. |
| WAL durability-fence ring | `FENCE_RING_MAX` | modules/app/durability/wal.rs | 8 | `fence_depth` is clamped to this capacity. A full ring delays issue/acknowledgement; it must not overwrite an unacknowledged fsync fence. |
| Raft metadata copies | `META_SLOTS` | modules/app/consensus/raft.rs | 2 | Two alternating metadata records provide recoverable publication; this is redundancy policy, not user capacity. |
| Snapshot pointer copies | `SNAP_PTR_SLOTS` | modules/app/durability/snapshot.rs | 2 | Two alternating pointer records provide recoverable publication; this is redundancy policy, not user capacity. |
| Raft metadata path staging | `META_PATH_MAX` | modules/app/consensus/raft.rs | 32 | Bounds internally generated per-partition metadata paths; builders and partition-id formatting must remain within it. |
| WAL path staging | `WAL_PATH_MAX` | modules/app/durability/wal.rs | 48 | Bounds internally generated segment/index paths; builders must not silently truncate a generated name. |
| Snapshot path staging | `SNAP_PATH_MAX` | modules/app/durability/snapshot.rs | 64 | Bounds internally generated snapshot/pointer paths; builders must not silently truncate a generated name. |
| Concurrent peer connections | `MAX_CONNS` | modules/app/peer_router/mod.rs | 64 | A full connection table drops the accept; overflow clients never complete a handshake. |
| Routed peer/client frame | `ROUTE_FRAME_MAX` | modules/app/peer_router/mod.rs | 4096 | Oversized frames are dropped and counted. All gateway/peer copies must share this bound; undersizing any hop wedges replication or times out clients. |
| Local partitions per router | `MAX_LOCAL_PARTITIONS` | modules/app/partition_router/mod.rs | 4 | `num_partitions` is clamped at init; larger deployments compose routers. |
| Node-set identifier width | `NODE_SET_CAPACITY` | modules/common/types.rs | — | Typed value 8. This is the bitset envelope; active voters remain capped at `MAX_NODES` (7). |
| Consumer facade default in-flight requests | `DEFAULT_INFLIGHT_CAPACITY` | modules/common/replica_facade.rs | 64 | Per-consumer backpressure table. Callers may select another capacity but must size correlation state and retry policy together. |
| Sessions in the session registry | `SR_MAX_SESSIONS` | modules/common/session_registry.rs | 64 | Fixed-size replicated state; a BIND with no free slot is refused `SR_ST_NO_CAPACITY`. |
| KEK-wrapped key blob | `SR_MAX_WRAPPED_KEY` | modules/common/session_registry.rs | 80 | A larger blob is refused at encode and at apply; the key is never stored. |
| Pending session-directory proposals | `MAX_PENDING` | modules/app/session_directory/mod.rs | 16 | A full table leaves requests in the input channel. If the proposal channel fills after consumption, the request is dropped and the client must recover by reply-timeout retry; slots expire after 10 seconds. |
| Deterministic-timing owners | `TM_MAX_OWNERS` | modules/common/timing.rs | 4 | Rejects another independently drained timing owner. |
| Timing deadline slots | `TM_MAX_DEADLINES` | modules/common/timing.rs | 64 | A `KEY_PUT` whose TTL deadline cannot register fails `SR_ST_DEADLINE_CAPACITY` without storing the key. |
| RBAC connection identities | `IDENTITY_SLOTS` | modules/app/operations/rbac.rs | 32 | Security defect: on overflow a new connection receives no binding, and an absent binding falls back to `default_role`, currently operator by default. Until fixed, this narrower table can make peer-router connections fail open rather than merely lose identity metadata. |
| RBAC SVID prefix | `SVID_PREFIX_MAX` | modules/app/operations/rbac.rs | 64 | Identity matching sees at most this prefix; longer identities are truncated for role matching and require collision-safe provisioning. |
| Telemetry metric slots | `METRIC_SLOTS` | modules/app/operations/telemetry.rs | 320 | LRU-evicts the oldest metric and increments an eviction counter. This can remove readiness/diagnostic evidence under high-cardinality instrumentation. |
| Metrics export payload | `SAFE_EXPORT_MAX` | modules/app/operations/telemetry.rs | 7400 | The export must fit one atomic channel frame; records past the budget are dropped and counted in the eviction metric. |

## Notes

On `MAX_SNAPSHOT_BODY`: bodies are 40 B disk-resident markers for disk
state stores (the store's manifest-named runs ARE the snapshot);
full-fidelity bodies exist only for memory stores, whose bounded worst
case must fit. A body that does not fit is refused at the EXPORT side
(the app emits no chunks and the WAL stays authoritative) — see the
denial accounting on the state worker. If a memory-store deployment
outgrows the cap, size the buffer from the deployment envelope via
fluxor's elastic resource region rather than raising the const — the
buffer is per-module state, and the elastic path keeps the envelope
reviewable on one screen.

Interaction: on the replicated path the tighter ceiling binds first.
`MAX_ENTRY_BODY` (2048) caps what one WAL entry can carry, so a
facade-legal command near `MAX_COMMAND_BYTES` (4096) is refused at
the gateway's staging bound (2048); the HTTP `/propose` bridge caps
bodies at 1024 via `MAX_EXT_BODY`. The facade cap governs the
direct consumer path only up to what the entry frame admits.

Duplicates: `MAX_NODES` and `MAX_PAYLOAD` are re-declared in
`modules/common/replica_facade.rs` for host-side consumers and must
stay equal to the registered constants above.

Cross-repo note: the ceiling that binds FIRST for the app-snapshot
round-trip is the state worker's export scratch in lattice
(`kv_state_worker` `SNAPSHOT_BODY_MAX` = `SCRATCH_BUF_SIZE −
APP_SNAPSHOT_HDR` ≈ 8 KiB). It is registered on the lattice side; this
register only guards clustor's own constants.

## Topology and composition

`MAX_NODES=7` is a replica-group ceiling, not a cluster-wide scaling target.
Three replicas are generally the useful availability/performance baseline;
five or seven increase failure tolerance at the cost of quorum traffic and do
not add storage capacity because every replica holds the same partition. Scale
well beyond three machines by composing independent partition groups and
routing ranges between them. Each partition router hosts at most four local
partitions, while Lattice currently exposes only two partition ports per KV
request router and 64 ranges per map; those Lattice bounds can bind before
Clustor's local partition capacity.

Single-node mode still exercises the ordered log, deterministic apply,
snapshots, and recovery but removes network quorum latency and availability.
Raw in-memory Lattice mode bypasses Clustor entirely and is a cache profile,
not a durable log. Replicated in-memory mode uses Clustor for ordering and
failover but keeps Lattice's 1024-key/4096-byte-value table and its much smaller
memory-snapshot envelope.

## Pacing limits

These deliberately defer work rather than refuse a finite workload:

| Limit | Symbol | Source | Value | Behaviour |
|---|---|---|---:|---|
| WAL entry pump per step | `MAX_ENTRY_PUMP_RECORDS` | modules/app/durability/wal.rs | 8 | Remaining records wait for another step. |
| WAL sync/fsync pump per step | `MAX_SYNC_FSYNC_RECORDS` | modules/app/durability/wal.rs | 4 | Remaining fences wait for another step. |
| WAL replay frames per step | `REPLAY_FRAMES_PER_STEP` | modules/app/durability/wal.rs | 4 | Remaining frames wait for another step. Each frame costs two reads plus a CRC over up to 2 KiB, so four keeps a step inside the guard while still draining a large segment in reasonable wall-clock. |
| WAL below-floor segment scan per step | `SCAN_RECORDS_PER_STEP` | modules/app/durability/wal.rs | 16 | Remaining records wait for another step. The scan cursor persists across steps and across served requests, so a sequential recovery resumes rather than rescanning from the segment start. |
| WAL segment unlinks per step | `COMPACT_UNLINKS_PER_STEP` | modules/app/durability/wal.rs | 4 | Remaining deletions wait for another step. `FS_UNLINK` is synchronous, so `continue_compaction` paces a deep post-snapshot trim rather than unlinking the whole droppable range in one step. |
| Deterministic-time drain batch | `TM_BATCH_MAX` | modules/common/timing.rs | 8 | Remaining deadlines wait for another committed drain. |

Snapshot chunks are 4096 bytes as registered above. These values must be
benchmarked with the 48-entry quorum window, the
`VOLATILE_RETENTION_SLOTS`-entry WAL window, and WAL fence depth. Failure to reschedule deferred work is a correctness defect.

## Known risk and maintenance contract

- The ReadIndex probe table correctly returns unconfirmed when its 32 slots
  fill, but the eight-slot reply seam can silently drop a confirmation. Make
  this path lossless or explicitly rejected before treating strict reads as
  complete under saturation.
- The RBAC identity table is half the peer connection table. Its overflow path
  discards a new binding and missing bindings currently fall back to the
  operator-default role. This must become explicit fail-closed denial (and be
  saturation-tested) before the connection profile is safe.
- The 2048-byte WAL body binds before the facade's nominal 4096-byte command.
  Either narrow the advertised facade contract or introduce deterministic
  chunking above consensus.
- Lattice's 8164-byte memory snapshot binds before this register's 16384-byte
  Clustor snapshot body. Snapshot compatibility is a graph property, not a
  local constant.
- The host test checks documented literal values against source, but it does
  not discover a new source constant omitted here. New fixed tables, bounded
  buffers, capacity/depth/slot constants, overwrite/drop paths, and semantic
  fallbacks must update this register. A reverse source scan remains needed to
  make completeness mechanical; non-constant behaviours will still need
  review even after that guard exists.
