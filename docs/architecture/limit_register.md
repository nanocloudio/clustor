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
| Leader ReadIndex probes in flight | `MAX_INFLIGHT_PROBES` | modules/app/consensus/raft.rs | 32 | A full probe table answers unconfirmed, and the read is rejected to the caller for retry. |
| Pending linearizable reads at apply | `PENDING_READ_SLOTS` | modules/app/consensus/apply.rs | 16 | A full queue evicts the oldest read with an explicit client reject, so the submitter fails closed. |
| Pending committed-entry bodies at apply | `PENDING_ENTRY_SLOTS` | modules/app/consensus/apply.rs | 64 | Capacity/backpressure: sized above the 48-entry uncommitted window so committed bodies are not evicted before apply. Changing either side requires a joint review. |
| Coalesced proposals per WAL entry | `MAX_BATCH_PROPOSALS` | modules/app/consensus/raft.rs | 256 | Shape/pacing: caps correlation records in one proposal batch; remaining proposals wait for another step. The byte cap normally binds first. |
| Uncommitted leader entries | `MAX_UNCOMMITTED_INFLIGHT` | modules/app/consensus/raft.rs | — | Typed value 48. Raft stops pulling proposals until commit advances; this is the principal quorum-latency throughput window. It must stay at or below apply and tail-ring capacity. |
| WAL-unacknowledged entries | `MAX_WAL_UNACKED` | modules/app/consensus/raft.rs | — | Typed value 256. Raft stops admission when the WAL falls behind; a stalled WAL becomes backpressure rather than unbounded divergence. |
| Pending WAL requests in replicator | `MAX_PENDING_WAL_REQS` | modules/app/consensus/replicator.rs | 16 | Backpressures further work while WAL request/reply state is occupied. |
| ReadIndex seam queue | `PROBE_QUEUE_SLOTS` | modules/app/consensus/seam.rs | 8 | A full Raft reply queue currently drops the confirmation silently. This is a correctness-sensitive lossy boundary and should become retained backpressure or an explicit reject. |
| HTTP request body accepted | `MAX_EXT_BODY` | modules/app/operations/http.rs | 1024 | A larger forwarded body is answered 413, never truncated. Wire-side body/connection bounds are wave's (`max_body_kib`, per-target slot tables). |
| HTTP request path accepted | `MAX_EXT_PATH` | modules/app/operations/http.rs | 64 | A longer path is answered 404 — nothing this surface serves is longer. |
| Complete HTTP request staging | `MAX_EXT_REQUEST` | modules/app/operations/http.rs | 8192 | Bounds the assembled external request/envelope. Requests that do not fit are refused rather than partially interpreted. |
| Single-envelope response body / `/metrics` stream slice | `RESP_SLICE` | modules/app/operations/http.rs | 3072 | Sized under wave's per-connection send buffer; larger bodies stream via MORE_BODY. |
| Concurrent HTTP `/propose` requests | `HTTP_INFLIGHT` | modules/app/operations/http.rs | 64 | Slot exhaustion answers 503 "propose queue unavailable". |
| Admin op body via HTTP | `ADMIN_BODY_MAX` | modules/common/http_admin.rs | 1022 | An oversize admin POST is answered 503 before any work is staged. |
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
| Deterministic-time drain batch | `TM_BATCH_MAX` | modules/common/timing.rs | 8 | Remaining deadlines wait for another committed drain. |

Snapshot chunks are 4096 bytes as registered above. These values must be
benchmarked with the 48-entry quorum window, 256-entry WAL window, and WAL
fence depth. Failure to reschedule deferred work is a correctness defect.

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
