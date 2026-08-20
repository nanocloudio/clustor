# Limit register

The list of clustor's *deliberate* hard ceilings, following the same
discipline as fluxor's `docs/architecture/limit_register.md`: a policy
ceiling found in source but absent here is a bug. Every checkable
row's `Symbol` must exist in its `Source` file as a `const` whose
value matches `Value`; a ceiling changed in source without updating
this register is a defect. A `Value` of `—` marks a row that is
documented but not value-checkable (the constant is not written as a
plain integer).

Pacing and backpressure bounds (batch sizes, rings that overwrite,
windows that defer work to the next tick) are not registered: they
shape throughput but never refuse work.

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
| HTTP request body at ingress | `MAX_BODY` | modules/app/operations/ingress.rs | 1024 | A request advertising a larger Content-Length is answered 413 and closed, never truncated. |
| Buffered HTTP request (head + body) | `RX_BUF` | modules/app/operations/ingress.rs | 2048 | A request that overruns the receive buffer is answered 431 and closed. |
| Concurrent diagnostic-HTTP connections | `MAX_CONNS` | modules/app/operations/ingress.rs | 32 | Overflow connections are refused at the accept boundary. |
| Concurrent HTTP `/propose` requests | `HTTP_INFLIGHT` | modules/app/operations/http.rs | 64 | Slot exhaustion answers 503 "propose queue unavailable". |
| Admin op body via HTTP | `ADMIN_BODY_MAX` | modules/common/http_admin.rs | 1022 | An oversize admin POST is answered 503 before any work is staged. |
| Concurrent peer connections | `MAX_CONNS` | modules/app/peer_router/mod.rs | 64 | A full connection table drops the accept; overflow clients never complete a handshake. |
| Local partitions per router | `MAX_LOCAL_PARTITIONS` | modules/app/partition_router/mod.rs | 4 | `num_partitions` is clamped at init; larger deployments compose routers. |
| Sessions in the session registry | `SR_MAX_SESSIONS` | modules/common/session_registry.rs | 64 | Fixed-size replicated state; a BIND with no free slot is refused `SR_ST_NO_CAPACITY`. |
| KEK-wrapped key blob | `SR_MAX_WRAPPED_KEY` | modules/common/session_registry.rs | 80 | A larger blob is refused at encode and at apply; the key is never stored. |
| Timing deadline slots | `TM_MAX_DEADLINES` | modules/common/timing.rs | 64 | A `KEY_PUT` whose TTL deadline cannot register fails `SR_ST_DEADLINE_CAPACITY` without storing the key. |
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
bodies at 1024 via ingress `MAX_BODY`. The facade cap governs the
direct consumer path only up to what the entry frame admits.

Duplicates: `MAX_NODES` and `MAX_PAYLOAD` are re-declared in
`modules/common/replica_facade.rs` for host-side consumers and must
stay equal to the registered constants above.

Cross-repo note: the ceiling that binds FIRST for the app-snapshot
round-trip is the state worker's export scratch in lattice
(`kv_state_worker` `SNAPSHOT_BODY_MAX` = `SCRATCH_BUF_SIZE −
APP_SNAPSHOT_HDR` ≈ 8 KiB). It is registered on the lattice side; this
register only guards clustor's own constants.
