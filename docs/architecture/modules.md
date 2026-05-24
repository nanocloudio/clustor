# Module Graph

Clustor is a graph of 23 cooperative fluxor substrate modules,
plus `example_consumer` as a minimal downstream demo wired into the
smoke graph. The modules implement Raft consensus, durability, and
a small control plane. They ship as position-independent `no_std`
ELFs, communicate over mailbox channels, and run on the fluxor
runtime — Pi 5 / CM5 hardware or a host-linux harness. The graph
is the implementation; there is no separate "library" layer
underneath.

The decomposition pins each module to a single scheduling concern
with bounded step time. Modules with shared deadlines and tight
data dependencies sit on the same core; cross-core hops use
SEV/WFE-woken mailbox channels (~200ns latency on CM5's coherent
L3). The consensus hot path runs as an inlined topological walk
on a single poll-mode core, so `raft_engine → wal →
durability_ledger → commit_tracker` executes as one fused
iteration with no scheduler dispatch between steps.

---

## Module reference

### Network surface

Three modules — `nic`, `ip`, `tls` — are fluxor foundation modules,
shared with every fluxor application. The rest are clustor's own.

| Module | Description |
|--------|-------------|
| `nic` | Kernel-bypass NIC driver (DPDK / io_uring); exchanges raw frames with the IP stack at line rate. *(fluxor foundation)* |
| `ip` | TCP/UDP socket service with connection tracking; provides the transport substrate for all HTTP and Raft RPC traffic. *(fluxor foundation)* |
| `tls` | TLS 1.3 termination (ChaCha20-Poly1305, AES-GCM, P-256 ECDH) with SPIFFE identity and X.509 validation. *(fluxor foundation)* |
| `peer_router` | Multi-peer connection routing. Maps replica_id to TCP connections, manages outbound CMD_CONNECT with reconnection backoff, demuxes routed envelopes per peer, and splits inbound traffic between client (→ `client_surface`) and peer (→ `replicator`) paths. |
| `http_ingress` | HTTP/1.1 listener and parser. Frames inbound requests as `MSG_HTTP_REQUEST` for `http_adapter`. See [../net_http.md](../net_http.md). |

### Client ingest

| Module | Description |
|--------|-------------|
| `client_codec` | Parses inbound client requests (read / write / admin); frames responses; multiplexes connections over the socket service. |
| `throttle_gate` | Admission control point. Consumes credit tokens from `flow_controller` and rejects or enqueues requests that exceed the throttle envelope. |
| `partition_router` | Routes proposals to the correct per-partition `raft_engine` instance based on partition id. |
| `client_surface` | Client envelope adapter. Demuxes inbound clustor wire envelopes from `peer_router` to `raft_engine`, `client_codec`, or `rbac`, and aggregates outbound responses, rejects, and telemetry payloads. Not an HTTP parser — `http_ingress` owns HTTP framing. |

### Raft consensus core

| Module | Description |
|--------|-------------|
| `raft_engine` | Core Raft state machine: election terms, pre-vote protocol, leader heartbeats, vote handling, leadership transfer coordination. |
| `replicator` | Pipelines AppendEntries to followers with batch framing; collects DurabilityAck responses and advances match indices; detects structural lag. |
| `commit_tracker` | Computes quorum commit index from match indices and durability acks; gates commit advancement on durability mode (Strict / GroupFsync / Relaxed). |
| `apply_pipeline` | Ordered, deduplicated delivery of committed entries to the embedded state machine; maintains apply index and dedup shard state. |

### Persistence

| Module | Description |
|--------|-------------|
| `wal` | Write-ahead log with AEAD-encrypted segments. Appends framed entries (binary or JSON encoding) with CRC32C integrity lanes; fsyncs per entry and emits the local FsyncAck stamped with `self_id` directly to `durability_ledger`. |
| `durability_ledger` | Tracks per-node last-fsynced indices; computes quorum durability proofs; emits system log entries on durable transitions. |
| `snapshot_engine` | Manages full and incremental snapshot cadence; coordinates chunked export with bandwidth throttling and AEAD-signed manifest handshakes; validates imports with chain verification. |

### Control plane

| Module | Description |
|--------|-------------|
| `cp_bridge` | HTTP client to the external control-plane service; fetches and refreshes CP proofs on a state-dependent polling schedule (Fresh → 5s, Stale → 600ms). |
| `cp_proof_cache` | Cache state machine (Fresh / Cached / Stale / Expired) governing read/write availability; triggers strict-fallback transitions when proofs age beyond grace period. |
| `placement_router` | Epoch-based partition-to-node routing; validates routing epochs on inbound requests and rejects stale placements. |
| `read_gate` | Issues linearizable read permits by verifying quorum CP proof equality; blocks reads during strict-fallback with structured blocking reasons. |

### Operations and security

| Module | Description |
|--------|-------------|
| `flow_controller` | Dual-token PID controller (entry credits + byte credits) with configurable gains per profile (Latency / Throughput / WAN); emits throttle envelopes with credit hints. |
| `key_manager` | DEK/KEK epoch watcher with weekly rotation and 48h retention; maintains nonce reservation ledger for AES-GCM counter safety. |
| `rbac` | Evaluates RBAC manifests (Operator / TenantAdmin / Observer / BreakGlass roles); validates break-glass SPIFFE SVIDs with TTL ≤ 300ms; writes to signed audit log. |
| `admin_handler` | Idempotency-keyed admin envelope. Routes `FREEZE` / `THAW` / `TRANSFER_LEADER` / `DURABILITY_MODE` / `SNAPSHOT` to `raft_engine` and replies with `ADMIN_STATUS_OK` / `ADMIN_STATUS_DUPLICATE`. `ADD_VOTER` / `REMOVE_VOTER` return `ADMIN_STATUS_UNSUPPORTED`; the joint-consensus path is documented in [lifecycle.md](lifecycle.md#membership-changes-and-joint-consensus). |
| `http_adapter` | Translates parsed `MSG_HTTP_REQUEST` envelopes into the appropriate downstream wire message (`/admin/<op>` → `admin_handler`) and frames the reply as `MSG_HTTP_RESPONSE`. |
| `telemetry_agg` | Metrics aggregator with fixed histogram buckets; incident correlation with storm guard; feature gate state tracking; `/readyz`, `/why`, `/metrics` payloads consumed by `http_adapter`. |

### Examples

| Module | Description |
|--------|-------------|
| `example_consumer` | Minimal downstream consumer module that `#[path]`-includes `modules/sdk/replica_facade.rs` and wires to `apply_pipeline.committed_entries`. Built alongside every clustor module on every `make ci` run — the gate that catches `no_std` regressions in the facade or in the per-entry emitter. See [consumer_facade.md](consumer_facade.md). |

---

## Graph definition

The canonical graph definition lives in
[../../configs/single.yaml](../../configs/single.yaml). It enumerates:

- **23 substrate modules** (plus `example_consumer` in the smoke
  graph) across four execution domains (ops, consensus, network,
  apply).
- **~50 wiring edges**, including cross-core mailbox edges with
  SEV/WFE wake.
- **Platform integration** via `platform: net: {}` (virtio_net + ip
  injected) and `services: socket: ip` for TCP connection management.
- **Response path:** `apply_pipeline.applied` → `client_codec.responses`
  → `client_codec.responses_out` → `client_surface.client_responses`
  → `peer_router.client_resp` → `tls` → `ip` → client. Throttle
  rejects (`MSG_CLIENT_REJECT`) ride the same path.

The yaml is the authoritative module list and edge set; per-module
port contracts live in each module's
[`manifest.toml`](../../modules/app/).

---

## Four-domain core layout

The graph is partitioned across four execution domains so the
consensus hot path never waits for a tick boundary.

| Core | Domain | Tier | Modules | Rationale |
|------|--------|------|---------|-----------|
| 0 | ops | Tier 0, 1ms | `client_surface`, `cp_bridge`, `cp_proof_cache`, `admin_handler`, `rbac`, `snapshot_engine`, `telemetry_agg`, `key_manager`, `http_ingress`, `http_adapter` | None of these are latency-critical. 1ms tick is fine for CP proof refresh (5s intervals), admin operations, and telemetry aggregation. |
| 1 | consensus | Tier 3, poll | `raft_engine`, `wal`, `durability_ledger`, `commit_tracker` | The persistence pipeline must never wait for a tick boundary. Poll-mode steps continuously: log append → WAL write → group fsync → durability ack → commit advance, all in one iteration when work is available. |
| 2 | network | Tier 3, poll | `nic`, `ip`, `tls`, `peer_router`, `replicator` | Kernel-bypass NIC with zero-copy mailbox edges. `replicator` co-located with the network stack so AppendEntries RPC dispatch is a local channel write followed by immediate TLS framing and NIC TX — no domain crossing on the send path. |
| 3 | apply | Tier 1, 250µs | `client_codec`, `throttle_gate`, `partition_router`, `flow_controller`, `read_gate`, `apply_pipeline`, `placement_router` | 250µs tick gives 4 kHz state machine application rate. The flow controller and throttle gate are co-located to avoid a cross-core hop on the credit path. |

### Cross-domain edges

Edges between domains use CrossCore mailbox channels with SEV/WFE
hardware wake signalling (~200ns latency on CM5's coherent L3
cache). The write commit path crosses three domain boundaries:

```
client request (apply) →[cross-core]→ raft_engine (consensus)
                                       ↓ inlined walk
                                       commit_tracker (consensus)
                                       →[cross-core]→ apply_pipeline (apply)
                                                       →[cross-core]→ client_surface (ops)
```

Three crossings × ~200ns ≈ 600ns of scheduling overhead — negligible
relative to NVMe fsync latency (~50µs) and network RTT (~1-2ms LAN).

---

## Hot-path properties

**Single-domain Raft state.** Each domain is single-threaded. The
consensus domain owns all Raft state exclusively — no mutexes, no
atomics, no contention. Fluxor's cooperative scheduling provides
the serialisation guarantee Raft requires for free.

**Proposal coalescing.** `raft_engine` accumulates up to
`proposal_batch_max` client proposals per step, bounded by
`proposal_batch_timeout_us` (100µs). One batched AppendEntries
message is emitted per peer rather than one per proposal. This
amortises RPC framing, serialisation, and WAL entry overhead across
many client writes.

**Zero-copy WAL path.** The `raft_engine` → `wal` edge uses
mailbox channels. The engine acquires a write buffer, fills it
with the batched entry, and releases it. The `wal` module acquires
the same buffer for `pwrite` — zero memcpy. For 4 MiB batches this
avoids ~1ms of copy time.

**Replication fan-out.** `replicator` writes to all peer TLS
channels in a single step (sequential memcpy to ring buffers, ~µs
total for a 5-node cluster). The `nic` module then transmits all
queued frames in its next poll iteration. From the network's
perspective every AppendEntries RPC is dispatched within
microseconds of every other one.

**Per-entry fsync.** `wal` fsyncs each appended entry and emits the
local FsyncAck stamped with `self_id` directly to
`durability_ledger`. The ack edge is a single mailbox hop within
the consensus domain.

---

## Backpressure as graph structure

When the WAL or fsync pipeline stalls, `wal`'s input mailbox stays
in STREAMING state (not released). `raft_engine`'s next step sees
the output channel as not-ready via `channel_poll(out, POLL_OUT)`
and stops accepting proposals. Backpressure propagates upstream:
`raft_engine` stops reading from its proposal input → `throttle_gate`'s
output fills → `throttle_gate` begins rejecting requests with
throttle envelopes. The propagation is structural (channel
fullness), not imperative (credit counters checked in application
code).

## Control plane resilience

`cp_proof_cache`'s state machine (Fresh → Cached → Stale → Expired)
drives strict-fallback transitions through cross-core control
channels to `raft_engine` and `commit_tracker`. When CP proofs
expire, the graph degrades to Strict durability mode and blocks
linearizable reads — all through channel wiring, not runtime
conditionals.

## Observability is structural

Every module emits metrics through its `.metrics` output port.
`telemetry_agg` on Core 0 aggregates these via cross-core edges
(best-effort, never blocking the hot path). The `/readyz` and
`/why` diagnostic endpoints are first-class graph outputs.
Fluxor's per-step metering gives microsecond-level visibility into
consensus latency, WAL throughput, and replication lag without
instrumentation overhead.

## Security boundaries

mTLS termination (`tls`), RBAC evaluation (`rbac`), and key
management (`key_manager`) are isolated modules with explicit
channel boundaries. Admin requests must traverse `rbac` before
reaching `admin_handler`. Key material flows unidirectionally
from `key_manager` to consumers. Break-glass tokens are validated
and audit-logged within `rbac` before any privileged operation
executes.

---

## Embedding as substrate

Applications like Quantum (MQTT broker) and Lattice (KV store)
plug into the `apply_pipeline` output. The graph exposes the full
consensus, persistence, and control-plane machinery while the
application only implements the state machine transform. The
`client_surface` module can be extended with application-specific
routes by wiring additional modules to its request fan-out ports.
The application's state machine module runs on Core 3 (apply
domain), co-located with the apply pipeline for zero-overhead
committed-entry delivery.

The typed integration surface for downstream consumers is the
`replica_facade` helper at
[`modules/sdk/replica_facade.rs`](../../modules/sdk/replica_facade.rs).
Consumers include it the same way they include `wire.rs` and
`types.rs` (`#[path = "../sdk/replica_facade.rs"] mod
replica_facade;`). The full contract — bounded/opaque command
invariants, propose lifecycle, leader-change protocol, snapshot
install layout, and read-gate predicate — lives in
[consumer_facade.md](consumer_facade.md).
