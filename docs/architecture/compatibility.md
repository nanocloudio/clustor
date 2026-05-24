# Compatibility and Versioning

The promises clustor makes across releases — what wire shapes are
frozen, how feature gates flip, how cache states age, and how a node
becomes ready to serve traffic.

## Table of Contents

1. [Wire and schema stability](#wire-and-schema-stability)
2. [Version negotiation and feature gates](#version-negotiation-and-feature-gates)
3. [ControlPlaneRaft cache lifecycle](#controlplaneraft-cache-lifecycle)
4. [Readiness and deployment](#readiness-and-deployment)

---

## Wire and schema stability

- Wire catalog and system log entry IDs are **frozen for v0.1.x**.
  Additive fields append at the tail. Field names and casing in
  JSON and gRPC mirrors are stable.
- Clients tolerate additive optional fields but reject missing
  required fields.
- Nodes do not raise frame or body caps without negotiating
  `WireExtension::WideFrame`. `body_len` remains ≤ 4 MiB (RPCs) or
  ≤ 32 KiB (Explain / Why* / throttle) unless the extension is
  mutually set.
- Enumerations treat unknown discriminants as hard failures.
  Best-effort parsing is forbidden. JSON mirrors accept recognised
  numeric enum values but emit canonical strings.
- Large lists chunk via `ChunkedList` framing until
  `WireExtension::WideCount` is mutually enabled.

Encoding details and message catalog: [wire.md](wire.md).

---

## Version negotiation and feature gates

Peers record handshake tuples in `bundle_negotiation_log`. Mismatched
catalogues close connections immediately.

Feature enablement — leader leases, incremental snapshots, observer
admission, BLAKE3 leaves, PID auto-tuner, Group-Fsync — requires
**all** of:

- Uniform support across the voter set.
- ControlPlaneRaft gate flips.
- Strict fallback cleared.
- Published predicates with matching digests.

Capability telemetry (`feature.<name>_gate_state`, predicate digest)
matches ControlPlaneRaft's feature manifest exactly.

---

## ControlPlaneRaft cache lifecycle

### 1) Refresh loop

ControlPlaneRaft caches follow a deterministic retry hierarchy. A
background watcher continuously calls `attempt_refresh()` on the
cadence implied below. Even when `cache_state = Fresh` the watcher
wakes every 5,000 ms to confirm freshness.

```rust
loop {
    match controlplane.cache_state {
        Fresh   => sleep(5_000),
        Cached  => { attempt_refresh(); sleep(min(5_000, remaining_grace / 4)); }
        Stale   => { attempt_refresh(); sleep(min(2_500, remaining_grace / 8)); }
        Expired => { attempt_refresh(); sleep(1_000); }
    }
}
```

`remaining_grace = max(0, controlplane.cache_grace_ms − controlplane.cache_age_ms)`.

All timers use 64-bit monotone math; additions saturate at
`u64::MAX`. Every transition to `Expired` increments
`controlplane.cache_expiry_total`.

### 2) Cache state definitions

| State | Age condition | Allowed operations |
|---|---|---|
| `Fresh` | `cache_age_ms ≤ controlplane.cache_fresh_ms` (default 60,000) | Normal writes, reads, capability grants. |
| `Cached` | `cache_fresh_ms < age ≤ 0.5 × cache_grace_ms` | Writes and reads continue; telemetry raises `controlplane.cache_warning`. |
| `Stale` | `0.5 × cache_grace_ms < age < cache_grace_ms` | Writes continue but clamp to Strict durability; effective `commit_visibility` behaves as `DurableOnly`; incremental snapshots pause; follower-read and observer capabilities revoked. |
| `Expired` | `age ≥ cache_grace_ms` | Mutating admin / control APIs fail closed; Group-Fsync and leases stay disabled; read gate forces `ControlPlaneUnavailable{reason = CacheExpired}`; data-plane writes continue only in Strict durability with effective `commit_visibility = DurableOnly`. |

Entering `Stale` or `Expired` forces `strict_fallback = true` until
a fresh proof clears the gate (see
[lifecycle.md](lifecycle.md#strict-fallback-and-the-read-gate)).

### 3) Cache mode truth table

| Cache state | Writes | ReadIndex / leases | Leader snapshot-only reads |
|---|---|---|---|
| `Fresh` | Allowed (configured durability mode) | Allowed when read-gate predicate passes | Allowed; clamped to `applied_index` |
| `Cached` | Allowed (configured durability mode) | Allowed when read-gate predicate passes | Allowed; clamped |
| `Stale` | Allowed but auto-clamped to Strict; effective `commit_visibility = DurableOnly` | Rejected with `ControlPlaneUnavailable{reason = CacheNotFresh}` | Allowed; clamped |
| `Expired` | Allowed only in Strict durability; admin / control APIs disabled; effective `commit_visibility = DurableOnly` | Rejected with `ControlPlaneUnavailable{reason = CacheExpired}` | Allowed; clamped to last verified snapshot before expiry |

### 4) Proof TTLs

Durability proofs expire after the profile's
`controlplane.durability_proof_ttl_ms_profile`
(43,200,000 – 86,400,000 ms). Stale proofs force strict fallback
until refreshed.

`DefinitionBundle` readiness requires
`warmup_ready_ratio ≥ readiness_threshold`. `DefineActivate` logs
include readiness digests hashed over sorted readiness records.

---

## Readiness and deployment

### Graceful shutdown

1. `TransferLeader`.
2. Wait `commit_quiescence_ms = 200`.
3. Ensure `apply_queue_depth < 10%`.
4. Flush WAL and snapshots.
5. Respect `graceful_shutdown_timeout_ms = 10,000`.

### Kubernetes guidance

- `StatefulSets` with `maxUnavailable = 1`.
- Anti-affinity: ≤ 1 voter per node and per zone.
- cgroup v2 with `io.max`.
- `terminationGracePeriodSeconds ≥ 10`.
- Read-write `/state`, read-only elsewhere.
- Unsupported mounts or stacked devices lacking explicit overrides
  cause bootstrap rejection.

### Repair mode

`bootstrap.repair_mode = true`:

- Mounts partitions read-only.
- Runs scrub.
- Allows snapshot download and upload.
- Requires Break-Glass `AdminResumePartition` to exit.
