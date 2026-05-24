# Error Handling

The structured rejections clustor surfaces when a write, read, or
admin call cannot be honoured. Wire-level encoding errors live in
[wire.md](wire.md#error-codes); this doc covers the higher-level
envelopes a client or operator actually observes.

Every envelope carries the shared schema header from
[wire.md](wire.md#envelopes):
`{schema_version, generated_at, partition_id, routing_epoch,
durability_mode_epoch}`.

## Table of Contents

1. [Wire rejections](#wire-rejections)
2. [Gate failures](#gate-failures)
3. [Quarantine reasons](#quarantine-reasons)

---

## Wire rejections

### `RoutingEpochMismatch`

Stale or missing routing epoch on writes or admin calls. The payload
includes the observed and expected `routing_epoch`, plus lease and
durability epochs. Clients refresh placement and retry.

### `ModeConflict`

Stale durability mode epoch when toggling Strict ↔ Group, or when an
inbound Raft control message carries an older `durability_mode_epoch`
than the receiver has persisted. See
[lifecycle.md](lifecycle.md#3-monotone-epoch-enforcement) for the
monotone-epoch rules.

### `ControlPlaneUnavailable`

Read-gate or lease-gate failure, mapped through the priority order
in [concepts.md](concepts.md#behaviour-switches):

```
reason ∈ { CacheExpired, CacheNotFresh, NeededForReadIndex }
```

| Reason | Mapped from |
|---|---|
| `CacheExpired` | Cache aged into `Expired` |
| `CacheNotFresh` | Cache aged into `Stale` |
| `NeededForReadIndex` | Strict-fallback latch or proof-equality failure |

The envelope carries retry metadata, surfaces as HTTP 503 / gRPC
`UNAVAILABLE`, and includes `Retry-After ≥ 250 ms`. Clients falling
back to snapshot-only reads do so via an explicit `SnapshotOnly`
flag — `ControlPlaneUnavailable` itself does not authorise that
fallback.

### `snapshot_full_invalidated` / `snapshot_delta_invalidated`

Emitted when the trust cache for this snapshot is invalid, the
schema has bumped, the emit version changed, the DEK epoch rolled
over, or a delta chain violation was detected.

### `ThrottleEnvelope`

```
reason ∈ {
    ApplyBudget,
    WALDevice,
    FollowerLag,
    DiskSoft,
    DiskHard,
    TenantQuota,
    FrameAlignment,
    SnapshotImport,
}
```

Carries backlog metrics, current credits, observed durations,
`credit_hint ∈ {Recover, Hold, Shed}`, and ingest plus durability
status codes.

### Other rejection families

These share the schema header and the list-truncation conventions:

- `FollowerCapabilityRevoked`
- `SnapshotChunkAuthFailure`
- `SnapshotDeltaRetired`
- `NonceReservationGapWarning`
- `OverrideStrictOnlyBackpressure`
- `WhyCreditZero`
- `WhyNotLeader`
- `WhySnapshotBlocked`
- `WhyQuarantined`

---

## Gate failures

### Read gate

Read-gate predicate failures emit `ControlPlaneUnavailable` with
prioritised reasons. The predicate itself is in
[replication.md](replication.md#read-gate-predicate).

### Group-Fsync gate

Group-Fsync gating returns one of:

- `ModeConflict(strict_fallback)` over RPC
- `GroupFsyncQuarantine` as a telemetry incident (the identifier
  omits the hyphen even though the feature name is "Group-Fsync")

### Lease gate

Lease revocation produces:

- `LeaseGapExceeded`
- `clock_guard_alarm`
- `LeaseRevokedDueToStrictFallback`

### Snapshot import and authorisation

- `SnapshotDeterminismViolation`
- `SnapshotChunkAuthFailure`
- `SnapshotImportNodePressure`

---

## Quarantine reasons

Quarantine entry reasons are typed so policy can branch:

```
reason ∈ { Integrity, Administrative, ApplyFault }
```

The reason controls whether snapshot exports and follower reads stay
enabled while quarantined. See
[lifecycle.md](lifecycle.md#startup-scrub-and-quarantine).
