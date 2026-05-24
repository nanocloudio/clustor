# Replication and Read Safety

The replication loop itself — elections, leases, reads, durability,
flow control, and compaction. Where [lifecycle.md](lifecycle.md)
describes the states a replica passes through,
[concepts.md](concepts.md) defines the vocabulary, and
[wire.md](wire.md) defines the byte shapes, this doc is the algorithms
those pieces compose into.

## Table of Contents

1. [Elections and pre-vote](#elections-and-pre-vote)
2. [Lease inequality](#lease-inequality)
3. [Read gate predicate](#read-gate-predicate)
4. [Commit-visibility modes](#commit-visibility-modes)
5. [ACK contract](#ack-contract)
6. [Durable watermarks](#durable-watermarks)
7. [Ledger ordering and replay](#ledger-ordering-and-replay)
8. [Flow control](#flow-control)
9. [Snapshot cadence](#snapshot-cadence)
10. [Compaction floor](#compaction-floor)

---

## Elections and pre-vote

Election timeouts draw uniformly from `[150, 300]` ms
(ConsistencyProfile / Throughput) or `[300, 600]` ms (WAN).
Heartbeats fire every 50 ms. PreVote is always on.

### 1) High-RTT detection widens the next window

A follower that observes `ema_heartbeat_rtt_ms ≥ threshold` for three
consecutive heartbeats responds with `PreVoteResponse.high_rtt = true`.
Thresholds: 150 ms (ConsistencyProfile / Throughput), 350 ms (WAN).

The high-RTT follower then widens its next election window to the WAN
range. It reverts to its profile's normal window as soon as it
observes a healthy leader heartbeat or grants a vote in a successful
election.

### 2) Leader stickiness

A leader's grace period is `min_leader_term_ms = 750`. Step-down
happens on structural lag, device latency violations (three
consecutive samples above threshold or a 500 ms moving average over
bound), or a ControlPlaneRaft `TransferLeader`.

### 3) Device latency hysteresis

Step-down requires three consecutive fsync samples above
`durability.max_device_latency_ms`, or a 500 ms moving average over
the bound. Recovery requires five consecutive samples below 80% of
the threshold. The asymmetry is intentional — re-entering normal
operation should clear a higher bar than failing out of it.

---

## Lease inequality

Leases run only when:

```
lease_duration_ms + lease_rtt_margin_ms + clock_skew_bound_ms + heartbeat_period_ms
    < min_election_timeout_ms
```

`min_election_timeout_ms` is the lower bound of the election-timeout
range for the active profile — 150 ms for ConsistencyProfile /
Throughput, 300 ms for WAN.

Operators must verify the inequality against the active profile.
v0.1 profiles meet the guard but ship with `lease_gap_max = 0`,
keeping leases disabled until a future profile explicitly enables
them.

### Additional prerequisites

Even when the inequality holds, leases require all of:

- `strict_fallback == false`
- `commit_visibility == DurableOnly`
- ControlPlaneRaft cache state ∈ `{Fresh, Cached}`
- The `DurabilityProofTupleV1` subset matches the local ledger
- `wal_committed_index == raft_commit_index`
- `clock_guard_alarm == 0`

Even though equality is already enforced, `lease_gap_max` continues
to emit `LeaseGapExceeded` incidents when the instantaneous gap
deviates — telemetry on near-miss conditions.

### Skew alarms

A clock skew alarm triggers voluntary leader step-down within 500 ms
and revokes leases immediately. NTP-only deployments declare
`clock_guard_source = NtpOnly`, relax bounds (15 / 20 / 60 ms), keep
leases disabled, and continue step-down on alarms.

---

## Read gate predicate

Leaders serve ReadIndex requests only when **all** of:

- `strict_fallback == false`
- `controlplane.cache_state ∈ {Fresh, Cached}` (not `Stale` or
  `Expired`)
- `commit_visibility == DurableOnly`
- The `DurabilityProofTupleV1` subset equals the leader's last
  quorum-fsynced tuple
- `wal_committed_index == raft_commit_index`

Violations emit `ControlPlaneUnavailable{reason}` with the priority
order in [errors.md](errors.md#controlplaneunavailable). Telemetry
exposes `read_gate.can_serve_readindex` and
`read_gate.failed_clause`.

### Reference predicate

```rust
fn read_gate_predicate(state: &LeaderState) -> (bool, FailedClause) {
    if state.controlplane.cache_state == CacheState::Expired {
        return (false, FailedClause::ControlPlaneCacheExpired);
    }
    if state.controlplane.cache_state == CacheState::Stale {
        return (false, FailedClause::ControlPlaneCacheStale);
    }
    if state.strict_fallback {
        return (false, FailedClause::StrictFallback);
    }
    if state.commit_visibility != CommitVisibility::DurableOnly {
        return (false, FailedClause::CommitVisibility);
    }
    if state.controlplane_proof_tuple != state.last_quorum_fsynced_tuple {
        return (false, FailedClause::ControlPlaneProofMismatch);
    }
    if state.wal_committed_index != state.raft_commit_index {
        return (false, FailedClause::IndexInequality);
    }
    (true, FailedClause::None)
}
```

Follower versions replace the last clause with
`local_wal_durable_index ≥ applied_index_floor` when serving
snapshot-only reads.

### Service matrix

| Node role / read type | Normal mode | Strict fallback |
|---|---|---|
| Leader ReadIndex / lease | Allowed when predicate passes | Rejected (`ControlPlaneUnavailable{reason = NeededForReadIndex}`) |
| Leader snapshot-only reads (explicit flag) | Allowed; clamped to `applied_index` | Allowed; clamped to last verified `applied_index`, never linearizable |
| Follower snapshot-only reads | Allowed only when `follower_read_snapshot_capability` is set | Capability revoked within 100 ms; outstanding RPCs fail with `FollowerCapabilityRevoked` |
| Observer streams | Allowed while cache is `Fresh` and strict fallback is false | Revoked; observers reconnect after proof publication |

---

## Commit-visibility modes

### `DurableOnly` (default)

The v0.1 default for every profile. Required whenever linearizable
reads, follower-read capabilities, or observers are enabled.

### `CommitAllowsPreDurable` (optional)

An optional Throughput-profile feature. Enabled only when **all** of:

- Group-Fsync is active and healthy.
- The product surface explicitly marks all resulting reads as
  `read_semantics = SnapshotOnly`.
- Clients that need read-after-write pin their writes by waiting for
  `last_quorum_fsynced_index ≥ ack_index`.

Under `CommitAllowsPreDurable`, leaders may expose `raft_commit_index`
ahead of `wal_committed_index` to snapshot-only reads. The ACK
contract still holds. The mode clears immediately when strict
fallback, cache staleness, or any read-gate clause fails.

Linearizable reads (ReadIndex or leases) remain forbidden in this
mode. Follower-read capabilities stay disabled. Without these
guardrails, the mode is not safe to enable.

---

## ACK contract

A client ACK is the strongest commitment clustor makes. It promises
that the entry survives any single-node loss, has been physically
fsynced on a quorum, and is durable enough that subsequent reads can
rely on it.

### 1) Four conditions

All of the following must hold before the leader emits the ACK:

1. The entry is **Raft-committed in the current term**. Entries
   inherited from an earlier term that happen to be
   majority-replicated do not qualify (see fresh-leader gate below).
2. The leader has persisted the WAL bytes and the matching
   `DurabilityRecord` locally.
3. A quorum of followers — including the leader — has returned
   `DurabilityAck` evidence proving the same WAL bytes and
   `DurabilityRecord` are durably on disk on that follower.
4. The leader has advanced `wal_committed_index` to the ack index and
   recorded the advance.

### 2) Idempotency

Clients supply `AppendRequest.idempotency_key`. The server replays
the same ack index when the same key arrives twice, so retries are
safe.

### 3) Fresh-leader gate

A freshly elected leader does not ACK any client write until at least
one entry from its own term has committed — even if older-term writes
were already replicated to a majority by the previous leader. This is
the standard Raft current-term rule, restated because it's the most
commonly violated property when consumers try to optimise the ACK
path.

---

## Durable watermarks

Two indexes carry durability. The mental model is in
[concepts.md §Indexes](concepts.md#indexes); the algorithm is here.

### 1) How `wal_committed_index` advances

Every tick on the leader:

1. Raft advances `raft_commit_index` by the standard majority rule.
   Durability does not enter this step.
2. When the WAL and durability log have both reached step (4) of the
   [ledger ordering rules](#ledger-ordering-and-replay) for index *n*,
   the leader updates `local_wal_durable_index = n`. Durability
   progress is independent of commit progress; an entry can be
   durable before it's Raft-committed.
3. The leader picks the highest *m* such that quorum-size replicas
   (counting itself) advertise `local_wal_durable_index ≥ m`, the
   entry at *m* lives in the current term, and
   *m* ≤ `raft_commit_index`. That *m* becomes the new
   `wal_committed_index`.

The constraint `wal_committed_index ≤ raft_commit_index` is invariant.
Durability ACKs arriving early do not let it sprint ahead.

### 2) What followers may not do

A follower's `DurabilityAck.last_fsynced_index` is the **minimum** of:

- the follower's own last-appended log index, and
- the follower's last synced `DurabilityRecord` index.

A follower reporting anything higher is in violation: it would be
claiming durability for an entry that may not be on disk.

### 3) Why this shape matters for reads

Linearizable reads on the leader reduce to a single equality check:
`wal_committed_index == raft_commit_index`. Followers serving
snapshot-only reads instead check `local_wal_durable_index ≥
applied_index_floor`. Both predicates come from the same machinery —
leader-side quorum-fsync and follower-side local fsync — which is why
the indexes stay distinct.

### 4) Stale-term durability claims

If a leader advertises durability for an entry whose term is older
than the current term, followers still process the AppendEntries
normally (so the log catches up) but treat the durability claim as
unusable when comparing it against the ControlPlaneRaft proof. They
log `ControlPlaneProofMismatch`. This prevents a leader from clearing
the read gate by leaning on durability proofs inherited from a
predecessor.

---

## Ledger ordering and replay

### Ordered steps

Five ordered steps, identical for leaders and followers:

1. Append the entry bytes to the WAL segment (`pwrite`).
2. Complete the WAL durability step: in Strict mode `fdatasync` the
   WAL file; in Group-Fsync flush the batch covering the entry,
   ensuring the entry bytes are on stable storage.
3. Append the corresponding `DurabilityRecord` (and any coalesced
   reservation metadata) to `wal/durability.log`.
4. `fdatasync(wal/durability.log)` to make the ledger record durable.
5. After step (4), leaders count quorum `DurabilityAck`s toward
   `wal_committed_index` and may emit the client ACK once the ACK
   contract is satisfied.

Followers execute steps (1)–(4) before sending their `DurabilityAck`.

### Replay

```rust
fn replay_durability_log(log_path, wal_index) -> ReplayResult {
    let mut last_good_offset = 0;
    let mut last_good_record = None;
    for record in read_records_in_order(log_path) {
        if !record.verify_crc() { break; }
        if !wal_index.contains(record.term, record.index, record.segment_seq) { break; }
        enforce_step_order(record);
        last_good_offset = record.file_end_offset;
        last_good_record = Some(record);
    }
    truncate_file_to(last_good_offset);
    fdatasync(log_path);
    ReplayResult {
        proof: last_good_record,
        strict_fallback: last_good_record.is_none(),
        truncated_bytes,
    }
}
```

Truncation uses synchronous primitives and immediately `fdatasync`s
descriptors. Background threads do not truncate asynchronously.

---

## Flow control

A dual-token PID controller with sample period 100 ms. Default gains
per profile:

| Profile | Kp | Ki | Kd |
|---|---|---|---|
| Latency | 0.60 | 0.20 | 0.10 |
| Throughput | 0.50 | 0.15 | 0.08 |
| WAN | 0.40 | 0.10 | 0.05 |

Guardrail: `Ki × sample_period_s ≤ 1.0`.

### Credit pools

- `entry_credit_max = 4096`
- `byte_credit_max = 64 MiB`
- Minimum quantum admits one ≤ 16 KiB frame each tick even when byte
  credits exhaust.

The PID auto-tuner runs on Throughput / WAN when
`io_writer_mode = FixedUring` and caches are `Fresh`. It reverts to
last stable gains on oscillation and reports
`flow.pid_auto_tune_state`.

### Structural lag

| Category | Condition | Effect |
|---|---|---|
| Transient | `lag_bytes ≤ 64 MiB` and `lag_duration < 30 s` | Halves credits |
| Structural | Beyond transient thresholds or `≥ 256 MiB` | Forces Strict durability, reduces credits to 25%, triggers snapshots, alerts ControlPlaneRaft, steps down after `flow.structural_stepdown_ms = 15,000` ms unless `flow.structural_override` is active |

Manual `flow.structural_hard_block` halts writes entirely.

---

## Snapshot cadence

Import procedure lives in
[lifecycle.md](lifecycle.md#snapshot-lifecycle). The cadence rules:

- Retry policy: exponential backoff `min(2^attempt × 1000, 10,000)`
  ms with ±25% jitter, ≤ 3 attempts, ≤ 60 s.
- Incremental snapshots target
  `snapshot.delta_emit_period_ms_target` but enforce the operator or
  profile hard bound.
- `delta_chain_length` counts only incrementals since the last full
  snapshot and stays ≤ `snapshot.delta_chain_max_profile`.
- Authorisation logs include parent info and elapsed time since the
  last full snapshot. ControlPlaneRaft retires a chain only when the
  operator or hard bound is exceeded — not because an SLO target was
  missed.

AP workloads restore `ap_pane_digest` and `dedup_shards[]` before
applying entries beyond `base_index`. Mismatches cause
`SnapshotDeterminismViolation`.

---

## Compaction floor

```rust
fn compute_compaction_floor(state: CompactionState) -> u64 {
    let learner_floor = state.learner_slack_floor.unwrap_or(0);
    let quorum_floor = state.quorum_applied_index;
    let floor_effective = learner_floor
        .max(quorum_floor)
        .max(state.snapshot_base_index);
    if state.quorum_sm_durable_index < state.snapshot_base_index {
        return state.snapshot_base_index;
    }
    floor_effective
}
```

Bytes below `floor_effective` are deleted only after manifest
authorisation, learner retirement guards, and nonce-reservation
clearance succeed. See
[lifecycle.md](lifecycle.md#compaction-and-storage-hygiene).
