# Replica Lifecycle

The state machine each replica steps through over its lifetime —
healthy steady state, degraded modes, scrub, quarantine, snapshot
install, membership changes, and (rarely) repair.

The replication-loop algorithms themselves are in
[replication.md](replication.md). This doc covers the states the loop
runs inside.

## Table of Contents

1. [Strict fallback and the read gate](#strict-fallback-and-the-read-gate)
2. [Leader and follower lifecycle](#leader-and-follower-lifecycle)
3. [Durability modes and I/O writer states](#durability-modes-and-io-writer-states)
4. [Startup scrub and quarantine](#startup-scrub-and-quarantine)
5. [Snapshot lifecycle](#snapshot-lifecycle)
6. [Compaction and storage hygiene](#compaction-and-storage-hygiene)
7. [Definition bundles and activation barriers](#definition-bundles-and-activation-barriers)
8. [ControlPlaneRaft proof publication](#controlplaneraft-proof-publication)
9. [Membership changes and joint consensus](#membership-changes-and-joint-consensus)

---

## Strict fallback and the read gate

`strict_fallback` is a latch on every leader. It engages whenever
either:

- (a) the ControlPlaneRaft cache is `Stale` or `Expired`, or
- (b) the leader lacks a ControlPlaneRaft-published
  `DurabilityProofTupleV1` whose equality subset matches the leader's
  last quorum-fsynced tuple (and therefore proves the current-term
  durable watermark).

While the latch is set, the leader's read and lease capabilities are
gated off and local I/O behaves as Strict mode. No new durability or
`commit_visibility` transition is appended; the leader behaves *as
though* `commit_visibility = DurableOnly` until the latch clears,
regardless of the configured mode.

### 1) What latched leaders do

While `strict_fallback == true`, leaders:

- Reject Group-Fsync enablement
  (`DurabilityTransition{to=Group}`), leases, follower-read
  capabilities, incremental snapshot enablement, observer admission,
  and admin overrides that try to bypass the gate.
- Clamp read exposure to `DurableOnly`. `CommitAllowsPreDurable` is
  neither enabled nor continued while the latch holds.
  `lease_gap_max` is disabled.
- Continue accepting writes strictly (each append increments
  `strict_fallback_pending_entries`) but block ReadIndex and lease
  reads with
  `ControlPlaneUnavailable{reason = NeededForReadIndex}`.

Followers continue honouring whatever `DurabilityTransition` entries
already exist in the log. The clamp to Strict is purely a
leader-local I/O behaviour until a new transition entry commits.

### 2) Cache state and the latch are coupled

Once a cache transitions to `Stale` or `Expired`, clause (a) forces
`strict_fallback = true` until ControlPlaneRaft publishes a proof
covering the current `raft_commit_index` and the cache returns to
`Fresh` or `Cached`. Clause (b) can keep the latch asserted
independently even when caches are still `Fresh` or `Cached`.

### 3) State tracking telemetry

```
strict_fallback_state ∈ { Healthy, LocalOnly, ProofPublished }
strict_fallback_last_local_proof
strict_fallback_blocking_reason
strict_fallback_gate_blocked{operation}
strict_fallback_decision_epoch
```

`strict_fallback_state = LocalOnly` lasting longer than
`strict_fallback_local_only_demote_ms` forces self-demotion unless a
Break-Glass override renews the timer. Profile defaults:

| Profile | `local_only_demote_ms` |
|---|---|
| ConsistencyProfile / Throughput | 14,400,000 (4 h) |
| WAN | 21,600,000 (6 h) |

### 4) Demotion protocol

When the demote threshold is exceeded, the leader steps down and
waits at least `min_leader_term_ms` before campaigning again. After
demotion the node is barred from leadership until **all** of:

1. ControlPlaneRaft is back.
2. A fresh `DurabilityProofTupleV1` is published and observed in
   cache.
3. A jittered backoff of
   `strict_fallback_recampaign_backoff_ms = 60,000` elapses.

The bar prevents thrash where the same leader keeps regaining term
without clearing strict fallback.

### 5) Behaviour while barred

A barred node still:

- Responds to inbound `PreVote` / `RequestVote` RPCs truthfully,
  granting votes when the candidate's log is at least as up to date.
  Responses carry `vote_annotation = StrictFallbackBarred` so
  operators can see why the node isn't seeking leadership.
- Processes AppendEntries from the active leader, updating
  `match_index` and durability state normally so it rejoins quickly
  once the bar lifts.
- Exposes `strict_fallback_barred_until_ms` telemetry so operators
  can correlate the enforced backoff.

What it does **not** do: start local `Campaign` or `PreVote` attempts.

### 6) Liveness escape hatch

If no leader is observed for
`strict_fallback_no_leader_grace_ms = 120,000`, barred nodes may
temporarily lift the campaign suppression to restore write
availability — while staying in strict fallback. The escape hatch
never re-enables ReadIndex or leases, so it does not bypass the proof
requirement. The bar reactivates as soon as a leader is elected or
ControlPlaneRaft caches return to `Fresh`.

---

## Leader and follower lifecycle

- Leaders persist `current_term` before AppendEntries, enforce
  `wal_committed_index ≤ raft_commit_index`, and export telemetry
  referencing the controlling clauses (durability equality, etc).
- Election timeouts: `[150, 300]` ms (ConsistencyProfile /
  Throughput) or `[300, 600]` ms (WAN). Heartbeats every 50 ms.
  PreVote always on.
- `PreVoteResponse.high_rtt = true` widens the next election window
  when a follower observes high RTT for three consecutive heartbeats.
- `min_leader_term_ms = 750` provides stickiness. Step-down happens
  on structural lag, device latency violations, or
  ControlPlaneRaft `TransferLeader`.
- Followers never serve ReadIndex. They serve snapshot-only reads
  only after ControlPlaneRaft grants
  `follower_read_snapshot_capability`. Capabilities are revoked
  within 100 ms when guardrails fail; in-flight RPCs close with
  `FollowerCapabilityRevoked`.
- Observers rely on dedicated bandwidth pools and are revoked
  whenever `strict_fallback == true` or cache freshness fails.

All numeric guardrails (`observer.bandwidth_cap`,
`membership.catchup_slack_bytes`, etc.) come from the profile bundles
described in [concepts.md](concepts.md#profiles).

---

## Durability modes and I/O writer states

`io_writer_mode ∈ { FixedUring, RegisteredUring, Blocking }`.

Group-Fsync is disabled whenever any voter reports `Blocking` and
remains disabled until all voters report non-`Blocking` modes for the
recovery window. Downgrades clamp group batch sizes and timers and
emit incidents after `io_writer_mode.downgrade_incident_ms`.

Leaders authenticate `io_writer_mode` via the same Raft heartbeat
metadata used for flow-control telemetry. The mTLS channel plus
replica identity and term fields provide integrity; spoofing would
require a compromised replica (the same trust model as
`DurabilityAck`). Because the fault model is crash-only, a single
voter stuck in `Blocking` is enough to fence Group-Fsync. Operators
must demote or repair such a replica.

### 1) Group-Fsync re-enablement predicate

```rust
fn can_enable_group_fsync(state) -> bool {
    !state.strict_fallback
        && state.controlplane.cache_state == CacheState::Fresh
        && now() >= state.downgrade_backoff_deadline
        && state.voters.iter().all(|v| v.io_mode != Blocking)
        && state.device_latency_violations_in_window < 3
        && !state.incident_flags.contains("GroupFsyncQuarantine")
}
```

### 2) Per-partition limits

- `group_fsync.max_batch_bytes ≤ 64 KiB`
- `max_batch_ms ≤ 5 ms`
- Inflight bytes ≤ 4 MiB per partition
- ≤ 64 MiB per node
- `overrun_limit = 2`
- Exponential backoff up to 15 min

Node-level incidents may clamp credits further without changing the
predicate.

### 3) Monotone epoch enforcement

`durability_mode_epoch` is monotone across the cluster. A follower
that has persisted epoch `E` rejects any AppendEntries or admin RPC
carrying an older epoch (`E' < E`) by replying with
`ModeConflict(durability_mode_epoch)` over RPC (or closing the Raft
stream) and logging `DurabilityModeEpochConflict`. The stale leader
steps down immediately and replays the transition fences once it has
refreshed its proof cache. ControlPlaneRaft mirrors the conflict as
an incident so operators can audit stale binaries.

---

## Startup scrub and quarantine

### Startup scrub

- Authenticate AEAD blocks.
- Validate MACs, CRC, Merkle digests.
- Rebuild `.idx` files.
- Verify ledger ordering.
- Truncate unreadable tails.
- Record `boot_record.scrub_state`.

AEAD or MAC failures immediately quarantine the partition. CRC-only
failures mark `needs_repair` with exponential backoff (up to three
retries) before escalation.

### Background scrub

Samples ≥ 1% of entries per segment every 21,600,000 ms (6 h),
ensuring every WAL byte is hashed at least once per 604,800,000 ms
(7 days). Reports `scrub.coverage_age_days`. Repair escalation
enters Quarantine on repeated anomalies.

### Quarantine state transitions

```
Healthy   ─►  Quarantine          on integrity faults
Quarantine ─► RepairMode          for offline work
Quarantine ─► Decommissioned      when removed
```

While quarantined: writes and membership changes are disabled.
Follower reads and snapshot exports depend on the quarantine reason.
Readiness surfaces `WhyQuarantined{reason, since_ms}`.

### Per-partition scope

Quarantine is strictly per-partition. ControlPlaneRaft records the
reason and timestamp, but other partitions on the same node continue
operating unless they independently violate guardrails. Admin tooling
does not propagate quarantine automatically — operators investigate
neighbouring partitions separately, to avoid cascading outages.

---

## Snapshot lifecycle

### Full snapshot emit triggers

Any one of:

- Log bytes reach `snapshot.log_bytes_target = 512 MiB`.
- Elapsed wall-clock time since the last successful full snapshot
  exceeds `snapshot.full_emit_period_ms_operator` (if set) or the
  profile hard bound `snapshot.full_emit_period_ms_hard_profile`.
- Follower lag ≥ 64 MiB.

`snapshot.full_emit_period_ms_target` (30,000 ms default) is
advisory. Missing it by > 25% emits `delta_chain_state =
GracefulCatchup` plus telemetry, but only operator or hard bound
overruns set `delta_chain_state = Orphaned` (which disables
incrementals).

Manifest emission, `content_hash` computation, and signing follow the
canonical JSON procedure in
[concepts.md](concepts.md#6-snapshot-manifest).

### Incremental snapshot cadence

Independent cadence measured from the previous delta's
`manifest_id.emit_ts`. Targets are advisory; hard bounds gate.
Temporary overruns produce `GracefulCatchup`. Only operator or hard
bound overruns force a full snapshot and mark the chain orphaned
until a compliant delta resumes the cadence.

### Import procedure

1. Canonicalise and verify the manifest signature plus DEK epoch.
2. Check `version_id` bounds.
3. Stream AEAD-authenticated chunks. Zeroise buffers and retry up to
   three times (≤ 60 s) before quarantining.
4. Buffer AppendEntries until `applied_index >= base_index`.
5. Reconcile follower checkpoints and ControlPlaneRaft trust caches.

The step 4 buffer is bounded per-partition by
`snapshot.import_buffer_max_entries_profile` (default 8,192) and
`snapshot.import_buffer_max_bytes_profile` (default 8 GiB), and
globally by `snapshot.import_node_buffer_hard_cap_bytes_profile`
(default `min(32 GiB, 15% RAM)` per node). Effective limit is
`min(per-partition, remaining node budget)`. Per-partition values are
upper bounds subject to the node cap; implementations spill to
disk-backed staging if necessary.

Buffer exhaustion emits `ThrottleEnvelope{reason = SnapshotImport}`.

### Bandwidth budgets

- `snapshot.max_bytes_per_sec = 128 MiB/s` per peer with 90% / 60%
  hysteresis.
- Node-level cap `min(0.7 × NIC capacity, 1 GiB/s)`.

---

## Compaction and storage hygiene

WAL deletion requires **all** of:

- (a) At least `compaction.quorum_ack_count` replicas reporting
  `sm_durable_index ≥ snapshot_base_index`.
- (b) A floor `max(learner_slack_floor,
  min(quorum_applied_index, snapshot_base_index))`.
- (c) Manifest authorisation handshake complete.
- (d) Learner retirement guardrails satisfied.
- (e) Nonce reservations cleared or abandoned.
- (f) No integrity or quarantine blocks active.

Disk policy checks enforce safe write-cache modes, barriers, and
stacked-device validation before bootstrap.

The compaction floor itself is computed by
[`compute_compaction_floor`](replication.md#compaction-floor).

---

## Definition bundles and activation barriers

ControlPlaneRaft issues two related records:

```
DefinitionBundle {
    bundle_id,
    version,
    sha256,
    definition_blob,
    warmup_recipe,
}
ActivationBarrier {
    barrier_id,
    bundle_id,
    readiness_threshold,
    warmup_deadline_ms,
    readiness_window_ms,
    partitions[],
}
```

Nodes stage bundles under `/state/<partition>/definitions`, verify
digests, run shadow apply queues, and publish:

```
WarmupReadiness {
    partition_id,
    bundle_id,
    shadow_apply_checkpoint_index,
    partition_ready_ratio,
}
```

`DefineActivate` commits only when every partition reports
`warmup_ready_ratio ≥ readiness_threshold` within the deadline.
Mismatches abort with `ActivationBarrierExpired`.

---

## ControlPlaneRaft proof publication

The proof consumed by read gates and strict-fallback clearance:

```
DurabilityProofTupleV1 {
    partition_id,
    last_durable_term,
    last_durable_index,
    segment_seq,
    io_writer_mode,
    durability_mode_epoch,
    controlplane_signature,
    updated_at,
}
```

`controlplane_signature` is an Ed25519 signature produced by the
ControlPlaneRaft proof-signing key (`ControlPlaneProofKey` in
[security.md](security.md#key-purpose-registry)).

ControlPlaneRaft enforces strict monotone ordering on `(last_durable_term,
last_durable_index, segment_seq, durability_mode_epoch)` per
partition. Toggling `durability_mode_epoch` therefore requires the
same `DurabilityTransition` entry to advance `(last_durable_term,
last_durable_index)` as well.

### 1) Verification

Nodes:

1. Verify the signature.
2. Compare `{last_durable_term, last_durable_index, segment_seq,
   io_writer_mode, durability_mode_epoch}` to the last
   `DurabilityRecord` persisted locally.

`updated_at` and the signature bytes are excluded from the equality
check. Reads are refused whenever the signed tuple and the local
record diverge. Wherever the docs refer to the proof "matching" or
to `controlplane.proof`, that's the subset.

### 2) Conflicting proofs

When two proofs are observed (e.g. after a partitioned
ControlPlaneRaft quorum) replicas accept the one with the higher
`(last_durable_term, last_durable_index, segment_seq,
durability_mode_epoch)` tuple. Identical
`(last_durable_term, last_durable_index)` with different
`segment_seq` or `durability_mode_epoch` immediately raises
`ControlPlaneProofConflict`. Replicas stay in strict fallback and
require operators to reconcile ControlPlaneRaft before proceeding.

### 3) Clearing strict fallback

Leaders leave strict fallback only after ControlPlaneRaft durably
appends the proof matching their local ledger. A locally verified
tuple without the ControlPlaneRaft append is insufficient — leaders
stay in Strict mode until they can publish a fresh proof and observe
it replicated with the correct signature.

---

## Membership changes and joint consensus

> **Status note.** The phases below describe the design target. The
> current substrate has the `raft_engine` joint state machine
> (`CONFIG_CHANGE_OP_JOINT`/`_NEW`, voter-set overlay, auto-`C_new` on
> commit) and the `commit_tracker` joint-aware quorum logic, but two
> downstream pieces are unfinished:
>
> - `durability_ledger` does not yet consume `MSG_VOTER_SET_UPDATE`
>   and still uses the fixed-`voter_count` quorum median.
> - None of the shipped graphs in `configs/` route
>   `raft_engine.voter_set` to `commit_tracker.voter_set`.
>
> `admin_handler` accordingly returns `ADMIN_STATUS_UNSUPPORTED` for
> `ADD_VOTER` / `REMOVE_VOTER`. The safe gate stays closed until the
> union-quorum implementation in `durability_ledger` and the
> end-to-end wiring land.

Reconfigurations walk through four phases.

### 1) Preflight

ControlPlaneRaft validates:

- Placement feasibility (≤ 70% utilisation after the move).
- Survivability prechecks (`Q` and `H` ratios).
- Deterministic rehearsal (`placement_digest`).

Failure produces a structured error. Overrides require signed
justification recorded in the override ledger.

### 2) Catch-up

Joining replicas enter `Learner` state. They satisfy at least one of:

- `(raft_commit_index − membership.catchup_slack_bytes)` with default
  4 MiB, or
- `(leader.last_log_index − membership.catchup_index_slack)` with
  default 1024 entries,

within `membership.catchup_timeout = 120,000` ms. Either guard
suffices unless policy demands both.

### 3) Joint consensus

After catch-up, the leader writes:

```
MembershipChange {
    old_members[],
    new_members[],
    routing_epoch,
    placement_digest,
}
```

and operates with the **union quorum**. Voluntary leader transfers
are blocked while in joint config. Each `MembershipChange` carries
the rehearsal digest so replay can prove the change was prevalidated.

### 4) Finalise

Once **both**:

- `joint_commit_count ≥ membership.finalize_window` (default 64), and
- structural lag is below both `lag_bytes < 64 MiB` and
  `lag_duration < 30 s`,

the leader commits the pure new configuration and mirrors it back to
ControlPlaneRaft, which records the resulting proof so subsequent
joins can cite the exact ledger index.

### Rollback

Triggered when catch-up fails, lag remains structural beyond
`membership.rollback_grace_ms = 3000`, or survivability prechecks
fail mid-flight. Rollback appends:

```
MembershipRollback { reason, failing_nodes[], override_ref }
```

commits it under the joint quorum, records the durability proof for
the rollback index, and only then allows elections to proceed.

### Cross-cutting

Every membership transition emits `DurabilityTransition` and
`FenceCommit` proofs if durability modes or DR fences change
simultaneously. Replicas persist the ControlPlaneRaft ack containing
`{routing_epoch, membership_digest, durability_mode_epoch}` before
serving client traffic under the new membership. That way observers
can prove which quorum composition produced the active log suffix.
