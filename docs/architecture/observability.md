# Observability

The metrics surface, the structured-explain APIs, the throttle
envelope shape, and the artifact bundles that audit and validation
tooling consume. Designed so deployment controllers can gate
activations on exactly the same predicates the data plane evaluates
— a single source of truth for "is this cluster ready?"

## Table of Contents

1. [Metrics and telemetry](#metrics-and-telemetry)
2. [Readiness](#readiness)
3. [Throttle envelopes and explain APIs](#throttle-envelopes-and-explain-apis)
4. [Artifact bundles and audit](#artifact-bundles-and-audit)

---

## Metrics and telemetry

### Namespaces

```
clustor.raft.*
clustor.wal.*
clustor.snapshot.*
clustor.flow.*
clustor.controlplane.*
clustor.security.*
```

Every export also carries `metrics.schema_version` and
`metrics.build_git_sha`.

### Histogram buckets

Fixed across releases. Implicit `+Inf` bucket is in addition to the
inclusive upper bounds listed:

| Metric | Buckets (inclusive upper bounds) | Unit |
|---|---|---|
| `clustor.wal.fsync_latency_ms` | `0.25, 0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100` | ms |
| `clustor.raft.commit_latency_ms` | `0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100` | ms |
| `clustor.flow.apply_batch_latency_ms` | `0.25, 0.5, 1, 2, 4, 6, 8, 10` | ms |
| `clustor.snapshot.transfer_seconds` | `1, 2, 4, 8, 16, 32, 64, 128, 256` | s |

Deployments outside profile SLOs still alert even if they saturate
the top bucket — saturation is itself the signal.

### Required telemetry fields

Every conforming node exports the following. Tooling rejects runs
that omit any:

```
strict_fallback_state
strict_fallback_blocking_read_index
strict_fallback_pending_entries
read_gate.*
io_writer_mode_gate_state
lease_gate_runtime_state
clock_guard_alarm*
observer_capability_state
snapshot.delta_chain_length
snapshot.delta_emit_skew_ms
snapshot_only_ready_ratio
flow.pid_auto_tune_state
flow.pid_auto_tune_adjust_total
transport.pool_*
feature.<name>_gate_state
feature.<name>_predicate_digest
controlplane.cache_state
controlplane.cache_age_ms
controlplane.cache_warning
controlplane.cache_expiry_total
strict_only_runtime_ms
ingest_status_code
credit_hint
durability_status_code
```

### Incident logging

Alerts feed correlated incidents under a storm guard:

```
incident_max_per_window      = max(5, ceil(active_partitions_on_node / 250))
window                       = 600,000 ms (10 min)
cooldown_between_duplicates  = 300,000 ms
```

Safety-critical classes are exempt from the storm guard.

---

## Readiness

`/readyz` surfaces:

- Readiness ratios.
- Definition bundle state.
- Activation barriers.
- Warmup readiness.
- Fixture bundle version and age.
- Ingest status and credit hints.
- Feature gates.

Deployment controllers gate activations on the same fields the data
plane evaluates. The contract is symmetry: if `/readyz` says the
cluster is ready, the data plane has already cleared every predicate.

---

## Throttle envelopes and explain APIs

### Throttle envelopes

Constraints:

- ≤ 32 KiB JSON.
- ≤ 32 IDs per array.
- IDs sorted lexicographically.
- Continuation tokens included when truncated.

Wire shape and reasons in
[errors.md](errors.md#throttleenvelope).

### Explain endpoints

A family of structured-explain endpoints share the envelope schema
header. Every endpoint carries decision trace IDs, guardrail deltas,
and truncated-list metadata so an operator can trace a decision back
to the predicate that produced it.

| Endpoint | Surfaces |
|---|---|
| `WhyNotLeader` | Why this node refuses to serve writes |
| `WhyCreditZero` | Which credit pool is empty and why |
| `WhySnapshotBlocked` | Which guardrail is fencing snapshot emission |
| `WhyDiskBlocked` | Disk-policy or geometry block |
| `WhyQuarantined` | Quarantine reason and `since_ms` |
| `WhyCreditHint` | Why the credit hint is `Recover`/`Hold`/`Shed` |

### Admin dry-run endpoints

Report computed guardrails (catch-up slack and timeout, predicted
credit impact) without committing the change:

- `DryRunMovePartition`
- `DryRunSnapshot`
- `DryRunFailover`

---

## Artifact bundles and audit

Specification automation regenerates machine-readable bundles from
the source tree. Builds compare bundles byte-for-byte and block
releases on drift.

### Bundle catalog

```
wire_catalog.json
chunked_list_schema.json
system_log_catalog.json
wide_int_catalog.json
spec_fixtures.bundle.json
consensus_core_manifest.json
proof_artifacts.json
term_registry.json
metrics_buckets.json
```

Each bundle entry carries SHA-256 digests, schema versions, manifest
hashes, and Ed25519 signatures (`ReleaseAutomationKey`,
`CPReleaseKey` — see
[security.md](security.md#key-purpose-registry)). The manifest maps
section IDs to digests plus a Merkle tree root
(`spec_hash_format = "SpecHashV1"`).

### Proof provenance

Releases publish `proof_bundle_schema_version`,
`proof_bundle_sha256`, and detached signatures binding Loom and
TLA+ archives, fixture suites, and feature manifests. Auditors
recompute digests to validate artifacts without CI access.

### Fixture catalog

The clause-to-fixture map and wide-int registry feed deterministic
`spec_fixtures.bundle.json`. Automation enforces coverage and
rejects mismatched fixtures. Vendors may add private fixtures but
retain canonical vectors:

- `PreVoteResponse` ([wire.md](wire.md#prevoteresponse-frames))
- `ChunkedList`
- Lease inequality
- Snapshot manifest ([security.md](security.md#snapshot-manifest-sample))
- Segment MAC ([security.md](security.md#segment-mac-vector))
- AEAD constant-time ([security.md](security.md#aead-constant-time-comparison))
- Crash-consistency harness
- Jepsen-like scenarios

### Startup spec self-tests

Rerun encoding fixtures, catalog regeneration, lease inequalities,
incremental cadence, BLAKE3 vectors, and other checks before mounting
partitions. Failures quarantine nodes and require operator override.

### Release evidence

Exposed via `/readyz`:

- `bundle_version`
- `bundle_sha256`
- `fixture_suite_ts`
- `fixtures.bundle_version`
- `fixtures.bundle_age_ms`

CI blocks release artifacts if the bundle timestamp vs git tag
differs by > 86,400,000 ms (24 h).

### Artifact location independence

Runtime correctness does not depend on reading files from
`/artifacts` or `/manifests`. Binaries embed the necessary catalogs
and expose them via APIs
(`/.well-known/wide-int-registry`, `/readyz`). Artifact files only
serve validation, audit, or tooling workflows outside the hot path.

When `/artifacts` is absent (e.g. production images that strip
optional bundles), nodes default to skipping startup validation by
exporting `CLUSTOR_SKIP_ARTIFACT_VALIDATION=1`. Operators who need
the original fail-closed behaviour instead set
`CLUSTOR_REQUIRE_ARTIFACT_VALIDATION=1`, which forces bootstrap to
error until the artifacts are restored.
