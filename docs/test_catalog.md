# Test Catalog

Where regression coverage lives today, what each surface asserts, and
which prerequisites it depends on.

`tests/**` and `benches/**` are **shadow-tracked** per
[`standards/test-tracking.md`](../../standards/test-tracking.md):
fully versioned in a second local-only repo at `.git-shadow/`
(operate on it with `git shadow status` / `log` / `commit`), never
pushed to this repo's GitHub remote. Don't look for their history in
the primary `git log` — it lives in the shadow repo only. CI
hard-fails when the trees are absent (`tools/ci-e2e.sh`), so a
checkout without the shadow content cannot report a vacuous green.

## Host-side integration tests (`tests/*.rs`)

These compile against the cargo host toolchain and run as part of
`cargo test --workspace`.

| File | Scope | Skip behaviour |
|---|---|---|
| `tests/facade.rs` | Encode/decode and bookkeeping for `modules/common/replica_facade.rs` — `build_tagged_proposal`, `InflightTable`, `CommittedSubscriber`, `SnapshotInstaller` / `SnapshotExporter`, `MembershipView`, `ReadGateInputs`. Full facade contract: [`architecture/consumer_facade.md`](architecture/consumer_facade.md). | Never skips. |
| `tests/facade_stress.rs` | Facade data structures under thread stress (correlation table + committed subscriber under heavy concurrent push/drain). | Never skips. |
| `tests/sdk_primitives.rs` | Substrate-wide primitives every clustor module pulls via `#[path]`: `RingBuf` (`modules/common/collections.rs`), `NodeSet` and `quorum_index*` (`modules/common/types.rs`). Bugs here surface as multi-module corruption at runtime, so coverage lives here rather than in any single module's test. | Never skips. |
| `tests/sandbox.rs` | Self-test for the `TestSandbox` helper (`tests/support/sandbox.rs`): per-test scratch dir creation, cleanup on drop, and the `CLUSTOR_KEEP_TEST_SANDBOXES=1` override. | Never skips. |
| `tests/config_validate.rs` | Renders every `configs/*.yaml` using the defaults in `fluxor.toml::[ci.templates].vars`, prepends `module_search_paths: [modules/app]`, and runs `fluxor build --check --target linux` against the rendered config. Catches dangling-edge drift — e.g., a port reference like `consensus.cross_durability_ack` in a YAML that does not declare `consensus`. | Skips with a note if `fluxor` is not on `PATH`. |
| `tests/http_admin.rs` | Pure-logic coverage for the HTTP admin mapping shared between the `http` component of `operations` and host tests (`modules/common/http_admin.rs`): path → op-code mapping, body-size cap, and a drift assertion against the canonical wire ABI bytes. | Never skips. |
| `tests/wal_scan.rs` | Host-side coverage for the WAL's below-ring-floor segment-scan fallback (`modules/app/durability/wal.rs::step_entry_scan`) — recovery refetch of indices older than the 8192-entry location ring. | Never skips. |
| `tests/session_registry.rs` | State-machine-level tests for the session-registry replicated consumer (fluxor `rfc_protocols.md` §8.3 / §13.7): the R1–R5 verification gates — key custody, reservation monotonicity, epoch fencing, snapshot round-trip. | Never skips. |

## Cluster harness tests (`tests/cluster.rs`, `tests/chaos.rs`, `tests/partition.rs`)

These spawn real `fluxor-linux` processes via the harness at
`tests/support/cluster.rs`. They have hard prerequisites and **runtime-skip** when
prereqs are missing — a green `cargo test cluster` without those
prereqs means the tests skipped, not that they exercised the
multi-node path.

Required prerequisites:

- `fluxor` on `PATH` (defaults to `/usr/bin/fluxor`).
- `fluxor-linux` at `target/<host-target>/release/fluxor-linux` — materialised by `fluxor sync` from the local registry (`fluxor publish runtime --binary fluxor-linux` upstream).
- Built clustor `.fmod` artefacts at `target/fluxor/<silicon>/modules/` — the default `fluxor modules build` output. Build **without** `--out`: a redirected output path is not where the harness looks, so tests would run stale fmods.

To make a missing prereq a hard failure instead of a skip, set
`CLUSTOR_REQUIRE_E2E=1`. CI surfaces that claim to gate on
multi-node behaviour should set this.

| File | Scope |
|---|---|
| `tests/cluster.rs` | End-to-end smoke and Raft correctness over 1- / 2- / 3-replica topologies: bring-up + tear-down hygiene, basic AppendEntries flow, propose-and-commit, leader-change cancellation, HTTP diagnostics (`/readyz`, `/why`, `/metrics`) and the admin POST path. |
| `tests/chaos.rs` | Fault-injection on top of the cluster harness — `kill -STOP / -CONT` on individual nodes, asserts liveness recovery and apply-pipeline reconvergence. |
| `tests/partition.rs` | 2-node × 2-partition (`multi-2node-2p*.yaml`) coverage. Asserts each partition maintains independent leadership and that durability ledgers don't cross-pollinate. |
| `tests/wal_group_fsync.rs` | WAL group-fsync behavioural gates against a single-node cluster: per-entry ack at `fsync_mode = 0`; batched group-fsync ack at `fsync_mode = 1`; `group_max_pending = 1` collapses to per-entry equivalence; mid-batch crash replays orphan acks. Assertions only inspect operator-visible log signatures, not private state. |
| `tests/wal_replay.rs` | WAL replay across restart: drives a single node in per-entry-fsync mode through admin operations, kills it, restarts against the same `wal/` directory, and asserts startup replay re-emits the durable entries and the apply pipeline catches up to the pre-shutdown commit index. |
| `tests/session_directory_e2e.rs` | End-to-end for the `session_directory` consumer: boots `configs/session-directory.yaml` and drives the BIND → RESERVE → RESERVE smoke sequence as tagged raft entries, asserting each reply arrives only after commit. |

The hardware-rig fixtures live under `tests/hardware/`
(`drive-pi5-rig.sh`, `wal_group_fsync_pi5.toml`, recorded baselines
in `tests/hardware/baselines/`); see `tests/hardware/README.md` and
[`standards/rig.md`](../../standards/rig.md).

The full punch list of scenarios still gated on substrate or tooling
work (POST `/propose`, joint-consensus admin ops, network-fault
injection) lives at `.context/test_scenarios_pending.md`.

## Inline module tests

The fluxor hygiene scanner blocks `#[cfg(test)] mod tests` and
`#[test]` under `modules/**` and `src/**` per
`standards/tests.md`. The one structured exemption is
`modules/common/replica_facade.rs`, which is dual-targeted (no_std
module ELF + host `cargo test` via `#[path]`) and carries its
exemption row in `fluxor.toml::[[ci.hygiene.exemption]]`.

Everything else that wants test coverage either:

- Lives as an integration test under `tests/` (see above), or
- Has its pure-logic surface extracted to `modules/common/` so the
  same `#[path]` mechanism works for both the no_std module and the
  host test crate. `modules/common/http_admin.rs` is the canonical
  example.

## Benches (`benches/*.rs`)

`benches/` is shadow-tracked alongside `tests/` (see the note at the
top of this catalog) — the sources are on disk and versioned in
`.git-shadow/`, registered in `Cargo.toml`'s `[[bench]]` table:

| Bench | Asserts |
|---|---|
| `benches/wire_codec.rs` | `MSG_TAGGED_PROPOSAL` encode and `MSG_PROPOSAL_ASSIGNED` decode microbench. |
| `benches/inflight_table.rs` | Full register → assign → commit → take_committed lifecycle in `InflightTable`. |
| `benches/committed_subscriber.rs` | Strict-order ingest path for batched `MSG_COMMITTED_BATCH` envelopes. |

Each uses Criterion with `harness = false`. Run with `make bench`,
or `cargo bench --bench <name> -- --quick` for one suite.
