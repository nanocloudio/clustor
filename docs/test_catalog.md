# Test Catalog

Where regression coverage lives today, what each surface asserts, and
which prerequisites it depends on.

## Host-side integration tests (`tests/*.rs`)

These compile against the cargo host toolchain and run as part of
`cargo test --workspace`.

| File | Scope | Skip behaviour |
|---|---|---|
| `tests/facade.rs` | Encode/decode and bookkeeping for `modules/sdk/replica_facade.rs` — `build_tagged_proposal`, `InflightTable`, `CommittedSubscriber`, `SnapshotInstaller` / `SnapshotExporter`, `MembershipView`, `ReadGateInputs`. The full facade contract documented at `docs/architecture/consumer_facade.md`. | Never skips. |
| `tests/facade_stress.rs` | Facade data structures under thread stress (correlation table + committed subscriber under heavy concurrent push/drain). | Never skips. |
| `tests/sandbox.rs` | Self-test for the `TestSandbox` helper (`tests/support/sandbox.rs`): per-test scratch dir creation, cleanup on drop, and the `CLUSTOR_KEEP_TEST_SANDBOXES=1` override. | Never skips. |
| `tests/config_validate.rs` | Renders every `configs/*.yaml` using the defaults in `fluxor.toml::[ci.templates].vars`, prepends `module_search_paths: [modules/app]`, and runs `fluxor validate --target linux` against the rendered config. Catches dangling-edge drift like the previous `replicator.cross_durability_ack` reference in `single-minimal.yaml` with no `replicator` module declared. | Skips with a note if `fluxor` is not on `PATH`. |
| `tests/http_admin.rs` | Pure-logic coverage for the HTTP admin mapping shared between `http_adapter` and host tests (`modules/sdk/http_admin.rs`): path → op-code mapping, body-size cap, and a drift assertion against the canonical wire ABI bytes. | Never skips. |

## Cluster harness tests (`tests/cluster.rs`, `tests/chaos.rs`, `tests/partition.rs`)

These spawn real `fluxor-linux` processes via the harness at
`tests/support/cluster.rs`. They have hard prerequisites and **runtime-skip** when
prereqs are missing — a green `cargo test cluster` without those
prereqs means the tests skipped, not that they exercised the
multi-node path.

Required prerequisites:

- `fluxor` on `PATH` (defaults to `/usr/bin/fluxor`).
- `fluxor-linux` at `deps/fluxor/target/aarch64-unknown-linux-gnu/release/fluxor-linux`.
- Built clustor `.fmod` artefacts at `target/fluxor/<silicon>/modules/` (or the legacy `deps/fluxor/target/<silicon>/modules/` with a one-shot deprecation warning).

To make a missing prereq a hard failure instead of a skip, set
`CLUSTOR_REQUIRE_E2E=1`. CI surfaces that claim to gate on
multi-node behaviour should set this.

| File | Scope |
|---|---|
| `tests/cluster.rs` | End-to-end smoke and Raft correctness over 1- / 2- / 3-replica topologies: bring-up + tear-down hygiene, basic AppendEntries flow, propose-and-commit, leader-change cancellation, HTTP diagnostics (`/readyz`, `/why`, `/metrics`) and the admin POST path. |
| `tests/chaos.rs` | Fault-injection on top of the cluster harness — `kill -STOP / -CONT` on individual nodes, asserts liveness recovery and apply-pipeline reconvergence. |
| `tests/partition.rs` | 2-node × 2-partition (`multi-2node-2p*.yaml`) coverage. Asserts each partition maintains independent leadership and that durability ledgers don't cross-pollinate. |

The full punch list of scenarios still gated on substrate or tooling
work (POST `/propose`, joint-consensus admin ops, network-fault
injection) lives at `.context/test_scenarios_pending.md`.

## Inline module tests

The fluxor hygiene scanner blocks `#[cfg(test)] mod tests` and
`#[test]` under `modules/**` and `src/**` per
`standards/tests.md`. The one structured exemption is
`modules/sdk/replica_facade.rs`, which is dual-targeted (no_std
module ELF + host `cargo test` via `#[path]`) and carries its
exemption row in `fluxor.toml::[[ci.hygiene.exemption]]`.

Everything else that wants test coverage either:

- Lives as an integration test under `tests/` (see above), or
- Has its pure-logic surface extracted to `modules/sdk/` so the
  same `#[path]` mechanism works for both the no_std module and the
  host test crate. `modules/sdk/http_admin.rs` is the canonical
  example.

## Benches (`benches/*.rs`)

| Bench | Asserts |
|---|---|
| `benches/wire_codec.rs` | `MSG_TAGGED_PROPOSAL` encode and `MSG_PROPOSAL_ASSIGNED` decode microbench. |
| `benches/inflight_table.rs` | Full register → assign → commit → take_committed lifecycle in `InflightTable`. |
| `benches/committed_subscriber.rs` | Strict-order ingest path for batched `MSG_COMMITTED_BATCH` envelopes. |

Each uses Criterion with `harness = false`. Run with `cargo bench`
or `cargo bench --bench <name> -- --quick`.
