# Clustor

Clustor is a Raft replication substrate for products like Quantum
(MQTT broker) and Lattice (KV store). It provides a drop-in
consensus kernel with durable log replication, quorum tracking,
diagnostic surfaces, and a typed consumer facade for replicated
state machines.

The implementation is Fluxor-native: 23 substrate modules plus
`example_consumer` (24 buildable `.fmod` artifacts) ship as
position-independent ELFs and run cooperatively on the Fluxor
runtime.

The architecture docs — every wire byte, durability invariant, and
operational guardrail — live under
[`docs/architecture/`](docs/architecture/), indexed by
[`docs/overview.md`](docs/overview.md). The module-map and
execution-domain rationale is at
[`docs/architecture/modules.md`](docs/architecture/modules.md).

## Setup

Clustor consumes fluxor through a local-first registry. The
contract lives at
[`../standards/dependencies.md`](../standards/dependencies.md);
the day-to-day guide is
[`docs/consuming_fluxor.md`](docs/consuming_fluxor.md).

```sh
# one-time, per developer machine
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
cd ../fluxor
make setup                 # install the fluxor CLI onto PATH
fluxor registry init       # bootstrap ~/.fluxor/registry/
fluxor registry setup-cargo  # add [registries.fluxor] to ~/.cargo/config.toml
make publish               # publish abi + sdk crates, fmod palette, runtime

# in clustor's checkout
cd ../clustor
make setup                 # install the fluxor CLI onto PATH
make update                # resolve fluxor.lock against the local registry
make sync                  # materialise crates / fmods / runtime into target/
```

Subsequent fluxor changes flow through with `make publish && (cd
../clustor && make update && make sync)`. The lockfile records what
fluxor publishes; the deployment YAML decides which subset is wired
into the runtime (RFC §5).

### Iterating on fluxor and clustor together

When iterating on both repos at once, add them to
`~/.fluxor/workspace.toml`:

```toml
[workspace]
members = [
  "/home/dev/Development/fluxor",
  "/home/dev/Development/clustor",
]
```

`fluxor sync` then prefers fluxor's locally-built `target/`
artefacts as an override; anything unbuilt locally resolves from
the registry copy recorded in `fluxor.lock`. Source crates resolve
through the registry either way — re-publish on demand when you
change fluxor's SDK source.

### Bumping fluxor

```sh
# in ../fluxor
make publish               # canonical (bump [project].version first)

# in clustor
make update                # regenerate fluxor.lock against the registry
make sync                  # materialise resolved artefacts into target/
git commit fluxor.lock     # commit the pin
```

### Publishing clustor downstream

Projects that depend on clustor (Lattice, Loam, Quantum, …) pin it
through the same registry mechanism by declaring `clustor = "X.Y"`
in their `fluxor.toml::[dependencies]`. From clustor's checkout:

```sh
make publish               # publish clustor-common + 24 substrate fmods
```

This populates `~/.fluxor/registry/cargo/clustor-common-X.Y.Z.crate`
and `~/.fluxor/registry/fmod/clustor/<silicon>/<name>/X.Y.Z.fmod`
for every module under `modules/app/`. Downstream consumers then
run `make update && make sync` in their own checkouts to resolve
and materialise the published palette. Bump
`[workspace.package].version` (Cargo.toml), the matching
`[package].version` in `crates/clustor-common/Cargo.toml`, and
`[project].version` in `fluxor.toml` together before publishing a
new release; `fluxor publish` rejects mismatches at publish time.

## Quick start

```sh
make modules              # build .fmod for bcm2712 (default target)
make up                   # render+run configs/single.yaml
make up CONFIG=configs/multi-3node.yaml NODE_ID=0  # node 0 of a 3-node cluster
make test                 # host-side test suite (~20 s)
make ci                   # full pipeline (fmt + test + clippy + modules)
make help                 # everything else
```

The cluster harness needs `fluxor` on PATH (defaults to
`/usr/bin/fluxor`) and `fluxor-linux` at
`target/aarch64-unknown-linux-gnu/release/fluxor-linux` (materialised
by `make sync` from the local registry). Missing
prereqs cause `cluster.rs` / `chaos.rs` / `partition.rs` to
**runtime-skip** with a one-line note rather than fail — so a green
`cargo test` from a workstation without those prereqs proves only
that the host-side tests (`facade.rs`, `facade_stress.rs`,
`sandbox.rs`, `config_validate.rs`) and the unit suites passed, not
that the cluster path was exercised. Set `CLUSTOR_REQUIRE_E2E=1`
to make a missing prereq a hard test failure instead — the right
default for any CI surface that claims to gate on multi-node
behaviour.

## Repo layout

| Path           | Contents |
|----------------|----------|
| `modules/app/`    | 24 `no_std` PIC modules — 23 substrate modules (`raft_engine`, `wal`, …) plus `example_consumer`, the minimal downstream module that exercises the per-entry stream. `make modules` packs each `mod.rs` + `manifest.toml` into a `.fmod`. |
| `modules/common/` | Shared types, wire constants, the consumer facade, and the HTTP admin mapping. Pulled into each app module via `#[path]` and into host tests via the same mechanism. |
| `configs/`     | `fluxor run` graph templates. `single.yaml` (1 node), `multi-2node.yaml` (2 replicas), `multi-3node.yaml` (3 replicas, canonical Raft availability shape), `multi-2node-2p*.yaml` (partition-group experiments), `single-minimal.yaml` (commit-pipeline only). Each carries `__SELF_ID__` / `__LISTEN_PORT__` / `__PEER{0,1,2}_PORT__` placeholders that `fluxor render-template` (and the cluster harness) substitute per node. |
| `tests/`       | Host-side integration tests: `facade.rs`, `facade_stress.rs`, `cluster.rs`, `chaos.rs`, `sandbox.rs`. The cluster harness at `tests/support/cluster.rs` spawns multi-node `fluxor-linux` processes. |
| `benches/`     | Criterion microbenches against `replica_facade.rs`. |
| `docs/`        | Stable reference: architecture (`docs/architecture/`), module map, subsystem deep-dives. |
| `.context/`    | In-flight design work — RFCs, audits, plans, working notes. Not part of the stable reference surface. |
| `fluxor.toml`  | Project config consumed by the `fluxor` CLI: identity, dependency declarations, CI targets, hygiene tier policy, structured exemptions. See [`standards/`](../standards/). |
| `Makefile`     | Thin alias layer over the `fluxor` CLI. `make help` lists every canonical target. |

## Module map

The 23 substrate modules (`example_consumer` is wired only into the
minimal smoke graph) sit in four execution domains on a Pi 5 / CM5:

| Domain     | Tick   | Modules                                                                                             |
|------------|--------|------------------------------------------------------------------------------------------------------|
| consensus  | poll   | `raft_engine`, `wal`, `durability_ledger`, `commit_tracker`                                          |
| network    | poll   | `peer_router`, `replicator` (with platform `nic`/`ip`/`tls`)                                         |
| apply      | 250 µs | `client_codec`, `throttle_gate`, `partition_router`, `flow_controller`, `read_gate`, `apply_pipeline`, `placement_router` |
| ops        | 1 ms   | `client_surface`, `cp_bridge`, `cp_proof_cache`, `rbac`, `admin_handler`, `snapshot_engine`, `telemetry_agg`, `key_manager`, `http_ingress`, `http_adapter` |

Cross-domain edges run over fluxor mailbox channels with SEV/WFE
hardware wake (~200 ns on coherent L3). The full wiring graph is
canonical in [`configs/single.yaml`](configs/single.yaml); see
[`docs/architecture/modules.md`](docs/architecture/modules.md) for the rationale.

## Consumer facade

Replicated apps (Lattice, Loam, Quantum, …) integrate against the
`no_std` helper at
[`modules/common/replica_facade.rs`](modules/common/replica_facade.rs):

```rust
#[path = "../common/replica_facade.rs"]
mod replica_facade;
```

It provides `build_tagged_proposal`, `InflightTable`,
`CommittedSubscriber`, `SnapshotInstaller`/`SnapshotExporter`,
`MembershipView`, and `ReadGateInputs`. The normative contract
(`ReplicaGroup` trait, propose lifecycle, leader-change protocol,
snapshot install layout, read-gate predicate) is
[`docs/architecture/consumer_facade.md`](docs/architecture/consumer_facade.md).
Host-side
unit and integration coverage lives in
[`tests/facade.rs`](tests/facade.rs); multi-node end-to-end is in
[`tests/cluster.rs`](tests/cluster.rs).

## Status

| Surface              | State |
|----------------------|-------|
| `raft_engine`        | Leader election, AE, log matching, conflict-repair retry, joint consensus, leadership transfer — passing in `cluster.rs`. |
| `wal` / `durability_ledger` | Per-partition WAL, fsync ack, quorum durability — passing. |
| `apply_pipeline`     | Strict commit-order delivery, snapshot reset, per-entry fan-out — passing. |
| `snapshot_engine`    | Manifest auth, chunked install/export, follower catch-up — passing. |
| `read_gate` / `cp_proof_cache` | Fresh→Cached→Stale state machine, strict-fallback transitions — passing. |
| `admin_handler`      | `FREEZE`, `THAW`, `TRANSFER_LEADER`, `DURABILITY_MODE`, `SNAPSHOT_TRIGGER` route through. `ADD/REMOVE_VOTER` returns `ADMIN_STATUS_UNSUPPORTED` — the `raft_engine` joint-consensus state machine (`CONFIG_CHANGE_OP_JOINT/_NEW`, voter-set overlay, auto-C_new on commit) exists and applies entries correctly, but `commit_tracker` and `durability_ledger` don't yet enforce *union* quorum during the joint phase. Accepting membership changes without that enforcement risks losing committed entries; the safe gate stays closed until learner + union-quorum lands (see [`docs/architecture/lifecycle.md#membership-changes-and-joint-consensus`](docs/architecture/lifecycle.md#membership-changes-and-joint-consensus)). |
| `partition_router`   | FNV-1a partition routing, 2-partition smoke working ([configs/multi-2node-2p.yaml](configs/multi-2node-2p.yaml), exercised by [tests/partition.rs](tests/partition.rs)). N-partition + per-partition admin still in flight. |
| `cp_bridge`          | HTTP fetcher polls a host control plane; production CP integration is the next milestone. |
| Telemetry            | `GET /readyz` / `/why` / `/metrics` reachable on each node's `listen_port + 10000` HTTP socket via `http_ingress` + `http_adapter`; histograms and incidents in place; full Prometheus pull is pending. |

## Performance

Criterion microbenches on a Pi 5 / Pi-class ARM64:

| Bench                                   | Time      | Throughput                  |
|-----------------------------------------|-----------|-----------------------------|
| `wire_codec` / `committed_entry/1024`   | 2.6 ns    | 372 GiB/s                   |
| `wire_codec` / `proposal_assigned`      | 4.3 ns    | —                           |
| `committed_subscriber/ingest/1024`      | 153 ns    | 6.3 GiB/s                   |
| `inflight_table/full_lifecycle/32`      | 41 ns     | —                           |

End-to-end cluster smoke (18 multi-node tests, default
`cargo test`) finishes in ~21 s on a Pi 5.

## Development conventions

| Topic                          | Convention |
|--------------------------------|-----------|
| Tests                          | One file per concern: `cluster.rs`, `chaos.rs`, `facade.rs`, `facade_stress.rs`, `sandbox.rs`. No `_it`/`_smoke`/`_checkpoint` suffix salad. |
| Sandboxes                      | Every disk-touching test goes through `tests/support/sandbox.rs::TestSandbox` (under `target/test-sandboxes/`). `CLUSTOR_KEEP_TEST_SANDBOXES=1` keeps them on drop for post-mortem. |
| Cluster harness                | `tests/support/cluster.rs`. Each cluster gets a unique yaml stem so `fluxor run`'s outputs land in disjoint `target/linux/cluster-<pid>-c<seq>-n<i>/` dirs and are wiped on `Drop`. |
| Module hygiene                 | `fluxor lint hygiene` (run as part of `fluxor ci`) blocks `#[cfg(test)]` / `mod tests` / `#[test]` under `modules/**` and `src/**` per [`standards/tests.md`](../standards/tests.md). The one exception is `modules/common/replica_facade.rs`, which is dual-targeted (`no_std` ELF + host `cargo test`) and carries a structured exemption in `fluxor.toml`. |
| Cleanup                        | `make clean` runs `cargo clean` plus `fluxor modules clean`. |

## Specification & docs

- [`docs/architecture/`](docs/architecture/) — concepts, wire,
  replication, lifecycle, security, observability, compatibility,
  consumer facade. Indexed by
  [`docs/overview.md`](docs/overview.md).
- [`docs/architecture/modules.md`](docs/architecture/modules.md) — module map,
  domain layout, design rationale.
- [`docs/`](docs/) — subsystem deep-dives: proposal correlation,
  substrate sharing, management, security posture, test catalog.
- [`.context/`](.context/) — in-flight RFCs (partition groups,
  security, phase-3 plan), audits, design notes.

## License

See [`LICENSE`](LICENSE).
