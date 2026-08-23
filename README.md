# Clustor

Clustor is a Raft replication substrate for the nanocloud products
(Lattice, Loam, Quantum). It provides a consensus kernel with
durable log replication, quorum tracking, diagnostic surfaces, and a
typed consumer facade for replicated state machines. It runs
standalone, as shown below, or embedded as the replication layer of
a downstream product.

The implementation is native to the [fluxor](../fluxor/) runtime: a
palette of seven substrate modules (`peer_router`, `consensus`,
`durability`, `gateway`, `admission`, `control_plane`, `operations`)
ships as position-independent `no_std` ELFs and runs cooperatively
on a wired module graph. Alongside the palette sit the standalone
`session_directory` and `partition_router` modules, two bench
drivers, `example_consumer`, and the `clustor_cli` applet.

## Quick start

```sh
fluxor modules build --all      # build the module palette
fluxor run --replicas 3 - <<'EOF'
<the cluster config — embedded in docs/guides/running.md>
EOF
```

The deployment config pipes straight into `fluxor run` from the run
guide, which carries it inline: nothing else to fetch. A node is
ready when `GET /readyz` on its HTTP port (wire port + 10000, so
19090 for the defaults) returns 200; `POST /propose` commits a
replicated entry and answers `committed`. Ports and node identity
come from the command line (`--base-port`, `--http-offset`,
`--var`); the config carries only the graph.
[`docs/guides/running.md`](docs/guides/running.md) has the full
config plus bring-up, smoke checks, and a failover.

## Setup

Clustor consumes fluxor through the local OCI store
(`$FLUXOR_STORE`, default `~/.local/share/fluxor/store`). The
day-to-day guide is
[`docs/guides/consuming_fluxor.md`](docs/guides/consuming_fluxor.md).

```sh
# one-time, per developer machine
git clone git@github.com:nanocloudio/fluxor.git ../fluxor
make -C ../fluxor install    # put the fluxor CLI launcher on PATH
make -C ../fluxor publish    # publish SDK, module palette, runtime into the store

# in clustor's checkout
fluxor modules build --all   # build; pre-flight materialises pinned
                             # artefacts from fluxor.lock
```

To pick up new fluxor changes: `make publish` in fluxor, then
`fluxor update` in clustor to advance `fluxor.lock` to the latest
published digests, and commit the lockfile. When iterating on both
repos at once, add them to `~/.fluxor/workspace.toml`; workspace
members resolve `:latest` automatically and `fluxor sync` writes the
resolved digests through the lockfile.

### Publishing clustor downstream

Projects that depend on clustor pin it through the same store
mechanism by declaring `clustor = "X.Y"` in their
`fluxor.toml [dependencies]`. From clustor's checkout, `make publish`
publishes the `clustor-common` source tree (store reference
`clustor/src/clustor-common`; the cargo crate lives at
`crates/clustor-common/`) and one module artefact per module under
`modules/app/`, each digest-addressed and epoch-annotated.
Downstream consumers then run `fluxor update` in their own
checkouts. Bump `[workspace.package].version` (Cargo.toml), the
matching version in `crates/clustor-common/Cargo.toml`, and
`[project].version` in `fluxor.toml` together before publishing;
`fluxor publish` rejects mismatches.

### The clustor CLI applet

The product CLI is itself a PIC fmod, run by fluxor rather than
built as a host cargo binary:

```sh
fluxor install packaging/cli/workload.toml     # one-time registration
fluxor exec clustor -- help
fluxor exec clustor -- crc <payload-hex>       # CRC32C of a payload
fluxor exec clustor -- wal-frame <payload-hex> # frame a payload as a WAL entry
fluxor exec clustor -- wal-scan <segment-hex>  # durable-prefix scan of a segment
```

`wal-scan` runs the same frame validation as the `durability`
module's replay, so its verdict on a segment image is the durable
prefix a replica would recover. Module source:
[`modules/app/clustor_cli/`](modules/app/clustor_cli/); packaging:
[`packaging/cli/`](packaging/cli/).

## Repository layout

| Path              | Contents |
|-------------------|----------|
| `modules/app/`    | `no_std` PIC modules: the seven substrate modules, `session_directory`, `partition_router`, the `consensus_bench` / `nvme_bench` drivers, `example_consumer`, and `clustor_cli`. `fluxor modules build` packs each into a `.fmod`, plus one per declared variant (`durability` has a `volatile` variant, `operations` a `headless` one). |
| `modules/common/` | Shared types, wire constants, the WAL frame contract, the consumer facade, and the HTTP admin mapping. Pulled into each app module via `#[path]`. |
| `crates/`         | `clustor-common`, the publishable cargo crate re-exporting the pure `no_std` subset of `modules/common/` for host consumers. |
| `packaging/`      | Distribution packaging; `packaging/cli/` holds the CLI applet's graph and workload manifest. |
| `tools/`          | The `clustor-bench` host crate (`clustor-scrape`, `clustor-loadgen`) and repository scripts. |
| `docs/`           | Stable reference: guides (`docs/guides/`) and architecture (`docs/architecture/`). Indexed by [`docs/overview.md`](docs/overview.md). |
| `fluxor.toml`     | Project manifest for the `fluxor` CLI: identity, dependencies, project policy. |
| `Makefile`        | Thin alias layer over the `fluxor` CLI; `make help` lists the targets. |

## Module map

Each module is one scheduler entity with one arena; components are
source subtrees inside it, stepped by an explicit dispatch table so
intra-tick ordering is owned in one place. Cross-module edges are
fluxor mailbox channels.

| Module          | Components | Role |
|-----------------|------------|------|
| `consensus`     | raft, replicator, commit, apply | Elections, log replication, commit ordering, apply fan-out |
| `durability`    | wal, ledger, snapshot, keys | Segment WAL, quorum durability tracking, snapshots |
| `peer_router`   | — | Wire envelope demux between replicas and clients |
| `gateway`       | surface, codec, throttle | Client framing, proposal tagging, admission |
| `admission`     | proof_cache, read_gate, flow | Proof cache, read gating, PID flow control |
| `control_plane` | cp, placement | Control-plane proof and placement feed |
| `operations`    | rbac, admin, telemetry, http | Admin commands, metrics, diagnostic HTTP |

The full wiring is the graph embedded in
[`docs/guides/running.md`](docs/guides/running.md);
[`docs/architecture/modules.md`](docs/architecture/modules.md) has
the per-module reference and design rationale.

## Consumer facade

Replicated applications integrate against the `no_std` helper at
[`modules/common/replica_facade.rs`](modules/common/replica_facade.rs):

```rust
#[path = "../common/replica_facade.rs"]
mod replica_facade;
```

It provides `build_tagged_proposal`, `InflightTable`,
`CommittedSubscriber`, `SnapshotInstaller` / `SnapshotExporter`,
`MembershipView`, and `ReadGateInputs`. The normative contract is
[`docs/architecture/consumer_facade.md`](docs/architecture/consumer_facade.md).

## Status

| Surface | State |
|---------|-------|
| `consensus` (raft) | Leader election, AppendEntries, log matching, conflict repair, leadership transfer: working. |
| `durability` (wal / ledger) | Per-partition WAL, fsync acknowledgement, quorum durability: working. |
| `consensus` (apply) | Strict commit-order delivery, snapshot reset, per-entry fan-out: working. |
| `durability` (snapshot) | Manifest handling, chunked install/export, follower catch-up: working. |
| `admission` | Fresh→Cached→Stale proof ladder, strict-fallback transitions, read permits: working. |
| `operations` (admin) | `FREEZE`, `THAW`, `TRANSFER_LEADER`, `DURABILITY_MODE`, `SNAPSHOT_TRIGGER` route through. `ADD/REMOVE_VOTER` returns `ADMIN_STATUS_UNSUPPORTED`: the joint-consensus state machine exists, but the durability ledger does not yet enforce union quorum during the joint phase, so the gate stays closed. See [`docs/architecture/lifecycle.md`](docs/architecture/lifecycle.md#membership-changes-and-joint-consensus). |
| `partition_router` | FNV-1a partition routing; 2-partition graphs working. N-partition and per-partition admin are in flight. |
| `control_plane` | Emits a synthetic proof on a fixed schedule; a production control-plane feed is the next milestone. |
| Telemetry | `/readyz`, `/why`, `/metrics` served per node by `operations`; per-component step histograms in place. The export is binary; `clustor-scrape` decodes it. |

## Documentation

- [`docs/guides/running.md`](docs/guides/running.md) — bring-up and smoke checks.
- [`docs/overview.md`](docs/overview.md) — index of everything below.
- [`docs/architecture/`](docs/architecture/) — concepts, wire format,
  replication, lifecycle, security posture, observability,
  compatibility, consumer facade, session directory.
- [`docs/guides/`](docs/guides/) — guides: proposal correlation,
  substrate sharing, HTTP surface, fluxor consumption.

## License

See [`LICENSE`](LICENSE).
