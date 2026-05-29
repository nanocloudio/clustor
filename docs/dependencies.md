# Dependency Inventory

Clustor's runtime substrate has no `cargo install`-able footprint —
cryptographic primitives, codecs, transports, and runtime helpers
come from fluxor's published SDK (consumed via the local registry,
see [`../../standards/dependencies.md`](../../standards/dependencies.md)).
Shipping a clustor module just means packing its `.fmod` and dropping
it into the graph.

That leaves only the host-side build and test surface to account for.

## `[dev-dependencies]`

| Crate       | Why it's needed                                                                  | Feature stance |
|-------------|----------------------------------------------------------------------------------|----------------|
| `tempfile`  | Per-test scratch directories for the cluster / facade / sandbox suites under `target/test-sandboxes/`. | Default; `[dev-dependencies]` only. |
| `criterion` | Microbenches against `replica_facade.rs` (`wire_codec`, `inflight_table`, `committed_subscriber`).    | `default-features = false`, plus `plotters` + `cargo_bench_support` for `cargo bench` output. |
| `libc`      | `tests/support/cluster.rs` uses `libc::setpgid` via `Command::pre_exec` to put spawned `fluxor` children into their own process group so `kill -TERM -<pgid>` reaps the whole subtree. Without it, a crashed test orphans `fluxor-linux` onto init and the listen port stays bound for the next run. | Default; `[dev-dependencies]` only. |

Adding any of these to runtime `[dependencies]` would land them in
the `clustor` cargo package's compiled artefact (currently just the
empty `lib_stub.rs`), not in any module ELF. The substrate's runtime
footprint is unchanged.

## Fluxor consumption

Clustor consumes fluxor through the local registry; see
[`../../standards/dependencies.md`](../../standards/dependencies.md)
for the contract. The pin lives in
`fluxor.toml::[dependencies] fluxor = "X.Y"`; `fluxor update`
resolves it to specific crate, fmod, and runtime versions, recorded
in `fluxor.lock`. `fluxor sync` materialises those into
`target/fluxor/<crate>/` (source crates) and
`target/<host-target>/release/<bin>` (runtime binaries).

The ABI is derived from the resolved fluxor version; `fluxor ci`'s
version-skew phase fails if the installed CLI's ABI doesn't match
the resolved lockfile entry. `[required] fluxor = { abi = N }` is
also honoured as an optional explicit assertion for defense in
depth.

PIC modules in `modules/app/*/mod.rs` `#[path]`-mount fluxor's SDK
source from the synced location at
`target/fluxor/fluxor-abi/sdk/<file>.rs`.

## Verifying

There is no `cargo audit` step today — the empty dependency tree
makes the standard audit a no-op. If runtime dependencies ever land,
`fluxor ci` is the place to add a `cargo audit` phase.
