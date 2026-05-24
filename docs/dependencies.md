# Dependency Inventory

Clustor's `[dependencies]` table is empty. Every cryptographic
primitive, codec, transport, and runtime piece the substrate needs is
part of the fluxor SDK or implemented in `modules/sdk/`. The
substrate has no `cargo install`-able dependency footprint at runtime;
shipping a module just means packing its `.fmod` and dropping it into
the graph.

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

## Submodule: `deps/fluxor`

Clustor pins the `fluxor` source tree as a submodule (in practice a
local symlink during development; a real git submodule in CI). The
pinned ABI lives in `fluxor.toml::[required].fluxor.abi`; `fluxor ci`'s
version-skew phase fails if the installed CLI's ABI doesn't match.

## Verifying

There is no `cargo audit` step today — the empty dependency tree
makes the standard audit a no-op. If runtime dependencies ever land,
`fluxor ci` is the place to add a `cargo audit` phase.
