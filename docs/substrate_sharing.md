# Substrate-module sharing between clustor and quantum

`clustor/modules/app/` is the single source of truth for substrate
modules. Quantum (and any other downstream that builds on the Raft
substrate) consumes them by **manifest search path**, not by file
duplication.

## How it works

Every YAML graph that wants substrate declares a top-level
`module_search_paths:` key listing additional directories the fluxor
host tool should search when resolving manifests. Quantum's configs do:

```yaml
target: linux
tick_us: 1000

module_search_paths:
  - ../../clustor/modules/app
```

The path points at `modules/app/` (not `modules/`) because the host
tool's resolver looks for `<search-path>/<type_name>/manifest.toml`
literally — it does not descend tier subdirectories. Clustor's
substrate modules live under `modules/app/` because the substrate
is the consuming application of fluxor's foundation modules.

When the host tool encounters a module entry like
`{ name: raft_engine_p0, type: raft_engine }`, it walks (in order):

1. Each entry from `module_search_paths:`, resolved relative to the
   config file's directory.
2. The invoking project's standard module subdirs
   (`modules/drivers`, `modules/foundation`, `modules/app`,
   `modules/builtin/...`, `modules`).
3. The same standard subdirs under the install root, if different
   from the project root.

The first matching `<dir>/<type_name>/manifest.toml` wins. See
`fluxor/tools/src/config.rs::resolve_module_root` for the canonical
implementation.

## Why search paths, not hardlinks

A hardlink-based alternative — every substrate module exposed at
both `clustor/modules/app/<name>/` and `quantum/modules/app/<name>/`
with shared inodes — was considered and rejected. The failure modes
ruled it out:

- Tooling that does atomic-rename-on-write (most editors, including
  the agent's `Edit` tool) silently breaks the link, leaving the two
  paths pointing at different inodes after the first save.
- Adding a substrate module would require remembering to `ln -f`
  it into the downstream tree — easy to forget, with the failure
  surfacing as a missing port at `fluxor run` time.
- "Do not modify quantum" guidance becomes ambiguous because
  quantum's tree contains files clustor owns.
- Cross-repo changes show as modified in two `git status` outputs
  with no automatic linkage.

The search-path approach provides everything the hardlink shape
would have, with none of those fragilities:

- Single source of truth: substrate edits land in
  `clustor/modules/app/` and quantum picks them up at the next
  `fluxor run`.
- Quantum's `git status` only shows quantum-specific files.
- The substrate / app boundary is visible at the YAML layer
  (`module_search_paths:`), not implicit in disk layout.
- Adding a substrate module needs zero downstream action.

## Build chain

Each repo packs only what it owns:

| Repo | `make modules TARGET=bcm2712` packs |
|------|-------------------------------------|
| `clustor` | The 23 substrate modules plus `example_consumer` — full map in [architecture/modules.md](architecture/modules.md) and the canonical edge set in [`../configs/single.yaml`](../configs/single.yaml). |
| `quantum` | The quantum-specific app modules (codecs, session processing, topic/dedup engines, retained store, audit, DR, metrics, consumer groups, transactions, tenancy). |

Both clustor and quantum publish `.fmod` files into the local
fluxor registry (`make publish` per project; see
[`../../standards/dependencies.md`](../../standards/dependencies.md)
for the contract). A consumer project that depends on both via
`fluxor.toml::[dependencies]` runs `fluxor sync` to materialise the
resolved palette into its own `target/<silicon>/modules/<name>.fmod`
layout. At runtime fluxor's host tool composes the graph using the
manifests it discovers via search paths and resolves each module's
`.fmod` against that synced output directory.

To build a fresh quantum graph from scratch:

```sh
cd clustor && make modules TARGET=bcm2712
cd quantum && make modules TARGET=bcm2712
fluxor run quantum/configs/quantum-linux-minimal.yaml
```

The two `make modules` invocations are independent. Either order
works; both have to run at least once on a clean tree.

## What lives where

- `clustor/modules/app/<name>/` — substrate source. **Edit here.**
- `clustor/modules/common/{wire,types,collections,replica_facade,http_admin}.rs`
  — pure no_std helpers shared across substrate modules. Each
  substrate module references them via
  `#[path = "../../common/wire.rs"]` from `modules/app/<name>/mod.rs`.
- `clustor/modules/common/wire_channels.rs` — PIC-only channel I/O
  wrappers over `SyscallTable`. Same-project app modules
  `#[path]`-include it; the `clustor-common` cargo crate does not
  export it, so downstream host consumers never see it.
- `clustor/crates/clustor-common/` — the published cargo crate
  façade over the pure files above. Downstream Rust code that wants
  to compile against clustor's helpers depends on `clustor-common`
  rather than reaching into `modules/common/`.
- `quantum/modules/app/<name>/` — quantum-specific source.
- `quantum/modules/common/{wire,types}.rs` — quantum-specific wire
  format helpers (e.g. `MSG_TOPIC_PUBLISH`, MQTT dedup keys).
  Distinct from clustor's `common/wire.rs`.
- `<consuming-project>/target/<silicon>/modules/<name>.fmod` —
  packed artifacts read at runtime. `fluxor sync` lands the
  registry-resolved fmods here; `make modules` lands the ones the
  consumer owns.

## PIC module pitfalls

- **No `core::panicking` symbols.** PIC modules link with
  `--no-undefined` against an arena-only runtime; `rustc` will happily
  emit panic landing pads for runtime arithmetic checks
  (`rem_by_zero`, `div_by_zero`, `index_out_of_bounds`,
  `arithmetic_overflow`) and the linker will then refuse the module
  with `undefined symbol: core::panicking::panic_const_*`. Fix at the
  call site, not the linker:
  - For `x % n` / `x / n`: write `x % n.max(1)` (or `x / n.max(1)`)
    when `n` is a runtime value, even if `module_new` clamps it.
    The optimizer can't see across module boundaries to prove `n != 0`.
  - For slice indexing: prefer `slice.get(i)` / `slice.get_mut(i)` when
    the index is dynamic.
  - Example: `partition_router`'s `(h % num_partitions)` pulls in
    `panic_const_rem_by_zero` unless written as
    `(h % num_partitions.max(1))`.
