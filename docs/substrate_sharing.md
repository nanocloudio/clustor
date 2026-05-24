# Substrate-module sharing between clustor and quantum

`clustor/modules/` is the single source of truth for substrate
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
  - ../../clustor/modules
```

When the host tool encounters a module entry like
`{ name: raft_engine_p0, type: raft_engine }`, it walks (in order):

1. Standard fluxor dirs (`modules/drivers`, `modules/foundation`,
   `modules/builtin/...`, `modules`) under the fluxor working tree.
2. Each entry from `module_search_paths:`, resolved relative to the
   config file's directory.
3. The implicit `<config-parent>/../modules` default (so legacy
   configs without `module_search_paths:` keep working).

The first matching `manifest.toml` wins. See
`fluxor/tools/src/config.rs::extract_module_search_paths` for the
canonical implementation.

## Why this shape (and what it replaces)

The previous model used filesystem hardlinks: every substrate module
existed at both `clustor/modules/<name>/` and
`quantum/modules/<name>/` with the same inode. Editing either path
edited both.

That worked for one minute and then started costing time:

- Tooling that does atomic-rename-on-write (most editors, including
  the agent's `Edit` tool) silently broke the link, leaving quantum
  pointing at the old inode and clustor at the new one.
- Adding a new substrate module meant remembering to manually
  `ln -f` it into quantum/modules/ — easy to forget, and the failure
  mode was `fluxor run` 30 seconds later asking why a port name
  didn't exist.
- "Do not modify quantum" instructions to agents and reviewers were
  ambiguous because quantum/modules/ contained files clustor owned.
- Cross-repo changes appeared modified in two `git status` outputs
  with no automatic linkage.

The search-path model gives every property the hardlink convention
was trying to provide and none of the fragility:

- Single source of truth: substrate edits land in `clustor/modules/`
  and quantum picks them up at the next `fluxor run`.
- Quantum's `git status` only ever shows quantum-specific files.
- The substrate / app boundary is visible at the YAML layer
  (`module_search_paths:`), not implicit in disk layout.
- Adding a new substrate module needs zero quantum-side action.

## Build chain

Each repo packs only what it owns:

| Repo | `make modules TARGET=bcm2712` packs |
|------|-------------------------------------|
| `clustor` | substrate (24 modules: raft_engine, wal, peer_router, partition_router, replicator, durability_ledger, commit_tracker, apply_pipeline, cp_bridge, cp_proof_cache, throttle_gate, flow_controller, client_surface, telemetry_agg, client_codec, admin_handler, snapshot_engine, key_manager, read_gate, placement_router, rbac, http_ingress, http_adapter, example_consumer) |
| `quantum` | quantum-specific (20 modules: ack_tracker, mqtt_codec, kafka_codec, amqp_codec, session_processor, protocol_router, response_mux, topic_engine, dedup_engine, offline_queue, retained_store, backpressure_propagator, forward_coordinator, prefetch_controller, audit_logger, dr_manager, metrics_aggregator, consumer_group_coordinator, transaction_coordinator, tenant_manager) |

Both write `.fmod` files into the shared output directory at
`fluxor/target/bcm2712/modules/` (clustor reaches it via
`deps/fluxor → ../../fluxor`, quantum the same way). At runtime
fluxor's host tool composes the graph using the manifests it discovers
via search paths, and resolves each module's `.fmod` against the
shared output directory.

To build a fresh quantum graph from scratch:

```sh
cd clustor && make modules TARGET=bcm2712
cd quantum && make modules TARGET=bcm2712
fluxor run quantum/configs/quantum-linux-minimal.yaml
```

The two `make modules` invocations are independent. Either order
works; both have to run at least once on a clean tree.

## What lives where

- `clustor/modules/<name>/` — substrate source. **Edit here.**
- `clustor/modules/sdk/{wire,types,collections}.rs` — substrate
  wire format helpers. Substrate modules reference this via
  `#[path = "../sdk/wire.rs"]` and the relative path is correct
  because substrate modules live in `clustor/modules/`.
- `quantum/modules/<name>/` — quantum-specific source.
- `quantum/modules/sdk/{wire,types}.rs` — quantum-specific wire
  format helpers (e.g. `MSG_TOPIC_PUBLISH`, MQTT dedup keys). Different
  file from clustor's `common/wire.rs`.
- `fluxor/target/bcm2712/modules/<name>.fmod` — packed artifacts
  from both repos, read at runtime.

## PIC module pitfalls hit while doing this

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
  - Encountered first on `partition_router` — `(h % num_partitions)`
    pulled in `panic_const_rem_by_zero` until rewritten as
    `(h % num_partitions.max(1))`.
