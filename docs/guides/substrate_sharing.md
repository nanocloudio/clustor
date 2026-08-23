# Substrate-module sharing with downstream products

`clustor/modules/app/` is the single source of truth for substrate
modules. Downstream products that build on the Raft substrate
consume them by **manifest search path**, not by file duplication.

The substrate is a palette of seven modules (`peer_router`,
`consensus`, `durability`, `gateway`, `admission`, `control_plane`,
`operations`) plus the standalone `session_directory` and
`partition_router`. A downstream graph instantiates the palette and
attaches its own modules to the ports enumerated in
[Published attach surface](#published-attach-surface) below. Those
ports are the contract; the message-shaped functions between
components *inside* a module are not, and carry no stability
promise.

## How it works

Every YAML graph that wants substrate declares a top-level
`module_search_paths:` key listing additional directories the fluxor
host tool should search when resolving manifests. A consumer graph
that sits in a sibling checkout of clustor declares:

```yaml
target: linux
tick_us: 1000

module_search_paths:
  - ../../clustor/modules/app
```

The path points at `modules/app/` (not `modules/`) because the host
tool's resolver looks for `<search-path>/<type_name>/manifest.toml`
literally; it does not descend tier subdirectories. Clustor's
substrate modules live under `modules/app/` because the substrate
is the consuming application of fluxor's foundation modules.

When the host tool encounters a module entry like
`{ name: consensus_p0, type: consensus }`, it walks (in order):

1. Each entry from `module_search_paths:`, resolved relative to the
   config file's directory.
2. The invoking project's standard module subdirs
   (`modules/drivers`, `modules/foundation`, `modules/app`,
   `modules/builtin/...`, `modules`).
3. The same standard subdirs under the install root, if different
   from the project root.

The first matching `<dir>/<type_name>/manifest.toml` wins. See
`fluxor/tools/src/config/manifest.rs::resolve_module_root` for the canonical
implementation.

## Published attach surface

These are the ports a downstream graph may wire. They are the
palette's API: shapes are stable, names are stable, and a change to
either is a change to every consuming repo. Ports not listed here
exist on the manifests to carry palette-internal plumbing (the
`consensus ⇄ durability` append/flush/refetch legs, the metric
fan-in, the `peer_router` transport legs); a deployment wires them
exactly as the graph embedded in [running.md](running.md) does,
rather than treating them as extension points.

Every name below is declared in the corresponding
`modules/app/<module>/manifest.toml`, which is authoritative if this
table and a manifest ever disagree.

### `peer_router`

| Direction | Ports |
|---|---|
| in | `net_in`, `peer_tx`, `repl_tx`, `client_resp`, `tls_identity` |
| out | `net_out`, `cleartext`, `peer_rx`, `raft_rpc`, `metrics` |

The transport anchor. A downstream graph that terminates its own
protocol attaches to `cleartext` / `client_resp`; one that adds a
second peer producer attaches to `peer_tx` or `repl_tx`.

### `consensus`

| Direction | Ports |
|---|---|
| in | `proposals`, `proposals_tagged`, `proposals_partitioned`, `proposals_partitioned_tagged`, `read`, `read_permits`, `admin_proposals`, `rpc`, `ack`, `snapshot_rx` |
| out | `proposal_assigned`, `committed_entries`, `applied`, `leader_state`, `admin_applied`, `retention_floor`, `snapshot_import`, `snapshot_request`, `rpc_out`, `metrics` |

`committed_entries` is the per-entry replicated stream every
downstream state machine consumes; `proposals_tagged` +
`proposal_assigned` are the correlated propose path
([proposal_correlation.md](proposal_correlation.md)). The
`proposals_partitioned*` pair carries the 5-byte partition
envelope for multi-Raft graphs.

Read probes and the strict-fallback signal are not separately
attachable: the read-probe exchange is interior to the module, and
the fallback signal arrives on the shared `cp_state` fan-in
alongside `MSG_CACHE_STATE`, demuxed by frame type.

### `durability`

| Direction | Ports |
|---|---|
| in | `trigger`, `install_request`, `retention_floor`, `app_snapshot_body`, `import_chunks`, `compact_before` |
| out | `flushed`, `replay_complete`, `quorum_durable`†, `compaction_signal`, `export_chunks`, `app_snapshot_ctl`, `manifest_auth`, `installed_local`, `cert_refresh`, `metrics` |

† `disk` variant only. The `volatile` variant compiles the ledger
component out and omits both `ack` and `quorum_durable`, so a
volatile composition cannot emit a durability proof and a graph
that wires one fails validation rather than degrading silently.

`app_snapshot_ctl` / `app_snapshot_body` are the state-machine
snapshot round trip: the substrate asks the consumer for a payload
on `app_snapshot_ctl` and takes the bytes back on
`app_snapshot_body`. Key epochs reach a consumer's certificate
material on `cert_refresh`; the DEK epoch itself never leaves the
module.

### `gateway`

| Direction | Ports |
|---|---|
| in | `requests`, `client_requests`, `proposals`, `credit_supply`, `placement`, `admin_responses`, `readyz_data`, `why_data`, `metrics_data` |
| out | `responses`, `proposals_tagged`, `reads`, `rejected`, `admin_req`, `raft_rpc`, `metrics` |

`requests` / `responses` are the `peer_router` side of the client
path. `proposals` is the injection point for producers that are not
on the wire (bench drivers and the `operations` module's
`/propose` and admin-PROPOSE bridges); their traffic is
admitted through the same throttle as wire-side client traffic.
An unwired `credit_supply` means unlimited, not zero.

`client_requests` is the third intake, for producers that own their
own connection namespace and have already demuxed the request:
`[conn_id:u8][body]` framed as `MSG_CLIENT_PROPOSAL` or
`MSG_CLIENT_READ_REQUEST`, entering the correlation hub directly.
`requests` (peer_router's `MSG_CLIENT_FRAME` envelope) and
`proposals` (already correlation-tagged) are the other two. Replies
to all three leave on `responses`.

### `admission`

| Direction | Ports |
|---|---|
| in | `proof`, `input`, `lag` |
| out | `cache_state`, `fresh_state`, `strict_fallback`, `permits`, `credits`, `metrics` |

`proof` and `input` are the same contract on two attach points, as
are `cache_state` and `fresh_state`. Deployments differ in which
name they wire; all four are published, so a graph written against
either name resolves.

### `control_plane`

| Direction | Ports |
|---|---|
| out | `proof`, `tenant_records`, `capabilities`, `routing`, `epoch_events`, `metrics` |

Pure sources; the module has no inputs. `tenant_records`,
`capabilities` and `epoch_events` are optional — a graph without
tenancy or session fencing leaves them unwired. `metrics` carries
only the module's per-component step-accounting samples and may
likewise stay unwired.

### `operations`

| Direction | Ports |
|---|---|
| in | `admin_req`, `admin_requests`, `identity`, `admin_applied`, `ingest`, `proposal_assigned`†, `applied`†, `proposal_rejected`†, `request`† |
| out | `responses`, `denied`, `audit_events`, `authorized`, `raft_commands`, `raft_proposal`, `readyz`, `why`, `export`, `proposal`†, `response`† |

† `diag` variant only. The `headless` variant omits the HTTP ports
entirely; readiness and metrics still publish on `readyz`, `why`
and `export`.

`admin_req` carries wire-side admin commands, evaluated against
identity bindings supplied on `identity`. `admin_requests` accepts
pre-authorized commands from a graph that runs its own admission
upstream. There is no attach point *between* admission and the
admin workflow — an authorized command is delivered inside the
module, so no configuration can route around the role check. The
*decision* is observable on both sides: `denied` carries the
refusals, and `authorized` tees the commands that passed (the same
`MSG_ADMIN_COMMAND` bytes the admin workflow received). The tee is
best-effort and never gates or delays that delivery.
`ingest` is the metric fan-in every other palette module's
`metrics` output feeds.

`request` / `response` are the HTTP seam. This module owns what a
request means, never the mechanics: wave's `http` module (`app`
variant) terminates the wire and hands each matched request over as
an `HttpRequest` envelope, and replies leave as `HttpResponse`
envelopes. Both graph edges run in mailbox mode (a distinct non-zero
`buffer_group` each), so one write is one whole envelope; replies
are correlated on the echoed `(conn_id, stream_id)` pair. See
[net_http.md](net_http.md).

## Why search paths, not hardlinks

Exposing every substrate module in each downstream tree as a
hardlink to the clustor copy does not work. Tooling that does
atomic-rename-on-write, which includes most editors, silently breaks
a hardlink on the first save, leaving the two paths pointing at
different inodes. Adding a substrate module would require remembering
to `ln -f` it into each downstream tree, with a forgotten link
surfacing as a missing port at `fluxor run` time. And ownership
becomes ambiguous once a downstream tree contains files clustor
owns: "do not modify the downstream repo" stops being checkable, and
one cross-repo change shows as modified in two `git status` outputs.

With search paths, substrate edits land only in
`clustor/modules/app/` and each downstream picks them up at the next
`fluxor run`; a downstream's `git status` shows only its own files;
the substrate/app boundary is visible at the YAML layer in
`module_search_paths:` rather than implicit in disk layout; and
adding a substrate module needs no downstream action.

## Build chain

Each repo packs only what it owns:

| Repo | `fluxor modules build --target bcm2712` packs |
|------|-------------------------------------|
| `clustor` | The seven substrate modules (with the `durability` and `operations` variant fmods), the standalone `session_directory` and `partition_router`, the two bench drivers, `example_consumer`, and the `clustor_cli` applet — full map in [architecture/modules.md](../architecture/modules.md) and the canonical edge set embedded in [running.md](running.md). |
| downstream | That project's own app modules. |

Every project publishes its `.fmod` module artefacts into the
local OCI store (`make publish` per project). A consumer project
that depends on them via
`fluxor.toml::[dependencies]` runs `fluxor modules build --all`; the
build pre-flight materialises the digest-pinned palette from
`fluxor.lock` into the consumer's own
`target/fluxor/<silicon>/modules/<name>.fmod` layout, so no separate
sync step is required. At runtime fluxor's host tool composes the
graph using the manifests it discovers via search paths and resolves
each module's `.fmod` against that output directory.

To build a fresh downstream graph from scratch:

```sh
cd clustor && fluxor modules build --target bcm2712
cd ../<downstream> && fluxor modules build --target bcm2712
fluxor run <graph>.yaml
```

The two module builds are independent. Either order
works; both have to run at least once on a clean tree.

## What lives where

- `clustor/modules/app/<name>/` — substrate source. **Edit here.**
- `clustor/modules/common/{wire,types,collections,replica_facade,http_admin,log_fmt,session_registry,step_accounting,timing,wal_frame}.rs`
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
- `<downstream>/modules/app/<name>/` — that product's own source.
- `<downstream>/modules/common/` — that product's own wire and type
  helpers, distinct from clustor's `common/wire.rs`.
- `<consuming-project>/target/fluxor/<silicon>/modules/<name>.fmod` —
  packed artefacts read at runtime. The build pre-flight lands the
  store-resolved fmods here from `fluxor.lock`; `fluxor modules
  build` lands the ones the consumer owns.

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
