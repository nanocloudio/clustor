# Consuming fluxor

How clustor depends on, pulls in, and uses fluxor. This is the
"working with fluxor day-to-day" guide for clustor contributors.

For the upstream side ("I'm working on fluxor and need to push
changes to clustor"), see fluxor's
[`docs/guides/publishing.md`](../../fluxor/docs/guides/publishing.md).

Design rationale: fluxor's
[`.context/rfc_project_dependencies.md`](../../fluxor/.context/rfc_project_dependencies.md).
Prescriptive contract:
[`../../standards/dependencies.md`](../../standards/dependencies.md).

## TL;DR

```sh
fluxor sync && fluxor modules build --all
```

In clustor's checkout. `sync` resolves `fluxor.lock` against the
local OCI store and materialises fluxor's published source trees,
fmods, and `fluxor-linux` into clustor's `target/` tree (writing
resolved digests through the lockfile for workspace members). `make
modules` builds clustor's PIC modules against the synced fluxor SDK.
`fluxor update` is the deliberate verb for advancing pinned
(non-workspace) entries to the latest published digests.

## What clustor consumes from fluxor

| What | Where it lands after sync | Used by |
|---|---|---|
| `fluxor-abi` source | `target/fluxor/fluxor-abi/sdk/{abi,wire,...}.rs` | `modules/app/*/mod.rs` via `#[path]` |
| `fluxor-sdk` source | `target/fluxor/fluxor-sdk/sdk/...` | same file set as `fluxor-abi/sdk/` at the resolved fluxor version; will diverge as `fluxor-sdk` grows the macro surface |
| Fluxor's published fmod palette | `target/<silicon>/modules/<name>.fmod` (every fmod fluxor publishes — foundation, drivers, builtin, probes) | Deployment yamls wire subsets by name; unused fmods sit on disk unmounted |
| `fluxor-linux` runtime | `target/aarch64-unknown-linux-gnu/release/fluxor-linux` | `tests/support/cluster.rs` spawns it |
| `module.ld` linker script | `target/fluxor/fluxor-abi/sdk/module.ld` | `fluxor modules build` picks it up automatically |

Every consumed artefact flows through the local OCI store —
`$FLUXOR_STORE`, else `$XDG_DATA_HOME/fluxor/store`, else
`~/.local/share/fluxor/store` — pinned by digest in `fluxor.lock`.

## First-time setup (per developer machine)

You need both fluxor and clustor checked out, and a published fluxor
in the local store.

```sh
# 1. Clone fluxor as a sibling of clustor (any layout works; sibling is
#    convention)
cd ~/Development/nanocloudio
git clone git@github.com:nanocloudio/fluxor.git

# 2. Bootstrap the fluxor CLI (first build on an empty-store machine;
#    thereafter the installed launcher resolves the CLI from the store)
cd fluxor
make install

# 3. First publish (see "Two modes" below for workspace setup)
make publish                         # publishes SDK source + fmods + runtime into the store
```

Then in clustor:

```sh
cd ../clustor
fluxor sync                          # resolves fluxor.lock, materialises everything into target/
```

After that, the normal clustor workflow works:

```sh
fluxor modules build --all           # builds clustor's PIC modules
make test                            # cluster harness, facade tests, etc.
make ci                              # full gate
```

## Two modes — when to use which

### Mode A — pinned (default, no workspace membership)

`fluxor.lock` records a `[[artifact]]` digest pin for every fluxor
artefact clustor consumes. Sync materialises exactly what the
lockfile says; tag movement upstream is invisible until you ask
for it. Reproducible across machines.

**Workflow:**

```sh
# upstream maintainer publishes
cd ../fluxor
make publish

# downstream picks it up
cd ../clustor
fluxor update                        # advances fluxor.lock to the latest published digests
fluxor sync                          # materialises the new artefacts into target/
git add fluxor.lock                  # commit the new pins
```

This is the right mode for CI, release branches, and any tree state
you want reproducible.

### Mode B — live workspace iteration

When iterating fluxor + clustor simultaneously. Live mode is a
resolution policy, not a file format: workspace membership is the
only thing that distinguishes it. Set up once:

```sh
# ~/.fluxor/workspace.toml — user-local, NOT committed
[workspace]
members = [
  "/home/pi/Development/nanocloudio/fluxor",
  "/home/pi/Development/nanocloudio/clustor",
]
```

`fluxor workspace status` from inside either checkout confirms live
mode is active.

**In live mode:**

- `fluxor sync` resolves each workspace member's artefacts to
  `:latest` — the most recently published digest — and **writes the
  resolved digest through `fluxor.lock`**. The lockfile is never
  bypassed; what changed is visible as an ordinary `git diff
  fluxor.lock`, reviewed with normal commit discipline.
- Publish is always explicit. Sync never builds or publishes on
  fluxor's behalf: edits in a member checkout reach clustor only
  after `fluxor publish` in that member (`fluxor workspace publish`
  batches every stale member in dependency order).
- Sync warns per artefact whose inputs changed since its last
  publish — e.g. `warning: module 'tls' inputs changed since
  publish (fluxor)` — and proceeds. `fluxor workspace status`
  shows the same data. `fluxor ci` is the one place that staleness
  is a hard failure.
- Everything materialised stays digest-verified, live or pinned.

This is the right mode for active development. Because sync writes
the lockfile through, the branch you push already carries real
digest pins — review the `fluxor.lock` diff like any other change.

Switch between modes by toggling `~/.fluxor/workspace.toml`: removing
the file (or removing fluxor from `members`) reverts to pinned
resolution.

## Daily-iteration checklist

While iterating between fluxor and clustor in Mode B:

```sh
# edited fluxor
cd ../fluxor
[edit anything]
fluxor publish            # publish the changed artefacts; repoints :latest
                          # (or `fluxor workspace publish` to batch every
                          # stale member in dependency order)

# pick up in clustor
cd ../clustor
fluxor sync               # members resolve :latest; digests written through fluxor.lock
fluxor modules build --all   # rebuild clustor modules against the synced fluxor SDK
make test                 # cluster harness picks up the synced fluxor-linux
```

Publish only what changed — `fluxor publish`'s work is scoped by
input digests, and `workspace publish`'s work-list IS the
input-digest comparison. Sync's per-artifact advisory names every
member artefact whose inputs changed since its last publish, so
it's clear at a glance when a publish is owed.

## Updating the fluxor pin (Mode A)

```sh
# upstream publishes
cd ../fluxor
make publish                         # repoints :latest to the new digests

# downstream adopts
cd ../clustor
fluxor update                        # fluxor.lock pins advance to the new digests
fluxor sync                          # source trees re-materialised, fmods re-copied
git diff fluxor.lock                 # review the new pins
git add fluxor.lock
git commit -m "Advance fluxor pins"
```

`fluxor.toml::[dependencies] fluxor = "..."` in clustor doesn't
need to change — the version string is a readability label;
resolution is by lockfile digest and `:latest`, never by version
ordering.

## Things to know

### The lockfile is committed.

`fluxor.lock` records the `sha256:` digest of every resolved
artefact. Committing it means anyone with the same store state can
reproduce your build; rollback and history are git's (`git log
fluxor.lock`, revert + `fluxor sync`). CI verifies consistency via
`fluxor ci`'s lockfile phase.

### `make ci` validates the lockfile.

Lockfile-vs-tree inconsistency is a hard `fluxor ci` failure, as is
a live workspace member whose inputs changed since its last publish
— a green gate against a known-stale upstream would be a clean
build wearing a misleading name.

### PIC module paths are stable across fluxor versions.

`modules/app/*/mod.rs` reference `../../../target/fluxor/fluxor-abi/sdk/<file>.rs`.
The directory name is `fluxor-abi/` (no version suffix) — sync
overwrites the directory contents on every version bump. Module
sources don't need editing across fluxor updates.

### The `clustor-common` crate.

`crates/clustor-common/` exposes clustor's pure no_std helpers
(`wire.rs`, `replica_facade.rs`, `types.rs`, `collections.rs`,
`http_admin.rs`) as a cargo crate. Each file is path-mounted as
`pub mod` with `#[rustfmt::skip]` so the hand-aligned const tables
in the source files render unchanged.

The crate is fully self-contained: zero runtime dependencies, no
`unsafe`, no syscalls. The packaged surface is governed by an
explicit `[package].include` allowlist in
`crates/clustor-common/Cargo.toml`; PIC-only files like
`modules/common/wire_channels.rs` (channel I/O over fluxor's
`SyscallTable`) sit alongside the pure files for `#[path]`
inclusion from clustor's app modules but are not shipped to host
consumers. This matches RFC §6.5.1's pure-no_std-fragments shape
for downstream `common/` crates.

`clustor-common`'s version inherits from `[workspace.package].version`
in clustor's root `Cargo.toml`. Bumping the workspace version
cascades to every publishable crate; the publish CLI enforces that
the resolved version matches `fluxor.toml::[project].version`.

Downstream projects of clustor (loam, lattice, future siblings)
consume `clustor-common` through the same store mechanism that
clustor uses for fluxor.

### Workspace mode is per-developer.

`~/.fluxor/workspace.toml` is user-local and gitignored. Each
developer maintains their own. CI runners shouldn't have one — they
resolve fully pinned against the store.

## Things that can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `fluxor sync` says a dependency has no published artefacts | fluxor hasn't been published yet | Run `make publish` in fluxor's checkout |
| `fluxor sync` says a pinned digest is `no longer in store — run 'fluxor update'` | The pinned blob was garbage-collected (this checkout isn't a workspace member, so its pins aren't GC roots) | `fluxor update && fluxor sync` |
| `fluxor sync` reports a digest mismatch | Store blob out of sync with lockfile | Re-run `make publish` upstream, then `fluxor update && fluxor sync` here |
| `fluxor modules build` says "no manifest found for module 'ip'" | Search paths don't include fluxor's modules | Set `$FLUXOR_PROJECT_ROOT` to fluxor's checkout, OR ensure `target/fluxor/fluxor-abi/sdk/` is populated via `fluxor sync` |
| `cargo check` says "rustc 1.92.0 not supported by fixed@1.31" | Transitive dep of fluxor-sdk wants newer rustc | `cargo update fixed --precise 1.29.0` (or whatever's compatible) |
| Tests fail to find `fluxor-linux` | Either upstream didn't publish runtime, or sync didn't run | `cd ../fluxor && make publish` then back to clustor `fluxor sync` |
| Tests skip with "fluxor checkout not found" | `config_validate` needs fluxor's `targets/` directory | Set `$FLUXOR_CHECKOUT` env var, or place fluxor at `../fluxor` |

## Related reading

- [`../../fluxor/docs/guides/publishing.md`](../../fluxor/docs/guides/publishing.md) — the upstream-maintainer side
- [`../../standards/dependencies.md`](../../standards/dependencies.md) — prescriptive contract
- [`./dependencies.md`](./dependencies.md) — clustor's own dep inventory + fluxor consumption notes
- [`./substrate_sharing.md`](./substrate_sharing.md) — how clustor and sibling projects share fluxor as substrate
