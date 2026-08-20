# Consuming fluxor

How clustor depends on, pulls in, and uses fluxor. This is the
"working with fluxor day-to-day" guide for clustor contributors.

For the upstream side ("I'm working on fluxor and need to push
changes to clustor"), see fluxor's
[`docs/guides/publishing.md`](../../../fluxor/docs/guides/publishing.md).

## TL;DR

```sh
fluxor modules build --all
```

In clustor's checkout. The build's pre-flight replays `fluxor.lock`
against the local OCI store and materialises fluxor's published
source trees, fmods, and `fluxor-linux` into clustor's `target/`
tree, then builds clustor's PIC modules against that SDK. Pins are
advanced separately: `fluxor update` is the deliberate verb for
advancing pinned (non-workspace) entries to the latest published
digests, and `fluxor sync` re-resolves workspace members to
`:latest` (writing the resolved digests through the lockfile) and
re-materialises the tree without building. Neither is a routine
step in pinned mode; builds materialise on their own.

## What clustor consumes from fluxor

| What | Where it lands after materialisation | Used by |
|---|---|---|
| `fluxor-abi` source | `target/fluxor/fluxor-abi/sdk/{abi,wire,...}.rs` | `modules/app/*/mod.rs` via `#[path]` |
| `fluxor-contracts` source | `target/fluxor/fluxor-contracts/src/` | Materialised because the lock pins it; no clustor source mounts it today |
| `wave-common` source | `target/fluxor/wave-common/` (protocol cores: `ws_core.rs`, `rtp_core.rs`, ...) | Materialised via the `wave` pin; no clustor source mounts it today |
| Fluxor's published fmod palette | `target/fluxor/<silicon>/modules/<name>.fmod` (every fmod fluxor publishes — foundation, drivers, builtin, probes) | Deployment yamls wire subsets by name; unused fmods sit on disk unmounted |
| `fluxor-linux` runtime | `target/aarch64-unknown-linux-gnu/release/fluxor-linux` | `fluxor run` execs it per node |
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
fluxor modules build --all           # pre-flight materialises fluxor.lock into target/, then builds clustor's PIC modules
fluxor run --replicas 1 - <<'EOF' ...         # bring up a node (config embedded in running.md)
```

## Two modes — when to use which

### Mode A — pinned (default, no workspace membership)

`fluxor.lock` records a `[[artifact]]` digest pin for every fluxor
artefact clustor consumes. Materialisation delivers exactly what the
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
fluxor modules build --all           # pre-flight materialises the new artefacts into target/
git add fluxor.lock                  # commit the new pins
```

This is the right mode for release branches and any tree state you
want reproducible.

### Mode B — live workspace iteration

When iterating fluxor + clustor simultaneously. Workspace membership
is the only thing that distinguishes live mode. Set up once:

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
  fluxor.lock`, reviewed with normal commit discipline. (The build
  pre-flight replays the lockfile verbatim; sync is the verb that
  advances member pins.)
- Publish is always explicit. Sync never builds or publishes on
  fluxor's behalf: edits in a member checkout reach clustor only
  after `fluxor publish` in that member (`fluxor workspace publish`
  batches every stale member in dependency order).
- Sync warns per artefact whose inputs changed since its last
  publish — e.g. `warning: module 'tls' inputs changed since
  publish (fluxor)` — and proceeds. `fluxor workspace status`
  shows the same data.
- Everything materialised stays digest-verified, live or pinned.

This is the right mode for active development.

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
fluxor sync               # members re-resolve :latest; digests written through fluxor.lock
fluxor modules build --all   # rebuild clustor modules against the new fluxor SDK
```

Publish only what changed — `fluxor publish`'s work is scoped by
input digests, and `workspace publish`'s work-list is the
input-digest comparison. The per-artefact advisory names every
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
fluxor sync                          # optional: re-materialise now; the next build does this anyway
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
fluxor.lock`, revert and rebuild). A tree that does not match the
lockfile should be reverted and rebuilt, not patched around.

### PIC module paths are stable across fluxor versions.

`modules/app/*/mod.rs` reference `../../../target/fluxor/fluxor-abi/sdk/<file>.rs`.
The directory name is `fluxor-abi/` (no version suffix) —
materialisation overwrites the directory contents on every version
bump. Module sources don't need editing across fluxor updates.

### The `clustor-common` crate.

`crates/clustor-common/` exposes clustor's pure no_std helpers
(`wire.rs`, `replica_facade.rs`, `types.rs`, `collections.rs`,
`http_admin.rs`, `session_registry.rs`, `timing.rs`, `wal_frame.rs`)
as a cargo crate. Each file is path-mounted as
`pub mod` with `#[rustfmt::skip]` so the hand-aligned const tables
in the source files render unchanged.

The crate is fully self-contained: zero runtime dependencies, no
`unsafe`, no syscalls. The packaged surface is governed by an
explicit `[package].include` allowlist in
`crates/clustor-common/Cargo.toml`; PIC-only files like
`modules/common/wire_channels.rs` (channel I/O over fluxor's
`SyscallTable`) sit alongside the pure files for `#[path]`
inclusion from clustor's app modules but are not shipped to host
consumers.

`clustor-common`'s version inherits from `[workspace.package].version`
in clustor's root `Cargo.toml`. Bumping the workspace version
cascades to every publishable crate; the publish CLI enforces that
the resolved version matches `fluxor.toml::[project].version`.

Downstream projects of clustor (loam, lattice, future siblings)
consume `clustor-common` through the same store mechanism that
clustor uses for fluxor.

### Workspace mode is per-developer.

`~/.fluxor/workspace.toml` is user-local and gitignored. Each
developer maintains their own; a machine that needs reproducible
builds shouldn't have one — it resolves fully pinned against the
store.

## Things that can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| Materialisation says a dependency has no published artefacts | fluxor hasn't been published yet | Run `make publish` in fluxor's checkout |
| Materialisation says a pinned digest is `no longer in store — run 'fluxor update'` | The pinned blob was garbage-collected (this checkout isn't a workspace member, so its pins aren't GC roots) | `fluxor update`, then rebuild |
| Materialisation reports a digest mismatch | Store blob out of sync with lockfile | Re-run `make publish` upstream, then `fluxor update` and rebuild here |
| `fluxor modules build` says "no manifest found for module 'ip'" | Search paths don't include fluxor's modules | Set `$FLUXOR_PROJECT_ROOT` to fluxor's checkout, OR ensure `target/fluxor/fluxor-abi/sdk/` is populated via `fluxor sync` |
| `cargo check` says "rustc 1.92.0 not supported by fixed@1.31" | Transitive dep of fluxor's SDK sources wants newer rustc | `cargo update fixed --precise 1.29.0` (or whatever's compatible) |
| `fluxor run` fails to find `fluxor-linux` | Either upstream didn't publish the runtime, or nothing has materialised it yet | `cd ../fluxor && make publish`, then rebuild in clustor |

## Related reading

- [`../../fluxor/docs/guides/publishing.md`](../../../fluxor/docs/guides/publishing.md) — the upstream-maintainer side
- [`./dependencies.md`](./dependencies.md) — clustor's own dep inventory + fluxor consumption notes
- [`./substrate_sharing.md`](./substrate_sharing.md) — how clustor and sibling projects share fluxor as substrate
