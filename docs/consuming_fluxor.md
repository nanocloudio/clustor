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
make update && make sync && make modules
```

In clustor's checkout. `update` re-resolves `fluxor.lock` against
the local registry. `sync` materialises fluxor's published crates,
fmods, and `fluxor-linux` into clustor's `target/` tree. `make
modules` builds clustor's PIC modules against the synced fluxor SDK.

## What clustor consumes from fluxor

| What | Where it lands after sync | Used by |
|---|---|---|
| `fluxor-abi` source | `target/fluxor/fluxor-abi/sdk/{abi,wire,...}.rs` | `modules/app/*/mod.rs` via `#[path]` |
| `fluxor-sdk` source | `target/fluxor/fluxor-sdk/sdk/...` | same file set as `fluxor-abi/sdk/` at the resolved fluxor version; will diverge as `fluxor-sdk` grows the macro surface |
| Fluxor's published fmod palette | `target/<silicon>/modules/<name>.fmod` (every fmod fluxor publishes — foundation, drivers, builtin, probes) | Deployment yamls wire subsets by name; unused fmods sit on disk unmounted |
| `fluxor-linux` runtime | `target/aarch64-unknown-linux-gnu/release/fluxor-linux` | `tests/support/cluster.rs` spawns it |
| `module.ld` linker script | `target/fluxor/fluxor-abi/sdk/module.ld` | `fluxor modules build` picks it up automatically |

Every consumed artefact flows through the local registry at
`~/.fluxor/registry/`.

## First-time setup (per developer machine)

You need both fluxor and clustor checked out, and a published fluxor
in the local registry.

```sh
# 1. Clone fluxor as a sibling of clustor (any layout works; sibling is
#    convention)
cd ~/Development/nanocloudio
git clone git@github.com:nanocloudio/fluxor.git

# 2. Install the fluxor CLI and bootstrap the registry
cd fluxor
make setup                          # cargo install --locked --path tools
fluxor registry init                # bootstrap ~/.fluxor/registry/
fluxor registry setup-cargo         # adds [registries.fluxor] to ~/.cargo/config.toml

# 3. First canonical publish (or workspace setup — see "Two modes" below)
make publish                         # publishes abi + sdk + fmods + runtime
```

Then in clustor:

```sh
cd ../clustor
make update                          # resolves fluxor.lock against the registry
make sync                            # materialises everything into target/
```

After that, the normal clustor workflow works:

```sh
make modules                         # builds clustor's PIC modules
make test                            # cluster harness, facade tests, etc.
make ci                              # full gate
```

## Two modes — when to use which

### Mode A — canonical, registry-pinned (default)

`fluxor.lock` records exact `(name, version, sha256)` for every
fluxor artefact clustor consumes. Reproducible across machines.

**Workflow:**

```sh
# upstream maintainer publishes
cd ../fluxor
[bump fluxor.toml's [project].version]
make publish

# downstream picks it up
cd ../clustor
make update                          # rewrites fluxor.lock with new version
make sync                            # copies new artefacts into target/
git add fluxor.lock                  # commit the new pin
```

This is the right mode for CI, release branches, and any tree state
you want reproducible.

### Mode B — live workspace iteration

When iterating fluxor + clustor simultaneously and you don't want
to bump versions on every change. Set up once:

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

- `make sync` prefers fluxor's locally-built `target/` artefacts as
  an override; anything not built locally resolves from the registry
  copy recorded in `fluxor.lock` (hash-verified). Iteration is
  opt-in per artefact — build only what you change, take the rest
  from the registry. A summary advisory at the end of sync names
  every workspace member that fell back, so it's clear at a glance
  whether local edits are flowing through.
- Source crates resolve via the registry-extracted location and
  refresh whenever you re-run `make sync` after a fluxor publish.
- `fluxor.lock` hashes are bypassed only for artefacts that
  resolved live; fallbacks stay hash-verified.
- `[dependencies] fluxor = "..."` in `fluxor.toml` is advisory
  inside the workspace — version pinning takes effect only when
  the CLI is invoked from outside any workspace member.

This is the right mode for active development. **Hand off to Mode A
before pushing branches** — leaving live-mode artefacts in
`fluxor.lock` would make CI non-reproducible.

Switch between modes by toggling `~/.fluxor/workspace.toml`: removing
the file (or removing fluxor from `members`) reverts to canonical
mode.

## Daily-iteration checklist

While iterating between fluxor and clustor in Mode B:

```sh
# edited fluxor
cd ../fluxor
[edit anything]
make modules-all          # rebuild the .fmod artefacts you changed
                          # (skip if no module source changed)
make linux-bin            # rebuild fluxor-linux if you changed it
                          # (skip otherwise)

# pick up in clustor
cd ../clustor
make sync                 # live builds override; everything else from the registry
make modules              # rebuild clustor modules against the synced fluxor SDK
make test                 # cluster harness picks up the synced fluxor-linux
```

Rebuild only what you changed. `make sync` takes whatever fluxor's
`target/` holds as the override and resolves everything else from
the lockfile's registry copy. Sync's tail advisory names every
workspace member that fell back to the registry, so it's clear at a
glance which paths are live.

## Updating the fluxor pin (Mode A)

```sh
# upstream cuts a release
cd ../fluxor
[bump fluxor.toml's [project].version, e.g. 0.1.0 → 0.1.1]
make publish                         # publishes everything at the new version

# downstream adopts
cd ../clustor
make update                          # fluxor.lock now has version = "0.1.1"
make sync                            # crates re-extracted, fmods re-copied
git diff fluxor.lock                 # review the new pin
git add fluxor.lock
git commit -m "Bump fluxor to 0.1.1"
```

`fluxor.toml::[dependencies] fluxor = "0.1"` in clustor doesn't
need to change — the caret semver range continues to match every
`0.1.x`. Only edit it when fluxor cuts a new major (e.g. ABI bump
to `0.2`).

## Things to know

### The lockfile is committed.

`fluxor.lock` records SHA-256 hashes of every resolved artefact.
Committing it means anyone with the same registry state can
reproduce your build. CI verifies consistency via `fluxor ci`'s
`lockfile-consistency` phase.

### `make ci` validates the lockfile.

The `lockfile-consistency` phase rejects drift — if your local
registry has a different fluxor version than what `fluxor.lock`
pins, CI fails with a precise diff. Run `make update` to bring the
lockfile up to date.

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
consume `clustor-common` through the same registry mechanism that
clustor uses for fluxor.

### Workspace mode is per-developer.

`~/.fluxor/workspace.toml` is user-local and gitignored. Each
developer maintains their own. CI runners shouldn't have one — they
operate in canonical mode against the registry.

## Things that can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `make update` says "no matching canonical artefacts" | fluxor hasn't been published yet | Run `make publish` in fluxor's checkout |
| `make sync` reports `hash mismatch` | Registry tampered or out of sync with lockfile | Re-run `make publish` upstream, then `make update && make sync` here |
| `fluxor modules build` says "no manifest found for module 'ip'" | Search paths don't include fluxor's modules | Set `$FLUXOR_PROJECT_ROOT` to fluxor's checkout, OR ensure `target/fluxor/fluxor-abi/sdk/` is populated via `make sync` |
| `cargo check` says "rustc 1.92.0 not supported by fixed@1.31" | Transitive dep of fluxor-sdk wants newer rustc | `cargo update fixed --precise 1.29.0` (or whatever's compatible) |
| Tests fail to find `fluxor-linux` | Either upstream didn't publish runtime, or sync didn't run | `cd ../fluxor && make publish` then back to clustor `make sync` |
| Tests skip with "fluxor checkout not found" | `config_validate` needs fluxor's `targets/` directory | Set `$FLUXOR_CHECKOUT` env var, or place fluxor at `../fluxor` |

## Related reading

- [`../../fluxor/docs/guides/publishing.md`](../../fluxor/docs/guides/publishing.md) — the upstream-maintainer side
- [`../../standards/dependencies.md`](../../standards/dependencies.md) — prescriptive contract
- [`./dependencies.md`](./dependencies.md) — clustor's own dep inventory + fluxor consumption notes
- [`./substrate_sharing.md`](./substrate_sharing.md) — how clustor and sibling projects share fluxor as substrate
