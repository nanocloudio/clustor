# Dependency Inventory

Clustor's runtime substrate has no `cargo install`-able footprint.
Cryptographic primitives, codecs, transports, and runtime helpers
come from fluxor's published SDK, consumed via the local registry.
Shipping a clustor module means packing its `.fmod` and dropping it
into the graph.

## Fluxor consumption

Clustor consumes fluxor through the local registry; see
[`consuming_fluxor.md`](consuming_fluxor.md) for the day-to-day
workflow. The pin lives in
`fluxor.toml::[dependencies] fluxor = "X.Y"`; `fluxor update`
resolves it to specific crate, fmod, and runtime versions, recorded
in `fluxor.lock`. Materialisation (the module-build pre-flight, or
`fluxor sync` on demand) lands those in `target/fluxor/<crate>/`
(source crates) and `target/<host-target>/release/<bin>` (runtime
binaries).

The module ABI is derived from the resolved fluxor version and is
digest-pinned: the toolchain refuses to load modules whose ABI digest
disagrees with the runtime. `[required] fluxor = { abi = N }` is also
honoured as an optional explicit assertion for defence in depth.

`fluxor.toml::[dependencies]` also pins `wave`, the sibling project
that publishes the protocol-module palette (`http`, `ws_stream`,
`rtp`) into the same local registry. Clustor consumes those fmods
through the deployment graph exactly like fluxor's foundation
modules; nothing links against wave at the cargo level.

PIC modules in `modules/app/*/mod.rs` `#[path]`-mount fluxor's SDK
source from the materialised location at
`target/fluxor/fluxor-abi/sdk/<file>.rs`.

## Host crates

The `clustor` cargo package's compiled artefact is the placeholder
`src/lib.rs`, a doc-comment stub; no runtime code ships through
cargo.

The `clustor-bench` host crate (`tools/clustor-bench/`) — the
`clustor-scrape` / `clustor-loadgen` driver-host binaries — is
std-only by design and pulls in no external crates (raw `std::net`,
hand-rolled JSON and histogram); its only dependency is a path
dependency on `clustor-common` for shared wire contracts, so it
builds on an offline Pi. It sits outside the runtime substrate and
holds a structured lint exemption in `fluxor.toml`.
