# Clustor Architecture & Visibility Rules

## Entry Points

- `src/lib.rs` is the sole crate root. There is no `src/main.rs` or `src/bin/*`.
- Public API surface is limited to re-exports declared in `src/lib.rs`; binaries/examples must rely on these exports rather than reaching into module internals.

## Layering

- **control_plane** can depend on `replication`, `persistence`, `security`, and shared `util`.
- **replication** may depend on `persistence` (storage/durability) and `util`, but not on `control_plane`.
- **persistence** is storage-only and must not depend on `control_plane` or `replication`.
- **observability** modules (readyz/system_log/telemetry) may depend on any domain for reporting, but no other module should depend on observability internals.
- **net** sticks to transport/adapters and depends on `control_plane`/`replication` APIs behind clearly defined traits.
- Integration tests live under `tests/<domain>/` and consume only the public API or helpers in `tests/support/`.
- Async code must run on Tokio. `tools/check_async_runtime.sh` is part of the CI gate and fails if `async_std`, `smol`, `ntex`, etc. show up in the tree.

## Logging policy

- The repository uses the `log` facade exclusively. There is no `tracing` dependency.
- Values should be emitted with the existing `log::{error,warn,info,debug,trace}` macros.
- Adding a new logging backend requires updating this document plus the dependency justification in `docs/dependencies.md`.

## Visibility policy

- Modules expose the minimum surface needed: internal helpers (`DurabilityState`, `ShrinkPlanRecord`, etc.) are `pub(crate)` and only higher-level services (`AdminService`, `AdminHandler`) are exported.
- Shared internal-only utilities should be re-exported via `src/internal.rs` (or a domain-specific module) rather than marked `pub`.
- Adding new modules must document their allowed dependencies in this file, and new `pub` items should be justified via doc comments.
