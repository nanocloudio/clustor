//! Operations — admin admission, workflows, telemetry aggregation and
//! the HTTP diagnostic surface.
//!
//! One graph module composed of four components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`rbac`]      — role-based admission for admin commands.
//!   - [`admin`]     — idempotency-keyed admin workflows → raft.
//!   - [`telemetry`] — metrics fan-in, readiness, /metrics export.
//!   - [`http`]      — diagnostic + write-bridge request handling
//!     (`http` feature). HTTP mechanics live outside
//!     the module: wave's `http` server parses the
//!     wire and is the requester of an exchange
//!     (SDK `contracts/exchange.rs`) whose provider is
//!     this component — request records on
//!     `request_in`, answers on `response_out`.
//!
//! Every admin command — wire or HTTP — is admitted through the rbac
//! component; there is no path around it. The `headless` variant
//! carries no HTTP surface at all: the `http` component is compiled
//! out and its ports are absent from the manifest.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else. Components never call each other:
//! each returns message-shaped records (requests, verdicts, staged
//! responses) and the routing between them — request → http,
//! admin envelope → rbac → admin — happens in `module_step`'s loops
//! (standards fluxor-modules.md §8):
//!
//!   1. `telemetry` — drain ingest, recompute readiness, emit tick.
//!      (Heaviest single step on the emit tick: one global + up to 32
//!      per-module histogram scrapes, export ≤ 7400 B.)
//!   2. on an emit tick: refresh the http caches from telemetry's
//!      snapshot values.
//!   3. `rbac`  — identity bindings, then the wire admin-command
//!      loop (≤4): each authorized envelope delivers into `admin`
//!      same-step, here.
//!   4. `admin` — apply acknowledgements, direct-inject commands.
//!   5. `http`  — proposal feedback loops (assignments, ≤8
//!      rejections, ≤16 applies, one expiry — each pull gated on
//!      `http::ready_to_answer`, which first places any record the
//!      `response_out` port had no room for), self-telemetry into
//!      `telemetry`.
//!   6. `http` `request_in` loop (≤8) — exchange request records,
//!      each pull likewise gated; answers egress on `response_out`.
//!
//! Per-component step bounds are documented on each component's
//! `step`; the sum stays well inside the runtime step guard.
//!
//! The dispatch table brackets each section with `dev_micros` reads
//! and hands a per-component step-time histogram to the in-module
//! telemetry component each second under the component's source id
//! (`step_accounting`, §8 rule 8); a section's routing chains bill
//! the section's driving component.
//!
//! ## Two module types, one body
//!
//! This is the node's type: its telemetry also scrapes the kernel's
//! scheduler step-time histograms (global and per module) over the
//! monitor ABI, which takes the `monitor` permission. A workload may hold
//! no node permission, so a tenant graph runs `operations_tenant`
//! (`modules/app/operations_tenant/`): the same body (`composite.rs`), the
//! same ports, params and variants, no `monitor`, no kernel scrape.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

/// The kernel step-time scrape (`STEP_HISTOGRAM_QUERY`, under `monitor`):
/// on in the node's type.
const KERNEL_STEPS: bool = true;

include!("composite.rs");
