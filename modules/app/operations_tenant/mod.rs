//! operations_tenant — `operations` for a tenant graph.
//!
//! The same composite as `operations` (admin admission, workflows,
//! telemetry aggregation and the HTTP diagnostic surface; see
//! `modules/app/operations/mod.rs` for its components and dispatch table),
//! built from the same body (`modules/app/operations/composite.rs`) with the
//! same ports, params and variants, less the node's privilege: a workload
//! may hold no module permission but `observe`, so this type declares none,
//! and its telemetry does not scrape the kernel's scheduler step-time
//! histograms (the monitor ABI's `STEP_HISTOGRAM_QUERY`, which takes
//! `monitor`). Its `/metrics` export carries the global step histogram's
//! records empty and no per-module ones; the per-component step histograms,
//! the module's own accounting, are in place. The clustor-directory stacks
//! run this type, so a graph including them may run as a workload.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

/// The kernel step-time scrape: off, as this type holds no `monitor`.
const KERNEL_STEPS: bool = false;

include!("../operations/composite.rs");
