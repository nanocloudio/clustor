//! Placeholder library root for the `clustor` cargo package.
//!
//! The Clustor implementation lives as a graph of fluxor-native PIC
//! modules under [`modules/app/`](modules/app/) and is built with
//! `make modules TARGET=<board>`.
//!
//! Host-side tests and benches pull module source files directly
//! with `#[path = "../modules/..."]`, so this stub deliberately
//! exposes nothing. It exists only so `cargo` has a library target
//! to register in the package metadata — removing the file (and the
//! `[lib]` entry in `Cargo.toml`) is fine the moment cargo gains a
//! "no-library, integration-tests-only" mode.
