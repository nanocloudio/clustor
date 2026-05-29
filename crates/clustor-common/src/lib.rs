//! Clustor common — host-consumable façade over `modules/common/*.rs`.
//!
//! Each pure common file is mounted as its own `pub mod` so
//! cross-file `crate::FOO::*` references resolve the same way they
//! do in PIC builds, where each app module mounts the same files
//! with its own `#[path]` declarations (`mod wire;`, `mod types;`,
//! and so on). The `common/` directory is symlinked at the crate
//! root so cargo bundles the files at package time.
//!
//! The crate exposes only the pure no_std surface from RFC §6.5.1:
//! constants, codecs, and state machines, with no `unsafe` and no
//! syscalls. PIC-only channel I/O over fluxor's `SyscallTable`
//! lives at `modules/common/wire_channels.rs` and is consumed
//! exclusively through PIC `#[path]` mounts.

#![no_std]
#![allow(
    clippy::too_many_arguments,
    clippy::manual_range_contains,
    clippy::needless_range_loop,
    clippy::identity_op,
    reason = "common source is shared with PIC builds, where a different lint baseline applies"
)]

// `#[rustfmt::skip]` on each `mod` declaration preserves the
// hand-aligned const tables in the bundled files. The same files
// are `#[path]`-mounted by clustor's PIC modules and were authored
// with vertical alignment for readability across every use site;
// rustfmt's default settings collapse the alignment. Skipping is
// safe because the bundled files contain only tables, wire codecs,
// and state machines — nothing that benefits from rustfmt's other
// rules.

#[rustfmt::skip]
#[path = "../common/types.rs"]
pub mod types;

#[rustfmt::skip]
#[path = "../common/collections.rs"]
pub mod collections;

#[rustfmt::skip]
#[path = "../common/wire.rs"]
pub mod wire;

#[rustfmt::skip]
#[path = "../common/replica_facade.rs"]
pub mod replica_facade;

#[rustfmt::skip]
#[path = "../common/http_admin.rs"]
pub mod http_admin;
