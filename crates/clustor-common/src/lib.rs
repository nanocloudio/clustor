//! Clustor common — host-consumable façade over `modules/common/*.rs`.
//!
//! Each pure common file is mounted as its own `pub mod` so
//! cross-file `crate::FOO::*` references resolve the same way they
//! do in PIC builds, where each app module mounts the same files
//! with its own `#[path]` declarations (`mod wire;`, `mod types;`,
//! and so on). The `common/` directory is symlinked at the crate
//! root so cargo bundles the files at package time.
//!
//! The crate exposes only the pure no_std surface:
//! constants, codecs, and state machines, with no `unsafe` and no
//! syscalls. PIC-only channel I/O over fluxor's `SyscallTable`
//! lives at `modules/common/wire_channels.rs` and is consumed
//! exclusively through PIC `#[path]` mounts.

#![no_std]

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

#[rustfmt::skip]
#[path = "../common/slot_index.rs"]
pub mod slot_index;
#[rustfmt::skip]
#[path = "../common/timing.rs"]
pub mod timing;

#[rustfmt::skip]
#[path = "../common/session_registry.rs"]
pub mod session_registry;
#[rustfmt::skip]
#[path = "../common/transport_registry.rs"]
pub mod transport_registry;
#[rustfmt::skip]
#[path = "../common/vip_registry.rs"]
pub mod vip_registry;
#[rustfmt::skip]
#[path = "../common/failover_registry.rs"]
pub mod failover_registry;
#[rustfmt::skip]
#[path = "../common/region_registry.rs"]
pub mod region_registry;
#[rustfmt::skip]
#[path = "../common/operation_registry.rs"]
pub mod operation_registry;
#[rustfmt::skip]
#[path = "../common/attachment_registry.rs"]
pub mod attachment_registry;
#[rustfmt::skip]
#[path = "../common/reservation_registry.rs"]
pub mod reservation_registry;

#[rustfmt::skip]
#[path = "../common/wal_frame.rs"]
pub mod wal_frame;
