//! HTTP admin path / op-code mapping, shared between the
//! `http_adapter` module and host-side tests.
//!
//! Pulled in from both sides via `#[path = "../sdk/http_admin.rs"]`
//! so the wire constant for each `/admin/<op>` path is defined in
//! exactly one place and host tests can exercise the mapping without
//! pulling the whole no_std module into the cargo build.
//!
//! ## Why the constants are duplicated here
//!
//! The op-code byte values (`ADMIN_OP_*`) are the wire admin ABI and
//! also live in `modules/sdk/wire.rs`. wire.rs takes `&SyscallTable`
//! in its channel-write helpers, which means a host test crate can't
//! pull wire.rs in without stubbing the kernel ABI. Duplicating the
//! constants here keeps host tests trivial; the
//! `op_code_values_match_wire_ABI` assertion below catches drift in
//! either direction.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple targets; each consumer uses a subset of the surface so single-target rustc invocations see unused items"
)]

// Mirror of `modules/sdk/wire.rs`'s `ADMIN_OP_*` constants. If
// either side changes, the `op_code_values_match_wire_ABI` test in
// the http_admin host test crate fails.
pub const ADMIN_OP_FREEZE: u8 = 0x01;
pub const ADMIN_OP_THAW: u8 = 0x02;
pub const ADMIN_OP_TRANSFER_LEADER: u8 = 0x03;
pub const ADMIN_OP_DURABILITY_MODE: u8 = 0x04;
pub const ADMIN_OP_SNAPSHOT: u8 = 0x05;

/// Max body length the admin envelope can carry. `emit_admin_command`
/// uses a 1 KiB stack buffer with a 2-byte header (conn_id + op_code),
/// so bodies up to 1022 bytes fit. Beyond that, the call returns
/// false and the HTTP caller gets a 503.
pub const ADMIN_BODY_MAX: usize = 1022;

/// Map a path-tail (everything after `/admin/`) to the admin op byte
/// expected by `admin_handler`. Returns `None` for unknown op names so
/// the adapter can reply 400.
pub fn admin_op_code(name: &[u8]) -> Option<u8> {
    if name == b"freeze" {
        Some(ADMIN_OP_FREEZE)
    } else if name == b"thaw" {
        Some(ADMIN_OP_THAW)
    } else if name == b"transfer-leader" {
        Some(ADMIN_OP_TRANSFER_LEADER)
    } else if name == b"durability-mode" {
        Some(ADMIN_OP_DURABILITY_MODE)
    } else if name == b"snapshot" {
        Some(ADMIN_OP_SNAPSHOT)
    } else {
        None
    }
}

/// Whether a body of `body_len` bytes fits inside the admin envelope's
/// fixed-size buffer. The `http_adapter` enqueue path checks this
/// before doing any work and short-circuits with `false` (→ HTTP 503)
/// when it doesn't fit.
#[inline]
pub const fn admin_body_fits(body_len: usize) -> bool {
    body_len <= ADMIN_BODY_MAX
}
