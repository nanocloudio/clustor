//! WAL on-disk frame contract — the single source of truth for the
//! per-entry segment layout, shared by the durability module's
//! replay / segment-scan / catch-up paths and the `clustor_cli`
//! `wal-frame` / `wal-scan` commands. Because both sides compile this
//! exact file, a `wal-scan` verdict on a segment image is the durable
//! prefix a replica's replay would recover — by construction, not by
//! convention.
//!
//! Layout, per entry:
//!
//! ```text
//! [entry_len: u32 LE][crc32c: u32 LE][payload: entry_len bytes]
//! ```
//!
//! The CRC (Castagnoli, `collections::Crc32c`) covers the payload
//! only. The payload's first 16 bytes are the term/index prologue
//! (`wire::decode_term_index`). An entry is torn or invalid when
//! `entry_len` is 0, exceeds [`MAX_ENTRY_LEN`], or runs past the
//! readable region; replay stops at the first bad frame and
//! everything before it is the durable prefix.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface so single-module rustc invocations see unused items"
)]

/// Frame header size: `[entry_len: u32 LE][crc32c: u32 LE]`.
pub const FRAME_HDR: usize = 8;

/// Payload prologue size: `[term: u64 LE][index: u64 LE]`
/// (`wire::encode_term_index` / `wire::decode_term_index`).
pub const ENTRY_PROLOGUE: usize = 16;

/// Cap on the entry body (the bytes after the prologue): one coalesced
/// proposal batch. This is the same value every proposal-carrying
/// buffer in the graph must size against — raft's batch, the gateway's
/// proposal frames, the session directory's message buffer.
pub const MAX_ENTRY_BODY: usize = 2048;

/// Replay's per-entry payload cap: prologue + max body. A header whose
/// `entry_len` exceeds this is treated as torn, not as a large entry,
/// so a write path emitting more silently truncates the durable log at
/// replay. Buffers staging a whole entry (frame payloads, `wal-frame`
/// output) size against this; buffers holding only command bytes size
/// against `MAX_ENTRY_BODY`.
pub const MAX_ENTRY_LEN: usize = ENTRY_PROLOGUE + MAX_ENTRY_BODY;

/// Split a frame header into `(entry_len, crc32c)`.
#[inline]
pub fn parse_header(hdr: &[u8; FRAME_HDR]) -> (u32, u32) {
    let entry_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let crc = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    (entry_len, crc)
}

/// True when a header's `entry_len` is structurally invalid against
/// `remaining` readable payload bytes (the bytes after the header):
/// zero, over the cap, or running past the readable region. Any true
/// result means "torn frame — stop here"; it never means "skip".
#[inline]
pub fn len_invalid(entry_len: u32, remaining: u64) -> bool {
    entry_len == 0 || entry_len as usize > MAX_ENTRY_LEN || u64::from(entry_len) > remaining
}
