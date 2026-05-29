//! Channel I/O wrappers over fluxor's `SyscallTable`.
//!
//! PIC-only companion to `wire.rs`. The cargo crate
//! `clustor-common` exposes only the pure no_std surface from
//! `wire.rs` (constants and codecs); the wrappers in this file
//! touch `SyscallTable` and so live outside that publishable
//! surface per RFC §6.5.1. Each app module mounts both files
//! side by side:
//!
//! ```ignore
//! #[path = "../../common/wire.rs"]
//! mod wire;
//! #[path = "../../common/wire_channels.rs"]
//! mod wire_channels;
//! ```
//!
//! Function bodies reference envelope constants and codecs from
//! `crate::wire::*`, which resolves because every consumer mounts
//! `wire.rs` at the crate root as `mod wire`.
//!
//! These wrappers are fluxor-adjacent — they only touch
//! `SyscallTable` and the envelope formats fluxor channels carry —
//! and a future RFC may move them upstream into `fluxor-sdk`.

use crate::wire::{
    decode_header, decode_partitioned_header, encode_header, encode_partitioned_header,
    ENVELOPE_HDR, MAX_PAYLOAD, PARTITIONED_HDR, ROUTED_HDR, ROUTED_PARTITIONED_HDR,
};

/// Write a complete envelope (header + payload) into a channel.
/// Returns bytes written (ENVELOPE_HDR + payload_len) on success, or <=0 on
/// failure (channel full or error).
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid channel handle.
#[inline]
pub unsafe fn channel_write_msg(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    let total = ENVELOPE_HDR + payload.len();
    if total > MAX_PAYLOAD + ENVELOPE_HDR { return -1; }

    let mut hdr = [0u8; ENVELOPE_HDR];
    encode_header(&mut hdr, msg_type, payload.len() as u16);

    let w1 = (sys.channel_write)(chan, hdr.as_ptr(), ENVELOPE_HDR);
    if w1 < ENVELOPE_HDR as i32 { return -1; }

    if !payload.is_empty() {
        let w2 = (sys.channel_write)(chan, payload.as_ptr(), payload.len());
        if w2 < payload.len() as i32 { return -1; }
    }

    total as i32
}

/// Read a complete envelope (header + payload) from a channel into `buf`.
/// The header is consumed but NOT stored in buf — only the payload is placed
/// at buf[0..payload_len]. Returns (msg_type, payload_len) on success,
/// or (0, 0) if no data available or buf too small.
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid channel handle.
#[inline]
pub unsafe fn channel_read_msg(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    buf: &mut [u8],
) -> (u8, u16) {
    let mut hdr = [0u8; ENVELOPE_HDR];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), ENVELOPE_HDR);
    if n < ENVELOPE_HDR as i32 { return (0, 0); }

    let (msg_type, payload_len) = decode_header(&hdr);
    let plen = payload_len as usize;

    if plen == 0 {
        return (msg_type, 0);
    }

    if plen > buf.len() {
        // Payload too large for buffer — drain and discard.
        let mut discard = [0u8; 256];
        let mut remaining = plen;
        while remaining > 0 {
            let chunk = remaining.min(256);
            let r = (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
            if r <= 0 { break; }
            remaining -= r as usize;
        }
        return (0, 0);
    }

    let n2 = (sys.channel_read)(chan, buf.as_mut_ptr(), plen);
    if (n2 as usize) < plen { return (0, 0); }

    (msg_type, payload_len)
}

/// Write a complete partitioned envelope (header + payload) into a channel.
/// Returns total bytes written on success, or <=0 on failure.
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid handle.
#[inline]
pub unsafe fn channel_write_partitioned(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    partition_id: u16,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    let total = PARTITIONED_HDR + payload.len();
    if total > MAX_PAYLOAD + PARTITIONED_HDR { return -1; }

    let mut hdr = [0u8; PARTITIONED_HDR];
    encode_partitioned_header(&mut hdr, partition_id, msg_type, payload.len() as u16);

    let w1 = (sys.channel_write)(chan, hdr.as_ptr(), PARTITIONED_HDR);
    if w1 < PARTITIONED_HDR as i32 { return -1; }

    if !payload.is_empty() {
        let w2 = (sys.channel_write)(chan, payload.as_ptr(), payload.len());
        if w2 < payload.len() as i32 { return -1; }
    }

    total as i32
}

/// Read a complete partitioned envelope from a channel. Header is consumed
/// but not stored in `buf`; only the payload is placed at `buf[0..payload_len]`.
/// Returns `(partition_id, msg_type, payload_len)` on success, or `(0, 0, 0)`
/// when no data is available or `buf` is too small (oversized payloads are
/// drained and discarded so the channel doesn't desync).
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid handle.
#[inline]
pub unsafe fn channel_read_partitioned(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    buf: &mut [u8],
) -> (u16, u8, u16) {
    let mut hdr = [0u8; PARTITIONED_HDR];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), PARTITIONED_HDR);
    if n < PARTITIONED_HDR as i32 { return (0, 0, 0); }

    let (partition_id, msg_type, payload_len) = decode_partitioned_header(&hdr);
    let plen = payload_len as usize;

    if plen == 0 {
        return (partition_id, msg_type, 0);
    }

    if plen > buf.len() {
        let mut discard = [0u8; 256];
        let mut remaining = plen;
        while remaining > 0 {
            let chunk = remaining.min(256);
            let r = (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
            if r <= 0 { break; }
            remaining -= r as usize;
        }
        return (0, 0, 0);
    }

    let n2 = (sys.channel_read)(chan, buf.as_mut_ptr(), plen);
    if (n2 as usize) < plen { return (0, 0, 0); }

    (partition_id, msg_type, payload_len)
}

/// Write a routed message (target_replica prefix + envelope + payload).
///
/// # Safety
/// `sys` must point to a valid SyscallTable.
#[inline]
pub unsafe fn channel_write_routed(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    target: u8,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    let total = ROUTED_HDR + payload.len();
    if total > MAX_PAYLOAD + ROUTED_HDR { return -1; }

    let mut hdr = [0u8; ROUTED_HDR];
    hdr[0] = target;
    hdr[1] = msg_type;
    let lb = (payload.len() as u16).to_le_bytes();
    hdr[2] = lb[0];
    hdr[3] = lb[1];

    let w1 = (sys.channel_write)(chan, hdr.as_ptr(), ROUTED_HDR);
    if w1 < ROUTED_HDR as i32 { return -1; }

    if !payload.is_empty() {
        let w2 = (sys.channel_write)(chan, payload.as_ptr(), payload.len());
        if w2 < payload.len() as i32 { return -1; }
    }

    total as i32
}

/// Read a routed message. Returns (target, msg_type, payload_len).
/// Payload is placed at buf[0..payload_len].
///
/// # Safety
/// `sys` must point to a valid SyscallTable.
#[inline]
pub unsafe fn channel_read_routed(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    buf: &mut [u8],
) -> (u8, u8, u16) {
    let mut hdr = [0u8; ROUTED_HDR];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), ROUTED_HDR);
    if n < ROUTED_HDR as i32 { return (0, 0, 0); }

    let target = hdr[0];
    let msg_type = hdr[1];
    let payload_len = u16::from_le_bytes([hdr[2], hdr[3]]);
    let plen = payload_len as usize;

    if plen == 0 {
        return (target, msg_type, 0);
    }

    if plen > buf.len() {
        // Drain oversized payload
        let mut discard = [0u8; 256];
        let mut remaining = plen;
        while remaining > 0 {
            let chunk = remaining.min(256);
            let r = (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
            if r <= 0 { break; }
            remaining -= r as usize;
        }
        return (0, 0, 0);
    }

    let n2 = (sys.channel_read)(chan, buf.as_mut_ptr(), plen);
    if (n2 as usize) < plen { return (0, 0, 0); }

    (target, msg_type, payload_len)
}

/// Write a routed + partitioned message.
///
/// # Safety
/// `sys` must point to a valid SyscallTable.
#[inline]
pub unsafe fn channel_write_routed_partitioned(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    target: u8,
    partition_id: u16,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    let total = ROUTED_PARTITIONED_HDR + payload.len();
    if total > MAX_PAYLOAD + ROUTED_PARTITIONED_HDR { return -1; }

    let mut hdr = [0u8; ROUTED_PARTITIONED_HDR];
    hdr[0] = target;
    let pid = partition_id.to_le_bytes();
    hdr[1] = pid[0];
    hdr[2] = pid[1];
    hdr[3] = msg_type;
    let lb = (payload.len() as u16).to_le_bytes();
    hdr[4] = lb[0];
    hdr[5] = lb[1];

    let w1 = (sys.channel_write)(chan, hdr.as_ptr(), ROUTED_PARTITIONED_HDR);
    if w1 < ROUTED_PARTITIONED_HDR as i32 { return -1; }

    if !payload.is_empty() {
        let w2 = (sys.channel_write)(chan, payload.as_ptr(), payload.len());
        if w2 < payload.len() as i32 { return -1; }
    }

    total as i32
}

/// Read a routed + partitioned message. Returns
/// `(target, partition_id, msg_type, payload_len)`.
///
/// # Safety
/// `sys` must point to a valid SyscallTable.
#[inline]
pub unsafe fn channel_read_routed_partitioned(
    sys: &crate::abi::SyscallTable,
    chan: i32,
    buf: &mut [u8],
) -> (u8, u16, u8, u16) {
    let mut hdr = [0u8; ROUTED_PARTITIONED_HDR];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), ROUTED_PARTITIONED_HDR);
    if n < ROUTED_PARTITIONED_HDR as i32 { return (0, 0, 0, 0); }

    let target = hdr[0];
    let partition_id = u16::from_le_bytes([hdr[1], hdr[2]]);
    let msg_type = hdr[3];
    let payload_len = u16::from_le_bytes([hdr[4], hdr[5]]);
    let plen = payload_len as usize;

    if plen == 0 {
        return (target, partition_id, msg_type, 0);
    }

    if plen > buf.len() {
        let mut discard = [0u8; 256];
        let mut remaining = plen;
        while remaining > 0 {
            let chunk = remaining.min(256);
            let r = (sys.channel_read)(chan, discard.as_mut_ptr(), chunk);
            if r <= 0 { break; }
            remaining -= r as usize;
        }
        return (0, 0, 0, 0);
    }

    let n2 = (sys.channel_read)(chan, buf.as_mut_ptr(), plen);
    if (n2 as usize) < plen { return (0, 0, 0, 0); }

    (target, partition_id, msg_type, payload_len)
}
