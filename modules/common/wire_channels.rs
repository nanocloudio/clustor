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
//! `super::wire::*`, which resolves in any consumer that mounts
//! `wire.rs` as a sibling `mod wire` in the same parent module.
//!
//! These wrappers are fluxor-adjacent — they only touch
//! `SyscallTable` and the envelope formats fluxor channels carry —
//! and a future RFC may move them upstream into `fluxor-sdk`.

use super::wire::{
    decode_header, decode_partitioned_header, encode_header, encode_partitioned_header,
    ENVELOPE_HDR, MAX_PAYLOAD, PARTITIONED_HDR, ROUTED_HDR, ROUTED_PARTITIONED_HDR,
};

/// Compose `hdr` + `payload` into one stack buffer and emit a SINGLE
/// `channel_write`. Returns the total bytes written (`hdr.len() +
/// payload.len()`) on success, or `<= 0` when the frame did not fit (the
/// channel is full) or is oversize — in which case NOTHING was written.
///
/// Why one write, not two: fluxor FIFO channels are byte rings whose
/// `channel_write` is **all-or-nothing** (`kernel::ringbuf::write` returns
/// 0 if the frame doesn't fit — "partial writes corrupt byte-stream
/// framing"). Writing the header and payload as two separate
/// `channel_write` calls therefore tears a frame whenever the ring has
/// room for the header but not the payload: the header commits, the
/// payload write returns 0, and every subsequent frame on the channel is
/// misaligned (the reader takes the next frame's bytes as this one's
/// payload). At saturation a downstream that frees ~one frame per step
/// keeps the ring in exactly that danger zone, so the tear is the common
/// case, not a rare one (raft → wal entries silently shredded → garbage
/// commit_index, RFC §13/§14). A single combined write is atomic against
/// that: the whole
/// frame lands or nothing does, and the return value is a reliable
/// "did it fit" backpressure signal. Mirrors the fluxor SDK's own
/// `msg_write` (`runtime.rs`), which composes into one buffer for the
/// same reason.
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid handle.
#[inline]
unsafe fn write_framed(
    sys: &super::abi::SyscallTable,
    chan: i32,
    hdr: &[u8],
    payload: &[u8],
) -> i32 {
    let total = hdr.len() + payload.len();
    // The channel ring caps at CHANNEL_BUFFER_SIZE; a larger frame can
    // never be delivered. Reject up front rather than half-write.
    if total > super::abi::CHANNEL_BUFFER_SIZE {
        return -1;
    }
    let mut buf = [0u8; super::abi::CHANNEL_BUFFER_SIZE];
    buf[..hdr.len()].copy_from_slice(hdr);
    buf[hdr.len()..total].copy_from_slice(payload);
    let w = (sys.channel_write)(chan, buf.as_ptr(), total);
    // `channel_write` returns `total` (whole frame landed), a short
    // non-negative count (partial — shouldn't happen for the all-or-nothing
    // ring), or a NEGATIVE errno (CHAN_EAGAIN = -11 when the channel is full,
    // CHAN_EINVAL, …). Compare SIGNED: an unsigned `(w as usize) < total`
    // test wraps a negative errno to a huge usize, so a full-channel EAGAIN
    // reads as ">= total" and the caller is told the write SUCCEEDED —
    // silently dropping the frame under backpressure.
    // Anything that didn't fully land is a failure: pass a negative errno
    // through (so callers can distinguish full-vs-error) and collapse a short
    // count to 0.
    if w < total as i32 {
        return if w < 0 { w } else { 0 };
    }
    total as i32
}

/// Write a complete envelope (header + payload) into a channel.
/// Returns bytes written (ENVELOPE_HDR + payload_len) on success, or <=0 on
/// failure (channel full or error).
///
/// # Safety
/// `sys` must point to a valid SyscallTable. `chan` must be a valid channel handle.
#[inline]
pub unsafe fn channel_write_msg(
    sys: &super::abi::SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    if ENVELOPE_HDR + payload.len() > MAX_PAYLOAD + ENVELOPE_HDR { return -1; }

    let mut hdr = [0u8; ENVELOPE_HDR];
    encode_header(&mut hdr, msg_type, payload.len() as u16);
    write_framed(sys, chan, &hdr, payload)
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
    sys: &super::abi::SyscallTable,
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
    sys: &super::abi::SyscallTable,
    chan: i32,
    partition_id: u16,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    if PARTITIONED_HDR + payload.len() > MAX_PAYLOAD + PARTITIONED_HDR { return -1; }

    let mut hdr = [0u8; PARTITIONED_HDR];
    encode_partitioned_header(&mut hdr, partition_id, msg_type, payload.len() as u16);
    write_framed(sys, chan, &hdr, payload)
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
    sys: &super::abi::SyscallTable,
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
    sys: &super::abi::SyscallTable,
    chan: i32,
    target: u8,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    if ROUTED_HDR + payload.len() > MAX_PAYLOAD + ROUTED_HDR { return -1; }

    let mut hdr = [0u8; ROUTED_HDR];
    hdr[0] = target;
    hdr[1] = msg_type;
    let lb = (payload.len() as u16).to_le_bytes();
    hdr[2] = lb[0];
    hdr[3] = lb[1];
    write_framed(sys, chan, &hdr, payload)
}

/// Read a routed message. Returns (target, msg_type, payload_len).
/// Payload is placed at buf[0..payload_len].
///
/// # Safety
/// `sys` must point to a valid SyscallTable.
#[inline]
pub unsafe fn channel_read_routed(
    sys: &super::abi::SyscallTable,
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
    sys: &super::abi::SyscallTable,
    chan: i32,
    target: u8,
    partition_id: u16,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    if ROUTED_PARTITIONED_HDR + payload.len() > MAX_PAYLOAD + ROUTED_PARTITIONED_HDR { return -1; }

    let mut hdr = [0u8; ROUTED_PARTITIONED_HDR];
    hdr[0] = target;
    let pid = partition_id.to_le_bytes();
    hdr[1] = pid[0];
    hdr[2] = pid[1];
    hdr[3] = msg_type;
    let lb = (payload.len() as u16).to_le_bytes();
    hdr[4] = lb[0];
    hdr[5] = lb[1];
    write_framed(sys, chan, &hdr, payload)
}

/// Read a routed + partitioned message. Returns
/// `(target, partition_id, msg_type, payload_len)`.
///
/// # Safety
/// `sys` must point to a valid SyscallTable.
#[inline]
pub unsafe fn channel_read_routed_partitioned(
    sys: &super::abi::SyscallTable,
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
