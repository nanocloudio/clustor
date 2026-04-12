//! Wire format helpers for inter-module channel messages.
//!
//! Every message uses a 3-byte envelope:
//!   [msg_type: u8] [len: u16 LE] [payload: len bytes]

#![allow(dead_code)]

// ── Message type constants ──────────────────────────────────────────────────

// Raft RPC
pub const MSG_APPEND_ENTRIES: u8      = 0x01;
pub const MSG_APPEND_ENTRIES_RESP: u8 = 0x02;
pub const MSG_REQUEST_VOTE: u8        = 0x03;
pub const MSG_REQUEST_VOTE_RESP: u8   = 0x04;
pub const MSG_PRE_VOTE: u8            = 0x05;
pub const MSG_PRE_VOTE_RESP: u8       = 0x06; // reuse slot: high bit unused
pub const MSG_HEARTBEAT: u8           = 0x07;
pub const MSG_HEARTBEAT_RESP: u8      = 0x08;

// Client
pub const MSG_CLIENT_PROPOSAL: u8     = 0x10;
pub const MSG_CLIENT_RESPONSE: u8     = 0x11;
pub const MSG_ADMIN_COMMAND: u8       = 0x12;
pub const MSG_ADMIN_RESPONSE: u8      = 0x13;

// Persistence
pub const MSG_WAL_ENTRY: u8           = 0x20;
pub const MSG_FSYNC_ACK: u8           = 0x21;
pub const MSG_DURABILITY_PROOF: u8    = 0x22;
pub const MSG_COMMITTED_BATCH: u8     = 0x23;

// Control plane
pub const MSG_CP_PROOF: u8            = 0x30;
pub const MSG_CACHE_STATE: u8         = 0x31;
pub const MSG_FALLBACK_SIGNAL: u8     = 0x32;
pub const MSG_READ_PERMIT: u8         = 0x33;

// Flow control
pub const MSG_THROTTLE_CREDITS: u8    = 0x40;
pub const MSG_THROTTLE_ENVELOPE: u8   = 0x41;
pub const MSG_LAG_SIGNAL: u8          = 0x42;

// Snapshot
pub const MSG_SNAPSHOT_CHUNK: u8      = 0x50;
pub const MSG_SNAPSHOT_MANIFEST: u8   = 0x51;
pub const MSG_SNAPSHOT_TRIGGER: u8    = 0x52;

// Key management
pub const MSG_DEK_EPOCH: u8           = 0x60;
pub const MSG_CERT_REFRESH: u8        = 0x61;

// Telemetry
pub const MSG_METRICS: u8             = 0x70;
pub const MSG_READYZ: u8              = 0x71;
pub const MSG_WHY: u8                 = 0x72;

// Routing
pub const MSG_PLACEMENT_UPDATE: u8    = 0x80;

/// Envelope header size (1 byte type + 2 bytes length).
pub const ENVELOPE_HDR: usize = 3;

/// Maximum payload size in a single envelope (64 KiB - 1).
pub const MAX_PAYLOAD: usize = 0xFFFF;

// ── Encoding helpers ────────────────────────────────────────────────────────

/// Encode an envelope header into `buf[0..3]`. Returns 3 on success, -1 if
/// buf is too small.
#[inline]
pub fn encode_header(buf: &mut [u8], msg_type: u8, payload_len: u16) -> i32 {
    if buf.len() < ENVELOPE_HDR { return -1; }
    buf[0] = msg_type;
    let lb = payload_len.to_le_bytes();
    buf[1] = lb[0];
    buf[2] = lb[1];
    ENVELOPE_HDR as i32
}

/// Decode an envelope header from `buf[0..3]`. Returns `(msg_type, payload_len)`.
/// Caller must ensure buf.len() >= ENVELOPE_HDR.
#[inline]
pub fn decode_header(buf: &[u8]) -> (u8, u16) {
    let msg_type = buf[0];
    let payload_len = u16::from_le_bytes([buf[1], buf[2]]);
    (msg_type, payload_len)
}

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

// ── Routed message helpers (for peer_tx channel) ────────────────────────────
//
// Messages on the peer_tx channel between raft_engine/replicator and
// peer_router carry a 1-byte target_replica prefix BEFORE the standard
// envelope so peer_router can route to the correct peer connection.
//
// Wire: [target_replica: u8] [msg_type: u8] [len: u16 LE] [payload]

/// Routed envelope header: 4 bytes (target + standard 3-byte envelope).
pub const ROUTED_HDR: usize = 4;

/// Broadcast target: send to all peers.
pub const TARGET_BROADCAST: u8 = 0xFF;

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

// ── Payload serialization for common Raft structures ────────────────────────

/// Encode a term + index pair (16 bytes).
#[inline]
pub fn encode_term_index(buf: &mut [u8], term: u64, index: u64) {
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8..16].copy_from_slice(&index.to_le_bytes());
}

/// Decode a term + index pair (16 bytes).
#[inline]
pub fn decode_term_index(buf: &[u8]) -> (u64, u64) {
    let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let index = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
    (term, index)
}

/// Encode term + index + replica_id (17 bytes).
#[inline]
pub fn encode_term_index_replica(buf: &mut [u8], term: u64, index: u64, replica: u8) {
    encode_term_index(buf, term, index);
    buf[16] = replica;
}

/// Decode term + index + replica_id (17 bytes).
#[inline]
pub fn decode_term_index_replica(buf: &[u8]) -> (u64, u64, u8) {
    let (term, index) = decode_term_index(buf);
    (term, index, buf[16])
}

/// Encode a RequestVote / PreVote payload (25 bytes):
///   term(8) + candidate_id(1) + last_log_index(8) + last_log_term(8)
#[inline]
pub fn encode_vote_request(buf: &mut [u8], term: u64, candidate: u8, last_index: u64, last_term: u64) {
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8] = candidate;
    buf[9..17].copy_from_slice(&last_index.to_le_bytes());
    buf[17..25].copy_from_slice(&last_term.to_le_bytes());
}

/// Decode a RequestVote / PreVote payload (25 bytes).
#[inline]
pub fn decode_vote_request(buf: &[u8]) -> (u64, u8, u64, u64) {
    let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let candidate = buf[8];
    let last_index = u64::from_le_bytes([buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16]]);
    let last_term = u64::from_le_bytes([buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24]]);
    (term, candidate, last_index, last_term)
}

/// Encode a VoteResponse payload (10 bytes):
///   term(8) + granted(1) + voter_id(1)
#[inline]
pub fn encode_vote_response(buf: &mut [u8], term: u64, granted: bool, voter: u8) {
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8] = granted as u8;
    buf[9] = voter;
}

/// Decode a VoteResponse payload (10 bytes).
#[inline]
pub fn decode_vote_response(buf: &[u8]) -> (u64, bool, u8) {
    let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let granted = buf[8] != 0;
    let voter = buf[9];
    (term, granted, voter)
}

/// Encode an FsyncAck / DurabilityProof payload (17 bytes):
///   term(8) + index(8) + replica_id(1)
#[inline]
pub fn encode_fsync_ack(buf: &mut [u8], term: u64, index: u64, replica: u8) {
    encode_term_index_replica(buf, term, index, replica);
}

/// Decode an FsyncAck / DurabilityProof payload (17 bytes).
#[inline]
pub fn decode_fsync_ack(buf: &[u8]) -> (u64, u64, u8) {
    decode_term_index_replica(buf)
}

/// Encode a CacheState payload (1 byte): the CP_* constant.
#[inline]
pub fn encode_cache_state(buf: &mut [u8], state: u8) {
    buf[0] = state;
}

/// Decode a CacheState payload (1 byte).
#[inline]
pub fn decode_cache_state(buf: &[u8]) -> u8 {
    buf[0]
}

/// Encode ThrottleCredits payload (8 bytes): entry_credits(4) + byte_credits(4).
#[inline]
pub fn encode_credits(buf: &mut [u8], entry: i32, byte: i32) {
    buf[0..4].copy_from_slice(&entry.to_le_bytes());
    buf[4..8].copy_from_slice(&byte.to_le_bytes());
}

/// Decode ThrottleCredits payload (8 bytes).
#[inline]
pub fn decode_credits(buf: &[u8]) -> (i32, i32) {
    let entry = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let byte = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    (entry, byte)
}
