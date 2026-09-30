//! Sealed durability records: the v1 byte layouts of Clustor's
//! sealed durability records and the KEY_VAULT calls that seal and
//! open them.
//!
//! The layouts are the cross-project v1 contract of Fluxor's
//! encrypted-storage record formats (keys and derivation; Clustor sealed
//! records). All integers are little-endian.
//!
//! WAL frame:
//!
//! ```text
//! 0      1   discriminator 0xA5
//! 1      3   reserved, zero
//! 4      4   frame length, from offset 8 to the end of the CRC (C + 52)
//! 8      4   key epoch
//! 12     16  segment incarnation
//! 28     8   frame sequence
//! 36     4   ciphertext length C
//! 40     C   ciphertext of term(8) ‖ index(8) ‖ entry
//! 40+C   16  tag
//! 56+C   4   CRC32C over bytes 0..56+C
//!
//! nonce = "WAL0" ‖ frame sequence(8)
//! aad   = cluster(16) ‖ partition(8) ‖ replica(8) ‖ segment sequence(8)
//!       ‖ incarnation(16) ‖ epoch(4) ‖ frame sequence(8)
//!       ‖ plaintext length(4) ‖ C(4)
//! key   = HKDF(master, "clustor/wal",
//!              cluster(16) ‖ partition(8) ‖ replica(8) ‖ epoch(4) ‖ incarnation(16))
//! ```
//!
//! Snapshot chunk:
//!
//! ```text
//! 0      4   magic "FXSC"
//! 4      4   key epoch
//! 8      16  snapshot generation
//! 24     8   chunk index
//! 32     1   flags: bit 0 = final chunk
//! 33     3   reserved, zero
//! 36     4   ciphertext length C
//! 40     C   ciphertext
//! 40+C   16  tag
//!
//! nonce = "SNP0" ‖ chunk index(8)
//! aad   = cluster(16) ‖ partition(8) ‖ source replica(8) ‖ generation(16)
//!       ‖ last included term(8) ‖ last included index(8) ‖ epoch(4)
//!       ‖ chunk index(8) ‖ flags(1) ‖ plaintext length(4)
//! key   = HKDF(master, "clustor/snapshot",
//!              cluster(16) ‖ partition(8) ‖ generation(16) ‖ epoch(4))
//! ```
//!
//! The key bytes never enter this module: the master is a KEY_VAULT
//! `KDF_KEY` handle, each purpose key is a `DERIVE`d handle, and
//! sealing is `AEAD_SEAL_UNITS` / `AEAD_OPEN_UNITS` in place with the
//! nonce this file computes. A stream AEAD's ciphertext is as long as
//! its plaintext, so the plaintext length and `C` are always equal;
//! both are bound because the v1 AAD names both.

#![allow(
    dead_code,
    reason = "shared via #[path] into several modules and host tests; each consumer uses a subset of the surface"
)]

use crate::abi::contracts::key_vault as kv;
use crate::abi::SyscallTable;
use crate::collections::Crc32c;

// ── Suites ──────────────────────────────────────────────────────────────

/// Suite ids as the v1 formats record them.
pub const SUITE_CHACHA20_POLY1305: u16 = 1;
pub const SUITE_AES_256_GCM: u16 = 2;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const INCARNATION_LEN: usize = 16;
pub const GENERATION_LEN: usize = 16;
pub const CLUSTER_LEN: usize = 16;

/// The KEY_VAULT suite that holds a key for format suite `suite`, or
/// `None` for an id the v1 formats do not define.
pub fn vault_suite(suite: u16) -> Option<u16> {
    match suite {
        SUITE_CHACHA20_POLY1305 => Some(kv::suite::AEAD_KEY),
        SUITE_AES_256_GCM => Some(kv::suite::AEAD_AES256_GCM),
        _ => None,
    }
}

/// Who a record belongs to: the fields every derivation context and
/// every AAD begins with.
#[derive(Clone, Copy)]
pub struct Identity {
    pub cluster: [u8; CLUSTER_LEN],
    pub partition: u64,
    pub replica: u64,
}

#[inline]
fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() {
        out[at + i] = bytes[i];
        i += 1;
    }
    at + bytes.len()
}

#[inline]
fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[inline]
fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

// ── WAL frame ───────────────────────────────────────────────────────────

pub const WAL_DISCRIMINATOR: u8 = 0xA5;
/// Bytes before the ciphertext.
pub const WAL_HDR_LEN: usize = 40;
/// Bytes after the ciphertext: tag and CRC.
pub const WAL_TRAILER_LEN: usize = TAG_LEN + 4;
/// Bytes a frame adds to its plaintext.
pub const WAL_OVERHEAD: usize = WAL_HDR_LEN + WAL_TRAILER_LEN;
/// The prefix that says what follows: discriminator, reserved, length.
pub const WAL_PREFIX_LEN: usize = 8;
/// `frame length` = C + this.
pub const WAL_LEN_BIAS: u32 = (WAL_OVERHEAD - WAL_PREFIX_LEN) as u32;

pub const WAL_OFF_LEN: usize = 4;
pub const WAL_OFF_EPOCH: usize = 8;
pub const WAL_OFF_INCARNATION: usize = 12;
pub const WAL_OFF_SEQ: usize = 28;
pub const WAL_OFF_CT_LEN: usize = 36;
pub const WAL_OFF_CT: usize = 40;

pub const WAL_NONCE_DOMAIN: [u8; 4] = *b"WAL0";
pub const WAL_LABEL: &[u8] = b"clustor/wal";
pub const WAL_AAD_LEN: usize = 16 + 8 + 8 + 8 + 16 + 4 + 8 + 4 + 4;
pub const WAL_CONTEXT_LEN: usize = 16 + 8 + 8 + 4 + 16;

pub fn wal_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    put(&mut n, 0, &WAL_NONCE_DOMAIN);
    put(&mut n, 4, &seq.to_le_bytes());
    n
}

pub fn wal_context(
    id: &Identity,
    epoch: u32,
    incarnation: &[u8; INCARNATION_LEN],
) -> [u8; WAL_CONTEXT_LEN] {
    let mut c = [0u8; WAL_CONTEXT_LEN];
    let mut at = put(&mut c, 0, &id.cluster);
    at = put(&mut c, at, &id.partition.to_le_bytes());
    at = put(&mut c, at, &id.replica.to_le_bytes());
    at = put(&mut c, at, &epoch.to_le_bytes());
    put(&mut c, at, incarnation);
    c
}

pub fn wal_aad(
    id: &Identity,
    segment_seq: u64,
    incarnation: &[u8; INCARNATION_LEN],
    epoch: u32,
    seq: u64,
    plaintext_len: u32,
    ct_len: u32,
) -> [u8; WAL_AAD_LEN] {
    let mut a = [0u8; WAL_AAD_LEN];
    let mut at = put(&mut a, 0, &id.cluster);
    at = put(&mut a, at, &id.partition.to_le_bytes());
    at = put(&mut a, at, &id.replica.to_le_bytes());
    at = put(&mut a, at, &segment_seq.to_le_bytes());
    at = put(&mut a, at, incarnation);
    at = put(&mut a, at, &epoch.to_le_bytes());
    at = put(&mut a, at, &seq.to_le_bytes());
    at = put(&mut a, at, &plaintext_len.to_le_bytes());
    put(&mut a, at, &ct_len.to_le_bytes());
    a
}

/// Total stored bytes of a frame carrying `ct_len` bytes.
#[inline]
pub const fn wal_frame_len(ct_len: usize) -> usize {
    ct_len + WAL_OVERHEAD
}

/// Write bytes `0..40` of a frame: everything before the ciphertext.
/// `out` must hold at least `WAL_HDR_LEN` bytes.
pub fn wal_write_header(
    out: &mut [u8],
    epoch: u32,
    incarnation: &[u8; INCARNATION_LEN],
    seq: u64,
    ct_len: u32,
) {
    out[0] = WAL_DISCRIMINATOR;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    put(out, WAL_OFF_LEN, &(ct_len + WAL_LEN_BIAS).to_le_bytes());
    put(out, WAL_OFF_EPOCH, &epoch.to_le_bytes());
    put(out, WAL_OFF_INCARNATION, incarnation);
    put(out, WAL_OFF_SEQ, &seq.to_le_bytes());
    put(out, WAL_OFF_CT_LEN, &ct_len.to_le_bytes());
}

/// CRC32C over a frame's bytes `0..56+C`.
pub fn wal_crc(frame: &[u8], ct_len: usize) -> u32 {
    let mut c = Crc32c::new();
    c.update(&frame[..WAL_HDR_LEN + ct_len + TAG_LEN]);
    c.finalize()
}

/// Write the CRC of a frame whose header, ciphertext and tag are in place.
pub fn wal_write_crc(frame: &mut [u8], ct_len: usize) {
    let crc = wal_crc(frame, ct_len);
    put(frame, WAL_HDR_LEN + ct_len + TAG_LEN, &crc.to_le_bytes());
}

/// What the first eight bytes at a replay position say.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WalPrefix {
    /// Zero discriminator: a replay terminator or never-written space.
    /// The clean end of a segment's live data.
    End,
    /// A frame of `frame_len + 8` stored bytes follows, if the
    /// structural checks hold.
    Frame { frame_len: u32 },
    /// Neither: a torn or foreign byte pattern.
    Garbage,
}

/// Classify a frame prefix. `max_ct` bounds the ciphertext a frame may
/// claim, so a torn length can never ask for more than one entry.
pub fn wal_parse_prefix(p: &[u8], max_ct: usize) -> WalPrefix {
    if p.len() < WAL_PREFIX_LEN {
        return WalPrefix::Garbage;
    }
    if p[0] == 0 {
        return WalPrefix::End;
    }
    if p[0] != WAL_DISCRIMINATOR || p[1] != 0 || p[2] != 0 || p[3] != 0 {
        return WalPrefix::Garbage;
    }
    let frame_len = get_u32(p, WAL_OFF_LEN);
    if frame_len < WAL_LEN_BIAS || (frame_len - WAL_LEN_BIAS) as usize > max_ct {
        return WalPrefix::Garbage;
    }
    WalPrefix::Frame { frame_len }
}

/// The authenticated-by-AAD header fields of a frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WalHeader {
    pub epoch: u32,
    pub incarnation: [u8; INCARNATION_LEN],
    pub seq: u64,
    pub ct_len: u32,
}

/// Parse a whole frame's header, checking that its declared lengths
/// agree. `frame` holds at least `WAL_HDR_LEN` bytes.
pub fn wal_parse_header(frame: &[u8]) -> Option<WalHeader> {
    if frame.len() < WAL_HDR_LEN {
        return None;
    }
    let frame_len = get_u32(frame, WAL_OFF_LEN);
    let ct_len = get_u32(frame, WAL_OFF_CT_LEN);
    if frame[0] != WAL_DISCRIMINATOR
        || frame[1] != 0
        || frame[2] != 0
        || frame[3] != 0
        || ct_len.checked_add(WAL_LEN_BIAS) != Some(frame_len)
    {
        return None;
    }
    let mut incarnation = [0u8; INCARNATION_LEN];
    let mut i = 0;
    while i < INCARNATION_LEN {
        incarnation[i] = frame[WAL_OFF_INCARNATION + i];
        i += 1;
    }
    Some(WalHeader {
        epoch: get_u32(frame, WAL_OFF_EPOCH),
        incarnation,
        seq: get_u64(frame, WAL_OFF_SEQ),
        ct_len,
    })
}

// ── Snapshot chunk ──────────────────────────────────────────────────────

pub const SNAP_MAGIC: [u8; 4] = *b"FXSC";
pub const SNAP_HDR_LEN: usize = 40;
pub const SNAP_OVERHEAD: usize = SNAP_HDR_LEN + TAG_LEN;
pub const SNAP_FLAG_FINAL: u8 = 1;
pub const SNAP_OFF_EPOCH: usize = 4;
pub const SNAP_OFF_GENERATION: usize = 8;
pub const SNAP_OFF_INDEX: usize = 24;
pub const SNAP_OFF_FLAGS: usize = 32;
pub const SNAP_OFF_CT_LEN: usize = 36;

pub const SNAP_NONCE_DOMAIN: [u8; 4] = *b"SNP0";
pub const SNAP_LABEL: &[u8] = b"clustor/snapshot";
pub const SNAP_AAD_LEN: usize = 16 + 8 + 8 + 16 + 8 + 8 + 4 + 8 + 1 + 4;
pub const SNAP_CONTEXT_LEN: usize = 16 + 8 + 16 + 4;

pub fn snap_nonce(chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    put(&mut n, 0, &SNAP_NONCE_DOMAIN);
    put(&mut n, 4, &chunk_index.to_le_bytes());
    n
}

pub fn snap_context(
    id: &Identity,
    generation: &[u8; GENERATION_LEN],
    epoch: u32,
) -> [u8; SNAP_CONTEXT_LEN] {
    let mut c = [0u8; SNAP_CONTEXT_LEN];
    let mut at = put(&mut c, 0, &id.cluster);
    at = put(&mut c, at, &id.partition.to_le_bytes());
    at = put(&mut c, at, generation);
    put(&mut c, at, &epoch.to_le_bytes());
    c
}

/// Where a snapshot sits: the fields its chunks' AAD binds besides the
/// chunk's own position.
#[derive(Clone, Copy)]
pub struct SnapBinding {
    pub generation: [u8; GENERATION_LEN],
    pub last_term: u64,
    pub last_index: u64,
    pub epoch: u32,
}

pub fn snap_aad(
    id: &Identity,
    b: &SnapBinding,
    chunk_index: u64,
    flags: u8,
    plaintext_len: u32,
) -> [u8; SNAP_AAD_LEN] {
    let mut a = [0u8; SNAP_AAD_LEN];
    let mut at = put(&mut a, 0, &id.cluster);
    at = put(&mut a, at, &id.partition.to_le_bytes());
    at = put(&mut a, at, &id.replica.to_le_bytes());
    at = put(&mut a, at, &b.generation);
    at = put(&mut a, at, &b.last_term.to_le_bytes());
    at = put(&mut a, at, &b.last_index.to_le_bytes());
    at = put(&mut a, at, &b.epoch.to_le_bytes());
    at = put(&mut a, at, &chunk_index.to_le_bytes());
    at = put(&mut a, at, &[flags]);
    put(&mut a, at, &plaintext_len.to_le_bytes());
    a
}

/// Write a chunk header. `out` holds at least `SNAP_HDR_LEN` bytes.
pub fn snap_write_header(
    out: &mut [u8],
    epoch: u32,
    generation: &[u8; GENERATION_LEN],
    chunk_index: u64,
    flags: u8,
    ct_len: u32,
) {
    put(out, 0, &SNAP_MAGIC);
    put(out, SNAP_OFF_EPOCH, &epoch.to_le_bytes());
    put(out, SNAP_OFF_GENERATION, generation);
    put(out, SNAP_OFF_INDEX, &chunk_index.to_le_bytes());
    out[SNAP_OFF_FLAGS] = flags;
    out[SNAP_OFF_FLAGS + 1] = 0;
    out[SNAP_OFF_FLAGS + 2] = 0;
    out[SNAP_OFF_FLAGS + 3] = 0;
    put(out, SNAP_OFF_CT_LEN, &ct_len.to_le_bytes());
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapHeader {
    pub epoch: u32,
    pub generation: [u8; GENERATION_LEN],
    pub chunk_index: u64,
    pub flags: u8,
    pub ct_len: u32,
}

/// Parse a chunk header: magic, reserved bytes zero, no flag the v1
/// format does not define, and a ciphertext no longer than `max_ct`.
pub fn snap_parse_header(h: &[u8], max_ct: usize) -> Option<SnapHeader> {
    if h.len() < SNAP_HDR_LEN
        || h[0..4] != SNAP_MAGIC
        || h[SNAP_OFF_FLAGS] & !SNAP_FLAG_FINAL != 0
        || h[SNAP_OFF_FLAGS + 1] != 0
        || h[SNAP_OFF_FLAGS + 2] != 0
        || h[SNAP_OFF_FLAGS + 3] != 0
    {
        return None;
    }
    let ct_len = get_u32(h, SNAP_OFF_CT_LEN);
    if ct_len as usize > max_ct {
        return None;
    }
    let mut generation = [0u8; GENERATION_LEN];
    let mut i = 0;
    while i < GENERATION_LEN {
        generation[i] = h[SNAP_OFF_GENERATION + i];
        i += 1;
    }
    Some(SnapHeader {
        epoch: get_u32(h, SNAP_OFF_EPOCH),
        generation,
        chunk_index: get_u64(h, SNAP_OFF_INDEX),
        flags: h[SNAP_OFF_FLAGS],
        ct_len,
    })
}

// ── Key labels ──────────────────────────────────────────────────────────

/// Longest master label this file writes.
pub const MASTER_LABEL_CAP: usize = 32;

fn hex_digits(out: &mut [u8], at: usize, v: u32, nibbles: usize) -> usize {
    let mut i = 0;
    while i < nibbles {
        let shift = (nibbles - 1 - i) * 4;
        let n = ((v >> shift) & 0xF) as u8;
        out[at + i] = if n < 10 { b'0' + n } else { b'a' + n - 10 };
        i += 1;
    }
    at + nibbles
}

/// The vault label epoch `epoch`'s durability master is filed under:
/// `wal/p<partition:4hex>/r<replica:2hex>/e<epoch:8hex>`.
///
/// One master per partition group and replica, so a group owns every
/// key its records name and retires them on its own evidence. The
/// vault files labels under the calling module's type, so another
/// module cannot reach them.
pub fn master_label(
    partition: u16,
    replica: u8,
    epoch: u32,
    out: &mut [u8; MASTER_LABEL_CAP],
) -> usize {
    let mut at = put(out, 0, b"wal/p");
    at = hex_digits(out, at, u32::from(partition), 4);
    at = put(out, at, b"/r");
    at = hex_digits(out, at, u32::from(replica), 2);
    at = put(out, at, b"/e");
    hex_digits(out, at, epoch, 8)
}

// ── KEY_VAULT client ────────────────────────────────────────────────────

/// Open epoch `epoch`'s persisted master (`KDF_KEY`), generating it when
/// `create`. Returns the handle or a negative errno (`-ENOENT` when
/// absent and not created).
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn open_master(sys: &SyscallTable, label: &[u8], create: bool) -> i32 {
    if label.is_empty() || label.len() > MASTER_LABEL_CAP {
        return -22;
    }
    let mut arg = [0u8; 8 + MASTER_LABEL_CAP + 12];
    put(&mut arg, 0, &kv::suite::KDF_KEY.to_le_bytes());
    put(
        &mut arg,
        2,
        &(kv::usage::DERIVE | kv::usage::PERSIST).to_le_bytes(),
    );
    arg[7] = label.len() as u8;
    put(&mut arg, 8, label);
    let n = 8 + label.len() + 12;
    let op = if create {
        kv::OPEN_OR_GENERATE
    } else {
        kv::OPEN
    };
    (sys.provider_call)(-1, op, arg.as_mut_ptr(), n)
}

/// Whether the vault will give `handle` back after a restart. A master
/// that will not is refused: every record sealed under it would be
/// unreadable at the next boot.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn persisted(sys: &SyscallTable, handle: i32) -> bool {
    let mut d = [0u8; 8];
    let rc = (sys.provider_call)(handle, kv::DESCRIBE, d.as_mut_ptr(), d.len());
    rc >= 8 && d[7] != 0
}

/// Destroy the persisted master filed under `label`.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn destroy_label(sys: &SyscallTable, label: &[u8]) -> i32 {
    if label.is_empty() || label.len() > MASTER_LABEL_CAP {
        return -22;
    }
    let mut arg = [0u8; 1 + MASTER_LABEL_CAP];
    arg[0] = label.len() as u8;
    put(&mut arg, 1, label);
    (sys.provider_call)(-1, kv::DESTROY_BY_LABEL, arg.as_mut_ptr(), 1 + label.len())
}

/// `DERIVE` a purpose key from `master`: a fresh handle the caller owns
/// and destroys.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn derive(
    sys: &SyscallTable,
    master: i32,
    suite: u16,
    usage: u32,
    label: &[u8],
    context: &[u8],
) -> i32 {
    use kv::derive as d;
    const LABEL_CAP: usize = 32;
    const CONTEXT_CAP: usize = 64;
    if label.len() > LABEL_CAP || context.len() > CONTEXT_CAP {
        return -22;
    }
    let mut arg = [0u8; d::LABEL + LABEL_CAP + CONTEXT_CAP];
    put(&mut arg, d::TARGET_SUITE, &suite.to_le_bytes());
    put(&mut arg, d::TARGET_USAGE, &usage.to_le_bytes());
    arg[d::LABEL_LEN] = label.len() as u8;
    put(
        &mut arg,
        d::CONTEXT_LEN,
        &(context.len() as u16).to_le_bytes(),
    );
    let at = put(&mut arg, d::LABEL, label);
    put(&mut arg, at, context);
    let n = d::LABEL + label.len() + context.len();
    (sys.provider_call)(master, kv::DERIVE, arg.as_mut_ptr(), n)
}

/// Destroy a derived handle.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn destroy(sys: &SyscallTable, handle: i32) {
    if handle >= 0 {
        (sys.provider_call)(handle, kv::DESTROY, core::ptr::null_mut(), 0);
    }
}

/// Outcome of one in-place AEAD call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Aead {
    Ok,
    /// The tag did not verify; the buffer was zeroed by the vault.
    AuthFailed,
    /// The vault refused the request before touching it.
    Refused(i32),
}

/// Seal (`seal`) or open `len` bytes at `data` in place under `key`,
/// the 16-byte tag at `tag`.
///
/// # Safety
/// `sys` must reach live kernel routines; `data` must be valid for `len`
/// bytes and `tag` for 16, neither aliasing `aad` or `nonce`.
pub unsafe fn aead(
    sys: &SyscallTable,
    key: i32,
    seal: bool,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: *mut u8,
    len: usize,
    tag: *mut u8,
) -> Aead {
    use kv::units as u;
    let mut arg = [0u8; u::HEADER_LEN + u::ENTRY_LEN];
    put(&mut arg, u::COUNT, &1u16.to_le_bytes());
    let e = u::HEADER_LEN;
    put(&mut arg, e + u::NONCE, nonce);
    put(&mut arg, e + u::AAD_LEN, &(aad.len() as u16).to_le_bytes());
    put(
        &mut arg,
        e + u::AAD_PTR,
        &(aad.as_ptr() as u64).to_le_bytes(),
    );
    put(&mut arg, e + u::DATA_PTR, &(data as u64).to_le_bytes());
    put(&mut arg, e + u::DATA_LEN, &(len as u32).to_le_bytes());
    put(&mut arg, e + u::TAG_PTR, &(tag as u64).to_le_bytes());
    let op = if seal {
        kv::AEAD_SEAL_UNITS
    } else {
        kv::AEAD_OPEN_UNITS
    };
    let rc = (sys.provider_call)(key, op, arg.as_mut_ptr(), arg.len());
    if rc < 0 {
        Aead::Refused(rc)
    } else if rc == 0 && arg[e + u::STATUS] == 0 {
        Aead::Ok
    } else {
        Aead::AuthFailed
    }
}

/// HMAC-SHA256 of `msg` under the HMAC handle `key` (`SIGN`, raw mode).
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn hmac(sys: &SyscallTable, key: i32, msg: &[u8], out: &mut [u8; 32]) -> bool {
    const MSG_CAP: usize = 256;
    if msg.len() > MSG_CAP {
        return false;
    }
    let mut arg = [0u8; 6 + MSG_CAP + 12];
    arg[0] = kv::sign_mode::RAW;
    put(&mut arg, 2, &(msg.len() as u32).to_le_bytes());
    let t = put(&mut arg, 6, msg);
    put(&mut arg, t, &(out.as_mut_ptr() as u64).to_le_bytes());
    put(&mut arg, t + 8, &32u16.to_le_bytes());
    (sys.provider_call)(key, kv::SIGN, arg.as_mut_ptr(), t + 12) >= 0
}

/// Check an HMAC-SHA256 tag inside the vault (`VERIFY` against the
/// slot), so the comparison is the vault's constant-time one.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn hmac_verify(sys: &SyscallTable, key: i32, msg: &[u8], tag: &[u8; 32]) -> bool {
    const MSG_CAP: usize = 256;
    if msg.len() > MSG_CAP {
        return false;
    }
    let mut arg = [0u8; 8 + MSG_CAP + 32];
    put(&mut arg, 0, &(msg.len() as u16).to_le_bytes());
    put(&mut arg, 2, &32u16.to_le_bytes());
    let at = put(&mut arg, 8, msg);
    put(&mut arg, at, tag);
    (sys.provider_call)(key, kv::VERIFY, arg.as_mut_ptr(), at + 32) == 1
}

/// Whether the vault can hold keys of `vault_suite`.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn suite_offered(sys: &SyscallTable, vault_suite: u16) -> bool {
    let mut q = [0u8; 14];
    put(&mut q, 0, &vault_suite.to_le_bytes());
    (sys.provider_call)(-1, kv::SUITE_QUERY, q.as_mut_ptr(), q.len()) >= 0
}

/// Fill `out` from the platform CSPRNG.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn random_fill(sys: &SyscallTable, out: &mut [u8]) -> bool {
    (sys.provider_call)(
        -1,
        crate::abi::kernel_abi::RANDOM_FILL,
        out.as_mut_ptr(),
        out.len(),
    ) == 0
}
