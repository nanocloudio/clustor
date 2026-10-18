//! wal_seal — sealing for the WAL: sealed frames, the nonce-domain
//! allocator and key epochs.
//!
//! Selected by the durability `aead` parameter (the v1 suite id: 1 =
//! ChaCha20-Poly1305, 2 = AES-256-GCM). With it at 0 nothing here runs
//! and the WAL writes its cleartext `[len][crc][payload]` frames.
//!
//! Sealed, every entry is one v1 WAL frame (`sealed_record.rs`) under a
//! per-incarnation key `DERIVE`d from this group's persisted master for
//! the current key epoch. The Raft-visible payload (`term ‖ index ‖
//! entry`) is the frame's plaintext, so every consumer above the WAL
//! sees exactly the bytes it sees unsealed.
//!
//! ## Nonce domain
//!
//! A frame's nonce is `"WAL0" ‖ frame sequence`, unique because its key
//! is unique to one incarnation, and an incarnation is never reused:
//!
//! - an incarnation is `salt(8) ‖ counter(8)`. The counter comes from a
//!   durably reserved range in the allocator state (reserved ahead in
//!   strides, so a range is written before any incarnation in it is
//!   used); the salt is drawn from the platform CSPRNG at each writer
//!   start, so even a whole-device rollback of state and segments
//!   together does not repeat an incarnation except with 2^-64 odds;
//! - a segment opens a fresh incarnation, and so does every truncation
//!   (the writer then rewrites indices and offsets it used before);
//! - a writer never resumes an incarnation after a restart: recovery
//!   always appends to a new segment, so the frame sequence needs no
//!   durable reservation of its own. It is assigned at staging, before
//!   any acknowledgement, and an exhausted sequence closes the
//!   incarnation rather than wrapping;
//! - a staged frame is sealed once and its bytes are retained until
//!   the write lands, so a retry after an unknown outcome writes the
//!   identical ciphertext.
//!
//! ## Allocator state
//!
//! Two slot files (`wal/p<NNNN>_seal<0|1>`, `<p>SEAL<0|1>.WAL` at the FS
//! root) hold the A/B record below; the higher valid generation wins
//! and a write goes to the other slot, so a torn write loses at most
//! the record being written. Each record is HMAC-SHA256 authenticated
//! under a key derived from the master of the epoch it names.
//!
//! ```text
//! 0   4   magic "CLWS"
//! 4   4   reserved, zero
//! 8   8   generation
//! 16  4   current key epoch
//! 20  2   suite
//! 22  2   reserved, zero
//! 24  8   incarnation counter reserved through (exclusive)
//! 32  16  cluster
//! 48  8   partition
//! 56  8   replica
//! 64  4   oldest key epoch still live
//! 68  4   epoch mark count
//! 72  64  epoch marks: 8 × [epoch:u32][first segment:u32]
//! 136 8   reserved, zero
//! 144 32  HMAC-SHA256 over 0..144
//! ```
//!
//! A replay that finds an incarnation at or past the reserved counter,
//! or a frame under a later epoch than the state names, has media newer
//! than the allocator: the state was rolled back or lost a write. The
//! writer then creates a new key epoch before its first append, so no
//! nonce the stale state could hand out again is ever used under a key
//! that sealed anything before.
//!
//! ## Replay verdicts
//!
//! - a zero discriminator is the clean end of a segment;
//! - an incomplete prefix, a frame running past the file, or a CRC32C
//!   mismatch is a torn append: replay stops at the previous frame and
//!   no later segment is acked (the cleartext rule);
//! - a complete frame whose CRC holds and whose tag fails, whose header
//!   lengths disagree, or whose epoch's master is unavailable, fails the
//!   replica closed: replay never completes and nothing is acked past
//!   the last authenticated frame. CRC never substitutes for the tag;
//! - a repeated or backwards `(incarnation, sequence)` is a nonce
//!   conflict and fails the replica closed.
//!
//! ## Key epochs
//!
//! Masters are persisted vault `KDF_KEY`s labelled per group, replica
//! and epoch (`sealed_record::master_label`). A rotation (the keys
//! component's timer, or a stale allocator) takes effect at the next
//! segment boundary: the new master is created, then the state naming
//! it is written durably, then the first frame under it is sealed. A
//! master is destroyed only once no retained segment and no retained
//! snapshot names its epoch, and only after the state recording that is
//! durable.

use super::fs_step::{self, later, Io};
use super::sealed as sr;
use super::{
    dev_log, end_replay_segment, fence_wal_dir, note_config, note_ledger_ack, publish_name,
    record_entry_loc, wal_frame, wire, wire_channels, write_part, Step, Wal, FS_CLOSE, FS_FSYNC,
    FS_MKDIR, FS_OPEN, FS_OPEN_CREATE, FS_WRITE, STEP_BURST, WAL_PATH_MAX,
};
use crate::abi::contracts::key_vault as kv;
use crate::abi::SyscallTable;

/// Incarnations reserved per allocator write.
pub const INCARNATION_STRIDE: u64 = 64;
/// Epoch marks the allocator state carries: the live epochs of one
/// group. A rotation that would need a ninth waits for compaction.
pub const MAX_MARKS: usize = 8;
/// Masters of older epochs held open for reading at once.
const MASTER_CACHE: usize = 4;
/// Incarnations remembered by replay to catch one reappearing in a
/// later segment.
const SEEN_INCARNATIONS: usize = 16;

pub const STATE_LEN: usize = 176;
const STATE_MAC_OFF: usize = 144;
const STATE_MAGIC: [u8; 4] = *b"CLWS";
/// Purpose label of the allocator-state MAC key.
const STATE_LABEL: &[u8] = b"clustor/wal-state";

/// Lifecycle.
pub const PHASE_LOAD: u8 = 0;
pub const PHASE_READY: u8 = 1;
pub const PHASE_FAULT: u8 = 2;

/// Why a sealed WAL failed closed.
pub mod fault {
    pub const NONE: u8 = 0;
    /// A complete frame did not authenticate.
    pub const TAG: u8 = 1;
    /// A key epoch's master could not be opened.
    pub const KEY: u8 = 2;
    /// Allocator state exists and no copy authenticates.
    pub const STATE: u8 = 3;
    /// An `(incarnation, sequence)` tuple repeated or went backwards.
    pub const NONCE: u8 = 4;
    /// Segments exist but no allocator state does: a cleartext WAL, or
    /// state that was removed. Neither is read as sealed.
    pub const MISMATCH: u8 = 5;
    /// The vault refused: suite not offered, master not persisted, no
    /// slot, or an unknown `aead` value.
    pub const VAULT: u8 = 6;
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EpochMark {
    pub epoch: u32,
    pub first_segment: u32,
}

impl EpochMark {
    const fn zero() -> Self {
        Self {
            epoch: 0,
            first_segment: 0,
        }
    }
}

#[repr(C)]
pub struct WalSeal {
    /// v1 suite id from the `aead` parameter; 0 = unsealed.
    pub suite: u16,
    /// `cluster` parameter, zero-padded.
    pub cluster: [u8; sr::CLUSTER_LEN],
    pub phase: u8,
    pub fault: u8,

    // Allocator state as last written or adopted.
    state_gen: u64,
    state_slot: u8,
    /// The state was created at this boot: no earlier writer existed.
    fresh: bool,
    pub epoch: u32,
    inc_reserved: u64,
    oldest_epoch: u32,
    marks: [EpochMark; MAX_MARKS],
    mark_count: u8,

    /// Current epoch's master.
    master: i32,
    /// Older epochs' masters opened for reading: `(epoch, handle)`.
    masters: [(u32, i32); MASTER_CACHE],
    salt: [u8; 8],
    inc_next: u64,

    /// The writer's open incarnation, its key and next sequence.
    write_open: bool,
    write_inc: [u8; sr::INCARNATION_LEN],
    write_key: i32,
    write_epoch: u32,
    write_seq: u64,

    /// Last key derived for a read: `(epoch, incarnation) → handle`.
    read_key: i32,
    read_epoch: u32,
    read_inc: [u8; sr::INCARNATION_LEN],

    /// A new key epoch is wanted at the next segment boundary.
    pub rotate_requested: bool,
    /// Media is newer than the allocator state: no append until a new
    /// epoch exists.
    stale: bool,

    // Replay's view of the nonce domain.
    last_inc: [u8; sr::INCARNATION_LEN],
    last_seq: u64,
    have_last: bool,
    max_counter_seen: u64,
    max_epoch_seen: u32,
    seen: [[u8; sr::INCARNATION_LEN]; SEEN_INCARNATIONS],
    seen_count: u8,
    seen_head: u8,
    /// A non-empty segment has been opened by replay.
    saw_segment: bool,
    /// Replay authenticated at least one frame (`max_counter_seen` and
    /// `max_epoch_seen` are meaningful).
    saw_frame: bool,

    /// Epoch of the retained local snapshot (0 = none), fed by the
    /// composite: its master must outlive every segment's.
    pub snapshot_epoch: u32,

    pub tag_failures: u32,
    pub nonce_conflicts: u32,
    pub rotations: u32,
    pub rotations_refused: u32,
    pub incarnations: u32,
    pub state_writes: u32,
    pub retired_epochs: u32,

    // ── Non-blocking fs: allocator-state I/O in flight ──────────────
    /// Boot load phase (`LD_*`) and what each slot read found.
    ld_phase: u8,
    ld_a: SlotRead,
    ld_b: SlotRead,
    /// The slot read in flight: descriptor, bytes, buffer.
    rd_fd: i32,
    rd_got: u16,
    rd_buf: [u8; STATE_LEN],
    /// The state write in flight (`SW_*`): descriptor, bytes written, the
    /// slot, whether the parent self-heal was tried, the record and
    /// effects it adopts, and its encoded bytes.
    sw_phase: u8,
    sw_fd: i32,
    sw_moved: u16,
    sw_slot: u8,
    sw_mkdir: bool,
    sw_rec: Record,
    sw_fx: Effects,
    sw_buf: [u8; STATE_LEN],
    /// A rotation's new master, held while its state write is undecided.
    rot_h: i32,
}

pub fn init(z: &mut WalSeal) {
    z.suite = 0;
    z.cluster = [0; sr::CLUSTER_LEN];
    z.phase = PHASE_LOAD;
    z.fault = fault::NONE;
    z.state_gen = 0;
    z.state_slot = 1;
    z.fresh = false;
    z.epoch = 0;
    z.inc_reserved = 0;
    z.oldest_epoch = 0;
    z.marks = [EpochMark::zero(); MAX_MARKS];
    z.mark_count = 0;
    z.master = -1;
    z.masters = [(0, -1); MASTER_CACHE];
    z.salt = [0; 8];
    z.inc_next = 0;
    z.write_open = false;
    z.write_inc = [0; sr::INCARNATION_LEN];
    z.write_key = -1;
    z.write_epoch = 0;
    z.write_seq = 0;
    z.read_key = -1;
    z.read_epoch = 0;
    z.read_inc = [0; sr::INCARNATION_LEN];
    z.rotate_requested = false;
    z.stale = false;
    z.last_inc = [0; sr::INCARNATION_LEN];
    z.last_seq = 0;
    z.have_last = false;
    z.max_counter_seen = 0;
    z.max_epoch_seen = 0;
    z.seen = [[0; sr::INCARNATION_LEN]; SEEN_INCARNATIONS];
    z.seen_count = 0;
    z.seen_head = 0;
    z.saw_segment = false;
    z.saw_frame = false;
    z.snapshot_epoch = 0;
    z.tag_failures = 0;
    z.nonce_conflicts = 0;
    z.rotations = 0;
    z.rotations_refused = 0;
    z.incarnations = 0;
    z.state_writes = 0;
    z.retired_epochs = 0;
    z.ld_phase = LD_SLOT0;
    z.ld_a = SlotRead::Absent;
    z.ld_b = SlotRead::Absent;
    z.rd_fd = -1;
    z.rd_got = 0;
    z.rd_buf = [0; STATE_LEN];
    z.sw_phase = SW_IDLE;
    z.sw_fd = -1;
    z.sw_moved = 0;
    z.sw_slot = 0;
    z.sw_mkdir = false;
    z.sw_rec = Record {
        gen: 0,
        epoch: 0,
        suite: 0,
        inc_reserved: 0,
        oldest_epoch: 0,
        marks: [EpochMark::zero(); MAX_MARKS],
        mark_count: 0,
    };
    z.sw_fx = NO_EFFECTS;
    z.sw_buf = [0; STATE_LEN];
    z.rot_h = -1;
}

/// Whether this WAL seals its frames.
#[inline]
pub fn enabled(s: &Wal) -> bool {
    s.seal.suite != 0 && !s.no_fs
}

/// Stored bytes one entry of `payload_len` bytes occupies.
#[inline]
pub fn frame_len(s: &Wal, payload_len: usize) -> usize {
    if enabled(s) {
        sr::wal_frame_len(payload_len)
    } else {
        wal_frame::FRAME_HDR + payload_len
    }
}

/// Bytes between a frame's start and its payload (the ciphertext when
/// sealed).
#[inline]
pub fn payload_lead(s: &Wal) -> u32 {
    if enabled(s) {
        sr::WAL_HDR_LEN as u32
    } else {
        wal_frame::FRAME_HDR as u32
    }
}

/// Bytes after a frame's payload.
#[inline]
pub fn payload_trail(s: &Wal) -> u32 {
    if enabled(s) {
        sr::WAL_TRAILER_LEN as u32
    } else {
        0
    }
}

/// The group and replica a WAL's keys and records belong to.
#[derive(Clone, Copy)]
pub struct Who {
    pub partition: u16,
    pub replica: u8,
}

#[inline]
pub fn who(s: &Wal) -> Who {
    Who {
        partition: s.partition_id,
        replica: s.self_id,
    }
}

fn identity(z: &WalSeal, w: Who) -> sr::Identity {
    sr::Identity {
        cluster: z.cluster,
        partition: u64::from(w.partition),
        replica: u64::from(w.replica),
    }
}

fn counter_of(inc: &[u8; sr::INCARNATION_LEN]) -> u64 {
    u64::from_le_bytes([
        inc[8], inc[9], inc[10], inc[11], inc[12], inc[13], inc[14], inc[15],
    ])
}

unsafe fn fail(s: &mut Wal, sys: &SyscallTable, why: u8, msg: &[u8]) {
    if s.seal.phase != PHASE_FAULT {
        s.seal.phase = PHASE_FAULT;
        s.seal.fault = why;
        dev_log(sys, 1, msg.as_ptr(), msg.len());
    }
    // Nothing more is written or acknowledged: the log has a record that
    // cannot be trusted, or no safe nonce domain to write in.
    s.fence_failed = true;
}

/// The replica failed closed for a sealing reason.
#[inline]
pub fn faulted(s: &Wal) -> bool {
    s.seal.phase == PHASE_FAULT
}

// ── Masters and keys ────────────────────────────────────────────────────

fn master_label(w: Who, epoch: u32, out: &mut [u8; sr::MASTER_LABEL_CAP]) -> usize {
    sr::master_label(w.partition, w.replica, epoch, out)
}

/// Open (or create) epoch `epoch`'s master and check the vault will
/// keep it. A handle the vault would not give back after a restart is
/// refused: records sealed under it would not survive the boot.
unsafe fn open_master(w: Who, sys: &SyscallTable, epoch: u32, create: bool) -> i32 {
    let mut label = [0u8; sr::MASTER_LABEL_CAP];
    let n = master_label(w, epoch, &mut label);
    let h = sr::open_master(sys, &label[..n], create);
    if h < 0 {
        return h;
    }
    if !sr::persisted(sys, h) {
        return -5;
    }
    h
}

/// The master for `epoch`, opening it for reading when it is not the
/// current one. Negative when the vault has no such key.
unsafe fn master_for(z: &mut WalSeal, w: Who, sys: &SyscallTable, epoch: u32) -> i32 {
    if epoch == z.epoch && z.master >= 0 {
        return z.master;
    }
    for i in 0..MASTER_CACHE {
        if z.masters[i].1 >= 0 && z.masters[i].0 == epoch {
            return z.masters[i].1;
        }
    }
    let h = open_master(w, sys, epoch, false);
    if h < 0 {
        return h;
    }
    // Evict the oldest cached epoch when full. The handle is this
    // module's, and nothing else holds it across a step.
    let mut slot = 0;
    let mut lowest = u32::MAX;
    for i in 0..MASTER_CACHE {
        if z.masters[i].1 < 0 {
            slot = i;
            break;
        }
        if z.masters[i].0 < lowest {
            lowest = z.masters[i].0;
            slot = i;
        }
    }
    if z.masters[slot].1 >= 0 {
        sr::destroy(sys, z.masters[slot].1);
    }
    z.masters[slot] = (epoch, h);
    h
}

fn vault_suite(z: &WalSeal) -> u16 {
    sr::vault_suite(z.suite).unwrap_or(0)
}

/// The key sealing `(epoch, incarnation)`, derived when not cached.
unsafe fn key_for(
    z: &mut WalSeal,
    w: Who,
    sys: &SyscallTable,
    epoch: u32,
    inc: &[u8; sr::INCARNATION_LEN],
) -> i32 {
    if z.write_open && z.write_epoch == epoch && z.write_inc == *inc {
        return z.write_key;
    }
    if z.read_key >= 0 && z.read_epoch == epoch && z.read_inc == *inc {
        return z.read_key;
    }
    let master = master_for(z, w, sys, epoch);
    if master < 0 {
        return master;
    }
    let ctx = sr::wal_context(&identity(z, w), epoch, inc);
    let usage = kv::usage::SEAL | kv::usage::OPEN;
    let k = sr::derive(sys, master, vault_suite(z), usage, sr::WAL_LABEL, &ctx);
    if k < 0 {
        return k;
    }
    sr::destroy(sys, z.read_key);
    z.read_key = k;
    z.read_epoch = epoch;
    z.read_inc = *inc;
    k
}

/// Drop the writer's incarnation. The next append opens a new one: a
/// segment rotation, a truncation, or an exhausted sequence.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn close_incarnation(s: &mut Wal, sys: &SyscallTable) {
    if s.seal.write_open {
        sr::destroy(sys, s.seal.write_key);
        s.seal.write_key = -1;
        s.seal.write_open = false;
    }
}

// ── Allocator state ─────────────────────────────────────────────────────

fn state_path(partition_id: u16, root: bool, slot: u8, out: &mut [u8; WAL_PATH_MAX]) -> usize {
    let mut i = 0usize;
    let hex = |n: u8| if n < 10 { b'0' + n } else { b'a' + n - 10 };
    if root {
        out[i] = hex((partition_id & 0xF) as u8);
        i += 1;
        for &b in b"SEAL" {
            out[i] = b;
            i += 1;
        }
        out[i] = b'0' + (slot & 1);
        i += 1;
        for &b in b".WAL" {
            out[i] = b;
            i += 1;
        }
        return i;
    }
    for &b in b"wal/p" {
        out[i] = b;
        i += 1;
    }
    for digit in (0..4).rev() {
        out[i] = hex(((partition_id >> (digit * 4)) & 0xF) as u8);
        i += 1;
    }
    for &b in b"_seal" {
        out[i] = b;
        i += 1;
    }
    out[i] = b'0' + (slot & 1);
    i + 1
}

/// The fields of one allocator record.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Record {
    gen: u64,
    epoch: u32,
    suite: u16,
    inc_reserved: u64,
    oldest_epoch: u32,
    marks: [EpochMark; MAX_MARKS],
    mark_count: u8,
}

fn encode_record(s: &Wal, r: &Record, out: &mut [u8; STATE_LEN]) {
    *out = [0; STATE_LEN];
    out[0..4].copy_from_slice(&STATE_MAGIC);
    out[8..16].copy_from_slice(&r.gen.to_le_bytes());
    out[16..20].copy_from_slice(&r.epoch.to_le_bytes());
    out[20..22].copy_from_slice(&r.suite.to_le_bytes());
    out[24..32].copy_from_slice(&r.inc_reserved.to_le_bytes());
    out[32..48].copy_from_slice(&s.seal.cluster);
    out[48..56].copy_from_slice(&u64::from(s.partition_id).to_le_bytes());
    out[56..64].copy_from_slice(&u64::from(s.self_id).to_le_bytes());
    out[64..68].copy_from_slice(&r.oldest_epoch.to_le_bytes());
    out[68..72].copy_from_slice(&u32::from(r.mark_count).to_le_bytes());
    for i in 0..(r.mark_count as usize).min(MAX_MARKS) {
        let at = 72 + i * 8;
        out[at..at + 4].copy_from_slice(&r.marks[i].epoch.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&r.marks[i].first_segment.to_le_bytes());
    }
}

fn rd_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn rd_u64(b: &[u8], at: usize) -> u64 {
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

/// Parse a record's fields, refusing one for another group, replica or
/// cluster, or with non-zero reserved bytes. Its MAC is checked apart.
fn decode_record(s: &Wal, b: &[u8; STATE_LEN]) -> Option<Record> {
    if b[0..4] != STATE_MAGIC
        || rd_u32(b, 4) != 0
        || b[22] != 0
        || b[23] != 0
        || rd_u64(b, 136) != 0
        || b[32..48] != s.seal.cluster
        || rd_u64(b, 48) != u64::from(s.partition_id)
        || rd_u64(b, 56) != u64::from(s.self_id)
    {
        return None;
    }
    let mark_count = rd_u32(b, 68);
    if mark_count as usize > MAX_MARKS {
        return None;
    }
    let mut marks = [EpochMark::zero(); MAX_MARKS];
    for (i, m) in marks.iter_mut().enumerate().take(mark_count as usize) {
        let at = 72 + i * 8;
        m.epoch = rd_u32(b, at);
        m.first_segment = rd_u32(b, at + 4);
    }
    Some(Record {
        gen: rd_u64(b, 8),
        epoch: rd_u32(b, 16),
        suite: u16::from_le_bytes([b[20], b[21]]),
        inc_reserved: rd_u64(b, 24),
        oldest_epoch: rd_u32(b, 64),
        marks,
        mark_count: mark_count as u8,
    })
}

/// The allocator-state MAC key under `master`.
unsafe fn state_key(s: &Wal, sys: &SyscallTable, master: i32) -> i32 {
    let mut ctx = [0u8; 32];
    ctx[0..16].copy_from_slice(&s.seal.cluster);
    ctx[16..24].copy_from_slice(&u64::from(s.partition_id).to_le_bytes());
    ctx[24..32].copy_from_slice(&u64::from(s.self_id).to_le_bytes());
    sr::derive(
        sys,
        master,
        kv::suite::HMAC_SHA256,
        kv::usage::SIGN | kv::usage::VERIFY,
        STATE_LABEL,
        &ctx,
    )
}

/// Why a slot file holds no usable record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotErr {
    /// Not an authentic record for this group.
    Bad,
    /// It names an epoch whose master the vault does not have.
    Key,
}

/// What reading one slot found.
#[derive(Clone, Copy)]
enum SlotRead {
    /// The slot file does not exist.
    Absent,
    Found(Record),
    Err(SlotErr),
}

// Boot-load phases (`ld_phase`).
const LD_SLOT0: u8 = 0;
const LD_SLOT1: u8 = 1;
const LD_PICK: u8 = 2;
const LD_FRESH: u8 = 3;

// Allocator-state write phases (`sw_phase`).
const SW_IDLE: u8 = 0;
const SW_OPEN: u8 = 1;
const SW_MKDIR: u8 = 2;
const SW_WRITE: u8 = 3;
const SW_FSYNC: u8 = 4;
const SW_NAME: u8 = 5;

/// What adopting a state write does besides adopting its record. Carried
/// by the write itself, so whichever step finishes it — the caller that
/// started it, or the per-step drive — leaves the allocator consistent.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Effects {
    /// The new epoch's master to make current (rotation), or -1.
    set_master: i32,
    /// The next incarnation counter to adopt (a reservation), or `u64::MAX`.
    set_inc_next: u64,
    /// Masters of epochs `retire_from..retire_to` to destroy (retirement).
    retire_from: u32,
    retire_to: u32,
    /// The state is created at this boot.
    fresh: bool,
}

const NO_EFFECTS: Effects = Effects {
    set_master: -1,
    set_inc_next: u64::MAX,
    retire_from: 0,
    retire_to: 0,
    fresh: false,
};

/// Read slot `slot`, resumably: the open and the read are re-asked until
/// answered (`None` meanwhile). `Absent` only for an answered "no such
/// file"; `Err` when the file exists and does not hold an authentic
/// record for this group.
unsafe fn read_slot(s: &mut Wal, sys: &SyscallTable, slot: u8) -> Option<SlotRead> {
    if s.seal.rd_fd < 0 {
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = state_path(s.partition_id, s.root_path != 0, slot, &mut path);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if later(fd) {
            return None;
        }
        if fd < 0 {
            return Some(SlotRead::Absent);
        }
        s.seal.rd_fd = fd;
        s.seal.rd_got = 0;
    }
    let mut got = s.seal.rd_got as usize;
    let io = fs_step::read_into(
        sys.provider_call,
        s.seal.rd_fd,
        s.seal.rd_buf.as_mut_ptr(),
        STATE_LEN,
        &mut got,
    );
    s.seal.rd_got = got as u16;
    if io == Io::Later {
        return None;
    }
    (sys.provider_call)(s.seal.rd_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    s.seal.rd_fd = -1;
    if io != Io::Done {
        return Some(SlotRead::Err(SlotErr::Bad));
    }
    let b = s.seal.rd_buf;
    let Some(r) = decode_record(s, &b) else {
        return Some(SlotRead::Err(SlotErr::Bad));
    };
    let w = who(s);
    let master = master_for(&mut s.seal, w, sys, r.epoch);
    if master < 0 {
        return Some(SlotRead::Err(SlotErr::Key));
    }
    let k = state_key(s, sys, master);
    if k < 0 {
        return Some(SlotRead::Err(SlotErr::Bad));
    }
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&b[STATE_MAC_OFF..STATE_LEN]);
    let ok = sr::hmac_verify(sys, k, &b[..STATE_MAC_OFF], &tag);
    sr::destroy(sys, k);
    if ok {
        Some(SlotRead::Found(r))
    } else {
        Some(SlotRead::Err(SlotErr::Bad))
    }
}

/// Write `r` (its generation one past the current) to the slot not
/// holding the current copy, durably, and adopt it with `fx`. The MAC is
/// taken under `mac_master` (or the record's epoch master when -1), which
/// must be open.
///
/// One state write is in flight at a time, as a step machine over `sw_*`:
/// the encoded, MAC'd bytes are fixed when it starts, every request is
/// re-asked unchanged until decided, and the record and its effects are
/// adopted only once its name fence answers. `Done` when THIS write
/// (record and effects) has been adopted; `Later` while it — or another
/// caller's write — is still in flight (the caller asks again next step,
/// and recomputes its record from the then-current state); `Fail` when
/// it was refused.
#[inline(never)]
unsafe fn write_state(
    s: &mut Wal,
    sys: &SyscallTable,
    r: &mut Record,
    fx: Effects,
    mac_master: i32,
) -> Step {
    r.gen = s.seal.state_gen.wrapping_add(1);
    if s.seal.sw_phase == SW_IDLE {
        let master = if mac_master >= 0 {
            mac_master
        } else {
            let w = who(s);
            master_for(&mut s.seal, w, sys, r.epoch)
        };
        if master < 0 {
            return Step::Fail;
        }
        let mut b = [0u8; STATE_LEN];
        encode_record(s, r, &mut b);
        let k = state_key(s, sys, master);
        if k < 0 {
            return Step::Fail;
        }
        let mut tag = [0u8; 32];
        let signed = sr::hmac(sys, k, &b[..STATE_MAC_OFF], &mut tag);
        sr::destroy(sys, k);
        if !signed {
            return Step::Fail;
        }
        b[STATE_MAC_OFF..STATE_LEN].copy_from_slice(&tag);
        s.seal.sw_buf = b;
        s.seal.sw_rec = *r;
        s.seal.sw_fx = fx;
        s.seal.sw_slot = s.seal.state_slot ^ 1;
        s.seal.sw_moved = 0;
        s.seal.sw_mkdir = false;
        s.seal.sw_phase = SW_OPEN;
    }
    let mine = s.seal.sw_rec == *r && s.seal.sw_fx == fx;
    if !mine {
        // Another write owns the slot; it is driven by its own caller and
        // by the per-step drive. Ask again once it is adopted.
        drive(s, sys);
        return Step::Later;
    }
    drive_state_write(s, sys)
}

/// Resume the in-flight state write, if any. Called every step, so a
/// write is finished — and its effects applied — whoever started it.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
pub unsafe fn drive(s: &mut Wal, sys: &SyscallTable) {
    if s.seal.sw_phase != SW_IDLE {
        let _ = drive_state_write(s, sys);
    }
}

/// Close the state write's descriptor and idle the machine.
unsafe fn sw_reset(s: &mut Wal, sys: &SyscallTable) {
    if s.seal.sw_fd >= 0 {
        (sys.provider_call)(s.seal.sw_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.seal.sw_fd = -1;
    }
    s.seal.sw_phase = SW_IDLE;
}

/// The state write was refused: nothing is adopted. A rotation's new
/// master, which no durable record names, is let go.
unsafe fn sw_refused(s: &mut Wal, sys: &SyscallTable) -> Step {
    sw_reset(s, sys);
    let h = s.seal.sw_fx.set_master;
    if h >= 0 {
        sr::destroy(sys, h);
        if s.seal.rot_h == h {
            s.seal.rot_h = -1;
        }
    }
    Step::Fail
}

#[inline(never)]
unsafe fn drive_state_write(s: &mut Wal, sys: &SyscallTable) -> Step {
    let mut path = [0u8; WAL_PATH_MAX];
    let plen = state_path(s.partition_id, s.root_path != 0, s.seal.sw_slot, &mut path);
    loop {
        match s.seal.sw_phase {
            SW_OPEN => {
                let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_mut_ptr(), plen);
                if later(fd) {
                    return Step::Later;
                }
                if fd < 0 {
                    if s.root_path == 0 && !s.seal.sw_mkdir {
                        // The first state write precedes the first segment,
                        // so it is the one that meets a missing `wal/`
                        // parent: create it and retry, as the segment opener
                        // does.
                        s.seal.sw_mkdir = true;
                        s.seal.sw_phase = SW_MKDIR;
                        continue;
                    }
                    return sw_refused(s, sys);
                }
                s.seal.sw_fd = fd;
                s.seal.sw_phase = SW_WRITE;
            }
            SW_MKDIR => {
                let mut dir = *b"wal";
                let rc = (sys.provider_call)(-1, FS_MKDIR, dir.as_mut_ptr(), dir.len());
                if later(rc) {
                    return Step::Later;
                }
                if rc == 0 {
                    // Minted here: fenced before the state inside it is
                    // adopted (`SW_NAME`).
                    s.dir_unfenced = true;
                }
                s.seal.sw_phase = SW_OPEN;
            }
            SW_WRITE => {
                let mut moved = s.seal.sw_moved as usize;
                let io = fs_step::write_from(
                    sys.provider_call,
                    FS_WRITE,
                    s.seal.sw_fd,
                    s.seal.sw_buf.as_ptr(),
                    STATE_LEN,
                    &mut moved,
                );
                s.seal.sw_moved = moved as u16;
                match io {
                    Io::Later => return Step::Later,
                    Io::Done => s.seal.sw_phase = SW_FSYNC,
                    Io::Fail(_) | Io::End => return sw_refused(s, sys),
                }
            }
            SW_FSYNC => {
                // Fenced before the close: CLOSE reports no write-back.
                let rc = (sys.provider_call)(s.seal.sw_fd, FS_FSYNC, core::ptr::null_mut(), 0);
                if later(rc) {
                    return Step::Later;
                }
                if rc != 0 {
                    return sw_refused(s, sys);
                }
                (sys.provider_call)(s.seal.sw_fd, FS_CLOSE, core::ptr::null_mut(), 0);
                s.seal.sw_fd = -1;
                s.seal.sw_phase = SW_NAME;
            }
            SW_NAME => match fence_wal_dir(s, sys) {
                Step::Later => return Step::Later,
                Step::Fail => return sw_refused(s, sys),
                Step::Done => match publish_name(s, sys, &mut path, plen) {
                    Step::Later => return Step::Later,
                    Step::Fail => return sw_refused(s, sys),
                    Step::Done => {
                        sw_reset(s, sys);
                        adopt_state(s, sys);
                        return Step::Done;
                    }
                },
            },
            _ => {
                sw_reset(s, sys);
                return Step::Later;
            }
        }
    }
}

/// The state write is durable under its fenced name: adopt its record
/// and apply its effects.
unsafe fn adopt_state(s: &mut Wal, sys: &SyscallTable) {
    let r = s.seal.sw_rec;
    let fx = s.seal.sw_fx;
    let old_master = s.seal.master;
    let old_epoch = s.seal.epoch;
    s.seal.state_slot = s.seal.sw_slot;
    s.seal.state_gen = r.gen;
    s.seal.epoch = r.epoch;
    s.seal.inc_reserved = r.inc_reserved;
    s.seal.oldest_epoch = r.oldest_epoch;
    s.seal.marks = r.marks;
    s.seal.mark_count = r.mark_count;
    s.seal.state_writes = s.seal.state_writes.saturating_add(1);
    if fx.fresh {
        s.seal.fresh = true;
    }
    if fx.set_inc_next != u64::MAX {
        s.seal.inc_next = fx.set_inc_next;
    }
    if fx.set_master >= 0 {
        // A rotation: the new master is current, and the old one is kept
        // readable for segments still sealed under it.
        s.seal.master = fx.set_master;
        if s.seal.rot_h == fx.set_master {
            s.seal.rot_h = -1;
        }
        let mut placed = false;
        for i in 0..MASTER_CACHE {
            if s.seal.masters[i].1 < 0 {
                s.seal.masters[i] = (old_epoch, old_master);
                placed = true;
                break;
            }
        }
        if !placed {
            sr::destroy(sys, old_master);
        }
        s.seal.inc_next = s.seal.inc_reserved;
        s.seal.rotations = s.seal.rotations.saturating_add(1);
        // The boundary the rotation was wanted at has been served.
        s.seal.rotate_requested = false;
        s.seal.stale = false;
        dev_log(sys, 3, b"[wal] seal epoch rotated".as_ptr(), 24);
    }
    if fx.retire_to > fx.retire_from {
        // Retirement: the floor naming no epoch below `retire_to` is
        // durable, so their masters may go.
        for epoch in fx.retire_from..fx.retire_to {
            for i in 0..MASTER_CACHE {
                if s.seal.masters[i].1 >= 0 && s.seal.masters[i].0 == epoch {
                    sr::destroy(sys, s.seal.masters[i].1);
                    s.seal.masters[i] = (0, -1);
                }
            }
            if s.seal.read_key >= 0 && s.seal.read_epoch == epoch {
                sr::destroy(sys, s.seal.read_key);
                s.seal.read_key = -1;
            }
            let mut label = [0u8; sr::MASTER_LABEL_CAP];
            let n = master_label(who(s), epoch, &mut label);
            sr::destroy_label(sys, &label[..n]);
            s.seal.retired_epochs = s.seal.retired_epochs.saturating_add(1);
        }
        dev_log(sys, 3, b"[wal] seal epoch retired".as_ptr(), 24);
    }
}

fn current_record(s: &Wal) -> Record {
    Record {
        gen: s.seal.state_gen,
        epoch: s.seal.epoch,
        suite: s.seal.suite,
        inc_reserved: s.seal.inc_reserved,
        oldest_epoch: s.seal.oldest_epoch,
        marks: s.seal.marks,
        mark_count: s.seal.mark_count,
    }
}

/// Record that `epoch` covers segments from `segment`. Marks stay in
/// ascending segment order; false when a new mark would not fit.
fn add_mark(r: &mut Record, epoch: u32, segment: u32) -> bool {
    let n = r.mark_count as usize;
    if n > 0 && r.marks[n - 1].epoch == epoch {
        return true;
    }
    if n > 0 {
        for i in 0..n {
            if r.marks[i].epoch == epoch {
                return true;
            }
        }
    }
    if n >= MAX_MARKS {
        return false;
    }
    r.marks[n] = EpochMark {
        epoch,
        first_segment: segment,
    };
    r.mark_count += 1;
    true
}

// ── Boot ────────────────────────────────────────────────────────────────

/// Load or create the allocator state and open the current master,
/// before replay reads a frame. `Some(rc)` while this owns the step
/// (including forever once failed closed), `None` once ready.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
pub unsafe fn boot_step(s: &mut Wal, sys: &SyscallTable) -> Option<i32> {
    match s.seal.phase {
        PHASE_READY => {
            drive(s, sys);
            None
        }
        PHASE_FAULT => Some(0),
        _ => {
            load(s, sys);
            Some(STEP_BURST)
        }
    }
}

/// The fresh allocator record this boot creates when no state exists.
fn fresh_record(s: &Wal) -> Record {
    let mut r = Record {
        gen: 0,
        epoch: 1,
        suite: s.seal.suite,
        inc_reserved: 0,
        oldest_epoch: 1,
        marks: [EpochMark::zero(); MAX_MARKS],
        mark_count: 0,
    };
    add_mark(&mut r, 1, 1);
    r
}

/// The boot load, resumed across steps: read slot 0, read slot 1 (each
/// re-asked until answered — an unanswered slot may hold the newer
/// generation), pick, and either adopt or durably create the state.
#[inline(never)]
unsafe fn load(s: &mut Wal, sys: &SyscallTable) {
    if s.seal.ld_phase == LD_SLOT0 {
        let Some(vsuite) = sr::vault_suite(s.seal.suite) else {
            fail(s, sys, fault::VAULT, b"[wal] seal: unknown aead suite");
            return;
        };
        if !sr::suite_offered(sys, vsuite) {
            fail(s, sys, fault::VAULT, b"[wal] seal: suite not offered");
            return;
        }
        let Some(a) = read_slot(s, sys, 0) else {
            return;
        };
        s.seal.ld_a = a;
        s.seal.ld_phase = LD_SLOT1;
    }
    if s.seal.ld_phase == LD_SLOT1 {
        let Some(b) = read_slot(s, sys, 1) else {
            return;
        };
        s.seal.ld_b = b;
        s.seal.ld_phase = LD_PICK;
    }
    if s.seal.ld_phase == LD_PICK {
        let pick = match (s.seal.ld_a, s.seal.ld_b) {
            (SlotRead::Found(x), SlotRead::Found(y)) => {
                Some(if y.gen > x.gen { (y, 1) } else { (x, 0) })
            }
            (SlotRead::Found(x), _) => Some((x, 0)),
            (_, SlotRead::Found(y)) => Some((y, 1)),
            (SlotRead::Absent, SlotRead::Absent) => None,
            (a, b) => {
                if matches!(a, SlotRead::Err(SlotErr::Key))
                    || matches!(b, SlotRead::Err(SlotErr::Key))
                {
                    fail(s, sys, fault::KEY, b"[wal] seal: key epoch unavailable");
                } else {
                    fail(s, sys, fault::STATE, b"[wal] seal: state unauthentic");
                }
                return;
            }
        };
        match pick {
            Some((r, slot)) => {
                if r.suite != s.seal.suite {
                    fail(
                        s,
                        sys,
                        fault::VAULT,
                        b"[wal] seal: suite differs from state",
                    );
                    return;
                }
                let h = open_master(who(s), sys, r.epoch, false);
                if h < 0 {
                    fail(s, sys, fault::KEY, b"[wal] seal: key epoch unavailable");
                    return;
                }
                s.seal.master = h;
                s.seal.state_gen = r.gen;
                s.seal.state_slot = slot;
                s.seal.epoch = r.epoch;
                s.seal.inc_reserved = r.inc_reserved;
                s.seal.oldest_epoch = r.oldest_epoch;
                s.seal.marks = r.marks;
                s.seal.mark_count = r.mark_count;
                // The cache may hold this epoch from the MAC check.
                for i in 0..MASTER_CACHE {
                    if s.seal.masters[i].1 == h {
                        s.seal.masters[i] = (0, -1);
                    }
                }
                finish_load(s, sys);
                return;
            }
            None => {
                let h = open_master(who(s), sys, 1, true);
                if h < 0 {
                    fail(s, sys, fault::VAULT, b"[wal] seal: master unavailable");
                    return;
                }
                s.seal.master = h;
                s.seal.epoch = 1;
                s.seal.state_gen = 0;
                s.seal.state_slot = 1;
                s.seal.ld_phase = LD_FRESH;
            }
        }
    }
    if s.seal.ld_phase == LD_FRESH {
        let mut r = fresh_record(s);
        let fx = Effects {
            fresh: true,
            ..NO_EFFECTS
        };
        match write_state(s, sys, &mut r, fx, -1) {
            Step::Later => {}
            Step::Fail => fail(s, sys, fault::STATE, b"[wal] seal: state write failed"),
            Step::Done => finish_load(s, sys),
        }
    }
}

/// The allocator state is in hand: draw the salt and become ready.
unsafe fn finish_load(s: &mut Wal, sys: &SyscallTable) {
    if !sr::random_fill(sys, &mut s.seal.salt) {
        fail(s, sys, fault::VAULT, b"[wal] seal: no random source");
        return;
    }
    // Everything below the reserved mark may have been issued by an
    // earlier writer; the next incarnation reserves a new range first.
    s.seal.inc_next = s.seal.inc_reserved;
    s.seal.phase = PHASE_READY;
    dev_log(sys, 3, b"[wal] seal ready".as_ptr(), 16);
}

/// A non-empty segment was opened by replay. Sealed segments without a
/// prior allocator state are not this WAL's to read.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
pub unsafe fn on_replay_segment(s: &mut Wal, sys: &SyscallTable) -> bool {
    s.seal.saw_segment = true;
    if s.seal.fresh {
        fail(
            s,
            sys,
            fault::MISMATCH,
            b"[wal] seal: segments without seal state",
        );
        return false;
    }
    true
}

/// Replay has finished: judge the allocator against the media.
pub fn after_replay(s: &mut Wal) {
    if s.seal.phase != PHASE_READY {
        return;
    }
    if s.seal.saw_frame
        && (s.seal.max_counter_seen >= s.seal.inc_reserved || s.seal.max_epoch_seen > s.seal.epoch)
    {
        s.seal.stale = true;
    }
    s.seal.have_last = false;
}

// ── Write path ──────────────────────────────────────────────────────────

/// A key epoch change is wanted and must happen at a segment boundary.
#[inline]
pub fn boundary_wanted(s: &Wal) -> bool {
    enabled(s) && (s.seal.rotate_requested || s.seal.stale)
}

/// Ask for a new key epoch at the next segment boundary.
pub fn request_rotation(s: &mut Wal) {
    if enabled(s) {
        s.seal.rotate_requested = true;
    }
}

/// Create the next epoch's master and durably name it current. The new
/// master is opened once and held (`rot_h`) across the steps its state
/// write takes; the rotation takes effect when that write is adopted
/// (`adopt_state`), and a refused write lets the master go.
#[inline(never)]
unsafe fn rotate_epoch(s: &mut Wal, sys: &SyscallTable) -> Step {
    let next = s.seal.epoch.max(s.seal.max_epoch_seen).saturating_add(1);
    if s.seal.rot_h < 0 {
        let h = open_master(who(s), sys, next, true);
        if h < 0 {
            return Step::Fail;
        }
        s.seal.rot_h = h;
    }
    let h = s.seal.rot_h;
    let mut r = current_record(s);
    r.epoch = next;
    if !add_mark(&mut r, next, s.segment_seq) {
        sr::destroy(sys, h);
        s.seal.rot_h = -1;
        return Step::Fail;
    }
    if s.seal.saw_frame && r.inc_reserved <= s.seal.max_counter_seen {
        r.inc_reserved = s.seal.max_counter_seen.saturating_add(1);
    }
    // The state's MAC is under the new master.
    let fx = Effects {
        set_master: h,
        ..NO_EFFECTS
    };
    write_state(s, sys, &mut r, fx, h)
}

/// Make the writer ready to seal the next frame: at a boundary, change
/// epoch if wanted; open an incarnation if none is open (reserving a
/// counter range durably first when the reserved one is used up).
/// Anything but `Done` holds the append: nothing is sealed, nothing
/// acknowledged. `Later` is a state write still undecided (not an
/// error); `Fail` a refusal.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
pub(super) unsafe fn ensure_writable(s: &mut Wal, sys: &SyscallTable) -> Step {
    if s.seal.phase != PHASE_READY {
        return Step::Fail;
    }
    if boundary_wanted(s) && s.cursor == 0 && !s.seal.write_open {
        let rotated = rotate_epoch(s, sys);
        if rotated == Step::Later {
            // The new epoch's state write is undecided: hold the append.
            return Step::Later;
        }
        if rotated == Step::Fail {
            s.seal.rotations_refused = s.seal.rotations_refused.saturating_add(1);
            if s.seal.stale {
                // Appending under the stale epoch could repeat a nonce.
                dev_log(
                    sys,
                    1,
                    b"[wal] seal: stale state, rotation failed".as_ptr(),
                    40,
                );
                return Step::Fail;
            }
        }
        s.seal.rotate_requested = false;
        s.seal.stale = false;
    }
    if s.seal.write_open && s.seal.write_seq == u64::MAX {
        close_incarnation(s, sys);
    }
    if s.seal.write_open {
        return Step::Done;
    }
    if s.seal.inc_next >= s.seal.inc_reserved {
        let mut r = current_record(s);
        let base = if s.seal.saw_frame {
            s.seal
                .inc_reserved
                .max(s.seal.max_counter_seen.saturating_add(1))
        } else {
            s.seal.inc_reserved
        };
        if base > u64::MAX - INCARNATION_STRIDE {
            // The counter never wraps: a new epoch gives a new key domain.
            s.seal.rotate_requested = true;
            return Step::Fail;
        }
        r.inc_reserved = base + INCARNATION_STRIDE;
        if !add_mark(&mut r, s.seal.epoch, s.segment_seq) {
            return Step::Fail;
        }
        // The reservation is durable before any incarnation of it seals a
        // frame; until its write is adopted the append is held.
        let fx = Effects {
            set_inc_next: base,
            ..NO_EFFECTS
        };
        match write_state(s, sys, &mut r, fx, -1) {
            Step::Done => {}
            other => return other,
        }
    } else {
        match mark_current(s, sys) {
            Step::Done => {}
            other => return other,
        }
    }
    let mut inc = [0u8; sr::INCARNATION_LEN];
    inc[0..8].copy_from_slice(&s.seal.salt);
    inc[8..16].copy_from_slice(&s.seal.inc_next.to_le_bytes());
    let ctx = sr::wal_context(&identity(&s.seal, who(s)), s.seal.epoch, &inc);
    let usage = kv::usage::SEAL | kv::usage::OPEN;
    let k = sr::derive(
        sys,
        s.seal.master,
        vault_suite(&s.seal),
        usage,
        sr::WAL_LABEL,
        &ctx,
    );
    if k < 0 {
        return Step::Fail;
    }
    s.seal.inc_next += 1;
    s.seal.write_open = true;
    s.seal.write_inc = inc;
    s.seal.write_key = k;
    s.seal.write_epoch = s.seal.epoch;
    s.seal.write_seq = 0;
    s.seal.incarnations = s.seal.incarnations.saturating_add(1);
    Step::Done
}

/// Make sure the state's marks cover the segment being written under
/// the current epoch, writing the state when they do not.
unsafe fn mark_current(s: &mut Wal, sys: &SyscallTable) -> Step {
    let n = s.seal.mark_count as usize;
    for i in 0..n {
        if s.seal.marks[i].epoch == s.seal.epoch {
            return Step::Done;
        }
    }
    let mut r = current_record(s);
    if !add_mark(&mut r, s.seal.epoch, s.segment_seq) {
        return Step::Fail;
    }
    write_state(s, sys, &mut r, NO_EFFECTS, -1)
}

/// Seal `payload_len` bytes of `msg_buf` into `write_buf` at `pos` as
/// one frame of the current segment. The caller has checked the frame
/// fits and called `ensure_writable`. False when the vault refused; the
/// buffer is then untouched past `pos` and the sequence unconsumed.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
pub unsafe fn seal_into(s: &mut Wal, sys: &SyscallTable, pos: usize, payload_len: usize) -> bool {
    let seq = s.seal.write_seq;
    let inc = s.seal.write_inc;
    let epoch = s.seal.write_epoch;
    let c = payload_len as u32;
    let aad = sr::wal_aad(
        &identity(&s.seal, who(s)),
        u64::from(s.segment_seq),
        &inc,
        epoch,
        seq,
        c,
        c,
    );
    let nonce = sr::wal_nonce(seq);
    sr::wal_write_header(&mut s.write_buf[pos..], epoch, &inc, seq, c);
    let ct = pos + sr::WAL_HDR_LEN;
    core::ptr::copy_nonoverlapping(
        s.msg_buf.as_ptr(),
        s.write_buf.as_mut_ptr().add(ct),
        payload_len,
    );
    let base = s.write_buf.as_mut_ptr();
    let rc = sr::aead(
        sys,
        s.seal.write_key,
        true,
        &nonce,
        &aad,
        sr::AeadBuf {
            data: base.add(ct),
            len: payload_len,
            tag: base.add(ct + payload_len),
        },
    );
    if rc != sr::Aead::Ok {
        return false;
    }
    sr::wal_write_crc(&mut s.write_buf[pos..], payload_len);
    s.seal.write_seq = seq + 1;
    true
}

// ── Read path ───────────────────────────────────────────────────────────

/// Outcome of opening one stored frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Opened {
    /// Authenticated; the plaintext is `buf[40..40 + ct_len]`.
    Ok { ct_len: u32 },
    /// CRC mismatch or inconsistent prefix: torn, never authenticated.
    Torn,
    /// A complete frame that does not authenticate.
    AuthFailed,
    /// Its epoch's master is not in the vault.
    KeyUnavailable,
}

/// Verify and open, in place, the whole stored frame in `buf` (prefix
/// through CRC) that segment `seg` holds. The CRC is judged first, over
/// the bytes the prefix's length names: only a frame stored whole gets
/// an authentication verdict, and a whole one whose declared lengths
/// disagree is as untrustworthy as one whose tag fails.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
#[inline(never)]
pub unsafe fn open_stored(
    z: &mut WalSeal,
    w: Who,
    sys: &SyscallTable,
    seg: u32,
    buf: &mut [u8],
) -> Opened {
    let total = buf.len();
    if total < sr::WAL_OVERHEAD {
        return Opened::Torn;
    }
    let declared = u32::from_le_bytes([
        buf[sr::WAL_OFF_LEN],
        buf[sr::WAL_OFF_LEN + 1],
        buf[sr::WAL_OFF_LEN + 2],
        buf[sr::WAL_OFF_LEN + 3],
    ]) as usize;
    if declared + sr::WAL_PREFIX_LEN != total {
        return Opened::Torn;
    }
    let stored = u32::from_le_bytes([
        buf[total - 4],
        buf[total - 3],
        buf[total - 2],
        buf[total - 1],
    ]);
    let mut crc = crate::collections::Crc32c::new();
    crc.update(&buf[..total - 4]);
    if crc.finalize() != stored {
        return Opened::Torn;
    }
    let Some(h) = sr::wal_parse_header(buf) else {
        return Opened::AuthFailed;
    };
    let c = h.ct_len as usize;
    let k = key_for(z, w, sys, h.epoch, &h.incarnation);
    if k < 0 {
        return Opened::KeyUnavailable;
    }
    let aad = sr::wal_aad(
        &identity(z, w),
        u64::from(seg),
        &h.incarnation,
        h.epoch,
        h.seq,
        h.ct_len,
        h.ct_len,
    );
    let nonce = sr::wal_nonce(h.seq);
    let base = buf.as_mut_ptr();
    match sr::aead(
        sys,
        k,
        false,
        &nonce,
        &aad,
        sr::AeadBuf {
            data: base.add(sr::WAL_HDR_LEN),
            len: c,
            tag: base.add(sr::WAL_HDR_LEN + c),
        },
    ) {
        sr::Aead::Ok => Opened::Ok { ct_len: h.ct_len },
        sr::Aead::AuthFailed => Opened::AuthFailed,
        sr::Aead::Refused(_) => Opened::KeyUnavailable,
    }
}

/// A served read found a frame that does not authenticate: fail the
/// replica closed, as replay would.
///
/// # Safety
/// `sys` must reach live kernel routines per the module ABI.
#[inline(never)]
pub unsafe fn serve_verdict(s: &mut Wal, sys: &SyscallTable, o: Opened) {
    match o {
        Opened::AuthFailed => {
            s.seal.tag_failures = s.seal.tag_failures.saturating_add(1);
            fail(s, sys, fault::TAG, b"[wal] seal tag FAIL (serve)");
        }
        Opened::KeyUnavailable => {
            fail(s, sys, fault::KEY, b"[wal] seal: key epoch unavailable");
        }
        Opened::Torn => {
            s.checksum_failures = s.checksum_failures.saturating_add(1);
        }
        Opened::Ok { .. } => {}
    }
}

/// Track the nonce domain as replay walks frames: sequences rise within
/// an incarnation, and an incarnation never comes back once another has
/// followed it. False on a conflict.
fn note_nonce(s: &mut Wal, inc: &[u8; sr::INCARNATION_LEN], seq: u64) -> bool {
    if s.seal.have_last && s.seal.last_inc == *inc {
        if seq <= s.seal.last_seq {
            return false;
        }
        s.seal.last_seq = seq;
        return true;
    }
    for i in 0..(s.seal.seen_count as usize) {
        if s.seal.seen[i] == *inc {
            return false;
        }
    }
    if s.seal.have_last {
        let at = s.seal.seen_head as usize % SEEN_INCARNATIONS;
        s.seal.seen[at] = s.seal.last_inc;
        s.seal.seen_head = ((at + 1) % SEEN_INCARNATIONS) as u8;
        if (s.seal.seen_count as usize) < SEEN_INCARNATIONS {
            s.seal.seen_count += 1;
        }
    }
    s.seal.last_inc = *inc;
    s.seal.last_seq = seq;
    s.seal.have_last = true;
    let counter = counter_of(inc);
    if !s.seal.saw_frame || counter > s.seal.max_counter_seen {
        s.seal.max_counter_seen = counter;
    }
    s.seal.saw_frame = true;
    true
}

/// End replay of the open segment. `torn` marks the walk tainted so no
/// later segment is acknowledged over the hole.
unsafe fn end_segment(s: &mut Wal, sys: &SyscallTable, torn: bool) -> i32 {
    end_replay_segment(s, sys, torn);
    0
}

/// Replay up to `max_frames` sealed frames of the open segment. The
/// sealed twin of `step_replay`'s frame loop: the same acks, ledger
/// latch, location ring and gap rule, fed only by frames whose tag
/// verified. A frame the provider has only part-delivered is resumed at
/// `replay_got` next step (the prefix stays in `msg_buf`, which nothing
/// else touches during replay).
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
pub unsafe fn replay_frames(s: &mut Wal, sys: &SyscallTable, max_frames: usize) -> i32 {
    let mut frames = 0usize;
    while frames < max_frames {
        if s.out_flushed >= 0 && !wire_channels::writable(sys, s.out_flushed) {
            return 0;
        }
        frames += 1;
        let frame_start = s.replay_pos;
        let remaining = s.replay_file_size.saturating_sub(s.replay_pos) as usize;
        if s.replay_got == 0 && remaining < sr::WAL_PREFIX_LEN {
            // A terminator, or nothing: the segment's live data ends here.
            return end_segment(s, sys, false);
        }
        if (s.replay_got as usize) < sr::WAL_PREFIX_LEN {
            let mut got = s.replay_got as usize;
            let io = fs_step::read_into(
                sys.provider_call,
                s.replay_fd,
                s.msg_buf.as_mut_ptr(),
                sr::WAL_PREFIX_LEN,
                &mut got,
            );
            s.replay_got = got as u32;
            match io {
                Io::Later => return 0,
                Io::Done => {}
                Io::End | Io::Fail(_) => return end_segment(s, sys, true),
            }
        }
        let frame_len = match sr::wal_parse_prefix(
            &s.msg_buf[..sr::WAL_PREFIX_LEN],
            wal_frame::MAX_ENTRY_LEN,
        ) {
            sr::WalPrefix::End => return end_segment(s, sys, false),
            sr::WalPrefix::Garbage => return end_segment(s, sys, true),
            sr::WalPrefix::Frame { frame_len } => frame_len as usize,
        };
        if frame_len > remaining.saturating_sub(sr::WAL_PREFIX_LEN) {
            // Short ciphertext or absent tag at the physical tail.
            return end_segment(s, sys, true);
        }
        let mut got = (s.replay_got as usize).saturating_sub(sr::WAL_PREFIX_LEN);
        let io = fs_step::read_into(
            sys.provider_call,
            s.replay_fd,
            s.msg_buf.as_mut_ptr().add(sr::WAL_PREFIX_LEN),
            frame_len,
            &mut got,
        );
        s.replay_got = (sr::WAL_PREFIX_LEN + got) as u32;
        match io {
            Io::Later => return 0,
            Io::Done => {}
            Io::End | Io::Fail(_) => return end_segment(s, sys, true),
        }
        s.replay_got = 0;
        s.replay_pos += (sr::WAL_PREFIX_LEN + frame_len) as u32;
        let total = sr::WAL_PREFIX_LEN + frame_len;
        let seg = s.replay_seg;
        let hdr = sr::wal_parse_header(&s.msg_buf[..total]);
        let w = who(s);
        match open_stored(&mut s.seal, w, sys, seg, &mut s.msg_buf[..total]) {
            Opened::Ok { ct_len } => {
                let Some(h) = hdr else {
                    return end_segment(s, sys, true);
                };
                if ct_len < 16 {
                    fail(
                        s,
                        sys,
                        fault::TAG,
                        b"[wal] seal: frame shorter than its prologue",
                    );
                    return end_segment(s, sys, false);
                }
                if !note_nonce(s, &h.incarnation, h.seq) {
                    s.seal.nonce_conflicts = s.seal.nonce_conflicts.saturating_add(1);
                    fail(s, sys, fault::NONCE, b"[wal] seal: nonce conflict");
                    return end_segment(s, sys, false);
                }
                if h.epoch > s.seal.max_epoch_seen {
                    s.seal.max_epoch_seen = h.epoch;
                }
                let payload = &s.msg_buf[sr::WAL_HDR_LEN..sr::WAL_HDR_LEN + ct_len as usize];
                let Some((term, index)) = wire::decode_term_index(payload) else {
                    return end_segment(s, sys, true);
                };
                if s.current_index != 0 && index > s.current_index.saturating_add(1) {
                    s.continuity_errors = s.continuity_errors.saturating_add(1);
                    dev_log(sys, 1, b"[wal] replay gap".as_ptr(), 16);
                    return end_segment(s, sys, true);
                }
                if index > s.current_index {
                    s.current_index = index;
                    s.current_term = term;
                }
                if s.replay_first_index == 0 {
                    s.replay_first_index = index;
                }
                record_entry_loc(
                    s,
                    index,
                    term,
                    seg,
                    frame_start + sr::WAL_HDR_LEN as u32,
                    ct_len,
                );
                note_config(s, index, sr::WAL_HDR_LEN, ct_len as usize);
                note_ledger_ack(s, term, index);
                if s.out_flushed >= 0 {
                    let mut ack = [0u8; 17];
                    wire::encode_fsync_ack(&mut ack, term, index, s.self_id);
                    write_part(s, sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack[..17]);
                    dev_log(sys, 3, b"[wal] replayed".as_ptr(), 14);
                }
                s.entries_written += 1;
                s.replayed_count += 1;
            }
            Opened::Torn => {
                s.checksum_failures = s.checksum_failures.saturating_add(1);
                dev_log(sys, 3, b"[wal] replay CRC FAIL".as_ptr(), 21);
                return end_segment(s, sys, true);
            }
            Opened::AuthFailed => {
                s.seal.tag_failures = s.seal.tag_failures.saturating_add(1);
                fail(s, sys, fault::TAG, b"[wal] seal tag FAIL");
                return end_segment(s, sys, false);
            }
            Opened::KeyUnavailable => {
                fail(s, sys, fault::KEY, b"[wal] seal: key epoch unavailable");
                return end_segment(s, sys, false);
            }
        }
    }
    0
}

// ── Retirement ──────────────────────────────────────────────────────────

/// The oldest epoch any retained segment or the retained snapshot names.
fn oldest_live(s: &Wal) -> u32 {
    let mut live = s.seal.epoch;
    let n = s.seal.mark_count as usize;
    // The mark covering the oldest retained segment: the last mark
    // starting at or below it.
    let mut covering = 0u32;
    for i in 0..n {
        if s.seal.marks[i].first_segment <= s.oldest_segment_seq {
            covering = s.seal.marks[i].epoch;
        }
    }
    if covering == 0 && n > 0 {
        covering = s.seal.marks[0].epoch;
    }
    if covering != 0 && covering < live {
        live = covering;
    }
    if s.seal.snapshot_epoch != 0 && s.seal.snapshot_epoch < live {
        live = s.seal.snapshot_epoch;
    }
    live
}

/// Retire masters no retained record names: record the new floor
/// durably, then destroy each master below it. At most one state write
/// per call. Returns whether it did provider work.
///
/// # Safety
/// Exclusive `&mut Wal`; `sys` must reach live kernel routines.
#[inline(never)]
pub unsafe fn maybe_retire(s: &mut Wal, sys: &SyscallTable) -> bool {
    if !enabled(s) || s.seal.phase != PHASE_READY || s.has_batch || s.retire_active {
        return false;
    }
    let live = oldest_live(s);
    if live <= s.seal.oldest_epoch {
        return false;
    }
    let from = s.seal.oldest_epoch.max(1);
    // At most MAX_MARKS epochs per call: the gap is the rotations since
    // the last retirement, and a step's work must stay bounded whatever
    // it is. The rest follows on later steps.
    let live = live.min(from.saturating_add(MAX_MARKS as u32));
    let mut r = current_record(s);
    r.oldest_epoch = live;
    // Drop marks wholly below the floor, keeping the one that covers it.
    let mut kept = [EpochMark::zero(); MAX_MARKS];
    let mut k = 0usize;
    for i in 0..(r.mark_count as usize) {
        if r.marks[i].epoch >= live {
            kept[k] = r.marks[i];
            k += 1;
        }
    }
    r.marks = kept;
    r.mark_count = k as u8;
    // The masters below the floor are destroyed when the record naming
    // the floor is adopted (`adopt_state`) — whichever step finishes it.
    let fx = Effects {
        retire_from: from,
        retire_to: live,
        ..NO_EFFECTS
    };
    write_state(s, sys, &mut r, fx, -1) != Step::Later
}
