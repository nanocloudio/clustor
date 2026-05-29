//! WAL — Write-ahead log module.
//!
//! Accepts log entries from raft_engine, buffers them into 4 KiB blocks,
//! computes CRC32C integrity, and emits flushed acks downstream.
//! Actual disk I/O is deferred (Phase 8) — this phase validates the
//! pipeline with in-memory buffering.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/params.rs");

#[path = "../../common/types.rs"]
mod types;

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

#[path = "../../common/collections.rs"]
mod collections;

use types::*;
use collections::Crc32c;

const WRITE_BUF_SIZE: usize = 4096;
const METRICS_INTERVAL_MS: u64 = 1000;

/// Power of two so `index % RING_SIZE` is a cheap mask. Sized to cover
/// the last few seconds of a hot writer without inflating module state.
const ENTRY_RING_SIZE: usize = 256;
const ENTRY_RING_MASK: u64 = (ENTRY_RING_SIZE as u64) - 1;

#[derive(Clone, Copy)]
#[repr(C)]
struct EntryLoc {
    /// Log index. 0 means slot is empty.
    index: u64,
    term: u64,
    /// WAL segment file this entry lives in.
    seg_seq: u32,
    /// Byte offset of the entry payload (after the 4-byte length prefix)
    /// within the segment file.
    payload_offset: u32,
    /// Length in bytes of the entry payload (the [term:u64][index:u64][body...]
    /// blob that was written to the file).
    payload_len: u32,
}

impl EntryLoc {
    const fn zero() -> Self {
        Self { index: 0, term: 0, seg_seq: 0, payload_offset: 0, payload_len: 0 }
    }
}

define_params! {
    ModuleState;

    1, encoding, u8, 0
        => |s, d, len| { s.encoding = p_u8(d, len, 0, 0); };

    2, segment_bytes, u32, 67_108_864
        => |s, d, len| { s.segment_limit = p_u32(d, len, 0, 67_108_864); };

    // 3, aead — reserved (0=none, 1=aes_256_gcm); not yet read at runtime.

    // Partition slot for multi-Raft graphs. Default 0 → legacy "wal/seg_*"
    // path. Non-zero → "wal/p<NNNN>/seg_<NNNNNNNN>" so per-partition WALs
    // don't collide on disk. See .context/rfc_partition_groups.md.
    4, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };

    // Replica id this WAL belongs to. Stamped into outgoing FsyncAcks
    // so durability_ledger can key per-replica progress correctly.
    // Must match raft_engine.self_id on the same node.
    5, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    // 0 = per-entry fsync + ack (default, strict). 1 = group fsync:
    // FS_WRITE per entry, but fsync + ack deferred until either
    // `group_window_ms` elapses or `group_max_pending` entries accumulate,
    // at which point one ack is emitted carrying the high-water
    // (term, index). Replay-time re-ack stays per-entry in both modes.
    6, fsync_mode, u8, 0
        => |s, d, len| { s.fsync_mode = p_u8(d, len, 0, 0); };

    7, group_window_ms, u16, 2
        => |s, d, len| { s.group_window_ms = p_u16(d, len, 0, 2); };

    8, group_max_pending, u16, 64
        => |s, d, len| { s.group_max_pending = p_u16(d, len, 0, 64); };
}

// FS opcodes (from abi::dev_fs)
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
/// Write-side opener. `FS_OPEN` is read-only-if-exists per the FS
/// contract (see `target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs`),
/// so a fresh WAL with no segment file on disk silently degrades to
/// in-memory; segment creation needs the write tier.
const FS_OPEN_CREATE: u32 = 0x0909;

const WAL_PATH_MAX: usize = 48;

// Module phases
const PHASE_REPLAY: u8 = 0;
const PHASE_NORMAL: u8 = 1;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    // Channels: 4 in, 4 out
    in_entries: i32,        // in[0]: WalEntry from raft_engine
    in_key_update: i32,     // in[1]: DekEpoch from key_manager
    in_entry_request: i32,  // in[2]: MSG_WAL_ENTRY_REQUEST (replicator NACK path)
    in_compact_before: i32, // in[3]: MSG_WAL_COMPACT_BEFORE (post-snapshot trim)
    out_flushed: i32,       // out[0]: FsyncAck to durability_ledger
    out_compaction: i32,    // out[1]: SnapshotTrigger to snapshot_engine
    out_metrics: i32,       // out[2]: MetricsPayload to telemetry_agg
    out_entry_reply: i32,   // out[3]: MSG_WAL_ENTRY_REPLY back to requester

    // WAL state
    partition_id: u16,
    self_id: u8,
    current_term: Term,
    current_index: Index,
    segment_seq: u32,
    cursor: u32,            // bytes written in current logical segment
    segment_limit: u32,     // from params (default 64 MiB)
    /// Oldest segment_seq still on disk after compaction. Requests for
    /// entries in segments < `oldest_segment_seq` return NOT_FOUND, which
    /// triggers the snapshot-install fallback on the leader.
    oldest_segment_seq: u32,
    dek_epoch: u32,
    encoding: u8,           // 0=binary

    /// Ring buffer of recent entry locations for random-access lookup
    /// (replicator NACK retry, etc.). `ENTRY_RING_SIZE` covers the
    /// last 256 indices; older indices fall through to a NOT_FOUND
    /// reply and snapshot fallback.
    entry_ring: [EntryLoc; ENTRY_RING_SIZE],
    entry_ring_max_index: u64,
    entry_ring_min_index: u64,

    // File I/O
    fd: i32,                    // file descriptor for current segment, -1 = not open
    path_buf: [u8; WAL_PATH_MAX],
    path_len: u8,

    // Write buffer
    write_buf: [u8; WRITE_BUF_SIZE],
    write_pos: u16,
    needs_flush: bool,

    // CRC
    crc: Crc32c,

    // Metrics
    entries_written: u32,
    bytes_written: u64,
    last_metrics_ms: u64,

    // Replay state
    phase: u8,              // PHASE_REPLAY or PHASE_NORMAL
    replay_seg: u32,        // current segment being replayed
    replay_fd: i32,         // fd for replay segment, -1 = none
    replay_file_size: u32,  // total bytes in replay segment
    replay_pos: u32,        // current read position

    // Group-fsync batching (active iff fsync_mode == 1).
    fsync_mode: u8,
    group_window_ms: u16,
    group_max_pending: u16,
    batch_start_ms: u64,
    pending_count: u16,
    pending_max_index: Index,
    pending_max_term: Term,
    has_batch: bool,

    // Scratch buffer for reading messages
    msg_buf: [u8; 2048],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }

        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        // Channel bindings
        s.in_entries = in_chan;
        s.out_flushed = out_chan;
        s.in_key_update = dev_channel_port(sys, 0, 1);
        s.in_entry_request = dev_channel_port(sys, 0, 2);
        s.in_compact_before = dev_channel_port(sys, 0, 3);
        s.out_compaction = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.out_entry_reply = dev_channel_port(sys, 1, 3);

        s.segment_seq = 1;
        s.oldest_segment_seq = 1;
        s.crc = Crc32c::new();
        s.fd = -1;
        s.phase = PHASE_REPLAY;
        s.replay_seg = 1;
        s.replay_fd = -1;
        s.entry_ring = [EntryLoc::zero(); ENTRY_RING_SIZE];
        s.entry_ring_max_index = 0;
        s.entry_ring_min_index = 0;

        // Defaults + TLV param parsing (schema lives in `define_params!`
        // above; values come from the YAML `params:` map via the host
        // tool's encoder).
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        dev_log(sys, 3, b"[wal] init".as_ptr(), 10);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        if s.phase == PHASE_REPLAY {
            // Replay existing WAL segments before accepting new entries
            return step_replay(s, sys);
        }

        // Time-based group flush: a quiescent writer drains its tail
        // batch within group_window_ms even when no new entries arrive.
        if s.has_batch {
            let now = dev_millis(sys);
            if now.wrapping_sub(s.batch_start_ms) >= s.group_window_ms as u64 {
                flush_batch(s, sys);
            }
        }

        // Normal operation
        // 1. Drain key_update (ctrl-style: keep latest)
        drain_key_updates(s, sys);

        // 2. Process entries
        process_entries(s, sys);

        // 3. Service random-access read-back requests (replicator NACK retry).
        drain_entry_requests(s, sys);

        // 4. Apply compact-before signals (post-snapshot trim).
        drain_compact_before(s, sys);

        // 5. Emit metrics periodically
        emit_metrics(s, sys);

        0 // Continue
    }
}

// ── Entry-location ring buffer ──────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn record_entry_loc(
    s: &mut ModuleState,
    index: u64,
    term: u64,
    seg_seq: u32,
    payload_offset: u32,
    payload_len: u32,
) {
    if index == 0 { return; }
    let slot = (index & ENTRY_RING_MASK) as usize;
    s.entry_ring[slot] = EntryLoc { index, term, seg_seq, payload_offset, payload_len };
    if index > s.entry_ring_max_index {
        s.entry_ring_max_index = index;
    }
    let floor = if s.entry_ring_max_index > ENTRY_RING_SIZE as u64 {
        s.entry_ring_max_index - ENTRY_RING_SIZE as u64 + 1
    } else {
        1
    };
    if floor > s.entry_ring_min_index {
        s.entry_ring_min_index = floor;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn lookup_entry_loc(s: &ModuleState, index: u64) -> Option<EntryLoc> {
    if index == 0 || index > s.entry_ring_max_index { return None; }
    if index < s.entry_ring_min_index { return None; }
    let slot = (index & ENTRY_RING_MASK) as usize;
    let loc = s.entry_ring[slot];
    if loc.index != index { return None; }
    Some(loc)
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_entry_requests(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_entry_request < 0 || s.out_entry_reply < 0 { return; }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_entry_request, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_entry_request, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_ENTRY_REQUEST { continue; }
        let pl = plen as usize;
        let (request_id, wal_index) = match wire::decode_wal_entry_request(&s.msg_buf[..pl]) {
            Some(v) => v,
            None => continue,
        };
        serve_entry_request(s, sys, request_id, wal_index);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn serve_entry_request(
    s: &mut ModuleState,
    sys: &SyscallTable,
    request_id: u32,
    wal_index: u64,
) {
    let poll_out = (sys.channel_poll)(s.out_entry_reply, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }

    let loc = match lookup_entry_loc(s, wal_index) {
        Some(l) => l,
        None => {
            // NOT_FOUND — reply with header only, empty body. The leader
            // takes this as a signal to fall through to snapshot install.
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index);
            wire_channels::channel_write_msg(
                sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr,
            );
            return;
        }
    };

    // Read the entry body from disk. The body that lands in the WAL is
    // `[term:u64][index:u64][body...]` (16-byte header + body). We pass
    // the whole payload back so the replicator can reconstruct an AE.
    let mut body = [0u8; 2048];
    let payload_len = loc.payload_len as usize;
    if payload_len == 0 || payload_len > body.len() {
        // Defensive: shouldn't happen given the 2048 cap in writes.
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index);
        wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
        return;
    }

    let read_fd = if loc.seg_seq == s.segment_seq && s.fd >= 0 {
        s.fd
    } else {
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = encode_segment_path(s.partition_id, loc.seg_seq, &mut path);
        let fd = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        if fd < 0 {
            let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
            wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index);
            wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
            return;
        }
        fd
    };

    let seek_arg = (loc.payload_offset as i32).to_le_bytes();
    let seek_rc =
        (sys.provider_call)(read_fd, FS_SEEK, seek_arg.as_ptr() as *mut u8, 4);
    let mut ok = seek_rc >= 0;
    if ok {
        let n = (sys.provider_call)(read_fd, FS_READ, body.as_mut_ptr(), payload_len);
        ok = (n as usize) >= payload_len;
    }

    // Restore write-fd position to end-of-segment so the next write
    // appends correctly. We always FS_SEEK to `s.cursor`.
    if read_fd == s.fd {
        let restore = (s.cursor as i32).to_le_bytes();
        (sys.provider_call)(read_fd, FS_SEEK, restore.as_ptr() as *mut u8, 4);
    } else {
        (sys.provider_call)(read_fd, FS_CLOSE, core::ptr::null_mut(), 0);
    }

    if !ok {
        let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
        wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, 0, wal_index);
        wire_channels::channel_write_msg(sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &hdr);
        return;
    }

    // Body is [term:u64][index:u64][rest...]; strip the 16-byte header
    // when forming the reply so the wire format matches the doc-comment
    // on MSG_WAL_ENTRY_REPLY (`[request_id][term][index][body...]`).
    let rest = if payload_len > 16 { &body[16..payload_len] } else { &[][..] };
    let total = wire::WAL_ENTRY_REPLY_HDR + rest.len();
    if total > 2048 { return; }
    let mut reply = [0u8; 2048];
    let mut hdr = [0u8; wire::WAL_ENTRY_REPLY_HDR];
    wire::encode_wal_entry_reply_hdr(&mut hdr, request_id, loc.term, loc.index);
    reply[..wire::WAL_ENTRY_REPLY_HDR].copy_from_slice(&hdr);
    reply[wire::WAL_ENTRY_REPLY_HDR..total].copy_from_slice(rest);
    wire_channels::channel_write_msg(
        sys, s.out_entry_reply, wire::MSG_WAL_ENTRY_REPLY, &reply[..total],
    );
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_compact_before(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_compact_before < 0 { return; }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_compact_before, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_compact_before, &mut s.msg_buf);
        if msg_type != wire::MSG_WAL_COMPACT_BEFORE || (plen as usize) < 8 { continue; }
        let before_index = u64::from_le_bytes([
            s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
        ]);
        compact_before(s, sys, before_index);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn compact_before(s: &mut ModuleState, sys: &SyscallTable, before_index: u64) {
    if before_index == 0 { return; }
    // Bump the floor index in the in-memory ring so we stop serving
    // entries below it even if the ring slots still hold them.
    if before_index > s.entry_ring_min_index {
        s.entry_ring_min_index = before_index;
    }
    // Drop segments whose max-index is strictly below the requested
    // floor. The current write segment is exempt — we never delete it
    // while we're still appending to it.
    let mut max_safe_seq_to_drop: u32 = 0;
    for slot in s.entry_ring.iter() {
        if slot.index == 0 { continue; }
        // If the entry is still relevant (>= floor), the segment that
        // holds it stays. We deliberately scan the whole ring rather
        // than rely on segment_seq monotonicity, because a recent
        // entry's segment may equal an older entry's segment.
        if slot.index < before_index && slot.seg_seq < s.segment_seq {
            if slot.seg_seq > max_safe_seq_to_drop {
                max_safe_seq_to_drop = slot.seg_seq;
            }
        }
    }
    if max_safe_seq_to_drop == 0 { return; }
    // Delete segments [oldest_segment_seq .. max_safe_seq_to_drop].
    while s.oldest_segment_seq <= max_safe_seq_to_drop
        && s.oldest_segment_seq < s.segment_seq
    {
        let mut path = [0u8; WAL_PATH_MAX];
        let plen = encode_segment_path(s.partition_id, s.oldest_segment_seq, &mut path);
        // FS contract: no explicit unlink op exists in the current SDK.
        // Open + truncate-on-write isn't a deletion either. Until the
        // FS contract exposes an unlink/truncate, we mark the segment
        // as compacted by emitting a metric and rely on operators to
        // garbage-collect old files out-of-band. The on-disk segment
        // remains until then but the WAL ring will not serve its
        // entries.
        let _ = (sys.provider_call)(-1, FS_OPEN, path.as_mut_ptr(), plen);
        dev_log(sys, 3, b"[wal] compacted".as_ptr(), 15);
        s.oldest_segment_seq += 1;
    }
}

// ── Replay phase ────────────────────────────────────────────
//
// On startup, scans for existing WAL segment files and re-emits
// their entries through the flushed output. This allows the
// downstream pipeline (durability_ledger → commit_tracker) to
// reconstruct committed state.
//
// Processes one chunk per step (bounded work per tick).

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn step_replay(s: &mut ModuleState, sys: &SyscallTable) -> i32 {
    // Try to open the current replay segment.
    // Use FS_OPEN without O_CREAT semantics: open the file, check its size.
    // If the file doesn't exist or is empty, replay is complete.
    // Note: the Linux FS provider opens O_RDWR|O_CREAT, so we check size
    // to distinguish real segments from auto-created empty ones.
    if s.replay_fd < 0 {
        build_segment_path(s, s.replay_seg);
        let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), s.path_len as usize);
        if fd < 0 {
            // FS not available — skip replay
            dev_log(sys, 3, b"[wal] no fs".as_ptr(), 11);
            s.phase = PHASE_NORMAL;
            s.segment_seq = s.replay_seg;
            return 0;
        }

        // Check file size — empty or nonexistent means no more segments.
        // FS_STAT writes [size:u32 LE][mtime:u32 LE] into the supplied buffer.
        let mut stat_buf = [0u8; 8];
        let stat_rc = (sys.provider_call)(fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        let size = if stat_rc < 0 { 0 } else {
            u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]])
        };
        if size == 0 {
            // No data in this segment — replay complete
            (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            dev_log(sys, 3, b"[wal] replay done".as_ptr(), 17);
            s.phase = PHASE_NORMAL;
            s.segment_seq = s.replay_seg;
            return 0;
        }

        s.replay_fd = fd;
        s.replay_file_size = size;
        s.replay_pos = 0;
        dev_log(sys, 3, b"[wal] replay seg".as_ptr(), 16);
    }

    // Read one framed entry: [entry_len: u32 LE] [entry_data]
    let remaining = s.replay_file_size - s.replay_pos;
    if remaining < 4 {
        // Not enough data for a frame header — segment done
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Read 4-byte length header
    let mut len_buf = [0u8; 4];
    let n = (sys.provider_call)(s.replay_fd, FS_READ, len_buf.as_mut_ptr(), 4);
    if n < 4 {
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }
    s.replay_pos += 4;

    let entry_len = u32::from_le_bytes(len_buf) as usize;
    if entry_len == 0 || entry_len > 2048 {
        // Invalid entry — stop replay for this segment
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Read entry data
    let entry_payload_offset = s.replay_pos;
    let n2 = (sys.provider_call)(s.replay_fd, FS_READ, s.msg_buf.as_mut_ptr(), entry_len);
    if (n2 as usize) < entry_len {
        (sys.provider_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }
    s.replay_pos += entry_len as u32;

    // Parse: first 16 bytes are term(8) + index(8)
    if entry_len >= 16 {
        let (term, index) = wire::decode_term_index(&s.msg_buf);

        if index > s.current_index {
            s.current_index = index;
            s.current_term = term;
        }
        record_entry_loc(s, index, term, s.replay_seg, entry_payload_offset, entry_len as u32);

        // Re-emit as FsyncAck — entry is already durable on disk
        let poll = (sys.channel_poll)(s.out_flushed, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            let mut ack = [0u8; 17];
            wire::encode_fsync_ack(&mut ack, term, index, s.self_id);
            wire_channels::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack[..17]);
            dev_log(sys, 3, b"[wal] replayed".as_ptr(), 14);
        }

        s.entries_written += 1;
    }

    0
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn build_segment_path(s: &mut ModuleState, seq: u32) {
    let n = encode_segment_path(s.partition_id, seq, &mut s.path_buf);
    s.path_len = n as u8;
}

/// Free function: write the segment path for `(partition_id, seq)`
/// into `out` and return the length written. Used by both the
/// stateful `build_segment_path` (above) and by random-access
/// readers that need a local path buffer.
fn encode_segment_path(partition_id: u16, seq: u32, out: &mut [u8]) -> usize {
    let cap = out.len();
    let mut i = 0usize;
    for &b in b"wal/" {
        if i < cap { out[i] = b; i += 1; }
    }
    if partition_id != 0 {
        if i < cap { out[i] = b'p'; i += 1; }
        for digit in (0..4).rev() {
            let nibble = ((partition_id >> (digit * 4)) & 0xF) as u8;
            let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            if i < cap { out[i] = ch; i += 1; }
        }
        if i < cap { out[i] = b'/'; i += 1; }
    }
    for &b in b"seg_" {
        if i < cap { out[i] = b; i += 1; }
    }
    for digit in (0..8).rev() {
        let nibble = ((seq >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        if i < cap { out[i] = ch; i += 1; }
    }
    i
}

// ── Normal operation ────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_key_updates(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key_update < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_key_update, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_key_update, &mut s.msg_buf);
        if msg_type == wire::MSG_DEK_EPOCH && plen >= 4 {
            s.dek_epoch = u32::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            ]);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_entries(s: &mut ModuleState, sys: &SyscallTable) {
    // Check input readiness
    let poll_in = (sys.channel_poll)(s.in_entries, 0x01);
    if poll_in <= 0 || (poll_in as u32 & 0x01) == 0 { return; }

    // Output back-pressure: only block when out_flushed is wired AND
    // currently not writable. An unwired output (`out_flushed < 0`,
    // e.g. a partitioned graph that hasn't built the per-partition
    // commit pipeline yet) shouldn't gate disk durability — the WAL's
    // job is to write entries, the FsyncAck is a downstream
    // optimisation. Skipping the ack is fine; skipping the write
    // would silently drop committed log entries.
    if s.out_flushed >= 0 {
        let poll_out = (sys.channel_poll)(s.out_flushed, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }
    }

    // Read entry
    let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
    if msg_type != wire::MSG_WAL_ENTRY || plen < 16 { return; }

    let (term, index) = wire::decode_term_index(&s.msg_buf);
    let payload_len = plen as usize;

    // [entry_len: u32 LE] [entry_data]. Track the payload offset
    // (after the length prefix) so MSG_WAL_ENTRY_REQUEST can read it
    // back. In group mode the FS_FSYNC is deferred to flush_batch —
    // emitting the ack before that fsync would signal durability
    // that doesn't yet hold on disk.
    let entry_payload_offset = s.cursor.saturating_add(4);
    ensure_segment_open(s, sys);
    if s.fd >= 0 {
        let len_bytes = (payload_len as u32).to_le_bytes();
        (sys.provider_call)(s.fd, FS_WRITE, len_bytes.as_ptr() as *mut u8, 4);
        (sys.provider_call)(s.fd, FS_WRITE, s.msg_buf.as_mut_ptr(), payload_len);
        if s.fsync_mode == 0 {
            (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
        }
    }

    s.current_term = term;
    s.current_index = index;
    s.cursor += (4 + payload_len) as u32;
    s.entries_written += 1;
    s.bytes_written += payload_len as u64;
    record_entry_loc(s, index, term, s.segment_seq, entry_payload_offset, payload_len as u32);

    if s.fsync_mode == 0 {
        if s.out_flushed >= 0 {
            dev_log(sys, 3, b"[wal] entry ok".as_ptr(), 14);
            let mut ack_buf = [0u8; 17];
            wire::encode_fsync_ack(&mut ack_buf, term, index, s.self_id);
            wire_channels::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17]);
        } else {
            dev_log(sys, 3, b"[wal] entry ok (no ack)".as_ptr(), 23);
        }
    } else {
        if !s.has_batch {
            s.batch_start_ms = dev_millis(sys);
            s.has_batch = true;
        }
        if index >= s.pending_max_index {
            s.pending_max_index = index;
            s.pending_max_term = term;
        }
        s.pending_count = s.pending_count.saturating_add(1);
        dev_log(sys, 3, b"[wal] entry queued".as_ptr(), 18);
        if s.pending_count >= s.group_max_pending {
            flush_batch(s, sys);
        }
    }

    // Segment rotation must flush any pending batch first so the ack
    // is ordered relative to the close.
    if s.cursor >= s.segment_limit {
        if s.has_batch {
            flush_batch(s, sys);
        }
        flush_block(s, sys);
        fsync_segment(s, sys);
        close_segment(s, sys);

        if s.out_compaction >= 0 {
            let mut trig = [0u8; 16];
            wire::encode_term_index(&mut trig, s.current_term, s.current_index);
            wire_channels::channel_write_msg(sys, s.out_compaction, wire::MSG_SNAPSHOT_TRIGGER, &trig[..16]);
        }
        s.segment_seq += 1;
        s.cursor = 0;
        s.crc.reset();
    }
}

/// Fsync the segment and emit one MSG_FSYNC_ACK for the batch
/// high-water (term, index). No-op on an empty batch. If the channel
/// is full we drop the ack rather than block — bytes are durable and
/// durability_ledger consumes high-water marks, so the next ack
/// subsumes any skipped one.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_batch(s: &mut ModuleState, sys: &SyscallTable) {
    if !s.has_batch { return; }

    fsync_segment(s, sys);

    if s.out_flushed >= 0 {
        let poll_out = (sys.channel_poll)(s.out_flushed, POLL_OUT);
        if poll_out > 0 && (poll_out as u32 & POLL_OUT) != 0 {
            let mut ack_buf = [0u8; 17];
            wire::encode_fsync_ack(
                &mut ack_buf, s.pending_max_term, s.pending_max_index, s.self_id,
            );
            wire_channels::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17]);
            dev_log(sys, 3, b"[wal] group fsync".as_ptr(), 17);
        }
    } else {
        dev_log(sys, 3, b"[wal] group fsync (no ack)".as_ptr(), 26);
    }

    s.has_batch = false;
    s.pending_count = 0;
    s.pending_max_index = 0;
    s.pending_max_term = 0;
    s.batch_start_ms = 0;
}

/// Open or create the current WAL segment file. Replay (read-only)
/// still uses `FS_OPEN` so it can detect "no more segments" via
/// ENODEV; the write side needs the create tier.
///
/// fd < 0 means FS unavailable (e.g. bare-metal without a mounted
/// filesystem) — module degrades to in-memory only.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ensure_segment_open(s: &mut ModuleState, sys: &SyscallTable) {
    if s.fd >= 0 { return; }
    build_segment_path(s, s.segment_seq);
    s.fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), s.path_len as usize);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_block(s: &mut ModuleState, sys: &SyscallTable) {
    if s.write_pos == 0 { return; }

    ensure_segment_open(s, sys);

    if s.fd >= 0 {
        let len = s.write_pos as usize;
        (sys.provider_call)(s.fd, FS_WRITE, s.write_buf.as_mut_ptr(), len);
    }

    s.write_pos = 0;
    s.needs_flush = false;
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Fsync the current segment file.
unsafe fn fsync_segment(s: &ModuleState, sys: &SyscallTable) {
    if s.fd >= 0 {
        (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Close current segment and prepare for rotation.
unsafe fn close_segment(s: &mut ModuleState, sys: &SyscallTable) {
    if s.fd >= 0 {
        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // `[wal] hb` — steady-state liveness on the foundation-module
    // heartbeat cadence. Survives log_net's history-skip (drain_net
    // seeds TAIL_NET=HEAD on first call), which discards init-time
    // one-shot markers. Fires regardless of out_metrics wiring.
    let mut hb = [0u8; 96];
    let mut pos = 0usize;
    pos += emit_field(hb.as_mut_ptr(), pos, b"[wal] hb mode=", s.fsync_mode as u32);
    pos += emit_field(hb.as_mut_ptr(), pos, b" seg=", s.segment_seq);
    pos += emit_field(hb.as_mut_ptr(), pos, b" entries=", s.entries_written);
    pos += emit_field(hb.as_mut_ptr(), pos, b" batch=", s.has_batch as u32);
    pos += emit_field(hb.as_mut_ptr(), pos, b" pending=", s.pending_count as u32);
    dev_log(sys, 3, hb.as_ptr(), pos);

    if s.out_metrics < 0 { return; }

    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&s.entries_written.to_le_bytes());
    buf[4..12].copy_from_slice(&s.bytes_written.to_le_bytes());
    buf[12..16].copy_from_slice(&s.segment_seq.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..16]);
    }
}

/// Append `tag` followed by `val`'s decimal representation at
/// `buf[start..]`. Returns the number of bytes written.
///
/// # Safety
///
/// `buf` must have room for `tag.len() + 10` bytes starting at `start`.
unsafe fn emit_field(buf: *mut u8, start: usize, tag: &[u8], val: u32) -> usize {
    core::ptr::copy_nonoverlapping(tag.as_ptr(), buf.add(start), tag.len());
    tag.len() + fmt_u32_raw(buf.add(start + tag.len()), val)
}
