//! WAL — Write-ahead log module.
//!
//! Accepts log entries from raft_engine, buffers them into 4 KiB blocks,
//! computes CRC32C integrity, and emits flushed acks downstream.
//! Actual disk I/O is deferred (Phase 8) — this phase validates the
//! pipeline with in-memory buffering.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/types.rs"]
mod types;

#[path = "../common/wire.rs"]
mod wire;

#[path = "../common/collections.rs"]
mod collections;

use types::*;
use collections::Crc32c;

const WRITE_BUF_SIZE: usize = 4096;
const METRICS_INTERVAL_MS: u64 = 1000;

// FS opcodes (from abi::dev_fs)
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;

const WAL_PATH_MAX: usize = 48;

// Module phases
const PHASE_REPLAY: u8 = 0;
const PHASE_NORMAL: u8 = 1;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    // Channels: 2 in, 3 out
    in_entries: i32,      // in[0]: WalEntry from raft_engine
    in_key_update: i32,   // in[1]: DekEpoch from key_manager
    out_flushed: i32,     // out[0]: FsyncAck to fsync_scheduler
    out_compaction: i32,  // out[1]: SnapshotTrigger to snapshot_engine
    out_metrics: i32,     // out[2]: MetricsPayload to telemetry_agg

    // WAL state
    current_term: Term,
    current_index: Index,
    segment_seq: u32,
    cursor: u32,            // bytes written in current logical segment
    segment_limit: u32,     // from params (default 64 MiB)
    dek_epoch: u32,
    encoding: u8,           // 0=binary

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
        s.out_compaction = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);

        // Defaults
        s.segment_limit = 64 * 1024 * 1024; // 64 MiB
        s.segment_seq = 1;
        s.crc = Crc32c::new();
        s.fd = -1;
        s.phase = PHASE_REPLAY;
        s.replay_seg = 1;
        s.replay_fd = -1;

        // Parse params (TLV v2 or raw)
        if !params.is_null() && params_len >= 4 {
            s.encoding = p_u8(params, params_len, 0, 0);
            s.segment_limit = p_u32(params, params_len, 1, s.segment_limit);
        }

        dev_log(sys, 3, b"[wal] init".as_ptr(), 10);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        if s.phase == PHASE_REPLAY {
            // Replay existing WAL segments before accepting new entries
            return step_replay(s, sys);
        }

        // Normal operation
        // 1. Drain key_update (ctrl-style: keep latest)
        drain_key_updates(s, sys);

        // 2. Process entries
        process_entries(s, sys);

        // 3. Emit metrics periodically
        emit_metrics(s, sys);

        0 // Continue
    }
}

// ── Replay phase ────────────────────────────────────────────
//
// On startup, scans for existing WAL segment files and re-emits
// their entries through the flushed output. This allows the
// downstream pipeline (fsync_scheduler → durability_ledger →
// commit_tracker) to reconstruct committed state.
//
// Processes one chunk per step (bounded work per tick).

unsafe fn step_replay(s: &mut ModuleState, sys: &SyscallTable) -> i32 {
    // Try to open the current replay segment.
    // Use FS_OPEN without O_CREAT semantics: open the file, check its size.
    // If the file doesn't exist or is empty, replay is complete.
    // Note: the Linux FS provider opens O_RDWR|O_CREAT, so we check size
    // to distinguish real segments from auto-created empty ones.
    if s.replay_fd < 0 {
        build_segment_path(s, s.replay_seg);
        let fd = (sys.dev_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), s.path_len as usize);
        if fd < 0 {
            // FS not available — skip replay
            dev_log(sys, 3, b"[wal] no fs".as_ptr(), 11);
            s.phase = PHASE_NORMAL;
            s.segment_seq = s.replay_seg;
            return 0;
        }

        // Check file size — empty or nonexistent means no more segments
        let size = (sys.dev_call)(fd, FS_STAT, core::ptr::null_mut(), 0);
        if size <= 0 {
            // No data in this segment — replay complete
            (sys.dev_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
            dev_log(sys, 3, b"[wal] replay done".as_ptr(), 17);
            s.phase = PHASE_NORMAL;
            s.segment_seq = s.replay_seg;
            return 0;
        }

        s.replay_fd = fd;
        s.replay_file_size = size as u32;
        s.replay_pos = 0;
        dev_log(sys, 3, b"[wal] replay seg".as_ptr(), 16);
    }

    // Read one framed entry: [entry_len: u32 LE] [entry_data]
    let remaining = s.replay_file_size - s.replay_pos;
    if remaining < 4 {
        // Not enough data for a frame header — segment done
        (sys.dev_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Read 4-byte length header
    let mut len_buf = [0u8; 4];
    let n = (sys.dev_call)(s.replay_fd, FS_READ, len_buf.as_mut_ptr(), 4);
    if n < 4 {
        (sys.dev_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }
    s.replay_pos += 4;

    let entry_len = u32::from_le_bytes(len_buf) as usize;
    if entry_len == 0 || entry_len > 2048 {
        // Invalid entry — stop replay for this segment
        (sys.dev_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.replay_fd = -1;
        s.replay_seg += 1;
        return 0;
    }

    // Read entry data
    let n2 = (sys.dev_call)(s.replay_fd, FS_READ, s.msg_buf.as_mut_ptr(), entry_len);
    if (n2 as usize) < entry_len {
        (sys.dev_call)(s.replay_fd, FS_CLOSE, core::ptr::null_mut(), 0);
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

        // Re-emit as FsyncAck — entry is already durable on disk
        let poll = (sys.channel_poll)(s.out_flushed, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            let mut ack = [0u8; 17];
            wire::encode_fsync_ack(&mut ack, term, index, 0);
            wire::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack[..17]);
            dev_log(sys, 3, b"[wal] replayed".as_ptr(), 14);
        }

        s.entries_written += 1;
    }

    0
}

unsafe fn build_segment_path(s: &mut ModuleState, seq: u32) {
    let prefix = b"wal/seg_";
    let mut i = 0usize;
    for &b in prefix {
        if i < WAL_PATH_MAX { s.path_buf[i] = b; i += 1; }
    }
    for digit in (0..8).rev() {
        let nibble = ((seq >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        if i < WAL_PATH_MAX { s.path_buf[i] = ch; i += 1; }
    }
    s.path_len = i as u8;
}

// ── Normal operation ────────────────────────────────────────

unsafe fn drain_key_updates(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_key_update < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_key_update, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_key_update, &mut s.msg_buf);
        if msg_type == wire::MSG_DEK_EPOCH && plen >= 4 {
            s.dek_epoch = u32::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            ]);
        }
    }
}

unsafe fn process_entries(s: &mut ModuleState, sys: &SyscallTable) {
    // Check input readiness
    let poll_in = (sys.channel_poll)(s.in_entries, 0x01);
    if poll_in <= 0 || (poll_in as u32 & 0x01) == 0 { return; }

    // Check output readiness before consuming
    let poll_out = (sys.channel_poll)(s.out_flushed, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }

    // Read entry
    let (msg_type, plen) = wire::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
    if msg_type != wire::MSG_WAL_ENTRY || plen < 16 { return; }

    let (term, index) = wire::decode_term_index(&s.msg_buf);
    let payload_len = plen as usize;

    // Write to disk: [entry_len: u32 LE] [entry_data]
    ensure_segment_open(s, sys);
    if s.fd >= 0 {
        let len_bytes = (payload_len as u32).to_le_bytes();
        (sys.dev_call)(s.fd, FS_WRITE, len_bytes.as_ptr() as *mut u8, 4);
        (sys.dev_call)(s.fd, FS_WRITE, s.msg_buf.as_mut_ptr(), payload_len);
        (sys.dev_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
    }

    // Track state
    s.current_term = term;
    s.current_index = index;
    s.cursor += (4 + payload_len) as u32;
    s.entries_written += 1;
    s.bytes_written += payload_len as u64;

    // Emit flushed ack
    dev_log(sys, 3, b"[wal] entry ok".as_ptr(), 14);
    let mut ack_buf = [0u8; 17];
    wire::encode_fsync_ack(&mut ack_buf, term, index, 0);
    wire::channel_write_msg(sys, s.out_flushed, wire::MSG_FSYNC_ACK, &ack_buf[..17]);

    // Check segment limit
    if s.cursor >= s.segment_limit {
        // Flush and fsync remaining data, then close
        flush_block(s, sys);
        fsync_segment(s, sys);
        close_segment(s, sys);

        if s.out_compaction >= 0 {
            let mut trig = [0u8; 16];
            wire::encode_term_index(&mut trig, s.current_term, s.current_index);
            wire::channel_write_msg(sys, s.out_compaction, wire::MSG_SNAPSHOT_TRIGGER, &trig[..16]);
        }
        s.segment_seq += 1;
        s.cursor = 0;
        s.crc.reset();
    }
}

/// Open (or reopen) the current WAL segment file.
unsafe fn ensure_segment_open(s: &mut ModuleState, sys: &SyscallTable) {
    if s.fd >= 0 { return; }
    build_segment_path(s, s.segment_seq);
    s.fd = (sys.dev_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), s.path_len as usize);
    // fd < 0 means FS not available — module degrades to in-memory only.
}

unsafe fn flush_block(s: &mut ModuleState, sys: &SyscallTable) {
    if s.write_pos == 0 { return; }

    ensure_segment_open(s, sys);

    if s.fd >= 0 {
        let len = s.write_pos as usize;
        (sys.dev_call)(s.fd, FS_WRITE, s.write_buf.as_mut_ptr(), len);
    }

    s.write_pos = 0;
    s.needs_flush = false;
}

/// Fsync the current segment file.
unsafe fn fsync_segment(s: &ModuleState, sys: &SyscallTable) {
    if s.fd >= 0 {
        (sys.dev_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
    }
}

/// Close current segment and prepare for rotation.
unsafe fn close_segment(s: &mut ModuleState, sys: &SyscallTable) {
    if s.fd >= 0 {
        (sys.dev_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        s.fd = -1;
    }
}

unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&s.entries_written.to_le_bytes());
    buf[4..12].copy_from_slice(&s.bytes_written.to_le_bytes());
    buf[12..16].copy_from_slice(&s.segment_seq.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..16]);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
