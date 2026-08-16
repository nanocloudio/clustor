//! NVMe floor benchmark (L0) — `.context/rfc_performance_benchmarking.md` §6.
//!
//! Exercises the fluxor `dev_fs` contract directly (FS_OPEN_CREATE,
//! FS_WRITE, FS_FSYNC, FS_SEEK, FS_CLOSE) with no WAL/Raft above it, to
//! establish the raw storage floor every higher tier sits on:
//!
//!   - sequential write throughput at a configured block size,
//!   - per-`FS_FSYNC` latency distribution (the number the WAL lives on,
//!     shares `wire::hist::FSYNC_LATENCY_US` buckets so L0 and L1 are
//!     directly comparable),
//!   - random write throughput (seek + write within the file).
//!
//! The sequential phase runs in one of two tiers, selected by `io_mode`:
//!
//!   - L1a (`io_mode = 0`): synchronous queue-depth-1 durable writes —
//!     `FS_WRITE` plus a blocking `FS_FSYNC`. One durability round-trip is
//!     outstanding at a time, so this is a LATENCY measurement; its KB/s is
//!     the reciprocal of that latency and is not a device-bandwidth number.
//!   - L1b (`io_mode = 1`): pipelined async durability — `FS_WRITE_ASYNC`
//!     with up to `fence_depth` `FS_FSYNC_SUBMIT` fences outstanding, reaped
//!     by `FS_FSYNC_POLL`. Per-step work is O(1) submissions and O(1) polls
//!     instead of a device round-trip, so its KB/s does measure how much
//!     bandwidth the durable-write path sustains. Requires the FS provider
//!     to advertise `FS_CAP_FSYNC_ASYNC`; without it the run aborts rather
//!     than degrading to L1a behind an L1b label.
//!
//! Both tiers fold their durability latency (submit→durable for a fence)
//! into the same `FSYNC_LATENCY_US` buckets, so they share one axis. The
//! device's rated ceiling and QD scaling below the FS contract are covered
//! by the `fio` cross-check documented in the rig run procedure, not from
//! inside a cooperative module.
//!
//! Results are emitted two ways: parseable `[nvbench] ...` lines over
//! `dev_log` (the rig's UDP `log_net` channel) and typed
//! `MSG_METRIC_SAMPLE` to operations so `/metrics` carries the floor.
//!
//! The benchmark is a phased state machine advanced a bounded number of
//! blocks per `module_step` so it never overruns the cooperative step
//! budget. It runs once on startup, then idles in DONE.

#![cfg_attr(not(feature = "host-test"), no_std)]
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
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;
#[path = "../../common/log_fmt.rs"]
mod log_fmt;
use log_fmt::{log_field, log_field_i32};

// dev_fs opcodes (mirror `abi::dev_fs`; see modules/app/wal/mod.rs).
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;
/// Async durable-write tier (`fs.rs::{WRITE_ASYNC, FSYNC_SUBMIT,
/// FSYNC_POLL}`). `FS_WRITE_ASYNC` takes the same args as `FS_WRITE` and
/// returns bytes accepted; a short count is backpressure, not an error.
/// `FS_FSYNC_SUBMIT` fills an 8-byte out buffer with a u64 LE ticket and
/// returns 0; `FS_FSYNC_POLL` takes that ticket and returns 0 = durable,
/// 1 = in flight, negative errno = a fenced write failed.
const FS_WRITE_ASYNC: u32 = 0x090F;
const FS_FSYNC_SUBMIT: u32 = 0x0910;
const FS_FSYNC_POLL: u32 = 0x0911;
/// Capability discovery + the bit that gates the tier above. A provider
/// that does not advertise it (the linux host FS) cannot serve `io_mode = 1`.
const FS_CAPS: u32 = 0x09FF;
const FS_CAP_FSYNC_ASYNC: u32 = 1 << 10;

/// `io_mode` selectors. `IO_MODE_SYNC` is the latency tier: queue-depth-1
/// `FS_WRITE` + blocking `FS_FSYNC`, whose throughput number is the
/// reciprocal of durability latency, not device bandwidth. `IO_MODE_ASYNC`
/// is the pipelined tier: `FS_WRITE_ASYNC` with up to `fence_depth`
/// durability fences outstanding, which is what the throughput number
/// there actually measures.
const IO_MODE_SYNC: u16 = 0;
const IO_MODE_ASYNC: u16 = 1;

/// Outstanding-fence ring capacity, and therefore the ceiling on
/// `fence_depth`. Matches the nvme driver's async bulk-write ring, past
/// which extra fences queue in the driver rather than overlapping on the
/// device. A power of two so the head/tail wrap is a mask the compiler can
/// prove in range — no bounds-check panic path in a `no_std` PIC module.
const FENCE_RING_MAX: usize = 8;

/// Largest single `FS_WRITE` the module buffers. Covers the WAL-relevant
/// 4 KiB–64 KiB range; the `fio` cross-check covers larger blocks.
const BLOCK_MAX: usize = 64 * 1024;

const METRICS_INTERVAL_MS: u64 = 1000;

/// Sized for the longest line the module composes: the PH_DONE
/// fsync-histogram heartbeat — "[nvbench] fsyncus" (17 B) + " <u32>"
/// (11 B) per bucket (`FSYNC_LATENCY_US` bounds + overflow) +
/// " seqKBps=" (9 B) + 10 digits. The `log_fmt` helpers drop a field
/// that would not fit, so undersizing truncates rather than overruns.
const LOG_BUF_LEN: usize = 17 + (wire::hist::FSYNC_LATENCY_US.len() + 1) * 11 + 9 + 10;

/// Fallback per-step work budget when `step_budget_us` is unset, in µs.
/// Sized under the kernel's 2000 µs default step deadline with room
/// for the heartbeat. A deployment that raises `step_deadline_us`
/// raises `step_budget_us` with it — the module cannot read the
/// scheduler's deadline, so the two are declared together.
const DEFAULT_STEP_BUDGET_US: u32 = 1500;

// Phases.
const PH_OPEN: u8 = 0;
const PH_SEQ: u8 = 1;
const PH_RAND: u8 = 2;
const PH_VERIFY: u8 = 6;
const PH_REPORT: u8 = 3;
const PH_DONE: u8 = 4;
const PH_NOFS: u8 = 5;

// One-shot bracket-log guard bits (`ModuleState::dbg`). Each marks that a
// per-phase boundary log has already fired, so the decisive "last line
// before silence" diagnostic isn't drowned by per-step repeats.
const DBG_OPEN_TRY: u8 = 1 << 0; // about to issue the first FS_OPEN_CREATE
const DBG_OPEN_OK: u8 = 1 << 1; // FS_OPEN_CREATE returned a valid fd
const DBG_W_BEGIN: u8 = 1 << 2; // about to issue the first FS_WRITE
const DBG_W_DONE: u8 = 1 << 3; // first FS_WRITE returned
const DBG_FS_PRE: u8 = 1 << 4; // about to issue the first FS_FSYNC
const DBG_FS_POST: u8 = 1 << 5; // first FS_FSYNC returned
const DBG_VERIFY_OPEN: u8 = 1 << 6; // verify read-fd opened, cursor armed

/// Sectors read per PH_VERIFY step. Bounds the read-back work per
/// module_step (× 512 B) so a large file's verify never overruns the
/// step-guard deadline — the same per-step work bound `step_batch`
/// gives the write phase. 16 × ~100 µs sync reads ≈ 1.6 ms, inside the
/// 2 ms default deadline so the verify config needs no deadline override.
const VERIFY_SECTORS_PER_STEP: u32 = 16;

/// Path written by the bench. Root-dir form (`root_path = 1`) avoids the
/// parent-directory dependency on bare-metal FAT32 (no mkdir).
const PATH_ROOT: &[u8] = b"nvbench.bin";
const PATH_WAL: &[u8] = b"wal/nvbench.bin";

/// Default steps to wait for FS_OPEN_CREATE to stop returning E_AGAIN.
/// On a pi5 cold boot the FS provider (fat32) is not ready until nvme
/// enumerates the namespace and fat32 reads block0/GPT/boot/root/FAT —
/// all async, and it can take tens of seconds. E_AGAIN means "present
/// but not ready, retry"; the bench waits this many steps (~1 step/ms,
/// so ~60 s) before giving up on a stuck provider. The linux platform
/// provider is ready on step 1, so this only matters on pi5.
/// Overridable via the `open_retry_max` param.
const OPEN_RETRY_MAX_DEFAULT: u32 = 60_000;

/// FS E_AGAIN: provider present but not yet ready. Retried patiently
/// (up to `open_retry_max`), unlike a hard error. Mirrors the kernel
/// `errno::EAGAIN` the fat32/platform FS providers return pre-ready.
const FS_E_AGAIN: i32 = -11;

/// Steps to retry a HARD FS_OPEN_CREATE error (anything other than
/// E_AGAIN — e.g. ENOSYS/ENODEV when no FS provider is wired) before
/// declaring no-fs. Small, so a genuinely absent provider surfaces fast
/// instead of after the full E_AGAIN patience window.
const OPEN_HARD_FAIL_RETRIES: u32 = 200;

define_params! {
    ModuleState;

    // Bytes per FS_WRITE. Clamped to BLOCK_MAX.
    1, block_size, u32, 4096
        => |s, d, len| { s.block_size = p_u32(d, len, 0, 4096); };
    // Sequential-phase block count (total bytes = block_size * this).
    2, seq_blocks, u32, 16384
        => |s, d, len| { s.seq_blocks = p_u32(d, len, 0, 16384); };
    // FS_FSYNC after every N writes (1 = per-write, the strict-WAL floor).
    3, fsync_every, u16, 1
        => |s, d, len| { s.fsync_every = p_u16(d, len, 0, 1); };
    // Random-phase block count (seek + write within the seq file).
    4, rand_blocks, u32, 4096
        => |s, d, len| { s.rand_blocks = p_u32(d, len, 0, 4096); };
    // Blocks processed per module_step (step-budget bound).
    5, step_batch, u16, 64
        => |s, d, len| { s.step_batch = p_u16(d, len, 0, 64); };

    // Per-step work budget (µs). `step_batch` is the UPPER bound on
    // blocks per step; this is the real limiter — the batch stops early
    // once the step has consumed its budget. Declare it just under the
    // deployment's `step_deadline_us`: a fast device then does more work
    // per step and a stalled one (fat32/NVMe cache flushes run 35-150 ms
    // on the rig) yields immediately, instead of a fixed block count
    // that is simultaneously unsafe on the default deadline and an
    // override of a deliberately raised one.
    11, step_budget_us, u32, DEFAULT_STEP_BUDGET_US
        => |s, d, len| { s.step_budget_us = p_u32(d, len, 0, DEFAULT_STEP_BUDGET_US); };
    // 1 = write to a root-directory file "nvbench.bin"; 0 = "wal/nvbench.bin"
    // (the parent dir must already exist for 0). pi5/FAT32 has no mkdir, so
    // the bare-metal bench uses root. Default 0 preserves the linux path.
    6, root_path, u16, 0
        => |s, d, len| { s.root_path = p_u16(d, len, 0, 0); };
    // 1 = after the write phases, reopen the file and read it back,
    // verifying byte-exactness against the written pattern. Emits
    // `[nvbench] verify ok|FAIL`. Off by default (linux reference run).
    7, verify, u16, 0
        => |s, d, len| { s.verify = p_u16(d, len, 0, 0); };
    // Steps to retry FS_OPEN_CREATE before declaring no-fs (see
    // OPEN_RETRY_MAX_DEFAULT). Lower it to surface a failing create fast.
    8, open_retry_max, u32, OPEN_RETRY_MAX_DEFAULT
        => |s, d, len| { s.open_retry_max = p_u32(d, len, 0, OPEN_RETRY_MAX_DEFAULT); };
    // Defer the first FS_OPEN_CREATE until kernel uptime ≥ this many ms.
    // On pi5 the log_net consumer seeds its TAIL ~30 s post-boot, dropping
    // earlier one-shot lines; delaying the create+write+verify past that
    // window makes the per-step bracket logs (open/seq/fsync) observable so
    // a fault can be localised. 0 = no delay (linux reference). pi5 ~20000.
    9, start_delay_ms, u32, 0
        => |s, d, len| { s.start_delay_ms = p_u32(d, len, 0, 0); };
    // 1 = durability mode: skip create/write, FS_OPEN the existing file
    // read-only and verify it byte-exact against the pattern a prior write
    // run left (same block_size × seq_blocks). Run after a cold power cycle
    // to prove the data + dir-entry + FAT survived (NVMe Flush durability),
    // independent of the write-run's in-boot verify (which can read cache).
    10, verify_only, u16, 0
        => |s, d, len| { s.verify_only = p_u16(d, len, 0, 0); };

    // I/O tier for the sequential phase. 0 = synchronous queue-depth-1
    // durable writes (FS_WRITE + blocking FS_FSYNC): a LATENCY measurement,
    // bounded by one device round-trip at a time. 1 = pipelined async
    // durability (FS_WRITE_ASYNC + FS_FSYNC_SUBMIT/FS_FSYNC_POLL) with
    // `fence_depth` fences in flight: a BANDWIDTH measurement. Mode 1
    // requires the provider to advertise FS_CAP_FSYNC_ASYNC; on a provider
    // without it the run aborts rather than degrading to mode 0, so an
    // async baseline can never be a synchronous number under another name.
    12, io_mode, u16, IO_MODE_SYNC
        => |s, d, len| { s.io_mode = p_u16(d, len, 0, IO_MODE_SYNC); };
    // Durability fences kept outstanding in `io_mode = 1`, clamped to
    // FENCE_RING_MAX. This is the swept variable of the pipelined tier: it
    // sets how much device latency the bench overlaps. Each fence covers
    // `fsync_every` blocks, so blocks per step is bounded by
    // `fence_depth * fsync_every` — size both against the tick so the sweep
    // measures the device rather than the scheduler. Ignored in mode 0.
    13, fence_depth, u16, 1
        => |s, d, len| { s.fence_depth = p_u16(d, len, 0, 1); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_trigger: i32,  // in[0]: unused start trigger (may be unwired)
    out_metrics: i32, // out[0]: MSG_METRIC_SAMPLE to operations

    // Params
    block_size: u32,
    seq_blocks: u32,
    fsync_every: u16,
    rand_blocks: u32,
    step_batch: u16,
    step_budget_us: u32,
    root_path: u16,
    verify: u16,
    open_retry_max: u32,
    start_delay_ms: u32,
    verify_only: u16,
    io_mode: u16,
    fence_depth: u16,

    // FS capability probe (one-shot, once the provider has returned an fd).
    fs_caps: u32,
    /// 1 when the provider advertises `FS_CAP_FSYNC_ASYNC`.
    fs_async: u16,
    // Outstanding-fence ring (FIFO): ticket and its submit timestamp, so a
    // completion folds submit→durable latency into the fsync histogram.
    fence_tickets: [u64; FENCE_RING_MAX],
    fence_t0: [u64; FENCE_RING_MAX],
    fence_head: u8,
    fence_count: u8,
    fences_submitted: u32,
    fences_done: u32,
    /// FS_WRITE_ASYNC backpressure events (E_AGAIN or a short count).
    write_again: u32,
    /// FS_FSYNC_SUBMIT backpressure events (fence ring full at the provider).
    fence_again: u32,
    /// Bytes of the in-progress block the provider has already accepted. A
    /// short `FS_WRITE_ASYNC` resumes from here, so the file still holds one
    /// contiguous copy of the block pattern and the read-back verify holds.
    part: u32,

    // Run state
    phase: u8,
    fd: i32,
    open_retries: u32,
    last_open_rc: i32, // FS_OPEN_CREATE return of the last attempt
    steps: u64,        // module_step invocations (deferred_ready liveness)
    dbg: u8,           // one-shot bracket-log guard bits (DBG_*)
    verify_off: u64,
    verify_fail: u32,
    io_errors: u32,
    blocks_done: u32,
    since_fsync: u16,
    prng: u32,

    // Timing / results
    phase_start_us: u64,
    bytes_written: u64,
    fsyncs: u32,
    seq_kbps: u32,
    rand_kbps: u32,
    fsync_buckets: [u32; wire::hist::FSYNC_LATENCY_US.len() + 1],

    last_metrics_ms: u64,
    reported: bool,

    data_buf: [u8; BLOCK_MAX],
    vbuf: [u8; 512],
    log_buf: [u8; LOG_BUF_LEN],
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 { core::mem::size_of::<ModuleState>() as u32 }

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of at least
    // `module_state_size()` bytes and a live `syscalls` table.
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_trigger = in_chan;
        s.out_metrics = out_chan;

        s.phase = PH_OPEN;
        s.fd = -1;
        s.open_retries = 0;
        s.last_open_rc = 0;
        s.steps = 0;
        s.dbg = 0;
        s.verify_off = 0;
        s.verify_fail = 0;
        s.io_errors = 0;
        s.blocks_done = 0;
        s.since_fsync = 0;
        s.prng = 0x9E37_79B9;
        s.phase_start_us = 0;
        s.bytes_written = 0;
        s.fsyncs = 0;
        s.seq_kbps = 0;
        s.rand_kbps = 0;
        s.fsync_buckets = [0u32; wire::hist::FSYNC_LATENCY_US.len() + 1];
        s.last_metrics_ms = 0;
        s.reported = false;
        s.fs_caps = 0;
        s.fs_async = 0;
        s.fence_tickets = [0u64; FENCE_RING_MAX];
        s.fence_t0 = [0u64; FENCE_RING_MAX];
        s.fence_head = 0;
        s.fence_count = 0;
        s.fences_submitted = 0;
        s.fences_done = 0;
        s.write_again = 0;
        s.fence_again = 0;
        s.part = 0;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        if s.block_size as usize > BLOCK_MAX { s.block_size = BLOCK_MAX as u32; }
        if s.block_size == 0 { s.block_size = 4096; }
        if s.step_batch == 0 { s.step_batch = 64; }
        // One fence per block is the floor of the grouping knob in both
        // tiers; 0 would ask the async path to open a fence covering
        // nothing before it has written anything.
        if s.fsync_every == 0 { s.fsync_every = 1; }
        if s.fence_depth == 0 { s.fence_depth = 1; }
        if s.fence_depth as usize > FENCE_RING_MAX { s.fence_depth = FENCE_RING_MAX as u16; }
        if s.step_budget_us == 0 { s.step_budget_us = DEFAULT_STEP_BUDGET_US; }
        if s.open_retry_max == 0 { s.open_retry_max = OPEN_RETRY_MAX_DEFAULT; }
        // Durability mode skips create/write and goes straight to the
        // read-back verify of the file a prior write run persisted.
        if s.verify_only != 0 { s.phase = PH_VERIFY; }
        // Deterministic, non-zero fill so the FS provider can't optimise
        // away an all-zero write.
        for (i, b) in s.data_buf.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5A;
        }

        dev_log(sys, 3, b"[nvbench] init".as_ptr(), 14);
        0
    }
}

#[inline]
fn xorshift32(state: &mut u32) -> u32 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    x
}

/// True once this step has consumed its declared work budget. Checked
/// after each completed block so the batch ends on elapsed time rather
/// than a fixed count: a fast device gets through more blocks per step,
/// a stalled one yields after the block that stalled.
///
/// # Safety
/// `sys` must be live.
unsafe fn step_budget_spent(sys: &SyscallTable, step_t0: u64, budget_us: u32) -> bool {
    dev_micros(sys).wrapping_sub(step_t0) >= u64::from(budget_us)
}

/// Timed `FS_FSYNC` folded into the fsync-latency histogram. Returns the
/// provider rc (0 = success). On failure the latency/count are NOT recorded
/// and `io_errors` is bumped, so a failed fsync can never masquerade as a
/// fast successful one.
///
/// # Safety
/// `s.fd` must be a valid open descriptor and `sys` live.
unsafe fn fsync_timed(s: &mut ModuleState, sys: &SyscallTable) -> i32 {
    let start = dev_micros(sys);
    let rc = (sys.provider_call)(s.fd, FS_FSYNC, core::ptr::null_mut(), 0);
    if rc != 0 {
        s.io_errors = s.io_errors.saturating_add(1);
        return rc;
    }
    let elapsed = dev_micros(sys).wrapping_sub(start);
    let b = wire::hist::bucket(&wire::hist::FSYNC_LATENCY_US, elapsed);
    s.fsync_buckets[b] = s.fsync_buckets[b].saturating_add(1);
    s.fsyncs = s.fsyncs.saturating_add(1);
    rc
}

/// Abort the run after a failed I/O op: log `what` + `rc` and route to
/// `PH_REPORT` so a broken run never reports throughput as if it succeeded.
/// The caller is responsible for the `io_errors` count (`fsync_timed` bumps
/// it itself; write/seek sites bump it before calling here).
///
/// # Safety
/// `sys` must be live.
unsafe fn bench_abort(s: &mut ModuleState, sys: &SyscallTable, what: &[u8], rc: i32) {
    let p = log_field_i32(&mut s.log_buf, 0, what, rc);
    dev_log(sys, 3, s.log_buf.as_ptr(), p);
    s.phase = PH_REPORT;
}

/// One-shot FS capability probe, issued once the provider has proved
/// itself ready by returning an fd (a `FS_CAPS` call against an
/// initialising provider answers nothing useful). A provider that does not
/// implement the opcode at all leaves `fs_caps` zero, which reads as "no
/// async tier" — the conservative disposition.
///
/// # Safety
/// `sys` must be live.
unsafe fn probe_fs_caps(s: &mut ModuleState, sys: &SyscallTable) {
    let mut caps = [0u8; 4];
    let rc = (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4);
    s.fs_caps = if rc == 4 { u32::from_le_bytes(caps) } else { 0 };
    s.fs_async = u16::from(s.fs_caps & FS_CAP_FSYNC_ASYNC != 0);
}

/// Open one durability fence over everything written so far and queue it at
/// the tail of the ring with its submit timestamp. Returns true when a fence
/// was opened.
///
/// `FS_E_AGAIN` is the provider's own fence ring signalling full: counted as
/// backpressure and retried next step, with `since_fsync` left standing so
/// the blocks it covers stay unfenced until one lands. Any other non-zero rc
/// is a hard failure and aborts the run.
///
/// The caller must have checked that the ring has room (`fence_count <
/// effective depth`).
///
/// # Safety
/// `s.fd` must be a valid open descriptor and `sys` live.
unsafe fn fence_submit(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let mut tb = [0u8; 8];
    let t0 = dev_micros(sys);
    let rc = (sys.provider_call)(s.fd, FS_FSYNC_SUBMIT, tb.as_mut_ptr(), 8);
    if rc == FS_E_AGAIN {
        s.fence_again = s.fence_again.saturating_add(1);
        return false;
    }
    if rc != 0 {
        s.io_errors = s.io_errors.saturating_add(1);
        bench_abort(s, sys, b"[nvbench] FAIL fence submit rc=", rc);
        return false;
    }
    let tail = (s.fence_head as usize + s.fence_count as usize) % FENCE_RING_MAX;
    s.fence_tickets[tail] = u64::from_le_bytes(tb);
    s.fence_t0[tail] = t0;
    s.fence_count += 1;
    s.fences_submitted = s.fences_submitted.saturating_add(1);
    s.since_fsync = 0;
    true
}

/// One step of the pipelined-async sequential phase (`io_mode = 1`).
///
/// Per-step work is O(1) by construction: at most `fence_depth`
/// `FS_FSYNC_POLL`s — the reap stops at the oldest fence still in flight, so
/// it never waits on the device — followed by at most `step_batch`
/// `FS_WRITE_ASYNC` submissions, cut short by `step_budget_us`. Nothing here
/// blocks, which is the whole point of the tier: throughput is bounded by
/// device bandwidth and `fence_depth`, not by one durability round-trip.
///
/// Backpressure (`FS_E_AGAIN` or a short count from `FS_WRITE_ASYNC`,
/// `FS_E_AGAIN` from `FS_FSYNC_SUBMIT`, or a full fence ring) ends the
/// step's submissions and is counted, not treated as an error: the accepted
/// prefix of the in-flight block (`part`) and the unfenced block count
/// (`since_fsync`) both persist, so the next step resumes exactly where this
/// one stopped. A negative rc that is not E_AGAIN, and a poll reporting that
/// a fenced write failed, are hard errors that abort the run — a durability
/// gap must never be reported as throughput.
///
/// # Safety
/// `s.fd` must be a valid open descriptor and `sys` live.
unsafe fn step_seq_async(s: &mut ModuleState, sys: &SyscallTable, step_t0: u64) {
    let bs = s.block_size as usize;
    let depth = (s.fence_depth as usize).min(FENCE_RING_MAX);

    // ── Reap durable fences, oldest first (FIFO → in-order latencies). ──
    while s.fence_count > 0 {
        let head = s.fence_head as usize % FENCE_RING_MAX;
        let mut tb = s.fence_tickets[head].to_le_bytes();
        let rc = (sys.provider_call)(s.fd, FS_FSYNC_POLL, tb.as_mut_ptr(), 8);
        if rc == 1 { break; } // oldest still in flight; nothing newer can be done
        if rc != 0 {
            s.io_errors = s.io_errors.saturating_add(1);
            bench_abort(s, sys, b"[nvbench] FAIL fence poll rc=", rc);
            return;
        }
        // Submit→durable, folded into the same buckets the synchronous
        // FS_FSYNC uses, so the two tiers share one latency axis.
        let elapsed = dev_micros(sys).wrapping_sub(s.fence_t0[head]);
        let b = wire::hist::bucket(&wire::hist::FSYNC_LATENCY_US, elapsed);
        s.fsync_buckets[b] = s.fsync_buckets[b].saturating_add(1);
        s.fsyncs = s.fsyncs.saturating_add(1);
        s.fences_done = s.fences_done.saturating_add(1);
        s.fence_head = ((head + 1) % FENCE_RING_MAX) as u8;
        s.fence_count -= 1;
    }

    // ── Submit writes, opening a fence every `fsync_every` blocks. ──
    let mut n = 0u32;
    while n < s.step_batch as u32 && s.blocks_done < s.seq_blocks {
        if s.since_fsync >= s.fsync_every {
            if (s.fence_count as usize) >= depth { break; } // pipeline full
            if !fence_submit(s, sys) { break; }
        }
        // A short count leaves `part` bytes of this block accepted; the
        // remainder is offered again next step at the same file position,
        // so the on-disk pattern stays one contiguous copy per block.
        let off = s.part as usize;
        let rem = bs - off;
        let w = (sys.provider_call)(s.fd, FS_WRITE_ASYNC, s.data_buf.as_mut_ptr().add(off), rem);
        if w == FS_E_AGAIN || w == 0 {
            s.write_again = s.write_again.saturating_add(1);
            break;
        }
        if w < 0 {
            s.io_errors = s.io_errors.saturating_add(1);
            bench_abort(s, sys, b"[nvbench] FAIL write async rc=", w);
            return;
        }
        s.bytes_written += w as u64;
        if (w as usize) < rem {
            s.part += w as u32;
            s.write_again = s.write_again.saturating_add(1);
            break;
        }
        s.part = 0;
        s.blocks_done += 1;
        s.since_fsync += 1;
        n += 1;
        if step_budget_spent(sys, step_t0, s.step_budget_us) { break; }
    }

    // ── Drain: fence the tail, then let the ring empty across steps. ──
    // Each drain step costs one poll pass and returns, so waiting out the
    // last fences never spins inside a step.
    if s.blocks_done >= s.seq_blocks && s.since_fsync > 0 && (s.fence_count as usize) < depth {
        fence_submit(s, sys);
    }
    if s.phase == PH_SEQ
        && s.blocks_done >= s.seq_blocks
        && s.since_fsync == 0
        && s.fence_count == 0
    {
        seq_complete(s, sys);
    }
}

/// Score the sequential phase and route to the next one. Every byte counted
/// here is durable: the synchronous tier has fsynced its tail and the
/// pipelined tier has reaped its last fence before this is called.
///
/// # Safety
/// `sys` must be live.
unsafe fn seq_complete(s: &mut ModuleState, sys: &SyscallTable) {
    let elapsed = dev_micros(sys).wrapping_sub(s.phase_start_us);
    s.seq_kbps = kbps(s.bytes_written, elapsed);
    let mut p = 0usize;
    p = log_field(&mut s.log_buf, p, b"[nvbench] seq bs=", s.block_size);
    p = log_field(&mut s.log_buf, p, b" blocks=", s.seq_blocks);
    p = log_field(&mut s.log_buf, p, b" us=", elapsed as u32);
    p = log_field(&mut s.log_buf, p, b" KBps=", s.seq_kbps);
    dev_log(sys, 3, s.log_buf.as_ptr(), p);

    if s.io_mode == IO_MODE_ASYNC {
        // The async tier is an append-only durable-write pipeline; random
        // overwrite is not part of that contract, so the phase is announced
        // as skipped rather than silently scoring zero.
        if s.rand_blocks > 0 {
            dev_log(sys, 3, b"[nvbench] rand skipped io_mode=1".as_ptr(), 32);
        }
        s.phase = if s.verify != 0 { PH_VERIFY } else { PH_REPORT };
        return;
    }
    // Reset for the random phase over the same file.
    s.phase = PH_RAND;
    s.blocks_done = 0;
    s.since_fsync = 0;
    s.bytes_written = 0;
    s.phase_start_us = dev_micros(sys);
}

/// Throughput in KB/s = `bytes / elapsed_ms` = `bytes * 1000 / us`.
/// Saturating, integer-only. Zero elapsed → 0 (not yet measurable).
fn kbps(bytes: u64, elapsed_us: u64) -> u32 {
    if elapsed_us == 0 { return 0; }
    let v = bytes.saturating_mul(1000) / elapsed_us;
    if v > u32::MAX as u64 { u32::MAX } else { v as u32 }
}

/// Self-driven module: the bench has no input port to wake it, so it must
/// be stepped every tick regardless of channel activity. The bare-metal
/// scheduler only steps an input-less module when it advertises deferred
/// readiness (mirrors fluxor's `nvme_perf_probe`); without this, the pi5
/// scheduler never calls `module_step` and the bench sits in PH_OPEN.
/// (On linux every module is stepped, so this is a no-op there.)
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: see module_new — the kernel hands us a live state + syscalls.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let bs = s.block_size as usize;
        // `step_batch` bounds the batch; `step_budget_us` ends it early
        // (see `step_budget_deadline`). Both loops below re-check the
        // budget after each block, so one slow device op costs at most
        // one overrun instead of the whole batch.
        let batch = s.step_batch as u32;
        let step_t0 = dev_micros(sys);

        // Liveness: proves the (input-less) bench is actually being stepped
        // each tick on bare metal — i.e. that module_deferred_ready() took.
        // A flat `steps` across boots means the deferred_ready race lost.
        s.steps = s.steps.wrapping_add(1);

        // Generator readiness (one-shot). `module_deferred_ready()` exempts us
        // from the scheduler's startup readiness GATE so we step from tick 1,
        // but it leaves our OWN `ready` bit clear until we signal
        // `StepOutcome::Ready`. A load generator has no serving-state to reach
        // — it is "ready" the instant it is stepped — so we advertise Ready on
        // the first step, mirroring `foundation/ip` signalling Ready once
        // `ip_configured`. Without this, a downstream aggregator whose ONLY
        // forward upstream is this bench (operations in nvme-bench-pi5)
        // would stay ready-gated forever — its `/metrics` export never fills.
        // The bit is sticky (the scheduler clears it only on module restart),
        // so this fires exactly once; we still emit metrics this tick — only
        // the StepOutcome differs. (The busy consensus graph is unaffected: its
        // operations upstreams are non-deferred, so they are ready by
        // default and never gate it.)
        if s.steps == 1 {
            emit_metrics(s, sys);
            return 3; // StepOutcome::Ready
        }

        // Defer the first FS op past the log_net history-skip (~30 s TAIL
        // seed) so the bracket logs survive, and — more importantly — past
        // the fat32 init window, so the bench never hammers FS_OPEN_CREATE
        // while the provider is mid-init (see start_delay_ms). The hb keeps
        // emitting during the wait, so liveness stays observable.
        if (dev_millis(sys) as u32) < s.start_delay_ms {
            emit_metrics(s, sys);
            return 0;
        }

        match s.phase {
            PH_OPEN => {
                // One-shot: the last bracket line before silence localises a
                // fault. Fires once, right before the first FS_OPEN_CREATE.
                if s.dbg & DBG_OPEN_TRY == 0 {
                    s.dbg |= DBG_OPEN_TRY;
                    let now32 = dev_millis(sys) as u32;
                    let p = log_field(&mut s.log_buf, 0, b"[nvbench] open try ms=", now32);
                    dev_log(sys, 3, s.log_buf.as_ptr(), p);
                }
                // Path is ptr+len with NO null terminator (the FS provider
                // takes exactly `len` bytes — a trailing \0 becomes part of
                // the filename and the open fails).
                let path: &[u8] = if s.root_path != 0 { PATH_ROOT } else { PATH_WAL };
                s.fd = (sys.provider_call)(-1, FS_OPEN_CREATE, path.as_ptr() as *mut u8, path.len());
                s.last_open_rc = s.fd;
                if s.fd < 0 {
                    // E_AGAIN means the FS provider (fat32 on bare metal) is
                    // present but still coming up (nvme enumeration, BPB/GPT/
                    // root/FAT reads) — retry patiently up to `open_retry_max`.
                    // A HARD error (ENOSYS/ENODEV: no FS provider wired) gives
                    // up fast. The rc + retry count are emitted every heartbeat
                    // (see emit_metrics) so the wait is visible, not silent.
                    s.open_retries += 1;
                    let hard = s.fd != FS_E_AGAIN;
                    let give_up = s.open_retries >= s.open_retry_max
                        || (hard && s.open_retries >= OPEN_HARD_FAIL_RETRIES);
                    if give_up {
                        let rc = (-s.fd) as u32;
                        let p = log_field(&mut s.log_buf, 0, b"[nvbench] no fs rc=", rc);
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                        s.phase = PH_NOFS;
                    }
                } else {
                    if s.dbg & DBG_OPEN_OK == 0 {
                        s.dbg |= DBG_OPEN_OK;
                        let p = log_field_i32(&mut s.log_buf, 0, b"[nvbench] open ok fd=", s.fd);
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                    }
                    // The fd proves the provider is up, so its capability
                    // bitmap is now meaningful. `io_mode = 1` on a provider
                    // without FS_CAP_FSYNC_ASYNC aborts with a named reason:
                    // falling back to the synchronous path would publish a
                    // queue-depth-1 latency number as a pipelined-bandwidth
                    // one, which is the mislabelling this tier exists to end.
                    probe_fs_caps(s, sys);
                    if s.io_mode == IO_MODE_ASYNC && s.fs_async == 0 {
                        let p = log_field(
                            &mut s.log_buf, 0, b"[nvbench] FAIL async unsupported caps=", s.fs_caps,
                        );
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                        s.phase = PH_REPORT;
                    } else {
                        s.phase = PH_SEQ;
                        s.blocks_done = 0;
                        s.since_fsync = 0;
                        s.bytes_written = 0;
                        s.phase_start_us = dev_micros(sys);
                    }
                }
            }
            PH_SEQ if s.io_mode == IO_MODE_ASYNC => step_seq_async(s, sys, step_t0),
            PH_SEQ => {
                let mut n = 0u32;
                while n < batch && s.blocks_done < s.seq_blocks {
                    // One-shot bracket around the very first FS_WRITE: if the
                    // module goes silent here, the write path is the fault.
                    if s.dbg & DBG_W_BEGIN == 0 {
                        s.dbg |= DBG_W_BEGIN;
                        let p = log_field(&mut s.log_buf, 0, b"[nvbench] w begin bs=", bs as u32);
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                    }
                    let wrc = (sys.provider_call)(s.fd, FS_WRITE, s.data_buf.as_mut_ptr(), bs);
                    if s.dbg & DBG_W_DONE == 0 {
                        s.dbg |= DBG_W_DONE;
                        let p = log_field_i32(&mut s.log_buf, 0, b"[nvbench] w0 rc=", wrc);
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                    }
                    // A correct FS_WRITE returns exactly `bs`. A short write or
                    // negative errno (e.g. disk full) must not advance the
                    // byte/block counters — that would fabricate throughput.
                    if wrc != bs as i32 {
                        s.io_errors = s.io_errors.saturating_add(1);
                        bench_abort(s, sys, b"[nvbench] FAIL write rc=", wrc);
                        break;
                    }
                    s.bytes_written += bs as u64;
                    s.since_fsync += 1;
                    if s.since_fsync >= s.fsync_every {
                        if s.dbg & DBG_FS_PRE == 0 {
                            s.dbg |= DBG_FS_PRE;
                            dev_log(sys, 3, b"[nvbench] fsync0 pre".as_ptr(), 20);
                        }
                        let frc = fsync_timed(s, sys);
                        if s.dbg & DBG_FS_POST == 0 {
                            s.dbg |= DBG_FS_POST;
                            dev_log(sys, 3, b"[nvbench] fsync0 post".as_ptr(), 21);
                        }
                        if frc != 0 { bench_abort(s, sys, b"[nvbench] FAIL fsync rc=", frc); break; }
                        s.since_fsync = 0;
                    }
                    s.blocks_done += 1;
                    n += 1;
                    if step_budget_spent(sys, step_t0, s.step_budget_us) { break; }
                }
                if s.phase == PH_SEQ && s.blocks_done >= s.seq_blocks {
                    if s.since_fsync > 0 {
                        let frc = fsync_timed(s, sys);
                        s.since_fsync = 0;
                        if frc != 0 { bench_abort(s, sys, b"[nvbench] FAIL fsync rc=", frc); }
                    }
                }
                if s.phase == PH_SEQ && s.blocks_done >= s.seq_blocks {
                    seq_complete(s, sys);
                }
            }
            PH_RAND => {
                let span = if s.seq_blocks == 0 { 1 } else { s.seq_blocks };
                let mut n = 0u32;
                while n < batch && s.blocks_done < s.rand_blocks {
                    let blk = xorshift32(&mut s.prng) % span;
                    let off = (blk as u64 * bs as u64) as u32;
                    let arg = off.to_le_bytes();
                    let src = (sys.provider_call)(s.fd, FS_SEEK, arg.as_ptr() as *mut u8, 4);
                    // Success is any non-negative rc: providers may
                    // return the resulting absolute offset.
                    if src < 0 {
                        s.io_errors = s.io_errors.saturating_add(1);
                        bench_abort(s, sys, b"[nvbench] FAIL seek rc=", src);
                        break;
                    }
                    let wrc = (sys.provider_call)(s.fd, FS_WRITE, s.data_buf.as_mut_ptr(), bs);
                    if wrc != bs as i32 {
                        s.io_errors = s.io_errors.saturating_add(1);
                        bench_abort(s, sys, b"[nvbench] FAIL write rc=", wrc);
                        break;
                    }
                    s.bytes_written += bs as u64;
                    s.since_fsync += 1;
                    if s.since_fsync >= s.fsync_every {
                        let frc = fsync_timed(s, sys);
                        if frc != 0 { bench_abort(s, sys, b"[nvbench] FAIL fsync rc=", frc); break; }
                        s.since_fsync = 0;
                    }
                    s.blocks_done += 1;
                    n += 1;
                    if step_budget_spent(sys, step_t0, s.step_budget_us) { break; }
                }
                if s.phase == PH_RAND && s.blocks_done >= s.rand_blocks {
                    if s.since_fsync > 0 {
                        let frc = fsync_timed(s, sys);
                        s.since_fsync = 0;
                        if frc != 0 { bench_abort(s, sys, b"[nvbench] FAIL fsync rc=", frc); }
                    }
                }
                if s.phase == PH_RAND && s.blocks_done >= s.rand_blocks {
                    let elapsed = dev_micros(sys).wrapping_sub(s.phase_start_us);
                    s.rand_kbps = kbps(s.bytes_written, elapsed);
                    let mut p = 0usize;
                    p = log_field(&mut s.log_buf, p, b"[nvbench] rand bs=", s.block_size);
                    p = log_field(&mut s.log_buf, p, b" blocks=", s.rand_blocks);
                    p = log_field(&mut s.log_buf, p, b" us=", elapsed as u32);
                    p = log_field(&mut s.log_buf, p, b" KBps=", s.rand_kbps);
                    dev_log(sys, 3, s.log_buf.as_ptr(), p);
                    s.phase = if s.verify != 0 { PH_VERIFY } else { PH_REPORT };
                }
            }
            PH_VERIFY => {
                // Reopen the file read-only and read it back incrementally,
                // verifying byte-exactness against the written pattern (the
                // file is `data_buf[0..bs]` repeated `seq_blocks` times).
                // Proves the FS write contract (create/append/fsync) round-
                // trips on the real device — and, run standalone after a cold
                // power cycle (verify_only), that the data was durably
                // NAND-committed, not just cached. Bounded to
                // VERIFY_SECTORS_PER_STEP reads/step so a large file never
                // overruns the step-guard deadline.
                let bs_nz = if bs == 0 { 4096u64 } else { bs as u64 };
                let total = (s.seq_blocks as u64).wrapping_mul(bs_nz);

                // First entry: close any write fd, open read-only, arm cursor.
                // The open retries on E_AGAIN (fat32 still initialising — at a
                // larger tick its async init is slow, so even past start_delay
                // the provider may not be ready), exactly like PH_OPEN. Only a
                // HARD error (e.g. ENOENT: file absent after a cold boot) is a
                // real verify failure — that IS the durability signal.
                if s.dbg & DBG_VERIFY_OPEN == 0 {
                    if s.fd >= 0 {
                        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                        s.fd = -1;
                    }
                    let path: &[u8] = if s.root_path != 0 { PATH_ROOT } else { PATH_WAL };
                    let rfd = (sys.provider_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path.len());
                    s.last_open_rc = rfd;
                    if rfd == FS_E_AGAIN {
                        // Provider not ready — retry next step (don't arm).
                        s.open_retries += 1;
                        if s.open_retries < s.open_retry_max {
                            emit_metrics(s, sys);
                            return 0;
                        }
                        // Fall through to fail on persistent E_AGAIN.
                    }
                    s.fd = rfd;
                    s.verify_off = 0;
                    s.dbg |= DBG_VERIFY_OPEN;
                    if s.fd < 0 {
                        // Hard open failure (file absent / provider gone) — a
                        // durability failure in verify_only mode.
                        s.verify_fail = 1;
                        let p = log_field_i32(
                            &mut s.log_buf, 0, b"[nvbench] verify FAIL open rfd=", s.fd,
                        );
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                        s.phase = PH_REPORT;
                    } else {
                        // Open succeeded — do the read-back on subsequent steps
                        // so the open's directory walk and the first read chunk
                        // don't share one step's deadline.
                        emit_metrics(s, sys);
                        return 0;
                    }
                }

                if s.phase == PH_VERIFY && s.fd >= 0 {
                    let mut read_sectors = 0u32;
                    let mut bad = false;
                    while s.verify_off < total && read_sectors < VERIFY_SECTORS_PER_STEP {
                        let n = (sys.provider_call)(s.fd, FS_READ, s.vbuf.as_mut_ptr(), 512);
                        if n <= 0 { bad = true; break; }
                        // The written pattern is `data_buf[0..bs]` repeated, so
                        // the file byte at offset `verify_off + i` corresponds
                        // to `data_buf[(verify_off + i) % bs]`. Wrap at the block
                        // boundary — a 512-byte sector can span several
                        // repetitions when bs < 512, and without the wrap the
                        // index also runs past `data_buf` (OOB) when bs is large.
                        let bw = bs_nz as usize;
                        let base = (s.verify_off % bs_nz) as usize;
                        let mut i = 0usize;
                        while i < n as usize {
                            if s.vbuf[i] != s.data_buf[(base + i) % bw] { bad = true; break; }
                            i += 1;
                        }
                        if bad { break; }
                        s.verify_off += n as u64;
                        read_sectors += 1;
                    }
                    if bad || s.verify_off >= total {
                        (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                        s.fd = -1;
                        let mut p = 0usize;
                        if !bad {
                            p = log_field(&mut s.log_buf, p, b"[nvbench] verify ok blocks=", s.seq_blocks);
                            p = log_field(&mut s.log_buf, p, b" bytes=", total as u32);
                        } else {
                            s.verify_fail = 1;
                            let off32 = s.verify_off as u32;
                            p = log_field(&mut s.log_buf, p, b"[nvbench] verify FAIL off=", off32);
                            p = log_field(&mut s.log_buf, p, b" bytes=", total as u32);
                        }
                        dev_log(sys, 3, s.log_buf.as_ptr(), p);
                        s.phase = PH_REPORT;
                    }
                }
            }
            PH_REPORT => {
                if s.fd >= 0 {
                    (sys.provider_call)(s.fd, FS_CLOSE, core::ptr::null_mut(), 0);
                    s.fd = -1;
                }
                let mut p = 0usize;
                p = log_field(&mut s.log_buf, p, b"[nvbench] done fsyncs=", s.fsyncs);
                p = log_field(&mut s.log_buf, p, b" seqKBps=", s.seq_kbps);
                p = log_field(&mut s.log_buf, p, b" randKBps=", s.rand_kbps);
                dev_log(sys, 3, s.log_buf.as_ptr(), p);
                s.reported = true;
                s.phase = PH_DONE;
            }
            _ => {}
        }

        // Emit metrics each second so /metrics carries live progress and
        // the final floor numbers.
        emit_metrics(s, sys);
        0
    }
}

/// Emit bench counters, throughput gauges, and the fsync-latency
/// histogram as typed samples (RFC §4.3). Module id 0x16, partition 0.
///
/// # Safety
/// `sys` must be a live syscall table.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // Non-one-shot heartbeat over log_net. One-shot phase-transition lines
    // (`[nvbench] seq …`) are dropped by the log_net history-skip when they
    // fire before the consumer's TAIL seed (~30 s post-boot); this steady
    // line is always observable and answers "is the bench being stepped,
    // and what is FS_OPEN_CREATE returning?" on every boot.
    {
        let mut p = 0usize;
        p = log_field(&mut s.log_buf, p, b"[nvbench] hb ph=", u32::from(s.phase));
        p = log_field(&mut s.log_buf, p, b" steps=", s.steps as u32);
        p = log_field_i32(&mut s.log_buf, p, b" rc=", s.last_open_rc);
        p = log_field(&mut s.log_buf, p, b" retries=", s.open_retries);
        p = log_field_i32(&mut s.log_buf, p, b" fd=", s.fd);
        p = log_field(&mut s.log_buf, p, b" fsyncs=", s.fsyncs);
        p = log_field(&mut s.log_buf, p, b" vfail=", s.verify_fail);
        dev_log(sys, 3, s.log_buf.as_ptr(), p);

        // Pipeline occupancy, emitted every heartbeat (not one-shot) so a
        // `fence_depth` sweep is interpretable: a depth that never fills
        // (`outst` below `depth`, `wagain`/`fagain` at zero) was not the
        // limiter, and a run whose `cap` is 0 measured nothing at all.
        if s.io_mode == IO_MODE_ASYNC {
            let mut p = 0usize;
            p = log_field(&mut s.log_buf, p, b"[nvbench] async cap=", u32::from(s.fs_async));
            p = log_field(&mut s.log_buf, p, b" depth=", u32::from(s.fence_depth));
            p = log_field(&mut s.log_buf, p, b" subm=", s.fences_submitted);
            p = log_field(&mut s.log_buf, p, b" done=", s.fences_done);
            p = log_field(&mut s.log_buf, p, b" outst=", u32::from(s.fence_count));
            p = log_field(&mut s.log_buf, p, b" wagain=", s.write_again);
            p = log_field(&mut s.log_buf, p, b" fagain=", s.fence_again);
            dev_log(sys, 3, s.log_buf.as_ptr(), p);
        }

        // Once the run is DONE, re-emit the fsync-latency histogram every
        // heartbeat. The one-shot PH_REPORT line is unreliable on the rig —
        // the log_net ring overflows during the write/verify burst and drops
        // it ([log_net: dropped …]). In the idle PH_DONE period there is no
        // log pressure, so this line lands and is capturable at any time.
        // Bucket bounds: wire::hist::FSYNC_LATENCY_US (250 µs … 100 ms) + 1
        // overflow bucket. This is the L0/L1 WAL-path number the WAL lives on.
        // This is the line LOG_BUF_LEN is sized for.
        if s.phase == PH_DONE {
            let tag = b"[nvbench] fsyncus";
            s.log_buf[..tag.len()].copy_from_slice(tag);
            let mut q = tag.len();
            for i in 0..s.fsync_buckets.len() {
                q = log_field(&mut s.log_buf, q, b" ", s.fsync_buckets[i]);
            }
            q = log_field(&mut s.log_buf, q, b" seqKBps=", s.seq_kbps);
            dev_log(sys, 3, s.log_buf.as_ptr(), q);
        }
    }

    if s.out_metrics < 0 { return; }
    let mid = wire::SOURCE_ID_NVME_BENCH;
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_PHASE, wire::METRIC_KIND_GAUGE, i64::from(s.phase));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_BYTES_WRITTEN, wire::METRIC_KIND_COUNTER, s.bytes_written as i64);
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_SEQ_KBPS, wire::METRIC_KIND_GAUGE, i64::from(s.seq_kbps));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_RAND_KBPS, wire::METRIC_KIND_GAUGE, i64::from(s.rand_kbps));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_FSYNCS, wire::METRIC_KIND_COUNTER, i64::from(s.fsyncs));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_STEPS, wire::METRIC_KIND_COUNTER, s.steps as i64);
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_OPEN_RC, wire::METRIC_KIND_GAUGE, i64::from(s.last_open_rc));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_OPEN_RETRIES, wire::METRIC_KIND_COUNTER, i64::from(s.open_retries));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_VERIFY_FAIL, wire::METRIC_KIND_GAUGE, i64::from(s.verify_fail));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_IO_ERRORS, wire::METRIC_KIND_COUNTER, i64::from(s.io_errors));
    // Pipeline occupancy: a depth sweep is only interpretable if the
    // scrape can tell a full pipeline from a starved one.
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_IO_MODE, wire::METRIC_KIND_GAUGE, i64::from(s.io_mode));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_FENCES_SUBMITTED, wire::METRIC_KIND_COUNTER, i64::from(s.fences_submitted));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_FENCES_DONE, wire::METRIC_KIND_COUNTER, i64::from(s.fences_done));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_FENCES_OUTSTANDING, wire::METRIC_KIND_GAUGE, i64::from(s.fence_count));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_WRITE_AGAIN, wire::METRIC_KIND_COUNTER, i64::from(s.write_again));
    emit_sample(s, sys, mid, wire::metric_ids::NVBENCH_FENCE_AGAIN, wire::METRIC_KIND_COUNTER, i64::from(s.fence_again));
    // Cumulative bucket counts per the wire contract (wire::hist): emit the
    // running prefix sum so bucket i = count of samples <= bound[i].
    let base = wire::hist::HIST_BASE;
    let mut cum: i64 = 0;
    for i in 0..s.fsync_buckets.len() {
        cum += i64::from(s.fsync_buckets[i]);
        emit_sample(s, sys, mid, base + i as u16, wire::METRIC_KIND_HISTOGRAM, cum);
    }
}

/// Emit one typed sample if `out_metrics` has write space.
///
/// # Safety
/// `sys` must be a live syscall table.
unsafe fn emit_sample(
    s: &ModuleState,
    sys: &SyscallTable,
    module_id: u8,
    metric_id: u16,
    kind: u8,
    value: i64,
) {
    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
    wire::encode_metric_sample(&mut buf, module_id, 0, metric_id, kind, value);
    wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
}
