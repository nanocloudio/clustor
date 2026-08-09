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
//! All I/O is single-stream (queue depth 1); QD scaling and the device's
//! rated ceiling are covered by the `fio` cross-check documented in the
//! rig run procedure, not from inside a cooperative module.
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

// dev_fs opcodes (mirror `abi::dev_fs`; see modules/app/wal/mod.rs).
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPEN_CREATE: u32 = 0x0909;

/// Largest single `FS_WRITE` the module buffers. Covers the WAL-relevant
/// 4 KiB–64 KiB range; the `fio` cross-check covers larger blocks.
const BLOCK_MAX: usize = 64 * 1024;

const METRICS_INTERVAL_MS: u64 = 1000;

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
    root_path: u16,
    verify: u16,
    open_retry_max: u32,
    start_delay_ms: u32,
    verify_only: u16,

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
    log_buf: [u8; 128],
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

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        if s.block_size as usize > BLOCK_MAX { s.block_size = BLOCK_MAX as u32; }
        if s.block_size == 0 { s.block_size = 4096; }
        if s.step_batch == 0 { s.step_batch = 64; }
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
    let mut p = 0usize;
    let lb = s.log_buf.as_mut_ptr();
    p = log_field_i32(lb, p, what, rc);
    dev_log(sys, 3, lb, p);
    s.phase = PH_REPORT;
}

/// Append `tag` + decimal `val` into `log_buf` at `pos`; returns new pos.
///
/// # Safety
/// `log_buf` must have room for `tag.len() + 10` bytes at `pos`.
unsafe fn log_field(buf: *mut u8, pos: usize, tag: &[u8], val: u32) -> usize {
    core::ptr::copy_nonoverlapping(tag.as_ptr(), buf.add(pos), tag.len());
    pos + tag.len() + fmt_u32_raw(buf.add(pos + tag.len()), val)
}

/// Like `log_field` but for a possibly-negative `i32` (e.g. an errno-style
/// FS return code): writes `tag`, a leading `-` when negative, then the
/// magnitude. `FS_OPEN_CREATE` returns a tagged fd (positive) or `-errno`.
///
/// # Safety
/// `buf` must have room for `tag.len() + 11` bytes at `pos`.
unsafe fn log_field_i32(buf: *mut u8, pos: usize, tag: &[u8], val: i32) -> usize {
    core::ptr::copy_nonoverlapping(tag.as_ptr(), buf.add(pos), tag.len());
    let mut p = pos + tag.len();
    let mag = if val < 0 {
        *buf.add(p) = b'-';
        p += 1;
        (val as i64).unsigned_abs() as u32
    } else {
        val as u32
    };
    p + fmt_u32_raw(buf.add(p), mag)
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
        let batch = s.step_batch as u32;

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
                    let mut p = 0usize;
                    let lb = s.log_buf.as_mut_ptr();
                    p = log_field(lb, p, b"[nvbench] open try ms=", dev_millis(sys) as u32);
                    dev_log(sys, 3, lb, p);
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
                        let mut p = 0usize;
                        let lb = s.log_buf.as_mut_ptr();
                        p = log_field(lb, p, b"[nvbench] no fs rc=", (-s.fd) as u32);
                        dev_log(sys, 3, lb, p);
                        s.phase = PH_NOFS;
                    }
                } else {
                    if s.dbg & DBG_OPEN_OK == 0 {
                        s.dbg |= DBG_OPEN_OK;
                        let mut p = 0usize;
                        let lb = s.log_buf.as_mut_ptr();
                        p = log_field_i32(lb, p, b"[nvbench] open ok fd=", s.fd);
                        dev_log(sys, 3, lb, p);
                    }
                    s.phase = PH_SEQ;
                    s.blocks_done = 0;
                    s.since_fsync = 0;
                    s.bytes_written = 0;
                    s.phase_start_us = dev_micros(sys);
                }
            }
            PH_SEQ => {
                let mut n = 0u32;
                while n < batch && s.blocks_done < s.seq_blocks {
                    // One-shot bracket around the very first FS_WRITE: if the
                    // module goes silent here, the write path is the fault.
                    if s.dbg & DBG_W_BEGIN == 0 {
                        s.dbg |= DBG_W_BEGIN;
                        let mut p = 0usize;
                        let lb = s.log_buf.as_mut_ptr();
                        p = log_field(lb, p, b"[nvbench] w begin bs=", bs as u32);
                        dev_log(sys, 3, lb, p);
                    }
                    let wrc = (sys.provider_call)(s.fd, FS_WRITE, s.data_buf.as_mut_ptr(), bs);
                    if s.dbg & DBG_W_DONE == 0 {
                        s.dbg |= DBG_W_DONE;
                        let mut p = 0usize;
                        let lb = s.log_buf.as_mut_ptr();
                        p = log_field_i32(lb, p, b"[nvbench] w0 rc=", wrc);
                        dev_log(sys, 3, lb, p);
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
                }
                if s.phase == PH_SEQ && s.blocks_done >= s.seq_blocks {
                    if s.since_fsync > 0 {
                        let frc = fsync_timed(s, sys);
                        s.since_fsync = 0;
                        if frc != 0 { bench_abort(s, sys, b"[nvbench] FAIL fsync rc=", frc); }
                    }
                }
                if s.phase == PH_SEQ && s.blocks_done >= s.seq_blocks {
                    let elapsed = dev_micros(sys).wrapping_sub(s.phase_start_us);
                    s.seq_kbps = kbps(s.bytes_written, elapsed);
                    let mut p = 0usize;
                    let lb = s.log_buf.as_mut_ptr();
                    p = log_field(lb, p, b"[nvbench] seq bs=", s.block_size);
                    p = log_field(lb, p, b" blocks=", s.seq_blocks);
                    p = log_field(lb, p, b" us=", elapsed as u32);
                    p = log_field(lb, p, b" KBps=", s.seq_kbps);
                    dev_log(sys, 3, lb, p);
                    // Reset for the random phase over the same file.
                    s.phase = PH_RAND;
                    s.blocks_done = 0;
                    s.since_fsync = 0;
                    s.bytes_written = 0;
                    s.phase_start_us = dev_micros(sys);
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
                    if src != 0 {
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
                    let lb = s.log_buf.as_mut_ptr();
                    p = log_field(lb, p, b"[nvbench] rand bs=", s.block_size);
                    p = log_field(lb, p, b" blocks=", s.rand_blocks);
                    p = log_field(lb, p, b" us=", elapsed as u32);
                    p = log_field(lb, p, b" KBps=", s.rand_kbps);
                    dev_log(sys, 3, lb, p);
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
                        let mut p = 0usize;
                        let lb = s.log_buf.as_mut_ptr();
                        p = log_field_i32(lb, p, b"[nvbench] verify FAIL open rfd=", s.fd);
                        dev_log(sys, 3, lb, p);
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
                        let lb = s.log_buf.as_mut_ptr();
                        if !bad {
                            p = log_field(lb, p, b"[nvbench] verify ok blocks=", s.seq_blocks);
                            p = log_field(lb, p, b" bytes=", total as u32);
                        } else {
                            s.verify_fail = 1;
                            p = log_field(lb, p, b"[nvbench] verify FAIL off=", s.verify_off as u32);
                            p = log_field(lb, p, b" bytes=", total as u32);
                        }
                        dev_log(sys, 3, lb, p);
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
                let lb = s.log_buf.as_mut_ptr();
                p = log_field(lb, p, b"[nvbench] done fsyncs=", s.fsyncs);
                p = log_field(lb, p, b" seqKBps=", s.seq_kbps);
                p = log_field(lb, p, b" randKBps=", s.rand_kbps);
                dev_log(sys, 3, lb, p);
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
        let lb = s.log_buf.as_mut_ptr();
        p = log_field(lb, p, b"[nvbench] hb ph=", u32::from(s.phase));
        p = log_field(lb, p, b" steps=", s.steps as u32);
        p = log_field_i32(lb, p, b" rc=", s.last_open_rc);
        p = log_field(lb, p, b" retries=", s.open_retries);
        p = log_field_i32(lb, p, b" fd=", s.fd);
        p = log_field(lb, p, b" fsyncs=", s.fsyncs);
        p = log_field(lb, p, b" vfail=", s.verify_fail);
        dev_log(sys, 3, lb, p);

        // Once the run is DONE, re-emit the fsync-latency histogram every
        // heartbeat. The one-shot PH_REPORT line is unreliable on the rig —
        // the log_net ring overflows during the write/verify burst and drops
        // it ([log_net: dropped …]). In the idle PH_DONE period there is no
        // log pressure, so this line lands and is capturable at any time.
        // Bucket bounds: wire::hist::FSYNC_LATENCY_US (250 µs … 100 ms) + 1
        // overflow bucket. This is the L0/L1 WAL-path number the WAL lives on.
        if s.phase == PH_DONE {
            let hb = s.log_buf.as_mut_ptr();
            let tag = b"[nvbench] fsyncus";
            core::ptr::copy_nonoverlapping(tag.as_ptr(), hb, tag.len());
            let mut q = tag.len();
            for i in 0..s.fsync_buckets.len() {
                *hb.add(q) = b' '; q += 1;
                q += fmt_u32_raw(hb.add(q), s.fsync_buckets[i]);
            }
            q = log_field(hb, q, b" seqKBps=", s.seq_kbps);
            dev_log(sys, 3, hb, q);
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
