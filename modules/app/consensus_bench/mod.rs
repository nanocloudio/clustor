//! Consensus load injector (L2) — `.context/rfc_performance_benchmarking.md` §6.
//!
//! Injects `MSG_CLIENT_PROPOSAL` bodies straight into
//! `raft_engine.proposals` (the untagged proposal port), bypassing the
//! client codec / throttle gate so the measurement isolates the
//! consensus + durability path: `raft_engine → wal → durability_ledger
//! → commit_tracker`. The numbers we care about — propose→commit
//! latency and commit throughput — come from the already-instrumented
//! producers (`clustor.raft.commit_latency_ms`, commit_tracker's
//! `commit_advances`, the WAL fsync histogram). This module only drives
//! offered load and reports how much it injected.
//!
//! Phased: wait `warmup_ms` for the single node to self-elect leader,
//! then inject up to `batch_per_step` proposals per step (bounded by
//! channel backpressure) until `total` is reached, then idle. Offered
//! load is closed-loop / saturating — for peak throughput. (Open-loop
//! Poisson arrival for coordinated-omission-free latency is L3 driver
//! work, off-DUT; see RFC §2.3.)

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

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

const METRICS_INTERVAL_MS: u64 = 1000;
const BODY_MAX: usize = 1024;

const PH_WARMUP: u8 = 0;
const PH_INJECT: u8 = 1;
const PH_DONE: u8 = 2;

define_params! {
    ModuleState;

    // Total proposals to inject before idling.
    1, total, u32, 5000
        => |s, d, len| { s.total = p_u32(d, len, 0, 5000); };
    // Proposal body size in bytes (clamped to BODY_MAX).
    2, body_size, u16, 64
        => |s, d, len| { s.body_size = p_u16(d, len, 0, 64); };
    // Proposals offered per module_step (saturating; channel backpressure caps it).
    3, batch_per_step, u16, 8
        => |s, d, len| { s.batch_per_step = p_u16(d, len, 0, 8); };
    // Warmup window (ms) before injecting, to let the node elect a leader.
    4, warmup_ms, u16, 2000
        => |s, d, len| { s.warmup_ms = p_u16(d, len, 0, 2000); };
    // Inject the batch only every Nth step (1 = every step). With a 1 ms
    // tick this rate-limits offered load: batch_per_step / inject_period
    // per ms. Keep offered rate at or below sustainable WAL throughput so
    // the raft→wal channel doesn't overflow (raft has no backpressure on
    // this path — it is normally fronted by throttle_gate, which this
    // direct-injection bench deliberately bypasses to isolate consensus).
    5, inject_period, u16, 1
        => |s, d, len| { s.inject_period = p_u16(d, len, 0, 1); };
    // 0 = untagged body straight to raft_engine.proposals (isolates
    // consensus). 1 = tagged `[correlation_id:u64 LE][body]` for
    // throttle_gate.requests (exercises admission control on the way in).
    6, tagged, u16, 0
        => |s, d, len| { s.tagged = p_u16(d, len, 0, 0); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_trigger: i32,   // in[0]: unused start trigger
    out_proposals: i32, // out[0]: MSG_CLIENT_PROPOSAL → raft_engine.proposals
    out_metrics: i32,   // out[1]: MSG_METRIC_SAMPLE → telemetry_agg

    total: u32,
    body_size: u16,
    batch_per_step: u16,
    warmup_ms: u16,
    inject_period: u16,
    tagged: u16,

    phase: u8,
    step_ctr: u32,
    start_ms: u64,
    sent: u32,
    blocked: u32,
    last_metrics_ms: u64,

    body_buf: [u8; BODY_MAX],
    log_buf: [u8; 96],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 { core::mem::size_of::<ModuleState>() as u32 }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    // SAFETY: the kernel hands us a live, exclusively-borrowed state of
    // at least module_state_size() bytes and a live syscall table.
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_trigger = in_chan;
        s.out_proposals = out_chan;
        s.out_metrics = dev_channel_port(sys, 1, 1);

        s.phase = PH_WARMUP;
        s.step_ctr = 0;
        s.sent = 0;
        s.blocked = 0;
        s.last_metrics_ms = 0;
        s.start_ms = dev_millis(sys);

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Leave room for the optional 8-byte correlation_id prefix.
        if s.body_size as usize + wire::TAGGED_PROPOSAL_HDR > BODY_MAX {
            s.body_size = (BODY_MAX - wire::TAGGED_PROPOSAL_HDR) as u16;
        }
        if s.body_size == 0 { s.body_size = 64; }
        if s.batch_per_step == 0 { s.batch_per_step = 8; }
        if s.inject_period == 0 { s.inject_period = 1; }
        for (i, b) in s.body_buf.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x3C;
        }

        dev_log(sys, 3, b"[cbench] init".as_ptr(), 13);
        0
    }
}

/// Append `tag` + decimal `val` into `buf` at `pos`; returns new pos.
///
/// # Safety
/// `buf` must have room for `tag.len() + 10` bytes at `pos`.
unsafe fn log_field(buf: *mut u8, pos: usize, tag: &[u8], val: u32) -> usize {
    core::ptr::copy_nonoverlapping(tag.as_ptr(), buf.add(pos), tag.len());
    pos + tag.len() + fmt_u32_raw(buf.add(pos + tag.len()), val)
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: see module_new.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        match s.phase {
            PH_WARMUP => {
                if now.wrapping_sub(s.start_ms) >= s.warmup_ms as u64 {
                    s.phase = PH_INJECT;
                    s.start_ms = now; // re-anchor for elapsed
                    dev_log(sys, 3, b"[cbench] start".as_ptr(), 14);
                }
            }
            PH_INJECT => {
                // Countdown gate (no `%`, which would emit a rem-by-zero
                // panic path with no handler in no_std). inject_period is
                // clamped >= 1 in module_new.
                s.step_ctr = s.step_ctr.wrapping_add(1);
                let due = s.step_ctr >= s.inject_period as u32;
                if due {
                    s.step_ctr = 0;
                }
                if due && s.out_proposals >= 0 {
                    let mut n = 0u16;
                    while n < s.batch_per_step && s.sent < s.total {
                        let poll = (sys.channel_poll)(s.out_proposals, 0x02);
                        if poll <= 0 || (poll as u32 & 0x02) == 0 {
                            s.blocked = s.blocked.saturating_add(1);
                            break; // backpressure — try again next step
                        }
                        let bs = s.body_size as usize;
                        let payload = if s.tagged != 0 {
                            // [correlation_id:u64 LE][body]; cid must be
                            // non-zero (0 is reserved). body lives at [8..].
                            let cid = (s.sent as u64).wrapping_add(1);
                            s.body_buf[0..8].copy_from_slice(&cid.to_le_bytes());
                            &s.body_buf[..wire::TAGGED_PROPOSAL_HDR + bs]
                        } else {
                            &s.body_buf[..bs]
                        };
                        // `channel_poll(0x02)` only guarantees ≥1 byte free, NOT
                        // that the whole framed proposal fits — and
                        // `channel_write_msg` is all-or-nothing (a short write
                        // lands NOTHING and returns < frame_len). Counting an
                        // unchecked write as `sent` would silently drop
                        // proposals under disk-latency backpressure (raft
                        // suspends intake at the inflight cap, the channel
                        // fills, writes start failing). Honor the write
                        // result: a failed write is real backpressure — count
                        // it as blocked and retry the SAME proposal next step.
                        let frame_len = (wire::ENVELOPE_HDR + payload.len()) as i32;
                        let wrote = wire_channels::channel_write_msg(
                            sys, s.out_proposals, wire::MSG_CLIENT_PROPOSAL, payload,
                        );
                        // SIGNED compare: a full channel returns CHAN_EAGAIN (-11),
                        // not 0 — `(wrote as usize)` would wrap it to a huge value
                        // and mis-read it as success. Anything < the frame length
                        // (negative errno or short) means nothing landed: real
                        // backpressure -> count blocked and retry the SAME proposal.
                        if wrote < frame_len {
                            s.blocked = s.blocked.saturating_add(1);
                            break; // frame didn't land — retry next step (lossless)
                        }
                        s.sent += 1;
                        n += 1;
                    }
                }
                if s.sent >= s.total {
                    let elapsed = now.wrapping_sub(s.start_ms);
                    let mut p = 0usize;
                    let lb = s.log_buf.as_mut_ptr();
                    p = log_field(lb, p, b"[cbench] done sent=", s.sent);
                    p = log_field(lb, p, b" ms=", elapsed as u32);
                    p = log_field(lb, p, b" blocked=", s.blocked);
                    dev_log(sys, 3, lb, p);
                    s.phase = PH_DONE;
                }
            }
            _ => {}
        }

        emit_metrics(s, sys, now);
        0
    }
}

/// Emit injector phase + counters as typed samples (RFC §4.3). The
/// interesting consensus metrics live in raft_engine/commit_tracker.
///
/// # Safety
/// `sys` must be a live syscall table.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mid = wire::MODULE_ID_CONSENSUS_BENCH;
    let samples: [(u16, u8, i64); 3] = [
        (wire::metric_ids::CBENCH_PHASE, wire::METRIC_KIND_GAUGE, i64::from(s.phase)),
        (wire::metric_ids::CBENCH_PROPOSALS_SENT, wire::METRIC_KIND_COUNTER, i64::from(s.sent)),
        (wire::metric_ids::CBENCH_BLOCKED, wire::METRIC_KIND_COUNTER, i64::from(s.blocked)),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, 0, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}
