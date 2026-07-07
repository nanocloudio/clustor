//! Flow Controller — Dual-token PID controller for admission control.
//!
//! Samples lag signal from replicator, computes PID output, and emits
//! credit updates to throttle_gate. Uses Q16.16 fixed-point arithmetic.

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

// Q16.16 fixed-point helpers
const FP_ONE: i32 = 1 << 16;

const METRICS_INTERVAL_MS: u64 = 1000;

define_params! {
    ModuleState;

    1, entry_credit_max, u16, 4096
        => |s, d, len| { s.entry_credit_max = p_u16(d, len, 0, 4096) as i32; };

    2, byte_credit_max_kib, u16, 64
        => |s, d, len| {
            s.byte_credit_max = i32::from(p_u16(d, len, 0, 64)) * 1024;
        };

    3, sample_period_ms, u16, 100
        => |s, d, len| { s.sample_period_ms = p_u16(d, len, 0, 100).max(1); };

    // Optional wall-clock admission rate. Zero preserves the legacy absolute
    // pool publication contract; non-zero derives each published grant from
    // actual elapsed milliseconds, so adaptive scheduler cadence cannot alter
    // the configured requests/second.
    4, entry_rate_per_sec, u16, 0
        => |s, d, len| { s.entry_rate_per_sec = p_u16(d, len, 0, 0) as u32; };
}

fn fp_mul(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 16) as i32
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_lag: i32,         // in[0]: LagSignal from replicator
    out_credits: i32,    // out[0]: ThrottleCredits to throttle_gate
    out_envelope: i32,   // out[1]: ThrottleEnvelope to client_surface
    out_metrics: i32,    // out[2]: MetricsPayload to telemetry_agg

    // PID gains (Q16.16)
    kp: i32,
    ki: i32,
    kd: i32,

    // PID state
    integral: i32,
    last_error: i32,
    derivative: i32,

    // Credits
    entry_credits: i32,
    byte_credits: i32,
    entry_credit_max: i32,
    byte_credit_max: i32,
    entry_rate_per_sec: u32,
    entry_rate_remainder: u32,

    // Timing
    sample_period_ms: u16,
    last_sample_ms: u64,
    last_metrics_ms: u64,

    // Current lag (from replicator)
    current_lag: i32,

    msg_buf: [u8; 32],
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
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
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

        s.in_lag = in_chan;
        s.out_credits = out_chan;
        s.out_envelope = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);

        // Defaults: Throughput profile gains
        s.kp = (0.60f32 * FP_ONE as f32) as i32;  // ~39321
        s.ki = (0.20f32 * FP_ONE as f32) as i32;  // ~13107
        s.kd = (0.10f32 * FP_ONE as f32) as i32;  // ~6553
        s.entry_credit_max = 4096;
        s.byte_credit_max = 64 * 1024; // 64 KiB (scaled down for module)
        s.entry_credits = 4096;
        s.byte_credits = 64 * 1024;
        s.sample_period_ms = 100;
        s.entry_rate_per_sec = 0;
        s.entry_rate_remainder = 0;

        if !params.is_null() && params_len > 0 {
            parse_tlv(s, params, params_len);
            s.entry_credits = s.entry_credit_max;
            s.byte_credits = s.byte_credit_max;
        }

        dev_log(sys, 3, b"[flow] init".as_ptr(), 11);
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
        let now = dev_millis(sys);

        // 1. Drain lag signals (keep latest)
        loop {
            let poll = (sys.channel_poll)(s.in_lag, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_lag, &mut s.msg_buf);
            if msg_type == wire::MSG_LAG_SIGNAL && plen >= 4 {
                s.current_lag = i32::from_le_bytes([
                    s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                ]);
            }
        }

        // 2. Run PID at sample interval
        if now.wrapping_sub(s.last_sample_ms) >= s.sample_period_ms as u64 {
            let elapsed_ms = now.wrapping_sub(s.last_sample_ms).max(1);
            s.last_sample_ms = now;

            // Error: positive = healthy headroom, negative = lagging
            let error = -s.current_lag; // invert: more lag = more negative

            // PID computation (Q16.16)
            let p = fp_mul(s.kp, error);
            s.integral += error;
            // Anti-windup clamp
            if s.integral > 2048 { s.integral = 2048; }
            if s.integral < -2048 { s.integral = -2048; }
            let i = fp_mul(s.ki, s.integral);
            let d = fp_mul(s.kd, error - s.last_error);
            s.last_error = error;

            let output = (p + i + d) >> 16; // scale back from Q16.16

            if s.entry_rate_per_sec > 0 {
                // Convert the wall-clock rate to this interval's absolute
                // grant. Carry sub-token thousandths across intervals so the
                // long-run rate is exact even for short/irregular samples.
                let numer = u64::from(s.entry_rate_per_sec)
                    .saturating_mul(elapsed_ms)
                    .saturating_add(u64::from(s.entry_rate_remainder));
                let base = (numer / 1000).min(i32::MAX as u64) as i32;
                s.entry_rate_remainder = (numer % 1000) as u32;
                s.entry_credits = base.saturating_add(output);
                if s.entry_credits > s.entry_credit_max {
                    s.entry_credits = s.entry_credit_max;
                }
                if s.entry_credits < 0 { s.entry_credits = 0; }
                // Entry rate is the governing limiter for this profile. Keep
                // enough byte credit for every admitted small request.
                s.byte_credits = s.byte_credit_max;
            } else {
                // Legacy absolute-pool PID behaviour.
                s.entry_credits += output;
                if s.entry_credits > s.entry_credit_max {
                    s.entry_credits = s.entry_credit_max;
                }
                if s.entry_credits < 0 { s.entry_credits = 0; }

                s.byte_credits += output * 16; // scale bytes proportionally
                if s.byte_credits > s.byte_credit_max {
                    s.byte_credits = s.byte_credit_max;
                }
                if s.byte_credits < 0 { s.byte_credits = 0; }
            }

            // 3. Emit credit update
            let poll_out = (sys.channel_poll)(s.out_credits, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                if s.entry_rate_per_sec > 0 {
                    let mut buf = [0u8; wire::THROTTLE_REFILL_LEN];
                    wire::encode_throttle_refill(
                        &mut buf,
                        s.entry_credits,
                        s.byte_credits,
                        s.entry_credit_max,
                        s.byte_credit_max,
                    );
                    wire_channels::channel_write_msg(
                        sys, s.out_credits, wire::MSG_THROTTLE_REFILL, &buf,
                    );
                } else {
                    let mut buf = [0u8; 8];
                    wire::encode_credits(&mut buf, s.entry_credits, s.byte_credits);
                    wire_channels::channel_write_msg(
                        sys, s.out_credits, wire::MSG_THROTTLE_CREDITS, &buf,
                    );
                }
            }
        }

        // 4. Periodic credit-pool gauges (RFC §4.2).
        emit_metrics(s, sys, now);

        0
    }
}

/// Emit the entry/byte credit-pool depths as typed gauges (RFC §4.3).
/// Node-level module, so partition_id is 0. Dropped under backpressure.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 { return; }
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mid = wire::MODULE_ID_FLOW_CONTROLLER;
    let kg = wire::METRIC_KIND_GAUGE;
    let samples: [(u16, i64); 2] = [
        (wire::metric_ids::FLOW_ENTRY_CREDITS, i64::from(s.entry_credits)),
        (wire::metric_ids::FLOW_BYTE_CREDITS, i64::from(s.byte_credits)),
    ];
    for &(metric_id, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, 0, metric_id, kg, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}
