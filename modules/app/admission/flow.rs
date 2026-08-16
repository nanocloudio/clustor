//! flow — dual-token PID controller for admission control.
//!
//! Samples the lag signal from replicator, computes PID output, and
//! emits credit updates on `credits` (consumed by the gateway's
//! throttle) plus a throttle envelope for client-facing status. Uses
//! Q16.16 fixed-point arithmetic.

use super::abi::SyscallTable;
use super::{wire, wire_channels};

// Q16.16 fixed-point helpers
const FP_ONE: i32 = 1 << 16;

const METRICS_INTERVAL_MS: u64 = 1000;

fn fp_mul(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 16) as i32
}

#[repr(C)]
pub struct Flow {
    pub in_lag: i32,       // in: LagSignal from replicator
    pub out_credits: i32,  // out: ThrottleCredits / ThrottleRefill
    pub out_metrics: i32,  // out: MetricsPayload

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
    pub entry_credit_max: i32,
    pub byte_credit_max: i32,
    pub entry_rate_per_sec: u32,
    entry_rate_remainder: u32,

    // Timing
    pub sample_period_ms: u16,
    last_sample_ms: u64,
    last_metrics_ms: u64,

    // Current lag (from replicator)
    current_lag: i32,

    msg_buf: [u8; 32],
}

pub unsafe fn init(f: &mut Flow) {
    f.in_lag = -1;
    f.out_credits = -1;
    f.out_metrics = -1;
    // Defaults: Throughput profile gains
    f.kp = (0.60f32 * FP_ONE as f32) as i32; // ~39321
    f.ki = (0.20f32 * FP_ONE as f32) as i32; // ~13107
    f.kd = (0.10f32 * FP_ONE as f32) as i32; // ~6553
    f.integral = 0;
    f.last_error = 0;
    f.derivative = 0;
    f.entry_credit_max = 4096;
    f.byte_credit_max = 64 * 1024; // 64 KiB (scaled down for module)
    f.entry_credits = 4096;
    f.byte_credits = 64 * 1024;
    f.entry_rate_per_sec = 0;
    f.entry_rate_remainder = 0;
    f.sample_period_ms = 100;
    f.last_sample_ms = 0;
    f.last_metrics_ms = 0;
    f.current_lag = 0;
}

/// Re-arm the credit pools after params land: pools start at their
/// configured caps.
pub fn arm_pools(f: &mut Flow) {
    f.entry_credits = f.entry_credit_max;
    f.byte_credits = f.byte_credit_max;
}

/// Per-step bound: ≤8 lag frames drained latest-wins; PID + one
/// credit emit on the sample tick; two gauges on the metrics tick.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Flow` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(f: &mut Flow, sys: &SyscallTable, now: u64) {
    // 1. Drain lag signals (keep latest)
    if f.in_lag >= 0 {
        for _ in 0..8 {
            let poll = (sys.channel_poll)(f.in_lag, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, f.in_lag, &mut f.msg_buf);
            if msg_type == wire::MSG_LAG_SIGNAL && plen >= 4 {
                f.current_lag = i32::from_le_bytes([
                    f.msg_buf[0], f.msg_buf[1], f.msg_buf[2], f.msg_buf[3],
                ]);
            }
        }
    }

    // 2. Run PID at sample interval
    if now.wrapping_sub(f.last_sample_ms) >= f.sample_period_ms as u64 {
        let elapsed_ms = now.wrapping_sub(f.last_sample_ms).max(1);
        f.last_sample_ms = now;

        // Error: positive = healthy headroom, negative = lagging
        let error = -f.current_lag; // invert: more lag = more negative

        // PID computation (Q16.16)
        let p = fp_mul(f.kp, error);
        f.integral += error;
        // Anti-windup clamp
        if f.integral > 2048 {
            f.integral = 2048;
        }
        if f.integral < -2048 {
            f.integral = -2048;
        }
        let i = fp_mul(f.ki, f.integral);
        let d = fp_mul(f.kd, error - f.last_error);
        f.last_error = error;

        // Scale: gains are Q16.16, error is a plain integer (lag
        // entries), and fp_mul already descales (>>16) — so p/i/d are
        // plain-integer credit deltas and their sum is the output
        // directly. A further >>16 here would double-descale and zero
        // the output for any realistic error.
        let output = p + i + d;

        if f.entry_rate_per_sec > 0 {
            // Convert the wall-clock rate to this interval's absolute
            // grant. Carry sub-token thousandths across intervals so the
            // long-run rate is exact even for short/irregular samples.
            let numer = u64::from(f.entry_rate_per_sec)
                .saturating_mul(elapsed_ms)
                .saturating_add(u64::from(f.entry_rate_remainder));
            let base = (numer / 1000).min(i32::MAX as u64) as i32;
            f.entry_rate_remainder = (numer % 1000) as u32;
            f.entry_credits = base.saturating_add(output);
            if f.entry_credits > f.entry_credit_max {
                f.entry_credits = f.entry_credit_max;
            }
            if f.entry_credits < 0 {
                f.entry_credits = 0;
            }
            // Entry rate is the governing limiter for this profile. Keep
            // enough byte credit for every admitted small request.
            f.byte_credits = f.byte_credit_max;
        } else {
            // Legacy absolute-pool PID behaviour.
            f.entry_credits += output;
            if f.entry_credits > f.entry_credit_max {
                f.entry_credits = f.entry_credit_max;
            }
            if f.entry_credits < 0 {
                f.entry_credits = 0;
            }

            f.byte_credits += output * 16; // scale bytes proportionally
            if f.byte_credits > f.byte_credit_max {
                f.byte_credits = f.byte_credit_max;
            }
            if f.byte_credits < 0 {
                f.byte_credits = 0;
            }
        }

        // 3. Emit credit update
        if f.out_credits >= 0 {
            let poll_out = (sys.channel_poll)(f.out_credits, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                if f.entry_rate_per_sec > 0 {
                    let mut buf = [0u8; wire::THROTTLE_REFILL_LEN];
                    wire::encode_throttle_refill(
                        &mut buf,
                        f.entry_credits,
                        f.byte_credits,
                        f.entry_credit_max,
                        f.byte_credit_max,
                    );
                    wire_channels::channel_write_msg(sys, f.out_credits, wire::MSG_THROTTLE_REFILL, &buf);
                } else {
                    let mut buf = [0u8; 8];
                    wire::encode_credits(&mut buf, f.entry_credits, f.byte_credits);
                    wire_channels::channel_write_msg(sys, f.out_credits, wire::MSG_THROTTLE_CREDITS, &buf);
                }
            }
        }
    }

    // 4. Periodic credit-pool gauges (RFC §4.2).
    emit_metrics(f, sys, now);
}

/// Emit the entry/byte credit-pool depths as typed gauges (RFC §4.3).
/// Node-level component, so partition_id is 0. Dropped under
/// backpressure.
unsafe fn emit_metrics(f: &mut Flow, sys: &SyscallTable, now: u64) {
    if f.out_metrics < 0 {
        return;
    }
    if now.wrapping_sub(f.last_metrics_ms) < METRICS_INTERVAL_MS {
        return;
    }
    f.last_metrics_ms = now;

    let mid = wire::SOURCE_ID_FLOW;
    let kg = wire::METRIC_KIND_GAUGE;
    let samples: [(u16, i64); 2] = [
        (wire::metric_ids::FLOW_ENTRY_CREDITS, i64::from(f.entry_credits)),
        (wire::metric_ids::FLOW_BYTE_CREDITS, i64::from(f.byte_credits)),
    ];
    for &(metric_id, value) in samples.iter() {
        let poll = (sys.channel_poll)(f.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            break;
        }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, 0, metric_id, kg, value);
        wire_channels::channel_write_msg(sys, f.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}
