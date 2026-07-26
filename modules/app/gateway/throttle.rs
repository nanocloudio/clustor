//! throttle — admission control point.
//!
//! Consumes credit tokens from the admission module's flow controller
//! and admits or rejects tagged client proposals delivered by the
//! [`codec`](super::codec) component. Admitted proposals leave on the
//! module's `proposals_tagged` port; rejections return to the codec
//! (which frames the wire-facing reject) and additionally publish on
//! the `rejected` port for external observers.

use super::abi::SyscallTable;
use super::{codec, surface, wire, wire_channels};
use super::dev_millis;

const METRICS_INTERVAL_MS: u64 = 1000;

#[repr(C)]
pub struct Throttle {
    pub in_credits: i32,   // in: ThrottleCredits / ThrottleRefill
    pub in_proposals: i32, // in: tagged proposals from external producers
    pub out_admitted: i32, // out: admitted ClientProposal
    pub out_rejected: i32, // out: rejection tee for external observers
    pub out_metrics: i32,  // out: MSG_METRIC_SAMPLE

    entry_credits: i32,
    byte_credits: i32,
    admitted_count: u32,
    rejected_count: u32,
    last_metrics_ms: u64,
    msg_buf: [u8; 2048],
}

pub unsafe fn init(t: &mut Throttle) {
    t.in_credits = -1;
    t.in_proposals = -1;
    t.out_admitted = -1;
    t.out_rejected = -1;
    t.out_metrics = -1;
    // Start with generous credits until the flow controller takes over
    t.entry_credits = 4096;
    t.byte_credits = 64 * 1024;
    t.admitted_count = 0;
    t.rejected_count = 0;
    t.last_metrics_ms = 0;
}

/// Per-step bound: ≤16 credit frames drained; ≤16 external proposals
/// admitted off the `proposals` port; two counters on the metrics
/// tick. Codec-path admission is additionally driven by the surface
/// request loop (≤8/step) through [`on_proposal`].
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(
    t: &mut Throttle,
    co: &mut codec::Codec,
    su: &mut surface::Surface,
    sys: &SyscallTable,
) {
    // Drain credit updates (keep latest / accumulate refills)
    if t.in_credits >= 0 {
        for _ in 0..16 {
            let poll = (sys.channel_poll)(t.in_credits, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, t.in_credits, &mut t.msg_buf);
            if msg_type == wire::MSG_THROTTLE_CREDITS && plen >= 8 {
                let (entry, byte) = wire::decode_credits(&t.msg_buf);
                t.entry_credits = entry;
                t.byte_credits = byte;
            } else if msg_type == wire::MSG_THROTTLE_REFILL
                && plen as usize >= wire::THROTTLE_REFILL_LEN
            {
                if let Some((entry, byte, entry_cap, byte_cap)) =
                    wire::decode_throttle_refill(&t.msg_buf[..plen as usize])
                {
                    t.entry_credits = t.entry_credits.saturating_add(entry);
                    t.byte_credits = t.byte_credits.saturating_add(byte);
                    let entry_cap = entry_cap.max(0);
                    let byte_cap = byte_cap.max(0);
                    if t.entry_credits > entry_cap {
                        t.entry_credits = entry_cap;
                    }
                    if t.byte_credits > byte_cap {
                        t.byte_credits = byte_cap;
                    }
                }
            }
        }
    }

    // Drain external tagged proposals (bench injectors, the
    // operations module's /propose and admin-PROPOSE bridges).
    // Drain at least one full wall-clock refill quantum: the flow
    // controller publishes an absolute grant; stopping short could
    // leave valid tokens unused, and the next update would overwrite
    // them, turning this loop bound into an accidental throughput
    // ceiling. Every consumed proposal must have a terminal route:
    // require the rejection tee (when wired) to be writable before
    // reading, and — when we hold credits we intend to spend — the
    // admitted channel too, so raft/WAL backpressure keeps frames
    // queued upstream rather than being read here and dropped.
    if t.in_proposals >= 0 {
        for _ in 0..16 {
            if t.out_rejected >= 0 {
                let poll_rejected = (sys.channel_poll)(t.out_rejected, 0x02);
                if poll_rejected <= 0 || (poll_rejected as u32 & 0x02) == 0 {
                    break;
                }
            }
            if t.entry_credits > 0 && t.out_admitted >= 0 {
                let poll_out = (sys.channel_poll)(t.out_admitted, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
                    break;
                }
            }
            let poll = (sys.channel_poll)(t.in_proposals, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, t.in_proposals, &mut t.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 {
                continue;
            }
            let pl = plen as usize;
            let mut local = [0u8; 2048];
            local[..pl].copy_from_slice(&t.msg_buf[..pl]);
            on_proposal(t, co, su, sys, &local[..pl]);
        }
    }

    emit_metrics(t, sys);
}

/// Admit or reject one tagged proposal `[correlation_id:u64 LE][body]`.
/// Every delivered proposal gets a terminal route: an atomic write to
/// `proposals_tagged`, or a rejection returned through the codec (and
/// teed on `rejected`). A `<= 0` admitted write means raft's channel
/// filled and NOTHING was written — the proposal falls through to a
/// throttled reject rather than being dropped silently, so the client
/// retries (RFC §13/§14).
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn on_proposal(
    t: &mut Throttle,
    co: &mut codec::Codec,
    su: &mut surface::Surface,
    sys: &SyscallTable,
    frame: &[u8],
) {
    let payload_len = frame.len();
    // Tagged-proposal convention (RFC §5.8): the codec stamps every
    // proposal with `[correlation_id:u64 LE][body]`. We need the
    // correlation_id so rejections map back to a conn_id; drop frames
    // that are too short to be tagged.
    if payload_len < wire::TAGGED_PROPOSAL_HDR {
        return;
    }
    let correlation_id = u64::from_le_bytes([
        frame[0], frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7],
    ]);

    // A graph without a flow controller (credit port unwired) runs
    // unthrottled — credits are the flow controller's lever, and with
    // no supplier the bootstrap pool must not become a hidden write
    // ceiling.
    let unlimited = t.in_credits < 0;
    let mut admitted = false;
    if (unlimited || (t.entry_credits > 0 && t.byte_credits >= payload_len as i32))
        && t.out_admitted >= 0
    {
        let poll_out = (sys.channel_poll)(t.out_admitted, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            let written =
                wire_channels::channel_write_msg(sys, t.out_admitted, wire::MSG_CLIENT_PROPOSAL, frame);
            if written > 0 {
                if !unlimited {
                    t.entry_credits -= 1;
                    t.byte_credits -= payload_len as i32;
                }
                t.admitted_count += 1;
                admitted = true;
            }
        }
    }
    if !admitted {
        // Reject with the internal envelope: `[correlation_id][...]`.
        // The codec looks up correlation_id → conn_id and emits the
        // wire-facing MSG_CLIENT_REJECT through the surface.
        let mut env = [0u8; wire::CLIENT_REJECT_INTERNAL_LEN];
        let retry_ms: u16 = if t.entry_credits > 0 { 5 } else { 50 };
        let entry_clamped = t.entry_credits.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        wire::encode_client_reject_internal(
            &mut env,
            correlation_id,
            wire::CLIENT_REJECT_THROTTLED,
            retry_ms,
            entry_clamped,
            t.byte_credits,
        );
        codec::on_reject_internal(co, su, sys, &env);
        // External tee for observers (e.g. the operations module's
        // proposal-rejection feedback). Best-effort.
        if t.out_rejected >= 0 {
            let poll_out = (sys.channel_poll)(t.out_rejected, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(
                    sys,
                    t.out_rejected,
                    wire::MSG_CLIENT_REJECT_INTERNAL,
                    &env[..wire::CLIENT_REJECT_INTERNAL_LEN],
                );
            }
        }
        t.rejected_count += 1;
    }
}

pub fn work_count(t: &Throttle) -> u32 {
    t.admitted_count.wrapping_add(t.rejected_count)
}

/// Emit admit/reject counters as typed samples (RFC §4.3). Node-level
/// component, so partition_id is 0. Dropped under backpressure.
unsafe fn emit_metrics(t: &mut Throttle, sys: &SyscallTable) {
    if t.out_metrics < 0 {
        return;
    }
    let now = dev_millis(sys);
    if now.wrapping_sub(t.last_metrics_ms) < METRICS_INTERVAL_MS {
        return;
    }
    t.last_metrics_ms = now;

    let mid = wire::SOURCE_ID_THROTTLE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, i64); 2] = [
        (wire::metric_ids::THROTTLE_ADMITTED, i64::from(t.admitted_count)),
        (wire::metric_ids::THROTTLE_REJECTED, i64::from(t.rejected_count)),
    ];
    for &(metric_id, value) in samples.iter() {
        let poll = (sys.channel_poll)(t.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            break;
        }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, 0, metric_id, kc, value);
        wire_channels::channel_write_msg(sys, t.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}
