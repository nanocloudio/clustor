//! Throttle Gate — Admission control point.
//!
//! Consumes credit tokens from flow_controller and admits or rejects
//! client proposals from client_codec.

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

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,      // in[0]: ClientProposal from client_codec
    in_credits: i32,       // in[1]: ThrottleCredits from flow_controller
    out_admitted: i32,     // out[0]: admitted ClientProposal to raft_engine
    out_rejected: i32,     // out[1]: rejected → client_codec
    out_metrics: i32,      // out[2]: MSG_METRIC_SAMPLE to telemetry_agg

    entry_credits: i32,
    byte_credits: i32,
    admitted_count: u32,
    rejected_count: u32,
    last_metrics_ms: u64,
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
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
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
        s.in_requests = in_chan;
        s.out_admitted = out_chan;
        s.in_credits = dev_channel_port(sys, 0, 1);
        s.out_rejected = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        // Start with generous credits until flow_controller takes over
        s.entry_credits = 4096;
        s.byte_credits = 64 * 1024;
        dev_log(sys, 3, b"[gate] init".as_ptr(), 11);
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

        // 1. Drain credit updates (keep latest)
        loop {
            let poll = (sys.channel_poll)(s.in_credits, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_credits, &mut s.msg_buf);
            if msg_type == wire::MSG_THROTTLE_CREDITS && plen >= 8 {
                let (entry, byte) = wire::decode_credits(&s.msg_buf);
                s.entry_credits = entry;
                s.byte_credits = byte;
            }
        }

        // 2. Process requests
        for _ in 0..8 {
            // Admission backpressure (RFC §13/§14): if we have credits we
            // intend to admit, but the downstream raft.proposals_tagged
            // channel has no space (raft is applying durability
            // backpressure on a full WAL), stop pulling requests so they
            // stay queued in client_codec rather than being read here and
            // silently dropped. Without credits we'd reject anyway, so the
            // gate only applies to the would-admit case.
            if s.entry_credits > 0 {
                let poll_out = (sys.channel_poll)(s.out_admitted, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }
            }

            let poll = (sys.channel_poll)(s.in_requests, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }

            let payload_len = plen as usize;

            // Tagged-proposal convention (RFC §5.8): client_codec stamps
            // every proposal with `[correlation_id:u64 LE][body]`. We need
            // the correlation_id so rejections can be mapped back to a
            // conn_id; drop frames that are too short to be tagged.
            if payload_len < wire::TAGGED_PROPOSAL_HDR { continue; }
            let correlation_id = u64::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                s.msg_buf[4], s.msg_buf[5], s.msg_buf[6], s.msg_buf[7],
            ]);

            let mut admitted = false;
            if s.entry_credits > 0 && s.byte_credits >= payload_len as i32 {
                // Admit — forward the tagged payload unchanged to
                // raft_engine.proposals_tagged (configured in YAML).
                // `channel_write_msg` is a single atomic frame write, so a
                // `<= 0` return means raft's channel filled between the
                // pre-read poll and here and NOTHING was written — fall
                // through to a throttled reject rather than dropping the
                // proposal silently, so the client retries (RFC §13/§14).
                let written = wire_channels::channel_write_msg(
                    sys, s.out_admitted, wire::MSG_CLIENT_PROPOSAL, &s.msg_buf[..payload_len],
                );
                if written > 0 {
                    s.entry_credits -= 1;
                    s.byte_credits -= payload_len as i32;
                    s.admitted_count += 1;
                    admitted = true;
                }
            }
            if !admitted {
                // Reject with the internal envelope: `[correlation_id][body]`.
                // client_codec will look up correlation_id → conn_id and
                // emit the wire-facing MSG_CLIENT_REJECT.
                if s.out_rejected >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_rejected, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        let mut env = [0u8; wire::CLIENT_REJECT_INTERNAL_LEN];
                        let retry_ms: u16 = if s.entry_credits > 0 { 5 } else { 50 };
                        let entry_clamped =
                            s.entry_credits.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                        wire::encode_client_reject_internal(
                            &mut env,
                            correlation_id,
                            wire::CLIENT_REJECT_THROTTLED,
                            retry_ms,
                            entry_clamped,
                            s.byte_credits,
                        );
                        wire_channels::channel_write_msg(
                            sys,
                            s.out_rejected,
                            wire::MSG_CLIENT_REJECT_INTERNAL,
                            &env[..wire::CLIENT_REJECT_INTERNAL_LEN],
                        );
                    }
                }
                s.rejected_count += 1;
            }
        }

        // 3. Periodic admission metrics (RFC §4.2).
        emit_metrics(s, sys);

        0
    }
}

/// Emit admit/reject counters as typed samples (RFC §4.3). Node-level
/// module, so partition_id is 0. Dropped under backpressure.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mid = wire::MODULE_ID_THROTTLE_GATE;
    let kc = wire::METRIC_KIND_COUNTER;
    let samples: [(u16, i64); 2] = [
        (wire::metric_ids::THROTTLE_ADMITTED, i64::from(s.admitted_count)),
        (wire::metric_ids::THROTTLE_REJECTED, i64::from(s.rejected_count)),
    ];
    for &(metric_id, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, 0, metric_id, kc, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}
