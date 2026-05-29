//! Telemetry Aggregator — Metrics fan-in and diagnostic output.
//!
//! Drains metrics from all modules (via auto-merge on ingest port),
//! maintains counters/gauges, and emits readyz/why/export payloads
//! to client_surface.

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

const EMIT_INTERVAL_MS: u64 = 1000;

/// Size of the per-(module, metric_id) latest-value table. 64 slots
/// covers the current per-module emission set with headroom; older
/// entries are LRU-evicted by simple oldest-write replacement.
const METRIC_SLOTS: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
struct MetricEntry {
    /// 0 = slot empty. Module ids are non-zero (RFC §4.3).
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
    last_update_ms: u64,
}

impl MetricEntry {
    const fn empty() -> Self {
        Self {
            module_id: 0,
            partition_id: 0,
            metric_id: 0,
            kind: 0,
            value: 0,
            last_update_ms: 0,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_ingest: i32,      // in[0]: metrics from all modules (fan-in)
    out_readyz: i32,     // out[0]: readyz to client_surface
    out_why: i32,        // out[1]: why to client_surface
    out_export: i32,     // out[2]: export to client_surface

    // Aggregated counters
    messages_ingested: u32,
    /// Count of typed `MSG_METRIC_SAMPLE` envelopes seen since startup.
    typed_samples_ingested: u32,
    last_emit_ms: u64,
    ready: bool,
    startup_ms: u64,

    /// Latest-value table for typed metric samples, indexed by
    /// `(module_id, partition_id, metric_id)`. Counters are stored
    /// as their absolute value (consumers compute deltas); gauges
    /// just overwrite.
    metrics: [MetricEntry; METRIC_SLOTS],

    msg_buf: [u8; 256],
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
        s.in_ingest = in_chan;
        s.out_readyz = out_chan;
        s.out_why = dev_channel_port(sys, 1, 1);
        s.out_export = dev_channel_port(sys, 1, 2);
        s.startup_ms = dev_millis(sys);
        s.typed_samples_ingested = 0;
        for slot in s.metrics.iter_mut() {
            *slot = MetricEntry::empty();
        }
        dev_log(sys, 3, b"[tele] init".as_ptr(), 11);
        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ingest_typed_sample(s: &mut ModuleState, payload: &[u8], now: u64) {
    let (module_id, partition_id, metric_id, kind, value) =
        match wire::decode_metric_sample(payload) {
            Some(v) => v,
            None => return,
        };
    if module_id == 0 {
        return;
    }
    // Same-slot update if we already track this metric.
    for slot in s.metrics.iter_mut() {
        if slot.module_id == module_id
            && slot.partition_id == partition_id
            && slot.metric_id == metric_id
        {
            slot.kind = kind;
            slot.value = value;
            slot.last_update_ms = now;
            return;
        }
    }
    // Otherwise pick an empty slot or evict the oldest.
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in s.metrics.iter().enumerate() {
        if slot.module_id == 0 {
            slot_idx = Some(i);
            break;
        }
    }
    let i = match slot_idx {
        Some(i) => i,
        None => {
            let mut oldest_idx = 0usize;
            let mut oldest_ms = u64::MAX;
            for (i, slot) in s.metrics.iter().enumerate() {
                if slot.last_update_ms < oldest_ms {
                    oldest_ms = slot.last_update_ms;
                    oldest_idx = i;
                }
            }
            oldest_idx
        }
    };
    s.metrics[i] = MetricEntry {
        module_id,
        partition_id,
        metric_id,
        kind,
        value,
        last_update_ms: now,
    };
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

        // 1. Drain all ingest metrics. Two envelope shapes coexist:
        //    legacy `MSG_METRICS` (opaque per-module payload — counted
        //    only) and typed `MSG_METRIC_SAMPLE` (decoded into the
        //    latest-value table). See RFC §4.3.
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_ingest, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_ingest, &mut s.msg_buf);
            match msg_type {
                wire::MSG_METRICS => {
                    s.messages_ingested += 1;
                }
                wire::MSG_METRIC_SAMPLE => {
                    s.messages_ingested += 1;
                    s.typed_samples_ingested += 1;
                    let pl = plen as usize;
                    // Copy out of msg_buf so the &mut s borrow inside
                    // ingest_typed_sample doesn't clash with the slice.
                    let mut local = [0u8; wire::METRIC_SAMPLE_LEN];
                    let take = pl.min(wire::METRIC_SAMPLE_LEN);
                    local[..take].copy_from_slice(&s.msg_buf[..take]);
                    ingest_typed_sample(s, &local[..take], now);
                }
                _ => {}
            }
        }

        // Mark ready after warmup (5 seconds)
        if !s.ready && now.wrapping_sub(s.startup_ms) >= 5000 {
            s.ready = true;
        }

        // 2. Emit readyz/why/export periodically
        if now.wrapping_sub(s.last_emit_ms) >= EMIT_INTERVAL_MS {
            s.last_emit_ms = now;

            // Readyz: 1 byte (ready flag)
            if s.out_readyz >= 0 {
                let poll = (sys.channel_poll)(s.out_readyz, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = [s.ready as u8];
                    wire_channels::channel_write_msg(sys, s.out_readyz, wire::MSG_READYZ, &buf);
                }
            }

            // Why: empty payload for now (no blocking reasons)
            if s.out_why >= 0 {
                let poll = (sys.channel_poll)(s.out_why, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = [0u8; 1];
                    wire_channels::channel_write_msg(sys, s.out_why, wire::MSG_WHY, &buf);
                }
            }

            // Export: ingested count
            if s.out_export >= 0 {
                let poll = (sys.channel_poll)(s.out_export, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = s.messages_ingested.to_le_bytes();
                    wire_channels::channel_write_msg(sys, s.out_export, wire::MSG_METRICS, &buf);
                }
            }
        }

        0
    }
}
