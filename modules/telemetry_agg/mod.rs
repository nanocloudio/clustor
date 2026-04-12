//! Telemetry Aggregator — Metrics fan-in and diagnostic output.
//!
//! Drains metrics from all modules (via auto-merge on ingest port),
//! maintains counters/gauges, and emits readyz/why/export payloads
//! to http_surface.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/wire.rs"]
mod wire;

const EMIT_INTERVAL_MS: u64 = 1000;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_ingest: i32,      // in[0]: metrics from all modules (fan-in)
    out_readyz: i32,     // out[0]: readyz to http_surface
    out_why: i32,        // out[1]: why to http_surface
    out_export: i32,     // out[2]: export to http_surface

    // Aggregated counters
    messages_ingested: u32,
    last_emit_ms: u64,
    ready: bool,
    startup_ms: u64,

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
        dev_log(sys, 3, b"[tele] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // 1. Drain all ingest metrics
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_ingest, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, _plen) = wire::channel_read_msg(sys, s.in_ingest, &mut s.msg_buf);
            if msg_type == wire::MSG_METRICS {
                s.messages_ingested += 1;
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
                    wire::channel_write_msg(sys, s.out_readyz, wire::MSG_READYZ, &buf);
                }
            }

            // Why: empty payload for now (no blocking reasons)
            if s.out_why >= 0 {
                let poll = (sys.channel_poll)(s.out_why, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = [0u8; 1];
                    wire::channel_write_msg(sys, s.out_why, wire::MSG_WHY, &buf);
                }
            }

            // Export: ingested count
            if s.out_export >= 0 {
                let poll = (sys.channel_poll)(s.out_export, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = s.messages_ingested.to_le_bytes();
                    wire::channel_write_msg(sys, s.out_export, wire::MSG_METRICS, &buf);
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
