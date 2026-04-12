//! CP Proof Cache — Fresh/Cached/Stale/Expired state machine.
//!
//! Tracks proof age and emits CacheState + FallbackSignal transitions.

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

use types::*;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_proof: i32,         // in[0]: CpProof from cp_bridge
    out_cache_state: i32,  // out[0]: CacheState to read_gate + commit_tracker
    out_fallback: i32,     // out[1]: FallbackSignal to raft_engine
    out_metrics: i32,      // out[2]: MetricsPayload to telemetry_agg

    // Config
    fresh_threshold_ms: u64,
    grace_period_ms: u64,

    // State
    last_proof_ms: u64,
    current_state: u8,
    last_emitted_state: u8,

    msg_buf: [u8; 32],
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
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_proof = in_chan;
        s.out_cache_state = out_chan;
        s.out_fallback = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.fresh_threshold_ms = 60_000;
        s.grace_period_ms = 120_000;
        s.current_state = CP_FRESH;
        s.last_emitted_state = 0xFF; // force first emit
        s.last_proof_ms = dev_millis(sys);

        if !params.is_null() && params_len >= 4 {
            s.fresh_threshold_ms = p_u16(params, params_len, 0, 60) as u64 * 1000;
            s.grace_period_ms = p_u16(params, params_len, 2, 120) as u64 * 1000;
        }

        dev_log(sys, 3, b"[cpc] init".as_ptr(), 10);
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

        // 1. Drain proofs (latest wins)
        loop {
            let poll = (sys.channel_poll)(s.in_proof, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_proof, &mut s.msg_buf);
            if msg_type == wire::MSG_CP_PROOF && plen >= 8 {
                s.last_proof_ms = now;
            }
        }

        // 2. Compute cache state from proof age
        let age = now.wrapping_sub(s.last_proof_ms);
        let new_state = if age < s.fresh_threshold_ms {
            CP_FRESH
        } else if age < s.grace_period_ms / 2 {
            CP_CACHED
        } else if age < s.grace_period_ms {
            CP_STALE
        } else {
            CP_EXPIRED
        };

        s.current_state = new_state;

        // 3. Emit on state change
        if new_state != s.last_emitted_state {
            s.last_emitted_state = new_state;

            // Emit CacheState
            let poll = (sys.channel_poll)(s.out_cache_state, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let mut buf = [0u8; 1];
                wire::encode_cache_state(&mut buf, new_state);
                wire::channel_write_msg(sys, s.out_cache_state, wire::MSG_CACHE_STATE, &buf[..1]);
            }

            // Emit FallbackSignal when entering/leaving strict fallback
            if s.out_fallback >= 0 {
                let fallback = new_state >= CP_STALE;
                let poll = (sys.channel_poll)(s.out_fallback, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = [fallback as u8];
                    wire::channel_write_msg(sys, s.out_fallback, wire::MSG_FALLBACK_SIGNAL, &buf[..1]);
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
