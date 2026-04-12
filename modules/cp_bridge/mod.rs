//! CP Bridge — Periodically fetches control-plane proofs.
//!
//! Pure source module. Emits CpProof messages at intervals determined
//! by the current cache state. In a real deployment, this would make
//! HTTP requests to the CP service via the socket service.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/wire.rs"]
mod wire;

const REFRESH_FRESH_MS: u64 = 5000;
const REFRESH_STALE_MS: u64 = 600;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    out_proof: i32,       // out[0]: CpProof to cp_proof_cache
    last_fetch_ms: u64,
    refresh_interval_ms: u64,
    proof_seq: u32,
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
    _in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.out_proof = out_chan;
        s.refresh_interval_ms = REFRESH_FRESH_MS;
        dev_log(sys, 3, b"[cpbr] init".as_ptr(), 11);
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

        if now.wrapping_sub(s.last_fetch_ms) >= s.refresh_interval_ms {
            s.last_fetch_ms = now;
            s.proof_seq += 1;

            // Emit a synthetic CP proof (timestamp + sequence).
            // Real implementation would fetch from CP HTTP endpoint.
            let mut buf = [0u8; 12];
            buf[0..8].copy_from_slice(&now.to_le_bytes());
            buf[8..12].copy_from_slice(&s.proof_seq.to_le_bytes());

            let poll = (sys.channel_poll)(s.out_proof, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                wire::channel_write_msg(sys, s.out_proof, wire::MSG_CP_PROOF, &buf[..12]);
            }
        }
        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
