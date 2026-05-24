//! CP Bridge — Periodically fetches control-plane proofs.
//!
//! Pure source module. Emits CpProof messages at intervals determined
//! by the current cache state. In a real deployment, this would make
//! HTTP requests to the CP service via the socket service.
//!
//! Quantum enhancement: also emits tenant records (out[1]) and
//! capability manifests (out[2]) alongside proofs. These ports are
//! optional — Clustor-only graphs leave them unwired.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in deps/fluxor/modules/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../../deps/fluxor/modules/sdk/params.rs");

#[path = "../../sdk/wire.rs"]
mod wire;

const REFRESH_FRESH_MS: u64 = 5000;
const REFRESH_STALE_MS: u64 = 600;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    out_proof: i32,           // out[0]: CpProof to cp_proof_cache
    out_tenant_records: i32,  // out[1]: tenant records (Quantum enhancement, optional)
    out_capabilities: i32,    // out[2]: capability manifests (Quantum enhancement, optional)
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
    // SAFETY: per the module ABI (deps/fluxor/modules/sdk/abi.rs),
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
        s.out_proof = out_chan;
        s.out_tenant_records = dev_channel_port(sys, 1, 1);
        s.out_capabilities = dev_channel_port(sys, 1, 2);
        s.refresh_interval_ms = REFRESH_FRESH_MS;
        dev_log(sys, 3, b"[cpbr] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (deps/fluxor/modules/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
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

            // Quantum enhancement: emit tenant records and capabilities
            // alongside proofs. In production these come from the same
            // CP HTTP response. Synthetic placeholders for now.
            if s.out_tenant_records >= 0 {
                let poll_t = (sys.channel_poll)(s.out_tenant_records, 0x02);
                if poll_t > 0 && (poll_t as u32 & 0x02) != 0 {
                    // [tenant_id:u32 = 0 (default)] [max_rate:u32 = 10000]
                    let mut tr = [0u8; 8];
                    tr[0..4].copy_from_slice(&0u32.to_le_bytes());
                    tr[4..8].copy_from_slice(&10000u32.to_le_bytes());
                    wire::channel_write_msg(sys, s.out_tenant_records, 0xD0, &tr);
                }
            }
            if s.out_capabilities >= 0 {
                let poll_c = (sys.channel_poll)(s.out_capabilities, 0x02);
                if poll_c > 0 && (poll_c as u32 & 0x02) != 0 {
                    // [schema_version:u16 = 1] [mqtt_enabled:u8 = 1]
                    let caps = [0x01u8, 0x00, 0x01];
                    wire::channel_write_msg(sys, s.out_capabilities, 0xD3, &caps);
                }
            }
        }
        0
    }
}
