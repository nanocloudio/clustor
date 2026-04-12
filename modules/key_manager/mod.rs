//! Key Manager — DEK/KEK epoch tracking and rotation.
//!
//! Pure source module. Emits DekEpoch messages on rotation schedule
//! and CertRefresh when certificate rotation is due.

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/wire.rs"]
mod wire;

const ROTATION_INTERVAL_MS: u64 = 168 * 3600 * 1000; // weekly

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    out_dek: i32,         // out[0]: DekEpoch to wal + snapshot_engine
    out_cert: i32,        // out[1]: CertRefresh to peer_router

    dek_epoch: u32,
    last_rotation_ms: u64,
    rotation_interval_ms: u64,
    emitted_initial: bool,
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
        s.out_dek = out_chan;
        s.out_cert = dev_channel_port(sys, 1, 1);
        s.dek_epoch = 1;
        s.rotation_interval_ms = ROTATION_INTERVAL_MS;
        s.last_rotation_ms = dev_millis(sys);
        dev_log(sys, 3, b"[keys] init".as_ptr(), 11);
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

        // Emit initial epoch
        if !s.emitted_initial {
            emit_dek(s, sys);
            s.emitted_initial = true;
        }

        // Check rotation schedule
        if now.wrapping_sub(s.last_rotation_ms) >= s.rotation_interval_ms {
            s.last_rotation_ms = now;
            s.dek_epoch += 1;
            emit_dek(s, sys);

            // Also trigger cert refresh
            if s.out_cert >= 0 {
                let poll = (sys.channel_poll)(s.out_cert, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = s.dek_epoch.to_le_bytes();
                    wire::channel_write_msg(sys, s.out_cert, wire::MSG_CERT_REFRESH, &buf);
                }
            }
        }

        0
    }
}

unsafe fn emit_dek(s: &ModuleState, sys: &SyscallTable) {
    let poll = (sys.channel_poll)(s.out_dek, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        let buf = s.dek_epoch.to_le_bytes();
        wire::channel_write_msg(sys, s.out_dek, wire::MSG_DEK_EPOCH, &buf);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
