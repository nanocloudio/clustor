//! Fsync Scheduler — Batches WAL flush acks into group-fsync windows.
//!
//! Accumulates flushed entries from the WAL and emits a single FsyncAck
//! per batch window, reducing fsync overhead on the durability path.

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
    in_pending: i32,    // in[0]: FsyncAck from wal
    out_synced: i32,    // out[0]: FsyncAck to durability_ledger

    // Batch state
    batch_window_ms: u16,     // from params (default 2ms)
    max_pending: u16,         // from params (default 64)
    batch_start_ms: u64,      // timestamp of first entry in batch
    pending_count: u16,
    pending_max_index: Index,
    pending_max_term: Term,
    has_batch: bool,          // at least one entry accumulated

    // Scratch
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
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }

        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_pending = in_chan;
        s.out_synced = out_chan;

        // Defaults
        s.batch_window_ms = 2;
        s.max_pending = 64;

        if !params.is_null() && params_len >= 4 {
            s.batch_window_ms = p_u16(params, params_len, 0, 2);
            s.max_pending = p_u16(params, params_len, 2, 64);
        }

        dev_log(sys, 3, b"[fsync] init".as_ptr(), 12);
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

        // 1. Drain all pending flushed acks, track highest index/term
        loop {
            let poll = (sys.channel_poll)(s.in_pending, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_pending, &mut s.msg_buf);
            if msg_type != wire::MSG_FSYNC_ACK || plen < 17 { continue; }

            let (term, index, _replica) = wire::decode_fsync_ack(&s.msg_buf);

            if !s.has_batch {
                s.batch_start_ms = now;
                s.has_batch = true;
            }

            if index > s.pending_max_index {
                s.pending_max_index = index;
                s.pending_max_term = term;
            }
            s.pending_count += 1;
        }

        // 2. Check if batch should be emitted
        if s.has_batch {
            let elapsed = now.wrapping_sub(s.batch_start_ms);
            let should_emit = elapsed >= s.batch_window_ms as u64
                || s.pending_count >= s.max_pending;

            if should_emit {
                // Check output readiness
                let poll_out = (sys.channel_poll)(s.out_synced, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    let mut ack = [0u8; 17];
                    wire::encode_fsync_ack(
                        &mut ack,
                        s.pending_max_term,
                        s.pending_max_index,
                        0, // self replica
                    );
                    wire::channel_write_msg(sys, s.out_synced, wire::MSG_FSYNC_ACK, &ack[..17]);
                    dev_log(sys, 3, b"[fsync] batch".as_ptr(), 13);

                    // Reset batch
                    s.pending_count = 0;
                    s.pending_max_index = 0;
                    s.pending_max_term = 0;
                    s.has_batch = false;
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
