//! Apply Pipeline — Ordered, deduplicated delivery of committed entries
//! to the embedded state machine (quantum/lattice).

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

const DEDUP_SHARDS: usize = 16;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_entries: i32,      // in[0]: CommittedBatch from commit_tracker
    in_read_permits: i32, // in[1]: ReadPermit from read_gate
    out_applied: i32,     // out[0]: ClientResponse to http_surface

    apply_index: Index,
    dedup_shards: [Index; DEDUP_SHARDS],
    entries_applied: u32,
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
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_entries = in_chan;
        s.out_applied = out_chan;
        s.in_read_permits = dev_channel_port(sys, 0, 1);
        dev_log(sys, 3, b"[apply] init".as_ptr(), 12);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 1. Process committed batches
        for _ in 0..8 {
            let poll = (sys.channel_poll)(s.in_entries, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
            if msg_type != wire::MSG_COMMITTED_BATCH || plen < 16 { continue; }

            let (_term, index) = wire::decode_term_index(&s.msg_buf);

            // Dedup: skip if already applied
            let shard = (index as usize) % DEDUP_SHARDS;
            if index <= s.dedup_shards[shard] { continue; }
            s.dedup_shards[shard] = index;

            if index <= s.apply_index { continue; }
            s.apply_index = index;
            s.entries_applied += 1;
            dev_log(sys, 3, b"[apply] ok".as_ptr(), 10);

            // Emit applied response
            let poll_out = (sys.channel_poll)(s.out_applied, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                let mut resp = [0u8; 16];
                wire::encode_term_index(&mut resp, _term, index);
                wire::channel_write_msg(sys, s.out_applied, wire::MSG_CLIENT_RESPONSE, &resp[..16]);
            }
        }

        // 2. Drain read permits (gate signal only — no response emitted
        //    unless there's a queued read request, which is future work)
        if s.in_read_permits >= 0 {
            loop {
                let poll = (sys.channel_poll)(s.in_read_permits, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let _ = wire::channel_read_msg(sys, s.in_read_permits, &mut s.msg_buf);
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
