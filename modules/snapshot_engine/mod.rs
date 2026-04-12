//! Snapshot Engine — Full and incremental snapshot management.
//!
//! Manages snapshot cadence. On trigger from WAL compaction signal,
//! begins chunked export. Receives import chunks from replicator.

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
    in_import: i32,       // in[0]: import chunks from replicator
    in_trigger: i32,      // in[1]: SnapshotTrigger from wal
    in_key_update: i32,   // in[2]: DekEpoch from key_manager
    out_export: i32,      // out[0]: export chunks to replicator
    out_manifest: i32,    // out[1]: manifest auth to peer_router
    out_metrics: i32,     // out[2]: metrics to telemetry_agg

    // State
    exporting: bool,
    export_index: Index,
    export_term: Term,
    export_chunk_seq: u32,
    dek_epoch: u32,
    snapshots_taken: u32,
    chunks_exported: u32,
    chunks_imported: u32,

    msg_buf: [u8; 1024],
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
        s.in_import = in_chan;
        s.out_export = out_chan;
        s.in_trigger = dev_channel_port(sys, 0, 1);
        s.in_key_update = dev_channel_port(sys, 0, 2);
        s.out_manifest = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        dev_log(sys, 3, b"[snap] init".as_ptr(), 11);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 1. Drain key updates
        if s.in_key_update >= 0 {
            loop {
                let poll = (sys.channel_poll)(s.in_key_update, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) = wire::channel_read_msg(sys, s.in_key_update, &mut s.msg_buf);
                if msg_type == wire::MSG_DEK_EPOCH && plen >= 4 {
                    s.dek_epoch = u32::from_le_bytes([s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3]]);
                }
            }
        }

        // 2. Check for snapshot trigger
        if s.in_trigger >= 0 {
            let poll = (sys.channel_poll)(s.in_trigger, 0x01);
            if poll > 0 && (poll as u32 & 0x01) != 0 {
                let (msg_type, plen) = wire::channel_read_msg(sys, s.in_trigger, &mut s.msg_buf);
                if msg_type == wire::MSG_SNAPSHOT_TRIGGER && plen >= 16 {
                    let (term, index) = wire::decode_term_index(&s.msg_buf);
                    s.exporting = true;
                    s.export_term = term;
                    s.export_index = index;
                    s.export_chunk_seq = 0;
                    s.snapshots_taken += 1;
                    dev_log(sys, 3, b"[snap] export".as_ptr(), 13);
                }
            }
        }

        // 3. Export chunks (one per step to bound step time)
        if s.exporting {
            let poll_out = (sys.channel_poll)(s.out_export, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                // Emit a synthetic chunk (real data comes from Phase 8 storage)
                let mut chunk = [0u8; 24];
                wire::encode_term_index(&mut chunk, s.export_term, s.export_index);
                chunk[16..20].copy_from_slice(&s.export_chunk_seq.to_le_bytes());
                chunk[20..24].copy_from_slice(&s.dek_epoch.to_le_bytes());

                wire::channel_write_msg(sys, s.out_export, wire::MSG_SNAPSHOT_CHUNK, &chunk[..24]);
                s.export_chunk_seq += 1;
                s.chunks_exported += 1;

                // For now, single-chunk snapshots
                s.exporting = false;
            }
        }

        // 4. Process import chunks
        if s.in_import >= 0 {
            let poll = (sys.channel_poll)(s.in_import, 0x01);
            if poll > 0 && (poll as u32 & 0x01) != 0 {
                let (msg_type, plen) = wire::channel_read_msg(sys, s.in_import, &mut s.msg_buf);
                if msg_type == wire::MSG_SNAPSHOT_CHUNK && plen > 0 {
                    s.chunks_imported += 1;
                    // Phase 8: apply snapshot data to storage
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
