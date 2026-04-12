//! Commit Tracker — Computes quorum commit index from match indices
//! and durability proofs.
//!
//! Receives match index updates from the replicator, durability proofs
//! from the durability ledger, and CP cache state from cp_proof_cache.
//! Emits CommittedBatch messages when the commit index advances.

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

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, voter_count, u8, 1
        => |s, d, len| { s.voter_count = p_u8(d, len, 0, 1); };

    3, durability_mode, u8, 1, enum { strict=0, group_fsync=1, relaxed=2 }
        => |s, d, len| { s.durability_mode = p_u8(d, len, 0, 1); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels: 3 in, 1 out
    in_match: i32,       // in[0]: match indices from replicator
    in_durable: i32,     // in[1]: DurabilityProof from durability_ledger
    in_cp_state: i32,    // in[2]: CacheState from cp_proof_cache
    out_committed: i32,  // out[0]: CommittedBatch to apply_pipeline

    // Configuration
    voter_count: u8,
    durability_mode: u8,  // DUR_STRICT / DUR_GROUP_FSYNC / DUR_RELAXED
    self_id: ReplicaId,

    // Per-replica match index tracking
    match_indices: [Index; MAX_NODES],

    // Durability state
    durable_index: Index,

    // Commit state
    committed_index: Index,
    committed_term: Term,

    // CP state
    cp_cache_state: u8,
    strict_fallback: bool,

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

        s.in_match = in_chan;
        s.out_committed = out_chan;
        s.in_durable = dev_channel_port(sys, 0, 1);
        s.in_cp_state = dev_channel_port(sys, 0, 2);

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        dev_log(sys, 3, b"[commit] init".as_ptr(), 13);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        let mut changed = false;

        // 1. Drain match index updates
        changed |= drain_match_indices(s, sys);

        // 2. Drain durability proofs
        changed |= drain_durability(s, sys);

        // 3. Drain CP state
        drain_cp_state(s, sys);

        // 4. Recompute commit index if anything changed
        if changed {
            advance_commit(s, sys);
        }

        0
    }
}

unsafe fn drain_match_indices(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let mut changed = false;
    loop {
        let poll = (sys.channel_poll)(s.in_match, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_match, &mut s.msg_buf);
        if plen < 17 { continue; }

        // Accept match index updates from replicator
        if msg_type == wire::MSG_APPEND_ENTRIES_RESP {
            let (_term, index, replica_byte) = wire::decode_term_index_replica(&s.msg_buf);
            let replica = replica_byte & 0x7F; // mask off success bit
            if (replica as usize) < MAX_NODES && index > s.match_indices[replica as usize] {
                s.match_indices[replica as usize] = index;
                changed = true;
            }
        }
    }
    changed
}

unsafe fn drain_durability(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_durable < 0 { return false; }
    let mut changed = false;
    loop {
        let poll = (sys.channel_poll)(s.in_durable, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_durable, &mut s.msg_buf);
        if msg_type != wire::MSG_DURABILITY_PROOF || plen < 17 { continue; }

        let (term, index, _replica) = wire::decode_fsync_ack(&s.msg_buf);
        if index > s.durable_index {
            s.durable_index = index;
            s.committed_term = term;
            changed = true;

            // Self-match: the local durable index counts as this node's
            // match index for quorum computation. Essential for single-node
            // clusters and for the leader's own vote in multi-node quorum.
            if (s.self_id as usize) < MAX_NODES && index > s.match_indices[s.self_id as usize] {
                s.match_indices[s.self_id as usize] = index;
            }
        }
    }
    changed
}

unsafe fn drain_cp_state(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_cp_state < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_cp_state, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire::channel_read_msg(sys, s.in_cp_state, &mut s.msg_buf);
        if msg_type == wire::MSG_CACHE_STATE && plen >= 1 {
            s.cp_cache_state = wire::decode_cache_state(&s.msg_buf);
            s.strict_fallback = s.cp_cache_state >= CP_STALE;
        } else if msg_type == wire::MSG_FALLBACK_SIGNAL && plen >= 1 {
            s.strict_fallback = s.msg_buf[0] != 0;
        }
    }
}

unsafe fn advance_commit(s: &mut ModuleState, sys: &SyscallTable) {
    // Compute quorum match index
    let quorum_match = quorum_index(&s.match_indices, s.voter_count);

    // Apply durability mode
    let effective_mode = if s.strict_fallback { DUR_STRICT } else { s.durability_mode };

    let new_commit = match effective_mode {
        DUR_STRICT | DUR_GROUP_FSYNC => {
            // Commit only up to what's durably synced
            if quorum_match < s.durable_index { quorum_match } else { s.durable_index }
        }
        DUR_RELAXED => quorum_match,
        _ => quorum_match,
    };

    if new_commit > s.committed_index {
        s.committed_index = new_commit;

        // Emit committed batch
        let poll = (sys.channel_poll)(s.out_committed, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            let mut buf = [0u8; 16];
            wire::encode_term_index(&mut buf, s.committed_term, s.committed_index);
            wire::channel_write_msg(sys, s.out_committed, wire::MSG_COMMITTED_BATCH, &buf[..16]);
            dev_log(sys, 3, b"[commit] adv".as_ptr(), 12);
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
