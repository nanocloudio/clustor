//! Durability Ledger — Tracks per-replica fsynced indices, computes
//! quorum durability proofs.
//!
//! Receives FsyncAck messages on `ack`, fans-in from two sources:
//!   - local `wal.flushed` (the local WAL's own `local_wal_durable_index`)
//!   - `replicator.cross_durability_ack` on the leader, which
//!     synthesizes per-peer FsyncAcks from the `durable_index` field
//!     each follower stamps into its AppendEntriesResponse envelope.
//!
//! Maintains a per-replica `progress[]` array and emits
//! `MSG_DURABILITY_PROOF` whenever the quorum-durable index advances
//! (spec §10.4.1 `wal_committed_index`). Followers see only their own
//! slot advance and therefore never emit a proof — the proof is a
//! leader-side artifact that gates `commit_tracker.committed`.

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

#[path = "../../sdk/types.rs"]
mod types;

#[path = "../../sdk/wire.rs"]
mod wire;

use types::*;

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, voter_count, u8, 1
        => |s, d, len| { s.voter_count = p_u8(d, len, 0, 1); };

    // Partition slot for multi-Raft graphs. Default 0 → legacy
    // single-partition graphs. Non-zero is stamped into outgoing
    // MSG_DURABILITY_PROOF so cross-partition consumers (ack_tracker
    // in particular) can disambiguate the same `wal_index` arriving
    // from different partitions.
    3, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_ack: i32,          // in[0]: FsyncAck (local: wal.flushed; remote: replicator)
    out_quorum: i32,      // out[0]: 19-byte DurabilityProof to commit_tracker / ack_tracker

    // Configuration
    self_id: ReplicaId,
    voter_count: u8,
    partition_id: u16,

    // Per-replica durable index tracking
    progress: [Index; MAX_NODES],

    // Quorum state
    committed_index: Index,
    committed_term: Term,

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
        s.in_ack = in_chan;
        s.out_quorum = out_chan;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // `voter_count` is operator-supplied; clamp here so the
        // downstream `quorum_index` slice access can never panic on
        // a typo'd cluster config.
        if (s.voter_count as usize) > MAX_NODES {
            s.voter_count = MAX_NODES as u8;
        }

        dev_log(sys, 3, b"[dur] init".as_ptr(), 10);
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

        let mut advanced = false;

        // Drain all incoming acks
        loop {
            let poll = (sys.channel_poll)(s.in_ack, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire::channel_read_msg(sys, s.in_ack, &mut s.msg_buf);
            if msg_type != wire::MSG_FSYNC_ACK || plen < 17 { continue; }

            let (term, index, replica) = wire::decode_fsync_ack(&s.msg_buf);

            // Validate replica slot
            if replica as usize >= MAX_NODES { continue; }

            // Only advance (never regress) per-replica durable index
            if index > s.progress[replica as usize] {
                s.progress[replica as usize] = index;
                advanced = true;
            }
            // Track latest term seen
            if term > s.committed_term {
                s.committed_term = term;
            }
        }

        // If any progress changed, recompute quorum
        if advanced {
            let new_quorum = quorum_index(&s.progress, s.voter_count);

            if new_quorum > s.committed_index {
                s.committed_index = new_quorum;

                // Emit DurabilityProof (19 bytes; partition_id at front).
                let poll_out = (sys.channel_poll)(s.out_quorum, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    let mut proof = [0u8; wire::DURABILITY_PROOF_LEN];
                    wire::encode_durability_proof(
                        &mut proof,
                        s.partition_id,
                        s.committed_term,
                        s.committed_index,
                        s.self_id,
                    );
                    wire::channel_write_msg(
                        sys,
                        s.out_quorum,
                        wire::MSG_DURABILITY_PROOF,
                        &proof,
                    );
                    dev_log(sys, 3, b"[dur] quorum".as_ptr(), 12);
                }
            }
        }

        0
    }
}
