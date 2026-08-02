//! Consensus — Raft leader election, log replication, quorum commit
//! and ordered apply.
//!
//! One graph module composed of four components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`raft`]       — the Raft state machine: elections (with
//!     pre-vote), proposal batching, follower log matching + §5.3
//!     conflict repair, admin/config apply, `RAFT<pppp>.MET`
//!     metadata persistence.
//!   - [`replicator`] — AppendEntries pipelining to followers, ack
//!     processing, WAL read-back catch-up, snapshot chunk transfer.
//!   - [`commit`]     — quorum match/durability fusion → the commit
//!     horizon.
//!   - [`apply`]      — ordered, deduplicated delivery of committed
//!     entries plus the linearizable-read queue.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else (per-component step bounds are
//! documented in each subtree):
//!
//!   1. cp demux     — the `cp_state` fan-in carries both admission
//!      signals: MSG_CACHE_STATE → `commit::on_cache_state`,
//!      MSG_FALLBACK_SIGNAL → `raft::on_fallback`. ≤8/step.
//!   2. `raft`       — consumes apply's probe-request queue (E7) and
//!      committed-admin ring (E9) filled LAST step (preserving the
//!      channel edges' next-step timing), plus the commit-horizon
//!      latch (E4) raised last step.
//!   2b. leader hint — E11: raft's role delivered to the replicator,
//!      which may only ship AppendEntries while this node leads.
//!   3. voter latch  — E10 delivered to commit + replicator in the
//!      same step raft applies a config change.
//!   4. `replicator` — drains raft's AE outbox ring (E1) at its
//!      original ≤4/step bound, gated on `net_out`.
//!   5. reply demux  — the `entry_reply` fan-in serves both WAL
//!      read-back consumers, split on request-id bit 31: set →
//!      `apply::on_entry_reply` (gap refetch), clear →
//!      `replicator::on_wal_reply` (catch-up AE synthesis). ≤16/step.
//!   6. match drain  — E2 coalesced per-replica max → `commit::on_match`.
//!   7. `commit`     — quorum recompute; raises the horizon latches.
//!   8. latch drain  — E4 → raft's `commit_in` (consumed NEXT step,
//!      one-tick feedback); E3/E6 horizons + the E6 RESET are
//!      handed to apply.
//!   9. `apply`      — consumes the RESET first, then raft's body
//!      ring (E5, ≤16/step), then the horizons, then the read path
//!      (probe replies E8 from raft's queue).
//!
//! Step effects are reported per component at their original sites;
//! the module step itself always returns 0.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/types.rs"]
mod types;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

mod apply;
mod commit;
mod raft;
mod replicator;
mod seam;

use types::MAX_NODES;

/// Kernel step ABI: 0=Continue, 1=Done, 2=Burst, 3=Ready.
const STEP_BURST: i32 = 2;

define_params! {
    ModuleState;

    // Replica id of this node. Shared: raft (election identity),
    // commit (self-match for quorum), replicator (peer-slot exclusion).
    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    // Shared: raft (initial voter set + majorities) and commit
    // (quorum median fallback).
    2, voter_count, u8, 1
        => |s, d, len| { s.voter_count = p_u8(d, len, 0, 1); };

    3, election_timeout_ms, u16, 1000
        => |s, d, len| { s.raft.election_timeout_ms = p_u16(d, len, 0, 1000); };

    4, heartbeat_interval_ms, u16, 150
        => |s, d, len| { s.raft.heartbeat_interval_ms = p_u16(d, len, 0, 150); };

    // Group commit: pack up to N client proposals into ONE raft log entry =
    // ONE WAL fsync. Default 1 — one proposal per log index, which every
    // consumer handles. Raising it REQUIRES the committed-entry consumer to
    // split the entry body back into its N self-delimiting proposals
    // (lattice does this in lattice_apply_bridge; clustor-native configs
    // whose responses route by unique wal_index must leave it at 1).
    5, proposal_batch_max, u16, 1
        => |s, d, len| { s.raft.proposal_batch_max = p_u16(d, len, 0, 256); };

    6, proposal_batch_timeout_ms, u16, 10
        => |s, d, len| { s.raft.proposal_batch_timeout_ms = p_u16(d, len, 0, 10); };

    // Partition slot for multi-Raft graphs. Default 0 means "single
    // partition"; per-partition instances set this to their slot id and
    // it drives the persistent metadata path and is stamped into every
    // component's metric samples. Shared across all four components.
    // See .context/rfc_partition_groups.md.
    7, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };

    // 1 = persist metadata to a root-level 8.3 file via FS_OPEN_CREATE
    // (bare-metal FAT32 has no mkdir). See raft's `meta_root_path` field.
    8, root_path, u8, 0
        => |s, d, len| { s.raft.meta_root_path = p_u8(d, len, 0, 0); };

    9, peer_count, u8, 0
        => |s, d, len| { s.repl.peer_count = p_u8(d, len, 0, 0); };

    10, pipeline_depth, u8, 8
        => |s, d, len| { s.repl.pipeline_depth = p_u8(d, len, 0, 8); };

    11, durability_mode, u8, 1, enum { strict=0, group_fsync=1, relaxed=2 }
        => |s, d, len| { s.commit.durability_mode = p_u8(d, len, 0, 1); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    // Shared params, copied into components after parse.
    self_id: u8,
    voter_count: u8,
    partition_id: u16,

    // Fan-in inputs demuxed by the dispatch table (two consumers each;
    // fluxor caps ports at 16 per direction, and these seams were
    // designed to demux by frame type / request-id namespace anyway).
    in_cp_state: i32,    // MSG_CACHE_STATE → commit, MSG_FALLBACK_SIGNAL → raft
    in_entry_reply: i32, // MSG_WAL_ENTRY_REPLY: id bit 31 set → apply, clear → replicator

    raft: raft::Raft,
    repl: replicator::Repl,
    commit: commit::Commit,
    apply: apply::Apply,

    /// Demux scratch: one inbound frame at a time.
    msg_buf: [u8; 4096],
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
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.self_id = 0;
        s.voter_count = 1;
        s.partition_id = 0;
        s.in_cp_state = -1;
        s.in_entry_reply = -1;
        for b in s.msg_buf.iter_mut() {
            *b = 0;
        }

        raft::init(&mut s.raft);
        replicator::init(&mut s.repl);
        commit::init(&mut s.commit);
        apply::init(&mut s.apply);

        // Port handles. Indices follow the manifest declaration order
        // (fluxor caps ports at 16 per direction).
        s.raft.in_rpc = in_chan; // in[0] rpc
        s.raft.in_proposals = dev_channel_port(sys, 0, 1);
        s.raft.in_admin = dev_channel_port(sys, 0, 2);
        s.raft.in_proposals_tagged = dev_channel_port(sys, 0, 3);
        s.raft.in_proposals_partitioned = dev_channel_port(sys, 0, 4);
        s.raft.in_proposals_partitioned_tagged = dev_channel_port(sys, 0, 5);
        s.raft.in_snapshot_installed = dev_channel_port(sys, 0, 6);
        s.raft.in_wal_flushed = dev_channel_port(sys, 0, 7);
        s.raft.in_wal_replay_complete = dev_channel_port(sys, 0, 8);
        s.repl.in_ack = dev_channel_port(sys, 0, 9);
        s.repl.in_snapshot_rx = dev_channel_port(sys, 0, 10);
        s.commit.in_durable = dev_channel_port(sys, 0, 11);
        s.in_cp_state = dev_channel_port(sys, 0, 12); // demuxed: commit + raft
        s.apply.in_read_permits = dev_channel_port(sys, 0, 13);
        s.apply.in_reads = dev_channel_port(sys, 0, 14);
        s.in_entry_reply = dev_channel_port(sys, 0, 15); // demuxed: apply + replicator
        s.raft.out_rpc = out_chan; // out[0] rpc_out
        s.repl.out_net = dev_channel_port(sys, 1, 1);
        s.raft.out_log = dev_channel_port(sys, 1, 2);
        s.raft.out_metrics = dev_channel_port(sys, 1, 3);
        s.raft.out_proposal_assigned = dev_channel_port(sys, 1, 4);
        s.raft.out_leader_state = dev_channel_port(sys, 1, 5);
        s.raft.out_admin_applied = dev_channel_port(sys, 1, 6);
        s.raft.out_wal_compact = dev_channel_port(sys, 1, 7);
        s.repl.out_lag = dev_channel_port(sys, 1, 8);
        s.repl.out_snapshot_import = dev_channel_port(sys, 1, 9);
        s.repl.out_snapshot_request = dev_channel_port(sys, 1, 10);
        s.repl.out_cross_durability_ack = dev_channel_port(sys, 1, 11);
        s.commit.out_retention_floor = dev_channel_port(sys, 1, 12);
        s.apply.out_committed_entries = dev_channel_port(sys, 1, 13);
        s.apply.out_applied = dev_channel_port(sys, 1, 14);
        s.apply.out_entry_request = dev_channel_port(sys, 1, 15);
        // All four components share the module's metrics port.
        s.repl.out_metrics = s.raft.out_metrics;
        s.commit.out_metrics = s.raft.out_metrics;
        s.apply.out_metrics = s.raft.out_metrics;
        // The replicator's WAL read-back requests share apply's
        // `entry_request` handle — one fan-in port at durability; the
        // bit-31 request-id namespace keeps their ids disjoint.
        s.repl.out_wal_request = s.apply.out_entry_request;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Fan shared params into components.
        s.raft.self_id = s.self_id;
        s.repl.self_id = s.self_id;
        s.commit.self_id = s.self_id;
        s.raft.voter_count = s.voter_count;
        s.commit.voter_count = s.voter_count;
        s.raft.partition_id = s.partition_id;
        s.repl.partition_id = s.partition_id;
        s.commit.partition_id = s.partition_id;
        s.apply.partition_id = s.partition_id;

        // Post-param boot logic (each component emits its own init log).
        raft::arm(&mut s.raft, sys);
        replicator::arm(&mut s.repl, sys);
        commit::arm(&mut s.commit, sys);
        apply::arm(&mut s.apply, sys);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // Dispatch table — see the module header for the ordering
        // contract.
        s.raft.meta_fs_step = false;

        // 0. cp_state fan-in demux: admission's cache-state and
        //    strict-fallback frames share one input (inputs merge B).
        //    MSG_CACHE_STATE feeds commit's CP gate; MSG_FALLBACK_SIGNAL
        //    feeds raft's proposal-intake gate — both delivered before
        //    their consumers step. ≤8/step.
        for _ in 0..8 {
            let poll = (sys.channel_poll)(s.in_cp_state, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) =
                wire_channels::channel_read_msg(sys, s.in_cp_state, &mut s.msg_buf);
            match msg_type {
                wire::MSG_CACHE_STATE => {
                    commit::on_cache_state(&mut s.commit, &s.msg_buf, plen);
                }
                wire::MSG_FALLBACK_SIGNAL => {
                    raft::on_fallback(&mut s.raft, &s.msg_buf, plen);
                }
                _ => {}
            }
        }

        // 1. raft. Consumes apply's E7 probe queue and E9 admin ring
        //    (filled during LAST step's apply dispatch → next-step
        //    timing preserved) and the E4 commit-horizon latch raised
        //    last step.
        raft::step(
            &mut s.raft,
            sys,
            now,
            &mut s.apply.admin_out,
            &mut s.apply.probe_out,
            &mut s.apply.probe_out_count,
        );

        // 1b. E11 leader-state hint → replicator. AppendEntries is a
        //     leader-only RPC; the replicator's catch-up fan-out must
        //     stop the moment raft leaves ROLE_LEADER.
        replicator::on_leader_state(&mut s.repl, raft::is_leader(&s.raft));

        // 2. E10 voter-set latch → commit + replicator, in the same
        //    step raft applied the config change.
        if let Some((current, joint, joint_active)) = s.raft.voter_out.take() {
            commit::on_voter_set(&mut s.commit, current, joint, joint_active != 0);
            replicator::on_voter_set(&mut s.repl, sys, current, joint, joint_active != 0);
        }

        // 3. replicator — drains raft's E1 AE outbox.
        replicator::step(&mut s.repl, &mut s.raft.outbox_ae, sys);

        // 3b. entry_reply fan-in demux (inputs merge A): one WAL
        //     read-back reply input serves both consumers, split on
        //     the request-id namespace — bit 31 set is apply's gap
        //     refetch, clear is the replicator's catch-up read-back.
        //     ≤16/step (≤8 per consumer).
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_entry_reply, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) =
                wire_channels::channel_read_msg(sys, s.in_entry_reply, &mut s.msg_buf);
            if msg_type != wire::MSG_WAL_ENTRY_REPLY || (plen as usize) < 4 {
                continue;
            }
            let request_id = u32::from_le_bytes([
                s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
            ]);
            if request_id & 0x8000_0000 != 0 {
                apply::on_entry_reply(&mut s.apply, sys, &s.msg_buf, plen);
            } else {
                replicator::on_wal_reply(&mut s.repl, sys, &s.msg_buf, plen);
            }
        }

        // 4. E2 coalesced match array → commit.
        if s.repl.match_dirty {
            s.repl.match_dirty = false;
            for r in 0..MAX_NODES {
                let index = s.repl.match_out[r];
                if index > 0 {
                    commit::on_match(&mut s.commit, r as u8, index);
                }
            }
        }

        // 5. commit — quorum recompute; raises the E3/E4 horizon latches.
        commit::step(&mut s.commit, sys);

        // 6. Latch drains. E4 → raft's commit_in (raft consumes it NEXT
        //    step because it dispatches first — the one-tick
        //    feedback and inflight-gate timing). E3/E6 horizons + the
        //    E6 RESET are handed to apply's step, which orders them
        //    internally (reset first, bodies before horizons).
        if s.commit.raft_commit_out.dirty {
            s.commit.raft_commit_out.dirty = false;
            s.raft
                .commit_in
                .raise(s.commit.raft_commit_out.term, s.commit.raft_commit_out.index);
        }
        let raft_horizon = if s.raft.apply_horizon_out.dirty {
            s.raft.apply_horizon_out.dirty = false;
            Some((s.raft.apply_horizon_out.term, s.raft.apply_horizon_out.index))
        } else {
            None
        };
        let commit_horizon = if s.commit.horizon_out.dirty {
            s.commit.horizon_out.dirty = false;
            Some((s.commit.horizon_out.term, s.commit.horizon_out.index))
        } else {
            None
        };
        let reset = s.raft.apply_reset_out.take();

        // 7. apply — reset first, then raft's E5 body ring, then the
        //    horizons, then the read path (E8 probe replies).
        apply::step(
            &mut s.apply,
            sys,
            now,
            reset,
            raft_horizon,
            commit_horizon,
            &mut s.raft.outbox_bodies,
            &mut s.raft.probe_reply_out,
            &mut s.raft.probe_reply_count,
        );

        // A step that persisted raft metadata (vote/term change) did a
        // synchronous FS write+fsync. Classify it as Burst so the
        // scheduler forgives the one-shot overrun instead of letting it
        // delay the heartbeat that keeps this leader elected.
        if s.raft.meta_fs_step { STEP_BURST } else { 0 }
    }
}
