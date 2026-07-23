//! Commit Tracker — Computes quorum commit index from match indices
//! and durability proofs.
//!
//! Receives match index updates from the replicator, durability proofs
//! from the durability ledger, and CP cache state from cp_proof_cache.
//! Emits CommittedBatch messages when the commit index advances.

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
include!("../../../target/fluxor/fluxor-abi/sdk/params.rs");

#[path = "../../common/types.rs"]
mod types;

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use types::*;

const METRICS_INTERVAL_MS: u64 = 1000;

define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, voter_count, u8, 1
        => |s, d, len| { s.voter_count = p_u8(d, len, 0, 1); };

    3, durability_mode, u8, 1, enum { strict=0, group_fsync=1, relaxed=2 }
        => |s, d, len| { s.durability_mode = p_u8(d, len, 0, 1); };

    // Partition slot for multi-Raft graphs (RFC §1.2). Stamped into
    // emitted metric samples so per-partition commit_trackers
    // (`commit_tracker_p0`, `_p1`) don't collide in telemetry_agg's
    // (module_id, partition_id, metric_id) table.
    4, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels: 4 in, 1 out
    in_match: i32,       // in[0]: match indices from replicator
    in_durable: i32,     // in[1]: DurabilityProof from durability_ledger
    in_cp_state: i32,    // in[2]: CacheState from cp_proof_cache
    in_voter_set: i32,   // in[3]: MSG_VOTER_SET_UPDATE from raft_engine (RFC §1.2)
    out_committed: i32,  // out[0]: CommittedBatch to apply_pipeline
    out_metrics: i32,    // out[1]: MSG_METRIC_SAMPLE to telemetry_agg
    out_retention_floor: i32, // out[2]: MSG_COMPACTION_FLOOR to snapshot_engine.retention_floor
    out_raft_commit: i32, // out[3]: CommittedBatch to raft_engine.commit (dedicated)

    // Configuration
    voter_count: u8,
    durability_mode: u8,  // DUR_STRICT / DUR_GROUP_FSYNC / DUR_RELAXED
    self_id: ReplicaId,
    partition_id: u16,

    // Metrics
    commit_advances: u32,
    last_metrics_ms: u64,

    /// Current and joint voter NodeSet bitmasks (RFC §1.2). Until
    /// raft_engine pushes the first `MSG_VOTER_SET_UPDATE`, the
    /// commit tracker falls back to `voter_count` for the median —
    /// preserving the existing single-config behaviour.
    current_voters: NodeSet,
    joint_voters: NodeSet,
    joint_active: bool,

    // Per-replica match index tracking
    match_indices: [Index; MAX_NODES],

    /// Last min-match retention floor emitted (see `emit_retention_floor`).
    last_floor_emitted: Index,

    // Durability state
    durable_index: Index,

    // Commit state
    committed_index: Index,
    committed_term: Term,
    // Highest committed_index actually DELIVERED per output channel. Commit
    // delivery must be retried, not fire-and-forget: `out_committed` fans out
    // to raft.commit and apply.entries, and a group-commit burst can leave it
    // full exactly when the horizon advances. A dropped, never-retried emit
    // means raft never learns the new commit, its uncommitted-inflight window
    // fills, and the pipeline deadlocks. `emit_committed` re-sends every step
    // until each channel has caught up, with raft additionally served by a
    // dedicated channel (`out_raft_commit`) that apply backpressure cannot
    // block.
    last_emitted_index: Index,   // delivered on out_committed (→ apply_pipeline)
    last_emitted_raft: Index,    // delivered on out_raft_commit (→ raft_engine)

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
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
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

        s.in_match = in_chan;
        s.out_committed = out_chan;
        s.in_durable = dev_channel_port(sys, 0, 1);
        s.in_cp_state = dev_channel_port(sys, 0, 2);
        s.in_voter_set = dev_channel_port(sys, 0, 3);
        s.out_metrics = dev_channel_port(sys, 1, 1);
        s.out_retention_floor = dev_channel_port(sys, 1, 2);
        s.out_raft_commit = dev_channel_port(sys, 1, 3);
        s.current_voters = NodeSet::empty();
        s.joint_voters = NodeSet::empty();
        s.joint_active = false;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // `voter_count` is operator-supplied; clamp here so the
        // downstream `quorum_index` slice access can never panic on
        // a typo'd cluster config. `NodeSet`-side mutators have a
        // matching guard for completeness.
        if (s.voter_count as usize) > MAX_NODES {
            s.voter_count = MAX_NODES as u8;
        }

        dev_log(sys, 3, b"[commit] init".as_ptr(), 13);
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

        let mut changed = false;

        // 1. Drain match index updates
        changed |= drain_match_indices(s, sys);

        // 2. Drain durability proofs
        changed |= drain_durability(s, sys);

        // 3. Drain CP state
        drain_cp_state(s, sys);

        // 4. Drain voter-set updates (RFC §1.2). Anything that changes
        //    the active quorum forces a commit-advance recheck.
        if drain_voter_set(s, sys) {
            changed = true;
        }

        // 5. Recompute commit index if anything changed
        if changed {
            advance_commit(s, sys);
            dev_report_step_effect(sys, step_effect::WORK_DONE);
        } else {
            // Retry delivery of the commit horizon even on quiet steps, so a
            // drop under backpressure is re-sent once the channel drains.
            emit_committed(s, sys);
        }

        // 6. Periodic metrics
        emit_metrics(s, sys);

        // 7. Retention floor for snapshot/compaction gating.
        emit_retention_floor(s, sys);

        0
    }
}

/// Publish min(match_indices over the active voter set) as a
/// MSG_COMPACTION_FLOOR so `snapshot_engine` defers snapshot triggers —
/// and therefore WAL compaction — past what the slowest LIVE voter has
/// replicated. Without this floor a leader-local snapshot can compact
/// entries a lagging follower still needs; with manifest-only snapshots
/// (no state body yet) that follower can then NEVER catch up: its
/// replicator NACK-refetches a compacted index forever, the permanent
/// lag signal makes flow_controller strangle proposal credits, and the
/// whole write path wedges. A DEAD follower
/// pins the floor — the safe default until state-body snapshots make
/// install-based catch-up lossless; operators drop dead voters via
/// membership change.
///
/// Emitted only on change; dropped under backpressure (the next change
/// or step re-emits — the gate degrades toward NOT compacting, which is
/// always safe). Wire shape (10 bytes, shared with lattice):
/// `[kpg_id:u16 LE][floor_revision:u64 LE]`.
unsafe fn emit_retention_floor(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_retention_floor < 0 { return; }
    let mut floor = Index::MAX;
    let mut any = false;
    for id in 0..MAX_NODES as u8 {
        let in_set = if s.current_voters.count() > 0 {
            s.current_voters.contains(id)
                || (s.joint_active && s.joint_voters.contains(id))
        } else {
            // Pre-voter-set fallback: ids 0..voter_count (mirrors the
            // quorum computation's fallback).
            id < s.voter_count
        };
        if in_set {
            any = true;
            if s.match_indices[id as usize] < floor {
                floor = s.match_indices[id as usize];
            }
        }
    }
    if !any || floor == Index::MAX { return; }
    if floor == s.last_floor_emitted { return; }
    let poll = (sys.channel_poll)(s.out_retention_floor, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&s.partition_id.to_le_bytes());
    buf[2..10].copy_from_slice(&floor.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_retention_floor, wire::MSG_COMPACTION_FLOOR, &buf);
    s.last_floor_emitted = floor;
}

/// Emit commit-index gauge + commit-advance counter as typed samples
/// (RFC §4.3). Dropped under backpressure — telemetry never stalls the
/// consensus path.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mid = wire::MODULE_ID_COMMIT_TRACKER;
    let pid = s.partition_id;
    let samples: [(u16, u8, i64); 2] = [
        (wire::metric_ids::COMMIT_INDEX, wire::METRIC_KIND_GAUGE, s.committed_index as i64),
        (wire::metric_ids::COMMIT_ADVANCES, wire::METRIC_KIND_COUNTER, i64::from(s.commit_advances)),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, pid, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_voter_set(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_voter_set < 0 {
        return false;
    }
    let mut changed = false;
    loop {
        let poll = (sys.channel_poll)(s.in_voter_set, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_voter_set, &mut s.msg_buf);
        if msg_type != wire::MSG_VOTER_SET_UPDATE || (plen as usize) < 3 {
            continue;
        }
        if let Some((current, joint, joint_active)) =
            wire::decode_voter_set_update(&s.msg_buf[..plen as usize])
        {
            s.current_voters = NodeSet(current);
            s.joint_voters = NodeSet(joint);
            s.joint_active = joint_active;
            s.voter_count = s.current_voters.count();
            changed = true;
        }
    }
    changed
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_match_indices(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let mut changed = false;
    loop {
        let poll = (sys.channel_poll)(s.in_match, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_match, &mut s.msg_buf);
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_durability(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.in_durable < 0 { return false; }
    let mut changed = false;
    loop {
        let poll = (sys.channel_poll)(s.in_durable, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_durable, &mut s.msg_buf);
        if msg_type != wire::MSG_DURABILITY_PROOF || (plen as usize) < wire::DURABILITY_PROOF_LEN {
            continue;
        }

        // partition_id is part of the proof envelope but commit_tracker
        // is per-partition; we just discard it (the proof always
        // matches our slot because each durability_ledger only fans
        // out to one commit_tracker).
        let (_partition_id, term, index, _replica) = wire::decode_durability_proof(&s.msg_buf);
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

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_cp_state(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_cp_state < 0 { return; }
    loop {
        let poll = (sys.channel_poll)(s.in_cp_state, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_cp_state, &mut s.msg_buf);
        if msg_type == wire::MSG_CACHE_STATE && plen >= 1 {
            s.cp_cache_state = wire::decode_cache_state(&s.msg_buf);
            s.strict_fallback = s.cp_cache_state >= CP_STALE;
        } else if msg_type == wire::MSG_FALLBACK_SIGNAL && plen >= 1 {
            s.strict_fallback = s.msg_buf[0] != 0;
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn advance_commit(s: &mut ModuleState, sys: &SyscallTable) {
    // Compute quorum match index. If a voter-set update has populated
    // `current_voters` we use the joint-aware path (RFC §1.2); during
    // joint mode the effective commit index is the minimum of the two
    // medians so an entry must be replicated to a majority of BOTH
    // sets before it counts as committed. Otherwise we fall back to
    // the legacy fixed-range `voter_count` median.
    let quorum_match = if s.current_voters.count() > 0 {
        let current_median = quorum_index_for_set(&s.match_indices, s.current_voters);
        if s.joint_active && s.joint_voters.count() > 0 {
            let joint_median = quorum_index_for_set(&s.match_indices, s.joint_voters);
            if current_median < joint_median {
                current_median
            } else {
                joint_median
            }
        } else {
            current_median
        }
    } else {
        quorum_index(&s.match_indices, s.voter_count)
    };

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
        // Count committed ENTRIES, not advance events: a single advance can
        // jump the commit index by many entries (group fsync), and throughput
        // benchmarks read this as entries committed.
        let advanced = (new_commit - s.committed_index).min(u32::MAX as Index) as u32;
        s.committed_index = new_commit;
        s.commit_advances = s.commit_advances.saturating_add(advanced);
    }
    // Delivery is handled by emit_committed(), called every step so a drop
    // under backpressure is retried rather than lost (see last_emitted_index).
    emit_committed(s, sys);
}

/// Deliver the current commit horizon on both output channels, retrying every
/// step until each has received it. Idempotent: the message carries the
/// absolute committed high-water, so duplicates are harmless and only the
/// per-channel `last_emitted_*` gate decides whether a send is due. A single
/// dropped, unretried emit under a group-commit burst would stall raft's
/// commit forever — see `last_emitted_index`.
unsafe fn emit_committed(s: &mut ModuleState, sys: &SyscallTable) {
    let mut buf = [0u8; 16];
    wire::encode_term_index(&mut buf, s.committed_term, s.committed_index);

    // raft.commit — dedicated channel, delivered independently of apply. raft
    // drains it promptly (tiny horizon message), so commit advances even
    // while apply.entries is backpressured by a group-commit burst.
    if s.committed_index > s.last_emitted_raft && s.out_raft_commit >= 0 {
        let poll = (sys.channel_poll)(s.out_raft_commit, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0
            && wire_channels::channel_write_msg(sys, s.out_raft_commit, wire::MSG_COMMITTED_BATCH, &buf[..16]) > 0
        {
            s.last_emitted_raft = s.committed_index;
        }
    }

    // apply.entries — may backpressure under bursts; retried until delivered.
    // Never blocks raft (separate channel above).
    if s.committed_index > s.last_emitted_index && s.out_committed >= 0 {
        let poll = (sys.channel_poll)(s.out_committed, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0
            && wire_channels::channel_write_msg(sys, s.out_committed, wire::MSG_COMMITTED_BATCH, &buf[..16]) > 0
        {
            s.last_emitted_index = s.committed_index;
        }
    }
}
