//! Consensus — Raft leader election, log replication, quorum commit
//! and ordered apply.
//!
//! One graph module composed of four components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`raft`]       — the Raft state machine: elections (with
//!     pre-vote), proposal batching, follower log matching + §5.3
//!     conflict repair, admin/config apply, two-slot CRC metadata
//!     persistence (`RAFT<pppp>.M<slot>` / `raft/meta<slot>`).
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
//!      declared ≤4/step bound, gated on `net_out`.
//!   5. reply demux  — the `entry_reply` fan-in serves both WAL
//!      read-back consumers, split on request-id bit 31: set →
//!      `apply::on_entry_reply` (gap refetch), clear →
//!      `replicator::on_wal_reply` (catch-up AE synthesis). ≤16/step.
//!   6. match drain  — E2 coalesced per-replica max → `commit::on_match`.
//!   6b. relaxed self-match — in `durability_mode: relaxed` there is
//!      no durability-proof source to advance commit's self slot, so
//!      raft's log tip is delivered to `commit::on_match` for it
//!      (same read-then-deliver shape as the E11 leader hint). O(1).
//!   7. `commit`     — quorum recompute; raises the horizon latches.
//!   8. latch drain  — E4 → raft's `commit_in` (consumed NEXT step,
//!      one-tick feedback); E3/E6 horizons + the E6 RESET are
//!      handed to apply.
//!   9. `apply`      — consumes the RESET first, then raft's body
//!      ring (E5, ≤16/step), then the horizons, then the read path
//!      (probe replies E8 from raft's queue).
//!
//! Step effects are reported per component at their emitting sites;
//! the module step itself always returns 0.
//!
//! The dispatch table brackets every `component::step` call with
//! `dev_micros` reads and publishes a per-component step-time
//! histogram each second under the component's source id
//! (`step_accounting`, §8 rule 8).

#![cfg_attr(not(feature = "host-test"), no_std)]
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

#[path = "../../common/collections.rs"]
mod collections;
#[path = "../../common/log_fmt.rs"]
mod log_fmt;
#[path = "../../common/step_accounting.rs"]
mod step_accounting;
#[path = "../../common/types.rs"]
mod types;
#[path = "../../common/wal_frame.rs"]
mod wal_frame;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

mod apply;
mod commit;
#[path = "../../common/frame_inbox.rs"]
mod inbox;
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
        => |s, d, len| { s.slots[0].self_id = p_u8(d, len, 0, 0); };

    // Shared: raft (initial voter set + majorities) and commit
    // (quorum median fallback).
    2, voter_count, u8, 1
        => |s, d, len| { s.slots[0].voter_count = p_u8(d, len, 0, 1); };

    3, election_timeout_ms, u16, 1000
        => |s, d, len| { s.slots[0].raft.election_timeout_ms = p_u16(d, len, 0, 1000); };

    4, heartbeat_interval_ms, u16, 150
        => |s, d, len| { s.slots[0].raft.heartbeat_interval_ms = p_u16(d, len, 0, 150); };

    // Group commit: pack up to N client proposals into ONE raft log entry =
    // ONE WAL fsync. Default 1 — one proposal per log index, which every
    // consumer handles. Raising it REQUIRES the committed-entry consumer to
    // split the entry body back into its N self-delimiting proposals — a
    // capability of the consumer, which the substrate cannot detect, so
    // the default stays at the value every consumer handles. Any config
    // whose responses route by unique wal_index must leave it at 1.
    // Maximum log lag, in entries, at which a learner may be promoted
    // to voter by ADMIN_OP_ADD_VOTER. Tight by default: the gate is
    // checked when the op arrives and the promotion applies a few
    // entries later, so a loose bound admits a voter that is still
    // materially behind.
    // Partition Raft Groups this engine hosts. Slot i takes
    // `partition_id = partition_id_param + i`. Clamped to 1..=K_MAX; a
    // graph asking for more gets the ceiling rather than a silent
    // misroute.
    // Relay client proposals from a follower to the leader. Default off.
    // Off, a proposal landing on a non-leader is never drained at all
    // (`drain_proposals` runs only from `step_leader`) and stalls in the
    // channel. On, it is forwarded — but only the untagged,
    // fire-and-forget path (MQTT QoS 0, Kafka acks=0); response-owed
    // writes still need a leader connection. Applies to every slot: with
    // K>1 each group elects its own leader, so a node is a follower for
    // some groups and the leader for others simultaneously.
    20, forward_proposals, u8, 0
        => |s, d, len| {
            // Slot 0 only: `clone_slot_from_zero` mirrors it into slots
            // 1..K after params are parsed, so writing every slot here
            // would be undone anyway.
            s.slots[0].raft.forward_proposals = p_u8(d, len, 0, 0) != 0;
        };

    19, partitions, u16, 1
        => |s, d, len| {
            let k = p_u16(d, len, 0, 1);
            s.active_slots = k.clamp(1, K_MAX as u16) as u8;
        };

    18, catchup_lag_max, u16, 64
        => |s, d, len| { s.slots[0].raft.catchup_lag_max = p_u16(d, len, 0, 64) as u64; };

    5, proposal_batch_max, u16, 1
        => |s, d, len| { s.slots[0].raft.proposal_batch_max = p_u16(d, len, 0, 256); };

    6, proposal_batch_timeout_ms, u16, 10
        => |s, d, len| { s.slots[0].raft.proposal_batch_timeout_ms = p_u16(d, len, 0, 10); };

    // Partition slot for multi-Raft graphs. Default 0 means "single
    // partition"; per-partition instances set this to their slot id and it
    // drives the persistent metadata path and is stamped into every
    // component's metric samples. Shared across all four components.
    7, partition_id, u16, 0
        => |s, d, len| { s.slots[0].partition_id = p_u16(d, len, 0, 0); };

    // 1 = persist metadata to a root-level 8.3 file via FS_OPEN_CREATE
    // (bare-metal FAT32 has no mkdir). See raft's `meta_root_path` field.
    8, root_path, u8, 0
        => |s, d, len| { s.slots[0].raft.meta_root_path = p_u8(d, len, 0, 0); };

    9, peer_count, u8, 0
        => |s, d, len| { s.slots[0].repl.peer_count = p_u8(d, len, 0, 0); };

    10, pipeline_depth, u8, 8
        => |s, d, len| { s.slots[0].repl.pipeline_depth = p_u8(d, len, 0, 8); };

    11, durability_mode, u8, 1, enum { strict=0, group_fsync=1, relaxed=2 }
        => |s, d, len| { s.slots[0].commit.durability_mode = p_u8(d, len, 0, 1); };

    // 0 = no metadata persistence: the declared volatile posture. No
    // load or saves; instead a boot vote hold-off (one election
    // timeout) plus a heard-term floor mitigate the restarted-node
    // double-vote hazard. Pair with the durability module's `volatile`
    // variant and `durability_mode: relaxed`. Default 1 persists via
    // the FS contract (`root_path` selects the layout).
    12, persist_meta, u8, 1, enum { none=0, fs=1 }
        => |s, d, len| { s.slots[0].raft.persist_meta = p_u8(d, len, 0, 1); };

    // Name-publication posture for the election-metadata slots, mirroring
    // the durability module's param of the same name. Default 1 = strict:
    // a provider that cannot fence a name persists nothing, so vote grants
    // and election starts stay withheld rather than resting on a slot the
    // next boot may not find. 0 = auto: fence each slot's directory entry
    // through `fs::FSYNC_NAME` where the provider advertises
    // `caps::FSYNC_NAME`, and report the disposition in `RAFT_NAME_FENCE`
    // where it does not — an observation posture, not a durability one.
    13, name_fence, u8, 1
        => |s, d, len| { s.slots[0].raft.name_fence = p_u8(d, len, 0, 1); };
}

/// Compile-time ceiling on the Partition Raft Groups one `consensus`
/// instance hosts.
///
/// Hosting K groups inside one instance is what keeps the graph's shape
/// independent of K. An instance per partition would scale the edge
/// count with the partition count and reach the fluxor port budget at
/// four, which is also where `partition_router` caps the partitions one
/// router fronts (`MAX_LOCAL_PARTITIONS`) — the two ceilings are set to
/// the same number because they bound the same deployment.
///
/// How many of the `K_MAX` slots are live comes from the `partitions`
/// param, clamped to `1..=K_MAX` and held in `active_slots`; slot `i`
/// owns `partition_id_param + i`. Two mechanisms make more than one
/// slot safe, and both are per-group rather than per-channel:
///
/// - Inbound frames arrive on shared partitioned channels and are
///   demultiplexed by `partition_id` into the owning slot's inbox
///   (`demux_partitioned`), so no slot can consume a frame addressed to
///   a sibling.
/// - Step time is shared by the deficit round-robin in `slot_order`,
///   which serves slot 0 first as a reserved share and rotates the
///   remainder, so neither a control-plane group nor a busy data group
///   can starve the others.
///
/// Two measured constraints set the ceiling:
///
/// - **Step time**: whole-engine step cost rises 1.66us per
///   additional slot, so K=64 extrapolates to ~133us against a 500us
///   half-tick budget. The >=500us tail is FLAT in K — it is WAL fsync,
///   not slot work — so the thing most likely to overrun the tick does
///   not scale with K at all.
/// - **Arena**: each slot costs ~342 KiB of module state (measured
///   31,415,168 -> 32,785,536 bytes going from K=4 to K=8). K=64 puts
///   the graph at ~52 MiB of the 96 MiB state arena.
///
/// Slot state is allocated at K_MAX regardless of `active_slots`, so
/// this is paid unconditionally, which is what makes the arena the
/// binding figure rather than step time.
///
/// NOT bounded by fluxor's 16-ports-per-direction cap: the engine takes
/// ONE partitioned input and demuxes on the envelope, so a graph wires
/// `partition_router.proposals_p0` alone whatever K is.
const K_MAX: usize = 64;

/// One Partition Raft Group's complete state.
///
/// Everything here is per-group and MUST NOT be shared between slots:
/// each group has its own term, log, commit horizon and leader. The
/// only state outside this struct is the engine's shared plumbing —
/// channel handles, demux scratch, telemetry — which carries no
/// group-specific meaning.
#[repr(C)]
struct PrgSlot {
    /// Replica id of this node WITHIN this group. Per-group by design:
    /// the same physical node may hold different replica ids in
    /// different groups.
    self_id: u8,
    voter_count: u8,
    partition_id: u16,

    raft: raft::Raft,
    repl: replicator::Repl,
    commit: commit::Commit,
    apply: apply::Apply,
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Fan-in inputs demuxed by the dispatch table (two consumers each;
    // fluxor caps ports at 16 per direction, and these seams were
    // designed to demux by frame type / request-id namespace anyway).
    in_cp_state: i32,    // MSG_CACHE_STATE → commit, MSG_FALLBACK_SIGNAL → raft
    in_entry_reply: i32, // MSG_WAL_ENTRY_REPLY: id bit 31 set → apply, clear → replicator

    /// The hosted groups. Shared plumbing lives outside; per-group state
    /// lives strictly inside a slot.
    slots: [PrgSlot; K_MAX],
    /// How many of `slots` this instance actually hosts, from the
    /// `partitions` param. Clamped to `1..=K_MAX`.
    active_slots: u8,

    /// Frames whose envelope named a partition no slot hosts. Consumed
    /// and counted rather than left on the channel, where they would
    /// block every frame behind them.
    frames_misrouted: u32,
    /// RPC frames dropped because their group's inbox was full. Raft's
    /// RPCs are all safe to lose — a heartbeat, a vote or an
    /// AppendEntries is retransmitted by the protocol itself — whereas
    /// holding one at the head of the SHARED channel stalls every other
    /// group's heartbeats behind it. At K=64 one group's backlog is
    /// enough to take every group on the node past its election timeout
    /// at once, and the resulting vote storm refills the inbox.
    rpc_dropped_full: u32,
    /// Frames taken off the shared rpc channel since the last accounting
    /// line, and when that line last went out. `[raft] eng rpc=N
    /// dropped=N misrouted=N` once a second, so a link that goes quiet
    /// shows up at the engine's door, not only as a follower timeout.
    rpc_demuxed: u32,
    /// Proposal frames (partitioned, tagged, forwarded) routed to a slot
    /// inbox since the last `[raft] eng` line, and the times the
    /// proposal demux stopped at the channel head because the owning
    /// slot's inbox was full (`held=`): a steady `held` with a low
    /// `prop` is one group holding every other group's writes behind
    /// it.
    prop_demuxed: u32,
    prop_held: u32,
    last_engine_log_ms: u64,

    /// Groups brought up at runtime by `MSG_SLOT_ACTIVATE`.
    slot_activations: u32,
    /// Activations refused for want of a free slot. Non-zero means
    /// placement believes this node hosts more groups than `K_MAX`
    /// allows — a capacity error, not a transient one.
    slot_activations_refused: u32,

    /// Deficit round-robin cursor over slots 1..active. Slot 0 is the
    /// reserved share and is never rotated out of first place.
    rr_offset: u8,

    /// One held frame per demuxed channel (rpc, proposals_partitioned,
    /// proposals_partitioned_tagged). Engine-wide, not per slot: a
    /// carry belongs to the channel, not to a group.
    carry: [Carry; 8],
    /// Shared durability-proof input, drained once per step by the
    /// engine and routed to the slot the proof names.
    durable_chan: i32,

    /// Per-component step-time histograms (§8 rule 8), owned by the
    /// dispatch table: [raft, replicator, commit, apply].
    comp_step: [step_accounting::CompStepHist; 4],
    comp_step_last_ms: u64,

    /// Demux scratch: one inbound frame at a time.
    msg_buf: [u8; 4096],
}

/// Per-module heap arena, shared by every hosted group.
///
/// Backs `apply`'s pending entry bodies. Sizing it here rather than
/// inlining a body in each pending slot is what decouples the memory
/// cost from `slot_count * entry_cap * K_MAX`: the arena holds the
/// entries actually in flight, which is a small fraction of the worst
/// case, and one number covers all K groups instead of multiplying by
/// them.
///
/// 256 KiB holds 128 full 2 KiB entries at once — twice the per-group
/// slot table — while the previous inline layout cost 128 KiB per group
/// unconditionally. Exhaustion is not data loss: `store_pending` fails
/// closed, counts it, and the entry is re-requested from the WAL once
/// applied entries free space.
const ARENA_BYTES: u32 = 256 * 1024;

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    ARENA_BYTES
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
        s.active_slots = 1;
        s.slot_activations = 0;
        s.slot_activations_refused = 0;
        s.rr_offset = 0;
        s.frames_misrouted = 0;
        s.rpc_dropped_full = 0;
        s.rpc_demuxed = 0;
        s.prop_demuxed = 0;
        s.prop_held = 0;
        s.last_engine_log_ms = 0;
        for c in s.carry.iter_mut() {
            *c = Carry::empty();
        }
        s.slots[0].self_id = 0;
        s.slots[0].voter_count = 1;
        s.slots[0].partition_id = 0;
        s.in_cp_state = -1;
        s.in_entry_reply = -1;
        for b in s.msg_buf.iter_mut() {
            *b = 0;
        }

        // EVERY slot, not just the hosted ones: `init` runs before the
        // params that say how many groups this instance hosts, and an
        // uninitialised slot is all-zeroes — which reads as channel
        // handle 0 (a real handle) rather than -1 (unwired).
        for i in 0..K_MAX {
            raft::init(&mut s.slots[i].raft);
            replicator::init(&mut s.slots[i].repl);
            commit::init(&mut s.slots[i].commit);
            apply::init(&mut s.slots[i].apply);
        }

        // Port handles. Indices follow the manifest declaration order
        // (fluxor caps ports at 16 per direction).
        s.slots[0].raft.in_rpc = in_chan; // in[0] rpc
        s.slots[0].raft.in_proposals = dev_channel_port(sys, 0, 1);
        s.slots[0].raft.in_admin = dev_channel_port(sys, 0, 2);
        s.slots[0].raft.in_proposals_tagged = dev_channel_port(sys, 0, 3);
        s.slots[0].raft.in_proposals_partitioned = dev_channel_port(sys, 0, 4);
        s.slots[0].raft.in_proposals_partitioned_tagged = dev_channel_port(sys, 0, 5);
        s.slots[0].raft.in_snapshot_installed = dev_channel_port(sys, 0, 6);
        s.slots[0].raft.in_wal_flushed = dev_channel_port(sys, 0, 7);
        s.slots[0].raft.in_wal_replay_complete = dev_channel_port(sys, 0, 8);
        s.slots[0].repl.in_ack = dev_channel_port(sys, 0, 9);
        s.slots[0].repl.in_snapshot_rx = dev_channel_port(sys, 0, 10);
        // The ENGINE owns this channel, not slot 0. K slots share one
        // handle and `commit::drain_durability` filtered by
        // `partition_id != self` with a `continue` — which CONSUMES the
        // frame. Whichever slot stepped first therefore ate every other
        // partition's durability proofs, so their `durable_index` stayed
        // 0, the commit gate `min(quorum_match, durable_index)` pinned at
        // 0, and their entries appended and replicated but NEVER
        // committed. Symptom: `[commit] hb commit=0 m=40 d=0` on the
        // partitions that lost the race, and exactly one partition
        // serving traffic at K>1.
        s.durable_chan = dev_channel_port(sys, 0, 11);
        s.in_cp_state = dev_channel_port(sys, 0, 12); // demuxed: commit + raft
        s.slots[0].apply.in_read_permits = dev_channel_port(sys, 0, 13);
        s.slots[0].apply.in_reads = dev_channel_port(sys, 0, 14);
        s.in_entry_reply = dev_channel_port(sys, 0, 15); // demuxed: apply + replicator
        s.slots[0].raft.out_rpc = out_chan; // out[0] rpc_out
        s.slots[0].repl.out_net = dev_channel_port(sys, 1, 1);
        s.slots[0].raft.out_log = dev_channel_port(sys, 1, 2);
        s.slots[0].raft.out_metrics = dev_channel_port(sys, 1, 3);
        s.slots[0].raft.out_proposal_assigned = dev_channel_port(sys, 1, 4);
        s.slots[0].raft.out_leader_state = dev_channel_port(sys, 1, 5);
        s.slots[0].raft.out_admin_applied = dev_channel_port(sys, 1, 6);
        s.slots[0].raft.out_wal_compact = dev_channel_port(sys, 1, 7);
        // Same port: the retention floor is multiplexed onto
        // `log_maintenance` by message type (MSG_COMPACTION_FLOOR), which
        // freed the slot `durable_horizon` now occupies.
        s.slots[0].commit.out_retention_floor = dev_channel_port(sys, 1, 7);
        s.slots[0].repl.out_lag = dev_channel_port(sys, 1, 8);
        s.slots[0].repl.out_snapshot_import = dev_channel_port(sys, 1, 9);
        s.slots[0].repl.out_snapshot_request = dev_channel_port(sys, 1, 10);
        s.slots[0].repl.out_cross_durability_ack = dev_channel_port(sys, 1, 11);
        s.slots[0].apply.out_committed_entries = dev_channel_port(sys, 1, 12);
        s.slots[0].apply.out_applied = dev_channel_port(sys, 1, 13);
        s.slots[0].apply.out_entry_request = dev_channel_port(sys, 1, 14);
        s.slots[0].raft.out_durable_horizon = dev_channel_port(sys, 1, 15);
        // All four components share the module's metrics port.
        s.slots[0].repl.out_metrics = s.slots[0].raft.out_metrics;
        s.slots[0].commit.out_metrics = s.slots[0].raft.out_metrics;
        s.slots[0].apply.out_metrics = s.slots[0].raft.out_metrics;
        // The replicator's WAL read-back requests share apply's
        // `entry_request` handle — one fan-in port at durability; the
        // bit-31 request-id namespace keeps their ids disjoint.
        s.slots[0].repl.out_wal_request = s.slots[0].apply.out_entry_request;

        s.comp_step = [step_accounting::CompStepHist::new(); 4];
        s.comp_step_last_ms = 0;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Slot 1..K-1 mirror slot 0's channel handles — every hosted
        // group shares this instance's ports, which is the entire point:
        // the graph's edge count stops scaling with the group count.
        // They differ only in identity, and each takes
        // `partition_id = base + i` so its WAL (`wal/pNNNN/`) and raft
        // metadata land in their own per-partition paths.
        let base_partition = s.slots[0].partition_id;
        let (self_id, voter_count) = (s.slots[0].self_id, s.slots[0].voter_count);
        for i in 1..s.active_slots as usize {
            clone_slot_from_zero(s, i, base_partition + i as u16, self_id, voter_count);
        }

        // Fan shared params into components, per slot.
        for i in 0..s.active_slots as usize {
            fan_slot_identity(s, i);
        }

        {
            let mut dbg = *b"[raft] slots=X";
            dbg[13] = b'0' + s.active_slots.min(9);
            dev_log(sys, 3, dbg.as_ptr(), 14);
        }
        // Post-param boot logic (each component emits its own init log).
        for i in 0..s.active_slots as usize {
            raft::arm(&mut s.slots[i].raft, sys);
            replicator::arm(&mut s.slots[i].repl, sys);
            commit::arm(&mut s.slots[i].commit, sys);
            apply::arm(&mut s.slots[i].apply, sys);
        }
        0
    }
}

/// Slot index for the `pass`-th step of a deficit round-robin that
/// always serves slot 0 first, then rotates the rest by `offset`.
///
/// Slot 0's reserved share is what keeps a control-plane group from being
/// starved by data-plane load; the rotation over the remainder is what keeps
/// any one data group from starving its siblings.
fn slot_order(offset: u8, active: usize, pass: usize) -> usize {
    if pass == 0 || active <= 1 {
        return 0;
    }
    // `active - 1` slots rotate among passes 1..active.
    let n = active - 1;
    1 + ((pass - 1 + offset as usize) % n)
}

/// Largest frame the intake carry can hold: the shared entry-body cap
/// plus envelope slack. `raft`'s own scratch is the same size, so a
/// partitioned frame larger than this cannot reach these channels.
const CARRY_MAX: usize = wal_frame::MAX_ENTRY_BODY + 64;

/// One frame consumed from a shared channel but not yet placed, because
/// its owning slot's inbox was full.
///
/// A shared FIFO cannot deliver a later frame without consuming the
/// earlier one, and `channel_peek` cannot help: the kernel restricts it
/// to PIPE channels and returns `EINVAL` on ordinary FIFOs
/// (`fluxor/src/kernel/ipc/channel.rs`). So the demux reads first and
/// HOLDS the frame when its owner has no room, rather than dropping it.
/// The channel stops being read until the carry places, which
/// backpressures the producer, while every other slot keeps draining
/// what is already in its inbox.
#[repr(C)]
struct Carry {
    active: bool,
    partition_id: u16,
    msg_type: u8,
    len: u16,
    buf: [u8; CARRY_MAX],
}

impl Carry {
    const fn empty() -> Self {
        Self {
            active: false,
            partition_id: 0,
            msg_type: 0,
            len: 0,
            buf: [0u8; CARRY_MAX],
        }
    }
}

/// Index of the slot hosting `partition_id`, if any.
/// Give slot `idx` slot 0's plumbing and the identity of one group.
///
/// Every hosted group shares this instance's ports — that is the whole
/// point of the multi-group engine: the graph's edge count stops
/// scaling with the group count. Slots differ only in identity, and
/// each takes its own `partition_id` so its WAL (`wal/pNNNN/`) and raft
/// metadata land in per-partition paths.
///
/// Used both at construction and by runtime activation, so the set of
/// handles a hosted slot receives has exactly ONE definition. A slot
/// activated at runtime that silently missed a handle the constructor
/// copies would be a group that looks live and cannot replicate.
///
/// `idx` must be non-zero: slot 0 is the template.
fn clone_slot_from_zero(
    s: &mut ModuleState,
    idx: usize,
    partition_id: u16,
    self_id: u8,
    voter_count: u8,
) {
    if idx == 0 || idx >= K_MAX {
        return;
    }
    let (head, tail) = s.slots.split_at_mut(idx);
    let (src, dst) = (&head[0], &mut tail[0]);
    dst.raft.in_rpc = src.raft.in_rpc;
    dst.raft.in_proposals = src.raft.in_proposals;
    dst.raft.in_admin = src.raft.in_admin;
    dst.raft.in_proposals_tagged = src.raft.in_proposals_tagged;
    dst.raft.in_proposals_partitioned = src.raft.in_proposals_partitioned;
    dst.raft.in_proposals_partitioned_tagged = src.raft.in_proposals_partitioned_tagged;
    dst.raft.in_snapshot_installed = src.raft.in_snapshot_installed;
    dst.raft.in_wal_flushed = src.raft.in_wal_flushed;
    dst.raft.in_wal_replay_complete = src.raft.in_wal_replay_complete;
    dst.repl.in_ack = src.repl.in_ack;
    dst.repl.in_snapshot_rx = src.repl.in_snapshot_rx;
    dst.commit.in_durable = src.commit.in_durable;
    dst.apply.in_read_permits = src.apply.in_read_permits;
    dst.apply.in_reads = src.apply.in_reads;

    dst.raft.out_rpc = src.raft.out_rpc;
    dst.repl.out_net = src.repl.out_net;
    dst.raft.out_log = src.raft.out_log;
    dst.raft.out_metrics = src.raft.out_metrics;
    dst.raft.out_proposal_assigned = src.raft.out_proposal_assigned;
    // Leader hints stay on slot 0 ONLY.
    //
    // `MSG_LEADER_HINT` carries `[leader_id][term]` and no partition, so
    // K groups sharing this channel make the value ambiguous: a
    // freshly-activated group announcing "leader unknown" during its
    // first election overwrites the hint for the group its consumers
    // actually care about. Measured: activating a second group flipped
    // `control_plane`'s view to 0xFF, and its "only the leader accepts
    // migration commands" gate then refused every command — which is
    // what made runtime slot activation look like it broke the engine.
    //
    // Both consumers (the gateway's NOT_LEADER answer and the
    // controller-ownership gate) ask about CLUSTER control-plane
    // leadership, which is group 0's. Per-shard leadership is a
    // different question that would need the hint partition-tagged and
    // per-group consumers; nothing asks it today, so restricting
    // emission makes the existing single-value semantics correct by
    // construction instead of ambiguous.
    dst.raft.out_leader_state = -1;
    dst.raft.out_admin_applied = src.raft.out_admin_applied;
    dst.raft.out_wal_compact = src.raft.out_wal_compact;
    dst.repl.out_lag = src.repl.out_lag;
    dst.repl.out_snapshot_import = src.repl.out_snapshot_import;
    dst.repl.out_snapshot_request = src.repl.out_snapshot_request;
    dst.repl.out_cross_durability_ack = src.repl.out_cross_durability_ack;
    dst.commit.out_retention_floor = src.commit.out_retention_floor;
    dst.raft.out_durable_horizon = src.raft.out_durable_horizon;
    // BEHAVIOUR, not a channel — but it belongs here for the same reason:
    // this clone runs AFTER `parse_tlv`, so anything a param sets on
    // slots 1..K is overwritten from slot 0 immediately afterwards.
    // Without this line `forward_proposals` was live on slot 0 only, and
    // at K>1 every partition whose leader sat elsewhere silently dropped
    // its client proposals — measured as 11/60 delivered at K=4 against
    // 60/60 at K=1.
    dst.raft.forward_proposals = src.raft.forward_proposals;
    dst.apply.out_committed_entries = src.apply.out_committed_entries;
    dst.apply.out_applied = src.apply.out_applied;
    dst.apply.out_entry_request = src.apply.out_entry_request;
    dst.repl.out_metrics = src.raft.out_metrics;
    dst.commit.out_metrics = src.raft.out_metrics;
    dst.apply.out_metrics = src.raft.out_metrics;
    dst.repl.out_wal_request = src.apply.out_entry_request;

    dst.raft.election_timeout_ms = src.raft.election_timeout_ms;
    dst.raft.heartbeat_interval_ms = src.raft.heartbeat_interval_ms;
    dst.raft.proposal_batch_max = src.raft.proposal_batch_max;
    dst.raft.proposal_batch_timeout_ms = src.raft.proposal_batch_timeout_ms;
    dst.raft.catchup_lag_max = src.raft.catchup_lag_max;
    dst.raft.persist_meta = src.raft.persist_meta;
    dst.raft.meta_root_path = src.raft.meta_root_path;
    dst.raft.name_fence = src.raft.name_fence;
    dst.repl.peer_count = src.repl.peer_count;
    dst.repl.pipeline_depth = src.repl.pipeline_depth;
    dst.commit.durability_mode = src.commit.durability_mode;

    dst.self_id = self_id;
    dst.voter_count = voter_count;
    dst.partition_id = partition_id;
}

/// Fan a slot's identity into its components.
fn fan_slot_identity(s: &mut ModuleState, i: usize) {
    let sl = &mut s.slots[i];
    sl.raft.self_id = sl.self_id;
    sl.repl.self_id = sl.self_id;
    sl.commit.self_id = sl.self_id;
    sl.raft.voter_count = sl.voter_count;
    sl.commit.voter_count = sl.voter_count;
    sl.raft.partition_id = sl.partition_id;
    sl.repl.partition_id = sl.partition_id;
    sl.commit.partition_id = sl.partition_id;
    sl.apply.partition_id = sl.partition_id;
}

/// Bring up a new hosted group at runtime.
///
/// Idempotent: activating a partition this engine already hosts is a
/// no-op, so a re-delivered or replayed activation cannot clone a
/// second slot for the same group and split its state across two.
///
/// Refused when full. `K_MAX` is a compile-time array bound, so there
/// is no growth path at runtime; saying so through a counter is better
/// than quietly hosting fewer groups than placement believes.
///
/// # Safety
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn activate_slot(
    s: &mut ModuleState,
    sys: &SyscallTable,
    partition_id: u16,
    self_id: u8,
    voter_count: u8,
) {
    if slot_for(s, partition_id).is_some() {
        return;
    }
    let idx = s.active_slots as usize;
    if idx == 0 || idx >= K_MAX {
        s.slot_activations_refused = s.slot_activations_refused.wrapping_add(1);
        return;
    }
    // `voter_count == 0` means "inherit this engine's existing
    // membership": the control plane does not yet own per-group
    // membership, so it cannot state one. Taking the 0 literally gives
    // the new group NO computable quorum — it can never commit, so it
    // campaigns forever, and its election traffic starves the groups
    // that were working. That is a whole-engine outage caused by
    // provisioning one group, so the inheritance is not a convenience.
    let voter_count = if voter_count == 0 {
        s.slots[0].voter_count
    } else {
        voter_count
    };

    // Components for every slot were initialised at construction — an
    // all-zero slot would read channel handle 0 as a real handle — so
    // activation is purely giving this one its plumbing and identity.
    clone_slot_from_zero(s, idx, partition_id, self_id, voter_count);
    fan_slot_identity(s, idx);
    // Publish the slot LAST. The per-slot dispatch loop runs
    // `0..active_slots`, so bumping the count only after the slot is
    // fully wired means a step can never reach a half-built group.
    s.active_slots = s.active_slots.saturating_add(1);
    s.slot_activations = s.slot_activations.wrapping_add(1);
    let mut dbg = *b"[raft] slot+X";
    dbg[12] = b'0' + (partition_id as u8).min(9);
    dev_log(sys, 3, dbg.as_ptr(), 13);
}

fn slot_for(s: &ModuleState, partition_id: u16) -> Option<usize> {
    let mut i = 0;
    while i < K_MAX {
        if s.slots[i].partition_id == partition_id {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Route one shared partitioned channel's frames into the owning slots'
/// inboxes.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
/// What to do with a frame whose group has no inbox room.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnFull {
    /// Keep it at the channel head until the group drains. Right for a
    /// stream the group's LOG depends on — a proposal held is a
    /// proposal delivered later; a proposal dropped is a write lost.
    Hold,
    /// Discard it and count. Right for Raft RPCs, which the protocol
    /// retransmits: a heartbeat resends next interval, a vote request
    /// re-campaigns, an AppendEntries is re-driven by the replicator.
    /// Holding one instead parks the whole shared channel behind a
    /// single group, and every OTHER group on the node then misses its
    /// heartbeats — a per-group backlog becoming a node-wide election.
    /// A forwarded PROPOSAL on the same channel is exempt: it is a
    /// client's write with no retransmit behind it, so it is held.
    Drop,
}

/// Forwarded proposals ride the rpc channel but are proposals, not RPCs.
fn is_forward_type(msg_type: u8) -> bool {
    msg_type == wire::MSG_PROPOSAL_FORWARD || msg_type == wire::MSG_PROPOSAL_FORWARD_TAGGED
}

/// The inbox a frame belongs in: forwards on the rpc channel (carry
/// index 0) go to the group's forward inbox, everything else to the
/// channel's own.
fn inbox_for(
    sl: &mut PrgSlot,
    carry_idx: usize,
    msg_type: u8,
    which: fn(&mut PrgSlot) -> &mut inbox::Inbox,
) -> &mut inbox::Inbox {
    if carry_idx == 0 && is_forward_type(msg_type) {
        &mut sl.raft.inbox_fwd
    } else {
        which(sl)
    }
}

unsafe fn demux_partitioned(
    s: &mut ModuleState,
    sys: &SyscallTable,
    chan: i32,
    carry_idx: usize,
    budget: usize,
    on_full: OnFull,
    which: fn(&mut PrgSlot) -> &mut inbox::Inbox,
) {
    if chan < 0 {
        return;
    }
    // Place a held frame before reading anything new — the order a
    // channel delivers is the order its partition's log must see.
    if s.carry[carry_idx].active {
        let pid = s.carry[carry_idx].partition_id;
        match slot_for(s, pid) {
            None => {
                s.carry[carry_idx].active = false;
                s.frames_misrouted = s.frames_misrouted.wrapping_add(1);
            }
            Some(slot) => {
                let mt = s.carry[carry_idx].msg_type;
                if !inbox_for(&mut s.slots[slot], carry_idx, mt, which).has_room() {
                    return;
                }
                let len = s.carry[carry_idx].len as usize;
                let placed = {
                    let (carry, slots) = (&s.carry[carry_idx], &mut s.slots);
                    inbox_for(&mut slots[slot], carry_idx, mt, which).push(sys, mt, &carry.buf[..len])
                };
                if !placed {
                    // Arena exhausted; keep holding and retry next step.
                    return;
                }
                s.carry[carry_idx].active = false;
            }
        }
    }

    for _ in 0..budget {
        if !wire_channels::readable(sys, chan) {
            break;
        }
        let (partition_id, msg_type, plen) =
            wire_channels::channel_read_partitioned(sys, chan, &mut s.msg_buf);
        if plen == 0 && msg_type == 0 {
            break;
        }
        if carry_idx == 0 {
            s.rpc_demuxed = s.rpc_demuxed.wrapping_add(1);
        } else if carry_idx == 1 || carry_idx == 2 {
            s.prop_demuxed = s.prop_demuxed.wrapping_add(1);
        }
        let len = (plen as usize).min(s.msg_buf.len()).min(CARRY_MAX);
        let Some(slot) = slot_for(s, partition_id) else {
            // No slot hosts this partition. Counted, not re-queued: a
            // frame nobody owns would block the channel head forever.
            s.frames_misrouted = s.frames_misrouted.wrapping_add(1);
            continue;
        };
        let placed = if inbox_for(&mut s.slots[slot], carry_idx, msg_type, which).has_room() {
            let (buf, slots) = (&s.msg_buf, &mut s.slots);
            inbox_for(&mut slots[slot], carry_idx, msg_type, which).push(sys, msg_type, &buf[..len])
        } else {
            false
        };
        if !placed {
            // A forwarded proposal is a client's WRITE, not a protocol
            // RPC: nothing retransmits it, so it is held like a proposal
            // even on a channel whose other traffic is dropped.
            let is_forward = is_forward_type(msg_type);
            if on_full == OnFull::Drop && !is_forward {
                s.rpc_dropped_full = s.rpc_dropped_full.wrapping_add(1);
                // Said once, then every 256th: a steady rate here means
                // a group cannot keep up with its RPC intake, which is a
                // step-budget problem, not a wire problem.
                if s.rpc_dropped_full & 0xFF == 1 {
                    let mut line = [0u8; 64];
                    let mut pos = log_fmt::log_field(
                        &mut line,
                        0,
                        b"[raft] rpc dropped n=",
                        s.rpc_dropped_full,
                    );
                    pos = log_fmt::log_field(&mut line, pos, b" p=", u32::from(partition_id));
                    pos = log_fmt::log_field(&mut line, pos, b" mt=", u32::from(msg_type));
                    dev_log(sys, 2, line.as_ptr(), pos);
                }
                continue;
            }
            // The owner is backed up (or the arena is) and the frame is
            // already off the channel — hold it.
            if carry_idx == 1 || carry_idx == 2 {
                s.prop_held = s.prop_held.wrapping_add(1);
            }
            let c = &mut s.carry[carry_idx];
            c.active = true;
            c.partition_id = partition_id;
            c.msg_type = msg_type;
            c.len = len as u16;
            c.buf[..len].copy_from_slice(&s.msg_buf[..len]);
            break;
        }
    }
}

/// Fill every slot's inbox from the shared partitioned channels.
///
/// Gate-before-place. What happens on a full inbox is per channel
/// (`OnFull`): a log-bearing stream is held so its producer feels
/// backpressure, an RPC stream is dropped and counted because the
/// protocol retransmits and a held RPC would stall every other group's
/// heartbeats behind it.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
/// Route durability proofs to the slots that own them.
///
/// Not a `demux_partitioned`: the proof rides a BARE envelope and names
/// its partition in the payload, so there is nothing for an
/// envelope-based demux to switch on. Applying it is a two-field update,
/// so no per-slot inbox is needed either — the engine decodes and
/// applies directly.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn route_durability_proofs(s: &mut ModuleState, sys: &SyscallTable) {
    if s.durable_chan < 0 {
        return;
    }
    let budget = 32 * s.active_slots.max(1) as usize;
    for _ in 0..budget {
        let Some((msg_type, plen)) =
            wire_channels::next_msg(sys, s.durable_chan, &mut s.msg_buf)
        else {
            break;
        };
        if msg_type != wire::MSG_DURABILITY_PROOF
            || (plen as usize) < wire::DURABILITY_PROOF_LEN
        {
            continue;
        }
        let Some((partition_id, term, index, _replica)) =
            wire::decode_durability_proof(&s.msg_buf[..plen as usize])
        else {
            continue;
        };
        // A proof for a partition this engine does not host is counted,
        // not re-queued — the same policy `demux_partitioned` uses.
        let Some(slot) = slot_for(s, partition_id) else {
            s.frames_misrouted = s.frames_misrouted.wrapping_add(1);
            continue;
        };
        commit::apply_durability_proof(&mut s.slots[slot].commit, term, index);
        if index & 31 == 0 {
            let mut line = [0u8; 72];
            let mut pos = log_fmt::log_field(&mut line, 0, b"[commit] durable p=", u32::from(partition_id));
            pos = log_fmt::log_field(&mut line, pos, b" idx=", index.min(u32::MAX as u64) as u32);
            pos = log_fmt::log_field(&mut line, pos, b" ms=", (dev_millis(sys) & 0xFFFF_FFFF) as u32);
            dev_log(sys, 3, line.as_ptr(), pos);
        }
    }
}

unsafe fn intake_demux(s: &mut ModuleState, sys: &SyscallTable) {
    // Intake budgets scale with the number of hosted groups.
    //
    // These were per-ENGINE constants sized when an engine hosted one
    // group. They are shared fan-ins: every group's RPCs arrive on ONE
    // rpc channel, so a fixed budget of 8 frames per step is 8 frames
    // for ALL K groups, not 8 each. At K=16 that starves elections
    // outright — measured: 32 campaigns, 64 RequestVotes, ZERO leaders,
    // because the votes could not be drained fast enough to be counted
    // before the next timeout.
    //
    // Scaling by `active_slots` restores the per-group share the
    // original constants intended. The ceiling keeps one very busy
    // channel from monopolising a step: this is intake, and the work
    // each frame causes is bounded separately by the per-slot component
    // budgets below.
    let k = s.active_slots.max(1) as usize;
    let per = |base: usize| (base * k).min(base * 16);

    let rpc = s.slots[0].raft.in_rpc;
    demux_partitioned(s, sys, rpc, 0, per(8), OnFull::Drop, |sl| &mut sl.raft.inbox_rpc);
    let pp = s.slots[0].raft.in_proposals_partitioned;
    demux_partitioned(s, sys, pp, 1, per(16), OnFull::Hold, |sl| &mut sl.raft.inbox_prop_p);
    let ppt = s.slots[0].raft.in_proposals_partitioned_tagged;
    demux_partitioned(s, sys, ppt, 2, per(16), OnFull::Hold, |sl| &mut sl.raft.inbox_prop_pt);
    let fl = s.slots[0].raft.in_wal_flushed;
    demux_partitioned(s, sys, fl, 3, per(16), OnFull::Hold, |sl| &mut sl.raft.inbox_flushed);
    let rp = s.slots[0].raft.in_wal_replay_complete;
    demux_partitioned(s, sys, rp, 4, per(4), OnFull::Hold, |sl| &mut sl.raft.inbox_replay);
    let sn = s.slots[0].raft.in_snapshot_installed;
    demux_partitioned(s, sys, sn, 5, per(4), OnFull::Hold, |sl| &mut sl.raft.inbox_snap);
    let ack = s.slots[0].repl.in_ack;
    demux_partitioned(s, sys, ack, 6, per(8), OnFull::Drop, |sl| &mut sl.repl.inbox_ack);
    let adm = s.slots[0].raft.in_admin;
    demux_partitioned(s, sys, adm, 7, per(4), OnFull::Hold, |sl| &mut sl.raft.inbox_admin);

    route_durability_proofs(s, sys);
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
        s.slots[0].raft.meta_fs_step = false;

        // 0-. INTAKE DEMUX. Read each shared partitioned channel once
        //     and route every frame to the slot its envelope names, so
        //     K groups can share a channel without one consuming
        //     another's frames. Runs before every component step so a
        //     frame that arrived this tick is drainable this tick.
        intake_demux(s, sys);
        if now.wrapping_sub(s.last_engine_log_ms) >= 1000 {
            s.last_engine_log_ms = now;
            let mut line = [0u8; 96];
            let mut pos = log_fmt::log_field(&mut line, 0, b"[raft] eng rpc=", s.rpc_demuxed);
            pos = log_fmt::log_field(&mut line, pos, b" dropped=", s.rpc_dropped_full);
            pos = log_fmt::log_field(&mut line, pos, b" misrouted=", s.frames_misrouted);
            pos = log_fmt::log_field(&mut line, pos, b" prop=", s.prop_demuxed);
            pos = log_fmt::log_field(&mut line, pos, b" held=", s.prop_held);
            dev_log(sys, 3, line.as_ptr(), pos);
            s.rpc_demuxed = 0;
            s.prop_demuxed = 0;
            s.prop_held = 0;
        }

        // 0. cp_state fan-in demux: admission's cache-state and
        //    strict-fallback frames share one input (inputs merge B).
        //    MSG_CACHE_STATE feeds commit's CP gate; MSG_FALLBACK_SIGNAL
        //    feeds raft's proposal-intake gate — both delivered before
        //    their consumers step. ≤8/step.
        for _ in 0..8 {
            let Some((msg_type, plen)) =
                wire_channels::next_msg(sys, s.in_cp_state, &mut s.msg_buf)
            else {
                break;
            };
            // BROADCAST, not demux. The control plane's cache state
            // and strict-fallback signal are cluster-wide admission
            // facts, not per-partition ones: a stale CP proof or a
            // fail-closed override applies to every group this engine
            // hosts. Routing one to a single slot would leave the
            // others admitting work the control plane has disowned.
            match msg_type {
                wire::MSG_CACHE_STATE => {
                    let mut i = 0;
                    while i < K_MAX {
                        commit::on_cache_state(&mut s.slots[i].commit, &s.msg_buf, plen);
                        i += 1;
                    }
                }
                wire::MSG_FALLBACK_SIGNAL => {
                    let mut i = 0;
                    while i < K_MAX {
                        raft::on_fallback(&mut s.slots[i].raft, &s.msg_buf, plen);
                        i += 1;
                    }
                }
                // Runtime group activation — the WORK of a migration's
                // PROVISIONING phase. NOT a broadcast: unlike the two
                // above, this names one group.
                wire::MSG_SLOT_ACTIVATE if (plen as usize) >= wire::SLOT_ACTIVATE_LEN => {
                    let partition_id = u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]);
                    let self_id = s.msg_buf[2];
                    let voter_count = s.msg_buf[3];
                    activate_slot(s, sys, partition_id, self_id, voter_count);
                }
                _ => {}
            }
        }

        // Per-slot dispatch. Each hosted group runs the SAME component
        // sequence in the SAME order it ran as a standalone instance —
        // the loop interleaves groups, it does not reorder any group's
        // own steps, so every one-tick feedback timing the components
        // are written against is preserved.
        //
        // DEFICIT ROUND-ROBIN (E3). Slot 0 always runs: it is the
        // reserved share, and in a deployment that hosts the control
        // plane as group 0 that is what stops data-plane load from
        // starving control. The remaining slots rotate, so a slot that
        // missed its turn last step is served first this step and no
        // group can be starved by a busier sibling.
        //
        // The rotation offset advances once per step regardless of how
        // much work each slot found, which is the "deficit" part: a
        // quiet slot does not spend its turn, and a saturated one does
        // not keep it.
        let active = s.active_slots as usize;
        s.rr_offset = if active > 1 {
            (s.rr_offset + 1) % (active as u8)
        } else {
            0
        };
        // Time exactly ONE slot per engine step, rotating.
        //
        // The per-component histograms took two `dev_micros` readings
        // around each of the four components, for EVERY slot, every
        // step. Each reading is a provider call into `clock_gettime`, so
        // at K=64 that is ~512 clock syscalls per step — half a million
        // a second. Profiling the K=64 cluster put 27% of its CPU in
        // `syscall_provider_call` and 11% in `clock_gettime`: the step
        // instrumentation was the dominant cost of running many groups,
        // which is a measurement changing what it measures.
        //
        // Sampling one slot per step keeps the histograms
        // representative — every slot is covered over K steps, and they
        // are a DISTRIBUTION, not a per-slot ledger — while making the
        // clock cost independent of K.
        let timed_slot = if active > 0 {
            slot_order(s.rr_offset, active, s.rr_offset as usize % active)
        } else {
            0
        };
        for pass in 0..active {
            let i = slot_order(s.rr_offset, active, pass);
            let timed = i == timed_slot;
            // 1. raft. Consumes apply's E7 probe queue and E9 admin ring
            //    (filled during LAST step's apply dispatch → next-step
            //    timing preserved) and the E4 commit-horizon latch raised
            //    last step.
            let t0 = if timed { dev_micros(sys) } else { 0 };
            raft::step(
                &mut s.slots[i].raft,
                sys,
                now,
                &mut s.slots[i].apply.admin_out,
                &mut s.slots[i].apply.probe_out,
                &mut s.slots[i].apply.probe_out_count,
            );
            if timed {
                s.comp_step[0].record(dev_micros(sys).wrapping_sub(t0));
            }

            // 1b. E11 leader-state hint → replicator. AppendEntries is a
            //     leader-only RPC; the replicator's catch-up fan-out must
            //     stop the moment raft leaves ROLE_LEADER.
            {
                let (lead, term, commit) = raft::leader_hint(&s.slots[i].raft);
                replicator::on_leader_state(&mut s.slots[i].repl, lead, term, commit);
            }

            // 2. E10 voter-set latch → commit + replicator, in the same
            //    step raft applied the config change.
            if let Some((current, joint, joint_active, learners)) = s.slots[i].raft.voter_out.take()
            {
                // Learners reach only the replicator: it must keep shipping
                // AppendEntries to them, while every quorum tally derives
                // from the voter sets alone and must never see them.
                commit::on_voter_set(&mut s.slots[i].commit, current, joint, joint_active != 0);
                replicator::on_voter_set(
                    &mut s.slots[i].repl,
                    sys,
                    current,
                    joint,
                    joint_active != 0,
                    learners,
                );

                // The durability ledger runs the same union-quorum tally on
                // fsync acks that `commit` runs on match indices, so it needs
                // the same voter sets — but it lives in the `durability`
                // module, across a channel.
                //
                // The update rides raft's WAL-entry channel rather than a
                // port of its own: `durability` is already at its input-port
                // budget, and message-type multiplexing on a shared channel
                // is the established way modules here stay under it. Riding
                // the entry stream also puts the update in FIFO order with
                // the entries whose acks it governs, which a side channel
                // could not guarantee — the ledger sees the new
                // configuration before any ack that must be judged against
                // it.
                if s.slots[i].raft.out_log >= 0 {
                    let mut vbuf = [0u8; wire::VOTER_SET_UPDATE_LEN];
                    wire::encode_voter_set_update(
                        &mut vbuf,
                        current,
                        joint,
                        joint_active != 0,
                        learners,
                    );
                    wire_channels::channel_write_partitioned(
                        sys,
                        s.slots[i].raft.out_log,
                        s.slots[i].partition_id,
                        wire::MSG_VOTER_SET_UPDATE,
                        &vbuf,
                    );
                }
            }

            // 2b. E12 term-fence latch → commit (§5.4.2 gate), raised when a
            //     fresh leader lands its no-op entry. Same-step delivery so
            //     the gate is armed before any match tallies of the new term.
            if let Some((fence_term, fence_index)) = s.slots[i].raft.commit_fence_out.take() {
                commit::on_term_fence(&mut s.slots[i].commit, fence_term, fence_index);
            }

            // 2c. E13 term hint ← replicator: a higher term observed in an
            //     AppendEntriesResponse means this leader is deposed; hand
            //     it to raft so it steps down instead of black-holing
            //     proposals behind a partition it cannot see.
            if let Some(resp_term) = s.slots[i].repl.term_hint_out.take() {
                raft::on_peer_term(&mut s.slots[i].raft, sys, resp_term);
            }

            // 3. replicator — drains raft's E1 AE outbox.
            let t0 = if timed { dev_micros(sys) } else { 0 };
            replicator::step(&mut s.slots[i].repl, &mut s.slots[i].raft.outbox_ae, sys);
            if timed {
                s.comp_step[1].record(dev_micros(sys).wrapping_sub(t0));
            }
        }

        // 3b. entry_reply fan-in demux (inputs merge A): one WAL
        //     read-back reply input serves both consumers, split on
        //     the request-id namespace — bit 31 set is apply's gap
        //     refetch, clear is the replicator's catch-up read-back.
        //     ≤16/step (≤8 per consumer).
        //     The edge now carries the partitioned envelope (one
        //     durability instance serves K groups), so the frame is
        //     routed to its slot first and the request-id split happens
        //     within that slot.
        for _ in 0..16 {
            if !wire_channels::readable(sys, s.in_entry_reply) {
                break;
            }
            let (partition_id, msg_type, plen) =
                wire_channels::channel_read_partitioned(sys, s.in_entry_reply, &mut s.msg_buf);
            if plen == 0 && msg_type == 0 {
                break;
            }
            if msg_type != wire::MSG_WAL_ENTRY_REPLY || (plen as usize) < 4 {
                continue;
            }
            let Some(slot) = slot_for(s, partition_id) else {
                s.frames_misrouted = s.frames_misrouted.wrapping_add(1);
                continue;
            };
            let request_id =
                u32::from_le_bytes([s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3]]);
            if request_id & 0x8000_0000 != 0 {
                apply::on_entry_reply(&mut s.slots[slot].apply, sys, &s.msg_buf, plen);
            } else {
                replicator::on_wal_reply(&mut s.slots[slot].repl, sys, &s.msg_buf, plen);
            }
        }

        // Per-slot dispatch, part two: steps 4-8, after the engine-level
        // entry_reply routing above. Same rotation as part one, so a
        // group's two halves stay adjacent in the step.
        for pass in 0..active {
            let i = slot_order(s.rr_offset, active, pass);
            // Same sampling as the first loop: one slot per step.
            let timed = i == timed_slot;
            // 4. E2 coalesced match array → commit.
            let mut matches = [0 as types::Index; MAX_NODES];
            if replicator::take_matches(&mut s.slots[i].repl, &mut matches) {
                for (r, &index) in matches.iter().enumerate() {
                    if index > 0 {
                        commit::on_match(&mut s.slots[i].commit, r as u8, index);
                        // Same array to raft, which needs per-replica
                        // progress for the learner-promotion gate. Commit
                        // tallies it; raft only reads it.
                        raft::on_match(&mut s.slots[i].raft, r as u8, index);
                    }
                }
            }

            // 4b. Relaxed-mode self-match seed. In strict/group_fsync the
            //     self slot advances on durability proofs; in relaxed mode
            //     there is no barrier to wait for — "self has the entry" is
            //     exactly "self appended the entry" — and a volatile
            //     composition has no proof source at all (quorum_durable is
            //     structurally absent), so without this seed the self slot
            //     pins at 0: single-node graphs never commit and 3-node
            //     medians degrade to min(followers).
            if s.slots[i].commit.durability_mode == types::DUR_RELAXED {
                commit::on_match(
                    &mut s.slots[i].commit,
                    s.slots[i].self_id,
                    raft::log_tip(&s.slots[i].raft),
                );
            }

            // 5. commit — quorum recompute; raises the E3/E4 horizon latches.
            let t0 = if timed { dev_micros(sys) } else { 0 };
            commit::step(&mut s.slots[i].commit, sys);
            if timed {
                s.comp_step[2].record(dev_micros(sys).wrapping_sub(t0));
            }

            // 6. Latch drains. E4 → raft's commit_in (raft consumes it NEXT
            //    step because it dispatches first — the one-tick
            //    feedback and inflight-gate timing). E3/E6 horizons + the
            //    E6 RESET are handed to apply's step, which orders them
            //    internally (reset first, bodies before horizons).
            if let Some((term, index)) = s.slots[i].commit.raft_commit_out.take() {
                s.slots[i].raft.commit_in.raise(term, index);
            }
            let raft_horizon = s.slots[i].raft.apply_horizon_out.take();
            let commit_horizon = s.slots[i].commit.horizon_out.take();
            let reset = s.slots[i].raft.apply_reset_out.take();

            // 7. apply — reset first, then raft's E5 body ring, then the
            //    horizons, then the read path (E8 probe replies).
            let t0 = if timed { dev_micros(sys) } else { 0 };
            apply::step(
                &mut s.slots[i].apply,
                sys,
                now,
                reset,
                raft_horizon,
                commit_horizon,
                &mut s.slots[i].raft.outbox_bodies,
                &mut s.slots[i].raft.probe_reply_out,
                &mut s.slots[i].raft.probe_reply_count,
            );
            if timed {
                s.comp_step[3].record(dev_micros(sys).wrapping_sub(t0));
            }

            // 8. Per-component step accounting (§8 rule 8): publish each
            //    component's step-time histogram every second under its
            //    own source id.
            if now.wrapping_sub(s.comp_step_last_ms) >= 1000 {
                s.comp_step_last_ms = now;
                const COMP_IDS: [u8; 4] = [
                    wire::SOURCE_ID_RAFT,
                    wire::SOURCE_ID_REPLICATOR,
                    wire::SOURCE_ID_COMMIT,
                    wire::SOURCE_ID_APPLY,
                ];
                for (h, &id) in s.comp_step.iter().zip(COMP_IDS.iter()) {
                    h.emit(
                        sys,
                        s.slots[i].raft.out_metrics,
                        id,
                        s.slots[i].partition_id,
                    );
                }
            }

            // A step that persisted raft metadata (vote/term change) did a
            // synchronous FS write+fsync. Classify it as Burst so the
            // scheduler forgives the one-shot overrun instead of letting it
            // delay the heartbeat that keeps this leader elected.
        }

        if s.slots[0].raft.meta_fs_step {
            STEP_BURST
        } else {
            0
        }
    }
}
