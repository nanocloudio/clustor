//! Durability — write-ahead log, quorum durability ledger, snapshots
//! and key epochs.
//!
//! One graph module composed of four components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`wal`]      — segment-file WAL: CRC32C framing, replay,
//!     group/async-fenced fsync, truncation, compaction, gap-refetch
//!     serving.
//!   - [`ledger`]   — per-replica durable indices → quorum durability
//!     proofs (compiled out of the `volatile` variant).
//!   - [`snapshot`] — manifest persistence, chunked install transfer,
//!     retention floors, app snapshot round-trip.
//!   - [`keys`]     — DEK epoch rotation.
//!
//! ## Variants
//!
//! `disk` (default) is the durable composition. `volatile` selects
//! the WAL's in-memory retention path at compile time and **compiles
//! the ledger component out** — its `ack` input and `quorum_durable`
//! output are absent from the manifest, so a volatile composition is
//! structurally incapable of emitting a durability proof. Fail-closed
//! by construction, not by configuration.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else:
//!
//!   1. `keys`     — rotation check; the epoch is handed to wal and
//!      snapshot (idempotent latest-wins). Bound (`keys::step`): one
//!      rotation check, ≤1 cert-refresh emit.
//!   2. `wal`      — replay or the write path. Durable high-water and
//!      rotation triggers land in monotone latches. Bound
//!      (`wal::step`): replay is one FS open OR one frame; normal
//!      mode ≤8 input records + ≤4 control frames (at most one of
//!      them a truncation) + ≤8 gap-refetch serves + at most one cold
//!      segment open. Physical segment removal, from compaction or a
//!      truncation's retirement alike, is paced at
//!      `COMPACT_UNLINKS_PER_STEP` per step; a step that removed any
//!      returns Burst, each removal being an unlink plus a directory
//!      fence.
//!   3. latch drain — the ledger receives the local durable advance;
//!      the snapshot component receives the rotation trigger. O(1)
//!      composition-layer code.
//!   4. `ledger`   — cross-node ack drain + quorum recompute (disk
//!      variant only). Bound (`ledger::step`): ≤32 acks + ≤1 quorum
//!      recompute and proof emit.
//!   4b. high-water seam — the wal's current `(term, index)` is
//!      delivered to `snapshot::on_wal_high_water`: the capture point
//!      for a demand-triggered snapshot. O(1).
//!   5. `snapshot` — floors, external triggers, install transfer.
//!      Bound (`snapshot::step`): ≤4 frames per input family + ≤1
//!      app-body chunk + ≤1 demand-triggered capture (a synchronous
//!      finalise, reported as a cold-FS step → Burst).
//!   5b. install fast-forward — an accepted peer install latches
//!      `(term, index)` for `wal::on_snapshot_installed`, so the wal
//!      advances its append contract past the prefix the snapshot
//!      subsumes before the next entry arrives. O(1).
//!
//! The wal's Burst classifications and the snapshot component's
//! cold-FS steps propagate as the module's step return.
//!
//! The dispatch table brackets every component step with `dev_micros`
//! reads and publishes a per-component step-time histogram each
//! second under the component's source id (`step_accounting`,
//! §8 rule 8).

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
#[path = "../../common/frame_inbox.rs"]
mod inbox;
#[path = "../../common/types.rs"]
mod types;
#[path = "../../common/wal_frame.rs"]
mod wal_frame;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

#[path = "../../common/step_accounting.rs"]
mod step_accounting;

mod keys;
#[cfg(not(feature = "volatile"))]
mod ledger;
mod snapshot;
mod wal;

/// Composite step return for a step that did cold synchronous disk
/// work (same contract as the kernel Burst outcome).
const STEP_BURST: i32 = 2;

define_params! {
    ModuleState;

    1, encoding, u8, 0
        => |s, d, len| { s.slots[0].wal.encoding = p_u8(d, len, 0, 0); };

    2, segment_bytes, u32, 67_108_864
        => |s, d, len| { s.slots[0].wal.segment_limit = p_u32(d, len, 0, 67_108_864); };

    // 3, aead — reserved (0=none, 1=aes_256_gcm); not yet read at runtime.

    // Partition slot for multi-Raft graphs. Stamped into segment and
    // snapshot filenames and into outgoing durability proofs.
    4, partition_id, u16, 0
        => |s, d, len| { s.slots[0].partition_id = p_u16(d, len, 0, 0); };

    // Replica id this node's durability belongs to. Stamped into
    // FsyncAcks/proofs; must match consensus.self_id on this node.
    5, self_id, u8, 0
        => |s, d, len| { s.slots[0].self_id = p_u8(d, len, 0, 0); };

    // 0 = per-entry write + fsync + ack (default, strict). 1 = group fsync.
    6, fsync_mode, u8, 0
        => |s, d, len| { s.slots[0].wal.fsync_mode = p_u8(d, len, 0, 0); };

    7, group_window_ms, u16, 2
        => |s, d, len| { s.slots[0].wal.group_window_ms = p_u16(d, len, 0, 2); };

    8, group_max_pending, u16, 64
        => |s, d, len| { s.slots[0].wal.group_max_pending = p_u16(d, len, 0, 64); };

    // 1 = 8.3-conforming names at the FS root (bare-metal FAT32) for
    // BOTH segments and snapshots — one param, one layout.
    // Partition Raft Groups this instance hosts. Mirrors consensus's
    // `partitions`; slot i takes `partition_id = partition_id + i`.
    16, partitions, u16, 1
        => |s, d, len| {
            let k = p_u16(d, len, 0, 1);
            s.active_slots = k.clamp(1, K_MAX as u16) as u8;
        };

    9, root_path, u8, 0
        => |s, d, len| { s.root_path = p_u8(d, len, 0, 0); };

    // 1 = skip boot replay (start fresh).
    10, skip_replay, u8, 0
        => |s, d, len| { s.slots[0].wal.skip_replay = p_u8(d, len, 0, 0); };

    // 1 = physically preallocated fixed-capacity segments.
    11, fixed_segment, u8, 0
        => |s, d, len| { s.slots[0].wal.fixed_segment = p_u8(d, len, 0, 0); };

    12, preallocate_settle_ms, u16, 0
        => |s, d, len| { s.slots[0].wal.preallocate_settle_ms = p_u16(d, len, 0, 0); };

    // Fence-pipelining depth (async FS backend only).
    13, fence_depth, u16, 1
        => |s, d, len| { s.slots[0].wal.fence_depth = p_u16(d, len, 0, 1); };

    14, voter_count, u8, 1
        => |s, d, len| { s.slots[0].voter_count = p_u8(d, len, 0, 1); };

    // Name-publication posture for WAL segments, snapshot artefacts and
    // pointer slots. Default 1 = strict: a provider that cannot fence a
    // name is refused, so no artefact is ever created under a name whose
    // durability is unproven. 0 = auto: fence every name through
    // `fs::FSYNC_NAME` where the provider advertises `caps::FSYNC_NAME`,
    // and meter the publications it cannot fence (`WAL_NAME_UNFENCED` /
    // `SNAP_NAME_UNFENCED`) — an observation posture, not a durability
    // one.
    15, name_fence, u8, 1
        => |s, d, len| { s.name_fence = p_u8(d, len, 0, 1); };
}

/// Compile-time ceiling on the Partition Raft Groups one `durability`
/// instance hosts.
///
/// Mirrors `consensus`'s `K_MAX`, and must: hosting K groups in one
/// instance is what keeps the graph shape independent of K, and it only
/// works if BOTH sides do it. A K>1 consensus engine wired to K separate
/// durability instances multiplies edges just the same.
///
/// Frames reach the right group the same way they do in `consensus`:
/// they arrive on shared partitioned channels and `demux_partitioned`
/// routes each by `partition_id` into the owning slot's inbox, so no
/// slot can consume a frame addressed to a sibling.
///
/// Memory is the dimension that distinguishes this side, and it is what
/// bounds the ceiling — step time does not. Slots are allocated at
/// K_MAX whatever `active_slots` is, so the cost is paid
/// unconditionally, and each slot carries a full `wal::Wal` whose rings
/// dominate it: `WAL_FOOTPRINT_BUDGET` bounds ONE of them at 320 KiB on
/// a disk build and 600 KiB on a volatile one, and the module's state is
/// K times that. K=64 is therefore tens of megabytes of the 96 MiB state
/// arena on a volatile build, which is why the rings are sized per
/// variant rather than at the larger of the two. Queued frames are the
/// exception: they live in the shared `ARENA_BYTES` heap rather than in
/// `K * depth * MAX_FRAME` of fixed state.
///
/// NOT bounded by fluxor's 16-ports-per-direction cap: the engine takes
/// ONE partitioned input and demuxes on the envelope, so a graph wires
/// `partition_router.proposals_p0` alone whatever K is.
const K_MAX: usize = 64;

/// Ring-telemetry id of `fsync_latency_us` — its POSITION in this manifest's
/// `[observability].metrics` list (28 wal + 6 snapshot names precede it).
/// The manifest's `[[observability.instrument]]` row carries the bounds and
/// the `fluxor.slot` dimension; drift between this constant and the list is
/// a mislabeled series, so both sit next to a counting comment.
const FSYNC_HIST_RING_ID: u16 = 34;
/// Ring id of `snapshot_transfer_us` (manifest position 35 — appended after
/// `fsync_latency_us`; count before reordering).
const SNAPSHOT_HIST_RING_ID: u16 = 35;
/// Declared numeric domain of the slot dimension (`max` in the manifest row).
/// A partition id at or past it folds to `__other__` rather than lying.
const FSYNC_DIM_MAX: u16 = K_MAX as u16;

/// One Partition Raft Group's durability state.
///
/// Everything here is per-group: its own WAL segments and index ring,
/// its own durability tally, its own snapshot artefacts and keys. The
/// only state outside a slot is deployment-wide config and the shared
/// plumbing.
#[repr(C)]
struct DurSlot {
    /// Replica id of this node WITHIN this group — per-group by design,
    /// as in `consensus::PrgSlot`.
    partition_id: u16,
    self_id: u8,
    voter_count: u8,

    wal: wal::Wal,
    #[cfg(not(feature = "volatile"))]
    ledger: ledger::Ledger,
    snapshot: snapshot::Snapshot,
    keys: keys::Keys,
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    /// Deployment-wide storage config, identical for every hosted group
    /// (they differ by partition id inside the path, not by root), so it
    /// stays shared rather than duplicated per slot.
    root_path: u8,
    name_fence: u8,

    /// The hosted groups.
    slots: [DurSlot; K_MAX],
    /// in: `MSG_SLOT_ACTIVATE` — bring up a group at runtime.
    in_slot_activate: i32,
    /// Groups brought up at runtime.
    slot_activations: u32,
    /// Activations refused for want of a free slot (`K_MAX` is a
    /// compile-time bound, so this is a capacity error).
    slot_activations_refused: u32,
    /// How many of `slots` this instance hosts, from the `partitions`
    /// param. Clamped to `1..=K_MAX`.
    active_slots: u8,
    /// Throttle for the kernel-ring telemetry emit (`dev_millis` of the last
    /// round). The wal fsync-latency histogram goes out on TWO wires from
    /// one set of accumulators: the kernel telemetry ring (id
    /// `FSYNC_HIST_RING_ID`, one record per hosted slot, partition id as the
    /// declared dimension) and the `MSG_METRIC_SAMPLE` channel export. The
    /// ring is a pull surface and the channel export a push one, so a
    /// deployment can scrape whichever its collector speaks.
    last_ring_tlm_ms: u64,
    /// Frames whose envelope named a partition no slot hosts.
    frames_misrouted: u32,
    /// One held frame per demuxed channel (entries, entry_request, ack).
    carry: [Carry; 7],
    /// Demux scratch — separate from any component's buffer.
    demux_buf: [u8; CARRY_MAX],

    /// Per-component step-time histograms (§8 rule 8), owned by the
    /// dispatch table: [keys, wal, ledger, snapshot]. The volatile
    /// variant leaves the ledger entry idle.
    comp_step: [step_accounting::CompStepHist; 4],
    comp_step_last_ms: u64,
}

/// Per-module heap arena, shared by every hosted group.
///
/// Backs the per-slot frame inboxes: the intake demux copies each
/// routed frame here rather than into `K * depth * MAX_FRAME` of fixed
/// module state. A queued frame lives only until the owning component's
/// next drain, so occupancy tracks frames actually in flight.
///
/// Without this export the kernel gives the module no heap,
/// `heap_alloc` returns null, and EVERY inbox push fails closed — which
/// is the safe direction but leaves the engine unable to deliver
/// anything at all.
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
        s.slots[0].partition_id = 0;
        s.slots[0].self_id = 0;
        s.slots[0].voter_count = 1;
        s.active_slots = 1;
        s.last_ring_tlm_ms = 0;
        s.frames_misrouted = 0;
        for c in s.carry.iter_mut() {
            *c = Carry::empty();
        }
        s.root_path = 0;
        s.name_fence = 0;
        // EVERY slot, not just the hosted ones: `init` runs before the
        // params that say how many groups this instance hosts, and an
        // uninitialised slot is all-zeroes — which reads as channel
        // handle 0 (a real handle) rather than -1 (unwired). Cheap, and
        // it removes the ordering hazard entirely.
        for i in 0..K_MAX {
            wal::init(&mut s.slots[i].wal);
            #[cfg(not(feature = "volatile"))]
            ledger::init(&mut s.slots[i].ledger);
            snapshot::init(&mut s.slots[i].snapshot);
            keys::init(&mut s.slots[i].keys, sys);
        }

        // Port handles. Indices follow the manifest declaration order;
        // the volatile variant omits the ledger ports and leaves their
        // indices as holes, so every index below is stable across
        // variants.
        s.slots[0].wal.in_entries = in_chan; // in[0] entries
        s.slots[0].wal.in_entry_request = dev_channel_port(sys, 0, 1);
        s.slots[0].wal.in_compact_before = dev_channel_port(sys, 0, 2);
        #[cfg(not(feature = "volatile"))]
        {
            s.slots[0].ledger.in_ack = dev_channel_port(sys, 0, 3);
        }
        s.slots[0].snapshot.in_import = dev_channel_port(sys, 0, 4);
        s.slots[0].snapshot.in_trigger = dev_channel_port(sys, 0, 5);
        s.slots[0].snapshot.in_install_request = dev_channel_port(sys, 0, 6);
        s.slots[0].wal.in_retention_floor = dev_channel_port(sys, 0, 7);
        s.slots[0].snapshot.in_app_body = dev_channel_port(sys, 0, 8);
        // Input 9: runtime group activation, declared last in the manifest.
        s.in_slot_activate = dev_channel_port(sys, 0, 9);
        s.slot_activations = 0;
        s.slot_activations_refused = 0;
        s.slots[0].wal.out_flushed = out_chan; // out[0] flushed
        s.slots[0].wal.out_replay_complete = dev_channel_port(sys, 1, 1);
        s.slots[0].wal.out_entry_reply = dev_channel_port(sys, 1, 2);
        // Declared LAST in the manifest, so these take the highest
        // indices and nothing above shifted.
        s.slots[0].wal.in_cold_read = dev_channel_port(sys, 0, 10);
        s.slots[0].wal.out_cold_reply = dev_channel_port(sys, 1, 11);
        s.slots[0].wal.out_compaction = dev_channel_port(sys, 1, 3);
        s.slots[0].wal.out_metrics = dev_channel_port(sys, 1, 4);
        #[cfg(not(feature = "volatile"))]
        {
            s.slots[0].ledger.out_quorum = dev_channel_port(sys, 1, 5);
        }
        s.slots[0].snapshot.out_export = dev_channel_port(sys, 1, 6);
        s.slots[0].snapshot.out_manifest = dev_channel_port(sys, 1, 7);
        s.slots[0].snapshot.out_installed = dev_channel_port(sys, 1, 8);
        s.slots[0].snapshot.out_app_ctl = dev_channel_port(sys, 1, 9);
        s.slots[0].keys.out_cert = dev_channel_port(sys, 1, 10);
        // The snapshot component shares the module's metrics port.
        s.slots[0].snapshot.out_metrics = s.slots[0].wal.out_metrics;

        s.comp_step = [step_accounting::CompStepHist::new(); 4];
        s.comp_step_last_ms = 0;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Slots 1..K-1 mirror slot 0's channel handles — every hosted
        // group shares this instance's ports. They differ only in
        // identity: `partition_id = base + i`, which is what puts each
        // group's WAL under its own `wal/pNNNN/` and its snapshots under
        // their own names.
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
            let mut dbg = *b"[dur] slots=X";
            dbg[12] = b'0' + s.active_slots.min(9);
            dev_log(sys, 3, dbg.as_ptr(), 13);
        }
        dev_log(sys, 3, b"[wal] init".as_ptr(), 10);
        #[cfg(not(feature = "volatile"))]
        dev_log(sys, 3, b"[dur] init".as_ptr(), 10);
        dev_log(sys, 3, b"[snap] init".as_ptr(), 11);
        dev_log(sys, 3, b"[keys] init".as_ptr(), 11);
        0
    }
}

/// Largest frame the intake carry can hold.
const CARRY_MAX: usize = wal_frame::MAX_ENTRY_BODY + 64;

/// A frame consumed from a shared channel but not yet placed, because
/// its owning slot's inbox was full. See `consensus`'s twin for why a
/// hold beats a peek here (`channel_peek` is PIPE-only in the kernel).
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
/// Bring up a new hosted group at runtime — the durability half of a
/// migration's PROVISIONING work.
///
/// Idempotent, and refused when full for the same reasons as the
/// consensus side: a second slot for one group would split its WAL, and
/// `K_MAX` is a compile-time array bound with no runtime growth path.
///
/// # Safety
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn drain_slot_activate(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_slot_activate < 0 {
        return;
    }
    // Local scratch: this module has no shared message buffer, and the
    // frame is four bytes.
    let mut buf = [0u8; wire::SLOT_ACTIVATE_LEN];
    for _ in 0..4 {
        let Some((msg_type, plen)) = wire_channels::next_msg(sys, s.in_slot_activate, &mut buf)
        else {
            break;
        };
        if msg_type != wire::MSG_SLOT_ACTIVATE || (plen as usize) < wire::SLOT_ACTIVATE_LEN {
            continue;
        }
        let partition_id = u16::from_le_bytes([buf[0], buf[1]]);
        let self_id = buf[2];
        // `0` means "inherit this engine's membership": the control
        // plane does not yet own per-group membership, so it cannot
        // state one, and a literal 0 leaves the group unable to form a
        // quorum.
        let voter_count = if buf[3] == 0 {
            s.slots[0].voter_count
        } else {
            buf[3]
        };
        if slot_for(s, partition_id).is_some() {
            continue;
        }
        let idx = s.active_slots as usize;
        if idx == 0 || idx >= K_MAX {
            s.slot_activations_refused = s.slot_activations_refused.wrapping_add(1);
            continue;
        }
        clone_slot_from_zero(s, idx, partition_id, self_id, voter_count);
        fan_slot_identity(s, idx);
        // Publish LAST: the per-slot dispatch runs `0..active_slots`,
        // so bumping only after the slot is wired means no step can
        // reach a half-built group.
        s.active_slots = s.active_slots.saturating_add(1);
        s.slot_activations = s.slot_activations.wrapping_add(1);
        dev_log(sys, 3, b"[dur] slot+".as_ptr(), 11);
    }
}

fn slot_for(s: &ModuleState, partition_id: u16) -> Option<usize> {
    let mut i = 0;
    while i < s.active_slots as usize {
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
unsafe fn demux_partitioned(
    s: &mut ModuleState,
    sys: &SyscallTable,
    chan: i32,
    carry_idx: usize,
    budget: usize,
    which: fn(&mut DurSlot) -> &mut inbox::Inbox,
) {
    if chan < 0 {
        return;
    }
    if s.carry[carry_idx].active {
        let pid = s.carry[carry_idx].partition_id;
        match slot_for(s, pid) {
            None => {
                s.carry[carry_idx].active = false;
                s.frames_misrouted = s.frames_misrouted.wrapping_add(1);
            }
            Some(slot) => {
                if !which(&mut s.slots[slot]).has_room() {
                    return;
                }
                let mt = s.carry[carry_idx].msg_type;
                let len = s.carry[carry_idx].len as usize;
                let placed = {
                    let (carry, slots) = (&s.carry[carry_idx], &mut s.slots);
                    which(&mut slots[slot]).push(sys, mt, &carry.buf[..len])
                };
                if !placed {
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
            wire_channels::channel_read_partitioned(sys, chan, &mut s.demux_buf);
        if plen == 0 && msg_type == 0 {
            break;
        }
        let len = (plen as usize).min(s.demux_buf.len()).min(CARRY_MAX);
        let Some(slot) = slot_for(s, partition_id) else {
            s.frames_misrouted = s.frames_misrouted.wrapping_add(1);
            continue;
        };
        let placed = if which(&mut s.slots[slot]).has_room() {
            let (buf, slots) = (&s.demux_buf, &mut s.slots);
            which(&mut slots[slot]).push(sys, msg_type, &buf[..len])
        } else {
            false
        };
        if !placed {
            let c = &mut s.carry[carry_idx];
            c.active = true;
            c.partition_id = partition_id;
            c.msg_type = msg_type;
            c.len = len as u16;
            c.buf[..len].copy_from_slice(&s.demux_buf[..len]);
            break;
        }
    }
}

/// Fill every slot's inbox from the shared partitioned channels.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn intake_demux(s: &mut ModuleState, sys: &SyscallTable) {
    let en = s.slots[0].wal.in_entries;
    demux_partitioned(s, sys, en, 0, 16, |sl| &mut sl.wal.inbox_entries);
    let er = s.slots[0].wal.in_entry_request;
    demux_partitioned(s, sys, er, 1, 8, |sl| &mut sl.wal.inbox_entry_req);
    #[cfg(not(feature = "volatile"))]
    {
        let ak = s.slots[0].ledger.in_ack;
        demux_partitioned(s, sys, ak, 2, 32, |sl| &mut sl.ledger.inbox_ack);
    }
    let im = s.slots[0].snapshot.in_import;
    demux_partitioned(s, sys, im, 3, 8, |sl| &mut sl.snapshot.inbox_import);
    let ir = s.slots[0].snapshot.in_install_request;
    demux_partitioned(s, sys, ir, 4, 4, |sl| &mut sl.snapshot.inbox_install_req);
    let rf = s.slots[0].wal.in_retention_floor;
    demux_partitioned(s, sys, rf, 5, 8, |sl| &mut sl.wal.inbox_retention);
    // Cold reads name the partition whose WAL holds the index: raft
    // indexes are per-log, so a request served by whichever slot
    // drained first would answer from the wrong log.
    let cr = s.slots[0].wal.in_cold_read;
    demux_partitioned(s, sys, cr, 6, 4, |sl| &mut sl.wal.inbox_cold_read);
}

/// Give slot `idx` slot 0's plumbing and the identity of one group.
///
/// The durability mirror of `consensus`'s helper of the same shape, and
/// for the same reason: every hosted group shares this instance's
/// ports, differing only in identity, and each takes its own
/// `partition_id` so its WAL and snapshots land in per-partition paths.
///
/// Used both at construction and by runtime activation, so a slot
/// brought up during a migration's PROVISIONING gets exactly the
/// handles a constructed one does.
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
    dst.wal.in_entries = src.wal.in_entries;
    dst.wal.in_entry_request = src.wal.in_entry_request;
    dst.wal.in_compact_before = src.wal.in_compact_before;
    dst.wal.out_flushed = src.wal.out_flushed;
    dst.wal.out_replay_complete = src.wal.out_replay_complete;
    dst.wal.out_entry_reply = src.wal.out_entry_reply;
    dst.wal.in_cold_read = src.wal.in_cold_read;
    dst.wal.out_cold_reply = src.wal.out_cold_reply;
    dst.wal.out_compaction = src.wal.out_compaction;
    dst.wal.out_metrics = src.wal.out_metrics;
    dst.snapshot.in_import = src.snapshot.in_import;
    dst.snapshot.in_trigger = src.snapshot.in_trigger;
    dst.snapshot.in_install_request = src.snapshot.in_install_request;
    dst.wal.in_retention_floor = src.wal.in_retention_floor;
    dst.snapshot.in_app_body = src.snapshot.in_app_body;
    dst.snapshot.out_export = src.snapshot.out_export;
    dst.snapshot.out_manifest = src.snapshot.out_manifest;
    dst.snapshot.out_installed = src.snapshot.out_installed;
    dst.snapshot.out_app_ctl = src.snapshot.out_app_ctl;
    dst.snapshot.out_metrics = src.wal.out_metrics;
    dst.keys.out_cert = src.keys.out_cert;
    #[cfg(not(feature = "volatile"))]
    {
        dst.ledger.in_ack = src.ledger.in_ack;
        dst.ledger.out_quorum = src.ledger.out_quorum;
    }
    // Tuning params too: every hosted group must write with the
    // same durability posture. Missing these is not cosmetic —
    // a slot left on the default `fsync_mode` would give its
    // group a different durability guarantee from its siblings
    // while reporting the same one.
    dst.wal.encoding = src.wal.encoding;
    dst.wal.segment_limit = src.wal.segment_limit;
    dst.wal.fsync_mode = src.wal.fsync_mode;
    dst.wal.group_window_ms = src.wal.group_window_ms;
    dst.wal.group_max_pending = src.wal.group_max_pending;
    dst.wal.skip_replay = src.wal.skip_replay;
    dst.wal.fixed_segment = src.wal.fixed_segment;
    dst.wal.preallocate_settle_ms = src.wal.preallocate_settle_ms;
    dst.wal.fence_depth = src.wal.fence_depth;

    dst.self_id = self_id;
    dst.voter_count = voter_count;
    dst.partition_id = partition_id;
}

/// Fan a slot's identity and shared params into its components.
fn fan_slot_identity(s: &mut ModuleState, i: usize) {
    s.slots[i].wal.partition_id = s.slots[i].partition_id;
    s.slots[i].wal.self_id = s.slots[i].self_id;
    s.slots[i].wal.root_path = s.root_path;
    s.slots[i].wal.name_fence = s.name_fence;
    s.slots[i].snapshot.partition_id = s.slots[i].partition_id;
    s.slots[i].snapshot.root_path = s.root_path;
    s.slots[i].snapshot.name_fence = s.name_fence;
    #[cfg(not(feature = "volatile"))]
    {
        s.slots[i].ledger.self_id = s.slots[i].self_id;
        s.slots[i].ledger.partition_id = s.slots[i].partition_id;
        s.slots[i].ledger.voter_count = s.slots[i].voter_count;
        ledger::clamp_voters(&mut s.slots[i].ledger);
    }
    wal::arm(&mut s.slots[i].wal);
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
        // INTAKE DEMUX. Read each shared partitioned channel once and
        // route every frame to the slot its envelope names. Without
        // this, one slot's destructive read consumes — and discards —
        // frames addressed to its siblings, which is exactly how a
        // second group ends up with an empty WAL while its raft happily
        // elects a leader.
        intake_demux(s, sys);

        // Runtime group activation. Ordered BEFORE the per-slot
        // dispatch so a group activated this step is durable from its
        // very first step — a consensus slot that starts replicating
        // before its durability slot exists has nowhere to persist.
        drain_slot_activate(s, sys);

        // Per-slot dispatch. Each hosted group runs the SAME component
        // sequence in the SAME order it ran as a standalone instance;
        // the loop interleaves groups without reordering any group's
        // own steps. `wal_rc` / `cold_fs` accumulate across groups —
        // one group's cold FS touch is a Burst for the whole engine,
        // which is the honest answer: the step really did that work.
        let mut wal_rc = 0i32;
        let mut cold_fs = false;
        for i in 0..s.active_slots as usize {
            let t0 = dev_micros(sys);
            let epoch = keys::step(&mut s.slots[i].keys, sys, now);
            s.comp_step[0].record(dev_micros(sys).wrapping_sub(t0));
            s.slots[i].wal.dek_epoch = epoch;
            s.slots[i].snapshot.dek_epoch = epoch;

            // Boot restore FIRST: the persisted local snapshot's app body
            // must reach the state machine before the wal replays its
            // (possibly compacted) tail on top of it. Holding `wal::step`
            // holds the whole replay → raft-resume handoff, so nothing is
            // applied out of order and proposal intake stays closed. A
            // running restore is Burst — its cold FS_OPEN is the same
            // tens-of-ms first touch the wal replay path is forgiven for.
            let t0 = dev_micros(sys);
            let slot_wal_rc = if snapshot::boot_restore(&mut s.slots[i].snapshot, sys) {
                wal::step(&mut s.slots[i].wal, sys)
            } else {
                STEP_BURST
            };
            s.comp_step[1].record(dev_micros(sys).wrapping_sub(t0));

            // Drain the wal's seam latches (monotone latest-wins).
            #[cfg(not(feature = "volatile"))]
            {
                let t0 = dev_micros(sys);
                // Voter-set update first, so a quorum recomputed this step
                // is tallied against the configuration that arrived with
                // (or before) the acks driving it.
                // Learners are deliberately dropped here: the durability
                // tally counts voters only, exactly as the commit tally does.
                if let Some((current, joint, joint_active, _learners)) =
                    s.slots[i].wal.voter_out.take()
                {
                    ledger::on_voter_set(&mut s.slots[i].ledger, current, joint, joint_active);
                }
                let local_advanced = if s.slots[i].wal.ledger_dirty {
                    s.slots[i].wal.ledger_dirty = false;
                    let (term, index) = s.slots[i].wal.ledger_ack;
                    ledger::on_ack(&mut s.slots[i].ledger, term, index, s.slots[i].self_id)
                } else {
                    false
                };
                ledger::step(&mut s.slots[i].ledger, sys, local_advanced);
                s.comp_step[2].record(dev_micros(sys).wrapping_sub(t0));
            }
            // The volatile variant has no ledger; still clear the latch so a
            // config change can't leave a stale Some() behind.
            #[cfg(feature = "volatile")]
            {
                let _ = s.slots[i].wal.voter_out.take();
            }

            if s.slots[i].wal.snap_trigger_dirty {
                s.slots[i].wal.snap_trigger_dirty = false;
                let (term, index) = s.slots[i].wal.snap_trigger;
                if snapshot::on_trigger(&mut s.slots[i].snapshot, sys, term, index) {
                    cold_fs = true;
                }
            }
            let t0 = dev_micros(sys);
            // 4b. Deliver the wal high-water: the capture point for a
            //     demand-triggered snapshot (an install request arriving
            //     before any snapshot exists — see snapshot::step 2b).
            let (hw_term, hw_index) = wal::high_water(&s.slots[i].wal);
            snapshot::on_wal_high_water(&mut s.slots[i].snapshot, hw_term, hw_index);
            if snapshot::step(&mut s.slots[i].snapshot, sys) {
                cold_fs = true;
            }
            // Return seam: an accepted peer install fast-forwards the wal's
            // append contract past the subsumed prefix (next step's appends
            // at `last_idx + 1` must be contiguous, not a continuity fault).
            if s.slots[i].snapshot.wal_fast_forward_dirty {
                s.slots[i].snapshot.wal_fast_forward_dirty = false;
                let (ff_term, ff_index) = s.slots[i].snapshot.wal_fast_forward;
                wal::on_snapshot_installed(&mut s.slots[i].wal, ff_term, ff_index);
            }
            s.comp_step[3].record(dev_micros(sys).wrapping_sub(t0));

            // Per-component step accounting (§8 rule 8): publish each
            // component's step-time histogram every second under its own
            // source id (the volatile variant's ledger entry stays zero
            // and is skipped).
            if now.wrapping_sub(s.comp_step_last_ms) >= 1000 {
                s.comp_step_last_ms = now;
                s.comp_step[0].emit(
                    sys,
                    s.slots[i].wal.out_metrics,
                    wire::SOURCE_ID_KEYS,
                    s.slots[i].partition_id,
                );
                s.comp_step[1].emit(
                    sys,
                    s.slots[i].wal.out_metrics,
                    wire::SOURCE_ID_WAL,
                    s.slots[i].partition_id,
                );
                #[cfg(not(feature = "volatile"))]
                s.comp_step[2].emit(
                    sys,
                    s.slots[i].wal.out_metrics,
                    wire::SOURCE_ID_LEDGER,
                    s.slots[i].partition_id,
                );
                s.comp_step[3].emit(
                    sys,
                    s.slots[i].wal.out_metrics,
                    wire::SOURCE_ID_SNAPSHOT,
                    s.slots[i].partition_id,
                );
            }

            if slot_wal_rc == STEP_BURST {
                wal_rc = STEP_BURST;
            }
        }

        // Kernel-ring histogram emit (see `last_ring_tlm_ms`). Zero-cost
        // when no telemetry consumer is subscribed; one hist16 record per
        // hosted slot every 5 s otherwise.
        if dev_telemetry_enabled(sys) && now.wrapping_sub(s.last_ring_tlm_ms) >= 5000 {
            s.last_ring_tlm_ms = now;
            let me = dev_self_index(sys);
            if me >= 0 {
                let t = dev_micros(sys);
                for i in 0..s.active_slots as usize {
                    let src = &s.slots[i].wal.fsync_buckets;
                    let mut b = [0u64; 16];
                    for (k, v) in src.iter().enumerate() {
                        b[k] = *v as u64;
                    }
                    let pid = s.slots[i].partition_id;
                    let dim = if pid < FSYNC_DIM_MAX {
                        pid
                    } else {
                        abi::contracts::telemetry::DIM_OTHER
                    };
                    dev_telemetry_histogram16(sys, -1, me as u16, t, FSYNC_HIST_RING_ID, dim, &b);
                    // Snapshot transfers are rare; skip an all-zero row so a
                    // node that never installed one emits no empty series.
                    let sn = &s.slots[i].snapshot.ring_transfer_buckets;
                    if sn.iter().any(|v| *v != 0) {
                        dev_telemetry_histogram16(
                            sys,
                            -1,
                            me as u16,
                            t,
                            SNAPSHOT_HIST_RING_ID,
                            dim,
                            sn,
                        );
                    }
                }
            }
        }

        if wal_rc == STEP_BURST || cold_fs {
            STEP_BURST
        } else {
            wal_rc
        }
    }
}
