//! Control plane — CP proof source and placement routing.
//!
//! One graph module composed of two source components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`cp`]        — periodic CP proofs, tenant records, capabilities.
//!   - [`placement`] — placement epochs and kpg-keyed epoch events.
//!
//! ## Dispatch table
//!
//! Both components are independent timer-driven sources; the order
//! below is fixed but carries no delivery dependency:
//!
//!   1. `cp`        — refresh-tick proof/tenant/capability emission.
//!      Bound (`cp::step`): ≤1 proof + ≤1 tenant record + ≤1
//!      capability manifest, on the refresh tick only.
//!   2. `placement` — bootstrap routing update + epoch transitions.
//!      Bound (`placement::step`): ≤1 routing update + ≤1 epoch
//!      event.
//!
//! The dispatch table brackets both component steps with `dev_micros`
//! reads and publishes a per-component step-time histogram each
//! second under the component's source id (`step_accounting`,
//! §8 rule 8) on the optional `metrics` port.

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

#[path = "../../common/step_accounting.rs"]
mod step_accounting;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

mod cp;
mod migration;
mod placement;

/// Leader id meaning "no hint yet". Mirrors `gateway/codec.rs`.
const LEADER_UNKNOWN: u8 = 0xFF;

define_params! {
    ModuleState;

    // This node's replica id, compared against the Raft leader hint to
    // decide whether this controller may ACCEPT migration commands.
    // Same `self_id` / `leader_id` pair the gateway uses to answer
    // NOT_LEADER, rather than a second notion of identity.
    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    // How many nodes this cluster has. Used ONLY to refuse a PRG
    // topology that would orphan shards — see `ADMIN_OP_PLACEMENT_TOPOLOGY`.
    // 0 (the default) disables the check, which is the honest behaviour
    // for a graph that has not told the controller its cluster size: it
    // cannot police a number it does not know.
    2, peer_count, u8, 0
        => |s, d, len| { s.peer_count = p_u8(d, len, 0, 0); };

    // Automatic placement policy: keep the PRG topology equal to the
    // cluster size, so adding a node widens the shard space without an
    // operator op. Off by default — a topology change RELEASES per-shard
    // state, and a broker must not start moving data because a config
    // was upgraded under it.
    //
    // This is the whole of W5's "policy" and it deliberately needs no
    // load signal. One PRG per node is the topology that makes the
    // cluster horizontally scalable BY MEMBERSHIP, which is the property
    // being asked for; a load-driven policy would be a different and
    // much larger thing, and inventing one without a load signal to
    // drive it would be guessing.
    3, auto_topology, u8, 0
        => |s, d, len| { s.auto_topology = p_u8(d, len, 0, 0); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    cp: cp::Cp,
    placement: placement::Placement,
    migration: migration::Migration,
    /// Operator migration commands (`MSG_MIGRATION_COMMAND`). The
    /// module's only input; `-1` in graphs that never migrate.
    in_migration: i32,
    /// Committed entries, carrying this controller's own migration
    /// phase records back once durable. `-1` when unwired, which stops
    /// migrations rather than advancing them undurably.
    in_committed: i32,
    /// Scratch for one inbound command.
    msg_buf: [u8; 64],
    /// Scratch for one committed entry: `[term:u64][index:u64][body]`.
    entry_buf: [u8; 128],
    /// Raft leader hints, so only ONE controller accepts migration
    /// commands. Without this every node accepts, and two operators
    /// hitting two nodes start two migrations that each believe
    /// MIG-SERIAL holds.
    in_leader_state: i32,
    /// This node's replica id (param 1).
    self_id: u8,
    /// Believed leader, `LEADER_UNKNOWN` until the first hint.
    leader_id: u8,
    /// Migration commands refused because this node is not the leader.
    migration_cmds_not_leader: u32,
    /// Routing-epoch records proposed by this node.
    epoch_records_proposed: u32,
    /// Tenant quota awaiting a durable record, and when it was last
    /// proposed. `None` means nothing outstanding.
    peer_count: u8,
    auto_topology: u8,
    /// Topologies this controller set itself, rather than being told.
    topology_auto_set: u32,
    /// Topology commands refused for naming more PRGs than there are
    /// nodes to own them.
    topology_refused: u32,
    pending_tenant: Option<(u32, u32)>,
    /// A shard-map override armed by an admin command and awaiting its
    /// record's COMMIT — `(shard_id, prg)`.
    pending_shard_map: Option<(u32, u16)>,
    shard_map_sent_ms: u64,
    shard_map_records_proposed: u32,
    shard_map_records_applied: u32,
    /// Monotone epoch stamped on emitted `MSG_SHARD_MAP_UPDATE` frames.
    /// `partition_router` drops an update whose epoch regresses, so a
    /// replayed record must not reuse an epoch a live update already
    /// used — hence a counter that only ever climbs.
    shard_map_epoch: u64,
    /// The committed overrides, mirrored here so this controller can
    /// answer "who owns this shard" itself — the map is CP state, and a
    /// migration must be refused when its source does not own what it
    /// names. Same capacity as the table every node applies.
    overrides: [ShardOverride; wire::SHARD_MAP_MAX_ENTRIES],
    /// Migrations refused because `source_prg` did not own every shard
    /// in the batch. The fence covers the source alone, so a batch that
    /// straddles PRGs would move most of its shards unfenced.
    migrations_refused_unowned: u32,
    tenant_sent_ms: u64,
    tenant_records_proposed: u32,
    tenant_records_applied: u32,
    /// Routing-epoch records adopted from a peer or from replay. On a
    /// restart this is how the node resumes above the epochs the
    /// cluster already used instead of reissuing them from 1.
    epoch_records_adopted: u32,
    /// out: `MSG_SLOT_ACTIVATE` to consensus (via its `cp_state` seam).
    /// Activations emitted.
    /// Migration whose PROVISIONING activation has already been sent,
    /// so a phase held across many steps emits once rather than every
    /// step. Zero when none.
    /// Migration whose cutover overrides have been emitted, so the
    /// batch goes out once rather than once per step while ACTIVE.
    cutover_migration: u64,
    cutovers: u32,

    /// Optional metrics port; carries only the §8 per-component step
    /// accounting (see the manifest's observability note).
    out_metrics: i32,
    /// Per-component step-time histograms (§8 rule 8), owned by the
    /// dispatch table: [cp, placement].
    comp_step: [step_accounting::CompStepHist; 2],
    comp_step_last_ms: u64,
}

/// Leader hint (`[leader_id:u8]`), the input to the controller-
/// ownership gate.
///
/// # Safety
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_leader_state(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_leader_state < 0 {
        return;
    }
    for _ in 0..4 {
        let Some((msg_type, plen)) =
            wire_channels::next_msg(sys, s.in_leader_state, &mut s.msg_buf)
        else {
            break;
        };
        if msg_type != wire::MSG_LEADER_HINT || (plen as usize) < 1 {
            continue;
        }
        s.leader_id = s.msg_buf[0];
    }
}

/// Watch committed entries for migration phase records.
///
/// Two jobs. For a record of the migration this controller holds, the
/// match clears `record_pending` — the ONLY thing that lets that
/// phase's work begin (MIG-DURABLE). For a record of a migration it
/// does NOT hold, which on WAL replay is an interrupted migration
/// coming back, the record is adopted so the controller resumes from
/// the phase the log last recorded.
///
/// Entry shape: `[term:u64][index:u64][body...]`. Bodies that are not
/// migration records — every other proposal in the cluster — are
/// skipped by the magic check.
///
/// # Safety
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
/// Retry interval for a tenant-quota record proposed but not yet
/// committed. Same reasoning and value as `migration::RECORD_RETRY_MS`.
const TENANT_RECORD_RETRY_MS: u64 = 500;
/// Retry interval for a shard-map record proposed but not yet committed.
const SHARD_MAP_RECORD_RETRY_MS: u64 = 500;

/// Publish one applied shard-map override to `partition_router`.
///
/// Best-effort: the record is already durable, so a dropped frame costs
/// only that this node routes on the baseline until the next update or
/// a restart replays the log. Blocking the apply loop on a full channel
/// would stall every other record class behind it.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
/// Propose one control-plane record, KEYED to `wire::CP_RECORD_SHARD` so
/// it lands on partition 0, the distinguished CP-Raft group.
///
/// One helper rather than a prefix hand-written at each of the four
/// record sites: a private copy of a wire layout per call site is how
/// the committed-entry header came to have six of them and drift.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn propose_cp_record(sys: &SyscallTable, chan: i32, body: &[u8]) -> bool {
    if chan < 0 {
        return false;
    }
    let mut keyed = [0u8; wire::KEYED_PROPOSAL_HDR + 64];
    let n = wire::encode_keyed_proposal(&mut keyed, wire::CP_RECORD_SHARD, body);
    if n <= 0 {
        return false;
    }
    wire_channels::channel_write_msg(
        sys,
        chan,
        wire::MSG_CLIENT_PROPOSAL_KEYED,
        &keyed[..n as usize],
    ) > 0
}

/// One committed shard-map override, mirrored from the `SM` record.
#[derive(Clone, Copy)]
#[repr(C)]
struct ShardOverride {
    shard: u32,
    prg: u16,
    active: bool,
}

impl ShardOverride {
    const fn empty() -> Self {
        Self {
            shard: 0,
            prg: 0,
            active: false,
        }
    }
}

/// Apply one committed override to the mirror. `SHARD_OVERRIDE_CLEAR`
/// removes it. A full mirror drops the entry: the router refuses the
/// same overflow and counts it, and a controller that believes an
/// override the routers could not hold would refuse migrations on a
/// map nobody routes by.
fn mirror_override(s: &mut ModuleState, shard: u32, prg: u16) {
    if let Some(e) = s.overrides.iter_mut().find(|e| e.active && e.shard == shard) {
        if prg == wire::SHARD_OVERRIDE_CLEAR {
            e.active = false;
        } else {
            e.prg = prg;
        }
        return;
    }
    if prg == wire::SHARD_OVERRIDE_CLEAR {
        return;
    }
    if let Some(e) = s.overrides.iter_mut().find(|e| !e.active) {
        *e = ShardOverride {
            shard,
            prg,
            active: true,
        };
    }
}

/// The PRG that owns `shard` under the committed map: the override if
/// one exists, otherwise the baseline over the topology in force.
fn owner_prg(s: &ModuleState, shard: u32) -> u16 {
    if let Some(e) = s.overrides.iter().find(|e| e.active && e.shard == shard) {
        return e.prg;
    }
    wire::baseline_prg(shard, placement::prg_count(&s.placement))
}

/// Publish one shard's owning PRG on the ROUTING stream.
///
/// The same channel the placement update goes out on, not a separate
/// edge, because the two answer one question between them — "who owns
/// this shard?" — and on separate edges they can arrive out of order,
/// leaving a node resolving ownership against a new `prg_count` and a
/// stale override set. One channel gives one order.
///
/// The map names a PRG, never a raft partition: those are different
/// namespaces: `prg_count` comes from the node count while
/// `num_partitions` is a graph parameter, and treating one as the other
/// sends a shard's writes to a group holding none of its history.
unsafe fn emit_shard_map(s: &mut ModuleState, sys: &SyscallTable, shard: u32, prg: u16) {
    let out = s.placement.out_routing;
    if out < 0 || !wire_channels::writable(sys, out) {
        return;
    }
    let mut buf = [0u8; wire::SHARD_MAP_HDR + wire::SHARD_MAP_ENTRY];
    // One entry per frame: overrides arrive one admin command at a
    // time, and batching would only matter for a bulk load the record
    // class does not yet express.
    // Through the shared encoders, not hand-written offsets: a private
    // copy of a wire layout is how the committed-entry header came to
    // have six of them and drift.
    wire::encode_shard_map_header(&mut buf, s.shard_map_epoch, 1);
    wire::encode_shard_map_entry(&mut buf[wire::SHARD_MAP_HDR..], shard, prg);
    wire_channels::channel_write_msg(sys, out, wire::MSG_SHARD_MAP_UPDATE, &buf);
}

unsafe fn drain_committed_records(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.in_committed < 0 {
        return;
    }
    // `entry_buf` is deliberately small: the only entry this module
    // cares about is a 49-byte migration record (16-byte term/index
    // header + 2 magic + 31). Every OTHER committed entry in the
    // cluster arrives here too — Kafka batches run to ~1900 bytes — and
    // `channel_read_msg` drains and discards anything that does not
    // fit. Discarding is correct here: those entries are delivered to
    // their real consumer over its own edge, and sizing this buffer to
    // the largest possible entry would cost per-instance state for
    // bytes this module would immediately ignore.
    //
    // `continue`, NOT `break`: `next_msg` collapses "channel empty" and
    // "oversize, discarded" onto the same `None`. Breaking on it would
    // stop the drain at the first large entry, so under Kafka load this
    // module would consume one entry per step and a migration record
    // sitting behind a burst of batches would be delayed by as many
    // steps as there were batches. The loop is bounded, so treating the
    // empty case as `continue` costs at most a few cheap `readable`
    // checks.
    for _ in 0..8 {
        let Some((_msg_type, plen)) =
            wire_channels::next_msg(sys, s.in_committed, &mut s.entry_buf)
        else {
            continue;
        };
        let pl = plen as usize;
        // MSG_COMMITTED_ENTRY now leads with the partition id
        // (`wire::COMMITTED_ENTRY_HDR`); the control plane does not need
        // it — its records are self-identifying by magic and it keeps no
        // per-partition apply cursor — but the body offset moved.
        if pl <= wire::COMMITTED_ENTRY_HDR {
            continue;
        }
        let body = &s.entry_buf[wire::COMMITTED_ENTRY_HDR..pl];
        if wire::is_epoch_record(body) {
            let epoch = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
            if placement::adopt_epoch(&mut s.placement, epoch) {
                s.epoch_records_adopted = s.epoch_records_adopted.wrapping_add(1);
                // Only alongside an epoch that was itself adopted, so
                // the divisor and the epoch naming it are never
                // separated. The tail is optional: a 6-byte record from
                // a controller that only advanced the epoch leaves the
                // topology alone.
                if body.len() >= wire::EPOCH_RECORD_LEN_PERM {
                    let prg_count = u16::from_le_bytes([body[6], body[7]]);
                    placement::adopt_topology(
                        &mut s.placement,
                        prg_count,
                        Some(&body[8..wire::EPOCH_RECORD_LEN_PERM]),
                    );
                } else if body.len() >= wire::EPOCH_RECORD_LEN_TOPO {
                    let prg_count = u16::from_le_bytes([body[6], body[7]]);
                    placement::adopt_prg_count(&mut s.placement, prg_count);
                }
            }
            // Settles this node's own pending record when the epoch it
            // proposed comes back committed, and equally settles it
            // against a PEER's record for the same or a higher epoch:
            // the point of the record is that SOME node put the epoch in
            // the log, and one copy of it is enough.
            placement::note_epoch_recorded(&mut s.placement, epoch);
            continue;
        }
        if wire::is_tenant_record(body) {
            let tenant_id = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
            let max_rate = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
            cp::set_tenant_quota(&mut s.cp, tenant_id, max_rate);
            // One line per applied quota. A quota that is recorded but
            // never APPLIED is indistinguishable from a working one by
            // looking at the log alone, and the whole point is that
            // `governance` starts enforcing the new rate. Quota changes
            // are operator actions, so this is not a hot path.
            dev_log(sys, 3, b"[cp] tenant quota".as_ptr(), 17);
            s.tenant_records_applied = s.tenant_records_applied.wrapping_add(1);
            // Settles this controller's own pending record when it
            // comes back, and equally a PEER's for the same tenant and
            // rate: one copy in the log is enough.
            if s.pending_tenant == Some((tenant_id, max_rate)) {
                // ONLY the pending-record state. An earlier edit leaked
                // two lines of `module_new`'s counter initialisation in
                // here (the stray indentation was the tell), so every
                // committed quota silently reset `topology_refused` and
                // `topology_auto_set` — both metrics, so an operator
                // watching them saw them fall to zero whenever anyone
                // set a quota.
                s.pending_tenant = None;
                s.tenant_sent_ms = 0;
            }
            continue;
        }
        if wire::is_shard_map_record(body) {
            if let Some((shard, prg)) = wire::decode_shard_map_record(body) {
                // Every node applies it, leader or not: the override is
                // a ROUTING fact and a follower routes too.
                s.shard_map_epoch = s.shard_map_epoch.saturating_add(1);
                mirror_override(s, shard, prg);
                emit_shard_map(s, sys, shard, prg);
                dev_log(sys, 3, b"[cp] shard map".as_ptr(), 14);
                s.shard_map_records_applied = s.shard_map_records_applied.wrapping_add(1);
                if s.pending_shard_map == Some((shard, prg)) {
                    s.pending_shard_map = None;
                    s.shard_map_sent_ms = 0;
                }
            }
            continue;
        }
        migration::on_committed(&mut s.migration, now, body);
    }
}

/// Apply operator migration commands to the state machine.
///
/// Body: `[op_code:u8][op_body...]`, the admin op codes forwarded
/// verbatim by `operations/admin.rs`. Each call is bounded to a few
/// commands per step so a burst cannot starve the rest of the module.
///
/// Refusals are silent here by design: `migration` already counts
/// illegal transitions and refused aborts, and the admin surface has
/// answered the operator. MIG-SERIAL means a BEGIN while one is active
/// simply loses — which is the rule, not an error to report twice.
///
/// # Safety
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_migration_commands(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.in_migration < 0 {
        return;
    }
    // Controller ownership. Only the Raft leader may DRIVE a migration;
    // every node still ADOPTS the committed records, which is how the
    // fence reaches all of them. Refusing while the leader is unknown
    // is deliberate: accepting then would let a node that has just lost
    // (or not yet learned of) leadership start a second migration, and
    // MIG-SERIAL is only enforceable within one controller.
    if s.in_leader_state >= 0 && (s.leader_id == LEADER_UNKNOWN || s.leader_id != s.self_id) {
        // Drain and discard, so a non-leader does not accumulate
        // commands it will never run and then act on stale ones the
        // moment it is elected.
        for _ in 0..4 {
            if wire_channels::next_msg(sys, s.in_migration, &mut s.msg_buf).is_none() {
                break;
            }
            s.migration_cmds_not_leader = s.migration_cmds_not_leader.wrapping_add(1);
        }
        return;
    }
    for _ in 0..4 {
        let Some((msg_type, plen)) = wire_channels::next_msg(sys, s.in_migration, &mut s.msg_buf)
        else {
            break;
        };
        if msg_type != wire::MSG_MIGRATION_COMMAND || plen == 0 {
            continue;
        }
        let pl = plen as usize;
        let op = s.msg_buf[0];
        let body = &s.msg_buf[1..pl];
        match op {
            wire::ADMIN_OP_MIGRATE_BEGIN => {
                if body.len() < wire::MIGRATE_BEGIN_BODY_LEN {
                    continue;
                }
                let migration_id = u64::from_le_bytes([
                    body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
                ]);
                let source_prg = u16::from_le_bytes([body[8], body[9]]);
                let target_prg = u16::from_le_bytes([body[10], body[11]]);
                let shard_count = u16::from_le_bytes([body[12], body[13]]);
                let base_shard =
                    u32::from_le_bytes([body[14], body[15], body[16], body[17]]);
                // The fence covers `source_prg` alone, so every shard in
                // the batch must be its. A batch that straddles PRGs
                // would hand most of itself over unfenced — split
                // ownership for exactly the window the fence exists to
                // close.
                let mut owned = true;
                let mut k = 0u16;
                while k < shard_count {
                    if owner_prg(s, base_shard.wrapping_add(u32::from(k))) != source_prg {
                        owned = false;
                        break;
                    }
                    k += 1;
                }
                if !owned {
                    s.migrations_refused_unowned = s.migrations_refused_unowned.wrapping_add(1);
                    dev_log(sys, 3, b"[cp] batch unowned".as_ptr(), 18);
                    continue;
                }
                // The target must exist under the topology in force —
                // the same rule the topology command enforces: a PRG
                // with no node behind it makes every shard moved to it
                // unreachable. A cluster with no stated topology has
                // exactly one PRG.
                let in_force = placement::prg_count(&s.placement).max(1);
                if target_prg >= in_force {
                    s.migrations_refused_unowned = s.migrations_refused_unowned.wrapping_add(1);
                    dev_log(sys, 3, b"[cp] target orphan".as_ptr(), 18);
                    continue;
                }
                // The epoch the migration is recorded against is the one
                // placement is publishing now; the fence and the cutover
                // each advance it from there.
                let epoch = placement::epoch(&s.placement) as u64;
                migration::begin(
                    &mut s.migration,
                    now,
                    migration_id,
                    source_prg,
                    target_prg,
                    epoch,
                    shard_count,
                    base_shard,
                );
            }
            wire::ADMIN_OP_TENANT_QUOTA => {
                if body.len() < wire::TENANT_QUOTA_BODY_LEN {
                    continue;
                }
                let tenant_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                let max_rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
                // Armed, NOT applied here. The quota takes effect when
                // its record COMMITS, exactly like a migration phase:
                // applying on the command would let a leader that loses
                // the election before the record commits enforce a
                // quota no other node has, and a restart would silently
                // revert it.
                s.pending_tenant = Some((tenant_id, max_rate));
                s.tenant_sent_ms = 0;
            }
            wire::ADMIN_OP_SHARD_MAP => {
                if body.len() < wire::SHARD_MAP_BODY_LEN {
                    continue;
                }
                let shard = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                let prg = u16::from_le_bytes([body[4], body[5]]);
                // Armed, not applied — same reason as the quota above.
                // Routing on a map that no other node has is worse than
                // a quota that no other node has: two nodes would
                // disagree about who owns a shard.
                s.pending_shard_map = Some((shard, prg));
                s.shard_map_sent_ms = 0;
            }
            wire::ADMIN_OP_PLACEMENT_TOPOLOGY => {
                if body.len() < wire::PLACEMENT_TOPOLOGY_BODY_LEN {
                    continue;
                }
                let prg_count = u16::from_le_bytes([body[0], body[1]]);
                // Refuse a topology that would orphan shards.
                //
                // `local_prg` is `self_id % prg_count`, so with N nodes
                // and `prg_count > N` the PRGs from N upward have NO
                // node claiming them. Every node then finds those
                // shards foreign and releases their state, and since no
                // node owns them the data becomes unreachable — sessions
                // dropped, retained values gone, and clients redirected
                // to a broker that does not exist.
                //
                // The binding constraint is a NODE per PRG, not a raft
                // group per PRG. While every PRG shares one group, all
                // nodes hold all the data, and serving a subset of
                // shards from each is perfectly safe — so `prg_count`
                // above the number of activated groups is harmless,
                // while `prg_count` above the node count is not.
                if s.peer_count > 0 && prg_count as u32 > s.peer_count as u32 {
                    s.topology_refused = s.topology_refused.wrapping_add(1);
                    dev_log(sys, 3, b"[cp] topology refused".as_ptr(), 21);
                    continue;
                }
                // Optional tail: which node serves each PRG, one byte
                // per PRG. Refused unless it is a permutation of
                // existing nodes — two nodes for one PRG is split
                // ownership, a missing node is an orphaned PRG.
                let perm = &body[wire::PLACEMENT_TOPOLOGY_BODY_LEN..];
                let perm = if perm.is_empty() {
                    None
                } else if placement::perm_is_valid(perm, prg_count, s.peer_count) {
                    Some(perm)
                } else {
                    s.topology_refused = s.topology_refused.wrapping_add(1);
                    dev_log(sys, 3, b"[cp] topology refused".as_ptr(), 21);
                    continue;
                };
                // Advances the epoch and arms the durable record, so
                // the topology reaches every node the same way the
                // epoch does and survives a restart. A topology that
                // lived only in the node that was told about it would
                // have each node resolving shard owners with a
                // different divisor — two owners for one shard, which
                // is the failure the whole placement chain exists to
                // prevent.
                placement::set_topology(&mut s.placement, prg_count, perm);
            }
            wire::ADMIN_OP_MIGRATE_PHASE_DONE => {
                if body.is_empty() {
                    continue;
                }
                // Leaving FENCED is the cutover. No explicit epoch bump
                // is needed: the fence mirror below sees the phase has
                // moved on, calls `set_fence(.., false)`, and that lift
                // carries its own epoch advance. Bumping here as well
                // would publish two updates for one transition.
                migration::phase_complete(&mut s.migration, now, body[0]);
            }
            wire::ADMIN_OP_MIGRATE_ABORT => {
                migration::abort(&mut s.migration, now);
            }
            _ => {}
        }
    }
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
    _in_chan: i32,
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

        cp::init(&mut s.cp);
        placement::init(&mut s.placement);
        migration::init(&mut s.migration);

        s.cp.out_proof = out_chan; // out[0] proof
                                   // Input 0: operator migration commands. The module's only
                                   // input; unwired in graphs that never migrate.
        s.in_migration = dev_channel_port(sys, 0, 0);
        // Input 1: committed entries, for migration-record durability.
        s.in_committed = dev_channel_port(sys, 0, 1);
        // Input 2: Raft leader hints, for the controller-ownership gate.
        s.in_leader_state = dev_channel_port(sys, 0, 2);
        // No hint yet. Until one arrives this controller refuses
        // migration commands rather than assume it is the leader.
        s.leader_id = LEADER_UNKNOWN;
        s.migration_cmds_not_leader = 0;
        s.epoch_records_proposed = 0;
        s.topology_refused = 0;
        s.topology_auto_set = 0;
        s.pending_tenant = None;
        s.tenant_sent_ms = 0;
        s.pending_shard_map = None;
        s.shard_map_sent_ms = 0;
        s.shard_map_records_proposed = 0;
        s.shard_map_records_applied = 0;
        s.overrides = [ShardOverride::empty(); wire::SHARD_MAP_MAX_ENTRIES];
        s.migrations_refused_unowned = 0;
        s.shard_map_epoch = 0;
        s.tenant_records_proposed = 0;
        s.tenant_records_applied = 0;
        s.epoch_records_adopted = 0;

        // Params. Without this the module's `define_params!` schema is
        // published in the .fmod but never applied, so a graph setting
        // `self_id` would be silently ignored and every node would
        // believe it is replica 0.
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // After `parse_tlv`, so the configured replica id is the one
        // `local_prg` derives from rather than the default 0.
        placement::set_self_id(&mut s.placement, s.self_id as u16);
        s.cp.out_tenant_records = dev_channel_port(sys, 1, 1);
        s.cp.out_capabilities = dev_channel_port(sys, 1, 2);
        s.placement.out_routing = dev_channel_port(sys, 1, 3);
        s.placement.out_epoch_events = dev_channel_port(sys, 1, 4);
        s.out_metrics = dev_channel_port(sys, 1, 5);
        // Index 6: `migration_record`, declared last in the manifest so
        // no existing output index shifted. Left at -1 when unwired,
        // which stops migrations rather than running them undurably.
        s.migration.out_record = dev_channel_port(sys, 1, 6);
        // Output 7, `slot_activate`, is declared last in the manifest and
        // unused while a PRG is not a raft group (see PROVISIONING below).
        s.comp_step = [step_accounting::CompStepHist::new(); 2];
        s.comp_step_last_ms = 0;

        dev_log(sys, 3, b"[cp] init".as_ptr(), 9);
        dev_log(sys, 3, b"[plac] init".as_ptr(), 11);
        0
    }
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

        let mut t0 = dev_micros(sys);
        cp::step(&mut s.cp, sys, now);
        let t1 = dev_micros(sys);
        s.comp_step[0].record(t1.wrapping_sub(t0));
        t0 = t1;
        // Operator migration commands. Drained BEFORE the fence is
        // mirrored so a command accepted this tick reaches the wire on
        // this tick rather than the next.
        drain_leader_state(s, sys);
        drain_migration_commands(s, sys, dev_millis(sys));
        drain_committed_records(s, sys, dev_millis(sys));

        // PROVISIONING work: bring up the target group. This is driven by
        // the PHASE, not by the operator command, so every node that adopts
        // the committed record does its own provisioning — the Raft log is
        // what carries the decision cluster-wide, exactly as it does for the
        // fence. PROVISIONING has nothing to bring up while a PRG is not a
        // raft group: the partitions an engine hosts are a graph parameter,
        // and `target_prg` is a PRG id, not a partition. Activating it as
        // one would raise a spurious group on every node whenever
        // `target_prg >= num_partitions`. The phase keeps its place in the
        // sequence for its durable record, and acquires work in a topology
        // where a PRG is its own raft group.

        // COPYING and CATCHING_UP carry no work, so nothing external has
        // anything to report and waiting for a `phase-done` command would
        // stall the migration on an operator poke for a step that has
        // already happened. The shard map moves OWNERSHIP: the shard's
        // entries stay in their raft partition, and every node already
        // applies that partition, so there is nothing to copy and nothing
        // to catch up on. They remain in the sequence because the durable
        // record of a transfer is the audit trail, and skipping the phases
        // would leave a log that cannot be replayed into the state machine
        // that wrote it.
        //
        // Gated on the record being durable, exactly as PROVISIONING
        // is: a phase may not be left until its own record commits
        // (MIG-DURABLE).
        if migration::is_active(&s.migration) && !migration::record_pending(&s.migration) {
            let ph = migration::phase(&s.migration);
            if ph == wire::MIG_COPYING || ph == wire::MIG_CATCHING_UP {
                migration::phase_complete(&mut s.migration, now, ph);
            }
        }

        // CUTOVER. Leaving FENCED is where the shards actually change
        // hands, so it is where the overrides go out — before this, the
        // source still serves them; after it, the target does.
        //
        // Emitted on EVERY node from the committed phase, not by the
        // node that ran the command: an override held only where the
        // command landed would have one node routing to the new owner
        // while the rest still resolved the old one.
        if migration::is_active(&s.migration)
            && migration::phase(&s.migration) == wire::MIG_ACTIVE
            && !migration::record_pending(&s.migration)
            && s.cutover_migration != migration::id(&s.migration)
        {
            let base = migration::base_shard(&s.migration);
            let count = migration::shard_count(&s.migration);
            let target = migration::target_prg(&s.migration);
            let mut sent = 0u16;
            while sent < count {
                let shard = base.wrapping_add(sent as u32);
                emit_shard_map(s, sys, shard, target);
                sent += 1;
            }
            // Latched on the migration id so the batch goes out once
            // per migration rather than once per step while ACTIVE.
            s.cutover_migration = migration::id(&s.migration);
            s.cutovers = s.cutovers.wrapping_add(1);
        }

        // Mirror the migration phase onto the placement fence
        // (EDGE-FENCE). The fence stands for exactly the FENCED phase:
        // the source PRG has stopped accepting and the target has not
        // started, so listeners refuse traffic for that PRG at both
        // ends rather than let two groups own it at once. Every other
        // phase — including the terminal ones — lifts it, so an abort
        // or a crash-resume can never leave a fence standing with no
        // migration behind it.
        //
        // Done BEFORE placement::step so the phase entered on this tick
        // reaches the wire on this tick; a fence that lags its phase by
        // a step is a window in which ownership is split.
        let fenced = migration::is_active(&s.migration)
            && migration::phase(&s.migration) == wire::MIG_FENCED;
        placement::set_fence(
            &mut s.placement,
            migration::source_prg(&s.migration),
            fenced,
        );

        // Record a locally-advanced routing epoch, so it survives this
        // node restarting and so peers converge on the highest one.
        // Rides the same durable path as the migration record.
        if placement::epoch_record_pending(&s.placement)
            && placement::epoch_record_due(&s.placement, now)
            && s.migration.out_record >= 0
            && wire_channels::writable(sys, s.migration.out_record)
        {
            // `[RE][epoch:u32][prg_count:u16]` — the topology rides the
            // epoch record because a topology change IS an epoch
            // change. Split across two records they could commit in
            // either order, leaving a window where the epoch says "new
            // placement" while the divisor is still the old one, and
            // every node resolves owners wrongly for exactly that
            // window.
            let mut body = [0u8; wire::EPOCH_RECORD_LEN_PERM];
            body[..2].copy_from_slice(&wire::EPOCH_CMD_MAGIC);
            body[2..6].copy_from_slice(&placement::epoch(&s.placement).to_le_bytes());
            body[6..8].copy_from_slice(&placement::prg_count(&s.placement).to_le_bytes());
            body[8..wire::EPOCH_RECORD_LEN_PERM]
                .copy_from_slice(placement::node_for_prg(&s.placement));
            if propose_cp_record(sys, s.migration.out_record, &body) {
                placement::note_epoch_record_sent(&mut s.placement, now);
                s.epoch_records_proposed = s.epoch_records_proposed.wrapping_add(1);
            }
        }

        // Tenant-quota record. Same lifecycle as the epoch record: the
        // write only arms a retry, the COMMIT clears the pending slot.
        // Clearing on the write would lose the quota outright when a
        // proposal is dropped by a leader change.
        if let Some((tenant_id, max_rate)) = s.pending_tenant {
            let due = s.tenant_sent_ms == 0
                || now.wrapping_sub(s.tenant_sent_ms) >= TENANT_RECORD_RETRY_MS;
            if due && s.migration.out_record >= 0 && wire_channels::writable(sys, s.migration.out_record)
            {
                let mut body = [0u8; wire::TENANT_RECORD_LEN];
                body[..2].copy_from_slice(&wire::TENANT_CMD_MAGIC);
                body[2..6].copy_from_slice(&tenant_id.to_le_bytes());
                body[6..10].copy_from_slice(&max_rate.to_le_bytes());
                if propose_cp_record(sys, s.migration.out_record, &body) {
                    s.tenant_sent_ms = if now == 0 { 1 } else { now };
                    s.tenant_records_proposed = s.tenant_records_proposed.wrapping_add(1);
                }
            }
        }

        // Shard-map record. Same lifecycle as the quota and the epoch:
        // the write only arms a retry, the COMMIT clears the slot.
        if let Some((shard, prg)) = s.pending_shard_map {
            let due = s.shard_map_sent_ms == 0
                || now.wrapping_sub(s.shard_map_sent_ms) >= SHARD_MAP_RECORD_RETRY_MS;
            if due
                && s.migration.out_record >= 0
                && wire_channels::writable(sys, s.migration.out_record)
            {
                let mut body = [0u8; wire::SHARD_MAP_RECORD_LEN];
                let n = wire::encode_shard_map_record(&mut body, shard, prg);
                if n > 0 && propose_cp_record(sys, s.migration.out_record, &body[..n]) {
                    s.shard_map_sent_ms = if now == 0 { 1 } else { now };
                    s.shard_map_records_proposed =
                        s.shard_map_records_proposed.wrapping_add(1);
                }
            }
        }

        // W5 policy: one PRG per node. Runs only on the LEADER — the
        // ownership gate above already refuses operator commands
        // elsewhere, and a topology proposed by three controllers at
        // once is three epoch bumps for one change.
        //
        // Proposed only when it DIFFERS, so this is a no-op in the
        // steady state rather than a per-step re-proposal.
        if s.auto_topology != 0
            && s.peer_count > 0
            && s.leader_id != LEADER_UNKNOWN
            && s.leader_id == s.self_id
        {
            let want = s.peer_count as u16;
            if placement::prg_count(&s.placement) != want {
                if placement::set_prg_count(&mut s.placement, want) {
                    s.topology_auto_set = s.topology_auto_set.wrapping_add(1);
                    dev_log(sys, 3, b"[cp] topology auto".as_ptr(), 18);
                }
            }
        }

        placement::step(&mut s.placement, sys);

        // 3. `migration` — the state machine's deadline check and
        //    its one durable record emit per step. Ordered after
        //    placement so a phase that changes placement is recorded
        //    against the epoch placement just published.
        migration::step(&mut s.migration, sys, dev_millis(sys));
        s.comp_step[1].record(dev_micros(sys).wrapping_sub(t0));

        // Per-component step accounting (§8 rule 8): publish each
        // component's step-time histogram every second under its own
        // source id (no-op when the metrics port is unwired).
        if now.wrapping_sub(s.comp_step_last_ms) >= 1000 {
            s.comp_step_last_ms = now;
            s.comp_step[0].emit(sys, s.out_metrics, wire::SOURCE_ID_CP, 0);
            s.comp_step[1].emit(sys, s.out_metrics, wire::SOURCE_ID_PLACEMENT, 0);
        }
        0
    }
}
