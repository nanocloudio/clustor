//! placement — epoch-based routing updates.
//!
//! Maintains the current placement epoch and emits
//! `MSG_PLACEMENT_UPDATE` (`routing`) when the epoch changes (driven
//! by admin operations or CP refresh).
//!
//! Also emits `MSG_PLACEMENT_EPOCH_EVENT` (`epoch_events`) per kpg so
//! that downstream session-bearing consumers (lattice's
//! `watch_registry`, `lease_manager`, `kv_state_worker`; future
//! siblings) can advance their per-session `session_epoch` atomically
//! with the placement change and fence stale frames in flight on
//! rebind. Optional — graphs that don't need session fencing leave
//! the port unwired.
//!
//! Wire shape of the kpg-keyed epoch event (7 bytes):
//!   `[kpg_id:u16 LE][new_epoch:u32 LE][reason:u8]`
//!
//! Single-kpg deployments today carry `kpg_id = 0` only at the
//! bootstrap emission. Sustained per-kpg tracking arrives with the
//! multi-kpg admin path; the wire shape is already fixed for that
//! future. `reason` (one of):
//!   0 = bootstrap, 1 = admin (reserved), 2 = rebalance (reserved).
//!
//! The kpg-keyed contract is `MSG_PLACEMENT_EPOCH_EVENT (0xD5)`,
//! declared in `modules/common/wire.rs`. It is deliberately NOT 0xD4:
//! that id carries a global-epoch transition, a different shape, and
//! the two must not be conflated by a consumer that sees both.

use super::abi::SyscallTable;
use super::{wire, wire_channels};

/// Reason byte values for `MSG_PLACEMENT_EPOCH_EVENT`. The emission
/// path selects `BOOTSTRAP` on the initial placement epoch and
/// `ADMIN` on any subsequent transition. `REBALANCE` is wire-
/// reserved for when the rebalance scheduler lands and needs to
/// distinguish substrate-driven moves from operator-driven ones.
const EPOCH_REASON_BOOTSTRAP: u8 = 0;
const EPOCH_REASON_ADMIN: u8 = 1;
#[allow(
    dead_code,
    reason = "wire-reserved; emitted when rebalance scheduler lands"
)]
const EPOCH_REASON_REBALANCE: u8 = 2;

/// Default kpg_id for the single-kpg deployment. Downstream
/// consumers that haven't migrated to per-kpg session tracking yet
/// treat any non-zero new_epoch as the global epoch.
const DEFAULT_KPG_ID: u16 = 0;

/// `local_prg` sentinel meaning "not asserting a placement". This
/// component tracks the epoch and the fence, not which PRG a given
/// listener belongs to, so it must not claim one — a literal 0 here
/// would reassign every listener to PRG 0.
const PLACEMENT_UNCHANGED: u16 = u16::MAX;

/// `prg_count` sentinel with the same meaning.
const PRG_COUNT_UNCHANGED: u16 = 0;

#[repr(C)]
pub struct Placement {
    pub out_routing: i32,      // out: PlacementUpdate
    pub out_epoch_events: i32, // out: kpg-keyed MSG_PLACEMENT_EPOCH_EVENT for session fencing
    current_epoch: u32,
    prev_epoch: u32,
    emitted: bool,
    /// PRG whose shards are mid-transfer, and whether that fence is
    /// live. Mirrored from the migration state machine (EDGE-FENCE):
    /// while it stands, listeners refuse traffic for that PRG at BOTH
    /// ends of the move rather than let two groups own it at once.
    fenced_prg: u16,
    fenced_active: bool,
    /// Set when the fence or the epoch changed and the update has not
    /// yet gone out. The emission is what makes a fence real, so this
    /// is retried every step until the channel accepts it.
    update_pending: bool,
    /// Set when the epoch advanced on THIS node and the record has not
    /// been proposed yet.
    epoch_record_pending: bool,
    /// Highest epoch this node has seen COMMITTED as a routing record.
    /// A max, like the epoch itself, so a replayed record cannot lower
    /// it.
    epoch_recorded: u32,
    /// Wall clock of the last epoch-record proposal, or 0 when none is
    /// outstanding. Mirrors `migration::record_sent_ms`: the pending
    /// flag clears only on COMMIT, so the retry needs an interval or it
    /// fires every tick.
    epoch_sent_ms: u64,
    /// The divisor mapping a virtual shard to its owning PRG.
    /// `PRG_COUNT_UNCHANGED` (0) until an operator sets one, which the
    /// wire treats as "leave it alone" so a controller that owns only
    /// the epoch and the fence says nothing about topology.
    prg_count: u16,
    /// This node's PRG, derived from its replica id through
    /// `node_for_prg`. Derived rather than configured so a topology
    /// change is one cluster-wide record instead of a per-node edit
    /// that could disagree between nodes and leave a shard owned twice.
    local_prg: u16,
    /// Which node serves each PRG: a permutation of `0..prg_count`,
    /// identity until a record states otherwise. This is what a
    /// whole-PRG move changes — one entry, one record, the PRG fence
    /// already the right unit — so no per-shard map is ever needed for
    /// it. A node the permutation does not name falls back to
    /// `self_id % prg_count`, which is the identity behaviour for a
    /// cluster with more nodes than PRGs.
    node_for_prg: [u8; wire::PERM_NODES],
    /// Replica id, for that derivation.
    self_id: u16,
}

/// Retry interval for an epoch record that has been proposed but has
/// not come back committed. Same reasoning as
/// `migration::RECORD_RETRY_MS`.
const EPOCH_RECORD_RETRY_MS: u64 = 500;

pub unsafe fn init(p: &mut Placement) {
    p.out_routing = -1;
    p.out_epoch_events = -1;
    p.current_epoch = 1;
    p.prev_epoch = 0;
    p.emitted = false;
    p.fenced_prg = 0;
    p.fenced_active = false;
    p.update_pending = false;
    p.epoch_record_pending = false;
    p.epoch_recorded = 0;
    p.epoch_sent_ms = 0;
    p.prg_count = PRG_COUNT_UNCHANGED;
    p.local_prg = PLACEMENT_UNCHANGED;
    p.node_for_prg = identity_perm();
    p.self_id = 0;
}

/// The permutation that names node `i` for PRG `i`.
pub const fn identity_perm() -> [u8; wire::PERM_NODES] {
    let mut perm = [0u8; wire::PERM_NODES];
    let mut i = 0;
    while i < wire::PERM_NODES {
        perm[i] = i as u8;
        i += 1;
    }
    perm
}

/// True when `perm[..prg_count]` is a permutation of distinct node ids,
/// each below `peer_count` (any id when `peer_count` is 0, i.e. not
/// stated). A malformed permutation would name two nodes for one PRG or
/// a node that does not exist — split ownership, or none.
pub fn perm_is_valid(perm: &[u8], prg_count: u16, peer_count: u8) -> bool {
    let n = prg_count as usize;
    if n > wire::PERM_NODES || perm.len() < n {
        return false;
    }
    let mut seen = 0u8;
    for &node in &perm[..n] {
        if node as usize >= wire::PERM_NODES || (peer_count > 0 && node >= peer_count) {
            return false;
        }
        if seen & (1 << node) != 0 {
            return false;
        }
        seen |= 1 << node;
    }
    true
}

/// Tell placement which replica this is, so `local_prg` can be derived.
pub fn set_self_id(p: &mut Placement, self_id: u16) {
    p.self_id = self_id;
    recompute_local_prg(p);
}

fn recompute_local_prg(p: &mut Placement) {
    p.local_prg = if p.prg_count == PRG_COUNT_UNCHANGED {
        // No topology stated: assert none. `PLACEMENT_UNCHANGED` is the
        // wire's "I am not claiming a placement", which leaves every
        // consumer on its single-PRG default rather than pinning them
        // to PRG 0 on the strength of a topology nobody set.
        PLACEMENT_UNCHANGED
    } else {
        // Inverse of the permutation: the PRG whose serving node is
        // this one. A node it does not name keeps the modulo fallback.
        let n = (p.prg_count as usize).min(wire::PERM_NODES);
        match (0..n).find(|&i| u16::from(p.node_for_prg[i]) == p.self_id) {
            Some(i) => i as u16,
            None => p.self_id % p.prg_count,
        }
    };
}

/// Set the cluster's PRG topology.
///
/// Changing the divisor re-owns EVERY shard at once, so it advances the
/// epoch exactly as a fence does — consumers adopt placement only when
/// strictly newer, so a topology published at the epoch already held
/// would be discarded and the new divisor would never take effect.
///
/// Idempotent: setting the topology already in force changes nothing
/// and does not burn an epoch.
pub fn set_prg_count(p: &mut Placement, prg_count: u16) -> bool {
    set_topology(p, prg_count, None)
}

/// Set the PRG count and, optionally, which node serves each PRG. A
/// count change without a permutation resets to identity: the old
/// permutation named PRGs that may no longer exist. Idempotent on an
/// unchanged topology.
pub fn set_topology(p: &mut Placement, prg_count: u16, perm: Option<&[u8]>) -> bool {
    if prg_count == PRG_COUNT_UNCHANGED {
        return false;
    }
    let mut next = if prg_count == p.prg_count {
        p.node_for_prg
    } else {
        identity_perm()
    };
    if let Some(perm) = perm {
        let n = (prg_count as usize).min(wire::PERM_NODES);
        next[..n].copy_from_slice(&perm[..n]);
    }
    if prg_count == p.prg_count && next == p.node_for_prg {
        return false;
    }
    p.prg_count = prg_count;
    p.node_for_prg = next;
    recompute_local_prg(p);
    advance_epoch(p);
    true
}

/// Which node serves each PRG, for the record.
pub fn node_for_prg(p: &Placement) -> &[u8; wire::PERM_NODES] {
    &p.node_for_prg
}

/// The topology in force, for the record and the update frame.
pub fn prg_count(p: &Placement) -> u16 {
    p.prg_count
}

/// Adopt a topology learned from the replicated log.
///
/// Applied only alongside an epoch that was itself adopted, so the
/// divisor and the epoch that names it can never be separated.
pub fn adopt_prg_count(p: &mut Placement, prg_count: u16) {
    adopt_topology(p, prg_count, None);
}

/// Adopt a topology — count and, when the record carries one, the
/// serving permutation — learned from the replicated log.
pub fn adopt_topology(p: &mut Placement, prg_count: u16, perm: Option<&[u8]>) {
    if prg_count == PRG_COUNT_UNCHANGED {
        return;
    }
    let mut next = if prg_count == p.prg_count {
        p.node_for_prg
    } else {
        identity_perm()
    };
    if let Some(perm) = perm {
        let n = (prg_count as usize).min(wire::PERM_NODES);
        next[..n].copy_from_slice(&perm[..n]);
    }
    if prg_count == p.prg_count && next == p.node_for_prg {
        return;
    }
    p.prg_count = prg_count;
    p.node_for_prg = next;
    recompute_local_prg(p);
    p.update_pending = true;
}

/// Raise or lift the fence on `prg`.
///
/// Idempotent: only a real change queues an update, so mirroring the
/// migration phase every step costs nothing while the phase holds.
///
/// A fence change ADVANCES THE EPOCH. Listeners adopt placement updates
/// only when strictly newer — that monotonicity is what stops a
/// re-delivered update from un-fencing a completed transfer — so a
/// fence published at the epoch already held would be discarded as
/// stale and the fence would never take effect. Bumping is also the
/// documented model: traffic moves only by routing-epoch change
/// (`docs/guides/scaling.md`), and a fence IS a traffic move.
pub fn set_fence(p: &mut Placement, prg: u16, active: bool) {
    if p.fenced_active == active && (!active || p.fenced_prg == prg) {
        return;
    }
    p.fenced_prg = prg;
    p.fenced_active = active;
    advance_epoch(p);
}

/// Advance the placement epoch — the act that moves traffic.
///
/// Called when a migration commits its new placement. Monotone by
/// construction; listeners ignore anything not strictly newer.
pub fn advance_epoch(p: &mut Placement) {
    p.current_epoch = p.current_epoch.wrapping_add(1);
    p.update_pending = true;
    // Advanced LOCALLY, so it must be recorded. Adoption from a peer's
    // record deliberately does NOT set this: re-proposing what we just
    // learned would be an endless round of records for one change.
    p.epoch_record_pending = true;
    p.epoch_sent_ms = 0;
}

/// Adopt an epoch learned from the replicated log.
///
/// A MAXIMUM, never an assignment — a replayed or re-delivered record
/// must not move the epoch backwards, and a restarted node must resume
/// ABOVE every epoch the cluster has already used rather than reissuing
/// them. Returns true when this node actually moved.
pub fn adopt_epoch(p: &mut Placement, epoch: u32) -> bool {
    if epoch <= p.current_epoch {
        return false;
    }
    p.current_epoch = epoch;
    // Republish locally so this node's listeners learn the epoch it just
    // adopted; do NOT mark it for recording, it is already in the log.
    p.update_pending = true;
    true
}

/// True while a locally-advanced epoch has not been recorded yet.
pub fn epoch_record_pending(p: &Placement) -> bool {
    p.epoch_record_pending
}

/// Note that an epoch record COMMITTED, and clear the pending flag when
/// the recorded epoch has caught up with the one held.
///
/// Clearing on the WRITE instead would lose the epoch outright when a
/// proposal is dropped by a leader change: nothing would re-send it, the
/// node would restart below the epoch the cluster had reached, and it
/// would then reissue epochs already used — the exact hazard the record
/// exists to prevent. So the write only arms the retry; the commit is
/// what settles it.
///
/// `>=`, not `==`: the epoch can advance again while a record is in
/// flight, and since adoption is a max-merge, recording the highest is
/// enough. A record for a LOWER epoch than the one held leaves the flag
/// standing, so the higher one is re-proposed.
pub fn note_epoch_recorded(p: &mut Placement, epoch: u32) {
    if epoch > p.epoch_recorded {
        p.epoch_recorded = epoch;
    }
    if p.epoch_recorded >= p.current_epoch {
        p.epoch_record_pending = false;
        p.epoch_sent_ms = 0;
    }
}

/// True when an epoch-record proposal may be written this tick: either
/// none is outstanding, or the last one has gone unanswered for long
/// enough to be presumed lost.
pub fn epoch_record_due(p: &Placement, now: u64) -> bool {
    p.epoch_sent_ms == 0 || now.wrapping_sub(p.epoch_sent_ms) >= EPOCH_RECORD_RETRY_MS
}

/// Record that a proposal was written, arming the retry interval.
pub fn note_epoch_record_sent(p: &mut Placement, now: u64) {
    p.epoch_sent_ms = if now == 0 { 1 } else { now };
}

/// Current placement epoch, for components that stamp it into records.
pub fn epoch(p: &Placement) -> u32 {
    p.current_epoch
}

/// Per-step bound: at most one routing update + one epoch event.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Placement` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(p: &mut Placement, sys: &SyscallTable) {
    // Emit the placement epoch on bootstrap, and again whenever the
    // epoch or the fence changes. The frame carries the full tail:
    //   [epoch:u32][prg_count:u16][local_prg:u16][fenced_prg:u16][active:u8]
    // with both placement fields set to their "unchanged" sentinels,
    // because this component owns the epoch and the fence but not the
    // PRG topology. Consumers that read only the leading epoch (the
    // gateway) are unaffected by the longer frame.
    if (!p.emitted || p.update_pending) && p.out_routing >= 0 {
        if wire_channels::writable(sys, p.out_routing) {
            let mut buf = [0u8; 11];
            buf[0..4].copy_from_slice(&p.current_epoch.to_le_bytes());
            buf[4..6].copy_from_slice(&p.prg_count.to_le_bytes());
            buf[6..8].copy_from_slice(&p.local_prg.to_le_bytes());
            buf[8..10].copy_from_slice(&p.fenced_prg.to_le_bytes());
            buf[10] = u8::from(p.fenced_active);
            wire_channels::channel_write_msg(sys, p.out_routing, wire::MSG_PLACEMENT_UPDATE, &buf);
            p.emitted = true;
            p.update_pending = false;
        }
    }

    // Emit a kpg-keyed epoch event each time the placement epoch
    // advances. Downstream consumers fence in-flight session frames
    // on receipt; see the component doc for the wire shape and
    // reason-byte conventions.
    if p.current_epoch != p.prev_epoch && p.out_epoch_events >= 0 {
        if wire_channels::writable(sys, p.out_epoch_events) {
            // Bootstrap is the very first transition out of
            // `prev_epoch = 0`. Any subsequent placement change
            // (admin op or, eventually, rebalance) reuses this
            // emission point — until those inputs are wired, the
            // post-bootstrap branch never fires, but the reason byte
            // is honest about which class of transition the consumer
            // is observing.
            let reason = if p.prev_epoch == 0 {
                EPOCH_REASON_BOOTSTRAP
            } else {
                EPOCH_REASON_ADMIN
            };
            let mut buf = [0u8; 7];
            buf[0..2].copy_from_slice(&DEFAULT_KPG_ID.to_le_bytes());
            buf[2..6].copy_from_slice(&p.current_epoch.to_le_bytes());
            buf[6] = reason;
            wire_channels::channel_write_msg(
                sys,
                p.out_epoch_events,
                wire::MSG_PLACEMENT_EPOCH_EVENT,
                &buf,
            );
            p.prev_epoch = p.current_epoch;
        }
    }
}
