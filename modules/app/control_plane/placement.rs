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
//! Distinct from quantum's `MSG_EPOCH_EVENT (0xD4)` global-epoch
//! slot; the kpg-keyed contract is `MSG_PLACEMENT_EPOCH_EVENT
//! (0xD5)`, declared byte-compatibly in both clustor and lattice
//! `modules/common/wire.rs`.

use super::abi::SyscallTable;
use super::{wire, wire_channels};

/// Reason byte values for `MSG_PLACEMENT_EPOCH_EVENT`. The emission
/// path selects `BOOTSTRAP` on the initial placement epoch and
/// `ADMIN` on any subsequent transition. `REBALANCE` is wire-
/// reserved for when the rebalance scheduler lands and needs to
/// distinguish substrate-driven moves from operator-driven ones.
const EPOCH_REASON_BOOTSTRAP: u8 = 0;
const EPOCH_REASON_ADMIN: u8 = 1;
#[allow(dead_code, reason = "wire-reserved; emitted when rebalance scheduler lands")]
const EPOCH_REASON_REBALANCE: u8 = 2;

/// Default kpg_id for the single-kpg deployment. Downstream
/// consumers that haven't migrated to per-kpg session tracking yet
/// treat any non-zero new_epoch as the global epoch.
const DEFAULT_KPG_ID: u16 = 0;

#[repr(C)]
pub struct Placement {
    pub out_routing: i32,      // out: PlacementUpdate
    pub out_epoch_events: i32, // out: kpg-keyed MSG_PLACEMENT_EPOCH_EVENT for session fencing
    current_epoch: u32,
    prev_epoch: u32,
    emitted: bool,
}

pub unsafe fn init(p: &mut Placement) {
    p.out_routing = -1;
    p.out_epoch_events = -1;
    p.current_epoch = 1;
    p.prev_epoch = 0;
    p.emitted = false;
}

/// Per-step bound: at most one routing update + one epoch event.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Placement` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(p: &mut Placement, sys: &SyscallTable) {
    // Emit initial placement epoch once
    if !p.emitted && p.out_routing >= 0 {
        let poll = (sys.channel_poll)(p.out_routing, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            let buf = p.current_epoch.to_le_bytes();
            wire_channels::channel_write_msg(sys, p.out_routing, wire::MSG_PLACEMENT_UPDATE, &buf);
            p.emitted = true;
        }
    }

    // Emit a kpg-keyed epoch event each time the placement epoch
    // advances. Downstream consumers fence in-flight session frames
    // on receipt; see the component doc for the wire shape and
    // reason-byte conventions.
    if p.current_epoch != p.prev_epoch && p.out_epoch_events >= 0 {
        let poll = (sys.channel_poll)(p.out_epoch_events, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
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
