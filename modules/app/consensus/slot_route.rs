//! Which hosted slot a partition's frames belong to, and what becomes of
//! a frame that arrives for one.
//!
//! The engine allocates `K_MAX` slots and hosts only `active` of them.
//! The rest are initialised but never stepped, and an initialised slot
//! reads `partition_id == 0`, which is a real partition. A lookup that
//! scanned every allocated slot would answer "hosted" for partition 0 on
//! any engine whose base partition is not 0, and file its frames into a
//! slot nothing drains: a forwarded proposal held there stops the engine
//! reading its rpc input, the shared buffer behind it fills, and the peer
//! router stops draining the node's inbound bytes. Every lookup is
//! therefore bounded by `active`, and that bound lives here, once, so the
//! demux, the durability-proof route, the WAL read-back route and runtime
//! activation share it.
//!
//! Pure: no syscalls, so the host tests mount this file as the engine
//! does.

/// Index of the hosted slot whose partition is `partition_id`, scanning
/// only the `active` slots the engine runs. `None` means this engine
/// does not host the partition, so the frame is misrouted.
pub fn slot_for<T>(
    slots: &[T],
    active: usize,
    partition_id: u16,
    pid: impl Fn(&T) -> u16,
) -> Option<usize> {
    let hosted = active.min(slots.len());
    slots[..hosted]
        .iter()
        .position(|sl| pid(sl) == partition_id)
}

/// What runtime activation of a partition does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activation {
    /// Already hosted at this slot: a re-delivered or replayed
    /// activation, so nothing changes.
    AlreadyHosted(usize),
    /// Every slot is in use. `K_MAX` is a compile-time bound, so there is
    /// no growth path.
    Full,
    /// Bring the partition up in this slot, the next one past `active`.
    Activate(usize),
}

/// Decide runtime activation of `partition_id` on an engine hosting
/// `active` of `slots`.
pub fn activation_for<T>(
    slots: &[T],
    active: usize,
    partition_id: u16,
    pid: impl Fn(&T) -> u16,
) -> Activation {
    if let Some(i) = slot_for(slots, active, partition_id, pid) {
        return Activation::AlreadyHosted(i);
    }
    // Slot 0 is the template every hosted slot is cloned from, so an
    // engine always hosts it; `active == 0` is a state nothing builds.
    if active == 0 || active >= slots.len() {
        return Activation::Full;
    }
    Activation::Activate(active)
}

/// What to do with a frame whose group has no inbox room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnFull {
    /// Keep it at the channel head until the group drains. Right for a
    /// stream the group's LOG depends on: a proposal held is a proposal
    /// delivered later; a proposal dropped is a write lost.
    Hold,
    /// Discard it and count. Right for Raft RPCs, which the protocol
    /// retransmits: a heartbeat resends next interval, a vote request
    /// re-campaigns, an AppendEntries is re-driven by the replicator.
    /// Holding one instead parks the whole shared channel behind a single
    /// group, and every OTHER group on the node then misses its
    /// heartbeats: a per-group backlog becoming a node-wide election. A
    /// forwarded PROPOSAL on the same channel is exempt: it is a client's
    /// write with no retransmit behind it, so it is held.
    Drop,
}

/// The fate of one frame read off a shared partitioned channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// No hosted slot owns the partition: count it and move on. Never
    /// held, whatever the channel's `OnFull`, because no step will ever
    /// make room for it and holding it would block the channel head for
    /// good.
    Misrouted,
    /// The owning slot has room: place it there.
    Place(usize),
    /// The owner is full and the frame is retransmitted by the protocol:
    /// drop and count.
    DropFull,
    /// The owner is full and nothing retransmits the frame: hold it at
    /// the channel head until the owner drains.
    Hold(usize),
}

/// Decide a frame's fate. `has_room` is asked only of a hosted slot.
pub fn dispose(
    slot: Option<usize>,
    has_room: impl FnOnce(usize) -> bool,
    on_full: OnFull,
    is_forward: bool,
) -> Disposition {
    let Some(slot) = slot else {
        return Disposition::Misrouted;
    };
    if has_room(slot) {
        Disposition::Place(slot)
    } else if on_full == OnFull::Drop && !is_forward {
        Disposition::DropFull
    } else {
        Disposition::Hold(slot)
    }
}
