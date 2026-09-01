//! Per-slot frame inbox — the seam that lets one module host K
//! Partition Raft Groups over shared channels.
//!
//! Shared by `consensus` and `durability`: both went from one instance
//! per group to one instance hosting K, and both therefore need the
//! same routed intake.
//!
//! ## Why this exists
//!
//! The substrate ran one `consensus` instance per partition, so the
//! graph's edge count scaled with the partition count and hit the
//! fluxor port budget at four (`partition_router`'s
//! `MAX_LOCAL_PARTITIONS`). Hosting K groups inside one instance fixes
//! that, but the groups then share input channels — and channel reads
//! are destructive, so the first slot to run would consume frames
//! addressed to the others.
//!
//! ## Why an inbox rather than something cheaper
//!
//! Two cheaper constructions were considered and rejected:
//!
//! - **Read once, dispatch synchronously** — the engine reads a frame
//!   and calls the owning slot's handler inline.
//! - **Peek and skip** — each slot uses `channel_peek` to consume only
//!   frames bearing its own `partition_id`.
//!
//! Both leave the shared channel head-of-line blocked by whichever slot owns
//! the frame at its head. If that slot cannot accept right now
//! (`flush_deferred`, the uncommitted-inflight cap, an unwritable output),
//! every other slot's traffic queues behind it. That is silent fan-in
//! across partitions — a stuck partition stalling another — which the
//! tee'd per-instance channels do not do, so adopting either would be a
//! regression dressed as a simplification. A one-deep overflow latch only
//! defers the same stall by one frame.
//!
//! Decoupling a shared channel from per-slot backpressure needs
//! per-slot queues with real depth. That is this.
//!
//! ## Shape
//!
//! An inbox lives INSIDE the component that drains it, and its `next`
//! has the same signature as `wire_channels::next_msg` — so a drain loop
//! changes its frame SOURCE and nothing else. The engine pushes; the
//! component pops; the loop body, its bounds and its guards are
//! untouched.
//!
//! Frame bodies come from the module's heap arena rather than a fixed
//! `[u8; MAX] * depth * K` block: a queued frame lives only until the
//! owning component's next drain, so arena occupancy tracks frames
//! actually in flight instead of the worst case for every queue at once
//! — the same lifetime argument that moved `apply`'s pending bodies
//! there.

use super::abi::SyscallTable;
use super::{heap_alloc, heap_free};

/// Queued frames per inbox. Deep enough that one slot's backpressure
/// does not immediately stall the shared channel, shallow enough that K
/// inboxes of descriptors stay small. Components drain up to 16 frames
/// per step, so a full inbox is one step's work.
pub const INBOX_DEPTH: usize = 16;

#[derive(Clone, Copy)]
struct Frame {
    msg_type: u8,
    len: u16,
    /// Arena allocation holding `len` bytes, or null for an empty frame.
    body: *mut u8,
}

impl Frame {
    const fn empty() -> Self {
        Self {
            msg_type: 0,
            len: 0,
            body: core::ptr::null_mut(),
        }
    }
}

/// A bounded FIFO of frames addressed to one slot on one input class.
#[repr(C)]
pub struct Inbox {
    ring: [Frame; INBOX_DEPTH],
    head: u8,
    count: u8,
    /// Frames refused because the ring was full. Non-zero means this
    /// slot is not keeping up with its share of the channel; the
    /// producer is backpressured (the engine stops reading for this
    /// slot), so it is a pacing signal, not a loss counter.
    pub refused: u32,
    /// Frames dropped because the arena could not hold the body.
    pub arena_exhausted: u32,
}

impl Inbox {
    pub const fn new() -> Self {
        Self {
            ring: [Frame::empty(); INBOX_DEPTH],
            head: 0,
            count: 0,
            refused: 0,
            arena_exhausted: 0,
        }
    }

    pub fn is_full(&self) -> bool {
        self.count as usize >= INBOX_DEPTH
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// True when this inbox can take another frame. The engine checks
    /// this BEFORE consuming from the channel, so a frame is never read
    /// and then dropped — the same gate-before-consume discipline
    /// `partition_router` follows.
    pub fn has_room(&self) -> bool {
        !self.is_full()
    }

    /// Append a frame, copying `body` into the arena.
    ///
    /// Returns false if the ring is full or the arena is exhausted; in
    /// both cases nothing is queued and the caller must not have
    /// consumed the frame.
    ///
    /// # Safety
    /// Caller must supply a valid `&SyscallTable` per the module ABI.
    pub unsafe fn push(&mut self, sys: &SyscallTable, msg_type: u8, body: &[u8]) -> bool {
        if self.is_full() {
            self.refused = self.refused.wrapping_add(1);
            return false;
        }
        let len = body.len();
        let p = if len > 0 {
            let p = heap_alloc(sys, len as u32);
            if p.is_null() {
                self.arena_exhausted = self.arena_exhausted.wrapping_add(1);
                return false;
            }
            core::ptr::copy_nonoverlapping(body.as_ptr(), p, len);
            p
        } else {
            core::ptr::null_mut()
        };
        let idx = (self.head as usize + self.count as usize) % INBOX_DEPTH;
        self.ring[idx] = Frame {
            msg_type,
            len: len as u16,
            body: p,
        };
        self.count += 1;
        true
    }

    /// Pop the oldest frame into `buf`, mirroring
    /// `wire_channels::next_msg`'s contract: `Some((msg_type, len))` on
    /// a frame, `None` when empty. A frame too large for `buf` is
    /// dropped rather than truncated — the same outcome
    /// `channel_read_msg` gives an oversize payload, and for the same
    /// reason: a truncated frame is worse than a missing one.
    ///
    /// # Safety
    /// Caller must supply a valid `&SyscallTable` per the module ABI.
    pub unsafe fn next(&mut self, sys: &SyscallTable, buf: &mut [u8]) -> Option<(u8, u16)> {
        if self.count == 0 {
            return None;
        }
        let idx = self.head as usize;
        let f = self.ring[idx];
        self.ring[idx] = Frame::empty();
        self.head = ((idx + 1) % INBOX_DEPTH) as u8;
        self.count -= 1;

        let len = f.len as usize;
        let fits = len <= buf.len();
        if fits && len > 0 && !f.body.is_null() {
            core::ptr::copy_nonoverlapping(f.body, buf.as_mut_ptr(), len);
        }
        if !f.body.is_null() {
            heap_free(sys, f.body);
        }
        if !fits {
            return None;
        }
        Some((f.msg_type, f.len))
    }

    /// Release every queued frame's arena allocation. Used on reset
    /// paths so a discarded queue cannot strand memory.
    ///
    /// # Safety
    /// Caller must supply a valid `&SyscallTable` per the module ABI.
    pub unsafe fn clear(&mut self, sys: &SyscallTable) {
        while self.count > 0 {
            let idx = self.head as usize;
            let f = self.ring[idx];
            if !f.body.is_null() {
                heap_free(sys, f.body);
            }
            self.ring[idx] = Frame::empty();
            self.head = ((idx + 1) % INBOX_DEPTH) as u8;
            self.count -= 1;
        }
    }
}
