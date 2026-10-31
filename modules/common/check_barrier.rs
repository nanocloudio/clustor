//! check_barrier — token checks held behind a log barrier (the session
//! directory's `checks` path).
//!
//! A token check reads a replica's applied registries, and applied state
//! can lag the commit: answered at once, a replica behind would verify a
//! token that a committed move has already ended. So a check is answered
//! only from state that has reached a barrier — an entry the replica
//! proposes when the check arrives. Raft appends the barrier behind every
//! entry committed before then, so state at or past the barrier reflects
//! each of them, and the verdict is the one the group's committed state
//! gives at a point between the check's arrival and its answer.
//!
//! This table holds the checks meanwhile: per check, the barrier's
//! correlation, the wal index and group raft assigned it (none until the
//! assignment arrives), when it was proposed, and the check itself. A
//! barrier assigned to another group orders nothing in this one, and one
//! that never applies here (lost with a leader) ages out: either way the
//! check is dropped unanswered, which a provider reads as a refusal.
//!
//! Pure, `no_std`, allocation-free.

#![allow(
    dead_code,
    reason = "shared #[path]-mounted core; each consumer uses a subset"
)]

/// Checks held at once. A full table leaves further checks in their
/// channel.
pub const MAX_CHECKS: usize = 8;

/// How long a check waits on its barrier: the longest a Fluxor provider
/// waits on a verdict (a continuity job's `TCS_JOB_MS`; an arm waits
/// `ARM_AUTH_WAIT_MS`, 2 s). Past it no provider is listening.
pub const CHECK_TTL_MS: u64 = 5_000;

/// What an assignment did to the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Assigned {
    /// No held check proposed this barrier.
    NotHeld,
    /// The check now waits on the barrier's index.
    Held,
    /// The barrier went to another group's log; its check is dropped.
    Foreign,
}

#[derive(Clone, Copy)]
struct Held<const LEN: usize> {
    corr: u64,
    /// 0 until raft assigns the barrier an index.
    index: u64,
    part: u16,
    born_ms: u64,
    msg: u8,
    len: u16,
    req: [u8; LEN],
}

/// Checks of at most `LEN` bytes awaiting their barriers.
pub struct CheckBarrier<const LEN: usize> {
    slots: [Option<Held<LEN>>; MAX_CHECKS],
}

impl<const LEN: usize> CheckBarrier<LEN> {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_CHECKS],
        }
    }

    /// Whether another check can be held.
    pub fn has_room(&self) -> bool {
        self.slots.iter().any(Option::is_none)
    }

    /// Checks held, assigned or not.
    pub fn held(&self) -> usize {
        self.slots.iter().filter(|h| h.is_some()).count()
    }

    /// Hold check `req` (message id `msg`) behind the barrier proposed
    /// with correlation `corr` into group `part` at `now_ms`. False when
    /// the table is full or the check is longer than `LEN`.
    pub fn hold(&mut self, corr: u64, part: u16, now_ms: u64, msg: u8, req: &[u8]) -> bool {
        if req.len() > LEN {
            return false;
        }
        let Some(slot) = self.slots.iter_mut().find(|h| h.is_none()) else {
            return false;
        };
        let mut held = Held {
            corr,
            index: 0,
            part,
            born_ms: now_ms,
            msg,
            len: req.len() as u16,
            req: [0; LEN],
        };
        held.req[..req.len()].copy_from_slice(req);
        *slot = Some(held);
        true
    }

    /// Raft assigned the proposal `corr` index `index` in group `part`.
    pub fn assign(&mut self, corr: u64, part: u16, index: u64) -> Assigned {
        let Some(slot) = self
            .slots
            .iter_mut()
            .find(|h| h.is_some_and(|h| h.corr == corr))
        else {
            return Assigned::NotHeld;
        };
        let Some(held) = slot.as_mut() else {
            return Assigned::NotHeld;
        };
        if held.part != part {
            *slot = None;
            return Assigned::Foreign;
        }
        held.index = index;
        Assigned::Held
    }

    /// Drop every check older than [`CHECK_TTL_MS`] at `now_ms`; the
    /// number dropped.
    pub fn expire(&mut self, now_ms: u64) -> u32 {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|h| now_ms.wrapping_sub(h.born_ms) > CHECK_TTL_MS) {
                *slot = None;
                n += 1;
            }
        }
        n
    }

    /// Release one check whose barrier state applied through `applied`
    /// has reached, copying it into `out`: its message id and length.
    /// State past the barrier answers as soundly as the barrier's own —
    /// it reflects every entry the barrier does, and more.
    pub fn take_ready(&mut self, applied: u64, out: &mut [u8; LEN]) -> Option<(u8, usize)> {
        let slot = self
            .slots
            .iter_mut()
            .find(|h| h.is_some_and(|h| h.index != 0 && h.index <= applied))?;
        let held = slot.take()?;
        let n = held.len as usize;
        out[..n].copy_from_slice(&held.req[..n]);
        Some((held.msg, n))
    }
}

impl<const LEN: usize> Default for CheckBarrier<LEN> {
    fn default() -> Self {
        Self::new()
    }
}
