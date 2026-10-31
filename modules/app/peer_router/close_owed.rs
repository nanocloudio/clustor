//! Connections whose `CMD_CLOSE` the transport is still owed.
//!
//! Fluxor's net_proto hands a closed connection's id back only when its
//! consumer answers `MSG_CLOSED` with `CMD_CLOSE`: a peer's FIN
//! (`CLOSED_PEER_FIN`) keeps the socket for the consumer to send on, and a
//! connection gone (`CLOSED_GONE`) keeps its id held until the close. A
//! consumer that never answers leaves the transport to sweep the socket
//! after its grace and hold the id as long again — and a node whose clients
//! drop faster than that runs out of connections, its admin listener
//! included. So the router answers every close of a connection it owns, and
//! one the transport has no room for now is kept here, in order, and sent
//! on a later step.
//!
//! An answer kept past `MAX_AGE_MS` is dropped (counted): by then the
//! transport has swept the id itself and may have given it to a new
//! connection, which a late close would end. Pure: the router supplies the
//! write.

/// Closes kept at once. A transport refusing writes for longer than it
/// takes this many clients to drop has its own grace sweep behind it; past
/// it the oldest is dropped and counted.
pub const CLOSE_OWED_MAX: usize = 256;
/// The age past which a kept close is dropped rather than sent: under the
/// Linux transport's 5 s grace for a held id.
pub const MAX_AGE_MS: u64 = 4_000;

/// One owed close: the connection, the channel its transport reads, when
/// it was owed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owed {
    pub conn_id: u16,
    pub chan: i32,
    pub since_ms: u64,
}

/// The kept closes, oldest first. All-zero is the empty queue.
pub struct CloseOwed {
    q: [Owed; CLOSE_OWED_MAX],
    head: usize,
    len: usize,
    /// Closes dropped unsent (too old, or the queue full).
    pub dropped: u32,
    /// Closes sent from the queue rather than at once.
    pub deferred: u32,
}

impl CloseOwed {
    pub const fn new() -> Self {
        Self {
            q: [Owed {
                conn_id: 0,
                chan: 0,
                since_ms: 0,
            }; CLOSE_OWED_MAX],
            head: 0,
            len: 0,
            dropped: 0,
            deferred: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Answer the close of `conn_id` on `chan`: at once when nothing is
    /// kept and `write` takes it, otherwise kept behind what is.
    pub fn close(
        &mut self,
        conn_id: u16,
        chan: i32,
        now: u64,
        write: &mut impl FnMut(i32, u16) -> bool,
    ) {
        if chan < 0 {
            return;
        }
        if self.len == 0 && write(chan, conn_id) {
            return;
        }
        if self.len == CLOSE_OWED_MAX {
            self.head = (self.head + 1) % CLOSE_OWED_MAX;
            self.len -= 1;
            self.dropped = self.dropped.wrapping_add(1);
        }
        let at = (self.head + self.len) % CLOSE_OWED_MAX;
        self.q[at] = Owed {
            conn_id,
            chan,
            since_ms: now,
        };
        self.len += 1;
    }

    /// Send what is kept, oldest first, until `write` refuses one; one
    /// kept past `MAX_AGE_MS` is dropped instead. Whether nothing is left.
    pub fn flush(&mut self, now: u64, write: &mut impl FnMut(i32, u16) -> bool) -> bool {
        while self.len > 0 {
            let o = self.q[self.head];
            if now.saturating_sub(o.since_ms) > MAX_AGE_MS {
                self.dropped = self.dropped.wrapping_add(1);
            } else if write(o.chan, o.conn_id) {
                self.deferred = self.deferred.wrapping_add(1);
            } else {
                return false;
            }
            self.head = (self.head + 1) % CLOSE_OWED_MAX;
            self.len -= 1;
        }
        true
    }
}

impl Default for CloseOwed {
    fn default() -> Self {
        Self::new()
    }
}
