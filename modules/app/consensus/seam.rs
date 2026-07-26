//! seam — in-module message seams for the consensus composite.
//!
//! [`SeamRing`] stands in for an internal channel edge: a producer-owned
//! wrapping byte ring carrying the channel layer's `[type:u8][len:u16 LE]`
//! record framing with the same all-or-nothing write contract (a record
//! that does not fit the free space is dropped whole — atomic single
//! frames, never a torn two-part write). The consumer drains it at its
//! original per-step bound.
//!
//! [`HorizonLatch`] stands in for a retried commit-horizon channel: a
//! monotone latest-wins latch the dispatch table drains every step, so
//! delivery can never fail and per-consumer retry machinery is
//! unnecessary. Collapsing multiple raises per step to the max is
//! semantics-preserving because horizon progress is advance-only.

/// Record header: `[msg_type:u8][len:u16 LE]`.
const HDR: usize = 3;

/// Slots in the fixed strict-ReadIndex probe queues (E7 request /
/// E8 reply). A probe issued at step N is seen at step N+1 — the same
/// one-tick spacing the channel edges had.
pub const PROBE_QUEUE_SLOTS: usize = 8;

/// Producer-owned wrapping byte ring with channel-record framing.
#[repr(C)]
pub struct SeamRing<const N: usize> {
    buf: [u8; N],
    head: u16,
    used: u16,
}

impl<const N: usize> SeamRing<N> {
    /// Reset to empty. Ring bytes are dead while `used == 0`, so the
    /// buffer content is left as-is (avoids an N-byte stack temporary
    /// in `module_new`; module state arrives zeroed from the kernel).
    pub fn reset(&mut self) {
        self.head = 0;
        self.used = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// All-or-nothing enqueue of one framed record. Returns `false` —
    /// dropping the record whole — when `3 + payload.len()` exceeds
    /// the free space, mirroring an atomic channel write against a
    /// full ring.
    pub fn push(&mut self, msg_type: u8, payload: &[u8]) -> bool {
        let total = HDR + payload.len();
        if total > N - self.used as usize {
            return false;
        }
        let len = payload.len() as u16;
        let hdr = [msg_type, (len & 0xFF) as u8, (len >> 8) as u8];
        let mut w = (self.head as usize + self.used as usize) % N;
        for &b in hdr.iter().chain(payload.iter()) {
            self.buf[w] = b;
            w = (w + 1) % N;
        }
        self.used += total as u16;
        true
    }

    /// Dequeue one record into `dst`. Returns `(msg_type, len)` where
    /// `len` is the record's stored payload length; bytes beyond
    /// `dst.len()` are consumed but not copied (the channel reader's
    /// truncating contract).
    pub fn pop(&mut self, dst: &mut [u8]) -> Option<(u8, u16)> {
        if (self.used as usize) < HDR {
            return None;
        }
        let mut r = self.head as usize;
        let msg_type = self.buf[r];
        r = (r + 1) % N;
        let lo = self.buf[r];
        r = (r + 1) % N;
        let hi = self.buf[r];
        r = (r + 1) % N;
        let len = u16::from_le_bytes([lo, hi]) as usize;
        for i in 0..len {
            let b = self.buf[r];
            r = (r + 1) % N;
            if i < dst.len() {
                dst[i] = b;
            }
        }
        self.head = r as u16;
        self.used -= (HDR + len) as u16;
        Some((msg_type, len as u16))
    }
}

/// Monotone latest-wins horizon latch. Always deliverable: the
/// dispatch table reads `(term, index)` and clears `dirty` each step.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HorizonLatch {
    pub term: u64,
    pub index: u64,
    pub dirty: bool,
}

impl HorizonLatch {
    pub const fn new() -> Self {
        Self { term: 0, index: 0, dirty: false }
    }

    /// Raise the horizon, keeping the max index (and its term).
    pub fn raise(&mut self, term: u64, index: u64) {
        if index >= self.index {
            self.term = term;
            self.index = index;
            self.dirty = true;
        }
    }
}
