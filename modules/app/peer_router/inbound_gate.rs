//! The inbound record walk and its per-destination backpressure.
//!
//! Peer bytes arrive as one stream of partitioned records
//! (`[partition_id:u16 LE][msg_type:u8][len:u16 LE][payload]`) and each
//! record goes to one of two consensus inputs, `raft_rpc` or `peer_rx`.
//! When an input refuses a record, the rest of the chunk is held and no
//! further net event is drained until it goes: the consumers parse each
//! input as a continuous stream of whole records, so skipping one out of
//! order is not an option while the input is merely slow.
//!
//! But a held chunk blocks every event behind it, for every peer:
//! accepts, dial completions, closes, and the other input's records. An
//! input that has stopped reading for good therefore takes the whole
//! node's peer plane with it. Measured on Nanocloud: an engine wedged on
//! its own rpc input, the shared buffer behind it full, `peer_router`
//! holding the same chunk for ever, every link closed as stale after
//! 15 s, and every redial queued behind the stall.
//!
//! So a hold is bounded. An input that has accepted nothing for
//! `SHED_AFTER_MS` is wedged, and while it stays wedged its records are
//! dropped whole and counted, so the walk goes on delivering the other
//! input's records and the event drain goes on. The first record it
//! accepts again ends the episode, and holding resumes. A shed record is
//! a whole record, so no consumer's framing is touched: what the Raft
//! peer sees is loss, which it tolerates (RPCs retransmit, a snapshot
//! transfer whose offsets skip is refused and restarted), never
//! corruption. A forwarded proposal shed here is lost as one dropped by
//! a leader that stepped down is lost.
//!
//! Pure: no syscalls, so the host tests mount this file as the router
//! does.

/// Partitioned record header: `[partition_id:u16][msg_type:u8][len:u16]`.
pub const HDR: usize = 5;

/// Inputs the walk delivers to: `raft_rpc` and `peer_rx`.
pub const DESTS: usize = 2;

/// How long an input may accept nothing before its records are shed.
/// Above an election timeout, so an input that is only slow keeps
/// backpressure, and well inside the 15 s a silent link survives, so a
/// wedged one is shed before its peers are closed as stale.
pub const SHED_AFTER_MS: u64 = 2000;

/// Per-input refusal tracking.
#[repr(C)]
pub struct Gate {
    /// Set from an input's first refusal until it next accepts.
    refusing: [bool; DESTS],
    /// When the current refusal began.
    since: [u64; DESTS],
    /// Set while records for the input are being shed.
    shedding: [bool; DESTS],
    /// Records shed per input, ever.
    pub shed: [u32; DESTS],
    /// Shedding episodes per input, ever.
    pub episodes: [u32; DESTS],
}

/// What to do with a record its input refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Retain it and everything after it; stop draining.
    Hold,
    /// Drop it whole and go on: the input is wedged.
    Shed,
}

impl Gate {
    pub const fn new() -> Self {
        Self {
            refusing: [false; DESTS],
            since: [0; DESTS],
            shedding: [false; DESTS],
            shed: [0; DESTS],
            episodes: [0; DESTS],
        }
    }

    /// The input took a record: any refusal or shedding episode is over.
    pub fn accepted(&mut self, dest: usize) {
        self.refusing[dest] = false;
        self.shedding[dest] = false;
    }

    /// The input refused a record at `now`.
    pub fn refused(&mut self, dest: usize, now: u64) -> Verdict {
        if !self.refusing[dest] {
            self.refusing[dest] = true;
            self.since[dest] = now;
        }
        if now.wrapping_sub(self.since[dest]) < SHED_AFTER_MS {
            return Verdict::Hold;
        }
        if !self.shedding[dest] {
            self.shedding[dest] = true;
            self.episodes[dest] = self.episodes[dest].wrapping_add(1);
        }
        self.shed[dest] = self.shed[dest].wrapping_add(1);
        Verdict::Shed
    }

    /// Whether records for `dest` are being shed.
    pub fn shedding(&self, dest: usize) -> bool {
        self.shedding[dest]
    }
}

/// Where the walk's records go.
pub trait Sink {
    /// Whether the record's partition is one this graph serves.
    fn admitted(&mut self, partition: u16) -> bool;
    /// The input a message type belongs on, or `None` for a shape no
    /// peer may send.
    fn dest(&mut self, msg_type: u8) -> Option<usize>;
    /// Hand one whole record to an input; false when it refused.
    fn write(&mut self, dest: usize, record: &[u8]) -> bool;
}

/// How a walk ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// Every whole record was handled; a partial one, if any, starts at
    /// this offset and is the peer's tail.
    Tail(usize),
    /// The record at this offset was refused by an input that is not
    /// wedged: retain from here and stop draining.
    Held(usize),
    /// A length no legal record has: nothing from here can be trusted.
    Desync,
}

/// What a walk did, for the caller's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Walked {
    pub delivered: u32,
    pub partitions_refused: u32,
    pub untrusted: u32,
    pub shed: u32,
}

/// Walk the whole records in `bytes`, at most `max_record` bytes each.
pub fn walk(
    bytes: &[u8],
    max_record: usize,
    now: u64,
    gate: &mut Gate,
    sink: &mut impl Sink,
) -> (End, Walked) {
    let mut w = Walked::default();
    let mut off = 0usize;
    while off < bytes.len() {
        let left = bytes.len() - off;
        if left < HDR {
            break;
        }
        let len = u16::from_le_bytes([bytes[off + 3], bytes[off + 4]]) as usize;
        let rec_len = HDR + len;
        if rec_len > max_record {
            return (End::Desync, w);
        }
        if left < rec_len {
            break;
        }
        let partition = u16::from_le_bytes([bytes[off], bytes[off + 1]]);
        if !sink.admitted(partition) {
            w.partitions_refused += 1;
            off += rec_len;
            continue;
        }
        let Some(dest) = sink.dest(bytes[off + 2]) else {
            w.untrusted += 1;
            off += rec_len;
            continue;
        };
        if sink.write(dest, &bytes[off..off + rec_len]) {
            gate.accepted(dest);
            w.delivered += 1;
        } else {
            match gate.refused(dest, now) {
                Verdict::Hold => return (End::Held(off), w),
                Verdict::Shed => w.shed += 1,
            }
        }
        off += rec_len;
    }
    (End::Tail(off), w)
}
