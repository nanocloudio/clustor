//! directory_front_core — one namespace of the session directory behind
//! a consumer's own port pair (the `directory_front` module's logic).
//!
//! The broker and egress surfaces Wormhole's modules stand on are
//! directory namespaces: `rs/` egress block and address-range
//! reservations (an egress gateway's `BlockAuthority`, a prefix's address
//! record), `att/` attachment boundaries (the private-service broker's
//! admission generations), and `op/` EVACUATION records (a failure-domain
//! controller's restart-safe evacuation). A consumer reaches one through
//! this front: it writes the namespace's own request frames —
//! `[request msg][len u16][its request id u64][command body]`, the bodies
//! `reservation_registry`, `attachment_registry` and `operation_registry`
//! define — and reads the committed replies back under its own ids. The
//! front gives every request an id of its own (`tag << 32 | counter`, the
//! tag drawn once per start, so a reply to an earlier life or to another
//! requester on the shared `replies` port is never taken), resends a
//! request unanswered after `retry_ms` (every command of these namespaces
//! carries an operation id, so a resend is the same command and the
//! registry answers it from the grant or record it made), passes an
//! operation REPLAY's streamed records through as they come and completes
//! it on its end, and refuses — before the directory sees it — a request
//! outside its namespace (or, for `op/`, of another kind than its own),
//! answering the refusal at once (`refusal_answer`). It never answers a
//! command from state of its own and holds no record past its reply.
//!
//! Pure, `no_std`, allocation-free.

#![allow(
    dead_code,
    reason = "shared #[path]-mounted core; each consumer uses a subset"
)]

/// Which namespace a front serves.
pub const NS_RS: u8 = 1;
pub const NS_AT: u8 = 2;
pub const NS_OP: u8 = 3;

/// The directory's request / reply message ids (`wire.rs`).
pub const MSG_OP_REQUEST: u8 = 0x9A;
pub const MSG_OP_REPLY: u8 = 0x9B;
pub const MSG_AT_REQUEST: u8 = 0x9C;
pub const MSG_AT_REPLY: u8 = 0x9D;
pub const MSG_RS_REQUEST: u8 = 0x9E;
pub const MSG_RS_REPLY: u8 = 0x9F;
pub const MSG_DIR_OUT_OF_SCOPE: u8 = 0xA0;

/// The largest command body any of the three namespaces carries (an
/// `op/` CAS: `[op][record 256]`, 257 bytes).
pub const FRONT_CMD_MAX: usize = 257;
/// The largest reply (an `op/` reply: 8 + 256 bytes).
pub const FRONT_REPLY_MAX: usize = 264;
/// Requests in flight at once.
pub const FRONT_PENDING: usize = 8;

/// `op/` bytes the front reads (`operation_registry.rs`).
const OP_OP_CAS: u8 = 1;
const OP_OP_REPLAY: u8 = 2;
const OP_ST_REPLAY: u8 = 2;

/// A refused request's answer to its consumer, in the directory's own
/// out-of-scope shape: `MSG_DIR_OUT_OF_SCOPE` `[consumer id:u64]
/// [request msg][reason]`, the reason one of `FRONT_REFUSED_*`.
pub const FRONT_REFUSED_NAMESPACE: u8 = 1;
pub const FRONT_REFUSED_KIND: u8 = 2;
pub const FRONT_REFUSED_MALFORMED: u8 = 3;
pub const FRONT_REFUSAL_LEN: usize = 8 + 2;

/// The answer to a request refused for `why`; `None` for a request that is
/// only waiting (`Busy`).
pub fn refusal_answer(
    consumer_id: u64,
    msg: u8,
    why: FrontRefusal,
) -> Option<[u8; FRONT_REFUSAL_LEN]> {
    let reason = match why {
        FrontRefusal::Namespace => FRONT_REFUSED_NAMESPACE,
        FrontRefusal::Kind => FRONT_REFUSED_KIND,
        FrontRefusal::Malformed => FRONT_REFUSED_MALFORMED,
        FrontRefusal::Busy => return None,
    };
    let mut a = [0u8; FRONT_REFUSAL_LEN];
    a[..8].copy_from_slice(&consumer_id.to_le_bytes());
    a[8] = msg;
    a[9] = reason;
    Some(a)
}

/// Why a consumer's request was refused here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrontRefusal {
    /// Not this front's namespace.
    Namespace,
    /// An `op/` record or REPLAY of another kind than this front's.
    Kind,
    /// Empty, or longer than any command of the namespace.
    Malformed,
    /// Every pending slot is in flight: the consumer's frame stays where
    /// it is until one frees.
    Busy,
}

#[derive(Clone, Copy)]
struct Pending {
    used: bool,
    /// Sent at least once.
    sent: bool,
    consumer_id: u64,
    our_id: u64,
    sent_ms: u64,
    resends: u32,
    len: u16,
    body: [u8; FRONT_CMD_MAX],
}

impl Pending {
    const fn empty() -> Self {
        Self {
            used: false,
            sent: false,
            consumer_id: 0,
            our_id: 0,
            sent_ms: 0,
            resends: 0,
            len: 0,
            body: [0; FRONT_CMD_MAX],
        }
    }
}

/// A request to put on the directory's `requests` port.
pub struct Outbound<'a> {
    pub msg: u8,
    pub request_id: u64,
    pub body: &'a [u8],
}

/// A reply to hand the consumer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Answer {
    /// The namespace's reply id, or `MSG_DIR_OUT_OF_SCOPE`.
    pub msg: u8,
    pub consumer_id: u64,
    /// More of this request's answers follow (an `op/` REPLAY's records).
    pub more: bool,
}

/// One front's state.
pub struct FrontCore {
    ns: u8,
    /// `op/` fronts: the one record kind served (0: any).
    op_kind: u8,
    retry_ms: u64,
    tag: u32,
    counter: u32,
    pending: [Pending; FRONT_PENDING],
    /// Round-robin cursor over the pending table for sends.
    cursor: usize,
    pub admitted: u32,
    pub refused: u32,
    pub answered: u32,
    pub resent: u32,
    /// Replies on the shared port that were not ours.
    pub foreign: u32,
}

impl FrontCore {
    /// A front for namespace `ns` (`NS_*`) whose request ids carry `tag`.
    pub const fn new(ns: u8, op_kind: u8, retry_ms: u64, tag: u32) -> Self {
        Self {
            ns,
            op_kind,
            retry_ms: if retry_ms == 0 { 1 } else { retry_ms },
            tag,
            counter: 0,
            pending: [Pending::empty(); FRONT_PENDING],
            cursor: 0,
            admitted: 0,
            refused: 0,
            answered: 0,
            resent: 0,
            foreign: 0,
        }
    }

    pub const fn request_msg(&self) -> u8 {
        match self.ns {
            NS_RS => MSG_RS_REQUEST,
            NS_AT => MSG_AT_REQUEST,
            _ => MSG_OP_REQUEST,
        }
    }

    pub const fn reply_msg(&self) -> u8 {
        match self.ns {
            NS_RS => MSG_RS_REPLY,
            NS_AT => MSG_AT_REPLY,
            _ => MSG_OP_REPLY,
        }
    }

    /// Whether a slot is free for the next consumer request.
    pub fn has_room(&self) -> bool {
        self.pending.iter().any(|p| !p.used)
    }

    /// Requests in flight.
    pub fn in_flight(&self) -> usize {
        self.pending.iter().filter(|p| p.used).count()
    }

    /// Take a consumer's request: `msg` its frame's id, `consumer_id` its
    /// request id, `body` the command after it.
    pub fn admit(&mut self, msg: u8, consumer_id: u64, body: &[u8]) -> Result<(), FrontRefusal> {
        if msg != self.request_msg() {
            self.refused = self.refused.wrapping_add(1);
            return Err(FrontRefusal::Namespace);
        }
        if body.is_empty() || body.len() > FRONT_CMD_MAX {
            self.refused = self.refused.wrapping_add(1);
            return Err(FrontRefusal::Malformed);
        }
        if self.ns == NS_OP && self.op_kind != 0 {
            let kind = match body[0] {
                OP_OP_CAS => body.get(1 + 24).copied(),
                OP_OP_REPLAY => body.get(1).copied(),
                _ => None,
            };
            if kind != Some(self.op_kind) {
                self.refused = self.refused.wrapping_add(1);
                return Err(FrontRefusal::Kind);
            }
        }
        let Some(i) = self.pending.iter().position(|p| !p.used) else {
            return Err(FrontRefusal::Busy);
        };
        self.counter = self.counter.wrapping_add(1);
        let p = &mut self.pending[i];
        *p = Pending::empty();
        p.used = true;
        p.consumer_id = consumer_id;
        p.our_id = (u64::from(self.tag) << 32) | u64::from(self.counter);
        p.len = body.len() as u16;
        p.body[..body.len()].copy_from_slice(body);
        self.admitted = self.admitted.wrapping_add(1);
        Ok(())
    }

    /// The next request due on the directory's port at `now`: one never
    /// sent, or one unanswered `retry_ms` after its last send. The caller
    /// sends it and confirms with `sent`.
    pub fn due(&self, now: u64) -> Option<(usize, Outbound<'_>)> {
        for k in 0..FRONT_PENDING {
            let i = (self.cursor + k) % FRONT_PENDING;
            let p = &self.pending[i];
            if !p.used {
                continue;
            }
            if !p.sent || now.wrapping_sub(p.sent_ms) >= self.retry_ms {
                return Some((
                    i,
                    Outbound {
                        msg: self.request_msg(),
                        request_id: p.our_id,
                        body: &p.body[..usize::from(p.len)],
                    },
                ));
            }
        }
        None
    }

    /// Slot `i`'s request went out at `now`.
    pub fn sent(&mut self, i: usize, now: u64) {
        let p = &mut self.pending[i];
        if p.sent {
            p.resends = p.resends.wrapping_add(1);
            self.resent = self.resent.wrapping_add(1);
        }
        p.sent = true;
        p.sent_ms = now;
        self.cursor = (i + 1) % FRONT_PENDING;
    }

    /// A frame off the directory's `replies` port: `msg` its id, `payload`
    /// `[request id u64][reply]`. Ours becomes the consumer's answer (the
    /// same frame with the consumer's id in place of ours); anything else
    /// is `None`. A streamed REPLAY record at `now` restarts its request's
    /// retry clock: the stream is the answer arriving.
    pub fn reply(&mut self, msg: u8, payload: &[u8], now: u64) -> Option<Answer> {
        if payload.len() < 8 || (msg != self.reply_msg() && msg != MSG_DIR_OUT_OF_SCOPE) {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&payload[..8]);
        let id = u64::from_le_bytes(id);
        let Some(i) = self
            .pending
            .iter()
            .position(|p| p.used && p.sent && p.our_id == id)
        else {
            self.foreign = self.foreign.wrapping_add(1);
            return None;
        };
        // An op/ REPLAY streams its records, each a reply with status
        // REPLAY, then its own reply: the request completes on the last.
        let more = msg == MSG_OP_REPLY
            && self.pending[i].body[0] == OP_OP_REPLAY
            && payload.get(8 + 1) == Some(&OP_ST_REPLAY);
        let consumer_id = self.pending[i].consumer_id;
        if more {
            self.pending[i].sent_ms = now;
        } else {
            self.pending[i] = Pending::empty();
            self.answered = self.answered.wrapping_add(1);
        }
        Some(Answer {
            msg,
            consumer_id,
            more,
        })
    }
}
