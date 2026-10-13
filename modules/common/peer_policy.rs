//! Peer identity policy: which connection may speak for which replica, and
//! for how long.
//!
//! Pure decisions over what `peer_router` knows of a connection — the
//! replica it claims in-band, the identity the TLS layer established for
//! it, the pins the graph configured — so every case is checked on the
//! host and the router only acts on the answers.

/// A key fingerprint: SHA-256 of the peer's public key, as
/// `MSG_PEER_IDENTITY` reports it.
pub const KEY_FP_LEN: usize = 32;

/// A pin as configured: 64 hex characters. `None` for anything else,
/// which pins nothing.
pub fn parse_pin(text: &[u8]) -> Option<[u8; KEY_FP_LEN]> {
    if text.len() != 2 * KEY_FP_LEN {
        return None;
    }
    let mut fp = [0u8; KEY_FP_LEN];
    for (i, pair) in text.chunks(2).enumerate() {
        fp[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(fp)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// What the TLS layer established for a connection: nothing yet, or a
/// verified credential with its key's fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity<'a> {
    None,
    Verified(&'a [u8]),
}

/// May a connection with `identity` bind the replica it claims, whose pin
/// is `pin`?
///
/// - A pinned replica binds only under its pin, from a verified identity
///   — whatever the policy, a configured pin is never bypassed by a
///   different key.
/// - With `require` (identity required), a replica with no pin, or a
///   connection with no verified identity, binds nothing: fail closed.
/// - Without it (a cleartext graph), a claim with no identity binds; a
///   pinned replica's claim from a verified but different key does not.
pub fn claim_admitted(
    require: bool,
    pin: Option<&[u8; KEY_FP_LEN]>,
    identity: Identity<'_>,
) -> bool {
    match (pin, identity) {
        (Some(pin), Identity::Verified(fp)) => fp == pin.as_slice(),
        (Some(_), Identity::None) => !require,
        (None, _) => !require,
    }
}

/// What to do with a replica claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    Bind,
    /// Hold the claim: its connection's identity report is still on its
    /// way, and the claim stands or falls on it.
    Wait,
    Refuse,
}

/// Judge a claim given the connection's identity report — `None` when a
/// report is due and has not arrived. The TLS layer reports on a channel
/// of its own, so a claim can arrive first; one that would bind without
/// an identity binds now, and any other waits for the report rather than
/// being judged without it.
pub fn judge_claim(
    require: bool,
    pin: Option<&[u8; KEY_FP_LEN]>,
    reported: Option<Identity<'_>>,
) -> Claim {
    match reported {
        Some(identity) if claim_admitted(require, pin, identity) => Claim::Bind,
        Some(_) => Claim::Refuse,
        None if claim_admitted(require, pin, Identity::None) => Claim::Bind,
        None => Claim::Wait,
    }
}

/// What a connection's identity report means, given the report it already
/// took (`None`: none yet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reported {
    /// The connection's identity.
    Adopt,
    /// A repeat of the identity it holds.
    Same,
    /// A different identity for a connection that already has one — a
    /// report outliving its connection and landing on a recycled id, or a
    /// transport fault. Neither identity can be trusted for the
    /// connection: it closes, and the peer redials.
    Contradicts,
}

/// A connection takes one identity for its life.
pub fn identity_reported(held: Option<Identity<'_>>, offered: Identity<'_>) -> Reported {
    match held {
        None => Reported::Adopt,
        Some(held) if held == offered => Reported::Same,
        Some(_) => Reported::Contradicts,
    }
}

/// What is known of the time, for judging a credential's end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Now {
    /// Trusted Unix seconds, and the uncertainty around them (ms).
    Trusted { secs: u64, uncertainty_ms: u32 },
    /// No time a security decision may rest on.
    Untrusted,
}

/// Has a link ended? At its credential's `not_after` (Unix seconds; 0:
/// none stated) on trusted time, counting the time's uncertainty against
/// the link; without trusted time — or a stated end — once it has lived
/// `max_link_ms` since it bound (0: no bound).
pub fn link_ended(now: Now, not_after: u64, lived_ms: u64, max_link_ms: u64) -> bool {
    match now {
        Now::Trusted {
            secs,
            uncertainty_ms,
        } if not_after != 0 => {
            secs.saturating_add(u64::from(uncertainty_ms).div_ceil(1000)) >= not_after
        }
        _ => max_link_ms != 0 && lived_ms >= max_link_ms,
    }
}

/// May a bound peer's frame name `partition`, in a graph hosting
/// `partitions` groups (0: unchecked)?
pub fn partition_admitted(partitions: u16, partition: u16) -> bool {
    partitions == 0 || partition < partitions
}

/// The longest principal (a SPIFFE URI) a report carries; a longer one is
/// not carried at all, and so names no replica.
pub const PRINCIPAL_MAX: usize = 128;

/// Does `principal` name replica `id` under `prefix`? It must be exactly
/// `prefix` + the decimal id, or that followed by `.` and a role — a node
/// certifies a key per direction (`replica-1.server`, `replica-1.client`).
/// `replica-1` never matches `replica-10`. An empty prefix names nothing.
pub fn principal_names(prefix: &[u8], id: u8, principal: &[u8]) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let mut digits = [0u8; 3];
    let mut n = 0;
    let mut v = id;
    loop {
        digits[n] = b'0' + v % 10;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let Some(rest) = principal.strip_prefix(prefix) else {
        return false;
    };
    let mut i = 0;
    while i < n {
        if rest.get(i) != Some(&digits[n - 1 - i]) {
            return false;
        }
        i += 1;
    }
    match rest.get(n) {
        None => true,
        Some(&b'.') => rest.len() > n + 1,
        Some(_) => false,
    }
}

/// One identity report from the TLS layer, copied out of the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub conn_id: u16,
    /// The session generation the report names (0: the transport numbers
    /// none) — [`report_belongs`].
    pub generation: u16,
    /// The chain reached an anchor and the peer proved its key.
    pub verified: bool,
    pub fp: [u8; KEY_FP_LEN],
    pub fp_len: u8,
    /// End of the credential's validity, Unix seconds (0: none stated).
    pub not_after: u64,
    /// When the report arrived (monotonic ms).
    pub at_ms: u64,
    /// The verified principal (the leaf's URI SAN under a CA profile);
    /// empty when the profile verified none.
    pub principal: [u8; PRINCIPAL_MAX],
    pub principal_len: u8,
}

impl Report {
    pub fn identity(&self) -> Identity<'_> {
        if self.verified {
            Identity::Verified(&self.fp[..self.fp_len as usize])
        } else {
            Identity::None
        }
    }
}

/// Whether a report naming session `report_gen` belongs to the connection
/// opened as session `conn_gen`. A transport that numbers sessions puts the
/// number on both, and a report of another session — one outliving its
/// connection, its id since reused — is not this connection's. Either
/// unnumbered (0) matches: there is nothing to tell them apart by.
pub fn report_belongs(conn_gen: u16, report_gen: u16) -> bool {
    conn_gen == 0 || report_gen == 0 || conn_gen == report_gen
}

/// How long a report waits for its connection to open (ms). The TLS layer
/// reports a session's identity just before it opens the connection, so a
/// report older than this belongs to a session that never opened.
pub const AWAIT_MS: u64 = 1000;

/// Reports for connections not yet open. The TLS layer reports a session's
/// identity, then opens its connection, on separate channels; a report
/// that arrives first waits here and is taken when the connection opens.
///
/// Per connection id the latest report wins: reports and opens each keep
/// their order, so a second report before an open means the first
/// session closed unopened. A full table drops its oldest report, and that
/// connection opens with no identity — refused wherever one is required.
pub struct Awaiting<const N: usize> {
    held: [Option<Report>; N],
}

impl<const N: usize> Awaiting<N> {
    pub const fn new() -> Self {
        Self { held: [None; N] }
    }

    /// Hold `report`. Whether an older report was dropped to make room.
    pub fn hold(&mut self, report: Report) -> bool {
        let mut free = None;
        let mut oldest = 0;
        for i in 0..N {
            match &self.held[i] {
                Some(r) if r.conn_id == report.conn_id => {
                    self.held[i] = Some(report);
                    return false;
                }
                Some(r) => {
                    if self.held[oldest].is_some_and(|o| r.at_ms < o.at_ms) {
                        oldest = i;
                    }
                }
                None => {
                    free.get_or_insert(i);
                }
            }
        }
        match free {
            Some(i) => {
                self.held[i] = Some(report);
                false
            }
            None if N > 0 => {
                self.held[oldest] = Some(report);
                true
            }
            None => true,
        }
    }

    /// The report waiting for `conn_id`, unless it is older than
    /// [`AWAIT_MS`]. Either way, no report for `conn_id` waits after this.
    pub fn take(&mut self, conn_id: u16, now_ms: u64) -> Option<Report> {
        for slot in self.held.iter_mut() {
            if slot.is_some_and(|r| r.conn_id == conn_id) {
                let r = slot.take()?;
                return (now_ms.wrapping_sub(r.at_ms) <= AWAIT_MS).then_some(r);
            }
        }
        None
    }
}

impl<const N: usize> Default for Awaiting<N> {
    fn default() -> Self {
        Self::new()
    }
}
