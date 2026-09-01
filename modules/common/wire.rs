//! Wire format helpers for inter-module channel messages.
//!
//! Every message uses a 3-byte envelope:
//!   [msg_type: u8] [len: u16 LE] [payload: len bytes]
//!
//! ## Stability
//!
//! External consumers (Quantum, Lattice, Chronicle, Loam) MUST go
//! through `modules/common/replica_facade.rs` instead of importing
//! these constants directly.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface so single-module rustc invocations see unused items"
)]

// ── Fixed-layout codec primitives ───────────────────────────────────────────
//
// Every payload in this file is a fixed sequence of little-endian
// scalars, and every codec below reads and writes it through `Reader` /
// `Writer`. Access is positional: fields come off the cursor in
// declaration order, so an encoder and its decoder can be compared line
// for line and neither can drift to an offset the other does not share.
// The length check lives at `Reader::new` — one check per payload, in
// the decoder rather than in each caller.
//
// Both are `#[inline]` and every offset is a compile-time constant, so
// each accessor folds to the same indexed load or store a literal
// `buf[9..17]` spells out. Nothing here is benchmarked separately —
// `benches/wire_codec.rs` covers the facade's codecs, not these — so
// treat that as the design intent it is built to, not a measured
// result.

/// Sequential little-endian reader over a payload slice.
///
/// Construct with [`Reader::new`], which is where the single length
/// check lives: a payload shorter than the codec's fixed width yields
/// `None` and the decoder returns `None` in turn, so a truncated frame
/// is reported as absent rather than decoded into zeros.
///
/// The accessors below are unchecked by design — one check per payload,
/// not one per field. That makes `need` a contract: it MUST cover every
/// byte the decoder goes on to consume, skips included. Understating it
/// indexes past the slice, and a `no_std` module cannot unwind, so the
/// panic kills the module rather than failing the frame.
///
/// Each accessor advances the cursor, so call order IS field order.
/// Decoders here build their tuple inline (`Some((r.u64(), r.u8()))`),
/// which is well defined: Rust evaluates a tuple expression's operands
/// left to right.
pub struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    /// Bind a reader to `buf`, requiring at least `need` readable bytes.
    ///
    /// `need` is the codec's whole fixed width — see the type-level note
    /// on why it must cover every subsequent read.
    #[inline]
    pub fn new(buf: &'a [u8], need: usize) -> Option<Self> {
        if buf.len() < need {
            return None;
        }
        Some(Self { buf, off: 0 })
    }

    #[inline]
    pub fn u64(&mut self) -> u64 {
        let b = &self.buf[self.off..self.off + 8];
        self.off += 8;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    #[inline]
    pub fn u32(&mut self) -> u32 {
        let b = &self.buf[self.off..self.off + 4];
        self.off += 4;
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    #[inline]
    pub fn u16(&mut self) -> u16 {
        let b = &self.buf[self.off..self.off + 2];
        self.off += 2;
        u16::from_le_bytes([b[0], b[1]])
    }

    #[inline]
    pub fn u8(&mut self) -> u8 {
        let v = self.buf[self.off];
        self.off += 1;
        v
    }

    #[inline]
    pub fn i64(&mut self) -> i64 {
        self.u64() as i64
    }

    #[inline]
    pub fn i32(&mut self) -> i32 {
        self.u32() as i32
    }

    #[inline]
    pub fn i16(&mut self) -> i16 {
        self.u16() as i16
    }

    /// A `u8` field carrying a boolean. Any non-zero byte is `true`, so
    /// a peer that writes `1` and one that writes `0xFF` agree.
    #[inline]
    pub fn bool(&mut self) -> bool {
        self.u8() != 0
    }

    /// Advance past `n` bytes the decoder does not surface — a field
    /// present on the wire that this caller has no use for, or a
    /// reserved span. Counts toward the `need` the reader was built
    /// with, and keeps every following field positional.
    #[inline]
    pub fn skip(&mut self, n: usize) -> &mut Self {
        self.off += n;
        self
    }
}

/// Sequential little-endian writer over a destination slice.
///
/// Encoders here take a buffer the caller has already sized against the
/// codec's published width — usually a `[u8; N]`, otherwise behind an
/// explicit length check — so `Writer` indexes directly and a short
/// buffer panics rather than silently truncating the frame.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> Writer<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, off: 0 }
    }

    #[inline]
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf[self.off..self.off + 8].copy_from_slice(&v.to_le_bytes());
        self.off += 8;
        self
    }

    #[inline]
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf[self.off..self.off + 4].copy_from_slice(&v.to_le_bytes());
        self.off += 4;
        self
    }

    #[inline]
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf[self.off..self.off + 2].copy_from_slice(&v.to_le_bytes());
        self.off += 2;
        self
    }

    #[inline]
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf[self.off] = v;
        self.off += 1;
        self
    }

    #[inline]
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.u64(v as u64)
    }

    #[inline]
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.u32(v as u32)
    }

    #[inline]
    pub fn i16(&mut self, v: i16) -> &mut Self {
        self.u16(v as u16)
    }

    #[inline]
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    /// Copy a byte run verbatim: a magic prefix, a nested body, or a
    /// variable-length tail. Keeps a payload that mixes scalars and
    /// opaque bytes on one cursor.
    #[inline]
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf[self.off..self.off + v.len()].copy_from_slice(v);
        self.off += v.len();
        self
    }
}

// ── Message type constants ──────────────────────────────────────────────────

// Raft RPC
pub const MSG_APPEND_ENTRIES: u8 = 0x01;
pub const MSG_APPEND_ENTRIES_RESP: u8 = 0x02;
pub const MSG_REQUEST_VOTE: u8 = 0x03;
pub const MSG_REQUEST_VOTE_RESP: u8 = 0x04;
/// A proposal a FOLLOWER received on its client-proposal channel and
/// relayed to the leader, so a client connected to a non-leader is not
/// silently stalled. Payload is the raw proposal body — no correlation
/// tag, so this carries fire-and-forget writes only (MQTT QoS 0,
/// Kafka acks=0). Response-owed proposals still need the origin tag
/// plumbed back and are NOT forwarded.
pub const MSG_PROPOSAL_FORWARD: u8 = 0x0F;

/// A RESPONSE-OWED proposal relayed by a follower (QoS 1+, `acks>=1`).
/// Payload is `[origin:u8][correlation_id:u64 LE][body]`. The origin is
/// carried explicitly because the leader must send the resulting
/// `MSG_PROPOSAL_ASSIGNED` back to the ring that holds the waiting
/// inflight slot — its own ring is the wrong one.
pub const MSG_PROPOSAL_FORWARD_TAGGED: u8 = 0x1D;
/// The leader's answer to `MSG_PROPOSAL_FORWARD_TAGGED`, addressed to
/// the ORIGIN node: `[correlation_id:u64 LE][partition_id:u16 LE]
/// [wal_index:u64 LE]`, the same shape as `MSG_PROPOSAL_ASSIGNED`,
/// which the origin re-emits locally to its proposer.
pub const MSG_PROPOSAL_ASSIGNED_REMOTE: u8 = 0x1E;
/// `[origin:u8][correlation_id:u64 LE]` prefix on a forwarded tagged
/// proposal.
pub const FORWARD_TAGGED_HDR: usize = 9;
pub const MSG_PRE_VOTE: u8 = 0x05;
pub const MSG_PRE_VOTE_RESP: u8 = 0x06; // reuse slot: high bit unused
pub const MSG_HEARTBEAT: u8 = 0x07;
pub const MSG_HEARTBEAT_RESP: u8 = 0x08;
/// Periodic leader-state hint emitted by `consensus.leader_state` so
/// downstream modules (notably `gateway`) can short-circuit
/// proposals with an explicit `CLIENT_REJECT_NOT_LEADER` when the local
/// node is not the leader. Payload: `[leader_id:u8 (0xFF = unknown)][term:u64 LE]`.
pub const MSG_LEADER_HINT: u8 = 0x09;
/// Leader-transfer "TimeoutNow" RPC. Sent by a stepping-down leader to
/// the target it wants to promote. Receiver immediately bumps term and
/// starts an election. Payload: `[caller_term:u64 LE]` (8 bytes) so the
/// receiver can drop stale messages.
pub const MSG_TIMEOUT_NOW: u8 = 0x0A;
/// Strict ReadIndex peer-network probe (Raft paper §6.4). Sent by the
/// leader to every peer when it needs to confirm that it still holds
/// the leadership at the point the read was issued. Payload (16 bytes):
/// `[probe_id:u64 LE][term:u64 LE]`.
pub const MSG_READ_INDEX_PROBE: u8 = 0x0B;
/// Peer's reply to `MSG_READ_INDEX_PROBE`. The leader counts these to
/// majority before answering the read. Payload (17 bytes):
/// `[probe_id:u64 LE][term:u64 LE][replica:u8]`.
pub const MSG_READ_INDEX_PROBE_RESP: u8 = 0x0C;
/// Internal consensus seam, apply → raft: "I have a read with this
/// correlation id, please confirm a read-index for me." Payload (8 bytes):
/// `[correlation_id:u64 LE]`.
pub const MSG_READ_PROBE_REQ: u8 = 0x0D;
/// Internal consensus seam, raft → apply: reply to `MSG_READ_PROBE_REQ`.
/// Payload (17 bytes):
/// `[correlation_id:u64 LE][confirmed_commit:u64 LE][confirmed:u8]`.
/// `confirmed == 0` means "not leader" or "probe timed out" — the
/// apply pipeline must reject the read with `CLIENT_REJECT_FALLBACK`.
pub const MSG_READ_PROBE_REPLY: u8 = 0x0E;

#[inline]
pub fn encode_read_index_probe(buf: &mut [u8; 16], probe_id: u64, term: u64) {
    Writer::new(buf).u64(probe_id).u64(term);
}

#[inline]
pub fn decode_read_index_probe(buf: &[u8]) -> Option<(u64, u64)> {
    let mut r = Reader::new(buf, 16)?;
    let probe = r.u64();
    let term = r.u64();
    Some((probe, term))
}

#[inline]
pub fn encode_read_index_probe_resp(buf: &mut [u8; 17], probe_id: u64, term: u64, replica: u8) {
    Writer::new(buf).u64(probe_id).u64(term).u8(replica);
}

#[inline]
pub fn decode_read_index_probe_resp(buf: &[u8]) -> Option<(u64, u64, u8)> {
    let mut r = Reader::new(buf, 17)?;
    Some((r.u64(), r.u64(), r.u8()))
}

#[inline]
pub fn encode_read_probe_reply(
    buf: &mut [u8; 17],
    correlation_id: u64,
    confirmed_commit: u64,
    confirmed: bool,
) {
    Writer::new(buf)
        .u64(correlation_id)
        .u64(confirmed_commit)
        .u8(confirmed as u8);
}

#[inline]
pub fn decode_read_probe_reply(buf: &[u8]) -> Option<(u64, u64, bool)> {
    let mut r = Reader::new(buf, 17)?;
    let correlation_id = r.u64();
    let confirmed_commit = r.u64();
    let confirmed = r.bool();
    Some((correlation_id, confirmed_commit, confirmed))
}

// Client
pub const MSG_CLIENT_PROPOSAL: u8 = 0x10;
pub const MSG_CLIENT_RESPONSE: u8 = 0x11;
pub const MSG_ADMIN_COMMAND: u8 = 0x12;
pub const MSG_ADMIN_RESPONSE: u8 = 0x13;
/// Structured client rejection on the wire (after gateway stamps
/// `conn_id`). Wire payload (11 bytes):
/// `[conn_id:u8][status:u8][reserved:u8][retry_after_ms:u16 LE][entry_credits:i16 LE][byte_credits:i32 LE]`
/// Surfaced when a request is denied before it can be replicated —
/// throttle rejection, NotLeader, stale-epoch, read-unsupported, etc.
pub const MSG_CLIENT_REJECT: u8 = 0x15;
/// Linearizable read request from a client. Payload after the conn_id prefix
/// supplied by gateway: `[read_id:u64 LE][body]`. The substrate does not yet
/// implement linearizable reads end-to-end — gateway answers every read with
/// `CLIENT_REJECT_READ_UNSUPPORTED`.
pub const MSG_CLIENT_READ_REQUEST: u8 = 0x16;
/// Internal rejection envelope used between the gateway's throttle
/// reject path and its response egress. Carries the correlation_id assigned
/// by gateway so the codec can map it back to a conn_id.
/// Payload (18 bytes):
/// `[correlation_id:u64 LE][status:u8][reserved:u8][retry_after_ms:u16 LE][entry_credits:i16 LE][byte_credits:i32 LE]`
pub const MSG_CLIENT_REJECT_INTERNAL: u8 = 0x17;
/// Linearizable read response from `consensus.applied` to
/// `gateway.responses`. Emitted when a queued read has reached its ReadIndex
/// linearization point (apply_index ≥ submission-time commit horizon) AND
/// the CP cache is still Fresh/Cached. The body is empty — downstream
/// consumers MUST query their state machine via the per-entry
/// `committed_entries` stream once they observe the matching index. Payload:
/// `[correlation_id:u64 LE]` (8 bytes).
pub const MSG_CLIENT_READ_RESPONSE: u8 = 0x18;
/// Admin-command apply confirmation from `consensus.admin_applied` to
/// the admin component's `applied` input. Carries the per-admin command_id that
/// the admin component stamped onto the request, plus the status the engine
/// decided. Payload (5 bytes):
/// `[command_id:u32 LE][status:u8]`.
pub const MSG_ADMIN_APPLIED: u8 = 0x19;

/// `MSG_ADMIN_RESPONSE` payload status codes (first byte). The admin
/// component chooses one per command; see `operations/admin.rs` for which
/// op takes which route and therefore which status it can return.
pub const ADMIN_STATUS_OK: u8 = 0x00;
pub const ADMIN_STATUS_DUPLICATE: u8 = 0x01;
pub const ADMIN_STATUS_UNSUPPORTED: u8 = 0x80;
pub const ADMIN_STATUS_REJECTED: u8 = 0x81;
pub const ADMIN_STATUS_NOT_LEADER: u8 = 0x82;

/// Admin op codes (first body byte of an admin command). FREEZE / THAW /
/// DURABILITY_MODE replicate through the log; TRANSFER_LEADER / SNAPSHOT
/// and the membership ops reach `consensus` directly, which turns a
/// membership change into the `CONFIG_CHANGE` entry that carries the
/// joint-consensus transition. The migration, placement, tenant-quota and
/// shard-map ops go to the control-plane controller instead.
pub const ADMIN_OP_FREEZE: u8 = 0x01;
pub const ADMIN_OP_THAW: u8 = 0x02;
pub const ADMIN_OP_TRANSFER_LEADER: u8 = 0x03;
pub const ADMIN_OP_DURABILITY_MODE: u8 = 0x04;
pub const ADMIN_OP_SNAPSHOT: u8 = 0x05;
pub const ADMIN_OP_ADD_VOTER: u8 = 0x06;
pub const ADMIN_OP_REMOVE_VOTER: u8 = 0x07;
/// Add a replica as a non-voting learner: it receives the log and
/// counts toward no quorum. The catch-up step that must precede
/// [`ADMIN_OP_ADD_VOTER`]. Op body: `[replica_id:u8]`.
pub const ADMIN_OP_ADD_LEARNER: u8 = 0x0C;
/// Drop a replica from the learner set. Op body: `[replica_id:u8]`.
pub const ADMIN_OP_REMOVE_LEARNER: u8 = 0x0D;
/// `POST /propose` client-write bridge. Carried on the admin command
/// channel for wiring reuse, but the admin component emits it as a RAW
/// (un-marked) `MSG_CLIENT_PROPOSAL` — the op_body is opaque application data,
/// NOT an admin op, so it is never applied at commit time. Lets an off-DUT
/// generator drive real client writes over HTTP without a dedicated ingress.
pub const ADMIN_OP_PROPOSE: u8 = 0x08;

/// Start a shard migration. Op body: `[migration_id:u64 LE]
/// [source_prg:u16 LE][target_prg:u16 LE][shard_count:u16 LE]`.
pub const ADMIN_OP_MIGRATE_BEGIN: u8 = 0x0E;
/// Report that the CURRENT migration phase's work has finished, so the
/// state machine may advance. Op body: `[phase:u8]` — naming the phase
/// being completed is what makes a late or re-sent signal harmless
/// (MIG-IDEMPOTENT).
pub const ADMIN_OP_MIGRATE_PHASE_DONE: u8 = 0x0F;
/// Abort the active migration. Refused once fenced (MIG-ONEWAY).
/// Empty op body.
pub const ADMIN_OP_MIGRATE_ABORT: u8 = 0x10;

/// Set the cluster's PRG topology: `[prg_count:u16]`.
///
/// The divisor that maps a virtual shard to its owning PRG. Changing it
/// re-owns every shard at once, so it advances the placement epoch and
/// is recorded durably with it.
///
/// DANGER, and the reason this is an explicit operator action rather
/// than something inferred: publishing a `prg_count` higher than the
/// number of PRGs that actually exist makes every node release the
/// state for shards mapping to groups that were never activated. Those
/// shards are then owned by nobody and their sessions, retained values
/// and offline queues are dropped. Raising the topology is gated on
/// having activated the groups first — never the reverse.
pub const ADMIN_OP_PLACEMENT_TOPOLOGY: u8 = 0x11;

/// Op-body length of [`ADMIN_OP_PLACEMENT_TOPOLOGY`].
pub const PLACEMENT_TOPOLOGY_BODY_LEN: usize = 2;

/// Set a tenant's publish-rate quota: `[tenant_id:u32][max_rate:u32]`.
///
/// The quota `governance` enforces was a synthetic constant re-emitted
/// on every refresh tick — not settable, and reset to the same default
/// on every restart, so an operator could neither raise a tenant's rate
/// nor keep a lowered one across a reboot. Recorded through Raft so it
/// is cluster-wide and survives.
pub const ADMIN_OP_TENANT_QUOTA: u8 = 0x12;

/// Op-body length of [`ADMIN_OP_TENANT_QUOTA`].
pub const TENANT_QUOTA_BODY_LEN: usize = 8;

/// Magic prefixing a committed tenant-quota record.
pub const TENANT_CMD_MAGIC: [u8; 2] = *b"TQ";

/// Body length of a tenant-quota record (magic + tenant_id + rate).
pub const TENANT_RECORD_LEN: usize = 2 + 4 + 4;

/// True when `buf` is a committed tenant-quota record.
#[inline]
pub fn is_tenant_record(buf: &[u8]) -> bool {
    buf.len() >= TENANT_RECORD_LEN && buf[..2] == TENANT_CMD_MAGIC
}

/// Pin one shard to a PRG, overriding the modulo baseline — the `ShardMap`
/// record class. Body: `[shard_id:u32 LE][prg:u16 LE]`, with `prg ==
/// SHARD_OVERRIDE_CLEAR` removing the override.
///
/// The override is recorded through Raft for the same reason the tenant
/// quota is: it is applied on the COMMIT, so a leader that loses its
/// term before the record commits cannot route on a map no other node
/// has, and a restart cannot lose a placement an operator set.
pub const ADMIN_OP_SHARD_MAP: u8 = 0x13;

/// Op-body length of [`ADMIN_OP_SHARD_MAP`]: shard + prg.
pub const SHARD_MAP_BODY_LEN: usize = 6;

/// Magic prefixing a committed shard-map record.
pub const SHARD_MAP_CMD_MAGIC: [u8; 2] = *b"SM";

/// Body length of a shard-map record (magic + shard_id + prg).
pub const SHARD_MAP_RECORD_LEN: usize = 2 + 4 + 2;

/// True when `buf` is a committed shard-map record.
#[inline]
pub fn is_shard_map_record(buf: &[u8]) -> bool {
    buf.len() >= SHARD_MAP_RECORD_LEN && buf[..2] == SHARD_MAP_CMD_MAGIC
}

/// Encode a committed shard-map record.
pub fn encode_shard_map_record(buf: &mut [u8], shard: u32, prg: u16) -> usize {
    if buf.len() < SHARD_MAP_RECORD_LEN {
        return 0;
    }
    buf[..2].copy_from_slice(&SHARD_MAP_CMD_MAGIC);
    buf[2..6].copy_from_slice(&shard.to_le_bytes());
    buf[6..8].copy_from_slice(&prg.to_le_bytes());
    SHARD_MAP_RECORD_LEN
}

/// Decode a committed shard-map record into `(shard, prg)`.
pub fn decode_shard_map_record(buf: &[u8]) -> Option<(u32, u16)> {
    if !is_shard_map_record(buf) {
        return None;
    }
    Some((
        u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]),
        u16::from_le_bytes([buf[6], buf[7]]),
    ))
}

/// Migration command carried from the admin surface to the controller
/// that owns the state machine. Body:
/// `[op_code:u8][op_body...]` — the admin op codes above, forwarded
/// verbatim so the controller and the admin surface share one
/// vocabulary rather than translating between two.
pub const MSG_MIGRATION_COMMAND: u8 = 0x83;

/// Op-body length of [`ADMIN_OP_MIGRATE_BEGIN`].
/// `[migration_id:u64][source_prg:u16][target_prg:u16][shard_count:u16][base_shard:u32]`
///
/// The batch is named, not implied. A PRG owns every shard congruent to
/// it mod `prg_count`, which at the designed shard-space size is 2^18
/// of them, so "the source's shards" is not a set any bounded override
/// table can carry. A
/// migration moves a NAMED batch, and `base_shard` is what lets the
/// cutover emit exactly the overrides it promised.
pub const MIGRATE_BEGIN_BODY_LEN: usize = 8 + 2 + 2 + 2 + 4;

/// Magic prefix of an admin entry replicated through the Raft log. When a
/// committed entry's body starts with these eight bytes, the substrate
/// interprets the remainder as `[command_id:u32 LE][op_code:u8][op_body...]`
/// and applies the op at commit time on every replica. Plain proposal bodies
/// (no magic) remain opaque and are passed through unchanged.
///
/// Sizing: entry TYPE is inferred from the head of a body that is
/// otherwise opaque application data, so the magic must be wide enough
/// that no real payload collides into it. Application bodies routinely
/// lead with dense counters — a correlation id whose low byte cycles
/// through all 256 values is an ordinary way to start a record — so any
/// short tag is forged within a few hundred entries, and a forged
/// config change can apply a C_new that removes the node from its own
/// voter set. Eight bytes put accidental collision at ~2^-64 and cost
/// application entries nothing: only clustor's own admin/config
/// entries carry a magic.
pub const ADMIN_MAGIC: [u8; 8] = [0xAD, 0x4D, 0x4E, 0x21, 0x9E, 0x1F, 0x5C, 0xA7];

/// True when `buf` begins with [`ADMIN_MAGIC`].
#[inline]
pub fn has_admin_magic(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[..8] == ADMIN_MAGIC
}

/// `consensus` → `consensus` admin commit signal. Emitted when a
/// committed entry's body begins with `ADMIN_MAGIC` so consensus
/// can apply the op locally. Payload: same body bytes that landed in
/// the WAL minus the 8-byte magic:
/// `[command_id:u32 LE][op_code:u8][op_body...]`.
pub const MSG_ADMIN_COMMITTED: u8 = 0x1A;
/// `consensus` → `consensus` config-change commit. Emitted when a committed
/// entry's body begins with `CONFIG_CHANGE_MAGIC`. Payload is the entry body
/// verbatim — the magic STAYS, so the consumer validates with
/// `decode_config_change`.
pub const MSG_CONFIG_COMMITTED: u8 = 0x1B;

/// Client proposal carrying a proposer-chosen virtual-shard id.
/// Payload is `[shard_id:u32 LE]` followed by the payload the router
/// forwards after stripping it — see "Keyed proposal envelope" below.
/// Accepted only by `partition_router`; `consensus` never sees this
/// type, because the router rewrites it to [`MSG_CLIENT_PROPOSAL`].
pub const MSG_CLIENT_PROPOSAL_KEYED: u8 = 0x1C;

/// Body-prefix byte for a Raft-replicated configuration change (joint
/// consensus). Followed by:
/// `[op_code:u8 (1 = C_old,new, 2 = C_new)][voter_count:u8]
///  [voter_id_0:u8]...[voter_id_{n-1}:u8]` for the "new" voter set.
/// For `C_old,new` entries the old set is recoverable from the
/// follower's persisted `current_voters`. Joint consensus is not yet
/// fully implemented; the magic is reserved so the log format
/// stays stable while the engine work lands.
/// Magic prefix of a Raft config-change entry body. See [`ADMIN_MAGIC`]
/// for the sizing rationale.
pub const CONFIG_CHANGE_MAGIC: [u8; 8] = [0xCC, 0x46, 0x47, 0x21, 0x9E, 0x1F, 0x5C, 0xA7];

/// True when `buf` begins with [`CONFIG_CHANGE_MAGIC`].
#[inline]
pub fn has_config_change_magic(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[..8] == CONFIG_CHANGE_MAGIC
}
pub const CONFIG_CHANGE_OP_JOINT: u8 = 0x01;
pub const CONFIG_CHANGE_OP_NEW: u8 = 0x02;
/// Replace the learner set. Learners receive the log but count toward
/// NO quorum — not the commit tally, not the durability tally, not an
/// election. They exist so a replica can catch up on the real log
/// before it is made a voter: a voter added cold would join with an
/// empty log and immediately count toward both majorities, which can
/// stall commit until it catches up and can lose entries if the leader
/// fails meanwhile.
///
/// Body is the same shape as the voter ops — the id list is the
/// COMPLETE learner set, not a delta, so replay is idempotent.
pub const CONFIG_CHANGE_OP_LEARNER: u8 = 0x03;

/// Fixed prefix of a config-change body: the 8-byte magic, the op code
/// and the id count. A buffer must be `CONFIG_CHANGE_HDR + voters.len()`
/// or [`encode_config_change`] refuses it and returns 0.
pub const CONFIG_CHANGE_HDR: usize = 10;

/// Encode a config-change entry body for the WAL log. Layout:
///   `[CONFIG_CHANGE_MAGIC:8][op_code:u8][voter_count:u8][voter_id_0..n-1:u8]`
/// Returns total bytes written or 0 on buffer-too-small.
#[inline]
pub fn encode_config_change(buf: &mut [u8], op_code: u8, voters: &[u8]) -> usize {
    let n = voters.len().min(0xFF);
    let total = CONFIG_CHANGE_HDR + n;
    if buf.len() < total {
        return 0;
    }
    Writer::new(buf)
        .bytes(&CONFIG_CHANGE_MAGIC)
        .u8(op_code)
        .u8(n as u8)
        .bytes(&voters[..n]);
    total
}

/// Decode a config-change body. Returns `(op_code, voter_ids_offset, voter_count)`
/// or `None` if the body doesn't start with `CONFIG_CHANGE_MAGIC` or is
/// truncated.
#[inline]
pub fn decode_config_change(buf: &[u8]) -> Option<(u8, usize, usize)> {
    if !has_config_change_magic(buf) || buf.len() < 10 {
        return None;
    }
    let op_code = buf[8];
    let n = buf[9] as usize;
    if buf.len() < 10 + n {
        return None;
    }
    Some((op_code, 10, n))
}

/// Magic prefix of a deterministic-timing substrate entry. Followed by
/// `[op:u8 (1 = TimeAdvance, 2 = TimeDrain)][time_ms:u64 LE]`. TimeAdvance
/// carries the proposed logical time; TimeDrain carries `through_time_ms`,
/// which must equal the applied logical time or the drain is a deterministic
/// no-op. These are internal entries: only the leader's time producer may
/// propose them, and the gateway rejects client bodies carrying this prefix.
/// See [`ADMIN_MAGIC`] for the 8-byte sizing rationale.
pub const TIMING_MAGIC: [u8; 8] = [0x54, 0x4D, 0x45, 0x21, 0x9E, 0x1F, 0x5C, 0xA7];

/// True when `buf` begins with [`TIMING_MAGIC`].
#[inline]
pub fn has_timing_magic(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[..8] == TIMING_MAGIC
}

pub const TIMING_OP_ADVANCE: u8 = 0x01;
pub const TIMING_OP_DRAIN: u8 = 0x02;

/// Total encoded size of a timing entry body.
pub const TIMING_ENTRY_LEN: usize = 8 + 1 + 8;

/// Encode a timing entry body (`TimeAdvance` / `TimeDrain`).
/// Returns bytes written or 0 on buffer-too-small / bad op.
#[inline]
pub fn encode_time_entry(buf: &mut [u8], op: u8, time_ms: u64) -> usize {
    if buf.len() < TIMING_ENTRY_LEN || (op != TIMING_OP_ADVANCE && op != TIMING_OP_DRAIN) {
        return 0;
    }
    Writer::new(buf).bytes(&TIMING_MAGIC).u8(op).u64(time_ms);
    TIMING_ENTRY_LEN
}

/// Decode a timing entry body. Returns `(op, time_ms)` or `None` when
/// the prefix, op or length is wrong (unknown timing entries fail
/// closed at the consumer).
#[inline]
pub fn decode_time_entry(buf: &[u8]) -> Option<(u8, u64)> {
    if !has_timing_magic(buf) || buf.len() < TIMING_ENTRY_LEN {
        return None;
    }
    let mut r = Reader::new(buf, TIMING_ENTRY_LEN)?;
    r.skip(TIMING_MAGIC.len());
    let op = r.u8();
    if op != TIMING_OP_ADVANCE && op != TIMING_OP_DRAIN {
        return None;
    }
    Some((op, r.u64()))
}

/// `consensus` → `consensus` / `durability` voter-set
/// update. Sent every time the current or joint voter set changes so
/// the downstream quorum tracker can adjust. Payload (3 bytes):
///   `[current_set:u8][joint_set:u8][joint_active:u8][learner_set:u8]`
/// Each `u8` is a [`super::types::NodeSet`] bitmask. `joint_active = 0`
/// means single-config; otherwise both sets must be considered for
/// quorum.
///
/// `learner_set` names replicas that receive the log but count toward
/// no quorum. It is carried here so the replicator knows to keep
/// shipping AppendEntries to them; every quorum tally derives from
/// `current_set` / `joint_set` alone and must ignore it.
pub const MSG_VOTER_SET_UPDATE: u8 = 0x76;

/// Payload length of [`MSG_VOTER_SET_UPDATE`].
pub const VOTER_SET_UPDATE_LEN: usize = 4;

#[inline]
pub fn encode_voter_set_update(
    buf: &mut [u8; VOTER_SET_UPDATE_LEN],
    current_set: u8,
    joint_set: u8,
    joint_active: bool,
    learner_set: u8,
) {
    Writer::new(buf)
        .u8(current_set)
        .u8(joint_set)
        .bool(joint_active)
        .u8(learner_set);
}

/// Returns `(current, joint, joint_active, learners)`.
#[inline]
pub fn decode_voter_set_update(buf: &[u8]) -> Option<(u8, u8, bool, u8)> {
    if buf.len() < VOTER_SET_UPDATE_LEN {
        return None;
    }
    Some((buf[0], buf[1], buf[2] != 0, buf[3]))
}

/// `MSG_CLIENT_REJECT` status codes (status byte, after the conn_id /
/// correlation_id prefix depending on envelope variant).
pub const CLIENT_REJECT_THROTTLED: u8 = 0x01;
pub const CLIENT_REJECT_NOT_LEADER: u8 = 0x02;
pub const CLIENT_REJECT_STALE_EPOCH: u8 = 0x03;
pub const CLIENT_REJECT_FALLBACK: u8 = 0x04;
pub const CLIENT_REJECT_READ_UNSUPPORTED: u8 = 0x05;
/// The record's payload exceeds the largest proposal the log can
/// carry. Rejected at the gateway surface, before any bytes are
/// consumed downstream — truncating and proposing a prefix would
/// commit a corrupted entry while acking the client's full write.
pub const CLIENT_REJECT_TOO_LARGE: u8 = 0x06;

/// Inner reject body, independent of envelope variant: 10 bytes
/// `[status:u8][reserved:u8=0][retry_after_ms:u16 LE][entry_credits:i16 LE][byte_credits:i32 LE]`.
pub const CLIENT_REJECT_BODY_LEN: usize = 10;
/// `MSG_CLIENT_REJECT_INTERNAL` (throttle → codec) total payload size:
/// 8-byte correlation_id + 10-byte body.
pub const CLIENT_REJECT_INTERNAL_LEN: usize = 8 + CLIENT_REJECT_BODY_LEN;
/// `MSG_CLIENT_REJECT` wire payload size (codec → surface → peer):
/// 1-byte conn_id + 10-byte body.
pub const CLIENT_REJECT_WIRE_LEN: usize = 1 + CLIENT_REJECT_BODY_LEN;

/// Encode the 10-byte reject body. Used by both envelope variants.
/// `reserved` is repurposed as `leader_id` when
/// `status == CLIENT_REJECT_NOT_LEADER`. Pass `0` for every other status.
#[inline]
pub fn encode_client_reject_body(
    buf: &mut [u8; CLIENT_REJECT_BODY_LEN],
    status: u8,
    reserved: u8,
    retry_after_ms: u16,
    entry_credits: i16,
    byte_credits: i32,
) {
    Writer::new(buf)
        .u8(status)
        .u8(reserved)
        .u16(retry_after_ms)
        .i16(entry_credits)
        .i32(byte_credits);
}

/// Encode an internal reject envelope `[correlation_id:u64][body 10b]`.
#[inline]
pub fn encode_client_reject_internal(
    buf: &mut [u8; CLIENT_REJECT_INTERNAL_LEN],
    correlation_id: u64,
    status: u8,
    retry_after_ms: u16,
    entry_credits: i16,
    byte_credits: i32,
) {
    let mut body = [0u8; CLIENT_REJECT_BODY_LEN];
    encode_client_reject_body(
        &mut body,
        status,
        0,
        retry_after_ms,
        entry_credits,
        byte_credits,
    );
    Writer::new(buf).u64(correlation_id).bytes(&body);
}

/// Decode an internal reject envelope. Returns
/// `(correlation_id, status, retry_after_ms, entry_credits, byte_credits)`.
#[inline]
pub fn decode_client_reject_internal(buf: &[u8]) -> Option<(u64, u8, u16, i16, i32)> {
    let mut r = Reader::new(buf, CLIENT_REJECT_INTERNAL_LEN)?;
    let correlation_id = r.u64();
    let status = r.u8();
    r.skip(1); // reserved
    let retry = r.u16();
    let entry = r.i16();
    let byte = r.i32();
    Some((correlation_id, status, retry, entry, byte))
}

/// Encode a wire reject envelope `[conn_id:u8][body 10b]`.
///
/// `reserved` carries `leader_id` when `status == CLIENT_REJECT_NOT_LEADER`,
/// otherwise pass 0.
#[inline]
pub fn encode_client_reject_wire(
    buf: &mut [u8; CLIENT_REJECT_WIRE_LEN],
    conn_id: u8,
    status: u8,
    reserved: u8,
    retry_after_ms: u16,
    entry_credits: i16,
    byte_credits: i32,
) {
    buf[0] = conn_id;
    let mut body = [0u8; CLIENT_REJECT_BODY_LEN];
    encode_client_reject_body(
        &mut body,
        status,
        reserved,
        retry_after_ms,
        entry_credits,
        byte_credits,
    );
    buf[1..1 + CLIENT_REJECT_BODY_LEN].copy_from_slice(&body);
}

/// Emitted by consensus on its `proposal_assigned` output port for every
/// tagged proposal once the leader has assigned it a log index. Lets the
/// proposer (e.g. quantum/session_processor) bind a per-message correlation
/// id to the durable wal_index without relying on FIFO heuristics.
/// Payload:
/// `[correlation_id:u64 LE][partition_id:u16 LE][wal_index:u64 LE]` (18 bytes).
pub const MSG_PROPOSAL_ASSIGNED: u8 = 0x14;

// Persistence
pub const MSG_WAL_ENTRY: u8 = 0x20;
pub const MSG_FSYNC_ACK: u8 = 0x21;
pub const MSG_DURABILITY_PROOF: u8 = 0x22;
pub const MSG_COMMITTED_BATCH: u8 = 0x23;
/// WAL entry random-access request from `replicator` (or any other
/// consumer that needs to read back a specific log index). Payload
/// (12 bytes): `[request_id:u32 LE][wal_index:u64 LE]`. The WAL
/// replies on `entry_reply` with `MSG_WAL_ENTRY_REPLY`. A zero-body
/// reply means the index is unknown / below the retention floor —
/// callers should fall back to a snapshot install.
pub const MSG_WAL_ENTRY_REQUEST: u8 = 0x29;
/// WAL entry random-access reply. Payload (20+ bytes):
/// `[request_id:u32 LE][term:u64 LE][index:u64 LE][body...]`. When
/// `body.is_empty()` the entry was not found at this WAL.
pub const MSG_WAL_ENTRY_REPLY: u8 = 0x2A;
/// Apply-pipeline reset notification emitted by `consensus` after a
/// snapshot install fast-forwards `commit_index`. Payload (16 bytes):
/// `[term:u64 LE][index:u64 LE]`. The pipeline must drop any pending
/// observer entries whose index <= reset index and bump its own
/// `apply_index` to the reset point.
pub const MSG_APPLY_PIPELINE_RESET: u8 = 0x2B;
/// WAL compaction request emitted by `consensus` after a snapshot
/// install or post-snapshot trim. Payload (8 bytes):
/// `[before_index:u64 LE]`. WAL deletes segments whose max-index <
/// `before_index` and trims its in-memory offset map.
pub const MSG_WAL_COMPACT_BEFORE: u8 = 0x2C;
/// WAL → consensus boot-time replay-complete signal. Emitted exactly once
/// after the WAL finishes its replay scan (PHASE_REPLAY → NORMAL), carrying
/// the EXACT on-disk high-water it reconstructed. Payload (16 bytes):
/// `[term:u64 LE][high_water_index:u64 LE]` (encoded via
/// `encode_term_index`). On a crash-recovery boot raft loads only a
/// THROTTLED durable hint from its metadata slots (`META_PERSIST_STRIDE`),
/// which lags the WAL's true replayed high-water; resuming at the stale hint
/// makes new post-recovery appends collide with the replayed index space.
/// raft HOLDS proposal intake until this signal arrives, then resumes
/// `last_log_index` at `high_water_index` and re-seeds consensus. This needs
/// its OWN dedicated edge — it CANNOT ride the shared `wal.flushed` fan-out
/// (which also feeds durability; a one-shot signal there is consumed by the
/// wrong consumer and the boot deadlocks).
pub const MSG_WAL_REPLAY_COMPLETE: u8 = 0x2D;
/// consensus → WAL log-suffix truncation (Raft §5.3 conflict repair).
/// Emitted by a follower when an AppendEntries reveals a divergent suffix:
/// every entry strictly AFTER `keep_through_index` must be discarded before
/// the leader's entries can be appended. Payload (12 bytes):
/// `[keep_through_index:u64 LE][request_id:u32 LE]`. The WAL seeks the live
/// segment to the end of `keep_through_index`, writes a zero-length
/// terminator frame so replay stops there, fsyncs, retires every discarded
/// segment above the keep point, and only THEN publishes its own high-water
/// and answers `MSG_WAL_TRUNCATE_ACK`.
///
/// The request is a REQUEST, not a fact: raft keeps its old tip and refuses
/// conflicting AppendEntries until the correlated ack arrives. A repeat of
/// the same `(keep_through_index, request_id)` is idempotent.
///
/// SAFETY: raft never emits this for `keep_through_index < commit_index` —
/// committed entries are immutable, so truncation can only ever touch the
/// uncommitted tail. Shares the `wal.compact_before` control channel.
pub const MSG_WAL_TRUNCATE_AFTER: u8 = 0x2E;
/// Length of the `MSG_WAL_TRUNCATE_AFTER` payload.
pub const WAL_TRUNCATE_AFTER_LEN: usize = 12;

/// WAL → consensus truncation outcome, correlated by `request_id`.
/// Payload (13 bytes): `[keep_through_index:u64 LE][request_id:u32 LE]
/// [durable:u8]`.
///
/// `durable = 1` means every part of the truncation reached stable storage:
/// the retained prefix, the terminator frame, the required fsync, and any
/// segment retirement. Only then may raft rewind its tip and accept
/// replacement entries. `durable = 0` means nothing was published — the WAL's
/// own high-water is unchanged and a retry is a clean repeat.
///
/// Rides the `wal.flushed` channel alongside `MSG_FSYNC_ACK`.
pub const MSG_WAL_TRUNCATE_ACK: u8 = 0x25;
/// Length of the `MSG_WAL_TRUNCATE_ACK` payload.
pub const WAL_TRUNCATE_ACK_LEN: usize = 13;

/// Encode the `MSG_WAL_TRUNCATE_AFTER` payload.
#[inline]
pub fn encode_wal_truncate_after(
    buf: &mut [u8; WAL_TRUNCATE_AFTER_LEN],
    keep_through_index: u64,
    request_id: u32,
) {
    Writer::new(buf).u64(keep_through_index).u32(request_id);
}

/// Decode the `MSG_WAL_TRUNCATE_AFTER` payload. A shorter payload
/// carries no request id and decodes as id 0.
#[inline]
pub fn decode_wal_truncate_after(buf: &[u8]) -> Option<(u64, u32)> {
    if buf.len() < 8 {
        return None;
    }
    let index = Reader::new(buf, 8)?.u64();
    // `request_id` is optional on the wire: an 8-byte frame carries
    // none and decodes with id 0, so a peer emitting the narrower
    // shape stays readable.
    let request_id = Reader::new(buf, WAL_TRUNCATE_AFTER_LEN).map_or(0, |mut r| r.skip(8).u32());
    Some((index, request_id))
}

/// Encode the `MSG_WAL_TRUNCATE_ACK` payload.
#[inline]
pub fn encode_wal_truncate_ack(
    buf: &mut [u8; WAL_TRUNCATE_ACK_LEN],
    keep_through_index: u64,
    request_id: u32,
    durable: bool,
) {
    Writer::new(buf)
        .u64(keep_through_index)
        .u32(request_id)
        .u8(durable as u8);
}

/// Decode the `MSG_WAL_TRUNCATE_ACK` payload.
#[inline]
pub fn decode_wal_truncate_ack(buf: &[u8]) -> Option<(u64, u32, bool)> {
    let mut r = Reader::new(buf, WAL_TRUNCATE_ACK_LEN)?;
    Some((r.u64(), r.u32(), r.bool()))
}

/// `durability` → `consensus` continuity rejection. Emitted when the WAL is
/// handed an entry whose index is not `wal_current_index + 1`, i.e. raft's log
/// has diverged from what the WAL actually holds. Payload (8 bytes):
/// `[expected_index:u64 LE]` — the index the WAL will accept next.
///
/// A successful `channel_write_msg` is NOT an acknowledgement that the WAL
/// took the entry — it only means the frame entered the WAL's input channel.
/// The continuity check runs inside the WAL after that call returns, so this
/// message is raft's only signal that an entry it counted was never
/// persisted. Raft must resync its tip down to `expected_index - 1` and
/// replay from there; without it the WAL's sticky fail-closed latch wedges
/// the node silently.
pub const MSG_WAL_REJECT: u8 = 0x2F;

/// Encode / decode the 8-byte `MSG_WAL_REJECT` payload.
#[inline]
pub fn encode_wal_reject(buf: &mut [u8; 8], expected_index: u64) {
    Writer::new(buf).u64(expected_index);
}

#[inline]
pub fn decode_wal_reject(buf: &[u8]) -> Option<u64> {
    Some(Reader::new(buf, 8)?.u64())
}

/// `MSG_WAL_ENTRY_REQUEST` payload size (12 bytes).
pub const WAL_ENTRY_REQUEST_LEN: usize = 12;
/// Fixed header size of `MSG_WAL_ENTRY_REPLY` (28 bytes); body follows.
/// `[request_id:u32][term:u64][index:u64][prev_term:u64]`. `prev_term` is the
/// term of the entry at `index-1` (0 if `index<=1` or not resident) so the
/// replicator can build a catch-up AppendEntries with the CORRECT
/// `prev_log_term` — guessing it (e.g. reusing `term`) causes a follower to
/// see a spurious term conflict at a term boundary and wrongly truncate.
pub const WAL_ENTRY_REPLY_HDR: usize = 28;

#[inline]
pub fn encode_wal_entry_request(
    buf: &mut [u8; WAL_ENTRY_REQUEST_LEN],
    request_id: u32,
    wal_index: u64,
) {
    Writer::new(buf).u32(request_id).u64(wal_index);
}

#[inline]
pub fn decode_wal_entry_request(buf: &[u8]) -> Option<(u32, u64)> {
    let mut r = Reader::new(buf, WAL_ENTRY_REQUEST_LEN)?;
    let request_id = r.u32();
    let wal_index = r.u64();
    Some((request_id, wal_index))
}

#[inline]
pub fn encode_wal_entry_reply_hdr(
    buf: &mut [u8; WAL_ENTRY_REPLY_HDR],
    request_id: u32,
    term: u64,
    index: u64,
    prev_term: u64,
) {
    Writer::new(buf)
        .u32(request_id)
        .u64(term)
        .u64(index)
        .u64(prev_term);
}

#[inline]
pub fn decode_wal_entry_reply(buf: &[u8]) -> Option<(u32, u64, u64, u64, usize)> {
    let mut r = Reader::new(buf, WAL_ENTRY_REPLY_HDR)?;
    let request_id = r.u32();
    let term = r.u64();
    let index = r.u64();
    let prev_term = r.u64();
    Some((request_id, term, index, prev_term, WAL_ENTRY_REPLY_HDR))
}
/// Per-entry committed envelope emitted on `consensus.committed_entries`.
/// Payload: `[term:u64 LE][index:u64 LE][body...]`. Same body bytes the
/// proposer originally submitted via `MSG_CLIENT_PROPOSAL` (or, for
/// tagged proposals, after the 8-byte correlation_id is stripped). The
/// stream is in strict commit-index order and only contains entries
/// whose index has been observed in a `MSG_COMMITTED_BATCH` horizon.
/// Consumers MUST treat the body as opaque.
pub const MSG_COMMITTED_ENTRY: u8 = 0x24;

// Control plane
pub const MSG_CP_PROOF: u8 = 0x30;
pub const MSG_CACHE_STATE: u8 = 0x31;
pub const MSG_FALLBACK_SIGNAL: u8 = 0x32;
pub const MSG_READ_PERMIT: u8 = 0x33;

// Flow control
pub const MSG_THROTTLE_CREDITS: u8 = 0x40;
pub const MSG_THROTTLE_ENVELOPE: u8 = 0x41;
pub const MSG_LAG_SIGNAL: u8 = 0x42;
/// Additive wall-clock refill: `[entry_grant:i32][byte_grant:i32]
/// [entry_capacity:i32][byte_capacity:i32]`.
pub const MSG_THROTTLE_REFILL: u8 = 0x43;

// Snapshot
pub const MSG_SNAPSHOT_CHUNK: u8 = 0x50;
pub const MSG_SNAPSHOT_MANIFEST: u8 = 0x51;
pub const MSG_SNAPSHOT_TRIGGER: u8 = 0x52;
/// InstallSnapshot RPC (leader → follower). Payload header (33 bytes):
/// `[term:u64][last_included_index:u64][last_included_term:u64][offset:u64][done:u8][data...]`
/// `done == 1` marks the final chunk. Until then the follower accumulates
/// `data` at `offset` into a per-source buffer.
pub const MSG_INSTALL_SNAPSHOT: u8 = 0x53;
/// Follower → leader response. Payload (9 bytes): `[term:u64][success:u8]`.
pub const MSG_INSTALL_SNAPSHOT_RESP: u8 = 0x54;
/// Internal signal `durability` → `consensus` when an install
/// finishes locally. Payload (24 bytes):
/// `[term:u64][last_included_index:u64][last_included_term:u64]`.
pub const MSG_SNAPSHOT_INSTALLED: u8 = 0x55;
/// `replicator` → `durability` on-demand catch-up trigger. The replicator
/// emits this when a follower's `next_index` falls below the leader's WAL
/// retention floor (a NOT_FOUND `MSG_WAL_ENTRY_REPLY` is the canonical
/// signal). `durability` responds by emitting `MSG_INSTALL_SNAPSHOT` chunks
/// at the most recent snapshot point. Payload (1 byte):
/// `[target_replica_id:u8]` (0xFF = broadcast).
pub const MSG_SNAPSHOT_INSTALL_REQUEST: u8 = 0x56;

/// TLS peer identity from the foundation `tls` module to
/// `peer_router` and `operations`' RBAC. Fired once per accepted or
/// established TLS session. A consumer keys the connection's
/// authorisation from this record and refuses to honour any in-band
/// plaintext handshake that disagrees.
///
/// The record is fluxor's — `modules/foundation/tls/mod.rs` owns the
/// format and this is a mirror of it, not a second definition. It
/// replaced a `[conn_id][replica_id][verified][svid_len][svid]`
/// payload in which the transport was expected to name a clustor
/// replica id. It never could: fluxor has no idea what a replica is
/// and always wrote `0xFF`, which was this repo's "clear the
/// binding" sentinel, so every TLS identity envelope tore down the
/// binding it was supposed to establish. The replica id is now
/// derived where it is actually known — from the peer's own
/// handshake, cross-checked against the fingerprint below.
///
/// Payload (variable):
///   `[session_id:u32 LE]
///    [verification_result:u8]
///    [credential_kind:u8]
///    [profile_id:u16 LE]
///    [not_before:u64 LE][not_after:u64 LE]
///    [verification_flags:u32 LE]
///    [key_fp_alg:u8][key_fp_len:u8]
///    [principal_len:u16 LE]
///    [key_fingerprint:key_fp_len][principal:principal_len]`
///
/// `verification_result != PEER_RESULT_OK` clears any previously
/// bound identity for the connection: the peer offered no usable
/// credential, or one that failed a check the profile required.
pub const MSG_PEER_IDENTITY: u8 = 0x5A;

/// `MSG_PEER_IDENTITY` fixed payload size; fingerprint and principal
/// follow.
pub const PEER_IDENTITY_HDR: usize = 4 + 1 + 1 + 2 + 8 + 8 + 4 + 1 + 1 + 2;

/// Every check the profile demanded passed.
pub const PEER_RESULT_OK: u8 = 0;

/// The peer's certificate chain was validated to a configured anchor.
pub const PEER_CHECK_CHAIN: u32 = 0x0000_0001;
/// The SAN was parsed and matched the profile's name rule.
pub const PEER_CHECK_SAN: u32 = 0x0000_0008;
/// The peer proved possession of the key its credential names.
pub const PEER_CHECK_KEY_POSSESSION: u32 = 0x0000_0010;

/// A decoded `MSG_PEER_IDENTITY`, with offsets rather than slices so
/// a caller can copy out of its own scratch buffer without holding a
/// borrow across the copy.
pub struct PeerIdentity {
    pub session_id: u32,
    pub result: u8,
    pub flags: u32,
    /// Offset and length of the key fingerprint within the payload.
    pub fingerprint_at: usize,
    pub fingerprint_len: usize,
    /// Offset and length of the principal name. Empty unless the
    /// chain and the SAN were both verified — fluxor drops the name
    /// rather than report one it did not establish.
    pub principal_at: usize,
    pub principal_len: usize,
}

impl PeerIdentity {
    /// Whether this record establishes an identity worth binding: the
    /// profile's checks passed, the chain reached an anchor, and the
    /// peer proved it holds the key. A fingerprint without those is a
    /// value copied off a certificate anyone could present.
    #[inline]
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.result == PEER_RESULT_OK
            && (self.flags & PEER_CHECK_CHAIN) != 0
            && (self.flags & PEER_CHECK_KEY_POSSESSION) != 0
    }

    /// Whether the principal name may be used to authorize. Requires
    /// everything `is_established` does plus a verified SAN.
    #[inline]
    #[must_use]
    pub fn has_principal(&self) -> bool {
        self.is_established() && (self.flags & PEER_CHECK_SAN) != 0 && self.principal_len > 0
    }

    /// Connection ids are `u8` on this side; slot ids never reach 256.
    #[inline]
    #[must_use]
    pub fn conn_id(&self) -> u8 {
        (self.session_id & 0xFF) as u8
    }
}

#[inline]
#[must_use]
pub fn decode_peer_identity(buf: &[u8]) -> Option<PeerIdentity> {
    let mut r = Reader::new(buf, PEER_IDENTITY_HDR)?;
    let session_id = r.u32();
    let result = r.u8();
    // `credential_kind:u8`, `profile_id:u16`, `not_before:u64`,
    // `not_after:u64` — on the wire and counted in PEER_IDENTITY_HDR,
    // but nothing downstream of this decoder consumes them.
    r.skip(1 + 2 + 8 + 8);
    let flags = r.u32();
    r.skip(1); // key_fp_alg
    let fingerprint_len = r.u8() as usize;
    let principal_len = r.u16() as usize;
    let fingerprint_at = PEER_IDENTITY_HDR;
    let principal_at = fingerprint_at + fingerprint_len;
    if buf.len() < principal_at + principal_len {
        return None;
    }
    Some(PeerIdentity {
        session_id,
        result,
        flags,
        fingerprint_at,
        fingerprint_len,
        principal_at,
        principal_len,
    })
}

/// State-machine snapshot chunk sent from a downstream consumer to
/// `durability` (export path) or from `durability` to the
/// downstream consumer (install path). Payload (28+ bytes):
/// `[term:u64 LE][last_included_index:u64 LE][offset:u64 LE]
///  [done:u8][reserved:u8;3][body...]`. The body is opaque — only
/// the producing consumer knows how to interpret it.
pub const MSG_APP_SNAPSHOT_CHUNK: u8 = 0x57;
/// Snapshot-export trigger from `durability` to a downstream
/// consumer. Payload (16 bytes):
/// `[term:u64 LE][last_included_index:u64 LE]`. The consumer
/// responds by emitting one or more `MSG_APP_SNAPSHOT_CHUNK` messages
/// back on its `snapshot_export_out` port, terminated by `done = 1`.
pub const MSG_APP_SNAPSHOT_REQUEST: u8 = 0x58;
/// "Discard current state, replay from incoming chunks" signal from
/// `durability` to a downstream consumer after `MSG_APP_SNAPSHOT_CHUNK`
/// install begins for a snapshot ahead of the consumer's current
/// `apply_index`. Payload (16 bytes):
/// `[term:u64 LE][last_included_index:u64 LE]`.
pub const MSG_APP_SNAPSHOT_RESET: u8 = 0x59;

/// "The exported snapshot is now DURABLE" signal from `durability` to a
/// downstream consumer, emitted only after the snapshot body has been
/// written crash-atomically (`write_snapshot_durable`) AND its boot
/// pointer persisted — i.e. exactly when raft is told the local snapshot
/// is durable and the WAL compaction floor advances. Payload (16 bytes):
/// `[term:u64 LE][last_included_index:u64 LE]`.
///
/// This is the acknowledgement an app worker needs before it may advance
/// any garbage-collection floor past `last_included_index`: a consumer
/// that trusts its own export COMPLETION instead can advance the GC floor
/// onto state a crash-before-durable would force WAL replay to read as
/// compacted-away. The signal is leader-local (the durable snapshot is a
/// per-node fact); a follower learns durability through install, not this.
pub const MSG_APP_SNAPSHOT_DURABLE: u8 = 0x5B;

/// `MSG_APP_SNAPSHOT_CHUNK` fixed header size (28 bytes); body follows.
pub const APP_SNAPSHOT_HDR: usize = 28;

#[inline]
pub fn encode_app_snapshot_chunk(
    buf: &mut [u8],
    term: u64,
    last_included_index: u64,
    offset: u64,
    done: bool,
    body: &[u8],
) -> usize {
    let total = APP_SNAPSHOT_HDR + body.len();
    if buf.len() < total {
        return 0;
    }
    Writer::new(buf)
        .u64(term)
        .u64(last_included_index)
        .u64(offset)
        .u8(done as u8)
        .u8(0)
        .u8(0)
        .u8(0);
    if !body.is_empty() {
        buf[APP_SNAPSHOT_HDR..total].copy_from_slice(body);
    }
    total
}

#[inline]
pub fn decode_app_snapshot_chunk(buf: &[u8]) -> Option<(u64, u64, u64, bool, usize)> {
    let mut r = Reader::new(buf, APP_SNAPSHOT_HDR)?;
    let term = r.u64();
    let idx = r.u64();
    let offset = r.u64();
    let done = r.bool();
    Some((term, idx, offset, done, APP_SNAPSHOT_HDR))
}

pub const INSTALL_SNAPSHOT_HDR: usize = 33;

#[inline]
pub fn encode_install_snapshot(
    buf: &mut [u8],
    term: u64,
    last_included_index: u64,
    last_included_term: u64,
    offset: u64,
    done: bool,
    data: &[u8],
) -> usize {
    let total = INSTALL_SNAPSHOT_HDR + data.len();
    if buf.len() < total {
        return 0;
    }
    Writer::new(buf)
        .u64(term)
        .u64(last_included_index)
        .u64(last_included_term)
        .u64(offset)
        .u8(if done { 1 } else { 0 });
    if !data.is_empty() {
        buf[INSTALL_SNAPSHOT_HDR..total].copy_from_slice(data);
    }
    total
}

#[inline]
pub fn decode_install_snapshot(buf: &[u8]) -> Option<(u64, u64, u64, u64, bool, usize)> {
    let mut r = Reader::new(buf, INSTALL_SNAPSHOT_HDR)?;
    let term = r.u64();
    let last_idx = r.u64();
    let last_term = r.u64();
    let offset = r.u64();
    let done = r.bool();
    Some((
        term,
        last_idx,
        last_term,
        offset,
        done,
        INSTALL_SNAPSHOT_HDR,
    ))
}

/// `MSG_SNAPSHOT_INSTALLED` payload size: 24 bytes.
pub const SNAPSHOT_INSTALLED_LEN: usize = 24;

#[inline]
pub fn encode_snapshot_installed(
    buf: &mut [u8; SNAPSHOT_INSTALLED_LEN],
    term: u64,
    last_included_index: u64,
    last_included_term: u64,
) {
    Writer::new(buf)
        .u64(term)
        .u64(last_included_index)
        .u64(last_included_term);
}

#[inline]
pub fn decode_snapshot_installed(buf: &[u8]) -> Option<(u64, u64, u64)> {
    let mut r = Reader::new(buf, SNAPSHOT_INSTALLED_LEN)?;
    let term = r.u64();
    let last_idx = r.u64();
    let last_term = r.u64();
    Some((term, last_idx, last_term))
}

// Key management
pub const MSG_DEK_EPOCH: u8 = 0x60;
pub const MSG_CERT_REFRESH: u8 = 0x61;

// Telemetry
pub const MSG_METRICS: u8 = 0x70;
pub const MSG_READYZ: u8 = 0x71;
pub const MSG_WHY: u8 = 0x72;
/// Typed metric sample envelope. Replaces ad-hoc per-module `MSG_METRICS`
/// payloads with a uniform shape so `operations` can aggregate without
/// per-module parse code.
///
/// Payload (14 bytes):
/// `[module_id:u8]
///  [partition_id:u16 LE]
///  [metric_id:u16 LE]
///  [kind:u8 (0=counter, 1=gauge, 2=histogram_bucket_high_water)]
///  [value:i64 LE]`
///
/// `value` is signed so counter resets, signed credits, and gauges
/// taking on negative values all use the same slot.
pub const MSG_METRIC_SAMPLE: u8 = 0x73;
// 0x74, 0x75 and 0x79 are retired and reserved. HTTP framing is not
// clustor's: the `operations` request/response ports carry wave's own
// `HttpRequest` / `HttpResponse` envelopes, and readiness reaches the
// http component as an interior seam — seams carry no opcode and no
// stability promise (standards fluxor-modules.md §8). Do not reuse
// these ids until the sibling repos confirm no reader remains.

/// Multiplexed client record on the cleartext path. Payload is
/// `[conn_id:u8][raw client bytes]`. peer_router wraps every cleartext
/// write in this length-delimited envelope so records from different
/// conn_ids never coalesce on the byte-FIFO channel (a raw write per
/// record loses the per-record boundary and the next conn_id byte is
/// misread as stream data, silently dropping that connection).
/// Consumers demarcate with `channel_read_msg`. The id is fixed here
/// and a protocol stack in front of this router conforms to it;
/// changing it silently breaks every one of them, so it does not move.
pub const MSG_CLIENT_FRAME: u8 = 0xEA;

/// Transport-level connection-closed notice on the cleartext lane.
/// Payload `[conn_id:u8]`. peer_router emits it when a CLIENT socket
/// closes so a downstream consumer can release per-connection state
/// deterministically rather than leaking it until a timeout. The id is
/// fixed here; a consumer that does not care ignores the msg_type (the
/// gateway does).
pub const MSG_CONN_CLOSED: u8 = 0xEB;

/// Ask `peer_router` to CLOSE a client connection. Payload `[conn_id:u8]`,
/// on the same `client_resp` lane the codecs write frames to.
///
/// The inverse direction of [`MSG_CONN_CLOSED`], which is a NOTICE that a
/// socket went away. This is a command, and it exists because MQTT 3.1.1
/// has no server-initiated DISCONNECT: when placement moves a session's
/// shard, a v5 client is told `0x9D` Server moved and reconnects, but a
/// 3.1.1 client can only be informed by closing its socket. Without this
/// it stays connected to a node that no longer owns it, receives
/// nothing, and never reaches the CONNECT redirect.
pub const MSG_CONN_CLOSE_REQUEST: u8 = 0xEC;

/// Metric kinds for `MSG_METRIC_SAMPLE`.
pub const METRIC_KIND_COUNTER: u8 = 0;
pub const METRIC_KIND_GAUGE: u8 = 1;
pub const METRIC_KIND_HISTOGRAM: u8 = 2;

/// Module id space. Stable across releases — never re-number an existing
/// entry. Add new modules at the end.
pub const SOURCE_ID_RAFT: u8 = 0x01;
pub const SOURCE_ID_WAL: u8 = 0x02;
pub const SOURCE_ID_REPLICATOR: u8 = 0x03;
pub const SOURCE_ID_COMMIT: u8 = 0x04;
pub const SOURCE_ID_LEDGER: u8 = 0x05;
pub const SOURCE_ID_APPLY: u8 = 0x06;
pub const SOURCE_ID_SNAPSHOT: u8 = 0x07;
pub const SOURCE_ID_PROOF_CACHE: u8 = 0x08;
pub const SOURCE_ID_READ_GATE: u8 = 0x09;
pub const SOURCE_ID_THROTTLE: u8 = 0x0A;
pub const SOURCE_ID_FLOW: u8 = 0x0B;
pub const SOURCE_ID_CODEC: u8 = 0x0C;
pub const SOURCE_ID_SURFACE: u8 = 0x0D;
pub const SOURCE_ID_PEER_ROUTER: u8 = 0x0E;
pub const SOURCE_ID_PARTITION_ROUTER: u8 = 0x0F;
pub const SOURCE_ID_PLACEMENT: u8 = 0x10;
pub const SOURCE_ID_ADMIN: u8 = 0x11;
pub const SOURCE_ID_RBAC: u8 = 0x12;
pub const SOURCE_ID_KEYS: u8 = 0x13;
pub const SOURCE_ID_CP: u8 = 0x14;
pub const SOURCE_ID_TELEMETRY: u8 = 0x15;
pub const SOURCE_ID_NVME_BENCH: u8 = 0x16;
pub const SOURCE_ID_CONSENSUS_BENCH: u8 = 0x17;
pub const SOURCE_ID_HTTP: u8 = 0x18;
pub const SOURCE_ID_TIMING: u8 = 0x19;
// 0x1A is retired and reserved — do not reassign.

/// Per-module metric ids. Each module owns a small private space
/// (0x00..0xFF). Documented next to the module's metric emission.
pub mod metric_ids {
    // consensus — raft component (source_id = 0x01)
    pub const RAFT_ROLE: u16 = 0x0001;
    pub const RAFT_CURRENT_TERM: u16 = 0x0002;
    pub const RAFT_PROPOSALS_RECEIVED: u16 = 0x0003;
    pub const RAFT_ENTRIES_APPENDED: u16 = 0x0004;
    pub const RAFT_ELECTIONS_STARTED: u16 = 0x0005;
    pub const RAFT_PROPOSALS_DROPPED_FROZEN: u16 = 0x0006;
    pub const RAFT_PROPOSALS_DROPPED_STRICT: u16 = 0x0007;
    pub const RAFT_FROZEN_FLAG: u16 = 0x0008;
    pub const RAFT_STRICT_FALLBACK_FLAG: u16 = 0x0009;
    /// Counter: proposal-batch flushes deferred because `wal.entries`
    /// (out_log) had no write space — the durability-backpressure signal.
    /// Non-zero means raft held the log at WAL durability rather than
    /// over-producing; sustained growth = WAL-bound plateau.
    pub const RAFT_FLUSHES_DEFERRED: u16 = 0x000A;
    /// Gauge: uncommitted-inflight window (`last_log_index - commit_index`).
    /// Sitting at `MAX_UNCOMMITTED_INFLIGHT` means the leader is holding
    /// intake to keep the log from running past quorum-durable commit.
    pub const RAFT_UNCOMMITTED_INFLIGHT: u16 = 0x000B;
    /// Gauge: raft's `last_log_index` (highest appended index). After a
    /// crash-recovery boot this reflects whether raft RESUMED its index from
    /// the persisted metadata (high) or restarted fresh (low) — the L4
    /// recovery-coherence diagnostic.
    pub const RAFT_LAST_LOG_INDEX: u16 = 0x000C;
    /// Gauge: raft's own `commit_index` view (fed from consensus).
    pub const RAFT_COMMIT_INDEX: u16 = 0x000D;
    /// Gauge: 1 while raft is holding proposal intake awaiting the WAL's
    /// replay-complete high-water (recovery boot), else 0. Diagnostic.
    pub const RAFT_AWAITING_REPLAY: u16 = 0x000E;
    /// Gauge: the WAL replay high-water raft last RESUMED at via
    /// MSG_WAL_REPLAY_COMPLETE (0 if none received). Diagnostic.
    pub const RAFT_REPLAY_HW: u16 = 0x000F;
    /// Gauge: log index raft loaded from its metadata slots at boot
    /// (0 = fresh).
    pub const RAFT_META_HINT: u16 = 0x0010;
    /// Counter: Raft §5.3 conflict-repair truncations driven (divergent
    /// suffix discarded). Steady-state replication should hold this at 0;
    /// non-zero marks log divergence + repair (e.g. post-failover).
    pub const RAFT_LOG_TRUNCATIONS: u16 = 0x0011;
    /// Gauge (readiness sub-signal): 1 once boot replay is complete,
    /// metadata is loaded, no truncation is outstanding (a node holding
    /// one refuses every AppendEntries, so it is not carrying
    /// replication), and consensus is established (we are leader, or we
    /// know the leader). Consumed by operations to drive a real
    /// `/readyz` instead of a fixed boot timer. 0 until all four hold.
    pub const RAFT_READY: u16 = 0x0012;
    /// Counter: WAL continuity rejections repaired — times raft rolled its
    /// tip back to the index the WAL actually holds (`MSG_WAL_REJECT`).
    /// Steady state is 0. Non-zero means raft's log had claimed entries the
    /// WAL never persisted; sustained growth means something upstream is
    /// repeatedly desynchronising the two.
    pub const RAFT_WAL_RESYNCS: u16 = 0x0013;
    /// Counter: appends held because the log was already `MAX_WAL_UNACKED`
    /// ahead of the local durable index. Non-zero = the WAL is the
    /// bottleneck and durability backpressure is engaging (healthy under
    /// load); it is what keeps the log from diverging from the WAL.
    pub const RAFT_WAL_UNACKED_HOLDS: u16 = 0x0014;
    /// Counter: AppendEntries refused because the carried `entry_index` was
    /// not `last_log_index + 1` even though `prev_log_*` matched — i.e. the
    /// leader shipped a mis-sequenced entry. Refusing turns what would have
    /// been an unrepairable WAL hole into ordinary Raft log repair.
    pub const RAFT_AE_NONCONTIGUOUS: u16 = 0x0015;
    /// Counter: hard Raft metadata persist failures (term/vote/durable
    /// hint could not be written). Steady state 0. Non-zero means the
    /// node's stable term/vote store is broken: vote grants and
    /// election starts are being withheld (they gate on the persist),
    /// so the node follows and serves but cannot move elections.
    /// Transient FS-initialising outcomes are not counted.
    pub const RAFT_META_WRITE_ERRORS: u16 = 0x0016;
    /// Counter: AppendEntries held (`busy`) because a conflict-repair
    /// truncation was still unacknowledged by the WAL. Non-zero means
    /// log repair is waiting on durability, which is the fail-closed
    /// behaviour; sustained growth means the WAL cannot complete the
    /// truncation and this node is stuck out of the repair path.
    pub const RAFT_TRUNCATE_HOLDS: u16 = 0x0017;
    /// Counter: truncation requests the WAL refused as not durable.
    /// Steady state 0. Non-zero means the new log tail could not be
    /// persisted; the old tip is retained and the request is re-sent.
    pub const RAFT_TRUNCATE_NACKS: u16 = 0x0018;
    /// Gauge: the provider's name-publication disposition for the
    /// election-metadata slots. `0` = not probed, `1` =
    /// `caps::FSYNC_NAME` advertised and each slot's name is fenced
    /// when it is created, `2` = absent.
    pub const RAFT_NAME_FENCE: u16 = 0x0019;
    /// Counter: metadata slot names published without a name fence
    /// because the provider does not advertise `caps::FSYNC_NAME`. In
    /// the strict posture this is always 0 — the publication is
    /// refused instead, so a non-zero value is the auto posture
    /// reporting what it could not fence.
    pub const RAFT_NAME_UNFENCED: u16 = 0x001A;
    /// Counter: AppendEntries answered without a verdict because the
    /// follower's tail ring held no term for the index the leader named.
    /// The follower keeps its log and reports its tip; the leader's next
    /// append past that tip resolves it. Steady state 0; a climbing value
    /// on a node that just restarted means its WAL replay acks are not
    /// reaching raft.
    pub const RAFT_AE_UNVERIFIED: u16 = 0x001B;

    // wal (module_id = 0x02)
    pub const WAL_ENTRIES_WRITTEN: u16 = 0x0001;
    pub const WAL_BYTES_WRITTEN: u16 = 0x0002;
    pub const WAL_SEGMENT_SEQ: u16 = 0x0003;
    /// UpDownCounter: entries written but not yet group-fsynced.
    pub const WAL_PENDING_DEPTH: u16 = 0x0004;
    /// Gauge: last FS_OPEN_CREATE return (>=0 = disk fd, <0 = errno;
    /// in-memory fallback diagnostic).
    pub const WAL_OPEN_RC: u16 = 0x0005;
    /// Counter: module_step invocations (frozen = not being stepped).
    pub const WAL_STEPS: u16 = 0x0006;
    /// Gauge: high-water (current_index) the WAL handed raft in
    /// MSG_WAL_REPLAY_COMPLETE (0 until emitted). Diagnostic.
    pub const WAL_REPLAY_HW: u16 = 0x0007;
    /// Counter: entries re-emitted during boot replay. Diagnostic — lets a
    /// scraper tell replayed entries apart from fresh appends in
    /// `entries_written`.
    pub const WAL_REPLAYED: u16 = 0x0008;
    /// Gauge: FS_STAT size (bytes) of the FIRST segment opened during replay.
    /// Diagnostic — distinguishes a physically-truncated on-disk segment from
    /// a read-back that stops at a cluster boundary.
    pub const WAL_REPLAY_FSIZE: u16 = 0x0009;
    /// Counter: entry-request lookups that hit (served a body). Diagnostic.
    pub const WAL_ENTRYREQ_SERVED: u16 = 0x000A;
    /// Counter: entry-request lookups that returned NOT_FOUND (below ring /
    /// disk read failed). Diagnostic for the apply-refetch stall.
    pub const WAL_ENTRYREQ_NOTFOUND: u16 = 0x000B;
    /// Counter: durable-write failures (FS_WRITE short/error, FS_FSYNC error,
    /// or segment open failure). Non-zero means entries went un-acked rather
    /// than being falsely reported durable.
    pub const WAL_WRITE_ERRORS: u16 = 0x000C;
    /// Counter: WAL replay entries rejected because the stored CRC32C did not
    /// match the recomputed payload checksum (torn / corrupt entry). A torn
    /// tail stops replay at that point rather than replaying garbage.
    pub const WAL_CHECKSUM_FAILURES: u16 = 0x000D;
    /// Counter: WAL log-suffix truncations applied (Raft §5.3 conflict
    /// repair discarded a divergent uncommitted tail).
    pub const WAL_TRUNCATIONS: u16 = 0x000E;
    /// Gauge: live byte grant resolved from the classed WAL input edge.
    pub const WAL_INPUT_BUDGET_BYTES: u16 = 0x000F;
    /// Gauge: records persisted by the most recent non-empty input pump.
    pub const WAL_PUMP_RECORDS: u16 = 0x0010;
    /// Counter: non-contiguous append indices observed at the WAL input.
    pub const WAL_CONTINUITY_ERRORS: u16 = 0x0011;
    /// Counter: records consumed from the input channel that could not be
    /// staged this step and were STASHED for re-drive rather than dropped.
    /// Non-zero is healthy backpressure at the WAL; it is what keeps the
    /// index sequence contiguous. (Dropping them was the cause of the
    /// continuity faults this counter now prevents.)
    pub const WAL_STASHED_HOLDS: u16 = 0x0012;
    /// Gauge: the WAL's own `current_index` — the value continuity is
    /// compared against. Distinct from `entries_written` (a count, which
    /// diverges from the index across replay/ephemeral paths).
    pub const WAL_CURRENT_INDEX: u16 = 0x0013;
    /// Gauge: index the WAL expected / actually got at the first continuity
    /// break. The pair IS the diagnosis.
    pub const WAL_FAULT_EXPECTED: u16 = 0x0014;
    pub const WAL_FAULT_GOT: u16 = 0x0015;
    /// Counter: truncation requests refused because the new tail could
    /// not be made durable. Nothing was published for these: the
    /// high-water is unchanged and the requester keeps its old tip.
    pub const WAL_TRUNCATE_FAILURES: u16 = 0x0016;
    /// Gauge: how the current segment file is being written.
    /// `0` = dynamically grown because fixed segments were not
    /// requested, `1` = protected fixed-capacity operation
    /// (`PREALLOCATE` active), `2` = compatibility fallback — fixed
    /// segments were requested but the provider has no `PREALLOCATE`,
    /// so the segment grows dynamically. `2` is the only value where
    /// the configured mode and the achieved mode differ.
    pub const WAL_SEGMENT_MODE: u16 = 0x0017;
    /// Counter: segment admissions refused because `PREALLOCATE`
    /// reported an allocation or device failure rather than a missing
    /// opcode. A full disk or a failing device never becomes a
    /// different segment mode; the segment stays unopened and entries
    /// go un-acked.
    pub const WAL_PREALLOCATE_FAILURES: u16 = 0x0018;
    /// Gauge: the errno of the most recent `PREALLOCATE` refusal
    /// (negative), or `0` when preallocation has never been refused.
    /// Pairs with `WAL_SEGMENT_MODE` to say WHY a node is not in
    /// protected fixed-segment operation.
    pub const WAL_PREALLOCATE_ERRNO: u16 = 0x0019;
    /// Gauge: the provider's name-publication disposition. `0` = not
    /// probed yet, `1` = `caps::FSYNC_NAME` advertised and every
    /// segment name is fenced, `2` = absent.
    pub const WAL_NAME_FENCE: u16 = 0x001A;
    /// Counter: segment names created or retired without a name fence
    /// because the provider does not advertise `caps::FSYNC_NAME`. In
    /// the strict posture this is always 0 — the publication is
    /// refused instead.
    pub const WAL_NAME_UNFENCED: u16 = 0x001B;
    /// Counter: compactions whose trim point a retention floor (an
    /// application's window, or the slowest voter's match) pulled
    /// below the snapshot index. Rising means the floor, not the
    /// snapshot cadence, bounds disk.
    pub const WAL_COMPACT_FLOORED: u16 = 0x001C;

    // replicator (module_id = 0x03)
    pub const REPL_RPCS_SENT: u16 = 0x0001;
    pub const REPL_ACKS_RECEIVED: u16 = 0x0002;
    pub const REPL_NACKS_RECEIVED: u16 = 0x0003;
    pub const REPL_CATCHUP_SENT: u16 = 0x0004;
    /// UpDownCounter: AppendEntries RPCs in flight (sent, not yet acked).
    pub const REPL_INFLIGHT_DEPTH: u16 = 0x0005;
    /// Counter: failure responses caused by follower WAL backpressure (busy),
    /// as distinct from log-divergence NACKs. Retire an in-flight RPC without
    /// rolling next_index back.
    pub const REPL_BACKPRESSURE: u16 = 0x0006;
    /// Gauge: consecutive leader steps that replicated nothing because the
    /// WAL has not answered a tip probe (`last_emitted_index == 0`). 0 in
    /// steady state INCLUDING an idle leader with nothing to ship; sustained
    /// non-zero on a leader means it is silently not replicating at all.
    pub const REPL_TIP_UNRESOLVED: u16 = 0x0007;
    /// Counter: snapshot-install escalations dropped because the
    /// `snapshot_request` port is unwired. Non-zero = a follower has fallen
    /// past this WAL's read-back retention and this graph cannot recover it.
    pub const REPL_SNAPSHOT_DROPPED: u16 = 0x0008;

    // consensus — commit component (source_id = 0x04)
    pub const COMMIT_INDEX: u16 = 0x0001;
    pub const COMMIT_ADVANCES: u16 = 0x0002;

    // durability (module_id = 0x07)
    pub const SNAP_SNAPSHOTS_TAKEN: u16 = 0x0001;
    pub const SNAP_CHUNKS_IMPORTED: u16 = 0x0002;
    pub const SNAP_TRIGGERS_DEFERRED: u16 = 0x0003;
    /// Counter: snapshot body bytes durably written to disk.
    pub const SNAP_BYTES_WRITTEN: u16 = 0x0004;
    /// Counter: durable-install failures (short write / fsync error) — the
    /// install signal was withheld so consensus never trusts a torn body.
    pub const SNAP_INSTALL_FAILURES: u16 = 0x0005;
    /// Counter: complete app-snapshot bodies received from the state
    /// machine.
    pub const SNAP_APP_BODIES_RECEIVED: u16 = 0x0006;
    /// Counter: app-snapshot captures that timed out with no body — the
    /// app refused (capacity denial) or is wedged; either way the WAL
    /// cannot compact until a capture completes.
    pub const SNAP_APP_CAPTURES_TIMED_OUT: u16 = 0x0007;
    /// Gauge: the provider's name-publication disposition for snapshot
    /// artefacts and pointer slots. `0` = not probed, `1` =
    /// `caps::FSYNC_NAME` advertised, `2` = absent.
    pub const SNAP_NAME_FENCE: u16 = 0x0008;
    /// Counter: snapshot names published or retired without a name
    /// fence. Non-zero means a recovery root's discoverability rests
    /// on the provider's own flushing policy; the strict posture
    /// refuses the publication instead and leaves this at 0.
    pub const SNAP_NAME_UNFENCED: u16 = 0x0009;

    // consensus — apply component (source_id = 0x06)
    pub const APPLY_ENTRIES_APPLIED: u16 = 0x0001;
    pub const APPLY_DEDUP_DROPS: u16 = 0x0002;
    /// UpDownCounter: committed entries queued, not yet delivered.
    pub const APPLY_QUEUE_DEPTH: u16 = 0x0003;
    /// Counter: committed entries refetched from the WAL after the lossy
    /// `log_observe` fan-out dropped the body under overdrive (apply-side
    /// gap recovery). Non-zero means the observer stream gapped but apply
    /// stayed lossless by reading the durable entry back from the WAL.
    pub const APPLY_REFETCHED: u16 = 0x0004;
    /// Gauge (readiness sub-signal): 1 when the apply cursor has caught up to
    /// the committed horizon (`apply_index >= commit_horizon`). Consumed by
    /// the operations module's real `/readyz`.
    pub const APPLY_CAUGHT_UP: u16 = 0x0005;
    /// Counter: pending committed entries evicted from the body buffer before
    /// they could be applied (overdrive backpressure surfaced as a drop).
    pub const APPLY_ENTRIES_EVICTED: u16 = 0x0006;
    /// Counter: refetch read-back slots evicted before consumption.
    pub const APPLY_READS_EVICTED: u16 = 0x0007;
    /// Counter: apply passes that ended holding a committed entry one of
    /// its destinations refused (client ack, admin seam, or the
    /// per-entry stream). NOT a loss count — the entry keeps its buffer
    /// slot and is re-offered on the next step, and `apply_index` is
    /// deliberately frozen behind it. A value climbing steadily means a
    /// consumer has stopped draining; `APPLY_CAUGHT_UP` will read 0 for
    /// the same reason.
    pub const APPLY_DELIVERY_STALLS: u16 = 0x0008;

    // the http component (module_id = 0x18)
    pub const HTTP_CORRELATIONS_INFLIGHT: u16 = 0x0001;
    pub const HTTP_INDICES_INFLIGHT: u16 = 0x0002;
    pub const HTTP_INFLIGHT_HIGH_WATER: u16 = 0x0003;
    pub const HTTP_PROPOSAL_TIMEOUTS: u16 = 0x0004;
    pub const HTTP_COMMIT_TIMEOUTS: u16 = 0x0005;
    pub const HTTP_ASSIGNMENTS_UNMATCHED: u16 = 0x0006;
    pub const HTTP_ASSIGNMENTS_NO_SLOT: u16 = 0x0007;
    pub const HTTP_APPLIES_UNMATCHED: u16 = 0x0008;
    pub const HTTP_REJECTIONS: u16 = 0x0009;
    pub const HTTP_QUEUE_UNAVAILABLE: u16 = 0x000A;
    pub const HTTP_COMMITTED: u16 = 0x000B;
    pub const HTTP_REQUESTS: u16 = 0x000C;
    pub const HTTP_REQUESTS_404: u16 = 0x000D;
    pub const HTTP_RESPONSES_DROPPED: u16 = 0x000E;
    pub const HTTP_ADMIN_DROPPED: u16 = 0x000F;

    // the gateway's throttle (module_id = 0x0A)
    pub const THROTTLE_ADMITTED: u16 = 0x0001;
    pub const THROTTLE_REJECTED: u16 = 0x0002;

    // admission (module_id = 0x0B)
    /// UpDownCounter: remaining entry-credit pool.
    pub const FLOW_ENTRY_CREDITS: u16 = 0x0001;
    /// UpDownCounter: remaining byte-credit pool.
    pub const FLOW_BYTE_CREDITS: u16 = 0x0002;

    // peer_router (module_id = 0x0E)
    /// UpDownCounter: open peer connections.
    pub const PEER_CONNECTIONS_OPEN: u16 = 0x0001;
    /// Counter: total data bytes received from the network.
    pub const PEER_BYTES_IN: u16 = 0x0002;
    /// Counter: total data bytes sent to the network.
    pub const PEER_BYTES_OUT: u16 = 0x0003;
    /// Counter: frames the router dropped (oversize chunk / route
    /// frame / undeliverable response).
    pub const PEER_FRAMES_DROPPED: u16 = 0x0004;
    /// Counter: outbound peer writes `net_out` refused and retried. A
    /// rising count means the peer net edge is undersized for the
    /// traffic; nothing was lost.
    pub const PEER_TX_REFUSED: u16 = 0x0005;
    /// Counter: client chunks the `cleartext` consumer refused and the
    /// router retained (see `peer_router::client_stash`). A refusal
    /// used as a drop corrupts that connection's protocol stream for
    /// good — the codec parses a continuous byte stream — so the chunk
    /// is held and inbound draining pauses until it lands. Steady
    /// state 0; a climbing value means the codec's input edge is too
    /// small for the connection count.
    pub const PEER_CLIENT_REFUSED: u16 = 0x0006;

    // operations (module_id = 0x15) — the aggregator's self-metrics.
    pub const TELE_MESSAGES_INGESTED: u16 = 0x0001;
    pub const TELE_TYPED_SAMPLES: u16 = 0x0002;
    pub const TELE_METRIC_SLOTS_USED: u16 = 0x0003;
    /// Counter: metric-table slots evicted (oldest-write LRU) because the
    /// fixed table filled. Non-zero means the table is undersized for the
    /// live metric cardinality — surfaces silent loss before it bites.
    pub const TELE_METRICS_EVICTED: u16 = 0x0004;
    /// Counter: export records dropped this scrape because the ~8 KiB channel
    /// ring budget was hit (table tail or per-module step histograms). Makes
    /// export truncation observable instead of silent.
    pub const TELE_RECORDS_DROPPED: u16 = 0x0005;

    // nvme_bench (module_id = 0x16) — L0 NVMe floor bench.
    pub const NVBENCH_PHASE: u16 = 0x0001;
    pub const NVBENCH_BYTES_WRITTEN: u16 = 0x0002;
    pub const NVBENCH_SEQ_KBPS: u16 = 0x0003;
    pub const NVBENCH_RAND_KBPS: u16 = 0x0004;
    pub const NVBENCH_FSYNCS: u16 = 0x0005;
    pub const NVBENCH_STEPS: u16 = 0x0006;
    pub const NVBENCH_OPEN_RC: u16 = 0x0007;
    pub const NVBENCH_OPEN_RETRIES: u16 = 0x0008;
    pub const NVBENCH_VERIFY_FAIL: u16 = 0x0009;
    /// Counter: failed FS_WRITE/FS_SEEK/FS_FSYNC ops (short write, errno).
    /// Non-zero invalidates the throughput figures for the run.
    pub const NVBENCH_IO_ERRORS: u16 = 0x000A;
    /// Gauge: 0 = synchronous QD1 tier, 1 = pipelined async-fence tier.
    pub const NVBENCH_IO_MODE: u16 = 0x000B;
    /// Counter: durability fences opened (`FS_FSYNC_SUBMIT`).
    pub const NVBENCH_FENCES_SUBMITTED: u16 = 0x000C;
    /// Counter: durability fences reaped durable (`FS_FSYNC_POLL` == 0).
    pub const NVBENCH_FENCES_DONE: u16 = 0x000D;
    /// Gauge: fences currently in flight. Sitting below the configured
    /// depth with no backpressure means the bench, not the device, is
    /// the limiter.
    pub const NVBENCH_FENCES_OUTSTANDING: u16 = 0x000E;
    /// Counter: `FS_WRITE_ASYNC` backpressure events (E_AGAIN or short).
    pub const NVBENCH_WRITE_AGAIN: u16 = 0x000F;
    /// Counter: `FS_FSYNC_SUBMIT` backpressure events (E_AGAIN).
    pub const NVBENCH_FENCE_AGAIN: u16 = 0x0010;

    // consensus_bench (module_id = 0x17) — L2 consensus load injector.
    pub const CBENCH_PHASE: u16 = 0x0001;
    pub const CBENCH_PROPOSALS_SENT: u16 = 0x0002;
    pub const CBENCH_BLOCKED: u16 = 0x0003;

    // timing (source_id = 0x19) — deterministic replicated timing, emitted
    // by the deadline-enabled consumer module (session_directory today).
    /// Gauge: committed PRG logical time (ms since epoch).
    pub const TIMING_LOGICAL_TIME_MS: u16 = 0x0001;
    /// Gauge: disciplined wall time minus logical time on the leader
    /// (staleness / lateness signal). 0 on followers.
    pub const TIMING_LOGICAL_LAG_MS: u16 = 0x0002;
    /// Counter: committed TimeAdvance entries applied.
    pub const TIMING_ADVANCE_TOTAL: u16 = 0x0003;
    /// Counter: committed TimeDrain entries applied.
    pub const TIMING_DRAIN_TOTAL: u16 = 0x0004;
    /// Gauge: live deadlines in the index.
    pub const TIMING_DEADLINES_ACTIVE: u16 = 0x0005;
    /// Gauge: due-but-undelivered backlog (drain depth).
    pub const TIMING_DUE_DEPTH: u16 = 0x0006;
    /// Counter: due handlers that performed their domain transition.
    pub const TIMING_FIRED_TOTAL: u16 = 0x0007;
    /// Counter: due handlers that were deterministic no-ops
    /// (generation mismatch / object gone).
    pub const TIMING_NOOP_TOTAL: u16 = 0x0008;
    /// Gauge: why time production is paused on this node
    /// (`TIMING_PAUSE_*`), 0 = producing / not applicable.
    pub const TIMING_PAUSE_REASON: u16 = 0x0009;
}

/// `TIMING_PAUSE_REASON` gauge values.
pub const TIMING_PAUSE_NONE: u8 = 0;
pub const TIMING_PAUSE_NOT_LEADER: u8 = 1;
pub const TIMING_PAUSE_CLOCK_ALARM: u8 = 2;
pub const TIMING_PAUSE_DRAIN_BACKLOG: u8 = 3;
pub const TIMING_PAUSE_IDLE: u8 = 4;

/// Fixed-bucket histograms.
///
/// Each histogram occupies a contiguous per-module `metric_id` range
/// starting at [`hist::HIST_BASE`]: bucket `i` is emitted as a
/// `METRIC_KIND_HISTOGRAM` sample at `metric_id = HIST_BASE + i`,
/// `value = cumulative count in that bucket` (monotone high-water).
/// There are `bounds.len() + 1` buckets — the final one is the implicit
/// `+Inf` overflow bucket, so saturation of the top bucket is itself a
/// signal. Bounds are stored in the producer's native sampling unit
/// (µs or ms) so classification stays integer-only in `no_std`.
pub mod hist {
    /// First `metric_id` of any histogram bucket range. Chosen above the
    /// scalar `metric_ids` space so the two never collide within a module.
    pub const HIST_BASE: u16 = 0x1000;

    /// First `metric_id` for the operations module's PER-MODULE kernel step-timing
    /// histogram. Each scheduler module's 8 step buckets are
    /// emitted under `module_id = SOURCE_ID_TELEMETRY`,
    /// `partition_id = scheduler_module_idx`, `metric_id = STEP_PERMOD_BASE + i`
    /// — distinct from the global step histogram (which uses HIST_BASE,
    /// partition 0) so the two never collide.
    pub const STEP_PERMOD_BASE: u16 = 0x1100;

    /// `clustor.wal.fsync_latency_ms` — inclusive upper bounds, microseconds.
    pub const FSYNC_LATENCY_US: [u64; 15] = [
        250, 500, 1_000, 2_000, 4_000, 6_000, 8_000, 10_000, 15_000, 20_000, 30_000, 40_000,
        60_000, 80_000, 100_000,
    ];
    /// `clustor.raft.commit_latency_ms` — inclusive upper bounds, microseconds.
    pub const COMMIT_LATENCY_US: [u64; 14] = [
        500, 1_000, 2_000, 4_000, 6_000, 8_000, 10_000, 15_000, 20_000, 30_000, 40_000, 60_000,
        80_000, 100_000,
    ];
    /// `clustor.flow.apply_batch_latency_ms` — inclusive upper bounds, microseconds.
    pub const APPLY_BATCH_US: [u64; 8] = [250, 500, 1_000, 2_000, 4_000, 6_000, 8_000, 10_000];
    /// `clustor.snapshot.transfer_seconds` — inclusive upper bounds, milliseconds.
    pub const SNAPSHOT_MS: [u64; 9] = [
        1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000,
    ];

    /// Per-component step-time histogram (fluxor-modules.md §8 rule 8)
    /// — inclusive upper bounds, microseconds. Mirrors the kernel
    /// scheduler's per-module step bucket edges (`<2, <4, <8, <16,
    /// <32, <64, <256 µs, +Inf` expressed as inclusive integer-µs
    /// bounds) so component and module histograms compare directly.
    pub const COMP_STEP_US: [u64; 7] = [1, 3, 7, 15, 31, 63, 255];

    /// First `metric_id` of the per-component step histogram range.
    /// Bucket i is emitted at `COMP_STEP_BASE + i` under
    /// `module_id = SOURCE_ID_<component>` — distinct from HIST_BASE
    /// (module-scalar histograms) and STEP_PERMOD_BASE (kernel
    /// per-slot step histograms) so the three never collide.
    pub const COMP_STEP_BASE: u16 = 0x1200;

    /// Classify `v` (same unit as `bounds`) into a bucket index in
    /// `0..=bounds.len()`. The returned index is the first bound `v`
    /// is `<=`; `bounds.len()` is the `+Inf` overflow bucket.
    #[inline]
    #[must_use]
    pub fn bucket(bounds: &[u64], v: u64) -> usize {
        let mut i = 0usize;
        while i < bounds.len() {
            if v <= bounds[i] {
                return i;
            }
            i += 1;
        }
        bounds.len()
    }
}

/// `/metrics` export payload (operations → the http component → `GET /metrics`).
///
/// Layout: `[magic:u8=0xC7][version:u8=1][record_count:u16 LE]` followed by
/// `record_count` 14-byte records, each identical to the
/// [`MSG_METRIC_SAMPLE`] body (`encode_metric_sample`): `module_id:u8`,
/// `partition_id:u16 LE`, `metric_id:u16 LE`, `kind:u8`, `value:i64 LE`.
/// A scraper iterates fixed-width records with no per-module parser.
pub const METRICS_EXPORT_MAGIC: u8 = 0xC7;
pub const METRICS_EXPORT_VERSION: u8 = 1;
pub const METRICS_EXPORT_HDR: usize = 4;
pub const METRICS_RECORD_LEN: usize = METRIC_SAMPLE_LEN;

/// `MSG_METRIC_SAMPLE` payload size (14 bytes).
pub const METRIC_SAMPLE_LEN: usize = 14;

#[inline]
pub fn encode_metric_sample(
    buf: &mut [u8; METRIC_SAMPLE_LEN],
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
) {
    Writer::new(buf)
        .u8(module_id)
        .u16(partition_id)
        .u16(metric_id)
        .u8(kind)
        .i64(value);
}

#[inline]
pub fn decode_metric_sample(buf: &[u8]) -> Option<(u8, u16, u16, u8, i64)> {
    let mut r = Reader::new(buf, METRIC_SAMPLE_LEN)?;
    let module_id = r.u8();
    let partition_id = r.u16();
    let metric_id = r.u16();
    let kind = r.u8();
    let value = r.i64();
    Some((module_id, partition_id, metric_id, kind, value))
}

// Session directory (fluxor / — the replicated session-registry
// consumer in `modules/app/session_directory/`).
//
// `MSG_SR_REQUEST`: anchor/orchestrator → session_directory. Payload:
// `[request_id:u64 LE][session_registry command body]` where the body
// is one of the `SR_OP_*` layouts in `modules/common/session_registry.rs`
// (opcode byte first). The directory replays the body verbatim as a
// tagged raft proposal; the reply is sent ONLY after the command is
// quorum-committed and applied — the R2/R5 "durable before ack"
// invariant lives on this boundary.
//
// `MSG_SR_REPLY`: session_directory → requester. Payload:
// `[request_id:u64 LE][SessionReply (SR_REPLY_LEN bytes)]`.
pub const MSG_SR_REQUEST: u8 = 0x90;
pub const MSG_SR_REPLY: u8 = 0x91;

// Routing
pub const MSG_PLACEMENT_UPDATE: u8 = 0x80;

// ── Shard map ────────────────────────────────────────────────────────────────
//
// Which Partition Raft Group owns a virtual shard. The control plane
// owns this mapping; `partition_router` consumes it.
//
// The map is a MODULO BASELINE plus SPARSE OVERRIDES, not a dense table. A
// dense `VIRTUAL_SHARDS`-entry array is 512 KiB, which no module can hold
// and no channel should carry; and at steady state the baseline is what
// every shard uses anyway. An override exists only for a shard the control
// plane has deliberately placed somewhere other than its baseline — which is
// exactly what a migration produces, a bounded batch at a time (: a
// migration moves a named shard list, not the whole space).
//
// The override table is what makes a MIGRATION cheap. A RESIZE is cheap
// because of the baseline: `baseline_prg` is a jump consistent hash, so
// growing the PRG count from N to N+1 moves exactly the 1/(N+1) of shards
// that land on the new PRG and nothing else, and shrinking moves only the
// departing PRG's shards. No dense map is needed for either.

/// Shard-map update. Payload:
///   `[epoch:u64 LE][count:u16 LE]` then `count` × `[shard:u32 LE][prg:u16 LE]`.
///
/// An entry maps one virtual shard to the group that owns it,
/// overriding the modulo baseline. `prg == SHARD_OVERRIDE_CLEAR`
/// removes the override and returns the shard to its baseline.
pub const MSG_SHARD_MAP_UPDATE: u8 = 0x81;

/// Header length of a [`MSG_SHARD_MAP_UPDATE`] payload.
/// Largest override set a consumer is required to hold, and therefore
/// the largest batch one migration may move.
///
/// The wire contract states it because the PRODUCER must not emit a map
/// bigger than every consumer can apply: a consumer that dropped the
/// tail would resolve those shards to their baseline owner while other
/// nodes used the override, which is split ownership. Quantum's
/// `edge_routing_core::MAX_SHARD_OVERRIDES` is sized to match.
pub const SHARD_MAP_MAX_ENTRIES: usize = 256;

pub const SHARD_MAP_HDR: usize = 10;
/// Bytes per shard-map entry.
pub const SHARD_MAP_ENTRY: usize = 6;
/// `prg` value that clears an override rather than setting one.
/// `0xFFFF` is already wire-reserved as "never a real partition id".
pub const SHARD_OVERRIDE_CLEAR: u16 = 0xFFFF;

// ── Migration state machine ──────────────────────────────────────────────────
//
// One executable, durable state machine covers every elastic operation:
// shard move, PRG activation, node add, node drain, replica move.
//
//   PLANNED -> PROVISIONING -> COPYING -> CATCHING_UP -> FENCED
//           -> ACTIVE -> RETIRING -> DONE
//                     \
//                      -> ABORTED   (only before FENCED)
//
// The phase is written to the durable record BEFORE the work of that
// phase begins (MIG-DURABLE), so a controller crash resumes by reading
// the phase and re-running it — which every phase must tolerate
// (MIG-IDEMPOTENT). FENCED is the point of no return (MIG-ONEWAY):
// before it, abort restores the old map at the old epoch; after it, the
// target has begun accepting and only roll-forward is safe.

pub const MIG_PLANNED: u8 = 0;
pub const MIG_PROVISIONING: u8 = 1;
pub const MIG_COPYING: u8 = 2;
pub const MIG_CATCHING_UP: u8 = 3;
pub const MIG_FENCED: u8 = 4;
pub const MIG_ACTIVE: u8 = 5;
pub const MIG_RETIRING: u8 = 6;
pub const MIG_DONE: u8 = 7;
pub const MIG_ABORTED: u8 = 8;

/// True when `phase` is past the point of no return. Abort is refused
/// from here on: the target has begun accepting at the new epoch, so
/// restoring the old placement would give two groups the same shards.
#[inline]
pub fn mig_is_committed(phase: u8) -> bool {
    matches!(phase, MIG_FENCED | MIG_ACTIVE | MIG_RETIRING | MIG_DONE)
}

/// True when `phase` is terminal — no further transition is legal.
#[inline]
pub fn mig_is_terminal(phase: u8) -> bool {
    matches!(phase, MIG_DONE | MIG_ABORTED)
}

/// The phase that follows `phase` on the success path, or `None` at a
/// terminal phase.
#[inline]
pub fn mig_next(phase: u8) -> Option<u8> {
    match phase {
        MIG_PLANNED => Some(MIG_PROVISIONING),
        MIG_PROVISIONING => Some(MIG_COPYING),
        MIG_COPYING => Some(MIG_CATCHING_UP),
        MIG_CATCHING_UP => Some(MIG_FENCED),
        MIG_FENCED => Some(MIG_ACTIVE),
        MIG_ACTIVE => Some(MIG_RETIRING),
        MIG_RETIRING => Some(MIG_DONE),
        _ => None,
    }
}

/// Whether `from -> to` is a legal transition.
///
/// Advancing one step on the success path is legal; so is aborting, but
/// only from a phase that has not yet fenced. Everything else — a skip,
/// a rewind, a move out of a terminal phase — is refused, so a
/// controller bug cannot walk a migration into a state its invariants
/// were never checked against.
#[inline]
pub fn mig_transition_ok(from: u8, to: u8) -> bool {
    if mig_is_terminal(from) {
        return false;
    }
    if to == MIG_ABORTED {
        return !mig_is_committed(from);
    }
    mig_next(from) == Some(to)
}

/// Migration record payload:
///   `[migration_id:u64 LE][phase:u8][source_prg:u16 LE][target_prg:u16 LE]`
///   `[epoch:u64 LE][shard_count:u16 LE][deadline_ms:u64 LE]`
pub const MIGRATION_RECORD_LEN: usize = 35;

/// Activate a hosted Raft group at runtime — the WORK of a migration's
/// PROVISIONING phase. Body: `[partition_id:u16
/// LE][self_id:u8][voter_count:u8]`.
///
/// Carried on the `cp_state` seam rather than a port of its own: the
/// consensus engine is at fluxor's 16-port-per-direction ceiling, and
/// that input already demuxes control-plane frames by type. A slot
/// activation IS control-plane state reaching consensus, so it belongs
/// there on meaning as well as on necessity.
pub const MSG_SLOT_ACTIVATE: u8 = 0x84;

/// Body length of [`MSG_SLOT_ACTIVATE`].
pub const SLOT_ACTIVATE_LEN: usize = 4;

/// Magic prefix of a migration record replicated through the Raft log,
/// inside the opaque proposal body (the same idiom as
/// `session_directory`'s `SR`). A committed entry starting with these
/// two bytes is the controller's own phase record coming back durable.
///
/// The record MUST travel this way rather than straight to a sink:
/// MIG-DURABLE is satisfied by the entry being COMMITTED, not by it
/// being accepted for write, and only the commit round-trip can tell
/// the controller which of those happened.
pub const MIG_CMD_MAGIC: [u8; 2] = *b"MG";

/// True when `buf` is a committed migration record body.
#[inline]
pub fn is_migration_record(buf: &[u8]) -> bool {
    buf.len() >= 2 + MIGRATION_RECORD_LEN && buf[..2] == MIG_CMD_MAGIC
}

/// Magic prefix of a ROUTING EPOCH record replicated through the Raft
/// log, inside the opaque proposal body (same idiom as `MG` and
/// `session_directory`'s `SR`).
///
/// The epoch is otherwise per-node and in memory: it starts at 1 and
/// advances on local fence transitions. While every node is up they
/// track together, because the transitions come from replicated
/// migration records — but a node that RESTARTS resets to 1 while its
/// peers are at N. It then routes on a stale epoch, and the forwards it
/// stamps carry an epoch its peers treat as superseded. Recording the
/// epoch makes it survive the restart.
///
/// Body: `[epoch:u32 LE]`. Applied as a MAXIMUM, so replay,
/// re-delivery and out-of-order arrival all converge, and an epoch can
/// only move forward.
pub const EPOCH_CMD_MAGIC: [u8; 2] = *b"RE";

/// Body length of a routing-epoch record (magic + epoch).
pub const EPOCH_RECORD_LEN: usize = 2 + 4;

/// Body length of a routing-epoch record that also carries the PRG
/// topology: `[RE][epoch:u32][prg_count:u16]`.
///
/// The topology rides the epoch record rather than getting a record of
/// its own, because a topology change IS an epoch change — every shard
/// changes owner when the divisor changes, which is precisely what an
/// epoch means. Two records could commit in either order and leave a
/// window where the epoch says "new placement" while the divisor is
/// still the old one, and every node would resolve owners wrongly for
/// exactly that window. One record makes them inseparable.
///
/// The tail is OPTIONAL, matching `MSG_PLACEMENT_UPDATE`: a 6-byte
/// record from a controller that only advanced the epoch leaves the
/// topology alone.
pub const EPOCH_RECORD_LEN_TOPO: usize = 2 + 4 + 2;

/// Body length of a routing-epoch record that also carries which node
/// serves each PRG: `[RE][epoch:u32][prg_count:u16][node_for_prg:u8 x
/// MAX_NODES]`. A permutation of `0..prg_count` (identity when absent),
/// so a whole PRG changes hands with one record and the fence unit —
/// the PRG — is already the right one. It rides the same record as the
/// count for the same reason the count rides the epoch: a change to who
/// serves what IS an epoch change.
pub const EPOCH_RECORD_LEN_PERM: usize = EPOCH_RECORD_LEN_TOPO + PERM_NODES;

/// Width of the `node_for_prg` permutation on the wire: `types::MAX_NODES`,
/// restated because this file is mounted where `types` is not.
pub const PERM_NODES: usize = 7;

/// True when `buf` is a committed routing-epoch record.
#[inline]
pub fn is_epoch_record(buf: &[u8]) -> bool {
    buf.len() >= EPOCH_RECORD_LEN && buf[..2] == EPOCH_CMD_MAGIC
}

/// Envelope carrying a migration record.
pub const MSG_MIGRATION_RECORD: u8 = 0x82;

#[expect(
    clippy::too_many_arguments,
    reason = "one argument per wire field; the record is a flat struct"
)]
#[inline]
pub fn encode_migration_record(
    buf: &mut [u8; MIGRATION_RECORD_LEN],
    migration_id: u64,
    phase: u8,
    source_prg: u16,
    target_prg: u16,
    epoch: u64,
    shard_count: u16,
    deadline_ms: u64,
    base_shard: u32,
) {
    Writer::new(buf)
        .u64(migration_id)
        .u8(phase)
        .u16(source_prg)
        .u16(target_prg)
        .u64(epoch)
        .u16(shard_count)
        .u64(deadline_ms)
        .u32(base_shard);
}

/// Returns `(migration_id, phase, source_prg, target_prg, epoch,
/// shard_count, deadline_ms, base_shard)`.
#[inline]
#[expect(
    clippy::type_complexity,
    reason = "one element per wire field; a struct here would be a second \
              definition of the record layout, which is how this header \
              acquired six drifting copies"
)]
pub fn decode_migration_record(buf: &[u8]) -> Option<(u64, u8, u16, u16, u64, u16, u64, u32)> {
    let mut r = Reader::new(buf, MIGRATION_RECORD_LEN)?;
    let migration_id = r.u64();
    let phase = r.u8();
    let source_prg = r.u16();
    let target_prg = r.u16();
    let epoch = r.u64();
    let shard_count = r.u16();
    let deadline_ms = r.u64();
    let base_shard = r.u32();
    Some((
        migration_id,
        phase,
        source_prg,
        target_prg,
        epoch,
        shard_count,
        deadline_ms,
        base_shard,
    ))
}

/// Encode a shard-map update header. Returns bytes written.
#[inline]
pub fn encode_shard_map_header(buf: &mut [u8], epoch: u64, count: u16) -> usize {
    if buf.len() < SHARD_MAP_HDR {
        return 0;
    }
    Writer::new(buf).u64(epoch).u16(count);
    SHARD_MAP_HDR
}

/// Decode a shard-map update header into `(epoch, count)`.
#[inline]
pub fn decode_shard_map_header(buf: &[u8]) -> Option<(u64, u16)> {
    let mut r = Reader::new(buf, SHARD_MAP_HDR)?;
    Some((r.u64(), r.u16()))
}

/// Write one `(shard, prg)` entry at `buf`. Returns bytes written.
#[inline]
pub fn encode_shard_map_entry(buf: &mut [u8], shard: u32, prg: u16) -> usize {
    if buf.len() < SHARD_MAP_ENTRY {
        return 0;
    }
    Writer::new(buf).u32(shard).u16(prg);
    SHARD_MAP_ENTRY
}

/// Read the `i`-th `(shard, prg)` entry of a shard-map payload.
#[inline]
pub fn decode_shard_map_entry(buf: &[u8], i: usize) -> Option<(u32, u16)> {
    let off = SHARD_MAP_HDR + i * SHARD_MAP_ENTRY;
    let mut r = Reader::new(buf.get(off..)?, SHARD_MAP_ENTRY)?;
    Some((r.u32(), r.u16()))
}

/// `control_plane` → any downstream session-bearing consumer: a kpg's
/// placement has changed, and a session bound to that kpg should
/// advance its `session_epoch` atomically so stale frames in flight
/// get fenced.
///
/// Payload (7 bytes): `[kpg_id:u16 LE][new_epoch:u32 LE][reason:u8]`.
///
/// This declaration is the contract. A consumer that mirrors the
/// constant mirrors THIS one; the substrate does not track who has and
/// does not change the shape to suit any of them. 0xD5 is the kpg-keyed
/// form specifically — a global-epoch transition is a different message
/// with a different shape and must not be given this id.
///
/// `reason` field — values shipped today:
///   0 = bootstrap (initial placement-router epoch on launch)
///   1 = admin     (operator-driven placement change, reserved)
///   2 = rebalance (substrate-driven, reserved)
pub const MSG_PLACEMENT_EPOCH_EVENT: u8 = 0xD5;

/// Downstream consumer → `durability`: the aggregated per-kpg retention
/// floor. `durability` must not advance compaction past
/// `floor_revision` for that `kpg_id` — otherwise a watcher whose
/// `start_revision` is below the new floor cannot be satisfied by
/// replay-after-rebind.
///
/// Payload (10 bytes): `[kpg_id:u16 LE][floor_revision:u64 LE]`.
///
/// The substrate accepts ONE floor per kpg and takes it as final. How a
/// consumer arrives at that number — how many watchers or readers it
/// polled, whether it aggregates several of its own per-source floors
/// first — is the consumer's business and deliberately invisible here:
/// this port would mean the same thing with a different consumer on the
/// other end of it.
pub const MSG_COMPACTION_FLOOR: u8 = 0xE1;

/// Envelope header size (1 byte type + 2 bytes length).
pub const ENVELOPE_HDR: usize = 3;

/// Maximum payload size in a single envelope (64 KiB - 1).
pub const MAX_PAYLOAD: usize = 0xFFFF;

// ── Encoding helpers ────────────────────────────────────────────────────────

/// Encode an envelope header into `buf[0..3]`. Returns 3 on success, -1 if
/// buf is too small.
#[inline]
pub fn encode_header(buf: &mut [u8], msg_type: u8, payload_len: u16) -> i32 {
    if buf.len() < ENVELOPE_HDR {
        return -1;
    }
    Writer::new(buf).u8(msg_type).u16(payload_len);
    ENVELOPE_HDR as i32
}

/// Decode an envelope header from `buf[0..3]` — `(msg_type, payload_len)`,
/// or `None` if the buffer is shorter than the envelope.
#[inline]
pub fn decode_header(buf: &[u8]) -> Option<(u8, u16)> {
    let mut r = Reader::new(buf, ENVELOPE_HDR)?;
    Some((r.u8(), r.u16()))
}

// Channel I/O over `SyscallTable` (`channel_{write,read}_msg`,
// partitioned and routed variants) lives in `wire_channels.rs`,
// the PIC-only companion to this file.

// ── Partitioned envelope helpers (multi-Raft channels) ──────────────────────
//
// Channels between partition-aware modules carry a 2-byte `partition_id`
// prefix in front of the standard 3-byte envelope. §"Wire envelope".
// Partitioned and non-partitioned channels coexist via distinct ports, never
// via in-band flag bytes.
//
// Wire: [partition_id: u16 LE] [msg_type: u8] [len: u16 LE] [payload]

/// Partitioned envelope header size (5 bytes).
pub const PARTITIONED_HDR: usize = 5;

/// Encode a partitioned envelope header into `buf[0..5]`. Returns 5 on
/// success, -1 if `buf` is too small.
#[inline]
pub fn encode_partitioned_header(
    buf: &mut [u8],
    partition_id: u16,
    msg_type: u8,
    payload_len: u16,
) -> i32 {
    if buf.len() < PARTITIONED_HDR {
        return -1;
    }
    Writer::new(buf)
        .u16(partition_id)
        .u8(msg_type)
        .u16(payload_len);
    PARTITIONED_HDR as i32
}

/// Decode a partitioned envelope header from `buf[0..5]` —
/// `(partition_id, msg_type, payload_len)`, or `None` if the buffer is
/// shorter than the partitioned envelope.
#[inline]
pub fn decode_partitioned_header(buf: &[u8]) -> Option<(u16, u8, u16)> {
    let mut r = Reader::new(buf, PARTITIONED_HDR)?;
    Some((r.u16(), r.u8(), r.u16()))
}

// ── Routed message helpers (for peer_tx channel) ────────────────────────────
//
// Messages on the peer_tx channel between consensus/replicator and
// peer_router carry a 1-byte target_replica prefix BEFORE the standard
// envelope so peer_router can route to the correct peer connection.
//
// Wire: [target_replica: u8] [msg_type: u8] [len: u16 LE] [payload]

/// Routed envelope header: 4 bytes (target + standard 3-byte envelope).
pub const ROUTED_HDR: usize = 4;

/// Broadcast target: send to all peers.
pub const TARGET_BROADCAST: u8 = 0xFF;

// ── Routed + partitioned envelope (peer_tx_partitioned channel) ─────────────
//
// Like the routed envelope above, but with a 2-byte `partition_id` between
// `target_replica` and the standard 3-byte envelope. Used on the channel
// between per-partition consensus instances and peer_router.
//
// `target_replica` semantics become "replica id within the named partition";
// a single physical node may hold replica 0 of partition A and replica 3
// of partition B. peer_router's replica → connection table is keyed by
// `(partition_id, target_replica)` when reading from this channel.
//
// Wire: [target_replica: u8] [partition_id: u16 LE] [msg_type: u8]
//       [len: u16 LE] [payload]

/// Routed partitioned envelope header: 6 bytes.
pub const ROUTED_PARTITIONED_HDR: usize = 6;

// ── Payload serialization for common Raft structures ────────────────────────

/// Encode a term + index pair (16 bytes).
#[inline]
pub fn encode_term_index(buf: &mut [u8], term: u64, index: u64) {
    Writer::new(buf).u64(term).u64(index);
}

/// Prefix on a `MSG_COMMITTED_ENTRY` body:
/// `[partition_id:u16 LE][term:u64 LE][index:u64 LE]`, then the entry.
///
/// The partition id is REQUIRED, not decorative. One engine hosts K raft
/// groups whose logs each number from 1, and every slot writes this one
/// stream — so without it a consumer tracking a single `apply_index`
/// sees partition 1's index 1 arrive after partition 0's and discards it
/// as a duplicate, or worse treats a forward jump as a gap and wipes its
/// apply-derived state. At K=4 that shows up as only ~1/4 of topics
/// ever delivering, deterministically. The ack path keys on
/// `(partition_id, wal_index)` for exactly this reason.
pub const COMMITTED_ENTRY_HDR: usize = 18;

/// Write the `MSG_COMMITTED_ENTRY` prefix. Body goes at
/// `COMMITTED_ENTRY_HDR`.
pub fn encode_committed_entry_hdr(buf: &mut [u8], partition_id: u16, term: u64, index: u64) {
    Writer::new(buf).u16(partition_id).u64(term).u64(index);
}

/// Read it back: `(partition_id, term, index)`, or `None` if short.
pub fn decode_committed_entry_hdr(buf: &[u8]) -> Option<(u16, u64, u64)> {
    let mut r = Reader::new(buf, COMMITTED_ENTRY_HDR)?;
    Some((r.u16(), r.u64(), r.u64()))
}

/// Decode a term + index pair (16 bytes), or `None` on a short frame.
///
/// A truncated peer frame must never index past the buffer: `no_std`
/// modules cannot unwind, so a panic kills the module. It must also
/// never decode to inert zeros, which `(term 0, index 0)` — a legal
/// pre-election value — makes indistinguishable from a real record.
/// `None` is the only answer that is both safe and honest.
#[inline]
pub fn decode_term_index(buf: &[u8]) -> Option<(u64, u64)> {
    let mut r = Reader::new(buf, 16)?;
    Some((r.u64(), r.u64()))
}

// ── Extended AppendEntries envelope ────────────────────────────────────────
//
// `[term:u64][leader_id:u8][prev_log_index:u64][prev_log_term:u64]
//  [leader_commit:u64][entry_term:u64][entry_index:u64][body...]`
//
// Total fixed header: 49 bytes. An empty-entry "log matching probe" uses
// the same envelope with entry_term = entry_index = 0 (no entry body).
//
// Old code paths that decoded the legacy 17-byte `[term][index][replica]`
// shape are migrated to call `decode_append_entries` below.
pub const AE_HDR_LEN: usize = 49;

#[inline]
pub fn encode_append_entries(
    buf: &mut [u8],
    term: u64,
    leader_id: u8,
    prev_log_index: u64,
    prev_log_term: u64,
    leader_commit: u64,
    entry_term: u64,
    entry_index: u64,
    body: &[u8],
) -> usize {
    let total = AE_HDR_LEN + body.len();
    if buf.len() < total {
        return 0;
    }
    Writer::new(buf)
        .u64(term)
        .u8(leader_id)
        .u64(prev_log_index)
        .u64(prev_log_term)
        .u64(leader_commit)
        .u64(entry_term)
        .u64(entry_index);
    if !body.is_empty() {
        buf[AE_HDR_LEN..total].copy_from_slice(body);
    }
    total
}

#[inline]
pub fn decode_append_entries(buf: &[u8]) -> Option<(u64, u8, u64, u64, u64, u64, u64)> {
    let mut r = Reader::new(buf, AE_HDR_LEN)?;
    let term = r.u64();
    let leader_id = r.u8();
    let prev_idx = r.u64();
    let prev_term = r.u64();
    let leader_commit = r.u64();
    let entry_term = r.u64();
    let entry_index = r.u64();
    Some((
        term,
        leader_id,
        prev_idx,
        prev_term,
        leader_commit,
        entry_term,
        entry_index,
    ))
}

pub fn encode_term_index_replica(buf: &mut [u8], term: u64, index: u64, replica: u8) {
    Writer::new(buf).u64(term).u64(index).u8(replica);
}

/// Decode term + index + replica_id (17 bytes), or `None` on a short frame.
#[inline]
pub fn decode_term_index_replica(buf: &[u8]) -> Option<(u64, u64, u8)> {
    let mut r = Reader::new(buf, 17)?;
    Some((r.u64(), r.u64(), r.u8()))
}

/// Encode a RequestVote / PreVote payload (25 bytes):
///   term(8) + candidate_id(1) + last_log_index(8) + last_log_term(8)
#[inline]
pub fn encode_vote_request(
    buf: &mut [u8],
    term: u64,
    candidate: u8,
    last_index: u64,
    last_term: u64,
) {
    Writer::new(buf)
        .u64(term)
        .u8(candidate)
        .u64(last_index)
        .u64(last_term);
}

/// Decode a RequestVote / PreVote payload (25 bytes), or `None` on a
/// short frame. A truncated vote request must not decode to term 0 /
/// candidate 0 — that is a well-formed message the election path would
/// otherwise act on.
#[inline]
pub fn decode_vote_request(buf: &[u8]) -> Option<(u64, u8, u64, u64)> {
    let mut r = Reader::new(buf, 25)?;
    Some((r.u64(), r.u8(), r.u64(), r.u64()))
}

/// Encode a VoteResponse payload (10 bytes):
///   term(8) + granted(1) + voter_id(1)
#[inline]
pub fn encode_vote_response(buf: &mut [u8], term: u64, granted: bool, voter: u8) {
    Writer::new(buf).u64(term).bool(granted).u8(voter);
}

/// Decode a VoteResponse payload (10 bytes), or `None` on a short frame.
#[inline]
pub fn decode_vote_response(buf: &[u8]) -> Option<(u64, bool, u8)> {
    let mut r = Reader::new(buf, 10)?;
    Some((r.u64(), r.bool(), r.u8()))
}

/// Encode an FsyncAck payload (17 bytes):
///   term(8) + index(8) + replica_id(1)
///
/// Emitted by `wal` directly on `wal.flushed` (one `wal` per partition). The
/// `replica` byte must be the WAL's `self_id` so `durability` keys
/// per-replica progress correctly. For cross-partition fan-in to
/// `ack_tracker` see `encode_durability_proof` below.
///
/// On the leader, `durability` also receives FsyncAck frames
/// synthesized by `replicator` from follower AppendEntriesResponse
/// envelopes (see `AE_RESP_LEN`), so the per-replica progress array
/// covers every voter quorum-fsync semantic.
#[inline]
pub fn encode_fsync_ack(buf: &mut [u8], term: u64, index: u64, replica: u8) {
    encode_term_index_replica(buf, term, index, replica);
}

/// Decode an FsyncAck payload (17 bytes), or `None` on a short frame.
#[inline]
pub fn decode_fsync_ack(buf: &[u8]) -> Option<(u64, u64, u8)> {
    decode_term_index_replica(buf)
}

/// AppendEntriesResponse payload size (25 bytes):
///   `[term:u64][last_log_index:u64][replica_byte:u8][durable_index:u64]`
/// where `replica_byte = self_id | (success << 7)`.
///
/// `durable_index` is the follower's `local_wal_durable_index` at the
/// moment the response is sent. The leader's
/// `replicator` decodes this field and forwards a synthesized
/// `MSG_FSYNC_ACK` to `durability.ack` so the leader can
/// compute quorum durability across replicas.
///
/// The first 17 bytes are the legacy `[term][last_log_index][replica_byte]`
/// shape so older readers (e.g. `consensus.drain_match_indices`,
/// which only needs `(term, last_log_index, replica)`) keep working
/// without code change.
/// Byte 25 is a `busy` flag: a failure (`success == 0`) that means the
/// follower's WAL channel was full (local durability backpressure), NOT a log
/// mismatch. The leader retries the same entry instead of rolling `next_index`
/// back — see `replicator`. Absent (legacy/short frame) it defaults to 0.
pub const AE_RESP_LEN: usize = 26;

#[inline]
pub fn encode_append_entries_resp(
    buf: &mut [u8; AE_RESP_LEN],
    term: u64,
    last_log_index: u64,
    self_id: u8,
    success: bool,
    durable_index: u64,
    busy: bool,
) {
    Writer::new(buf)
        .u64(term)
        .u64(last_log_index)
        .u8(self_id | (u8::from(success) << 7))
        .u64(durable_index)
        .bool(busy);
}

/// Decode an AppendEntriesResponse payload. Accepts the 26-byte modern shape,
/// the 25-byte shape (busy defaults to 0), or the legacy 17-byte shape
/// (durable_index defaults to 0, which leaves the leader's `durability`
/// progress slot for that replica unchanged).
/// Returns `(term, last_log_index, replica, success, durable_index, busy)`.
#[inline]
pub fn decode_append_entries_resp(buf: &[u8]) -> Option<(u64, u64, u8, bool, u64, bool)> {
    let (term, last_index, replica_byte) = decode_term_index_replica(buf)?;
    let success = (replica_byte & 0x80) != 0;
    let replica = replica_byte & 0x7F;
    // Both tail fields are optional on the wire: a 17-byte response
    // carries neither, a 25-byte one carries `durable_index` only.
    // Each decodes to its default when absent, so a peer emitting a
    // narrower response stays readable.
    let durable_index = Reader::new(buf, 25).map_or(0, |mut r| r.skip(17).u64());
    let busy = Reader::new(buf, 26).is_some_and(|mut r| r.skip(25).bool());
    Some((term, last_index, replica, success, durable_index, busy))
}

/// DurabilityProof payload size (19 bytes):
///   partition_id(2) + term(8) + index(8) + replica_id(1)
pub const DURABILITY_PROOF_LEN: usize = 19;

/// Encode a DurabilityProof payload. The `partition_id` prefix lets
/// downstream consumers (especially `ack_tracker`, which fans in
/// proofs from every per-partition `durability`) disambiguate
/// the same `wal_index` across partitions. Per-partition consumers
/// like `consensus` ignore the prefix — it always matches their
/// own configured slot.
#[inline]
pub fn encode_durability_proof(
    buf: &mut [u8],
    partition_id: u16,
    term: u64,
    index: u64,
    replica: u8,
) {
    Writer::new(buf)
        .u16(partition_id)
        .u64(term)
        .u64(index)
        .u8(replica);
}

/// Decode a DurabilityProof payload (19 bytes) —
/// `(partition_id, term, index, replica)`, or `None` on a short frame.
///
/// This proof is what `commit` trusts to advance the durable index, so
/// a truncated one decoding to index 0 would be a silent no-op where a
/// dropped frame is the honest outcome.
#[inline]
pub fn decode_durability_proof(buf: &[u8]) -> Option<(u16, u64, u64, u8)> {
    let mut r = Reader::new(buf, DURABILITY_PROOF_LEN)?;
    Some((r.u16(), r.u64(), r.u64(), r.u8()))
}

/// Encode a CacheState payload (1 byte): the CP_* constant.
#[inline]
pub fn encode_cache_state(buf: &mut [u8], state: u8) {
    buf[0] = state;
}

/// Decode a CacheState payload (1 byte), or `None` on an empty frame.
#[inline]
pub fn decode_cache_state(buf: &[u8]) -> Option<u8> {
    Some(Reader::new(buf, 1)?.u8())
}

/// Encode ThrottleCredits payload (8 bytes): entry_credits(4) + byte_credits(4).
#[inline]
pub fn encode_credits(buf: &mut [u8], entry: i32, byte: i32) {
    Writer::new(buf).i32(entry).i32(byte);
}

/// Decode ThrottleCredits payload (8 bytes), or `None` on a short frame.
#[inline]
pub fn decode_credits(buf: &[u8]) -> Option<(i32, i32)> {
    let mut r = Reader::new(buf, 8)?;
    Some((r.i32(), r.i32()))
}

pub const THROTTLE_REFILL_LEN: usize = 16;

#[inline]
pub fn encode_throttle_refill(
    buf: &mut [u8; THROTTLE_REFILL_LEN],
    entry_grant: i32,
    byte_grant: i32,
    entry_capacity: i32,
    byte_capacity: i32,
) {
    Writer::new(buf)
        .i32(entry_grant)
        .i32(byte_grant)
        .i32(entry_capacity)
        .i32(byte_capacity);
}

#[inline]
pub fn decode_throttle_refill(buf: &[u8]) -> Option<(i32, i32, i32, i32)> {
    if buf.len() < THROTTLE_REFILL_LEN {
        return None;
    }
    let mut r = Reader::new(buf, THROTTLE_REFILL_LEN)?;
    Some((r.i32(), r.i32(), r.i32(), r.i32()))
}

// ── FNV-1a 64-bit hash ──────────────────────────────────────────────────────
//
// Used by `partition_router` for routing-key → partition_id mapping.
// Stock FNV-1a with the standard 64-bit offset basis and prime, chosen
// because it is unambiguous: a protocol stack that hashes a routing key
// at its own boundary (an MQTT topic string, say) gets the same
// partition without either side publishing a private variant.

const FNV1A_64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit hash of a byte slice.
#[inline]
pub fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h = FNV1A_64_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV1A_64_PRIME);
    }
    h
}

// ── Tagged proposal envelope ─────────────────────────────────────────────────
//
// Two MSG_CLIENT_PROPOSAL payload shapes coexist on the leader's intake:
//
// 1. Legacy (untagged) — sent on consensus.proposals (in[1]):
//        payload = body
//    No correlation back to the proposer; ack-on-durability has to be
//    inferred (e.g. by FIFO heuristics in ack_tracker).
//
// 2. Tagged — sent on consensus.proposals_tagged (in[4]):
//        payload = [correlation_id: u64 LE][body]
//    correlation_id MUST be non-zero. The leader stores the id alongside
//    the proposal in its batch and, once the batch is flushed and gets a
//    log index, emits MSG_PROPOSAL_ASSIGNED back on out[4]
//    (proposal_assigned) so the proposer can bind id → wal_index.
//
// The proposal body that lands in the WAL is identical in both cases —
// the correlation_id is stripped before batching.

/// Header size of a tagged proposal envelope (correlation_id prefix only).
pub const TAGGED_PROPOSAL_HDR: usize = 8;

/// Build a tagged proposal payload into `dst`. Returns total bytes written
/// (`8 + body.len()`), or -1 if `dst` is too small.
#[inline]
pub fn encode_tagged_proposal(dst: &mut [u8], correlation_id: u64, body: &[u8]) -> i32 {
    let total = TAGGED_PROPOSAL_HDR + body.len();
    if dst.len() < total {
        return -1;
    }
    Writer::new(dst).u64(correlation_id).bytes(body);
    total as i32
}

/// Decode a tagged proposal payload. Returns `(correlation_id, body_offset)`
/// where `body_offset == TAGGED_PROPOSAL_HDR`. Caller slices `buf[body_offset..]`
/// to obtain the body. Returns `None` if `buf` is shorter than the header.
#[inline]
pub fn decode_tagged_proposal(buf: &[u8]) -> Option<(u64, usize)> {
    let correlation_id = Reader::new(buf, TAGGED_PROPOSAL_HDR)?.u64();
    Some((correlation_id, TAGGED_PROPOSAL_HDR))
}

// ── Keyed proposal envelope ──────────────────────────────────────────────────
//
// A third MSG_CLIENT_PROPOSAL shape, used when the *proposer* — not the
// substrate — decides which partition a proposal belongs to.
//
// 3. Keyed — sent as MSG_CLIENT_PROPOSAL_KEYED on either proposal port:
//        proposals        (untagged): [shard_id: u32 LE][body]
//        proposals_tagged (tagged):   [shard_id: u32 LE][correlation_id: u64 LE][body]
//
// `partition_router` maps `shard_id` to a partition, strips the 4-byte
// prefix, and forwards the remaining payload as a plain
// MSG_CLIENT_PROPOSAL — so `consensus` sees exactly the two shapes it
// already handles and needs no change.
//
// Why the shard id rides a *stripped prefix* rather than the body: the
// facade's opaque-command invariant (replica_facade.rs "Clustor never
// inspects the body bytes") is load-bearing. Routing is the substrate's
// concern, the schema is the consumer's, and the correlation_id prefix
// already established that a proposer-supplied, router-stripped prefix
// is how the two meet. Anything the *apply* path must re-derive after a
// replay (a routing epoch, a dedupe key) belongs in the consumer's own
// body schema, where Clustor still never looks.
//
// The shard id is a virtual-shard index, already reduced modulo
// [`VIRTUAL_SHARDS`] by the proposer (see [`shard_for_key`]). It is not
// a partition id: the shard space is fixed for the life of a cluster
// while the partition count changes, which is the whole point — growing
// the partition count moves shards between partitions instead of
// rehashing every key.

/// Size of the virtual-shard space. Fixed for the life of a cluster:
/// changing it rehashes every key and is a full-cluster migration, not an
/// operation. Sized so that a large cluster still gets tens of shards per
/// partition, keeping the smallest possible load movement small (see
/// quantum's).
pub const VIRTUAL_SHARDS: u32 = 1 << 18;

/// Reduce a routing-key hash to a virtual-shard id.
///
/// Callers hash their own routing key with [`fnv1a_64`] — an MQTT
/// `(tenant, client_id)` or `(tenant, normalized_topic)`, a Kafka
/// `(tenant, topic, partition)` — and pass the result here. Both sides
/// of a forward therefore agree on the shard without either publishing
/// a private hash variant.
#[inline]
pub fn shard_for_key(key_hash: u64) -> u32 {
    (key_hash % VIRTUAL_SHARDS as u64) as u32
}

/// The PRG a shard belongs to when no override names another: jump
/// consistent hash (Lamping & Veach, 2014) over `prg_count` PRGs.
///
/// Chosen over `shard % prg_count` for what happens when the count
/// changes. Under modulo a resize re-homes most of the shard space;
/// under jump hash growing N -> N+1 moves exactly the 1/(N+1) of shards
/// that land on the NEW PRG and leaves every other shard where it was,
/// and shrinking moves only the departing PRG's shards. That is the
/// property a dense shard map was going to be built to provide, and it
/// costs six lines and no table.
///
/// One implementation for the whole cluster: the edge core in quantum
/// mirrors this function byte for byte and the two are pinned to the
/// same vectors by test. A node running a different baseline would
/// resolve a different owner for every shard, so a cluster is rebuilt
/// together when this changes (the ABI-epoch discipline).
///
/// `prg_count == 0` is treated as 1 — the wire's "unchanged" sentinel
/// must never divide.
#[inline]
pub fn baseline_prg(shard: u32, prg_count: u16) -> u16 {
    let buckets = i64::from(prg_count.max(1));
    let mut key = u64::from(shard);
    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets {
        b = j;
        key = key.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(1);
        // (b + 1) * (2^31 / (high 31 bits of key + 1)), in the paper's
        // double arithmetic — reproduced exactly so every implementation
        // agrees on every shard.
        let denom = ((key >> 33) + 1) as f64;
        j = ((b + 1) as f64 * (2_147_483_648.0_f64 / denom)) as i64;
    }
    b as u16
}

/// Header size of a keyed proposal envelope (shard_id prefix only).
pub const KEYED_PROPOSAL_HDR: usize = 4;

/// The shard every CONTROL-PLANE record is keyed to.
///
/// `shard_to_partition` is `shard % num_partitions` (modulo any
/// override), and `0 % n == 0` for every `n`, so a record keyed here
/// always lands on partition 0, the distinguished CP-Raft group.
///
/// Without a key a record goes out UNTAGGED on `consensus.proposals`,
/// whose channel handle is cloned to every slot. At K>1 each hosted
/// group's `drain_proposals` reads that same handle, so whichever slot
/// stepped first would take the record — a control-plane entry landing
/// on an ARBITRARY partition, varying run to run. Keying them makes
/// group 0 the answer by construction.
pub const CP_RECORD_SHARD: u32 = 0;

/// Build a keyed proposal payload into `dst`. `rest` is the payload the
/// router will forward once it strips the prefix — a bare body for the
/// untagged port, or `[correlation_id: u64 LE][body]` for the tagged
/// one. Returns total bytes written (`4 + rest.len()`), or -1 if `dst`
/// is too small.
#[inline]
pub fn encode_keyed_proposal(dst: &mut [u8], shard_id: u32, rest: &[u8]) -> i32 {
    let total = KEYED_PROPOSAL_HDR + rest.len();
    if dst.len() < total {
        return -1;
    }
    Writer::new(dst).u32(shard_id).bytes(rest);
    total as i32
}

/// Decode a keyed proposal payload. Returns `(shard_id, rest_offset)`
/// where `rest_offset == KEYED_PROPOSAL_HDR`. Returns `None` if `buf` is
/// shorter than the header.
#[inline]
pub fn decode_keyed_proposal(buf: &[u8]) -> Option<(u32, usize)> {
    let shard_id = Reader::new(buf, KEYED_PROPOSAL_HDR)?.u32();
    Some((shard_id, KEYED_PROPOSAL_HDR))
}

/// MSG_PROPOSAL_ASSIGNED payload size (18 bytes):
///   correlation_id(8 LE) + partition_id(2 LE) + wal_index(8 LE)
pub const PROPOSAL_ASSIGNED_LEN: usize = 18;

/// Encode a MSG_PROPOSAL_ASSIGNED payload. `partition_id` is the slot
/// that assigned the index — proposers that route the same logical
/// session across multiple partitions (e.g. quantum's session_processor
/// dispatching QoS 1 PUBLISHes through partition_router) need this to
/// register `(partition_id, wal_index)` with their ack tracker.
#[inline]
pub fn encode_proposal_assigned(
    dst: &mut [u8],
    correlation_id: u64,
    partition_id: u16,
    wal_index: u64,
) {
    Writer::new(dst)
        .u64(correlation_id)
        .u16(partition_id)
        .u64(wal_index);
}

/// Decode a MSG_PROPOSAL_ASSIGNED payload (18 bytes) —
/// `(correlation_id, partition_id, wal_index)`, or `None` on a short frame.
#[inline]
pub fn decode_proposal_assigned(buf: &[u8]) -> Option<(u64, u16, u64)> {
    let mut r = Reader::new(buf, 18)?;
    Some((r.u64(), r.u16(), r.u64()))
}
