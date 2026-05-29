//! Wire format helpers for inter-module channel messages.
//!
//! Every message uses a 3-byte envelope:
//!   [msg_type: u8] [len: u16 LE] [payload: len bytes]
//!
//! ## Stability — DRAFT (do not pin consumers to these encodings yet)
//!
//! Every `MSG_*` constant and payload layout in this file is treated as
//! draft until the Clustor module-coherence work in
//! `.context/rfc_fluxor_native_module_coherence.md` lands its facade
//! stabilization pass (§11, §12 Phase 2). External consumers
//! (Quantum, Lattice, Chronicle, Loam) MUST go through
//! `modules/common/replica_facade.rs` instead of importing these
//! constants directly. Numeric ids and payload field orders may change
//! without notice until the registry is promoted to v1.

#![allow(
    dead_code,
    reason = "shared via #[path] into multiple modules; each consumer uses a subset of the surface so single-module rustc invocations see unused items"
)]

// ── Message type constants ──────────────────────────────────────────────────

// Raft RPC
pub const MSG_APPEND_ENTRIES: u8      = 0x01;
pub const MSG_APPEND_ENTRIES_RESP: u8 = 0x02;
pub const MSG_REQUEST_VOTE: u8        = 0x03;
pub const MSG_REQUEST_VOTE_RESP: u8   = 0x04;
pub const MSG_PRE_VOTE: u8            = 0x05;
pub const MSG_PRE_VOTE_RESP: u8       = 0x06; // reuse slot: high bit unused
pub const MSG_HEARTBEAT: u8           = 0x07;
pub const MSG_HEARTBEAT_RESP: u8      = 0x08;
/// Periodic leader-state hint emitted by `raft_engine.leader_state` so
/// downstream modules (notably `client_codec`) can short-circuit
/// proposals with an explicit `CLIENT_REJECT_NOT_LEADER` when the local
/// node is not the leader. Payload: `[leader_id:u8 (0xFF = unknown)][term:u64 LE]`.
pub const MSG_LEADER_HINT: u8         = 0x09;
/// Leader-transfer "TimeoutNow" RPC. Sent by a stepping-down leader to
/// the target it wants to promote. Receiver immediately bumps term and
/// starts an election. Payload: `[caller_term:u64 LE]` (8 bytes) so the
/// receiver can drop stale messages.
pub const MSG_TIMEOUT_NOW: u8         = 0x0A;
/// Strict ReadIndex peer-network probe (Raft paper §6.4). Sent by the
/// leader to every peer when it needs to confirm that it still holds
/// the leadership at the point the read was issued. Payload (16 bytes):
/// `[probe_id:u64 LE][term:u64 LE]`.
pub const MSG_READ_INDEX_PROBE: u8    = 0x0B;
/// Peer's reply to `MSG_READ_INDEX_PROBE`. The leader counts these to
/// majority before answering the read. Payload (17 bytes):
/// `[probe_id:u64 LE][term:u64 LE][replica:u8]`.
pub const MSG_READ_INDEX_PROBE_RESP: u8 = 0x0C;
/// Internal apply_pipeline → raft_engine: "I have a read with this
/// correlation id, please confirm a read-index for me." Payload (8 bytes):
/// `[correlation_id:u64 LE]`.
pub const MSG_READ_PROBE_REQ: u8      = 0x0D;
/// Internal raft_engine → apply_pipeline: reply to `MSG_READ_PROBE_REQ`.
/// Payload (17 bytes):
/// `[correlation_id:u64 LE][confirmed_commit:u64 LE][confirmed:u8]`.
/// `confirmed == 0` means "not leader" or "probe timed out" — the
/// apply pipeline must reject the read with `CLIENT_REJECT_FALLBACK`.
pub const MSG_READ_PROBE_REPLY: u8    = 0x0E;

#[inline]
pub fn encode_read_index_probe(buf: &mut [u8; 16], probe_id: u64, term: u64) {
    buf[0..8].copy_from_slice(&probe_id.to_le_bytes());
    buf[8..16].copy_from_slice(&term.to_le_bytes());
}

#[inline]
pub fn decode_read_index_probe(buf: &[u8]) -> Option<(u64, u64)> {
    if buf.len() < 16 { return None; }
    let probe = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let term = u64::from_le_bytes([buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]]);
    Some((probe, term))
}

#[inline]
pub fn encode_read_index_probe_resp(buf: &mut [u8; 17], probe_id: u64, term: u64, replica: u8) {
    buf[0..8].copy_from_slice(&probe_id.to_le_bytes());
    buf[8..16].copy_from_slice(&term.to_le_bytes());
    buf[16] = replica;
}

#[inline]
pub fn decode_read_index_probe_resp(buf: &[u8]) -> Option<(u64, u64, u8)> {
    if buf.len() < 17 { return None; }
    let probe = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let term = u64::from_le_bytes([buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]]);
    Some((probe, term, buf[16]))
}

#[inline]
pub fn encode_read_probe_reply(buf: &mut [u8; 17], correlation_id: u64, confirmed_commit: u64, confirmed: bool) {
    buf[0..8].copy_from_slice(&correlation_id.to_le_bytes());
    buf[8..16].copy_from_slice(&confirmed_commit.to_le_bytes());
    buf[16] = confirmed as u8;
}

#[inline]
pub fn decode_read_probe_reply(buf: &[u8]) -> Option<(u64, u64, bool)> {
    if buf.len() < 17 { return None; }
    let correlation_id = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let confirmed_commit = u64::from_le_bytes([buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]]);
    let confirmed = buf[16] != 0;
    Some((correlation_id, confirmed_commit, confirmed))
}

// Client
pub const MSG_CLIENT_PROPOSAL: u8     = 0x10;
pub const MSG_CLIENT_RESPONSE: u8     = 0x11;
pub const MSG_ADMIN_COMMAND: u8       = 0x12;
pub const MSG_ADMIN_RESPONSE: u8      = 0x13;
/// Structured client rejection on the wire (after client_codec stamps
/// `conn_id`). Wire payload (11 bytes):
/// `[conn_id:u8][status:u8][reserved:u8][retry_after_ms:u16 LE][entry_credits:i16 LE][byte_credits:i32 LE]`
/// Surfaced when a request is denied before it can be replicated —
/// throttle rejection, NotLeader, stale-epoch, read-unsupported, etc.
/// See RFC §5.8/§5.9.
pub const MSG_CLIENT_REJECT: u8       = 0x15;
/// Linearizable read request from a client. Payload after the conn_id
/// prefix supplied by client_surface: `[read_id:u64 LE][body]`. The
/// substrate does not yet implement linearizable reads end-to-end —
/// client_codec answers every read with `CLIENT_REJECT_READ_UNSUPPORTED`.
/// See RFC §4.3.
pub const MSG_CLIENT_READ_REQUEST: u8 = 0x16;
/// Internal rejection envelope used between `throttle_gate.rejected`
/// and `client_codec.responses`. Carries the correlation_id assigned
/// by client_codec so the codec can map it back to a conn_id.
/// Payload (18 bytes):
/// `[correlation_id:u64 LE][status:u8][reserved:u8][retry_after_ms:u16 LE][entry_credits:i16 LE][byte_credits:i32 LE]`
pub const MSG_CLIENT_REJECT_INTERNAL: u8 = 0x17;
/// Linearizable read response from `apply_pipeline.applied` to
/// `client_codec.responses`. Emitted when a queued read has reached its
/// ReadIndex linearization point (apply_index ≥ submission-time commit
/// horizon) AND the CP cache is still Fresh/Cached. The body is empty —
/// downstream consumers MUST query their state machine via the per-entry
/// `committed_entries` stream once they observe the matching index. See
/// RFC §4.3.
/// Payload: `[correlation_id:u64 LE]` (8 bytes).
pub const MSG_CLIENT_READ_RESPONSE: u8 = 0x18;
/// Admin-command apply confirmation from `raft_engine.admin_applied` to
/// `admin_handler.applied_in`. Carries the per-admin command_id that
/// `admin_handler` stamped onto the request, plus the status the engine
/// decided. Payload (5 bytes):
/// `[command_id:u32 LE][status:u8]`.
pub const MSG_ADMIN_APPLIED: u8       = 0x19;

/// `MSG_ADMIN_RESPONSE` payload status codes (first byte).
///
/// `OK` and `DUPLICATE` are reserved for the day admin commands actually
/// apply through Raft. Until then `admin_handler` returns `UNSUPPORTED`
/// for every request — see RFC §4.4 / §5.12 and `admin_handler/mod.rs`.
pub const ADMIN_STATUS_OK: u8          = 0x00;
pub const ADMIN_STATUS_DUPLICATE: u8   = 0x01;
pub const ADMIN_STATUS_UNSUPPORTED: u8 = 0x80;
pub const ADMIN_STATUS_REJECTED: u8    = 0x81;
pub const ADMIN_STATUS_NOT_LEADER: u8  = 0x82;

/// Admin op codes (first body byte of an admin command). FREEZE / THAW /
/// TRANSFER_LEADER / DURABILITY_MODE / SNAPSHOT are local-only effects
/// applied by `raft_engine`. Membership ops (ADD/REMOVE voter) require
/// joint consensus and are intentionally still `ADMIN_STATUS_UNSUPPORTED`
/// — see RFC §14.
pub const ADMIN_OP_FREEZE: u8           = 0x01;
pub const ADMIN_OP_THAW: u8             = 0x02;
pub const ADMIN_OP_TRANSFER_LEADER: u8  = 0x03;
pub const ADMIN_OP_DURABILITY_MODE: u8  = 0x04;
pub const ADMIN_OP_SNAPSHOT: u8         = 0x05;
pub const ADMIN_OP_ADD_VOTER: u8        = 0x06;
pub const ADMIN_OP_REMOVE_VOTER: u8     = 0x07;

/// Body-prefix byte for an admin entry replicated through the Raft log
/// (RFC §3.1). When a committed entry's body starts with this byte,
/// the substrate interprets the remainder as
/// `[command_id:u32 LE][op_code:u8][op_body...]` and applies the op
/// at commit time on every replica. Plain proposal bodies (no marker)
/// remain opaque per the RFC and are passed through unchanged.
pub const ADMIN_MARKER: u8              = 0xAD;

/// `apply_pipeline` → `raft_engine` admin commit signal. Emitted when a
/// committed entry's body begins with `ADMIN_MARKER` so raft_engine
/// can apply the op locally. Payload: same body bytes that landed in
/// the WAL minus the marker byte:
/// `[command_id:u32 LE][op_code:u8][op_body...]`.
pub const MSG_ADMIN_COMMITTED: u8     = 0x1A;
/// `apply_pipeline` → `raft_engine` config-change commit. Emitted
/// when a committed entry's body begins with `CONFIG_CHANGE_MARKER`.
/// Payload mirrors the body bytes (minus the marker): see
/// `decode_config_change`. See RFC §1.2 / phase-3 plan §1.2.
pub const MSG_CONFIG_COMMITTED: u8    = 0x1B;

/// Body-prefix byte for a Raft-replicated configuration change (joint
/// consensus, RFC §1.2). Followed by:
/// `[op_code:u8 (1 = C_old,new, 2 = C_new)][voter_count:u8]
///  [voter_id_0:u8]...[voter_id_{n-1}:u8]` for the "new" voter set.
/// For `C_old,new` entries the old set is recoverable from the
/// follower's persisted `current_voters`. Joint consensus is not yet
/// fully implemented; the marker is reserved so the wire format
/// stays stable while the engine work lands.
pub const CONFIG_CHANGE_MARKER: u8    = 0xCC;
pub const CONFIG_CHANGE_OP_JOINT: u8  = 0x01;
pub const CONFIG_CHANGE_OP_NEW: u8    = 0x02;

/// Encode a config-change entry body for the WAL log. Layout:
///   `[CONFIG_CHANGE_MARKER][op_code:u8][voter_count:u8][voter_id_0..n-1:u8]`
/// Returns total bytes written or 0 on buffer-too-small.
#[inline]
pub fn encode_config_change(
    buf: &mut [u8],
    op_code: u8,
    voters: &[u8],
) -> usize {
    let n = voters.len().min(0xFF);
    let total = 3 + n;
    if buf.len() < total {
        return 0;
    }
    buf[0] = CONFIG_CHANGE_MARKER;
    buf[1] = op_code;
    buf[2] = n as u8;
    buf[3..3 + n].copy_from_slice(&voters[..n]);
    total
}

/// Decode a config-change body. Returns `(op_code, voter_ids_offset, voter_count)`
/// or `None` if the body doesn't start with `CONFIG_CHANGE_MARKER` or is
/// truncated.
#[inline]
pub fn decode_config_change(buf: &[u8]) -> Option<(u8, usize, usize)> {
    if buf.len() < 3 {
        return None;
    }
    if buf[0] != CONFIG_CHANGE_MARKER {
        return None;
    }
    let op_code = buf[1];
    let n = buf[2] as usize;
    if buf.len() < 3 + n {
        return None;
    }
    Some((op_code, 3, n))
}

/// `raft_engine` → `commit_tracker` / `durability_ledger` voter-set
/// update. Sent every time the current or joint voter set changes so
/// the downstream quorum tracker can adjust. Payload (3 bytes):
///   `[current_set:u8][joint_set:u8][joint_active:u8]`
/// Each `u8` is a [`crate::types::NodeSet`] bitmask. `joint_active = 0`
/// means single-config; otherwise both sets must be considered for
/// quorum.
pub const MSG_VOTER_SET_UPDATE: u8    = 0x76;

#[inline]
pub fn encode_voter_set_update(
    buf: &mut [u8; 3],
    current_set: u8,
    joint_set: u8,
    joint_active: bool,
) {
    buf[0] = current_set;
    buf[1] = joint_set;
    buf[2] = joint_active as u8;
}

#[inline]
pub fn decode_voter_set_update(buf: &[u8]) -> Option<(u8, u8, bool)> {
    if buf.len() < 3 {
        return None;
    }
    Some((buf[0], buf[1], buf[2] != 0))
}

/// `MSG_CLIENT_REJECT` status codes (status byte, after the conn_id /
/// correlation_id prefix depending on envelope variant).
pub const CLIENT_REJECT_THROTTLED: u8        = 0x01;
pub const CLIENT_REJECT_NOT_LEADER: u8       = 0x02;
pub const CLIENT_REJECT_STALE_EPOCH: u8      = 0x03;
pub const CLIENT_REJECT_FALLBACK: u8         = 0x04;
pub const CLIENT_REJECT_READ_UNSUPPORTED: u8 = 0x05;

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
/// `reserved` is repurposed as `leader_id` when `status == CLIENT_REJECT_NOT_LEADER`
/// (per RFC §5.8). Pass `0` for every other status.
#[inline]
pub fn encode_client_reject_body(
    buf: &mut [u8; CLIENT_REJECT_BODY_LEN],
    status: u8,
    reserved: u8,
    retry_after_ms: u16,
    entry_credits: i16,
    byte_credits: i32,
) {
    buf[0] = status;
    buf[1] = reserved;
    buf[2..4].copy_from_slice(&retry_after_ms.to_le_bytes());
    buf[4..6].copy_from_slice(&entry_credits.to_le_bytes());
    buf[6..10].copy_from_slice(&byte_credits.to_le_bytes());
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
    buf[0..8].copy_from_slice(&correlation_id.to_le_bytes());
    let mut body = [0u8; CLIENT_REJECT_BODY_LEN];
    encode_client_reject_body(&mut body, status, 0, retry_after_ms, entry_credits, byte_credits);
    buf[8..8 + CLIENT_REJECT_BODY_LEN].copy_from_slice(&body);
}

/// Decode an internal reject envelope. Returns
/// `(correlation_id, status, retry_after_ms, entry_credits, byte_credits)`.
#[inline]
pub fn decode_client_reject_internal(buf: &[u8]) -> Option<(u64, u8, u16, i16, i32)> {
    if buf.len() < CLIENT_REJECT_INTERNAL_LEN { return None; }
    let correlation_id = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let status = buf[8];
    let retry = u16::from_le_bytes([buf[10], buf[11]]);
    let entry = i16::from_le_bytes([buf[12], buf[13]]);
    let byte = i32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]);
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
    encode_client_reject_body(&mut body, status, reserved, retry_after_ms, entry_credits, byte_credits);
    buf[1..1 + CLIENT_REJECT_BODY_LEN].copy_from_slice(&body);
}

// Legacy aliases (kept so the previous in-tree call sites compile while the
// throttle/codec switch lands. New code should call the explicit variants.)
pub const CLIENT_REJECT_LEN: usize = CLIENT_REJECT_BODY_LEN;
#[inline]
pub fn encode_client_reject(
    buf: &mut [u8; CLIENT_REJECT_BODY_LEN],
    status: u8,
    retry_after_ms: u16,
    entry_credits: i16,
    byte_credits: i32,
) {
    encode_client_reject_body(buf, status, 0, retry_after_ms, entry_credits, byte_credits);
}
/// Emitted by raft_engine on its `proposal_assigned` output port for every
/// tagged proposal once the leader has assigned it a log index. Lets the
/// proposer (e.g. quantum/session_processor) bind a per-message correlation
/// id to the durable wal_index without relying on FIFO heuristics.
/// Payload:
/// `[correlation_id:u64 LE][partition_id:u16 LE][wal_index:u64 LE]` (18 bytes).
pub const MSG_PROPOSAL_ASSIGNED: u8   = 0x14;

// Persistence
pub const MSG_WAL_ENTRY: u8           = 0x20;
pub const MSG_FSYNC_ACK: u8           = 0x21;
pub const MSG_DURABILITY_PROOF: u8    = 0x22;
pub const MSG_COMMITTED_BATCH: u8     = 0x23;
/// WAL entry random-access request from `replicator` (or any other
/// consumer that needs to read back a specific log index). Payload
/// (12 bytes): `[request_id:u32 LE][wal_index:u64 LE]`. The WAL
/// replies on `entry_reply` with `MSG_WAL_ENTRY_REPLY`. A zero-body
/// reply means the index is unknown / below the retention floor —
/// callers should fall back to a snapshot install.
pub const MSG_WAL_ENTRY_REQUEST: u8   = 0x29;
/// WAL entry random-access reply. Payload (20+ bytes):
/// `[request_id:u32 LE][term:u64 LE][index:u64 LE][body...]`. When
/// `body.is_empty()` the entry was not found at this WAL.
pub const MSG_WAL_ENTRY_REPLY: u8     = 0x2A;
/// Apply-pipeline reset notification emitted by `raft_engine` after a
/// snapshot install fast-forwards `commit_index`. Payload (16 bytes):
/// `[term:u64 LE][index:u64 LE]`. The pipeline must drop any pending
/// observer entries whose index <= reset index and bump its own
/// `apply_index` to the reset point. See §2.3 of the phase-3 RFC.
pub const MSG_APPLY_PIPELINE_RESET: u8 = 0x2B;
/// WAL compaction request emitted by `raft_engine` after a snapshot
/// install or post-snapshot trim. Payload (8 bytes):
/// `[before_index:u64 LE]`. WAL deletes segments whose max-index <
/// `before_index` and trims its in-memory offset map.
pub const MSG_WAL_COMPACT_BEFORE: u8  = 0x2C;

/// `MSG_WAL_ENTRY_REQUEST` payload size (12 bytes).
pub const WAL_ENTRY_REQUEST_LEN: usize = 12;
/// Fixed header size of `MSG_WAL_ENTRY_REPLY` (20 bytes); body follows.
pub const WAL_ENTRY_REPLY_HDR: usize = 20;

#[inline]
pub fn encode_wal_entry_request(buf: &mut [u8; WAL_ENTRY_REQUEST_LEN], request_id: u32, wal_index: u64) {
    buf[0..4].copy_from_slice(&request_id.to_le_bytes());
    buf[4..12].copy_from_slice(&wal_index.to_le_bytes());
}

#[inline]
pub fn decode_wal_entry_request(buf: &[u8]) -> Option<(u32, u64)> {
    if buf.len() < WAL_ENTRY_REQUEST_LEN { return None; }
    let request_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let wal_index = u64::from_le_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    Some((request_id, wal_index))
}

#[inline]
pub fn encode_wal_entry_reply_hdr(
    buf: &mut [u8; WAL_ENTRY_REPLY_HDR],
    request_id: u32,
    term: u64,
    index: u64,
) {
    buf[0..4].copy_from_slice(&request_id.to_le_bytes());
    buf[4..12].copy_from_slice(&term.to_le_bytes());
    buf[12..20].copy_from_slice(&index.to_le_bytes());
}

#[inline]
pub fn decode_wal_entry_reply(buf: &[u8]) -> Option<(u32, u64, u64, usize)> {
    if buf.len() < WAL_ENTRY_REPLY_HDR { return None; }
    let request_id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let term = u64::from_le_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    let index = u64::from_le_bytes([
        buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
    ]);
    Some((request_id, term, index, WAL_ENTRY_REPLY_HDR))
}
/// Per-entry committed envelope emitted on `apply_pipeline.committed_entries`.
/// Payload: `[term:u64 LE][index:u64 LE][body...]`. Same body bytes the
/// proposer originally submitted via `MSG_CLIENT_PROPOSAL` (or, for
/// tagged proposals, after the 8-byte correlation_id is stripped). The
/// stream is in strict commit-index order and only contains entries
/// whose index has been observed in a `MSG_COMMITTED_BATCH` horizon.
/// Consumers MUST treat the body as opaque.
pub const MSG_COMMITTED_ENTRY: u8     = 0x24;

// Control plane
pub const MSG_CP_PROOF: u8            = 0x30;
pub const MSG_CACHE_STATE: u8         = 0x31;
pub const MSG_FALLBACK_SIGNAL: u8     = 0x32;
pub const MSG_READ_PERMIT: u8         = 0x33;

// Flow control
pub const MSG_THROTTLE_CREDITS: u8    = 0x40;
pub const MSG_THROTTLE_ENVELOPE: u8   = 0x41;
pub const MSG_LAG_SIGNAL: u8          = 0x42;

// Snapshot
pub const MSG_SNAPSHOT_CHUNK: u8      = 0x50;
pub const MSG_SNAPSHOT_MANIFEST: u8   = 0x51;
pub const MSG_SNAPSHOT_TRIGGER: u8    = 0x52;
/// InstallSnapshot RPC (leader → follower). Payload header (33 bytes):
/// `[term:u64][last_included_index:u64][last_included_term:u64][offset:u64][done:u8][data...]`
/// `done == 1` marks the final chunk. Until then the follower accumulates
/// `data` at `offset` into a per-source buffer. See RFC §5.13.
pub const MSG_INSTALL_SNAPSHOT: u8    = 0x53;
/// Follower → leader response. Payload (9 bytes): `[term:u64][success:u8]`.
pub const MSG_INSTALL_SNAPSHOT_RESP: u8 = 0x54;
/// Internal signal `snapshot_engine` → `raft_engine` when an install
/// finishes locally. Payload (24 bytes):
/// `[term:u64][last_included_index:u64][last_included_term:u64]`.
pub const MSG_SNAPSHOT_INSTALLED: u8  = 0x55;
/// `replicator` → `snapshot_engine` on-demand catch-up trigger. The
/// replicator emits this when a follower's `next_index` falls below
/// the leader's WAL retention floor (a NOT_FOUND `MSG_WAL_ENTRY_REPLY`
/// is the canonical signal). `snapshot_engine` responds by emitting
/// `MSG_INSTALL_SNAPSHOT` chunks at the most recent snapshot point.
/// Payload (1 byte): `[target_replica_id:u8]` (0xFF = broadcast).
/// See RFC §4.2 of the phase-3 plan.
pub const MSG_SNAPSHOT_INSTALL_REQUEST: u8 = 0x56;

/// TLS peer identity binding from the foundation `tls` module to
/// `peer_router`. Fired once per accepted/established TLS session;
/// `peer_router` keys the connection's `replica_id` from this
/// envelope and refuses to honour any in-band plaintext handshake
/// that disagrees. Until fluxor TLS exposes the SVID this envelope
/// remains the binding-contract surface — operators can stub it via
/// a sidecar module that reads cert metadata directly.
///
/// Payload (variable):
///   `[conn_id:u8]
///    [replica_id:u8]
///    [verified:u8 (0 = plaintext, 1 = TLS-verified)]
///    [svid_len:u8]
///    [svid:svid_len bytes — UTF-8 SPIFFE ID, may be empty]`
///
/// `replica_id == 0xFF` clears any previously bound identity for the
/// connection (e.g. the TLS layer downgraded / mismatched). See RFC
/// §5.1 of the phase-3 plan.
pub const MSG_PEER_IDENTITY: u8       = 0x5A;

/// `MSG_PEER_IDENTITY` payload minimum size (no SVID body): 4 bytes.
pub const PEER_IDENTITY_HDR: usize = 4;

#[inline]
pub fn encode_peer_identity(
    buf: &mut [u8],
    conn_id: u8,
    replica_id: u8,
    verified: bool,
    svid: &[u8],
) -> usize {
    let total = PEER_IDENTITY_HDR + svid.len();
    if buf.len() < total {
        return 0;
    }
    buf[0] = conn_id;
    buf[1] = replica_id;
    buf[2] = if verified { 1 } else { 0 };
    buf[3] = svid.len().min(0xFF) as u8;
    if !svid.is_empty() {
        buf[PEER_IDENTITY_HDR..total].copy_from_slice(&svid[..svid.len().min(0xFF)]);
    }
    total
}

#[inline]
pub fn decode_peer_identity(buf: &[u8]) -> Option<(u8, u8, bool, usize)> {
    if buf.len() < PEER_IDENTITY_HDR {
        return None;
    }
    let conn_id = buf[0];
    let replica_id = buf[1];
    let verified = buf[2] != 0;
    let svid_len = buf[3] as usize;
    if buf.len() < PEER_IDENTITY_HDR + svid_len {
        return None;
    }
    Some((conn_id, replica_id, verified, PEER_IDENTITY_HDR))
}
/// State-machine snapshot chunk sent from a downstream consumer to
/// `snapshot_engine` (export path) or from `snapshot_engine` to the
/// downstream consumer (install path). Payload (28+ bytes):
/// `[term:u64 LE][last_included_index:u64 LE][offset:u64 LE]
///  [done:u8][reserved:u8;3][body...]`. The body is opaque — only
/// the producing consumer knows how to interpret it. See RFC §2.1.
pub const MSG_APP_SNAPSHOT_CHUNK: u8  = 0x57;
/// Snapshot-export trigger from `snapshot_engine` to a downstream
/// consumer. Payload (16 bytes):
/// `[term:u64 LE][last_included_index:u64 LE]`. The consumer
/// responds by emitting one or more `MSG_APP_SNAPSHOT_CHUNK` messages
/// back on its `snapshot_export_out` port, terminated by `done = 1`.
pub const MSG_APP_SNAPSHOT_REQUEST: u8 = 0x58;
/// "Discard current state, replay from incoming chunks" signal from
/// `snapshot_engine` to a downstream consumer after `MSG_APP_SNAPSHOT_CHUNK`
/// install begins for a snapshot ahead of the consumer's current
/// `apply_index`. Payload (16 bytes):
/// `[term:u64 LE][last_included_index:u64 LE]`.
pub const MSG_APP_SNAPSHOT_RESET: u8  = 0x59;

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
    if buf.len() < total { return 0; }
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8..16].copy_from_slice(&last_included_index.to_le_bytes());
    buf[16..24].copy_from_slice(&offset.to_le_bytes());
    buf[24] = done as u8;
    buf[25] = 0; buf[26] = 0; buf[27] = 0;
    if !body.is_empty() {
        buf[APP_SNAPSHOT_HDR..total].copy_from_slice(body);
    }
    total
}

#[inline]
pub fn decode_app_snapshot_chunk(buf: &[u8]) -> Option<(u64, u64, u64, bool, usize)> {
    if buf.len() < APP_SNAPSHOT_HDR { return None; }
    let term = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let idx = u64::from_le_bytes([buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]]);
    let offset = u64::from_le_bytes([buf[16],buf[17],buf[18],buf[19],buf[20],buf[21],buf[22],buf[23]]);
    let done = buf[24] != 0;
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
    if buf.len() < total { return 0; }
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8..16].copy_from_slice(&last_included_index.to_le_bytes());
    buf[16..24].copy_from_slice(&last_included_term.to_le_bytes());
    buf[24..32].copy_from_slice(&offset.to_le_bytes());
    buf[32] = if done { 1 } else { 0 };
    if !data.is_empty() {
        buf[INSTALL_SNAPSHOT_HDR..total].copy_from_slice(data);
    }
    total
}

#[inline]
pub fn decode_install_snapshot(buf: &[u8]) -> Option<(u64, u64, u64, u64, bool, usize)> {
    if buf.len() < INSTALL_SNAPSHOT_HDR { return None; }
    let term = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let last_idx = u64::from_le_bytes([buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]]);
    let last_term = u64::from_le_bytes([buf[16],buf[17],buf[18],buf[19],buf[20],buf[21],buf[22],buf[23]]);
    let offset = u64::from_le_bytes([buf[24],buf[25],buf[26],buf[27],buf[28],buf[29],buf[30],buf[31]]);
    let done = buf[32] != 0;
    Some((term, last_idx, last_term, offset, done, INSTALL_SNAPSHOT_HDR))
}

/// `MSG_SNAPSHOT_INSTALLED` payload size: 24 bytes.
pub const SNAPSHOT_INSTALLED_LEN: usize = 24;

#[inline]
pub fn encode_snapshot_installed(buf: &mut [u8; SNAPSHOT_INSTALLED_LEN], term: u64, last_included_index: u64, last_included_term: u64) {
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8..16].copy_from_slice(&last_included_index.to_le_bytes());
    buf[16..24].copy_from_slice(&last_included_term.to_le_bytes());
}

#[inline]
pub fn decode_snapshot_installed(buf: &[u8]) -> Option<(u64, u64, u64)> {
    if buf.len() < SNAPSHOT_INSTALLED_LEN { return None; }
    let term = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let last_idx = u64::from_le_bytes([buf[8],buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15]]);
    let last_term = u64::from_le_bytes([buf[16],buf[17],buf[18],buf[19],buf[20],buf[21],buf[22],buf[23]]);
    Some((term, last_idx, last_term))
}

// Key management
pub const MSG_DEK_EPOCH: u8           = 0x60;
pub const MSG_CERT_REFRESH: u8        = 0x61;

// Telemetry
pub const MSG_METRICS: u8             = 0x70;
pub const MSG_READYZ: u8              = 0x71;
pub const MSG_WHY: u8                 = 0x72;
/// Typed metric sample envelope (RFC §4.3). Replaces ad-hoc
/// per-module `MSG_METRICS` payloads with a uniform shape so
/// `telemetry_agg` can aggregate without per-module parse code.
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
pub const MSG_METRIC_SAMPLE: u8       = 0x73;
/// Inbound HTTP request frame for the diagnostic adapter (RFC §4.4).
/// Payload (variable):
///   `[conn_id:u8][method:u8 (G=0x47, P=0x50, ...)][path_len:u8][path bytes][body...]`
/// The method byte is the first character of the HTTP verb so the
/// adapter can dispatch without parsing the whole verb.
pub const MSG_HTTP_REQUEST: u8        = 0x74;
/// Outbound HTTP response frame from the adapter back to the HTTP
/// server module. Payload (variable):
///   `[conn_id:u8][status:u16 LE][body_len:u16 LE][body bytes]`
/// `Content-Type` is implied by status: 200 → text/plain, 4xx/5xx →
/// text/plain with a short error string. The HTTP server module
/// frames the wire-level HTTP response itself.
pub const MSG_HTTP_RESPONSE: u8       = 0x75;

/// Metric kinds for `MSG_METRIC_SAMPLE`.
pub const METRIC_KIND_COUNTER: u8     = 0;
pub const METRIC_KIND_GAUGE: u8       = 1;
pub const METRIC_KIND_HISTOGRAM: u8   = 2;

/// Module id space (RFC §4.3). Stable across releases — never
/// re-number an existing entry. Add new modules at the end.
pub const MODULE_ID_RAFT_ENGINE: u8       = 0x01;
pub const MODULE_ID_WAL: u8               = 0x02;
pub const MODULE_ID_REPLICATOR: u8        = 0x03;
pub const MODULE_ID_COMMIT_TRACKER: u8    = 0x04;
pub const MODULE_ID_DURABILITY_LEDGER: u8 = 0x05;
pub const MODULE_ID_APPLY_PIPELINE: u8    = 0x06;
pub const MODULE_ID_SNAPSHOT_ENGINE: u8   = 0x07;
pub const MODULE_ID_CP_PROOF_CACHE: u8    = 0x08;
pub const MODULE_ID_READ_GATE: u8         = 0x09;
pub const MODULE_ID_THROTTLE_GATE: u8     = 0x0A;
pub const MODULE_ID_FLOW_CONTROLLER: u8   = 0x0B;
pub const MODULE_ID_CLIENT_CODEC: u8      = 0x0C;
pub const MODULE_ID_CLIENT_SURFACE: u8    = 0x0D;
pub const MODULE_ID_PEER_ROUTER: u8       = 0x0E;
pub const MODULE_ID_PARTITION_ROUTER: u8  = 0x0F;
pub const MODULE_ID_PLACEMENT_ROUTER: u8  = 0x10;
pub const MODULE_ID_ADMIN_HANDLER: u8     = 0x11;
pub const MODULE_ID_RBAC: u8              = 0x12;
pub const MODULE_ID_KEY_MANAGER: u8       = 0x13;
pub const MODULE_ID_CP_BRIDGE: u8         = 0x14;

/// Per-module metric ids. Each module owns a small private space
/// (0x00..0xFF). Documented next to the module's metric emission.
pub mod metric_ids {
    // raft_engine (module_id = 0x01)
    pub const RAFT_ROLE: u16                   = 0x0001;
    pub const RAFT_CURRENT_TERM: u16           = 0x0002;
    pub const RAFT_PROPOSALS_RECEIVED: u16     = 0x0003;
    pub const RAFT_ENTRIES_APPENDED: u16       = 0x0004;
    pub const RAFT_ELECTIONS_STARTED: u16      = 0x0005;
    pub const RAFT_PROPOSALS_DROPPED_FROZEN: u16  = 0x0006;
    pub const RAFT_PROPOSALS_DROPPED_STRICT: u16 = 0x0007;
    pub const RAFT_FROZEN_FLAG: u16            = 0x0008;
    pub const RAFT_STRICT_FALLBACK_FLAG: u16   = 0x0009;

    // wal (module_id = 0x02)
    pub const WAL_ENTRIES_WRITTEN: u16         = 0x0001;
    pub const WAL_BYTES_WRITTEN: u16           = 0x0002;
    pub const WAL_SEGMENT_SEQ: u16             = 0x0003;

    // replicator (module_id = 0x03)
    pub const REPL_RPCS_SENT: u16              = 0x0001;
    pub const REPL_ACKS_RECEIVED: u16          = 0x0002;
    pub const REPL_NACKS_RECEIVED: u16         = 0x0003;
    pub const REPL_CATCHUP_SENT: u16           = 0x0004;
}

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
    buf[0] = module_id;
    buf[1..3].copy_from_slice(&partition_id.to_le_bytes());
    buf[3..5].copy_from_slice(&metric_id.to_le_bytes());
    buf[5] = kind;
    buf[6..14].copy_from_slice(&value.to_le_bytes());
}

#[inline]
pub fn decode_metric_sample(buf: &[u8]) -> Option<(u8, u16, u16, u8, i64)> {
    if buf.len() < METRIC_SAMPLE_LEN {
        return None;
    }
    let module_id = buf[0];
    let partition_id = u16::from_le_bytes([buf[1], buf[2]]);
    let metric_id = u16::from_le_bytes([buf[3], buf[4]]);
    let kind = buf[5];
    let value = i64::from_le_bytes([
        buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
    ]);
    Some((module_id, partition_id, metric_id, kind, value))
}

// Routing
pub const MSG_PLACEMENT_UPDATE: u8    = 0x80;

/// Envelope header size (1 byte type + 2 bytes length).
pub const ENVELOPE_HDR: usize = 3;

/// Maximum payload size in a single envelope (64 KiB - 1).
pub const MAX_PAYLOAD: usize = 0xFFFF;

// ── Encoding helpers ────────────────────────────────────────────────────────

/// Encode an envelope header into `buf[0..3]`. Returns 3 on success, -1 if
/// buf is too small.
#[inline]
pub fn encode_header(buf: &mut [u8], msg_type: u8, payload_len: u16) -> i32 {
    if buf.len() < ENVELOPE_HDR { return -1; }
    buf[0] = msg_type;
    let lb = payload_len.to_le_bytes();
    buf[1] = lb[0];
    buf[2] = lb[1];
    ENVELOPE_HDR as i32
}

/// Decode an envelope header from `buf[0..3]`. Returns `(msg_type, payload_len)`.
/// Caller must ensure buf.len() >= ENVELOPE_HDR.
#[inline]
pub fn decode_header(buf: &[u8]) -> (u8, u16) {
    let msg_type = buf[0];
    let payload_len = u16::from_le_bytes([buf[1], buf[2]]);
    (msg_type, payload_len)
}

// Channel I/O over `SyscallTable` (`channel_{write,read}_msg`,
// partitioned and routed variants) lives in `wire_channels.rs`,
// the PIC-only companion to this file.

// ── Partitioned envelope helpers (multi-Raft channels) ──────────────────────
//
// Channels between partition-aware modules carry a 2-byte `partition_id`
// prefix in front of the standard 3-byte envelope. See
// `.context/rfc_partition_groups.md` §"Wire envelope". Partitioned and
// non-partitioned channels coexist via distinct ports, never via in-band
// flag bytes.
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
    if buf.len() < PARTITIONED_HDR { return -1; }
    let pid = partition_id.to_le_bytes();
    buf[0] = pid[0];
    buf[1] = pid[1];
    buf[2] = msg_type;
    let lb = payload_len.to_le_bytes();
    buf[3] = lb[0];
    buf[4] = lb[1];
    PARTITIONED_HDR as i32
}

/// Decode a partitioned envelope header from `buf[0..5]`. Returns
/// `(partition_id, msg_type, payload_len)`. Caller must ensure
/// `buf.len() >= PARTITIONED_HDR`.
#[inline]
pub fn decode_partitioned_header(buf: &[u8]) -> (u16, u8, u16) {
    let partition_id = u16::from_le_bytes([buf[0], buf[1]]);
    let msg_type = buf[2];
    let payload_len = u16::from_le_bytes([buf[3], buf[4]]);
    (partition_id, msg_type, payload_len)
}

// ── Routed message helpers (for peer_tx channel) ────────────────────────────
//
// Messages on the peer_tx channel between raft_engine/replicator and
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
// between per-partition raft_engines / replicators and peer_router.
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
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8..16].copy_from_slice(&index.to_le_bytes());
}

/// Decode a term + index pair (16 bytes).
#[inline]
pub fn decode_term_index(buf: &[u8]) -> (u64, u64) {
    let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let index = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
    (term, index)
}

// ── Extended AppendEntries envelope (RFC §5.1 log matching) ────────────────
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
    if buf.len() < total { return 0; }
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8] = leader_id;
    buf[9..17].copy_from_slice(&prev_log_index.to_le_bytes());
    buf[17..25].copy_from_slice(&prev_log_term.to_le_bytes());
    buf[25..33].copy_from_slice(&leader_commit.to_le_bytes());
    buf[33..41].copy_from_slice(&entry_term.to_le_bytes());
    buf[41..49].copy_from_slice(&entry_index.to_le_bytes());
    if !body.is_empty() {
        buf[AE_HDR_LEN..total].copy_from_slice(body);
    }
    total
}

#[inline]
pub fn decode_append_entries(buf: &[u8]) -> Option<(u64, u8, u64, u64, u64, u64, u64)> {
    if buf.len() < AE_HDR_LEN { return None; }
    let term = u64::from_le_bytes([buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]]);
    let leader_id = buf[8];
    let prev_idx = u64::from_le_bytes([buf[9],buf[10],buf[11],buf[12],buf[13],buf[14],buf[15],buf[16]]);
    let prev_term = u64::from_le_bytes([buf[17],buf[18],buf[19],buf[20],buf[21],buf[22],buf[23],buf[24]]);
    let leader_commit = u64::from_le_bytes([buf[25],buf[26],buf[27],buf[28],buf[29],buf[30],buf[31],buf[32]]);
    let entry_term = u64::from_le_bytes([buf[33],buf[34],buf[35],buf[36],buf[37],buf[38],buf[39],buf[40]]);
    let entry_index = u64::from_le_bytes([buf[41],buf[42],buf[43],buf[44],buf[45],buf[46],buf[47],buf[48]]);
    Some((term, leader_id, prev_idx, prev_term, leader_commit, entry_term, entry_index))
}

pub fn encode_term_index_replica(buf: &mut [u8], term: u64, index: u64, replica: u8) {
    encode_term_index(buf, term, index);
    buf[16] = replica;
}

/// Decode term + index + replica_id (17 bytes).
#[inline]
pub fn decode_term_index_replica(buf: &[u8]) -> (u64, u64, u8) {
    let (term, index) = decode_term_index(buf);
    (term, index, buf[16])
}

/// Encode a RequestVote / PreVote payload (25 bytes):
///   term(8) + candidate_id(1) + last_log_index(8) + last_log_term(8)
#[inline]
pub fn encode_vote_request(buf: &mut [u8], term: u64, candidate: u8, last_index: u64, last_term: u64) {
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8] = candidate;
    buf[9..17].copy_from_slice(&last_index.to_le_bytes());
    buf[17..25].copy_from_slice(&last_term.to_le_bytes());
}

/// Decode a RequestVote / PreVote payload (25 bytes).
#[inline]
pub fn decode_vote_request(buf: &[u8]) -> (u64, u8, u64, u64) {
    let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let candidate = buf[8];
    let last_index = u64::from_le_bytes([buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16]]);
    let last_term = u64::from_le_bytes([buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24]]);
    (term, candidate, last_index, last_term)
}

/// Encode a VoteResponse payload (10 bytes):
///   term(8) + granted(1) + voter_id(1)
#[inline]
pub fn encode_vote_response(buf: &mut [u8], term: u64, granted: bool, voter: u8) {
    buf[0..8].copy_from_slice(&term.to_le_bytes());
    buf[8] = granted as u8;
    buf[9] = voter;
}

/// Decode a VoteResponse payload (10 bytes).
#[inline]
pub fn decode_vote_response(buf: &[u8]) -> (u64, bool, u8) {
    let term = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
    let granted = buf[8] != 0;
    let voter = buf[9];
    (term, granted, voter)
}

/// Encode an FsyncAck payload (17 bytes):
///   term(8) + index(8) + replica_id(1)
///
/// Emitted by `wal` directly on `wal.flushed` (one `wal` per
/// partition). The `replica` byte must be the WAL's `self_id` so
/// `durability_ledger` keys per-replica progress correctly — see
/// RFC §4.1. For cross-partition fan-in to `ack_tracker` see
/// `encode_durability_proof` below.
///
/// On the leader, `durability_ledger` also receives FsyncAck frames
/// synthesized by `replicator` from follower AppendEntriesResponse
/// envelopes (see `AE_RESP_LEN`), so the per-replica progress array
/// covers every voter — the spec §10.4.1 quorum-fsync semantic.
#[inline]
pub fn encode_fsync_ack(buf: &mut [u8], term: u64, index: u64, replica: u8) {
    encode_term_index_replica(buf, term, index, replica);
}

/// Decode an FsyncAck payload (17 bytes).
#[inline]
pub fn decode_fsync_ack(buf: &[u8]) -> (u64, u64, u8) {
    decode_term_index_replica(buf)
}

/// AppendEntriesResponse payload size (25 bytes):
///   `[term:u64][last_log_index:u64][replica_byte:u8][durable_index:u64]`
/// where `replica_byte = self_id | (success << 7)`.
///
/// `durable_index` is the follower's `local_wal_durable_index` at the
/// moment the response is sent (spec §10.4.1). The leader's
/// `replicator` decodes this field and forwards a synthesized
/// `MSG_FSYNC_ACK` to `durability_ledger.ack` so the leader can
/// compute quorum durability across replicas.
///
/// The first 17 bytes are the legacy `[term][last_log_index][replica_byte]`
/// shape so older readers (e.g. `commit_tracker.drain_match_indices`,
/// which only needs `(term, last_log_index, replica)`) keep working
/// without code change.
pub const AE_RESP_LEN: usize = 25;

#[inline]
pub fn encode_append_entries_resp(
    buf: &mut [u8; AE_RESP_LEN],
    term: u64,
    last_log_index: u64,
    self_id: u8,
    success: bool,
    durable_index: u64,
) {
    encode_term_index_replica(buf, term, last_log_index, self_id);
    buf[16] = self_id | ((success as u8) << 7);
    buf[17..25].copy_from_slice(&durable_index.to_le_bytes());
}

/// Decode an AppendEntriesResponse payload. Accepts either the
/// 25-byte modern shape or the legacy 17-byte shape (durable_index
/// defaults to 0, which leaves the leader's `durability_ledger`
/// progress slot for that replica unchanged).
/// Returns `(term, last_log_index, replica, success, durable_index)`.
#[inline]
pub fn decode_append_entries_resp(buf: &[u8]) -> Option<(u64, u64, u8, bool, u64)> {
    if buf.len() < 17 { return None; }
    let (term, last_index, replica_byte) = decode_term_index_replica(buf);
    let success = (replica_byte & 0x80) != 0;
    let replica = replica_byte & 0x7F;
    let durable_index = if buf.len() >= AE_RESP_LEN {
        u64::from_le_bytes([
            buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23], buf[24],
        ])
    } else {
        0
    };
    Some((term, last_index, replica, success, durable_index))
}

/// DurabilityProof payload size (19 bytes):
///   partition_id(2) + term(8) + index(8) + replica_id(1)
pub const DURABILITY_PROOF_LEN: usize = 19;

/// Encode a DurabilityProof payload. The `partition_id` prefix lets
/// downstream consumers (especially `ack_tracker`, which fans in
/// proofs from every per-partition `durability_ledger`) disambiguate
/// the same `wal_index` across partitions. Per-partition consumers
/// like `commit_tracker` ignore the prefix — it always matches their
/// own configured slot.
#[inline]
pub fn encode_durability_proof(
    buf: &mut [u8],
    partition_id: u16,
    term: u64,
    index: u64,
    replica: u8,
) {
    let pid = partition_id.to_le_bytes();
    buf[0] = pid[0];
    buf[1] = pid[1];
    buf[2..10].copy_from_slice(&term.to_le_bytes());
    buf[10..18].copy_from_slice(&index.to_le_bytes());
    buf[18] = replica;
}

/// Decode a DurabilityProof payload (19 bytes).
/// Returns `(partition_id, term, index, replica)`.
#[inline]
pub fn decode_durability_proof(buf: &[u8]) -> (u16, u64, u64, u8) {
    let partition_id = u16::from_le_bytes([buf[0], buf[1]]);
    let term = u64::from_le_bytes([
        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
    ]);
    let index = u64::from_le_bytes([
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
    ]);
    let replica = buf[18];
    (partition_id, term, index, replica)
}

/// Encode a CacheState payload (1 byte): the CP_* constant.
#[inline]
pub fn encode_cache_state(buf: &mut [u8], state: u8) {
    buf[0] = state;
}

/// Decode a CacheState payload (1 byte).
#[inline]
pub fn decode_cache_state(buf: &[u8]) -> u8 {
    buf[0]
}

/// Encode ThrottleCredits payload (8 bytes): entry_credits(4) + byte_credits(4).
#[inline]
pub fn encode_credits(buf: &mut [u8], entry: i32, byte: i32) {
    buf[0..4].copy_from_slice(&entry.to_le_bytes());
    buf[4..8].copy_from_slice(&byte.to_le_bytes());
}

/// Decode ThrottleCredits payload (8 bytes).
#[inline]
pub fn decode_credits(buf: &[u8]) -> (i32, i32) {
    let entry = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let byte = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    (entry, byte)
}

// ── FNV-1a 64-bit hash ──────────────────────────────────────────────────────
//
// Used by `partition_router` for routing-key → partition_id mapping. Same
// algorithm as `quantum/modules/common/wire.rs::fnv1a_64` so a hash
// computed at the broker boundary (e.g. of an MQTT topic string) stays
// stable through clustor.

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
// 1. Legacy (untagged) — sent on raft_engine.proposals (in[1]):
//        payload = body
//    No correlation back to the proposer; ack-on-durability has to be
//    inferred (e.g. by FIFO heuristics in ack_tracker).
//
// 2. Tagged — sent on raft_engine.proposals_tagged (in[4]):
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
    if dst.len() < total { return -1; }
    dst[0..8].copy_from_slice(&correlation_id.to_le_bytes());
    dst[8..total].copy_from_slice(body);
    total as i32
}

/// Decode a tagged proposal payload. Returns `(correlation_id, body_offset)`
/// where `body_offset == TAGGED_PROPOSAL_HDR`. Caller slices `buf[body_offset..]`
/// to obtain the body. Returns `None` if `buf` is shorter than the header.
#[inline]
pub fn decode_tagged_proposal(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.len() < TAGGED_PROPOSAL_HDR { return None; }
    let correlation_id = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    Some((correlation_id, TAGGED_PROPOSAL_HDR))
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
    dst[0..8].copy_from_slice(&correlation_id.to_le_bytes());
    let pid = partition_id.to_le_bytes();
    dst[8] = pid[0];
    dst[9] = pid[1];
    dst[10..18].copy_from_slice(&wal_index.to_le_bytes());
}

/// Decode a MSG_PROPOSAL_ASSIGNED payload (18 bytes).
/// Returns `(correlation_id, partition_id, wal_index)`.
#[inline]
pub fn decode_proposal_assigned(buf: &[u8]) -> (u64, u16, u64) {
    let correlation_id = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let partition_id = u16::from_le_bytes([buf[8], buf[9]]);
    let wal_index = u64::from_le_bytes([
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
    ]);
    (correlation_id, partition_id, wal_index)
}
