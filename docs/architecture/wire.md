# Clustor Wire Format

How bytes flow between clustor's modules and between clustor nodes.
One shared file, `modules/common/wire.rs`, defines every message id,
payload layout, and envelope helper; each module compiles it in via
`#[path]`, so producers and consumers agree by construction. The WAL's
on-disk frame layout lives in its own shared file,
`modules/common/wal_frame.rs`, summarised in
[WAL frame contract](#wal-frame-contract).

## Stability

External consumers go through `modules/common/replica_facade.rs`
rather than importing `MSG_*` constants directly; the facade is the
integration surface, and this file documents the encodings behind
it.

## Encoding rules

All on-wire integers are fixed-width little-endian. There is no
schema-version header, no handshake or extension negotiation, and no
numeric wire-error registry: a decoder that receives a truncated or
malformed payload returns a failure value (`None`, or inert zeros on
the infallible paths) and the frame is dropped.

Every message travels in an envelope. Four envelope shapes exist, on
distinct channels — the shape is a property of the port, never
signalled in-band. Source: `modules/common/wire.rs`.

### Plain envelope (3-byte header, `ENVELOPE_HDR`)

| Offset | Field | Type |
|---|---|---|
| 0 | `msg_type` | `u8` |
| 1 | `len` | `u16` LE |
| 3 | payload | `len` bytes |

### Partitioned envelope (5-byte header, `PARTITIONED_HDR`)

Used between partition-aware modules (multi-Raft channels).

| Offset | Field | Type |
|---|---|---|
| 0 | `partition_id` | `u16` LE |
| 2 | `msg_type` | `u8` |
| 3 | `len` | `u16` LE |
| 5 | payload | `len` bytes |

### Routed envelope (4-byte header, `ROUTED_HDR`)

Used on the `peer_tx` channel from consensus/replicator to
`peer_router`: a 1-byte `target_replica` precedes the plain envelope.
`target_replica = 0xFF` (`TARGET_BROADCAST`) means "send to all
peers".

### Routed partitioned envelope (6-byte header, `ROUTED_PARTITIONED_HDR`)

`[target_replica:u8][partition_id:u16 LE][msg_type:u8][len:u16 LE]`
then the payload. `target_replica` is scoped to the named partition;
`peer_router` keys its connection table by
`(partition_id, target_replica)`.

### Payload cap

The `len` field is a `u16`, so a single envelope carries at most
`MAX_PAYLOAD = 0xFFFF` bytes (64 KiB − 1). Larger transfers (snapshot
bodies, catch-up entries) are chunked at the message layer. Individual
messages carry much smaller caps of their own — a proposal body is
bounded by the WAL entry cap below.

## Message catalog

Ids are grouped by area. Layouts shown field-by-field are the encode /
decode helpers in `modules/common/wire.rs`; messages listed without a
layout carry payloads private to their producer and consumer. This
catalog covers the major families rather than every id.

### Raft RPCs (0x01–0x0E)

| Id | Message | Payload |
|---|---|---|
| 0x01 | `MSG_APPEND_ENTRIES` | 49-byte header + entry body (below) |
| 0x02 | `MSG_APPEND_ENTRIES_RESP` | 26 bytes (below) |
| 0x03 / 0x04 | `MSG_REQUEST_VOTE` / `_RESP` | request 25 B, response 10 B (below) |
| 0x05 / 0x06 | `MSG_PRE_VOTE` / `_RESP` | same shapes as RequestVote |
| 0x07 / 0x08 | `MSG_HEARTBEAT` / `_RESP` | leader liveness |
| 0x09 | `MSG_LEADER_HINT` | `[leader_id:u8 (0xFF = unknown)][term:u64 LE]` |
| 0x0A | `MSG_TIMEOUT_NOW` | `[caller_term:u64 LE]` — leader-transfer promotion |
| 0x0B / 0x0C | `MSG_READ_INDEX_PROBE` / `_RESP` | probe `[probe_id:u64][term:u64]`; response adds `[replica:u8]` |
| 0x0D / 0x0E | `MSG_READ_PROBE_REQ` / `_REPLY` | internal apply ↔ raft read-confirmation seam |

`MSG_APPEND_ENTRIES` fixed header (`AE_HDR_LEN = 49`), one entry per
frame; an empty-entry log-matching probe sets
`entry_term = entry_index = 0`:

| Offset | Field | Type |
|---|---|---|
| 0 | `term` | `u64` LE |
| 8 | `leader_id` | `u8` |
| 9 | `prev_log_index` | `u64` LE |
| 17 | `prev_log_term` | `u64` LE |
| 25 | `leader_commit` | `u64` LE |
| 33 | `entry_term` | `u64` LE |
| 41 | `entry_index` | `u64` LE |
| 49 | entry body | variable |

`MSG_APPEND_ENTRIES_RESP` (`AE_RESP_LEN = 26`):
`[term:u64][last_log_index:u64][replica_byte:u8][durable_index:u64][busy:u8]`,
where `replica_byte = self_id | (success << 7)`. `durable_index` is
the follower's locally durable WAL index, which the leader's
replicator forwards as a synthesised `MSG_FSYNC_ACK` so quorum
durability covers every voter. `busy = 1` marks a failure caused by
follower WAL backpressure, not log divergence — the leader retries
without rolling `next_index` back. Decoders accept the legacy 17- and
25-byte shapes with the missing fields defaulting to zero.

Vote request (25 bytes): `[term:u64][candidate_id:u8]
[last_log_index:u64][last_log_term:u64]`. Vote response (10 bytes):
`[term:u64][granted:u8][voter_id:u8]`. Pre-vote uses the same layouts
under its own ids; there is no `high_rtt` field.

### Client path (0x10–0x1B)

| Id | Message | Notes |
|---|---|---|
| 0x10 | `MSG_CLIENT_PROPOSAL` | body is opaque; tagged form prefixes `[correlation_id:u64 LE]` (must be non-zero) on the `proposals_tagged` port |
| 0x11 | `MSG_CLIENT_RESPONSE` | commit ack; internal v2 `[partition_id:u16][term:u64][index:u64]` |
| 0x12 / 0x13 | `MSG_ADMIN_COMMAND` / `_RESPONSE` | response's first byte is an `ADMIN_STATUS_*` code |
| 0x14 | `MSG_PROPOSAL_ASSIGNED` | `[correlation_id:u64][partition_id:u16][wal_index:u64]` (18 B) — binds a tagged proposal to its log index |
| 0x15 | `MSG_CLIENT_REJECT` | structured rejection, 11 B — see [errors.md](errors.md) |
| 0x16 | `MSG_CLIENT_READ_REQUEST` | linearizable read: `[read_id:u64 LE][body]` after the gateway's conn_id prefix |
| 0x17 | `MSG_CLIENT_REJECT_INTERNAL` | throttle → codec rejection, 18 B — see [errors.md](errors.md) |
| 0x18 | `MSG_CLIENT_READ_RESPONSE` | `[correlation_id:u64]` — the linearization point was reached; the state-machine query is the application's job |
| 0x19 | `MSG_ADMIN_APPLIED` | `[command_id:u32][status:u8]` — apply confirmation to the admin component |
| 0x1A | `MSG_ADMIN_COMMITTED` | internal consensus seam: committed admin entry minus its magic |
| 0x1B | `MSG_CONFIG_COMMITTED` | committed config-change entry, body verbatim (magic retained) |

### Persistence and durability (0x20–0x2F)

| Id | Message | Notes |
|---|---|---|
| 0x20 | `MSG_WAL_ENTRY` | entry to append |
| 0x21 | `MSG_FSYNC_ACK` | `[term:u64][index:u64][replica:u8]` (17 B) — emitted by the WAL on `wal.flushed`, and synthesised by the replicator from follower AE responses |
| 0x22 | `MSG_DURABILITY_PROOF` | `[partition_id:u16][term:u64][index:u64][replica:u8]` (19 B) — cross-partition fan-in to the ack tracker |
| 0x23 | `MSG_COMMITTED_BATCH` | commit-horizon advance |
| 0x24 | `MSG_COMMITTED_ENTRY` | `[term:u64][index:u64][body...]` — per-entry committed stream in strict commit order; body is opaque |
| 0x25 | `MSG_WAL_TRUNCATE_ACK` | `[keep_through_index:u64][request_id:u32][durable:u8]` (13 B) — the WAL's answer to a truncation request; `durable = 0` means the suffix is still on disk and the tip must not be rewound |
| 0x29 / 0x2A | `MSG_WAL_ENTRY_REQUEST` / `_REPLY` | random-access read-back; request `[request_id:u32][wal_index:u64]`, reply header `[request_id:u32][term:u64][index:u64][prev_term:u64]` (28 B) + body; an empty body means not found |
| 0x2B | `MSG_APPLY_PIPELINE_RESET` | `[term:u64][index:u64]` after a snapshot install fast-forwards commit |
| 0x2C | `MSG_WAL_COMPACT_BEFORE` | `[before_index:u64]` — drop segments below the floor |
| 0x2D | `MSG_WAL_REPLAY_COMPLETE` | `[term:u64][high_water_index:u64]` — boot replay finished; raft resumes its index here |
| 0x2E | `MSG_WAL_TRUNCATE_AFTER` | `[keep_through_index:u64][request_id:u32]` (12 B) — Raft §5.3 conflict repair; never crosses `commit_index`. The request id correlates the `MSG_WAL_TRUNCATE_ACK` that releases the tip |
| 0x2F | `MSG_WAL_REJECT` | `[expected_index:u64]` — continuity rejection, see [errors.md](errors.md) |

### Control plane (0x30–0x33)

`MSG_CP_PROOF` (0x30), `MSG_CACHE_STATE` (0x31, one `CP_*` state
byte), `MSG_FALLBACK_SIGNAL` (0x32), `MSG_READ_PERMIT` (0x33).

### Flow control (0x40–0x43)

`MSG_THROTTLE_CREDITS` (0x40, `[entry_credits:i32][byte_credits:i32]`),
`MSG_THROTTLE_ENVELOPE` (0x41), `MSG_LAG_SIGNAL` (0x42), and
`MSG_THROTTLE_REFILL` (0x43,
`[entry_grant:i32][byte_grant:i32][entry_capacity:i32][byte_capacity:i32]`).

### Snapshots (0x50–0x59) and peer identity (0x5A)

| Id | Message | Notes |
|---|---|---|
| 0x50–0x52 | `MSG_SNAPSHOT_CHUNK` / `_MANIFEST` / `_TRIGGER` | snapshot plumbing |
| 0x53 | `MSG_INSTALL_SNAPSHOT` | 33-byte header `[term:u64][last_included_index:u64][last_included_term:u64][offset:u64][done:u8]` + data |
| 0x54 | `MSG_INSTALL_SNAPSHOT_RESP` | `[term:u64][success:u8]` |
| 0x55 | `MSG_SNAPSHOT_INSTALLED` | `[term:u64][last_included_index:u64][last_included_term:u64]` (24 B) |
| 0x56 | `MSG_SNAPSHOT_INSTALL_REQUEST` | `[target_replica_id:u8]` (0xFF = broadcast) — follower fell below the WAL retention floor |
| 0x57 | `MSG_APP_SNAPSHOT_CHUNK` | 28-byte header `[term:u64][last_included_index:u64][offset:u64][done:u8][reserved:u8;3]` + opaque body |
| 0x58 / 0x59 | `MSG_APP_SNAPSHOT_REQUEST` / `_RESET` | `[term:u64][last_included_index:u64]` |
| 0x5A | `MSG_PEER_IDENTITY` | `[conn_id:u8][replica_id:u8][verified:u8][svid_len:u8][svid...]` — TLS identity binding to `peer_router` |

### Key management, telemetry, and membership (0x60–0x76)

`MSG_DEK_EPOCH` (0x60) and `MSG_CERT_REFRESH` (0x61) cover key
management. The telemetry family:

- `MSG_METRICS` (0x70), `MSG_READYZ` (0x71), `MSG_WHY` (0x72).
- `MSG_METRIC_SAMPLE` (0x73), 14 bytes:
  `[module_id:u8][partition_id:u16][metric_id:u16][kind:u8][value:i64]`
  with `kind` 0 = counter, 1 = gauge, 2 = histogram bucket.
- 0x74, 0x75 and 0x79 are retired and reserved. HTTP framing is
  wave's, not clustor's: the `operations` `request` / `response` ports
  carry wave's `HttpRequest` / `HttpResponse` envelopes, described in
  [../guides/net_http.md](../guides/net_http.md).
- `MSG_VOTER_SET_UPDATE` (0x76):
  `[current_set:u8][joint_set:u8][joint_active:u8]` bitmasks.

The `GET /metrics` export payload is a self-describing blob:
`[magic:u8 = 0xC7][version:u8 = 1][record_count:u16 LE]` followed by
`record_count` fixed 14-byte records identical to the
`MSG_METRIC_SAMPLE` body, so a scraper iterates records with no
per-module parser.

### Routing and session registry

`MSG_PLACEMENT_UPDATE` (0x80); `MSG_SR_REQUEST` (0x90) and
`MSG_SR_REPLY` (0x91), the replicated session-registry boundary of
`modules/app/session_directory` — a reply is sent only after the
command is quorum-committed and applied; `MSG_PLACEMENT_EPOCH_EVENT`
(0xD5, `[kpg_id:u16][new_epoch:u32][reason:u8]`);
`MSG_COMPACTION_FLOOR` (0xE1, `[kpg_id:u16][floor_revision:u64]`);
`MSG_CLIENT_FRAME` (0xEA, `[conn_id:u8][raw client bytes]`, the
multiplexed cleartext client lane); `MSG_CONN_CLOSED` (0xEB,
`[conn_id:u8]`).

## Log-entry body magics

Entries replicated through the Raft log are opaque application bytes
by default. Clustor's own control entries are distinguished by an
8-byte magic prefix on the entry body, not by a 1-byte type code: body
heads routinely carry dense counters (a correlation id's low byte
cycles through all 256 values), so any short tag would be forged
within a few hundred entries, and a forged config change could remove
a node from its own voter set. Eight bytes put accidental collision at
about 2⁻⁶⁴ and cost application entries nothing.

| Magic | Bytes | Body after the magic |
|---|---|---|
| `ADMIN_MAGIC` | `AD 4D 4E 21 9E 1F 5C A7` | `[command_id:u32 LE][op_code:u8][op_body...]` — applied at commit time on every replica |
| `CONFIG_CHANGE_MAGIC` | `CC 46 47 21 9E 1F 5C A7` | `[op_code:u8 (1 = C_old,new, 2 = C_new)][voter_count:u8][voter_ids...]` |
| `TIMING_MAGIC` | `54 4D 45 21 9E 1F 5C A7` | `[op:u8 (1 = TimeAdvance, 2 = TimeDrain)][time_ms:u64 LE]` — leader-only; the gateway rejects client bodies carrying this prefix |

Bodies without a recognised magic pass through unchanged.

## WAL frame contract

The on-disk segment layout is defined once in
`modules/common/wal_frame.rs` and compiled into both the durability
module and the `clustor_cli` `wal-frame` / `wal-scan` commands, so a
`wal-scan` verdict on a segment image is the durable prefix a
replica's replay would recover.

Per entry:

| Offset | Field | Type |
|---|---|---|
| 0 | `entry_len` | `u32` LE |
| 4 | `crc32c` | `u32` LE |
| 8 | payload | `entry_len` bytes |

The CRC (Castagnoli) covers the payload only. The payload's first 16
bytes are the term/index prologue (`[term:u64 LE][index:u64 LE]`);
the rest is the entry body, capped at `MAX_ENTRY_BODY = 2048` bytes —
one coalesced proposal batch, the value every proposal-carrying buffer
in the graph sizes against. The full payload cap is therefore
`MAX_ENTRY_LEN = 2064`. An entry is torn when `entry_len` is zero,
exceeds `MAX_ENTRY_LEN`, or runs past the readable region: replay
stops at the first bad frame and everything before it is the durable
prefix. A torn frame is never skipped.
