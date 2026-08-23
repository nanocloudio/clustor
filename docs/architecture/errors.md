# Error Handling

The structured rejections a client or operator actually observes:
wire-level client rejects, admin status codes, the WAL's continuity
rejection, and the HTTP status behaviour of the operations module.
Byte layouts and message ids are defined in
[wire.md](wire.md#message-catalog); this document explains when each
rejection occurs. Sources: `modules/common/wire.rs`,
`modules/app/gateway/`, `modules/app/consensus/apply.rs`,
`modules/app/operations/`.

## Client rejections (`MSG_CLIENT_REJECT`)

A request denied before it can be replicated is answered with an
11-byte `MSG_CLIENT_REJECT` payload:

| Offset | Field | Type |
|---|---|---|
| 0 | `conn_id` | `u8` |
| 1 | `status` | `u8` |
| 2 | `reserved` | `u8` — carries `leader_id` when `status` is NOT_LEADER, otherwise 0 |
| 3 | `retry_after_ms` | `u16` LE |
| 5 | `entry_credits` | `i16` LE |
| 7 | `byte_credits` | `i32` LE |

Between the gateway's throttle and its codec the same 10-byte body
rides an internal envelope (`MSG_CLIENT_REJECT_INTERNAL`) keyed by an
8-byte correlation id instead of the conn_id.

| Status | Value | When it occurs |
|---|---|---|
| `CLIENT_REJECT_THROTTLED` | 0x01 | The gateway's throttle could not admit the proposal: credits are exhausted, or raft's intake channel was full and nothing was written. The client should retry. |
| `CLIENT_REJECT_NOT_LEADER` | 0x02 | The gateway's codec knows the leader and it is not the local node. The `reserved` byte carries the believed `leader_id` so the client can redirect. Applies to both writes and reads. |
| `CLIENT_REJECT_STALE_EPOCH` | 0x03 | The local node has seen a newer placement epoch than the request implies. The client refreshes placement and retries. |
| `CLIENT_REJECT_FALLBACK` | 0x04 | A linearizable read failed in the consensus apply pipeline: the ReadIndex probe was unconfirmed (not leader, or the probe timed out), the read aged past its 5 s queue timeout, or it was evicted from the bounded read queue. |
| `CLIENT_REJECT_READ_UNSUPPORTED` | 0x05 | A read arrived but the graph has no read path wired to consensus, so a structured reject replaces a silent drop. |
| `CLIENT_REJECT_TOO_LARGE` | 0x06 | The record's payload exceeds the largest proposal the log can carry (`MAX_ENTRY_BODY`, see [wire.md](wire.md#wal-frame-contract)). Rejected at the gateway surface before any bytes are consumed downstream — proposing a truncated prefix would commit a corrupted entry while acking the full write. |

`retry_after_ms` is only populated by the throttle: 5 ms when entry
credits remain (the raft channel was momentarily full), 50 ms when
credits are exhausted. Throttle rejects also carry the current
(clamped) entry and byte credit balances; every other status leaves
all three fields at zero.

## Admin status codes (`MSG_ADMIN_RESPONSE` / `MSG_ADMIN_APPLIED`)

The first payload byte of an admin response is one of:

| Status | Value | When it occurs |
|---|---|---|
| `ADMIN_STATUS_OK` | 0x00 | The op applied: freeze, thaw, transfer-leader, durability-mode, snapshot. |
| `ADMIN_STATUS_DUPLICATE` | 0x01 | Idempotency collapse of a rapid retransmit — a command byte-identical to its immediate predecessor within the in-flight window. |
| `ADMIN_STATUS_UNSUPPORTED` | 0x80 | Membership ops (add / remove voter): joint consensus is deliberately gated until union-quorum enforcement lands. |
| `ADMIN_STATUS_REJECTED` | 0x81 | The command is too large to stage in the admin envelope buffer. |
| `ADMIN_STATUS_NOT_LEADER` | 0x82 | Transfer-leader issued on a node that is not the leader. |

## WAL continuity rejection (`MSG_WAL_REJECT`)

Emitted by the durability module to consensus when the WAL is handed
an entry whose index is not `wal_current_index + 1` — raft's log has
diverged from what the WAL actually holds. The 8-byte payload is the
index the WAL will accept next. A successful channel write only means
the frame entered the WAL's input channel; this message is raft's only
signal that a counted entry was never persisted. Raft resyncs its tip
down to `expected_index − 1` and replays from there
(the `RAFT_WAL_RESYNCS` counter counts the repairs).

## HTTP status behaviour

The operations module serves `GET /readyz`, `GET /why`,
`GET /metrics`, `POST /propose`, and `POST /admin/<op>` through its
http component, behind wave's `http` module on the diagnostic
listener.

- `/readyz` answers with a one-byte body from the cached readiness
  byte: 200 when non-zero, 503 otherwise.
- Malformed HTTP is answered by wave at the wire; an unknown
  `/admin/<op>` name is answered 400 `unknown admin op`; any other
  unknown path is 404 `not found`.
- A forwarded body over `MAX_EXT_BODY` (1 KiB), or a body wave has
  split across envelopes, is answered 413 `body too large` — never
  truncated. Requests too large for wave's own wire buffers never
  reach this module; wave answers those itself.
- `GET /metrics` streams across several envelopes and only one
  export streams at a time; a concurrent scrape is answered 503
  `metrics busy` until the slot frees.
- `POST /propose` (the synchronous write bridge) answers 200
  `committed` once apply acknowledges the assigned WAL index, and 503
  with a reason body otherwise: `propose queue unavailable` (the
  proposal channel refused the frame), `proposal rejected` (a throttle
  reject came back for the correlation), `proposal timeout` or
  `commit timeout` (the 10 s in-flight backstops expired).
- `POST /admin/<op>` answers 202 `accepted` when the command was
  authorised and delivered to the admin component (the op's real
  status still answers on the module's `responses` port), 403
  `forbidden` when authorisation fails, and 503
  `admin body too large` when the body cannot be staged.
