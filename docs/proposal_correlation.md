# Proposal correlation: tagged proposals + assignment events

`consensus` accepts client proposals on two distinct input ports. They
carry the same `MSG_CLIENT_PROPOSAL` opcode but have different payload
shapes, and only one of them rides a feedback loop back to the proposer.

## Ports

| Port | Direction | Index | Purpose |
|------|-----------|-------|---------|
| `proposals` | input | in[1] | Untagged proposals. Payload is the bare body. No feedback. |
| `proposals_tagged` | input | in[3] | Tagged proposals carrying a per-message correlation id. Acknowledged via `proposal_assigned`. |
| `proposal_assigned` | output | out[4] | One `MSG_PROPOSAL_ASSIGNED` per tagged proposal once a log index is assigned. |

The partitioned pair `proposals_partitioned` (in[4]) and
`proposals_partitioned_tagged` (in[5]) carry the same two shapes
behind a 5-byte `[partition_id:u16][msg_type:u8][len:u16]` envelope
for multi-Raft graphs.

Untagged producers work unchanged — `operations` bridges replicable
admin ops onto `proposals`, for instance. Wiring the tagged port is
opt-in; clustor's own client path takes it, since the gateway's
codec component needs the assignment feedback to route responses.

## Forward envelope (proposer → consensus)

```
MSG_CLIENT_PROPOSAL on proposals_tagged:
  [correlation_id : u64 LE]   non-zero, opaque to raft
  [body           : bytes  ]   identical to the untagged form
```

The body lands in the WAL exactly as it does for untagged proposals —
the correlation header is stripped before batching, so the appliers
(`consensus`'s apply component, downstream state machines) see no
change.

`correlation_id == 0` is reserved as "untagged"; raft will accept the
proposal but emit no assignment event for it. Producers SHOULD pick a
strictly-positive id (e.g. monotonic counter, packet id ⊕ session
generation, FNV hash of `(session, msg_id)`).

Helper: `wire::encode_tagged_proposal(dst, correlation_id, body)`.

## Backward envelope (consensus → proposer)

```
MSG_PROPOSAL_ASSIGNED on proposal_assigned:
  [correlation_id : u64 LE]   echoed from the inbound proposal
  [partition_id   : u16 LE]   the accepting partition slot
  [wal_index      : u64 LE]   leader-assigned log index (NOT yet durable)
```

`PROPOSAL_ASSIGNED_LEN = 18`. The `(partition_id, wal_index)` tuple
— not `wal_index` alone — is the canonical key, because one consumer
process may host replicas of several partitions.

One assignment event is emitted per tagged proposal. Multiple proposals
batched into the same Raft log entry share the same `wal_index` — that is
the intended semantics: ack-on-durability (`durable_index >= wal_index`)
will fire for all of them at once.

Helpers: `wire::encode_proposal_assigned`, `wire::decode_proposal_assigned`.

## Consumer pattern (e.g. quantum/session_processor)

1. On outbound proposal, allocate a non-zero `correlation_id` and remember
   `correlation_id → (session_slot, packet_id)` in an inflight map.
2. Send via `proposals_tagged` using `encode_tagged_proposal`.
3. When `MSG_PROPOSAL_ASSIGNED` arrives, look up the proposer-side state,
   then forward the real `wal_index` to `ack_tracker` via
   `MSG_ACK_REGISTER`.
4. `ack_tracker` matches on the real `wal_index` rather than inferring
   one from `last_durable_index + 1`.

## Loss & ordering guarantees

- Assignment events are emitted in the same step as `flush_proposal_batch`
  and in the same order proposals were appended to the batch.
- If `out_proposal_assigned` back-pressures (channel full), the assignment
  is **dropped** rather than blocking the leader. Producers should treat a
  missed assignment as a fatal correlation loss for that proposal — the
  WAL entry still exists, so the message is durable, but the proposer
  cannot bind it to a packet id. A proposer-side FIFO heuristic is a
  useful safety net against that case.
- Leadership change resets pending correlations
  (`become_follower` / `become_leader`). Producers should retry on a new
  leader.

## See also

- [architecture/replication.md](architecture/replication.md) — the
  surrounding propose / commit pipeline this protocol rides on.
- [architecture/consumer_facade.md](architecture/consumer_facade.md)
  — typed Rust helpers (`build_tagged_proposal`, `InflightTable`)
  that implement the proposer-side bookkeeping described above.
- [architecture/wire.md](architecture/wire.md) — `MSG_CLIENT_PROPOSAL`
  and `MSG_PROPOSAL_ASSIGNED` opcode catalog entries.
