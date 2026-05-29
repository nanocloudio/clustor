# Proposal correlation: tagged proposals + assignment events

`raft_engine` accepts client proposals on two distinct input ports. They
carry the same `MSG_CLIENT_PROPOSAL` opcode but have different payload
shapes, and only one of them rides a feedback loop back to the proposer.

## Ports

| Port | Direction | Index | Purpose |
|------|-----------|-------|---------|
| `proposals` | input | in[1] | Legacy untagged proposals. Payload is the bare body. No feedback. |
| `proposals_tagged` | input | in[4] | Tagged proposals carrying a per-message correlation id. Acknowledged via `proposal_assigned`. |
| `proposal_assigned` | output | out[4] | One `MSG_PROPOSAL_ASSIGNED` per tagged proposal once a log index is assigned. |

Untagged consumers (e.g. clustor's own `client_codec` path, the
pre-correlation quantum graph) continue to work unchanged. Wiring the
tagged port is opt-in.

## Forward envelope (proposer → raft_engine)

```
MSG_CLIENT_PROPOSAL on proposals_tagged:
  [correlation_id : u64 LE]   non-zero, opaque to raft
  [body           : bytes  ]   identical to the legacy untagged form
```

The body lands in the WAL exactly as it does for legacy proposals — the
correlation header is stripped before batching, so applier modules
(`apply_pipeline`, downstream state machines) see no change.

`correlation_id == 0` is reserved as "untagged"; raft will accept the
proposal but emit no assignment event for it. Producers SHOULD pick a
strictly-positive id (e.g. monotonic counter, packet id ⊕ session
generation, FNV hash of `(session, msg_id)`).

Helper: `wire::encode_tagged_proposal(dst, correlation_id, body)`.

## Backward envelope (raft_engine → proposer)

```
MSG_PROPOSAL_ASSIGNED on proposal_assigned:
  [correlation_id : u64 LE]   echoed from the inbound proposal
  [wal_index      : u64 LE]   leader-assigned log index (NOT yet durable)
```

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
4. `ack_tracker` no longer needs to invent `wal_index` from
   `last_durable_index + 1`; the heuristic in
   `quantum/modules/ack_tracker/mod.rs` should be removed.

## Loss & ordering guarantees

- Assignment events are emitted in the same step as `flush_proposal_batch`
  and in the same order proposals were appended to the batch.
- If `out_proposal_assigned` back-pressures (channel full), the assignment
  is **dropped** rather than blocking the leader. Producers should treat a
  missed assignment as a fatal correlation loss for that proposal — the
  WAL entry still exists, so the message is durable, but the proposer
  cannot bind it to a packet id. The current ack_tracker FIFO heuristic
  is a useful safety net during this transition.
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
