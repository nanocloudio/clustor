# Clustor Concepts and Data Model

Clustor agrees on an ordered log, fsyncs it on a quorum, and exposes
the result through a typed consumer facade. The terms and entities
defined here are the vocabulary the rest of the architecture docs
use. If a later doc refers to `wal_committed_index` or
`DurabilityRecord` without elaboration, this is where they're
introduced.

## Table of Contents

1. [Indexes](#indexes) — the watermarks that drive replication and reads
2. [Behaviour switches](#behaviour-switches) — modes, epochs, and routing
3. [Profiles and roles](#profiles-and-roles)
4. [System model](#system-model)
5. [Data entities](#data-entities)
6. [Invariants](#invariants)
7. [Snapshot and ledger metadata](#snapshot-and-ledger-metadata)

---

## Indexes

Five watermarks. Keeping them straight is the single most useful
mental model when reading the rest of the docs.

| Term | Definition |
|---|---|
| `raft_commit_index` | The standard Raft commit index: highest log index replicated on a majority, advanced only when the leader has a current-term entry in the majority. Implied when the docs say `commit_index` bare. |
| `local_wal_durable_index` | Replica-local. The last log index whose WAL bytes completed step (2) of the [ledger ordering rules](replication.md#ledger-ordering-and-replay) **and** whose `DurabilityRecord` completed step (4). Both halves matter — bytes on disk without the matching record don't count. |
| `wal_committed_index` | Leader-only. The largest *m* such that (a) the leader's own `local_wal_durable_index ≥ m`, (b) at least quorum-size replicas (counting the leader) report the same, (c) the entry at *m* lives in the current term, and (d) `m ≤ raft_commit_index`. Followers never compute it. |
| `sm_durable_index` | Product-visible state-machine durability. Non-normative for consensus, surfaced for compaction and readiness decisions. |
| `quorum_applied_index` | Smallest `applied_index` among the most recent quorum heartbeat bundle. Forms a compaction floor. |
| `applied_index_floor` | Follower-local: `min(applied_index, snapshot_base_index)`, persisted alongside snapshot authorisation. Follower snapshot-only reads require `local_wal_durable_index ≥ applied_index_floor`. |

The relationship that drives read safety:

```
local_wal_durable_index  ≤  wal_committed_index  ≤  raft_commit_index
        (per replica)          (leader only)           (standard Raft)
```

Linearizable reads require the right two to be equal. Strict equality
is what proves "everything readable is durable".

---

## Behaviour switches

The flags and epochs that govern mode, routing, and feature
availability.

| Term | Definition |
|---|---|
| `commit_visibility` | `DurableOnly` or `CommitAllowsPreDurable`. Controls whether reads can observe entries ahead of `wal_committed_index`. See [replication.md](replication.md#commit-visibility-modes). |
| `lease_gap_max` | Bound on `(raft_commit_index − wal_committed_index)` while leases are enabled. Set to 0 to disable leases. Equality is already required for linearizable reads, so this guard is a telemetry clamp for near-miss conditions. |
| `lease_epoch` | Monotone identifier carried on heartbeats. Followers reject lease reads on epoch mismatch. |
| `routing_epoch` | Placement / reconfiguration version issued by ControlPlaneRaft. |
| `durability_mode` | Consensus mode: `Strict` or `Group-Fsync`. Toggled by `DurabilityTransition` entries; see [lifecycle.md](lifecycle.md#durability-modes-and-io-writer-states). |
| `wal.fs_block_bytes` | WAL I/O alignment hint, taken from the filesystem (`st_blksize`) or an operator override. WAL writes and truncations align to this quantum. |
| `wal.crypto_block_bytes` | Fixed AEAD block size, 4096 bytes. Used for nonce counters and reservations. |
| `ControlPlaneUnavailablePriorityOrder` | Rejection precedence when mapping read/lease gate failures to `ControlPlaneUnavailable`: `{CacheExpired, CacheNotFresh, NeededForReadIndex}`. Cache-related clauses map to the first two; everything else maps to `NeededForReadIndex`. |
| `CanonicalJson` | [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) Canonical JSON: UTF-8, deterministic object member ordering, no insignificant whitespace. All signatures and `content_hash` calculations over JSON or JSONL use this encoding after removing any explicitly excluded fields. |

Runtime nouns with stable casing — telemetry and APIs match these
spellings exactly: `Clustor`, `Strict`, `Group-Fsync`,
`DurabilityRecord`, `FollowerReadSnapshot`, `LeaseEnable`,
`SnapshotDeltaEnable`, `ControlPlaneRaft`, `ConsistencyProfile`.

---

## Profiles and roles

### Profiles

Five profile bundles tune durability batching, ack deferral, flow
control, telemetry sampling, and feature availability. The full
parameter set is published in `consensus_core_manifest.json` and
surfaced through `/.well-known/wide-int-registry`.

| Profile | Intent |
|---|---|
| `ConsistencyProfile` | Default. Tight election timeouts, Strict durability available. |
| `Throughput` | Larger group-fsync batches, may opt into `CommitAllowsPreDurable`. |
| `WAN` | Wider election timeouts and RTT thresholds for cross-region voters. |
| `ZFS` | Tuned for `sync=always` / `logbias=throughput` semantics. |
| `Aggregator` | Read-heavy ingest fanout role with observer fairness budgets. |

### Roles

Roles describe what a node is doing *right now*, not what type it is.
A single binary moves through every role over its lifetime.

- **Leader** — serves writes and ReadIndex / lease reads.
- **Follower** — replicates the log; serves snapshot-only reads once
  granted the capability bit.
- **Learner** — catch-up replica during joint consensus; does not
  vote.
- **Observer** — read-only stream consumer; bandwidth-bounded; does
  not participate in quorum.
- **ControlPlaneRaft** — independent Raft cluster governing
  placements, proofs, feature gates, and DR fences.

---

## System model

### Components

- **Data-plane nodes** host one or more Raft Partition Groups (RPGs).
  Each RPG maintains WAL segments, durability ledgers, apply
  pipelines, snapshot emitters and importers, flow controllers, and
  telemetry streams.
- **ControlPlaneRaft** is an independent Raft cluster storing routing
  epochs, durability proofs, feature manifests, overrides, DR fences,
  `DefinitionBundle` metadata, and readiness signals. Data-plane
  nodes rely on its caches as the source of truth for placement and
  durability policy.
- **Clients** interact with leaders via Raft RPCs or Admin APIs,
  carrying `routing_epoch` plus durability and lease epochs.
- **Observers** receive read-only streams under dedicated bandwidth
  quotas (`0.1 × snapshot.max_bytes_per_sec` per partition) and do
  not participate in quorum.

### Environment

Nodes target Linux ≥ 5.15 with `io_uring`, PHC/PTP clock discipline,
and storage configured with explicit write barriers (XFS / ext4 with
barriers enabled, ZFS with `sync=always` and `logbias=throughput`).

WAL segments are preallocated (≥ 1 GiB) and aligned to
`wal.fs_block_bytes`. Strict mode issues `pwrite` + `fdatasync` per
append; Group-Fsync batches operations under profile ceilings.

### Crash model

- Fail-stop nodes.
- Power loss may occur between any two ordered steps.
- Storage may reorder writes unless a step explicitly orders or
  durably commits via `fdatasync` or an equivalent barrier.
- The fault model is **crash-only, not Byzantine**. Signatures on
  proofs and telemetry give auditability and tamper evidence; they
  don't turn clustor into a BFT protocol. A replica that actively
  lies must be removed by operators.

### Operating assumptions

- Minimum three voters per partition; five for the DR profile.
- ControlPlaneRaft outages may last up to
  `controlplane.cache_grace_ms` (default 300,000 ms). While caches
  remain `Fresh`, nodes continue in their configured durability
  modes. `Cached` allows existing predicates to continue with
  telemetry warnings. Once caches age into `Stale` or `Expired`,
  nodes clamp to Strict durability, revoke leases, pause incremental
  snapshots, and halve credits once `strict_only_runtime_ms` exceeds
  the profile's backpressure bound.
- Observers and follower-read capabilities are gated on Strict
  durability, fresh proofs, and explicit capability bits from
  ControlPlaneRaft.

---

## Data entities

### 1) WAL Entry Frame

```
EntryFrameHeader { version:u8, codec:u8, flags:u16, body_len:u32, trailer_len:u32 }
body[body_len]
EntryFrameTrailer { crc32c:u32, [merkle_leaf_digest:32] }
```

`trailer_len` is either 4 (CRC only) or 36 (CRC + Merkle). The
trailer's `crc32c` covers the serialised header bytes concatenated
with the body bytes — it does **not** cover the trailer itself.

Body caps:
- ConsistencyProfile: ≤ 1 MiB
- Throughput / WAN: ≤ 4 MiB

These WAL caps are independent of RPC body caps in
[wire.md](wire.md#encoding-rules).

### 2) Segment Trailer

Every segment ends with a `segment_mac_trailer` that authenticates
the segment under HMAC-SHA256 keyed by `integrity_mac_epoch`:

```
segment_mac_trailer {
    version:u8,
    mac_suite_id:u8,
    segment_seq:u64,
    first_index:u64,
    last_index:u64,
    entry_count:u32,
    entries_crc32c_lanes_bytes[16],
    offsets_crc32c_lanes_bytes[16],
    mac:[32]
}
```

The packed CRC lanes are deterministic. For each entry in physical
WAL order, append the byte range used by that entry's CRC calculation
(header bytes followed by body bytes) to a canonical byte stream with
no separators or padding. Treat the stream as 32-bit little-endian
words; pad the tail with zero bytes if needed so the length is a
multiple of 4 (this padding exists only for the CRC-lane computation
and is not persisted elsewhere). Distribute each word into lane
`word_index mod 4`, compute CRC32C (Castagnoli) per lane, and emit
four little-endian `u32` lane CRCs ordered lane0 → lane3. The packed
`entries_crc32c_lanes_bytes` is exactly 16 bytes.

`offsets_crc32c_lanes_bytes` uses the `.idx` offsets serialised as
contiguous 64-bit little-endian values with no separators. Each
offset is 8 bytes, so the stream is inherently word-aligned and needs
no padding. The same lane ordering applies.

The segment MAC covers every trailer field except `mac` itself,
authenticating the serialised CRC-lane bytes verbatim. A worked CRC
lane vector lives in [wire.md](wire.md#crc-lane-packing-example).

### 3) Durability Ledger

Append-only sidecar file beside the WAL. Each record is one of:

- `DurabilityRecord { term, index, segment_seq, io_writer_mode, record_crc32c }`
- `NonceReservationRange { segment_seq, start_block_counter, reserved_blocks }`
- `NonceReservationAbandon { segment_seq, abandon_reason }`
- `DurabilityTransition` — fences a Strict ↔ Group-Fsync mode change

The ledger is the durability ground truth: an entry counts as durable
only after its WAL bytes are on disk **and** the matching
`DurabilityRecord` has been appended and `fdatasync`ed. Ordering
rules in
[replication.md](replication.md#ledger-ordering-and-replay).

### 4) DurabilityAck Attestation

```
DurabilityAck {
    partition_id,
    replica_id,
    last_fsynced_index,
    segment_seq,
    io_writer_mode,
}
```

A follower emits the ack only after three preconditions:

1. The WAL bytes for `last_fsynced_index` are durable.
2. The matching `DurabilityRecord` has been appended to
   `wal/durability.log`.
3. `fdatasync(wal/durability.log)` has completed.

Acks emitted before any of those complete are protocol violations
and are discarded at the leader. The
`{last_fsynced_index, segment_seq, io_writer_mode}` tuple is treated
as peer-authenticated: mTLS plus replica identity in the crash-only
fault model proves the follower can regenerate the quorum proof after
a crash. `io_writer_mode` rides the ack so the leader can fence
Group-Fsync eligibility — not because it contributes to replay-proof
durability.

Leaders bind every received tuple to the current term and stream
context. Stale tuples cannot help clear a read gate without a fresh
ControlPlaneRaft proof.

### 5) Durability Mode Epoch

`durability_mode_epoch` is a monotone `u32` stored in ControlPlaneRaft
and mirrored into `DurabilityTransition` entries, envelopes, and
telemetry. It increments every time a partition toggles
Strict ↔ Group.

Every Raft control message (AppendEntries, heartbeats, RequestVote,
PreVote) carries the sender's current epoch. Nodes persist the epoch
alongside `wal/durability.log`. Any message or ledger record that
regresses the epoch is rejected — `ModeConflict` on admin RPCs, Raft
streams closed or answered with a `ModeConflict` envelope. Leaders
acknowledge a transition only after the epoch and the durability
proof checkpoint are durably recorded.

### 6) Snapshot Manifest

Canonical JSON (per `CanonicalJson` above):

```json
{
  "manifest_id": "...",
  "version_id": ...,
  "producer_version": "...",
  "emit_version": ...,
  "base_term": ...,
  "base_index": ...,
  "snapshot_kind": "Full" | "Delta",
  "delta_parent_manifest_id": "...",
  "delta_chain_length": ...,
  "content_hash": "0x...",
  "signature": "0x...",
  "encryption": { "dek_epoch": ..., "iv_salt": "0x..." },
  "chunks": [...],
  "logical_markers": [...],
  "ap_pane_digest": "0x...",
  "dedup_shards": [...],
  "commit_epoch_vector": [...]
}
```

Incremental manifests set `snapshot_kind = Delta` and record parent
information. Their `encryption{…}` uses the snapshot-specific IV
derivation in [security.md](security.md#snapshot-chunks); WAL IV
derivation ignores `iv_salt`.

Computing `content_hash` or signing the manifest removes the
top-level `content_hash` and `signature` fields first, then hashes or
signs the canonical encoding of the remaining object. Every manifest
is signed with the cluster's `SnapshotManifestKey` (see
[security.md](security.md#key-purpose-registry)).

A worked sample is in
[security.md](security.md#snapshot-manifest-sample).

### 7) Filesystem Layout

```
/state/<partition>/wal/segment-*.log
/state/<partition>/wal/segment-*.idx
/state/<partition>/wal/durability.log
/state/<partition>/snapshot/<term>-<index>/manifest.json
/state/<partition>/snapshot/chunks/
/state/<partition>/definitions/<bundle_id>.blob
/state/<partition>/metadata.json
/state/<partition>/boot_record.json
```

Tenant- or product-specific files MAY be added under
`/state/<partition>/…` so long as the layout above stays intact.

### 8) ControlPlaneRaft Objects

ControlPlaneRaft stores: partition manifests, durability ledger
entries, `QuarantineCleared` records, `DefinitionBundles`,
`ActivationBarriers`, `WarmupReadiness` entries, override ledger
items, feature manifest rows, DR fences, key epochs, RBAC manifests.

### 9) Throttle Envelope Payload

JSON envelope carrying: reason, retry hints, backlog, credit levels,
durability metadata, decision trace ID, credit hint, ingest and
durability status codes, sorted-and-truncated ID lists with
continuation tokens. Wire shape in
[wire.md](wire.md#message-catalog).

### 10) ChunkedList Frame

```
ChunkedListFrame {
    total_count:u32,
    chunk_offset:u32,
    chunk_len:u16,
    chunk_flags:u8,
    items[],
    [chunk_crc32c:u32 when has_crc=1]
}
```

Constraints: `chunk_len ≤ 1024`, serialised payload ≤ 64 KiB,
reassembly cap 8 MiB, `total_count ≤ 1,000,000`.

---

## Invariants

The properties that hold across every replica in every run. Anything
violating these is a protocol bug, not a tuning issue.

### 1) Raft safety

Log matching, leader completeness, and monotone `raft_commit_index`
hold for every replica. `raft_commit_index` follows the Raft
current-term rule: only entries from the current term may become
committed in the current term.

`wal_committed_index ≤ raft_commit_index` always. Equality is
required whenever `commit_visibility = DurableOnly`.

### 2) Durability before ACK

Client ACKs occur only after:
- the leader has persisted,
- a quorum has sent `DurabilityAck` evidence,
- the ledger record has been appended and `fdatasync`ed, and
- `wal_committed_index` has advanced.

`DurabilityTransition` entries fence every Strict ↔ Group change.
No batch may span a fence.

### 3) Linearizable read prerequisites

All of the following must hold:

- `strict_fallback == false`
- `commit_visibility == DurableOnly`
- Cache freshness — state ∈ `{Fresh, Cached}`
- Proof equality on the `DurabilityProofTupleV1` subset
  `{last_durable_term, last_durable_index, segment_seq,
   io_writer_mode, durability_mode_epoch}` matching the leader's
  last quorum-fsynced tuple
- `wal_committed_index == raft_commit_index`

The reference predicate is in
[replication.md](replication.md#read-gate-predicate).

### 4) Snapshot integrity

Full and incremental snapshots use signed manifests,
AEAD-authenticated chunks, digest verification before apply, and
profile-bound cadence controls. Targets are advisory; hard bounds
gate.

### 5) Nonce uniqueness

`(segment_seq, block_counter)` pairs are globally unique.
Reservations are contiguous, bounded by
`nonce.reservation_max_blocks_profile`, proactively flushed
(writers persist after ≤ 5 ms of inactivity and whenever windows
fill), and durably recorded before any ciphertext uses the counters.
Reservations are explicitly abandoned before compaction.

### 6) Startup scrub

Nodes authenticate AEAD tags in constant time, zeroise buffers on
failure, verify MACs / CRC / Merkle, and check ledger ordering before
taking action. No plaintext influences state before authentication
completes.

### 7) Quarantine

AEAD or MAC failures, repeated fatal apply outcomes, nonce reuse
suspicion, integrity policy violations, or admin pause force
Quarantine. Exit requires snapshot or WAL rebuild plus a
ControlPlaneRaft acknowledgement.

---

## Snapshot and ledger metadata

Snapshot authorisation walks through four steps in order:

1. `fsync` the manifest.
2. Re-list (`stat` + checksum).
3. Emit
   `SnapshotAuthorizationRecord { manifest_id, base_index, auth_seq, manifest_hash }`.
4. Emit `CompactionAuthAck { manifest_id, auth_seq }` with hash
   chaining.

`boot_record.json` captures the scrub outcome, durability watermark,
WAL geometry, `io_writer_mode`, and spec self-test metadata for
audit. The same data is surfaced via `/readyz`.
