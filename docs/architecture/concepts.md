# Clustor Concepts and Data Model

Clustor agrees on an ordered log, fsyncs it on a quorum, and exposes
the result to applications through a typed replica facade. It is built
as a set of `no_std`, position-independent modules on the fluxor
runtime. This page defines the vocabulary the other architecture docs
use: the index watermarks, the configuration switches, the roles, and
the on-disk and on-wire data entities as they exist in the code.

## Table of Contents

1. [Indexes](#indexes) — the watermarks that drive replication and reads
2. [Behaviour switches](#behaviour-switches) — modes and tuning knobs
3. [Roles](#roles)
4. [System model](#system-model) — components, environment, [crash model](#crash-model)
5. [Data entities](#data-entities)
6. [Invariants](#invariants)

---

## Indexes

An entry moves through five watermarks between proposal and
application. Sources: `modules/app/consensus/commit.rs`,
`modules/app/consensus/apply.rs`, `modules/app/durability/ledger.rs`,
`modules/common/wire.rs`.

| Term | Definition |
|---|---|
| `wal_index` | The log index the leader assigns to a proposal when it appends the entry. For tagged proposals the assignment is reported back to the proposer via `MSG_PROPOSAL_ASSIGNED` (`[correlation_id:u64][partition_id:u16][wal_index:u64]`). |
| `durable_index` (replica-local) | The highest index whose WAL bytes have been written and fsynced on this replica. The local WAL component reports it as a `FsyncAck`; followers also stamp it into every AppendEntriesResponse so the leader can track peer durability without a separate ack stream. |
| `wal_committed_index` (quorum-durable index) | Leader-side. The largest index durable on a quorum of voters, computed by the durability ledger from per-replica `FsyncAck` evidence and emitted as a `DurabilityProof`. Followers only ever see their own slot advance and therefore never emit a proof. |
| `commit_index` | The Raft commit index (`committed_index` in `commit.rs`). Under strict and group_fsync it advances to the minimum of the replication quorum match and the quorum-durable index from the latest `DurabilityProof`; under relaxed it advances on replication match alone. The current-term fence applies: a prior-term entry commits only transitively, once a current-term entry commits above it. |
| `apply_index` | The highest index the apply pipeline has handed to the state machine. Read fencing compares it against the commit horizon: a fenced read is answered only once `apply_index` has caught up to the commit index observed at submission. |

The ordering that read safety relies on:

```
apply_index  ≤  commit_index  ≤  quorum-durable index (strict / group_fsync)
```

Under relaxed the commit index may run ahead of the quorum-durable
index; that is the mode's explicit trade.

The quorum match itself is the median of the per-voter `match_indices`
(`quorum_index` in `modules/common/types.rs`). During a joint-consensus
membership change the effective quorum match is the minimum of the two
set medians, so an entry must reach a majority of both the old and the
new voter set before it counts.

---

## Behaviour switches

The runtime knobs, with their defaults, as declared in the modules'
`define_params!` blocks. Sources: `modules/app/consensus/mod.rs`,
`modules/app/durability/mod.rs`, `modules/app/admission/mod.rs`,
`modules/common/types.rs`.

| Switch | Definition |
|---|---|
| `durability_mode` | Consensus commit gating: strict (0), group_fsync (1), relaxed (2) — `DUR_STRICT` / `DUR_GROUP_FSYNC` / `DUR_RELAXED` in `types.rs`. Default group_fsync. Strict and group_fsync gate the commit index on quorum durability; relaxed commits on replication match alone. |
| `fsync_mode` | WAL writer behaviour in the durability module: 0 = write + fsync + ack per entry, 1 = group fsync. Group mode batches under `group_window_ms` (default 2) and `group_max_pending` (default 64). |
| `segment_bytes` | WAL segment size limit. Default 67,108,864 (64 MiB). |
| `partition_id` | Partition slot for multi-Raft graphs. Stamped into segment and snapshot filenames, durability proofs, and raft metadata paths. |
| `fresh_threshold_s` / `grace_period_s` | Admission proof-cache ladder thresholds; defaults 60 and 120. See the cache states below. |
| `dek_epoch` | Data-encryption-key epoch, owned by the durability module's keys component. Rotated locally on a weekly timer and stamped into snapshot manifests and headers. There is no AEAD encryption of WAL or snapshot bytes; the epoch is carried metadata. |

Control-plane cache states (`CP_FRESH` / `CP_CACHED` / `CP_STALE` /
`CP_EXPIRED` in `types.rs`) are derived from the age of the last
control-plane proof. With the default thresholds the ladder is: Fresh
below 60 s, Cached 60–90 s, Stale 90–120 s, Expired at 120 s and
beyond. Once the cache ages into Stale or Expired, consensus and
admission force strict fallback: the effective durability mode is
clamped to strict regardless of the configured mode.

---

## Roles

Roles describe what a replica is doing right now, not what type of
node it is. Sources: `modules/common/types.rs`,
`modules/app/consensus/raft.rs`.

- **Follower** (`ROLE_FOLLOWER`) — replicates the log and stamps its
  `durable_index` into AppendEntries responses.
- **Candidate** (`ROLE_CANDIDATE`) — running an election; pre-vote is
  implemented and runs first.
- **Leader** (`ROLE_LEADER`) — appends proposals, dispatches
  replication, computes the commit index, and emits durability proofs
  via the ledger.
- **Learner** — a mode, not a fourth role constant. A replica whose id
  is outside the current voter set (typically after a
  `CONFIG_CHANGE_OP_NEW` removed it) keeps replicating and serving
  reads but does not start elections or grant votes. The flag clears
  if a later configuration change re-adds the node.

The control plane is a local module in the same graph — a timer-driven
source that emits periodic control-plane proofs, tenant records,
capability manifests, and placement epochs
(`modules/app/control_plane/mod.rs`). It is not a separate Raft
cluster.

---

## System model

### Components

A clustor node is a fluxor graph of modules: consensus (raft, commit,
apply components), durability (wal, ledger, snapshot, keys),
replicator, admission (flow control plus proof cache), gateway (HTTP
and proposal ingress), control plane, and the application state
machine behind the replica facade in
`modules/common/replica_facade.rs`. Multi-partition graphs stamp a
`partition_id` into every file name and proof so partitions never
share state.

### Environment

Two targets exist. On Raspberry Pi 5 bare metal the filesystem is
FAT32 with no mkdir, so persistent files live in the volume root under
8.3 names (for example `RAFT<pppp>.MET` and `<p><seq7>.WAL`). On the
Linux host harness files live under `./wal/` relative to the working
directory (`wal/p<NNNN>_seg_<NNNNNNNN>`,
`wal/p<NNNN>_snap_<NNNNNNNN>.bin`, `raft/meta`). Strict-mode WAL
appends issue a write plus fsync per entry; group_fsync batches writes
inside the configured window.

### Crash model

- Fail-stop nodes; power loss may occur between any two ordered
  steps.
- Storage may reorder writes unless an fsync (or the platform's
  equivalent flush) orders them.
- Recovery is CRC replay: on start the WAL is scanned frame by frame,
  each frame's CRC32C is verified, and replay stops at the first torn
  or invalid frame. Everything before that point is the durable
  prefix; everything after it is discarded. Log divergence discovered
  by AppendEntries conflict checks is repaired with the truncation
  primitive before new entries are appended.
- The fault model is crash-only, not Byzantine. There are no
  signatures or MACs on log or snapshot data; a replica that actively
  lies must be removed by operators.

---

## Data entities

### 1) WAL Entry Frame

The per-entry segment layout is defined once, in
`modules/common/wal_frame.rs`, and compiled into both the durability
module and the `clustor_cli` `wal-frame` / `wal-scan` commands.

```
[entry_len: u32 LE][crc32c: u32 LE][payload: entry_len bytes]
```

The CRC32C (Castagnoli) covers the payload only. The payload's first
16 bytes are the term/index prologue (`[term:u64 LE][index:u64 LE]`);
the remainder is the entry body, capped at `MAX_ENTRY_BODY` = 2048
bytes, giving `MAX_ENTRY_LEN` = 2064 as the largest valid `entry_len`.
A frame whose `entry_len` is zero, exceeds the cap, or runs past the
readable region is torn; replay stops there.

### 2) WAL segments and naming

Segments are plain append-only files rolled at `segment_bytes`
(default 64 MiB). Naming (`encode_segment_path` in
`modules/app/durability/wal.rs`):

- Linux host: `wal/p<NNNN>_seg_<NNNNNNNN>` — partition id as four hex
  digits, segment sequence as eight.
- Bare-metal FAT32 root: `<p><seq7>.WAL` — one partition nibble plus
  seven sequence nibbles, 8.3-conforming.

There is no segment trailer, index sidecar, or MAC; segment integrity
is entirely the per-entry CRC chain.

### 3) Raft metadata record

Consensus persists election and log-tip state via the FS contract
(`modules/app/consensus/raft.rs`): `RAFT<pppp>.MET` on bare-metal
FAT32, `raft/meta` (or `raft/p<NNNN>/meta` for non-zero partitions)
on the host. The record is 28 bytes:

```
[current_term:u64][voted_for:i8][last_log_index:u64]
[last_log_term:u64][current_voters:u8][joint_voters:u8][joint_active:u8]
```

Persistence on the durable-ack path is rate-limited; a crash loses at
most the configured advance window of durable-index bookkeeping, never
term or vote.

### 4) Tagged proposal envelope

A proposer that needs to correlate results prefixes its proposal body
with a non-zero 8-byte correlation id: `[correlation_id:u64 LE][body]`
(`modules/app/gateway/codec.rs`, `modules/common/replica_facade.rs`).
The leader strips the prefix before logging — the WAL entry body is
the untagged application payload — and answers with
`MSG_PROPOSAL_ASSIGNED` binding the correlation id to the assigned
`wal_index`. A zero correlation id is rejected.

### 5) FsyncAck and DurabilityProof

The durability evidence messages (`modules/common/wire.rs`,
`modules/app/durability/ledger.rs`):

- `FsyncAck` (17 bytes): `[term:u64][index:u64][replica:u8]`. Emitted
  by the local WAL component when its durable point advances; on the
  leader, per-peer acks are synthesised from the `durable_index` field
  of each AppendEntriesResponse.
- `DurabilityProof` (19 bytes):
  `[partition_id:u16][term:u64][index:u64][replica:u8]`. Emitted by
  the ledger whenever the quorum-durable index advances; it gates the
  commit index under strict and group_fsync.

The ledger is an in-memory per-replica progress tracker, not a file.
There is no durability sidecar log; durable ground truth is the WAL
bytes themselves, re-proven by replay after a crash.

### 6) Snapshot Manifest

A snapshot manifest is a 32-byte binary record
(`build_manifest` in `modules/common/replica_facade.rs`):

```
[magic:u32 = 0x534E4150 "SNAP"][partition_id:u16][reserved:u16]
[term:u64][base_index:u64][dek_epoch:u32][reserved:u32]
```

Snapshot content travels as `MSG_SNAPSHOT_CHUNK` frames with an
8-byte `[seq:u32][len:u32]` prefix, followed by the manifest as the
completion record. The durability module persists the snapshot to
`wal/p<NNNN>_snap_<NNNNNNNN>.bin` with a CRC-validated file layout and
a pointer sidecar naming the current durable snapshot, which makes the
install crash-atomic without an FS rename
(`modules/app/durability/snapshot.rs`). Manifests are not signed and
not JSON.

### 7) Timing entries

Deterministic replicated timing rides the ordinary log. A proposal
whose payload begins with the 8-byte `TIMING_MAGIC`
(`modules/common/wire.rs`) is a timing command — deadline
registration and related operations — applied deterministically at
apply time by the state in `modules/common/timing.rs`. The producer is
leader-fenced so only one node injects timing entries per term.

---

## Invariants

Properties that hold on every replica in every run; a violation is a
protocol bug, not a tuning issue.

1. **Raft safety.** Log matching, leader completeness, and a monotone
   commit index hold. The current-term fence in `commit.rs` enforces
   the standard rule: the commit index may not advance by counting
   replicas while the quorum sits below the current term's first
   entry.
2. **Durability before commit (strict / group_fsync).** The commit
   index never exceeds the quorum-durable index proven by the latest
   `DurabilityProof`. Client-visible acknowledgement of a proposal
   therefore implies quorum fsync in these modes.
3. **Replay recovers exactly the durable prefix.** `wal-scan` over a
   segment image and a replica's replay agree by construction — both
   compile `wal_frame.rs` — and both stop at the first torn frame.
4. **Strict fallback on stale control-plane proofs.** Once the proof
   cache ages into Stale or Expired, the effective durability mode is
   strict regardless of configuration, until fresh proofs arrive.
5. **Read fencing.** A fenced read is answered only after
   `apply_index` reaches the commit horizon captured at submission,
   so a client never reads state older than a write it has been
   acknowledged for.
6. **Partition isolation.** Every persistent file name and every
   durability proof carries the `partition_id`; partitions sharing a
   node share no state.
