# Clustor – Raft Replication Substrate
Version: Draft 0.1 (condensed)
Language: Rust (no GC runtime)
Deployment: Library crate + sidecar utilities shared across product binaries

## Table of Contents
0. Safety Kernel & Wire Freeze
1. Architecture & Crash Model
2. Replication & Consistency Semantics
3. Partitioning & Topology
4. Log Entry Interfaces
5. Durability & Write-Ahead Log
6. Apply Pipeline & State Machine Hooks
7. Snapshots & State Transfer
8. Storage Layout, Encryption & Recovery
9. Flow Control & Backpressure
10. Control Plane – CP-Raft
11. Security & Isolation
12. Admin & Lifecycle APIs
13. Telemetry & Observability
14. Deployment & Bootstrap
15. Summary of Guarantees
Appendices A–E and P

### Appendix Cross-Index
| Appendix | Topic |
| --- | --- |
| Appendix A (see App. A) | SLOs, alert thresholds, telemetry policies |
| Appendix B (see App. B) | Operational profiles & limits |
| Appendix C (see App. C) | Test matrix, fixtures, conformance helpers |
| Appendix D (see App. D) | Wire envelope schemas & override scopes |
| Appendix E (see App. E) | ChunkedList framing rules |
| Appendix P (see App. P) | Parked features slated for >v0.1 |

For automation that addresses appendices numerically, appendices A–P map to ordinal IDs 16–31 (A=16, B=17, …, P=31); spec-lint publishes the same alias list so tooling never depends on prose strings.

---

## 0  Safety Kernel & Wire Freeze (v0.1)

The Safety Kernel is normative for v0.1 and supersedes conflicting statements. Later sections cite the controlling clauses as “per §0.x” whenever they restate the invariants; if divergence is observed in future drafts, the §0 text wins without additional errata.

**Change Control:** spec-lint deterministically re-derives the normative bundles `wire_catalog.json`, `chunked_list_schema.json`, and `wide_int_catalog.json` (plus the shared fixture archive noted in Appendix C) from the shipping source tree on every build. Releases therefore fail if the prose and generated artifacts disagree, and any change to this section must land together with regenerated bundles so downstream auditors can diff byte-for-byte.

### 0.1 Safety Kernel (invariants)
- **Raft:** log matching, leader completeness, and monotone `commit_index` hold for every replica (§2.1).
- **Durability:** acknowledgements follow quorum `fdatasync(data_fd)`; `wal_committed_index` is monotone; `DurabilityTransition` entries fence every mode change so no batch straddles a transition (§5.2).
- **Reads:** Linearizability uses ReadIndex; leader leases are disabled by default. Crash-linearizable reads require `commit_visibility=DurableOnly` (§2.3).
- **Snapshots:** Only full snapshots ship in v0.1. Imports require signed manifests, AEAD-authenticated chunks, and digest verification before state is touched (§7).
- **Startup scrub:** Always decrypt + verify AEAD tags in constant time → zeroize buffers on failure → verify CRC/Merkle/idx-MAC → act (§5.3). No plaintext may influence state before tag verification succeeds, and any AEAD failure quarantines the replica.

### 0.2 Defaults for v0.1
| Item | Default |
| --- | --- |
| `commit_visibility` | `DurableOnly` (Throughput may gate `CommitAllowsPreDurable`). |
| Leader leases | Disabled for all profiles. |
| Merkle enforcement | Mandatory for CP-Raft / DR / ZFS / Latency; optional elsewhere, default-off only for Throughput. |
| Observers | Disallowed in Latency/CP; optional (off) in Throughput/WAN. |
| Durability mode | Strict on boot; Group-Fsync is opt-in with guardrails (§5.2). |

### 0.2.1 Clause Classification
To keep the separation between normative requirements, operational guidance, and informational context machine-readable, spec-lint now emits paragraph-level tags `[Normative]`, `[Operational]`, or `[Informative]` into the metadata bundle referenced above. Contributors SHOULD prefix new paragraphs with the appropriate tag (e.g., `[Normative] Crash-linearizable reads require …`) and spec-lint will reject mixed or missing tags once the migration completes. Until all legacy text is annotated, the default interpretation remains “normative unless otherwise tagged,” but downstream tooling can already consume the emitted metadata to filter for the required subset.

### 0.3 Wire/API Freeze (v0.1)
Frozen wire catalog for 0.1.x (new fields may append, no breaking changes):
- System entries: `MembershipChange (0x01)`, `MembershipRollback (0x02)`, `DurabilityTransition (0x03)`, `FenceCommit (0x04)`.
- Messages: `DurabilityAck{partition_id, replica_id, last_fsynced_index, segment_seq, io_writer_mode}`, `PreVoteResponse{term, vote_granted, high_rtt}`.
- `PreVoteResponse` serialization: `{term:u64, vote_granted:u8, has_high_rtt:u8, [high_rtt:u8 when has_high_rtt=1]}`. v0.1 senders MUST set `has_high_rtt=1` and include `high_rtt ∈ {0=false,1=true}`. For backward compatibility, receivers MUST treat the absence of the tail bytes (i.e., legacy peers that omit `has_high_rtt`) as `has_high_rtt=0` and MUST ignore any additional tail bytes beyond the known optional fields when `body_len` allows skipping, per the general rule in §0.3. Frames whose `body_len` is shorter than the mandatory `{term(8) + vote_granted(1) + has_high_rtt(1)}` = 10-byte floor (or 9 bytes when legacy peers legitimately omit `has_high_rtt`) MUST be rejected as `WireBodyTooShort`. Future optional fields MUST follow the same “has_*/value” pattern so older parsers can skip them safely.
- Envelopes: `RoutingEpochMismatch`, `ModeConflict`, `ThrottleEnvelope`, and the shared `Why*` schema header.
- Encoding freeze:
  - Binary wires use little-endian fixed-width integers (`u8/u16/u32/u64` as declared) and 32-bit little-endian length prefixes for slices/strings. Arrays first carry a `u16` element count followed by tightly packed elements. Enumerations consume `u8` discriminants; new values append at the tail. Receivers MUST treat any discriminant beyond the highest cataloged value as `WireUnknownField` (never “best-effort” parsing) so forward compatibility remains fail-closed.
  - Lists that could exceed `u16::MAX` entries MUST be chunked across multiple envelopes/messages. v0.1 reserves `WideCount(u32)` extension IDs for v0.2 so implementers can plan a drop-in upgrade path without rewriting payload semantics; until that extension lands, every field that might grow beyond 65,535 elements must document its chunking rules. The canonical `ChunkedList` framing—including layout, CRC policy, receiver obligations, and JSON mirror rules—is defined in Appendix E (see App. E). Fields that adopt `ChunkedList` MUST cite Appendix E (see App. E) and follow its behavioral requirements verbatim so streaming parsers can recover deterministically.
  - Unknown binary fields MUST be ignored when they appear after known fields and the enclosing length permits skipping; unknown mandatory fields before the known region cause `WireUnknownField` rejects. Implementations SHALL compute the minimum required byte length for all mandatory fields of a message; if the declared `body_len` (or envelope length) is shorter than that floor, the receiver MUST reject the payload as `WireUnknownField` even before parsing tail fields.
  - Appendix C (see App. C) (“Binary Schema & `has_*` Pattern Vectors”) publishes normative byte layouts plus pass/fail fixtures for the length-prefixed strings, arrays, and `has_optional_field` pattern described here. Implementations MUST round-trip those vectors exactly before claiming §0.3 compliance.
  - Every message/envelope is length-delimited: a 32-bit little-endian byte length (or message-specific 32-bit `body_len`) precedes the payload so receivers can skip unknown tail fields without stream corruption. Each catalog entry therefore declares a maximum `body_len`: unless noted otherwise, Raft RPCs and admin messages MUST set `body_len ≤ 4 MiB`, while Explain/Why*/Throttle envelopes MUST remain ≤32 KiB. The total frame on the wire is therefore `4 bytes (length prefix) + body_len`; no implementation may hide bytes outside that window, and the effective “frame cap” is `4 MiB + 4` for Raft RPCs and `32 KiB + 4` for envelopes. Receivers MUST begin parsing as a streaming read with bounded buffers and MUST abort with `WireBodyTooLarge` if `body_len` exceeds the catalog cap or if more than the declared length arrives on the wire (protecting against DoS). Payloads that exceed the cap MUST be rejected in their entirety—truncation or “best effort” processing is forbidden so that senders cannot smuggle partial frames past the cap. When a frame is shorter than the mandatory floor, both transports behave identically: gRPC replies with `INTERNAL` carrying `WireBodyTooShort`, and raw TCP peers emit the same `WireBodyTooShort` catalog code before tearing down the connection. Streaming parsers MAY buffer the entire payload only when the cap is ≤64 KiB; beyond that they MUST enforce a rolling window.
  - Large-frame roadmap: catalog bit `WireExtension::WideFrame (0x10)` is reserved for v0.2 so future snapshot-control or bulk-admin RPCs can negotiate `body_len` up to 32 MiB without fragmenting payloads. v0.1 implementations MUST ignore the extension bit (and keep the 4 MiB cap) but SHOULD plumb configuration so the negotiated limit can be raised atomically once the extension is ratified.
  - gRPC services always transmit enums numerically; JSON mirrors emit enum **strings** and also accept the numeric value for backward compatibility. Servers reject unknown enum **strings** with `WireUnknownField` (or HTTP 400) but MUST accept recognized numeric IDs so upgraded clients can talk to older servers. Field names and casing are frozen; clients must tolerate additive fields but reject missing required ones.
  - JSON numeric safety: any integer field whose range may exceed `2^53-1` MUST be encoded as a base-10 string **even when the concrete value fits inside `2^53-1`**. This mandate explicitly covers every `*_ms` timestamp such as `expires_at_ms`, `updated_at_ms`, and ledger TTL fields; they remain strings forever unless Appendix C is amended. Servers therefore emit strings for the authoritative JSONPath list defined in Appendix C (see App. C), and clients MUST accept the string form. Generators and documentation MUST import that Appendix C (see App. C) catalog verbatim; spec-lint tests fail if §0.3 drifts from it. Servers MUST expose a golden “wide-int catalog” artifact (generated at build time) and CI MUST diff it against Appendix C (see App. C) so new fields cannot land without updating the list. Violations on the wire return `WireWideIntNotString`. Servers MAY accept numeric input for backward compatibility only when `json.accept_numeric_wide_ints=true` (default false). Even when that flag is enabled, servers MUST reject any numeric token that cannot round-trip to the canonical decimal string without precision loss (i.e., when `value != parse_decimal(to_decimal_string(value))` or `|value| > 2^53-1`). Enums remain numeric, and the only allowed deviations from the string rule are the small set enumerated in Appendix C’s `json_numeric_exception_list` (currently enum discriminants and `error_code` integers). For `entries_crc32c`/`offsets_crc32c`, JSON uses fixed-length hex strings (`"0x" + 32 hex chars`, little-endian interpretation) so language runtimes without `u128` can interoperate. Canonical serializers MUST left-pad the hexadecimal payload to exactly 32 nibbles (lowercase recommended); receivers MUST accept either case but MUST reject any string whose length differs from 34 characters (`"0x"` prefix + 32 hex digits). Conformance tests (Appendix C (see App. C)) enforce both parser and serializer behavior.
  - Machine-readable schema bundle: every build MUST emit a deterministic `wire_catalog.json` (system entries, RPCs, envelopes, enums, field ordering, byte widths) plus `chunked_list_schema.json` derived mechanically from §0.3 and Appendices C/E. Spec-lint fails the build if those artifacts drift from the prose, and release manifests MUST include the exact git hash of the emitted bundle so downstreams can diff their generators. Nodes carry the same bundle at runtime and refuse to start when the embedded bytes differ from the published catalog.
  - Error code registry: Wire-level errors reserve numeric IDs `1000–1099` (e.g., `WireBodyTooShort=1001`, `WireBodyTooLarge=1002`, `WireUnknownField=1003`, `WireChunkMissing=1004`, `WireChunkOverlap=1005`), while control-plane availability errors reserve `2000–2010` (`CpUnavailable{NeededForReadIndex}=2000`, `CpUnavailable{CacheExpired}=2001`). IDs `1090–1099` are permanently reserved for vendor-specific extensions so third parties can experiment without colliding with future mainline assignments. gRPC enumerations SHALL use these IDs verbatim, and JSON payloads SHOULD include `error_code` so telemetry and clients can reason about failures without string parsing.
  - `ChunkedList` receiver rules: chunks may arrive out of order. Receivers MUST deduplicate by `chunk_offset`, reject overlaps or gaps, verify that `∑ chunk_len == total_count`, and validate `chunk_crc32c` whenever the field requires it. Fields that legitimately omit the CRC MUST continue to perform strict offset accounting. Missing chunks MUST produce `WireChunkMissing`.

### 0.4 Negative Space (out of scope in v0.1)
- Lease reads and observers never contribute to quorum, ReadIndex, compaction, or durability.
- Incremental snapshots and integrity hash-suite flips are parked in Appendix P (see App. P).
- No relaxed crash model beyond fail-stop + ordered filesystems.
- ZFS deployments are treated as “ordered” only when `sync=always` pins intent log semantics (SLOG or main pool). Operators must ensure the SLOG/main pool pair delivers the same write-ordering guarantees promised in §1.2.1 or downgrade the filesystem profile.

### 0.5 Strict Fallback Gate (normative table)
`strict_fallback_state` ties every guardrail in §§2, 5, 7, 8, and 10 back to the Safety Kernel. `LocalOnly` corresponds to `strict_fallback=true`. This table now lives in §0 so that future drafts cannot diverge without an explicit kernel change; Appendix C (see App. C) only mirrors it for telemetry guidance.

| Operation | Healthy | LocalOnly | ProofPublished |
| --- | --- | --- | --- |
| Accept Strict-mode writes | Allowed | Allowed (forced Strict, `group_fsync=false`) | Allowed |
| Enable Group-Fsync / `DurabilityTransition{to=Group}` | Allowed (subject to other guards) | Reject with `ModeConflict(strict_fallback)` | Allowed |
| Expose `CommitAllowsPreDurable` reads | Allowed where profile permits | Forced `commit_visibility=DurableOnly` | Allowed |
| ReadIndex / linearizable reads | Allowed | Reject with `CpUnavailable{reason=NeededForReadIndex}` | Allowed |
| Grant `follower_read_snapshot_capability` | Allowed when other caps satisfied | Reject (`FollowerCapabilityRevoked`/CP refuses bit) | Allowed |
| Enable delta snapshots / `snapshot_delta` APIs | Allowed | Reject with `CpUnavailable{reason=CacheExpired}` | Allowed |

`ProofPublished` is a telemetry-only state indicating CP has mirrored the leader’s proof; once it lands, the gate behaves identically to `Healthy`.

---

## 1  Architecture & Crash Model

Clustor is a reusable Raft substrate that embeds in higher-level services. All behavior is subordinate to §0.

### Goals
- Ship a replicated log + WAL stack with explicit hooks for encoding, apply, snapshot, and audit extensions.
- Align durability and ordering semantics with downstream terminology so products can map acknowledgment policies directly.
- Provide PID-style flow-control hooks for ingest-heavy services.
- Include CP-Raft for tenants, placements, keys, feature gates, and DR fencing.
- Deliver deterministic recovery, explainable throttling, and auditable operations.

### 1.1 Integration Targets & Use Cases
| Product | What Clustor Provides | Upper-Layer Responsibility |
| --- | --- | --- |
| MQTT Broker | Partitioned Raft log for session state + retained messages; CP-Raft tenancy objects | MQTT protocol, routing, QoS |
| Key-Value Store | Ordered log, snapshot shipping, placement metadata | Serialization, compaction, read serving |
| Control-Plane Services | CP-Raft tenancy, DR fencing, placement enforcement | API surface, orchestration, IAM |
| Streaming Processors | Flow-controlled append API with strict/batched durability and trace metadata | Payload encoding, windowing, higher-level semantics |

### 1.2 Architectural Guarantees
| Dimension | Guarantee |
| --- | --- |
| Consistency | Linearizable writes per partition; followers serve only `applied_index` checkpoints (§2.3). |
| Availability | Raft majority progress with hot-standby followers. |
| Durability modes | Strict (per-append fdatasync) and Group-Fsync (bounded batching with auto-downgrade). |
| Storage | Segment-structured WAL + signed snapshot manifests. |
| Telemetry | Uniform metrics, explain endpoints, signed audit streams. |
| Security | mTLS/SPIFFE, AEAD WAL/snapshots, keyed epochs. |

† Crash-linearizable reads require `commit_visibility=DurableOnly` (§1.2.1, §2.3) per the §0.2 default.
†† Follower-serving APIs are limited to signed snapshot exports or `FollowerReadSnapshot` capability surfaces; followers never respond to ReadIndex RPCs (§2.3).

> **Availability note:** Linearizable reads remain CP-dependent. During CP outages, leaders continue to accept writes in Strict mode but ReadIndex/follower reads fail closed with `CpUnavailable{reason=NeededForReadIndex}` until CP acknowledges the durability watermark (§2.3). Users who require read availability during CP partitions must provision snapshot-only fallbacks or accept degraded semantics.

#### 1.2.1 Crash Model & Visibility Policy
- Fail-stop crashes: dirty cache lost unless `fdatasync` completes; multiple replicas may fail simultaneously.
- Supported filesystems: XFS, ext4 with ordered barriers, or ZFS with `sync=always`. Bootstrap rejects incompatible mounts per the table below.

| Filesystem | Required policy | Notes |
| --- | --- | --- |
| ext4 | `data=ordered`, barriers/`auto_da_alloc` enabled, `commit <= 5`, `nojournal_checksum=false`, and device write cache configured for `write through` or `write back` with `fua=1`. `nobarrier`, `data=writeback`, `commit>5`, or `write_cache=unsafe` mounts are rejected. | `journal_async_commit` is recommended for latency but optional; operators must document deviations. |
| XFS | `logbsize >= 256k`, device reports `queue/write_cache ∈ {write through, write back}` with `queue/fua=1` or `queue/flush=1`. Mount options that disable barriers are disallowed even if ignored by the kernel. | Barrier enforcement is verified via `/sys/block/*/queue` capabilities rather than mount strings. |
| ZFS | Dataset property `sync=always`, `logbias=throughput`, devices expose `queue/fua=1`. | Group-Fsync remains disabled unless devices prove `<20 ms` fsync (§Appendix B (see App. B)). |
- ZFS proof of `<20 ms` fsync: nodes MUST run the built-in `fsync_probe` (128 sequential `fdatasync`s against the WAL device) at bootstrap and every `zfs.fsync_probe_interval = 3600 s`. Results (`fsync_probe_p99_ms`, sample count, dataset GUID, device serial) are recorded in `boot_record.json` and telemetered to CP-Raft. Group-Fsync may only be enabled when the most recent probe shows `p99 ≤ 20 ms` and at least 128 samples; a regression above 20 ms for three consecutive probes forces automatic Strict downgrade with hysteresis matching `durability.max_device_latency_ms`.
- Mirrored SLOG devices that rely on asynchronous replication are acceptable only when the probe above still reports `p99 ≤ 20 ms`; otherwise Group-Fsync remains locked out even if individual devices appear healthy.
- The probe writes to a dedicated file under the same dataset/mount as the WAL (default path `wal/.fsync_probe/probe.bin`) so the measurement captures the exact storage stack. Each run truncates the file to `zfs.fsync_probe_bytes = 4 MiB`, issues the 128 `fdatasync`s, and then unlinks the file; no residual state remains beyond telemetry.
- Multi-device WAL environments (RAID, dm-crypt, dm-multipath) are permitted only when the **composite** stack can prove ordered flushes: every layer between the filesystem and physical media MUST advertise barriers/FUA, and operators MUST document the journaling or write-intent mechanism (e.g., MD journal mode, battery-backed cache) that preserves `pwrite → fdatasync` ordering. Stacks lacking such attestations are treated as “unknown filesystem” and quarantined until CP-Raft records an explicit `disk_override`.
  - `disk_override` objects are canonical JSON documents stored in CP-Raft and MUST match the schema below so tooling can diff overrides automatically:
    | Field | Type | Description |
    | --- | --- | --- |
    | `override_id` | `string` (UUIDv7) | Primary key referenced by telemetry/audit logs. |
    | `devices[]` | array | Each entry describes one block device participating in the stack. |
    | `devices[].sys_path` | string | Absolute `/sys/block/...` path captured when the override was minted. |
    | `devices[].serial` | string | Stable serial/WWN so replacements can be detected. |
    | `devices[].queue.flush` / `devices[].queue.fua` | bool | Capabilities observed at mint time; nodes compare them to the current kernel view and reject mismatches. |
    | `devices[].write_cache` | enum `{"write through","write back"}` | Expected cache policy. |
    | `stack_diagram` | string | Free-form diagram describing the exact layering (dm-crypt → mdraid → NVMe, etc.). |
    | `attested_by` | string | Operator identity who supplied the proof. |
    | `ticket_url` | string | Change-management reference. |
    | `expires_at_ms` | string wide-int | RFC 3339 or epoch encoded per Appendix C so overrides cannot silently live forever. |
  Nodes MUST refuse the override if any field is missing, if `expires_at_ms` is in the past, or if the live `/sys/block/*` capabilities differ from the recorded tuple; quarantining remains the fallback if the operator cannot refresh the document in time.
- Supported OS matrix: v0.1 targets Linux kernels ≥5.15 with `io_uring`; other kernels/OSes are “best effort” only if they can prove the same cache/barrera semantics. Bootstrap rejects unknown platforms unless an explicit compatibility waiver is recorded in CP-Raft so operators cannot assume portability from the table above.
- For ext4 the phrase “barriers/`auto_da_alloc` enabled” means both safeguards must be on simultaneously (barriers enforced, `auto_da_alloc=1`); turning off either guardrail rejects the mount.
- `commit_visibility` governs whether `raft_commit_index` may exceed `wal_committed_index`:
  - `DurableOnly` (default) enforces equality for crash-linearizable reads.
  - `CommitAllowsPreDurable` (Throughput-only gate) allows a gap for lower-latency reads; leaders export gauges `commit_visibility_gap_entries` (count) and `commit_visibility_gap_ms` (time) and `alerts.commit_visibility_gap_ms` fires after 5 s (default).
- Client acknowledgements MUST satisfy §2.4 (ACK Contract) so that `wal_committed_index` reflects every ACKed write even when `CommitAllowsPreDurable` exposes Raft-only state to reads.
- Leaders reconcile `wal_committed_index` with the durability ledger on election; lacking proof forces Strict mode with leases + Group-Fsync disabled until the ledger or peers confirm durability (§2.1).

### 1.3 Definitions & Conventions
| Term | Meaning |
| --- | --- |
| `raft_commit_index` | Highest log index replicated on a majority; all references to `commit_index` imply this value unless qualified. |
| `wal_committed_index` | Highest index quorum-fsynced per §5.2. |
| `sm_durable_index` | Product-managed watermark indicating side effects are durably materialized (§6). |
| `quorum_applied_index` | Minimum `applied_index` observed across the most recent quorum heartbeat bundle; used as a compaction floor (§8.1). |
| `commit_visibility` | `DurableOnly` or `CommitAllowsPreDurable`; governs read exposure. |
| `lease_gap_max` | Profile-specific cap on `(raft_commit_index - wal_committed_index)` when leases are enabled; 0 disables leases entirely (§2.3, Appendix B (see App. B)). |
| `lease_epoch` | Monotone identifier on heartbeats; followers reject lease reads when epochs diverge. |
| `routing_epoch` | Placement version from CP-Raft (§3, §10). |
| `durability_mode` | `Strict` or `Group-Fsync`, with explicit `DurabilityTransition` fencing. |
| `wal.fs_block_bytes` | Filesystem-reported block size; all WAL buffers align to this value. |
| `wal.crypto_block_bytes` | Fixed AEAD block size (4 KiB, power-of-two) used for nonce counters; constant cluster-wide and recorded per segment (§8.2). |
| Encoding | Unless noted, binary integers are little-endian; manifests use UUIDv7/ULID big-endian ordering. |
| Epochs | Every `*_epoch` field is a monotone `u32` serialized little-endian in binary wires and as base-10 strings in JSON; regressions are treated as tampering (§8.2, §10.3). |

#### 1.3.1 Terminology Normalization
| Canonical term | Synonyms in docs | Notes |
| --- | --- | --- |
| `Strict` | `Strict durability`, `Strict mode` | Means per-append `fdatasync` with no batching. |
| `Group-Fsync` | `Group` | Batching mode guarded by `DurabilityTransition`. |
| `DurabilityRecord` | `durability ledger entry`, `ledger watermark` | Always refers to `{term,index,segment_seq,io_writer_mode}` record in `wal/durability.log`. |
| `FollowerReadSnapshot` | `follower read endpoint` | Snapshot-style, never linearizable. |

Spec-lint enforces the casing shown above for every runtime state and lifecycle noun (`StrictFallback`, `LocalOnly`, `ProofPublished`, `Quarantine`, `RepairMode`, `StrictFallbackState`, etc.) so auto-generated docs and telemetry remain mechanically comparable; new terms must be added to this table before appearing elsewhere in the spec.
---

## 2  Replication & Consistency Semantics
Clustor follows Raft with explicit guardrails.

### 2.1 Term/Index Invariants
1. Persist `current_term` before AppendEntries; terms strictly increase.
2. `commit_index` never decreases; `applied_index <= commit_index`.
3. `wal_committed_index <= raft_commit_index` always; equality is enforced when `commit_visibility=DurableOnly`.
4. Votes require candidates with `(last_log_term, last_log_index)` ≥ voter. Leaders therefore contain all committed entries.
5. Conflicts truncate from the conflicting index before appending new entries.
6. AppendEntries rejections carry `{term, conflict_term, conflict_index}` to fast-forward leaders.
7. Snapshots delete WAL below `base_index` only after signature verification and once reads can serve `applied_index >= base_index`.
8. New leaders reconcile durability: proceed only in Strict mode when durability ledger proof is missing; if peers prove a gap, refuse leadership/votes until data is repaired.

#### 2.1.1 Strict Fallback Gate Checklist
`strict_fallback=true` whenever the leader lacks a CP-published `(last_durable_term, last_durable_index)` proof that covers its current `raft_commit_index`. The flag clears only after the leader republishes a fresh proof. While `strict_fallback=true`, the following operations MUST hard-fail even if operators attempt Break-Glass overrides, and the leader MUST emit `strict_fallback_gate_blocked{operation}` telemetry for every rejection:

| Operation | Behavior while `strict_fallback=true` |
| --- | --- |
| `DurabilityTransition{to=Group}` (Group-Fsync enable) | Reject with `ModeConflict(strict_fallback)` and remain in Strict mode. |
| Lease enablement or any attempt to serve lease reads | Reject with `CpUnavailable{reason=NeededForReadIndex}`; `lease_gap_max` enforcement stays at 0. |
| `follower_read_snapshot_capability` bit grant | CP-Raft MUST refuse the capability; follower endpoints stay disabled. |
| Incremental snapshot enablement (`snapshot.delta_chain_max > 0` or `snapshot_delta` APIs) | Reject with `CpUnavailable{reason=CacheExpired}` until a proof lands. |

These failures are normative so every section (leases, durability, follower reads, snapshots) shares the same gate and drift is impossible. While `strict_fallback=true`, the runtime also forces `commit_visibility=DurableOnly` regardless of the prior profile setting so reads never race ahead of durability proofs.

Leaders that possess a locally `fdatasync`'d `wal/durability.log` covering their current `raft_commit_index` but lack quorum proof operate as follows:
- **Writes:** continue to accept appends in Strict mode (`strict_fallback_writes=Allowed`). Each append increments `strict_fallback_pending_entries`.
- **ReadIndex:** remain blocked until CP mirrors a proof whose `(term,index)` ≥ the leader’s `raft_commit_index`. Telemetry emits `strict_fallback_blocking_read_index=true` and `strict_fallback_last_local_proof=index`.
- **Telemetry transitions:** `strict_fallback_state ∈ {Healthy, LocalOnly, ProofPublished}`; transitions occur when (a) the leader loads its local ledger (`LocalOnly`) and (b) CP acknowledges the proof (`ProofPublished`, which clears the gate). Operators must page on `strict_fallback_state=LocalOnly` persisting beyond `strict_fallback_alert_ms` (default 30,000 ms).
- **LocalOnly timeout:** `strict_fallback_state=LocalOnly` that lasts longer than `strict_fallback_local_only_demote_ms = 14,400,000` (4 h) forces the leader to self-demote, emit `StrictFallbackLocalOnlyTimeout`, and page operators so partitions never run indefinitely without CP visibility. Overrides may pause the demotion only while the timer is explicitly renewed (Break-Glass scope `DurabilityOverride`).
Appendix C (see App. C) (“Strict Fallback Gate Truth Table”) restates the admissible operations per `strict_fallback_state` so conformance tests and Explain APIs can assert the same matrix. Every release documents which invariants are machine-checked: the model-checking suite proves §2.1 term/index monotonicity, §2.1.1 gate enforcement, and the §2.4 ACK contract for both 3- and 5-voter clusters using Loom/TLA+. The build manifest MUST list the specific proof artifacts consumed by CI so auditors can trace them to the shipped binary.

### 2.2 Elections & Leader Stickiness
- Election timeout = uniform random `[150, 300] ms` (Throughput/Latency/CP) or `[300, 600] ms` (WAN). Heartbeats every 50 ms. Randomness derives from independent ChaCha PRNG per partition.
- Pre-vote is always enabled. `PreVoteResponse.high_rtt=true` instructs candidates to widen the next election window to WAN range for one term; leases recompute bounds immediately.
- Followers set `high_rtt=true` only after `ema_heartbeat_rtt_ms >= pre_vote.high_rtt_threshold_ms(profile)` for `pre_vote.high_rtt_confirmations = 3` consecutive heartbeats (resets on any healthy heartbeat). This keeps widening opt-in to sustained latency spikes instead of transient pauses and makes the signal deterministic across vendors.

| Profile | `pre_vote.high_rtt_threshold_ms` |
| --- | --- |
| Latency / CP | 150 |
| Throughput | 150 |
| WAN | 350 |

- Telemetry exports `clustor.raft.pre_vote_high_rtt_threshold_ms` (per partition) and `clustor.raft.pre_vote_high_rtt_trip_total` so operators and test harnesses can assert the same constants. Appendix C (see App. C) simulators cover both edges of the threshold.
- High-RTT widening applies per follower: only the partition that observed `high_rtt` stretches its timeout, and it reverts to the profile default after one successful heartbeat or a completed election. Randomization for other partitions remains unchanged to avoid cross-cluster synchronization.
- Leader stickiness: `min_leader_term_ms = 750 ms`. Forced step-down occurs on structural lag (§9.2), device latency overruns (`durability.max_device_latency_ms`), or CP `TransferLeader`. Device latency enforcement uses hysteresis: a leader must see `N=3` consecutive fsync samples above the threshold or a moving-average window (`durability.device_latency_window_ms = 500`) exceeding the bound before stepping down. Recovery requires `M=5` consecutive samples below 80% of the threshold to clear the `DeviceLatencyDegraded` flag and resume normal transfers, preventing flip-flop.
- Backoff: failed elections multiply timeout by 1.5 up to 2 s; resets after a leader survives `min_leader_term_ms`.
- AppendEntries RPC timers (per follower): `append.rpc_timeout_ms = clamp(2 × ema_heartbeat_rtt_ms, 100, 1000)` with up to 4 inflight batches. Timeouts double once (max 2×) until a response arrives.

### 2.3 Read Paths
- Leader leases remain disabled for all profiles in v0.1; the bounds below are frozen solely for future enablement and testability.
- `FutureGate(Leases v0.2)`: The remainder of this subsection (inequalities, `lease_gap_max`, profile tables) documents the constraints that will apply once the lease feature gate opens. Implementations MUST keep leases disabled in production binaries for the entire v0.1 line even though the parameters are specified here for simulator coverage.
- A compile-time flag (`feature.leases=Disabled`), a persisted metadata knob (`metadata.json.feature_leases_state ∈ {HardDisabled,TestOnly,Enabled}`), and a runtime assertion (`lease_gate_runtime_state=HardDisabled`) jointly enforce this rule: production v0.1 builds MUST ship with the metadata knob set to `HardDisabled`, MUST refuse to start if it reads `TestOnly/Enabled`, and MUST fail fast if `lease_gap_max > 0` or any admin API attempts to set `LeaseEnable`. Nodes that boot with `feature.leases != HardDisabled` MUST require the operator to pass `--allow-unsafe-test-features`, flip `node.production_state=TestOnly`, suppress SLO exports, and emit `leases_test_mode_active=1`; without that flag they refuse to mount the partition and emit `LeaseGateMetadataRejected`. Profiles therefore ship with `lease_gap_max=0`, and simulator/tests that temporarily raise the gap must declare `feature.leases=TestOnly` in their metadata **and** run with the explicit test-only flag so production code never accepts the binary.
- ReadIndex is the default linearizable read path. Leaders that restarted must replay through `commit_index` before serving reads. Algorithmically: on start, block every read until `applied_index >= preserved_raft_commit_index_at_start`. Under `commit_visibility=DurableOnly`, further require `wal_committed_index == raft_commit_index` **and** a CP-published durability proof whose `(term,index)` ≥ the `raft_commit_index` observed at read start; otherwise respond with `CpUnavailable{reason=NeededForReadIndex}`. The sole optimization is when `cp.cache_state=Fresh` **and** the cached CP proof matches the local `wal/durability.log` entry byte-for-byte (including `(term,index,segment_seq,io_writer_mode,updated_at/signature)`): in that case the leader may serve reads until either value advances. Any divergence between the cached proof and the local ledger forces `CpUnavailable{reason=NeededForReadIndex}` until CP mirrors the new proof.
- Canonical comparison above normalizes `updated_at` into RFC 3339 (UTC, millisecond precision) strings on both sides and encodes integers little-endian inside the proof blob; spec-lint replays the same canonicalization so JSON caches and binary ledgers remain comparable without lossy conversions.
- `commit_visibility` determines crash semantics (§1.2.1). Leaders export `commit_visibility_gap_*` gauges. Under `DurableOnly`, a leader MAY NOT serve reads (even ReadIndex) until it reloads `wal/durability.log`, proves `wal_committed_index == raft_commit_index`, and CP-Raft mirrors that watermark (§5.5, §10.1); any transient divergence during elections is therefore masked from clients. When the commit index advances beyond the cached CP proof (common during CP outages), subsequent reads fail with `CpUnavailable{reason=NeededForReadIndex}` until a new proof is durably published.
- If CP-Raft is unreachable, freshly elected leaders still accept writes under Strict durability but MUST fail linearizable reads (ReadIndex, follower-read fallbacks) with `CpUnavailable{reason=NeededForReadIndex}` until either (a) CP accepts the durability watermark or (b) a cached CP proof equals the leader’s `raft_commit_index`.
- Every `CpUnavailable{reason=NeededForReadIndex}` response carries retry guidance so clients can fall back cleanly: HTTP surfaces `Retry-After` (minimum 250 ms, encoded as a base-10 integer milliseconds value per RFC 7231’s delta-seconds form) plus `X-Clustor-Last-Cp-Durable: term:index` and `X-Clustor-Commit-Index: term:index`; gRPC mirrors emit metadata `{retry_after_ms, cp_last_durable_term, cp_last_durable_index, leader_commit_term, leader_commit_index}`. Clients MUST treat these responses as transient (HTTP 503 / gRPC `UNAVAILABLE`) and either retry with exponential backoff or downgrade to documented snapshot-style reads when their semantics allow it. Vendors MUST document any alternate behavior, but silent busy loops are prohibited.
- This deliberate fail-closed behavior means **Strict-mode writes continue while linearizable reads block** any time the control plane cannot prove durability. Products MUST therefore ship snapshot or otherwise clearly-documented fallback read endpoints by default so customers retain diagnostic visibility during CP partitions; launching without such a fallback requires an explicit exception from the safety review board.
- Followers NEVER service ReadIndex. They only expose reads via signed snapshot exports or `FollowerReadSnapshot` endpoints that stream `applied_index` checkpoints after a CP-granted capability bit is set; speculative apply buffers remain private. The capability stays revoked unless the partition runs in Strict durability (Group-Fsync disabled), advertises `commit_visibility=DurableOnly`, and the follower proves `applied_index >= advertised_checkpoint`. CP yanks the bit immediately when any guard fails.
- Follower endpoints clamp every response to their current `applied_index`, never service linearizable RPCs, and must be documented to clients as “snapshot-style” reads that fall back to leader ReadIndex on version or epoch mismatch. Responses MUST carry `read_semantics = SnapshotOnly` (HTTP header or gRPC metadata) plus the exporting `routing_epoch`, otherwise clients MUST treat the reply as invalid. In-flight snapshot reads MUST fail closed with `FollowerCapabilityRevoked` if the capability bit is yanked during transmission (e.g., quarantine). Revocation is synchronous: within `follower_capability_revocation_grace_ms = 100` the runtime MUST abort every outstanding follower-read RPC and strip cached authorizations so clients never continue using a revoked capability.
- Enforcement detail: each follower-read RPC carries a cancellable token that re-checks the capability bit on every heartbeat tick (`heartbeat_period_ms = 50`) and on CP/telemetry revocation interrupts; the transport closes the stream immediately when the token fires, ensuring the ≤100 ms grace even on slow clients and making the mechanism portable across runtimes.
- Closed streams MUST surface a terminal status/code of `FollowerCapabilityRevoked` (never a generic transport error) so clients can distinguish capability yanks from network glitches and retry against the leader.
- Lease reads remain disabled unless the inequality holds for two consecutive heartbeats:

```
lease_duration_ms + lease_rtt_margin_ms + clock_skew_bound_ms + heartbeat_period_ms < min_election_timeout_ms
```

| Profile | `min_election_timeout_ms` | `clock_skew_bound_ms` | `lease_rtt_margin_ms` | `heartbeat_period_ms` | `default_lease_duration_ms` | `max_allowed_lease_duration_ms` |
| --- | --- | --- | --- | --- | --- | --- |
| Latency / Base | 150 | 5 | 10 | 50 | 80 | 85 |
| Throughput | 150 | 10 | 10 | 50 | 75 | 80 |
| WAN (lease gate off) | 300 | 50 | 10 | 50 | 180 | 190 |

- Clock skew bounds derive from the node’s `clock_guard` service: each replica samples its PHC/PTP clock (preferred) or chrony/NTP discipline every `clock_skew_sample_period_ms = 1000`, computes the absolute offset from the cluster’s monotonic fence (derived from CP-Raft heartbeats and a GPS/PTP reference), and raises a “skew alarm” when two consecutive samples exceed the profile’s `clock_skew_bound_ms`. Alarmed nodes immediately revoke leases (once enabled), mark `lease_gate_runtime_state=HardDisabled`, and surface `clock_guard_alarm{bound_ms, observed_ms, source}` telemetry so operators can trace the upstream time source.
- Clock discipline requirements: PHC/PTP sources MUST advertise `max_slew_ppm ≤ 20`, `clockClass ≤ 7`, and jitter `< 5 ms` over any 60 s window; chrony-based deployments MUST enable `makestep 1.0 -1` (step on any >1 ms jump during boot) and cap `maxslewrate 400 ppm`. Nodes log both the raw PHC offset and the chrony-supplied dispersion so operators can prove compliance during audits.

- Regardless of profile, leases are hard-disabled whenever `commit_visibility=CommitAllowsPreDurable`; the inequality above is evaluated only once the partition returns to `DurableOnly`.
- `lease_gap_max` (Appendix B (see App. B)) bounds `(raft_commit_index - wal_committed_index)` while leases are active; exceeding it immediately revokes leases and emits `LeaseGapExceeded`.
- Followers invalidate leases on epoch changes, skew alarms, two missed heartbeats, Group-Fsync downgrades, or stickiness resets. Lease responses include `(lease_epoch, routing_epoch, durability_mode_epoch)` and clients must fall back to ReadIndex on mismatch.
- Clients requiring read-your-write semantics under `CommitAllowsPreDurable` must wait for `last_quorum_fsynced_index >= ack_index`.

### 2.4 ACK Contract (Normative)
Leaders may emit a client ACK only when every clause below is simultaneously satisfied for the `ack_index` being returned:
1. **Raft commitment:** `ack_index <= raft_commit_index` and the entry is replicated on a quorum in the current term.
2. **Quorum durability evidence:** The leader has received and persisted a quorum of `DurabilityAck{last_fsynced_index}` records showing `last_fsynced_index >= ack_index`. Followers must append the matching `DurabilityRecord` to `wal/durability.log` **and `fdatasync` that log** (see §5.5) before replying so that the leader can rebuild the proof after crashes.
3. **Leader durability:** The leader has locally persisted through `ack_index`. Strict mode requires `fdatasync` completion for the entry itself; Group-Fsync requires the batch covering `ack_index` to have completed `fdatasync` and to have recorded the batch watermark in `wal/durability.log`.
4. **Ledger alignment:** The leader advanced `wal_committed_index` to at least `ack_index` and recorded that watermark before sending the client response.

These rules make equality of `raft_commit_index` and `wal_committed_index` a leader-side invariant under `DurableOnly` and prevent crash regressions when `CommitAllowsPreDurable` is enabled for reads. Violations must surface as `AppendDecision::Reject(Consistency)` and emit guardrail telemetry.

Leader crashes after counting a follower’s `DurabilityAck` but before emitting the client response are safe: the new leader reconstructs the quorum proof from `wal/durability.log` and either (a) replays the same ACK once it revalidates the ledger, or (b) withholds the ACK if quorum evidence is missing. Client APIs MUST therefore carry an idempotency key (`AppendRequest.idempotency_key`, shared with the admin API header) so callers can distinguish “ACK lost in flight” from “not acknowledged”—servers repeat the same `ack_index` for duplicate keys once the contract is satisfied.

---

## 3  Partitioning & Topology
- Logical keys hash to Raft Partition Groups (RPG). Products choose the hash, but partition IDs must be stable with ≥128-bit entropy.
- Default replica set: 3 voters; DR profile supports 5. Observers (telemetry-only) are disallowed for Latency/CP profiles and optional (default-off) in Throughput/WAN; regardless of profile they are excluded from quorum, ReadIndex, durability, and compaction.
- Throughput/WAN profiles that enable observers may attach at most `observers.max_per_partition = 2` per partition. Observer streams consume a dedicated bandwidth pool capped at `observer.bandwidth_cap = 0.1 × snapshot.max_bytes_per_sec` per partition so they cannot starve snapshot or learner pipes; once the pool is exhausted, observers receive `ThrottleEnvelope{reason=ObserverBandwidth}` and leaders emit `observer_bandwidth_exhausted`.
- Leaders gate all writes and ReadIndex. Followers execute `on_commit` to stay hot for failover and snapshot export; speculative buffers never expose uncommitted state.
- Clients target leaders discovered via CP-Raft placements. Requests MUST carry the latest `routing_epoch`; stale or missing epochs return `RoutingEpochMismatch{observed, expected, lease_epoch, durability_mode_epoch}` (HTTP 409 / gRPC `FAILED_PRECONDITION`).

### 3.1 Membership & Resizing (Normative)
1. **Preflight:** CP-Raft runs placement feasibility (≤70% budgets post-move) and deterministic quorum rehearsal (§3.2). Failures return reasons; optional overrides require audit records.
2. **Catch-up:** New replicas join as `Learner` and must reach either `(commit_index - membership.catchup_slack_bytes)` with default 4 MiB (auto-scaled by throughput) **or** `(leader.last_log_index - membership.catchup_index_slack)` with default 1024 entries inside `membership.catchup_timeout = 120 s` (auto-scaled). Meeting either guard suffices; policy may demand both.
3. **Joint consensus:** After catch-up, Raft enters joint config. `min_leader_term_ms` blocks voluntary transfers. Each `MembershipChange`/`MembershipRollback` records the rehearsal `placement_digest`.
4. **Finalize:** After `joint_commit_count >= membership.finalize_window` (default 64) and no structural lag (§9.2), the leader commits the pure new set and mirrors the decision into CP-Raft.
   - “No structural lag” is codified as `lag_bytes < 64 MiB` AND `lag_duration < 30 s` (i.e., still within the “Transient” class from §9.2). If either bound is exceeded, finalization MUST pause until the lag returns to the transient band or CP explicitly grants `flow.structural_override`.
5. **Rollback triggers:** catch-up timeout, loss of ≥f voters for `membership.rollback_grace_ms = 3000 ms`, or survivability precheck failure. Rollback appends `MembershipRollback{reason, failing_nodes[]}`, commits under the joint quorum, persists the durability ledger watermark for that index, and only then does the leader step down so the next election increments term.

### 3.2 Survivability Precheck
- `quorum_survivability_precheck` enforces deterministic guardrails:
  - `Q`: fraction of single fault-domain losses that retain quorum (voters only). Minimums: 3-voter `Q=1.0`, 5-voter `Q>=0.8` (profiles may raise, never lower).
  - `H`: headroom ratio (post-move CPU/disk utilization vs budget). Default floor 0.2.
  - Advisory `F`: fraction of voters on independent power/network; surfaced via Explain APIs.
- Fault domains are hierarchical (`zone > rack > chassis`). CP-Raft snapshots labels when the move starts; label changes abort the move.
- Overrides require `survivability.policy=Advisory`. Latency/CP deployments default to `Strict` (no overrides). Throughput/WAN may override only `H` with signed justification.
- Catch-up slack and timeout auto-scale with observed throughput and RTT (clamped 10–500 ms); dry-run APIs surface computed values (§12.2).

---

## 4  Log Entry Interfaces
Clustor exposes a versioned framing layer; products extend payload semantics.

```
struct EntryFrameHeader {
    u8  version;
    u8  codec;
    u16 flags;
    u32 body_len;
    u32 trailer_len;      // bytes following body (>=4 for crc32c)
}

struct EntryFrameTrailer {
    u32 crc32c;            // header+body
    [u8; 32] merkle_leaf;  // optional; SHA-256 or BLAKE3 per profile
}
```

Key rules:
- Integer fields are little-endian; manifests retain big-endian UUIDv7/ULID ordering.
- `trailer_len` counts the exact bytes serialized after the body. Frames MUST store at least the 4-byte CRC (`trailer_len >= 4`). `trailer_len = 4` means the CRC is present without a Merkle leaf for that frame; `trailer_len = 36` includes both the CRC and the 32-byte `merkle_leaf`. Profiles that mandate Merkle trees MUST reject frames whose `trailer_len < 36`. `trailer_len = 0` is invalid for v0.1 and receivers treat it as corruption.
- Hash primitives: CRC32C always covers `header || body`. `merkle_leaf = H(header || body || crc32c_le)` where `crc32c_le` is the 4-byte little-endian CRC value and `H` is the selected `integrity.hash_suite`.
- Metadata extensions: required `trace_id`, `span_id`, `ingest_timestamp_ms`; bounded to `entry.metadata_budget_bytes` (default 256 B, up to 1 KiB via policy). Missing metadata yields `AppendDecision::Reject(MetadataMissing)`.
- Frame sizing: `entry.max_frame_bytes = 1 MiB` for Latency/CP, up to 4 MiB for Throughput/WAN (hard stop 4 MiB). Buffers must align to `wal.fs_block_bytes`; misaligned inputs route through `FrameStagingPool`, which throttles at 80% partition or node budgets (64 MiB per partition, 1 GiB per node) and emits `FrameAlignment` throttles.
- Products register codec IDs globally and implement deterministic `encode_entry` / `decode_entry` functions.
- Validation hooks may veto appends (`before_append`). Rejections must carry retry hints.
- `integrity.hash_suite` is selected once per cluster generation (default CRC32C leaves + SHA-256 segment/manifests; Throughput may gate BLAKE3 leaves). Switching requires draining segments that reference the prior suite.

#### 4.1 Segment Integrity MAC (Mandatory)
- Every WAL segment ends with `segment_mac_trailer{version:u8, mac_suite_id:u8, segment_seq:u64, first_index:u64, last_index:u64, entry_count:u32, entries_crc32c:u128, offsets_crc32c:u128, mac:[u8;32]}`.
- `entries_crc32c` is derived by splitting the concatenated entry `{header || body}` stream into 32-bit words, interleaving them across four lanes (`word_index mod 4`), computing CRC32C per lane, then packing the little-endian lane CRCs into a 128-bit value (`lane0` least significant, `lane3` most). `offsets_crc32c` applies the same procedure to the sequence of 64-bit offsets (treated as two 32-bit words each). This binds both payload bytes and their positions, preventing “valid frame moved to a new offset” attacks even when Merkle leaves are disabled. JSON mirrors emit both fields as fixed-length `0x`-prefixed hex strings (32 hex characters, little-endian interpretation).
- The packed `u128` values above are serialized little-endian (lane0 least significant byte, lane3 most significant byte) regardless of host architecture so tooling on big-endian systems must swap accordingly.
- Worked example: suppose `lane0=0x89ABCDEF`, `lane1=0x01234567`, `lane2=0xFEDCBA98`, `lane3=0x76543210`. The packed byte stream is `[EF CD AB 89 | 67 45 23 01 | 98 BA DC FE | 10 32 54 76]` (lane0 first). The emitted JSON string is `0x1032547698badcfe67452301efcdab89` (32 hex digits after the prefix). Receivers MUST reject strings that are shorter/longer than 34 characters or whose hex payload does not match the packed little-endian value; Appendix C (see App. C) adds explicit acceptance/rejection tests (including mixed-case hex).
- `mac_suite_id` selects the MAC algorithm. v0.1 fixes `mac_suite_id=1 (HMAC-SHA256)` and readers MUST reject unknown IDs (`UnknownSegmentMacSuite`). Future suites require a new ID plus a CP-approved `integrity_mac_epoch` bump; segments MUST NOT mix multiple MAC suites even across re-encryptions.
- `mac_suite_id=2` is reserved for `BLAKE3-MAC` in v0.2+. Reserving it here prevents third-party profiles from colliding with the upcoming suite; nodes MUST treat `mac_suite_id=2` as “unsupported but reserved” until CP explicitly raises `integrity_mac_epoch` to a build that implements it.
- `mac` = HMAC-SHA256 keyed by the epoch-specific MAC key. The input bytes are the ASCII string `segment-mac-v1` (no terminator) followed by the little-endian encoding of `{segment_seq:u64 || first_index:u64 || last_index:u64 || entry_count:u32 || entries_crc32c:u128 || offsets_crc32c:u128}`. Implementations MUST preserve that order and width exactly; omitting the prefix or re-encoding the integers is a wire break. Appendix C (see App. C) (“Snapshot Manifest & Segment-MAC Test Fixtures”) publishes a reference vector using key `00..1f`, `segment_seq=7`, `first_index=42`, `last_index=121`, `entry_count=17`, `entries_crc32c=0x1032547698badcfe67452301efcdab89`, and `offsets_crc32c=0x0123456789abcdeffedcba9876543210`, which yields MAC `5c50cc7f43ef3c0127db59a3a8394ed16782e7997b53093c35bff32f8644b8f0`. Production keys MUST NOT reuse the test key.
- The MAC suite is independent of `integrity.hash_suite`; v0.1 therefore mandates `mac_suite_id=1` for every trailer even when BLAKE3 leaves are enabled, and a segment MUST NOT mix multiple MAC suites.
- The trailer is written only after all entries land on disk, then `fdatasync`'d alongside the `.log`. Replay refuses to trust a segment whose MAC fails, regardless of profile Merkle settings. `.idx` files remain MAC-protected but are now advisory helpers rather than the root of trust for entry placement.
- When `integrity.hash_suite` disables Merkle leaves (Throughput profile default), the trailer MAC becomes the sole detection signal for relocation or bit-rot. Operators must rely on §5.4 scrub coverage to detect intra-segment corruption and should expect lower detection granularity than when Merkle trees are enabled.

---

## 5  Durability & Write-Ahead Log

### 5.1 Fsync Semantics
- WAL segments are preallocated (default 1 GiB; ZFS ≥2 GiB) and written with aligned buffers. Each append uses `pwrite` followed by `fdatasync(data_fd)` in Strict mode; Group-Fsync defers `fdatasync` per batch but keeps ordering `data → index` and dir `fsync` only on rollover.
- “Ordered filesystem” above refers to kernels that honor Linux’s `O_DSYNC`/`RWF_DSYNC` guarantees: write completion implies the corresponding journal transaction (if any) reached persistent media and all dependent metadata was durably recorded. Operators who cannot provide Linux 5.15+ with XFS/ext4 semantics MUST present an engineering note that shows equivalent ordering (e.g., vendor whitepaper for XFS on write-through NVMe); absent that, the stack is treated as “unordered” and quarantined at bootstrap.
- Every segment closes with the mandatory `segment_mac_trailer` from §4.1; leaders flush the trailer, then `fdatasync` the `.log` and `.idx`, and finally `fsync` the directory entry before marking the segment deletable.
- Directory `fsync` occurs only on file create/rename/rollover (explicitly including new `wal/durability.log` generations and ledger truncations) and manifest publication per §7.1. Platforms lacking direct I/O must still honor aligned writes and `fdatasync` ordering.
- WAL writer prefers `io_uring` with fixed buffers, downgrading to registered buffers or blocking I/O transparently while emitting telemetry.
- Downgrades enforce guardrails: moving from fixed buffers to registered buffers or blocking I/O clamps `group_fsync.max_batch_ms = min(2 ms, configured)` and `group_fsync.max_batch_bytes = min(32 KiB, configured)`, emits `PerformanceModeDegraded{from_mode,to_mode}`, and raises an incident if the condition persists for `io_writer_mode.downgrade_incident_ms = 5000`. SLO dashboards track the new baseline explicitly so degraded hardware cannot silently violate §9 targets.
- Health samples are recorded once per durability flush completion (Strict `fdatasync` or Group-Fsync batch) and at least every `io_writer_mode.sample_period_ms = 200` via a watchdog so the `N`-sample gates below compare equivalent wall-clock windows across replicas.
- `io_writer_mode ∈ {FixedUring(0), RegisteredUring(1), Blocking(2)}` and is included in `DurabilityAck` so leaders know which guardrails followers are honoring. Any node advertising `Blocking` is barred from Group-Fsync until it reports `RegisteredUring` or better for `io_writer_mode.recovery_window_ms = 60000`.
- Leaders MUST keep the partition in Strict mode (no Group-Fsync batching) whenever any voter reports `io_writer_mode=Blocking`; observers/learners do not gate this decision. The gate lifts only after all voters return to `RegisteredUring` or better for an entire `io_writer_mode.recovery_window_ms` window.
- To avoid perpetual lockout when a single replica remains degraded, the leader starts `io_writer_mode.degraded_grace_ms = 300000` as soon as it observes a voter stuck in `Blocking`. When the grace elapses, the leader MUST either (a) demote the degraded replica to `Learner` via the membership workflow or (b) eject it from the voter set if demotion fails. After demotion, Group-Fsync eligibility is recalculated against the remaining voters, and the degraded replica may rejoin only after it sustains `RegisteredUring` (or better) for one full recovery window.
- To avoid flap storms, a leader also requires `io_writer_mode.recovery_sample_count = 5` consecutive healthy samples from every voter before re-enabling Group-Fsync; any relapse to `Blocking` resets the timer and sample counter. Telemetry emits `io_writer_mode_gate_state ∈ {Open, BlockedByBlockingFollower, RecoveryTimer}` so operators can diagnose why batching is disabled.
- `wal.segment_bytes` tunable: Latency/CP/Throughput `[256 MiB, 2 GiB]`, WAN `[512 MiB, 2 GiB]`, ZFS `[2, 4] GiB`. All writes align to `wal.fs_block_bytes` and exported via metrics for Explain APIs.
- Tooling that reasons about `entries_crc32c`/`offsets_crc32c` can assume at most `wal.segment_bytes / entry.max_frame_bytes(profile)` frames per segment (e.g., Latency/CP ≤256 frames at 1 MiB caps for a 256 MiB segment, Throughput/WAN ≤512 frames at 4 MiB caps for a 2 GiB segment); exceeding those bounds requires first bumping the profile’s explicit `entry.max_frame_bytes`.

### 5.2 Group-Fsync Guardrails
| Parameter | Default | Behavior |
| --- | --- | --- |
| `group_fsync.max_batch_bytes` | ≤ profile ceiling (64 KiB default) | Exceeding forces immediate flush; runtimes MAY adapt downward based on telemetry but MUST never exceed the ceiling.
| `group_fsync.max_batch_ms` | ≤ profile ceiling (5 ms default) | Timer flush; resets per batch; adaptive controllers MAY shorten the window when devices degrade but MUST never exceed the safety bound.
| `group_fsync.max_inflight_bytes_per_partition` | 4 MiB | Breach parks the partition and forces flush.
| `group_fsync.max_inflight_bytes_per_node` | 64 MiB | Node-level cap halts appends until catch-up.
| `group_fsync.overrun_limit` | 2 | Consecutive overruns trigger Strict downgrade.
| `group_fsync.backoff_factor` | 2× | Re-enable delay = 60 s × factor^downgrade_count (≤15 min).

A partition’s controller MAY use telemetry (io_uring latencies, device class) to set tighter runtime limits, but the per-profile ceilings above remain hard safety bounds shipped in artifacts and gates like §0.2 keep them immutable without a spec update. Downgrade counters, hysteresis timers, and the exponential backoff are tracked **per partition**; node-level incidents MAY add additional throttles, but they never reuse another partition’s backoff state.
Acknowledgements remain quorum-`fdatasync`; unacknowledged exposure is bounded by the inflight caps. Downgrades emit `DurabilityTransition{from=Group,to=Strict,effective_index}` after flushing entries ≤ `N` and immediately disable batching until the transition commits. Re-enables append the inverse transition only when CP-Raft is reachable and do not share batches across the fence. `DurabilityAck` records `{last_fsynced_index, segment_seq}` durably so leaders count quorum only after persisted acknowledgements.

Re-enables remaining CP-gated is an intentional safety choice: batching without CP coordination risks asymmetric durability policies and audit gaps. During CP outages the cluster therefore stays in Strict mode (per-append `fdatasync`) even if the underlying I/O remains healthy; expect higher latency/throughput cost, document it in incidents, and re-enable Group-Fsync only after CP returns and logs the transition.

### 5.3 Startup Scrub & Repair
1. Scan tail segments, authenticating AEAD per block and validating `segment_mac_trailer` before CRC/Merkle checks.
2. Rebuild `.idx` files when missing/corrupt using deterministic metadata `{term, index, offset, body_len, crc32c}` plus optional Bloom filters.
3. Verify `wal/durability.log` records and refuse to mount when gaps exceed WAL tails.
4. Truncate partial tail entries deterministically; AEAD or MAC failures quarantine the partition.
5. Record `boot_record.json` with scrub status, durability watermark, WAL geometry, and `io_writer_mode`; replicate to CP-Raft.
- CRC/Merkle failures with a valid MAC are treated as repairable corruption: the segment is marked `needs_repair`, scrubbed via snapshot import, and only escalates to quarantine if retries continue to fail or the MAC later disagrees (§5.4).

Decision table (normative for scrub tooling and operator docs):

| AEAD tag valid? | MAC valid? | CRC/Merkle valid? | Action |
| --- | --- | --- | --- |
| Yes | Yes | Yes | Healthy. |
| Yes | Yes | No | Repair path: mark `needs_repair`, rehydrate via snapshot/import while keeping the replica online but alerting operators. |
| Yes | No | * | Immediate Quarantine — MAC disagreement means integrity epoch cannot be trusted regardless of CRC result. |
| No | * | * | Immediate Quarantine — ciphertext MUST NOT influence state when AEAD authentication fails. |

`*` = don’t-care (ignored once a prior column dictates quarantine).

- Repair loops MUST apply exponential backoff: after each `needs_repair` import attempt that fails integrity checks, the runtime waits `scrub.repair_backoff_ms = min(2^attempt * 1000, 60000)` before retrying and records `repair_attempt_count` plus `repair_in_progress=true` in `boot_record.json`. After `scrub.repair_attempt_limit = 3` consecutive failures (without a successful manifest re-validation) the replica MUST escalate to Quarantine even if the MAC remains valid, preventing infinite oscillation against a flaky object store.

### 5.4 Background Scrubbing & Quarantine
- `scrub.interval = 6 h` sampling 1% of entries per segment (or full CRC when Merkle disabled). Coverage SLO: every WAL byte hashed at least once every 7 days; metric `scrub.coverage_age_days` enforces this.
- Any checksum, AEAD, or MAC anomaly triggers quarantine: block writes, request re-replication, emit incident log. Exit requires a full snapshot + WAL rebuild.
- Failure-injection conformance set: every vendor MUST exercise the following crash kill points at least once per release and prove the outcomes match Appendix C (see App. C) expectations: (a) kill after WAL `pwrite` but before `fdatasync`, (b) kill after `fdatasync` but before `wal/durability.log` append, (c) kill after ledger append but before client ACK, (d) kill during `.idx` rebuild, and (e) kill between `NonceReservationRange` flush and data write. The crash-consistency harness enumerates these five points explicitly so downstream implementations cannot silently skip a class of failures.

### 5.5 Durability Ledger Ordering (Proof Obligation)
- Each replica maintains `wal/durability.log` beside the WAL. Records are append-only `DurabilityRecord{term, index, segment_seq, io_writer_mode}` entries; each record asserts that the local WAL bytes through `(term, index)` have completed the fsync described in §5.1 while the node was operating in `io_writer_mode`. Records never rewrite in place—monotonicity is enforced by rejecting regressions.
- Followers persist the `DurabilityRecord` that covers the index they will advertise in the next `DurabilityAck{last_fsynced_index, segment_seq, io_writer_mode}` and MUST block the ack until the `durability.log` `fdatasync` from step 4 completes so leaders can reconstruct quorum proofs after crashes.
- Leaders and followers therefore execute the identical sequence `pwrite → fdatasync(data_fd) → durability.log append → fdatasync(durability.log)` regardless of role. Spec-lint’s `ledger_ordering_test` replays the ordered steps on both sides and fails the build if either implementation attempts to reorder or coalesce them, preventing asymmetric crash recovery.
- Before appending a `DurabilityRecord`, replicas MUST verify from the on-disk WAL (not process buffers) that the referenced `(term, index)` bytes are readable, that the header/body region matches the expected length, and that the frame-level CRC32C recalculated from those on-disk bytes matches the stored value. If the verification fails—even on allegedly “ordered” filesystems—the replica MUST retry the read after a randomized backoff (`durability.read_verify_retry_ms ∈ [5,20]`) to filter transient device stalls. After a single retry, if the bytes are still unreadable the replica MUST delay the ledger append, re-run startup scrub, and enter Quarantine if the mismatch persists; advertising durability evidence without readable bytes is forbidden.
- **Ledger replay (§5.5-LR):** on startup, replicas scan `wal/durability.log` sequentially and verify each record’s `{term,index,segment_seq,io_writer_mode}` against the WAL bytes. Encountering a hole or corrupted record forces deterministic truncation to the last verified entry; all trailing records are discarded (never skipped) and the replica enters Strict fallback until CP mirrors a fresh proof. Nodes MUST NOT attempt to “skip over” damaged records because that would fabricate durability evidence.
- Leaders compute `last_quorum_fsynced_index` from the intersection of their local `DurabilityRecord` and the quorum of follower acknowledgements. Formally, let `A = {leader_local_index} ∪ {ack_i | ack_i reported by follower i}`. Sort `A` descending and select the highest index `n` such that at least `quorum_size = floor(voters/2)+1` elements of `A` satisfy `value >= n`. That `n` becomes `last_quorum_fsynced_index`, and it always refers to a ledger record (not an in-flight append). They mirror only the resulting `(last_durable_term, last_durable_index)` summary into the CP-Raft durability ledger (§10.1) once the ordering below reaches step 4; CP entries are rejected unless they advance that pair.
- Ordering rule for every replicated entry (clauses §5.5-(1) … (5b)):
  1. Append entry bytes to the WAL segment (`pwrite`).
  2. Complete the WAL `fdatasync` (Strict) or batch flush (Group-Fsync). No ledger or ACK action may occur before this step finishes.
  3. Append the new `DurabilityRecord` (and any coalesced `NonceReservation`, see §8.2) so that it covers `entry.index`.
  4. `fdatasync(wal/durability.log)`.
  5. After clause (4):
     (5a) The leader MAY count follower `DurabilityAck`s toward quorum only if they cover indices ≤ the freshly `fdatasync`'d record.
     (5b) The leader MAY emit the client ACK (§2.4) only after clause §5.5-(5a) succeeds.
- Followers execute the exact same sequence locally and MUST complete steps (1)–(4) before emitting their `DurabilityAck{last_fsynced_index, ...}`. An ack that arrives before the follower `fdatasync`'s both the WAL bytes and the matching `DurabilityRecord` is a protocol violation and must be treated as missing evidence.
- Nonce reservations are range-based. Writers append `NonceReservationRange{segment_seq, start_block_counter, reserved_blocks}` entries measured in units of `wal.crypto_block_bytes`. v0.1 fixes `wal.crypto_block_bytes = 4096 B`, so `nonce.reservation_max_blocks = 1024` and `nonce.reservation_max_bytes = wal.crypto_block_bytes × nonce.reservation_max_blocks = 4 MiB`. Reservations MUST `fdatasync` no later than 4 MiB of new data or 5 ms (whichever occurs first); the 5 ms timer is tracked per partition (never coalesced across partitions) so a noisy neighbor cannot delay another partition’s reservation flush. When a partition flushes a WAL batch for any reason, it MUST also flush any pending reservation entry before acknowledging the batch. On restart, the next block counter resumes at `max(start_block_counter + reserved_blocks)`; therefore the largest benign “hole” scrub may encounter is exactly `wal.crypto_block_bytes × nonce.reservation_max_blocks` (4 MiB in v0.1). The runtime tracks both `wal.nonce_reservation_gap_blocks` and `wal.nonce_reservation_gap_bytes` (largest contiguous reserved-but-unused window) plus `wal.nonce_reservation_gap_events_total`; exceeding the profile-tunable `nonce.reservation_gap_quarantine_threshold_bytes` (default 4 MiB, max 8 MiB under Break-Glass) raises `NonceReservationGapWarning`. Mandatory Quarantine only triggers when (a) the same gap exceeding the threshold is observed across two consecutive boots, or (b) the gap coincides with any scrub/integrity failure in the same segment, or (c) the implementation detects a reused `(dek_epoch, segment_seq, block_counter)` tuple (which remains immediate Quarantine). Hitting three threshold-crossing gap events within `nonce.reservation_gap_incident_window_ms = 86,400,000` also escalates to Quarantine unless the operator applied a Break-Glass exception before the third event. Operators who know a workload will create large benign gaps must raise the threshold explicitly (with ticket) before the workload runs.
- Overflow is forbidden: `start_block_counter + reserved_blocks` MUST stay ≤ `u64::MAX`, and implementations SHALL reject (and page) any attempt to allocate a reservation that would wrap the counter space.
- When a segment is rewritten or abandoned (e.g., re-encryption, repair), replicas MUST append `NonceReservationAbandon{segment_seq, abandon_reason}` to `wal/durability.log` after proving that every block in the reservation range was either written or explicitly zeroed. Compaction engines across the quorum MUST observe either (a) every reservation range for that `segment_seq` marked “fully spent” (i.e., `max_written_block >= start + reserved_blocks`) or (b) a committed `NonceReservationAbandon` before unlinking any WAL bytes tied to that `segment_seq`.
- The happens-before chain is therefore:

```
AppendEntries payload
  → WAL pwrite
  → `fdatasync` WAL data file (or flush the current Group-Fsync batch) while keeping index/directory ordering
  → durability.log append
  → `fdatasync` `wal/durability.log`
  → `fsync` the WAL directory entry when a new segment/ledger file is created or rotated
  → quorum DurabilityAck counted (derives last_quorum_fsynced_index)
  → client ACK (per §2.4)
```

Any crash between these edges preserves either (a) WAL data without a `DurabilityRecord` (forcing Strict fallback on replay) or (b) the `DurabilityRecord` without a client ACK, which remains safe because the ACK contract refuses to respond without step 5 completing. New leaders must load `wal/durability.log`, recompute `last_quorum_fsynced_index`, and publish the resulting `(last_durable_term, last_durable_index)` into CP-Raft before serving writes (§2.1, §10.1).

### 5.6 Quarantine Lifecycle
Quarantine is a named runtime state with a single purpose: halt new writes until integrity doubts are cleared. The state machine is:

| Transition | Trigger | Allowed operations while quarantined | Exit requirements |
| --- | --- | --- | --- |
| Healthy → Quarantine | AEAD/MAC/CRC failure (§5.3/§5.4), repeated `ApplyOutcome::Fatal` (3 within 60 s), dropped `AckHandle`s (3 within window), partial re-encryption detected (§8.2), admin `AdminPausePartition`, disk policy violation (§14.1). | Read-only APIs (snapshot export, telemetry), Explain/Why*, `AdminResumePartition` (Break-Glass), snapshot import for repair. No appends, no membership changes, no durability transitions. | Complete snapshot import or WAL rebuild that replays through `wal_committed_index`, incident ticket referencing remediation, CP-Raft acknowledgement (`QuarantineCleared`) recorded, and supervisor restart. |
| Quarantine → RepairMode | Operator sets `bootstrap.repair_mode=true` for offline work. | Same as above plus data-plane listeners stopped. | Successful repair and `AdminResumePartition`. |
| Quarantine → Decommissioned | Operator deletes replica/partition. | None (partition removed). | N/A |

Every entry/exit emits an audit log with `{partition_id, reason, ticket}`. While quarantined, Explain APIs must return `WhyQuarantined{reason, since_ms}` so clients understand the condition; observers cannot override it.

Commit-index monotonicity is logical (client-facing). Repair actions may truncate local WAL segments below the last advertised `commit_index`, but nodes MUST NOT report a lower `raft_commit_index`/`wal_committed_index` to clients after quarantine. Explain/Why* APIs, telemetry, and admin surfaces therefore continue to emit the pre-quarantine watermark until a fresh proof is republished. While quarantined, leaders serve reads **only** from the last verified snapshot/`applied_index` checkpoint that predates the quarantine event; they MUST NOT materialize new snapshots or follower-read checkpoints until the repair completes, preventing operators from accidentally exporting partially repaired state. Instead, the recovered replica remains paused (no writes, follower reads disabled) until it replays through the prior `commit_index` or imports a snapshot covering it and proves—via a fresh durability ledger record—that `wal_committed_index` continuity holds. Only after that proof is mirrored into CP-Raft may the replica rejoin quorum, preserving the monotone guarantee exposed to clients.

---

## 6  Apply Pipeline & State Machine Hooks
- Every committed entry executes `on_commit(batch: &[EntryView], ctx: ApplyContext)` on leaders and followers. `on_commit` returns `ApplyOutcome::{Ack, Retryable{reason}, Fatal}`. Fatal outcomes force leader step-down and quarantine the replica until replay succeeds.
- `on_applied(last_applied)` publishes watermarks for upper layers. `sm_durable_index` must persist in product storage and never exceed `raft_commit_index`.
- `ApplyContext` exposes async `AckHandle` so products can defer durability confirmation without stalling Raft.
- Crash recovery replays from `wal_committed_index`, and products must reject duplicate side effects above their persisted `sm_durable_index`.

### 6.1 Apply Budget SLA
| Parameter | Default | Notes |
| --- | --- | --- |
| `apply.max_batch_ns` | 2 ms p99 | Leaky bucket increments per breach; drains at 2/s. |
| `apply.budget_breach_threshold` | 5 | Crossing triggers `apply_budget_breach`, PID credit penalty ≤50%, and optional operator overrides. |
| `apply.max_batch_entries` | 512 | Batches beyond this split automatically. |
| `apply.handoff_queue_len` | 1024 | 90% utilization emits `ApplyQueueNearFull` and throttles credits. |
| `ack_handle.max_defer_ms` | 250 ms | Upper bound for deferring `AckHandle::complete`; timer enforced even for products that opt out of crash-linearizable reads. |
| Forbidden work | Blocking syscalls during `on_commit`; use `ApplyDeferredQueue` + `AckHandle`. |

Profiles set per-partition ceilings for `ack_handle.max_defer_ms` via Appendix B (see App. B): Latency/CP partitions remain capped at 250 ms, Throughput partitions may raise the ceiling to 400 ms, and WAN partitions may raise it to 500 ms. Implementations MUST reject configs that exceed their profile’s ceiling even if the local default is lower.

`ApplyOutcome::Fatal` trips a supervisor poison pill; 3 fatals within 60 s trigger a 5 s backoff before campaigning again. The `apply.max_batch_ns` limit is enforced as a sliding-window p99 over the most recent `apply.p99_window_batches = 10,000` batches per partition (windows <10 samples fall back to max), preventing jitter from tiny samples while still catching sustained regressions quickly.

Profile overrides: Appendix B (see App. B) publishes the per-profile ceiling for `apply.max_batch_ns`. Latency/CP profiles inherit the 2 ms p99 ceiling above; Throughput profiles may raise it to 4 ms (documented in the profile bundle) to accommodate larger codecs, while WAN profiles cap at 5 ms because RTT dominates. Implementations MUST enforce those ceilings per partition profile and reject configs that exceed them.

### 6.2 Idempotency & Replay
- Each `EntryView` carries `dedupe_token = (term, index)`; caches MUST evict entries `< snapshot_index` and bound themselves by `apply.dedupe_max_entries = 1M` or `apply.dedupe_max_bytes = 128 MiB`.
- Cold-start replay blocks client reads/writes until `applied_index >= raft_commit_index_at_election`. `ApplyContext.random_seed` is reused on replay for determinism.
- `ApplyOutcome::Retryable` requires explicit reason codes (`TransientIo`, `CodecMismatch`, `QuotaExceeded`, `Backpressure`).

### 6.3 AckHandle Lifecycle
- `AckHandle::complete()` (or `AckHandle::fail(reason)`) MUST be invoked before `ack_handle.max_defer_ms` elapses. The runtime arms a deadline per handle; exceeding it automatically converts the entry into `ApplyOutcome::Retryable{reason=AckTimeout}` and rolls the partition back to the last durable index before accepting more writes.
- Dropping an `AckHandle` without resolving it triggers the same timeout behavior immediately and increments `apply.ack_handle_drop_total`. Three consecutive drops within `ack_handle.drop_window_ms = 1000` quarantine the partition until a supervisor clears the fault, preventing upper layers from silently starving `applied_index`.
- Products that legitimately need longer work must explicitly opt into `ApplyDeferredQueue` with sharded handles and surface their own user-facing status; the runtime still enforces the global deadline to uphold visibility guarantees from §2.4.
---

## 7  Snapshots & State Transfer
- Triggers: log size (`snapshot.log_bytes_target = 512 MiB`), time (`snapshot.max_interval = 15 min`), or follower lag (`snapshot.catchup_threshold = 64 MiB`). Incremental snapshots are disabled in v0.1 (§Appendix P (see App. P)).
- Products implement `snapshot_export` and `snapshot_import`. Importers must accept at least `current_version-1`.

### 7.1 Snapshot Manifest Format
| Field | Description |
| --- | --- |
| `manifest_id` | UUIDv7/ULID, monotonic per partition. |
| `version_id` | Incrementing integer; CP-Raft tracks `accepted_min/max`. |
| `producer_version` / `emit_version` | Emitter build + CP-selected emit version. |
| `base_term`, `base_index` | Last included log entry. |
| `content_hash` | SHA-256 of canonical manifest. |
| `chunks[]` | `{chunk_id, offset, len, digest}` (SHA-256). |
| `logical_markers` | Product-defined (tenant IDs, ranges). |
| `signature` | Ed25519 (or gated P256) over canonical body. |
| `encryption` | `{dek_epoch, iv_salt}` for AEAD decrypt. |

Manifests MUST be emitted as RFC 8785 Canonical JSON: UTF-8 encoding, no insignificant whitespace, deterministic object member ordering (lexicographic by UTF-16 code unit), and minimal numeric representations. Producers first populate every field except `content_hash`/`signature`, canonicalize the JSON, compute `content_hash = sha256(canonical_bytes)` as a lowercase `0x`-prefixed hex string, inject that field, re-canonicalize (still omitting the `signature` field), and finally sign that canonical byte stream. Appendix C (see App. C) (“Snapshot Manifest & Segment-MAC Test Fixtures”) provides a worked manifest plus signer key so implementations can validate hashing and signature coverage end-to-end; spec-lint replays that vector to prevent drift.

CP-Raft manages ManifestSigner keys with anti-rollback counters and dual-validity windows. Nodes refuse manifests from unknown or superseded epochs unless a time-boxed override is applied (§12.2).
`manifest.json` and its directory entry MUST be `fsync`'d immediately after emission; the producer re-lists the manifest (stat + checksum) before advertising it as deletion-authorizing so §8.1 can rely on the manifest being durably discoverable. After the re-list succeeds, the producer appends `SnapshotAuthorizationRecord{manifest_id, base_index, auth_seq, manifest_hash}` to `snapshot/manifest_authorizations.log` (monotone `auth_seq` per partition) and `fdatasync`s the log. Compactors consume that log, re-stat the manifest, and persist `CompactionAuthAck{manifest_id, auth_seq}` in `metadata.json` before unlinking any WAL segment. Missing acks abort deletion, enforcing a two-phase handshake.

### 7.2 Snapshot Import Flow
1. Canonicalize JSON (RFC 8785) and verify signature + DEK epoch via cached trust roots. Dual-validity windows allow reads while CP is unreachable for up to `cp.cache_grace_ms`.
2. Validate `version_id` is within `[accepted_min, accepted_max]`.
3. Stream chunks: authenticate AEAD, decrypt, then verify digest before applying.
4. Apply entries `(base_index + 1 .. latest)` via normal AppendEntries; handle conflicts via truncate-and-replay. AppendEntries arrivals are buffered until `applied_index >= base_index` to avoid interleaving, and MUST NOT be applied (or expose `applied_index > base_index`) until the manifest signature + version checks from steps 1–2 succeed. If the manifest is rejected, buffered RPCs MUST be dropped and the leader notified via `ThrottleEnvelope{reason=SnapshotRejected}` to prevent partially-applied state.
   - The buffer is bounded to `snapshot.import_append_buffer_max_entries = 8192` per partition by default; profiles MAY raise it (≤65,536) via `snapshot.import_buffer_multiplier` when sustained throughput would otherwise starve replication. To cap resident memory, the product of `buffered_entries × entry.max_frame_bytes(profile)` MUST remain ≤ `snapshot.import_buffer_max_bytes = 8 GiB` (configurable downward), and spec-lint enforces the inequality during profile generation. Every change MUST appear in the profile bundle so both sides agree on the cap. Hitting either bound stalls new AppendEntries by emitting `ThrottleEnvelope{reason=SnapshotImport}` so leaders back-pressure until import catches up.
  - Once the importer finishes applying the snapshot (or discards it on failure), the buffer automatically drains in FIFO order and the transport replays any deferred AppendEntries without requiring the leader to re-probe; leaders simply resume their normal heartbeat-based catch-up loop and the throttle clears itself when the buffer drops below 80%.
5. If trust caches expire, imports fail with `snapshot_full_invalidated(reason)` or `snapshot_delta_invalidated(reason)`; operators may issue a time-limited override (`snapshot_full_override`).

### 7.3 Snapshot I/O Budgeting
- Per-peer budget `snapshot.max_bytes_per_sec = 128 MiB/s` with classes `CatchUp`, `Bootstrap`, `DR`. Meters resume only after utilization <90% (10% hysteresis).
- Node-level cap `snapshot.node_max_bytes_per_sec = min(0.7 * detected_nic_capacity, 1 GiB/s)`; exceeding demotes all snapshot traffic until the rolling meter drops below 60%.
- AppendEntries replication always preempts snapshot traffic via weighted fair queuing; heavy snapshot traffic emits `WhySnapshotBlocked` hints.

---

## 8  Storage Layout, Encryption & Recovery

```
/state/<partition_id>/
  wal/
    segment-0000000001.log
    segment-0000000001.idx
  snapshot/
    snap-<term>-<index>/manifest.json
    chunks/
  metadata.json
  boot_record.json
```

### 8.1 Compaction Safety Gates
- Delete WAL below the latest snapshot only when:
  - ≥ `compaction.quorum_ack_count` replicas (2 for 3-node, 3 for 5-node) report `sm_durable_index >= snapshot.index`.
  - Hard floor: never delete below `min(quorum_applied_index, base_index)` where `quorum_applied_index` is the smallest `applied_index` observed across the latest quorum heartbeat bundle, even if `sm_durable_index` advances faster.
  - `checkpoint.quorum_guard_bytes` (default 256 MiB) and learner slack requirements are satisfied. Learners within `membership.catchup_slack_bytes` retain their needed WAL range regardless of guard consumption.
  - The snapshot authorizing deletion remains the latest manifest.
  - The authorizing snapshot manifest and directory entries were `fsync`'d post-rotate, re-listed (stat + checksum), and covered by a `SnapshotAuthorizationRecord` + matching `CompactionAuthAck{manifest_id, auth_seq}` (§7.1) before any WAL unlink occurs to prevent TOCTOU between manifest publication and persistence.
  - If a re-listed manifest later fails signature or hash verification (object-store bitrot), compaction aborts with `CompactionAuthAbort{manifest_id, reason=ManifestSignatureMismatch}` and the manifest is quarantined until a new snapshot replaces it.
  - Re-encryption jobs mark segments `rewrite_inflight`; compaction skips them until `rewrite_complete` is fsync'd.
- All gates above are conjunctive; compaction MUST satisfy both the `sm_durable_index` quorum clause and the `min(quorum_applied_index, base_index)` floor (plus the remaining bullets) before any WAL bytes are unlinked.
- When both a learner slack requirement and the `min(quorum_applied_index, base_index)` floor apply, compaction uses `max(learner_slack_floor, min(quorum_applied_index, base_index))` as the effective floor so that learners retain their guarded range even if `base_index` lags.
- Putting it together: the WAL deletion guard is `floor_effective = max(learner_slack_floor, min(quorum_applied_index, base_index))`, and bytes below `floor_effective` leave disk only after the quorum-level `sm_durable_index` test is satisfied. *Example:* in a 3-replica set with `base_index=1,200`, `quorum_applied_index=1,300`, and a learner that must retain the most recent 100 entries (`learner_slack_floor=1,250`), we compute `min(quorum_applied_index, base_index)=1,200`, so `floor_effective = max(1,250, 1,200) = 1,250`. Even if two replicas report `sm_durable_index=1,500`, compaction MUST keep WAL bytes below 1,250 until the learner catches up and the snapshot manifest authorizes deletion.
- Learner retirement guardrail: when a `MembershipChange` (§3.1) removes or decommissions a learner, compaction MUST continue honoring the most recent `learner_slack_floor` until the retiring replica either (a) acknowledges `applied_index >= learner_slack_floor` or (b) both `learner_retirement_delay_entries = 65,536` and `learner_retirement_delay_ms = 300000` elapse after the joint consensus commit that removed it. CP-Raft records `membership.learner_retire_index` when finalization occurs; compaction MUST surface `compaction.learner_retirement_pending=true` and cite that index in Explain APIs until the guard clears so operators cannot accidentally drop WAL needed by a “dangling” learner that is still replaying offline.
- Compactors MUST also confirm that every `segment_seq` whose bytes would be unlinked either (a) has no outstanding `NonceReservationRange` entries (all are fully spent) or (b) carries a committed `NonceReservationAbandon{segment_seq}` record (§5.5, §8.2). Deletion that races ahead of nonce accounting is forbidden.
- Disk pressure: `disk.soft_usage_percent = 80%` halves credits and triggers snapshots if gates allow; `disk.hard_usage_percent = 90%` rejects appends with `AppendDecision::Reject(DiskFull)` but still serves reads.

Reference pseudocode (`compaction_floor.rs`) ensures every implementation computes the same floor:
```
fn compute_compaction_floor(state: CompactionState) -> u64 {
    let learner_floor = state.learner_slack_floor.unwrap_or(0);
    let quorum_floor = state.quorum_applied_index.min(state.snapshot_base_index);
    let floor_effective = learner_floor.max(quorum_floor);

    if state.quorum_sm_durable_index < state.snapshot_base_index {
        return state.snapshot_base_index; // snapshot not yet safe
    }

    floor_effective
}
```
Callers delete WAL bytes `< compute_compaction_floor(...)` only after the SnapshotAuthorization + CompactionAck handshake succeeds and nonce reservations are cleared.

### 8.2 Encryption & Key Epoching
- `wal.crypto_block_bytes = 4096 (2^12)` is a fixed crypto constant independent of `wal.fs_block_bytes`. Every WAL segment begins with a `segment_header{wal_format_version:u8, segment_seq:u64, crypto_block_bytes:u16, dek_epoch:u32, reserved:u16, ...}` that records both the nonce geometry **and** the encryption epoch. CP-Raft enforces a single `wal.crypto_block_bytes` per cluster generation; allocating a `segment_seq` therefore captures that value, and readers MUST reject (`SegmentCryptoBlockMismatch`) any segment whose header disagrees with the configured constant or changes mid-segment. Mirroring `dek_epoch` into the header lets scrub detect cross-epoch reuse before decrypting bytes. The header is `fdatasync`'d at allocation so crash recovery can verify it before decrypting the first block. Telemetry exports `clustor.wal.crypto_block_bytes` so operators can confirm uniformity, and Appendix C (see App. C) tests assert mixed values are rejected.
- AEAD (AES-256-GCM default) encrypts WAL segments and snapshot chunks. Tags are fixed at 16 bytes for the GCM suite, matching the constant-time comparison helpers in Appendix C; future suites that emit 32-byte tags MUST update both the macros and this clause before landing. To stay on the well-tested 96-bit IV path, every `wal.crypto_block_bytes` chunk derives `iv96 = Truncate96(H(dek_epoch || segment_seq || block_counter || b"WAL-Block-IV v1"))`, where `H` is SHA-256 or BLAKE3 and the concatenated fields are encoded big-endian. `{aad_version:u8=1, partition_id, dek_epoch, segment_seq}` remain the AAD so future field order changes cannot be replayed against older binaries. Raising the AAD version requires a CP-approved upgrade plan and keeps old nodes failing-closed. (AES-GCM-SIV is parked for v0.2 but remains optional in dev clusters.)
  - MAC suite selection is orthogonal to `integrity.hash_suite`; even when `H=BLAKE3` for IV derivation or leaf hashing, segment trailers continue using the cluster-wide MAC (HMAC-SHA256 in v0.1) until CP-Raft bumps `integrity_mac_epoch`. Segments MUST NOT mix MAC suites.
  - **Nonce domain:** For every DEK, `(segment_seq, block_counter)` MUST be globally unique. `block_counter` monotonically increments per `wal.crypto_block_bytes` chunk inside a segment and resets only after a new `segment_seq` is allocated.
  - **Segment identifiers:** `segment_seq` values are reserved from a monotone counter that is stored in CP-Raft and in `wal/durability.log`; WAL rotation, re-encryption, and post-crash rewrites must allocate a fresh `segment_seq` before emitting the first block so rewrites never reuse the prior nonce space.
    Reusing an old `segment_seq` for any content—regardless of offsets or data—is forbidden even if the previous segment was deleted.
  - **Crash-safe reservations:** Writers reserve nonce ranges in chunks of ≤`nonce.reservation_max_blocks = 1024` `wal.crypto_block_bytes` blocks (4 MiB). Before writing block `n`, the runtime ensures a `NonceReservationRange` covering `[n, n + range_len)` is present in `wal/durability.log`; new ranges are `fdatasync`'d at least every 4 MiB or 5 ms (step 4 of §5.5). Blocks within a reserved window may be written without additional ledger traffic, and restarts resume at `max(start + reserved_blocks)`. Crashes can therefore create benign gaps up to 4 MiB; larger gaps imply tampering and trigger quarantine.
    Reservations NEVER span multiple `segment_seq` values; rotating the segment or re-encrypting it forces a fresh reservation anchored to the new `segment_seq`, and any leftover reservation tied to the old `segment_seq` is invalidated once the rewrite finishes.
  - **Out-of-order `io_uring` completions:** Completion events may arrive out of order, but nonce retirement is serialized. Writers MUST stage completions in a per-segment commit queue keyed by `block_counter` and only advance the reservation tail when every counter ≤ the candidate has durably landed. Dropping an out-of-order completion on the floor is forbidden; instead, the runtime parks it until all earlier counters commit, guaranteeing the `(segment_seq, block_counter)` pairs consume reservations monotonically even when the kernel signals completion early. Telemetry `wal.nonce_out_of_order_total` counts how often completions had to be parked so operators can spot devices that routinely reorder DMA writes.
  - **Reservation retirement:** Re-encryption, repair, or compaction that abandons a `segment_seq` MUST append `NonceReservationAbandon{segment_seq, abandon_reason}` after proving the referenced bytes cannot be replayed. CP-Raft tracks abandon records so compaction logic can prove no nonce window is left dangling.
  - **Gap accounting:** Scrub jobs distinguish `NonceReservation` gaps (reserved-but-unused, ≤4 MiB) from corruption by exporting `wal.nonce_reservation_gap_bytes` vs `wal.nonce_corruption_bytes`. Nodes raise `wal.nonce_reservation_gap_alarm` once the gauge exceeds 2 MiB; exceeding `wal.nonce_reservation_max_gap_bytes = 4 MiB` triggers an exponential backoff policy before quarantine: the first violation emits only telemetry, the second within `nonce.reservation_gap_backoff_ms = 600000` forces `OverrideStrictOnlyBackpressure`, and the third within the same window escalates to Quarantine. Gaps that persist across two reboots or coincide with scrub failures bypass the backoff and quarantine immediately. Reservation gaps do not block compaction; they only influence telemetry and scrub sampling priorities.
- Key provider tracks `{kek_version, dek_epoch, integrity_mac_epoch}`. Rotations occur time-based (24h for DEK, 30d for KEK), on membership change, or via admin `RotateKeys` (Break-Glass).
- `wal/durability.log`, `.idx`, and manifest footers include MACs keyed by `integrity_mac_epoch`. Nodes refuse to mount when epochs drift by >1; the only override is `AdminOverrideKeyEpoch` (Break-Glass) which temporarily allows a +2/-2 window while raising `KeyEpochOverrideActive` telemetry and forcing Strict mode until the mismatch is cleared.
- Re-encryption streams rewrite segments with new `segment_seq` reservations recorded in CP-Raft; partial rewrites quarantine until resumed. Resuming a rewrite allocates a fresh `segment_seq`, appends `NonceReservationAbandon` for the superseded one, and continues only after CP acknowledges the new reservation range so nonce space never overlaps.
- CP-Raft persists every epoch as a monotone `u32`; any attempt to replay a lower `{kek_version, dek_epoch, integrity_mac_epoch}` value—whether due to CP rollback or malicious injection—is rejected with `KeyEpochReplay` and forces Strict fallback until operators investigate. Data-plane caches mirror the same invariant and MUST refuse to consume a proof whose epoch regresses.

### 8.3 Compatibility Contracts
- WAL segments declare `wal_format_version`; nodes advertise `[wal_min, wal_max]` and refuse unsupported ranges.
- `.idx` files carry `index_format_version` and MAC metadata. Rebuilds emit the highest version readable by every replica in the voter set; incompatible disks require snapshot+restore.
- Snapshot `emit_version` equals `min(max_schema across quorum)`; CP-Raft raises it only after all replicas advertise support. Admin tooling surfaces `clustor.compat.emit_version_blocked{feature}` when features wait on emit-version bumps.
- Recovery flow: validate manifests, replay WAL to `commit_index`, rebuild apply caches, reconcile durability ledger, and require Strict mode until proof exists.

---

## 9  Flow Control & Backpressure

### 9.1 Credit Controller Model
- PID loop samples every `flow.sample_period_ms = 100` with error `e = target_backlog - observed_backlog`.
- Baseline gains (manual mode):

| Profile | Kp | Ki | Kd |
| --- | --- | --- | --- |
| Latency / CP-Raft | 0.60 | 0.20 | 0.10 |
| Throughput | 0.50 | 0.15 | 0.08 |
| WAN | 0.40 | 0.10 | 0.05 |

- Numeric stability guardrail: for every profile, `Ki × (flow.sample_period_ms / 1000)` MUST remain ≤ 1.0; config validators clamp or reject values that would violate this condition to prevent integrator blow-up.
- Integral windup clamp ±2048 entries; derivative term uses EMA (`flow.pid_derivative_tau_ms = 300` Latency/Throughput, 450 WAN).
- Targets: `target_latency_ms=25`, `target_backlog_entries=512` (scaled per tenant quotas). Credits are bounded `credit_min = 1 batch`, `credit_max = 4096 entries`.
- Dual-token bucket: every partition tracks `entry_credits` and `byte_credits`. Large frames burn both counters; the leader pauses admission whenever either hits zero. Defaults: `entry_credit_max = 4096`, `byte_credit_max = 64 MiB`, `byte_credit_refill_rate = target_backlog_bytes / flow.sample_period`. PID error now consumes a weighted sum of the two deficits so jumbo frames cannot starve small ones. Explain APIs expose both balances.
- Minimum service quantum: even when byte credits are exhausted by jumbo frames, the scheduler admits at least one frame ≤`flow.min_small_frame_bytes = 16 KiB` per `flow.sample_period_ms` so small requests continue making progress.
- Operator ergonomics: profiles ship with pre-tuned gains and bucket sizes so most clusters run the controller in “standard” mode (no custom knobs). Advanced tuning is optional and requires a documented change ticket; otherwise operators can treat the flow controller as a black box and rely on Explain APIs + throttle envelopes for visibility.
- Tenant quotas enforce weighted-fair sharing; `OverrideCredit` is Break-Glass with TTL ≤10 min.
- Auto-tuning gate remains disabled in production (Appendix P (see App. P)). Dev/test clusters may enable it with soak requirements and persisted gains.
- Leadership changes reset the controller’s integrator/derivative state to zero and clamp both credit buckets to `credit_min` until the new leader observes `flow.pid_state_checkpoint` replicated in the current term. This avoids inheriting stale windup from the prior leader and makes `TransferLeader` deterministic: the handoff copies the last checkpoint only when `strict_fallback=false`, otherwise the new leader performs a cold start and emits `flow.pid_reset_reason=StrictFallbackOrElection`.

### 9.2 Lag Classification & Mitigation
| Lag Class | Definition | Action |
| --- | --- | --- |
| Transient | `lag_bytes <= 64 MiB` and `lag_duration < 30 s` | Cut credits 50%, boost snapshot priority, log `FollowerTransientLag`. |
| Structural | Beyond thresholds above or bytes ≥256 MiB | Force Strict durability, cut credits to 25%, trigger snapshot rebuild, alert CP-Raft, optionally step down leader. |
| Manual kill-switch | `flow.structural_hard_block` (default false) | Operators may block writes entirely while retaining reads. |

Leaders MUST step down when structural lag persists for `flow.structural_stepdown_ms = 15000 ms` unless CP approves `flow.structural_override` (Break-Glass). Overrides expire automatically after `flow.structural_override_ttl_ms = 120000` unless renewed, and they are cleared as soon as lag returns to the Transient band for three consecutive sampling windows to avoid oscillation. The “optional” action above therefore only refers to whether operators step down earlier than the hard limit.

### 9.3 Client-Facing Throttling
Canonical throttle envelope (HTTP 429 / gRPC `RESOURCE_EXHAUSTED`):
```
{
  "reason": "ApplyBudget|WALDevice|FollowerLag|DiskSoft|DiskHard|TenantQuota|FrameAlignment|SnapshotImport",
  "retry_after_ms": <ms>,
  "observed_backlog_entries": <n>,
  "observed_backlog_bytes": <bytes>,
  "entry_credits_available": <n>,
  "byte_credits_available_bytes": <bytes>,
  "estimated_drain_ms": <ms>,
  "durability_mode": "Strict|Group",
  "durability_mode_epoch": <id>,
  "lease_epoch": <id>,
  "routing_epoch": <id>,
  "ack_term": <term>,
  "ack_index": <index>,
  "last_quorum_fsynced_index": <index>,
  "decision_trace_id": <uuid>
}
```
Clients must ignore unknown `reason` values. `entry_credits_available`/`byte_credits_available_bytes` summarize the dual-bucket state so clients understand whether large frames or entry counts triggered throttling. `last_quorum_fsynced_index` reflects the quorum proof derived from §5.5’s ledger ordering. `decision_trace_id` feeds Explain APIs (`WhyCreditZero`, `WhyDiskBlocked`). To prevent oversized replies, throttle/Why* envelopes MUST remain ≤32 KiB JSON and MAY list at most 32 IDs per array field; beyond that, servers MUST summarize with counters and set the shared field `truncated_ids_count` to the number of elided IDs (0 omits the field). Lists MUST be sorted lexicographically by their primary key (e.g., `(partition_id, shard, reason)`), and when truncation occurs the payload MUST also include `continuation_token` so clients can request the next page deterministically. Every Why* schema inherits these fields so clients can programmatically detect truncation and resume pagination.

---

## 10  Control Plane – CP-Raft
Dedicated Raft cluster managing durable metadata.

### 10.1 Durable Objects & Feature Gates
| Object | Purpose |
| --- | --- |
| Tenant descriptors | Auth, quotas, regional placement policy |
| Partition manifests | Replica placements, durability modes, key epochs |
| Session descriptors | Lease metadata, sequencing constraints |
| DR fences | Failover epochs, manifest hashes |
| Feature gates | Versioned toggles |
| Override ledger | Signed operator overrides |
| Durability ledger | `{partition_id, last_durable_term, last_durable_index, updated_at}` |
| QuarantineCleared records | `{partition_id, cleared_at_ms, ticket_url, cp_signature}` acknowledgements that the quarantine exit handshake from §5.6 completed |

- The data-plane ledger lives in `wal/durability.log` (same filesystem as the WAL) and emits append-only `DurabilityRecord{term, index, segment_seq, io_writer_mode}` entries per §5.5. Leaders publish only the summarized `(last_durable_term, last_durable_index, updated_at)` into the CP-Raft durability ledger once the local record is `fdatasync`'d and they hold a quorum proof; CP entries are rejected unless they advance that pair monotonically.
- Ledger appenders also record `NonceReservationRange` and `NonceReservationAbandon{segment_seq, abandon_reason}` entries so the control plane can prove nonce ranges were either spent or explicitly retired before WAL compaction (§5.5, §8.1, §8.2).
- CP signs each durability-ledger update. Nodes MUST retain `{term,index,segment_seq,io_writer_mode,updated_at,cp_signature}` so cached proofs can be compared byte-for-byte against local `wal/durability.log` records when enforcing the read gate in §2.3; mismatches suppress reads even if the numbers align.
- During elections, candidates must supply their latest `wal/durability.log` watermark (or a CP-provided proof with equal/greater values) before they may leave Strict mode or re-enable leases/Group-Fsync (§2.1).
- CP-Raft also tracks the `follower_read_snapshot_capability` bit per partition; it refuses to set the bit unless the partition is in Strict durability, `commit_visibility=DurableOnly`, and the follower proved its `applied_index` watermark. Only then may a node advertise follower read-only endpoints (§2.3).
- Feature enablement requires dry-run validation, audit entry, deterministic simulator coverage, and homogeneous gate state across a voter set.
- CP-Raft supports `N/N+1` upgrades. Nodes emit snapshots up to version `N` until every replica upgrades, then CP raises `emit_version`.
- Durability proofs stored in CP-Raft expire automatically after `cp.durability_proof_ttl_ms = 86400000` (24 h). A background janitor GC deletes proofs older than the TTL once every `cp.durability_gc_period_ms = 600000`. Nodes MUST refresh their proofs proactively before expiry; stale proofs falling out of the ledger force strict fallback until a fresh `(last_durable_term, last_durable_index)` lands. Operators MAY raise the TTL only when long-running maintenance windows require it, and every change is logged in the override ledger.
- During CP outages, data-plane nodes continue serving traffic using cached routing epochs, RBAC, durability ledger, and key epochs for up to `cp.cache_grace_ms = 300000`. Mutating admin APIs return `CpUnavailable`. Safety downgrades (Strict fallback, lease disable, Group-Fsync lockout, key quarantines) continue without CP, and §2.3 clarifies that client appends are still accepted under Strict durability while linearizable reads fail with `CpUnavailable{reason=NeededForReadIndex}` unless a cached proof exists. When caches expire, nodes remain in Strict mode and disable incremental snapshots/leases until CP returns.
- The Strict-only fallback above typically increases per-partition latency by 40–60% on Throughput hardware; Appendix A (see App. A) tracks this via `cp.outage_strict_mode_active`. Nodes also expose `strict_only_runtime_ms` (monotone while CP is unreachable). Profiles define `cp.strict_only_backpressure_ms` (default: Latency/CP=120000, Throughput=300000, WAN=600000); once `strict_only_runtime_ms` exceeds that bound, leaders MUST halve `entry_credits`/`byte_credits` (bounded floor = 1 batch), emit `CpOutageBackpressure` incidents, and recommend load shedding. Operators MAY keep serving if they acknowledge the incident, but the runtime will continue to clamp credits until CP returns or the operator explicitly overrides via Break-Glass (`OverrideStrictOnlyBackpressure`, TTL ≤ 5 min).
- Once `cp.cache_age_ms > cp.cache_grace_ms`, the following operations hard-fail with `CpUnavailable{reason=CacheExpired}` regardless of operator overrides: (a) membership changes (`MembershipChange`, `MembershipRollback`), (b) durability transitions, (c) key rotations/epoch bumps, and (d) DR fencing (`FenceCommit`, `FenceAbort`). Read-only APIs still work using the frozen cache snapshot; writes continue only under Strict durability.
- Nodes export `cp.cache_state ∈ {Fresh, Cached, Stale, Expired}` to keep dashboards and admission code in sync: `Fresh` (age ≤ `cp.cache_fresh_ms = 60,000`), `Cached` (`cp.cache_fresh_ms < age ≤ 0.5 × cp.cache_grace_ms`), `Stale` (`0.5 × cp.cache_grace_ms < age < cp.cache_grace_ms`), and `Expired` (age ≥ `cp.cache_grace_ms`, which forces the hard failures listed above). Admin APIs and incidents MUST source their decision from this metric rather than reimplementing the thresholds.
- Every transition into `cp.cache_state=Expired` increments the monotonic counter `cp.cache_expiry_total{partition_id}` so SLO tooling can correlate cache lapses with user-visible incidents.
- Early warning: nodes derive `cp.cache_warn_ms = max(0.75 × cp.cache_grace_ms, cp.cache_grace_ms - 60000)` and flip `cp.cache_warning=1` telemetry plus a `CpCacheWarning` incident as soon as `cp.cache_age_ms ≥ cp.cache_warn_ms`. While the warning bit is set, leaders MUST attach `cache_warning_ms_remaining = cp.cache_grace_ms - cp.cache_age_ms` to every `CpUnavailable{reason=NeededForReadIndex}` response so clients and operators have at least one minute of lead time before hard failures trigger.
- Mixed-version guardrails: features that require parity (leases, Group-Fsync, incremental snapshots) remain disabled until every replica advertises support. CP logs `FeatureResume` once reenabling succeeds.

### 10.2 DR Fencing Enforcement
1. CP-Raft writes `(fence_epoch, manifest_id)` and lists participating partitions.
2. Each partition appends `FenceCommit{fence_epoch, manifest_id, dr_cluster_id}` and reports `fence_committed_index` once `wal_committed_index` covers it.
3. CP flips tenant/placement state only after all partitions acknowledge. Aborts append `FenceAbort{fence_epoch}` and require a fresh epoch for retries.
4. Any mismatched fence forces immediate step-down and `fence_reject_reason` in `boot_record`.

### 10.3 Key Material Epochs
- CP-Raft tracks `{kek_version, dek_epoch, integrity_mac_epoch}` per partition. Nodes fetch keys via the KeyProvider; grace to retrieve updates: `key_fetch.grace_ms = 30000`. Expiry quarantines the replica (`KeyEpochMismatch`).
- Dual-validity windows keep old/new KEKs valid for `trust.dual_validity_ms = 600000` **for decryption only**; encryption and proof publication always use the newest CP-issued epoch once it is locally available so fresh ciphertext never regresses to an older key.
- CP persists every epoch update in the durability ledger with a strictly monotone `{epoch, updated_at}` pair. Replicas MUST reject any CP snapshot or log replay that attempts to decrease an epoch, and the override ledger MUST record the ticket/TTL whenever operators temporarily widen the acceptance window.

### 10.4 System Log Entry Catalog
| Entry | Wire ID | Fields |
| --- | --- | --- |
| `MembershipChange` | 0x01 | `{old_members[], new_members[], routing_epoch}` |
| `MembershipRollback` | 0x02 | `{reason, failing_nodes[], override_ref}` |
| `DurabilityTransition` | 0x03 | `{from_mode, to_mode, effective_index, durability_mode_epoch}` |
| `FenceCommit` | 0x04 | `{fence_epoch, manifest_id, dr_cluster_id}` |

`DurabilityAck` messages persist `{last_fsynced_index, segment_seq, io_writer_mode}` before replying.

Encoding contract: every system log entry packs its fields in the listed order using the frozen binary rules from §0.3 (`u8` enums, little-endian fixed widths, `u16` array counts, `u32` byte lengths). Senders append new optional fields only at the tail with a preceding `u8 has_field` flag; receivers MUST ignore recognized tail fields they don't understand while rejecting unknown mandatory slots. gRPC mirrors expose numeric enums, while JSON shadows return the canonical enum string and accept both string and numeric inputs for upgrades.

---

## 11  Security & Isolation

### 11.1 mTLS & SPIFFE Rotation
- All node-to-node RPCs use mTLS with SPIFFE identities. Rotation: upload new trust bundle → dual-validity (`trust.dual_validity_ms = 600000`) → drop old bundle once every peer confirms. Short-lived certs (≤24 h) require fresh CRL/OCSP material; nodes fail closed if revocation data exceeds `revocation.max_staleness_ms = 300000`. Break-glass tokens can bypass revocation temporarily with audit reason.

### 11.2 AEAD Usage & Re-Encryption
- WAL segments and snapshot chunks use AEAD with 64-bit `segment_seq` and `block_counter` fields forming the nonce, where `block_counter` advances in `wal.crypto_block_bytes` increments. Tags and MAC epochs bind ciphertext to `{partition_id, dek_epoch, segment_seq}`. `.idx` files remain plaintext but carry HMAC footers keyed by `integrity_mac_epoch`.
- Re-encryption jobs stream data through an AEAD rewriter, allocate fresh `segment_seq` ranges via CP-Raft, and mark segments `rewrite_inflight` until `rewrite_complete` is fsync'd. Partial rewrites quarantine partitions until resumed; resumption MUST allocate a brand-new `segment_seq`, append `NonceReservationAbandon{segment_seq_old, abandon_reason=Rewrite}`, and only then continue emitting ciphertext under the latest `dek_epoch`. Encrypting new blocks always uses the newest epoch/key; dual-validity windows apply solely to decryption so replicas can read older ciphertext while keys roll.

### 11.3 RBAC & Break-Glass Controls
| Role | Capabilities |
| --- | --- |
| Operator | Partition lifecycle, durability changes, `TransferLeader`, snapshot triggers/imports. |
| TenantAdmin | Read telemetry, per-tenant flow overrides within quotas. |
| Observer | Read-only metrics and Explain APIs. |
| BreakGlass | Required for destructive/risk-expanding APIs (survivability overrides, Group-Fsync re-enables, key rotations, `AdminResumePartition` from quarantine, throttle overrides beyond quota). |

RBAC manifests replicate via CP-Raft; caches refresh every 30 s. Failure to refresh twice enters fail-secure mode: admin APIs reject with `RBACUnavailable`, data plane continues for `rbac.grace_ms = 60000` using last known manifest, and telemetry surfaces `rbac_cache_stale`.

**Break-Glass token issuance (normative):**
- Tokens are minted only by CP-Raft via `IssueBreakGlassToken{scope, ticket_url, expires_at}` after a dual-approval workflow that records the request in the override ledger. Operators never self-mint tokens from data-plane nodes.
- Tokens MUST be encoded as SPIFFE X.509 SVIDs that carry the extension `urn:clustor:breakglass:<scope>` plus the ticket URL in `subjectAltName`. The SVID lifetime is capped at `breakglass.max_ttl_ms = 300000` (5 min) and cannot be renewed; clients must request a fresh token after expiry.
- Scopes enumerate the concrete API set (`DurabilityOverride`, `SurvivabilityOverride`, `ThrottleOverride`, etc.). Nodes MUST reject a token whose scope does not match the attempted API, whose TTL has elapsed, or whose SPIFFE trust domain differs from the cluster’s configured domain.
- Every token is bound to `{cluster_id, partition_or_global_scope, actor_id}` and logged in the override ledger with `used_at` timestamps and the exact SPIFFE ID that exercised it (`used_by_spiffe_id`). Data-plane components MUST emit `breakglass_token_used{scope, actor_id, ticket_url}` telemetry on first use and MUST zeroize the SVID immediately afterward so it cannot be replayed.

---

## 12  Admin & Lifecycle APIs
All admin APIs are gRPC/JSON dual surfaces; every mutating request requires `Idempotency-Key` (retained 24 h by default, up to 7 days per policy).

| Category | Endpoints (sample) | Notes |
| --- | --- | --- |
| Partition lifecycle | `CreatePartition`, `DeletePartition`, `MovePartition`, `DryRunMovePartition` | Idempotent CP-Raft transactions. |
| Replica management | `CreateReplica`, `AdminPausePartition`, `AdminResumePartition` | Resume while quarantined is Break-Glass. |
| Durability | `SetDurabilityMode`, `GetDurabilityMode` | Mode changes append `DurabilityTransition{from,to,effective_index}`; stale callers receive `ModeConflict` (HTTP 409). |
| Snapshots | `TriggerSnapshot`, `ListSnapshots`, `DownloadSnapshot`, `UploadSnapshot`, `DryRunSnapshot`, `SnapshotFullOverride` | Overrides are time-boxed and audited. |
| Flow control | `GetPartitionBacklog`, `OverrideCredit`, `WhyCreditZero` | Overrides require TTL + justification. |
| DR ops | `BeginFailover`, `CompleteFailover`, `AbortFailover`, `DryRunFailover` | Align with §10.2 fencing. |
| Telemetry | `SetMetricsLevel`, `SubscribeAuditLog`, `WhyNotLeader`, `WhyDiskBlocked`, `WhySnapshotBlocked` | Shared schema header (`schema_version`, `generated_at`). |

Dry-run endpoints report guardrails and computed parameters (e.g., auto-scaled catch-up slack/timeout, predicted credit impact). Explain APIs always include `routing_epoch`, `durability_mode_epoch`, observed vs expected guardrail, and `decision_trace_id` when relevant.

Runbook snippets (normative summaries only):
1. **Disk replacement:** pause partition, verify latest snapshot, replace disk, rerun startup scrub, rejoin via `CreateReplica`.
2. **Hot partition rebalance:** require `Q`/`H` healthy, lag below thresholds; run `DryRunMovePartition`, execute move, confirm `WhyNotLeader` reflects new placement.
3. **Leadership transfer:** ensure Group-Fsync healthy, no structural lag, `apply_queue_depth < 10%`; issue `TransferLeader`, wait `commit_quiescence_ms = 200`, then drain.
4. **DR failover:** require CP reachable, fence mismatch clear, lag ≤128 KiB; `BeginFailover`, verify first entry includes `(fence_epoch, manifest_id)`, `CompleteFailover` once lag=0.
5. **Snapshot seeding:** ensure delta chain < cap or plan full snapshot, NIC utilization <70%; run `DryRunSnapshot`, then transfer and verify signature.
6. **Certificate rotation:** upload bundle, observe dual-validity, drop old bundle after all nodes report adoption.

### 12.1 CP Outage Behavior (Runbook Tile)
- **Detection:** Page when `cp.cache_state ∈ {Stale, Expired}` or when `strict_only_runtime_ms` exceeds `cp.strict_only_backpressure_ms` (§10.1). Expect `strict_fallback_state=LocalOnly`, `CpUnavailable` incidents, and throttle envelopes that cite `CpUnavailable{reason=NeededForReadIndex}`.
- **Client error mapping:** Leaders continue to accept writes (Strict only) but every linearizable read returns HTTP 503 / gRPC `UNAVAILABLE` with `CpUnavailable{reason=NeededForReadIndex}`, `Retry-After ≥ 250 ms`, and the `{cp_last_durable_*, leader_commit_*}` metadata from §2.3. Admin mutations fail with `CpUnavailable{reason=CacheExpired}` once caches exceed `cp.cache_grace_ms`. These codes are normative; custom surfaces MUST NOT remap them.
- **Retry/backoff:** Clients MUST honor the provided `Retry-After` or, when absent, back off exponentially starting at ≥250 ms with full jitter, capping at 5 s. Busy-loop retries are forbidden and treated as misbehaving tenants via throttles.
- **Fallback reads:** Products that require availability during outages MUST pre-wire snapshot-style fallbacks (`FollowerReadSnapshot` or exported snapshots). Responses MUST continue to carry `read_semantics=SnapshotOnly`, epoch headers, and capability checks so clients cannot accidentally treat them as linearizable results. Document any dataset-specific caveats (e.g., “metadata may lag up to N seconds”) in the product SLO.
- **SLO impact:** While CP is unreachable the cluster remains in Strict durability and halves credits after `cp.strict_only_backpressure_ms`; §10.1 notes that write latency typically regresses by 40–60% and throughput drops accordingly. Operators SHOULD communicate the degraded SLO externally and track recovery in incident tooling.
- **Product-team expectations:** Every product surface that embeds Clustor MUST document (a) how `CpUnavailable` propagates to customers, (b) the supported snapshot/read fallback, and (c) operational steps to revalidate data once CP returns. Launch reviews fail if these artifacts are missing.

---

## 13  Telemetry & Observability
- Metric namespaces: `clustor.raft.*`, `clustor.wal.*`, `clustor.snapshot.*`, `clustor.flow.*`, `clustor.cp.*`, `clustor.security.*`.
- Naming convention: metrics MUST use dotted Prometheus-style names rooted at `clustor.*` (e.g., `clustor.raft.commit_latency_ms`), incidents MUST use the same namespace suffixed with `.incident.*`, and JSON payload fields remain snake_case (matching the API schema). Spec-lint validates new metric names against this pattern so exporters never need per-signal translation layers.
- Canonical histogram buckets (latency in ms unless noted):
  - `clustor.wal.fsync_latency_ms`: `[0.25, 0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100]`
  - `clustor.raft.commit_latency_ms`: `[0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100]`
  - `clustor.snapshot.transfer_seconds`: `[1, 2, 4, 8, 16, 32, 64, 128, 256]`
  - `flow.apply_batch_latency_ms`: `[0.25, 0.5, 1, 2, 4, 6, 8, 10]`
- Out-of-profile systems (e.g., WAN, ZFS-on-HDD) are expected to saturate the top bucket; alerts still fire if the p99 exceeds the Appendix A (see App. A) bands even when measurements clamp at the bucket ceiling.
- CP metrics expose `cp.ledger_status ∈ {Fresh, Cached, Stale}` and `cp.cache_age_ms` so leaders can explain Strict fallbacks.
- Operators running ≥2,000 partitions per node SHOULD enable the optional aggregation layer described in Appendix A (see App. A): per-partition histograms may be down-sampled to 0.2 Hz or aggregated into cohort-level histograms so long as the SLO guardrails in Appendix A (see App. A) continue to evaluate against the reconstructed percentiles. Implementations MUST expose the sampling rate via `metrics.sample_rate` so observability tooling can rescale alerts.

### 13.1 Golden Signals & Incident Logging
- Alerts from Appendix A (see App. A) feed correlated incident logs once breached for `alerts.incident_correlation_window = 120 s`. Incidents bundle durability mode, credit levels, leader term, recent admin actions, and remediation hints. Cooldown: `alerts.incident_emit_cooldown_ms = 300000`; storm guard caps incidents at 5 per 10 min, but `SafetyCritical` classes (durability regression, key epoch lag, fence mismatch) bypass the cap so cascading failures still surface immediately.
- Audit logs are signed JSON batches (Ed25519) with 400-day retention; AEAD AAD = `{cluster_id, cp_epoch, wall_clock_bucket}`.
- Metrics cardinality guardrails cap active `partition_id` series at 2048 per node; high-cardinality labels sample at `metrics.high_cardinality_sample_rate = 0.1`. Evictions emit `metrics_cardinality_dropped`.

### 13.2 Startup Spec Self-Tests
- Before a partition advertises readiness (and again after every binary upgrade), the node MUST execute `spec_self_test` while still in bootstrap: the procedure recalculates the local `wire_catalog.json`, `chunked_list_schema.json`, and wide-int catalog from the shipping code, compares them byte-for-byte with the artifacts generated at build time (§0.3), and refuses to mount the partition if any diff is observed.
- The same self-test replays the canonical `PreVoteResponse`, `ChunkedList`, and JSON fixtures from Appendix C (see App. C) plus the snapshot-manifest and segment-MAC vectors (§7.1, §4.1). Failures raise `SpecSelfTestFailed{fixture}` telemetry, mark the node Quarantined, and require an operator override to proceed.
- Nodes persist the most recent `spec_self_test` result (timestamp, git hash, fixture version) in `boot_record.json` and emit `clustor.spec.self_test_duration_ms`/`clustor.spec.self_test_fail_total` metrics so fleet automation can confirm the checks ran on every restart. CI MUST reject releases whose binaries omit the self-test hook.

---

## 14  Deployment & Bootstrap

### 14.1 Bootstrap & Disk Hygiene
1. Start CP-Raft (3 or 5 nodes) and load tenant/partition manifests.
2. Launch data-plane nodes referencing CP-Raft endpoints; bootstrap refuses unassigned partitions or stale disks.
3. Nodes run startup scrub (§5.3) before joining quorum.
- Disk policy verification (blocking, per §1.2.1 table):
  - Read `/proc/mounts` and `/sys/block/<dev>/queue/write_cache` to ensure the cache mode matches the table (write through or write back with FUA). Violations raise `DiskPolicyViolation{reason=WriteCache}`.
  - Inspect `/sys/block/<dev>/queue/fua` and `/sys/block/<dev>/queue/flush` to confirm barrier support; failures quarantine the node even if mount options look correct.
  - Validate ext4 mounts use `data=ordered`, `commit<=5`, and keep `auto_da_alloc` enabled; warn (but do not block) when `journal_async_commit` is absent if latency SLOs require it. Reject XFS mounts that attempt to disable barriers even if the option is deprecated, and confirm ZFS datasets advertise `sync=always` + `logbias=throughput`.
  - For dm-crypt/mdraid stacks, validate the effective `/sys/block/<stacked>/queue/*` flags as well as the underlying physical devices; mismatches between layers trigger `DiskPolicyViolation{reason=StackedDeviceInconclusive}` until operators provide an explicit allow-list. The allow-list is a CP-Raft object (`disk_override`) that records the exact device paths, attested `queue/*` capabilities, author, TTL, and ticket; nodes remain quarantined until such an entry exists and matches the observed topology.
  - Reconcile detected filesystem UUIDs with prior boot records to ensure disks were not hot-swapped without operator intent.
  - CI environments that rely on loopback devices or ephemeral cloud volumes MUST register an explicit `disk_override` describing the synthetic topology (including TTL) before tests run; otherwise bootstrap halts to avoid silently accepting lossy backing stores.

### 14.2 Graceful Shutdown
- Prefer `TransferLeader`, wait `commit_quiescence_ms = 200`, ensure `apply_queue_depth < 10%`, flush WAL/checkpoints, then stop listeners. Force shutdown after `graceful_shutdown_timeout_ms = 10000` with telemetry explaining the reason.

### 14.3 Kubernetes & Host Guidance
- Run as StatefulSets with PDB `maxUnavailable=1`, anti-affinity (≤1 voter per node/zone). In single-AZ clusters this degenerates to “one voter per node” while still using topologySpreadConstraints for rack/zonal labels so the requirement remains meaningful. Pods expose `/state` with read-write volume; other paths read-only.
- Set `terminationGracePeriodSeconds ≥ graceful_shutdown_timeout_ms` (10 s default) so `TransferLeader` + WAL flush finish before the kubelet SIGKILLs the pod; shorter windows are rejected by admission webhooks.
- Require cgroup v2 with `io.max`, Linux ≥5.15 with `io_uring`, and dedicated storage (NVMe preferred). Unsupported mounts (no barriers, unsafe write cache, missing `sync=always` on ZFS) are rejected during bootstrap.
- Sidecars (snapshot service, log shipper) run with least privilege; pods needing encrypted WALs require `CAP_IPC_LOCK` to pin keys.

### 14.4 Configuration Profiles
Profiles are declarative bundles that gate hard limits and defaults (details in Appendix B (see App. B)). Validators reject configs exceeding profile bounds; feature gates must be homogeneous per voter set.

### 14.5 Repair-Mode Bootstrap
- `bootstrap.repair_mode=true` mounts partitions read-only, runs scrub, and blocks quorum participation.
- Operators can download/upload snapshots for offline repair.
- `AdminResumePartition` (Break-Glass) remounts read-write, forces snapshot import to refresh dedupe state, clears quarantine, and rejoins quorum.

---

## 15  Summary of Guarantees
| Area | Guarantee |
| --- | --- |
| Ordering | Raft total order per partition enforced by §0/§2 invariants. |
| Durability | Strict or Group-Fsync with `DurabilityTransition` fencing and automatic downgrade. |
| Recovery | Crash-safe WAL replay + scrub reports + boot records. |
| Control Plane | CP-Raft manages placements, durability ledger, DR fences, and feature gates. |
| Extensibility | Codec hooks, apply callbacks, snapshot plugins with mandatory tracing metadata. |
| Observability | Golden signals, Explain APIs, signed audits, throttle envelopes. |
| Security | AEAD everywhere, SPIFFE/mTLS, RBAC with break-glass audit. |
| Read Availability | Linearizable reads depend on CP proofs; during CP outages only Strict-mode writes and snapshot-style reads continue (§2.3). |
| Operations | Documented runbooks, dry-run tooling, Kubernetes-ready defaults. |

---

## Appendix A Appendix A (see App. A) – SLOs & Alerts
| Signal | Target | Alert Threshold | Notes |
| --- | --- | --- | --- |
| `clustor.raft.commit_latency_ms` (p99) | ≤15 ms | ≥25 ms for 2 min | Drives `commit_latency_breach`. |
| `clustor.wal.fsync_latency_ms` (p99) | ≤10 ms | ≥20 ms for 3 batches | Forces Strict downgrade. |
| `clustor.flow.zero_credit_duration_ms` | 0 | ≥500 ms | Triggers throttle envelopes. |
| `clustor.snapshot.staleness_seconds` | ≤120 | ≥300 | Signals snapshot backlog. |
| `clustor.cp.epoch_drift` | 0 | >0 | Indicates CP/Data desync. |
| `clustor.security.key_epoch_lag` | 0 | >1 epoch | Blocks new leaders. |
| `clustor.raft.commit_visibility_gap_ms` | 0 | >0 for `alerts.commit_visibility_gap_ms=5000` | Warns reads running ahead of durability. |
| `clustor.cp.ledger_status` | `Fresh` | `Stale` for >`cp.cache_grace_ms` | Forces Strict fallback. |

Default `alerts.commit_visibility_gap_ms` values: Latency/CP = 0 (alert immediately), Throughput = 5000 ms, WAN = 10000 ms. Profiles that deviate MUST document the new bound in their runbooks.

---

## Appendix B Appendix B (see App. B) – Operational Profiles (Highlights)
| Profile | Defaults | Hard Limits |
| --- | --- | --- |
| Latency / CP | Strict durability, `target_latency_ms=10`, `target_backlog_entries=128`, `lease_gap_max=0`, Merkle enabled, observers disallowed. | Rejects `batch_bytes > 64 KiB` or `sample_period_ms > 100`; leases disabled; `apply.max_batch_ns` hard ceiling 2 ms; `ack_handle.max_defer_ms` hard ceiling 250 ms. |
| Throughput | Group-Fsync on, `target_latency_ms=40`, `target_backlog_entries=1024`, `lease_gap_max=1024`, Merkle optional (off by default), `CommitAllowsPreDurable` gate available. | `group_fsync.max_inflight_bytes_per_partition ≤ 8 MiB`; observers optional (default off); `apply.max_batch_ns` ceiling 4 ms; `ack_handle.max_defer_ms` ceiling 400 ms. |
| WAN | Election timeout `[300,600]`, `pre_vote.max_rtt_ms=500`, lease reads disabled by default, delta snapshots gated. | Requires healthy PTP/GPS; `clock_skew_bound_ms ≤ 50`; `apply.max_batch_ns` ceiling 5 ms; `ack_handle.max_defer_ms` ceiling 500 ms. |
| ZFS | `wal.segment_bytes ≥ 2 GiB`, `durability.max_device_latency_ms=40`, Merkle mandatory. | Requires `sync=always`; Group-Fsync disabled unless devices prove <20 ms fsync.

Profile layer controls optional integrity features (`segment.merkle_tree`) and hash suites. Only Throughput/WAN may enable `integrity.hash_suite=blake3` once all replicas agree.

---

## Appendix C Appendix C (see App. C) – Test Matrix (Representative)
Normative JSON string fields (servers MUST emit them as base-10 strings; clients MUST accept strings and MAY accept numerics for backwards compatibility): `$.ack_term`, `$.ack_index`, `$.append.decisions[*].index`, `$.durability_mode_epoch`, `$.routing_epoch`, `$.wal_committed_index`, `$.raft_commit_index`, `$.sm_durable_index`, `$.quorum_applied_index`, `$.last_quorum_fsynced_index`, `$.ledger.last_durable_index`, any `$.snapshot.*.version_id`, every `$.segment_seq`, and all `clustor.*` histogram bucket boundaries and `*_bytes`/`*_entries` counters surfaced via Explain/Admin APIs. This appendix is the sole authoritative catalog; §0.3 defers to it and spec-lint (`json_wide_int_catalog_test`) fails if generators or docs drift. New wide-int fields MUST update this list before landing code. CI emits the same material in a machine-readable bundle (`spec_fixtures.bundle.json` + signature) so downstream generators can diff artifacts without scraping prose.

`json_numeric_exception_list` (the only integers that MAY remain numeric in JSON because they are enums or constrained IDs) is frozen as follows:

| JSONPath | Rationale |
| --- | --- |
| `$.error_code` | Matches the wire-level numeric registry so tooling can compare IDs without string parsing. |
| `$.throttle.reason_id` (when present alongside the string `reason`) | Optional numeric mirror for histogram bucketing; never exceeds `u8`. |
| `$.wire_enum_id` fields emitted by Explain/Why* payloads | Mirrors the numeric discriminant already sent on the binary transport. |

A proposal to add a new exception MUST update this table, the machine-readable bundle, and spec-lint’s `json_numeric_exception_test`.
| Scenario | Coverage | Acceptance | Quarantine expectation |
| --- | --- | --- | --- |
| Deterministic Raft simulator | Membership changes, durability transitions, ReadIndex vs lease reads | No invariant violations; divergence <1 entry. | No |
| Fault injection harness | I/O delays, EINTR/EIO, partial writes | Strict downgrade within 2 batches; zero acknowledged loss. | No |
| Model checking (TLA+/Loom) | Log matching, fencing, lease inequality | Proofs required for 3/5-node configs per release. | N/A (formal proof only) |
| Jepsen-style suites | (a) Partition + clock skew during joint consensus (b) Tail corruption (c) DR failover w/ stale fence (d) Leader transfer + SYN storm (e) Compaction vs slow learner (f) Snapshot delta exhaustion | (a) Safe rollback (b) Quarantine within 5 min (c) Followers refuse mismatched fence (d) No dual leaders beyond lease bound (e) Learner protected (f) Forces full snapshot). | Case (b) explicitly quarantines; others remain Healthy |
| Frame fuzzing + allocator alignment fuzz | Codec limits, truncated frames, misaligned buffers | No panics; rejects malformed frames; alignment path only when needed. | No |
| Crash-consistency harness | Kill points at `pwrite`, `fdatasync`, dir `fsync` | Startup scrub always recovers last committed index. | No |
| Out-of-order persistence probe | Followers forced to fsync `wal/durability.log` before WAL bytes land (buggy layered stack simulation) | Replica detects unreadable entries, refuses to append `DurabilityRecord`, and enters Quarantine if the mismatch persists. | Conditional (Quarantine only if unreadable bytes persist) |
| Power-loss mid-block | Kill between `NonceReservation` flush and WAL block completion | No nonce reuse; AEAD rejects partial tail; partition quarantines until scrub + rewrite succeed. | Yes |
| Crypto drift tests | Epoch skew >1, nonce reuse attempts | Nodes quarantine; `(key, nonce)` never reused. | Yes |
| Group-Fsync durability | Crash combinations of leader/follower ack timing | `wal_committed_index` monotone; no acknowledged loss; transitions fenced. | No |
| Blocking follower downgrade | Followers stuck in `io_writer_mode=Blocking` while leader stays `RegisteredUring` | Group-Fsync automatically disabled; throughput drops gracefully (<40% regression) without violating ACK contract. | No |
| Background replay gating | Cold restart while serving writes | Writes admit only after replay; reads blocked until `applied_index >= raft_commit_index`. | No |
| JSON & ChunkedList conformance | Wide integers serialized as decimal strings; the normative JSONPath list (Appendix C (see App. C)) MUST always emit strings; the auto-generated “wide-int catalog” golden file is diffed in CI; `entries_crc32c`/`offsets_crc32c` strings left-pad to 32 hex nibbles (case-insensitive read) and match the worked example packing; ChunkedList reassembly enforces size caps, overlap/gap detection, out-of-order delivery, total_count=0, `chunk_crc32c` rules, and rejects `has_crc=0` whenever the catalog marks the field as order-significant. | Tests inject values ≥`2^63`, verify servers still emit strings when the value < `2^53`, reject shorter/longer hex strings and case-flipped mismatches, ensure receivers reject overlapping chunks, missing CRCs, illegal `has_crc=0` usages, or zero-count lists with stray chunks, and fail fast if §0.3 drifts from the golden catalog (or if the server emits a numeric wide int, which now returns `WireWideIntNotString`). | No |
| Snapshot bandwidth hysteresis | Throttle/resume near NIC limits | Hysteresis respected (90%/60%). | No |
| CP-outage snapshot import | CP offline beyond grace | Deltas fail with `snapshot_delta_invalidated`; full snapshots succeed while trust caches valid. | No |
| Re-encryption vs compaction | Concurrent operations | `rewrite_inflight` prevents deletion; no data loss. | No |
| Metrics + incident plumbing | Golden signals, throttle envelopes | Alerts feed incidents with dedup + storm guard. | No |
| Performance baselines | Strict ≥50k appends/s @ p99 ≤12 ms; Group-Fsync ≥120k @ p99 ≤20 ms (reference HW) | Regressions >10% block releases unless waived. | No |
| Key-epoch rollback | `{kek_version, dek_epoch, integrity_mac_epoch}` replay attempts | Nodes reject any proof/log entry whose epochs regress; emits `KeyEpochReplay` and enters Strict fallback. | No (remains in Strict fallback) |

Reference HW = dual-socket x86, PCIe Gen4 NVMe, Linux ≥5.15 with `io_uring`. Profiles running on different storage or after `io_writer_mode` downgrades should treat the numbers as directional only; publish their own baselines before enforcing Appendix A (see App. A) SLOs.

### Binary Schema & `has_*` Pattern Vectors
§0.3’s encoding contract is enforced via deterministic fixtures. The length-prefixed format is `LenPrefixedBytes(payload) = <u32 little-endian byte_len> || payload`. Optional tail fields always use a leading `u8 has_field` byte (0 = absent, 1 = present) immediately before the optional value; older parsers can therefore skip the value when `has_field=0` or when the bytes are truncated. Spec-lint replays the following hex vectors and refuses releases that drift:

| Vector | Bytes (hex, little-endian) | Notes |
| --- | --- | --- |
| `LenPrefixedString("OK")` | `020000004f4b` | Demonstrates 32-bit length prefix and tight packing. |
| `PreVoteResponse{term=42, vote_granted=1, has_high_rtt=1, high_rtt=1}` | `2a00000000000000010101` | Total length 11 bytes (≥10 floor). |
| `PreVoteResponse{term=42, vote_granted=0}` (legacy peers omitting `has_high_rtt`) | `2a0000000000000000` | 9-byte legacy floor; receivers MUST treat missing bytes as `has_high_rtt=0`. |

Vendors MAY add their own fixtures but MUST keep the §0.3 vectors byte-identical; CI compares hex dumps verbatim.

### Ledger Replay Pseudocode (§5.5-LR)
The deterministic truncation rule is expressed as reference pseudocode so every implementation rebuilds proofs identically:
```
fn replay_durability_log(log_path, wal_index) -> ReplayResult {
    let last_good_offset = 0
    let last_good_record = None
    for record in read_records_in_order(log_path) {
        if !record.verify_crc() { break }
        if !wal_index.contains(record.term, record.index, record.segment_seq) {
            break  // hole or corruption; stop immediately
        }
        enforce_step_order(record)  // §5.5-(1)…(5b)
        last_good_offset = record.file_end_offset
        last_good_record = record
    }
    truncate_file_to(last_good_offset)
    fdatasync(log_path)
    return ReplayResult {
        proof: last_good_record,
        strict_fallback: last_good_record.is_none(),
        truncated_bytes: file_size_before - last_good_offset
    }
}
```
Every implementation MUST (1) stop scanning on the first failed CRC/MAC, (2) truncate the log to the last verified record (never “skip ahead”), (3) zeroize unreadable tails before replaying WAL bytes, and (4) enter Quarantine + `strict_fallback_state=LocalOnly` until CP mirrors a proof ≥ the last good record. Spec-lint runs this pseudocode against synthetic logs (good, corrupt, reordered, and missing `NonceReservationRange`) to prove identical truncation behavior.

### Strict Fallback Gate Truth Table
The normative table now lives in §0.5 so Safety-Kernel updates require an explicit diff. This appendix references §0.5 for tooling but continues to house telemetry fields and conformance fixtures.

### Strict Fallback Telemetry Fields
The following metric/trace fields are normative and frozen for interoperability dashboards and tests:

| Field | Meaning |
| --- | --- |
| `strict_fallback_state` | Enum `Healthy|LocalOnly|ProofPublished` exported per partition. |
| `strict_fallback_gate_blocked{operation}` | Counter labeled by `operation` (e.g., `DurabilityTransitionToGroup`, `LeaseEnable`, `FollowerCapabilityGrant`, `SnapshotDeltaEnable`) incremented every time §2.1.1 rejects the call. |
| `strict_fallback_blocking_read_index` | Boolean gauge indicating whether ReadIndex is currently suppressed. |
| `strict_fallback_last_local_proof` | Last `(term,index)` from the local ledger that justified the current state; emitted as two wide integers listed in Appendix C (see App. C)’s JSON catalog. |
| `strict_fallback_pending_entries` | Count of appends accepted since entering strict fallback but not yet covered by a CP proof. |

Explain/Why* APIs MUST surface these exact field names (or their JSON equivalents) so tooling can rely on them without additional schema negotiation.

### Clause-to-Fixture Map
To cut cross-referencing overhead, the table below lists representative clauses and the conformance fixture (from `spec_fixtures.bundle.json`) that enforces them:

| Clause | Fixture ID | Notes |
| --- | --- | --- |
| §0.3 PreVoteResponse layout | `wire.prevote_response_v1` | Hex dump verifies the 10-byte mandatory floor and optional tail byte. |
| §2.3 ReadIndex proof equality | `consistency.read_index_proof_match` | Simulator asserts byte-for-byte equality between cached CP proof and `wal/durability.log`. |
| §5.5 Ledger replay truncation | `durability.ledger_replay_strict` | Synthetic log with mid-file corruption; harness ensures truncation stops at the last good record. |
| §8.2 Segment MAC derivation | `integrity.segment_mac_v1` | Matches the worked example MAC bytes and rejects byte-order drift. |

Spec-lint fails the build if any clause loses its fixture mapping or if a fixture claims coverage for a clause not listed here.

### Snapshot Manifest & Segment-MAC Test Fixtures
- **Manifest canonical bytes:**  
  `{"base_index":4096,"base_term":7,"chunks":[{"chunk_id":"00000000-0000-0000-0000-000000000001","digest":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","len":1048576,"offset":0}],"content_hash":"0xb1caf4297447b97c418f5c52ac1b922c3c32022f61d59f73c462931b89d6ad86","emit_version":1,"encryption":{"dek_epoch":3,"iv_salt":"0x000102030405060708090a0b0c0d0e0f"},"logical_markers":[],"manifest_id":"018c0d6c-9c11-7e9d-8000-86f5bb8c0001","producer_version":"clustor-test","version_id":12}`  
  Removing the `content_hash` and `signature` fields before hashing yields `content_hash = 0xb1caf4297447b97c418f5c52ac1b922c3c32022f61d59f73c462931b89d6ad86`. Signing the canonical string above with the Ed25519 private key whose public half is `MCowBQYDK2VwAyEArsd58cxPIL53CzjGSfRe7x3whwv0yhjWEXS2rSTAqAI=` produces signature `0xe655924767bf28bca3ff9e59ad0fde247564fbd4aac11d9e98adcd56bf69b747b7ea6215046978369f29dc80760b708a34c365c94f6a50122f7e35293caaed01`. Implementations MUST verify both the hash and the signature before importing manifests.
- **Segment MAC vector:** using MAC key bytes `00 01 … 1f`, `segment_seq=7`, `first_index=42`, `last_index=121`, `entry_count=17`, `entries_crc32c=0x1032547698badcfe67452301efcdab89`, and `offsets_crc32c=0x0123456789abcdeffedcba9876543210` MUST yield `mac = 5c50cc7f43ef3c0127db59a3a8394ed16782e7997b53093c35bff32f8644b8f0`. Tooling SHOULD treat this as a self-test.

### Read Semantics Proof Artifacts
The “Model checking (TLA+/Loom)” row now requires explicit artifacts for the read-path gate: every release MUST ship (a) a TLA+ fragment that models `strict_fallback_state`, ReadIndex blocking, and `CpUnavailable` propagation, and (b) a Loom/Jepsen scenario that demonstrates the truth-table transitions above (writes admitted, reads blocked, follower capability revoked) under CP outage. CI fails unless both artifacts cover the current parameter set referenced in §§2.1.1 and 2.3, preventing future drafts from drifting from the documented behavior.

### Lease Inequality Fixture (FutureGate)
Although leases remain disabled in v0.1, conformance tooling already exercises the inequality from §2.3. The canonical vector below MUST be replayed verbatim; implementations that change any operand MUST update the table and spec-lint simultaneously.

| Profile | `min_election_timeout_ms` | `clock_skew_bound_ms` | `lease_rtt_margin_ms` | `heartbeat_period_ms` | `default_lease_duration_ms` | LHS Sum | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Latency / Base | 150 | 5 | 10 | 50 | 80 | 145 | `145 < 150` ✓ |
| Throughput | 150 | 10 | 10 | 50 | 75 | 145 | `145 < 150` ✓ |
| WAN (gate off) | 300 | 50 | 10 | 50 | 180 | 290 | `290 < 300` ✓ (documented but gate stays disabled) |

Spec-lint’s `lease_inequality_test` recomputes `lease_duration_ms + lease_rtt_margin_ms + clock_skew_bound_ms + heartbeat_period_ms` for each profile and fails if the sum is ≥ the declared `min_election_timeout_ms`.

### AEAD Tag Comparison Guidance
§0.1 and §5.3 already mandate constant-time AEAD verification; this appendix makes the requirement executable. All implementations MUST use the reference macros below (or byte-for-byte equivalents) when comparing authentication tags. The helpers are defined for 16-byte (GCM) and 32-byte (future suites) tags and are evaluated in spec-lint to ensure no early-exit paths remain:
```
fn ct_equal_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    // Convert to bool without branches.
    (diff == 0)
}

fn ct_equal_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    (diff == 0)
}
```
Guidelines:
- Tag verification MUST run before any plaintext influences state. Nodes should zeroize `a/b` buffers immediately after the comparison, regardless of outcome.
- Implementations MAY wrap hardware instructions (e.g., `vaes`/`vpclmulqdq`) but MUST retain a software fallback that is byte-identical to the macros above for conformance testing.
- Appendix C (see App. C) conformance now includes `aead_constant_time_test`, which feeds mismatching tags that share long identical prefixes to ensure runtimes never shortcut the comparison.

---

## Appendix D Appendix D (see App. D) – Wire Envelopes (Shared Schema)
Every envelope returns JSON/gRPC with `{schema_version, generated_at, partition_id, routing_epoch, durability_mode_epoch}`. Binary encodings follow §0.3 (little-endian lengths, `u8` enums); JSON surfaces enums as strings but accepts numeric IDs for forward compatibility. Receivers MUST ignore unknown optional fields and reject envelopes that omit required ones. All `Why*` payload names use PascalCase (e.g., `WhyNotLeader`, `WhySnapshotBlocked`) and the casing is normative for telemetry filters.
| Envelope | Status | Notes |
| --- | --- | --- |
| `RoutingEpochMismatch` | HTTP 409 / gRPC `FAILED_PRECONDITION` | Includes `{observed_epoch, expected_epoch, lease_epoch, durability_mode_epoch}`. |
| `ModeConflict` | HTTP 409 | Returned by `SetDurabilityMode` when stale. |
| `CpUnavailable` | HTTP 503 | `{observed_epoch, cache_age_ms, reason ∈ {CacheExpired, NeededForReadIndex}}`; admin-only except `NeededForReadIndex`, which surfaces on client reads. |
| `snapshot_full_invalidated` | HTTP 409 | Reasons: `{GraceWindowExpired, SchemaBump, EmitVersionChange, DekEpochRollover}`. |
| `snapshot_delta_invalidated` | HTTP 409 | Reasons: above plus `DeltaChainLength`. |
| `ThrottleEnvelope` | HTTP 429 / gRPC `RESOURCE_EXHAUSTED` | Payload per §9.3 (includes dual credit counters). |
| `Why*` payloads | HTTP 200 | `WhyNotLeader`, `WhyDiskBlocked`, `WhySnapshotBlocked`, etc. share schema header and MUST include `truncated_ids_count` (absent/0 when no truncation) whenever an ID list is shortened per §9.3; when truncated they MUST also include `continuation_token` so clients can resume from the exact lexicographic position. Lists are always sorted by their primary key before transmission. |
| `OverrideLedgerEntry` | HTTP 200 | `{override_id, reason, ticket_url?, expires_at}` for audits. |

### Break-Glass Scope Map
Scopes embedded in Break-Glass tokens (§11.3) are frozen as follows:

| Scope string | Authorized APIs |
| --- | --- |
| `DurabilityOverride` | `SetDurabilityMode`, `OverrideStrictOnlyBackpressure`, `AdminOverrideKeyEpoch` |
| `SurvivabilityOverride` | `flow.structural_override`, `DryRunMovePartition` force-execute, `MembershipChange` with override flag |
| `ThrottleOverride` | `OverrideCredit`, `flow.structural_hard_block`, `WhyCreditZero` override actions |
| `SnapshotOverride` | `SnapshotFullOverride`, `snapshot_full_invalidated` overrides, repair-mode resume |
| `QuarantineOverride` | `AdminResumePartition`, `AdminPausePartition` while quarantined, `OverrideStrictOnlyBackpressure` when reason=`Quarantine` |

Tokens that present an unknown scope or call an API outside the table MUST be rejected and logged as `BreakGlassScopeMismatch`.

---

## Appendix E Appendix E (see App. E) – ChunkedList Specification
1. **Framing (`ChunkedListFrame`)**  
   `total_count:u32, chunk_offset:u32, chunk_len:u16, chunk_flags:u8, items[chunk_len], [chunk_crc32c:u32 when chunk_flags.has_crc=1]`. `chunk_offset`/`chunk_len` are counted in elements, never bytes.
2. **Chunk flags**  
   Bit0 = `has_crc`. When set, senders append `chunk_crc32c:u32` over the serialized `items[]` payload and receivers MUST validate it (`WireChunkCrcMismatch` on failure). The CRC is CRC-32C (Castagnoli polynomial `0x1EDC6F41`) emitted little-endian so tooling can share the same implementation as WAL CRC32Cs. `has_crc=0` is permitted **only** for set-semantics fields whose elements are fixed-width POD scalars with a unique little-endian encoding (e.g., `u32` IDs). All order-sensitive fields and every set that encodes variable-width elements MUST keep `has_crc=1`. Receivers MUST reject order-sensitive fields that arrive with `has_crc=0` (`WireChunkMissingCrc`).
3. **Element serialization**  
   Items follow the host field’s binary encoding rules: fixed-width integers pack tightly; structs serialize fields in catalog order with no padding; strings/bytes emit a 32-bit length prefix followed by raw bytes. This canonical form prevents padding-based ambiguity and defines the CRC input.
4. **Size limits**  
   `chunk_len ≤ 1024`, serialized `items[] ≤ 64 KiB` pre-CRC, and `total_count ≤ 1,000,000`. Senders MUST split larger lists across multiple chunks. Receivers reject `total_count=0` when chunks exist and fail payloads where `∑ chunk_len > total_count`.
5. **Receiver obligations**  
   - Deduplicate by `chunk_offset` and reject overlaps/gaps (`WireChunkOverlap`).  
   - Enforce `∑ chunk_len == total_count`; abort reassembly when cumulative byte limits (`≤8 MiB`) or `chunk_reassembly_timeout_ms = 5000` expire (`WireChunkReassemblyAborted`).  
   - Emit `WireChunkMissing` when the stream terminates before all offsets arrive.  
   - Perform strict offset accounting even when CRCs are omitted (allowed cases only).
6. **Set semantics**  
   Fields explicitly labeled “set semantics” MUST enforce uniqueness by serialized-byte representation; duplicates trigger `WireChunkDuplicateItem`. JSON mirrors of set lists MUST sort elements lexicographically by their canonical key and use a single canonical stringification per element so clients can deterministically merge pages.
7. **Catalog usage**  
   Fields using `ChunkedList` (e.g., `MembershipChange.old_members[]`, `MembershipChange.new_members[]`, `MembershipRollback.failing_nodes[]`, `RoutingEpochMismatch.expected[]`, `Explain/Why*` enumerations that exceed `u16::MAX`) MUST cite this appendix so auditors know the framing contracts being enforced.

---

## Appendix P Appendix P (see App. P) – Parked (>0.1)
- Incremental snapshot policy (delta chains, ancestry validation, `snapshot.delta_chain_max = 2`, `snapshot.delta_gap_bytes = 128 MiB`).
- Leader leases (bounds documented in §2.3) remain disabled until soak coverage completes.
- `integrity.hash_suite = blake3` for segment leaves in Throughput/WAN profiles.
- PID auto-tuner for production clusters.
- Observers in Latency/CP profiles.

### Feature Manifest (FutureGates)
| Feature | Gate flag / CP object | Enablement predicate | Telemetry hook |
| --- | --- | --- | --- |
| Leader leases | `feature.leases` metadata knob + CP `LeaseEnable` gate | All voters advertise `lease_gap_max > 0`, CP cache `Fresh`, durability proof published | `lease_gate_runtime_state`, `leases_test_mode_active` |
| PID auto-tuner | `flow.pid_auto_tune` feature flag | Partition profile ∈ {Throughput,WAN}, `io_writer_mode=FixedUring`, CP override present | `flow.pid_auto_tune_state`, `flow.pid_auto_tune_last_profile` |
| Incremental snapshots | `snapshot.delta_chain_max > 0` + CP `SnapshotDeltaEnable` | Partition in Strict durability, follower capability granted, CP trust cache `Fresh` | `snapshot.delta_state`, `snapshot.delta_chain_len` |
| BLAKE3 Merkle leaves | `integrity.hash_suite=blake3` + `integrity_mac_epoch >= 2` | All replicas advertise suite support; key epochs synchronized; spec-self-test succeeded post-upgrade | `integrity.hash_suite_active`, `integrity_mac_epoch` |

The control plane persists the manifest so operators can audit why a feature remained disabled; data-plane binaries MUST refuse to enable a gate unless the table’s predicate succeeds.
