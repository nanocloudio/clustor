1. Title
Clustor Raft Consensus Core Technical Specification v0.1

2. Overview
- Clustor provides a Raft-based consensus library plus sidecar services that replicate ordered log entries within each partition with crash-consistent durability and security guardrails.
- Every replica participates in a crash-consistent write-ahead log (WAL) with configurable durability modes: Strict (per-append `fdatasync`) and Group-Fsync (batched `fdatasync` bounded by profile ceilings).
- A dedicated control plane (ControlPlaneRaft) stores placements, durability proofs, feature gates, DR fences, overrides, and readiness records used by all partitions.
- Linearizable reads satisfy the read-gate predicate (`commit_visibility=DurableOnly`, cache state Fresh/Cached, ControlPlaneRaft proof equality, and `wal_committed_index == raft_commit_index`); when any clause fails—such as Stale/Expired caches or strict fallback—leaders continue accepting writes in Strict mode while ReadIndex/lease requests fail closed.
- Snapshot import/export, flow control, telemetry, RBAC, and cryptographic requirements are integrated into the runtime so every deployment produces auditable behavior across profiles (ConsistencyProfile, Throughput, WAN, ZFS, Aggregator).

3. Scope
- Raft replication behavior, leader election, quorum handling, and observer semantics.
- WAL layout, entry encoding, durability ledger ordering, nonce reservation, compaction, and scrub.
- Apply pipeline contracts, ack handling, flow control, throttling, snapshots (full and incremental), and state-transfer requirements.
- ControlPlaneRaft contracts covering placements, caches, feature gates, overrides, barriers, and readiness.
- Wire encoding, message catalogs, error handling, telemetry, security (mTLS, AEAD, RBAC, break-glass), and compatibility/versioning expectations.
- Operational states such as strict fallback, quarantine, repair mode, and structural lag mitigation.

**Normative language and units:** This specification uses “MUST/SHALL”, “SHOULD”, and “MAY” in the RFC 2119 sense. Failing a MUST/SHALL requirement is a protocol violation. SHOULD clauses describe safety or interoperability guidance; deviating requires a documented justification and may affect SLO commitments. MAY clauses describe optional behavior. All numeric ceilings called out as profile parameters (e.g., `snapshot.delta_emit_period_ms`) are SLO defaults drawn from App.B; deployments MAY tighten them but MUST NOT exceed the hard bounds noted in App.B without a profile update. Unless explicitly stated otherwise, KiB/MiB/GiB units use binary powers (2^10, 2^20, 2^30 bytes respectively), and `_ms` suffixes denote milliseconds.

4. Non-Goals
- Product-specific state machines above `on_commit`/`on_applied`.
- Alternate consensus algorithms, eventual-consistency modes, or speculative leader extensions beyond the defined lease/read gates.
- New cryptographic primitives beyond AES-256-GCM, SHA-256/BLAKE3 hash suites (used for Merkle leaves and, when gated, IV derivation), and HMAC-SHA256 MAC trailers described herein.
- Fleet orchestration, CI tooling, or release workflow automation (captured separately as non-normative guidance).

5. Terminology and Concepts

5.1 Core Terms
| Term | Definition |
| --- | --- |
| `raft_commit_index` | Highest log index considered committed under Raft rules (replicated on a majority, with the leader only using entries from its current term to advance the index even though earlier entries become committed as a result); implied when `commit_index` is referenced. |
| `local_wal_durable_index` | Replica-local watermark equal to the last log index whose WAL bytes completed §10.5 step (2) and whose `DurabilityRecord` completed §10.5 step (4); step (2) means the bytes are already on stable storage regardless of Strict vs Group-Fsync batching. |
| `wal_committed_index` | Leader-only quorum durable watermark computed as the maximum index *m* such that (a) the leader’s `local_wal_durable_index ≥ m`, (b) at least quorum-size replicas (including the leader) have advertised `local_wal_durable_index ≥ m`, (c) the log entry at *m* has `term(m) == current_term`, and (d) `m ≤ raft_commit_index`. Followers never compute or approximate this value; they gate snapshot-only reads using `local_wal_durable_index` vs their defined `applied_index_floor`. |
| `sm_durable_index` | Product-visible watermark that side effects are durably materialized (non-normative for consensus, but surfaced for compaction/readiness decisions). |
| `quorum_applied_index` | Smallest `applied_index` among the most recent quorum heartbeat bundle; forms a compaction floor. |
| `applied_index_floor` | Follower-local watermark equal to `min(applied_index, snapshot_base_index)` persisted alongside snapshot authorization; follower snapshot-only reads require `local_wal_durable_index ≥ applied_index_floor`. |
| `commit_visibility` | `CommitVisibility::DurableOnly` or `CommitVisibility::CommitAllowsPreDurable`; controls whether reads may observe entries ahead of `wal_committed_index`. |
| `lease_gap_max` | Profile-specific bound on `(raft_commit_index - wal_committed_index)` while leases are enabled (0 disables leases); equality is already required for linearizable reads, so this guard functions as an additional telemetry clamp/alert when the gap deviates even temporarily. |
| `lease_epoch` | Monotone identifier carried on heartbeats; followers reject lease reads on epoch mismatch. |
| `routing_epoch` | Placement/reconfiguration version issued by ControlPlaneRaft. |
| `durability_mode` | Consensus mode `Strict` or `Group-Fsync`, fenced by `DurabilityTransition` entries. |
| `wal.fs_block_bytes` | WAL I/O alignment hint derived from the filesystem’s preferred block size (`st_blksize` from `fstat`) or an operator override; implementations align WAL writes/truncations to this quantum but may override it explicitly when the operator configures a safer value. |
| `wal.crypto_block_bytes` | Fixed AEAD block size (4096 bytes) used for nonce counters and reservations. |
| `ControlPlaneUnavailablePriorityOrder` | Rejection precedence `{CacheExpired, CacheNotFresh, NeededForReadIndex}` applied after clause evaluation when mapping read/lease gate failures to `ControlPlaneUnavailable`; cache expiry/staleness clauses map to the first two reasons, all other read-gate clauses map to `NeededForReadIndex`. Admin/control APIs MAY introduce additional reasons (e.g., `ModeConflict(strict_fallback)`) but MUST document deviations. |
| `CanonicalJson` | Unless otherwise noted, “canonical JSON” refers to RFC 8785 Canonical JSON (UTF-8, deterministic object member ordering, no insignificant whitespace); all signatures and `content_hash` calculations over JSON/JSONL payloads use this encoding after removing any explicitly excluded fields called out in §7/§9/§12. |
| `Clustor`, `Strict`, `Group-Fsync`, `DurabilityRecord`, `FollowerReadSnapshot`, `LeaseEnable`, `SnapshotDeltaEnable`, `ControlPlaneRaft`, `ConsistencyProfile` | Canonical runtime nouns whose casing must match telemetry and APIs. |

5.2 Profiles and Roles
- Profiles (ConsistencyProfile, Throughput, WAN, ZFS, Aggregator) define hard ceilings for durability batching, ack deferral, flow control, telemetry sampling, and feature availability.
- Roles include Leaders (serve writes and ReadIndex), Followers (replicate and expose snapshot-only reads once allowed), Learners (catch-up replicas), Observers (read-only/telemetry), and ControlPlaneRaft which governs placements and proofs.

6. System Model

6.1 Components
- **Data-plane nodes** host one or more Raft Partition Groups (RPGs). Each RPG maintains WAL segments, durability ledgers, apply pipelines, snapshot emitters/importers, flow controllers, and telemetry streams.
- **ControlPlaneRaft** is an independent Raft cluster storing routing epochs, durability proofs, feature manifests, overrides, DR fences, DefinitionBundle metadata, and readiness signals. Data-plane nodes rely on its caches as the source of truth for placement and durability policy.
- **Clients** interact with leaders via Raft RPCs or Admin APIs carrying `routing_epoch` plus durability/lease epochs.
- **Observers** receive read-only streams using dedicated bandwidth quotas (`0.1 × snapshot.max_bytes_per_sec` per partition) and do not participate in quorum.

6.2 Environment and Crash Model
- Nodes target Linux ≥5.15 with `io_uring`, PHC/PTP clock discipline, and storage configured with explicit write barriers (e.g., XFS/ext4 with barriers enabled, ZFS with `sync=always` and `logbias=throughput`).
- WAL segments are preallocated (≥1 GiB) and aligned to `wal.fs_block_bytes`. Strict mode issues `pwrite` + `fdatasync` per append; Group-Fsync batches operations under profile ceilings.
- Crash model assumes fail-stop nodes, power loss between any ordered step, and storage that may reorder writes unless a step explicitly orders/durably commits via `fdatasync` (or an equivalent barrier).

6.3 Assumptions
- A minimum of three voters per partition (five for DR profile) ensures quorum.
- ControlPlaneRaft outages may last up to `controlplane.cache_grace_ms` (300,000 ms default). While caches remain `Fresh`, nodes continue in their configured durability modes; `Cached` allows existing predicates to continue (with telemetry warnings) and does not itself force strict fallback or block ReadIndex/lease gates, though other clauses (e.g., proof mismatch/TTL expiry) may independently assert strict fallback even while the cache is merely Cached. Once caches age into `Stale` or `Expired`, nodes automatically clamp to Strict durability, revoke leases, pause incremental snapshots, and halve credits once `strict_only_runtime_ms` exceeds the profile’s backpressure bound.
- Observers and follower-read capabilities are gated on Strict durability, fresh proofs, and capability bits issued by ControlPlaneRaft.
- Fault model: consensus safety assumes crash-only (non-Byzantine) failures. Cryptographic signatures on telemetry and proofs provide auditability and tamper evidence but do not convert the system into a Byzantine-tolerant protocol; replicas that actively lie must be removed by operators.

7. Data Model

7.1 Entities
- **WAL Entry Frame**: `EntryFrameHeader{version:u8, codec:u8, flags:u16, body_len:u32, trailer_len:u32}` followed by body and `EntryFrameTrailer{crc32c:u32, [merkle_leaf_digest:32 bytes]}`. `trailer_len` MUST be either 4 (CRC-only) or 36 (CRC+Merkle). `EntryFrameTrailer.crc32c` covers the serialized header bytes concatenated with the frame body bytes (it excludes the trailer itself). Frame bodies ≤1 MiB (ConsistencyProfile) or ≤4 MiB (Throughput/WAN); these WAL-specific caps are independent of any RPC body caps described in §8.
- **Segment Trailer**: `segment_mac_trailer{version:u8, mac_suite_id:u8, segment_seq:u64, first_index:u64, last_index:u64, entry_count:u32, entries_crc32c_lanes_bytes[16], offsets_crc32c_lanes_bytes[16], mac:32 bytes}` using HMAC-SHA256 keyed per `integrity_mac_epoch`. Packed CRC lanes are derived deterministically: for every entry in physical WAL order, append the exact byte range used by that entry’s `EntryFrameTrailer.crc32c` calculation (serialized header bytes followed by body bytes, excluding the trailer) to a canonical byte stream with no separators or padding. Treat that stream as a sequence of 32-bit little-endian words, pad the tail with zero bytes (padding exists only for this CRC-lane computation and is not persisted elsewhere) if necessary so the length is a multiple of 4, distribute each word into lane `word_index mod 4`, compute CRC32C (Castagnoli) independently per lane, then emit four little-endian `u32` lane CRCs ordered lane0 → lane3. The packed field `entries_crc32c_lanes_bytes` therefore contains exactly 16 bytes. `offsets_crc32c_lanes_bytes` uses the .idx offsets serialized as contiguous 64-bit little-endian values (two 32-bit words each) with no separators; because each offset is 8 bytes (two words), the stream is inherently word-aligned and therefore needs no additional padding. The packed 16-byte field follows the same lane ordering. The segment MAC covers every trailer field except `mac` itself and therefore authenticates the serialized CRC-lane bytes verbatim.
- **Durability Ledger**: Append-only `DurabilityRecord{term, index, segment_seq, io_writer_mode, record_crc32c}` persisted beside the WAL. Additional record families include `NonceReservationRange{segment_seq, start_block_counter, reserved_blocks}`, `NonceReservationAbandon{segment_seq, abandon_reason}`, and `DurabilityTransition`.
- **DurabilityAck Attestation**: Followers return `DurabilityAck{partition_id, replica_id, last_fsynced_index, segment_seq, io_writer_mode}` only after `(a)` the WAL bytes for `last_fsynced_index` are durable via step (2) in §10.5, `(b)` the matching `DurabilityRecord` is appended to `wal/durability.log`, and `(c)` `fdatasync(wal/durability.log)` completes per §10.5 step (4). Leaders treat the tuple `{last_fsynced_index, segment_seq, io_writer_mode}` as a peer-authenticated statement (integrity provided by the mTLS channel and node identity in the crash-only fault model) proving the follower can regenerate the quorum proof after a crash; acknowledgements emitted before step (2) or step (4) completes are protocol violations and must be discarded. `io_writer_mode` is carried so leaders can fence Group-Fsync eligibility, not because it contributes to replay-proof durability. Because the model is crash-only, transport authentication suffices, but leaders MUST bind received tuples to the current term/stream context so stale tuples cannot help clear a read gate without a fresh ControlPlaneRaft proof.
- **Durability mode epoch**: `durability_mode_epoch:u32` is a monotone epoch stored in ControlPlaneRaft and mirrored into `DurabilityTransition` entries, envelopes, and telemetry. ControlPlaneRaft increments it every time a partition toggles Strict ↔ Group. Every Raft control message (AppendEntries/heartbeats, RequestVote/PreVote) carries the sender’s current epoch, and `DurabilityTransition` entries include the epoch fence. Nodes persist the current epoch alongside `wal/durability.log`; any message or ledger record that regresses the epoch must be rejected (`ModeConflict` returned on admin RPCs, Raft streams closed or answered with a `ModeConflict` envelope), and leaders only acknowledge a transition after the epoch and durability proof checkpoint are durably recorded.
- **Snapshot Manifest**: canonical JSON (per the `CanonicalJson` entry in §5.1) containing `{manifest_id, version_id, producer_version, emit_version, base_term, base_index, snapshot_kind, delta_parent_manifest_id?, delta_chain_length, content_hash, signature, encryption{dek_epoch, iv_salt}, chunks[], logical_markers[], ap_pane_digest, dedup_shards[], commit_epoch_vector[]}`. Incremental manifests set `snapshot_kind=Delta` and record parent information, and their `encryption{…}` fields use the snapshot-specific IV derivation in §12.2 (snapshots consume `iv_salt`; WAL IV derivation ignores this field). Computing `content_hash` or signature digests removes the top-level `content_hash` and `signature` fields first, then hashes/signs the canonical encoding of the remaining object. Every manifest is signed with the cluster’s `SnapshotManifestKey` (see §12.4) so verifiers can authenticate runtime exports.
- **Filesystem Layout**:
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
Implementations MAY add other tenant- or product-specific files under `/state/<partition>/…` so long as the layout above remains intact.
- **ControlPlaneRaft Objects**: Partition manifests, durability ledger entries, QuarantineCleared records, DefinitionBundles, ActivationBarriers, WarmupReadiness entries, Override ledger items, Feature manifest rows, DR fences, Key epochs, RBAC manifests.
- **Throttle Envelope Payload**: JSON envelope with reason, retry hints, backlog, credit levels, durability metadata, decision trace ID, credit hint, ingest/durability status codes, and sorted/truncated ID lists with continuation tokens.
- **ChunkedList Frame**: `ChunkedListFrame{total_count:u32, chunk_offset:u32, chunk_len:u16, chunk_flags:u8, items[], [chunk_crc32c:u32 when has_crc=1]}`. `chunk_len ≤ 1024`, serialized payload ≤64 KiB, reassembly cap 8 MiB, `total_count ≤ 1,000,000`.

7.2 Invariants
- **Raft**: Log matching, leader completeness, and monotone `raft_commit_index` hold for every replica. `raft_commit_index` itself follows the Raft current-term rule (only entries from the current term may become committed in the current term). `wal_committed_index ≤ raft_commit_index` always; equality is enforced whenever `commit_visibility=DurableOnly`.
- **Durability**: Client ACKs occur only after `(a)` leader persistence, `(b)` quorum `DurabilityAck` evidence, `(c)` ledger append + `fdatasync`, and `(d)` `wal_committed_index` advance. `DurabilityTransition` entries fence every Strict↔Group change; no batch may span a fence.
- **Read Safety**: Linearizable reads require `strict_fallback=false`, `commit_visibility=DurableOnly`, cache freshness, proof equality (the `DurabilityProofTupleV1` subset `{last_durable_term, last_durable_index, segment_seq, io_writer_mode, durability_mode_epoch}` matching the leader’s last quorum-fsynced tuple), and `wal_committed_index == raft_commit_index`.
- **Snapshots**: Full and incremental snapshots must use signed manifests, AEAD-authenticated chunks, digest verification prior to apply, and profile-bound cadence controls (`snapshot.delta_emit_period_ms_hard_profile`, `snapshot.full_emit_period_ms_hard_profile`, `snapshot.delta_chain_max_profile`). Implementations SHOULD meet the App.B SLO targets (`snapshot.delta_emit_period_ms_target ≤ 10,000`, `snapshot.full_emit_period_ms_target ≤ 30,000`), but hard rejection occurs only when the operator or profile hard bounds are exceeded without progress.
- **Nonce Reuse**: `(segment_seq, block_counter)` pairs are globally unique. Reservations are contiguous, bounded (≤`nonce.reservation_max_blocks_profile`), proactively flushed (writers attempt to persist after ≤5 ms of inactivity and whenever windows fill as an optimization) yet MUST still be durably recorded before any ciphertext uses the counters, and are abandoned explicitly before compaction.
- **Startup Scrub**: Nodes authenticate AEAD tags in constant time, zeroize buffers on failure, verify MACs, CRC/Merkle, and ledger ordering before taking action. No plaintext influences state before authentication completes.
- **Quarantine**: AEAD or MAC failures, repeated fatal apply outcomes, nonce reuse suspicion, integrity policy violations, or admin pause force Quarantine. Exiting requires snapshot/WAL rebuild plus ControlPlaneRaft acknowledgement.

7.3 Snapshot and Ledger Metadata
- Snapshot authorization requires manifest `fsync`, re-list (stat + checksum), `SnapshotAuthorizationRecord{manifest_id, base_index, auth_seq, manifest_hash}`, and `CompactionAuthAck{manifest_id, auth_seq}` with hash chaining.
- `boot_record.json` captures scrub outcome, durability watermark, WAL geometry, `io_writer_mode`, and spec self-test metadata for audit; readiness surfaces same data.

8. Interfaces and Wire Format

8.1 Encoding Rules
- Wire RPC/envelope frames use little-endian fixed-width integers and 32-bit length prefixes for slices/strings. Clustor raw TCP envelopes and other non-gRPC frames always begin with a 32-bit little-endian length prefix that counts only the body bytes; receivers MUST raise `WireBodyTooShort` whenever fewer body bytes arrive than promised. gRPC payloads retain their native 5-byte header framing on HTTP/2, so implementations rely on the runtime for that layer. Body caps: 4 MiB for Raft/admin RPCs, 32 KiB for Explain/Throttle/Why* envelopes, and these Explain/Throttle caps remain in force even when `WireExtension::WideFrame` is negotiated. WAL entry frames follow §7.1 and already carry `body_len`/`trailer_len` inside the `EntryFrameHeader`.
- Enumerated fields are encoded as a single `u8` discriminant; once assigned, discriminant values are stable for that enum. Additive enum variants allocate a fresh discriminant at the tail, and receivers MUST reject unknown enum discriminants as `WireUnknownField` even when they appear inside optional/tail structures—forward-compat tails are opaque byte ranges appended after all known fields and MUST NOT contain enums or other mandatory semantics, so new required fields demand either a schema-version bump or a new message ID rather than a tail extension.
- Optional fields use `u8 has_field` followed by the value. Receivers may skip unknown trailing bytes only when both peers have negotiated `WireExtension::ForwardCompat` and the surrounding framing (message ID, schema header, and body_len) is recognized; mandatory fields (including enums) that are unknown still trigger `WireUnknownField`, even if they reside inside a region that would otherwise be skippable, and unnegotiated trailing bytes are reported under the same error.
- Frames shorter than the mandatory minimum bytes are rejected as `WireBodyTooShort`; frames exceeding caps are rejected as `WireBodyTooLarge`. Streaming parsers enforce rolling-window buffers for payloads >64 KiB.
- Experimental enum range `0xF0–0xFF` is reserved; production builds reject messages that use it.
- Chunked lists follow Appendix E framing with strict CRC enforcement when `has_crc=1` (absence of the CRC when `has_crc=0` is permitted but integrity then relies on the transport) and deduplication by `chunk_offset`. JSON mirrors sort entries lexicographically and include continuation tokens when truncating.

8.2 Message Catalog
- System log entries: `MembershipChange (0x01)`, `MembershipRollback (0x02)`, `DurabilityTransition (0x03)`, `FenceCommit (0x04)`, `DefineActivate (0x05)`.
- Messages: `DurabilityAck{partition_id, replica_id, last_fsynced_index, segment_seq, io_writer_mode}`, `PreVoteResponse{term:u64, vote_granted:u8, [has_high_rtt:u8, high_rtt:u8]}`. v0.1+ senders append `has_high_rtt` and the optional `high_rtt` flag as a tail extension; legacy peers send only `term` and `vote_granted`. Receivers treat the absence of the extension as `has_high_rtt=0` and MAY ignore additional tail bytes beyond the defined extension only when the peers have negotiated `WireExtension::ForwardCompat` and `body_len` allows skipping; skipped tails are opaque blobs appended after all known fields (they MUST NOT contain mandatory enums or semantics, and `high_rtt` is a single boolean byte, not an enum discriminant), and absent negotiation any unknown tail bytes trigger `WireUnknownField`.
- Envelopes: `RoutingEpochMismatch`, `ModeConflict`, `ThrottleEnvelope`, `ControlPlaneUnavailable`, `snapshot_full_invalidated`, `snapshot_delta_invalidated`, `Why*` payloads, `OverrideLedgerEntry`. Each includes `{schema_version, generated_at, partition_id, routing_epoch, durability_mode_epoch}` plus reason-specific fields. Lists carry `truncated_ids_count` and `continuation_token` when truncated.
- Control-plane readiness surfaces `/readyz` with `{definition_bundle_id, activation_barrier_id, shadow_apply_state, shadow_apply_checkpoint_index, warmup_ready_ratio, partition_ready_ratio, feature.<name>_gate_state, feature.<name>_predicate_digest, readiness_digest}`.
- Nodes MUST expose `GET /.well-known/wide-int-registry` returning the canonical JSON listing of fields encoded as decimal strings (including all `*_ms`, timestamps, counters, CRC hex strings). JSON outputs accept numeric enums but emit enum strings.

8.3 Handshake and Negotiation
- Peers exchange `wire.catalog_version={major:u8, minor:u8}` plus negotiated `wire.max_body_len` during the Raft handshake. Optional extension fields ride in the same handshake envelope; when a node advertises `WireExtension::ForwardCompat (0x20)` it MUST include `forward_parse_max_minor:u8` alongside the extension bitmask (typically set to `minor+1`). Both sides must enforce `(remote_minor ≤ local_forward_parse_max_minor)` and `(local_minor ≤ remote_forward_parse_max_minor)` whenever either side advertises ForwardCompat. Violations close the transport before log traffic.
- `WireExtension::WideFrame (0x10)` reserves larger frame caps (up to 32 MiB) once both peers advertise it; until then, senders must keep RPCs ≤4 MiB, and even after negotiation Explain/Throttle/Why* envelopes remain capped at 32 KiB per §8.1. `WireExtension::WideCount (0x11)` allows `u32` element counts for fields explicitly marked “wide count capable” only when both peers support it; otherwise counts remain `u16` with chunking.
- Unknown extensions require explicit negotiation; peers reject opportunistic usage with `WireCatalogMismatch`.

8.4 Error Codes
| Range | Codes |
| --- | --- |
| `1000–1089` | Main wire errors (`WireBodyTooShort=1001`, `WireBodyTooLarge=1002`, `WireUnknownField=1003`, `WireChunkMissing=1004`, `WireChunkOverlap=1005`, `WireChunkMissingCrc=1006`, `WireChunkCrcMismatch=1007`, `WireChunkDuplicateItem=1008`, `WireChunkReassemblyAborted=1009`, `WireCatalogMismatch=1010`). |
| `1090–1099` | Vendor-specific extensions; production deployments must relinquish IDs if Clustor later assigns them. |
| `1100–1199` | Reserved for future Clustor wire-level errors. |

9. State and Lifecycle

9.1 Strict Fallback and Read Gate
- `strict_fallback=true` whenever either (a) the ControlPlaneRaft cache is `Stale` or `Expired` or (b) the leader lacks a ControlPlaneRaft-published `DurabilityProofTupleV1` whose equality subset matches the leader’s last quorum-fsynced tuple (and therefore proves the current-term durable watermark). This latch gates read/lease capability and forces the leader’s local I/O into Strict mode without appending a new durability or `commit_visibility` transition; instead, the leader must behave as though `commit_visibility=DurableOnly` until the latch clears even if the configured mode differed. While set, leaders must:
  - Reject Group-Fsync enablement (`DurabilityTransition{to=Group}`), leases, follower-read capabilities, incremental snapshot enablement, observer admission, and any admin overrides attempting to bypass the gate.
  - Clamp read exposure by serving only the DurableOnly semantics (leaders MUST NOT enable or continue serving `CommitAllowsPreDurable` while strict fallback holds) and disable `lease_gap_max`.
  - Continue accepting writes strictly (each append increments `strict_fallback_pending_entries`) but block ReadIndex and lease reads with `ControlPlaneUnavailable{reason=NeededForReadIndex}`.
- Followers continue honoring whatever `DurabilityTransition` entries already exist in the log; clamping to Strict while in strict fallback is purely a leader-local I/O behavior until a new transition entry commits.
- Cache freshness and strict fallback are tightly coupled: once a cache transitions to `Stale` or `Expired`, clause (a) above forces `strict_fallback=true` (and therefore clamps local I/O to Strict mode) until ControlPlaneRaft publishes a proof covering the current `raft_commit_index` and the cache returns to `Fresh/Cached`; clause (b) can also keep the latch asserted independently even if caches are still Fresh/Cached.
- State tracking: `strict_fallback_state ∈ {Healthy, LocalOnly, ProofPublished}`, `strict_fallback_last_local_proof`, `strict_fallback_blocking_reason`, `strict_fallback_gate_blocked{operation}`, `strict_fallback_decision_epoch`. `strict_fallback_state=LocalOnly` lasting longer than `strict_fallback_local_only_demote_ms` (profile-selected defaults: 14,400,000 ms for Consistency/Throughput, 21,600,000 ms for WAN) forces self-demotion unless a Break-Glass override renews the timer.
- When a ControlPlaneRaft outage exceeds `strict_fallback_local_only_demote_ms`, the leader must explicitly step down and wait at least `min_leader_term_ms` before campaigning again. After demotion, the node remains barred from leadership until (a) ControlPlaneRaft returns, (b) a fresh `DurabilityProofTupleV1` is published and observed in cache, and (c) a jittered backoff of `strict_fallback_recampaign_backoff_ms = 60,000` elapses. This prevents thrash where the same leader repeatedly regains term without clearing strict fallback.
- While barred, the node MUST:
  - Suppress local `Campaign`/`PreVote` attempts (it does not start elections) but still respond to inbound `PreVote`/`RequestVote` RPCs truthfully, granting votes when the candidate’s log is at least as up to date. The response carries `vote_annotation=StrictFallbackBarred` so operators know why the node is not seeking leadership.
  - Continue processing AppendEntries from the active leader, updating `match_index` and durability state normally so it can rejoin quickly once the bar lifts.
  - Expose `strict_fallback_barred_until_ms` telemetry so operators can correlate the enforced backoff.
- Liveness escape hatch: if no leader is observed for `strict_fallback_no_leader_grace_ms = 120,000`, barred nodes MAY temporarily lift the campaign suppression (while remaining in strict fallback) to restore write availability. This escape hatch never re-enables ReadIndex or leases and therefore does not bypass the proof requirement. The bar automatically reactivates once a leader is elected or ControlPlaneRaft `DurabilityProofTupleV1` caches become Fresh.

9.2 Leader and Follower Lifecycle
- Leaders must persist `current_term` before AppendEntries, enforce `wal_committed_index ≤ raft_commit_index`, and export telemetry referencing the controlling clauses (e.g., durability equality).
- Elections: timeouts `[150,300] ms` (ConsistencyProfile/Throughput) or `[300,600]` ms (WAN); heartbeats every 50 ms; PreVote always enabled. `PreVoteResponse.high_rtt=true` widens the next election window when a follower observes high RTT for three consecutive heartbeats. `min_leader_term_ms=750` ensures stickiness; step-down occurs on structural lag, device latency violations (three consecutive samples above threshold or moving average > bound), or ControlPlaneRaft `TransferLeader`.
- Followers never serve ReadIndex; they operate snapshot-only reads after ControlPlaneRaft grants `follower_read_snapshot_capability`. Capabilities are revoked within 100 ms when guardrails fail, and RPCs must close with `FollowerCapabilityRevoked`.
- Observers rely on dedicated bandwidth pools and are revoked whenever `strict_fallback` or cache freshness fails.
- All numeric guardrails referenced in this section (`observer.bandwidth_cap`, `membership.catchup_slack_bytes`, etc.) originate from the profile bundles in App.B; deployments MAY tighten them but MUST keep them within the documented profile ranges.

9.3 Durability Modes and I/O Writer States
- `io_writer_mode ∈ {FixedUring, RegisteredUring, Blocking}`. Group-Fsync is disabled whenever any voter reports `Blocking` and remains disabled until all voters report non-Blocking modes (`FixedUring`/`RegisteredUring`) for the recovery window. Downgrades clamp group batch sizes/timers and emit incidents after `io_writer_mode.downgrade_incident_ms`.
- Leaders authenticate `io_writer_mode` via the same Raft heartbeat metadata used for flow-control telemetry; the mTLS channel plus replica identity/term fields provide integrity, so spoofing requires a compromised replica (the same trust model as `DurabilityAck`). Because the fault model is crash-only, a single voter stuck in `Blocking` is sufficient to fence Group-Fsync; operators must demote or repair the replica if it wedges the gate. Byzantine behavior is out of scope—if a replica maliciously reports `Blocking`, the operator must remove it from the voter set.
- Group-Fsync re-enablement predicate:
  ```
  fn can_enable_group_fsync(state) -> bool {
      !state.strict_fallback &&
      state.controlplane.cache_state == CacheState::Fresh &&
      now() >= state.downgrade_backoff_deadline &&
      state.voters.iter().all(|v| v.io_mode != Blocking) &&
      state.device_latency_violations_in_window < 3 &&
      !state.incident_flags.contains("GroupFsyncQuarantine") // incident flag that fences Group-Fsync batches
  }
  ```
- Per-partition limits: `group_fsync.max_batch_bytes ≤64 KiB`, `max_batch_ms ≤5 ms`, inflight bytes ≤4 MiB per partition, ≤64 MiB per node, `overrun_limit=2`, exponential backoff up to 15 min. Node-level incidents may further clamp credits without changing the predicate.
- `durability_mode_epoch` MUST be monotone across the cluster. A follower that has persisted epoch `E` MUST reject any AppendEntries or admin RPC that carries an older epoch (`E' < E`) by replying with `ModeConflict(durability_mode_epoch)` over RPC (or closing the Raft stream) and logging `DurabilityModeEpochConflict`. The stale leader must step down immediately and replay the transition fences once it has refreshed its proof cache. ControlPlaneRaft mirrors the conflict as an incident so operators can audit stale binaries.

9.4 Startup, Scrub, and Quarantine
- Startup scrub authenticates AEAD blocks, validates MACs/CRC/Merkle, rebuilds `.idx` files, verifies ledger ordering, truncates unreadable tails, and records `boot_record.scrub_state`. AEAD or MAC failures immediately quarantine the partition; CRC-only failures mark `needs_repair` with exponential backoff (up to three retries) before escalation.
- Background scrub samples ≥1% of entries per segment every 21,600,000 ms (6 h), ensuring every WAL byte is hashed at least once every 604,800,000 ms (7 days) and reporting `scrub.coverage_age_days`. Repair escalation enters Quarantine on repeated anomalies.
- Quarantine states: `Healthy → Quarantine` on integrity faults, `Quarantine → RepairMode` for offline work, `Quarantine → Decommissioned` when removed. While quarantined, writes and membership changes are disabled, follower reads and snapshot exports depend on reason, and readiness surfaces `WhyQuarantined{reason, since_ms}`.
- Quarantine scope is strictly per-partition. ControlPlaneRaft records `quarantine_reason` and `since_ms`, but other partitions on the same node continue operating unless they independently violate guardrails. Admin tooling MUST NOT propagate quarantine automatically; operators must investigate neighboring partitions separately to avoid cascading outages.

9.5 Snapshot Lifecycle
- Emit full snapshots when log bytes reach `snapshot.log_bytes_target = 512 MiB`, when the elapsed wall-clock time since the last successful full snapshot would exceed the operator/ hard bound (`snapshot.full_emit_period_ms_operator` if set, otherwise the profile hard bound `snapshot.full_emit_period_ms_hard_profile`), or when follower lag ≥64 MiB. Implementations SHOULD meet `snapshot.full_emit_period_ms_target` (30,000 ms default) and SHOULD emit `delta_chain_state=GracefulCatchup` plus telemetry whenever the target is missed by >25%, but they MUST only disable incrementals (set `delta_chain_state=Orphaned`) when the operator or hard bound is exceeded without progress; failure to meet a target alone never forces a mode change. Snapshot emission, `content_hash` computation, and manifest signing follow the canonical JSON procedure in §7.1 (remove `content_hash`/`signature` before hashing).
- Incremental snapshots run on an independent cadence measured from the `manifest_id.emit_ts` of the previous delta. Implementations SHOULD meet `snapshot.delta_emit_period_ms_target` (10,000 ms default) and MUST NOT exceed `snapshot.delta_emit_period_ms_operator` (if configured) or the profile hard bound `snapshot.delta_emit_period_ms_hard_profile`. Temporary overruns produce `GracefulCatchup`; only exceeding the operator/hard bound without emission forces a full snapshot and marks the chain orphaned until a compliant delta resumes the cadence.
- Snapshot import steps: (1) canonicalize & verify manifest signature/DEK epoch; (2) check `version_id` bounds; (3) stream AEAD-authenticated chunks, zeroizing buffers and retrying up to three times (≤60 s) before quarantining; (4) buffer AppendEntries (bounded per partition by `snapshot.import_buffer_max_entries_profile` (default 8,192) and `snapshot.import_buffer_max_bytes_profile` (default 8 GiB) but also globally capped by `snapshot.import_node_buffer_hard_cap_bytes_profile` (default min(32 GiB, 15% RAM) per node)—the effective limit is `min(per-partition cap, remaining node budget)` and implementations MUST treat the per-partition values as upper bounds subject to the node cap, spilling to disk-backed staging if necessary) until `applied_index >= base_index`; (5) reconcile follower checkpoints and ControlPlaneRaft trust caches. Buffer exhaustion emits `ThrottleEnvelope{reason=SnapshotImport}`. Profiles MAY tune these SLO parameters within the bounds in App.B.
- Snapshot bandwidth budgets: `snapshot.max_bytes_per_sec = 128 MiB/s` per peer with 90%/60% hysteresis; node-level cap `min(0.7 × NIC capacity, 1 GiB/s)`.

9.6 Compaction and Storage Hygiene
- WAL deletion requires `(a)` at least `compaction.quorum_ack_count` replicas reporting `sm_durable_index ≥ snapshot_base_index`, `(b)` floor `max(learner_slack_floor, min(quorum_applied_index, snapshot_base_index))`, `(c)` manifest authorization handshake, `(d)` learner retirement guardrails, `(e)` nonce reservations cleared or abandoned, `(f)` no integrity/quarantine blocks. Disk policy checks enforce safe write cache modes, barriers, and stacked-device validation before bootstrap.

9.7 Definition Bundles and Activation Barriers
- ControlPlaneRaft issues `DefinitionBundle{bundle_id, version, sha256, definition_blob, warmup_recipe}` plus `ActivationBarrier{barrier_id, bundle_id, readiness_threshold, warmup_deadline_ms, readiness_window_ms, partitions[]}`. Nodes stage bundles under `/state/<partition>/definitions`, verify digests, run shadow apply queues, and publish `WarmupReadiness{partition_id, bundle_id, shadow_apply_checkpoint_index, partition_ready_ratio}`. `DefineActivate` commits only when every partition reports `warmup_ready_ratio ≥ readiness_threshold` within the deadline; mismatches abort with `ActivationBarrierExpired`.

9.8 ControlPlaneRaft Proof Publication
- The proof consumed by read gates and strict-fallback clearance is serialized as `DurabilityProofTupleV1 = {partition_id, last_durable_term, last_durable_index, segment_seq, io_writer_mode, durability_mode_epoch, controlplane_signature, updated_at}`. `controlplane_signature` is an Ed25519 signature produced by the ControlPlaneRaft proof-signing key (`ControlPlaneProofKey` in §12.4). ControlPlaneRaft enforces that this tuple is strictly monotone when compared lexicographically on `(last_durable_term, last_durable_index, segment_seq, durability_mode_epoch)` per partition; toggling `durability_mode_epoch` therefore requires the same `DurabilityTransition` entry to advance `(last_durable_term, last_durable_index)` as well. Nodes MUST verify the signature, then compare `{last_durable_term, last_durable_index, segment_seq, io_writer_mode, durability_mode_epoch}` to the last `DurabilityRecord` persisted locally; `updated_at` and the signature bytes are excluded from the equality check. Reads are refused whenever the signed tuple and the local record diverge. Whenever this document says the proof “matches” or references `controlplane.proof`, it refers to equality on that exact subset.
- When two proofs are observed (e.g., after a partitioned ControlPlaneRaft quorum) replicas accept only the one with the higher `(last_durable_term, last_durable_index, segment_seq, durability_mode_epoch)` tuple. Observing identical `(last_durable_term, last_durable_index)` values with different `segment_seq` or `durability_mode_epoch` immediately raises `ControlPlaneProofConflict`; replicas stay in strict fallback and require operators to reconcile ControlPlaneRaft before proceeding.
- Leaders may leave strict fallback only after ControlPlaneRaft durably appends the proof that matches their local ledger. Possessing a locally verified tuple without the ControlPlaneRaft append is insufficient, and leaders must continue in Strict mode until they can publish a fresh proof and observe it replicated with the correct signature.

9.9 Membership Changes and Joint Consensus
- Reconfigurations follow four phases:
  1. **Preflight**: ControlPlaneRaft validates placement feasibility (≤70% utilization after the move), survivability prechecks (`Q` and `H` ratios), and deterministic rehearsal (`placement_digest`). Failure produces a structured error; overrides require signed justification in the override ledger.
  2. **Catch-up**: Joining replicas enter `Learner` state and must satisfy either `(raft_commit_index - membership.catchup_slack_bytes)` with default 4 MiB or `(leader.last_log_index - membership.catchup_index_slack)` with default 1024 entries within `membership.catchup_timeout = 120,000` ms. Meeting either guard is sufficient unless policy demands both.
  3. **Joint consensus**: After catch-up, the leader writes `MembershipChange{old_members[], new_members[], routing_epoch, placement_digest}` and operates with the union quorum. Voluntary leader transfers are blocked while in joint config. Each `MembershipChange` carries the rehearsal digest so replay can prove the change was prevalidated.
  4. **Finalize**: Once `joint_commit_count >= membership.finalize_window` (default 64) and structural lag is below both `lag_bytes < 64 MiB` and `lag_duration < 30 s`, the leader commits the pure new configuration and mirrors it back to ControlPlaneRaft. ControlPlaneRaft records the resulting proof so subsequent joins can cite the exact ledger index.
- Rollback occurs when catch-up fails, lag remains structural beyond `membership.rollback_grace_ms = 3000`, or survivability prechecks fail mid-flight. Rollback appends `MembershipRollback{reason, failing_nodes[], override_ref}`, commits it under the joint quorum, records the durability proof for the rollback index, and only then allows elections to proceed.
- Every membership transition emits `DurabilityTransition`/`FenceCommit` proofs if durability modes or DR fences change simultaneously. Replicas must persist the ControlPlaneRaft ack containing `{routing_epoch, membership_digest, durability_mode_epoch}` before serving client traffic under the new membership, ensuring observers can prove which quorum composition produced the active log suffix.

10. Algorithms and Consistency Rules

10.1 Election and Pre-Vote Logic
- Election timeout draws uniformly from `[150,300]` ms (ConsistencyProfile/Throughput) or `[300,600]` ms (WAN). PreVote high-RTT detection requires `ema_heartbeat_rtt_ms ≥ threshold` for three consecutive heartbeats; thresholds: 150 ms (ConsistencyProfile/Throughput), 350 ms (WAN). High-RTT followers widen their next election window to the WAN range for the next leadership attempt and revert to their profile’s normal window as soon as they observe a healthy leader heartbeat or grant a vote in a successful election.
- Leader stickiness: `min_leader_term_ms=750`. Device latency hysteresis requires 3 consecutive fsync samples above `durability.max_device_latency_ms` or a 500 ms moving average before forcing step-down; recovery requires 5 consecutive samples below 80% of the threshold.

10.2 Lease Inequality
- Leases may run only when:
  ```
  lease_duration_ms + lease_rtt_margin_ms + clock_skew_bound_ms + heartbeat_period_ms
  < min_election_timeout_ms
  ```
- `min_election_timeout_ms` equals the lower bound of the election-timeout range for the active profile (150 ms for ConsistencyProfile/Throughput, 300 ms for WAN).
- Operators MUST verify the inequality using the profile parameters in Appendix B (lease duration, RTT margin, clock skew bound, heartbeat period); v0.1 profiles meet the guard but ship with `lease_gap_max=0`, keeping leases disabled until a future profile explicitly enables them. Additional prerequisites: `strict_fallback=false`, `commit_visibility=DurableOnly`, ControlPlaneRaft cache ∈ {Fresh, Cached}, the `DurabilityProofTupleV1` subset `{last_durable_term, last_durable_index, segment_seq, io_writer_mode, durability_mode_epoch}` matches the local ledger tuple, `wal_committed_index == raft_commit_index`, `clock_guard_alarm=0`. Even though equality is already enforced, `lease_gap_max` continues to emit `LeaseGapExceeded` incidents whenever the instantaneous gap deviates, so operators retain telemetry on near-miss conditions.
- Skew alarms trigger voluntary leader step-down within 500 ms and immediately revoke leases. NTP-only deployments must declare `clock_guard_source=NtpOnly`, relax bounds (15/20/60 ms), keep leases disabled, and continue step-down behavior on alarms.

10.3 Read Gate Predicate and Service Matrix
- Leaders serve ReadIndex requests only when:
  - `strict_fallback == false`
  - `controlplane.cache_state ∈ {Fresh, Cached}` (i.e., caches are not `Stale` or `Expired`)
  - `commit_visibility == DurableOnly`
  - the `DurabilityProofTupleV1` subset `{last_durable_term, last_durable_index, segment_seq, io_writer_mode, durability_mode_epoch}` equals the leader’s last quorum-fsynced tuple
  - `wal_committed_index == raft_commit_index`
- Violations emit `ControlPlaneUnavailable{reason ∈ {CacheNotFresh, CacheExpired, NeededForReadIndex}}` per the priority order (`CacheExpired` for `Expired`, `CacheNotFresh` for `Stale`, `NeededForReadIndex` for strict-fallback/proof failures). Telemetry must expose `read_gate.can_serve_readindex` and `read_gate.failed_clause`.
- Reference predicate used across the spec:
  ```
  fn read_gate_predicate(state: &LeaderState) -> (bool, FailedClause) {
      if state.controlplane.cache_state == CacheState::Expired {
          return (false, FailedClause::ControlPlaneCacheExpired);
      }
      if state.controlplane.cache_state == CacheState::Stale {
          return (false, FailedClause::ControlPlaneCacheStale);
      }
      if state.strict_fallback { return (false, FailedClause::StrictFallback); }
      if state.commit_visibility != CommitVisibility::DurableOnly {
          return (false, FailedClause::CommitVisibility);
      }
      if state.controlplane_proof_tuple != state.last_quorum_fsynced_tuple {
          return (false, FailedClause::ControlPlaneProofMismatch);
      }
      if state.wal_committed_index != state.raft_commit_index {
          return (false, FailedClause::IndexInequality);
      }
      (true, FailedClause::None)
  }
  ```
  Follower versions replace the last clause with `local_wal_durable_index ≥ applied_index_floor` when serving snapshot-only reads.
- Read availability across modes:
| Node role / read type | Normal mode | Strict fallback |
| --- | --- | --- |
| Leader ReadIndex / lease | Allowed when predicate above holds | Rejected (`ControlPlaneUnavailable{reason=NeededForReadIndex}`) |
| Leader snapshot-only reads (explicit SnapshotOnly flag) | Allowed; reads clamp to `applied_index` | Allowed; still clamped to last verified `applied_index`, never linearizable |
| Follower snapshot-only reads | Allowed only when `follower_read_snapshot_capability` bit is set | Capability revoked within 100 ms; outstanding RPCs fail with `FollowerCapabilityRevoked` |
| Observer streams | Allowed while cache is Fresh and strict fallback is false | Revoked; observers must reconnect after proof publication |

10.3.1 `commit_visibility` Modes
- `commit_visibility=DurableOnly` is the v0.1 default for every profile and is required whenever linearizable reads, follower-read capabilities, or observers are enabled.
- `commit_visibility=CommitAllowsPreDurable` is an optional Throughput-profile feature that MAY be enabled only when:
  - Group-Fsync is active and healthy.
  - The product surface explicitly marks all resulting reads as `read_semantics=SnapshotOnly`.
  - Clients that require read-after-write guarantees pin their writes by waiting for `last_quorum_fsynced_index ≥ ack_index`.
- Under `CommitAllowsPreDurable`, leaders MAY expose `raft_commit_index` ahead of `wal_committed_index` to snapshot-only reads, but leaders MUST continue enforcing the ACK contract and MUST clear the mode immediately when strict fallback, cache staleness, or any read gate clause fails. Linearizable reads (ReadIndex or leases) remain forbidden in this mode, so no predicate ever requires `wal_committed_index == raft_commit_index` while `CommitAllowsPreDurable` is active; follower-read capabilities stay disabled. If a deployment does not implement these guardrails, `CommitAllowsPreDurable` MUST remain disabled.

10.4 ACK Contract
- Client ACK prerequisites:
  1. Entry is Raft-committed in the current term.
  2. Leader has persisted local WAL bytes and `DurabilityRecord`.
  3. Leader has quorum `DurabilityAck` evidence (followers persisted the same record plus `fdatasync`).
  4. `wal_committed_index` advanced to the ack index and is recorded before responding.
- Idempotency requires `AppendRequest.idempotency_key`; servers repeat the same ack index when reprocessing duplicates.
- Because of prerequisite (1), a freshly elected leader MUST wait until it commits at least one entry from its own term before acknowledging any client writes—even if those writes became committed due to earlier-term majority replication—matching the standard Raft current-term rule.

10.4.1 Durable Watermarks
- Every replica maintains `local_wal_durable_index`, equal to the highest log index whose WAL bytes completed §10.5 step (2) and whose `DurabilityRecord` completed §10.5 step (4). Followers advertise this value inside `DurabilityAck` only after clause §7.1 (DurabilityAck attestation) is satisfied.
- Leaders additionally compute `wal_committed_index` by intersecting their own `local_wal_durable_index` with the quorum of `DurabilityAck` attestations gathered for the current term:
  1. Raft establishes `raft_commit_index` via the standard majority rule with the current-term requirement.
  2. Once steps (1)–(4) in §10.5 complete for index *n*, the leader updates `local_wal_durable_index = n`. This durability progression is independent of Raft commit timing, but entries cannot contribute to `wal_committed_index` until they are Raft-committed in the current term.
  3. The leader recomputes `wal_committed_index = max{m | at least quorum_size attestations (including the leader) report `local_wal_durable_index ≥ m`, the log entry at index *m* exists locally with `term(m) == current_term`, and `m ≤ raft_commit_index` }`.
- Leaders MUST NOT advance `wal_committed_index` ahead of `raft_commit_index`, even if durability acknowledgements arrive early. Followers MUST NOT advertise a `local_wal_durable_index` that exceeds the smaller of their locally known last-appended (or last-written) log index and their last synced `DurabilityRecord`.
- Strict equality for linearizable reads therefore reduces to checking `wal_committed_index == raft_commit_index` on the leader; followers enforce the snapshot-only predicate by requiring `local_wal_durable_index ≥ applied_index_floor`.
- The “current term” constraint in Raft applies to both indices: an entry can contribute to `wal_committed_index` only after it is committed in the current term. Followers that notice a leader advertising durability for an entry from an older term MUST continue processing the AppendEntries but treat the resulting durability claim as unusable when comparing ControlPlaneRaft proofs (and SHOULD log `ControlPlaneProofMismatch`) so the leader cannot clear the read gate via stale terms.

10.5 Ledger Ordering and Replay
- Ordered steps (identical for leaders and followers):
  1. Append the entry bytes to the WAL segment (`pwrite`).
  2. Complete the WAL durability step: in Strict mode `fdatasync` the WAL file; in Group-Fsync flush the batch covering the entry, ensuring the entry bytes are on stable storage.
  3. Append the corresponding `DurabilityRecord` (and any coalesced reservation metadata) to `wal/durability.log`.
  4. `fdatasync(wal/durability.log)` to make the ledger record durable.
  5. After step (4), leaders count quorum `DurabilityAck`s toward `wal_committed_index` and may emit the client ACK once §10.4 succeeds.
Followers MUST execute steps (1)–(4) before sending their `DurabilityAck`. Replay pseudo:
  ```
  fn replay_durability_log(log_path, wal_index) -> ReplayResult {
      let mut last_good_offset = 0;
      let mut last_good_record = None;
      for record in read_records_in_order(log_path) {
          if !record.verify_crc() { break; }
          if !wal_index.contains(record.term, record.index, record.segment_seq) { break; }
          enforce_step_order(record);
          last_good_offset = record.file_end_offset;
          last_good_record = Some(record);
      }
      truncate_file_to(last_good_offset);
      fdatasync(log_path);
      ReplayResult { proof: last_good_record, strict_fallback: last_good_record.is_none(), truncated_bytes }
  }
  ```
  Truncation uses synchronous primitives and immediately `fdatasync`s descriptors; background threads may not truncate asynchronously.

10.6 Flow Control
- Dual-token PID controller with sample period 100 ms, default gains per profile (Latency: `Kp=0.60, Ki=0.20, Kd=0.10`; Throughput: `0.50/0.15/0.08`; WAN: `0.40/0.10/0.05`). Guardrail `Ki × sample_period_s ≤ 1.0`.
- Credits: `entry_credit_max=4096`, `byte_credit_max=64 MiB`, with minimum quantum admitting one ≤16 KiB frame each tick even when byte credits exhaust. PID auto-tuner runs on Throughput/WAN when `io_writer_mode=FixedUring` and caches are Fresh; it reverts to last stable gains on oscillation and reports `flow.pid_auto_tune_state`.
- Structural lag classification: Transient (`lag_bytes ≤64 MiB` and `lag_duration <30 s`) halves credits; Structural (beyond thresholds or ≥256 MiB) forces Strict durability, reduces credits to 25%, triggers snapshots, alerts ControlPlaneRaft, and steps down after `flow.structural_stepdown_ms = 15,000` ms unless `flow.structural_override` is active. Manual `flow.structural_hard_block` halts writes entirely.

10.7 Snapshot Import/Export; Incremental Cadence
- Import procedure enumerated in §9.5. Retry policy: exponential backoff `min(2^attempt × 1000, 10,000)` ms with ±25% jitter, ≤3 attempts, ≤60 s.
- Incremental snapshots SHOULD meet the profile SLO targets (`snapshot.delta_emit_period_ms_target`, `snapshot.full_emit_period_ms_target`) but MUST enforce the operator/profile hard bounds (`snapshot.delta_emit_period_ms_operator` if set, otherwise `snapshot.delta_emit_period_ms_hard_profile`; same for full). `delta_chain_length` counts only incrementals since the last full snapshot and MUST stay ≤ `snapshot.delta_chain_max_profile`. Authorization logs include parent info and elapsed time since the last full snapshot; ControlPlaneRaft only retires a chain when the operator/hard bound is exceeded, not merely because an SLO target was missed.
- AP workloads restore `ap_pane_digest` and `dedup_shards[]` before applying entries beyond `base_index`; mismatches cause `SnapshotDeterminismViolation`.

10.8 Compaction Floor
```
fn compute_compaction_floor(state: CompactionState) -> u64 {
    let learner_floor = state.learner_slack_floor.unwrap_or(0);
    let quorum_floor = state.quorum_applied_index;
    let floor_effective = learner_floor.max(quorum_floor).max(state.snapshot_base_index);
    if state.quorum_sm_durable_index < state.snapshot_base_index {
        return state.snapshot_base_index;
    }
    floor_effective
}
```
- Delete bytes `< floor_effective` only after manifest authorization, learner retirement guards, and nonce reservation clearance succeed.

11. Error Handling

11.1 Wire Rejections
- `RoutingEpochMismatch`: stale or missing epoch on writes/admin calls; includes observed/expected epochs, lease/durability epochs.
- `ModeConflict`: stale durability mode epoch when toggling Strict/Group.
- `ControlPlaneUnavailable`: `reason ∈ {CacheExpired, CacheNotFresh, NeededForReadIndex}` with retry metadata (HTTP 503 / gRPC `UNAVAILABLE`); read gates emit `CacheExpired` when caches have aged into `Expired`, `CacheNotFresh` when caches are `Stale`, and `NeededForReadIndex` when proof equality/strict-fallback clauses fail. Clients must honor `Retry-After ≥ 250 ms` and fall back to snapshot-only reads when supported.
- `snapshot_full_invalidated` / `snapshot_delta_invalidated`: invalid trust cache, schema bump, emit version change, DEK epoch rollover, or delta chain violation.
- `ThrottleEnvelope`: `reason ∈ {ApplyBudget, WALDevice, FollowerLag, DiskSoft, DiskHard, TenantQuota, FrameAlignment, SnapshotImport}`, includes backlog, credits, durations, `credit_hint ∈ {Recover, Hold, Shed}`, ingest/durability status codes.
- `FollowerCapabilityRevoked`, `SnapshotChunkAuthFailure`, `SnapshotDeltaRetired`, `NonceReservationGapWarning`, `OverrideStrictOnlyBackpressure`, `WhyCreditZero`, `WhyNotLeader`, `WhySnapshotBlocked`, `WhyQuarantined` share schema header and truncation rules.

11.2 Gate Failures
- Read gate predicate failures emit `ControlPlaneUnavailable` with prioritized reasons.
- Group-Fsync gating returns `ModeConflict(strict_fallback)` or the telemetry incident `GroupFsyncQuarantine` (the identifier omits the hyphen even though the feature name remains “Group-Fsync”).
- Lease revocation produces `LeaseGapExceeded`, `clock_guard_alarm`, or `LeaseRevokedDueToStrictFallback`.
- Snapshot import/authorization errors: `SnapshotDeterminismViolation`, `SnapshotChunkAuthFailure`, `SnapshotImportNodePressure`.
- Quarantine entry reasons are typed (`Integrity`, `Administrative`, `ApplyFault`), controlling whether snapshot exports/follower reads stay enabled.

12. Security Considerations

12.1 Transport Security
- Node-to-node traffic uses mTLS with SPIFFE identities. Revocation order: OCSP stapling cache, CRL fetch, break-glass waiver. If revocation data exceeds `revocation.max_staleness_ms = 300,000` or both feeds unavailable for `revocation.fail_closed_ms = 600,000`, peers must tear down mTLS connections and enter Quarantine until fresh material or waiver (≤300,000 ms extension) arrives. Short-lived certs (≤86,400,000 ms) require fresh revocation feeds. All timers referenced in revocation logic use the local monotonic clock; operators must ensure wall-clock discipline stays within 5 s (via the same `clock_guard` service used for leases) while safety gates evaluate monotonic timers to avoid skew-induced bypasses.
- Revocation-induced quarantine is scoped to the node that failed validation: connections initiated by healthy peers stay up so long as their revocation caches are fresh. Clusters MUST NOT propagate a revocation-triggered shutdown automatically; instead, every node independently evaluates revocation freshness and only quarantines itself if its local timers expire. Cross-node automation may page operators, but it MUST NOT mass-quarantine healthy nodes.

12.2 AEAD and Storage Encryption
- WAL segments use AES-256-GCM with 96-bit IV derived from `Truncate96(H(dek_epoch || segment_seq || block_counter || "WAL-Block-IV v1"))`, where `H` is SHA-256 by default. Switching the IV hash function (e.g., to BLAKE3) is only legal when a cluster-wide `crypto.iv_hash_suite` gate is enabled, a durability fence commits the new suite, and every partition rotates `dek_epoch` after the fence so ciphertext never mixes suites for the same `(partition_id, dek_epoch)` tuple. The concatenation order is canonical: `dek_epoch` encoded as big-endian `u32`, `segment_seq` as big-endian `u64`, `block_counter` as big-endian `u64`, followed by the ASCII literal (with no terminating NUL). `Truncate96` takes the first 12 bytes of the hash output. Implementations MUST serialize exactly those byte widths before hashing or the IV space diverges. **Note:** This big-endian encoding applies only to the hash preimage used for IV derivation; all on-wire fields and AAD remain little-endian per protocol conventions, and every other section referencing IV derivation inherits this big-endian preimage requirement from §12.2.
- Snapshot chunks reuse AES-256-GCM but derive IVs with the manifest-provided salt: `Truncate96(H(dek_epoch || iv_salt || chunk_offset || chunk_block_counter || "Snapshot-Chunk-IV v1"))`, where `iv_salt` is the 16-byte value published in the manifest, `chunk_offset` is the chunk’s starting logical byte offset encoded as big-endian `u64`, and `chunk_block_counter` is a big-endian `u64` that increments per `wal.crypto_block_bytes` (4096-byte) block within the chunk. This derivation ensures each `(manifest_id, chunk_offset, block_counter)` pair produces a unique IV even when snapshots are re-emitted with the same `dek_epoch`; `iv_salt` MUST change whenever a new manifest is emitted. The literal string again has no terminating NUL.
- AAD includes `{aad_version=1, partition_id, dek_epoch, segment_seq}` encoded as little-endian integers; version bumps require explicit upgrade plans. Tags are 16 bytes; verification must be constant time (e.g., via a `ct_equal_16` helper).
- `wal.crypto_block_bytes=4096`, `nonce.reservation_max_blocks_profile ∈ [1024, 8192]`, `nonce.reservation_gap_quarantine_threshold_bytes` default 4 MiB. Writers queue reservation flush attempts every ≤5 ms (or sooner when a window is consumed), but ciphertext MUST still wait for the reservation record + `fdatasync` completion before using the counters. Implementations synthesize `NonceReservationAbandon` before compaction and track `wal.nonce_reservation_gap_bytes` vs `wal.nonce_corruption_bytes`.
- A block counter MUST NOT be used for encryption until its reservation has been durably recorded: writers append `NonceReservationRange`, `fdatasync` `wal/durability.log`, and only then emit ciphertext using the reserved `(segment_seq, block_counter)` window. Reboots therefore resume from the last reservation head without reusing counters.
- `block_counter` starts at 0 for each freshly allocated `segment_seq` and increments by one per `wal.crypto_block_bytes` chunk. `segment_seq` values are monotonically increasing per partition and are never reused, even after compaction or rewrite; partial rewrites allocate a new `segment_seq` and bump `dek_epoch` if necessary. Combined with the reservation rule above, the tuple `(partition_id, dek_epoch, segment_seq, block_counter)` is therefore globally unique for every encrypted block.
- Key epochs: ControlPlaneRaft tracks `{kek_version, dek_epoch, integrity_mac_epoch}`. Nodes fetch new DEKs every 604,800,000 ms (weekly, stated in ms), retain previous DEK for decrypt-only 172,800,000 ms (48 h), then zeroize hardware/software contexts (`crypto.zeroize_context`) and emit `crypto.zeroization_digest`. Epoch regression (`KeyEpochReplay`) forces Strict fallback; overrides are recorded via Break-Glass tokens.

12.3 RBAC and Break-Glass
- Roles: Operator (lifecycle, durability, transfers, snapshots), TenantAdmin (telemetry, tenant quotas), Observer (read-only), BreakGlass (durability overrides, survivability overrides, credit overrides, snapshot overrides, quarantine overrides).
- RBAC manifests refresh every 30 s; missing two refreshes causes `RBACUnavailable` for mutating APIs while reads continue for `rbac.grace_ms = 60,000`.
- Break-Glass tokens are SPIFFE SVIDs containing `urn:clustor:breakglass:<scope>`, TTL ≤300,000 ms, non-renewable. Validation allows ±5,000 ms skew, enforces cluster ID and scope-specific API coverage, and requires audit logging of `{scope, actor_id, ticket_url}` plus zeroization of token private material/resident credentials immediately after the first successful use. Scopes are enumerated in Appendix D’s map.
- Audit logs (`security/breakglass_audit.log`) store Canonical JSONL entries (each line serialized via the `CanonicalJson` rules) with Ed25519 signatures, batched per 1,000 lines, retained ≥400 days.

12.4 Key Purpose Registry
| Key | Use | Rotation |
| --- | --- | --- |
| ReleaseAutomationKey (Ed25519) | Signs release manifests | Rotates every 180 days; hardware-backed HSM. |
| CPReleaseKey (Ed25519) | Signs feature manifests, overrides, and other ControlPlaneRaft-issued durability records | Rotates with ControlPlaneRaft minors. |
| ControlPlaneProofKey (Ed25519) | Signs `DurabilityProofTupleV1` records | Rotates with ControlPlaneRaft minors (staged with overlap). |
| SnapshotManifestKey (Ed25519) | Signs runtime snapshot manifests exported by partitions (canonical JSON hashed per §7.1) | Rotates every 90 days with ControlPlaneRaft-supervised rollover. |
| AuditLogKey (Ed25519) | Signs audit log segments | Rotates annually with overlap. |
| BreakGlassTokenCA | Issues SPIFFE SVIDs for break-glass | Dedicated 45-day intermediates with ≥7 day overlap. |

12.5 Additional Controls
- Hardware accelerators must expose deterministic zeroization hooks; failures raise `CryptoZeroizationFailed` and quarantine the partition.
- Key rotations track `wal_kms_block_seconds` / `snapshot_kms_block_seconds`; >300 s growth per hour pages operators and blocks ControlPlaneRaft from finalizing rotations unless overrides cite ticket IDs.

13. Observability

13.1 Metrics and Telemetry
- Metric namespaces: `clustor.raft.*`, `clustor.wal.*`, `clustor.snapshot.*`, `clustor.flow.*`, `clustor.controlplane.*`, `clustor.security.*`. Export `metrics.schema_version` and `metrics.build_git_sha`.
- Histogram buckets (inclusive upper bounds; implicit `+Inf` bucket) are fixed as follows:
  - `clustor.wal.fsync_latency_ms`: `[0.25, 0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100]` milliseconds.
  - `clustor.raft.commit_latency_ms`: `[0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100]` milliseconds.
  - `clustor.flow.apply_batch_latency_ms`: `[0.25, 0.5, 1, 2, 4, 6, 8, 10]` milliseconds.
  - `clustor.snapshot.transfer_seconds`: `[1, 2, 4, 8, 16, 32, 64, 128, 256]` seconds.
Deployments outside profile SLOs still alert even if they saturate the top bucket.
- Required telemetry fields: `strict_fallback_state`, `strict_fallback_blocking_read_index`, `strict_fallback_pending_entries`, `read_gate.*`, `io_writer_mode_gate_state`, `lease_gate_runtime_state`, `clock_guard_alarm*`, `observer_capability_state`, `snapshot.delta_chain_length`, `snapshot.delta_emit_skew_ms`, `snapshot_only_ready_ratio`, `flow.pid_auto_tune_state`, `flow.pid_auto_tune_adjust_total`, `transport.pool_*`, `feature.<name>_gate_state`, `feature.<name>_predicate_digest`, `controlplane.cache_state`, `controlplane.cache_age_ms`, `controlplane.cache_warning`, `controlplane.cache_expiry_total`, `strict_only_runtime_ms`, `ingest_status_code`, `credit_hint`, `durability_status_code`.
- `/readyz` surfaces readiness ratios, definition bundle state, activation barriers, warmup readiness, fixture bundle version/age, ingest status, credit hints, and feature gates so deployment controllers can gate activations identically to the data plane.
- Incident logging: alerts from App.A feed correlated incidents with storm guard `incident_max_per_window = max(5, ceil(active_partitions_on_node / 250))` per 10 min except for safety-critical classes. Cooldown 300,000 ms between duplicate incidents.

13.2 Throttling and Explain APIs
- Throttle envelopes must remain ≤32 KiB JSON, list ≤32 IDs per array, sort lexicographically, and include continuation tokens when truncated.
- Explain endpoints (`WhyNotLeader`, `WhyCreditZero`, `WhySnapshotBlocked`, `WhyDiskBlocked`, `WhyQuarantined`, `WhyCreditHint`) share the schema header, surface decision trace IDs, guardrail deltas, and truncated lists metadata.
- Admin dry-run endpoints (`DryRunMovePartition`, `DryRunSnapshot`, `DryRunFailover`) report computed guardrails (catch-up slack/timeout, predicted credit impact).

14. Compatibility and Versioning

14.1 Wire and Schema Stability
- Wire catalog and system log entry IDs are frozen for v0.1.x; additive fields append at the tail. Field names/casing in JSON/gRPC mirrors are stable. Clients must tolerate additive optional fields but reject missing required fields.
- Nodes MUST NOT raise frame/body caps without negotiating `WireExtension::WideFrame`. `body_len` must remain ≤4 MiB (RPCs) or ≤32 KiB (Explain/Why*, throttle) unless the extension is mutually set.
- Enumerations treat unknown discriminants as hard failures; best-effort parsing is forbidden. JSON mirrors accept recognized numeric enum values but emit canonical strings.
- Large lists must chunk via ChunkedList until `WireExtension::WideCount` is mutually enabled.

14.2 Version Negotiation and Feature Gates
- Peers record handshake tuples in `bundle_negotiation_log`; mismatched catalogs close connections immediately.
- Feature enablement (leader leases, incremental snapshots, observer admission, BLAKE3 leaves, PID auto-tuner, Group-Fsync) requires uniform support across a voter set, ControlPlaneRaft gate flips, strict fallback cleared, and published predicates. Capability telemetry (`feature.<name>_gate_state`, predicate digest) must match ControlPlaneRaft’s feature manifest.
- ControlPlaneRaft caches follow a deterministic retry hierarchy. A background watcher continuously calls `attempt_refresh()` on the cadence implied below; even when `cache_state=Fresh` the watcher still wakes every 5,000 ms to confirm freshness.
  ```
  loop {
      match controlplane.cache_state {
          Fresh => sleep(5_000);
          Cached => attempt_refresh(); sleep(min(5_000, remaining_grace/4));
          Stale => attempt_refresh(); sleep(min(2_500, remaining_grace/8));
          Expired => attempt_refresh(); sleep(1_000);
      }
  }
  ```
  `remaining_grace = max(0, controlplane.cache_grace_ms - controlplane.cache_age_ms)`. All timers use 64-bit monotone math; additions saturate at `u64::MAX`. Every transition to `Expired` increments `controlplane.cache_expiry_total`.
- Cache states are defined as:
| State | Age condition | Allowed operations |
| --- | --- | --- |
| `Fresh` | `cache_age_ms ≤ controlplane.cache_fresh_ms` (default 60,000) | Normal writes, reads, capability grants. |
| `Cached` | `controlplane.cache_fresh_ms < age ≤ 0.5 × cache_grace_ms` | Writes and reads continue, but telemetry raises `controlplane.cache_warning`. |
| `Stale` | `0.5 × cache_grace_ms < age < cache_grace_ms` | Writes continue but are forced to Strict durability; the effective `commit_visibility` behaves as `DurableOnly`; incremental snapshots pause; follower-read/observer capabilities are revoked. |
| `Expired` | `age ≥ cache_grace_ms` | Mutating admin/control APIs fail closed, Group-Fsync/leases stay disabled, read gate forces `ControlPlaneUnavailable{reason=CacheExpired}`; data-plane writes MAY continue only in Strict durability with effective `commit_visibility=DurableOnly`. |
- Entering `Stale` or `Expired` also forces `strict_fallback=true` until a fresh proof clears the gate.

- Mode truth table:
  | Cache state | Writes | ReadIndex / leases | Leader snapshot-only reads |
  | --- | --- | --- | --- |
  | Fresh | Allowed (configured durability mode) | Allowed when read-gate predicate passes | Allowed; clamped to `applied_index` |
  | Cached | Allowed (configured durability mode) | Allowed when read-gate predicate passes | Allowed; clamped |
| Stale | Allowed but auto-clamped to Strict; effective `commit_visibility` behaves as `DurableOnly` | Rejected with `ControlPlaneUnavailable{reason=CacheNotFresh}` | Allowed; clamped |
| Expired | Allowed only in Strict durability; admin/control APIs disabled; effective `commit_visibility=DurableOnly` | Rejected with `ControlPlaneUnavailable{reason=CacheExpired}` | Allowed; clamped to last verified snapshot before expiry |

- Durability proofs expire after the profile’s `controlplane.durability_proof_ttl_ms_profile` (43,200,000–86,400,000 ms). Stale proofs force strict fallback until refreshed.
- DefinitionBundle readiness requires `warmup_ready_ratio ≥ readiness_threshold`; `DefineActivate` logs include readiness digests hashed over sorted readiness records.

14.3 Readiness and Deployment
- Graceful shutdown recommends `TransferLeader`, wait `commit_quiescence_ms=200`, ensure `apply_queue_depth < 10%`, flush WAL/snapshots, respect `graceful_shutdown_timeout_ms = 10,000`.
- Kubernetes guidance: StatefulSets with `maxUnavailable=1`, anti-affinity (≤1 voter per node/zone), cgroup v2 with `io.max`, `terminationGracePeriodSeconds ≥ 10`, read-write `/state`, read-only elsewhere. Unsupported mounts or stacked devices lacking explicit overrides cause bootstrap rejection.
- Repair mode (`bootstrap.repair_mode=true`) mounts partitions read-only, runs scrub, allows snapshot download/upload, and requires Break-Glass `AdminResumePartition` to exit.

Appendix A: Project Tooling and Artifacts (Non-Normative)
- Specification automation regenerates machine-readable bundles (`wire_catalog.json`, `chunked_list_schema.json`, `system_log_catalog.json`, `wide_int_catalog.json`, `spec_fixtures.bundle.json`, `consensus_core_manifest.json`, `proof_artifacts.json`, `term_registry.json`, `metrics_buckets.json`) from the source tree. Builds compare bundles byte-for-byte and block releases on drift.
- Each bundle entry carries SHA-256 digests, schema versions, manifest hashes, and Ed25519 signatures (ReleaseAutomationKey, CPReleaseKey) so downstream auditors can correlate prose and artifacts. Editors regenerate bundles when headings, entries, or fixtures change; the manifest maps section IDs to digests plus a Merkle tree root (`spec_hash_format="SpecHashV1"`).
- Proof provenance: releases publish `proof_bundle_schema_version`, `proof_bundle_sha256`, and detached signatures binding Loom/TLA+ archives, fixture suites, and feature manifests. Auditors recompute digests to validate artifacts without CI access.
- Fixture catalog: App.C’s clause-to-fixture map and wide-int registry feed deterministic `spec_fixtures.bundle.json`. Automation enforces coverage and rejects mismatched fixtures. Vendors add private fixtures but must retain canonical vectors (PreVoteResponse, ChunkedList, lease inequality, snapshot manifest, segment MAC, AEAD constant-time tests, crash-consistency harness, Jepsen/Jepsen-like scenarios).
- Startup spec self-tests rerun encoding fixtures, catalog regeneration, lease inequalities, incremental cadence, BLAKE3 vectors, and other checks before mounting partitions. Failures quarantine nodes and require operator override.
- Release evidence (`bundle_version`, `bundle_sha256`, `fixture_suite_ts`) is exposed via `/readyz` (`fixtures.bundle_version`, `fixtures.bundle_age_ms`). CI blocks release artifacts if bundle timestamp vs git tag differs by >86,400,000 ms (24 h).
- Runtime correctness MUST NOT depend on reading files from `/artifacts` or `/manifests`; binaries embed the necessary catalogs and expose them via APIs (`/.well-known/wide-int-registry`, `/readyz`). Artifact files only serve validation, audit, or tooling workflows outside the hot path. When `/artifacts` is absent (e.g., production images that strip optional bundles), nodes default to skipping startup validation by exporting `CLUSTOR_SKIP_ARTIFACT_VALIDATION=1`; operators who need the original fail-closed behavior instead set `CLUSTOR_REQUIRE_ARTIFACT_VALIDATION=1`, which forces bootstrap to error until the artifacts are restored.

Appendix B: Examples (Non-Normative)

B.1 PreVoteResponse Frames
- Frames serialize as `<u32 body_len little-endian> || body`. For `PreVoteResponse{term=42, vote_granted=1, has_high_rtt=1, high_rtt=1}` the body is `2a00000000000000010101` (12 bytes) and the full frame begins `0c0000002a00000000000000010101`. Legacy peers send only `term` and `vote_granted`, so their body is `2a0000000000000001` (9 bytes) and the full frame begins `090000002a0000000000000001`. Receivers treat missing extension bytes as “no `has_high_rtt` field present.” Frames that promise 12 body bytes but deliver only 9 (e.g., `0c0000002a0000000000000001`) must raise `WireBodyTooShort`.

B.2 Snapshot Manifest Sample
```
{
  "base_index": 4096,
  "base_term": 7,
  "chunks": [{
    "chunk_id": "00000000-0000-0000-0000-000000000001",
    "digest": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "len": 1048576,
    "offset": 0
  }],
  "content_hash": "0xb1caf4297447b97c418f5c52ac1b922c3c32022f61d59f73c462931b89d6ad86",
  "emit_version": 1,
  "encryption": {
    "dek_epoch": 3,
    "iv_salt": "0x000102030405060708090a0b0c0d0e0f"
  },
  "logical_markers": [],
  "manifest_id": "018c0d6c-9c11-7e9d-8000-86f5bb8c0001",
  "producer_version": "clustor-test",
  "version_id": 12,
  "snapshot_kind": "Full",
  "ap_pane_digest": "0x...",
  "dedup_shards": [],
  "commit_epoch_vector": []
}
```
Removing `content_hash` and `signature` before hashing yields the listed hash; signing the canonical encoding with the cluster’s `SnapshotManifestKey` produces `0xe6559247…ae d01`.

B.3 Segment MAC Vector
- MAC key bytes `00…1f`, `segment_seq=7`, `first_index=42`, `last_index=121`, `entry_count=17`, `entries_crc32c_lanes_bytes=0x1032547698badcfe67452301efcdab89`, `offsets_crc32c_lanes_bytes=0x0123456789abcdeffedcba9876543210` → `mac=5c50cc7f43ef3c0127db59a3a8394ed16782e7997b53093c35bff32f8644b8f0`.

B.4 AEAD Constant-Time Comparison
```
fn ct_equal_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 { diff |= a[i] ^ b[i]; }
    diff == 0
}
```
Implementations may wrap hardware intrinsics but must preserve this logic for conformance tests.

- B.5 CRC Lane Packing Example
  - Consider two entries:
    1. Entry A header/body bytes (hex): `01000000000010000000000000000000aa`.
    2. Entry B header/body bytes (hex): `01000000000008000000000000000000bb`.
  Concatenate headers and bodies to form the canonical stream `01000000000010000000000000000000aa01000000000008000000000000000000bb`. Splitting into 32-bit little-endian words and distributing across four lanes can, for illustration, use lane CRCs `{lane0=0x89ABCDEF, lane1=0x01234567, lane2=0xFEDCBA98, lane3=0x76543210}`. Packed little-endian bytes therefore equal `ef cd ab 89 67 45 23 01 98 ba dc fe 10 32 54 76`, which matches the illustrative value in §7.1. Offsets for the two entries (0 and 0x0000000000000010) serialized as contiguous little-endian u64 values `0000000000000000 1000000000000000` produce the same packed CRC `0x1032547698badcfe67452301efcdab89`. Tooling SHOULD replay this vector when validating lane implementations, but the CRC constants above are illustrative placeholders rather than computed CRC32C outputs for the example bytes.
