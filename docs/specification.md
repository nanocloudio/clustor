# Clustor – Raft Consensus Core
Version: Draft 0.1 (condensed)
Language: Rust (no GC runtime)
Deployment: Library crate + sidecar utilities shared across product binaries
Clustor is a Raft Consensus Core embedded as a library crate with sidecar utilities.

## Table of Contents
0. Specification Provenance & Wire Freeze
1. Architecture & Crash Model
2. Definitions & Vocabulary
3. Replication & Consistency Semantics
4. Partitioning & Topology
5. Log Entry Interfaces
6. Durability & Write-Ahead Log
7. Apply Pipeline & State Machine Hooks
8. Snapshots & State Transfer
9. Storage Layout, Encryption & Recovery
10. Flow Control & Backpressure
11. Control Plane – ControlPlaneRaft
12. Security & Isolation
13. Admin & Lifecycle APIs
14. Telemetry & Observability
15. Deployment & Bootstrap
16. Summary of Guarantees
Appendices A–E

### Appendix Cross-Index
| Appendix | Topic |
| --- | --- |
| Appendix A (App.A) | SLOs, alert thresholds, telemetry policies |
| Appendix B (App.B) | Operational profiles & limits |
| Appendix C (App.C) | Test matrix, fixtures, conformance helpers |
| Appendix D (App.D) | Wire envelope schemas & override scopes |
| Appendix E (App.E) | ChunkedList framing rules |

For automation that addresses appendices numerically, appendices A–E map to ordinal IDs 16–20 (A=16, B=17, …, E=20); spec-lint publishes the same alias list so tooling never depends on prose strings.
[Informative] Citation shorthand: whenever this spec references an appendix it uses the compact token `App.<Letter>` (e.g., `App.B`). Tooling auto-links the token to the cross-index above, so additional “see Appendix …” prose is unnecessary and discouraged for new text.

---

## 0  Specification Provenance & Wire Freeze (v0.1)

The Consensus Core is normative for v0.1; where conflicts exist, this section governs. Later sections cite the controlling clauses as “per §0.x” whenever they restate the invariants, and any divergence defaults to §0 without additional errata.

### 0.1 Specification Provenance

**Change Control:** spec-lint deterministically re-derives the normative bundles `wire_catalog.json`, `chunked_list_schema.json`, and `wide_int_catalog.json` (plus the shared fixture archive noted in App.C) from the shipping source tree on every build. Releases therefore fail if the prose and generated artifacts disagree, and any change to this section must land together with regenerated bundles so downstream auditors can diff byte-for-byte.

[Normative] The build also emits `consensus_core_manifest.json`, a hash chain that binds every numbered §0–§16 heading (and Appendix identifiers) to the SHA-256 digest of the generated bundles. spec-lint fails when any section hash changes without the manifest being regenerated, preventing renumbering or silent prose edits from producing bundles that auditors cannot correlate to the controlling text. The manifest MUST also embed `{proof_bundle_schema_version:u16, proof_bundle_sha256, proof_bundle_signature, feature_manifest_sha256}` so both proof artifacts and the feature manifest can be verified independently of the prose. `proof_bundle_schema_version` increments whenever the Loom/TLA+ archive format or signing process changes; `proof_bundle_signature` is a detached Ed25519 signature over `{schema_version || proof_bundle_sha256}` signed by the release automation key (public half published alongside the manifest). Nodes refuse to start if the schema version is unknown or the signature fails to verify, ensuring provers, feature declarations, and binaries remain in lockstep. The manifest additionally records `spec_sha256_tree_root`, the SHA-256 Merkle root derived from the per-section digests, giving auditors a single reproducible value to compare when reconstructing the spec hash tree.
[Normative] Each release ships a companion `proof_artifacts.json` that enumerates every Loom/TLA+ archive and supporting model artifact consumed by CI. Entries take the form `{artifact_name, sha256, size_bytes, download_uri}` and MUST match the bytes referenced by `proof_bundle_sha256`; auditors validate artifacts by recomputing the listed checksums without requiring CI access.
[Normative] Section hashes inside `consensus_core_manifest.json` are derived from a deterministic “SpecHash v1” byte stream so editors cannot influence the digest by changing encoding or line endings. SpecHash v1 converts every paragraph to UTF-8 NFC, rewrites CRLF/CR to LF, strips trailing horizontal whitespace, guarantees exactly one trailing newline per section, and omits any UTF-8 BOM before computing SHA-256. The manifest records `spec_hash_format="SpecHashV1"` and spec-lint refuses releases whose prose cannot be normalized, allowing auditors to reproduce the hash inputs exactly from the published Markdown.

### 0.2 Consensus Core (invariants)
- **Raft:** log matching, leader completeness, and monotone `commit_index` hold for every replica (§3.1).
- **Durability:** acknowledgements follow quorum `fdatasync(data_fd)`; `wal_committed_index` is monotone; `DurabilityTransition` entries fence every mode change so no batch straddles a transition (§6.2).
- **Reads:** Linearizability uses ReadIndex; leader leases are disabled by default. Crash-linearizable reads require `commit_visibility=DurableOnly` (§3.3).
- **Snapshots:** Full and incremental snapshots ship in v0.1. Imports require signed manifests, AEAD-authenticated chunks, and digest verification before state is touched (§8); incremental cadence follows the 10 s / 30 s rules in §8.4.
- **Startup scrub:** Always decrypt + verify AEAD tags in constant time → zeroize buffers on failure → verify CRC/Merkle/idx-MAC → act (§6.3). No plaintext may influence state before tag verification succeeds, and any AEAD failure quarantines the replica.

### 0.2 Defaults and Clause Classification
| Item | Default |
| --- | --- |
| `commit_visibility` | `DurableOnly` (Throughput may gate `CommitAllowsPreDurable`). |
| Leader leases | Disabled for all profiles. |
| Merkle enforcement | Mandatory for ControlPlaneRaft / DR / ZFS / Latency; optional elsewhere, default-off only for Throughput. |
| Observers | Supported in all profiles; Latency/ConsistencyProfile limit ≤2 per partition with dedicated bandwidth pool `0.1 × snapshot.max_bytes_per_sec`. |
| Durability mode | Strict on boot; Group-Fsync is opt-in with guardrails (§6.2). |

[Informative] To keep the separation between normative requirements, operational guidance, and informational context machine-readable, spec-lint now emits paragraph-level tags `[Normative]`, `[Operational]`, or `[Informative]` into the metadata bundle referenced above. Contributors SHOULD prefix new paragraphs with the appropriate tag (e.g., `[Normative] Crash-linearizable reads require …`) and spec-lint will reject mixed or missing tags once the migration completes. Until all legacy text is annotated, the default interpretation remains “normative unless otherwise tagged,” but downstream tooling can already consume the emitted metadata to filter for the required subset.

[Normative] Releases MAY NOT ship while any paragraph lacks an explicit tag. Spec-lint exposes `clause_tag_coverage` per file; cutting a public build requires `clause_tag_coverage = 100%` and the generated `wire_catalog.json`/`chunked_list_schema.json` bundles MUST embed the same coverage hash so auditors can prove the prose and artifacts were tagged together.
[Operational] Style guidance: use `reject`/`Reject` for API-level failures that return a cataloged error, reserve `MUST enter Quarantine` for state transitions, and use “fail closed” for read-path behavior. Mixing the verbs is now forbidden in lint, keeping audit language consistent.
[Informative] To limit terminology drift, every runtime noun or state MUST appear in §2.2’s vocabulary table; sections that introduce new names SHALL reference that table rather than re-describing synonyms inline.
[Normative] `[Deprecation]` is now a first-class tag for clauses that remain visible for operators but are superseded in a later minor. Spec-lint rejects any `[Deprecation]` paragraph that lacks `clause_superseded_by=<section/App token>` metadata or omits `deprecation_active_until_ms`. The metadata bundle mirrors those references so downstream auditors can prove which successor clause governs the replacement text, and release builds fail when the successor is missing.
[Operational] Contributors MUST only apply `[Deprecation]` when both the original clause ID and its successor are listed in the metadata bundle. Once the successor version is the sole normative text across all supported minors, either delete the deprecated paragraph or retag it `[Informative]` with the historical context; leaving stale `[Deprecation]` tags in place blocks `clause_tag_coverage = 100%`.

### 0.3 Wire/API Freeze (v0.1)
Frozen wire catalog for 0.1.x (new fields may append, no breaking changes):
- [Informative] App.C is the canonical source for the wide-int and `has_*` patterns, plus the per-message fixtures; §0.3 quotes the same rules only for readability. Spec-lint asserts byte-for-byte equality between this subsection and the App.C bundle so tooling always defers to a single machine-checked narrative.
- System entries: `MembershipChange (0x01)`, `MembershipRollback (0x02)`, `DurabilityTransition (0x03)`, `FenceCommit (0x04)`.
- [Normative] §11.4’s System Log Entry Catalog references the same IDs; spec-lint diff-checks `wire_catalog.json` and `system_log_catalog.json` so editors MUST regenerate both artifacts (and update §0.3/§11.4 together) before landing a new entry or renumbering an existing one.
- Messages: `DurabilityAck{partition_id, replica_id, last_fsynced_index, segment_seq, io_writer_mode}`, `PreVoteResponse{term, vote_granted, high_rtt}`.
- `PreVoteResponse` serialization: `{term:u64, vote_granted:u8, has_high_rtt:u8, [high_rtt:u8 when has_high_rtt=1]}`. v0.1 senders MUST set `has_high_rtt=1` and include `high_rtt ∈ {0=false,1=true}`. For backward compatibility, receivers MUST treat the absence of the tail bytes (i.e., legacy peers that omit `has_high_rtt`) as `has_high_rtt=0` and MUST ignore any additional tail bytes beyond the known optional fields when `body_len` allows skipping, per the general rule in §0.3. Frames whose `body_len` is shorter than the mandatory `{term(8) + vote_granted(1) + has_high_rtt(1)}` = 10-byte floor (or 9 bytes when legacy peers legitimately omit `has_high_rtt`) MUST be rejected as `WireBodyTooShort`. Future optional fields MUST follow the same “has_*/value” pattern so older parsers can skip them safely.
- Envelopes: `RoutingEpochMismatch`, `ModeConflict`, `ThrottleEnvelope`, and the shared `Why*` schema header.
- Encoding freeze:
  - Binary wires use little-endian fixed-width integers (`u8/u16/u32/u64` as declared) and 32-bit little-endian length prefixes for slices/strings. Arrays first carry a `u16` element count followed by tightly packed elements. Enumerations consume `u8` discriminants; new values append at the tail. Receivers MUST treat any discriminant beyond the highest cataloged value as `WireUnknownField` (never “best-effort” parsing) so forward compatibility remains fail-closed.
  - Enumerations reserve the `0xF0–0xFF` range as an explicit experimental block. Test-only builds MAY emit those discriminants only when both peers advertise `WireExtension::Experimental (0x40)` and `wire.experimental_range_enable=true`; production builds MUST fail closed with `WireExperimentalField` if any frame in the reserved block arrives. spec-lint enforces that GA catalogs never assign values inside the block, keeping experiments from colliding with future mainline IDs.
  - Lists that could exceed `u16::MAX` entries MUST be chunked across multiple envelopes/messages. v0.1 reserves `WideCount(u32)` extension IDs for v0.2 so implementers can plan a drop-in upgrade path without rewriting payload semantics; until that extension lands, every field that might grow beyond 65,535 elements must document its chunking rules. The canonical `ChunkedList` framing—including layout, CRC policy, receiver obligations, and JSON mirror rules—is defined in App.E. Fields that adopt `ChunkedList` MUST cite App.E and follow its behavioral requirements verbatim so streaming parsers can recover deterministically.
  - Unknown binary fields MUST be ignored when they appear after known fields and the enclosing length permits skipping; unknown mandatory fields before the known region cause `WireUnknownField` rejects. Implementations SHALL compute the minimum required byte length for all mandatory fields of a message; if the declared `body_len` (or envelope length) is shorter than that floor, the receiver MUST reject the payload as `WireUnknownField` even before parsing tail fields.
  - App.C (“Binary Schema & `has_*` Pattern Vectors”) publishes normative byte layouts plus pass/fail fixtures for the length-prefixed strings, arrays, and `has_optional_field` pattern described here. Implementations MUST round-trip those vectors exactly before claiming §0.3 compliance.
  - Every message/envelope is length-delimited: a 32-bit little-endian byte length (or message-specific 32-bit `body_len`) precedes the payload so receivers can skip unknown tail fields without stream corruption. Each catalog entry therefore declares a maximum `body_len`: unless noted otherwise, Raft RPCs and admin messages MUST set `body_len ≤ 4 MiB`, while Explain/Why*/Throttle envelopes MUST remain ≤32 KiB. The total frame on the wire is therefore `4 bytes (length prefix) + body_len`; no implementation may hide bytes outside that window, and the effective “frame cap” is `4 MiB + 4` for Raft RPCs and `32 KiB + 4` for envelopes. Receivers MUST begin parsing as a streaming read with bounded buffers and MUST abort with `WireBodyTooLarge` if `body_len` exceeds the catalog cap or if more than the declared length arrives on the wire (protecting against DoS). Payloads that exceed the cap MUST be rejected in their entirety—truncation or “best effort” processing is forbidden so that senders cannot smuggle partial frames past the cap. When a frame is shorter than the mandatory floor, both transports behave identically: gRPC replies with `INTERNAL` carrying `WireBodyTooShort`, and raw TCP peers emit the same `WireBodyTooShort` catalog code before tearing down the connection. Streaming parsers MAY buffer the entire payload only when the cap is ≤64 KiB; beyond that they MUST enforce a rolling window.
  - Large-frame roadmap: catalog bit `WireExtension::WideFrame (0x10)` is reserved for v0.2 so future snapshot-control or bulk-admin RPCs can negotiate `body_len` up to 32 MiB without fragmenting payloads. The sanctioned upgrade path is: (1) ControlPlaneRaft flips the `feature.wide_frame` gate, (2) both peers advertise `WireExtension::WideFrame` during the Raft handshake along with the negotiated `wire.max_body_len`, and (3) senders keep every RPC ≤4 MiB until the extension is observed in **both** handshake directions. v0.1 implementations MUST reject ad-hoc frame increases that attempt to bypass this sequence and MUST fall back to the 4 MiB cap whenever the extension bit clears mid-connection.
  - `WideCount(u32)` placeholder: v0.1 reserves `WireExtension::WideCount (0x11)` for payloads whose element counts may exceed `u16::MAX`. Until the extension is negotiated bidirectionally, senders MUST continue chunking via App.E and MUST bound every serialized `element_count` to `u16`. When both peers advertise `WireExtension::WideCount`, fields explicitly marked “wide count capable” MAY encode a `u32` count while maintaining the same `ChunkedList` framing; all other fields remain unchanged.
  - gRPC services always transmit enums numerically; JSON mirrors emit enum **strings** and also accept the numeric value for backward compatibility. Servers reject unknown enum **strings** with `WireUnknownField` (or HTTP 400) but MUST accept recognized numeric IDs so upgraded clients can talk to older servers. Field names and casing are frozen; clients must tolerate additive fields but reject missing required ones.
  - [Informative] JSON wide-int summary: App.C is the sole normative catalog for the JSONPath list, `json_numeric_exception_list`, `WireWideIntNotString`, and the golden `wide_int_catalog.json`. Per App.C, wide-integer fields (including every `*_ms` timestamp and ledger counter) continue to emit decimal strings even when the value fits inside `2^53-1`, optional numeric parsing is allowed only when `json.accept_numeric_wide_ints=true` and the token round-trips losslessly, and `entries_crc32c`/`offsets_crc32c` stay 34-character hex strings. This subsection captures the effect of that mandate so mainline docs and generators import the App.C bundle verbatim, expose `/.well-known/wide-int-registry`, and diff the generated catalog on every build instead of rephrasing the rules independently.
  - To keep client generators in sync, nodes MUST expose the same catalog at runtime via `GET /.well-known/wide-int-registry` (JSON). The payload is exactly the canonical artifact above (`schema_version`, list of JSONPaths, and exception list hash). Clients MAY cache it, but servers MUST update the endpoint whenever App.C changes so automation never scrapes prose to discover wide integers.
  - Machine-readable schema bundle: every build MUST emit a deterministic `wire_catalog.json` (system entries, RPCs, envelopes, enums, field ordering, byte widths) plus `chunked_list_schema.json` derived mechanically from §0.3 and Appendices C/E. Spec-lint fails the build if those artifacts drift from the prose, and release manifests MUST include the exact git hash of the emitted bundle so downstreams can diff their generators. Nodes carry the same bundle at runtime and refuse to start when the embedded bytes differ from the published catalog.
  - Forward-compatibility negotiation: transports MUST exchange `wire.catalog_version = {major:u8, minor:u8}` during the initial Raft handshake. Peers MAY communicate tolerance for one future minor by setting `WireExtension::ForwardCompat (0x20)` and advertising `forward_parse_max_minor = minor+1`; any larger gap forces the connection to close with `WireCatalogMismatch`. Major changes (e.g., 0.1 → 0.2) therefore require both ends to upgrade before traffic resumes, while minor bumps can flow one direction so long as the older peer sets `forward_parse_max_minor >= sender.minor`. During rolling upgrades, each side MUST validate both inequalities: `(remote_minor ≤ local_forward_parse_max_minor)` **and** `(local_minor ≤ remote_forward_parse_max_minor)`; violating either closes the transport before log traffic begins so asymmetric tolerances cannot silently downgrade safety. Older peers that advertise `forward_parse_max_minor = minor+1` MUST record that pledge in `bundle_negotiation_log` (the per-partition handshake transcript stored beside `wire_catalog.json`) and revoke it immediately after the handshake if the newer peer uses fields outside the catalog diff; skipping the revocation forces `WireCatalogMismatch` on the next RPC. The same version tuple MUST appear in `consensus_core_manifest.json` so bundle hashes, negotiation bytes, and ControlPlaneRaft durability proofs cannot diverge.
  - [Normative] Error code registry: spec-lint enforces the allocation table below so tooling has a single authoritative range map. Any change requires updating this subsection and regenerating the catalog in the same commit.

    | Range | Assignment |
    | --- | --- |
    | `1000–1089` | Mainline wire-level errors (e.g., `WireBodyTooShort=1001`, `WireBodyTooLarge=1002`, `WireUnknownField=1003`, `WireChunkMissing=1004`, `WireChunkOverlap=1005`). |
    | `1090–1099` | Vendor-specific extensions; downstream experiments MAY use these IDs but must relinquish them if Clustor later assigns the value. |
    | `1100–1199` | Reserved for future Clustor wire-level extensions after v0.1; vendors MUST NOT allocate from this block until §0.3 is updated with the concrete assignments. |
    | `2000–2010` | Control-plane availability errors (e.g., `ControlPlaneUnavailable{NeededForReadIndex}=2000`, `ControlPlaneUnavailable{CacheExpired}=2001`). |
    | `2011` | Snapshot fallback exhausted (`SnapshotOnlyUnavailable`). |
    | `2012` | Follower capability revoked (`FollowerCapabilityRevoked`), emitted when ControlPlaneRaft yanks the follower-read capability (§3.3). |

    gRPC enumerations SHALL use these numeric IDs verbatim, and JSON payloads SHOULD include the matching `error_code` field so telemetry and clients never rely on free-form strings.
  - `ChunkedList` receiver rules: chunks may arrive out of order. Receivers MUST deduplicate by `chunk_offset`, reject overlaps or gaps, verify that `∑ chunk_len == total_count`, and validate `chunk_crc32c` whenever the field requires it. Fields that legitimately omit the CRC MUST continue to perform strict offset accounting. Missing chunks MUST produce `WireChunkMissing`.

### 0.4 Negative Space (out of scope in v0.1)
- Lease reads and observers never contribute to quorum, ReadIndex, compaction, or durability.
- No relaxed crash model beyond fail-stop + ordered filesystems.
- ZFS deployments are treated as “ordered” only when `sync=always` pins intent log semantics (SLOG or main pool). Operators must ensure the SLOG/main pool pair delivers the same write-ordering guarantees promised in §1.2.1 or downgrade the filesystem profile.

### 0.5 Strict Fallback Gate (normative table)
`strict_fallback_state` ties every guardrail in §§3, 6, 8, 9, and 11 back to the Consensus Core. `LocalOnly` corresponds to `strict_fallback=true`. This table now lives in §0 so that future drafts cannot diverge without an explicit Consensus Core change; App.C only mirrors it for telemetry guidance.

| Operation | Healthy | LocalOnly | ProofPublished |
| --- | --- | --- | --- |
| Accept Strict-mode writes | Allowed | Allowed (forced Strict, `group_fsync=false`) | Allowed |
| Enable Group-Fsync / `DurabilityTransition{to=Group}` | Allowed (subject to other guards) | Reject with `ModeConflict(strict_fallback)` | Allowed |
| Expose `CommitAllowsPreDurable` reads | Allowed where profile permits | Forced `commit_visibility=DurableOnly` | Allowed |
| ReadIndex / linearizable reads | Allowed | Reject with `ControlPlaneUnavailable{reason=NeededForReadIndex}` | Allowed |
| Grant `follower_read_snapshot_capability` | Allowed when other caps satisfied | Reject (`FollowerCapabilityRevoked`/ControlPlaneRaft refuses bit) | Allowed |
| Enable delta snapshots / `snapshot_delta` APIs | Allowed | Reject with `ControlPlaneUnavailable{reason=CacheExpired}` | Allowed |

`ProofPublished` is a telemetry-only state indicating ControlPlaneRaft has mirrored the leader’s proof; once it lands, the gate behaves identically to `Healthy`.
[Normative] During `LocalOnly`, ReadIndex is always rejected regardless of cached proofs; only Snapshot-Only reads per §3.3 remain permitted until ControlPlaneRaft mirrors the durability proof.
[Normative] When `strict_fallback=true` and `controlplane.cache_state=Expired` occur simultaneously (common during extended ControlPlaneRaft outages), the stricter interpretation prevails: partitions remain in Strict mode, linearizable reads fail closed with `ControlPlaneUnavailable{reason=NeededForReadIndex}`, and admin operations that already require a fresh ControlPlaneRaft cache MUST fail with `ControlPlaneUnavailable{reason=CacheExpired}` even if the strict-fallback table would otherwise allow them. Implementations MUST NOT attempt to “partially” honor an operation because one state is less restrictive; instead, evaluate the strict-fallback truth table **and** the ControlPlaneRaft cache state, returning the first rejection reason per `StrictFallbackPriorityOrder` and surfacing the same ordering via telemetry (`strict_fallback_blocking_reason`). This keeps operators from seeing divergent gate decisions during long outages.
[Normative] Every transition of the strict-fallback decision logic MUST increment a monotone `strict_fallback_decision_epoch:u64`. All rejection telemetry (`strict_fallback_gate_blocked{operation}`, `ControlPlaneUnavailable{...}` driven by §0.5, `/readyz` fields, incidents) MUST carry the current epoch so overlapping rejections sharing the same predicate result can be correlated without appearing as flapping.
[Normative] `strict_fallback_state=LocalOnly` continues to authorize snapshot imports needed for DR so long as (a) the manifest’s ControlPlaneRaft signature validates against the last trusted keys, (b) the trust cache remains inside its dual-validity window, and (c) the import records `strict_fallback_snapshot_import_reason`. Imports MAY NOT clear strict fallback or advance ControlPlaneRaft durability proofs on their own, and any manifest authorized during LocalOnly MUST be revalidated once ControlPlaneRaft connectivity returns before compaction consumes it. Failed validations push the partition to Quarantine immediately even if the import initiated under LocalOnly.

---

## 1  Architecture & Crash Model

Clustor is a reusable Raft consensus core that embeds in higher-level services. All behavior is subordinate to §0.

### Goals
- Ship a replicated log + WAL stack with explicit hooks for encoding, apply, snapshot, and audit extensions.
- Align durability and ordering semantics with downstream terminology so products can map acknowledgment policies directly.
- Provide PID-style flow-control hooks for ingest-heavy services.
- Include ControlPlaneRaft for tenants, placements, keys, feature gates, and DR fencing.
- Deliver deterministic recovery, explainable throttling, and auditable operations.

### 1.1 Integration Targets & Use Cases
| Product | What Clustor Provides | Upper-Layer Responsibility |
| --- | --- | --- |
| MQTT Broker | Partitioned Raft log for session state + retained messages; ControlPlaneRaft tenancy objects | MQTT protocol, routing, QoS |
| Key-Value Store | Ordered log, snapshot shipping, placement metadata | Serialization, compaction, read serving |
| Control-Plane Services | ControlPlaneRaft tenancy, DR fencing, placement enforcement | API surface, orchestration, IAM |
| Streaming Processors | Flow-controlled append API with strict/batched durability and trace metadata | Payload encoding, windowing, higher-level semantics |

### 1.2 Architectural Guarantees
| Dimension | Guarantee |
| --- | --- |
| Consistency | Linearizable writes per partition; followers serve only `applied_index` checkpoints (§3.3). |
| Availability | Raft majority progress with hot-standby followers. |
| Durability modes | Strict (per-append fdatasync) and Group-Fsync (bounded batching with auto-downgrade). |
| Storage | Segment-structured WAL + signed snapshot manifests. |
| Telemetry | Uniform metrics, explain endpoints, signed audit streams. |
| Security | mTLS/SPIFFE, AEAD WAL/snapshots, keyed epochs. |

† Crash-linearizable reads require `commit_visibility=DurableOnly` (§1.2.1, §3.3) per the §0.2 default.
†† Follower-serving APIs are limited to signed snapshot exports or `FollowerReadSnapshot` capability surfaces; followers never respond to ReadIndex RPCs (§3.3).

> **Availability note:** Linearizable reads remain ControlPlaneRaft-dependent. During ControlPlaneRaft outages, leaders continue to accept writes in Strict mode but ReadIndex/follower reads fail closed with `ControlPlaneUnavailable{reason=NeededForReadIndex}` until ControlPlaneRaft acknowledges the durability watermark (§3.3). Users who require read availability during ControlPlaneRaft partitions must provision snapshot-only fallbacks or accept degraded semantics.

[Normative] Nodes MUST expose `/partitions/{id}:snapshot_read` (and the equivalent gRPC) during `strict_fallback_state ∈ {LocalOnly, ProofPublished}` with the header `read_semantics=SnapshotOnly`. Requests lacking the header continue to fail with `ControlPlaneUnavailable{reason=NeededForReadIndex}`; requests that include it return data exclusively from the latest durably verified snapshot (`manifest_id`, `base_index`, `content_hash`) plus the `applied_index` watermark recorded before the outage. Responses MUST carry `Snapshot-Only: true`, `Snapshot-Manifest-Id`, and `ControlPlane-Cache-Age-Ms` headers so clients can audit which checkpoint served the read.
[Normative] Even while ControlPlaneRaft durability proofs are stale, leaders MUST emit `partition_ready_ratio_snapshot`, `snapshot_manifest_age_ms`, and `snapshot_only_ready_state ∈ {Healthy, Degraded, Expired}` via telemetry and `/readyz`. `partition_ready_ratio_snapshot` is defined as `(applied_index_snapshot / last_advertised_ready_index)` clamped to `[0,1]` and is derived solely from locally persisted manifests so it remains valid without ControlPlaneRaft. Read fallback remains enabled only while the ratio ≥ `snapshot_only_min_ready_ratio = 0.80`; falling below forces snapshot reads to fail with `SnapshotOnlyUnavailable` and pages operators.
[Operational] The SnapshotOnly path carries an SLO of ≥99.5% success and ≤400 ms p99 latency for steady-state partitions; exceeding either threshold for `snapshot_only_slo_window_ms = 300000` increments `snapshot_only_slo_breach_total` and requires an incident. Dashboards MUST surface the SLO plus the readiness ratio so tenants know when reads are degraded but still within the documented guardrails.

#### 1.2.1 Crash Model & Visibility Policy
- Fail-stop crashes: dirty cache lost unless `fdatasync` completes; multiple replicas may fail simultaneously.
- Supported filesystems: XFS, ext4 with ordered barriers, or ZFS with `sync=always`. Bootstrap rejects incompatible mounts per the table below.

| Filesystem | Required policy | Notes | Enforcement outcome |
| --- | --- | --- | --- |
| ext4 | `data=ordered`, barriers and `auto_da_alloc` enabled, `commit <= 5`, `nojournal_checksum=false`, and device write cache configured for `write through` or `write back` with `fua=1`. `nobarrier`, `data=writeback`, `commit>5`, or `write_cache=unsafe` mounts are rejected. | `journal_async_commit` is recommended for latency but optional; operators must document deviations. | Reject the mount during bootstrap; node remains quarantined until policy-compliant settings are observed. |
| XFS | `logbsize >= 256k`, device reports `queue/write_cache ∈ {write through, write back}` with `queue/fua=1` or `queue/flush=1`. Mount options that disable barriers are disallowed even if ignored by the kernel. | Barrier enforcement is verified via `/sys/block/*/queue` capabilities rather than mount strings. | Reject on bootstrap or quarantine immediately if live telemetry diverges from the recorded capabilities. |
| ZFS | Dataset property `sync=always`, `logbias=throughput`, devices expose `queue/fua=1`. | Group-Fsync remains disabled unless devices prove `<20 ms` fsync (§App.B). | Allow Strict mode; quarantine Group-Fsync enablement until the fsync proof stays beneath the threshold. |
[Normative] Any future table that describes policy guardrails MUST reuse the `Enforcement outcome` header with `{Allow, Reject, Quarantine}` semantics so spec-lint can parse the Markdown mechanically and keep automation aligned with the prose.
- ZFS proof of `<20 ms` fsync: nodes MUST run the built-in `fsync_probe` (128 sequential `fdatasync`s against the WAL device) at bootstrap and every `zfs.fsync_probe_interval = 3600 s`. Results (`fsync_probe_p99_ms`, sample count, dataset GUID, device serial) are recorded in `boot_record.json` and telemetered to ControlPlaneRaft. Group-Fsync may only be enabled when the most recent probe shows `p99 ≤ 20 ms` and at least 128 samples; a regression above 20 ms for three consecutive probes forces automatic Strict downgrade with hysteresis matching `durability.max_device_latency_ms`.
- Mirrored SLOG devices that rely on asynchronous replication are acceptable only when the probe above still reports `p99 ≤ 20 ms`; otherwise Group-Fsync remains locked out even if individual devices appear healthy.
- The probe writes to a dedicated file under the same dataset/mount as the WAL (default path `wal/.fsync_probe/probe.bin`) so the measurement captures the exact storage stack. Each run truncates the file to `zfs.fsync_probe_bytes = 4 MiB`, issues the 128 `fdatasync`s, and then unlinks the file; no residual state remains beyond telemetry.
- Multi-device WAL environments (RAID, dm-crypt, dm-multipath) are permitted only when the **composite** stack can prove ordered flushes: every layer between the filesystem and physical media MUST advertise barriers and FUA, and operators MUST document the journaling or write-intent mechanism (e.g., MD journal mode, battery-backed cache) that preserves `pwrite → fdatasync` ordering. Stacks lacking such attestations are treated as “unknown filesystem” and quarantined until ControlPlaneRaft records an explicit `disk_override`.
  - `disk_override` objects are canonical JSON documents stored in ControlPlaneRaft and MUST match the schema below so tooling can diff overrides automatically:
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
    | `expires_at_ms` | string wide-int | RFC 3339 or epoch encoded per App.C so overrides cannot silently live forever. |
  Nodes MUST refuse the override if any field is missing, if `expires_at_ms` is in the past, or if the live `/sys/block/*` capabilities differ from the recorded tuple; quarantining remains the fallback if the operator cannot refresh the document in time.
- Supported OS matrix: v0.1 targets Linux kernels ≥5.15 with `io_uring`; other kernels/OSes are “best effort” only if they can prove the same cache/barrera semantics. Bootstrap rejects unknown platforms unless an explicit compatibility waiver is recorded in ControlPlaneRaft so operators cannot assume portability from the table above.
- For ext4 the phrase “barriers and `auto_da_alloc` enabled” means both safeguards must be on simultaneously (barriers enforced, `auto_da_alloc=1`); turning off either guardrail rejects the mount.
- `commit_visibility` governs whether `raft_commit_index` may exceed `wal_committed_index`:
  - `DurableOnly` (default) enforces equality for crash-linearizable reads.
  - `CommitAllowsPreDurable` (Throughput-only gate) allows a gap for lower-latency reads; leaders export gauges `commit_visibility_gap_entries` (count) and `commit_visibility_gap_ms` (time) and `alerts.commit_visibility_gap_ms` fires after 5 s (default).
- Client acknowledgements MUST satisfy §3.4 (ACK Contract) so that `wal_committed_index` reflects every ACKed write even when `CommitAllowsPreDurable` exposes Raft-only state to reads.
- Leaders reconcile `wal_committed_index` with the durability ledger on election; lacking proof forces Strict mode with leases + Group-Fsync disabled until the ledger or peers confirm durability (§3.1).

## 2  Definitions & Vocabulary

### 2.1 Definitions & Conventions
| Term | Meaning |
| --- | --- |
| `raft_commit_index` | Highest log index replicated on a majority; all references to `commit_index` imply this value unless qualified. |
| `wal_committed_index` | Highest index quorum-fsynced per §6.2. |
| `sm_durable_index` | Product-managed watermark indicating side effects are durably materialized (§7). |
| `quorum_applied_index` | Minimum `applied_index` observed across the most recent quorum heartbeat bundle; used as a compaction floor (§9.1). |
| `commit_visibility` | `DurableOnly` or `CommitAllowsPreDurable`; governs read exposure. |
| `lease_gap_max` | Profile-specific cap on `(raft_commit_index - wal_committed_index)` when leases are enabled; 0 disables leases entirely (§3.3, App.B). |
| `lease_epoch` | Monotone identifier on heartbeats; followers reject lease reads when epochs diverge. |
| `routing_epoch` | Placement version from ControlPlaneRaft (§4, §11). |
| `durability_mode` | `Strict` or `Group-Fsync`, with explicit `DurabilityTransition` fencing. |
| `wal.fs_block_bytes` | Filesystem-reported block size; all WAL buffers align to this value. |
| `wal.crypto_block_bytes` | Fixed AEAD block size (4 KiB, power-of-two) used for nonce counters; constant cluster-wide and recorded per segment (§9.2). |
| Encoding | Unless noted, binary integers are little-endian; manifests use UUIDv7/ULID big-endian ordering. |
| Epochs | Every `*_epoch` field is a monotone `u32` serialized little-endian in binary wires and as base-10 strings in JSON; regressions are treated as tampering (§9.2, §11.3). |
| `StrictFallbackPriorityOrder` | Ordered list `{CacheExpired, NeededForReadIndex, ModeConflict(strict_fallback)}` that defines the canonical rejection precedence for strict-fallback and ControlPlaneRaft cache decisions. |
[Normative] Time-unit convention: unless a clause explicitly cites hours/days for human readability, all configuration knobs and telemetry fields MUST be expressed in milliseconds and MUST carry the `_ms` suffix. Spec-lint’s `duration_unit_check` rejects identifiers that violate this rule or mix seconds/milliseconds for the same concept, ensuring generated schemas never disagree about units.

### 2.2 Terminology Normalization
| term_id | Canonical term | Synonyms in docs | Notes |
| --- | --- | --- | --- |
| `TERM-0001` | `Strict` | `Strict durability`, `Strict mode` | Means per-append `fdatasync` with no batching. |
| `TERM-0002` | `Group-Fsync` | `Group` | Batching mode guarded by `DurabilityTransition`. |
| `TERM-0003` | `DurabilityRecord` | `durability ledger entry`, `ledger watermark` | Always refers to `{term,index,segment_seq,io_writer_mode}` record in `wal/durability.log`. |
| `TERM-0004` | `FollowerReadSnapshot` | `follower read endpoint` | Snapshot-style, never linearizable. |
| `TERM-0005` | `LeaseEnable` | `lease gate`, `leader leases` | ControlPlaneRaft object that authorizes lease reads once `lease_gap_max > 0` and ControlPlaneRaft durability proofs are Fresh (§3.3). |
| `TERM-0006` | `SnapshotDeltaEnable` | `incremental snapshots`, `snapshot_delta` | ControlPlaneRaft capability that allows delta snapshots after follower readiness and cache freshness checks (§8, §11). |
| `TERM-0007` | `ControlPlaneRaft` | `control-plane cluster`, `control-plane Raft` | Dedicated Raft cluster that stores durable metadata (placements, durability proofs, feature gates, DR fences). |
| `TERM-0008` | `ConsistencyProfile` | `Consistency-focused profile`, `CAP Consistency-partitioned profile` | The consistency-prioritized runtime profile: strict durability by default; linearizable reads via ReadIndex/leases when gated. |

[Informative] This specification reserves the “CP” abbreviation solely for the Gilbert–Lynch CAP classification (Consistency-Partitioned) referenced by `ConsistencyProfile`; all other control-plane usages are spelled out as ControlPlaneRaft. Term IDs remain sorted numerically; the emitted `term_registry.json` provides an alphabetical index so tooling can diff additions without reordering this table.

Spec-lint enforces the casing shown above for every runtime state and lifecycle noun (`StrictFallback`, `LocalOnly`, `ProofPublished`, `Quarantine`, `RepairMode`, `StrictFallbackState`, etc.) so auto-generated docs and telemetry remain mechanically comparable; new terms must be added to this table before appearing elsewhere in the spec. [Normative] Telemetry, Explain payloads, and generated docs that refer to a runtime noun MUST include the matching `term_id` so downstream automation can round-trip without relying on string comparisons; spec-lint rejects any new noun whose row omits a `term_id`. [Normative] The `term_registry_check` gate in spec-lint executes pre-commit and in CI; it immediately fails when a diff introduces a capitalized noun that is absent from this table (or when an existing row changes without updating the associated `term_id`). Contributors therefore cannot land terminology changes unless the vocabulary table reflects them in the same patch.
---


## 3  Replication & Consistency Semantics
Clustor follows Raft with explicit guardrails.

### 3.1 Term/Index Invariants
The Raft invariants, durability monotonicity, and snapshot ordering rules are defined once in §0.2. This section consumes those clauses as the operational contract: leaders, followers, and tooling MUST enforce every bullet in §0.2 (“Consensus Core (invariants)”) and reference them verbatim when emitting telemetry or Explain traces (e.g., “per §0.2: Raft log matching” or “per §0.2: durability fence”). Implementation guidance:

- Persist `current_term` before AppendEntries; use §0.2’s Raft clause ID when logging compliance.
- Keep `wal_committed_index` ≤ `raft_commit_index` and force equality whenever `commit_visibility=DurableOnly` (label telemetry `consensus_core_invariant=durability`).
- Enforce the snapshot preconditions from §0.2 before deleting WAL bytes, surfacing the clause token in audit logs.
- During elections or recoveries, refuse leadership until the ledger proof cited in §0.2 (“Durability”) is reconstructed; the rejection reason SHOULD call out `§0.2.Durability`.

#### 3.1.1 Strict Fallback Gate Checklist
`strict_fallback=true` whenever the leader lacks a ControlPlaneRaft-published `(last_durable_term, last_durable_index)` proof that covers its current `raft_commit_index`. The flag clears only after the leader republishes a fresh proof. While `strict_fallback=true`, the following operations MUST hard-fail even if operators attempt Break-Glass overrides, and the leader MUST emit `strict_fallback_gate_blocked{operation}` telemetry for every rejection:

| Operation | Behavior while `strict_fallback=true` |
| --- | --- |
| `DurabilityTransition{to=Group}` (Group-Fsync enable) | Reject with `ModeConflict(strict_fallback)` and remain in Strict mode. |
| Lease enablement or any attempt to serve lease reads | Reject with `ControlPlaneUnavailable{reason=NeededForReadIndex}`; `lease_gap_max` enforcement stays at 0. |
| `follower_read_snapshot_capability` bit grant | ControlPlaneRaft MUST refuse the capability; follower endpoints stay disabled. |
| Incremental snapshot enablement (`snapshot.delta_chain_max > 0` or `snapshot_delta` APIs) | Reject with `ControlPlaneUnavailable{reason=CacheExpired}` until a proof lands. |

These failures are normative so every section (leases, durability, follower reads, snapshots) shares the same gate and drift is impossible. While `strict_fallback=true`, the runtime also forces `commit_visibility=DurableOnly` regardless of the prior profile setting so reads never race ahead of durability proofs.

Leaders that possess a locally `fdatasync`'d `wal/durability.log` covering their current `raft_commit_index` but lack quorum proof operate as follows:
- **Writes:** continue to accept appends in Strict mode (`strict_fallback_writes=Allowed`). Each append increments `strict_fallback_pending_entries`.
- **ReadIndex:** remain blocked until ControlPlaneRaft mirrors a proof whose `(term,index)` ≥ the leader’s `raft_commit_index`. Telemetry emits `strict_fallback_blocking_read_index=true` and `strict_fallback_last_local_proof=index`.
- **Telemetry transitions:** `strict_fallback_state ∈ {Healthy, LocalOnly, ProofPublished}`; transitions occur when (a) the leader loads its local ledger (`LocalOnly`) and (b) ControlPlaneRaft acknowledges the proof (`ProofPublished`, which clears the gate). Operators must page on `strict_fallback_state=LocalOnly` persisting beyond `strict_fallback_alert_ms` (default 30,000 ms).
- **LocalOnly timeout:** `strict_fallback_state=LocalOnly` that lasts longer than `strict_fallback_local_only_demote_ms = 14,400,000` (4 h) forces the leader to self-demote, emit `StrictFallbackLocalOnlyTimeout`, and page operators so partitions never run indefinitely without ControlPlaneRaft visibility. Overrides may pause the demotion only while the timer is explicitly renewed (Break-Glass scope `DurabilityOverride`).
- Profiles MAY tighten or loosen the timeout within App.B bounds by setting `strict_fallback_local_only_demote_ms_profile`; WAN/DR profiles typically raise the limit to 6 h so replicas with higher ControlPlaneRaft latency are not forced to demote prematurely, while the Latency/ConsistencyProfile profile keeps the 4 h default. Implementations MUST reject values outside their profile’s published window.
App.C (“Strict Fallback Gate Truth Table”) restates the admissible operations per `strict_fallback_state` so conformance tests and Explain APIs can assert the same matrix. Every release documents which invariants are machine-checked: the model-checking suite proves §3.1 term/index monotonicity, §3.1.1 gate enforcement, and the §3.4 ACK contract for both 3- and 5-voter clusters using Loom/TLA+. The build manifest MUST list the specific proof artifacts consumed by CI so auditors can trace them to the shipped binary.
[Normative] The `consensus_core_manifest.json` described in §0 SHALL embed `{proof_bundle_schema_version, proof_bundle_sha256, proof_bundle_signature}` referencing the exact Loom/TLA+ archive used for the release; binaries MUST refuse to start when either the schema version is unknown or the embedded hash/signature pair fails validation so formal proof provenance remains auditable.

### 3.2 Elections & Leader Stickiness
- Election timeout = uniform random `[150, 300] ms` (Throughput/Latency/ConsistencyProfile) or `[300, 600] ms` (WAN). Heartbeats every 50 ms. Randomness derives from independent ChaCha PRNG per partition.
- Pre-vote is always enabled. `PreVoteResponse.high_rtt=true` instructs candidates to widen the next election window to WAN range for one term; leases recompute bounds immediately.
- Followers set `high_rtt=true` only after `ema_heartbeat_rtt_ms >= pre_vote.high_rtt_threshold_ms(profile)` for `pre_vote.high_rtt_confirmations = 3` consecutive heartbeats (resets on any healthy heartbeat). This keeps widening opt-in to sustained latency spikes instead of transient pauses and makes the signal deterministic across vendors.

| Profile | `pre_vote.high_rtt_threshold_ms` |
| --- | --- |
| Latency / ConsistencyProfile | 150 |
| Throughput | 150 |
| WAN | 350 |

- Telemetry exports `clustor.raft.pre_vote_high_rtt_threshold_ms` (per partition) and `clustor.raft.pre_vote_high_rtt_trip_total` so operators and test harnesses can assert the same constants. App.C simulators cover both edges of the threshold.
- High-RTT widening applies per follower: only the partition that observed `high_rtt` stretches its timeout, and it reverts to the profile default after one successful heartbeat or a completed election. Randomization for other partitions remains unchanged to avoid cross-cluster synchronization.
- Leader stickiness: `min_leader_term_ms = 750 ms`. Forced step-down occurs on structural lag (§10.2), device latency overruns (`durability.max_device_latency_ms`), or ControlPlaneRaft `TransferLeader`. Device latency enforcement uses hysteresis: a leader must see `N=3` consecutive fsync samples above the threshold or a moving-average window (`durability.device_latency_window_ms = 500`) exceeding the bound before stepping down. Recovery requires `M=5` consecutive samples below 80% of the threshold to clear the `DeviceLatencyDegraded` flag and resume normal transfers, preventing flip-flop.
- Backoff: failed elections multiply timeout by 1.5 up to 2 s; resets after a leader survives `min_leader_term_ms`.
- AppendEntries RPC timers (per follower): `append.rpc_timeout_ms = clamp(2 × ema_heartbeat_rtt_ms, 100, 1000)` with up to 4 inflight batches. Timeouts double once (max 2×) until a response arrives.

### 3.3 Read Paths
- [Normative] Leader leases are a production feature in v0.1 and provide linearizable reads without issuing ReadIndex round trips when the lease predicate holds. A partition MAY enable leases only when (a) the inequality below evaluates true using the profile constants, (b) `strict_fallback=false`, (c) `commit_visibility=DurableOnly`, (d) `controlplane.cache_state=Fresh`, and (e) every voter reports `clock_guard_alarm=0`. Violating any clause immediately revokes leases and forces the partition back to ReadIndex.
- [Normative] Profile defaults determine whether leases are active on boot: Throughput profiles ship with `lease_gap_max_profile=1024` and `lease_enable_default=true`, the Latency/ConsistencyProfile profile defaults to `lease_gap_max_profile=0` (leases off by default but fully supported once operators configure a non-zero gap), WAN profiles keep `lease_enable_default=false`, and ZFS profiles inherit their parent’s default but require `strict` durability. Admin APIs MAY adjust `lease_gap_max` within the bounds published in App.B, but the runtime only transitions `lease_gate_runtime_state` to `Enabled` when the inequality, ControlPlaneRaft freshness, and strict-fallback conditions are satisfied. Telemetry `leases_enabled`, `lease_epoch`, and `lease_gate_runtime_state ∈ {Enabled,Disabled,Revoked}` MUST be exported so tooling can correlate lease availability with the read gate and strict-fallback truth table.
- ReadIndex is the default linearizable read path. Leaders that restarted must replay through `commit_index` before serving reads. Algorithmically: on start, block every read until `applied_index >= preserved_raft_commit_index_at_start`. Under `commit_visibility=DurableOnly`, further require `wal_committed_index == raft_commit_index` and satisfy the predicate in §3.3.1; otherwise respond with `ControlPlaneUnavailable{reason=NeededForReadIndex}`.
- Canonical comparison above normalizes `updated_at` into RFC 3339 (UTC, millisecond precision) strings on both sides and encodes integers little-endian inside the proof blob; spec-lint replays the same canonicalization so JSON caches and binary ledgers remain comparable without lossy conversions.
- `commit_visibility` determines crash semantics (§1.2.1). Leaders export `commit_visibility_gap_*` gauges. Under `DurableOnly`, a leader MAY NOT serve reads (even ReadIndex) until it reloads `wal/durability.log`, proves `wal_committed_index == raft_commit_index`, and the predicate in §3.3.1 evaluates to true; any transient divergence during elections is therefore masked from clients.
- If ControlPlaneRaft is unreachable, freshly elected leaders still accept writes under Strict durability but MUST fail linearizable reads (ReadIndex, follower-read fallbacks) with `ControlPlaneUnavailable{reason=NeededForReadIndex}` until ControlPlaneRaft accepts the durability watermark and the §3.3.1 predicate succeeds.
- Every `ControlPlaneUnavailable{reason=NeededForReadIndex}` response carries retry guidance so clients can fall back cleanly: HTTP surfaces `Retry-After` (minimum 250 ms, encoded as a base-10 integer milliseconds value per RFC 7231’s delta-seconds form) plus `X-Clustor-Last-ControlPlane-Durable: term:index` and `X-Clustor-Commit-Index: term:index`; gRPC mirrors emit metadata `{retry_after_ms, controlplane_last_durable_term, controlplane_last_durable_index, leader_commit_term, leader_commit_index}`. Clients MUST treat these responses as transient (HTTP 503 / gRPC `UNAVAILABLE`) and either retry with exponential backoff or downgrade to documented snapshot-style reads when their semantics allow it. Vendors MUST document any alternate behavior, but silent busy loops are prohibited.
- [Operational] SDKs SHOULD implement a uniform decision tree when dealing with read failures: (1) on `ControlPlaneUnavailable{reason=NeededForReadIndex}`, retry with jittered backoff up to the provided `Retry-After`, then (2) if the product surface documents a snapshot fallback, retry once with `read_semantics=SnapshotOnly`, and (3) if the fallback returns `SnapshotOnlyUnavailable`, stop retrying and surface the failure because every replica is below the advertised readiness ratio. This ordering keeps retries bounded, ensures Snapshot-only reads are never issued without the explicit header, and makes telemetry (`snapshot_only_ready_state`) align with client-visible behavior.
- This deliberate fail-closed behavior means **Strict-mode writes continue while linearizable reads block** any time ControlPlaneRaft cannot prove durability. Products MUST therefore ship snapshot or otherwise clearly-documented fallback read endpoints by default so customers retain diagnostic visibility during ControlPlaneRaft partitions; launching without such a fallback requires an explicit exception from the safety review board.
- Followers NEVER service ReadIndex. They only expose reads via signed snapshot exports or `FollowerReadSnapshot` endpoints that stream `applied_index` checkpoints after a ControlPlaneRaft-granted capability bit is set; speculative apply buffers remain private. The capability stays revoked unless the partition runs in Strict durability (Group-Fsync disabled), advertises `commit_visibility=DurableOnly`, and the follower proves `applied_index >= advertised_checkpoint`. ControlPlaneRaft yanks the bit immediately when any guard fails.
- Follower endpoints clamp every response to their current `applied_index`, never service linearizable RPCs, and must be documented to clients as “snapshot-style” reads that fall back to leader ReadIndex on version or epoch mismatch. Responses MUST carry `read_semantics = SnapshotOnly` (HTTP header or gRPC metadata) plus the exporting `routing_epoch`, otherwise clients MUST treat the reply as invalid. In-flight snapshot reads MUST fail closed with `FollowerCapabilityRevoked` if the capability bit is yanked during transmission (e.g., quarantine). Revocation is synchronous: within `follower_capability_revocation_grace_ms = 100` the runtime MUST abort every outstanding follower-read RPC and strip cached authorizations so clients never continue using a revoked capability.
- Enforcement detail: each follower-read RPC carries a cancellable token that re-checks the capability bit on every heartbeat tick (`heartbeat_period_ms = 50`) and on ControlPlaneRaft/telemetry revocation interrupts; the transport closes the stream immediately when the token fires, ensuring the ≤100 ms grace even on slow clients and making the mechanism portable across runtimes.
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

- Clock skew bounds derive from the node’s `clock_guard` service: each replica samples its PHC/PTP clock (preferred) or chrony/NTP discipline every `clock_skew_sample_period_ms = 1000`, computes the absolute offset from the cluster’s monotonic fence (derived from ControlPlaneRaft heartbeats and a GPS/PTP reference), and raises a “skew alarm” when two consecutive samples exceed the profile’s `clock_skew_bound_ms`. Alarmed nodes immediately revoke leases (once enabled), mark `lease_gate_runtime_state=HardDisabled`, and surface `clock_guard_alarm{bound_ms, observed_ms, source}` telemetry so operators can trace the upstream time source.
- [Normative] When a skew alarm fires while the node is leader, it MUST voluntarily step down within `clock_guard_alarm_stepdown_ms = 500` even if leases are disabled so that replicas with suspect clocks cannot continue issuing ReadIndex responses or acking writes without fresh elections. The voluntary step-down also cancels any in-flight pre-vote or election timer on that node to prevent rapid re-campaigning while the skew alarm remains asserted.
- Clock discipline requirements: PHC/PTP sources MUST advertise `max_slew_ppm ≤ 20`, `clockClass ≤ 7`, and jitter `< 5 ms` over any 60 s window; chrony-based deployments MUST enable `makestep 1.0 -1` (step on any >1 ms jump during boot) and cap `maxslewrate 400 ppm`. Nodes log both the raw PHC offset and the chrony-supplied dispersion so operators can prove compliance during audits.
- [Normative] Lab or test environments that lack PHC/PTP MUST declare `clock_guard_source = NtpOnly` at bootstrap. NTP-only nodes relax—but do not remove—the skew bounds to `{Latency/ConsistencyProfile: 15 ms, Throughput: 20 ms, WAN: 60 ms}` and continue sampling every 1,000 ms. In this mode leases remain hard-disabled, but ReadIndex MAY proceed so long as the observed skew stays below the relaxed bound; exceeding it still triggers the 500 ms leader step-down. Telemetry MUST publish `clock_guard_source`, `clock_guard_fallback_bound_ms`, and `ntp_only_mode=1` so auditors can distinguish production-grade clocks from test rigs, and spec-lint rejects builds that attempt to run NTP-only without setting the telemetry flag.

- Regardless of profile, leases are hard-disabled whenever `commit_visibility=CommitAllowsPreDurable`; the inequality above is evaluated only once the partition returns to `DurableOnly`.
- `lease_gap_max` (App.B) bounds `(raft_commit_index - wal_committed_index)` while leases are active; exceeding it immediately revokes leases and emits `LeaseGapExceeded`.
- Followers invalidate leases on epoch changes, skew alarms, two missed heartbeats, Group-Fsync downgrades, or stickiness resets. Lease responses include `(lease_epoch, routing_epoch, durability_mode_epoch)` and clients must fall back to ReadIndex on mismatch.
- Clients requiring read-your-write semantics under `CommitAllowsPreDurable` must wait for `last_quorum_fsynced_index >= ack_index`.

#### 3.3.1 Read Gate and Strict-Fallback Interplay (Normative)
[Normative] A leader MAY serve a linearizable ReadIndex request at time *t* only if all of the following clauses hold simultaneously:
- `strict_fallback == false`.
- `commit_visibility == DurableOnly`.
- `controlplane.cache_state == Fresh`.
- `controlplane.proof.term:index == wal.last_quorum_fsynced_term:index`.
- `wal_committed_index == raft_commit_index`.
If any clause fails, the node MUST fail closed with `ControlPlaneUnavailable{reason=NeededForReadIndex}` or `ControlPlaneUnavailable{reason=CacheExpired}` per `StrictFallbackPriorityOrder`.

[Normative] Additional handling requirements:
- `strict_fallback` always overrides ControlPlaneRaft durability proof freshness. Leaders MUST NOT serve reads while `strict_fallback == true`, even if a cached proof matches the ledger byte-for-byte. Cached proofs may only clear strict-fallback after being published into ControlPlaneRaft per §11.1.
- `Fresh` means `(a)` `controlplane.cache_age_ms ≤ controlplane.cache_fresh_ms` **and** `(b)` the cached proof tuple `{term,index,segment_seq,io_writer_mode,updated_at,controlplane_signature}` matches the on-disk `wal/durability.log` entry byte-for-byte.
- The runtime MUST abort in-flight reads within 50 ms whenever `controlplane.cache_state` transitions out of `Fresh` or `strict_fallback` flips to `true`.
- Follower read capabilities are revoked whenever the predicate above evaluates to false and MAY be reinstated only after `strict_fallback == false` **and** the predicate evaluates to true again.
- When multiple causes apply, the rejection reason priority remains the `StrictFallbackPriorityOrder`.
- Implementations MUST export telemetry fields `read_gate.can_serve_readindex` (bool) and `read_gate.failed_clause ∈ {StrictFallback, CommitVisibility, ControlPlaneCacheNotFresh, ControlPlaneProofMismatch, IndexInequality}` so tooling can assert predicate outcomes.

### 3.4 ACK Contract (Normative)
Leaders may emit a client ACK only when every clause below is simultaneously satisfied for the `ack_index` being returned:
1. **Raft commitment:** `ack_index <= raft_commit_index` and the entry is replicated on a quorum in the current term.
2. **Quorum durability evidence:** The leader has received and persisted a quorum of `DurabilityAck{last_fsynced_index}` records showing `last_fsynced_index >= ack_index`. Followers must append the matching `DurabilityRecord` to `wal/durability.log` **and `fdatasync` that log** (see §6.5) before replying so that the leader can rebuild the proof after crashes.
3. **Leader durability:** The leader has locally persisted through `ack_index`. Strict mode requires `fdatasync` completion for the entry itself; Group-Fsync requires the batch covering `ack_index` to have completed `fdatasync` and to have recorded the batch watermark in `wal/durability.log`.
4. **Ledger alignment:** The leader advanced `wal_committed_index` to at least `ack_index` and recorded that watermark before sending the client response.

These rules make equality of `raft_commit_index` and `wal_committed_index` a leader-side invariant under `DurableOnly` and prevent crash regressions when `CommitAllowsPreDurable` is enabled for reads. Violations must surface as `AppendDecision::Reject(Consistency)` and emit guardrail telemetry.

Leader crashes after counting a follower’s `DurabilityAck` but before emitting the client response are safe: the new leader reconstructs the quorum proof from `wal/durability.log` and either (a) replays the same ACK once it revalidates the ledger, or (b) withholds the ACK if quorum evidence is missing. Client APIs MUST therefore carry an idempotency key (`AppendRequest.idempotency_key`, shared with the admin API header) so callers can distinguish “ACK lost in flight” from “not acknowledged”—servers repeat the same `ack_index` for duplicate keys once the contract is satisfied.

---

## 4  Partitioning & Topology
- Logical keys hash to Raft Partition Groups (RPG). Products choose the hash, but partition IDs must be stable with ≥128-bit entropy.
- Default replica set: 3 voters; DR profile supports 5. Observers (telemetry-only) are supported in every profile and are always excluded from quorum, ReadIndex, durability, and compaction. Latency/ConsistencyProfile deployments may attach up to two observers per partition (same limit as Throughput/WAN) once ControlPlaneRaft authorizes the placements.
- Observer streams consume a dedicated bandwidth pool capped at `observer.bandwidth_cap = 0.1 × snapshot.max_bytes_per_sec` per partition so they cannot starve snapshot or learner pipes; once the pool is exhausted, observers receive `ThrottleEnvelope{reason=ObserverBandwidth}` and leaders emit `observer_bandwidth_exhausted`.
- [Normative] Observer admission participates in the strict-fallback truth table: while `strict_fallback=true` or `controlplane.cache_state ≠ Fresh`, ControlPlaneRaft refuses to grant or renew observer slots and leaders MUST revoke `observer_capability_state` from existing observers within 100 ms, surfacing `observer_capability_revoked_reason ∈ {StrictFallback, ControlPlaneCacheNotFresh}` via telemetry.
- Leaders gate all writes and ReadIndex. Followers execute `on_commit` to stay hot for failover and snapshot export; speculative buffers never expose uncommitted state.
- Clients target leaders discovered via ControlPlaneRaft placements. Requests MUST carry the latest `routing_epoch`; stale or missing epochs return `RoutingEpochMismatch{observed, expected, lease_epoch, durability_mode_epoch}` (HTTP 409 / gRPC `FAILED_PRECONDITION`).

### 4.1 Membership & Resizing (Normative)
1. **Preflight:** ControlPlaneRaft runs placement feasibility (≤70% budgets post-move) and deterministic quorum rehearsal (§4.2). Failures return reasons; optional overrides require audit records.
2. **Catch-up:** New replicas join as `Learner` and must reach either `(commit_index - membership.catchup_slack_bytes)` with default 4 MiB (auto-scaled by throughput) **or** `(leader.last_log_index - membership.catchup_index_slack)` with default 1024 entries inside `membership.catchup_timeout = 120 s` (auto-scaled). Meeting either guard suffices; policy may demand both.
3. **Joint consensus:** After catch-up, Raft enters joint config. `min_leader_term_ms` blocks voluntary transfers. Each `MembershipChange`/`MembershipRollback` records the rehearsal `placement_digest`.
4. **Finalize:** After `joint_commit_count >= membership.finalize_window` (default 64) and no structural lag (§10.2), the leader commits the pure new set and mirrors the decision into ControlPlaneRaft.
   - “No structural lag” is codified as `lag_bytes < 64 MiB` AND `lag_duration < 30 s` (i.e., still within the “Transient” class from §10.2). If either bound is exceeded, finalization MUST pause until the lag returns to the transient band or ControlPlaneRaft explicitly grants `flow.structural_override`.
5. **Rollback triggers:** catch-up timeout, loss of ≥f voters for `membership.rollback_grace_ms = 3000 ms`, or survivability precheck failure. Rollback appends `MembershipRollback{reason, failing_nodes[]}`, commits under the joint quorum, persists the durability ledger watermark for that index, and only then does the leader step down so the next election increments term.

### 4.2 Survivability Precheck
- `quorum_survivability_precheck` enforces deterministic guardrails:
  - `Q`: fraction of single fault-domain losses that retain quorum (voters only). Minimums: 3-voter `Q=1.0`, 5-voter `Q>=0.8` (profiles may raise, never lower).
  - `H`: headroom ratio (post-move CPU/disk utilization vs budget). Default floor 0.2.
  - Advisory `F`: fraction of voters on independent power/network; surfaced via Explain APIs.
- Fault domains are hierarchical (`zone > rack > chassis`). ControlPlaneRaft snapshots labels when the move starts; label changes abort the move.
- Overrides require `survivability.policy=Advisory`. Latency/ConsistencyProfile deployments default to `Strict` (no overrides). Throughput/WAN may override only `H` with signed justification.
- Catch-up slack and timeout auto-scale with observed throughput and RTT (clamped 10–500 ms); dry-run APIs surface computed values (§13.2).

---

## 5  Log Entry Interfaces
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
- AEAD/MAC semantics referenced in this subsection defer to §9.2; the bullets below describe only the segment-level layout that consumes those primitives.
- Integer fields are little-endian; manifests retain big-endian UUIDv7/ULID ordering.
- `trailer_len` counts the exact bytes serialized after the body. Frames MUST store at least the 4-byte CRC (`trailer_len >= 4`). `trailer_len = 4` means the CRC is present without a Merkle leaf for that frame; `trailer_len = 36` includes both the CRC and the 32-byte `merkle_leaf`. Profiles that mandate Merkle trees MUST reject frames whose `trailer_len < 36`. `trailer_len = 0` is invalid for v0.1 and receivers treat it as corruption.
- Hash primitives: CRC32C always covers `header || body`. `merkle_leaf = H(header || body || crc32c_le)` where `crc32c_le` is the 4-byte little-endian CRC value and `H` is the selected `integrity.hash_suite`.
- Metadata extensions: required `trace_id`, `span_id`, `ingest_timestamp_ms`; bounded to `entry.metadata_budget_bytes` (default 256 B, up to 1 KiB via policy). Missing metadata yields `AppendDecision::Reject(MetadataMissing)`.
- Frame sizing: `entry.max_frame_bytes = 1 MiB` for Latency/ConsistencyProfile, up to 4 MiB for Throughput/WAN (hard stop 4 MiB). Buffers must align to `wal.fs_block_bytes`; misaligned inputs route through `FrameStagingPool`, which throttles at 80% partition or node budgets (64 MiB per partition, 1 GiB per node) and emits `FrameAlignment` throttles.
- Products register codec IDs globally and implement deterministic `encode_entry` / `decode_entry` functions.
- Validation hooks may veto appends (`before_append`). Rejections must carry retry hints.
- `integrity.hash_suite` is selected once per cluster generation (default CRC32C leaves + SHA-256 segment/manifests). Throughput and WAN profiles MAY opt into BLAKE3 leaves once every voter advertises support and ControlPlaneRaft records the `integrity.hash_suite=blake3` epoch; Latency/ConsistencyProfile and ZFS profiles remain on SHA-256. Switching suites requires draining segments that reference the prior hash, `strict_fallback=false`, `controlplane.cache_state=Fresh`, and a matching entry in `feature_manifest.json`; violating any clause immediately revokes `integrity.hash_suite=blake3` and forces the cluster back to SHA-256.

#### 5.1 Segment Integrity MAC (Mandatory)
- Every WAL segment ends with `segment_mac_trailer{version:u8, mac_suite_id:u8, segment_seq:u64, first_index:u64, last_index:u64, entry_count:u32, entries_crc32c:u128, offsets_crc32c:u128, mac:[u8;32]}`.
- `entries_crc32c` is derived by splitting the concatenated entry `{header || body}` stream into 32-bit words, interleaving them across four lanes (`word_index mod 4`), computing CRC32C per lane, then packing the little-endian lane CRCs into a 128-bit value (`lane0` least significant, `lane3` most). `offsets_crc32c` applies the same procedure to the sequence of 64-bit offsets (treated as two 32-bit words each). This binds both payload bytes and their positions, preventing “valid frame moved to a new offset” attacks even when Merkle leaves are disabled. JSON mirrors emit both fields as fixed-length `0x`-prefixed hex strings (32 hex characters, little-endian interpretation).
- The packed `u128` values above are serialized little-endian (lane0 least significant byte, lane3 most significant byte) regardless of host architecture so tooling on big-endian systems must swap accordingly.
- Worked example: suppose `lane0=0x89ABCDEF`, `lane1=0x01234567`, `lane2=0xFEDCBA98`, `lane3=0x76543210`. The packed byte stream is `[EF CD AB 89 | 67 45 23 01 | 98 BA DC FE | 10 32 54 76]` (lane0 first). The emitted JSON string is `0x1032547698badcfe67452301efcdab89` (32 hex digits after the prefix). Receivers MUST reject strings that are shorter/longer than 34 characters or whose hex payload does not match the packed little-endian value; App.C adds explicit acceptance/rejection tests (including mixed-case hex).
- `mac_suite_id` selects the MAC algorithm. v0.1 fixes `mac_suite_id=1 = HMAC-SHA256` and readers MUST reject unknown IDs (`UnknownSegmentMacSuite`). Future suites require a new ID plus a ControlPlaneRaft-approved `integrity_mac_epoch` bump; segments MUST NOT mix multiple MAC suites even across re-encryptions.
- `mac_suite_id=2` is reserved for `BLAKE3-MAC`. Nodes MUST treat the value as “unsupported but reserved” until ControlPlaneRaft explicitly raises `integrity_mac_epoch` to a build that implements it, preventing collisions with vendor experiments.
- `mac` = HMAC-SHA256 keyed by the epoch-specific MAC key. The input bytes are the ASCII string `segment-mac-v1` (no terminator) followed by the little-endian encoding of `{segment_seq:u64 || first_index:u64 || last_index:u64 || entry_count:u32 || entries_crc32c:u128 || offsets_crc32c:u128}`. Implementations MUST preserve that order and width exactly; omitting the prefix or re-encoding the integers is a wire break. App.C (“Snapshot Manifest & Segment-MAC Test Fixtures”) publishes a reference vector using key `00..1f`, `segment_seq=7`, `first_index=42`, `last_index=121`, `entry_count=17`, `entries_crc32c=0x1032547698badcfe67452301efcdab89`, and `offsets_crc32c=0x0123456789abcdeffedcba9876543210`, which yields MAC `5c50cc7f43ef3c0127db59a3a8394ed16782e7997b53093c35bff32f8644b8f0`. Production keys MUST NOT reuse the test key.
- [Normative] ControlPlaneRaft issues `segment_seq_allocator_epoch` leases in each partition manifest; replicas MUST persist `{segment_seq_head, segment_seq_allocator_epoch}` before allocating bytes for a new WAL segment and MUST advance the head monotonically. Detecting either duplicate `segment_seq` values or `segment_seq < segment_seq_head` (locally or via ControlPlaneRaft durability proofs) forces immediate Quarantine because ControlPlaneRaft relies on `segment_seq` monotonicity to prove replay ordering. Every durability proof therefore includes the `{segment_seq_allocator_epoch, segment_seq}` pair so auditors can diff ControlPlaneRaft state against the ledger.
- The MAC suite is independent of `integrity.hash_suite`; v0.1 therefore mandates `mac_suite_id=1` for every trailer even when BLAKE3 leaves are enabled, and a segment MUST NOT mix multiple MAC suites.
- The trailer is written only after all entries land on disk, then `fdatasync`'d alongside the `.log`. Replay refuses to trust a segment whose MAC fails, regardless of profile Merkle settings. `.idx` files remain MAC-protected but are now advisory helpers rather than the root of trust for entry placement.
- When `integrity.hash_suite` disables Merkle leaves (Throughput profile default), the trailer MAC becomes the sole detection signal for relocation or bit-rot. Operators must rely on §6.4 scrub coverage to detect intra-segment corruption and should expect lower detection granularity than when Merkle trees are enabled.

---

## 6  Durability & Write-Ahead Log

### 6.1 Fsync Semantics
- WAL segments are preallocated (default 1 GiB; ZFS ≥2 GiB) and written with aligned buffers. Each append uses `pwrite` followed by `fdatasync(data_fd)` in Strict mode; Group-Fsync defers `fdatasync` per batch but keeps ordering `data → index` and dir `fsync` only on rollover.
- “Ordered filesystem” above refers to kernels that honor Linux’s `O_DSYNC`/`RWF_DSYNC` guarantees: write completion implies the corresponding journal transaction (if any) reached persistent media and all dependent metadata was durably recorded. Operators who cannot provide Linux 5.15+ with XFS/ext4 semantics MUST present an engineering note that shows equivalent ordering (e.g., vendor whitepaper for XFS on write-through NVMe); absent that, the stack is treated as “unordered” and quarantined at bootstrap.
- Every segment closes with the mandatory `segment_mac_trailer` from §5.1; leaders flush the trailer, then `fdatasync` the `.log` and `.idx`, and finally `fsync` the directory entry before marking the segment deletable.
- Directory `fsync` occurs only on file create/rename/rollover (explicitly including new `wal/durability.log` generations and ledger truncations) and manifest publication per §8.1. Platforms lacking direct I/O must still honor aligned writes and `fdatasync` ordering.
- WAL writer prefers `io_uring` with fixed buffers, downgrading to registered buffers or blocking I/O transparently while emitting telemetry.
- Downgrades enforce guardrails: moving from fixed buffers to registered buffers or blocking I/O clamps `group_fsync.max_batch_ms = min(2 ms, configured)` and `group_fsync.max_batch_bytes = min(32 KiB, configured)`, emits `PerformanceModeDegraded{from_mode,to_mode}`, and raises an incident if the condition persists for `io_writer_mode.downgrade_incident_ms_profile` (App.B; default 5,000 ms). SLO dashboards track the new baseline explicitly so degraded hardware cannot silently violate §10 targets.
- Health samples are recorded once per durability flush completion (Strict `fdatasync` or Group-Fsync batch) and at least every `io_writer_mode.sample_period_ms = 200` via a watchdog so the `N`-sample gates below compare equivalent wall-clock windows across replicas.
- `io_writer_mode ∈ {FixedUring(0), RegisteredUring(1), Blocking(2)}` and is included in `DurabilityAck` so leaders know which guardrails followers are honoring. Any node advertising `Blocking` is barred from Group-Fsync until it reports `RegisteredUring` or better for `io_writer_mode.recovery_window_ms = 60000`.
- Leaders MUST keep the partition in Strict mode (no Group-Fsync batching) whenever any voter reports `io_writer_mode=Blocking`; observers/learners do not gate this decision. The gate lifts only after all voters return to `RegisteredUring` or better for an entire `io_writer_mode.recovery_window_ms` window.
- To avoid perpetual lockout when a single replica remains degraded, the leader starts `io_writer_mode.degraded_grace_ms_profile` (App.B; default 300,000 ms) as soon as it observes a voter stuck in `Blocking`. When the grace elapses, the leader MUST either (a) demote the degraded replica to `Learner` via the membership workflow or (b) eject it from the voter set if demotion fails. After demotion, Group-Fsync eligibility is recalculated against the remaining voters, and the degraded replica may rejoin only after it sustains `RegisteredUring` (or better) for one full recovery window.
- To avoid flap storms, a leader also requires `io_writer_mode.recovery_sample_count = 5` consecutive healthy samples from every voter before re-enabling Group-Fsync; any relapse to `Blocking` resets the timer and sample counter. Telemetry emits `io_writer_mode_gate_state ∈ {Open, BlockedByBlockingFollower, RecoveryTimer}` so operators can diagnose why batching is disabled.
- `wal.segment_bytes` tunable: Latency/ConsistencyProfile/Throughput `[256 MiB, 2 GiB]`, WAN `[512 MiB, 2 GiB]`, ZFS `[2, 4] GiB`. All writes align to `wal.fs_block_bytes` and exported via metrics for Explain APIs.
- Tooling that reasons about `entries_crc32c`/`offsets_crc32c` can assume at most `wal.segment_bytes / entry.max_frame_bytes(profile)` frames per segment (e.g., Latency/ConsistencyProfile ≤256 frames at 1 MiB caps for a 256 MiB segment, Throughput/WAN ≤512 frames at 4 MiB caps for a 2 GiB segment); exceeding those bounds requires first bumping the profile’s explicit `entry.max_frame_bytes`.

### 6.2 Group-Fsync Guardrails
| Parameter | Default | Behavior |
| --- | --- | --- |
| `group_fsync.max_batch_bytes` | ≤ profile ceiling (64 KiB default) | Exceeding forces immediate flush; runtimes MAY adapt downward based on telemetry but MUST never exceed the ceiling.
| `group_fsync.max_batch_ms` | ≤ profile ceiling (5 ms default) | Timer flush; resets per batch; adaptive controllers MAY shorten the window when devices degrade but MUST never exceed the safety bound.
| `group_fsync.max_inflight_bytes_per_partition` | 4 MiB | Breach parks the partition and forces flush.
| `group_fsync.max_inflight_bytes_per_node` | 64 MiB | Node-level cap halts appends until catch-up.
| `group_fsync.overrun_limit` | 2 | Consecutive overruns trigger Strict downgrade.
| `group_fsync.backoff_factor` | 2× | Re-enable delay = `group_fsync.backoff_base_ms` (App.B; default 60,000 ms) × factor^downgrade_count (≤15 min).

A partition’s controller MAY use telemetry (io_uring latencies, device class) to set tighter runtime limits, but the per-profile ceilings above remain hard safety bounds shipped in artifacts and gates like §0.2 keep them immutable without a spec update. Downgrade counters, hysteresis timers, and the exponential backoff are tracked **per partition**; node-level incidents MAY add additional throttles, but they never reuse another partition’s backoff state.
[Normative] Implementations MUST drive re-enables from an identical predicate so controllers, telemetry, and Explain APIs agree:
```
fn can_enable_group_fsync(state: &PartitionState) -> bool {
    if state.strict_fallback { return false; }
    if state.controlplane_cache_state != CacheState::Fresh { return false; }
    if state.downgrade_backoff_deadline > now() { return false; }
    if state.voters.iter().any(|v| v.io_mode == Blocking) { return false; }
    if state.device_latency_violations_in_window >= 3 { return false; }
    if state.incident_flags.contains("GroupFsyncQuarantine") { return false; }
    true
}
```
`downgrade_backoff_deadline` is the exponential timer derived from `group_fsync.backoff_factor`. `device_latency_violations_in_window` is the same counter that triggers Strict downgrades in §6.1. Vendors MAY add stricter predicates, but they MUST evaluate the logic above verbatim and emit `group_fsync_eligibility=false` (with the first failing clause) whenever the predicate returns false so operators can reconcile automation with runtime decisions.

Acknowledgements remain quorum-`fdatasync`; unacknowledged exposure is bounded by the inflight caps. Downgrades emit `DurabilityTransition{from=Group,to=Strict,effective_index}` after flushing entries ≤ `N` and immediately disable batching until the transition commits. Re-enables append the inverse transition only when ControlPlaneRaft is reachable and do not share batches across the fence. `DurabilityAck` records `{last_fsynced_index, segment_seq}` durably so leaders count quorum only after persisted acknowledgements.

Re-enables remaining ControlPlaneRaft-gated is an intentional safety choice: batching without ControlPlaneRaft coordination risks asymmetric durability policies and audit gaps. During ControlPlaneRaft outages the cluster therefore stays in Strict mode (per-append `fdatasync`) even if the underlying I/O remains healthy; expect higher latency/throughput cost, document it in incidents, and re-enable Group-Fsync only after ControlPlaneRaft returns and logs the transition.
[Operational] Recovery runbook: once ControlPlaneRaft connectivity is restored, leaders MUST (1) refresh `wal/durability.log` proofs, (2) confirm `controlplane.cache_state=Fresh`, (3) re-run device health checks, and only then (4) issue `DurabilityTransition{to=Group}`. If any step fails, partitions remain in Strict until the blocking condition clears, ensuring operators have a deterministic checklist after prolonged ControlPlaneRaft outages.

### 6.3 Startup Scrub & Repair

#### 6.3.1 Preconditions
- [Normative] Startup scrub executes before a replica advertises readiness or participates in quorum, and it MAY NOT be skipped even when nodes boot in repair mode.
- [Normative] The scrub engine operates solely on on-disk bytes; RAM caches and speculative buffers are ignored so that the scrub outcome is reproducible.

#### 6.3.2 Procedure
1. Scan tail segments, authenticating AEAD per block and validating `segment_mac_trailer` before CRC/Merkle checks.
2. Rebuild `.idx` files when missing/corrupt using deterministic metadata `{term, index, offset, body_len, crc32c}` plus optional Bloom filters.
3. Verify `wal/durability.log` records and refuse to mount when gaps exceed WAL tails.
4. Truncate partial tail entries deterministically; AEAD or MAC failures quarantine the partition.
5. Record `boot_record.json` with scrub status, durability watermark, WAL geometry, and `io_writer_mode`; replicate to ControlPlaneRaft.
- CRC/Merkle failures with a valid MAC are treated as repairable corruption: the segment is marked `needs_repair`, scrubbed via snapshot import, and only escalates to quarantine if retries continue to fail or the MAC later disagrees (§6.4).

Decision table (normative for scrub tooling and operator docs):

| AEAD tag valid? | MAC valid? | CRC/Merkle valid? | Action |
| --- | --- | --- | --- |
| Yes | Yes | Yes | Healthy. |
| Yes | Yes | No | Repair path: mark `needs_repair`, rehydrate via snapshot/import while keeping the replica online but alerting operators. |
| Yes | No | * | Immediate Quarantine — MAC disagreement means integrity epoch cannot be trusted regardless of CRC result. |
| No | * | * | Immediate Quarantine — ciphertext MUST NOT influence state when AEAD authentication fails. |

`*` = don’t-care (ignored once a prior column dictates quarantine).

- Repair loops MUST apply exponential backoff: after each `needs_repair` import attempt that fails integrity checks, the runtime waits `scrub.repair_backoff_ms = min(2^attempt * 1000, 60000)` before retrying and records `repair_attempt_count` plus `repair_in_progress=true` in `boot_record.json`. After `scrub.repair_attempt_limit = 3` consecutive failures (without a successful manifest re-validation) the replica MUST escalate to Quarantine even if the MAC remains valid, preventing infinite oscillation against a flaky object store.

#### 6.3.3 Postconditions
- [Normative] Successful scrub yields a monotone `boot_record.scrub_state=Healthy`, replays through the last durable index, and emits `startup_scrub_duration_ms`.
- [Normative] Any scrub outcome other than Healthy MUST set `boot_record.scrub_state ∈ {NeedsRepair,Quarantine}` and cite the blocking clause so automation can fan out to the repair or quarantine workflows described below.

### 6.4 Background Scrubbing & Quarantine
#### 6.4.1 Background Scrub Loop
- `scrub.interval = 6 h` sampling 1% of entries per segment (or full CRC when Merkle disabled). Coverage SLO: every WAL byte hashed at least once every 7 days; metric `scrub.coverage_age_days` enforces this.
- Failure-injection conformance set: every vendor MUST exercise the following crash kill points at least once per release and prove the outcomes match App.C expectations: (a) kill after WAL `pwrite` but before `fdatasync`, (b) kill after `fdatasync` but before `wal/durability.log` append, (c) kill after ledger append but before client ACK, (d) kill during `.idx` rebuild, and (e) kill between `NonceReservationRange` flush and data write. The crash-consistency harness enumerates these five points explicitly so downstream implementations cannot silently skip a class of failures.

#### 6.4.2 Repair Escalation State Machine
- Any checksum, AEAD, or MAC anomaly triggers quarantine: block writes, request re-replication, emit incident log. Exit requires a full snapshot + WAL rebuild.

### 6.5 Durability Ledger Ordering (Proof Obligation)
- Each replica maintains `wal/durability.log` beside the WAL. Records are append-only `DurabilityRecord{term, index, segment_seq, io_writer_mode, record_crc32c}` entries; each record asserts that the local WAL bytes through `(term, index)` have completed the fsync described in §6.1 while the node was operating in `io_writer_mode`. `record_crc32c = crc32c(le(term) || le(index) || le(segment_seq) || io_writer_mode)` (Castagnoli polynomial) and MUST be verified before the record is trusted so partial-sector writes or torn headers are detected even when the surrounding CRC appears intact. Records never rewrite in place—monotonicity is enforced by rejecting regressions.
- Followers persist the `DurabilityRecord` that covers the index they will advertise in the next `DurabilityAck{last_fsynced_index, segment_seq, io_writer_mode}` and MUST block the ack until the `durability.log` `fdatasync` from step 4 completes so leaders can reconstruct quorum proofs after crashes.
- Leaders and followers therefore execute the identical sequence `pwrite → fdatasync(data_fd) → durability.log append → fdatasync(durability.log)` regardless of role. Spec-lint’s `ledger_ordering_test` replays the ordered steps on both sides and fails the build if either implementation attempts to reorder or coalesce them, preventing asymmetric crash recovery.
- Before appending a `DurabilityRecord`, replicas MUST verify from the on-disk WAL (not process buffers) that the referenced `(term, index)` bytes are readable, that the header/body region matches the expected length, and that the frame-level CRC32C recalculated from those on-disk bytes matches the stored value. If the verification fails—even on allegedly “ordered” filesystems—the replica MUST retry the read after a randomized backoff (`durability.read_verify_retry_ms ∈ [5,20]`) to filter transient device stalls. After a single retry, if the bytes are still unreadable the replica MUST delay the ledger append, re-run startup scrub, and enter Quarantine if the mismatch persists; advertising durability evidence without readable bytes is forbidden.
- **Ledger replay (§6.5):** on startup, replicas scan `wal/durability.log` sequentially and verify each record’s `{term,index,segment_seq,io_writer_mode}` against the WAL bytes. Encountering a hole or corrupted record forces deterministic truncation to the last verified entry; all trailing records are discarded (never skipped) and the replica enters Strict fallback until ControlPlaneRaft mirrors a fresh proof. Nodes MUST NOT attempt to “skip over” damaged records because that would fabricate durability evidence.
- [Normative] `truncate_file_to(last_good_offset)` MUST call the platform’s synchronous primitive (`ftruncate` on POSIX, `SetEndOfFile` followed by `FlushFileBuffers` on Windows) and MUST immediately `fdatasync`/`FlushFileBuffers` the descriptor before replay advances. Lazy truncation helpers that defer the shrink to background threads are forbidden because ControlPlaneRaft durability proofs assume the discarded bytes are irrecoverable once `consensus_core_manifest.json` seals the bundle.
- [Normative] Background scrubbers, log-rotation daemons, or compaction threads MUST NOT invoke `truncate_file_to` asynchronously or from worker threads that do not immediately wait for the synchronous `fdatasync` above; every caller routes through the replay thread so auditors can reason about a single serialization point for truncation.
- [Normative] Clauses §6.5-(1)…(5b) define the linearizable prefix relied upon by `last_quorum_fsynced_index` and the ControlPlaneRaft durability ledger. Implementations therefore MUST record `{linearizable_prefix_term, linearizable_prefix_index, segment_seq}` alongside the local proof tuple they publish to ControlPlaneRaft, and spec-lint’s `ledger_prefix_proof_test` rejects binaries that attempt to ACK a client before that prefix is durable.
- Leaders compute `last_quorum_fsynced_index` from the intersection of their local `DurabilityRecord` and the quorum of follower acknowledgements. Formally, let `A = {leader_local_index} ∪ {ack_i | ack_i reported by follower i}`. Sort `A` descending and select the highest index `n` such that at least `quorum_size = floor(voters/2)+1` elements of `A` satisfy `value >= n`. That `n` becomes `last_quorum_fsynced_index`, and it always refers to a ledger record (not an in-flight append). They mirror only the resulting `(last_durable_term, last_durable_index)` summary into the ControlPlaneRaft durability ledger (§11.1) once the ordering below reaches step 4; ControlPlaneRaft entries are rejected unless they advance that pair.
- Ordering rule for every replicated entry (clauses §6.5-(1) … (5b)):
  1. Append entry bytes to the WAL segment (`pwrite`).
  2. Complete the WAL `fdatasync` (Strict) or batch flush (Group-Fsync). No ledger or ACK action may occur before this step finishes.
  3. Append the new `DurabilityRecord` (and any coalesced `NonceReservation`, see §9.2) so that it covers `entry.index`.
  4. `fdatasync(wal/durability.log)`.
  5. After clause (4):
     (5a) The leader MAY count follower `DurabilityAck`s toward quorum only if they cover indices ≤ the freshly `fdatasync`'d record.
     (5b) The leader MAY emit the client ACK (§3.4) only after clause §6.5-(5a) succeeds.
- Followers execute the exact same sequence locally and MUST complete steps (1)–(4) before emitting their `DurabilityAck{last_fsynced_index, ...}`. An ack that arrives before the follower `fdatasync`'s both the WAL bytes and the matching `DurabilityRecord` is a protocol violation and must be treated as missing evidence.
- Nonce reservations are range-based. Writers append `NonceReservationRange{segment_seq, start_block_counter, reserved_blocks}` entries measured in units of `wal.crypto_block_bytes`. v0.1 fixes `wal.crypto_block_bytes = 4096 B`; the default reservation window therefore remains `nonce.reservation_max_blocks = 1024` (4 MiB), but profiles MAY raise it via `nonce.reservation_max_blocks_profile ∈ [1024, 8192]` (upper bound 32 MiB) when higher-latency devices benefit from larger amortization. `nonce.reservation_max_bytes = wal.crypto_block_bytes × nonce.reservation_max_blocks_profile` is emitted in the profile bundle and spec-lint rejects configs outside the range. Reservations MUST `fdatasync` no later than the smaller of `nonce.reservation_max_bytes_profile` bytes of newly reserved space or `nonce.reservation_flush_ms = 5` ms (tracked per partition, never coalesced). When a partition flushes a WAL batch for any reason, it MUST also flush any pending reservation entry before acknowledging the batch. On restart, the next block counter resumes at `max(start_block_counter + reserved_blocks)`; therefore the largest benign “hole” scrub may encounter equals the configured `nonce.reservation_max_bytes_profile`. The runtime tracks both `wal.nonce_reservation_gap_blocks` and `wal.nonce_reservation_gap_bytes` (largest contiguous reserved-but-unused window) plus `wal.nonce_reservation_gap_events_total`; exceeding the profile-tunable `nonce.reservation_gap_quarantine_threshold_bytes` (default 4 MiB, max 8 MiB under Break-Glass) raises `NonceReservationGapWarning`. The threshold compares strictly against the contiguous metric `wal.nonce_reservation_gap_bytes`; auxiliary counters such as `wal.nonce_reservation_gap_bytes_cumulative` remain observational only and MUST NOT page or quarantine on their own. Mandatory Quarantine only triggers when (a) the same gap exceeding the threshold is observed across two consecutive boots, or (b) the gap coincides with any scrub/integrity failure in the same segment, or (c) the implementation detects a reused `(dek_epoch, segment_seq, block_counter)` tuple (which remains immediate Quarantine). Hitting three threshold-crossing gap events within `nonce.reservation_gap_incident_window_ms = 86,400,000` also escalates to Quarantine unless the operator applied a Break-Glass exception before the third event. Operators who know a workload will create large benign gaps must raise the threshold explicitly (with ticket) before the workload runs.
- Overflow is forbidden: `start_block_counter + reserved_blocks` MUST stay ≤ `u64::MAX`, and implementations SHALL reject (and page) any attempt to allocate a reservation that would wrap the counter space.
- When a segment is rewritten or abandoned (e.g., re-encryption, repair), replicas MUST append `NonceReservationAbandon{segment_seq, abandon_reason}` to `wal/durability.log` after proving that every block in the reservation range was either written or explicitly zeroed. Compaction engines across the quorum MUST observe either (a) every reservation range for that `segment_seq` marked “fully spent” (i.e., `max_written_block >= start + reserved_blocks`) or (b) a committed `NonceReservationAbandon` before unlinking any WAL bytes tied to that `segment_seq`.
- [Informative] The nonce lifecycle can therefore be viewed as a finite-state machine shared across §6.5 and §9.2:
```
Reserve --(blocks written)--> Spent
Reserve --(scrub observes unused window ≤ 4 MiB)--> GapObserved
GapObserved --(second boot or scrub failure)--> Quarantine
Reserve --(segment rewrite/repair)--> Abandoned
Abandoned --(ControlPlaneRaft acknowledges + compaction)--> Retired
Spent --(compaction rule satisfied)--> Retired
```
Only the `GapObserved → Quarantine` edge is automatic; all other transitions require the ledger entries described above. Auditors can therefore inspect `NonceReservationRange`, `NonceReservationAbandon`, and scrub telemetry to prove every `(segment_seq, block_counter)` pair is either Spent or explicitly Retired before the WAL bytes disappear.
- The happens-before chain is therefore:

```
AppendEntries payload
  → WAL pwrite
  → `fdatasync` WAL data file (or flush the current Group-Fsync batch) while keeping index/directory ordering
  → durability.log append
  → `fdatasync` `wal/durability.log`
  → `fsync` the WAL directory entry when a new segment/ledger file is created or rotated
  → quorum DurabilityAck counted (derives last_quorum_fsynced_index)
  → client ACK (per §3.4)
```

Any crash between these edges preserves either (a) WAL data without a `DurabilityRecord` (forcing Strict fallback on replay) or (b) the `DurabilityRecord` without a client ACK, which remains safe because the ACK contract refuses to respond without step 5 completing. New leaders must load `wal/durability.log`, recompute `last_quorum_fsynced_index`, and publish the resulting `(last_durable_term, last_durable_index)` into ControlPlaneRaft before serving writes (§3.1, §11.1).

### 6.6 Quarantine Lifecycle
Quarantine is a named runtime state with a single purpose: halt new writes until integrity doubts are cleared. The state machine is:

| Transition | Trigger | Allowed operations while quarantined | Exit requirements |
| --- | --- | --- | --- |
| Healthy → Quarantine | AEAD/MAC/CRC failure (§6.3/§6.4), repeated `ApplyOutcome::Fatal` (3 within 60 s), dropped `AckHandle`s (3 within window), partial re-encryption detected (§9.2), admin `AdminPausePartition`, disk policy violation (§15.1). | Read-only APIs (snapshot export, telemetry), Explain/Why*, `AdminResumePartition` (Break-Glass), snapshot import for repair. No appends, no membership changes, no durability transitions. | Complete snapshot import or WAL rebuild that replays through `wal_committed_index`, incident ticket referencing remediation, ControlPlaneRaft acknowledgement (`QuarantineCleared`) recorded, and supervisor restart. |
| Quarantine → RepairMode | Operator sets `bootstrap.repair_mode=true` for offline work. | Same as above plus data-plane listeners stopped. | Successful repair and `AdminResumePartition`. |
| Quarantine → Decommissioned | Operator deletes replica/partition. | None (partition removed). | N/A |

Every entry/exit emits an audit log with `{partition_id, reason, ticket}`. While quarantined, Explain APIs must return `WhyQuarantined{reason, since_ms}` so clients understand the condition; observers cannot override it.
[Normative] Quarantine reasons are typed so read-only allowances remain unambiguous: `Integrity` covers AEAD/MAC/CRC failures, re-encryption faults, and disk hygiene violations; `Administrative` covers `AdminPausePartition`; `ApplyFault` covers repeated `ApplyOutcome::Fatal` or AckHandle drops. Integrity quarantines MUST disable new snapshot exports and follower-read capabilities entirely until ControlPlaneRaft acknowledges `QuarantineCleared`; operators may only retrieve already-signed manifests via metadata APIs, never stream chunks. Administrative pauses MAY continue serving snapshot exports (always marked `Snapshot-Only: true`) so tenants can drain state, but these exports MUST advertise `quarantine_reason=Administrative`. ApplyFault quarantines inherit Integrity behavior for follower reads but MAY continue exporting the last verified snapshot when `snapshot_only_ready_state=Healthy`. Telemetry MUST expose `snapshot_exports_blocked_reason ∈ {Integrity, ApplyFault, None}` so automation can correlate API availability with the quarantine class.

Commit-index monotonicity is logical (client-facing). Repair actions may truncate local WAL segments below the last advertised `commit_index`, but nodes MUST NOT report a lower `raft_commit_index`/`wal_committed_index` to clients after quarantine. Explain/Why* APIs, telemetry, and admin surfaces therefore continue to emit the pre-quarantine watermark until a fresh proof is republished. While quarantined, leaders serve reads **only** from the last verified snapshot/`applied_index` checkpoint that predates the quarantine event; they MUST NOT materialize new snapshots or follower-read checkpoints until the repair completes, preventing operators from accidentally exporting partially repaired state. Instead, the recovered replica remains paused (no writes, follower reads disabled) until it replays through the prior `commit_index` or imports a snapshot covering it and proves—via a fresh durability ledger record—that `wal_committed_index` continuity holds. Only after that proof is mirrored into ControlPlaneRaft may the replica rejoin quorum, preserving the monotone guarantee exposed to clients.

---

## 7  Apply Pipeline & State Machine Hooks
- Every committed entry executes `on_commit(batch: &[EntryView], ctx: ApplyContext)` on leaders and followers. `on_commit` returns `ApplyOutcome::{Ack, Retryable{reason}, Fatal}`. Fatal outcomes force leader step-down and quarantine the replica until replay succeeds.
- `on_applied(last_applied)` publishes watermarks for upper layers. `sm_durable_index` must persist in product storage and never exceed `raft_commit_index`.
- `ApplyContext` exposes async `AckHandle` so products can defer durability confirmation without stalling Raft.
- Crash recovery replays from `wal_committed_index`, and products must reject duplicate side effects above their persisted `sm_durable_index`.

### 7.1 Apply Budget SLA
| Parameter | Default | Notes |
| --- | --- | --- |
| `apply.max_batch_ns` | 2 ms p99 | Leaky bucket increments per breach; drains at 2/s. |
| `apply.budget_breach_threshold` | 5 | Crossing triggers `apply_budget_breach`, PID credit penalty ≤50%, and optional operator overrides. |
| `apply.max_batch_entries` | 512 | Batches beyond this split automatically. |
| `apply.handoff_queue_len` | 1024 | 90% utilization emits `ApplyQueueNearFull` and throttles credits. |
| `ack_handle.max_defer_ms` | 250 ms | Upper bound for deferring `AckHandle::complete`; timer enforced even for products that opt out of crash-linearizable reads. |
| Forbidden work | Blocking syscalls during `on_commit`; use `ApplyDeferredQueue` + `AckHandle`. |

Profiles set per-partition ceilings for `ack_handle.max_defer_ms` via App.B: Latency/ConsistencyProfile partitions remain capped at 250 ms, Throughput partitions may raise the ceiling to 400 ms, and WAN partitions may raise it to 500 ms. Implementations MUST reject configs that exceed their profile’s ceiling even if the local default is lower.

`ApplyOutcome::Fatal` trips a supervisor poison pill; 3 fatals within 60 s trigger a 5 s backoff before campaigning again. The `apply.max_batch_ns` limit is enforced as a sliding-window p99 over the most recent `apply.p99_window_batches = 10,000` batches per partition (windows <10 samples fall back to max), preventing jitter from tiny samples while still catching sustained regressions quickly.

Profile overrides: App.B publishes the per-profile ceiling for `apply.max_batch_ns`. The Latency/ConsistencyProfile profile inherits the 2 ms p99 ceiling above; Throughput profiles may raise it to 4 ms (documented in the profile bundle) to accommodate larger codecs, while WAN profiles cap at 5 ms because RTT dominates. Implementations MUST enforce those ceilings per partition profile and reject configs that exceed them.

### 7.2 Idempotency & Replay
- Each `EntryView` carries `dedupe_token = (term, index)`; caches MUST evict entries `< snapshot_index` and bound themselves by `apply.dedupe_max_entries = 1M` or `apply.dedupe_max_bytes = 128 MiB`.
- Cold-start replay blocks client reads/writes until `applied_index >= raft_commit_index_at_election`. `ApplyContext.random_seed` is reused on replay for determinism.
- `ApplyOutcome::Retryable` requires explicit reason codes (`TransientIo`, `CodecMismatch`, `QuotaExceeded`, `Backpressure`).

### 7.3 AckHandle Lifecycle
- `AckHandle::complete()` (or `AckHandle::fail(reason)`) MUST be invoked before `ack_handle.max_defer_ms` elapses. The runtime arms a deadline per handle; exceeding it automatically converts the entry into `ApplyOutcome::Retryable{reason=AckTimeout}` and rolls the partition back to the last durable index before accepting more writes.
- Dropping an `AckHandle` without resolving it triggers the same timeout behavior immediately and increments `apply.ack_handle_drop_total`. Three consecutive drops within `ack_handle.drop_window_ms = 1000` quarantine the partition until a supervisor clears the fault, preventing upper layers from silently starving `applied_index`.
- Products that legitimately need longer work must explicitly opt into `ApplyDeferredQueue` with sharded handles and surface their own user-facing status; the runtime still enforces the global deadline to uphold visibility guarantees from §3.4.

### 7.4 Aggregator Allowance Profile
[Normative] Partitions that run quantile/top-k/distinct aggregations MAY opt into the `Aggregator` profile published in App.B. The profile raises select limits only after the partition’s profile record sets `apply.profile=Aggregator`, `apply.max_batch_ns_profile=6000000` (6 ms p99), `apply.max_batch_entries_profile=2048`, and `ack_handle.max_defer_ms_profile=750`, and spec-lint enforces that the profile references these exact values.

| Parameter | Aggregator Profile | Guardrail / Telemetry |
| --- | --- | --- |
| `apply.max_batch_ns` | 6 ms p99 | Enforced via the existing leaky bucket and `apply.aggregator_budget_breach_total`. |
| `apply.max_batch_entries` | 2,048 | Runtime splits batches above 2,048 entries and emits `ApplyAggregatorSplit`. |
| `ack_handle.max_defer_ms` | 750 ms | Deadline is enforced plus `ack_handle.defer_guardrail_ms = 800` to page if exceeded. |

[Normative] AP workloads MUST prove compliance by emitting `ApplyProfileReport{profile, p95_batch_ns, p99_batch_ns, max_batch_entries, max_ack_defer_ms}` every `profile.report_period_ms = 10000` and by responding to `ExplainApplyProfile(profile=Aggregator)` with the last report plus `decision_trace_id`. Operators MUST reject or roll back the profile if any report shows breaches beyond 5 consecutive intervals; Clustor enforces this automatically by demoting the partition to the default profile and logging `ApplyProfileAutoDemote`.
[Operational] Instrumentation MUST capture `apply.aggregator_samples_total`, `apply.aggregator_guardrail_violations_total`, and `ack_handle.defer_guardrail_violation_total` so Explain APIs and dashboards can document whether AP workloads continue to respect the raised ceilings. The Explain API for throttling (`WhyCreditZero`) MUST cite the profile when aggregator allowances contribute to PID adjustments so downstream teams can reconcile telemetry with ingest hints.
---

## 8  Snapshots & State Transfer
- Triggers: log size (`snapshot.log_bytes_target = 512 MiB`), time (`snapshot.max_interval = 15 min`), or follower lag (`snapshot.catchup_threshold = 64 MiB`).
- [Normative] Incremental snapshots are enabled for every partition (`snapshot.delta_chain_max ≥ 1`) and MUST follow the cadence, chain, and manifest requirements in §8.4 so that delta checkpoints remain interoperable with full snapshots and ControlPlaneRaft authorization.
- Products implement `snapshot_export` and `snapshot_import`. Importers must accept at least `current_version-1`.

### 8.1 Snapshot Manifest Format
[Normative] Snapshot manifests MUST emit the fields below for both full and incremental checkpoints; producers treat every field as canonical and reject manifests that omit or reorder them.
| Field | Description |
| --- | --- |
| `manifest_id` | UUIDv7/ULID, monotonic per partition. |
| `version_id` | Incrementing integer; ControlPlaneRaft tracks `accepted_min/max`. |
| `producer_version` / `emit_version` | Emitter build + ControlPlaneRaft-selected emit version. |
| `base_term`, `base_index` | Last included log entry. |
| `content_hash` | SHA-256 of canonical manifest. |
| `chunks[]` | `{chunk_id, offset, len, digest}` (SHA-256). |
| `logical_markers` | Product-defined (tenant IDs, ranges). |
| `signature` | Ed25519 (or gated P256) over canonical body. |
| `encryption` | `{dek_epoch, iv_salt}` for AEAD decrypt. |
| `snapshot_kind` | Enum `Full` or `Delta`; `Delta` manifests also expose the parent below. |
| `delta_parent_manifest_id` | Parent manifest ID for delta chains; null for full snapshots. |
| `delta_chain_length` | Number of chained incrementals since the last full snapshot (1–3 inclusive). |
| `ap_pane_digest` | SHA-256 over deterministic AP pane state serialization (pane ID order). |
| `dedup_shards[]` | Ordered `{shard_id, ledger_epoch, shard_digest}` vector for dedup workloads. |
| `commit_epoch_vector[]` | Monotone `{dimension, epoch, checksum}` list proving commit-epoch metadata parity. |

[Normative] `ap_pane_digest`, `dedup_shards[]`, and `commit_epoch_vector[]` MUST be computed from the exact bytes replay would hydrate, using lexicographic ordering on pane/shard IDs and zero-padding absent shards so manifests from different emitters remain byte-for-byte comparable; any attempt to elide or reorder those collections invalidates the manifest (`SnapshotDeterminismViolation`) before authorization. Importers MUST verify that every `commit_epoch_vector` entry matches the ControlPlaneRaft-advertised epoch for the corresponding dimension and refuse to mount the snapshot otherwise to preserve Invariant C3.

Manifests MUST be emitted as RFC 8785 Canonical JSON: UTF-8 encoding, no insignificant whitespace, deterministic object member ordering (lexicographic by UTF-16 code unit), and minimal numeric representations. Producers first populate every field except `content_hash`/`signature`, canonicalize the JSON, compute `content_hash = sha256(canonical_bytes)` as a lowercase `0x`-prefixed hex string, inject that field, re-canonicalize (still omitting the `signature` field), and finally sign that canonical byte stream. App.C (“Snapshot Manifest & Segment-MAC Test Fixtures”) provides a worked manifest plus signer key so implementations can validate hashing and signature coverage end-to-end; spec-lint replays that vector to prevent drift.

ControlPlaneRaft manages ManifestSigner keys with anti-rollback counters and dual-validity windows. Nodes refuse manifests from unknown or superseded epochs unless a time-boxed override is applied (§13.2).
`manifest.json` and its directory entry MUST be `fsync`'d immediately after emission; the producer re-lists the manifest (stat + checksum) before advertising it as deletion-authorizing so §9.1 can rely on the manifest being durably discoverable. After the re-list succeeds, the producer appends `SnapshotAuthorizationRecord{manifest_id, base_index, auth_seq, manifest_hash}` to `snapshot/manifest_authorizations.log` (monotone `auth_seq` per partition) and `fdatasync`s the log. Compactors consume that log, re-stat the manifest, and persist `CompactionAuthAck{manifest_id, auth_seq}` in `metadata.json` before unlinking any WAL segment. Missing acks abort deletion, enforcing a two-phase handshake.
[Normative] Each `CompactionAuthAck` extends a hash chain `compaction_auth_chain = sha256(prev_chain || manifest_id || auth_seq || manifest_hash)` stored alongside the ack and `fdatasync`'d with it (the initial `prev_chain` is 32 zero bytes). Spec-lint replays the same derivation, and auditors can therefore prove that deletion authority itself has not been tampered with even if metadata files are copied offline.

### 8.2 Snapshot Import Flow
1. Canonicalize JSON (RFC 8785) and verify signature + DEK epoch via cached trust roots. Dual-validity windows allow reads while ControlPlaneRaft is unreachable for up to `controlplane.cache_grace_ms`.
2. Validate `version_id` is within `[accepted_min, accepted_max]`.
3. Stream chunks: authenticate AEAD, decrypt, then verify digest before applying. [Normative] If either the AEAD tag or chunk digest fails, the importer MUST zeroize the staging buffer, roll `applied_index` back to the last fully verified entry, emit `SnapshotChunkAuthFailure`, and retry the chunk up to `snapshot.import_chunk_retry_limit = 3` times with bounded exponential backoff (`retry_delay_ms = min(2^attempt × 1000, 10000)` with ±25% jitter). The total retry window for a chunk MAY NOT exceed 60 s wall-clock; exceeding either the attempt count or the time budget forces Quarantine for that partition. Under no circumstance may partially authenticated data advance `applied_index` or mutate product state; failures MUST also raise `snapshot.import_fail_reason="ChunkAuth"` telemetry so operators can correlate the rollback.
4. Apply entries `(base_index + 1 .. latest)` via normal AppendEntries; handle conflicts via truncate-and-replay. AppendEntries arrivals are buffered until `applied_index >= base_index` to avoid interleaving, and MUST NOT be applied (or expose `applied_index > base_index`) until the manifest signature + version checks from steps 1–2 succeed. If the manifest is rejected, buffered RPCs MUST be dropped and the leader notified via `ThrottleEnvelope{reason=SnapshotRejected}` to prevent partially-applied state.
  - The buffer is bounded to `snapshot.import_append_buffer_max_entries = 8192` per partition by default; profiles MAY raise it (≤65,536) via `snapshot.import_buffer_multiplier` when sustained throughput would otherwise starve replication. To cap resident memory, the product of `buffered_entries × entry.max_frame_bytes(profile)` MUST remain ≤ `snapshot.import_buffer_max_bytes_abs = 8 GiB`. Profiles MAY only tune the cap downward (`snapshot.import_buffer_max_bytes <= 8 GiB`); attempts to raise it above 8 GiB are rejected at config-parse time and in spec-lint. Every change MUST appear in the profile bundle so both sides agree on the cap. Hitting either bound stalls new AppendEntries by emitting `ThrottleEnvelope{reason=SnapshotImport}` so leaders back-pressure until import catches up.
  - Node-level protection: the runtime also enforces `snapshot.import_node_buffer_max_bytes = min(snapshot.import_node_buffer_hard_cap_bytes, max(8 GiB, floor(node_ram_bytes × snapshot.import_node_buffer_ram_fraction)))` across all concurrent imports on a node. The default fraction is `0.15`; profile bundles MAY tune it within `[0.05, 0.25]`. `snapshot.import_node_buffer_hard_cap_bytes` defaults to 32 GiB and MAY be increased (with ticket) up to 64 GiB on 1 TB+ hosts; spec-lint rejects values outside `[32 GiB, 64 GiB]`. When aggregate usage would exceed the computed cap, new imports block at the manifest-authorization step and emit `SnapshotImportNodePressure`; telemetry `snapshot.import_node_buffer_usage_bytes` exposes the headroom so operators can stage imports safely on high-density nodes.
  - [Informative] The proportional formula above keeps recovery throughput predictable as hardware footprints grow (e.g., a 1 TB RAM host yields a 32 GiB cap, while a 64 GiB host settles at ~9.6 GiB). This avoids new spec revisions each time hardware generations change while retaining the absolute 32 GiB safety guardrail.
  - Once the importer finishes applying the snapshot (or discards it on failure), the buffer automatically drains in FIFO order and the transport replays any deferred AppendEntries without requiring the leader to re-probe; leaders simply resume their normal heartbeat-based catch-up loop and the throttle clears itself when the buffer drops below 80%.
5. If trust caches expire, imports fail with `snapshot_full_invalidated(reason)` or `snapshot_delta_invalidated(reason)`; operators may issue a time-limited override (`snapshot_full_override`).

### 8.3 Snapshot I/O Budgeting
- Per-peer budget `snapshot.max_bytes_per_sec = 128 MiB/s` with classes `CatchUp`, `Bootstrap`, `DR`. Meters resume only after utilization <90% (10% hysteresis).
- Node-level cap `snapshot.node_max_bytes_per_sec = min(0.7 * detected_nic_capacity, 1 GiB/s)`; exceeding demotes all snapshot traffic until the rolling meter drops below 60%.
- AppendEntries replication always preempts snapshot traffic via weighted fair queuing; heavy snapshot traffic emits `WhySnapshotBlocked` hints.

### 8.4 Incremental Snapshot Cadence & Restore Guarantees
[Normative] Enabling `snapshot.delta_chain_max > 0` requires configuring `snapshot.delta_emit_period_ms <= 10000` (10 s cadence) and `snapshot.full_emit_period_ms <= 30000`; the runtime enforces both by auto-triggering a full snapshot whenever either bound would be exceeded. `delta_chain_length` counts only the incremental snapshots emitted since the last full checkpoint (the full snapshot itself is never included). Chains MUST cap at three incrementals between full snapshots; emitters automatically roll a full snapshot once `delta_chain_length` would grow past 3 or when the parent manifest ages past 30 s, whichever occurs first.
[Normative] `SnapshotAuthorizationRecord` entries for incremental manifests MUST include `{manifest_id, delta_parent_manifest_id, snapshot_kind}` and the elapsed time since the last full snapshot. ControlPlaneRaft rejects authorizations whose `full_age_ms > 30000` or whose `delta_emit_age_ms > 10000`, ensuring the authorization handshake guarantees the “30 s full + 10 s incremental” checkpoint envelope even when ControlPlaneRaft momentarily lags (§11.1 mirrors the same timers).
[Normative] AP (analytics-pane) workloads MUST hydrate their pane/dedup state exclusively from the deterministically recorded `ap_pane_digest` and `dedup_shards[]` vectors. Importers replay the serialized AP pane stream prior to replaying entries above `base_index`, refuse activation if recomputed digests differ, and write `ap_pane_restore_state=Complete` into `metadata.json` before acknowledging readiness. This rule preserves dedup shard ordering and eliminates cross-replica divergence for AP pane state.
[Normative] Restore flows MUST enforce Invariant C3 (commit-epoch monotonicity) by comparing each `commit_epoch_vector` entry with ControlPlaneRaft’s `commit_epoch` for the same dimension before admitting client writes; failures quarantine the partition with `InvariantC3RestoreFailed` until a compliant manifest arrives. Activation remains blocked until `shadow_apply_checkpoint_index` and `commit_epoch_vector` jointly prove that commit-epoch metadata never regressed relative to the last ControlPlaneRaft-published epoch.
[Normative] Crash/outage hygiene: when either the emitter or ControlPlaneRaft outage leaves an incomplete delta chain (missing parent manifest, `delta_chain_length` gap, or parent older than 30 s), partitions MUST mark the chain `delta_chain_state=Orphaned`, delete the orphaned manifests from the authorization log, and trigger an immediate full snapshot before delta replication resumes. Importers encountering an orphan MUST refuse to apply it and report `SnapshotDeltaRetired` so automation can track successful retirement. This guarantees that every surviving delta chain is rooted in an authorized full snapshot even after disruptions.
[Operational] Emitters and importers MUST publish `snapshot.delta_emit_skew_ms`, `snapshot.delta_chain_length`, and `snapshot.snapshot_only_ready_ratio` telemetry so Explain/WhySnapshotBlocked tooling can prove compliance and surface impending violations before the guardrail forces a full snapshot.

---

## 9  Storage Layout, Encryption & Recovery

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

### 9.1 Compaction Safety Gates
- Delete WAL below the latest snapshot only when:
  - ≥ `compaction.quorum_ack_count` replicas (2 for 3-node, 3 for 5-node) report `sm_durable_index >= snapshot.index`.
  - Hard floor: never delete below `min(quorum_applied_index, base_index)` where `quorum_applied_index` is the smallest `applied_index` observed across the latest quorum heartbeat bundle, even if `sm_durable_index` advances faster.
  - `checkpoint.quorum_guard_bytes` (default 256 MiB) and learner slack requirements are satisfied. Learners within `membership.catchup_slack_bytes` retain their needed WAL range regardless of guard consumption.
  - The snapshot authorizing deletion remains the latest manifest.
  - The authorizing snapshot manifest and directory entries were `fsync`'d post-rotate, re-listed (stat + checksum), and covered by a `SnapshotAuthorizationRecord` + matching `CompactionAuthAck{manifest_id, auth_seq}` (§8.1) before any WAL unlink occurs to prevent TOCTOU between manifest publication and persistence.
  - If a re-listed manifest later fails signature or hash verification (object-store bitrot), compaction aborts with `CompactionAuthAbort{manifest_id, reason=ManifestSignatureMismatch}` and the manifest is quarantined until a new snapshot replaces it.
  - Re-encryption jobs mark segments `rewrite_inflight`; compaction skips them until `rewrite_complete` is fsync'd.
- All gates above are conjunctive; compaction MUST satisfy both the `sm_durable_index` quorum clause and the `min(quorum_applied_index, base_index)` floor (plus the remaining bullets) before any WAL bytes are unlinked.
- When both a learner slack requirement and the `min(quorum_applied_index, base_index)` floor apply, compaction uses `max(learner_slack_floor, min(quorum_applied_index, base_index))` as the effective floor so that learners retain their guarded range even if `base_index` lags.
- Putting it together: the WAL deletion guard is `floor_effective = max(learner_slack_floor, min(quorum_applied_index, base_index))`, and bytes below `floor_effective` leave disk only after the quorum-level `sm_durable_index` test is satisfied. *Example:* in a 3-replica set with `base_index=1,200`, `quorum_applied_index=1,300`, and a learner that must retain the most recent 100 entries (`learner_slack_floor=1,250`), we compute `min(quorum_applied_index, base_index)=1,200`, so `floor_effective = max(1,250, 1,200) = 1,250`. Even if two replicas report `sm_durable_index=1,500`, compaction MUST keep WAL bytes below 1,250 until the learner catches up and the snapshot manifest authorizes deletion.
- [Normative] Implementations MUST calculate the effective floor using the pseudocode below (i.e., `max(learner_slack_floor, min(quorum_applied_index, base_index))`). Validators MUST NOT re-arrange the inequalities—doing so can silently flip the guardrail direction when learners lag—and spec-lint asserts identical results against the reference function.
- Learner retirement guardrail: when a `MembershipChange` (§4.1) removes or decommissions a learner, compaction MUST continue honoring the most recent `learner_slack_floor` until the retiring replica either (a) acknowledges `applied_index >= learner_slack_floor` or (b) both `learner_retirement_delay_entries = 65,536` and `learner_retirement_delay_ms = 300000` elapse after the joint consensus commit that removed it. ControlPlaneRaft records `membership.learner_retire_index` when finalization occurs; compaction MUST surface `compaction.learner_retirement_pending=true` and cite that index in Explain APIs until the guard clears so operators cannot accidentally drop WAL needed by a “dangling” learner that is still replaying offline.
- Compactors MUST also confirm that every `segment_seq` whose bytes would be unlinked either (a) has no outstanding `NonceReservationRange` entries (all are fully spent) or (b) carries a committed `NonceReservationAbandon{segment_seq}` record (§6.5, §9.2). Deletion that races ahead of nonce accounting is forbidden.
- Disk pressure: `disk.soft_usage_percent = 80%` halves credits and triggers snapshots if gates allow; `disk.hard_usage_percent = 90%` rejects appends with `AppendDecision::Reject(DiskFull)` but still serves reads.
[Normative] Compaction MUST remain suspended while `quarantine_reason=Integrity` so that no bytes are deleted while integrity is in doubt. Administrative or ApplyFault quarantines MAY continue compaction once all guardrails above are satisfied, but they still honor the SnapshotAuthorization/CompactionAck handshake and record their quarantine class in the audit trail before unlinking any WAL bytes.

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

### 9.2 Encryption & Key Epoching
- `wal.crypto_block_bytes = 4096 (2^12)` is a fixed crypto constant independent of `wal.fs_block_bytes`. Every WAL segment begins with a `segment_header{wal_format_version:u8, segment_seq:u64, crypto_block_bytes:u16, dek_epoch:u32, reserved:u16, ...}` that records both the nonce geometry **and** the encryption epoch. ControlPlaneRaft enforces a single `wal.crypto_block_bytes` per cluster generation; allocating a `segment_seq` therefore captures that value, and readers MUST reject (`SegmentCryptoBlockMismatch`) any segment whose header disagrees with the configured constant or changes mid-segment. Mirroring `dek_epoch` into the header lets scrub detect cross-epoch reuse before decrypting bytes. The header is `fdatasync`'d at allocation so crash recovery can verify it before decrypting the first block. Telemetry exports `clustor.wal.crypto_block_bytes` so operators can confirm uniformity, and App.C tests assert mixed values are rejected.
- AEAD (AES-256-GCM default) encrypts WAL segments and snapshot chunks. Tags are fixed at 16 bytes for the GCM suite, matching the constant-time comparison helpers in App.C; future suites that emit 32-byte tags MUST update both the macros and this clause before landing. To stay on the well-tested 96-bit IV path, every `wal.crypto_block_bytes` chunk derives `iv96 = Truncate96(H(dek_epoch || segment_seq || block_counter || b"WAL-Block-IV v1"))`, where `H` is SHA-256 or BLAKE3 and the concatenated fields are encoded big-endian. `{aad_version:u8=1, partition_id, dek_epoch, segment_seq}` remain the AAD so future field order changes cannot be replayed against older binaries. Raising the AAD version requires a ControlPlaneRaft-approved upgrade plan and keeps old nodes failing-closed. [Normative] Implementations MUST follow the explicit byte-ordering pseudocode in App.C (`aead_nonce_derivation`) when generating IVs; swapping endianness in any field invalidates compliance even if the resulting values appear unique.
- The big-endian encoding above is intentional even though the ledger and manifests serialize fields little-endian; repeat the exact byte order to keep nonce derivation stable across vendors and avoid replaying ciphertext with mixed endianness.
  - MAC suite selection is orthogonal to `integrity.hash_suite`; even when `H=BLAKE3` for IV derivation or leaf hashing, segment trailers continue using the cluster-wide MAC (HMAC-SHA256 in v0.1) until ControlPlaneRaft bumps `integrity_mac_epoch`. Segments MUST NOT mix MAC suites.
  - **Nonce domain:** For every DEK, `(segment_seq, block_counter)` MUST be globally unique. `block_counter` monotonically increments per `wal.crypto_block_bytes` chunk inside a segment and resets only after a new `segment_seq` is allocated.
  - **Segment identifiers:** `segment_seq` values are reserved from a monotone counter that is stored in ControlPlaneRaft and in `wal/durability.log`; WAL rotation, re-encryption, and post-crash rewrites must allocate a fresh `segment_seq` before emitting the first block so rewrites never reuse the prior nonce space.
    Reusing an old `segment_seq` for any content—regardless of offsets or data—is forbidden even if the previous segment was deleted.
  - **Crash-safe reservations:** Writers reserve nonce ranges in chunks of ≤`nonce.reservation_max_blocks_profile` `wal.crypto_block_bytes` blocks (default 1024, max 8192). Before writing block `n`, the runtime ensures a `NonceReservationRange` covering `[n, n + range_len)` is present in `wal/durability.log`; new ranges are `fdatasync`'d whenever either the configured byte window (`nonce.reservation_max_bytes_profile`) is consumed or 5 ms elapses (step 4 of §6.5). Blocks within a reserved window may be written without additional ledger traffic, and restarts resume at `max(start + reserved_blocks)`. Crashes can therefore create benign gaps up to `nonce.reservation_max_bytes_profile`; larger gaps imply tampering and trigger quarantine.
    Reservations NEVER span multiple `segment_seq` values; rotating the segment or re-encrypting it forces a fresh reservation anchored to the new `segment_seq`, and any leftover reservation tied to the old `segment_seq` is invalidated once the rewrite finishes.
    [Normative] Reservation ranges for a given `segment_seq` MUST be contiguous and non-overlapping: while a segment is writable, `next.start_block_counter == prev.start_block_counter + prev.reserved_blocks`. Writers MAY open the next range only after the prior one has been exhausted or abandoned; leaving holes larger than `nonce.reservation_max_bytes_profile` between contiguous ranges is forbidden and treated as nonce tampering. Segments therefore contain at most the single bounded “gap” created by a crash inside the active reservation; new ranges never skip forward arbitrarily, and rotation to a new `segment_seq` resets the counter to zero with the same contiguity requirement.
  - **Out-of-order `io_uring` completions:** Completion events may arrive out of order, but nonce retirement is serialized. Writers MUST stage completions in a per-segment commit queue keyed by `block_counter` and only advance the reservation tail when every counter ≤ the candidate has durably landed. Dropping an out-of-order completion on the floor is forbidden; instead, the runtime parks it until all earlier counters commit, guaranteeing the `(segment_seq, block_counter)` pairs consume reservations monotonically even when the kernel signals completion early. Telemetry `wal.nonce_out_of_order_total` counts how often completions had to be parked so operators can spot devices that routinely reorder DMA writes.
  - **Reservation retirement:** Re-encryption, repair, or compaction that abandons a `segment_seq` MUST append `NonceReservationAbandon{segment_seq, abandon_reason}` after proving the referenced bytes cannot be replayed. If a re-encryption rewrite is interrupted (operator abort or crash) before ControlPlaneRaft acknowledges the new `segment_seq`, the node MUST immediately mark the old `segment_seq` abandoned, zero any partially rewritten bytes, and log the abandonment to ControlPlaneRaft so a restart cannot reuse the pending reservation. ControlPlaneRaft tracks abandon records so compaction logic can prove no nonce window is left dangling.
  - **Gap accounting:** Scrub jobs distinguish `NonceReservation` gaps (reserved-but-unused, ≤4 MiB) from corruption by exporting `wal.nonce_reservation_gap_bytes` vs `wal.nonce_corruption_bytes`. Nodes raise `wal.nonce_reservation_gap_alarm` once the gauge exceeds 2 MiB; exceeding `wal.nonce_reservation_max_gap_bytes = 4 MiB` triggers an exponential backoff policy before quarantine: the first violation emits only telemetry, the second within `nonce.reservation_gap_backoff_ms = 600000` forces `OverrideStrictOnlyBackpressure`, and the third within the same window escalates to Quarantine. Gaps that persist across two reboots or coincide with scrub failures bypass the backoff and quarantine immediately. Reservation gaps do not block compaction; they only influence telemetry and scrub sampling priorities.
- Key provider tracks `{kek_version, dek_epoch, integrity_mac_epoch}`. Rotations occur time-based (24h for DEK, 30d for KEK), on membership change, or via admin `RotateKeys` (Break-Glass).
- `wal/durability.log`, `.idx`, and manifest footers include MACs keyed by `integrity_mac_epoch`. Nodes refuse to mount when epochs drift by >1; the only override is `AdminOverrideKeyEpoch` (Break-Glass) which temporarily allows a +2/-2 window while raising `KeyEpochOverrideActive` telemetry and forcing Strict mode until the mismatch is cleared.
- Re-encryption streams rewrite segments with new `segment_seq` reservations recorded in ControlPlaneRaft; partial rewrites quarantine until resumed. Resuming a rewrite allocates a fresh `segment_seq`, appends `NonceReservationAbandon` for the superseded one, and continues only after ControlPlaneRaft acknowledges the new reservation range so nonce space never overlaps.
- ControlPlaneRaft persists every epoch as a monotone `u32`; any attempt to replay a lower `{kek_version, dek_epoch, integrity_mac_epoch}` value—whether due to ControlPlaneRaft rollback or malicious injection—is rejected with `KeyEpochReplay` and forces Strict fallback until operators investigate. Data-plane caches mirror the same invariant and MUST refuse to consume a proof whose epoch regresses.

### 9.3 Compatibility Contracts
- WAL segments declare `wal_format_version`; nodes advertise `[wal_min, wal_max]` and refuse unsupported ranges.
- `.idx` files carry `index_format_version` and MAC metadata. Rebuilds emit the highest version readable by every replica in the voter set; incompatible disks require snapshot+restore.
- Snapshot `emit_version` equals `min(max_schema across quorum)`; ControlPlaneRaft raises it only after all replicas advertise support. Admin tooling surfaces `clustor.compat.emit_version_blocked{feature}` when features wait on emit-version bumps.
- Recovery flow: validate manifests, replay WAL to `commit_index`, rebuild apply caches, reconcile durability ledger, and require Strict mode until proof exists.

---

## 10  Flow Control & Backpressure

### 10.1 Credit Controller Model
- PID loop samples every `flow.sample_period_ms = 100` with error `e = target_backlog - observed_backlog`.
- Baseline gains (manual mode):

| Profile | Kp | Ki | Kd |
| --- | --- | --- | --- |
| Latency / ConsistencyProfile | 0.60 | 0.20 | 0.10 |
| Throughput | 0.50 | 0.15 | 0.08 |
| WAN | 0.40 | 0.10 | 0.05 |

- Numeric stability guardrail: for every profile, `Ki × (flow.sample_period_ms / 1000)` MUST remain ≤ 1.0; config validators clamp or reject values that would violate this condition to prevent integrator blow-up.
- Integral windup clamp ±2048 entries; derivative term uses EMA (`flow.pid_derivative_tau_ms = 300` Latency/Throughput, 450 WAN).
- Targets: `target_latency_ms=25`, `target_backlog_entries=512` (scaled per tenant quotas). Credits are bounded `credit_min = 1 batch`, `credit_max = 4096 entries`.
- Dual-token bucket: every partition tracks `entry_credits` and `byte_credits`. Large frames burn both counters; the leader pauses admission whenever either hits zero. Defaults: `entry_credit_max = 4096`, `byte_credit_max = 64 MiB`, `byte_credit_refill_rate = target_backlog_bytes / flow.sample_period`. PID error now consumes a weighted sum of the two deficits so jumbo frames cannot starve small ones. Explain APIs expose both balances.
- Minimum service quantum: even when byte credits are exhausted by jumbo frames, the scheduler admits at least one frame ≤`flow.min_small_frame_bytes = 16 KiB` per `flow.sample_period_ms` so small requests continue making progress.
- Operator ergonomics: profiles ship with pre-tuned gains and bucket sizes so most clusters run the controller in “standard” mode (no custom knobs). Advanced tuning is optional and requires a documented change ticket; otherwise operators can treat the flow controller as a black box and rely on Explain APIs + throttle envelopes for visibility.
- [Informative] App.A/App.B SLOs assume the steady-state PID solution `credits_ss = target_backlog_entries` with `throughput ≈ credits_ss / flow.sample_period_ms`. Keeping `Kp × target_backlog_entries` within ±10% of the profile’s `ingest_ops_target` ensures the closed-loop bandwidth matches the published SLO; simulator tooling therefore exports `flow.pid_expected_throughput = (target_backlog_entries / flow.sample_period_ms) × 1000` so operators can compare predicted vs observed throughput before altering gains.
- Tenant quotas enforce weighted-fair sharing; `OverrideCredit` is Break-Glass with TTL ≤10 min.
- [Normative] The PID auto-tuner is enabled for Throughput and WAN profiles whenever `io_writer_mode=FixedUring`, `strict_fallback=false`, and `controlplane.cache_state=Fresh`. The tuner samples backlog variance every `flow.pid_auto_tune_window_ms = 5000`, adjusts `{Kp,Ki,Kd}` within the bounds in App.B, and records each change in `flow.pid_auto_tune_last_profile`. Latency/ConsistencyProfile and ZFS profiles keep the auto-tuner disabled unless explicitly set to the Aggregator profile. If the tuner detects oscillation (`Ki × (flow.sample_period_ms / 1000) > 1.0` or variance exploding), it MUST revert to the last known-stable gains, mark `flow.pid_auto_tune_state=Revoked`, and page operators. Telemetry `flow.pid_auto_tune_state ∈ {Enabled,Disabled,Revoked}` and `flow.pid_auto_tune_adjust_total` track behavior for `/readyz` and Explain APIs.
- Leadership changes reset the controller’s integrator/derivative state to zero and clamp both credit buckets to `credit_min` until the new leader observes `flow.pid_state_checkpoint` replicated in the current term. This avoids inheriting stale windup from the prior leader and makes `TransferLeader` deterministic: the handoff copies the last checkpoint only when `strict_fallback=false`, otherwise the new leader performs a cold start and emits `flow.pid_reset_reason=StrictFallbackOrElection`.

### 10.2 Lag Classification & Mitigation
| Lag Class | Definition | Action |
| --- | --- | --- |
| Transient | `lag_bytes <= 64 MiB` and `lag_duration < 30 s` | Cut credits 50%, boost snapshot priority, log `FollowerTransientLag`. |
| Structural | Beyond thresholds above or bytes ≥256 MiB | Force Strict durability, cut credits to 25%, trigger snapshot rebuild, alert ControlPlaneRaft, optionally step down leader. |
| Manual kill-switch | `flow.structural_hard_block` (default false) | Operators may block writes entirely while retaining reads. |

Leaders MUST step down when structural lag persists for `flow.structural_stepdown_ms = 15000 ms` unless ControlPlaneRaft approves `flow.structural_override` (Break-Glass). Overrides expire automatically after `flow.structural_override_ttl_ms = 120000` unless renewed, and they are cleared as soon as lag returns to the Transient band for three consecutive sampling windows to avoid oscillation. The “optional” action above therefore only refers to whether operators step down earlier than the hard limit.

### 10.3 Client-Facing Throttling
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
  "decision_trace_id": <uuid>,
  "credit_hint": "Recover|Hold|Shed",
  "ingest_status_code": "HEALTHY|TRANSIENT_BACKPRESSURE|PERMANENT_DURABILITY",
  "durability_status_code": "HEALTHY|PERMANENT_DURABILITY"
}
```
Clients must ignore unknown `reason` values. `entry_credits_available`/`byte_credits_available_bytes` summarize the dual-bucket state so clients understand whether large frames or entry counts triggered throttling. `last_quorum_fsynced_index` reflects the quorum proof derived from §6.5’s ledger ordering. `decision_trace_id` feeds Explain APIs (`WhyCreditZero`, `WhyDiskBlocked`). To prevent oversized replies, throttle/Why* envelopes MUST remain ≤32 KiB JSON and MAY list at most 32 IDs per array field; beyond that, servers MUST summarize with counters and set the shared field `truncated_ids_count` to the number of elided IDs (0 omits the field). Lists MUST be sorted lexicographically by their primary key (e.g., `(partition_id, shard, reason)`), and when truncation occurs the payload MUST also include `continuation_token` so clients can request the next page deterministically. Every Why* schema inherits these fields so clients can programmatically detect truncation and resume pagination.

[Normative] The ingest/throttle mapping layer populates `ingest_status_code` using existing PID/throttle inputs: `TRANSIENT_BACKPRESSURE` whenever throttle reasons are limited to flow-control sources (`ApplyBudget`, `FollowerLag`, PID-derived credit depletion), `PERMANENT_DURABILITY` whenever Strict fallback, durability overrides, or AEAD violations force sustained throttling, and `HEALTHY` otherwise. `durability_status_code` mirrors whether the throttled request is blocked by durability proofs (`PERMANENT_DURABILITY`) or not; data-plane nodes MUST reject attempts to map other reasons into these codes so consuming services observe the same contract as the downstream ingest pipeline without a bespoke shim.
[Normative] `credit_hint` communicates how clients should adjust ingest without overriding the PID controller: `Recover` requires `entry_credits_available ≥ 0.75 × entry_credit_max` **and** `byte_credits_available_bytes ≥ 0.75 × byte_credit_max`; `Hold` is emitted only when both buckets satisfy `0.25 × max ≤ available < 0.75 × max` and `ingest_status_code != PERMANENT_DURABILITY`; `Shed` fires when either bucket drops below `0.25 × max`, when `/readyz` reports readiness ratios below §11.5’s activation barrier, or when `ingest_status_code=PERMANENT_DURABILITY`. The mapping layer is read-only: it MUST NOT mutate PID gains, buckets, or throttle envelopes, and PID enforcement continues to be authoritative even if clients ignore the hint. Leaders log `credit_hint_transition{from,to,reason}` and Explain APIs expose `WhyCreditHint` so operators can verify compliance.
[Operational] `/readyz` and the streaming readiness feed add `{ingest_status_code, credit_hint, durability_status_code, partition_ready_ratio}` so DEFINE_ACTIVATE workflows and dashboards can gate deploys on the same readiness ratios as the ingest contract. Telemetry MUST include `ingest_status_publish_ms` to surface missed publications and retain parity with the downstream hot-reload pipeline.

---

## 11  Control Plane – ControlPlaneRaft
Dedicated Raft cluster managing durable metadata.

### 11.1 Durable Objects & Feature Gates
| Object | Purpose |
| --- | --- |
| Tenant descriptors | Auth, quotas, regional placement policy |
| Partition manifests | Replica placements, durability modes, key epochs |
| Session descriptors | Lease metadata, sequencing constraints |
| DR fences | Failover epochs, manifest hashes |
| Feature gates | Versioned toggles |
| Override ledger | Signed operator overrides |
| Durability ledger | `{partition_id, last_durable_term, last_durable_index, updated_at}` |
| QuarantineCleared records | `{partition_id, cleared_at_ms, ticket_url, controlplane_signature}` acknowledgements that the quarantine exit handshake from §6.6 completed |
| DefinitionBundle objects | `{bundle_id, version, sha256, definition_blob, warmup_recipe}` hot-reload payloads staged ahead of activation |
| ActivationBarrier objects | `{barrier_id, bundle_id, readiness_threshold, warmup_deadline_ms}` guards gating DEFINE_ACTIVATE entries until readiness telemetry matches |
| WarmupReadiness records | `{partition_id, bundle_id, shadow_apply_checkpoint_index, partition_ready_ratio}` telemetry mirrored into `/readyz` |
| Feature manifest | `{feature_name, predicate_digest, gate_state}` records for `{incremental_snapshots, leader_leases, observers, blake3_leaves, pid_auto_tuner}` signed so `/readyz` and auditors share the same capability matrix |

#### Feature Manifest (FutureGates)
| Feature | Slug | ControlPlaneRaft object | Predicate |
| --- | --- | --- | --- |
| Leader leases | `leader_leases` | `LeaseEnable` | All voters advertise `lease_gap_max > 0`, the ControlPlaneRaft cache is Fresh, and a durability proof covering the leader’s `raft_commit_index` is published. |
| PID auto-tuner | `pid_auto_tune` | `FlowPidAutoTune` | Partition profile is `Throughput` or `WAN`, and `io_writer_mode=FixedUring`. |
| Incremental snapshots | `snapshot_delta` | `SnapshotDeltaEnable` | `snapshot.delta_chain_max > 0`, the ControlPlaneRaft cache is Fresh, and the follower capability bit is granted. |
| BLAKE3 Merkle leaves | `blake3_merkle` | `IntegrityHashSuite` | Every replica advertises BLAKE3 support and `integrity_mac_epoch >= 2`. |

[Normative] ControlPlaneRaft publishes these rows verbatim in `feature_manifest.json` and spec-lint’s future-gate coverage check fails any build where telemetry omits a listed feature or invents a gate not present in this table. Operators therefore have a single canonical list to compare against `/readyz`, incident reports, and release artifacts.

- The data-plane ledger lives in `wal/durability.log` (same filesystem as the WAL) and emits append-only `DurabilityRecord{term, index, segment_seq, io_writer_mode}` entries per §6.5. Leaders publish only the summarized `(last_durable_term, last_durable_index, updated_at)` into the ControlPlaneRaft durability ledger once the local record is `fdatasync`'d and they hold a quorum proof; ControlPlaneRaft entries are rejected unless they advance that pair monotonically.
- Ledger appenders also record `NonceReservationRange` and `NonceReservationAbandon{segment_seq, abandon_reason}` entries so ControlPlaneRaft can prove nonce ranges were either spent or explicitly retired before WAL compaction (§6.5, §9.1, §9.2).
- ControlPlaneRaft signs each durability-ledger update. Nodes MUST retain `{term,index,segment_seq,io_writer_mode,updated_at,controlplane_signature}` so cached proofs can be compared byte-for-byte against local `wal/durability.log` records when enforcing the read gate in §3.3; mismatches suppress reads even if the numbers align.
- During elections, candidates must supply their latest `wal/durability.log` watermark (or a ControlPlaneRaft-provided proof with equal/greater values) before they may leave Strict mode or re-enable leases/Group-Fsync (§3.1). [Normative] Strict fallback therefore clears only after ControlPlaneRaft durably appends the leader-supplied `(last_durable_term, last_durable_index)` proof; possessing a byte-equal cached proof without the ControlPlaneRaft append is insufficient.
[Normative] Each release ships a signed `feature_manifest.json` (Ed25519, ControlPlaneRaft release key) enumerating `{feature_name, predicate_digest, gate_state}` for incremental snapshots, leader leases, observer admission, BLAKE3 leaves, and the PID auto-tuner. Data-plane binaries MUST refuse to advertise a capability whose digest mismatches the manifest so `/readyz`, telemetry, and auditors consume the same capability matrix.
- ControlPlaneRaft also tracks the `follower_read_snapshot_capability` bit per partition; it refuses to set the bit unless the partition is in Strict durability, `commit_visibility=DurableOnly`, and the follower proved its `applied_index` watermark. Only then may a node advertise follower read-only endpoints (§3.3).
- Feature enablement requires dry-run validation, audit entry, deterministic simulator coverage, and homogeneous gate state across a voter set.
- ControlPlaneRaft supports `N/N+1` upgrades. Nodes emit snapshots up to version `N` until every replica upgrades, then ControlPlaneRaft raises `emit_version`.
- Durability proofs stored in ControlPlaneRaft expire automatically after the profile-published `controlplane.durability_proof_ttl_ms_profile`. Latency/ConsistencyProfile and ZFS set the TTL to 12 h, WAN sets 18 h, and Throughput keeps 24 h to match its batching window. Profiles MUST keep the TTL within `[21,600,000 ms (6 h), 86,400,000 ms (24 h)]`; spec-lint fails configuration bundles that diverge from that range or omit the per-profile value. A background janitor GC deletes proofs older than the active TTL once every `controlplane.durability_gc_period_ms = 600000`. Nodes MUST refresh their proofs proactively before expiry; stale proofs falling out of the ledger force Strict fallback until a fresh `(last_durable_term, last_durable_index)` lands. Any temporary TTL increase (e.g., maintenance windows) MUST be recorded in the override ledger with `{override_id, ttl_ms, ticket_url}` so auditors can trace the justification.
- During ControlPlaneRaft outages, data-plane nodes continue serving traffic using cached routing epochs, RBAC, durability ledger, and key epochs for up to `controlplane.cache_grace_ms = 300000`. Mutating admin APIs return `ControlPlaneUnavailable`. Safety downgrades (Strict fallback, lease revoke, Group-Fsync lockout, key quarantines) continue without ControlPlaneRaft, and §3.3 clarifies that client appends are still accepted under Strict durability while linearizable reads fail with `ControlPlaneUnavailable{reason=NeededForReadIndex}` until the predicate in §3.3.1 succeeds again. When caches expire, nodes remain in Strict mode, pause incremental snapshot emission (full snapshots only), and keep leases revoked until ControlPlaneRaft returns.
- The Strict-only fallback above typically increases per-partition latency by 40–60% on Throughput hardware; App.A tracks this via `controlplane.outage_strict_mode_active`. Nodes also expose `strict_only_runtime_ms` (monotone while ControlPlaneRaft is unreachable). Profiles define `controlplane.strict_only_backpressure_ms` (default: Latency/ConsistencyProfile=120000, Throughput=300000, WAN=600000); once `strict_only_runtime_ms` exceeds that bound, leaders MUST halve `entry_credits`/`byte_credits` (bounded floor = 1 batch), emit `ControlPlaneOutageBackpressure` incidents, and recommend load shedding. Operators MAY keep serving if they acknowledge the incident, but the runtime will continue to clamp credits until ControlPlaneRaft returns or the operator explicitly overrides via Break-Glass (`OverrideStrictOnlyBackpressure`, TTL ≤ 5 min).
- Once `controlplane.cache_age_ms > controlplane.cache_grace_ms`, the following operations hard-fail with `ControlPlaneUnavailable{reason=CacheExpired}` regardless of operator overrides: (a) membership changes (`MembershipChange`, `MembershipRollback`), (b) durability transitions, (c) key rotations/epoch bumps, and (d) DR fencing (`FenceCommit`, `FenceAbort`). Read-only APIs still work using the frozen cache snapshot; writes continue only under Strict durability.
- Nodes export `controlplane.cache_state ∈ {Fresh, Cached, Stale, Expired}` to keep dashboards and admission code in sync: `Fresh` (age ≤ `controlplane.cache_fresh_ms = 60,000`), `Cached` (`controlplane.cache_fresh_ms < age ≤ 0.5 × controlplane.cache_grace_ms`), `Stale` (`0.5 × controlplane.cache_grace_ms < age < controlplane.cache_grace_ms`), and `Expired` (age ≥ `controlplane.cache_grace_ms`, which forces the hard failures listed above). Admin APIs and incidents MUST source their decision from this metric rather than reimplementing the thresholds.
- [Normative] All cache timers (`controlplane.cache_*`) are stored and compared as unsigned 64-bit integers; implementations MUST saturate additions/subtractions at `u64::MAX` and MUST promote intermediate math to 128-bit (or an equivalent arbitrary-precision type) on 32-bit architectures so that values exceeding `2^31 ms` remain deterministic across the fleet.
- [Normative] Cache refresh follows a single retry hierarchy so partitions behave identically under partial network partitions:
```
loop {
    match controlplane.cache_state {
        Fresh => sleep(controlplane.cache_refresh_interval_ms = 5_000),
        Cached => attempt_refresh(); sleep(min(5_000, remaining_grace()/4)),
        Stale => attempt_refresh(); sleep(min(2_500, remaining_grace()/8)),
        Expired => attempt_refresh(); sleep(controlplane.cache_expired_retry_ms = 1_000),
    }
}
```
`remaining_grace()` returns `max(0, controlplane.cache_grace_ms - controlplane.cache_age_ms)`. `attempt_refresh()` performs a quorum read of `{routing_epoch, durability_ledger, rbac_manifest, feature_manifest}` from ControlPlaneRaft; if the fetch succeeds, the node atomically installs the snapshot and resets `controlplane.cache_age_ms`. If the fetch fails with a transport error, the node logs `controlplane.cache_refresh_failure{error}` and continues the loop without backoff. Implementations MUST NOT invent alternate timers or exponential backoffs: every partition shares the retry cadence above so auditors can reason about worst-case recovery during partial outages.
- Every transition into `controlplane.cache_state=Expired` increments the monotonic counter `controlplane.cache_expiry_total{partition_id}` so SLO tooling can correlate cache lapses with user-visible incidents.
- Early warning: nodes derive `controlplane.cache_warn_ms = max((3 × controlplane.cache_grace_ms) / 4, controlplane.cache_grace_ms - 60000)` using integer math (no floating-point rounding differences) and flip `controlplane.cache_warning=1` telemetry plus a `ControlPlaneCacheWarning` incident as soon as `controlplane.cache_age_ms ≥ controlplane.cache_warn_ms`. While the warning bit is set, leaders MUST attach `cache_warning_ms_remaining = controlplane.cache_grace_ms - controlplane.cache_age_ms` to every `ControlPlaneUnavailable{reason=NeededForReadIndex}` response so clients and operators have at least one minute of lead time before hard failures trigger.
- Mixed-version guardrails: capabilities that require parity (leases, incremental snapshots, observer admission, PID auto-tuner, BLAKE3 leaves, Group-Fsync) remain disabled until every replica advertises support. ControlPlaneRaft logs `FeatureResume` once reenabling succeeds so auditors can correlate the feature matrix with the upgrade.

### 11.2 DR Fencing Enforcement
1. ControlPlaneRaft writes `(fence_epoch, manifest_id)` and lists participating partitions.
2. Each partition appends `FenceCommit{fence_epoch, manifest_id, dr_cluster_id}` and reports `fence_committed_index` once `wal_committed_index` covers it.
3. ControlPlaneRaft flips tenant/placement state only after all partitions acknowledge. Aborts append `FenceAbort{fence_epoch}` and require a fresh epoch for retries.
4. Any mismatched fence forces immediate step-down and `fence_reject_reason` in `boot_record`.

### 11.3 Key Material Epochs
- ControlPlaneRaft tracks `{kek_version, dek_epoch, integrity_mac_epoch}` per partition. Nodes fetch keys via the KeyProvider; grace to retrieve updates: `key_fetch.grace_ms = 30000`. Expiry quarantines the replica (`KeyEpochMismatch`).
- Dual-validity windows keep old/new KEKs valid for `trust.dual_validity_ms = 600000` **for decryption only**; encryption and proof publication always use the newest ControlPlaneRaft-issued epoch once it is locally available so fresh ciphertext never regresses to an older key.
- ControlPlaneRaft persists every epoch update in the durability ledger with a strictly monotone `{epoch, updated_at}` pair. Replicas MUST reject any ControlPlaneRaft snapshot or log replay that attempts to decrease an epoch, and the override ledger MUST record the ticket/TTL whenever operators temporarily widen the acceptance window.

### 11.4 System Log Entry Catalog
| Entry | Wire ID | Fields |
| --- | --- | --- |
| `MembershipChange` | 0x01 | `{old_members[], new_members[], routing_epoch}` |
| `MembershipRollback` | 0x02 | `{reason, failing_nodes[], override_ref}` |
| `DurabilityTransition` | 0x03 | `{from_mode, to_mode, effective_index, durability_mode_epoch}` |
| `FenceCommit` | 0x04 | `{fence_epoch, manifest_id, dr_cluster_id}` |
| `DefineActivate` | 0x05 | `{bundle_id, barrier_id, partitions[], readiness_digest}` |

[Normative] This catalog is emitted verbatim as `system_log_catalog.json` alongside `wire_catalog.json`; spec-lint fails the build if §11.4 drifts from §0.3’s system-entry list or if either table diverges from the generated artifact. Editors therefore MUST edit the generator and regenerate the bundles instead of hand-editing the Markdown when assigning IDs.

`DurabilityAck` messages persist `{last_fsynced_index, segment_seq, io_writer_mode}` before replying.

Encoding contract: every system log entry packs its fields in the listed order using the frozen binary rules from §0.3 (`u8` enums, little-endian fixed widths, `u16` array counts, `u32` byte lengths). Senders append new optional fields only at the tail with a preceding `u8 has_field` flag; receivers MUST ignore recognized tail fields they don't understand while rejecting unknown mandatory slots. gRPC mirrors expose numeric enums, while JSON shadows return the canonical enum string and accept both string and numeric inputs for upgrades.

### 11.5 Definition Bundles, Activation Barriers & Readiness Telemetry
[Normative] `DefinitionBundle` objects are ControlPlaneRaft-authored records `{bundle_id, version, sha256, definition_blob, warmup_recipe, emitted_at_ms}`. Leaders MUST verify the `sha256` prior to staging, persist the bundle under `state/<partition_id>/definitions/<bundle_id>.blob`, and refuse the bundle if either the digest mismatches or the referenced emit-version differs from the current `emit_version`. ControlPlaneRaft retains at least two historical bundles per partition so rollback tooling can compare digests byte-for-byte.
[Normative] Each `ActivationBarrier` references one `bundle_id`, embeds `{barrier_id, readiness_threshold (0–1], warmup_deadline_ms, readiness_window_ms}`, and lists the partitions that must report readiness. ControlPlaneRaft declines to append `DefineActivate` unless every listed partition publishes `partition_ready_ratio >= readiness_threshold` within the deadline window and signs the `WarmupReadiness` record; missing ratios or expired deadlines automatically cancel the barrier with `ActivationBarrierExpired`.
[Normative] Data-plane replicas MUST maintain `shadow_apply_state ∈ {Pending, Replaying, Ready, Expired}`, `shadow_apply_checkpoint_index`, `shadow_apply_lag_ms`, and `warmup_ready_ratio` metrics per bundle. These metrics feed the replicated `WarmupReadiness` objects and `/readyz`; `shadow_apply_state=Ready` requires replaying the staged bundle through a shadow apply queue, verifying AP pane/dedup digests (§8.4), and persisting `shadow_apply_checkpoint_index >= activation_checkpoint_index`. ControlPlaneRaft refuses to transition the barrier if any replica still reports `shadow_apply_state ∈ {Pending, Replaying}`.
[Normative] `/readyz` responses MUST surface `{definition_bundle_id, activation_barrier_id, shadow_apply_state, warmup_ready_ratio, partition_ready_ratio, readiness_digest}` so that upstream controllers can gate DEFINE_ACTIVATE submissions using the same schema expected by the downstream hot-reload pipeline. `readiness_digest = sha256(sorted(WarmupReadiness.records))` and is echoed inside the `DefineActivate` log entry; nodes reject the entry unless the digest matches the values they most recently published. `/readyz` also reports `feature.<name>_gate_state`, `feature.<name>_predicate_digest`, and `feature.<name>_gate_state_digest` for `{incremental_snapshots, leader_leases, observers, blake3_leaves, pid_auto_tuner}` so control planes can confirm the active capability set.
[Operational] Nodes publish `readiness.publish_period_ms` (default 1000 ms) and `readiness.skipped_publications_total` so dashboards alert when readiness data goes stale. Explain APIs (`WhyNotReady`, `/readyz`) MUST quote the bundle/barrier IDs plus the blocking ratios to keep the DefinitionBundle contract debuggable without sampling ControlPlaneRaft directly.

---

## 12  Security & Isolation

### 12.1 mTLS & SPIFFE Rotation
- All node-to-node RPCs use mTLS with SPIFFE identities. Rotation: upload new trust bundle → dual-validity (`trust.dual_validity_ms = 600000`) → drop old bundle once every peer confirms. Short-lived certs (≤24 h) require fresh CRL/OCSP material; nodes fail closed if revocation data exceeds `revocation.max_staleness_ms = 300000`, and the absence of either feed is treated as “stale” immediately rather than waiting for the timer to elapse. Break-glass tokens can bypass revocation temporarily with audit reason.
- [Normative] Trust-domain hygiene: nodes MUST attempt revocation refresh in the following order—(1) OCSP stapling cache, (2) CRL fetch, (3) out-of-band break-glass waiver. If both OCSP and CRL material remain older than `revocation.fail_closed_ms = 600000` **or** if both feeds are simultaneously unavailable, peers MUST tear down every mTLS connection and enter Quarantine until fresh material arrives or a signed waiver is deployed. Break-glass waivers MAY extend the deadline by at most `revocation.waiver_extension_ms = 300000` and MUST cite a ticket ID mirrored in the override ledger so the boundary between ControlPlaneRaft and data plane stays auditable.

### 12.2 AEAD Usage & Re-Encryption
- WAL segments and snapshot chunks use AEAD with 64-bit `segment_seq` and `block_counter` fields forming the nonce, where `block_counter` advances in `wal.crypto_block_bytes` increments. Tags and MAC epochs bind ciphertext to `{partition_id, dek_epoch, segment_seq}`. `.idx` files remain plaintext but carry HMAC footers keyed by `integrity_mac_epoch`.
- Re-encryption jobs stream data through an AEAD rewriter, allocate fresh `segment_seq` ranges via ControlPlaneRaft, and mark segments `rewrite_inflight` until `rewrite_complete` is fsync'd. Partial rewrites quarantine partitions until resumed; resumption MUST allocate a brand-new `segment_seq`, append `NonceReservationAbandon{segment_seq_old, abandon_reason=Rewrite}`, and only then continue emitting ciphertext under the latest `dek_epoch`. Encrypting new blocks always uses the newest epoch/key; dual-validity windows apply solely to decryption so replicas can read older ciphertext while keys roll.
[Normative] WAL segments, checkpoint manifests, and snapshot chunks are pinned to AES-256-GCM (`crypto.wal_aead_suite = AES_256_GCM`, `crypto.snapshot_aead_suite = AES_256_GCM`). Cipher-suite changes are forbidden in v0.1; attempting to configure any other AEAD results in `CryptoSuiteRejected`. ControlPlaneRaft records the selected suite per cluster generation so forensic tooling can re-verify ciphertext with the exact algorithm.
[Normative] AES-256-GCM, SHA-256, and HMAC-SHA256 implementations MUST be sourced from FIPS 140-3 validated modules recorded as `{module_id, validation_cert_sha256}` inside ControlPlaneRaft. spec-self-test verifies that the loaded crypto provider digest matches the recorded certificate before a node mounts any partition; mismatches or unverifiable modules force bootstrap to fail with `FipsModuleMismatch` so audits can prove every deployed primitive passed independent validation.
[Normative] Cryptographic agility follows a three-step governance process: (1) the proposed AEAD suite is documented with interoperability predicates and simulator coverage, (2) §0 (Consensus Core) is amended to list the suite and its negotiation bits, and (3) a new `integrity_mac_epoch`/`crypto.*_aead_suite` pair is ratified via `consensus_core_manifest.json`. No binary may enable a new suite until all three steps land in the same release, ensuring auditors can trace the proposal → specification update → manifest entry without relying on tribal knowledge.
[Normative] Hardware accelerators or kernel providers that cache DEKs/KEKs (e.g., AES-NI wrappers, QAT cards, TLS NICs) MUST expose deterministic zeroization hooks. After every DEK rotation, reencryption abort, or accelerator reset, nodes invoke `crypto.zeroize_context` and emit `crypto.zeroization_digest = sha256(last_zeroize_result)`; accelerators MUST confirm that all cached material has been overwritten with zeros (or a fixed poison pattern) before acknowledging. Failure to observe the zeroization completion bit or digest mismatch places the partition in Quarantine and raises `CryptoZeroizationFailed`, preventing hardware caches from leaking historical keys.
[Normative] ControlPlaneRaft issues a fresh DEK every `crypto.dek_rotation_period_ms = 604800000` (weekly). Nodes MUST fetch and begin encrypting with the new DEK immediately, retain the prior DEK for decryption-only use for `crypto.dual_read_window_ms = 172800000` (48 h), then zeroize it. The dual-read window is measured against the ControlPlaneRaft timestamp embedded in the signed `dek_epoch` record; data-plane nodes MAY apply at most ±5,000 ms correction for local clock skew (derived from the same `clock_guard` service) before declaring the window expired. Operators therefore have a precise 48 h wall-clock overlap regardless of leap seconds or NTP adjustments. The rotation schedule is shared across data and checkpoints so snapshot emitters never lag more than the 48 h window; partitions that miss the window self-quarantine with `DekRotationMissed`.
[Normative] Every WAL append and snapshot emission records the blocking time spent waiting on the Key Management Service in `wal_kms_block_seconds` (monotone) and `snapshot_kms_block_seconds`. Nodes MUST page when either counter grows by >300 s within an hour, and Explain APIs MUST surface the counters so operators can diagnose KMS stalls. ControlPlaneRaft refuses to finalize a rotation if any replica reports `wal_kms_block_seconds_delta > 300` without an acknowledged `KeyRotationOverride`.
[Operational] Rotation deferrals require an override ledger entry `KeyRotationOverride{reason, ticket_url, expires_at_ms}` approved by ControlPlaneRaft; overrides grant at most one additional rotation period and MUST cite the impacted partitions. Telemetry `crypto.rotation_override_active=1` plus the override ID is included in `/readyz` and audit logs so downstream services understand why the shared rotation schedule drifted.

### 12.3 RBAC & Break-Glass Controls
| Role | Capabilities |
| --- | --- |
| Operator | Partition lifecycle, durability changes, `TransferLeader`, snapshot triggers/imports. |
| TenantAdmin | Read telemetry, per-tenant flow overrides within quotas. |
| Observer | Read-only metrics and Explain APIs. |
| BreakGlass | Required for destructive/risk-expanding APIs (survivability overrides, Group-Fsync re-enables, key rotations, `AdminResumePartition` from quarantine, throttle overrides beyond quota). |

RBAC manifests replicate via ControlPlaneRaft; caches refresh every 30 s. Failure to refresh twice enters fail-secure mode: admin APIs reject with `RBACUnavailable`, data plane continues for `rbac.grace_ms = 60000` using last known manifest, and telemetry surfaces `rbac_cache_stale`.

**Break-Glass token issuance (normative):**
- Tokens are minted only by ControlPlaneRaft via `IssueBreakGlassToken{scope, ticket_url, expires_at}` after a dual-approval workflow that records the request in the override ledger. Operators never self-mint tokens from data-plane nodes.
- Tokens MUST be encoded as SPIFFE X.509 SVIDs that carry the extension `urn:clustor:breakglass:<scope>` plus the ticket URL in `subjectAltName`. The SVID lifetime is capped at `breakglass.max_ttl_ms = 300000` (5 min) and cannot be renewed; clients must request a fresh token after expiry.
- Scopes enumerate the concrete API set (`DurabilityOverride`, `SurvivabilityOverride`, `ThrottleOverride`, etc.). Nodes MUST reject a token whose scope does not match the attempted API, whose TTL has elapsed, or whose SPIFFE trust domain differs from the cluster’s configured domain.
- [Normative] Token validity calculations use the local monotonic clock with ±5,000 ms allowance for skew; nodes therefore reject tokens whose `not_before` is more than 5 s in the future or whose `not_after` passed more than 5 s ago, preventing disputes during leap seconds or NTP step events while still honoring the 5 min TTL.
- Every token is bound to `{cluster_id, partition_or_global_scope, actor_id}` and logged in the override ledger with `used_at` timestamps and the exact SPIFFE ID that exercised it (`used_by_spiffe_id`). Data-plane components MUST emit `breakglass_token_used{scope, actor_id, ticket_url}` telemetry on first use and MUST zeroize the SVID immediately afterward so it cannot be replayed.
[Normative] Each BreakGlassTokenCA rotation MUST publish `breakglass_revocation_manifest.json`, a CPReleaseKey-signed document that lists the retiring intermediates’ serial numbers, validity windows, and rotation ticket IDs. Data-plane nodes fetch and apply the manifest (revoking every listed intermediate) before trusting the new CA, and spec-lint refuses builds whose manifest is missing or unsigned so short-lived certs cannot linger in caches.
[Normative] Break-Glass usage is also persisted in `security/breakglass_audit.log`, a Canonical JSONL stream whose entries are
```
{
  "log_version": 1,
  "cluster_id": "<uuid>",
  "partition_scope": "<partition_id|global>",
  "scope": "<DurabilityOverride|...>",
  "token_id": "<uuidv7>",
  "ticket_url": "<https://...>",
  "issued_at_ms": "<string wide-int>",
  "used_at_ms": "<string wide-int>",
  "actor_spiffe_id": "spiffe://...",
  "api": "<API invoked>",
  "result": "Success|Rejected",
  "signature": "<Ed25519 signature over the canonical entry>"
}
```
Entries are batched into 1,000-line segments; each segment’s SHA-256 is signed by the same Ed25519 key used for the audit stream in §14.1 and retained for ≥400 days. `SubscribeAuditLog` returns the raw entries plus the segment signature so downstream tooling can verify scope usage without scraping `App.D`.

### 12.4 Key Purpose Registry
| Key name | Signing scope | Artifacts covered | Rotation / storage requirements |
| --- | --- | --- | --- |
| `ReleaseAutomationKey` (Ed25519) | Build pipeline | `consensus_core_manifest.json`, `wire_catalog.json`, `chunked_list_schema.json`, `proof_bundle_signature` | Hardware-backed HSM in CI; rotates every 180 days or on personnel change; public half ships with release bundles so data-plane binaries can pin it. |
| `CPReleaseKey` (Ed25519) | Control-plane Raft | `feature_manifest.json`, override-ledger objects, durability-ledger acknowledgements | Stored in ControlPlaneRaft’s KMS-backed secret store with dual-control release; rotation coupled to ControlPlaneRaft minor upgrades and recorded in the override ledger. |
| `AuditLogKey` (Ed25519) | Security/audit plane | `security/breakglass_audit.log` segment digests, `/SubscribeAuditLog` stream signatures | Lives in a dedicated audit HSM; rotates annually with overlap so historical logs remain verifiable for ≥400 days. |
| `BreakGlassTokenCA` (SPIFFE CA) | Short-lived SVIDs | Break-Glass token certificates (`urn:clustor:breakglass:*`) | Uses the same mTLS CA infrastructure but with a 45-day rolling intermediate dedicated to tokens; every rotation overlaps the prior intermediate by ≥7 days and is recorded in ControlPlaneRaft so data-plane nodes can reject stale or non-overlapping intermediates immediately. |

[Normative] Implementations MUST keep these keys disjoint; no key may sign artifacts outside its row. Telemetry MUST expose `{release_automation_pubkey_id, controlplane_release_pubkey_id, audit_log_pubkey_id, breakglass_ca_id}` so auditors can confirm that every node trusts the expected hierarchy, and spec-lint fails the build if any artifact references an unknown key ID.

---

## 13  Admin & Lifecycle APIs
All admin APIs are gRPC/JSON dual surfaces; every mutating request requires `Idempotency-Key` (retained 24 h by default, up to 7 days per policy).

| Category | Endpoints (sample) | Notes |
| --- | --- | --- |
| Partition lifecycle | `CreatePartition`, `DeletePartition`, `MovePartition`, `DryRunMovePartition` | Idempotent ControlPlaneRaft transactions. |
| Replica management | `CreateReplica`, `AdminPausePartition`, `AdminResumePartition` | Resume while quarantined is Break-Glass. |
| Durability | `SetDurabilityMode`, `GetDurabilityMode` | Mode changes append `DurabilityTransition{from,to,effective_index}`; stale callers receive `ModeConflict` (HTTP 409). |
| Snapshots | `TriggerSnapshot`, `ListSnapshots`, `DownloadSnapshot`, `UploadSnapshot`, `DryRunSnapshot`, `SnapshotFullOverride` | Overrides are time-boxed and audited. |
| Flow control | `GetPartitionBacklog`, `OverrideCredit`, `WhyCreditZero` | Overrides require TTL + justification. |
| DR ops | `BeginFailover`, `CompleteFailover`, `AbortFailover`, `DryRunFailover` | Align with §11.2 fencing. |
| Telemetry | `SetMetricsLevel`, `SubscribeAuditLog`, `WhyNotLeader`, `WhyDiskBlocked`, `WhySnapshotBlocked` | Shared schema header (`schema_version`, `generated_at`). |

Dry-run endpoints report guardrails and computed parameters (e.g., auto-scaled catch-up slack/timeout, predicted credit impact). Explain APIs always include `routing_epoch`, `durability_mode_epoch`, observed vs expected guardrail, and `decision_trace_id` when relevant.

Runbook snippets (normative summaries only):
1. **Disk replacement:** pause partition, verify latest snapshot, replace disk, rerun startup scrub, rejoin via `CreateReplica`.
2. **Hot partition rebalance:** require `Q`/`H` healthy, lag below thresholds; run `DryRunMovePartition`, execute move, confirm `WhyNotLeader` reflects new placement.
3. **Leadership transfer:** ensure Group-Fsync healthy, no structural lag, `apply_queue_depth < 10%`; issue `TransferLeader`, wait `commit_quiescence_ms = 200`, then drain.
4. **DR failover:** require ControlPlaneRaft reachable, fence mismatch clear, lag ≤128 KiB; `BeginFailover`, verify first entry includes `(fence_epoch, manifest_id)`, `CompleteFailover` once lag=0.
5. **Snapshot seeding:** ensure delta chain < cap or plan full snapshot, NIC utilization <70%; run `DryRunSnapshot`, then transfer and verify signature.
6. **Certificate rotation:** upload bundle, observe dual-validity, drop old bundle after all nodes report adoption.

### 13.1 ControlPlaneRaft Outage Behavior (Runbook Tile)
- **Detection:** Page when `controlplane.cache_state ∈ {Stale, Expired}` or when `strict_only_runtime_ms` exceeds `controlplane.strict_only_backpressure_ms` (§11.1). Expect `strict_fallback_state=LocalOnly`, `ControlPlaneUnavailable` incidents, and throttle envelopes that cite `ControlPlaneUnavailable{reason=NeededForReadIndex}`.
- **Client error mapping:** Leaders continue to accept writes (Strict only) but every linearizable read returns HTTP 503 / gRPC `UNAVAILABLE` with `ControlPlaneUnavailable{reason=NeededForReadIndex}`, `Retry-After ≥ 250 ms`, and the `{controlplane_last_durable_*, leader_commit_*}` metadata from §3.3. Admin mutations fail with `ControlPlaneUnavailable{reason=CacheExpired}` once caches exceed `controlplane.cache_grace_ms`. These codes are normative; custom surfaces MUST NOT remap them.
- **Retry/backoff:** Clients MUST honor the provided `Retry-After` or, when absent, back off exponentially starting at ≥250 ms with full jitter, capping at 5 s. Busy-loop retries are forbidden and treated as misbehaving tenants via throttles.
- **Fallback reads:** Products that require availability during outages MUST pre-wire snapshot-style fallbacks (`FollowerReadSnapshot` or exported snapshots). Responses MUST continue to carry `read_semantics=SnapshotOnly`, epoch headers, and capability checks so clients cannot accidentally treat them as linearizable results. Document any dataset-specific caveats (e.g., “metadata may lag up to N seconds”) in the product SLO.
- **SLO impact:** While ControlPlaneRaft is unreachable the cluster remains in Strict durability and halves credits after `controlplane.strict_only_backpressure_ms`; §11.1 notes that write latency typically regresses by 40–60% and throughput drops accordingly. Operators SHOULD communicate the degraded SLO externally and track recovery in incident tooling.
- **Product-team expectations:** Every product surface that embeds Clustor MUST document (a) how `ControlPlaneUnavailable` propagates to customers, (b) the supported snapshot/read fallback, and (c) operational steps to revalidate data once ControlPlaneRaft returns. Launch reviews fail if these artifacts are missing.

---

## 14  Telemetry & Observability
- Metric namespaces: `clustor.raft.*`, `clustor.wal.*`, `clustor.snapshot.*`, `clustor.flow.*`, `clustor.controlplane.*`, `clustor.security.*`. In this document, the `controlplane.*` metric and field prefix refers exclusively to ControlPlaneRaft.
- Every exporter MUST emit `metrics.schema_version` (u32) and `metrics.build_git_sha` in both `/readyz` and the metrics stream; the value is baked at build time and bumps whenever metric names or bucket definitions change so dashboards can detect incompatible renames automatically.
- Naming convention: metrics MUST use dotted Prometheus-style names rooted at `clustor.*` (e.g., `clustor.raft.commit_latency_ms`), incidents MUST use the same namespace suffixed with `.incident.*`, and JSON payload fields remain snake_case (matching the API schema and the canonical field list emitted from §0.3’s wide-int catalog). Spec-lint validates new metric names against this pattern so exporters never need per-signal translation layers.
- Canonical histogram buckets (latency in ms unless noted):
  - `clustor.wal.fsync_latency_ms`: `[0.25, 0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100]`
  - `clustor.raft.commit_latency_ms`: `[0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100]`
- `clustor.snapshot.transfer_seconds`: `[1, 2, 4, 8, 16, 32, 64, 128, 256]`
- `flow.apply_batch_latency_ms`: `[0.25, 0.5, 1, 2, 4, 6, 8, 10]`
- [Normative] These bucket edges are generated from `metrics_buckets.json` inside the telemetry bundle; spec-lint compares App.A and §14 against that artifact every build, so editors MUST regenerate the bundle (never hand-edit Markdown) when tuning SLO buckets.
- Out-of-profile systems (e.g., WAN, ZFS-on-HDD) are expected to saturate the top bucket; alerts still fire if the p99 exceeds the App.A bands even when measurements clamp at the bucket ceiling.
- ControlPlaneRaft metrics expose `controlplane.ledger_status ∈ {Fresh, Cached, Stale}` and `controlplane.cache_age_ms` so leaders can explain Strict fallbacks.
- Operators running ≥2,000 partitions per node SHOULD enable the optional aggregation layer described in App.A: per-partition histograms may be down-sampled to 0.2 Hz or aggregated into cohort-level histograms so long as the SLO guardrails in App.A continue to evaluate against the reconstructed percentiles. Implementations MUST expose the sampling rate via `metrics.sample_rate` so observability tooling can rescale alerts.

### 14.1 Golden Signals & Incident Logging
- Alerts from App.A feed correlated incident logs once breached for `alerts.incident_correlation_window = 120 s`. Incidents bundle durability mode, credit levels, leader term, recent admin actions, and remediation hints. Cooldown: `alerts.incident_emit_cooldown_ms = 300000`; the storm guard cap scales with node density as `incident_max_per_window = max(5, ceil(active_partitions_on_node / 250))` per 10 min, while `SafetyCritical` classes (durability regression, key epoch lag, fence mismatch) remain exempt so cascading failures still surface immediately.
- Audit logs are signed JSON batches (Ed25519) with 400-day retention; AEAD AAD = `{cluster_id, controlplane_epoch, wall_clock_bucket}`.
- Metrics cardinality guardrails cap active `partition_id` series at 2048 per node; high-cardinality labels sample at `metrics.high_cardinality_sample_rate = 0.1`. Evictions emit `metrics_cardinality_dropped`.
- [Normative] Every dynamic capability—incremental snapshots, leader leases, observer admission, BLAKE3 Merkle leaves, and the PID auto-tuner—MUST export `feature.<name>_gate_state ∈ {Enabled,Disabled,Revoked}` and `feature.<name>_predicate_digest` (sha256 over the enabling predicate inputs). `/readyz` exposes the same values plus `feature.<name>_gate_state_digest` so automation can prove the feature matrix matches the running binary. Spec-lint cross-checks the telemetry bundle against this list to ensure no capability ships without the matching metrics.

### 14.2 Startup Spec Self-Tests
- Before a partition advertises readiness (and again after every binary upgrade), the node MUST execute `spec_self_test` while still in bootstrap: the procedure recalculates the local `wire_catalog.json`, `chunked_list_schema.json`, and wide-int catalog from the shipping code, compares them byte-for-byte with the artifacts generated at build time (§0.3), and refuses to mount the partition if any diff is observed.
- The same self-test replays the canonical `PreVoteResponse`, `ChunkedList`, and JSON fixtures from App.C plus the snapshot-manifest and segment-MAC vectors (§8.1, §5.1). It also executes the lease inequality suite (§3.3), the incremental snapshot authorization cadence (§8.4), and the BLAKE3 leaf vectors (App.C) so binaries cannot ship without verifying the active feature set. Failures raise `SpecSelfTestFailed{fixture}` telemetry, mark the node Quarantined, and require an operator override to proceed.
- Nodes persist the most recent `spec_self_test` result (timestamp, git hash, fixture version) in `boot_record.json` and emit `clustor.spec.self_test_duration_ms`/`clustor.spec.self_test_fail_total` metrics so fleet automation can confirm the checks ran on every restart. CI MUST reject releases whose binaries omit the self-test hook.

---

## 15  Deployment & Bootstrap

### 15.1 Bootstrap & Disk Hygiene
1. Start ControlPlaneRaft (3 or 5 nodes) and load tenant/partition manifests.
2. Launch data-plane nodes referencing ControlPlaneRaft endpoints; bootstrap refuses unassigned partitions or stale disks.
3. Nodes run startup scrub (§6.3) before joining quorum.
- Disk policy verification (blocking, per §1.2.1 table):
  - Read `/proc/mounts` and `/sys/block/<dev>/queue/write_cache` to ensure the cache mode matches the table (write through or write back with FUA). Violations raise `DiskPolicyViolation{reason=WriteCache}`.
  - Inspect `/sys/block/<dev>/queue/fua` and `/sys/block/<dev>/queue/flush` to confirm barrier support; failures quarantine the node even if mount options look correct.
  - Validate ext4 mounts use `data=ordered`, `commit<=5`, and keep `auto_da_alloc` enabled; warn (but do not block) when `journal_async_commit` is absent if latency SLOs require it. Reject XFS mounts that attempt to disable barriers even if the option is deprecated, and confirm ZFS datasets advertise `sync=always` + `logbias=throughput`.
  - For dm-crypt/mdraid stacks, validate the effective `/sys/block/<stacked>/queue/*` flags as well as the underlying physical devices; mismatches between layers trigger `DiskPolicyViolation{reason=StackedDeviceInconclusive}` until operators provide an explicit allow-list. The allow-list is a ControlPlaneRaft object (`disk_override`) that records the exact device paths, attested `queue/*` capabilities, author, TTL, and ticket; nodes remain quarantined until such an entry exists and matches the observed topology.
  - Reconcile detected filesystem UUIDs with prior boot records to ensure disks were not hot-swapped without operator intent.
  - CI environments that rely on loopback devices or ephemeral cloud volumes MUST register an explicit `disk_override` describing the synthetic topology (including TTL) before tests run; otherwise bootstrap halts to avoid silently accepting lossy backing stores.

### 15.2 Graceful Shutdown
- Prefer `TransferLeader`, wait `commit_quiescence_ms = 200`, ensure `apply_queue_depth < 10%`, flush WAL/checkpoints, then stop listeners. Force shutdown after `graceful_shutdown_timeout_ms = 10000` with telemetry explaining the reason.

### 15.3 Kubernetes & Host Guidance
- Run as StatefulSets with PDB `maxUnavailable=1`, anti-affinity (≤1 voter per node/zone). In single-AZ clusters this degenerates to “one voter per node” while still using topologySpreadConstraints for rack/zonal labels so the requirement remains meaningful. Pods expose `/state` with read-write volume; other paths read-only.
- Set `terminationGracePeriodSeconds ≥ graceful_shutdown_timeout_ms` (10 s default) so `TransferLeader` + WAL flush finish before the kubelet SIGKILLs the pod; shorter windows are rejected by admission webhooks.
- Require cgroup v2 with `io.max`, Linux ≥5.15 with `io_uring`, and dedicated storage (NVMe preferred). Unsupported mounts (no barriers, unsafe write cache, missing `sync=always` on ZFS) are rejected during bootstrap.
- Sidecars (snapshot service, log shipper) run with least privilege; pods needing encrypted WALs require `CAP_IPC_LOCK` to pin keys.

### 15.4 Configuration Profiles
Profiles are declarative bundles that gate hard limits and defaults (details in App.B). Validators reject configs exceeding profile bounds; feature gates must be homogeneous per voter set.

### 15.5 Repair-Mode Bootstrap
- `bootstrap.repair_mode=true` mounts partitions read-only, runs scrub, and blocks quorum participation.
- Operators can download/upload snapshots for offline repair.
- `AdminResumePartition` (Break-Glass) remounts read-write, forces snapshot import to refresh dedupe state, clears quarantine, and rejoins quorum.

---

## 16  Summary of Guarantees
| Area | Guarantee |
| --- | --- |
| Ordering | Raft total order per partition enforced by §0/§3 invariants. |
| Durability | Strict or Group-Fsync with `DurabilityTransition` fencing and automatic downgrade. |
| Recovery | Crash-safe WAL replay + scrub reports + boot records. |
| Control Plane | ControlPlaneRaft manages placements, durability ledger, DR fences, and feature gates. |
| Extensibility | Codec hooks, apply callbacks, snapshot plugins with mandatory tracing metadata. |
| Observability | Golden signals, Explain APIs, signed audits, throttle envelopes. |
| Security | AEAD everywhere, SPIFFE/mTLS, RBAC with break-glass audit. |
| Read Availability | Linearizable reads depend on ControlPlaneRaft durability proofs; during ControlPlaneRaft outages only Strict-mode writes and snapshot-style reads continue (§3.3). |
| Operations | Documented runbooks, dry-run tooling, Kubernetes-ready defaults. |

---

## Appendix A App.A – SLOs & Alerts
| Signal | Target | Alert Threshold | Notes |
| --- | --- | --- | --- |
| `clustor.raft.commit_latency_ms` (p99) | ≤15 ms | ≥25 ms for 2 min | Drives `commit_latency_breach`. |
| `clustor.wal.fsync_latency_ms` (p99) | ≤10 ms | ≥20 ms for 3 batches | Forces Strict downgrade. |
| `clustor.flow.ingest_ops_per_sec` (per profile) | ≥ profile target (App.B) | < profile alert floor for 5 min | Ensures throughput SLOs are enforced alongside latency/durability. |
| `clustor.flow.zero_credit_duration_ms` | 0 | ≥500 ms | Triggers throttle envelopes. |
| `clustor.snapshot.staleness_seconds` | ≤120 | ≥300 | Signals snapshot backlog. |
| `clustor.controlplane.epoch_drift` | 0 | >0 | Indicates ControlPlaneRaft/Data desync. |
| `clustor.security.key_epoch_lag` | 0 | >1 epoch | Blocks new leaders. |
| `clustor.raft.commit_visibility_gap_ms` | 0 | >0 for `alerts.commit_visibility_gap_ms=5000` | Warns reads running ahead of durability. |
| `clustor.controlplane.ledger_status` | `Fresh` | `Stale` for >`controlplane.cache_grace_ms` | Forces Strict fallback. |

Default `alerts.commit_visibility_gap_ms` values: Latency/ConsistencyProfile = 0 (alert immediately), Throughput = 5000 ms, WAN = 10000 ms. Profiles that deviate MUST document the new bound in their runbooks.
[Normative] To prevent metrics-store saturation, every profile now publishes `metrics.partition_histogram_sample_period_ms` in App.A. The default sample period remains 1000 ms; large fleets (≥2,000 active partitions per node) MAY relax it up to 5000 ms but MUST record the chosen value and resulting `metrics.sample_rate = 1000 / sample_period_ms` in telemetry. Sampling below 1000 ms (e.g., 200 ms high-resolution mode) is still permitted but MUST likewise be documented. spec-lint fails configuration bundles where the published sample period is missing or exceeds the 5 s ceiling, and `/readyz` plus Explain APIs MUST surface the same sampling interval so SLO tooling can compensate for down-sampled percentiles.

---

## Appendix B App.B – Operational Profiles (Highlights)
| Profile | Defaults | Hard Limits |
| --- | --- | --- |
| Latency / ConsistencyProfile | Strict durability, `target_latency_ms=10`, `target_backlog_entries=128`, incremental snapshots enabled (10 s delta / 30 s full cadence), leases supported but default `lease_gap_max=0`, Merkle enabled, observers allowed (≤2) with dedicated bandwidth pool, PID auto-tuner disabled, `ingest_ops_target=50k/s`, `strict_fallback_local_only_demote_ms_profile=14,400,000`, `controlplane.durability_proof_ttl_ms_profile=43,200,000` (12 h). | Rejects `batch_bytes > 64 KiB` or `sample_period_ms > 100`; leases may only be enabled when the inequality holds; `apply.max_batch_ns` hard ceiling 2 ms; `ack_handle.max_defer_ms` hard ceiling 250 ms; throughput alert floor 40k/s; BLAKE3 leaves and PID auto-tuner forbidden. |
| Throughput | Group-Fsync on, `target_latency_ms=40`, `target_backlog_entries=1024`, incremental snapshots enabled, leases enabled by default (`lease_gap_max=1024`), observers allowed (≤2), PID auto-tuner enabled when `io_writer_mode=FixedUring`, BLAKE3 leaves optional, `CommitAllowsPreDurable` available, `ingest_ops_target=120k/s`, `strict_fallback_local_only_demote_ms_profile=14,400,000`, `controlplane.durability_proof_ttl_ms_profile=86,400,000` (24 h). | `group_fsync.max_inflight_bytes_per_partition ≤ 8 MiB`; `apply.max_batch_ns` ceiling 4 ms; `ack_handle.max_defer_ms` ceiling 400 ms; throughput alert floor 100k/s. |
| WAN | Election timeout `[300,600]`, `pre_vote.max_rtt_ms=500`, incremental snapshots enabled, leases disabled (`lease_gap_max=0`), observers allowed (≤2) subject to WAN bandwidth accounting, PID auto-tuner enabled when `io_writer_mode=FixedUring`, BLAKE3 leaves optional, `ingest_ops_target=25k/s`, `strict_fallback_local_only_demote_ms_profile=21,600,000`, `controlplane.durability_proof_ttl_ms_profile=64,800,000` (18 h). | Requires healthy PTP/GPS; `clock_skew_bound_ms ≤ 50`; `apply.max_batch_ns` ceiling 5 ms; `ack_handle.max_defer_ms` ceiling 500 ms; throughput alert floor 20k/s. |
| ZFS | `wal.segment_bytes ≥ 2 GiB`, `durability.max_device_latency_ms=40`, incremental snapshots enabled with Strict durability, Merkle mandatory, observers optional (≤2) when ControlPlaneRaft authorizes, leases/auto-tuner/BLAKE3 leaves disabled, `controlplane.durability_proof_ttl_ms_profile=43,200,000` (12 h). | Requires `sync=always`; Group-Fsync disabled unless devices prove <20 ms fsync; `apply.max_batch_ns` ceiling 2 ms. |

Profile layer controls optional integrity features (`segment.merkle_tree`) and hash suites. Only Throughput/WAN may enable `integrity.hash_suite=blake3` once all replicas agree.

### Appendix B.1 Profile Capability Matrix
[Normative] The table below is the single source of truth for which runtime gates each profile may exercise. Sections §0.5, §3.1.1, and §6.2 MUST defer to this matrix; adding a new capability requires updating this annex plus the referenced sections in the same change.

| Capability | Latency/ConsistencyProfile | Throughput | WAN | ZFS |
| --- | --- | --- | --- | --- |
| Group-Fsync eligible | ✗ | ✓ (per §6.2 predicate) | ✓ (per §6.2 predicate and WAN storage proof) | ✗ |
| Incremental snapshots (10 s / 30 s cadence) | ✓ (per §8.4) | ✓ (per §8.4) | ✓ (per §8.4) | ✓ (Strict durability only, per §8.4) |
| Observers supported | ✓ (≤2, dedicated bandwidth per §4.1) | ✓ (≤2, per §4.1) | ✓ (≤2, per §4.1) | ✓ (≤2, per §4.1) |
| Leader leases | Supported but default `lease_gap_max=0` (per §3.3) | ✓ (default on per §3.3) | ✗ | ✗ |
| `CommitAllowsPreDurable` reads | ✗ | ✓ (per §3.3) | ✗ | ✗ |
| PID auto-tuner | ✗ | ✓ (when `io_writer_mode=FixedUring`, per §10.1) | ✓ (when `io_writer_mode=FixedUring`, per §10.1) | ✗ |
| Aggregator profile allowed | ✓ (per §7.4) | ✓ (per §7.4) | ✓ (per §7.4) | ✓ (per §7.4) |
| `integrity.hash_suite=blake3` | ✗ | ✓ (once all replicas agree, per §5.1/§9.2) | ✓ (once all replicas agree, per §5.1/§9.2) | ✗ |
| Strict-fallback demote window | 4 h (per §3.1.1) | 4 h (per §3.1.1) | 6 h (per §3.1.1) | 4 h (per §3.1.1) |

Legend: ✓ = allowed when the capability’s local guardrails pass, ✗ = forbidden regardless of overrides. Where “ControlPlaneRaft-gated” appears, ControlPlaneRaft must record an explicit gate flip before the capability may activate.

---

## Appendix C App.C – Test Matrix (Representative)

### C.1 Wire Fixture Catalog (Normative)
Normative JSON string fields (servers MUST emit them as base-10 strings; clients MUST accept strings and MAY accept numerics for backwards compatibility): `$.ack_term`, `$.ack_index`, `$.append.decisions[*].index`, `$.durability_mode_epoch`, `$.routing_epoch`, `$.wal_committed_index`, `$.raft_commit_index`, `$.sm_durable_index`, `$.quorum_applied_index`, `$.last_quorum_fsynced_index`, `$.ledger.last_durable_index`, any `$.snapshot.*.version_id`, every `$.segment_seq`, and all `clustor.*` histogram bucket boundaries and `*_bytes`/`*_entries` counters surfaced via Explain/Admin APIs. This appendix is the sole authoritative catalog; §0.3 defers to it and spec-lint (`json_wide_int_catalog_test`) fails if generators or docs drift. New wide-int fields MUST update this list before landing code. CI emits the same material in a machine-readable bundle (`spec_fixtures.bundle.json` + signature) so downstream generators can diff artifacts without scraping prose.

`json_numeric_exception_list` (the only integers that MAY remain numeric in JSON because they are enums or constrained IDs) is frozen as follows:

| JSONPath | Rationale |
| --- | --- |
| `$.error_code` | Matches the wire-level numeric registry so tooling can compare IDs without string parsing. |
| `$.throttle.reason_id` (when present alongside the string `reason`) | Optional numeric mirror for histogram bucketing; never exceeds `u8`. |
| `$.wire_enum_id` fields emitted by Explain/Why* payloads | Mirrors the numeric discriminant already sent on the binary transport. |

A proposal to add a new exception MUST update this table, the machine-readable bundle, and spec-lint’s `json_numeric_exception_test`.

### C.2 Behavioral Harness Matrix (Operational)
The scenarios below describe required harnesses and expected outcomes. They complement—but do not replace—the normative wire fixtures above; vendors MAY extend the behavioral catalog so long as the required rows continue to pass.
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
| JSON & ChunkedList conformance | Wide integers serialized as decimal strings; the normative JSONPath list (App.C) MUST always emit strings; the auto-generated “wide-int catalog” golden file is diffed in CI; `entries_crc32c`/`offsets_crc32c` strings left-pad to 32 hex nibbles (case-insensitive read) and match the worked example packing; ChunkedList reassembly enforces size caps, overlap/gap detection, out-of-order delivery, total_count=0, `chunk_crc32c` rules, and rejects `has_crc=0` whenever the catalog marks the field as order-significant. | Tests inject values ≥`2^63`, verify servers still emit strings when the value < `2^53`, reject shorter/longer hex strings and case-flipped mismatches, ensure receivers reject overlapping chunks, missing CRCs, illegal `has_crc=0` usages, or zero-count lists with stray chunks, and fail fast if §0.3 drifts from the golden catalog (or if the server emits a numeric wide int, which now returns `WireWideIntNotString`). | No |
| Snapshot bandwidth hysteresis | Throttle/resume near NIC limits | Hysteresis respected (90%/60%). | No |
| ControlPlaneRaft-outage snapshot import | ControlPlaneRaft offline beyond grace | Deltas fail with `snapshot_delta_invalidated`; full snapshots succeed while trust caches valid. | No |
| Re-encryption vs compaction | Concurrent operations | `rewrite_inflight` prevents deletion; no data loss. | No |
| Metrics + incident plumbing | Golden signals, throttle envelopes | Alerts feed incidents with dedup + storm guard. | No |
| Performance baselines | Strict ≥50k appends/s @ p99 ≤12 ms; Group-Fsync ≥120k @ p99 ≤20 ms (reference HW) | Regressions >10% block releases unless waived. | No |
| Key-epoch rollback | `{kek_version, dek_epoch, integrity_mac_epoch}` replay attempts | Nodes reject any proof/log entry whose epochs regress; emits `KeyEpochReplay` and enters Strict fallback. | No (remains in Strict fallback) |

Reference HW = dual-socket x86, PCIe Gen4 NVMe, Linux ≥5.15 with `io_uring`. Profiles running on different storage or after `io_writer_mode` downgrades should treat the numbers as directional only; publish their own baselines before enforcing App.A SLOs.

### Binary Schema & `has_*` Pattern Vectors
§0.3’s encoding contract is enforced via deterministic fixtures. The length-prefixed format is `LenPrefixedBytes(payload) = <u32 little-endian byte_len> || payload`. Optional tail fields always use a leading `u8 has_field` byte (0 = absent, 1 = present) immediately before the optional value; older parsers can therefore skip the value when `has_field=0` or when the bytes are truncated. Spec-lint replays the following hex vectors and refuses releases that drift:

| Vector | Bytes (hex, little-endian) | Notes |
| --- | --- | --- |
| `LenPrefixedString("OK")` | `020000004f4b` | Demonstrates 32-bit length prefix and tight packing. |
| `PreVoteResponse{term=42, vote_granted=1, has_high_rtt=1, high_rtt=1}` | `2a00000000000000010101` | Total length 11 bytes (≥10 floor). |
| `PreVoteResponse{term=42, vote_granted=0}` (legacy peers omitting `has_high_rtt`) | `2a0000000000000000` | 9-byte legacy floor; receivers MUST treat missing bytes as `has_high_rtt=0`. |
| `FrameDeclares12ButSends8` | `0c0000002a00000000000000` | Length prefix advertises 12 payload bytes but the fixture intentionally truncates after the 8-byte `{term}` field plus the 1-byte `vote_granted`, proving receivers MUST raise `WireBodyTooShort` when the stream ends before the mandatory 10-byte floor even if `body_len` promised more. |

Vendors MAY add their own fixtures but MUST keep the §0.3 vectors byte-identical; CI compares hex dumps verbatim.

### Ledger Replay Pseudocode (§6.5)
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
        enforce_step_order(record)  // §6.5-(1)…(5b)
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
Every implementation MUST (1) stop scanning on the first failed CRC/MAC, (2) truncate the log to the last verified record (never “skip ahead”), (3) zeroize unreadable tails before replaying WAL bytes, and (4) enter Quarantine + `strict_fallback_state=LocalOnly` until ControlPlaneRaft mirrors a proof ≥ the last good record. Spec-lint runs this pseudocode against synthetic logs (good, corrupt, reordered, and missing `NonceReservationRange`) to prove identical truncation behavior.

### Strict Fallback Gate Truth Table
The normative table now lives in §0.5 so Consensus Core updates require an explicit diff. This appendix references §0.5 for tooling but continues to house telemetry fields and conformance fixtures.

### Strict Fallback Telemetry Fields
The following metric/trace fields are normative and frozen for interoperability dashboards and tests:

| Field | Meaning |
| --- | --- |
| `strict_fallback_state` | Enum `Healthy|LocalOnly|ProofPublished` exported per partition. |
| `strict_fallback_gate_blocked{operation}` | Counter labeled by `operation` (e.g., `DurabilityTransitionToGroup`, `LeaseEnable`, `FollowerCapabilityGrant`, `SnapshotDeltaEnable`) incremented every time §3.1.1 rejects the call. |
| `strict_fallback_blocking_read_index` | Boolean gauge indicating whether ReadIndex is currently suppressed. |
| `strict_fallback_last_local_proof` | Last `(term,index)` from the local ledger that justified the current state; emitted as two wide integers listed in App.C’s JSON catalog. |
| `strict_fallback_pending_entries` | Count of appends accepted since entering strict fallback but not yet covered by a ControlPlaneRaft durability proof. |
| `strict_fallback_blocking_reason` | Enum reflecting the prioritized rejection reason defined by `StrictFallbackPriorityOrder` when §0.5/§11.1 gates overlap. |
| `strict_fallback_decision_epoch` | Monotone `u64` incremented every time the gate predicate changes; all rejection telemetry must include this epoch so overlapping denials are correlated deterministically. |

Explain/Why* APIs MUST surface these exact field names (or their JSON equivalents) so tooling can rely on them without additional schema negotiation.

### Clause-to-Fixture Map
[Normative] The authoritative clause/fixture mapping ships inside `spec_fixtures.bundle.json` as `fixtures.clause_map.json`; spec-lint compares the JSON artifact to this appendix and fails the build if the files diverge. Contributors MUST update the generator and regenerate the bundle before editing the table so downstream auditors can diff prose and machine-readable evidence together.

To cut cross-referencing overhead, the table below lists representative clauses and the conformance fixture (from `spec_fixtures.bundle.json`) that enforces them:

| Clause | Fixture ID | Notes |
| --- | --- | --- |
| §0.3 PreVoteResponse layout | `wire.prevote_response_v1` | Hex dump verifies the 10-byte mandatory floor and optional tail byte. |
| §3.3 ReadIndex proof equality | `consistency.read_index_proof_match` | Simulator asserts byte-for-byte equality between cached ControlPlaneRaft durability proof and `wal/durability.log`. |
| §6.5 Ledger replay truncation | `durability.ledger_replay_strict` | Synthetic log with mid-file corruption; harness ensures truncation stops at the last good record. |
| §9.2 Segment MAC derivation | `integrity.segment_mac_v1` | Matches the worked example MAC bytes and rejects byte-order drift. |

Spec-lint fails the build if any clause loses its fixture mapping or if a fixture claims coverage for a clause not listed here.

### Snapshot Manifest & Segment-MAC Test Fixtures
- **Manifest canonical bytes:**  
  `{"base_index":4096,"base_term":7,"chunks":[{"chunk_id":"00000000-0000-0000-0000-000000000001","digest":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","len":1048576,"offset":0}],"content_hash":"0xb1caf4297447b97c418f5c52ac1b922c3c32022f61d59f73c462931b89d6ad86","emit_version":1,"encryption":{"dek_epoch":3,"iv_salt":"0x000102030405060708090a0b0c0d0e0f"},"logical_markers":[],"manifest_id":"018c0d6c-9c11-7e9d-8000-86f5bb8c0001","producer_version":"clustor-test","version_id":12}`  
  Removing the `content_hash` and `signature` fields before hashing yields `content_hash = 0xb1caf4297447b97c418f5c52ac1b922c3c32022f61d59f73c462931b89d6ad86`. Signing the canonical string above with the Ed25519 private key whose public half is `MCowBQYDK2VwAyEArsd58cxPIL53CzjGSfRe7x3whwv0yhjWEXS2rSTAqAI=` produces signature `0xe655924767bf28bca3ff9e59ad0fde247564fbd4aac11d9e98adcd56bf69b747b7ea6215046978369f29dc80760b708a34c365c94f6a50122f7e35293caaed01`. Implementations MUST verify both the hash and the signature before importing manifests.
- **Segment MAC vector:** using MAC key bytes `00 01 … 1f`, `segment_seq=7`, `first_index=42`, `last_index=121`, `entry_count=17`, `entries_crc32c=0x1032547698badcfe67452301efcdab89`, and `offsets_crc32c=0x0123456789abcdeffedcba9876543210` MUST yield `mac = 5c50cc7f43ef3c0127db59a3a8394ed16782e7997b53093c35bff32f8644b8f0`. Tooling SHOULD treat this as a self-test.

### Read Semantics Proof Artifacts
The “Model checking (TLA+/Loom)” row now requires explicit artifacts for the read-path gate: every release MUST ship (a) a TLA+ fragment that models `strict_fallback_state`, ReadIndex blocking, and `ControlPlaneUnavailable` propagation, and (b) a Loom/Jepsen scenario that demonstrates the truth-table transitions above (writes admitted, reads blocked, follower capability revoked) under ControlPlaneRaft outage. CI fails unless both artifacts cover the current parameter set referenced in §§3.1.1 and 3.3, preventing future drafts from drifting from the documented behavior.

### Lease Inequality Fixture (Normative)
Leases ship in v0.1 with profile-specific gating, and conformance tooling already exercises the inequality from §3.3 so even profiles that default `lease_gap_max=0` continue to prove the guard. The canonical vector below MUST be replayed verbatim; implementations that change any operand MUST update the table and spec-lint simultaneously.

| Profile | `min_election_timeout_ms` | `clock_skew_bound_ms` | `lease_rtt_margin_ms` | `heartbeat_period_ms` | `default_lease_duration_ms` | LHS Sum | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Latency / Base | 150 | 5 | 10 | 50 | 80 | 145 | `145 < 150` ✓ |
| Throughput | 150 | 10 | 10 | 50 | 75 | 145 | `145 < 150` ✓ |
| WAN (default gate off) | 300 | 50 | 10 | 50 | 180 | 290 | `290 < 300` ✓ (profile default keeps leases off) |

Spec-lint’s `lease_inequality_test` recomputes `lease_duration_ms + lease_rtt_margin_ms + clock_skew_bound_ms + heartbeat_period_ms` for each profile and fails if the sum is ≥ the declared `min_election_timeout_ms`.

### AEAD Tag Comparison Guidance
§0.2 and §6.3 already mandate constant-time AEAD verification; this appendix makes the requirement executable. All implementations MUST use the reference macros below (or byte-for-byte equivalents) when comparing authentication tags. The helpers are defined for 16-byte (GCM) and 32-byte (future suites) tags and are evaluated in spec-lint to ensure no early-exit paths remain:
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
- App.C conformance now includes `aead_constant_time_test`, which feeds mismatching tags that share long identical prefixes to ensure runtimes never shortcut the comparison.

### C.3 Release Evidence (Normative)
[Normative] Every public release MUST re-execute the full fixture bundle (`spec_fixtures.bundle.json`) and stamp `bundle_version = <git tag>` before cutting artifacts. spec-lint compares the bundle version, git commit, and manifest hash; releases fail if any of the three disagree or if the fixture signatures predate the tag by more than 24 hours. CI pipelines MUST persist the tuple `{bundle_version, bundle_sha256, fixture_suite_ts}` and surface it via `/readyz` (`fixtures.bundle_version`, `fixtures.bundle_age_ms`) so downstream consumers can prove that the running binary executed the exact test matrix associated with the published build.

---

## Appendix D App.D – Wire Envelopes (Shared Schema)
Every envelope returns JSON/gRPC with `{schema_version, generated_at, partition_id, routing_epoch, durability_mode_epoch}`. Binary encodings follow §0.3 (little-endian lengths, `u8` enums); JSON surfaces enums as strings but accepts numeric IDs for forward compatibility. Receivers MUST ignore unknown optional fields and reject envelopes that omit required ones. All `Why*` payload names use PascalCase (e.g., `WhyNotLeader`, `WhySnapshotBlocked`) and the casing is normative for telemetry filters.
| Envelope | Status | Notes |
| --- | --- | --- |
| `RoutingEpochMismatch` | HTTP 409 / gRPC `FAILED_PRECONDITION` | Includes `{observed_epoch, expected_epoch, lease_epoch, durability_mode_epoch}`. |
| `ModeConflict` | HTTP 409 | Returned by `SetDurabilityMode` when stale. |
| `ControlPlaneUnavailable` | HTTP 503 | `{observed_epoch, cache_age_ms, reason ∈ {CacheExpired, NeededForReadIndex}}`; admin-only except `NeededForReadIndex`, which surfaces on client reads. |
| `snapshot_full_invalidated` | HTTP 409 | Reasons: `{GraceWindowExpired, SchemaBump, EmitVersionChange, DekEpochRollover}`. |
| `snapshot_delta_invalidated` | HTTP 409 | Reasons: above plus `DeltaChainLength`. |
| `ThrottleEnvelope` | HTTP 429 / gRPC `RESOURCE_EXHAUSTED` | Payload per §10.3 (includes dual credit counters). |
| `Why*` payloads | HTTP 200 | `WhyNotLeader`, `WhyDiskBlocked`, `WhySnapshotBlocked`, etc. share schema header and MUST include `truncated_ids_count` (absent/0 when no truncation) whenever an ID list is shortened per §10.3; when truncated they MUST also include `continuation_token` so clients can resume from the exact lexicographic position. Lists are always sorted by their primary key before transmission. |
| `OverrideLedgerEntry` | HTTP 200 | `{override_id, reason, ticket_url?, expires_at}` for audits. |

### Break-Glass Scope Map
Scopes embedded in Break-Glass tokens (§12.3) are frozen as follows:

| Scope string | Authorized APIs |
| --- | --- |
| `DurabilityOverride` | `SetDurabilityMode`, `OverrideStrictOnlyBackpressure`, `AdminOverrideKeyEpoch` |
| `SurvivabilityOverride` | `flow.structural_override`, `DryRunMovePartition` force-execute, `MembershipChange` with override flag |
| `ThrottleOverride` | `OverrideCredit`, `flow.structural_hard_block`, `WhyCreditZero` override actions |
| `SnapshotOverride` | `SnapshotFullOverride`, `snapshot_full_invalidated` overrides, repair-mode resume |
| `QuarantineOverride` | `AdminResumePartition`, `AdminPausePartition` while quarantined, `OverrideStrictOnlyBackpressure` when reason=`Quarantine` |

Tokens that present an unknown scope or call an API outside the table MUST be rejected and logged as `BreakGlassScopeMismatch`.

---

## Appendix E App.E – ChunkedList Specification
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
