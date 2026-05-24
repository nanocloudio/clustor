# Security

Transport security, on-disk encryption, RBAC, and the key purpose
registry. Designed for the **crash-only fault model** described in
[concepts.md](concepts.md#crash-model): cryptographic signatures
provide authenticity and audit trails, not Byzantine fault
tolerance. Operators remove replicas that actively lie.

## Table of Contents

1. [Transport security](#transport-security)
2. [AEAD and storage encryption](#aead-and-storage-encryption)
3. [RBAC and break-glass](#rbac-and-break-glass)
4. [Key purpose registry](#key-purpose-registry)
5. [Additional controls](#additional-controls)
6. [Worked examples](#worked-examples)

---

## Transport security

Node-to-node traffic uses **mTLS with SPIFFE identities**. Revocation
order:

1. OCSP stapling cache
2. CRL fetch
3. Break-glass waiver

### 1) Revocation freshness

If revocation data exceeds `revocation.max_staleness_ms = 300,000`,
or if both feeds are unavailable for
`revocation.fail_closed_ms = 600,000`, peers tear down mTLS
connections and enter Quarantine until fresh material or a waiver
(≤ 300,000 ms extension) arrives.

Short-lived certs (≤ 86,400,000 ms) require fresh revocation feeds —
they leave no room for stale validation.

### 2) Monotonic timers

All timers in revocation logic use the local monotonic clock.
Operators ensure wall-clock discipline stays within 5 s (via the
same `clock_guard` service used for leases) while safety gates
evaluate monotonic timers. This avoids skew-induced bypasses where
a clock jump silently invalidates a fresh certificate.

### 3) Quarantine scope is per-node

Revocation-induced quarantine is scoped to the node that failed
validation. Connections initiated by healthy peers stay up so long
as their revocation caches are fresh. Clusters do not propagate a
revocation-triggered shutdown automatically. Every node independently
evaluates revocation freshness and quarantines itself only if its
local timers expire. Cross-node automation may page operators but
does not mass-quarantine healthy nodes.

---

## AEAD and storage encryption

### 1) WAL segments — IV derivation

WAL segments use **AES-256-GCM with a 96-bit IV** derived from:

```
IV = Truncate96(H(dek_epoch || segment_seq || block_counter || "WAL-Block-IV v1"))
```

- `H` is SHA-256 by default.
- The concatenation order is canonical: `dek_epoch` encoded as
  big-endian `u32`, `segment_seq` as big-endian `u64`, `block_counter`
  as big-endian `u64`, followed by the ASCII literal with **no
  terminating NUL**.
- `Truncate96` takes the first 12 bytes of the hash output.

Exact byte widths matter. Diverge here and the IV space diverges.

Switching the IV hash function (e.g. to BLAKE3) is legal only when:

- a cluster-wide `crypto.iv_hash_suite` gate is enabled,
- a durability fence commits the new suite, **and**
- every partition rotates `dek_epoch` after the fence so ciphertext
  never mixes suites for the same `(partition_id, dek_epoch)` tuple.

**Note on endianness.** This big-endian encoding applies only to the
hash preimage. On-wire fields and AAD remain little-endian per
[wire.md §2](wire.md#2-little-endian-integers). Every section
referencing IV derivation inherits this big-endian preimage rule.

### 2) Snapshot chunks — IV derivation

Snapshot chunks reuse AES-256-GCM but derive IVs with the
manifest-provided salt:

```
IV = Truncate96(H(dek_epoch
                  || iv_salt
                  || chunk_offset
                  || chunk_block_counter
                  || "Snapshot-Chunk-IV v1"))
```

- `iv_salt` is the 16-byte value published in the snapshot manifest.
- `chunk_offset` is the chunk's starting logical byte offset, encoded
  as big-endian `u64`.
- `chunk_block_counter` is a big-endian `u64` that increments per
  `wal.crypto_block_bytes` (4096-byte) block within the chunk.

The derivation ensures each `(manifest_id, chunk_offset,
block_counter)` triple produces a unique IV even when snapshots are
re-emitted with the same `dek_epoch`. `iv_salt` changes whenever a
new manifest is emitted. The literal string has no terminating NUL.

### 3) AAD encoding

AAD includes `{aad_version = 1, partition_id, dek_epoch,
segment_seq}` encoded as **little-endian** integers. Version bumps
require explicit upgrade plans.

Tags are 16 bytes. Verification is constant time (e.g. via a
`ct_equal_16` helper — see
[Worked Examples](#aead-constant-time-comparison) below).

### 4) Nonce reservation

Parameters:

- `wal.crypto_block_bytes = 4096`
- `nonce.reservation_max_blocks_profile ∈ [1024, 8192]`
- `nonce.reservation_gap_quarantine_threshold_bytes` default 4 MiB

Writers queue reservation flush attempts every ≤ 5 ms (or sooner
when a window is consumed), but ciphertext waits for the reservation
record plus `fdatasync` completion before using the counters.
Implementations synthesise `NonceReservationAbandon` before
compaction and track `wal.nonce_reservation_gap_bytes` against
`wal.nonce_corruption_bytes`.

A block counter is **not** used for encryption until its reservation
has been durably recorded. The order is: append
`NonceReservationRange`, `fdatasync` `wal/durability.log`, then emit
ciphertext using the reserved `(segment_seq, block_counter)` window.
Reboots therefore resume from the last reservation head without
reusing counters.

### 5) Block counter and segment seq

- `block_counter` starts at 0 for each freshly allocated
  `segment_seq` and increments by one per `wal.crypto_block_bytes`
  chunk.
- `segment_seq` values are monotonically increasing per partition
  and are **never reused**, even after compaction or rewrite.
  Partial rewrites allocate a new `segment_seq` and bump `dek_epoch`
  if necessary.

Combined with the reservation rule, the tuple `(partition_id,
dek_epoch, segment_seq, block_counter)` is globally unique for every
encrypted block.

### 6) Key epoch rotation

ControlPlaneRaft tracks `{kek_version, dek_epoch,
integrity_mac_epoch}`.

| Action | Cadence |
|---|---|
| Nodes fetch new DEKs | every 604,800,000 ms (weekly) |
| Retain previous DEK for decrypt-only | 172,800,000 ms (48 h) |
| Then zeroise contexts | `crypto.zeroize_context` |
| Emit zeroisation digest | `crypto.zeroization_digest` |

Epoch regression (`KeyEpochReplay`) forces Strict fallback. Overrides
are recorded via Break-Glass tokens.

---

## RBAC and break-glass

### Roles

| Role | Authorities |
|---|---|
| `Operator` | Lifecycle, durability transitions, leader transfers, snapshots |
| `TenantAdmin` | Telemetry access, tenant quotas |
| `Observer` | Read-only |
| `BreakGlass` | Durability overrides, survivability overrides, credit overrides, snapshot overrides, quarantine overrides |

### RBAC manifests

Refresh every 30 s. Missing two refreshes causes `RBACUnavailable`
for mutating APIs while reads continue for `rbac.grace_ms = 60,000`.

### Break-Glass tokens

SPIFFE SVIDs containing `urn:clustor:breakglass:<scope>`.

| Property | Constraint |
|---|---|
| TTL | ≤ 300,000 ms |
| Renewable? | No |
| Allowed skew | ±5,000 ms |
| Required validation | Cluster ID and scope-specific API coverage |
| Audit logging | `{scope, actor_id, ticket_url}` |
| After first successful use | Zeroise token private material and any resident credentials immediately |

### Audit logs

Stored at `security/breakglass_audit.log` as canonical JSONL — each
line serialised per [`CanonicalJson`](concepts.md#behaviour-switches) —
with Ed25519 signatures, batched per 1,000 lines, retained ≥ 400
days.

---

## Key purpose registry

| Key | Use | Rotation |
|---|---|---|
| `ReleaseAutomationKey` (Ed25519) | Signs release manifests | Every 180 days; hardware-backed HSM |
| `CPReleaseKey` (Ed25519) | Signs feature manifests, overrides, and other ControlPlaneRaft-issued durability records | With ControlPlaneRaft minor releases |
| `ControlPlaneProofKey` (Ed25519) | Signs `DurabilityProofTupleV1` records | With ControlPlaneRaft minors, staged with overlap |
| `SnapshotManifestKey` (Ed25519) | Signs runtime snapshot manifests exported by partitions (canonical JSON hashed per [concepts.md](concepts.md#6-snapshot-manifest)) | Every 90 days with ControlPlaneRaft-supervised rollover |
| `AuditLogKey` (Ed25519) | Signs audit log segments | Annually with overlap |
| `BreakGlassTokenCA` | Issues SPIFFE SVIDs for break-glass | Dedicated 45-day intermediates with ≥ 7-day overlap |

---

## Additional controls

- Hardware accelerators expose deterministic zeroisation hooks.
  Failures raise `CryptoZeroizationFailed` and quarantine the
  partition.
- Key rotations track `wal_kms_block_seconds` and
  `snapshot_kms_block_seconds`. Growth > 300 s per hour pages
  operators and blocks ControlPlaneRaft from finalising rotations
  unless overrides cite ticket IDs.

---

## Worked examples

### AEAD constant-time comparison

```rust
fn ct_equal_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
```

Implementations may wrap hardware intrinsics but preserve this logic
for conformance tests.

### Segment MAC vector

MAC key bytes `00…1f`, `segment_seq = 7`, `first_index = 42`,
`last_index = 121`, `entry_count = 17`:

```
entries_crc32c_lanes_bytes = 0x1032547698badcfe67452301efcdab89
offsets_crc32c_lanes_bytes = 0x0123456789abcdeffedcba9876543210
mac                        = 5c50cc7f43ef3c0127db59a3a8394ed1
                             6782e7997b53093c35bff32f8644b8f0
```

### Snapshot manifest sample

```json
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

Removing `content_hash` and `signature` before hashing (per
[concepts.md](concepts.md#6-snapshot-manifest)) yields the listed
hash. Signing the canonical encoding with the cluster's
`SnapshotManifestKey` produces `0xe6559247…aed01`.
