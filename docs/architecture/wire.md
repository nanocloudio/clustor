# Clustor Wire Format

How bytes flow between clustor nodes and between clustor and its
clients. Encoding rules are uniform across Raft RPCs, admin APIs,
control envelopes, and the diagnostic surface, with two carve-outs:
gRPC payloads keep HTTP/2 framing, and the Explain / Throttle / Why
envelopes have their own size ceiling.

The wire format is **frozen for v0.1.x**. Additive fields append at
the tail; new mandatory fields demand a schema bump or a new message
ID. The same rules apply when the manifests under `modules/*/`
introduce a new envelope.

## Table of Contents

1. [Encoding rules](#encoding-rules)
2. [Message catalog](#message-catalog)
3. [Handshake and negotiation](#handshake-and-negotiation)
4. [Error codes](#error-codes)
5. [Worked examples](#worked-examples)

---

## Encoding rules

### 1) Length-prefixed framing

Clustor raw TCP envelopes and other non-gRPC frames begin with a
32-bit little-endian length prefix that counts only the body bytes.
Receivers raise `WireBodyTooShort` whenever fewer body bytes arrive
than promised.

gRPC payloads keep their native 5-byte header framing on HTTP/2; that
layer is the runtime's job.

### 2) Little-endian integers

All on-wire integers are fixed-width little-endian. Length prefixes
precede slices and strings.

The one exception is the AEAD IV-derivation preimage in
[security.md](security.md#aead-and-storage-encryption), which is
big-endian. AAD and on-wire fields stay little-endian even there.

### 3) Body caps by surface

| Surface | Cap |
|---|---|
| Raft / admin RPCs | 4 MiB |
| Explain / Throttle / Why* envelopes | 32 KiB (stays in force even with `WireExtension::WideFrame`) |
| WAL entry frames | Per `EntryFrameHeader.body_len` and `trailer_len`; see [concepts.md](concepts.md#1-wal-entry-frame) |

### 4) Enum discriminants are stable

One `u8` discriminant per enum. Once assigned, values never change.
Additive variants allocate a fresh discriminant at the **tail** of
the assignment range.

Unknown enum discriminants are rejected as `WireUnknownField`, even
inside otherwise-skippable optional or tail structures.
Forward-compatible tails are opaque byte ranges appended after all
known fields; they cannot contain enums or any other mandatory
semantics. New required fields demand either a schema-version bump
or a new message ID, never a tail extension.

The experimental enum range `0xF0–0xFF` is reserved. Production
builds reject messages that use it.

### 5) Optional fields use `has_field` prefix

Optional fields use a `u8 has_field` byte followed by the value when
present. Receivers may skip unknown trailing bytes only when both
peers have negotiated `WireExtension::ForwardCompat` and the
surrounding framing (message ID, schema header, `body_len`) is
recognised. Mandatory unknown fields — including enums — still
trigger `WireUnknownField` even inside otherwise-skippable regions.

### 6) Frame size errors

| Trigger | Error |
|---|---|
| Frame shorter than mandatory minimum | `WireBodyTooShort` |
| Frame exceeding surface cap | `WireBodyTooLarge` |
| Payloads > 64 KiB | Streaming parsers enforce rolling-window buffers |

### 7) Chunked lists

`ChunkedListFrame` (see [concepts.md](concepts.md#10-chunkedlist-frame)).
CRC enforcement is strict when `has_crc = 1`. `has_crc = 0` is
permitted but integrity then depends on the transport. Deduplication
is by `chunk_offset`. JSON mirrors sort entries lexicographically
and include continuation tokens when truncating.

---

## Message catalog

### System log entries

| Code | Entry |
|---|---|
| `0x01` | `MembershipChange` |
| `0x02` | `MembershipRollback` |
| `0x03` | `DurabilityTransition` |
| `0x04` | `FenceCommit` |
| `0x05` | `DefineActivate` |

### Messages

`DurabilityAck` — defined in
[concepts.md](concepts.md#4-durabilityack-attestation).

`PreVoteResponse`:

```
PreVoteResponse {
    term:         u64,
    vote_granted: u8,
    [has_high_rtt: u8,
     high_rtt:     u8]              // tail extension; v0.1+ senders
}
```

v0.1+ senders append `has_high_rtt` and the optional `high_rtt` flag
as a tail extension. Legacy peers send only `term` and
`vote_granted`. Receivers treat the absence of the extension as
`has_high_rtt = 0`. Additional tail bytes are accepted only when
`WireExtension::ForwardCompat` has been negotiated; otherwise they
trigger `WireUnknownField`.

A worked frame is below in
[Worked Examples](#prevoteresponse-frames).

### Envelopes

Every envelope carries a shared header:

```
{ schema_version, generated_at, partition_id, routing_epoch, durability_mode_epoch }
```

Envelope catalog:

- `RoutingEpochMismatch`
- `ModeConflict`
- `ThrottleEnvelope`
- `ControlPlaneUnavailable`
- `snapshot_full_invalidated`
- `snapshot_delta_invalidated`
- `Why*` payloads — `WhyNotLeader`, `WhyCreditZero`,
  `WhySnapshotBlocked`, `WhyDiskBlocked`, `WhyQuarantined`,
  `WhyCreditHint`
- `OverrideLedgerEntry`

Lists carry `truncated_ids_count` and `continuation_token` when
truncated.

### Control-plane readiness

`/readyz` returns:

```
{
  definition_bundle_id,
  activation_barrier_id,
  shadow_apply_state,
  shadow_apply_checkpoint_index,
  warmup_ready_ratio,
  partition_ready_ratio,
  feature.<name>_gate_state,
  feature.<name>_predicate_digest,
  readiness_digest
}
```

### Wide-integer registry

Every node exposes `GET /.well-known/wide-int-registry`. The response
is canonical JSON listing every field encoded as a decimal string —
all `*_ms` values, timestamps, counters, CRC hex strings. JSON
outputs accept numeric enums but emit enum strings.

---

## Handshake and negotiation

Peers exchange a handshake envelope during the Raft setup:

```
wire.catalog_version = { major: u8, minor: u8 }
wire.max_body_len    = <negotiated>
extensions           = <bitmask>
```

### `WireExtension::ForwardCompat` (0x20)

When a node advertises this extension it includes
`forward_parse_max_minor: u8` alongside the bitmask, typically set to
`minor + 1`. Both sides then enforce:

```
remote_minor ≤ local_forward_parse_max_minor
local_minor  ≤ remote_forward_parse_max_minor
```

Violations close the transport before log traffic flows.

### `WireExtension::WideFrame` (0x10)

Reserves larger frame caps (up to 32 MiB) once both peers advertise
it. Until then senders keep RPCs ≤ 4 MiB. Even after negotiation,
Explain / Throttle / Why* envelopes stay capped at 32 KiB.

### `WireExtension::WideCount` (0x11)

Allows `u32` element counts for fields explicitly marked "wide count
capable", only when both peers support it. Otherwise counts remain
`u16` with chunking.

### Unknown extensions

Unknown extensions require explicit negotiation. Peers reject
opportunistic usage with `WireCatalogMismatch`.

---

## Error codes

| Range | Codes |
|---|---|
| `1000 – 1089` | Main wire errors: `WireBodyTooShort = 1001`, `WireBodyTooLarge = 1002`, `WireUnknownField = 1003`, `WireChunkMissing = 1004`, `WireChunkOverlap = 1005`, `WireChunkMissingCrc = 1006`, `WireChunkCrcMismatch = 1007`, `WireChunkDuplicateItem = 1008`, `WireChunkReassemblyAborted = 1009`, `WireCatalogMismatch = 1010` |
| `1090 – 1099` | Vendor-specific extensions. Production deployments relinquish IDs if Clustor later assigns them. |
| `1100 – 1199` | Reserved for future Clustor wire-level errors. |

Higher-level rejection envelopes (`ControlPlaneUnavailable`,
`ThrottleEnvelope`) are catalogued in
[errors.md](errors.md#wire-rejections).

---

## Worked examples

### PreVoteResponse frames

Frames serialise as `<u32 body_len little-endian> || body`.

For `PreVoteResponse { term = 42, vote_granted = 1, has_high_rtt = 1,
high_rtt = 1 }` the body is `2a00000000000000010101` (12 bytes) and
the full frame begins:

```
0c0000002a00000000000000010101
```

Legacy peers send only `term` and `vote_granted`, so their body is
`2a0000000000000001` (9 bytes) and the full frame begins:

```
090000002a0000000000000001
```

Receivers treat missing extension bytes as "no `has_high_rtt` field
present". Frames that promise 12 body bytes but deliver only 9
(e.g. `0c0000002a0000000000000001`) raise `WireBodyTooShort`.

### CRC lane packing example

The CRC-lane packing rule in
[concepts.md §2 Segment Trailer](concepts.md#2-segment-trailer) is
easier to follow with concrete bytes.

Consider two entries:

1. Entry A header / body bytes (hex):
   `01000000000010000000000000000000aa`
2. Entry B header / body bytes (hex):
   `01000000000008000000000000000000bb`

Concatenate headers and bodies to form the canonical stream:

```
01000000000010000000000000000000aa
01000000000008000000000000000000bb
```

Splitting into 32-bit little-endian words and distributing across
four lanes can, for illustration, use lane CRCs:

```
{ lane0 = 0x89ABCDEF,
  lane1 = 0x01234567,
  lane2 = 0xFEDCBA98,
  lane3 = 0x76543210 }
```

Packed little-endian bytes therefore equal:

```
ef cd ab 89  67 45 23 01  98 ba dc fe  10 32 54 76
```

Offsets for the two entries (`0` and `0x0000000000000010`) serialised
as contiguous little-endian `u64` values:

```
0000000000000000  1000000000000000
```

produce the same packed CRC
`0x1032547698badcfe67452301efcdab89`.

Tooling replays this vector when validating lane implementations.
The CRC constants above are illustrative placeholders, not computed
CRC32C outputs for the example bytes.
