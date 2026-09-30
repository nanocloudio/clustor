# Security

What clustor implements today for transport security, access
control, and data integrity. Clustor targets the crash-only fault
model described in [concepts.md](concepts.md): the mechanisms below
detect corruption and gate administrative access; they do not
provide Byzantine fault tolerance. Operators remove replicas that
actively lie.

## Transport security

Clustor does not implement TLS itself. Transport security is
delegated to fluxor's foundation `tls` module: `peer_router` sits on
the cleartext side of that module and routes decrypted traffic to
the gateway or to per-partition consensus instances
(`modules/app/peer_router/mod.rs`). The graph position is:

```
ip ↔ tls (foundation) ↔ peer_router ↔ { gateway, consensus_pN }
```

The localhost and rig graphs wire
`peer_router` directly to the network module with no TLS at all;
whether a deployment is encrypted is a property of its module graph,
not of clustor code.

Peer identity crosses the boundary via the `MSG_PEER_IDENTITY`
envelope (`modules/common/wire.rs`): the transport layer stamps a
connection with `{conn_id, replica_id, verified flag, SPIFFE SVID
string}`, and `peer_router` refuses to honour any in-band plaintext
handshake that disagrees with it. Until fluxor's TLS module exposes
certificate SVIDs, this envelope is the binding contract; a
deployment can populate it from a sidecar that reads certificate
metadata directly.

## RBAC

RBAC is implemented in `modules/app/operations/rbac.rs`. Four role
bits exist: `ROLE_OPERATOR`, `ROLE_TENANT_ADMIN`, `ROLE_OBSERVER`,
and `ROLE_BREAKGLASS`.

Identity resolution depends on the request origin:

- **Wire** connections are mapped to roles by matching the SVID from
  `MSG_PEER_IDENTITY` against configured prefixes
  (`admin_svid_prefix`, `observer_svid_prefix`, at most 64 bytes
  compared). Bindings live in a 32-slot table keyed by connection id
  and are cleared by the transport's revoke envelope.
- **HTTP** requests carry no peer identity and always evaluate as
  the module-wide `default_role`, which defaults to operator. A
  deployment that must not accept HTTP admin sets `default_role` to
  observer or ships the `headless` variant.

Administrative commands are authorised when the resolved role
carries `ROLE_OPERATOR` or `ROLE_BREAKGLASS`. Each evaluation emits
a 3-byte audit envelope `{authorized, role, conn_id}` on the
`audit_events` channel for external consumers; there is no on-disk
audit log.

## Data integrity and key epochs

WAL frames carry per-frame CRC32C checksums, verified on replay and
on follower ingest (`modules/app/durability`). This detects
corruption; it is not tamper-proofing, since anyone who can write
the file can rewrite the checksum.

By default WAL segments and snapshots are written in cleartext and
the `dek_epoch` stamped into snapshot headers is a label from a local
168-hour timer (`modules/app/durability/keys.rs`), with no key behind
it.

## Sealed records

The durability module's `aead` parameter selects sealed records by
suite id: 1 = ChaCha20-Poly1305, 2 = AES-256-GCM, the latter only
where the vault offers it. Any other value fails the WAL closed.
`cluster` (up to 16 bytes) names the cluster every sealed record is
bound to. Sealing sits below the consumer facade: proposals,
acknowledgements, read-backs, replay and snapshots carry the same bytes
either way.

| Record | Layout | Key |
| --- | --- | --- |
| WAL frame | v1 `0xA5` frame: epoch, 128-bit segment incarnation, frame sequence, ciphertext of `term ‖ index ‖ entry`, tag, CRC32C | `DERIVE(master, "clustor/wal", cluster ‖ partition ‖ replica ‖ epoch ‖ incarnation)` |
| Snapshot body | v1 `FXSC` chunks of 4096 plaintext bytes, the last flagged final; the file header and CRC trailer stay in the clear | `DERIVE(master, "clustor/snapshot", cluster ‖ partition ‖ generation ‖ epoch)`, 128-bit random generation per snapshot |
| Allocator state | `wal/p<NNNN>_seal0`/`_seal1` A/B records: epoch, suite, reserved incarnation counter, live-epoch marks, HMAC-SHA256 | `DERIVE(master, "clustor/wal-state", cluster ‖ partition ‖ replica)` |

Keys live in the Fluxor KEY_VAULT; no key byte enters the module. Each
group and replica has one persisted `KDF_KEY` master per key epoch,
labelled `wal/p<partition>/r<replica>/e<epoch>` in the durability
module's vault namespace. A master the vault would not give back after
a restart is refused.

**Nonces.** A frame's nonce is `"WAL0" ‖ frame sequence` under a key
unique to one segment incarnation. Incarnations are `salt(8) ‖
counter(8)`: the counter is reserved durably, ahead, in the allocator
state; the salt is drawn from the platform CSPRNG at each writer start.
Every segment and every suffix truncation opens a new incarnation; a
recovering writer always appends to a new segment, so a sequence is
never resumed; a staged frame is sealed once and a retry rewrites its
exact bytes.

**Replay.** A CRC mismatch, a short frame or an incomplete prefix is a
torn tail, handled as unsealed. A whole frame whose tag fails, whose
header lengths disagree, whose `(incarnation, sequence)` repeats, or
whose epoch's master is missing fails the replica closed: no replay
handshake, no append. Only authenticated frames are acknowledged,
served or applied. A sealed snapshot is judged the same way at boot.

**Rotation.** The keys timer, or media newer than the allocator state,
starts a new key epoch at the next segment boundary: master first, then
the allocator state naming it, then the first frame. A master is
destroyed only once no retained segment and no retained snapshot names
its epoch.

**Scope.** Raft term/vote metadata, snapshot pointer slots and the
floor sidecar are not sealed; only an encrypted durability root covers
those. The `clustor_cli wal-scan` command reads unsealed segments only.

## Encrypted durability root

Sealing protects records one at a time, so the files around them —
metadata slots, pointer records, directory entries — stay in the clear.
Encrypting the storage beneath the filesystem covers all of it instead,
and the two compose.

`configs/single-encrypted-root.yaml` is that composition: `fat32` over
`crypt_block` over a `storage.block` source, with the WAL segments,
snapshots, snapshot pointers and Raft metadata slots all on the
decrypted device. Clustor writes its ordinary formats; only the
`file.data` provider beneath them differs, and the lower image holds
ciphertext alone. `crypt_block` holds its container's master key in the
vault, so a runtime without vault persistence cannot unwrap across a
restart what it wrote before one.

The two postures answer different threats. Sealing authenticates every
record against tampering and survives a filesystem that is readable by
others; an encrypted root hides everything at rest but authenticates
only what its own container does.

## Not implemented

The following do not exist in the codebase:

- mTLS/SPIFFE certificate validation, OCSP or CRL revocation
  checking, and revocation-driven quarantine.
- KEK/DEK fetching from a control plane, attachment envelopes and
  recovery shares for the WAL master; with `aead = 0` the `dek_epoch`
  is a local timer label with no key material behind it.
- RBAC manifest refresh; roles come from static module parameters.
- Break-glass TTL tokens and signed audit log files.
- An Ed25519 key purpose registry and zeroisation machinery.
