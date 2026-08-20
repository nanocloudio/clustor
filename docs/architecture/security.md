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

WAL segments and snapshots are written in cleartext. A `dek_epoch`
(`u32`) is stamped into WAL segment and snapshot headers so that
future encryption can key material per epoch. The epoch source
(`modules/app/durability/keys.rs`) rotates on a local 168-hour
timer. The durability module's `aead` parameter is reserved
(0 = none, 1 = aes_256_gcm) and is not yet read at runtime.

## Not implemented

The following do not exist in the codebase:

- mTLS/SPIFFE certificate validation, OCSP or CRL revocation
  checking, and revocation-driven quarantine.
- AES-256-GCM encryption of WAL segments or snapshot chunks,
  including AAD encoding, tag verification, and nonce reservation.
- KEK/DEK fetching from a control plane; `dek_epoch` rotation is a
  local timer with no key material behind it.
- RBAC manifest refresh; roles come from static module parameters.
- Break-glass TTL tokens and signed audit log files.
- An Ed25519 key purpose registry and zeroisation machinery.
