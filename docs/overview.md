# Clustor documentation

Clustor is a Raft consensus substrate built as a graph of
cooperative [fluxor](../../fluxor/) modules. Replicas agree on an
ordered log, fsync it durably, gate reads on quorum durability, and
expose the result through a typed consumer facade so downstream
products attach without reimplementing consensus.

The substrate is a wired graph of seven modules rather than a
library: `consensus` runs elections and orders the apply stream,
`durability` writes WAL segments and tracks per-replica fsync
watermarks, `gateway` frames and admits client traffic, `admission`
gates reads and paces intake, `peer_router` moves bytes between
replicas, `control_plane` publishes proofs and placement, and
`operations` carries admin and telemetry. The same graph runs as a
single node or a three-node cluster; only the config changes.

## Start here

- [running.md](guides/running.md) — bring up a single node or a three-node
  cluster and smoke check it
- [architecture/concepts.md](architecture/concepts.md) — terms,
  system model, data entities
- [architecture/replication.md](architecture/replication.md) — the
  consensus loop and durability
- [architecture/modules.md](architecture/modules.md) — module
  reference and design rationale

## Architecture reference

- [architecture/concepts.md](architecture/concepts.md) — terms,
  roles, system model, on-disk entities
- [architecture/wire.md](architecture/wire.md) — envelope formats,
  message catalog, WAL frame contract
- [architecture/replication.md](architecture/replication.md) —
  elections, log replication, durable watermarks, agreement without
  durability, the read gate, flow control
- [architecture/lifecycle.md](architecture/lifecycle.md) — boot and
  replay, durability modes, strict fallback, snapshots, admin
  operations, membership
- [architecture/errors.md](architecture/errors.md) — the rejection
  surface clients and operators observe
- [architecture/security.md](architecture/security.md) — transport
  posture, RBAC, key epochs, and what is not implemented yet
- [architecture/observability.md](architecture/observability.md) —
  metrics, histograms, the binary export, diagnostic HTTP
- [architecture/compatibility.md](architecture/compatibility.md) —
  wire stability, ABI pinning, cache states, readiness
- [architecture/modules.md](architecture/modules.md) — per-module
  reference: components, ports, parameters
- [architecture/substrate_capability_surface.md](architecture/substrate_capability_surface.md)
  — the substrate contract downstream consumers code against
- [architecture/consumer_facade.md](architecture/consumer_facade.md)
  — the typed Rust helpers (`replica_facade`) implementing the
  consumer side of that contract
- [architecture/session_directory.md](architecture/session_directory.md)
  — the session-directory / reservation-authority module
- [architecture/limit_register.md](architecture/limit_register.md) —
  machine-checked limits shared with downstream repositories

## Guides

- [running.md](guides/running.md) — bring-up, smoke checks, port overrides
- [proposal_correlation.md](guides/proposal_correlation.md) —
  tagged-proposal correlation across the propose/commit boundary
- [net_http.md](guides/net_http.md) — the diagnostic HTTP surface and its
  limits
- [substrate_sharing.md](guides/substrate_sharing.md) — how one clustor
  substrate is shared across consumer products
- [consuming_fluxor.md](guides/consuming_fluxor.md) — the fluxor dependency
  workflow
- [dependencies.md](guides/dependencies.md) — dependency inventory
