# Clustor Documentation

Clustor is a Raft consensus substrate built as a graph of cooperative
[fluxor](../../fluxor/) modules. Replicas agree on an ordered log,
fsync it durably, gate reads on quorum durability, and expose the
result through a typed consumer facade so downstream products
(Lattice, Loam, Quantum) attach without reimplementing consensus.

Where most Raft libraries are monolithic, clustor is a wired graph
of seven modules: `consensus` runs elections and orders the apply
stream, `durability` writes segments and tracks per-replica fsync
watermarks, `gateway` frames and admits client traffic,
`admission` gates it, `peer_router` moves bytes between replicas,
`control_plane` publishes proofs and placement, `operations`
carries admin and telemetry. Each module is one source tree of
named components with an explicit dispatch table; every module is
`no_std` PIC, position-independent, and lives behind explicit
channels — so the substrate looks the same whether the graph is a
single-node smoke test or a three-node production deployment.

## Start Here

- [architecture/concepts.md](architecture/concepts.md) — terms, system model, data entities
- [architecture/replication.md](architecture/replication.md) — how the consensus loop and durability work
- [architecture/modules.md](architecture/modules.md) — module reference, four-domain layout, hot-path properties

## Architecture

How the system works. These are the authoritative references.

- [architecture/concepts.md](architecture/concepts.md) — terms, profiles, roles, system model, data entities
- [architecture/wire.md](architecture/wire.md) — encoding rules, message catalog, handshake, wire error codes
- [architecture/replication.md](architecture/replication.md) — elections, leases, read gate, ACK contract, durable watermarks, ledger ordering, flow control, compaction
- [architecture/lifecycle.md](architecture/lifecycle.md) — strict fallback, leader/follower lifecycle, durability modes, scrub, snapshots, membership, ControlPlaneRaft proofs
- [architecture/errors.md](architecture/errors.md) — wire rejections, gate failures
- [architecture/security.md](architecture/security.md) — mTLS, AEAD, RBAC, key purpose registry
- [architecture/observability.md](architecture/observability.md) — metrics, telemetry, throttle/explain APIs, artifact bundles
- [architecture/compatibility.md](architecture/compatibility.md) — wire stability, version negotiation, cache states, readiness
- [architecture/modules.md](architecture/modules.md) — module reference, four-domain layout, hot-path properties
- [architecture/substrate_capability_surface.md](architecture/substrate_capability_surface.md) — the seven-primitive substrate contract downstream consumers code against
- [architecture/session_directory.md](architecture/session_directory.md) — the session-directory / reservation-authority consumer (fluxor rfc_protocols.md §13.7): quorum-committed counter-block grants, epoch fencing, key custody, fence ordering
- [architecture/consumer_facade.md](architecture/consumer_facade.md) — typed Rust helpers (`replica_facade`) implementing the consumer side of that surface

## Guides and integration

Subsystem deep-dives and operational guidance.

- [proposal_correlation.md](proposal_correlation.md) — tagged-proposal correlation across the propose/commit boundary
- [net_http.md](net_http.md) — diagnostic HTTP surface, parser limits, stderr signals
- [substrate_sharing.md](substrate_sharing.md) — the published attach surface downstream graphs wire, and how one clustor substrate is shared across consumer products
- [consuming_fluxor.md](consuming_fluxor.md) — day-to-day workflow for pulling fluxor in via the local registry
- [dependencies.md](dependencies.md) — fluxor consumption + `[dev-dependencies]` inventory
- [test_catalog.md](test_catalog.md) — test inventory and what each scenario asserts

In-flight design work — RFCs, audits, working notes — lives under
[`.context/`](../.context/) at the repo root, separate from the
stable architecture docs above.
