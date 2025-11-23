# Test Catalog

This catalog tracks where the current regression coverage lives and which areas still rely on
private-module unit tests.

## Unit Tests (`#[cfg(test)]`)

| Module | Focus | Decision |
| --- | --- | --- |
| `src/snapshot/` (`mod.rs`, `manifest.rs`, `pipeline.rs`, `throttle.rs`, `telemetry.rs`) | Manifest building, chunk encryption, trigger cadence logic | These tests exercise internal helpers that are not exported publicly (e.g., canonicalization). Keeping them beside the implementation avoids making helper APIs `pub`. |
| `src/security/` (cert lifecycle, RBAC cache, break-glass helpers) | mTLS rotation, key epoch tracking, RBAC cache, break-glass controls | The tests interact with private structs and `IncidentCorrelator`; moving them would require widening the API surface, so they remain in-place. |
| `src/cp.rs` | Cache policy transitions, snapshot import guard, circuit breaker | These tests rely on direct `CpProofCoordinator` mutations that are not exposed publicly; they stay local. |
| `src/readyz.rs` / `src/why.rs` | Presentation helpers that compose snapshot telemetry | Kept local because they validate private digest formatting and enum wiring. |
| `src/transport/raft.rs` | Frame validation + negotiation bookkeeping | Depends on private violation hooks, so covered in-module. |

## Integration Tests (`tests/`)

| File | Coverage |
| --- | --- |
| `tests/admin_checkpoint.rs` | Admin workflows, CP guard, throttle behaviour |
| `tests/apply_checkpoint.rs`, `tests/flow_checkpoint.rs`, `tests/flow_checkpoint.rs` | Apply path, flow-control regression fixtures |
| `tests/raft_checkpoint.rs`, `tests/cp_checkpoint.rs`, `tests/quorum_checkpoint.rs` | Consensus kernel invariants |
| `tests/snapshot_checkpoint.rs`, `tests/snapshot_read_checkpoint.rs` | Snapshot delta policies and read RPCs |
| `tests/security_checkpoint.rs` | mTLS + RBAC stories with synthetic manifests |
| `tests/storage_checkpoint.rs`, `tests/storage_segment_header_forward.rs` | WAL header/crypto compatibility |
| `tests/telemetry_checkpoint.rs`, `tests/spec_*` | Spec/telemetry conformance |
| `tests/net_raft_integration.rs` | End-to-end TLS Raft server/client round-trips |
| `tests/admin_http_integration.rs` | Admin HTTP server wiring over mutual TLS |
| `tests/snapshot_flow.rs` | Snapshot export/import/authorization flow over a temp layout |

## Large-Test Placement Decisions

- Snapshot authorizer/exporter tests remain inline because they lean on private chunk builders.
- Security/RBAC/break-glass flows stay inline; externalizing them would require exposing
  additional methods on `RbacManifestCache`.
- With the new integration suites, networking (Raft + Admin HTTP) and snapshot file-system flows
  now have black-box coverage and no longer rely solely on unit tests.
