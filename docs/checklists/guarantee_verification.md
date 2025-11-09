# Guarantee Verification Hooks (Section 15)

This checklist explains how operators prove Section 15 guarantees before handing a cluster back to tenants. Every item maps directly to an automated hook in the codebase.

## 1. Placement & Routing Epoch Integrity (Spec §15.1)
- Run `AdminHandler::handle_create_partition` in dry-run mode to confirm CP-Raft generated a fresh `routing_epoch`.
- Query `CpPlacementClient::placement_snapshot` and validate `routing_epoch` monotonicity (no reuse, no regression).
- Record the result in the override ledger and attach the trace ID emitted by `ThrottleExplainResponse`.

## 2. Strict Fallback & CP Cache Windows (Spec §15.2)
- Issue a `SnapshotThrottleRequest` with `enable=false` on the target partition; ensure `FlowThrottleEnvelope` returns `Throttled` with `BacklogDebt`.
- Force a CP cache expiry using `CpProofCoordinator::set_cache_state(CpCacheState::Expired)` in staging, then confirm `CpUnavailableReason::NeededForReadIndex` is emitted. Capture the `CpUnavailableResponse` and attach to the guarantee report.

## 3. Durability & Fence Epoch Proofs (Spec §15.3)
- Run the `DrFenceManager` handshake with `FenceCommit` + matching acknowledgements per Section 10.2.
- Persist the manifest ID + epoch into the manifest authorization log and link the audit entry to the guarantee ticket.

## 4. Flow Control & Tenant Quotas (Spec §15.4)
- Execute a `TenantFlowController::evaluate` call for each tenant and remove overrides once credit balances return to nominal values.
- Store the resulting `FlowThrottleEnvelope::explain()` output in the guarantee log so auditors see why throttles are enabled/disabled.

## 5. Observability & Incident Hooks (Spec §15.5)
- Snapshot the `MetricsRegistry` bucket for `clustor.cp.cache_hits` and attach it to the report.
- Run the telemetry checkpoint test (`cargo test --test telemetry_checkpoint`) to confirm `IncidentCorrelator` cooldowns match policy.

## 6. Documentation of Deviations
- Any deviation requires linking to the Break-Glass audit trail (`RbacManifestCache::audit_log`). Attach the ticket URL and `used_by_spiffe_id` as mandated by Section 11.

> **Submission Requirement**: When filing the guarantee report, include the JSON serialization of the newest `ThrottleExplainResponse`, the `BootstrapReport` for the last restart, and the results of the spec self-test (see `SpecSelfTestHarness`) in the archive that accompanies the ticket.
