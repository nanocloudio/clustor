# Limit register

The list of clustor's *deliberate* hard ceilings, following the same
discipline as fluxor's `docs/architecture/limit_register.md`: a policy
ceiling found in source but absent here is a bug, and every checkable
row is machine-verified against source by `tests/limit_register.rs`
(the `Symbol` must exist in `Source` as a `const` whose value matches
`Value`).

## Deliberate caps

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| App-snapshot body (capture + install accumulation, boot restore) | `MAX_SNAPSHOT_BODY` | modules/app/durability/snapshot.rs | 16384 | Policy: bodies are 40 B disk-resident markers for disk state stores (the store's manifest-named runs ARE the snapshot); full-fidelity bodies exist only for memory stores, whose bounded worst case must fit. A body that does not fit is refused at the EXPORT side (the app emits no chunks and the WAL stays authoritative) — see the denial accounting on the state worker. Upgrade path if a memory-store deployment outgrows it: size the buffer from the deployment envelope via the Tier B elastic region (`fluxor rfc_resource_model.md` §3.6) rather than raising the const — the buffer is per-module state, and the elastic path keeps the envelope-on-one-screen property. |
| Snapshot chunk per channel frame | `MAX_CHUNK_BODY` | modules/app/durability/snapshot.rs | 4096 | Wire pacing: one install-transfer chunk per frame; totals are unbounded because the stream is chunked. |

Cross-repo note: the ceiling that binds FIRST for the app-snapshot
round-trip is the state worker's export scratch in lattice
(`kv_state_worker` `SNAPSHOT_BODY_MAX` = `SCRATCH_BUF_SIZE −
APP_SNAPSHOT_HDR` ≈ 8 KiB). It is registered on the lattice side; this
register only guards clustor's own constants.
