# Compatibility and Versioning

What clustor promises across builds today: how the wire format is
versioned, how control-plane proofs age through cache states, and
how a node reports readiness.

## Wire and schema stability

External consumers go through `modules/common/replica_facade.rs`
rather than importing `MSG_*` constants from
`modules/common/wire.rs` directly; the facade is the integration
surface.

The compatibility story is same-build clusters. All nodes
in a cluster run the same build, and the module ABI is digest-pinned
through fluxor epochs: `fluxor.toml` declares
`[required] fluxor = { abi = 1 }`, and the toolchain refuses to load
modules whose ABI digest disagrees with the runtime. There is no
cross-version
negotiation, no feature-gate handshake, and no wire-extension
mechanism.

Every message uses a 3-byte envelope `[msg_type:u8][len:u16 LE]`
followed by the payload, so the maximum payload is 0xFFFF bytes.
Frames that would exceed a channel's capacity are rejected at the
sender; there is no chunking or wide-frame variant.

## Control-plane cache lifecycle

The admission module's proof cache
(`modules/app/admission/proof_cache.rs`) tracks the age of the most
recent control-plane proof and classifies it into one of four states
defined in `modules/common/types.rs`: `Fresh`, `Cached`, `Stale`,
`Expired`.

With the defaults (`fresh_threshold` 60 s, `grace_period` 120 s) the
ladder is:

| State | Proof age |
|---|---|
| `Fresh` | under 60 s |
| `Cached` | 60 s to 90 s |
| `Stale` | 90 s to 120 s |
| `Expired` | 120 s and beyond |

The `Cached` band ends at `fresh + (grace − fresh) / 2` = 90 s. The
boundary is derived from both thresholds rather than a bare
`grace / 2`: with the defaults, `grace / 2` equals the fresh
threshold, which would leave the `Cached` band empty and jump
straight from `Fresh` to `Stale`.

State transitions are broadcast to two consumers:

- The consensus commit path (`modules/app/consensus/commit.rs`) sets
  `strict_fallback` whenever the state is `Stale` or worse, clamping
  writes to strict durability regardless of the configured mode
  (strict, group_fsync, or relaxed).
- The read gate (`modules/app/admission/read_gate.rs`) issues read
  permits only while the state is `Fresh` or `Cached`; `Stale` and
  `Expired` block linearizable reads.

Today the proof feed is synthetic: the control-plane component
(`modules/app/control_plane/cp.rs`) emits a proof on a fixed 5000 ms
tick, so a healthy node normally stays `Fresh`. A production
control-plane feed that could genuinely withhold proofs is future
work.

## Readiness

`GET /readyz` returns 200 with a one-byte body when the node is
ready and 503 otherwise (`modules/app/operations/http.rs`).
Readiness is computed by the telemetry component
(`modules/app/operations/telemetry.rs`) from its aggregated metric
table: the node is ready when at least one raft instance is present
and every raft instance reports `RAFT_READY=1` (boot replay done,
metadata loaded, consensus established), and, if any apply instance
is present, every one reports `APPLY_CAUGHT_UP=1` (apply cursor at
the commit horizon). Scanning all slots handles multi-partition
graphs without special-casing.

Readiness is level-triggered: it is recomputed every step and drops
back to 503 if a node loses its leader or apply falls behind. A
gauge that has not been re-reported for 3 s counts as not ready, so
a dead producer cannot hold `/readyz` at 200. A 500 ms boot floor
prevents a 200 before the first sample window has populated the
table.
