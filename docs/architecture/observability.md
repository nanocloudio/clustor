# Observability

Clustor exports metrics as a compact binary record stream, serves a
small set of HTTP diagnostic endpoints, and ships host-side tooling
that decodes the stream into JSON baselines. Everything on the node
side is integer-only and fixed-width so the `no_std` hot path never
formats text or touches floating point.

## Table of Contents

1. [Metrics and telemetry](#metrics-and-telemetry)
2. [HTTP surface](#http-surface)
3. [Host-side tooling](#host-side-tooling)

---

## Metrics and telemetry

### Metric identity

Every sample is keyed by `(module_id, partition_id, metric_id)`.
`module_id` is the emitting component's source id
(`wire::SOURCE_ID_*` in `modules/common/wire.rs`), so components of a
composite module keep distinct identities in the export.
`partition_id` scopes a sample to a partition where that applies and
is 0 otherwise. `metric_id` is a per-module id: scalar metrics occupy
a small private space starting at `0x0001` (`wire::metric_ids`), and
histogram bucket ranges sit above it so the two never collide.

Samples travel as `MSG_METRIC_SAMPLE` frames on each module's metrics
port into the operations module. The 14-byte body carries
`module_id:u8`, `partition_id:u16 LE`, `metric_id:u16 LE`, `kind:u8`
(0 counter, 1 gauge, 2 histogram bucket) and `value:i64 LE`.

### Histogram buckets

Bucket bounds are fixed in `wire::hist` and stored in the producer's
native sampling unit (microseconds or milliseconds), so classification
stays integer-only. Each histogram occupies a contiguous `metric_id`
range starting at `HIST_BASE = 0x1000`: bucket `i` is emitted at
`HIST_BASE + i` with `value = cumulative count` of samples at or below
that bound. There are `bounds.len() + 1` buckets; the last is the
implicit `+Inf` overflow bucket, so saturation of the top bound still
registers.

| Metric | Buckets (inclusive upper bounds) | Unit |
|---|---|---|
| `clustor.wal.fsync_latency_ms` | `0.25, 0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100` | ms |
| `clustor.raft.commit_latency_ms` | `0.5, 1, 2, 4, 6, 8, 10, 15, 20, 30, 40, 60, 80, 100` | ms |
| `clustor.flow.apply_batch_latency_ms` | `0.25, 0.5, 1, 2, 4, 6, 8, 10` | ms |
| `clustor.snapshot.transfer_seconds` | `1, 2, 4, 8, 16, 32, 64, 128, 256` | s |

| Histogram | Producer | Timed at |
|---|---|---|
| `clustor.wal.fsync_latency_ms` | `durability` (`wal.rs`) | every `FS_FSYNC` |
| `clustor.raft.commit_latency_ms` | `consensus` (`raft.rs`) | leader append to commit, via a per-index timestamp ring |
| `clustor.flow.apply_batch_latency_ms` | `consensus` (`apply.rs`) | per commit-apply pass that delivers at least one entry |
| `clustor.snapshot.transfer_seconds` | `durability` (`snapshot.rs`) | first install chunk to `done` |
| kernel scheduler step time | `operations` (`telemetry.rs`) | scraped over the monitor ABI |

### Step-time histograms

Two further histogram families measure scheduler step time, each in
its own id range so the three families never collide within a module:

- **Per-module step histograms** (`STEP_PERMOD_BASE = 0x1100`). On
  its emit tick the telemetry component scrapes each kernel scheduler
  slot's 8-bucket step histogram over the monitor ABI and exports the
  non-idle slots. Bucket `i` is emitted at `STEP_PERMOD_BASE + i`
  under `module_id = SOURCE_ID_TELEMETRY` with `partition_id` set to
  the scheduler module index. The global scheduler step histogram uses
  the same buckets but sits at `HIST_BASE` with partition 0.
- **Per-component step histograms** (`COMP_STEP_BASE = 0x1200`,
  `modules/common/step_accounting.rs`). The kernel sees a composite
  module as one scheduler entity, so each composite's dispatch table
  brackets every `component::step` call with `dev_micros` reads and
  records the elapsed time into a `CompStepHist` per component. Bucket
  `i` is emitted at `COMP_STEP_BASE + i` under the component's own
  source id. The bucket edges mirror the kernel's per-module step
  buckets (`1, 3, 7, 15, 31, 63, 255` µs plus `+Inf`), so component
  and module distributions compare directly. The whole 8-bucket
  snapshot goes out in one atomic `channel_write`; a full ring drops
  the snapshot whole, and the cumulative counts re-publish complete on
  the next tick.

### Aggregation and export

The telemetry component of the operations module drains the metrics
fan-in each step, keeps a latest-value table keyed by
`(module_id, partition_id, metric_id)` (oldest-write eviction when
full), and on its emit tick serialises the table into the `/metrics`
export that the http component caches and serves verbatim. The
payload is a fixed-width binary record stream:

```
[0]      magic   = 0xC7   (wire::METRICS_EXPORT_MAGIC)
[1]      version = 1
[2..4]   record_count : u16 LE
[4..]    record_count × 14-byte records, each:
         [module_id:u8][partition_id:u16 LE][metric_id:u16 LE]
         [kind:u8][value:i64 LE]
```

Each record is byte-identical to the `MSG_METRIC_SAMPLE` body, so a
scraper iterates fixed-width records with no per-module parser. The
header carries the magic and version byte only; there are no embedded
schema-version or build-sha strings.

After the latest-value table the aggregator appends four self-metrics
under `module_id = SOURCE_ID_TELEMETRY` (0x15): messages ingested,
typed samples decoded, metric slots used, and `TELE_METRICS_EVICTED`,
which counts table slots evicted because the fixed table filled. Then
come the global scheduler step histogram and the per-module step
histograms, and finally `TELE_RECORDS_DROPPED`, the count of records
this scrape dropped to stay inside the byte-budgeted channel ring, so
export truncation is observable rather than silent. The self-metrics
and the drop counter are emitted unconditionally; the budget reserves
space for them.

### Strict fallback and cache state

The admission module's proof cache broadcasts its state as
`MSG_CACHE_STATE` frames. Consensus consumes them: a stale cache
drives the commit component's strict-fallback flag, and raft exports
that state as the gauge `RAFT_STRICT_FALLBACK_FLAG`, with the counter
`RAFT_PROPOSALS_DROPPED_STRICT` recording proposals refused while the
fallback held. The cache state is not exported as a metric of its
own; the raft gauge is where it surfaces in `/metrics`.

---

## HTTP surface

The operations module's http component serves five routes
(`operations/http.rs`), behind wave's `http` module on the dedicated
diagnostic listener (see [../guides/net_http.md](../guides/net_http.md)):

| Route | Behaviour |
|---|---|
| `GET /readyz` | One-byte body (0 or 1); status 200 when ready, 503 otherwise. Answered from a cached byte. |
| `GET /why` | Two-byte body: format version (1) followed by `timing_pause_reason` (`wire::TIMING_PAUSE_*`), stating why deterministic time production is paused on this node, 0 when producing. |
| `GET /metrics` | The cached binary export described above. |
| `POST /propose` | Synchronous write bridge; the response is deferred until apply acknowledges the assigned WAL index. |
| `POST /admin/<op>` | Staged through rbac to the admin component; 202 on delivery. Recognised ops (`modules/common/http_admin.rs`): `freeze`, `thaw`, `transfer-leader`, `durability-mode`, `snapshot`. |

Readiness is computed by the telemetry component from readiness
sub-signals in the metric table: raft must report `RAFT_READY = 1`
(boot replay complete, metadata loaded, consensus established) and
every apply instance present must report `APPLY_CAUGHT_UP = 1`. A
minimum boot delay stops the node flipping ready before its first
full scrape, and a staleness watchdog drops `/readyz` back to 503 if
the underlying signals stop refreshing. The diagnostic caches are
refreshed on exactly the steps telemetry emits, so `/readyz`, `/why`
and `/metrics` share the export cadence.

There is no JSON payload on any of these routes and no Prometheus
text endpoint; `/metrics` is binary only.

---

## Host-side tooling

`tools/clustor-bench` is the off-DUT harness that consumes this
surface. It is std-only with no external crates, so it builds on an
offline driver host. The library decodes the binary export
(`parse_export` mirrors the wire framing) and provides a minimal
HTTP/1.1 client, a JSON writer, and a log-linear latency histogram
with coordinated-omission-aware percentiles. Two binaries sit on top:

- **`clustor-scrape`** scrapes `/metrics` at a window's start and
  end, computes counter deltas and final gauges, and writes a JSON
  baseline record carrying run provenance (git SHA, config hash,
  target, label, workload parameters).
- **`clustor-loadgen`** drives the DUT over the real client path
  (`POST /propose` by default) at a fixed offered rate across worker
  threads, and self-reports whether a run was DUT-attributable or
  harness-bound.

An operator or rig therefore consumes metrics by fetching the binary
export and diffing decoded records across a window, not by scraping a
text exposition format.
