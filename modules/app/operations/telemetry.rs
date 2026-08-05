//! telemetry — metrics fan-in and diagnostic aggregation.
//!
//! Drains metrics from all modules (via auto-merge on the `ingest`
//! port) and from sibling components (delivered as message-shaped
//! calls), maintains the latest-value table, and emits readyz/why/
//! export payloads on the module's output ports every
//! `emit_interval_ms`. On each emit tick the fresh payloads are also
//! available to the [`http`](super::http) component, which caches
//! them for `GET /readyz|/why|/metrics`.

use super::abi::SyscallTable;
use super::{wire, wire_channels};
use super::dev_millis;

/// Default `/metrics` export cadence (ms). Overridable per-graph via
/// the `emit_interval_ms` param (RFC §4.4) — a bench profile lowers it
/// so a short measurement window still sees fresh samples; production
/// profiles leave it at 1 s. Cadence is configuration, never hardcoded
/// in a producer (standards `observability.md` §7).
pub const EMIT_INTERVAL_MS_DEFAULT: u64 = 1000;

/// Kernel scheduler step-timing histogram query (RFC §4.3). Internal
/// monitor opcode (`abi::internal::monitor::STEP_HISTOGRAM_QUERY`);
/// `handle = -1` reads the global histogram into 8 × u32 bucket counts.
/// Defined locally so the producer path doesn't depend on the unstable
/// internal-ABI module path.
const STEP_HISTOGRAM_QUERY: u32 = 0x0C55;
const STEP_HIST_BUCKETS: usize = 8;

/// Size of the per-(module, metric_id) latest-value table. 256 slots
/// covers the current scalar set plus the four fixed-bucket histograms
/// (RFC §4.1, ~50 bucket-slots) with headroom; older entries are
/// LRU-evicted by simple oldest-write replacement.
const METRIC_SLOTS: usize = 320;

/// Number of scheduler module slots scraped for the per-module step-timing
/// histogram (RFC §4.3). The kernel exposes `[u32; 8]` per module via
/// `STEP_HISTOGRAM_QUERY` with `handle = module_idx`. Only non-zero (active)
/// modules are exported, byte-budgeted against the channel ring.
const STEP_MODULES: usize = 32;

/// Safe export ceiling. The telemetry→client and http-response channels both
/// use the fixed ~8 KiB channel ring (`CHANNEL_BUFFER_SIZE`), and a frame
/// larger than the ring never lands (atomic all-or-nothing write). Keep the
/// export below this so `/metrics` never silently fails to publish; records
/// past the budget are dropped and counted in `TELE_RECORDS_DROPPED`.
pub const SAFE_EXPORT_MAX: usize = 7400;

/// Minimum boot delay before `/readyz` can flip to 200. Not a readiness
/// criterion itself — just a floor so the first metric-sample window has
/// populated the table before `compute_ready` is trusted (otherwise an empty
/// table would read as "no raft instance present" and could mis-evaluate).
const READY_MIN_MS: u64 = 500;

/// Export buffer for the `/metrics` payload. Sized to one full channel ring
/// (`CHANNEL_BUFFER_SIZE` = 8 KiB); `build_export` byte-budgets the actual
/// payload to `SAFE_EXPORT_MAX` so a frame always fits the ring.
const EXPORT_BUF_LEN: usize = 8192;

#[derive(Clone, Copy)]
#[repr(C)]
struct MetricEntry {
    /// 0 = slot empty. Module ids are non-zero (RFC §4.3).
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
    last_update_ms: u64,
}

impl MetricEntry {
    const fn empty() -> Self {
        Self {
            module_id: 0,
            partition_id: 0,
            metric_id: 0,
            kind: 0,
            value: 0,
            last_update_ms: 0,
        }
    }
}

#[repr(C)]
pub struct Telemetry {
    pub in_ingest: i32,  // in: metrics from all modules (fan-in)
    pub out_readyz: i32, // out: readyz
    pub out_why: i32,    // out: why
    pub out_export: i32, // out: export

    // Aggregated counters
    messages_ingested: u32,
    /// Count of typed `MSG_METRIC_SAMPLE` envelopes seen since startup.
    typed_samples_ingested: u32,
    /// Metric-table slots evicted because the table filled (LRU). Surfaces
    /// undersized-table loss instead of dropping silently.
    metrics_evicted: u32,
    /// Export records dropped on the last scrape because the channel-ring
    /// byte budget was hit (table tail or per-module step histograms).
    records_dropped: u32,
    /// `/metrics` export cadence in ms (param `emit_interval_ms`, §4.4).
    pub emit_interval_ms: u64,
    last_emit_ms: u64,
    pub ready: bool,
    pub startup_ms: u64,
    /// Set for exactly the steps on which the emit tick fired — the
    /// dispatch table uses it to refresh the http component's caches.
    pub emitted: bool,
    /// Byte length of the current `export_buf` payload (0 = never built).
    pub export_len: u16,

    /// Latest-value table for typed metric samples, indexed by
    /// `(module_id, partition_id, metric_id)`. Counters are stored
    /// as their absolute value (consumers compute deltas); gauges
    /// just overwrite.
    metrics: [MetricEntry; METRIC_SLOTS],

    msg_buf: [u8; 256],
    /// Serialized `/metrics` payload, rebuilt each export tick.
    pub export_buf: [u8; EXPORT_BUF_LEN],
    /// Global scheduler step-timing histogram (RFC §4.3), scraped from
    /// the kernel each export tick and appended to the export so a
    /// single `/metrics` read attributes time across modules.
    step_buckets: [u32; STEP_HIST_BUCKETS],
}

pub unsafe fn init(t: &mut Telemetry, sys: &SyscallTable) {
    t.in_ingest = -1;
    t.out_readyz = -1;
    t.out_why = -1;
    t.out_export = -1;
    t.messages_ingested = 0;
    t.typed_samples_ingested = 0;
    t.metrics_evicted = 0;
    t.records_dropped = 0;
    t.emit_interval_ms = EMIT_INTERVAL_MS_DEFAULT;
    t.last_emit_ms = 0;
    t.ready = false;
    t.startup_ms = dev_millis(sys);
    t.emitted = false;
    t.export_len = 0;
    for slot in t.metrics.iter_mut() {
        *slot = MetricEntry::empty();
    }
    t.step_buckets = [0u32; STEP_HIST_BUCKETS];
}

/// True on exactly the steps the export tick emitted — the dispatch
/// table refreshes the http/ingress caches on these steps.
pub fn emitted(t: &Telemetry) -> bool {
    t.emitted
}

/// Snapshot of the current readiness verdict and export payload for
/// cache refresh. Sibling components consume these values through the
/// dispatch table — never the telemetry struct itself.
pub fn snapshot(t: &Telemetry) -> (bool, &[u8]) {
    (t.ready, &t.export_buf[..t.export_len as usize])
}

/// Count a legacy opaque `MSG_METRICS` envelope from a sibling
/// component — the same accounting the `ingest` port gives external
/// producers.
pub fn on_legacy_envelope(t: &mut Telemetry) {
    t.messages_ingested += 1;
}

/// Ingest one typed metric sample from a sibling component. Identical
/// semantics to a `MSG_METRIC_SAMPLE` arriving on `ingest`, without
/// the wire round-trip.
pub fn on_typed_sample(
    t: &mut Telemetry,
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
    now: u64,
) {
    t.messages_ingested += 1;
    t.typed_samples_ingested += 1;
    upsert(t, module_id, partition_id, metric_id, kind, value, now);
}

/// Compute real readiness from the aggregated metric table. Ready iff at
/// least one raft instance is present and every raft instance reports
/// `RAFT_READY=1`, and — if any apply instance is present — every one
/// reports `APPLY_CAUGHT_UP=1`. Scanning slots handles multi-partition graphs
/// (one raft/apply pair per partition) without special-casing.
fn compute_ready(t: &Telemetry) -> bool {
    let mut saw_raft = false;
    let mut raft_ok = true;
    let mut saw_apply = false;
    let mut apply_ok = true;
    for slot in t.metrics.iter() {
        if slot.module_id == 0 {
            continue;
        }
        if slot.module_id == wire::SOURCE_ID_RAFT
            && slot.metric_id == wire::metric_ids::RAFT_READY
        {
            saw_raft = true;
            if slot.value == 0 {
                raft_ok = false;
            }
        } else if slot.module_id == wire::SOURCE_ID_APPLY
            && slot.metric_id == wire::metric_ids::APPLY_CAUGHT_UP
        {
            saw_apply = true;
            if slot.value == 0 {
                apply_ok = false;
            }
        }
    }
    saw_raft && raft_ok && (!saw_apply || apply_ok)
}

fn upsert(
    t: &mut Telemetry,
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
    now: u64,
) {
    if module_id == 0 {
        return;
    }
    // Same-slot update if we already track this metric.
    for slot in t.metrics.iter_mut() {
        if slot.module_id == module_id
            && slot.partition_id == partition_id
            && slot.metric_id == metric_id
        {
            slot.kind = kind;
            slot.value = value;
            slot.last_update_ms = now;
            return;
        }
    }
    // Otherwise pick an empty slot or evict the oldest.
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in t.metrics.iter().enumerate() {
        if slot.module_id == 0 {
            slot_idx = Some(i);
            break;
        }
    }
    let i = match slot_idx {
        Some(i) => i,
        None => {
            // Table full — evict the oldest-written slot and count it so an
            // undersized table is visible rather than silently lossy.
            t.metrics_evicted = t.metrics_evicted.saturating_add(1);
            let mut oldest_idx = 0usize;
            let mut oldest_ms = u64::MAX;
            for (i, slot) in t.metrics.iter().enumerate() {
                if slot.last_update_ms < oldest_ms {
                    oldest_ms = slot.last_update_ms;
                    oldest_idx = i;
                }
            }
            oldest_idx
        }
    };
    t.metrics[i] = MetricEntry {
        module_id,
        partition_id,
        metric_id,
        kind,
        value,
        last_update_ms: now,
    };
}

/// Append one 14-byte metric record at `buf[pos..]` and return the new
/// position. Caller guarantees `pos + METRICS_RECORD_LEN <= buf.len()`.
#[inline]
fn push_record(
    buf: &mut [u8],
    pos: usize,
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
) -> usize {
    let mut rec = [0u8; wire::METRICS_RECORD_LEN];
    wire::encode_metric_sample(&mut rec, module_id, partition_id, metric_id, kind, value);
    buf[pos..pos + wire::METRICS_RECORD_LEN].copy_from_slice(&rec);
    pos + wire::METRICS_RECORD_LEN
}

/// Serialise the latest-value table + self-metrics + global and per-module
/// kernel step histograms into `export_buf`, byte-budgeted to `SAFE_EXPORT_MAX`
/// so the frame always fits the channel ring. Records that don't fit are
/// dropped and counted in `t.records_dropped` (→ `TELE_RECORDS_DROPPED`),
/// making truncation observable rather than silent. Format is documented at
/// `wire::METRICS_EXPORT_MAGIC`.
///
/// # Safety
///
/// `sys` must be a live `&SyscallTable` (used for the per-module step scrape).
unsafe fn build_export(t: &mut Telemetry, sys: &SyscallTable) -> usize {
    let mut pos = wire::METRICS_EXPORT_HDR;
    let mut count = 0u16;
    let mut dropped = 0u32;
    // Each record is fixed-width; stop appending once the next record would
    // cross the safe budget so the emitted frame fits the channel ring.
    macro_rules! fits {
        () => {
            pos + wire::METRICS_RECORD_LEN <= SAFE_EXPORT_MAX
        };
    }

    // 1. Latest-value table.
    for i in 0..METRIC_SLOTS {
        let slot = t.metrics[i];
        if slot.module_id == 0 {
            continue;
        }
        if !fits!() {
            dropped += 1;
            continue;
        }
        pos = push_record(
            &mut t.export_buf,
            pos,
            slot.module_id,
            slot.partition_id,
            slot.metric_id,
            slot.kind,
            slot.value,
        );
        count += 1;
    }

    // 2. Aggregator self-metrics (module_id = 0x15). Always emitted (the
    //    drop/eviction counters in particular must survive a budget squeeze).
    let tele = wire::SOURCE_ID_TELEMETRY;
    let kc = wire::METRIC_KIND_COUNTER;
    let kg = wire::METRIC_KIND_GAUGE;
    pos = push_record(&mut t.export_buf, pos, tele, 0, wire::metric_ids::TELE_MESSAGES_INGESTED, kc, i64::from(t.messages_ingested));
    pos = push_record(&mut t.export_buf, pos, tele, 0, wire::metric_ids::TELE_TYPED_SAMPLES, kc, i64::from(t.typed_samples_ingested));
    pos = push_record(&mut t.export_buf, pos, tele, 0, wire::metric_ids::TELE_METRIC_SLOTS_USED, kg, i64::from(count));
    pos = push_record(&mut t.export_buf, pos, tele, 0, wire::metric_ids::TELE_METRICS_EVICTED, kc, i64::from(t.metrics_evicted));
    count += 4;

    // 3. Global kernel scheduler step-timing histogram (RFC §4.3). Cumulative
    //    per the wire contract: bucket i = count of samples <= bound[i].
    let kh = wire::METRIC_KIND_HISTOGRAM;
    let mut cum: i64 = 0;
    for i in 0..STEP_HIST_BUCKETS {
        cum += i64::from(t.step_buckets[i]);
        pos = push_record(&mut t.export_buf, pos, tele, 0, wire::hist::HIST_BASE + i as u16, kh, cum);
        count += 1;
    }

    // 4. Per-module step histograms (RFC §4.3). Scrape each scheduler module
    //    slot; export only NON-ZERO (active) modules, byte-budgeted. Tagged by
    //    partition_id = scheduler module_idx, metric_id = STEP_PERMOD_BASE + i.
    for m in 0..STEP_MODULES {
        let mut sb = [0u32; STEP_HIST_BUCKETS];
        let rc = (sys.provider_call)(
            m as i32,
            STEP_HISTOGRAM_QUERY,
            sb.as_mut_ptr() as *mut u8,
            (STEP_HIST_BUCKETS * 4) as usize,
        );
        if rc < 0 {
            continue;
        }
        let total: u32 = sb.iter().copied().fold(0u32, |a, b| a.saturating_add(b));
        if total == 0 {
            continue; // idle / unused slot — don't bloat the export
        }
        if pos + STEP_HIST_BUCKETS * wire::METRICS_RECORD_LEN > SAFE_EXPORT_MAX {
            dropped += STEP_HIST_BUCKETS as u32;
            continue;
        }
        let mut c: i64 = 0;
        for i in 0..STEP_HIST_BUCKETS {
            c += i64::from(sb[i]);
            pos = push_record(
                &mut t.export_buf,
                pos,
                tele,
                m as u16,
                wire::hist::STEP_PERMOD_BASE + i as u16,
                kh,
                c,
            );
            count += 1;
        }
    }

    // 5. Drop counter last (its own value reflects this scrape). Always fits —
    //    the budget leaves a record's headroom (SAFE_EXPORT_MAX < ring).
    t.records_dropped = dropped;
    pos = push_record(&mut t.export_buf, pos, tele, 0, wire::metric_ids::TELE_RECORDS_DROPPED, kc, i64::from(dropped));
    count += 1;

    // Header: magic, version, record_count LE.
    t.export_buf[0] = wire::METRICS_EXPORT_MAGIC;
    t.export_buf[1] = wire::METRICS_EXPORT_VERSION;
    t.export_buf[2..4].copy_from_slice(&count.to_le_bytes());
    pos
}

/// Per-step bound: 16 ingest envelopes; on the emit tick additionally
/// one global + up to 32 per-module histogram scrapes and the export
/// serialization (byte-budgeted to `SAFE_EXPORT_MAX`). The emit tick
/// is the module's heaviest single step — the dispatch table
/// schedules telemetry first so it never stacks behind the HTTP
/// serve path in the same step's tail.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Telemetry` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(t: &mut Telemetry, sys: &SyscallTable, now: u64) {
    t.emitted = false;

    // 1. Drain all ingest metrics. Two envelope shapes coexist:
    //    legacy `MSG_METRICS` (opaque per-module payload — counted
    //    only) and typed `MSG_METRIC_SAMPLE` (decoded into the
    //    latest-value table). See RFC §4.3.
    if t.in_ingest >= 0 {
        for _ in 0..16 {
            let poll = (sys.channel_poll)(t.in_ingest, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, t.in_ingest, &mut t.msg_buf);
            match msg_type {
                wire::MSG_METRICS => {
                    t.messages_ingested += 1;
                }
                wire::MSG_METRIC_SAMPLE => {
                    t.messages_ingested += 1;
                    t.typed_samples_ingested += 1;
                    let pl = plen as usize;
                    // Copy out of msg_buf so the &mut t borrow inside
                    // upsert doesn't clash with the slice.
                    let mut local = [0u8; wire::METRIC_SAMPLE_LEN];
                    let take = pl.min(wire::METRIC_SAMPLE_LEN);
                    local[..take].copy_from_slice(&t.msg_buf[..take]);
                    if let Some((module_id, partition_id, metric_id, kind, value)) =
                        wire::decode_metric_sample(&local[..take])
                    {
                        upsert(t, module_id, partition_id, metric_id, kind, value, now);
                    }
                }
                _ => {}
            }
        }
    }

    // Real readiness (replaces the old fixed 5 s boot timer): the node is
    // ready once every raft instance reports RAFT_READY=1 (boot replay
    // done, metadata loaded, consensus established) AND — if an
    // an apply instance is present in this graph — every apply instance
    // reports APPLY_CAUGHT_UP=1 (apply cursor reached the commit horizon).
    // Readiness is level-triggered (recomputed each step) so it correctly
    // drops back to 503 if a node loses its leader or apply falls behind.
    // A small `startup_ms` floor avoids a 200 before the first sample
    // window has populated the table.
    if now.wrapping_sub(t.startup_ms) >= READY_MIN_MS {
        t.ready = compute_ready(t);
    }

    // 2. Emit readyz/why/export periodically
    if now.wrapping_sub(t.last_emit_ms) >= t.emit_interval_ms {
        t.last_emit_ms = now;
        t.emitted = true;

        // Scrape the kernel scheduler step-timing histogram (RFC
        // §4.3). Best-effort: a negative return (opcode unsupported
        // on this target) leaves the last sample in place.
        let mut sb = [0u32; STEP_HIST_BUCKETS];
        let rc = (sys.provider_call)(
            -1,
            STEP_HISTOGRAM_QUERY,
            sb.as_mut_ptr() as *mut u8,
            (STEP_HIST_BUCKETS * 4) as usize,
        );
        if rc >= 0 {
            t.step_buckets = sb;
        }

        // Readyz: 1 byte (ready flag)
        if t.out_readyz >= 0 {
            let poll = (sys.channel_poll)(t.out_readyz, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let buf = [t.ready as u8];
                wire_channels::channel_write_msg(sys, t.out_readyz, wire::MSG_READYZ, &buf);
            }
        }

        // Why: empty payload for now (no blocking reasons)
        if t.out_why >= 0 {
            let poll = (sys.channel_poll)(t.out_why, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let buf = [0u8; 1];
                wire_channels::channel_write_msg(sys, t.out_why, wire::MSG_WHY, &buf);
            }
        }

        // Export: full latest-value table (RFC §4.1/§4.3). The payload
        // is the binary record stream documented at
        // `wire::METRICS_EXPORT_MAGIC`; the http component caches it
        // and serves it verbatim at `GET /metrics`. Built once per
        // tick and shared by the port write and the http cache.
        let len = build_export(t, sys);
        t.export_len = len as u16;
        if t.out_export >= 0 {
            let poll = (sys.channel_poll)(t.out_export, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(sys, t.out_export, wire::MSG_METRICS, &t.export_buf[..len]);
            }
        }
    }
}
