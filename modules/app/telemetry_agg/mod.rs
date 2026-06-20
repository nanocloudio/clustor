//! Telemetry Aggregator — Metrics fan-in and diagnostic output.
//!
//! Drains metrics from all modules (via auto-merge on ingest port),
//! maintains counters/gauges, and emits readyz/why/export payloads
//! to client_surface.

#![no_std]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; pending upstream allow attributes in target/fluxor/fluxor-abi/sdk/"
)]

use core::ffi::c_void;

#[allow(
    unused_imports,
    dead_code,
    reason = "see file-level allow: SDK surface is shared across modules"
)]
#[path = "../../../target/fluxor/fluxor-abi/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../../target/fluxor/fluxor-abi/sdk/runtime.rs");
include!("../../../target/fluxor/fluxor-abi/sdk/params.rs");

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

/// Default `/metrics` export cadence (ms). Overridable per-graph via
/// the `emit_interval_ms` param (RFC §4.4) — a bench profile lowers it
/// so a short measurement window still sees fresh samples; production
/// profiles leave it at 1 s. Cadence is configuration, never hardcoded
/// in a producer (standards `observability.md` §7).
const EMIT_INTERVAL_MS_DEFAULT: u64 = 1000;

define_params! {
    ModuleState;

    1, emit_interval_ms, u16, 1000
        => |s, d, len| { s.emit_interval_ms = p_u16(d, len, 0, 1000) as u64; };
}

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
const SAFE_EXPORT_MAX: usize = 7400;

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
struct ModuleState {
    syscalls: *const SyscallTable,
    in_ingest: i32,      // in[0]: metrics from all modules (fan-in)
    out_readyz: i32,     // out[0]: readyz to client_surface
    out_why: i32,        // out[1]: why to client_surface
    out_export: i32,     // out[2]: export to client_surface

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
    emit_interval_ms: u64,
    last_emit_ms: u64,
    ready: bool,
    startup_ms: u64,

    /// Latest-value table for typed metric samples, indexed by
    /// `(module_id, partition_id, metric_id)`. Counters are stored
    /// as their absolute value (consumers compute deltas); gauges
    /// just overwrite.
    metrics: [MetricEntry; METRIC_SLOTS],

    msg_buf: [u8; 256],
    /// Serialized `/metrics` payload, rebuilt each export tick.
    export_buf: [u8; EXPORT_BUF_LEN],
    /// Global scheduler step-timing histogram (RFC §4.3), scraped from
    /// the kernel each export tick and appended to the export so a
    /// single `/metrics` read attributes time across modules.
    step_buckets: [u32; STEP_HIST_BUCKETS],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 { core::mem::size_of::<ModuleState>() as u32 }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_ingest = in_chan;
        s.out_readyz = out_chan;
        s.out_why = dev_channel_port(sys, 1, 1);
        s.out_export = dev_channel_port(sys, 1, 2);
        s.startup_ms = dev_millis(sys);
        s.typed_samples_ingested = 0;
        for slot in s.metrics.iter_mut() {
            *slot = MetricEntry::empty();
        }
        s.step_buckets = [0u32; STEP_HIST_BUCKETS];
        // Default cadence, then override from params if present (§4.4).
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        dev_log(sys, 3, b"[tele] init".as_ptr(), 11);
        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Compute real readiness from the aggregated metric table. Ready iff at
/// least one raft instance is present and every raft instance reports
/// `RAFT_READY=1`, and — if any apply_pipeline instance is present — every one
/// reports `APPLY_CAUGHT_UP=1`. Scanning slots handles multi-partition graphs
/// (one raft/apply pair per partition) without special-casing.
fn compute_ready(s: &ModuleState) -> bool {
    let mut saw_raft = false;
    let mut raft_ok = true;
    let mut saw_apply = false;
    let mut apply_ok = true;
    for slot in s.metrics.iter() {
        if slot.module_id == 0 {
            continue;
        }
        if slot.module_id == wire::MODULE_ID_RAFT_ENGINE
            && slot.metric_id == wire::metric_ids::RAFT_READY
        {
            saw_raft = true;
            if slot.value == 0 {
                raft_ok = false;
            }
        } else if slot.module_id == wire::MODULE_ID_APPLY_PIPELINE
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

unsafe fn ingest_typed_sample(s: &mut ModuleState, payload: &[u8], now: u64) {
    let (module_id, partition_id, metric_id, kind, value) =
        match wire::decode_metric_sample(payload) {
            Some(v) => v,
            None => return,
        };
    if module_id == 0 {
        return;
    }
    // Same-slot update if we already track this metric.
    for slot in s.metrics.iter_mut() {
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
    for (i, slot) in s.metrics.iter().enumerate() {
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
            s.metrics_evicted = s.metrics_evicted.saturating_add(1);
            let mut oldest_idx = 0usize;
            let mut oldest_ms = u64::MAX;
            for (i, slot) in s.metrics.iter().enumerate() {
                if slot.last_update_ms < oldest_ms {
                    oldest_ms = slot.last_update_ms;
                    oldest_idx = i;
                }
            }
            oldest_idx
        }
    };
    s.metrics[i] = MetricEntry {
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

/// Serialize the latest-value table plus the aggregator's own
/// self-metrics into `s.export_buf` and return the byte length. Format
/// is documented at `wire::METRICS_EXPORT_MAGIC`.
/// Serialise the latest-value table + self-metrics + global and per-module
/// kernel step histograms into `export_buf`, byte-budgeted to `SAFE_EXPORT_MAX`
/// so the frame always fits the channel ring. Records that don't fit are
/// dropped and counted in `s.records_dropped` (→ `TELE_RECORDS_DROPPED`),
/// making truncation observable rather than silent.
///
/// # Safety
///
/// `sys` must be a live `&SyscallTable` (used for the per-module step scrape).
unsafe fn build_export(s: &mut ModuleState, sys: &SyscallTable) -> usize {
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
        let slot = s.metrics[i];
        if slot.module_id == 0 {
            continue;
        }
        if !fits!() {
            dropped += 1;
            continue;
        }
        pos = push_record(
            &mut s.export_buf,
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
    let tele = wire::MODULE_ID_TELEMETRY_AGG;
    let kc = wire::METRIC_KIND_COUNTER;
    let kg = wire::METRIC_KIND_GAUGE;
    pos = push_record(&mut s.export_buf, pos, tele, 0, wire::metric_ids::TELE_MESSAGES_INGESTED, kc, i64::from(s.messages_ingested));
    pos = push_record(&mut s.export_buf, pos, tele, 0, wire::metric_ids::TELE_TYPED_SAMPLES, kc, i64::from(s.typed_samples_ingested));
    pos = push_record(&mut s.export_buf, pos, tele, 0, wire::metric_ids::TELE_METRIC_SLOTS_USED, kg, i64::from(count));
    pos = push_record(&mut s.export_buf, pos, tele, 0, wire::metric_ids::TELE_METRICS_EVICTED, kc, i64::from(s.metrics_evicted));
    count += 4;

    // 3. Global kernel scheduler step-timing histogram (RFC §4.3). Cumulative
    //    per the wire contract: bucket i = count of samples <= bound[i].
    let kh = wire::METRIC_KIND_HISTOGRAM;
    let mut cum: i64 = 0;
    for i in 0..STEP_HIST_BUCKETS {
        cum += i64::from(s.step_buckets[i]);
        pos = push_record(&mut s.export_buf, pos, tele, 0, wire::hist::HIST_BASE + i as u16, kh, cum);
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
                &mut s.export_buf,
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
    s.records_dropped = dropped;
    pos = push_record(&mut s.export_buf, pos, tele, 0, wire::metric_ids::TELE_RECORDS_DROPPED, kc, i64::from(dropped));
    count += 1;

    // Header: magic, version, record_count LE.
    s.export_buf[0] = wire::METRICS_EXPORT_MAGIC;
    s.export_buf[1] = wire::METRICS_EXPORT_VERSION;
    s.export_buf[2..4].copy_from_slice(&count.to_le_bytes());
    pos
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // 1. Drain all ingest metrics. Two envelope shapes coexist:
        //    legacy `MSG_METRICS` (opaque per-module payload — counted
        //    only) and typed `MSG_METRIC_SAMPLE` (decoded into the
        //    latest-value table). See RFC §4.3.
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_ingest, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_ingest, &mut s.msg_buf);
            match msg_type {
                wire::MSG_METRICS => {
                    s.messages_ingested += 1;
                }
                wire::MSG_METRIC_SAMPLE => {
                    s.messages_ingested += 1;
                    s.typed_samples_ingested += 1;
                    let pl = plen as usize;
                    // Copy out of msg_buf so the &mut s borrow inside
                    // ingest_typed_sample doesn't clash with the slice.
                    let mut local = [0u8; wire::METRIC_SAMPLE_LEN];
                    let take = pl.min(wire::METRIC_SAMPLE_LEN);
                    local[..take].copy_from_slice(&s.msg_buf[..take]);
                    ingest_typed_sample(s, &local[..take], now);
                }
                _ => {}
            }
        }

        // Real readiness (replaces the old fixed 5 s boot timer): the node is
        // ready once every raft instance reports RAFT_READY=1 (boot replay
        // done, metadata loaded, consensus established) AND — if an
        // apply_pipeline is present in this graph — every apply instance
        // reports APPLY_CAUGHT_UP=1 (apply cursor reached the commit horizon).
        // Readiness is level-triggered (recomputed each step) so it correctly
        // drops back to 503 if a node loses its leader or apply falls behind.
        // A small `startup_ms` floor avoids a 200 before the first sample
        // window has populated the table.
        if now.wrapping_sub(s.startup_ms) >= READY_MIN_MS {
            s.ready = compute_ready(s);
        }

        // 2. Emit readyz/why/export periodically
        if now.wrapping_sub(s.last_emit_ms) >= s.emit_interval_ms {
            s.last_emit_ms = now;

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
                s.step_buckets = sb;
            }

            // Readyz: 1 byte (ready flag)
            if s.out_readyz >= 0 {
                let poll = (sys.channel_poll)(s.out_readyz, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = [s.ready as u8];
                    wire_channels::channel_write_msg(sys, s.out_readyz, wire::MSG_READYZ, &buf);
                }
            }

            // Why: empty payload for now (no blocking reasons)
            if s.out_why >= 0 {
                let poll = (sys.channel_poll)(s.out_why, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let buf = [0u8; 1];
                    wire_channels::channel_write_msg(sys, s.out_why, wire::MSG_WHY, &buf);
                }
            }

            // Export: full latest-value table (RFC §4.1/§4.3). The
            // payload is the binary record stream documented at
            // `wire::METRICS_EXPORT_MAGIC`; http_adapter caches it and
            // serves it verbatim at `GET /metrics`.
            if s.out_export >= 0 {
                let poll = (sys.channel_poll)(s.out_export, 0x02);
                if poll > 0 && (poll as u32 & 0x02) != 0 {
                    let len = build_export(s, sys);
                    wire_channels::channel_write_msg(sys, s.out_export, wire::MSG_METRICS, &s.export_buf[..len]);
                }
            }
        }

        0
    }
}
