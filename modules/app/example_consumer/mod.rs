//! Example replicated consumer module.
//!
//! A minimal reference implementation showing how a downstream
//! application (Loam, Lattice, future siblings) plugs into a Clustor
//! replica group through the typed surface in
//! `modules/common/replica_facade.rs`.
//!
//! What it does:
//!
//! - Subscribes to `apply_pipeline.committed_entries` and processes
//!   each `MSG_COMMITTED_ENTRY` in strict commit-index order, using
//!   `CommittedSubscriber::ingest_committed_entry`.
//! - Maintains a tiny xor-accumulator over each committed command
//!   body so an external observer can see deterministic state
//!   (every replica running this module should arrive at the same
//!   accumulator value after the same sequence of commits).
//! - Emits a heartbeat metric on `out_metrics` carrying
//!   `(applied_index:u64, applied_count:u32, accumulator:u32)`. This
//!   is the only way an operator confirms the per-entry stream is
//!   flowing end-to-end without inspecting the WAL.
//!
//! Wire shape:
//!
//!   in[0]  committed_entries     ← apply_pipeline.committed_entries
//!   out[0] metrics               → telemetry_agg.ingest
//!
//! This module is intentionally non-essential to the cluster's
//! correctness — it never proposes, never participates in quorum,
//! never gates anything else. Strip it from a deployment graph and
//! the cluster keeps running unchanged. It exists as a smoke test
//! that the facade contract is integration-correct, not just
//! unit-test correct.

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

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

#[path = "../../common/replica_facade.rs"]
mod replica_facade;

use replica_facade::{CommitOrderError, CommittedSubscriber};

const HEARTBEAT_INTERVAL_MS: u64 = 1000;
const SCRATCH_BUF_BYTES: usize = 2048 + 32;

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_entries: i32,            // in[0]: MSG_COMMITTED_ENTRY from apply_pipeline.committed_entries
    in_snapshot_chunk: i32,     // in[1]: MSG_APP_SNAPSHOT_CHUNK / MSG_APP_SNAPSHOT_RESET
    in_snapshot_request: i32,   // in[2]: MSG_APP_SNAPSHOT_REQUEST
    out_metrics: i32,           // out[0]: MSG_METRICS to telemetry_agg
    out_snapshot_export: i32,   // out[1]: MSG_APP_SNAPSHOT_CHUNK back to snapshot_engine

    /// Strict-commit-order subscriber for the per-entry stream.
    subscriber: CommittedSubscriber,

    /// Deterministic state: xor of every byte of every committed body
    /// the subscriber has accepted, folded down to a u32. Same
    /// command sequence → same accumulator on every replica.
    accumulator: u32,
    applied_count: u32,

    /// Count of gaps observed on the per-entry stream. Non-zero is a
    /// signal that the consumer fell behind apply_pipeline's ring;
    /// the right recovery is a snapshot install (out of scope for
    /// this example).
    stream_gaps: u32,
    /// Count of snapshot chunks accepted via the install path.
    snapshot_chunks_in: u32,
    /// Count of export chunks we've emitted in response to a request.
    snapshot_chunks_out: u32,
    last_metrics_ms: u64,

    msg_buf: [u8; SCRATCH_BUF_BYTES],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI (target/fluxor/fluxor-abi/sdk/abi.rs),
    // the kernel passes a valid, exclusively-borrowed `state` of
    // at least `module_state_size()` bytes, and a `syscalls`
    // table whose function pointers reach live kernel routines.
    // The dereferences and syscall invocations below rely on
    // those guarantees.
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_entries = in_chan;
        s.out_metrics = out_chan;
        s.in_snapshot_chunk = dev_channel_port(sys, 0, 1);
        s.in_snapshot_request = dev_channel_port(sys, 0, 2);
        s.out_snapshot_export = dev_channel_port(sys, 1, 1);
        s.subscriber = CommittedSubscriber::new(0);
        s.accumulator = 0;
        s.applied_count = 0;
        s.stream_gaps = 0;
        s.snapshot_chunks_in = 0;
        s.snapshot_chunks_out = 0;
        s.last_metrics_ms = 0;
        dev_log(sys, 3, b"[example] init".as_ptr(), 14);
        0
    }
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

        // 1) Drain up to 16 committed entries per step. The handler is
        //    a pure xor over the body bytes — deterministic, no I/O.
        for _ in 0..16 {
            let poll = (sys.channel_poll)(s.in_entries, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }
            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_entries, &mut s.msg_buf);
            if msg_type != wire::MSG_COMMITTED_ENTRY {
                continue;
            }
            let plen = plen as usize;
            match s.subscriber.ingest_committed_entry(&s.msg_buf[..plen]) {
                Ok(entry) => {
                    // Deterministic application: xor every body byte
                    // into a u32 accumulator. Trivially reproducible
                    // across replicas given the same byte stream.
                    let mut acc = s.accumulator;
                    for (i, &b) in entry.command.iter().enumerate() {
                        acc ^= (b as u32).rotate_left((i & 0x1f) as u32);
                    }
                    s.accumulator = acc;
                    s.applied_count = s.applied_count.saturating_add(1);
                    dev_log(sys, 3, b"[example] applied".as_ptr(), 17);
                }
                Err(CommitOrderError::GapInPerEntryStream { .. }) => {
                    s.stream_gaps = s.stream_gaps.saturating_add(1);
                    dev_log(sys, 2, b"[example] gap".as_ptr(), 13);
                    // No recovery in the example. A real consumer
                    // would request a snapshot install here.
                }
                Err(_) => {
                    // Malformed / non-monotonic — log and drop. The
                    // facade rejected the message; cursor is unchanged.
                    dev_log(sys, 2, b"[example] bad".as_ptr(), 13);
                }
            }
        }

        // 1b) Drain incoming state-machine snapshot chunks (RFC §2.1).
        //     The example accumulator has trivial state — a u32 xor —
        //     so a "snapshot" is just that u32. On reset, zero the
        //     state and accept incoming chunks as the new accumulator
        //     value; on done, fast-forward subscriber cursor to the
        //     snapshot index.
        if s.in_snapshot_chunk >= 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_snapshot_chunk, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_snapshot_chunk, &mut s.msg_buf);
                let pl = plen as usize;
                match msg_type {
                    wire::MSG_APP_SNAPSHOT_RESET => {
                        if pl >= 16 {
                            s.accumulator = 0;
                            s.applied_count = 0;
                            // The subscriber's cursor will be re-armed when
                            // the chunk stream ends with `done = 1` below.
                        }
                    }
                    wire::MSG_APP_SNAPSHOT_CHUNK => {
                        if let Some((term, last_idx, _off, done, hdr)) =
                            wire::decode_app_snapshot_chunk(&s.msg_buf[..pl])
                        {
                            // Apply chunk body to local state. The
                            // example body is a u32 LE accumulator
                            // value; the consumer xors successive
                            // chunks together.
                            let body = &s.msg_buf[hdr..pl];
                            for (i, &b) in body.iter().enumerate() {
                                s.accumulator ^= (b as u32).rotate_left((i & 0x1f) as u32);
                            }
                            s.snapshot_chunks_in = s.snapshot_chunks_in.saturating_add(1);
                            if done {
                                // Fast-forward the subscriber so the
                                // next committed entry must have index
                                // last_idx + 1; gaps below the snapshot
                                // are no longer errors.
                                s.subscriber = CommittedSubscriber::new(last_idx);
                                let _ = term;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 1c) Honour export requests by emitting our trivial accumulator
        //     as a single chunk back to snapshot_engine.
        if s.in_snapshot_request >= 0 && s.out_snapshot_export >= 0 {
            for _ in 0..2 {
                let poll = (sys.channel_poll)(s.in_snapshot_request, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_snapshot_request, &mut s.msg_buf);
                if msg_type != wire::MSG_APP_SNAPSHOT_REQUEST || (plen as usize) < 16 {
                    continue;
                }
                let (term, last_idx) = wire::decode_term_index(&s.msg_buf);
                let poll_out = (sys.channel_poll)(s.out_snapshot_export, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { continue; }
                let body = s.accumulator.to_le_bytes();
                let mut out = [0u8; wire::APP_SNAPSHOT_HDR + 4];
                let n = wire::encode_app_snapshot_chunk(
                    &mut out, term, last_idx, 0, true, &body,
                );
                if n > 0 {
                    wire_channels::channel_write_msg(
                        sys, s.out_snapshot_export, wire::MSG_APP_SNAPSHOT_CHUNK, &out[..n],
                    );
                    s.snapshot_chunks_out = s.snapshot_chunks_out.saturating_add(1);
                }
            }
        }

        // 2) Heartbeat metrics so an external observer can confirm the
        //    consumer is making progress.
        let now = dev_millis(sys);
        if now.wrapping_sub(s.last_metrics_ms) >= HEARTBEAT_INTERVAL_MS && s.out_metrics >= 0 {
            s.last_metrics_ms = now;
            let mut buf = [0u8; 24];
            buf[0..8].copy_from_slice(&s.subscriber.cursor().to_le_bytes());
            buf[8..12].copy_from_slice(&s.applied_count.to_le_bytes());
            buf[12..16].copy_from_slice(&s.accumulator.to_le_bytes());
            buf[16..20].copy_from_slice(&s.stream_gaps.to_le_bytes());
            buf[20..24].copy_from_slice(&(s.subscriber.last_term() as u32).to_le_bytes());
            let poll = (sys.channel_poll)(s.out_metrics, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf);
            }
        }

        0
    }
}
