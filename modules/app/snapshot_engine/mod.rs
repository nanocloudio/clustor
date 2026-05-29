//! Snapshot Engine — per-partition snapshot manifest persistence.
//!
//! Each instance handles snapshots for exactly one Raft partition and
//! writes its manifest to a partition-scoped path so per-partition
//! state stays isolated:
//!
//!   partition_id == 0  →  `wal/snap_<NNNNNNNN>.bin`
//!   partition_id == N  →  `wal/p<NNNN>/snap_<NNNNNNNN>.bin`
//!
//! On `MSG_SNAPSHOT_TRIGGER` (16 bytes `[term:u64][index:u64]` from
//! the per-partition WAL when its current segment fills) the engine:
//!
//!   1. Opens / creates a snapshot file at the partition path with
//!      filename suffix `snap_<index>.bin` (8 hex digits).
//!   2. Writes a 32-byte manifest record:
//!        [magic:u32 LE = 0x534E_4150 ("SNAP")]
//!        [partition_id:u16 LE]
//!        [reserved:u16  = 0]
//!        [term:u64 LE]
//!        [index:u64 LE]
//!        [dek_epoch:u32 LE]
//!   3. fsync + close.
//!
//! This is the plumbing for log compaction; actual log truncation
//! across the snapshot index and follower-catchup via
//! `InstallSnapshot` are deferred. Until those land, snapshots serve
//! as a durable record that "the partition reached this term/index"
//! — readable by ops tooling and useful for crash diagnostics.

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

#[path = "../../common/types.rs"]
mod types;

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use types::*;

const FS_OPEN: u32 = 0x0900;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;

const SNAP_PATH_MAX: usize = 64;
const MANIFEST_LEN: usize = 32;
const MAGIC_SNAP: u32 = 0x534E_4150; // "SNAP" little-endian as bytes

/// Max snapshot body bytes we'll buffer in module memory before
/// finalising. Once the state-machine snapshot API (§2.1) lands, the
/// reference path here moves to a temp file on disk; this cap acts as
/// a safety valve so a misbehaving leader can't OOM us.
const MAX_SNAPSHOT_BODY: usize = 16 * 1024;

/// Largest chunk we emit on the wire. Bounded so a single envelope
/// fits inside MAX_PAYLOAD (64 KiB - 1) with room for the
/// `MSG_INSTALL_SNAPSHOT` 33-byte header.
const MAX_CHUNK_BODY: usize = 4 * 1024;

define_params! {
    ModuleState;

    1, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_import: i32,             // in[0]: import chunks from replicator (InstallSnapshot RPC)
    in_trigger: i32,            // in[1]: SnapshotTrigger from wal
    in_key_update: i32,         // in[2]: DekEpoch from key_manager
    in_install_request: i32,    // in[3]: MSG_SNAPSHOT_INSTALL_REQUEST from replicator (§4.2)
    out_export: i32,            // out[0]: export chunks to replicator (peer transfer)
    out_manifest: i32,          // out[1]: manifest auth to peer_router (deferred)
    out_metrics: i32,           // out[2]: metrics to telemetry_agg
    out_installed: i32,         // out[3]: MSG_SNAPSHOT_INSTALLED to raft_engine

    // Most recent snapshot (term, index) we persisted. Used to answer
    // on-demand install requests from `replicator` (§4.2).
    last_snapshot_term: u64,
    last_snapshot_index: u64,

    partition_id: u16,

    // State
    dek_epoch: u32,
    snapshots_taken: u32,
    chunks_imported: u32,

    // In-flight install state (single-stream, fail-open if interleaved):
    in_progress_term: u64,
    in_progress_last_idx: u64,
    in_progress_last_term: u64,
    in_progress_active: bool,
    /// Next expected offset for the in-progress install. A chunk
    /// arriving with a different offset signals reordering or loss;
    /// we discard the install attempt and wait for the leader to
    /// re-send from offset 0.
    in_progress_offset: u64,
    /// Accumulated body bytes for the in-progress install. Capped at
    /// MAX_SNAPSHOT_BODY — beyond that the install is aborted.
    body_buf: [u8; MAX_SNAPSHOT_BODY],
    body_len: u32,

    // Scratch
    path_buf: [u8; SNAP_PATH_MAX],
    msg_buf: [u8; 8192],
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
        s.in_import = in_chan;
        s.out_export = out_chan;
        s.in_trigger = dev_channel_port(sys, 0, 1);
        s.in_key_update = dev_channel_port(sys, 0, 2);
        s.in_install_request = dev_channel_port(sys, 0, 3);
        s.out_manifest = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.out_installed = dev_channel_port(sys, 1, 3);

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }

        dev_log(sys, 3, b"[snap] init".as_ptr(), 11);
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

        // 1. Drain key updates (track current DEK epoch for manifest).
        if s.in_key_update >= 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_key_update, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_key_update, &mut s.msg_buf);
                if msg_type == wire::MSG_DEK_EPOCH && plen >= 4 {
                    s.dek_epoch = u32::from_le_bytes([
                        s.msg_buf[0], s.msg_buf[1], s.msg_buf[2], s.msg_buf[3],
                    ]);
                }
            }
        }

        // 2. Snapshot triggers from wal.
        if s.in_trigger >= 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_trigger, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_trigger, &mut s.msg_buf);
                if msg_type == wire::MSG_SNAPSHOT_TRIGGER && plen >= 16 {
                    let (term, index) = wire::decode_term_index(&s.msg_buf);
                    persist_manifest(s, sys, term, index);
                    s.last_snapshot_term = term;
                    s.last_snapshot_index = index;
                    emit_install_chunk(s, sys, term, index);
                    s.snapshots_taken += 1;
                }
            }
        }

        // 2b. On-demand install requests from replicator (§4.2). When a
        //     follower's next_index falls below our WAL retention floor,
        //     the replicator hits a NOT_FOUND WAL reply and asks us to
        //     re-broadcast the most recent snapshot.
        if s.in_install_request >= 0 && s.last_snapshot_index > 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_install_request, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_install_request, &mut s.msg_buf);
                if msg_type != wire::MSG_SNAPSHOT_INSTALL_REQUEST || (plen as usize) < 1 {
                    continue;
                }
                // We currently broadcast the install; targeted routing
                // is in flight — `peer_router` already accepts routed
                // envelopes via `replicator.forward_snapshots`. The
                // target byte in the request is preserved for the day
                // we switch to a routed snapshot port.
                emit_install_chunk(s, sys, s.last_snapshot_term, s.last_snapshot_index);
            }
        }

        // 3. Drain incoming chunks (InstallSnapshot RPC from leader).
        if s.in_import >= 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_import, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_import, &mut s.msg_buf);
                if plen == 0 { continue; }
                let pl = plen as usize;
                match msg_type {
                    wire::MSG_INSTALL_SNAPSHOT => {
                        ingest_install_chunk(s, sys, pl);
                    }
                    wire::MSG_SNAPSHOT_CHUNK => {
                        // Legacy untyped chunk — count for backward
                        // compatibility with older test fixtures, no
                        // install side effect.
                        s.chunks_imported += 1;
                    }
                    _ => {}
                }
            }
        }

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn ingest_install_chunk(s: &mut ModuleState, sys: &SyscallTable, plen: usize) {
    let (term, last_idx, last_term, offset, done, hdr_len) =
        match wire::decode_install_snapshot(&s.msg_buf[..plen]) {
            Some(t) => t,
            None => return,
        };
    let body_len = plen.saturating_sub(hdr_len);

    // Reset on first chunk (offset == 0) or when (term, last_idx) change
    // versus the install we were accumulating.
    let restart = offset == 0
        || !s.in_progress_active
        || s.in_progress_term != term
        || s.in_progress_last_idx != last_idx;
    if restart {
        s.in_progress_term = term;
        s.in_progress_last_idx = last_idx;
        s.in_progress_last_term = last_term;
        s.in_progress_offset = 0;
        s.body_len = 0;
        s.in_progress_active = true;
        // Persist the manifest on first chunk so a crash mid-install
        // still leaves a record of (term, index). Body finalisation
        // happens on `done`.
        persist_manifest(s, sys, term, last_idx);
    }

    // Offset gating: drop misordered chunks. The leader is expected to
    // re-send from offset 0 if it sees us stalled.
    if offset != s.in_progress_offset {
        dev_log(sys, 3, b"[snap] off skew".as_ptr(), 15);
        return;
    }

    // Buffer cap guard.
    let dst_off = s.body_len as usize;
    if dst_off + body_len > MAX_SNAPSHOT_BODY {
        dev_log(sys, 3, b"[snap] body cap".as_ptr(), 15);
        s.in_progress_active = false;
        return;
    }
    if body_len > 0 {
        s.body_buf[dst_off..dst_off + body_len]
            .copy_from_slice(&s.msg_buf[hdr_len..hdr_len + body_len]);
        s.body_len += body_len as u32;
    }
    s.in_progress_offset = offset + body_len as u64;
    s.chunks_imported += 1;

    if done {
        // Finalise: in a full implementation we'd write
        // body_buf[..body_len] to a temp file alongside the manifest
        // and atomically rename. Until §2.1 lands and the state
        // machine actually consumes a body, we just record the size.
        if s.out_installed >= 0 {
            let poll = (sys.channel_poll)(s.out_installed, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
                wire::encode_snapshot_installed(
                    &mut buf,
                    s.in_progress_term,
                    s.in_progress_last_idx,
                    s.in_progress_last_term,
                );
                wire_channels::channel_write_msg(
                    sys,
                    s.out_installed,
                    wire::MSG_SNAPSHOT_INSTALLED,
                    &buf,
                );
                dev_log(sys, 3, b"[snap] installed".as_ptr(), 16);
            }
        }
        s.in_progress_active = false;
        s.body_len = 0;
        s.in_progress_offset = 0;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Emit an InstallSnapshot RPC out to replicator/peers as one or more
/// chunks of up to `MAX_CHUNK_BODY` bytes. The "body" today is empty
/// because the substrate has no state-machine snapshot — peers learn
/// the `(term, index)` and trust their own log/WAL for everything
/// else. Once §2.1 (app snapshot API) lands, `emit_install_body` will
/// pull from the actual state-machine snapshot and this code path is
/// already multi-chunk capable. See RFC §4.1.
unsafe fn emit_install_chunk(s: &mut ModuleState, sys: &SyscallTable, term: Term, index: Index) {
    emit_install_body(s, sys, term, index, &[]);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_install_body(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    index: Index,
    body: &[u8],
) {
    if s.out_export < 0 { return; }
    let total = body.len();
    if total == 0 {
        // Manifest-only install: still send one chunk so the follower
        // can update its (term, index) bookkeeping.
        let poll = (sys.channel_poll)(s.out_export, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
        let mut buf = [0u8; wire::INSTALL_SNAPSHOT_HDR];
        let n = wire::encode_install_snapshot(&mut buf, term, index, term, 0, true, &[]);
        if n > 0 {
            wire_channels::channel_write_msg(sys, s.out_export, wire::MSG_INSTALL_SNAPSHOT, &buf[..n]);
        }
        return;
    }

    let mut offset: u64 = 0;
    let mut remaining = total;
    while remaining > 0 {
        let chunk = remaining.min(MAX_CHUNK_BODY);
        let start = total - remaining;
        let done = chunk == remaining;
        let poll = (sys.channel_poll)(s.out_export, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            // Channel saturated. We bail — the trigger path will retry
            // on the next segment rollover or explicit ADMIN_OP_SNAPSHOT.
            return;
        }
        let mut buf = [0u8; wire::INSTALL_SNAPSHOT_HDR + MAX_CHUNK_BODY];
        let n = wire::encode_install_snapshot(
            &mut buf,
            term,
            index,
            term,
            offset,
            done,
            &body[start..start + chunk],
        );
        if n == 0 { return; }
        wire_channels::channel_write_msg(sys, s.out_export, wire::MSG_INSTALL_SNAPSHOT, &buf[..n]);
        offset += chunk as u64;
        remaining -= chunk;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Build snapshot path:
///   partition_id == 0  →  `wal/snap_<NNNNNNNN>.bin`
///   partition_id == N  →  `wal/p<NNNN>/snap_<NNNNNNNN>.bin`
unsafe fn build_snapshot_path(s: &mut ModuleState, index: Index) -> usize {
    let mut i = 0usize;
    for &b in b"wal/" {
        if i < SNAP_PATH_MAX { s.path_buf[i] = b; i += 1; }
    }
    if s.partition_id != 0 {
        if i < SNAP_PATH_MAX { s.path_buf[i] = b'p'; i += 1; }
        for digit in (0..4).rev() {
            let nibble = ((s.partition_id >> (digit * 4)) & 0xF) as u8;
            let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            if i < SNAP_PATH_MAX { s.path_buf[i] = ch; i += 1; }
        }
        if i < SNAP_PATH_MAX { s.path_buf[i] = b'/'; i += 1; }
    }
    for &b in b"snap_" {
        if i < SNAP_PATH_MAX { s.path_buf[i] = b; i += 1; }
    }
    // 8-hex-digit suffix from the low 32 bits of index (matches
    // wal/seg_<NNNNNNNN> width; sufficient for the foreseeable index
    // range, and ops can join the high bits from the manifest body).
    let low = index as u32;
    for digit in (0..8).rev() {
        let nibble = ((low >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        if i < SNAP_PATH_MAX { s.path_buf[i] = ch; i += 1; }
    }
    for &b in b".bin" {
        if i < SNAP_PATH_MAX { s.path_buf[i] = b; i += 1; }
    }
    i
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Write a 32-byte snapshot manifest to disk and fsync.
unsafe fn persist_manifest(s: &mut ModuleState, sys: &SyscallTable, term: Term, index: Index) {
    let plen = build_snapshot_path(s, index);
    if plen == 0 { return; }

    let fd = (sys.provider_call)(-1, FS_OPEN, s.path_buf.as_mut_ptr(), plen);
    if fd < 0 {
        // FS unavailable (e.g. unwired contract on a drone). Log so
        // we know the trigger fired but no disk artefact will appear.
        dev_log(sys, 3, b"[snap] no fs".as_ptr(), 12);
        return;
    }

    let mut manifest = [0u8; MANIFEST_LEN];
    manifest[0..4].copy_from_slice(&MAGIC_SNAP.to_le_bytes());
    manifest[4..6].copy_from_slice(&s.partition_id.to_le_bytes());
    // bytes 6..8 reserved
    manifest[8..16].copy_from_slice(&term.to_le_bytes());
    manifest[16..24].copy_from_slice(&index.to_le_bytes());
    manifest[24..28].copy_from_slice(&s.dek_epoch.to_le_bytes());
    // bytes 28..32 reserved

    (sys.provider_call)(fd, FS_WRITE, manifest.as_mut_ptr(), MANIFEST_LEN);
    (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);

    dev_log(sys, 3, b"[snap] manifest".as_ptr(), 15);
}
