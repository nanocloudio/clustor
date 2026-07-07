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

#[path = "../../common/collections.rs"]
mod collections;

use collections::Crc32c;
use types::*;

const FS_OPEN: u32 = 0x0900;
const FS_WRITE: u32 = 0x0906;
const FS_FSYNC: u32 = 0x0905;
const FS_CLOSE: u32 = 0x0903;
/// Write-side opener. `FS_OPEN` is read-only-if-exists per the FS
/// contract (see `target/fluxor/fluxor-abi/sdk/contracts/storage/fs.rs`);
/// snapshot manifests are created from scratch, so persistence needs
/// the write tier.
const FS_OPEN_CREATE: u32 = 0x0909;
/// Remove a file by path (`modules/sdk/contracts/storage/fs.rs::UNLINK`).
/// Used to retire the previous snapshot file once a newer one is durable;
/// gated on the provider's `caps::UNLINK` bit (see `fs_unlink_supported`).
const FS_UNLINK: u32 = 0x090A;
/// FS capability-discovery opcode + the `UNLINK` bit
/// (`modules/sdk/contracts/storage/fs.rs::{CAPS, caps::UNLINK}`).
const FS_CAPS: u32 = 0x09FF;
const FS_CAP_UNLINK: u32 = 1 << 5;
/// FS E_AGAIN: the provider exists but is still initialising (fat32
/// reading the BPB/GPT/root on a cold boot). Distinct from ENODEV/ENOSYS
/// ("no provider"): an E_AGAIN persist failure must NOT be treated as the
/// in-memory-graph case, or we'd signal an install (and let raft compact
/// the WAL) against a manifest that never landed.
const FS_E_AGAIN: i32 = -11;

/// `module_step` return code for `StepOutcome::Burst` (kernel ABI:
/// 0=Continue, 1=Done, 2=Burst, 3=Ready). Returned from a step that
/// performed a synchronous disk op (manifest persist / chunk ingest):
/// on this NVMe a cold first-touch FS_OPEN_CREATE/write runs tens to
/// >100 ms, which would trip the step guard. Burst makes the scheduler
/// forgive that one-time overrun (the Burst transition disarms the
/// normal-deadline arm without checking it, then re-arms with the 8x
/// burst budget) — the same mechanism the WAL replay path uses for its
/// cold root-dir scan. Bounded work (≤4 triggers/step), so this is a
/// headroom grant, not unbounded I/O.
const STEP_BURST: i32 = 2;

const SNAP_PATH_MAX: usize = 64;
const MANIFEST_LEN: usize = 32;
const MAGIC_SNAP: u32 = 0x534E_4150; // "SNAP" little-endian as bytes

/// Durable snapshot file layout (crash-atomic without an FS rename, which the
/// FS contract does not expose):
///   `[MAGIC_SNAP:u32][partition:u16][rsvd:u16][term:u64][last_idx:u64]`
///   `[last_term:u64][dek_epoch:u32][body_len:u32]` = `SNAP_HDR_LEN` bytes,
///   then `body[body_len]`, then `[body_crc32c:u32][END_MAGIC:u32]`.
/// Written sequentially in one pass with a SINGLE trailing fsync, so a torn
/// or interrupted write never leaves a readable trailer — `load_snapshot`
/// rejects any file whose `END_MAGIC` or CRC doesn't check out and the node
/// falls back to its log. Snapshot filenames are index-keyed and indices are
/// monotonic, so a fresh install never overwrites a shorter valid file.
const SNAP_HDR_LEN: usize = 40;
const SNAP_TRAILER_LEN: usize = 8;
const END_MAGIC_SNAP: u32 = 0x534E_4445; // "ENDS"

/// Max snapshot body bytes we'll buffer in module memory before
/// finalising. Once the state-machine snapshot API (§2.1) lands, the
/// reference path here moves to a temp file on disk; this cap acts as
/// a safety valve so a misbehaving leader can't OOM us.
const MAX_SNAPSHOT_BODY: usize = 16 * 1024;

/// Largest chunk we emit on the wire. Bounded so a single envelope
/// fits inside MAX_PAYLOAD (64 KiB - 1) with room for the
/// `MSG_INSTALL_SNAPSHOT` 33-byte header.
const MAX_CHUNK_BODY: usize = 4 * 1024;

/// How many steps we'll wait for an app snapshot body before giving up
/// on the capture. At the rig's 1 ms tick this is ~2 s — long enough
/// for a worker busy draining a commit batch, short enough that a
/// wedged app only costs one rotation's snapshot.
const APP_CAPTURE_TIMEOUT_TICKS: u32 = 2000;

define_params! {
    ModuleState;

    1, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };

    // 1 = write snapshot files into the FS ROOT with an 8.3-conforming
    // name (`<p:1hex><idx:7hex>.SNP`) instead of `wal/p<NNNN>_snap_
    // <NNNNNNNN>.bin`. Required on bare-metal FAT32, which has no mkdir
    // (so no `wal/` parent) and rejects names longer than 8.3. Mirrors
    // the wal module's param of the same name — set BOTH or NEITHER so
    // segments and snapshots land in the same place.
    2, root_path, u8, 0
        => |s, d, len| { s.root_path = p_u8(d, len, 0, 0); };
}

/// Per-kpg retention-floor table capacity. Downstream consumers
/// (lattice's `compaction_coordinator` and the substrate-side
/// surfaces it aggregates) emit one `MSG_COMPACTION_FLOOR` per
/// active kpg they care about. 32 slots covers any realistic
/// per-partition kpg count; on overflow the engine fails closed
/// (see `retention_floor_overflow`) — eviction would silently
/// widen the compaction window past a floor we used to honour, and
/// fail-open would do the same for the unrecorded floor. Adjust
/// upwards if the lattice / quantum integration later proves it's
/// not enough.
const RETENTION_FLOOR_SLOTS: usize = 32;
const METRICS_INTERVAL_MS: u64 = 1000;

/// Empty-slot sentinel for the retention-floor table. `0xFFFF` is
/// wire-reserved as "never a real kpg id" so this value can mark
/// vacant slots without colliding with `kpg_id = 0`, which is the
/// well-known single-kpg / default placement-router id and the most
/// common `MSG_COMPACTION_FLOOR` key in practice.
const FLOOR_SLOT_EMPTY: u16 = u16::MAX;

#[derive(Clone, Copy)]
#[repr(C)]
struct RetentionFloorSlot {
    kpg_id: u16,
    floor_revision: u64,
}

impl RetentionFloorSlot {
    const fn empty() -> Self {
        Self {
            kpg_id: FLOOR_SLOT_EMPTY,
            floor_revision: 0,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_import: i32,             // in[0]: import chunks from replicator (InstallSnapshot RPC)
    in_trigger: i32,            // in[1]: SnapshotTrigger from wal
    in_key_update: i32,         // in[2]: DekEpoch from key_manager
    in_install_request: i32,    // in[3]: MSG_SNAPSHOT_INSTALL_REQUEST from replicator (§4.2)
    in_retention_floor: i32,    // in[4]: MSG_COMPACTION_FLOOR from compaction_coordinator
    out_export: i32,            // out[0]: export chunks to replicator (peer transfer)
    out_manifest: i32,          // out[1]: manifest auth to peer_router (deferred)
    out_metrics: i32,           // out[2]: metrics to telemetry_agg
    out_installed: i32,         // out[3]: MSG_SNAPSHOT_INSTALLED to raft_engine

    // Most recent snapshot (term, index) we persisted. Used to answer
    // on-demand install requests from `replicator` (§4.2).
    last_snapshot_term: u64,
    last_snapshot_index: u64,

    partition_id: u16,
    /// Param `root_path`: 1 = 8.3 snapshot names at the FS root (bare-metal
    /// FAT32); 0 = `wal/p<NNNN>_snap_<NNNNNNNN>.bin` (linux layout).
    root_path: u8,
    /// FS `caps::UNLINK` probe cache for previous-snapshot retirement:
    /// 0 = unprobed, 1 = supported, 2 = unsupported. See
    /// `fs_unlink_supported`.
    fs_unlink_probe: u8,

    // State
    dek_epoch: u32,
    snapshots_taken: u32,
    chunks_imported: u32,
    /// Snapshot triggers we declined because their `last_included_index`
    /// would have advanced compaction past the lowest active retention
    /// floor. Counted so operators can spot a stuck floor; the
    /// trigger itself is dropped (the leader's next rotation will
    /// re-fire it). Bumping a floor downwards is the application's
    /// job, not the snapshot engine's.
    triggers_deferred: u32,
    /// Total snapshot body bytes durably written to disk (across installs).
    snap_bytes_written: u64,
    /// Count of durable-install failures (OPEN_CREATE failed, short write, or
    /// fsync error). Non-zero means a received snapshot was NOT installed —
    /// the install signal is withheld so consensus never trusts a torn body.
    install_failures: u32,

    /// Per-kpg retention floors received from
    /// `compaction_coordinator`. Reads and writes are linear scans
    /// (no hashing) — `RETENTION_FLOOR_SLOTS` is small enough that
    /// the scan fits comfortably in one tick budget.
    retention_floors: [RetentionFloorSlot; RETENTION_FLOOR_SLOTS],
    /// Sticky bit set when a `MSG_COMPACTION_FLOOR` arrived for a
    /// kpg the table couldn't accommodate. The trigger gate fails
    /// closed (refuses to advance compaction) while this is set,
    /// because we no longer have a complete picture of which
    /// indices are still replay-needed. Recovery requires an
    /// operator restart with a larger `RETENTION_FLOOR_SLOTS`;
    /// there is no automatic clear path.
    retention_floor_overflow: bool,

    // Metrics
    last_metrics_ms: u64,
    /// Monotonic ms when the current install's first chunk arrived;
    /// used to time `clustor.snapshot.transfer_seconds`.
    install_start_ms: u64,
    /// `clustor.snapshot.transfer_seconds` cumulative bucket counts
    /// (RFC §4.1): wall time from first install chunk to `done`,
    /// ms-classified against `wire::hist::SNAPSHOT_MS`.
    transfer_buckets: [u32; wire::hist::SNAPSHOT_MS.len() + 1],

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

    // ── App state-machine snapshot round-trip (RFC §2.1) ──────────
    /// Port to the application state machine (request + restore) and
    /// the port its encoded body comes back on. Both -1 when the graph
    /// has no app snapshot provider, in which case snapshots stay
    /// manifest-only and this whole path is inert.
    out_app_ctl: i32,
    in_app_body: i32,
    /// A capture has been requested and we're waiting for the body.
    /// Triggers arriving meanwhile are dropped (the next rotation
    /// re-fires), so this never queues.
    app_capture_pending: bool,
    /// Ticks since the request went out — bounds the wait so a wedged
    /// or silent app can't block snapshotting forever.
    app_capture_ticks: u32,
    app_bodies_received: u32,
    app_captures_timed_out: u32,
    /// Body staged for the next install emit. Owned by state (not a
    /// borrow of msg_buf) so `finalize_snapshot` can take `&mut s`.
    app_body_buf: [u8; MAX_SNAPSHOT_BODY],
    app_body_len: u32,

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
        s.in_retention_floor = dev_channel_port(sys, 0, 4);
        s.out_manifest = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.out_installed = dev_channel_port(sys, 1, 3);
        s.in_app_body = dev_channel_port(sys, 0, 5);
        s.out_app_ctl = dev_channel_port(sys, 1, 4);
        s.app_capture_pending = false;
        s.app_capture_ticks = 0;
        s.app_body_len = 0;

        s.retention_floors = [RetentionFloorSlot::empty(); RETENTION_FLOOR_SLOTS];
        s.retention_floor_overflow = false;
        s.triggers_deferred = 0;
        s.transfer_buckets = [0u32; wire::hist::SNAPSHOT_MS.len() + 1];

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
        // Set when this step performed a synchronous disk op whose cold
        // first-touch can exceed the step deadline; we return Burst so the
        // scheduler forgives that one-time overrun (see STEP_BURST).
        let mut cold_fs = false;

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

        // 1b. Drain retention-floor updates from compaction_coordinator
        //     so the floor check below uses the freshest values when a
        //     trigger arrives in the same tick. The floor envelope is
        //     idempotent (same kpg_id, possibly-advanced floor_revision),
        //     so processing it before the trigger keeps the gate
        //     conservative: a floor declared in tick N applies to a
        //     trigger seen in tick N or later.
        drain_retention_floors(s, sys);

        // 2. Snapshot triggers from wal.
        if s.in_trigger >= 0 {
            for _ in 0..4 {
                let poll = (sys.channel_poll)(s.in_trigger, 0x01);
                if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }
                let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_trigger, &mut s.msg_buf);
                if msg_type == wire::MSG_SNAPSHOT_TRIGGER && plen >= 16 {
                    let (term, index) = wire::decode_term_index(&s.msg_buf);
                    // Retention floor gate: a snapshot at `index`
                    // implies compaction will trim entries < index.
                    // Any kpg whose floor_revision is below `index`
                    // still needs those entries for a replay-after-
                    // rebind, so we must NOT proceed. The trigger is
                    // dropped (logged); the leader's next rotation
                    // will re-fire it once the floor has caught up
                    // (typically when the lagging watcher rebinds or
                    // moves on).
                    if !retention_floor_allows(s, index) {
                        s.triggers_deferred = s.triggers_deferred.saturating_add(1);
                        dev_log(sys, 3, b"[snap] floor block".as_ptr(), 18);
                        continue;
                    }
                    // With an app state machine wired, the snapshot is
                    // only meaningful once we hold its state. Ask for a
                    // capture and stop here; the body's own (term,
                    // index) — which may have advanced past this
                    // trigger — drives finalisation in section 2c.
                    if s.out_app_ctl >= 0 {
                        if s.app_capture_pending {
                            // One capture in flight at a time; the next
                            // rotation re-fires this trigger.
                            s.triggers_deferred = s.triggers_deferred.saturating_add(1);
                            continue;
                        }
                        if request_app_capture(s, sys, term, index) {
                            s.app_capture_pending = true;
                            s.app_capture_ticks = 0;
                        }
                        continue;
                    }
                    cold_fs = true; // manifest persist did a (possibly cold) FS write
                    // No app provider on this graph — manifest-only
                    // snapshot, exactly as before.
                    s.app_body_len = 0;
                    finalize_local_snapshot(s, sys, term, index);
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

        // 2c. App state-machine snapshot bodies (RFC §2.1). The body's
        //     own (term, index) is authoritative — the app may have
        //     applied past the trigger that prompted the capture.
        if s.in_app_body >= 0 && s.app_capture_pending {
            let poll = (sys.channel_poll)(s.in_app_body, 0x01);
            if poll > 0 && (poll as u32 & 0x01) != 0 {
                let (msg_type, plen) =
                    wire_channels::channel_read_msg(sys, s.in_app_body, &mut s.msg_buf);
                let pl = plen as usize;
                if msg_type == wire::MSG_APP_SNAPSHOT_CHUNK && pl >= wire::APP_SNAPSHOT_HDR {
                    let (term, index) = wire::decode_term_index(&s.msg_buf);
                    let offset = u64::from_le_bytes([
                        s.msg_buf[16], s.msg_buf[17], s.msg_buf[18], s.msg_buf[19],
                        s.msg_buf[20], s.msg_buf[21], s.msg_buf[22], s.msg_buf[23],
                    ]) as usize;
                    let done = s.msg_buf[24] != 0;
                    let body_len = pl - wire::APP_SNAPSHOT_HDR;
                    // Strict in-order accumulation; a gap or an
                    // oversized body aborts the capture and the next
                    // rotation re-requests.
                    if offset != s.app_body_len as usize
                        || offset + body_len > MAX_SNAPSHOT_BODY
                    {
                        s.app_body_len = 0;
                        s.app_capture_pending = false;
                        s.app_capture_ticks = 0;
                        s.triggers_deferred = s.triggers_deferred.saturating_add(1);
                    } else {
                        s.app_body_buf[offset..offset + body_len]
                            .copy_from_slice(&s.msg_buf[wire::APP_SNAPSHOT_HDR..pl]);
                        s.app_body_len = (offset + body_len) as u32;
                        if done {
                            s.app_bodies_received = s.app_bodies_received.saturating_add(1);
                            s.app_capture_pending = false;
                            s.app_capture_ticks = 0;
                            if retention_floor_allows(s, index) {
                                cold_fs = true; // finalise persists the manifest
                                finalize_local_snapshot(s, sys, term, index);
                            } else {
                                s.triggers_deferred =
                                    s.triggers_deferred.saturating_add(1);
                            }
                            s.app_body_len = 0;
                        }
                    }
                }
            } else {
                // Bound the wait: a silent app (encode failed, or the
                // state outgrew its export budget) must not wedge
                // snapshotting for good.
                s.app_capture_ticks = s.app_capture_ticks.saturating_add(1);
                if s.app_capture_ticks > APP_CAPTURE_TIMEOUT_TICKS {
                    s.app_capture_pending = false;
                    s.app_capture_ticks = 0;
                    s.app_captures_timed_out = s.app_captures_timed_out.saturating_add(1);
                    dev_log(sys, 3, b"[snap] app timeout".as_ptr(), 18);
                }
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
                        cold_fs = true; // chunk ingest persists to disk
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

        // 4. Periodic metrics (RFC §4.1/§4.3).
        emit_metrics(s, sys);

        // Burst (forgive the cold-disk overrun) on a step that persisted a
        // manifest or ingested an install chunk; otherwise Continue.
        if cold_fs { STEP_BURST } else { 0 }
    }
}

/// Emit snapshot counters and the transfer-time histogram as typed
/// samples (RFC §4.3). Partition-stamped. Dropped under backpressure.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mid = wire::MODULE_ID_SNAPSHOT_ENGINE;
    let pid = s.partition_id;
    let kc = wire::METRIC_KIND_COUNTER;
    let scalars: [(u16, i64); 5] = [
        (wire::metric_ids::SNAP_SNAPSHOTS_TAKEN, i64::from(s.snapshots_taken)),
        (wire::metric_ids::SNAP_CHUNKS_IMPORTED, i64::from(s.chunks_imported)),
        (wire::metric_ids::SNAP_TRIGGERS_DEFERRED, i64::from(s.triggers_deferred)),
        (wire::metric_ids::SNAP_BYTES_WRITTEN, s.snap_bytes_written as i64),
        (wire::metric_ids::SNAP_INSTALL_FAILURES, i64::from(s.install_failures)),
    ];
    for &(metric_id, value) in scalars.iter() {
        emit_sample(s, sys, mid, pid, metric_id, kc, value);
    }
    // Cumulative bucket counts per the wire contract (wire::hist): emit the
    // running prefix sum so bucket i = count of samples <= bound[i].
    let base = wire::hist::HIST_BASE;
    let mut cum: i64 = 0;
    for i in 0..s.transfer_buckets.len() {
        cum += i64::from(s.transfer_buckets[i]);
        emit_sample(s, sys, mid, pid, base + i as u16, wire::METRIC_KIND_HISTOGRAM, cum);
    }
}

/// Emit one typed metric sample if `out_metrics` has write space.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_sample(
    s: &ModuleState,
    sys: &SyscallTable,
    module_id: u8,
    partition_id: u16,
    metric_id: u16,
    kind: u8,
    value: i64,
) {
    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
    wire::encode_metric_sample(&mut buf, module_id, partition_id, metric_id, kind, value);
    wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
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
        s.install_start_ms = dev_millis(sys);
        // Persist the manifest on first chunk so a crash mid-install
        // still leaves a record of (term, index). Body finalisation
        // happens on `done` — the durable-install gate lives there, so
        // this early record's outcome is advisory only.
        let _ = persist_manifest(s, sys, term, last_idx);
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
        // Finalise: durably write the accumulated body to disk
        // (crash-atomically — see write_snapshot_durable) BEFORE telling
        // raft the snapshot is installed. The install signal is what lets a
        // follower advance its state to last_idx and compact its log, so it
        // must not be emitted until the body survives a crash. A torn/failed
        // write withholds the signal; the leader re-sends from offset 0.
        let (durable, had_fs) =
            write_snapshot_durable(s, sys, s.in_progress_term, s.in_progress_last_idx, s.in_progress_last_term);

        // `had_fs == false` means no FS provider (in-memory graph): there is
        // no durable artefact possible, but the (term,index) is still a valid
        // install for an in-memory cluster — preserve the prior behaviour.
        // With an FS present, only signal on a confirmed durable write.
        // Hand the state-machine body to the app BEFORE signalling the
        // install. The install signal is what lets raft compact its log
        // to last_idx; if the app never received the state it could
        // then never catch up. A refused hand-off (channel full)
        // withholds the signal and the leader re-sends from offset 0.
        let mut app_restored = true;
        if s.out_app_ctl >= 0 && s.body_len > 0 {
            app_restored = emit_app_restore(
                s,
                sys,
                s.in_progress_term,
                s.in_progress_last_idx,
            );
        }

        if app_restored && (durable || !had_fs) && s.out_installed >= 0 {
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
                let prev_index = s.last_snapshot_index;
                s.last_snapshot_term = s.in_progress_term;
                s.last_snapshot_index = s.in_progress_last_idx;
                dev_log(sys, 3, b"[snap] installed".as_ptr(), 16);
                // Exactly-one-snapshot steady state (mirrors the local
                // trigger path): retire the superseded snapshot file only
                // when this install confirmed durable on a real FS.
                if durable {
                    unlink_prev_snapshot(s, sys, prev_index, s.last_snapshot_index);
                }
            }
        }
        // Fold the install duration into the transfer histogram (§4.1).
        let elapsed_ms = dev_millis(sys).wrapping_sub(s.install_start_ms);
        let b = wire::hist::bucket(&wire::hist::SNAPSHOT_MS, elapsed_ms);
        s.transfer_buckets[b] = s.transfer_buckets[b].saturating_add(1);
        s.in_progress_active = false;
        s.body_len = 0;
        s.in_progress_offset = 0;
    }
}


/// Finalise a locally-taken snapshot at `(term, index)`, shipping
/// whatever body is staged in `s.app_body_buf[..s.app_body_len]`
/// (empty = manifest-only).
///
/// Shared by the trigger path (no app provider — empty body) and the
/// app-body path (§2.1 capture round-trip), so both orders of
/// operations stay identical: persist, signal raft, retire the
/// superseded manifest, then ship to peers.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn finalize_local_snapshot(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    index: Index,
) {
    let prev_index = s.last_snapshot_index;
    let (durable, had_fs) = persist_manifest(s, sys, term, index);
    if !durable && had_fs {
        // FS present but the manifest didn't land (provider
        // initialising, ENOSPC, short write…). Drop it — the next
        // rotation re-fires. Signalling an install here would let raft
        // compact WAL segments against a snapshot that isn't on disk.
        return;
    }
    s.last_snapshot_term = term;
    s.last_snapshot_index = index;
    // Tell raft the local snapshot is durable so it advances the WAL
    // compaction floor (the leader-local leg of
    // `drain_snapshot_installed` — without this signal a leader never
    // retires segments). Same durable-or-no-FS gate as the import
    // path; skipped when the port is unwired or briefly full (the next
    // trigger re-signals).
    if s.out_installed >= 0 {
        let poll = (sys.channel_poll)(s.out_installed, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            let mut buf = [0u8; wire::SNAPSHOT_INSTALLED_LEN];
            wire::encode_snapshot_installed(&mut buf, term, index, term);
            wire_channels::channel_write_msg(
                sys,
                s.out_installed,
                wire::MSG_SNAPSHOT_INSTALLED,
                &buf,
            );
        }
    }
    // Exactly-one-snapshot steady state: retire the previous manifest
    // only after the new one is durable.
    if durable {
        unlink_prev_snapshot(s, sys, prev_index, index);
    }
    emit_install_staged(s, sys, term, index);
    s.snapshots_taken += 1;
}

/// Ask the app state machine to capture its state now. `(term, index)`
/// is a hint about the position we'd like; the app answers with its
/// own applied position, which is authoritative.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn request_app_capture(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    index: Index,
) -> bool {
    if s.out_app_ctl < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(s.out_app_ctl, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&term.to_le_bytes());
    buf[8..].copy_from_slice(&index.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_REQUEST, &buf);
    true
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


/// Deliver an installed snapshot to the app state machine: a
/// `MSG_APP_SNAPSHOT_RESET` (discard current state) followed by the
/// body as a `MSG_APP_SNAPSHOT_CHUNK` stream (RFC §2.1).
///
/// Returns false if the hand-off could not be completed, in which case
/// the caller MUST withhold the install signal — otherwise raft would
/// compact past state the app never received.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn emit_app_restore(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    index: Index,
) -> bool {
    if s.out_app_ctl < 0 {
        return false;
    }
    let total = s.body_len as usize;
    // RESET first: the app discards state up front, so a stream that
    // dies mid-way leaves it empty (catch-up from leader) rather than
    // half-old/half-new.
    let poll = (sys.channel_poll)(s.out_app_ctl, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    let mut hdr = [0u8; 16];
    hdr[..8].copy_from_slice(&term.to_le_bytes());
    hdr[8..].copy_from_slice(&index.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_app_ctl, wire::MSG_APP_SNAPSHOT_RESET, &hdr);

    let mut sent = 0usize;
    loop {
        let chunk = (total - sent).min(MAX_CHUNK_BODY);
        let done = sent + chunk == total;
        let poll = (sys.channel_poll)(s.out_app_ctl, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            return false;
        }
        let mut buf = [0u8; wire::APP_SNAPSHOT_HDR + MAX_CHUNK_BODY];
        buf[..8].copy_from_slice(&term.to_le_bytes());
        buf[8..16].copy_from_slice(&index.to_le_bytes());
        buf[16..24].copy_from_slice(&(sent as u64).to_le_bytes());
        buf[24] = u8::from(done);
        buf[wire::APP_SNAPSHOT_HDR..wire::APP_SNAPSHOT_HDR + chunk]
            .copy_from_slice(&s.body_buf[sent..sent + chunk]);
        wire_channels::channel_write_msg(
            sys,
            s.out_app_ctl,
            wire::MSG_APP_SNAPSHOT_CHUNK,
            &buf[..wire::APP_SNAPSHOT_HDR + chunk],
        );
        sent += chunk;
        if done {
            return true;
        }
    }
}

/// Emit an InstallSnapshot RPC carrying the body staged in
/// `s.app_body_buf[..s.app_body_len]`, chunked to `MAX_CHUNK_BODY`.
///
/// Separate from `emit_install_body` because the body lives in state:
/// passing it as a slice would alias the `&mut ModuleState` the
/// chunking loop needs.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines.
unsafe fn emit_install_staged(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    index: Index,
) {
    let total = s.app_body_len as usize;
    if total == 0 {
        emit_install_body(s, sys, term, index, &[]);
        return;
    }
    if s.out_export < 0 {
        return;
    }
    let mut offset: u64 = 0;
    let mut sent = 0usize;
    while sent < total {
        let chunk = (total - sent).min(MAX_CHUNK_BODY);
        let done = sent + chunk == total;
        let poll = (sys.channel_poll)(s.out_export, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            // Channel saturated — the trigger path retries on the next
            // rotation or an explicit ADMIN_OP_SNAPSHOT.
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
            &s.app_body_buf[sent..sent + chunk],
        );
        if n == 0 {
            return;
        }
        wire_channels::channel_write_msg(sys, s.out_export, wire::MSG_INSTALL_SNAPSHOT, &buf[..n]);
        offset += chunk as u64;
        sent += chunk;
    }
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
/// Build snapshot path: `wal/p<NNNN>_snap_<NNNNNNNN>.bin`.
///
/// All partitions share the one `wal/` directory; the partition_id
/// is stamped into the filename rather than a per-partition
/// subdirectory. This mirrors `wal/p<NNNN>_seg_<NNNNNNNN>` (see
/// `modules/app/wal/mod.rs::encode_segment_path`) so the operator
/// only needs to ensure one `wal/` directory exists regardless of
/// partition count — the Linux FS provider's `OPEN_CREATE` opcode
/// creates files but does not auto-`mkdir` parents, so the flat
/// layout is what makes the persisted manifest actually appear on
/// disk in a default deployment. See
/// `modules/app/snapshot_engine/manifest.toml` for the operator
/// note.
unsafe fn build_snapshot_path(s: &mut ModuleState, index: Index) -> usize {
    let mut i = 0usize;
    if s.root_path != 0 {
        // 8.3-conforming, root-relative: "<p:1hex><idx:7hex>.SNP" (≤12
        // chars). Bare-metal FAT32 has no mkdir (so no `wal/` parent) and
        // rejects names longer than 8.3. Mirrors the wal module's
        // `encode_segment_path` root layout ("<p:1hex><seq:7hex>.WAL") —
        // the distinct extension keeps segments and snapshots separable
        // in a flat root dir.
        let p = (s.partition_id & 0xF) as u8;
        s.path_buf[i] = if p < 10 { b'0' + p } else { b'a' + p - 10 };
        i += 1;
        let low = index as u32;
        for digit in (0..7).rev() {
            let nibble = ((low >> (digit * 4)) & 0xF) as u8;
            let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            s.path_buf[i] = ch;
            i += 1;
        }
        for &b in b".SNP" {
            s.path_buf[i] = b;
            i += 1;
        }
        return i;
    }
    for &b in b"wal/p" {
        if i < SNAP_PATH_MAX { s.path_buf[i] = b; i += 1; }
    }
    for digit in (0..4).rev() {
        let nibble = ((s.partition_id >> (digit * 4)) & 0xF) as u8;
        let ch = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        if i < SNAP_PATH_MAX { s.path_buf[i] = ch; i += 1; }
    }
    for &b in b"_snap_" {
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

/// Drain pending `MSG_COMPACTION_FLOOR` envelopes on the
/// retention-floor input and upsert each into the per-kpg floor
/// table. Bounded per-tick: at most four envelopes are absorbed so
/// the snapshot trigger path always gets a chance to run on the
/// same tick. Floor updates are idempotent (same `kpg_id`, possibly-
/// advanced `floor_revision`), so missing an update on tick N just
/// defers it to tick N+1.
///
/// Wire shape (10 bytes): `[kpg_id:u16 LE][floor_revision:u64 LE]`.
/// See `modules/common/wire.rs::MSG_COMPACTION_FLOOR` for the
/// byte-compatible declaration shared with lattice.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_retention_floors(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_retention_floor < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_retention_floor, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) =
            wire_channels::channel_read_msg(sys, s.in_retention_floor, &mut s.msg_buf);
        if msg_type != wire::MSG_COMPACTION_FLOOR || (plen as usize) < 10 {
            continue;
        }
        let kpg_id = u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]);
        // `0xFFFF` is the empty-slot sentinel; the wire reserves it
        // as "never a real kpg id" so a downstream that ever sent it
        // would be telling us about a nonexistent kpg. Drop loudly.
        if kpg_id == FLOOR_SLOT_EMPTY {
            dev_log(sys, 3, b"[snap] kpg sentinel".as_ptr(), 19);
            continue;
        }
        let floor_revision = u64::from_le_bytes([
            s.msg_buf[2], s.msg_buf[3], s.msg_buf[4], s.msg_buf[5],
            s.msg_buf[6], s.msg_buf[7], s.msg_buf[8], s.msg_buf[9],
        ]);
        upsert_retention_floor(s, sys, kpg_id, floor_revision);
    }
}

/// Insert or update the floor for `kpg_id`. Existing entry → update
/// in place. No entry → fill the first empty slot. Table full →
/// set the sticky overflow flag (the trigger gate fails closed
/// while it's set, blocking any further compaction advancement
/// until an operator restart with more slots) and log loudly so
/// the operator notices.
unsafe fn upsert_retention_floor(
    s: &mut ModuleState,
    sys: &SyscallTable,
    kpg_id: u16,
    floor_revision: u64,
) {
    // Existing entry: linear scan.
    for slot in &mut s.retention_floors {
        if slot.kpg_id == kpg_id {
            slot.floor_revision = floor_revision;
            return;
        }
    }
    // First empty slot.
    for slot in &mut s.retention_floors {
        if slot.kpg_id == FLOOR_SLOT_EMPTY {
            slot.kpg_id = kpg_id;
            slot.floor_revision = floor_revision;
            return;
        }
    }
    // Table full. The new kpg's floor has nowhere to land, so we
    // can no longer answer "is this index safe to compact past?"
    // honestly — that kpg might need indices we'd otherwise allow
    // to be trimmed. Fail closed: latch the overflow flag so
    // `retention_floor_allows` returns false until restart. Loud
    // log so the operator knows to bump `RETENTION_FLOOR_SLOTS`.
    s.retention_floor_overflow = true;
    dev_log(sys, 3, b"[snap] floor full".as_ptr(), 17);
}

/// Test whether a snapshot at `index` is permitted under the
/// current retention-floor set. Returns `false` whenever the floor
/// table has overflowed (we can't reason about an unrecorded floor,
/// so fail closed) or any populated slot's `floor_revision < index`
/// (advancing past that floor would lose replay-needed entries).
/// Returns `true` when the floor set is empty (no consumer has
/// asked for retention, so any snapshot index is fine).
///
/// Bounded scan; matches the upsert path's complexity. Safe to
/// call from the hot trigger path.
fn retention_floor_allows(s: &ModuleState, index: u64) -> bool {
    if s.retention_floor_overflow {
        return false;
    }
    for slot in &s.retention_floors {
        if slot.kpg_id == FLOOR_SLOT_EMPTY {
            continue;
        }
        if slot.floor_revision < index {
            return false;
        }
    }
    true
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Write a 32-byte snapshot manifest to disk and fsync.
///
/// Returns `(durable, had_fs)` — the same shape as
/// `write_snapshot_durable`: `durable` iff the manifest's write AND fsync
/// both succeeded; `had_fs = false` only when there is genuinely no FS
/// provider (in-memory graph), so the caller can distinguish "nothing to
/// persist" from "persist failed". A still-initialising provider
/// (`FS_E_AGAIN`) reports `(false, true)`: the FS exists, the persist
/// failed, and the caller must NOT signal an install against it.
unsafe fn persist_manifest(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    index: Index,
) -> (bool, bool) {
    let plen = build_snapshot_path(s, index);
    if plen == 0 { return (false, true); }

    // Snapshot manifests are always created fresh. `FS_OPEN` is
    // read-only-if-exists per the FS contract; opening at the
    // write tier (`FS_OPEN_CREATE`) is the only path that produces
    // a valid fd for a not-yet-existing manifest file.
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), plen);
    if fd < 0 {
        // FS contract unwired or the `wal/` parent directory
        // doesn't exist (`OPEN_CREATE` creates files but does not
        // `mkdir` parents). Log so the operator knows the trigger
        // fired but no disk artefact will appear.
        dev_log(sys, 3, b"[snap] no fs".as_ptr(), 12);
        return (false, fd == FS_E_AGAIN);
    }

    let mut manifest = [0u8; MANIFEST_LEN];
    manifest[0..4].copy_from_slice(&MAGIC_SNAP.to_le_bytes());
    manifest[4..6].copy_from_slice(&s.partition_id.to_le_bytes());
    // bytes 6..8 reserved
    manifest[8..16].copy_from_slice(&term.to_le_bytes());
    manifest[16..24].copy_from_slice(&index.to_le_bytes());
    manifest[24..28].copy_from_slice(&s.dek_epoch.to_le_bytes());
    // bytes 28..32 reserved

    let w = (sys.provider_call)(fd, FS_WRITE, manifest.as_mut_ptr(), MANIFEST_LEN);
    let f = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0);
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);
    let durable = w == MANIFEST_LEN as i32 && f == 0;
    if durable {
        dev_log(sys, 3, b"[snap] manifest".as_ptr(), 15);
    } else {
        s.install_failures = s.install_failures.saturating_add(1);
        dev_log(sys, 3, b"[snap] manifest fail".as_ptr(), 20);
    }
    (durable, true)
}

/// Lazily probe the FS provider's capability bitmap for `UNLINK` support
/// (same shape as `wal::fs_unlink_supported`). A failed CAPS call stays
/// unprobed and retries later rather than caching a transient error.
unsafe fn fs_unlink_supported(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    if s.fs_unlink_probe == 0 {
        let mut caps = [0u8; 4];
        let rc = (sys.provider_call)(-1, FS_CAPS, caps.as_mut_ptr(), 4);
        if rc == 4 {
            let bits = u32::from_le_bytes(caps);
            s.fs_unlink_probe = if bits & FS_CAP_UNLINK != 0 { 1 } else { 2 };
        }
    }
    s.fs_unlink_probe == 1
}

/// Retire the previous snapshot file after a NEWER one is durable, so the
/// disk holds exactly one snapshot artefact per partition in steady state
/// instead of accumulating one per WAL rotation. Best-effort: a missing
/// file (operator GC, skip_replay renumbering) or a provider without
/// `caps::UNLINK` leaves the old file orphaned — never an error, the new
/// snapshot's durability is already established by the caller.
unsafe fn unlink_prev_snapshot(
    s: &mut ModuleState,
    sys: &SyscallTable,
    prev_index: Index,
    new_index: Index,
) {
    if prev_index == 0 || prev_index == new_index { return; }
    if !fs_unlink_supported(s, sys) { return; }
    let plen = build_snapshot_path(s, prev_index);
    if plen == 0 { return; }
    if (sys.provider_call)(-1, FS_UNLINK, s.path_buf.as_mut_ptr(), plen) == 0 {
        dev_log(sys, 3, b"[snap] retired".as_ptr(), 14);
    }
}

/// Durably write the received snapshot body to disk, crash-atomically (see
/// `SNAP_HDR_LEN`). Returns true iff the whole file — header, body, and the
/// CRC+END_MAGIC trailer — landed and fsynced. On any short write or FS
/// failure the caller must withhold `MSG_SNAPSHOT_INSTALLED` so consensus
/// never advances onto a torn snapshot. A `false` return with `fd < 0` means
/// the FS is unwired (in-memory graph) — there's nothing to install durably,
/// which the caller treats as a soft skip, not a hard failure.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines per
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn write_snapshot_durable(
    s: &mut ModuleState,
    sys: &SyscallTable,
    term: Term,
    last_idx: Index,
    last_term: Term,
) -> (bool, bool) {
    let plen = build_snapshot_path(s, last_idx);
    if plen == 0 {
        return (false, false);
    }
    let fd = (sys.provider_call)(-1, FS_OPEN_CREATE, s.path_buf.as_mut_ptr(), plen);
    if fd < 0 {
        // FS unwired / parent dir missing — nothing to durably install.
        return (false, false);
    }
    let body_len = s.body_len as usize;
    let mut hdr = [0u8; SNAP_HDR_LEN];
    hdr[0..4].copy_from_slice(&MAGIC_SNAP.to_le_bytes());
    hdr[4..6].copy_from_slice(&s.partition_id.to_le_bytes());
    // 6..8 reserved
    hdr[8..16].copy_from_slice(&term.to_le_bytes());
    hdr[16..24].copy_from_slice(&last_idx.to_le_bytes());
    hdr[24..32].copy_from_slice(&last_term.to_le_bytes());
    hdr[32..36].copy_from_slice(&s.dek_epoch.to_le_bytes());
    hdr[36..40].copy_from_slice(&(body_len as u32).to_le_bytes());

    // CRC32C covers the header + body, binding metadata and payload together.
    let crc = {
        let mut c = Crc32c::new();
        c.update(&hdr);
        if body_len > 0 {
            c.update(&s.body_buf[..body_len]);
        }
        c.finalize()
    };
    let mut trailer = [0u8; SNAP_TRAILER_LEN];
    trailer[0..4].copy_from_slice(&crc.to_le_bytes());
    trailer[4..8].copy_from_slice(&END_MAGIC_SNAP.to_le_bytes());

    let mut ok = (sys.provider_call)(fd, FS_WRITE, hdr.as_mut_ptr(), SNAP_HDR_LEN) == SNAP_HDR_LEN as i32;
    if ok && body_len > 0 {
        ok = (sys.provider_call)(fd, FS_WRITE, s.body_buf.as_mut_ptr(), body_len) == body_len as i32;
    }
    if ok {
        ok = (sys.provider_call)(fd, FS_WRITE, trailer.as_mut_ptr(), SNAP_TRAILER_LEN)
            == SNAP_TRAILER_LEN as i32;
    }
    if ok {
        // Single trailing fsync: makes the whole file durable atomically.
        ok = (sys.provider_call)(fd, FS_FSYNC, core::ptr::null_mut(), 0) == 0;
    }
    (sys.provider_call)(fd, FS_CLOSE, core::ptr::null_mut(), 0);

    if ok {
        s.snap_bytes_written = s.snap_bytes_written.saturating_add(body_len as u64);
        dev_log(sys, 3, b"[snap] durable".as_ptr(), 14);
    } else {
        s.install_failures = s.install_failures.saturating_add(1);
        dev_log(sys, 3, b"[snap] durable FAIL".as_ptr(), 19);
    }
    (ok, true)
}
