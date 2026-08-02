//! Durability — write-ahead log, quorum durability ledger, snapshots
//! and key epochs.
//!
//! One graph module composed of four components (standards
//! `fluxor-modules.md` §8):
//!
//!   - [`wal`]      — segment-file WAL: CRC32C framing, replay,
//!     group/async-fenced fsync, truncation, compaction, gap-refetch
//!     serving.
//!   - [`ledger`]   — per-replica durable indices → quorum durability
//!     proofs (compiled out of the `volatile` variant).
//!   - [`snapshot`] — manifest persistence, chunked install transfer,
//!     retention floors, app snapshot round-trip.
//!   - [`keys`]     — DEK epoch rotation.
//!
//! ## Variants
//!
//! `disk` (default) is the durable composition. `volatile` selects
//! the WAL's in-memory retention path at compile time and **compiles
//! the ledger component out** — its `ack` input and `quorum_durable`
//! output are absent from the manifest, so a volatile composition is
//! structurally incapable of emitting a durability proof. Fail-closed
//! by construction, not by configuration.
//!
//! ## Dispatch table
//!
//! Components step in a fixed order; intra-step delivery order is
//! owned HERE and nowhere else:
//!
//!   1. `keys`     — rotation check; the epoch is handed to wal and
//!      snapshot (idempotent latest-wins).
//!   2. `wal`      — replay or the write path. Durable high-water and
//!      rotation triggers land in monotone latches.
//!   3. latch drain — the ledger receives the local durable advance;
//!      the snapshot component receives the rotation trigger.
//!   4. `ledger`   — cross-node ack drain + quorum recompute (disk
//!      variant only).
//!   5. `snapshot` — floors, external triggers, install transfer.
//!
//! The wal's Burst classifications and the snapshot component's
//! cold-FS steps propagate as the module's step return.

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
include!("../../../target/fluxor/fluxor-abi/sdk/runtime/params.rs");

#[path = "../../common/types.rs"]
mod types;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;
#[path = "../../common/collections.rs"]
mod collections;

mod keys;
#[cfg(not(feature = "volatile"))]
mod ledger;
mod snapshot;
mod wal;

/// Composite step return for a step that did cold synchronous disk
/// work (same contract as the kernel Burst outcome).
const STEP_BURST: i32 = 2;

define_params! {
    ModuleState;

    1, encoding, u8, 0
        => |s, d, len| { s.wal.encoding = p_u8(d, len, 0, 0); };

    2, segment_bytes, u32, 67_108_864
        => |s, d, len| { s.wal.segment_limit = p_u32(d, len, 0, 67_108_864); };

    // 3, aead — reserved (0=none, 1=aes_256_gcm); not yet read at runtime.

    // Partition slot for multi-Raft graphs. Stamped into segment and
    // snapshot filenames and into outgoing durability proofs.
    4, partition_id, u16, 0
        => |s, d, len| { s.partition_id = p_u16(d, len, 0, 0); };

    // Replica id this node's durability belongs to. Stamped into
    // FsyncAcks/proofs; must match consensus.self_id on this node.
    5, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    // 0 = per-entry write + fsync + ack (default, strict). 1 = group fsync.
    6, fsync_mode, u8, 0
        => |s, d, len| { s.wal.fsync_mode = p_u8(d, len, 0, 0); };

    7, group_window_ms, u16, 2
        => |s, d, len| { s.wal.group_window_ms = p_u16(d, len, 0, 2); };

    8, group_max_pending, u16, 64
        => |s, d, len| { s.wal.group_max_pending = p_u16(d, len, 0, 64); };

    // 1 = 8.3-conforming names at the FS root (bare-metal FAT32) for
    // BOTH segments and snapshots — one param, one layout.
    9, root_path, u8, 0
        => |s, d, len| { s.root_path = p_u8(d, len, 0, 0); };

    // 1 = skip boot replay (start fresh).
    10, skip_replay, u8, 0
        => |s, d, len| { s.wal.skip_replay = p_u8(d, len, 0, 0); };

    // 1 = physically preallocated fixed-capacity segments.
    11, fixed_segment, u8, 0
        => |s, d, len| { s.wal.fixed_segment = p_u8(d, len, 0, 0); };

    12, preallocate_settle_ms, u16, 0
        => |s, d, len| { s.wal.preallocate_settle_ms = p_u16(d, len, 0, 0); };

    // Fence-pipelining depth (async FS backend only).
    13, fence_depth, u16, 1
        => |s, d, len| { s.wal.fence_depth = p_u16(d, len, 0, 1); };

    14, voter_count, u8, 1
        => |s, d, len| { s.voter_count = p_u8(d, len, 0, 1); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    // Shared params, copied into components after parse.
    partition_id: u16,
    self_id: u8,
    voter_count: u8,
    root_path: u8,

    wal: wal::Wal,
    #[cfg(not(feature = "volatile"))]
    ledger: ledger::Ledger,
    snapshot: snapshot::Snapshot,
    keys: keys::Keys,
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
    params: *const u8,
    params_len: usize,
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
        s.partition_id = 0;
        s.self_id = 0;
        s.voter_count = 1;
        s.root_path = 0;

        wal::init(&mut s.wal);
        #[cfg(not(feature = "volatile"))]
        ledger::init(&mut s.ledger);
        snapshot::init(&mut s.snapshot);
        keys::init(&mut s.keys, sys);

        // Port handles. Indices follow the manifest declaration order;
        // the volatile variant omits the ledger ports and leaves their
        // indices as holes, so every index below is stable across
        // variants.
        s.wal.in_entries = in_chan; // in[0] entries
        s.wal.in_entry_request = dev_channel_port(sys, 0, 1);
        s.wal.in_compact_before = dev_channel_port(sys, 0, 2);
        #[cfg(not(feature = "volatile"))]
        {
            s.ledger.in_ack = dev_channel_port(sys, 0, 3);
        }
        s.snapshot.in_import = dev_channel_port(sys, 0, 4);
        s.snapshot.in_trigger = dev_channel_port(sys, 0, 5);
        s.snapshot.in_install_request = dev_channel_port(sys, 0, 6);
        s.snapshot.in_retention_floor = dev_channel_port(sys, 0, 7);
        s.snapshot.in_app_body = dev_channel_port(sys, 0, 8);
        s.wal.out_flushed = out_chan; // out[0] flushed
        s.wal.out_replay_complete = dev_channel_port(sys, 1, 1);
        s.wal.out_entry_reply = dev_channel_port(sys, 1, 2);
        s.wal.out_compaction = dev_channel_port(sys, 1, 3);
        s.wal.out_metrics = dev_channel_port(sys, 1, 4);
        #[cfg(not(feature = "volatile"))]
        {
            s.ledger.out_quorum = dev_channel_port(sys, 1, 5);
        }
        s.snapshot.out_export = dev_channel_port(sys, 1, 6);
        s.snapshot.out_manifest = dev_channel_port(sys, 1, 7);
        s.snapshot.out_installed = dev_channel_port(sys, 1, 8);
        s.snapshot.out_app_ctl = dev_channel_port(sys, 1, 9);
        s.keys.out_cert = dev_channel_port(sys, 1, 10);
        // The snapshot component shares the module's metrics port.
        s.snapshot.out_metrics = s.wal.out_metrics;

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Fan shared params into components.
        s.wal.partition_id = s.partition_id;
        s.wal.self_id = s.self_id;
        s.wal.root_path = s.root_path;
        s.snapshot.partition_id = s.partition_id;
        s.snapshot.root_path = s.root_path;
        #[cfg(not(feature = "volatile"))]
        {
            s.ledger.self_id = s.self_id;
            s.ledger.partition_id = s.partition_id;
            s.ledger.voter_count = s.voter_count;
            ledger::clamp_voters(&mut s.ledger);
        }
        wal::arm(&mut s.wal);

        dev_log(sys, 3, b"[wal] init".as_ptr(), 10);
        #[cfg(not(feature = "volatile"))]
        dev_log(sys, 3, b"[dur] init".as_ptr(), 10);
        dev_log(sys, 3, b"[snap] init".as_ptr(), 11);
        dev_log(sys, 3, b"[keys] init".as_ptr(), 11);
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
        let now = dev_millis(sys);

        // Dispatch table — see the module header for the ordering
        // contract.
        let epoch = keys::step(&mut s.keys, sys, now);
        s.wal.dek_epoch = epoch;
        s.snapshot.dek_epoch = epoch;

        let wal_rc = wal::step(&mut s.wal, sys);

        // Drain the wal's seam latches (monotone latest-wins).
        #[cfg(not(feature = "volatile"))]
        {
            let local_advanced = if s.wal.ledger_dirty {
                s.wal.ledger_dirty = false;
                let (term, index) = s.wal.ledger_ack;
                ledger::on_ack(&mut s.ledger, term, index, s.self_id)
            } else {
                false
            };
            ledger::step(&mut s.ledger, sys, local_advanced);
        }
        let mut cold_fs = false;
        if s.wal.snap_trigger_dirty {
            s.wal.snap_trigger_dirty = false;
            let (term, index) = s.wal.snap_trigger;
            // Floors before triggers: a retention floor declared this
            // tick must gate a rotation trigger delivered this tick,
            // same as the external-trigger path inside snapshot::step.
            snapshot::drain_retention_floors(&mut s.snapshot, sys);
            if snapshot::on_trigger(&mut s.snapshot, sys, term, index) {
                cold_fs = true;
            }
        }
        if snapshot::step(&mut s.snapshot, sys) {
            cold_fs = true;
        }

        if wal_rc == STEP_BURST || cold_fs {
            STEP_BURST
        } else {
            wal_rc
        }
    }
}
