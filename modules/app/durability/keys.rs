//! keys — DEK epoch source on a rotation timer.
//!
//! Owns the data-encryption-key epoch consumed by the
//! [`wal`](super::wal) and [`snapshot`](super::snapshot) components
//! (delivered in-module — the epoch is stamped into snapshot
//! manifests and headers). `cert_refresh` remains an external port
//! for deployments that wire certificate rotation.

use super::abi::SyscallTable;
use super::{wire, wire_channels};

/// Weekly DEK rotation.
const ROTATION_INTERVAL_MS: u64 = 168 * 3600 * 1000;

#[repr(C)]
pub struct Keys {
    pub out_cert: i32, // out: MSG_CERT_REFRESH (optional)
    pub dek_epoch: u32,
    last_rotation_ms: u64,
    rotation_interval_ms: u64,
}

pub unsafe fn init(k: &mut Keys, sys: &SyscallTable) {
    k.out_cert = -1;
    k.dek_epoch = 1;
    k.rotation_interval_ms = ROTATION_INTERVAL_MS;
    k.last_rotation_ms = super::dev_millis(sys);
}

/// Per-step bound: one rotation check; at most one cert-refresh emit.
/// Returns the current epoch — the dispatch table hands it to the
/// wal and snapshot components each step (idempotent latest-wins).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Keys` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(k: &mut Keys, sys: &SyscallTable, now: u64) -> u32 {
    if now.wrapping_sub(k.last_rotation_ms) >= k.rotation_interval_ms {
        k.last_rotation_ms = now;
        k.dek_epoch += 1;

        // Also trigger cert refresh
        if k.out_cert >= 0 {
            let poll = (sys.channel_poll)(k.out_cert, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let buf = k.dek_epoch.to_le_bytes();
                wire_channels::channel_write_msg(sys, k.out_cert, wire::MSG_CERT_REFRESH, &buf);
            }
        }
    }
    k.dek_epoch
}
