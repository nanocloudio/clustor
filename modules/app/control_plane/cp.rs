//! cp — periodic control-plane proof source.
//!
//! Emits CpProof messages at intervals determined by the current
//! cache state. In a real deployment, this would make HTTP requests
//! to the CP service via the socket service.
//!
//! Also emits tenant records and capability manifests alongside
//! proofs for graphs that enforce tenant policy. These ports are
//! optional — graphs without tenancy leave them unwired.

use super::abi::SyscallTable;
use super::dev_millis;
use super::{wire, wire_channels};

const REFRESH_FRESH_MS: u64 = 5000;

/// Tenants whose quota this controller holds.
///
/// A small fixed table, not the per-module heap: a quota lives as long as
/// its tenant, so the arena would be reserved for the worst case anyway.
pub const MAX_TENANTS: usize = 32;

/// Quota applied to a tenant with no record of its own.
///
/// A cluster that never sets a quota runs entirely on this value, so it
/// has to be a usable rate rather than a placeholder.
pub const DEFAULT_MAX_RATE: u32 = 10_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct TenantQuota {
    tenant_id: u32,
    max_rate: u32,
    active: u8,
}

impl TenantQuota {
    const fn zero() -> Self {
        Self { tenant_id: 0, max_rate: 0, active: 0 }
    }
}

#[repr(C)]
pub struct Cp {
    pub out_proof: i32,          // out: CpProof
    pub out_tenant_records: i32, // out: tenant records (optional)
    pub out_capabilities: i32,   // out: capability manifests (optional)
    last_fetch_ms: u64,
    refresh_interval_ms: u64,
    proof_seq: u32,

    tenants: [TenantQuota; MAX_TENANTS],
    /// Round-robin cursor: one tenant record is emitted per refresh
    /// tick, so a full table costs one frame per tick rather than
    /// `MAX_TENANTS` in a burst that would evict other traffic from the
    /// same channel.
    emit_cursor: u8,
    /// Quota records that did not fit the table. Non-zero means some
    /// tenant is silently running on the default.
    tenants_dropped: u32,
}

pub unsafe fn init(c: &mut Cp) {
    c.out_proof = -1;
    c.out_tenant_records = -1;
    c.out_capabilities = -1;
    c.last_fetch_ms = 0;
    c.refresh_interval_ms = REFRESH_FRESH_MS;
    c.proof_seq = 0;
    c.tenants = [TenantQuota::zero(); MAX_TENANTS];
    c.emit_cursor = 0;
    c.tenants_dropped = 0;
    // Tenant 0 is the default tenant every unauthenticated client maps
    // to. Seeded so a cluster with no quota records behaves exactly as
    // the synthetic record did, rather than leaving the default tenant
    // unmetered until an operator happens to set one.
    c.tenants[0] = TenantQuota { tenant_id: 0, max_rate: DEFAULT_MAX_RATE, active: 1 };
}

/// Apply a committed tenant-quota record. Last writer wins per tenant,
/// which is what an operator setting a quota twice expects.
pub fn set_tenant_quota(c: &mut Cp, tenant_id: u32, max_rate: u32) {
    for i in 0..MAX_TENANTS {
        if c.tenants[i].active == 1 && c.tenants[i].tenant_id == tenant_id {
            c.tenants[i].max_rate = max_rate;
            return;
        }
    }
    for i in 0..MAX_TENANTS {
        if c.tenants[i].active == 0 {
            c.tenants[i] = TenantQuota { tenant_id, max_rate, active: 1 };
            return;
        }
    }
    // Full. Counted rather than evicting: evicting some other tenant's
    // quota would silently return IT to the default, turning one
    // operator's change into another tenant's outage.
    c.tenants_dropped = c.tenants_dropped.wrapping_add(1);
}

/// The quota held for `tenant_id`, for tests and callers that need to
/// read back what was applied.
pub fn tenant_quota(c: &Cp, tenant_id: u32) -> Option<u32> {
    for i in 0..MAX_TENANTS {
        if c.tenants[i].active == 1 && c.tenants[i].tenant_id == tenant_id {
            return Some(c.tenants[i].max_rate);
        }
    }
    None
}

/// Per-step bound: at most one proof + one tenant record + one
/// capability manifest, on the refresh tick only.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Cp` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(c: &mut Cp, sys: &SyscallTable, now: u64) {
    if now.wrapping_sub(c.last_fetch_ms) < c.refresh_interval_ms {
        return;
    }

    // Emit a synthetic CP proof (timestamp + sequence).
    // Real implementation would fetch from CP HTTP endpoint.
    //
    // The refresh clock advances only once the proof actually lands: a
    // transiently full `out_proof` at tick time means "retry next
    // step", not "drop this proof for a whole refresh interval" —
    // dropping it would age the proof_cache toward Stale for no reason.
    let seq = c.proof_seq.wrapping_add(1);
    let mut buf = [0u8; 12];
    buf[0..8].copy_from_slice(&now.to_le_bytes());
    buf[8..12].copy_from_slice(&seq.to_le_bytes());

    if c.out_proof >= 0 {
        if !wire_channels::writable(sys, c.out_proof) {
            return; // output full — retry next step, clock not advanced
        }
        let wrote =
            wire_channels::channel_write_msg(sys, c.out_proof, wire::MSG_CP_PROOF, &buf[..12]);
        if wrote <= 0 {
            return; // frame didn't fit (poll only means ≥1 byte free) — retry
        }
    }
    c.last_fetch_ms = now;
    c.proof_seq = seq;

    // Tenant records and capabilities ride the same refresh tick; in a
    // deployed control plane both arrive in the same CP response.
    //
    // One HELD quota per tick, round-robin. Re-emitted on a cadence
    // rather than sent once because `governance` holds the quota in
    // memory: a module that restarts, or an edge that dropped a frame,
    // would otherwise run on the default until the next quota change —
    // which might be never.
    if c.out_tenant_records >= 0 && wire_channels::writable(sys, c.out_tenant_records) {
        let mut scanned = 0usize;
        while scanned < MAX_TENANTS {
            let i = c.emit_cursor as usize % MAX_TENANTS;
            c.emit_cursor = c.emit_cursor.wrapping_add(1);
            scanned += 1;
            if c.tenants[i].active != 1 {
                continue;
            }
            let mut tr = [0u8; 8];
            tr[0..4].copy_from_slice(&c.tenants[i].tenant_id.to_le_bytes());
            tr[4..8].copy_from_slice(&c.tenants[i].max_rate.to_le_bytes());
            wire_channels::channel_write_msg(sys, c.out_tenant_records, 0xD0, &tr);
            break;
        }
    }
    if c.out_capabilities >= 0 {
        if wire_channels::writable(sys, c.out_capabilities) {
            // [schema_version:u16 = 1] [mqtt_enabled:u8 = 1]
            let caps = [0x01u8, 0x00, 0x01];
            wire_channels::channel_write_msg(sys, c.out_capabilities, 0xD3, &caps);
        }
    }
}
