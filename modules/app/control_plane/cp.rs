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
use super::{wire, wire_channels};
use super::dev_millis;

const REFRESH_FRESH_MS: u64 = 5000;

#[repr(C)]
pub struct Cp {
    pub out_proof: i32,          // out: CpProof
    pub out_tenant_records: i32, // out: tenant records (optional)
    pub out_capabilities: i32,   // out: capability manifests (optional)
    last_fetch_ms: u64,
    refresh_interval_ms: u64,
    proof_seq: u32,
}

pub unsafe fn init(c: &mut Cp) {
    c.out_proof = -1;
    c.out_tenant_records = -1;
    c.out_capabilities = -1;
    c.last_fetch_ms = 0;
    c.refresh_interval_ms = REFRESH_FRESH_MS;
    c.proof_seq = 0;
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
    c.last_fetch_ms = now;
    c.proof_seq += 1;

    // Emit a synthetic CP proof (timestamp + sequence).
    // Real implementation would fetch from CP HTTP endpoint.
    let mut buf = [0u8; 12];
    buf[0..8].copy_from_slice(&now.to_le_bytes());
    buf[8..12].copy_from_slice(&c.proof_seq.to_le_bytes());

    if c.out_proof >= 0 {
        let poll = (sys.channel_poll)(c.out_proof, 0x02);
        if poll > 0 && (poll as u32 & 0x02) != 0 {
            wire_channels::channel_write_msg(sys, c.out_proof, wire::MSG_CP_PROOF, &buf[..12]);
        }
    }

    // Tenant records and capabilities ride the same refresh tick. In
    // production these come from the same CP response. Synthetic
    // placeholders for now.
    if c.out_tenant_records >= 0 {
        let poll_t = (sys.channel_poll)(c.out_tenant_records, 0x02);
        if poll_t > 0 && (poll_t as u32 & 0x02) != 0 {
            // [tenant_id:u32 = 0 (default)] [max_rate:u32 = 10000]
            let mut tr = [0u8; 8];
            tr[0..4].copy_from_slice(&0u32.to_le_bytes());
            tr[4..8].copy_from_slice(&10000u32.to_le_bytes());
            wire_channels::channel_write_msg(sys, c.out_tenant_records, 0xD0, &tr);
        }
    }
    if c.out_capabilities >= 0 {
        let poll_c = (sys.channel_poll)(c.out_capabilities, 0x02);
        if poll_c > 0 && (poll_c as u32 & 0x02) != 0 {
            // [schema_version:u16 = 1] [mqtt_enabled:u8 = 1]
            let caps = [0x01u8, 0x00, 0x01];
            wire_channels::channel_write_msg(sys, c.out_capabilities, 0xD3, &caps);
        }
    }
}
