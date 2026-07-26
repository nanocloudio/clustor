//! read_gate — linearizable read permits from CP cache state.
//!
//! The cache state arrives from the [`proof_cache`](super::proof_cache)
//! component on every transition; while the cache is Fresh or Cached
//! the gate emits a standing `MSG_READ_PERMIT` each step so
//! the apply component knows reads are allowed. Stale and Expired block
//! linearizable reads.

use super::abi::SyscallTable;
use super::{types, wire, wire_channels};

#[repr(C)]
pub struct ReadGate {
    pub out_permits: i32, // out: ReadPermit to consensus
    cache_state: u8,      // CP_FRESH..CP_EXPIRED
}

pub unsafe fn init(g: &mut ReadGate) {
    g.out_permits = -1;
    g.cache_state = types::CP_FRESH; // optimistic until CP tells us otherwise
}

/// Deliver the latest cache state (proof_cache transition).
pub fn on_cache_state(g: &mut ReadGate, state: u8) {
    g.cache_state = state;
}

/// Per-step bound: at most one permit emit.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ReadGate` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(g: &mut ReadGate, sys: &SyscallTable) {
    // Only issue read permits when cache is Fresh or Cached
    // (Stale and Expired block linearizable reads)
    if g.cache_state <= types::CP_CACHED && g.out_permits >= 0 {
        // Emit a standing permit each step so the apply component knows
        // reads are allowed. This is a lightweight signal.
        let poll_out = (sys.channel_poll)(g.out_permits, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            let buf = [g.cache_state];
            wire_channels::channel_write_msg(sys, g.out_permits, wire::MSG_READ_PERMIT, &buf[..1]);
        }
    }
}
