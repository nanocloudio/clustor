//! proof_cache — CP proof Fresh/Cached/Stale/Expired state machine.
//!
//! Tracks proof age and emits CacheState + FallbackSignal
//! transitions. Proofs arrive on either the `proof` or `input` port
//! (same contract; both are drained latest-wins). State transitions
//! publish on `cache_state` and `fresh_state` (same payload) and are
//! delivered to the [`read_gate`](super::read_gate) component
//! in-module.

use super::abi::SyscallTable;
use super::{read_gate, types, wire, wire_channels};

#[repr(C)]
pub struct ProofCache {
    pub in_proof: i32,        // in: CpProof
    pub in_input: i32,        // in: CpProof (second attach point, same contract)
    pub out_cache_state: i32, // out: CacheState
    pub out_fresh_state: i32, // out: CacheState (second attach point, same payload)
    pub out_fallback: i32,    // out: FallbackSignal

    // Config
    pub fresh_threshold_ms: u64,
    pub grace_period_ms: u64,

    // State
    last_proof_ms: u64,
    current_state: u8,
    last_emitted_state: u8,

    msg_buf: [u8; 32],
}

pub unsafe fn init(p: &mut ProofCache, sys: &SyscallTable) {
    p.in_proof = -1;
    p.in_input = -1;
    p.out_cache_state = -1;
    p.out_fresh_state = -1;
    p.out_fallback = -1;
    p.fresh_threshold_ms = 60_000;
    p.grace_period_ms = 120_000;
    p.current_state = types::CP_FRESH;
    p.last_emitted_state = 0xFF; // force first emit
    p.last_proof_ms = super::dev_millis(sys);
}

/// Per-step bound: both proof ports drained latest-wins (≤8 frames
/// each), one state-ladder evaluation, at most one transition emit.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(p: &mut ProofCache, gate: &mut read_gate::ReadGate, sys: &SyscallTable, now: u64) {
    // 1. Drain proofs (latest wins) from both attach points.
    drain_proofs(p, sys, now, 0);
    drain_proofs(p, sys, now, 1);

    // 2. Compute cache state from proof age
    let age = now.wrapping_sub(p.last_proof_ms);
    let new_state = if age < p.fresh_threshold_ms {
        types::CP_FRESH
    } else if age < p.grace_period_ms / 2 {
        types::CP_CACHED
    } else if age < p.grace_period_ms {
        types::CP_STALE
    } else {
        types::CP_EXPIRED
    };

    p.current_state = new_state;

    // 3. Emit on state change
    if new_state != p.last_emitted_state {
        p.last_emitted_state = new_state;

        // Deliver to the read gate in-module, then publish on both
        // external attach points.
        read_gate::on_cache_state(gate, new_state);

        let mut buf = [0u8; 1];
        wire::encode_cache_state(&mut buf, new_state);
        for chan in [p.out_cache_state, p.out_fresh_state] {
            if chan < 0 {
                continue;
            }
            let poll = (sys.channel_poll)(chan, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(sys, chan, wire::MSG_CACHE_STATE, &buf[..1]);
            }
        }

        // Emit FallbackSignal when entering/leaving strict fallback
        if p.out_fallback >= 0 {
            let fallback = new_state >= types::CP_STALE;
            let poll = (sys.channel_poll)(p.out_fallback, 0x02);
            if poll > 0 && (poll as u32 & 0x02) != 0 {
                let buf = [fallback as u8];
                wire_channels::channel_write_msg(sys, p.out_fallback, wire::MSG_FALLBACK_SIGNAL, &buf[..1]);
            }
        }
    }
}

unsafe fn drain_proofs(p: &mut ProofCache, sys: &SyscallTable, now: u64, which: u8) {
    let chan = if which == 0 { p.in_proof } else { p.in_input };
    if chan < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, chan, &mut p.msg_buf);
        if msg_type == wire::MSG_CP_PROOF && plen >= 8 {
            p.last_proof_ms = now;
        }
    }
}
