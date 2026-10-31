//! directory_front — one session-directory namespace behind a consumer's
//! own port pair: the broker and egress surfaces.
//!
//! `namespace: rs` fronts the egress reservations (`rs/`: an egress
//! gateway's port blocks per boot incarnation, a tenant's address ranges
//! with their quarantine), `namespace: att` the attachment boundaries
//! (`att/`: the private-service broker's attachment and revocation
//! generations), `namespace: op` the operation store (`op/`; with
//! `op_kind: evacuation`, only a failure-domain controller's EVACUATION
//! records). The logic — ids, resends, the REPLAY stream, refusals — is
//! `modules/common/directory_front_core.rs`; this file is its ports.
//!
//! Wiring:
//!
//! ```yaml
//! - from: egress_gateway.authority_out    # the consumer's requests
//!   to: directory_front.request_in
//! - from: directory_front.answer_out
//!   to: egress_gateway.authority_in
//! - from: directory_front.directory_out
//!   to: session_directory.requests
//! - from: session_directory.replies
//!   to: directory_front.directory_in
//! ```

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset"
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

#[path = "../../common/directory_front_core.rs"]
mod core_front;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use core_front::{
    refusal_answer, FrontCore, FrontRefusal, FRONT_CMD_MAX, FRONT_REPLY_MAX, NS_AT, NS_OP, NS_RS,
};

define_params! {
    ModuleState;

    // The namespace fronted: 1 rs/ (egress reservations), 2 att/
    // (attachment boundaries), 3 op/ (operation records).
    1, namespace, u8, 1, enum { rs=1, att=2, op=3 }
        => |s, d, len| { s.ns = p_u8(d, len, 0, 1); };

    // op/ only: the one record kind served (0 any, 1 takeover,
    // 2 evacuation, 3 region); a request of another kind is refused here.
    2, op_kind, u8, 0, enum { any=0, takeover=1, evacuation=2, region=3 }
        => |s, d, len| { s.op_kind = p_u8(d, len, 0, 0); };

    // A request unanswered this long is sent again (the same command:
    // its operation id makes the resend a retry). Zero is refused: every
    // resend is a log entry.
    3, retry_ms, u32, 2000
        => |s, d, len| { s.retry_ms = p_u32(d, len, 0, 2000); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_request: i32,
    in_directory: i32,
    out_answer: i32,
    out_directory: i32,
    out_metrics: i32,
    ns: u8,
    op_kind: u8,
    _pad: [u8; 2],
    retry_ms: u32,
    last_metrics_ms: u64,
    front: FrontCore,
    /// A reply taken off `directory_in` that `answer_out` had no room
    /// for: placed before anything else is read.
    held_len: u16,
    held_msg: u8,
    held: [u8; 8 + FRONT_REPLY_MAX],
    buf: [u8; 8 + FRONT_REPLY_MAX + 8],
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI the kernel passes a valid, exclusively
    // borrowed `state` of at least `module_state_size()` bytes and a live
    // syscall table.
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
        s.in_request = in_chan;
        s.in_directory = dev_channel_port(sys, 0, 1);
        s.out_answer = out_chan;
        s.out_directory = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.ns = NS_RS;
        s.op_kind = 0;
        s._pad = [0; 2];
        s.retry_ms = 2000;
        s.last_metrics_ms = 0;
        s.held_len = 0;
        s.held_msg = 0;
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        if !(s.ns == NS_RS || s.ns == NS_AT || s.ns == NS_OP) || s.op_kind > 3 {
            let m = b"[dir_front] namespace must be rs, att or op (op_kind 0..3)";
            dev_log(sys, 1, m.as_ptr(), m.len());
            return -22;
        }
        if s.retry_ms == 0 {
            let m = b"[dir_front] retry_ms must be non-zero";
            dev_log(sys, 1, m.as_ptr(), m.len());
            return -22;
        }
        if s.in_request < 0 || s.in_directory < 0 || s.out_answer < 0 || s.out_directory < 0 {
            let m =
                b"[dir_front] request_in, directory_in, answer_out and directory_out must be wired";
            dev_log(sys, 1, m.as_ptr(), m.len());
            return -22;
        }
        // The request-id tag, once per start: a reply to an earlier life's
        // request, or to another requester's, never matches.
        let mut tag = [0u8; 4];
        if dev_csprng_fill(sys, tag.as_mut_ptr(), 4) != 0 {
            tag = (dev_millis(sys) as u32).to_le_bytes();
        }
        let tag = u32::from_le_bytes(tag) | 1;
        let op_kind = if s.ns == NS_OP { s.op_kind } else { 0 };
        s.front = FrontCore::new(s.ns, op_kind, u64::from(s.retry_ms), tag);
        dev_log(sys, 3, b"[dir_front] init".as_ptr(), 16);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: as `module_new`.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        // 1) Replies: a held one first, then the directory's port, each
        //    of ours handed back under the consumer's id.
        if s.held_len > 0 {
            let n = usize::from(s.held_len);
            if wire_channels::channel_write_msg(sys, s.out_answer, s.held_msg, &s.held[..n]) > 0 {
                s.held_len = 0;
            }
        }
        let mut k = 0;
        while s.held_len == 0 && k < 8 {
            k += 1;
            let Some((msg, plen)) = wire_channels::next_msg(sys, s.in_directory, &mut s.buf) else {
                break;
            };
            let plen = usize::from(plen);
            let Some(a) = s.front.reply(msg, &s.buf[..plen], now) else {
                continue;
            };
            let n = plen.min(s.held.len());
            s.held[..n].copy_from_slice(&s.buf[..n]);
            s.held[..8].copy_from_slice(&a.consumer_id.to_le_bytes());
            if wire_channels::channel_write_msg(sys, s.out_answer, a.msg, &s.held[..n]) <= 0 {
                s.held_len = n as u16;
                s.held_msg = a.msg;
            }
        }

        // 2) The consumer's requests, while a slot is free: a request
        //    waits in `request_in` until one is.
        let mut k = 0;
        while s.front.has_room() && k < 8 {
            k += 1;
            let Some((msg, plen)) = wire_channels::next_msg(sys, s.in_request, &mut s.buf) else {
                break;
            };
            let plen = usize::from(plen);
            if plen < 8 {
                // No request id to answer under.
                s.front.refused = s.front.refused.wrapping_add(1);
                continue;
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(&s.buf[..8]);
            let consumer_id = u64::from_le_bytes(id);
            let verdict = if plen > 8 + FRONT_CMD_MAX {
                s.front.refused = s.front.refused.wrapping_add(1);
                Err(FrontRefusal::Malformed)
            } else {
                s.front.admit(msg, consumer_id, &s.buf[8..plen])
            };
            // A refusal is answered now, so the consumer does not wait out
            // its own timeout for a request that will never be sent.
            if let Err(why) = verdict {
                if let Some(a) = refusal_answer(consumer_id, msg, why) {
                    let _ = wire_channels::channel_write_msg(
                        sys,
                        s.out_answer,
                        core_front::MSG_DIR_OUT_OF_SCOPE,
                        &a,
                    );
                }
            }
        }

        // 3) What is due on the directory's port: new requests and
        //    resends, while it has room.
        let mut k = 0;
        while k < 8 {
            k += 1;
            let mut frame = [0u8; 8 + FRONT_CMD_MAX];
            let (slot, msg, n) = match s.front.due(now) {
                Some((i, o)) => {
                    frame[..8].copy_from_slice(&o.request_id.to_le_bytes());
                    frame[8..8 + o.body.len()].copy_from_slice(o.body);
                    (i, o.msg, 8 + o.body.len())
                }
                None => break,
            };
            if wire_channels::channel_write_msg(sys, s.out_directory, msg, &frame[..n]) <= 0 {
                break;
            }
            s.front.sent(slot, now);
        }

        // 4) Heartbeat.
        if s.out_metrics >= 0 && now.wrapping_sub(s.last_metrics_ms) >= 1000 {
            s.last_metrics_ms = now;
            let f = &s.front;
            let vals = [
                f.admitted,
                f.refused,
                f.answered,
                f.resent,
                f.foreign,
                f.in_flight() as u32,
            ];
            let mut b = [0u8; 24];
            for (i, v) in vals.iter().enumerate() {
                b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            if wire_channels::writable(sys, s.out_metrics) {
                let _ = wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &b);
            }
        }
        0
    }
}
