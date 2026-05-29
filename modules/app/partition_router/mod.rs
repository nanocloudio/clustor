//! Partition Router — fan-out point at the head of the partitioned graph.
//!
//! Receives proposals from the protocol stack (e.g. quantum's
//! `session_processor`) on two input ports — one carrying legacy
//! untagged `MSG_CLIENT_PROPOSAL` (payload = body), one carrying
//! tagged `MSG_CLIENT_PROPOSAL` whose payload is
//! `[correlation_id:u64 LE][body]`. Each proposal is hashed
//! (FNV-1a-64 over the body, never over the correlation_id prefix) to
//! a `partition_id` and re-emitted on the partitioned envelope to the
//! per-partition `raft_engine` instance.
//!
//! Per-partition outputs come in pairs: `proposals_out_p<i>` for
//! untagged proposals (raft side: `proposals_partitioned`) and
//! `proposals_tagged_out_p<i>` for tagged proposals (raft side:
//! `proposals_partitioned_tagged`). With four partitions per router
//! instance that's eight output ports total — exactly the fluxor
//! 8-port-per-direction budget. Larger fan-out needs the multi-tenant
//! raft_engine RFC follow-up (or a tree of partition_routers).
//!
//! See `clustor/.context/rfc_partition_groups.md` step 4 for the design.

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

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

const PROPOSAL_BUF: usize = 2048;

/// Hard cap on per-router-instance fan-out. With one untagged + one
/// tagged output port per partition we need 2N output channels; the
/// fluxor static graph allows 8 outputs per direction, so N = 4 is
/// the ceiling. Massive partition counts compose multiple
/// `partition_router` instances in a tree (or wait for the
/// multi-tenant raft RFC).
const MAX_LOCAL_PARTITIONS: usize = 4;

define_params! {
    ModuleState;

    1, num_partitions, u16, 1
        => |s, d, len| { s.num_partitions = p_u16(d, len, 0, 1); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // ── Channels ───────────────────────────────────────────────
    in_proposals: i32,                                    // in[0]: untagged MSG_CLIENT_PROPOSAL
    in_proposals_tagged: i32,                             // in[1]: tagged MSG_CLIENT_PROPOSAL (payload starts with correlation_id)
    out_untagged: [i32; MAX_LOCAL_PARTITIONS],            // out[0..N]:  partitioned untagged
    out_tagged: [i32; MAX_LOCAL_PARTITIONS],              // out[N..2N]: partitioned tagged

    // ── Params ─────────────────────────────────────────────────
    num_partitions: u16,

    // ── Metrics ────────────────────────────────────────────────
    proposals_routed_untagged: u32,
    proposals_routed_tagged: u32,
    proposals_dropped: u32,

    // ── Scratch ────────────────────────────────────────────────
    msg_buf: [u8; PROPOSAL_BUF],
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
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }

        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        s.in_proposals = in_chan;
        s.in_proposals_tagged = dev_channel_port(sys, 0, 1);

        // Untagged outputs occupy out[0..N], tagged outputs out[N..2N].
        // Any output port that the graph leaves unwired stays -1; the
        // router falls back to the closest wired sibling rather than
        // dropping silently.
        s.out_untagged[0] = out_chan;
        for i in 1..MAX_LOCAL_PARTITIONS {
            s.out_untagged[i] = dev_channel_port(sys, 1, i as u8);
        }
        for i in 0..MAX_LOCAL_PARTITIONS {
            let port_idx = (MAX_LOCAL_PARTITIONS + i) as u8;
            s.out_tagged[i] = dev_channel_port(sys, 1, port_idx);
        }

        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        if s.num_partitions == 0 { s.num_partitions = 1; }
        if (s.num_partitions as usize) > MAX_LOCAL_PARTITIONS {
            s.num_partitions = MAX_LOCAL_PARTITIONS as u16;
        }

        dev_log(sys, 3, b"[prtn] init".as_ptr(), 11);
        0
    }
}

/// Pick the output port for a partition, falling back to out[0] of
/// the same family if the per-partition port isn't wired. Returns -1
/// if no port is available.
#[inline]
fn pick_chan(table: &[i32; MAX_LOCAL_PARTITIONS], partition_id: u16) -> i32 {
    let idx = (partition_id as usize).min(MAX_LOCAL_PARTITIONS - 1);
    let primary = table[idx];
    if primary >= 0 { primary } else { table[0] }
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

        // Untagged proposals (in[0]) — payload is the bare body.
        for _ in 0..16 {
            let poll_in = (sys.channel_poll)(s.in_proposals, 0x01);
            if poll_in <= 0 || (poll_in as u32 & 0x01) == 0 { break; }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_proposals, &mut s.msg_buf);
            if msg_type != wire::MSG_CLIENT_PROPOSAL || plen == 0 { continue; }
            let body_len = plen as usize;

            // `.max(1)` keeps rustc from emitting a rem_by_zero
            // panic landing pad — module_new clamps num_partitions
            // to ≥1 already, but the optimizer can't see across
            // module boundaries.
            let partition_id = (wire::fnv1a_64(&s.msg_buf[..body_len])
                % (s.num_partitions.max(1) as u64)) as u16;

            let chan = pick_chan(&s.out_untagged, partition_id);
            if chan < 0 {
                s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                continue;
            }
            let poll_out = (sys.channel_poll)(chan, 0x02);
            if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
                s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                continue;
            }
            wire_channels::channel_write_partitioned(
                sys,
                chan,
                partition_id,
                wire::MSG_CLIENT_PROPOSAL,
                &s.msg_buf[..body_len],
            );
            s.proposals_routed_untagged = s.proposals_routed_untagged.wrapping_add(1);
        }

        // Tagged proposals (in[1]) — payload is `[correlation_id:u64 LE][body]`.
        // Hash the body (excluding the correlation prefix) so two
        // clients tagging the same body land on the same partition,
        // and the partition assignment is independent of the
        // correlation_id allocation policy.
        if s.in_proposals_tagged >= 0 {
            for _ in 0..16 {
                let poll_in = (sys.channel_poll)(s.in_proposals_tagged, 0x01);
                if poll_in <= 0 || (poll_in as u32 & 0x01) == 0 { break; }

                let (msg_type, plen) = wire_channels::channel_read_msg(
                    sys,
                    s.in_proposals_tagged,
                    &mut s.msg_buf,
                );
                if msg_type != wire::MSG_CLIENT_PROPOSAL { continue; }
                let plen = plen as usize;
                if plen < wire::TAGGED_PROPOSAL_HDR { continue; }

                let body_off = wire::TAGGED_PROPOSAL_HDR;

                let partition_id = (wire::fnv1a_64(&s.msg_buf[body_off..plen])
                    % (s.num_partitions.max(1) as u64)) as u16;

                let chan = pick_chan(&s.out_tagged, partition_id);
                if chan < 0 {
                    s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                    continue;
                }
                let poll_out = (sys.channel_poll)(chan, 0x02);
                if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
                    s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                    continue;
                }
                // Forward the tagged payload as-is (correlation_id +
                // body), wrapped in the partitioned envelope. The
                // recipient (raft_engine.proposals_partitioned_tagged)
                // strips the correlation prefix on the way into its
                // batch.
                wire_channels::channel_write_partitioned(
                    sys,
                    chan,
                    partition_id,
                    wire::MSG_CLIENT_PROPOSAL,
                    &s.msg_buf[..plen],
                );
                s.proposals_routed_tagged = s.proposals_routed_tagged.wrapping_add(1);
            }
        }

        0
    }
}
