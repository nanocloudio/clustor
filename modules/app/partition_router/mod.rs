//! Partition Router — fan-out point at the head of the partitioned graph.
//!
//! Receives proposals from the protocol stack (e.g. quantum's
//! `session_processor`) on two input ports — one untagged, one tagged
//! (payload prefixed with `[correlation_id:u64 LE]`) — and re-emits
//! each on the partitioned envelope to the per-partition `consensus`
//! instance.
//!
//! ## Routing: keyed, with a body-hashed fallback
//!
//! **Keyed (`MSG_CLIENT_PROPOSAL_KEYED`, preferred).** The proposer
//! hashes its own routing key — an MQTT `(tenant, client_id)` or
//! `(tenant, normalized_topic)`, a Kafka `(tenant, topic, partition)` —
//! reduces it with `wire::shard_for_key`, and sends
//! `[shard_id:u32 LE][rest]`. The router maps shard → partition, strips
//! the prefix, and forwards `rest` as a plain `MSG_CLIENT_PROPOSAL`.
//! Routing is therefore **stable per key**: every publish to one topic
//! lands on one partition regardless of payload.
//!
//! **Body-hashed (`MSG_CLIENT_PROPOSAL`).** FNV-1a-64 over the body
//! (never over the correlation_id prefix), for proposers that carry no
//! routing key of their own. Counted separately
//! (`proposals_body_hashed`) so a deployment can see how much of its
//! traffic takes it.
//!
//! Body hashing is **not** stable per key: two publishes to the same
//! topic with different payloads hash differently and select different
//! partitions. That is why keyed routing exists, and why a
//! multi-partition deployment must use it. With `num_partitions == 1`
//! every shard maps to the same partition, so the distinction is moot
//! and either shape places correctly.
//!
//! Per-partition outputs come in pairs: `proposals_out_p<i>` for
//! untagged proposals (raft side: `proposals_partitioned`) and
//! `proposals_tagged_out_p<i>` for tagged proposals (raft side:
//! `proposals_partitioned_tagged`). With four partitions per router
//! instance that's eight output ports total — exactly the fluxor
//! 8-port-per-direction budget. Larger fan-out needs a `consensus`
//! instance hosting more groups, or a tree of partition_routers.

#![cfg_attr(not(feature = "host-test"), no_std)]
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

#[path = "../../common/wal_frame.rs"]
mod wal_frame;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

/// Proposal scratch, sized to the shared WAL entry-body cap — the one
/// value every proposal-carrying buffer in the graph must agree on
/// (modules/common/wal_frame.rs).
const PROPOSAL_BUF: usize = wal_frame::MAX_ENTRY_BODY;

/// Per-partition OUTPUT PORTS this router declares. With one untagged +
/// one tagged port per partition that is 2N output channels against
/// fluxor's port budget, so N = 4. It bounds the ports, not the
/// partition count: `pick_chan` falls back to port 0 for a partition
/// without its own port, and the frame carries the partition id in its
/// envelope, which the multi-slot engine demuxes to the owning group.
const MAX_LOCAL_PARTITIONS: usize = 4;

/// Partitions this router routes to: the engine's `K_MAX`. Distinct
/// from the PORT count above — a clamp to the port count would give a
/// graph asking for 64 partitions four groups and leave sixty idle,
/// with nothing in the graph saying so.
const MAX_ROUTED_PARTITIONS: usize = 64;

define_params! {
    ModuleState;

    1, num_partitions, u16, 1
        => |s, d, len| { s.num_partitions = p_u16(d, len, 0, 1); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // ── Channels ───────────────────────────────────────────────
    in_proposals: i32,        // in[0]: untagged MSG_CLIENT_PROPOSAL
    in_proposals_tagged: i32, // in[1]: tagged MSG_CLIENT_PROPOSAL (payload starts with correlation_id)
    out_untagged: [i32; MAX_LOCAL_PARTITIONS], // out[0..N]:  partitioned untagged
    out_tagged: [i32; MAX_LOCAL_PARTITIONS], // out[N..2N]: partitioned tagged

    // ── Params ─────────────────────────────────────────────────
    num_partitions: u16,

    // ── Metrics ────────────────────────────────────────────────
    proposals_routed_untagged: u32,
    proposals_routed_tagged: u32,
    proposals_dropped: u32,
    /// Proposals routed by proposer-supplied shard id (the keyed path).
    proposals_routed_keyed: u32,
    /// Proposals routed by hashing the body. Non-zero on a
    /// multi-partition graph means some proposer supplies no routing
    /// key, and its traffic is not stably placed.
    proposals_body_hashed: u32,

    // ── Scratch ────────────────────────────────────────────────
    msg_buf: [u8; PROPOSAL_BUF],
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
        if s.num_partitions == 0 {
            s.num_partitions = 1;
        }
        if (s.num_partitions as usize) > MAX_ROUTED_PARTITIONS {
            dev_log(sys, 1, b"[prtn] num_partitions above K_MAX; clamped".as_ptr(), 40);
            s.num_partitions = MAX_ROUTED_PARTITIONS as u16;
        }

        dev_log(sys, 3, b"[prtn] init".as_ptr(), 11);
        0
    }
}

/// Baseline placement: a virtual shard's partition when the control
/// plane has not said otherwise.
///
/// The shard space (`wire::VIRTUAL_SHARDS`) is fixed for the life of a
/// cluster; the partition count is not. A modulo keeps routing *stable
/// per key* — the property the body hash never had.
#[inline]
fn baseline_partition(shard_id: u32, num_partitions: u16) -> u16 {
    // `.max(1)` keeps rustc from emitting a rem_by_zero panic landing
    // pad — module_new clamps to >=1 already, but the optimizer can't
    // see across module boundaries.
    (shard_id % num_partitions.max(1) as u32) as u16
}

/// Where a shard's LOG lives: `shard % num_partitions`, always.
///
/// There is deliberately no override here. The control-plane shard map
/// (`prg_id = shard_map[shard_id]`) names the PRG that SERVES a shard,
/// and PRG and raft partition are separate namespaces: `prg_count`
/// follows the node count while `num_partitions` is a graph parameter.
/// Applying an ownership decision as a partition would send a shard's
/// writes to a group holding none of its history. Ownership is answered
/// on the routing stream by `edge_routing_core`'s `EdgeMap`; this router
/// answers only where the LOG lives, which is the question its position
/// in the graph lets it answer.
#[inline]
fn shard_to_partition(s: &ModuleState, shard_id: u32) -> u16 {
    baseline_partition(shard_id, s.num_partitions)
}

/// Pick the output port for a partition, falling back to out[0] of
/// the same family if the per-partition port isn't wired. Returns -1
/// if no port is available.
#[inline]
fn pick_chan(table: &[i32; MAX_LOCAL_PARTITIONS], partition_id: u16) -> i32 {
    let idx = (partition_id as usize).min(MAX_LOCAL_PARTITIONS - 1);
    let primary = table[idx];
    if primary >= 0 {
        primary
    } else {
        table[0]
    }
}

/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn outputs_writable(
    sys: &SyscallTable,
    table: &[i32; MAX_LOCAL_PARTITIONS],
    num_partitions: u16,
) -> bool {
    for pid in 0..num_partitions.max(1) {
        let chan = pick_chan(table, pid);
        if chan < 0 {
            continue;
        }
        if !wire_channels::writable(sys, chan) {
            return false;
        }
    }
    true
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
            // Writability gate BEFORE consume — see outputs_writable.
            if !outputs_writable(sys, &s.out_untagged, s.num_partitions) {
                break;
            }
            let Some((msg_type, plen)) =
                wire_channels::next_msg(sys, s.in_proposals, &mut s.msg_buf)
            else {
                break;
            };
            let plen = plen as usize;

            // Keyed: [shard_id:u32 LE][body]. Unkeyed: [body].
            // Both forward as a plain MSG_CLIENT_PROPOSAL, so consensus
            // sees one shape.
            let (partition_id, fwd_off) = match msg_type {
                wire::MSG_CLIENT_PROPOSAL_KEYED => {
                    let Some((shard_id, off)) = wire::decode_keyed_proposal(&s.msg_buf[..plen])
                    else {
                        continue;
                    };
                    if plen == off {
                        continue;
                    }
                    s.proposals_routed_keyed = s.proposals_routed_keyed.wrapping_add(1);
                    (shard_to_partition(s, shard_id), off)
                }
                wire::MSG_CLIENT_PROPOSAL => {
                    if plen == 0 {
                        continue;
                    }
                    s.proposals_body_hashed = s.proposals_body_hashed.wrapping_add(1);
                    let shard = wire::shard_for_key(wire::fnv1a_64(&s.msg_buf[..plen]));
                    (shard_to_partition(s, shard), 0)
                }
                _ => continue,
            };

            let chan = pick_chan(&s.out_untagged, partition_id);
            if chan < 0 {
                s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                continue;
            }
            let wrote = wire_channels::channel_write_partitioned(
                sys,
                chan,
                partition_id,
                wire::MSG_CLIENT_PROPOSAL,
                &s.msg_buf[fwd_off..plen],
            );
            if wrote <= 0 {
                // The pre-consume gate polled writable, but poll(OUT)
                // only promises ">=1 byte free" and the atomic write
                // refused. Residual, counted — never silent.
                s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                continue;
            }
            s.proposals_routed_untagged = s.proposals_routed_untagged.wrapping_add(1);
        }

        // Tagged proposals (in[1]) — payload is `[correlation_id:u64 LE][body]`.
        // Hash the body (excluding the correlation prefix) so two
        // clients tagging the same body land on the same partition,
        // and the partition assignment is independent of the
        // correlation_id allocation policy.
        if s.in_proposals_tagged >= 0 {
            for _ in 0..16 {
                // Writability gate BEFORE consume — see outputs_writable.
                if !outputs_writable(sys, &s.out_tagged, s.num_partitions) {
                    break;
                }
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_proposals_tagged, &mut s.msg_buf)
                else {
                    break;
                };
                let plen = plen as usize;

                // Keyed: [shard_id:u32][correlation_id:u64][body].
                // Unkeyed: [correlation_id:u64][body]. Both forward as a
                // plain MSG_CLIENT_PROPOSAL whose payload still starts
                // with the correlation_id, which consensus strips on
                // the way into its batch.
                let (partition_id, fwd_off) = match msg_type {
                    wire::MSG_CLIENT_PROPOSAL_KEYED => {
                        let Some((shard_id, off)) = wire::decode_keyed_proposal(&s.msg_buf[..plen])
                        else {
                            continue;
                        };
                        if plen < off + wire::TAGGED_PROPOSAL_HDR {
                            continue;
                        }
                        s.proposals_routed_keyed = s.proposals_routed_keyed.wrapping_add(1);
                        (shard_to_partition(s, shard_id), off)
                    }
                    wire::MSG_CLIENT_PROPOSAL => {
                        if plen < wire::TAGGED_PROPOSAL_HDR {
                            continue;
                        }
                        s.proposals_body_hashed = s.proposals_body_hashed.wrapping_add(1);
                        let shard = wire::shard_for_key(wire::fnv1a_64(
                            &s.msg_buf[wire::TAGGED_PROPOSAL_HDR..plen],
                        ));
                        (shard_to_partition(s, shard), 0)
                    }
                    _ => continue,
                };

                let chan = pick_chan(&s.out_tagged, partition_id);
                if chan < 0 {
                    s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                    continue;
                }
                // Forward the tagged payload as-is (correlation_id +
                // body), wrapped in the partitioned envelope. The
                // recipient (consensus.proposals_partitioned_tagged)
                // strips the correlation prefix on the way into its
                // batch.
                let wrote = wire_channels::channel_write_partitioned(
                    sys,
                    chan,
                    partition_id,
                    wire::MSG_CLIENT_PROPOSAL,
                    &s.msg_buf[fwd_off..plen],
                );
                if wrote <= 0 {
                    // Residual: gate polled writable but the atomic
                    // write refused (poll(OUT) = ">=1 byte free").
                    s.proposals_dropped = s.proposals_dropped.wrapping_add(1);
                    continue;
                }
                s.proposals_routed_tagged = s.proposals_routed_tagged.wrapping_add(1);
            }
        }

        0
    }
}
