//! Peer Router — Multi-peer connection routing for Raft clusters.
//!
//! Sits on the cleartext side of the foundation tls module. Routes
//! inbound connections to either the gateway (clients) or
//! per-partition consensus instances (peers) based on an
//! identity handshake plus a partition_id stamped into the on-wire
//! envelope. Outbound messages from consensus arrive as
//! 6-byte routed-partitioned frames (`[target:u8][partition_id:u16 LE]
//! [msg_type:u8][len:u16 LE]`) and are forwarded to the named peer with
//! the 5-byte partitioned envelope `[partition_id:u16 LE][msg_type:u8]
//! [len:u16 LE]` on the wire.
//!
//! Graph position:
//!   ip ↔ tls (foundation) ↔ peer_router ↔ { gateway,
//!                                           consensus_pN }
//!
//! Ports:
//!   net_in      (in[0]):  cleartext from tls (net_proto events)
//!   peer_tx     (in[1]):  routed-partitioned outbound from
//!                         consensus.rpc_out (votes, AE, heartbeats)
//!   repl_tx     (in[2]):  routed-partitioned outbound from
//!                         consensus.net_out (AE bodies, snapshot
//!                         chunks)
//!   client_resp (in[3]):  slot-tagged responses from the gateway
//!   net_out     (out[0]): cleartext to tls (net_proto commands)
//!   cleartext   (out[1]): non-Raft client data → gateway
//!   peer_rx     (out[2]): MSG_APPEND_ENTRIES_RESP frames →
//!                         consensus_pN.ack (each instance's
//!                         replicator component filters by its own
//!                         partition_id; fluxor inserts a tee when
//!                         more than one consumer is wired in)
//!   raft_rpc    (out[3]): MSG_APPEND_ENTRIES / MSG_REQUEST_VOTE /
//!                         MSG_PRE_VOTE / MSG_HEARTBEAT (and their
//!                         _RESP siblings other than AE_RESP) →
//!                         consensus_pN.rpc (each filters by
//!                         partition_id)

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

#[path = "../../common/types.rs"]
mod types;

#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use types::*;

// Connection slot table. Sized to hold every concurrent peer link plus
// all simultaneous client connections — quantum fronts this router with
// an MQTT/AMQP/Kafka broker where many clients connect at once, so a
// raft-cluster-sized table (≈ a handful of peers) starves clients: once
// the table fills, alloc_conn drops NMSG_ACCEPT for the overflow conns
// and those clients never get a CONNACK. 64 covers a 7-node cluster's
// peer links with ample client headroom.
const MAX_CONNS: usize = 64;
// Must hold the largest frame on ANY lane through this module:
// peer side, a full proposal batch (2 KiB) plus AE/envelope headers;
// client side, the largest single client response (Kafka Fetch builds
// up to ~7.7 KiB against the 8 KiB channel ceiling). Undersizing this
// silently drops frames at every hop (channel_read_msg discards
// oversized payloads; encoders return 0) — followers wedge on the
// replication path, clients time out on the response path. 8192
// matches CHANNEL_BUFFER_SIZE: nothing larger can transit a channel.
const BUF_SIZE: usize = 8192;
// Route-lane frame budget: the largest frame any peer lane carries — a
// batched AppendEntries (2 KiB proposal batch) plus AE/envelope
// headers, and snapshot chunks. `route_outbound_chan`'s copy, the
// inbound NMSG_DATA copy, the gateway-facing MSG_CLIENT_FRAME tagging
// AND `send_to_conn`'s staging buffer are all sized by THIS const: a
// smaller cap anywhere on the path silently drops or truncates exactly
// the frames that matter. The gateway's `surface::msg_buf`
// (`1 + ROUTE_FRAME_MAX`) is the matching receive bound.
const ROUTE_FRAME_MAX: usize = 4096;
// send_to_conn staging: CMD_SEND `[conn_id:u16 LE]` + 5-byte
// partitioned envelope + route-budget data.
const SEND_STAGE_MAX: usize = 2 + wire::PARTITIONED_HDR + ROUTE_FRAME_MAX;
const METRICS_INTERVAL_MS: u64 = 1000;
const RECONNECT_MS: u64 = 2000;
/// A `connected` peer silent this long is deemed a dead/half-open link and
/// torn down for reconnection. Held WELL above the Raft heartbeat/election
/// cadence so a healthy peer is never dropped — and deliberately generous
/// (15 s) so a node that's merely slow to service its net input under load /
/// a scheduling stall is NOT mistaken for a dead link. A too-eager timeout
/// causes counterproductive reconnect churn precisely when a starved node can
/// least afford the CPU. Genuine link death is mostly caught immediately by
/// the transport's `NMSG_CLOSED`; this timeout only backstops the SILENT
/// half-open case the transport never reports, where a 15–30 s recovery is
/// perfectly acceptable.
const PEER_LIVENESS_MS: u64 = 15_000;

/// Counter: frames this router dropped (oversize chunk / route frame /
/// response). Shared id: `wire::metric_ids::PEER_FRAMES_DROPPED`.
const METRIC_PEER_FRAMES_DROPPED: u16 = wire::metric_ids::PEER_FRAMES_DROPPED;

// Net protocol (same as ip/tls)
define_params! {
    ModuleState;

    1, self_id, u8, 0
        => |s, d, len| { s.self_id = p_u8(d, len, 0, 0); };

    2, peer_count, u8, 0
        => |s, d, len| { s.peer_count = p_u8(d, len, 0, 0); };

    3, listen_port, u16, 9090
        => |s, d, len| { s.listen_port = p_u16(d, len, 0, 9090); };

    4, peer0_port, u16, 0
        => |s, d, len| { configure_peer(s, 0, p_u16(d, len, 0, 0)); };

    5, peer1_port, u16, 0
        => |s, d, len| { configure_peer(s, 1, p_u16(d, len, 0, 0)); };

    6, peer2_port, u16, 0
        => |s, d, len| { configure_peer(s, 2, p_u16(d, len, 0, 0)); };

    7, peer3_port, u16, 0
        => |s, d, len| { configure_peer(s, 3, p_u16(d, len, 0, 0)); };

    8, peer4_port, u16, 0
        => |s, d, len| { configure_peer(s, 4, p_u16(d, len, 0, 0)); };

    // Per-peer IPv4 host overrides for cross-machine clusters
    // (dotted-quad strings). Default (absent / unparseable) stays
    // 127.0.0.1, so single-machine templates work unchanged.
    9, peer0_host, str, 0
        => |s, d, len| { configure_peer_host(s, 0, d, len); };
    10, peer1_host, str, 0
        => |s, d, len| { configure_peer_host(s, 1, d, len); };
    11, peer2_host, str, 0
        => |s, d, len| { configure_peer_host(s, 2, d, len); };
    12, peer3_host, str, 0
        => |s, d, len| { configure_peer_host(s, 3, d, len); };
    13, peer4_host, str, 0
        => |s, d, len| { configure_peer_host(s, 4, d, len); };
}

fn configure_peer(s: &mut ModuleState, idx: usize, port: u16) {
    if idx < MAX_NODES && port > 0 {
        if s.peer_addrs[idx].ip == 0 {
            s.peer_addrs[idx].ip = 0x7F000001; // 127.0.0.1 (host LE)
        }
        s.peer_addrs[idx].port = port;
        s.peer_addrs[idx].configured = true;
    }
}

/// Parse a dotted-quad IPv4 param into the peer's address (host
/// LE byte order, matching `configure_peer`'s localhost default).
/// Order-independent with the port param: a host arriving before
/// OR after peer{N}_port wins over the localhost default.
unsafe fn configure_peer_host(s: &mut ModuleState, idx: usize, d: *const u8, len: usize) {
    if idx >= MAX_NODES || d.is_null() || len == 0 || len > 15 {
        return;
    }
    let mut octets = [0u32; 4];
    let mut oct = 0usize;
    let mut cur: u32 = 0;
    let mut digits = 0u8;
    let mut i = 0usize;
    while i < len {
        let c = *d.add(i);
        match c {
            b'0'..=b'9' => {
                cur = cur * 10 + (c - b'0') as u32;
                digits += 1;
                if digits > 3 || cur > 255 {
                    return;
                }
            }
            b'.' => {
                if digits == 0 || oct >= 3 {
                    return;
                }
                octets[oct] = cur;
                oct += 1;
                cur = 0;
                digits = 0;
            }
            _ => return,
        }
        i += 1;
    }
    if digits == 0 || oct != 3 {
        return;
    }
    octets[3] = cur;
    let ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    if ip == 0 {
        return;
    }
    s.peer_addrs[idx].ip = ip;
}

// net_proto stream contract — the SDK contract mounted through
// `abi.rs` (`target/fluxor/fluxor-abi/sdk/contracts/net/net_proto.rs`)
// is authoritative: every event/command payload leads with
// `conn_id: u16 LE`. Local aliases keep the short names used below.
use abi::contracts::net::net_proto;
const NMSG_ACCEPT: u8 = net_proto::MSG_ACCEPTED;
const NMSG_DATA: u8 = net_proto::MSG_DATA;
const NMSG_CLOSED: u8 = net_proto::MSG_CLOSED;
const NMSG_BOUND: u8 = net_proto::MSG_BOUND;
const NMSG_CONNOK: u8 = net_proto::MSG_CONNECTED;

const NCMD_BIND: u8 = net_proto::CMD_BIND;
const NCMD_SEND: u8 = net_proto::CMD_SEND;
const NCMD_CLOSE: u8 = net_proto::CMD_CLOSE;
const NCMD_CONNECT: u8 = net_proto::CMD_CONNECT;
const NSOCK_STREAM: u8 = net_proto::SOCK_TYPE_STREAM;

// Identity handshake: first message on any peer connection.
// [magic: u16 LE = 0xC1A0] [replica_id: u8]
const ID_MAGIC: u16 = 0xC1A0;
const ID_MSG_LEN: usize = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct Conn {
    /// Transport connection id (NetProto u16 LE on the wire).
    conn_id: u16,
    replica_id: i8, // -1 = unknown (client or pre-identify), 0..6 = peer
    active: bool,
    outbound: bool,   // we initiated
    identified: bool, // identity handshake complete
    /// True once `MSG_PEER_IDENTITY` from the TLS layer pinned this
    /// connection's `replica_id`. Plaintext-handshake bindings are
    /// only honoured when this is false; once a TLS-verified identity
    /// arrives, contradicting plaintext claims are rejected and the
    /// connection is marked unidentifiable (replica_id = -1). See
    /// RFC §5.1.
    tls_verified: bool,
    /// Pre-identify fragment: bytes of a connection's opening data
    /// that arrived in a chunk shorter than the 3-byte handshake
    /// magic. Buffered here (never dropped) until enough bytes exist
    /// to classify the conn as peer or client.
    frag_len: u8,
    frag: [u8; ID_MSG_LEN],
    /// Our identity frame is still owed on this conn (outbound after
    /// CONNOK; inbound reply after the peer identified). The transport
    /// write is atomic and returns 0 on backpressure — a dropped
    /// identity with no retry leaves the peer's side of the handshake
    /// incomplete FOREVER (the peer keeps `connected = false`, redials
    /// on its cadence, and the fresh conn's identity dedup then kills
    /// the previous one — a 2 s dial/close loop that carries no raft
    /// traffic). `flush_pending_identity` retries every step until the
    /// write commits.
    identity_pending: bool,
}

impl Conn {
    const fn empty() -> Self {
        Self {
            conn_id: 0,
            replica_id: -1,
            active: false,
            outbound: false,
            identified: false,
            tls_verified: false,
            frag_len: 0,
            frag: [0; ID_MSG_LEN],
            identity_pending: false,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PeerAddr {
    ip: u32,
    port: u16,
    configured: bool,
    connected: bool,
    last_attempt_ms: u64,
    /// Wall-clock (ms) of the last identified frame received from this peer.
    /// A healthy Raft link always carries traffic within a heartbeat interval
    /// (leader → AE/heartbeat, follower → response), so a `connected` peer that
    /// goes silent past `PEER_LIVENESS_MS` is a dead/half-open link the
    /// transport never reported closed — `reconnect_stale_peers` tears it down
    /// so the existing redial path re-establishes it. Set on identity and on
    /// every received peer frame; meaningless while `!connected`.
    last_rx_ms: u64,
}

impl PeerAddr {
    const fn empty() -> Self {
        Self {
            ip: 0,
            port: 0,
            configured: false,
            connected: false,
            last_attempt_ms: 0,
            last_rx_ms: 0,
        }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels
    net_in: i32,       // in[0]: cleartext net_proto events from tls/ip
    peer_tx: i32,      // in[1]: routed-partitioned outbound from consensus
    repl_tx: i32,      // in[2]: routed-partitioned outbound from replicator
    client_resp: i32,  // in[3]: slot-tagged responses from the gateway
    tls_identity: i32, // in[4]: MSG_PEER_IDENTITY from foundation tls
    net_out: i32,      // out[0]: net_proto commands to tls/ip
    cleartext: i32,    // out[1]: non-Raft client data → gateway
    peer_rx: i32,      // out[2]: AppendEntries acks → replicator_pN
    raft_rpc: i32,     // out[3]: votes/AE/heartbeats → consensus_pN
    out_metrics: i32,  // out[4]: MSG_METRIC_SAMPLE to operations

    // Config
    self_id: ReplicaId,
    peer_count: u8,
    listen_port: u16,
    last_metrics_ms: u64,
    bytes_in: u64,
    bytes_out: u64,

    // Connection table
    conns: [Conn; MAX_CONNS],

    // Peer addresses (indexed by replica_id)
    peer_addrs: [PeerAddr; MAX_NODES],

    // State
    bound: bool,
    /// Set once we've warned that a `MSG_ACCEPTED` arrived WITHOUT a
    /// stamped listener port (`payload_len < 4`). On a shared
    /// linux_net/ip provider that means we cannot tell our own client
    /// conns from another anchor's (e.g. the operations HTTP diagnostic
    /// port) and fall back to claiming everything — which silently
    /// misroutes the other anchor's bytes here as bogus client
    /// proposals. The modern provider stamps the port (fluxor
    /// `c8331d4`); seeing this warning means the runtime is stale or
    /// a legacy provider is in use. Warn once, not per-accept.
    legacy_accept_warned: bool,

    /// Retained inbound peer chunk whose destination channel could not
    /// accept it (length 0 = empty). `process_net_events` stops
    /// draining while this is occupied so the destination's continuous
    /// framed byte stream never loses or reorders a chunk mid-stream.
    inb_stash_len: u16,
    inb_stash_dest: i32,
    /// Retained client-response CMD_SEND payload awaiting net_out
    /// space (length 0 = empty). Also the staging buffer for every
    /// response frame, so the hot path never re-zeroes an 8 KiB stack
    /// buffer per iteration.
    resp_stash_len: u16,
    /// Frames dropped on this module's routing paths (oversize inbound
    /// chunk, oversize route frame, oversize response). Exported each
    /// metrics interval so the loss is never silent.
    frames_dropped: u32,
    inb_stash: [u8; ROUTE_FRAME_MAX],
    resp_stash: [u8; BUF_SIZE],

    buf: [u8; BUF_SIZE],
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

        s.net_in = in_chan;
        s.net_out = out_chan;
        s.peer_tx = dev_channel_port(sys, 0, 1);
        s.repl_tx = dev_channel_port(sys, 0, 2);
        s.client_resp = dev_channel_port(sys, 0, 3);
        s.tls_identity = dev_channel_port(sys, 0, 4);
        s.cleartext = dev_channel_port(sys, 1, 1);
        s.peer_rx = dev_channel_port(sys, 1, 2);
        s.raft_rpc = dev_channel_port(sys, 1, 3);
        s.out_metrics = dev_channel_port(sys, 1, 4);

        // Defaults + TLV param parsing
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Peer addresses are not yet configurable via TLV — they'll be
        // added as a blob param. For now, multi-node requires manual
        // configuration or a discovery mechanism.

        for i in 0..MAX_CONNS {
            s.conns[i] = Conn::empty();
        }
        s.inb_stash_len = 0;
        s.inb_stash_dest = -1;
        s.resp_stash_len = 0;
        s.frames_dropped = 0;

        dev_log(sys, 3, b"[pr] init".as_ptr(), 9);
        0
    }
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
        let now = dev_millis(sys);

        if !s.bound {
            try_bind(s, sys);
        }
        // Tear down any silently-dead peer link BEFORE redialing, so the
        // reconnect happens in the same step the staleness is detected.
        reconnect_stale_peers(s, sys, now);
        // Retry identity frames that hit transport backpressure — a
        // half-done handshake never completes on its own.
        flush_pending_identity(s, sys);
        connect_peers(s, sys, now);
        // Drain TLS identity bindings BEFORE processing inbound net
        // events so a per-connection identity is in place by the time
        // any in-band handshake arrives. See RFC §5.1.
        drain_tls_identity(s, sys);
        process_net_events(s, sys, now);
        // Second flush, after inbound processing: an identity owed by
        // a handshake that completed THIS step would otherwise stay
        // pending until the next one, and routing below skips a conn
        // whose identity is still owed — so the frames it drops would
        // be dropped for a whole step longer than necessary.
        flush_pending_identity(s, sys);
        route_outbound_chan(s, sys, s.peer_tx);
        route_outbound_chan(s, sys, s.repl_tx);
        route_client_responses(s, sys);
        emit_metrics(s, sys, now);

        0
    }
}

/// Emit the open-connection gauge as a typed sample (RFC §4.2/§4.3).
/// Node-level module, so partition_id is 0. Dropped under backpressure.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.out_metrics < 0 {
        return;
    }
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS {
        return;
    }
    s.last_metrics_ms = now;

    let mut open: i64 = 0;
    for c in s.conns.iter() {
        if c.active {
            open += 1;
        }
    }
    let mid = wire::SOURCE_ID_PEER_ROUTER;
    let samples: [(u16, u8, i64); 4] = [
        (
            wire::metric_ids::PEER_CONNECTIONS_OPEN,
            wire::METRIC_KIND_GAUGE,
            open,
        ),
        (
            wire::metric_ids::PEER_BYTES_IN,
            wire::METRIC_KIND_COUNTER,
            s.bytes_in as i64,
        ),
        (
            wire::metric_ids::PEER_BYTES_OUT,
            wire::METRIC_KIND_COUNTER,
            s.bytes_out as i64,
        ),
        (
            METRIC_PEER_FRAMES_DROPPED,
            wire::METRIC_KIND_COUNTER,
            s.frames_dropped as i64,
        ),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            break;
        }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, 0, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_tls_identity(s: &mut ModuleState, sys: &SyscallTable) {
    if s.tls_identity < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.tls_identity, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.tls_identity, &mut s.buf);
        if msg_type != wire::MSG_PEER_IDENTITY {
            continue;
        }
        let pl = plen as usize;
        let (conn_id, replica_id, verified, _svid_off) =
            match wire::decode_peer_identity(&s.buf[..pl]) {
                Some(v) => v,
                None => continue,
            };
        // Find the matching connection slot.
        // NOTE: MSG_PEER_IDENTITY (clustor-internal wire format) still
        // carries a u8 conn id; the transport's u16 ids above 255
        // cannot be matched by the TLS layer until that format widens.
        let mut slot_idx: Option<usize> = None;
        for (i, c) in s.conns.iter().enumerate() {
            if c.active && c.conn_id == conn_id as u16 {
                slot_idx = Some(i);
                break;
            }
        }
        let Some(i) = slot_idx else { continue };
        let c = &mut s.conns[i];
        if replica_id == 0xFF {
            // TLS layer revoked identity (e.g. mid-session
            // re-handshake mismatch). Strip the binding.
            c.replica_id = -1;
            c.identified = false;
            c.tls_verified = false;
            dev_log(sys, 2, b"[pr] tls revoked".as_ptr(), 16);
            continue;
        }
        if (replica_id as usize) >= MAX_NODES {
            dev_log(sys, 2, b"[pr] tls bad rid".as_ptr(), 16);
            continue;
        }
        c.replica_id = replica_id as i8;
        c.identified = true;
        c.tls_verified = verified;
        dev_log(sys, 3, b"[pr] tls bound".as_ptr(), 14);
    }
}

// ── Bind ────────────────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn try_bind(s: &mut ModuleState, sys: &SyscallTable) {
    if s.net_out < 0 {
        return;
    }

    // CMD_BIND payload: [port: u16 LE] (no sock_type — linux_net expects just port)
    let pb = s.listen_port.to_le_bytes();
    net_write_frame(
        sys,
        s.net_out,
        NCMD_BIND,
        pb.as_ptr(),
        2,
        s.buf.as_mut_ptr(),
        BUF_SIZE,
    );
    s.bound = true;
}

// ── Connect to peers ────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn connect_peers(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.net_out < 0 {
        return;
    }

    for i in 0..MAX_NODES {
        if !s.peer_addrs[i].configured || s.peer_addrs[i].connected {
            continue;
        }
        // DIAL-DIRECTION RULE: only the lower self_id dials; the higher
        // accepts. If both nodes dial each other, the pair holds TWO
        // TCP links, and the identity dedup ("keep one, close the rest
        // with this replica_id") runs independently on each node — each
        // side can keep the OPPOSITE link, so every frame lands on a
        // link the receiver already closed and the pair loses all
        // cross-traffic (no heartbeats → split-brain). One dialer =
        // one link = no dedup race.
        if (i as u8) <= s.self_id {
            continue;
        }
        if now.wrapping_sub(s.peer_addrs[i].last_attempt_ms) < RECONNECT_MS {
            continue;
        }
        s.peer_addrs[i].last_attempt_ms = now;

        let poll = (sys.channel_poll)(s.net_out, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            return;
        }

        // CMD_CONNECT payload: [sock_type:1] [ip:4 LE] [port:2 LE]
        let mut payload = [0u8; 7];
        payload[0] = NSOCK_STREAM;
        payload[1..5].copy_from_slice(&s.peer_addrs[i].ip.to_le_bytes());
        payload[5..7].copy_from_slice(&s.peer_addrs[i].port.to_le_bytes());
        net_write_frame(
            sys,
            s.net_out,
            NCMD_CONNECT,
            payload.as_ptr(),
            7,
            s.buf.as_mut_ptr(),
            BUF_SIZE,
        );
        dev_log(&*s.syscalls, 3, b"[pr] connecting".as_ptr(), 15);
    }
}

/// Ask the transport to close a connection (best-effort) so its fd is freed.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines per
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn close_conn(s: &mut ModuleState, sys: &SyscallTable, conn_id: u16) {
    if s.net_out < 0 {
        return;
    }
    let poll = (sys.channel_poll)(s.net_out, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return;
    }
    // CMD_CLOSE payload: [conn_id:u16 LE]
    let payload = conn_id.to_le_bytes();
    net_write_frame(
        sys,
        s.net_out,
        NCMD_CLOSE,
        payload.as_ptr(),
        2,
        s.buf.as_mut_ptr(),
        BUF_SIZE,
    );
}

/// Tear down peer links that are `connected` but have received no traffic for
/// `PEER_LIVENESS_MS` — a half-open / silently-dead connection the transport
/// never reported closed (no `NMSG_CLOSED`). Closing the conn slot(s) and
/// clearing `connected` lets `connect_peers` redial on the next pass, so a
/// node recovers from a transient link drop without an external restart.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines per
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn reconnect_stale_peers(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    for i in 0..MAX_NODES {
        if i == s.self_id as usize {
            continue;
        }
        if !s.peer_addrs[i].configured || !s.peer_addrs[i].connected {
            continue;
        }
        if now.wrapping_sub(s.peer_addrs[i].last_rx_ms) <= PEER_LIVENESS_MS {
            continue;
        }

        // Silent past the liveness window → dead link. Close every conn slot
        // bound to this peer (inbound and/or outbound) and free it so a fresh
        // dial + identity handshake re-establishes the binding cleanly.
        for slot in 0..MAX_CONNS {
            if s.conns[slot].active && s.conns[slot].replica_id == i as i8 {
                close_conn(s, sys, s.conns[slot].conn_id);
                s.conns[slot] = Conn::empty();
            }
        }
        s.peer_addrs[i].connected = false;
        // Redial promptly: clear the backoff so connect_peers dials this pass
        // rather than waiting out a stale RECONNECT_MS window from the last dial.
        s.peer_addrs[i].last_attempt_ms = now.wrapping_sub(RECONNECT_MS);
        {
            let age_s = (now.wrapping_sub(s.peer_addrs[i].last_rx_ms) / 1000) as u32;
            let mut m = *b"[pr] stale p=? age=????s";
            m[13] = b'0' + (i as u8 % 10);
            let mut x = age_s % 10000;
            for k in (0..4).rev() {
                m[19 + k] = b'0' + (x % 10) as u8;
                x /= 10;
            }
            dev_log(&*s.syscalls, 2, m.as_ptr(), m.len());
        }
    }
}

// ── Inbound event processing ────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_net_events(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.net_in < 0 {
        return;
    }

    // A retained chunk goes out FIRST, and no further inbound events
    // are drained until it does: consumers parse a continuous framed
    // stream, so reordering or skipping a chunk desyncs them for good.
    if !flush_inbound_stash(s, sys) {
        return;
    }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.net_in, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }

        // Read one net_proto TLV frame: [msg_type:1] [len:2 LE] [payload]
        let (event, payload_len) = net_read_frame(sys, s.net_in, s.buf.as_mut_ptr(), BUF_SIZE);
        if event == 0 {
            break;
        }

        // payload starts at buf[3]; every frame leads with the
        // connection id as u16 LE (NetProto contract).
        let conn_id = if payload_len >= 2 {
            u16::from_le_bytes([s.buf[NET_FRAME_HDR], s.buf[NET_FRAME_HDR + 1]])
        } else {
            0
        };

        match event {
            NMSG_ACCEPT => {
                // payload: [conn_id: u16 LE][local_port: u16 LE]
                //
                // We share `net_in` (linux_net / ip `net_out`) with the
                // other anchors on this node — wave's `http` module binds
                // the diagnostic port on the same provider. The provider
                // tees every MSG_ACCEPTED to all anchors and stamps the
                // accepting listener's port so each anchor claims only
                // the conns its own CMD_BIND accepted (see fluxor
                // `ip::net_send_accepted` / `linux_net` providers). Without
                // this filter peer_router would alloc a slot for a
                // diagnostic HTTP connection and forward its raw HTTP
                // bytes to the gateway as a bogus client proposal.
                let local_port = if payload_len >= 4 {
                    u16::from_le_bytes([s.buf[NET_FRAME_HDR + 2], s.buf[NET_FRAME_HDR + 3]])
                } else {
                    // Legacy providers that omit the port: claim as before.
                    // On a shared provider this misroutes other anchors'
                    // conns (e.g. the HTTP diagnostic port) here as bogus client
                    // proposals — warn once so a stale runtime is visible
                    // rather than a silent double-processing bug.
                    if !s.legacy_accept_warned {
                        s.legacy_accept_warned = true;
                        dev_log(
                            sys,
                            2,
                            b"[pr] accept w/o port stamp; stale runtime?".as_ptr(),
                            42,
                        );
                    }
                    s.listen_port
                };
                if payload_len >= 2 && local_port == s.listen_port {
                    reap_conn_id(s, sys, conn_id);
                    if let Some(slot) = alloc_conn(s) {
                        s.conns[slot] = Conn {
                            conn_id,
                            active: true,
                            ..Conn::empty()
                        };
                    }
                }
            }
            NMSG_CONNOK => {
                // Outbound connection established — send identity
                dev_log(sys, 2, b"[pr] dial-ok".as_ptr(), 11);
                if payload_len >= 2 {
                    reap_conn_id(s, sys, conn_id);
                    if let Some(slot) = alloc_conn(s) {
                        s.conns[slot] = Conn {
                            conn_id,
                            active: true,
                            outbound: true,
                            ..Conn::empty()
                        };
                        send_identity(s, sys, slot);
                    }
                }
            }
            NMSG_DATA => {
                // payload: [conn_id: u16 LE] [data...]
                if payload_len < 3 {
                    continue;
                }
                let data_start = NET_FRAME_HDR + 2; // after header + conn_id
                let data_len = payload_len - 2;
                s.bytes_in = s.bytes_in.wrapping_add(data_len as u64); // §4.2 ingress

                // Inbound copy sized for the largest peer frame (batched
                // AppendEntries ≈ 2 KiB + headers). A chunk over the
                // route budget is a contract violation; truncating it
                // poisons the destination's framed byte stream just as
                // surely as losing it — drop the whole chunk and count.
                if data_len > ROUTE_FRAME_MAX {
                    s.frames_dropped = s.frames_dropped.wrapping_add(1);
                    dev_log(sys, 2, b"[pr] oversize chunk".as_ptr(), 19);
                    continue;
                }
                let mut local = [0u8; ROUTE_FRAME_MAX];
                let cl = data_len;
                local[..cl].copy_from_slice(&s.buf[data_start..data_start + cl]);

                let slot = find_conn(s, conn_id);
                if slot >= MAX_CONNS {
                    continue;
                }

                if !s.conns[slot].identified {
                    // Try to parse identity message. `true` = a
                    // coalesced tail was stashed for a backpressured
                    // destination: stop draining so the stream stays
                    // continuous (same rule as the stash below).
                    if handle_identity(s, sys, slot, &local[..cl], now) {
                        break;
                    }
                } else {
                    // Route based on replica_id
                    let rid = s.conns[slot].replica_id;
                    if rid >= 0 && (rid as usize) < MAX_NODES {
                        // Liveness: this peer's link is carrying traffic.
                        s.peer_addrs[rid as usize].last_rx_ms = now;
                        // Peer traffic: parse 5-byte partitioned envelope
                        // [partition_id:u16 LE][msg_type:u8][len:u16 LE]
                        // - APPEND_ENTRIES_RESP        → peer_rx (replicator_pN)
                        // - Other Raft control RPCs    → raft_rpc (consensus_pN)
                        // - Anything else from a peer  → drop (untrusted shape)
                        if cl < wire::PARTITIONED_HDR {
                            continue;
                        }
                        let peer_msg_type = local[2];
                        let dest = peer_dest(s, peer_msg_type);

                        if dest >= 0 {
                            let p = (sys.channel_poll)(dest, 0x02);
                            let wrote = if p > 0 && (p as u32 & 0x02) != 0 {
                                (sys.channel_write)(dest, local.as_ptr(), cl)
                            } else {
                                0
                            };
                            if wrote != cl as i32 {
                                // Destination can't take the chunk right
                                // now (poll(OUT) only promises ">=1 byte
                                // free" and the atomic write refused, or
                                // the poll itself failed). Retain it and
                                // stop draining net_in: the destination
                                // parses a continuous framed stream, so
                                // skipping one chunk desyncs it for good.
                                s.inb_stash[..cl].copy_from_slice(&local[..cl]);
                                s.inb_stash_len = cl as u16;
                                s.inb_stash_dest = dest;
                                break;
                            }
                        }
                    } else {
                        // Client traffic → gateway. Frame each record as
                        // a MSG_CLIENT_FRAME envelope so records from
                        // different conns don't coalesce on the byte
                        // FIFO (see wire::MSG_CLIENT_FRAME). The 1-byte
                        // tag is CLUSTOR-INTERNAL: it carries the SLOT
                        // INDEX (the u16 transport conn id does not fit)
                        // and route_client_responses maps it back.
                        //
                        // Sized to pass the full inbound copy
                        // (`ROUTE_FRAME_MAX`); the gateway's
                        // `surface::msg_buf` is `1 + ROUTE_FRAME_MAX` and
                        // channel_read_msg silently discards anything
                        // larger, so the two bounds move together.
                        if s.cleartext >= 0 && cl <= ROUTE_FRAME_MAX {
                            let mut tagged = [0u8; 1 + ROUTE_FRAME_MAX];
                            tagged[0] = slot as u8;
                            tagged[1..1 + cl].copy_from_slice(&local[..cl]);
                            wire_channels::channel_write_msg(
                                sys,
                                s.cleartext,
                                wire::MSG_CLIENT_FRAME,
                                &tagged[..1 + cl],
                            );
                        }
                    }
                }
            }
            NMSG_CLOSED => {
                dev_log(sys, 2, b"[pr] net-closed".as_ptr(), 15);
                {
                    // Attribute peer-link closes: an anonymous
                    // net-closed is undiagnosable when a reconnect
                    // misbehaves (this arm also fires for every HTTP
                    // client close on shared-transport graphs).
                    let slot0 = find_conn(s, conn_id);
                    if slot0 < MAX_CONNS && s.conns[slot0].replica_id >= 0 {
                        let mut m = *b"[pr] peer closed p=?";
                        m[19] = b'0' + (s.conns[slot0].replica_id as u8 % 10);
                        dev_log(sys, 3, m.as_ptr(), m.len());
                    }
                }
                if payload_len >= 2 {
                    let slot = find_conn(s, conn_id);
                    if slot < MAX_CONNS {
                        let rid = s.conns[slot].replica_id;
                        // Client socket closed: tell the app layer so it can
                        // release per-connection state (protocol_router sniff,
                        // codec reassembly, session consumers/group members).
                        // Peers (rid >= 0) are handled by the Raft liveness
                        // machinery below, not this notice. The gateway-facing
                        // 1-byte tag is the SLOT INDEX (clustor-internal),
                        // matching the MSG_CLIENT_FRAME tagging above.
                        if rid < 0 && s.cleartext >= 0 {
                            wire_channels::channel_write_msg(
                                sys,
                                s.cleartext,
                                wire::MSG_CONN_CLOSED,
                                &[slot as u8],
                            );
                        }
                        s.conns[slot] = Conn::empty();
                        // Only mark the peer disconnected if NO other
                        // identified link to it survives. `handle_identity`'s
                        // dedup routinely closes a superseded DUPLICATE link
                        // the instant the live one identifies; clearing
                        // `connected` unconditionally on that close made
                        // `connect_peers` redial into a fresh duplicate, which
                        // dedup then closed too — a self-sustaining churn loop
                        // that floods the shared linux_net net_out tee /
                        // net_in merge and starves the client anchors (redis
                        // unreachable on busy/dialing nodes). Keeping
                        // `connected` while a live link remains breaks the loop.
                        if rid >= 0 && (rid as usize) < MAX_NODES {
                            let mut still_linked = false;
                            for other in 0..MAX_CONNS {
                                if s.conns[other].active
                                    && s.conns[other].identified
                                    && s.conns[other].replica_id == rid
                                {
                                    still_linked = true;
                                    break;
                                }
                            }
                            if !still_linked {
                                s.peer_addrs[rid as usize].connected = false;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

// ── Identity exchange ───────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn send_identity(s: &mut ModuleState, sys: &SyscallTable, slot: usize) {
    // Mark the identity owed, then try to flush it immediately. The
    // pending flag is what makes the handshake robust: a write that
    // hits transport backpressure is retried every step by
    // `flush_pending_identity` instead of being silently dropped.
    s.conns[slot].identity_pending = true;
    try_send_identity(s, sys, slot);
}

/// One identity write attempt for `slot`. Clears `identity_pending`
/// only when the transport committed the whole frame.
unsafe fn try_send_identity(s: &mut ModuleState, sys: &SyscallTable, slot: usize) {
    if s.net_out < 0 {
        return;
    }

    // CMD_SEND payload: [conn_id:u16 LE] [magic:2 LE] [self_id:1]
    let mut payload = [0u8; 2 + ID_MSG_LEN];
    payload[..2].copy_from_slice(&s.conns[slot].conn_id.to_le_bytes());
    let magic = ID_MAGIC.to_le_bytes();
    payload[2] = magic[0];
    payload[3] = magic[1];
    payload[4] = s.self_id;

    let written = net_write_frame(
        sys,
        s.net_out,
        NCMD_SEND,
        payload.as_ptr(),
        2 + ID_MSG_LEN,
        s.buf.as_mut_ptr(),
        BUF_SIZE,
    );
    if written > 0 {
        s.conns[slot].identity_pending = false;
    }
}

/// Retry every owed identity frame (bounded by MAX_CONNS; almost
/// always a no-op). Runs once per step so a handshake frame dropped
/// under transport backpressure completes on a later step instead of
/// never.
unsafe fn flush_pending_identity(s: &mut ModuleState, sys: &SyscallTable) {
    for slot in 0..MAX_CONNS {
        if s.conns[slot].active && s.conns[slot].identity_pending {
            try_send_identity(s, sys, slot);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn handle_identity(
    s: &mut ModuleState,
    sys: &SyscallTable,
    slot: usize,
    data: &[u8],
    now: u64,
) -> bool {
    if data.is_empty() {
        return false;
    }

    // Classification needs the full 3-byte handshake message. The
    // frame is already consumed, so a first chunk shorter than that is
    // BUFFERED per-conn (never dropped) and classified once the rest
    // arrives; otherwise the conn stays unclassified forever.
    let fl = s.conns[slot].frag_len as usize;
    if fl + data.len() < ID_MSG_LEN {
        s.conns[slot].frag[fl..fl + data.len()].copy_from_slice(data);
        s.conns[slot].frag_len = (fl + data.len()) as u8;
        return false;
    }
    let mut hdr = [0u8; ID_MSG_LEN];
    hdr[..fl].copy_from_slice(&s.conns[slot].frag[..fl]);
    hdr[fl..].copy_from_slice(&data[..ID_MSG_LEN - fl]);
    let total_len = fl + data.len();
    s.conns[slot].frag_len = 0;

    // Classification: the identity message is `[magic:2][replica_id:1]`
    // and a peer sends it as its own frame. On an INBOUND conn only a
    // magic match at EXACTLY that length is a peer handshake — anything
    // longer is client traffic whose first bytes merely collide with
    // the magic (0xA0 0xC1 is a perfectly ordinary start for a binary
    // client record). An OUTBOUND conn is a peer link BY CONSTRUCTION
    // (this module only ever dials configured peer addresses), so a
    // longer first chunk carrying the magic is the peer's identity
    // COALESCED with its first raft frames: TCP segments freely merge
    // the reply with the heartbeat behind it. Accept the identity and
    // route the tail as normal peer data. Classifying such a conn as
    // a client instead strands the handshake — the dialer never sees
    // `connected`, redials forever, and the pair carries no raft
    // traffic at all.
    //
    // The claimed id must be a CONFIGURED peer and not our own. Our
    // own id would bind a slot the liveness reaper skips by
    // construction (`reconnect_stale_peers` passes over `self_id`),
    // leaving an unreapable slot that broadcast routing keeps
    // feeding; an unconfigured id cannot be a peer of this graph at
    // all. Both also narrow the coalesced-length relaxation below to
    // frames that really can be a peer handshake.
    let magic = u16::from_le_bytes([hdr[0], hdr[1]]);
    let claimed = hdr[2];
    let is_peer_identity = magic == ID_MAGIC
        && (claimed as usize) < MAX_NODES
        && claimed != s.self_id
        && s.peer_addrs[claimed as usize].configured
        && (total_len == ID_MSG_LEN || (s.conns[slot].outbound && total_len > ID_MSG_LEN));
    if !is_peer_identity {
        // Not a peer — treat as client (no identity exchange)
        s.conns[slot].identified = true;
        s.conns[slot].replica_id = -1; // client

        // Forward everything that arrived — buffered fragment plus this
        // chunk (it's application data, not identity). Prepend the SLOT
        // INDEX (clustor-internal 1-byte tag; the u16 transport conn id
        // does not fit) for response routing. Frame as MSG_CLIENT_FRAME
        // so concurrent first-data records from different conns stay
        // demarcated on the byte FIFO (see wire::MSG_CLIENT_FRAME).
        //
        // Same `ROUTE_FRAME_MAX` bound as the steady-state path above:
        // the gateway's `surface::msg_buf` is `1 + ROUTE_FRAME_MAX` and
        // channel_read_msg silently discards a larger payload, so a
        // reassembled record past the budget is dropped and COUNTED
        // here rather than vanishing downstream.
        if s.cleartext >= 0 {
            if total_len > ROUTE_FRAME_MAX {
                s.frames_dropped = s.frames_dropped.wrapping_add(1);
                dev_log(sys, 2, b"[pr] oversize first".as_ptr(), 19);
                return false;
            }
            let mut tagged = [0u8; 1 + ROUTE_FRAME_MAX];
            tagged[0] = slot as u8;
            tagged[1..1 + fl].copy_from_slice(&hdr[..fl]);
            tagged[1 + fl..1 + total_len].copy_from_slice(data);
            wire_channels::channel_write_msg(
                sys,
                s.cleartext,
                wire::MSG_CLIENT_FRAME,
                &tagged[..1 + total_len],
            );
        }
        return false;
    }

    let peer_id = hdr[2];

    // RFC §5.1: a TLS-verified binding takes precedence over the
    // plaintext handshake. If the in-band claim contradicts a
    // previously TLS-pinned identity, drop the binding and mark the
    // connection unidentifiable so subsequent traffic can't route as
    // a Raft peer.
    if s.conns[slot].tls_verified {
        if s.conns[slot].replica_id != peer_id as i8 {
            dev_log(&*s.syscalls, 2, b"[pr] tls/plain mismatch".as_ptr(), 23);
            s.conns[slot].replica_id = -1;
            s.conns[slot].identified = false;
            return false;
        }
        // Match — keep the existing (TLS-verified) binding.
    } else {
        s.conns[slot].replica_id = peer_id as i8;
        s.conns[slot].identified = true;
    }
    s.peer_addrs[peer_id as usize].connected = true;
    {
        let mut m = *b"[pr] conn up p=?";
        m[15] = b'0' + (peer_id % 10);
        dev_log(sys, 2, m.as_ptr(), m.len());
    }
    // Fresh link — start the liveness window now so a just-established peer
    // isn't immediately judged stale before its first data frame.
    s.peer_addrs[peer_id as usize].last_rx_ms = now;

    // Dedupe: this (newest) conn is the live one for the peer. Only
    // one direction is ever in play — `connect_peers` dials strictly
    // upward (`peer_id <= self_id` is skipped), so every slot bound
    // to a given peer here shares one `outbound` value and a pair
    // holds exactly one link. Duplicates therefore mean the OLD conn
    // lingered half-open past a reconnect, and `find_conn_by_replica`
    // (outbound routing) would keep posting AEs into the dead one.
    // Closing every other conn bound to this replica forces routing
    // onto the live conn; TCP is full-duplex, so one conn carries
    // both directions. This is what lets a reconnected follower
    // receive AEs rather than merely complete the handshake.
    //
    // The closing side keeps `connected`: the slot is emptied before
    // the transport's NMSG_CLOSED notice lands, so that arm's
    // `find_conn` misses and never clears the flag — nobody redials
    // into fresh churn.
    for other in 0..MAX_CONNS {
        if other == slot {
            continue;
        }
        if s.conns[other].active && s.conns[other].replica_id == peer_id as i8 {
            close_conn(s, sys, s.conns[other].conn_id);
            s.conns[other] = Conn::empty();
            let mut m = *b"[pr] dedup close p=?";
            m[19] = b'0' + (peer_id % 10);
            dev_log(sys, 3, m.as_ptr(), m.len());
        }
    }

    // If we're the inbound side, reply with our identity
    if !s.conns[slot].outbound {
        send_identity(s, sys, slot);
    }

    dev_log(&*s.syscalls, 3, b"[pr] peer ok".as_ptr(), 12);

    // Coalesced tail after the identity prefix (outbound conns only —
    // inbound identity is exact-length by classification): the peer's
    // first raft frames, merged into the same TCP segment as its
    // identity reply. Route them exactly like steady-state peer data —
    // dropping them here would desync the framed byte stream for good,
    // so a backpressured destination stashes the tail instead (the
    // single-slot inbound stash is empty by invariant while an event
    // is being processed; `true` tells the caller to stop draining).
    let consumed = ID_MSG_LEN - fl;
    if s.conns[slot].outbound && data.len() > consumed {
        let tail_len = data.len() - consumed;
        if tail_len >= wire::PARTITIONED_HDR && tail_len <= ROUTE_FRAME_MAX {
            let dest = peer_dest(s, data[consumed + 2]);
            if dest < 0 {
                // Untrusted frame shape from a peer — same drop policy
                // as the steady-state path, and counted the same way.
                s.frames_dropped = s.frames_dropped.wrapping_add(1);
            }
            if dest >= 0 {
                let p = (sys.channel_poll)(dest, 0x02);
                let wrote = if p > 0 && (p as u32 & 0x02) != 0 {
                    (sys.channel_write)(dest, data.as_ptr().add(consumed), tail_len)
                } else {
                    0
                };
                if wrote != tail_len as i32 {
                    s.inb_stash[..tail_len].copy_from_slice(&data[consumed..]);
                    s.inb_stash_len = tail_len as u16;
                    s.inb_stash_dest = dest;
                    return true;
                }
            }
        } else {
            // A tail too short to classify (a mid-frame TCP split
            // inside the first 5 envelope bytes) or over the route
            // budget cannot be routed, and dropping a partial frame
            // desyncs everything after it on this conn. The liveness
            // reaper cannot rescue us — `last_rx_ms` is refreshed by
            // arriving bytes, not by routed ones, so a desynced link
            // looks alive forever. Tear it down here and let the
            // dialer re-establish a clean stream.
            s.frames_dropped = s.frames_dropped.wrapping_add(1);
            dev_log(sys, 2, b"[pr] tail desync; closing".as_ptr(), 25);
            close_conn(s, sys, s.conns[slot].conn_id);
            s.conns[slot] = Conn::empty();
        }
    }
    false
}

// ── Outbound routing ────────────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn route_outbound_chan(s: &mut ModuleState, sys: &SyscallTable, chan: i32) {
    if chan < 0 || s.net_out < 0 {
        return;
    }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }

        let poll_out = (sys.channel_poll)(s.net_out, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
            break;
        }

        let (target, partition_id, msg_type, plen) =
            wire_channels::channel_read_routed_partitioned(sys, chan, &mut s.buf);
        if plen == 0 && msg_type == 0 {
            break;
        }

        // Copy to stack to release borrow on s.buf. Sized for the
        // largest legal peer frame: an AppendEntries carrying a full
        // proposal batch (2 KiB) plus headers. A frame OVER the budget
        // is dropped whole and counted — truncating it would poison
        // the peer's framed stream.
        let pl = plen as usize;
        if pl > ROUTE_FRAME_MAX {
            s.frames_dropped = s.frames_dropped.wrapping_add(1);
            dev_log(sys, 2, b"[pr] oversize route".as_ptr(), 19);
            continue;
        }
        let mut local = [0u8; ROUTE_FRAME_MAX];
        local[..pl].copy_from_slice(&s.buf[..pl]);

        if target == wire::TARGET_BROADCAST {
            for slot in 0..MAX_CONNS {
                if !s.conns[slot].active || !s.conns[slot].identified {
                    continue;
                }
                if s.conns[slot].replica_id < 0 {
                    continue;
                }
                send_to_conn(s, sys, slot, partition_id, msg_type, &local[..pl]);
            }
        } else {
            let slot = find_conn_by_replica(s, target);
            if slot < MAX_CONNS {
                send_to_conn(s, sys, slot, partition_id, msg_type, &local[..pl]);
            } else {
                // The frame is already off the channel and there is no
                // live link to carry it. Raft re-covers its own RPCs on
                // the next heartbeat, but a snapshot chunk is
                // offset-ordered and never re-sent, so a silent loss
                // here strands an install. Count and say so once per
                // occurrence rather than dropping invisibly.
                s.frames_dropped = s.frames_dropped.wrapping_add(1);
                dev_log(sys, 2, b"[pr] no route to peer".as_ptr(), 21);
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Send data to a peer connection with the 5-byte partitioned wire
/// envelope: `[partition_id:u16 LE][msg_type:u8][len:u16 LE][data]`.
/// Wrapped in a CMD_SEND frame as:
/// CMD_SEND [conn_id:u16 LE] [partition_id:u16] [msg_type:u8] [len:u16 LE] [data]
unsafe fn send_to_conn(
    s: &mut ModuleState,
    sys: &SyscallTable,
    slot: usize,
    partition_id: u16,
    msg_type: u8,
    data: &[u8],
) {
    if s.net_out < 0 {
        return;
    }

    // CMD_SEND payload: [conn_id:u16 LE] [envelope: 5 bytes + data:N]
    // Staged at SEND_STAGE_MAX so the full route budget fits: callers
    // carry up to ROUTE_FRAME_MAX of batched-AE / snapshot-chunk data
    // and the route loop has already consumed the frame. The guard
    // below is residual only — count it, never lose it in silence.
    let envelope_len = wire::PARTITIONED_HDR + data.len();
    let payload_len = 2 + envelope_len;
    let mut payload = [0u8; SEND_STAGE_MAX];
    if payload_len > SEND_STAGE_MAX {
        s.frames_dropped = s.frames_dropped.wrapping_add(1);
        dev_log(sys, 2, b"[pr] oversize send".as_ptr(), 18);
        return;
    }

    payload[..2].copy_from_slice(&s.conns[slot].conn_id.to_le_bytes());
    let pid = partition_id.to_le_bytes();
    payload[2] = pid[0];
    payload[3] = pid[1];
    payload[4] = msg_type;
    let lb = (data.len() as u16).to_le_bytes();
    payload[5] = lb[0];
    payload[6] = lb[1];
    if !data.is_empty() {
        payload[7..7 + data.len()].copy_from_slice(data);
    }
    s.bytes_out = s.bytes_out.wrapping_add(data.len() as u64); // §4.2 egress

    net_write_frame(
        sys,
        s.net_out,
        NCMD_SEND,
        payload.as_ptr(),
        payload_len,
        s.buf.as_mut_ptr(),
        BUF_SIZE,
    );
}

// ── Client response routing ─────────────────────────────────

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Read slot-tagged responses from the gateway and send back to
/// the originating TCP connection.
/// Format: [slot: u8] [msg_type: u8] [len: u16 LE] [payload]
/// The 1-byte tag is CLUSTOR-INTERNAL: it is the connection-table
/// SLOT INDEX this router stamped on the inbound MSG_CLIENT_FRAME
/// (the transport's u16 conn id no longer fits in one byte). It is
/// used only to look the slot up; the outgoing NCMD_SEND carries the
/// slot's REAL u16 LE conn id.
unsafe fn route_client_responses(s: &mut ModuleState, sys: &SyscallTable) {
    if s.client_resp < 0 || s.net_out < 0 {
        return;
    }

    // An ack retained from a previous step goes first; while it can't
    // be flushed nothing new is consumed, so a response read off the
    // gateway channel is never dropped.
    if !flush_resp_stash(s, sys) {
        return;
    }

    // 32/tick: durability acks resolve in bursts (one group fsync
    // covers many publishes), so a tighter quota — not the pipeline —
    // becomes the cap on client response throughput.
    for _ in 0..32 {
        // Egress gate BEFORE consume: net_out must look writable before
        // an ack is taken off the channel. poll(OUT) only promises
        // ">=1 byte free", so the atomic net_write_frame can still
        // refuse — the retained stash below catches that residue.
        let poll_out = (sys.channel_poll)(s.net_out, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
            break;
        }

        let poll = (sys.channel_poll)(s.client_resp, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }

        // Envelope-framed read so back-to-back writes from the
        // codecs / response_mux don't coalesce on the byte FIFO.
        // The msg_type is informational here — peer_router routes
        // every frame the same way (NCMD_SEND of `[conn_id][data]`
        // to the connected client). Future demuxers can dispatch
        // on `_msg_type` if they need to.
        let (_msg_type, plen) = wire_channels::channel_read_msg(sys, s.client_resp, &mut s.buf);
        let len = plen as usize;
        if len < 2 {
            continue;
        }

        // The gateway's 1-byte tag is the slot index we stamped on
        // ingress; resolve it to the live connection's u16 conn id.
        // A stale/out-of-range tag (conn closed since the request)
        // drops the response — there is nowhere valid to send it.
        let slot = s.buf[0] as usize;
        if slot >= MAX_CONNS || !s.conns[slot].active {
            continue;
        }
        let conn_id = s.conns[slot].conn_id;

        // CMD_SEND payload: [conn_id:u16 LE] [data]
        //
        // Staged in the persistent resp_stash — sized to BUF_SIZE, the
        // largest response a channel can carry: any smaller cap
        // silently drops the big client responses (a Kafka Fetch, an
        // MQTT delivery) while small acks still pass. State-owned
        // rather than a stack array so the hot path never re-zeroes
        // 8 KiB per iteration (256 KiB at this loop's 32-frame bound).
        let data_len = len - 1; // strip the 1-byte slot tag
        let payload_len = 2 + data_len; // 2 (conn_id u16 LE) + data
        if NET_FRAME_HDR + payload_len > BUF_SIZE {
            // Cannot ever transit net_write_frame's scratch — a
            // producer bug, counted rather than wedging the stash.
            s.frames_dropped = s.frames_dropped.wrapping_add(1);
            continue;
        }
        s.resp_stash[..2].copy_from_slice(&conn_id.to_le_bytes());
        s.resp_stash[2..payload_len].copy_from_slice(&s.buf[1..len]);
        s.resp_stash_len = payload_len as u16;
        if !flush_resp_stash(s, sys) {
            // net_out refused the atomic write after all; the ack is
            // retained for next step instead of vanishing.
            break;
        }
    }
}

/// Try to send the retained client-response CMD_SEND payload. Returns
/// true when the stash is empty afterwards (nothing retained, or the
/// send just succeeded).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_resp_stash(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let len = s.resp_stash_len as usize;
    if len == 0 {
        return true;
    }
    let n = net_write_frame(
        sys,
        s.net_out,
        NCMD_SEND,
        s.resp_stash.as_ptr(),
        len,
        s.buf.as_mut_ptr(),
        BUF_SIZE,
    );
    if n > 0 {
        s.resp_stash_len = 0;
        true
    } else {
        false
    }
}

/// Try to deliver the retained inbound peer chunk. Returns true when
/// the stash is empty afterwards. `process_net_events` refuses to
/// drain further net events while a chunk is retained, so the
/// destination channel's framed byte stream keeps both order and
/// integrity under backpressure.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn flush_inbound_stash(s: &mut ModuleState, sys: &SyscallTable) -> bool {
    let cl = s.inb_stash_len as usize;
    if cl == 0 {
        return true;
    }
    let dest = s.inb_stash_dest;
    if dest < 0 {
        s.inb_stash_len = 0;
        return true;
    }
    let p = (sys.channel_poll)(dest, 0x02);
    if p <= 0 || (p as u32 & 0x02) == 0 {
        return false;
    }
    let wrote = (sys.channel_write)(dest, s.inb_stash.as_ptr(), cl);
    if wrote == cl as i32 {
        s.inb_stash_len = 0;
        true
    } else {
        false
    }
}

// ── Helpers ─────────────────────────────────────────────────

fn alloc_conn(s: &mut ModuleState) -> Option<usize> {
    for i in 0..MAX_CONNS {
        if !s.conns[i].active {
            return Some(i);
        }
    }
    None
}

/// Reap any slot still holding `conn_id` before registering a NEW
/// transport conn under that id. Transport conn ids are recycled
/// (lowest free slot), and a slot can go stale without an
/// `NMSG_CLOSED` ever landing (event pressure during a proposal
/// burst, a peer killed mid-stream). A stale slot with a recycled id
/// is poison: the identity dedup "close the other conns to this
/// peer" then calls `close_conn` with the ghost's id — which the
/// transport resolves to the FRESH connection and kills it, every
/// redial, indefinitely (the identity refresh keeps the ghost from
/// ever aging past the staleness reaper). The transport never has
/// two live conns under one id, so a collision at registration
/// PROVES the old slot is dead: clear it slot-only — no
/// `close_conn`, the id now belongs to the new conn — and drop the
/// peer's `connected` claim if the ghost was its last identified
/// link, so `connect_peers` may redial for real.
unsafe fn reap_conn_id(s: &mut ModuleState, sys: &SyscallTable, conn_id: u16) {
    for i in 0..MAX_CONNS {
        if !s.conns[i].active || s.conns[i].conn_id != conn_id {
            continue;
        }
        let rid = s.conns[i].replica_id;
        s.conns[i] = Conn::empty();
        // A reaped CLIENT slot must be announced exactly as a normal
        // close is: the gateway keys correlation state, codec
        // reassembly and session membership by the SLOT INDEX we
        // stamp on MSG_CLIENT_FRAME, and `alloc_conn` hands the
        // lowest free index straight back to the next conn. Skipping
        // the notice would let a new client inherit the previous
        // occupant's in-flight state and receive its responses.
        if rid < 0 && s.cleartext >= 0 {
            wire_channels::channel_write_msg(sys, s.cleartext, wire::MSG_CONN_CLOSED, &[i as u8]);
        }
        if rid >= 0 && (rid as usize) < MAX_NODES {
            let mut still_linked = false;
            for other in 0..MAX_CONNS {
                if s.conns[other].active
                    && s.conns[other].identified
                    && s.conns[other].replica_id == rid
                {
                    still_linked = true;
                    break;
                }
            }
            if !still_linked {
                s.peer_addrs[rid as usize].connected = false;
            }
        }
    }
}

fn find_conn(s: &ModuleState, conn_id: u16) -> usize {
    for i in 0..MAX_CONNS {
        if s.conns[i].active && s.conns[i].conn_id == conn_id {
            return i;
        }
    }
    MAX_CONNS
}

/// Destination channel for one peer frame type: replication responses
/// and snapshot streams → `peer_rx`; Raft control RPCs → `raft_rpc`.
/// -1 = untrusted shape from a peer, dropped by the caller. Single
/// source for both the steady-state data path and the
/// coalesced-identity tail path.
fn peer_dest(s: &ModuleState, peer_msg_type: u8) -> i32 {
    match peer_msg_type {
        wire::MSG_APPEND_ENTRIES_RESP
        | wire::MSG_INSTALL_SNAPSHOT_RESP
        | wire::MSG_INSTALL_SNAPSHOT
        | wire::MSG_SNAPSHOT_CHUNK => s.peer_rx,
        wire::MSG_APPEND_ENTRIES
        | wire::MSG_REQUEST_VOTE
        | wire::MSG_REQUEST_VOTE_RESP
        | wire::MSG_PRE_VOTE
        | wire::MSG_PRE_VOTE_RESP
        | wire::MSG_HEARTBEAT
        | wire::MSG_HEARTBEAT_RESP
        // ReadIndex leadership-confirm round (RFC §1.3): follower
        // receives the leader's PROBE, leader receives the follower's
        // RESP — consensus handles both on its rpc input. Omitting
        // these silently killed multi-node linearizable reads (every
        // probe timed out → LIN-BOUND reject). Unexercised until some
        // consumer wires the read fence, which is exactly why the
        // omission survived so long.
        | wire::MSG_READ_INDEX_PROBE
        | wire::MSG_READ_INDEX_PROBE_RESP
        | wire::MSG_TIMEOUT_NOW => s.raft_rpc,
        _ => -1,
    }
}

fn find_conn_by_replica(s: &ModuleState, replica_id: u8) -> usize {
    for i in 0..MAX_CONNS {
        // `identity_pending` gates outbound routing: raft frames must
        // never overtake our identity frame on a fresh conn, or the
        // peer's classifier sees non-identity first bytes and the
        // handshake never completes.
        if s.conns[i].active
            && s.conns[i].identified
            && !s.conns[i].identity_pending
            && s.conns[i].replica_id == replica_id as i8
        {
            return i;
        }
    }
    MAX_CONNS
}
