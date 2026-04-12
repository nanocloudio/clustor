//! Peer Router — Multi-peer connection routing for Raft clusters.
//!
//! Sits on the cleartext side of the foundation tls module. Routes
//! inbound connections to either http_surface (clients) or replicator
//! (peers) based on an identity handshake. Routes outbound messages
//! from raft_engine/replicator to the correct peer connection using
//! the routed envelope target_replica prefix.
//!
//! Graph position:
//!   ip ↔ tls (foundation) ↔ peer_router ↔ { http_surface, replicator }
//!
//! Ports:
//!   net_in    (in[0]): cleartext from tls (net_proto events)
//!   peer_tx   (in[1]): routed outbound from replicator/raft_engine
//!   net_out   (out[0]): cleartext to tls (net_proto commands)
//!   cleartext (out[1]): client data → http_surface
//!   peer_rx   (out[2]): peer data → replicator

#![no_std]

use core::ffi::c_void;

#[path = "../../deps/fluxor/modules/sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../deps/fluxor/modules/sdk/runtime.rs");
include!("../../deps/fluxor/modules/sdk/params.rs");

#[path = "../common/types.rs"]
mod types;

#[path = "../common/wire.rs"]
mod wire;

use types::*;

const MAX_CONNS: usize = 8;
const BUF_SIZE: usize = 2048;
const RECONNECT_MS: u64 = 2000;

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
}

fn configure_peer(s: &mut ModuleState, idx: usize, port: u16) {
    if idx < MAX_NODES && port > 0 {
        s.peer_addrs[idx].ip = 0x7F000001; // 127.0.0.1 in host (LE) byte order
        s.peer_addrs[idx].port = port;
        s.peer_addrs[idx].configured = true;
    }
}

const NMSG_ACCEPT: u8 = 0x01;  // NET_MSG_ACCEPTED in fluxor ip module
const NMSG_DATA: u8 = 0x02;   // NET_MSG_DATA in fluxor ip module
const NMSG_CLOSED: u8 = 0x03;
const NMSG_BOUND: u8 = 0x04;
const NMSG_CONNOK: u8 = 0x05;

const NCMD_BIND: u8 = 0x10;
const NCMD_SEND: u8 = 0x11;
const NCMD_CLOSE: u8 = 0x12;
const NCMD_CONNECT: u8 = 0x13;
const NSOCK_STREAM: u8 = 1;

// Identity handshake: first message on any peer connection.
// [magic: u16 LE = 0xC1A0] [replica_id: u8]
const ID_MAGIC: u16 = 0xC1A0;
const ID_MSG_LEN: usize = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct Conn {
    conn_id: u8,
    replica_id: i8,   // -1 = unknown (client or pre-identify), 0..6 = peer
    active: bool,
    outbound: bool,    // we initiated
    identified: bool,  // identity handshake complete
}

impl Conn {
    const fn empty() -> Self {
        Self { conn_id: 0, replica_id: -1, active: false, outbound: false, identified: false }
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
}

impl PeerAddr {
    const fn empty() -> Self {
        Self { ip: 0, port: 0, configured: false, connected: false, last_attempt_ms: 0 }
    }
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    // Channels
    net_in: i32,        // in[0]: cleartext net_proto events from tls/ip
    peer_tx: i32,       // in[1]: routed outbound from raft_engine (votes/heartbeats)
    repl_tx: i32,       // in[2]: routed outbound from replicator (AppendEntries)
    client_resp: i32,   // in[3]: conn_id-tagged responses from http_surface
    net_out: i32,       // out[0]: net_proto commands to tls/ip
    cleartext: i32,     // out[1]: client data → http_surface
    peer_rx: i32,       // out[2]: peer data → replicator

    // Config
    self_id: ReplicaId,
    peer_count: u8,
    listen_port: u16,

    // Connection table
    conns: [Conn; MAX_CONNS],

    // Peer addresses (indexed by replica_id)
    peer_addrs: [PeerAddr; MAX_NODES],

    // State
    bound: bool,

    buf: [u8; BUF_SIZE],
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
    in_chan: i32, out_chan: i32, _ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<ModuleState>() { return -2; }

        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;

        s.net_in = in_chan;
        s.net_out = out_chan;
        s.peer_tx = dev_channel_port(sys, 0, 1);
        s.repl_tx = dev_channel_port(sys, 0, 2);
        s.client_resp = dev_channel_port(sys, 0, 3);
        s.cleartext = dev_channel_port(sys, 1, 1);
        s.peer_rx = dev_channel_port(sys, 1, 2);

        // Defaults + TLV param parsing
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        // Peer addresses are not yet configurable via TLV — they'll be
        // added as a blob param. For now, multi-node requires manual
        // configuration or a discovery mechanism.

        for i in 0..MAX_CONNS { s.conns[i] = Conn::empty(); }

        dev_log(sys, 3, b"[pr] init".as_ptr(), 9);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;
        let now = dev_millis(sys);

        if !s.bound { try_bind(s, sys); }
        connect_peers(s, sys, now);
        process_net_events(s, sys);
        route_outbound_chan(s, sys, s.peer_tx);
        route_outbound_chan(s, sys, s.repl_tx);
        route_client_responses(s, sys);

        0
    }
}

// ── Bind ────────────────────────────────────────────────────

unsafe fn try_bind(s: &mut ModuleState, sys: &SyscallTable) {
    if s.net_out < 0 { return; }

    // CMD_BIND payload: [port: u16 LE] (no sock_type — linux_net expects just port)
    let pb = s.listen_port.to_le_bytes();
    net_write_frame(sys, s.net_out, NCMD_BIND, pb.as_ptr(), 2,
                    s.buf.as_mut_ptr(), BUF_SIZE);
    s.bound = true;
}

// ── Connect to peers ────────────────────────────────────────

unsafe fn connect_peers(s: &mut ModuleState, sys: &SyscallTable, now: u64) {
    if s.net_out < 0 { return; }

    for i in 0..MAX_NODES {
        if !s.peer_addrs[i].configured || s.peer_addrs[i].connected { continue; }
        if i == s.self_id as usize { continue; }
        if now.wrapping_sub(s.peer_addrs[i].last_attempt_ms) < RECONNECT_MS { continue; }
        s.peer_addrs[i].last_attempt_ms = now;

        let poll = (sys.channel_poll)(s.net_out, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }

        // CMD_CONNECT payload: [sock_type:1] [ip:4 LE] [port:2 LE]
        let mut payload = [0u8; 7];
        payload[0] = NSOCK_STREAM;
        payload[1..5].copy_from_slice(&s.peer_addrs[i].ip.to_le_bytes());
        payload[5..7].copy_from_slice(&s.peer_addrs[i].port.to_le_bytes());
        net_write_frame(sys, s.net_out, NCMD_CONNECT, payload.as_ptr(), 7,
                        s.buf.as_mut_ptr(), BUF_SIZE);
        dev_log(&*s.syscalls, 3, b"[pr] connecting".as_ptr(), 15);
    }
}

// ── Inbound event processing ────────────────────────────────

unsafe fn process_net_events(s: &mut ModuleState, sys: &SyscallTable) {
    if s.net_in < 0 { return; }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.net_in, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        // Read one net_proto TLV frame: [msg_type:1] [len:2 LE] [payload]
        let (event, payload_len) = net_read_frame(sys, s.net_in, s.buf.as_mut_ptr(), BUF_SIZE);
        if event == 0 { break; }
        let len = payload_len + NET_FRAME_HDR;

        // payload starts at buf[3], first byte of payload is conn_id
        let conn_id = if payload_len > 0 { s.buf[NET_FRAME_HDR] } else { 0 };

        match event {
            NMSG_ACCEPT => {
                // payload: [conn_id: u8]
                if payload_len >= 1 {
                    if let Some(slot) = alloc_conn(s) {
                        s.conns[slot] = Conn {
                            conn_id, replica_id: -1, active: true,
                            outbound: false, identified: false,
                        };
                    }
                }
            }
            NMSG_CONNOK => {
                // Outbound connection established — send identity
                if payload_len >= 1 {
                    if let Some(slot) = alloc_conn(s) {
                        s.conns[slot] = Conn {
                            conn_id, replica_id: -1, active: true,
                            outbound: true, identified: false,
                        };
                        send_identity(s, sys, slot);
                    }
                }
            }
            NMSG_DATA => {
                // payload: [conn_id: u8] [data...]
                if payload_len < 2 { continue; }
                let data_start = NET_FRAME_HDR + 1; // after header + conn_id
                let data_len = payload_len - 1;
                let mut local = [0u8; 512];
                let cl = data_len.min(512);
                local[..cl].copy_from_slice(&s.buf[data_start..data_start + cl]);

                let slot = find_conn(s, conn_id);
                if slot >= MAX_CONNS { continue; }

                if !s.conns[slot].identified {
                    // Try to parse identity message
                    handle_identity(s, sys, slot, &local[..cl]);
                } else {
                    // Route based on replica_id
                    let rid = s.conns[slot].replica_id;
                    if rid >= 0 && (rid as usize) < MAX_NODES {
                        // Peer traffic: route by msg_type
                        // - APPEND_ENTRIES_RESP → peer_rx (replicator)
                        // - Everything else → cleartext (http_surface → raft_engine)
                        let peer_msg_type = if cl > 0 { local[0] } else { 0 };

                        if peer_msg_type == wire::MSG_APPEND_ENTRIES_RESP {
                            // Replication ack → replicator directly
                            if s.peer_rx >= 0 {
                                let p = (sys.channel_poll)(s.peer_rx, 0x02);
                                if p > 0 && (p as u32 & 0x02) != 0 {
                                    (sys.channel_write)(s.peer_rx, local.as_ptr(), cl);
                                }
                            }
                        } else if s.cleartext >= 0 && cl < 511 {
                            // Raft RPC → http_surface (tags with conn_id)
                            let mut tagged = [0u8; 512];
                            tagged[0] = conn_id;
                            tagged[1..1 + cl].copy_from_slice(&local[..cl]);
                            let p = (sys.channel_poll)(s.cleartext, 0x02);
                            if p > 0 && (p as u32 & 0x02) != 0 {
                                (sys.channel_write)(s.cleartext, tagged.as_ptr(), 1 + cl);
                            }
                        }
                    } else {
                        // Client traffic → http_surface
                        dev_log(&*s.syscalls, 3, b"[pr] data in".as_ptr(), 12);
                        if s.cleartext >= 0 && cl < 511 {
                            let mut tagged = [0u8; 512];
                            tagged[0] = conn_id;
                            tagged[1..1 + cl].copy_from_slice(&local[..cl]);
                            let p = (sys.channel_poll)(s.cleartext, 0x02);
                            if p > 0 && (p as u32 & 0x02) != 0 {
                                (sys.channel_write)(s.cleartext, tagged.as_ptr(), 1 + cl);
                            }
                        }
                    }
                }
            }
            NMSG_CLOSED => {
                if payload_len >= 1 {
                    let slot = find_conn(s, conn_id);
                    if slot < MAX_CONNS {
                        let rid = s.conns[slot].replica_id;
                        s.conns[slot] = Conn::empty();
                        if rid >= 0 && (rid as usize) < MAX_NODES {
                            s.peer_addrs[rid as usize].connected = false;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

// ── Identity exchange ───────────────────────────────────────

unsafe fn send_identity(s: &mut ModuleState, sys: &SyscallTable, slot: usize) {
    if s.net_out < 0 { return; }

    // CMD_SEND payload: [conn_id:1] [magic:2 LE] [self_id:1]
    let mut payload = [0u8; 1 + ID_MSG_LEN];
    payload[0] = s.conns[slot].conn_id;
    let magic = ID_MAGIC.to_le_bytes();
    payload[1] = magic[0]; payload[2] = magic[1];
    payload[3] = s.self_id;

    net_write_frame(sys, s.net_out, NCMD_SEND, payload.as_ptr(), 1 + ID_MSG_LEN,
                    s.buf.as_mut_ptr(), BUF_SIZE);
}

unsafe fn handle_identity(s: &mut ModuleState, sys: &SyscallTable, slot: usize, data: &[u8]) {
    if data.len() < ID_MSG_LEN { return; }

    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != ID_MAGIC {
        // Not a peer — treat as client (no identity exchange)
        s.conns[slot].identified = true;
        s.conns[slot].replica_id = -1; // client

        // Forward the data that arrived (it's application data, not identity)
        // Prepend conn_id for response routing
        if s.cleartext >= 0 && data.len() < 511 {
            let mut tagged = [0u8; 512];
            tagged[0] = s.conns[slot].conn_id;
            tagged[1..1 + data.len()].copy_from_slice(data);
            let p = (sys.channel_poll)(s.cleartext, 0x02);
            if p > 0 && (p as u32 & 0x02) != 0 {
                (sys.channel_write)(s.cleartext, tagged.as_ptr(), 1 + data.len());
            }
        }
        return;
    }

    let peer_id = data[2];
    if peer_id as usize >= MAX_NODES {
        s.conns[slot].identified = true;
        s.conns[slot].replica_id = -1;
        return;
    }

    s.conns[slot].replica_id = peer_id as i8;
    s.conns[slot].identified = true;
    s.peer_addrs[peer_id as usize].connected = true;

    // If we're the inbound side, reply with our identity
    if !s.conns[slot].outbound {
        send_identity(s, sys, slot);
    }

    dev_log(&*s.syscalls, 3, b"[pr] peer ok".as_ptr(), 12);
}

// ── Outbound routing ────────────────────────────────────────

unsafe fn route_outbound_chan(s: &mut ModuleState, sys: &SyscallTable, chan: i32) {
    if chan < 0 || s.net_out < 0 { return; }

    for _ in 0..8 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let poll_out = (sys.channel_poll)(s.net_out, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (target, _msg_type, plen) = wire::channel_read_routed(sys, chan, &mut s.buf);
        if plen == 0 && _msg_type == 0 { break; }

        // Trace: log target + msg_type
        {
            let hex = b"0123456789abcdef";
            let d: [u8; 8] = [b'[', b'o', b']',
                hex[(target >> 4) as usize], hex[(target & 0xF) as usize],
                hex[(_msg_type >> 4) as usize], hex[(_msg_type & 0xF) as usize], 0];
            dev_log(&*s.syscalls, 3, d.as_ptr(), 7);
        }

        // Copy to stack to release borrow on s.buf
        let pl = (plen as usize).min(512);
        let mut local = [0u8; 512];
        local[..pl].copy_from_slice(&s.buf[..pl]);

        if target == wire::TARGET_BROADCAST {
            for slot in 0..MAX_CONNS {
                if !s.conns[slot].active || !s.conns[slot].identified { continue; }
                if s.conns[slot].replica_id < 0 { continue; }
                send_to_conn(s, sys, slot, _msg_type, &local[..pl]);
            }
        } else {
            let slot = find_conn_by_replica(s, target);
            if slot < MAX_CONNS {
                send_to_conn(s, sys, slot, _msg_type, &local[..pl]);
            }
        }
    }
}

/// Send data to a peer connection with wire envelope framing.
/// `msg_type` and `data` are from the routed envelope. Wraps as:
/// CMD_SEND [conn_id] [msg_type] [len: u16 LE] [data]
unsafe fn send_to_conn(s: &mut ModuleState, sys: &SyscallTable, slot: usize, msg_type: u8, data: &[u8]) {
    if s.net_out < 0 { return; }

    // CMD_SEND payload: [conn_id:1] [envelope: msg_type:1 + len:2 + data:N]
    let envelope_len = wire::ENVELOPE_HDR + data.len();
    let payload_len = 1 + envelope_len;
    let mut payload = [0u8; 256];
    if payload_len > 256 { return; }

    payload[0] = s.conns[slot].conn_id;
    // Wire envelope
    payload[1] = msg_type;
    let lb = (data.len() as u16).to_le_bytes();
    payload[2] = lb[0];
    payload[3] = lb[1];
    if !data.is_empty() {
        payload[4..4 + data.len()].copy_from_slice(data);
    }

    net_write_frame(sys, s.net_out, NCMD_SEND, payload.as_ptr(), payload_len,
                    s.buf.as_mut_ptr(), BUF_SIZE);
}

// ── Client response routing ─────────────────────────────────

/// Read conn_id-tagged responses from http_surface and send back to
/// the originating TCP connection.
/// Format: [conn_id: u8] [msg_type: u8] [len: u16 LE] [payload]
unsafe fn route_client_responses(s: &mut ModuleState, sys: &SyscallTable) {
    if s.client_resp < 0 || s.net_out < 0 { return; }

    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.client_resp, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let n = (sys.channel_read)(s.client_resp, s.buf.as_mut_ptr(), BUF_SIZE);
        if n < 4 { break; } // need conn_id + at least 3-byte envelope
        let len = n as usize;

        let conn_id = s.buf[0];
        let data = &s.buf[1..len]; // the wire envelope + payload
        let data_len = data.len();
        if data_len == 0 { continue; }

        // CMD_SEND payload: [conn_id:1] [data]
        let mut payload = [0u8; 256];
        let payload_len = 1 + data_len;
        if payload_len > 256 { continue; }
        payload[0] = conn_id;
        payload[1..1 + data_len].copy_from_slice(data);

        net_write_frame(sys, s.net_out, NCMD_SEND, payload.as_ptr(), payload_len,
                        s.buf.as_mut_ptr(), BUF_SIZE);
    }
}

// ── Helpers ─────────────────────────────────────────────────

fn alloc_conn(s: &mut ModuleState) -> Option<usize> {
    for i in 0..MAX_CONNS {
        if !s.conns[i].active { return Some(i); }
    }
    None
}

fn find_conn(s: &ModuleState, conn_id: u8) -> usize {
    for i in 0..MAX_CONNS {
        if s.conns[i].active && s.conns[i].conn_id == conn_id { return i; }
    }
    MAX_CONNS
}

fn find_conn_by_replica(s: &ModuleState, replica_id: u8) -> usize {
    for i in 0..MAX_CONNS {
        if s.conns[i].active && s.conns[i].identified
            && s.conns[i].replica_id == replica_id as i8
        { return i; }
    }
    MAX_CONNS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
