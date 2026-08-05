//! surface — client envelope adapter.
//!
//! Routes inbound Clustor wire envelopes from peer_router to the raft
//! RPC port, the [`codec`](super::codec) component (client traffic)
//! or the admin port, based on `msg_type`. Returns responses to
//! peer_router with per-message `[conn_id:u8]` routing tags
//! (RFC §4.5). This component does NOT parse HTTP — the operations
//! module owns the HTTP diagnostic surface.

use super::abi::SyscallTable;
use super::{codec, wire, wire_channels};

/// One pull off the `requests` port: nothing readable (or the
/// consume-gate closed), a frame routed internally (raft RPC / admin
/// — burns a loop slot), or a client frame handed to the dispatch
/// table for the codec.
pub enum Inbound {
    Empty,
    Handled,
    Client { msg_type: u8, len: usize },
    /// The record's payload exceeds the proposal cap. Truncating and
    /// forwarding a prefix would commit a corrupted entry while acking
    /// the full write, so the dispatch table sends a
    /// `CLIENT_REJECT_TOO_LARGE` instead (the consume-gate guarantees
    /// the response egress can carry it).
    Oversize { conn_id: u8 },
}

#[repr(C)]
pub struct Surface {
    pub in_requests: i32,        // in: cleartext MSG_CLIENT_FRAME from peer_router
    pub in_admin_resp: i32,      // in: AdminResponse from operations
    pub in_readyz: i32,          // in: readyz from operations
    pub in_why: i32,             // in: why from operations
    pub in_metrics: i32,         // in: export from operations
    pub out_raft_rpc: i32,       // out: Raft RPC to consensus
    pub out_admin_req: i32,      // out: admin requests to operations
    pub out_responses: i32,      // out: responses back to peer_router

    requests_routed: u32,
    responses_sent: u32,
    /// Must hold peer_router's largest MSG_CLIENT_FRAME payload:
    /// conn_id byte + a full 4 KiB client record. `channel_read_msg`
    /// silently discards any payload larger than this buffer, so
    /// undersizing it drops big client records with no error at
    /// exactly the hop after peer_router accepted them.
    msg_buf: [u8; 4097],
}

pub unsafe fn init(su: &mut Surface) {
    su.in_requests = -1;
    su.in_admin_resp = -1;
    su.in_readyz = -1;
    su.in_why = -1;
    su.in_metrics = -1;
    su.out_raft_rpc = -1;
    su.out_admin_req = -1;
    su.out_responses = -1;
    su.requests_routed = 0;
    su.responses_sent = 0;
}

pub fn work_count(su: &Surface) -> u32 {
    su.requests_routed.wrapping_add(su.responses_sent)
}

/// Pull ONE inbound request off the `requests` port and route it by
/// message type. Raft RPC and admin frames are routed here on the
/// surface's own ports ([`Inbound::Handled`]); client traffic is
/// copied into `out` as the `[conn_id:u8][body]` record and returned
/// as [`Inbound::Client`] for the dispatch table to hand to the
/// codec. The dispatch table drives the ≤8/step loop, so every
/// consumed frame — routed, handed off, or malformed — counts
/// against the one bound.
///
/// peer_router wraps each cleartext record in a MSG_CLIENT_FRAME
/// envelope; channel_read_msg strips it, leaving the record payload
/// `[conn_id][msg_type][len: u16 LE][payload]` at msg_buf[0..]. The
/// framing keeps records for distinct conn_ids from coalescing on
/// the byte FIFO (see wire::MSG_CLIENT_FRAME).
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Surface` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn next_request(su: &mut Surface, sys: &SyscallTable, out: &mut [u8; 2048]) -> Inbound {
    if su.in_requests < 0 {
        return Inbound::Empty;
    }
    // Consume-gate: a frame is read only while the response
    // egress can still carry a terminal reply. Every consumed
    // client proposal must end in an admit or a reject — if
    // `responses` is full, a throttled reject would vanish
    // after the frame was already consumed. Leaving the frame
    // on the channel instead backpressures peer_router (and
    // ultimately the client) losslessly.
    if su.out_responses >= 0 {
        let poll_resp = (sys.channel_poll)(su.out_responses, 0x02);
        if poll_resp <= 0 || (poll_resp as u32 & 0x02) == 0 {
            return Inbound::Empty;
        }
    }
    let poll = (sys.channel_poll)(su.in_requests, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return Inbound::Empty;
    }

    let (_frame_type, plen) = wire_channels::channel_read_msg(sys, su.in_requests, &mut su.msg_buf);
    if plen < 4 {
        return Inbound::Handled; // need at least conn_id + 3-byte envelope header
    }
    let len = plen as usize;

    // Extract conn_id prefix
    let conn_id = su.msg_buf[0];
    // Parse wire envelope from offset 1
    let msg_type = su.msg_buf[1];
    let payload_len = u16::from_le_bytes([su.msg_buf[2], su.msg_buf[3]]) as usize;
    let payload_start = 4usize; // 1 (conn_id) + 3 (envelope)
    let payload_end = (payload_start + payload_len).min(len);

    match msg_type {
        wire::MSG_APPEND_ENTRIES
        | wire::MSG_APPEND_ENTRIES_RESP
        | wire::MSG_REQUEST_VOTE
        | wire::MSG_REQUEST_VOTE_RESP
        | wire::MSG_PRE_VOTE
        | wire::MSG_PRE_VOTE_RESP
        | wire::MSG_HEARTBEAT
        | wire::MSG_HEARTBEAT_RESP => {
            if su.out_raft_rpc >= 0 {
                let poll_out = (sys.channel_poll)(su.out_raft_rpc, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    // consensus.rpc expects 5-byte partitioned
                    // envelopes. Client-injected Raft RPCs are
                    // admin-side and don't carry a partition tag,
                    // so we stamp partition_id=0; in multi-
                    // partition deployments those frames will be
                    // dropped by every raft instance with id != 0.
                    let payload = &su.msg_buf[payload_start..payload_end];
                    wire_channels::channel_write_partitioned(
                        sys, su.out_raft_rpc, 0, msg_type, payload,
                    );
                    su.requests_routed += 1;
                }
            }
            Inbound::Handled
        }
        wire::MSG_ADMIN_COMMAND => {
            if su.out_admin_req >= 0 {
                let poll_out = (sys.channel_poll)(su.out_admin_req, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    // Prepend per-message conn_id so the admin
                    // consumer can correlate responses back to
                    // this connection. See RFC §4.5 / §5.8.
                    let mut framed = [0u8; 2048];
                    if payload_end - payload_start > framed.len() - 1 {
                        su.requests_routed += 1;
                        return Inbound::Oversize { conn_id };
                    }
                    framed[0] = conn_id;
                    let pl = payload_end - payload_start;
                    framed[1..1 + pl]
                        .copy_from_slice(&su.msg_buf[payload_start..payload_start + pl]);
                    wire_channels::channel_write_msg(
                        sys, su.out_admin_req, msg_type, &framed[..1 + pl],
                    );
                    su.requests_routed += 1;
                }
            }
            Inbound::Handled
        }
        _ => {
            // Client traffic — MSG_CLIENT_PROPOSAL and
            // MSG_CLIENT_READ_REQUEST route to the codec;
            // unknown types are treated as proposals (the body
            // is opaque to the substrate).
            let routed_type = match msg_type {
                wire::MSG_CLIENT_PROPOSAL | wire::MSG_CLIENT_READ_REQUEST => msg_type,
                _ => wire::MSG_CLIENT_PROPOSAL,
            };
            if payload_end - payload_start > out.len() - 1 {
                su.requests_routed += 1;
                return Inbound::Oversize { conn_id };
            }
            out[0] = conn_id;
            let pl = payload_end - payload_start;
            out[1..1 + pl].copy_from_slice(&su.msg_buf[payload_start..payload_start + pl]);
            su.requests_routed += 1;
            Inbound::Client { msg_type: routed_type, len: 1 + pl }
        }
    }
}

/// The surface's own post-routing work, after the dispatch table's
/// request loop: forward admin responses → peer_router (client
/// responses return through [`send_response`] calls routed by the
/// dispatch table), then drain the diagnostic inputs. Per-step
/// bound: ≤4 admin responses, ≤4 frames from each diagnostic input.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Surface` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn finish_step(su: &mut Surface, sys: &SyscallTable) {
    forward_admin_responses(su, sys);

    // Drain telemetry/status inputs (these produce diagnostic
    // responses on /readyz, /why, /metrics endpoints — for now
    // drain to prevent backpressure; wire-side diagnostic framing
    // is future work)
    drain_input(sys, su.in_readyz, &mut su.msg_buf);
    drain_input(sys, su.in_why, &mut su.msg_buf);
    drain_input(sys, su.in_metrics, &mut su.msg_buf);
}

/// Send one codec-resolved [`codec::Outbound`] to peer_router.
/// Returns whether the frame was written, so the dispatch table can
/// report the outcome back to the codec's counters.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Surface` and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn send_outbound(su: &mut Surface, sys: &SyscallTable, out: &codec::Outbound) -> bool {
    if out.len == 0 {
        return false;
    }
    send_response(su, sys, out.msg_type, &out.buf[..out.len as usize])
}

/// Emit one response to peer_router. `payload` carries the
/// `[conn_id:u8]` prefix set by the producer; it is stripped and used
/// as the per-message routing tag (RFC §4.5). Wire bytes written:
/// `[conn_id:u8][msg_type:u8][len:u16 LE][payload-without-conn-id]`.
/// Returns whether the frame was written.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Surface` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn send_response(
    su: &mut Surface,
    sys: &SyscallTable,
    msg_type: u8,
    payload: &[u8],
) -> bool {
    if su.out_responses < 0 || payload.is_empty() {
        return false;
    }
    let poll_out = (sys.channel_poll)(su.out_responses, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
        return false;
    }
    let conn_id = payload[0];
    let inner_len = payload.len() - 1;
    let total = 1 + wire::ENVELOPE_HDR + inner_len;
    let mut frame = [0u8; 256];
    if total > 256 {
        return false;
    }
    frame[0] = conn_id;
    frame[1] = msg_type;
    let lb = (inner_len as u16).to_le_bytes();
    frame[2] = lb[0];
    frame[3] = lb[1];
    if inner_len > 0 {
        frame[4..4 + inner_len].copy_from_slice(&payload[1..1 + inner_len]);
    }
    (sys.channel_write)(su.out_responses, frame.as_ptr(), total);
    su.responses_sent += 1;
    true
}

/// Forward admin responses from the `admin_responses` port. Each
/// payload starts with `[conn_id:u8]` (set by the admin producer).
unsafe fn forward_admin_responses(su: &mut Surface, sys: &SyscallTable) {
    if su.in_admin_resp < 0 || su.out_responses < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(su.in_admin_resp, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }

        let poll_out = (sys.channel_poll)(su.out_responses, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
            break;
        }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, su.in_admin_resp, &mut su.msg_buf);
        if plen == 0 {
            break;
        }
        // Payload must carry at least the conn_id byte. Anything
        // shorter is a wiring mistake — drop it rather than misroute.
        if (plen as usize) < 1 {
            continue;
        }
        let pl = plen as usize;
        let mut local = [0u8; 256];
        if pl > 256 {
            continue;
        }
        local[..pl].copy_from_slice(&su.msg_buf[..pl]);
        send_response(su, sys, msg_type, &local[..pl]);
    }
}

unsafe fn drain_input(sys: &SyscallTable, chan: i32, buf: &mut [u8]) {
    if chan < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(chan, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let n = (sys.channel_read)(chan, buf.as_mut_ptr(), 2048);
        if n <= 0 {
            break;
        }
    }
}
