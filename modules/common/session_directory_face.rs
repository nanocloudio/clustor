// session_directory_face — the session directory's face on fluxor's
// SessionCtrlV1: how an anchor's contract verbs become replicated registry
// commands, and how each committed reply becomes the contract's frame.
//
// An anchor speaks the platform contract to a directory — HELLO, ATTACH,
// EPOCH_BUMP, DETACH — and reads ATTACHED, EPOCH_CONFIRMED, DETACHED, ERROR
// and the reservation grants that follow a binding. This file is the
// mapping and nothing else: no channels, no proposal plumbing, no state.
// The registry it maps onto is a raft state machine whose command bodies
// are its own (`session_registry.rs`); the wire the anchor sees is the
// contract's, so the directory a graph places is interchangeable with any
// other provider of `session.directory`.
//
// Mounted beside `session_registry` and `session_ctrl` (as
// `super::session_registry` and `super::session_ctrl`) by the module and
// by the host gate.

// The contract itself is the consumer's to provide as a sibling
// `session_ctrl` (the module reaches it through the SDK; the host gate
// mounts the staged file), so it is mounted exactly once per crate.
use super::session_ctrl as sc;

use super::session_registry::{
    build_bind, build_epoch_bump, build_reserve, build_unbind, SessionReply,
    SR_BIND_FENCE_REQUIRED, SR_PEER_ID, SR_SESSION_ID, SR_ST_NO_CAPACITY, SR_ST_OK,
    SR_ST_STALE_EPOCH, SR_ST_UNKNOWN_SESSION,
};

/// Which contract verb a pending command answers. `FACE_NONE` is a
/// request that arrived on the registry's own request port and is
/// answered there.
pub const FACE_NONE: u8 = 0;
pub const FACE_ATTACH: u8 = 1;
pub const FACE_EPOCH_BUMP: u8 = 2;
pub const FACE_DETACH: u8 = 3;
/// The RESERVE the directory proposes on its own behalf after a binding
/// commits, answered to the anchor as `CMD_SC_RESERVATION_GRANT`.
pub const FACE_GRANT: u8 = 4;

/// Egress-counter values in one grant: the block an anchor's transport
/// emits from before it asks again.
pub const GRANT_BLOCK_LEN: u64 = 1 << 20;

/// The contract's status for a registry verdict.
pub const fn sr_status_to_sc(status: u8) -> u8 {
    match status {
        SR_ST_OK => sc::STATUS_OK,
        SR_ST_STALE_EPOCH => sc::STATUS_STALE_EPOCH,
        SR_ST_UNKNOWN_SESSION => sc::STATUS_UNKNOWN_SESSION,
        SR_ST_NO_CAPACITY => sc::STATUS_NO_CAPACITY,
        _ => sc::STATUS_CORRUPT,
    }
}

fn session_of(p: &[u8]) -> [u8; SR_SESSION_ID] {
    let mut s = [0u8; SR_SESSION_ID];
    s.copy_from_slice(&p[..SR_SESSION_ID]);
    s
}

/// Map one contract command onto the registry command it is. Returns the
/// command's length in `out` and the face to answer it on; `None` for a
/// verb the directory does not take from an anchor (RELOCATE is the
/// directory's to send) or a payload the contract does not define.
pub fn request_to_command(msg: u8, p: &[u8], out: &mut [u8]) -> Option<(usize, u8)> {
    match msg {
        sc::CMD_SC_ATTACH if p.len() >= sc::ATTACH_PAYLOAD_LEN => {
            let sid = session_of(p);
            let mut anchor = [0u8; SR_PEER_ID];
            anchor.copy_from_slice(
                &p[sc::SESSION_ID_BYTES..sc::SESSION_ID_BYTES + sc::ANCHOR_ID_BYTES],
            );
            let epoch = sc::attach_epoch(p);
            let cc_at = sc::SESSION_ID_BYTES + sc::ANCHOR_ID_BYTES + sc::EPOCH_BYTES;
            let cc = p[cc_at];
            let mut worker = [0u8; SR_PEER_ID];
            worker.copy_from_slice(&p[cc_at + 1..cc_at + 1 + sc::WORKER_ID_BYTES]);
            // A transport that may itself move declares the fenced takeover;
            // every other class moves its worker behind a fixed anchor.
            let flags = if cc == sc::CC_TRANSPORT_MIGRATABLE {
                SR_BIND_FENCE_REQUIRED
            } else {
                0
            };
            let n = build_bind(out, &sid, epoch, &anchor, &worker, flags);
            (n > 0).then_some((n, FACE_ATTACH))
        }
        sc::CMD_SC_EPOCH_BUMP if p.len() >= sc::EPOCH_BUMP_PAYLOAD_LEN => {
            let sid = session_of(p);
            let n = build_epoch_bump(out, &sid, sc::epoch(p), sc::u32_after_header(p));
            (n > 0).then_some((n, FACE_EPOCH_BUMP))
        }
        sc::CMD_SC_DETACH if p.len() >= sc::DETACH_PAYLOAD_LEN => {
            let sid = session_of(p);
            let n = build_unbind(out, &sid, sc::epoch(p));
            (n > 0).then_some((n, FACE_DETACH))
        }
        _ => None,
    }
}

/// The RESERVE a directory proposes for a session it has just bound or
/// advanced: the AEAD nonce counter, one block.
pub fn grant_command(sid: &[u8; SR_SESSION_ID], epoch: u32, out: &mut [u8]) -> usize {
    build_reserve(out, sid, epoch, 0, GRANT_BLOCK_LEN)
}

/// Map a committed reply onto the contract's frame for the face it
/// answers: the message id and the payload length written to `out`.
/// A refused grant is not a grant and produces nothing.
pub fn reply_to_frame(face: u8, reply: &SessionReply, out: &mut [u8]) -> Option<(u8, usize)> {
    let status = sr_status_to_sc(reply.status);
    match face {
        FACE_ATTACH => {
            if out.len() < sc::SESSION_HEADER + 1 {
                return None;
            }
            sc::put_session_header(out, &reply.session_id, reply.epoch);
            out[sc::SESSION_HEADER] = status;
            Some((sc::MSG_SC_ATTACHED, sc::SESSION_HEADER + 1))
        }
        FACE_EPOCH_BUMP | FACE_DETACH => {
            if out.len() < sc::SESSION_HEADER + 1 {
                return None;
            }
            sc::put_session_header(out, &reply.session_id, reply.epoch);
            if reply.status == SR_ST_OK {
                let msg = if face == FACE_EPOCH_BUMP {
                    sc::MSG_SC_EPOCH_CONFIRMED
                } else {
                    sc::MSG_SC_DETACHED
                };
                Some((msg, sc::SESSION_HEADER))
            } else {
                out[sc::SESSION_HEADER] = status;
                Some((sc::MSG_SC_ERROR, sc::SESSION_HEADER + 1))
            }
        }
        FACE_GRANT => {
            if reply.status != SR_ST_OK || out.len() < sc::FLOW_ID_BYTES + sc::GRANT_LEN {
                return None;
            }
            // The registry's RESERVE reply is the contract's grant record.
            out[..sc::FLOW_ID_BYTES].copy_from_slice(&reply.session_id);
            reply.encode(&mut out[sc::FLOW_ID_BYTES..sc::FLOW_ID_BYTES + sc::GRANT_LEN]);
            Some((
                sc::CMD_SC_RESERVATION_GRANT,
                sc::FLOW_ID_BYTES + sc::GRANT_LEN,
            ))
        }
        _ => None,
    }
}

/// HELLO_ACK: `[role:1][directory id:8]`, the id naming this replica.
pub fn hello_ack(replica_id: u8, out: &mut [u8]) -> usize {
    let n = 1 + sc::ANCHOR_ID_BYTES;
    if out.len() < n {
        return 0;
    }
    out[0] = sc::ROLE_DIRECTORY;
    out[1..8].copy_from_slice(b"clustor");
    out[8] = b'0' + (replica_id % 10);
    n
}
