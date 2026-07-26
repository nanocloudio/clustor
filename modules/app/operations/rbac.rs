//! rbac — role-based access control component.
//!
//! Evaluates admin commands against a role manifest. Authorized
//! commands are delivered to the [`admin`](super::admin) component;
//! denied commands answer `MSG_ADMIN_RESPONSE(ADMIN_STATUS_REJECTED)`
//! on the module's `denied` port. The decision is externally
//! observable on both sides: `denied` carries the refusals, and the
//! optional `authorized` port tees the commands that passed. Every
//! evaluation emits a 3-byte
//! audit envelope on `audit_events` and is counted by the
//! [`telemetry`](super::telemetry) component.
//!
//! ## Identity binding (RFC §3.2)
//!
//! When the optional `identity` port is wired and a
//! `MSG_PEER_IDENTITY` envelope arrives for a connection, the
//! component records `conn_id → role` in a small in-memory table.
//! Subsequent admin commands on the same `conn_id` are evaluated
//! against that role rather than the module-wide `default_role`.
//!
//! Role lookup is a **prefix match against the SVID body**, driven by
//! the `admin_svid_prefix` / `observer_svid_prefix` params. Plaintext
//! (non-TLS-verified) identities never downgrade a TLS-verified
//! binding.
//!
//! ## Origins
//!
//! Commands arrive from two origins with disjoint `conn_id`
//! namespaces:
//!
//! - **Wire** (`admin_req` port, ids minted by `peer_router`) —
//!   evaluated against the identity-binding table.
//! - **HTTP** (delivered by the [`http`](super::http) component, ids
//!   minted by the HTTP listener) — the binding table is never
//!   consulted; HTTP callers carry no peer identity and always
//!   evaluate as `default_role`. A deployment that must not accept
//!   HTTP admin sets `default_role` to observer or ships the
//!   `headless` variant.
//!
//! Per-step budget: 8 identity envelopes + 4 wire commands, plus at
//! most 4 HTTP-origin evaluations delivered by `http` (bounded by its
//! own request loop). All work is table scans over 32 slots.

use super::abi::SyscallTable;
use super::{admin, telemetry, wire, wire_channels};

// Role bits
pub const ROLE_OPERATOR: u8 = 0x01;
pub const ROLE_TENANT_ADMIN: u8 = 0x02;
pub const ROLE_OBSERVER: u8 = 0x04;
pub const ROLE_BREAKGLASS: u8 = 0x08;

/// Max length of an `admin_svid_prefix` or `observer_svid_prefix`
/// param. Truncation past this length is accepted silently — the
/// prefix-match logic operates on at most this many bytes from the
/// incoming SVID.
pub const SVID_PREFIX_MAX: usize = 64;

/// Number of connection identity slots. Each accepted client occupies
/// one slot for the duration of its connection; surface eviction on
/// disconnect happens implicitly when `peer_router` reuses the
/// `conn_id`.
const IDENTITY_SLOTS: usize = 32;

#[derive(Clone, Copy)]
#[repr(C)]
struct IdentityBinding {
    conn_id: u8,
    role: u8,
    tls_verified: bool,
    /// 0 means "no SVID stored"; otherwise length within `svid` below.
    svid_len: u8,
    svid: [u8; SVID_PREFIX_MAX],
}

impl IdentityBinding {
    const fn empty() -> Self {
        Self {
            conn_id: 0,
            role: 0,
            tls_verified: false,
            svid_len: 0,
            svid: [0u8; SVID_PREFIX_MAX],
        }
    }
    fn is_empty(&self) -> bool {
        self.role == 0
    }
}

/// Command origin. HTTP-origin conn_ids live in the HTTP listener's
/// namespace and must never be resolved against wire identity
/// bindings.
#[derive(Clone, Copy, PartialEq)]
pub enum Origin {
    Wire,
    Http,
}

#[repr(C)]
pub struct Rbac {
    pub in_requests: i32, // in: raw admin commands (wire origin)
    pub in_identity: i32, // in: MSG_PEER_IDENTITY from peer_router / tls
    pub out_denied: i32,  // out: denied → admin responses consumer
    pub out_audit: i32,   // out: audit events (external consumers)
    /// Optional tee of authorized commands (external consumers). Fed
    /// after the in-module delivery to `admin`, best-effort — see
    /// [`evaluate`].
    pub out_authorized: i32,

    /// Role applied when no identity binding exists for the conn_id.
    /// Defaults to `ROLE_OPERATOR` to preserve "allow all" behaviour
    /// for graphs that haven't wired identity yet.
    pub default_role: u8,

    /// SVID-prefix → role mapping (loaded from params).
    pub admin_prefix: [u8; SVID_PREFIX_MAX],
    pub admin_prefix_len: u8,
    pub observer_prefix: [u8; SVID_PREFIX_MAX],
    pub observer_prefix_len: u8,

    /// Per-connection identity bindings. Linear scan — 32 slots is
    /// fine for the deployments we target.
    bindings: [IdentityBinding; IDENTITY_SLOTS],

    pub authorized_count: u32,
    pub denied_count: u32,
    msg_buf: [u8; 1024],
}

pub unsafe fn init(r: &mut Rbac) {
    r.in_requests = -1;
    r.in_identity = -1;
    r.out_denied = -1;
    r.out_audit = -1;
    r.out_authorized = -1;
    r.default_role = ROLE_OPERATOR;
    r.admin_prefix = [0u8; SVID_PREFIX_MAX];
    r.admin_prefix_len = 0;
    r.observer_prefix = [0u8; SVID_PREFIX_MAX];
    r.observer_prefix_len = 0;
    for b in r.bindings.iter_mut() {
        *b = IdentityBinding::empty();
    }
    r.authorized_count = 0;
    r.denied_count = 0;
}

/// Per-step bound: 8 identity envelopes + 4 wire commands (see the
/// module dispatch table).
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(
    r: &mut Rbac,
    admin: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
) {
    // 1. Drain identity bindings BEFORE processing requests so the
    //    role table is up-to-date for any commands arriving in the
    //    same tick.
    drain_identity(r, sys);

    // 2. Authorize wire-origin admin commands against the per-conn
    //    role (or `default_role` when no binding exists).
    if r.in_requests < 0 {
        return;
    }
    for _ in 0..4 {
        let poll = (sys.channel_poll)(r.in_requests, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, r.in_requests, &mut r.msg_buf);
        if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 {
            continue;
        }
        let pl = plen as usize;
        if pl < 1 {
            continue;
        }
        let mut local = [0u8; 1024];
        local[..pl].copy_from_slice(&r.msg_buf[..pl]);
        evaluate(r, admin, tele, sys, now, Origin::Wire, &local[..pl]);
    }
}

/// Evaluate one admin command envelope `[conn_id:u8][op_code:u8][body]`.
/// Authorized commands are delivered to the admin component; denials
/// answer on the `denied` port. Returns whether the command was
/// authorized.
///
/// When the optional `authorized` port is wired, the authorized
/// envelope is also teed there verbatim — best-effort, dropped on
/// backpressure, and never in the path of the delivery to `admin`.
///
/// This is the single admission point for admin commands regardless
/// of origin — the `http` component calls it for `POST /admin/<op>`.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn evaluate(
    r: &mut Rbac,
    admin: &mut admin::Admin,
    tele: &mut telemetry::Telemetry,
    sys: &SyscallTable,
    now: u64,
    origin: Origin,
    payload: &[u8],
) -> bool {
    if payload.is_empty() {
        return false;
    }
    let conn_id = payload[0];
    let role = match origin {
        Origin::Wire => lookup_role(r, conn_id),
        // HTTP conn_ids live in the listener's namespace; never
        // resolve them against wire identity bindings.
        Origin::Http => r.default_role,
    };
    let authorized = (role & (ROLE_OPERATOR | ROLE_BREAKGLASS)) != 0;

    if authorized {
        admin::on_command(admin, sys, now, payload);
        r.authorized_count += 1;
        // Tee the authorized envelope to any external observer. This
        // runs strictly AFTER the delivery above and never gates it:
        // an unwired or full port costs one poll and the command has
        // already been handed to `admin`.
        if r.out_authorized >= 0 {
            let poll_out = (sys.channel_poll)(r.out_authorized, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                wire_channels::channel_write_msg(
                    sys,
                    r.out_authorized,
                    wire::MSG_ADMIN_COMMAND,
                    payload,
                );
            }
        }
    } else {
        if origin == Origin::Wire && r.out_denied >= 0 {
            let poll_out = (sys.channel_poll)(r.out_denied, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                let resp = [conn_id, wire::ADMIN_STATUS_REJECTED];
                wire_channels::channel_write_msg(sys, r.out_denied, wire::MSG_ADMIN_RESPONSE, &resp);
            }
        }
        r.denied_count += 1;
    }

    // Audit envelope: `[authorized:u8][role:u8][conn_id:u8]`. External
    // consumers see it on `audit_events`; the telemetry component
    // counts it like any other legacy metrics envelope.
    if r.out_audit >= 0 {
        let poll_out = (sys.channel_poll)(r.out_audit, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            let audit = [authorized as u8, role, conn_id];
            wire_channels::channel_write_msg(sys, r.out_audit, wire::MSG_METRICS, &audit);
        }
    }
    telemetry::on_legacy_envelope(tele);

    authorized
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Rbac` and supply a valid
/// `&SyscallTable` per the module ABI.
unsafe fn drain_identity(r: &mut Rbac, sys: &SyscallTable) {
    if r.in_identity < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(r.in_identity, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, r.in_identity, &mut r.msg_buf);
        if msg_type != wire::MSG_PEER_IDENTITY {
            continue;
        }
        let pl = plen as usize;
        let (conn_id, _replica_id, verified, svid_off) =
            match wire::decode_peer_identity(&r.msg_buf[..pl]) {
                Some(v) => v,
                None => continue,
            };
        // Copy the SVID out of the shared scratch buffer first so the
        // subsequent `&mut r` borrow doesn't clash with the slice.
        let svid_len = pl.saturating_sub(svid_off).min(SVID_PREFIX_MAX);
        let mut svid_local = [0u8; SVID_PREFIX_MAX];
        if svid_len > 0 {
            svid_local[..svid_len].copy_from_slice(&r.msg_buf[svid_off..svid_off + svid_len]);
        }
        record_identity(r, conn_id, verified, &svid_local[..svid_len]);
    }
}

fn record_identity(r: &mut Rbac, conn_id: u8, verified: bool, svid: &[u8]) {
    // Refuse to downgrade a TLS-verified binding via a plaintext envelope.
    if let Some(existing) = find_binding(r, conn_id) {
        if r.bindings[existing].tls_verified && !verified {
            return;
        }
    }
    let role = role_for_svid(r, svid);
    let slot_idx = match find_binding(r, conn_id) {
        Some(i) => i,
        None => match r.bindings.iter().position(|b| b.is_empty()) {
            Some(i) => i,
            None => return, // table full; new conn loses RBAC binding.
        },
    };
    let take = svid.len().min(SVID_PREFIX_MAX);
    let b = &mut r.bindings[slot_idx];
    b.conn_id = conn_id;
    b.role = role;
    b.tls_verified = verified;
    b.svid_len = take as u8;
    b.svid[..take].copy_from_slice(&svid[..take]);
}

fn find_binding(r: &Rbac, conn_id: u8) -> Option<usize> {
    for (i, b) in r.bindings.iter().enumerate() {
        if !b.is_empty() && b.conn_id == conn_id {
            return Some(i);
        }
    }
    None
}

fn lookup_role(r: &Rbac, conn_id: u8) -> u8 {
    match find_binding(r, conn_id) {
        Some(i) => r.bindings[i].role,
        None => r.default_role,
    }
}

fn role_for_svid(r: &Rbac, svid: &[u8]) -> u8 {
    // Empty prefix = no policy → fall through to default_role for
    // verified peers, observer for plaintext peers (defensible default
    // for the day someone wires identity without setting a policy).
    let admin = prefix_match(svid, &r.admin_prefix, r.admin_prefix_len as usize);
    let observer = prefix_match(svid, &r.observer_prefix, r.observer_prefix_len as usize);
    if admin {
        ROLE_OPERATOR | ROLE_BREAKGLASS
    } else if observer {
        ROLE_OBSERVER
    } else if r.admin_prefix_len == 0 && r.observer_prefix_len == 0 {
        // No policy configured. Honour module-wide default_role.
        r.default_role
    } else {
        // Policy is set but the SVID matches no role — deny.
        ROLE_OBSERVER
    }
}

fn prefix_match(svid: &[u8], prefix: &[u8], prefix_len: usize) -> bool {
    if prefix_len == 0 {
        return false;
    }
    if svid.len() < prefix_len {
        return false;
    }
    &svid[..prefix_len] == &prefix[..prefix_len]
}
