//! RBAC — Role-based access control with break-glass support.
//!
//! Evaluates admin requests against a role manifest. Authorised
//! requests are forwarded to `admin_handler`; denied requests return
//! `MSG_ADMIN_RESPONSE` with `ADMIN_STATUS_REJECTED`.
//!
//! ## Identity binding (RFC §3.2)
//!
//! When the optional `identity_in` port is wired and a
//! `MSG_PEER_IDENTITY` envelope arrives for a connection, the module
//! records `conn_id → role` in a small in-memory table. Subsequent
//! admin requests on the same `conn_id` are evaluated against that
//! role rather than the module-wide `default_role`.
//!
//! Role lookup is currently a **prefix match against the SVID body**.
//! Two params drive the policy:
//!
//!   - `admin_svid_prefix` — SVIDs starting with this byte sequence
//!     get `ROLE_OPERATOR | ROLE_BREAKGLASS`. Empty (the default)
//!     disables the prefix check so the legacy "everyone is operator"
//!     behaviour holds.
//!   - `observer_svid_prefix` — SVIDs starting with this prefix get
//!     `ROLE_OBSERVER` (read-only). Admin commands from observer SVIDs
//!     are rejected.
//!
//! Plaintext (non-TLS-verified) identities are accepted only when no
//! TLS-verified binding exists for the connection. A TLS-verified
//! binding cannot be downgraded by a later plaintext envelope.

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

// Role bits
const ROLE_OPERATOR: u8     = 0x01;
const ROLE_TENANT_ADMIN: u8 = 0x02;
const ROLE_OBSERVER: u8     = 0x04;
const ROLE_BREAKGLASS: u8   = 0x08;

/// Max length of an `admin_svid_prefix` or `observer_svid_prefix`
/// param. Truncation past this length is accepted silently — the
/// prefix-match logic operates on at most this many bytes from the
/// incoming SVID.
const SVID_PREFIX_MAX: usize = 64;

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

define_params! {
    ModuleState;

    1, admin_svid_prefix, blob, 0
        => |s, d, len| {
            let take = (len as usize).min(SVID_PREFIX_MAX);
            for i in 0..take { s.admin_prefix[i] = *d.add(i); }
            s.admin_prefix_len = take as u8;
        };

    2, observer_svid_prefix, blob, 0
        => |s, d, len| {
            let take = (len as usize).min(SVID_PREFIX_MAX);
            for i in 0..take { s.observer_prefix[i] = *d.add(i); }
            s.observer_prefix_len = take as u8;
        };

    3, default_role, u8, ROLE_OPERATOR
        => |s, d, len| { s.default_role = p_u8(d, len, 0, ROLE_OPERATOR); };
}

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,
    in_requests: i32,     // in[0]: raw admin requests from client_surface
    in_identity: i32,     // in[1]: MSG_PEER_IDENTITY from peer_router / tls
    out_authorized: i32,  // out[0]: authorized → admin_handler
    out_denied: i32,      // out[1]: denied → client_surface
    out_audit: i32,       // out[2]: audit events → telemetry_agg

    /// Role applied when no identity binding exists for the conn_id.
    /// Defaults to `ROLE_OPERATOR` to preserve legacy "allow all"
    /// behaviour for graphs that haven't wired identity yet.
    default_role: u8,

    /// SVID-prefix → role mapping (loaded from params).
    admin_prefix: [u8; SVID_PREFIX_MAX],
    admin_prefix_len: u8,
    observer_prefix: [u8; SVID_PREFIX_MAX],
    observer_prefix_len: u8,

    /// Per-connection identity bindings. Linear scan — 32 slots is
    /// fine for the deployments we target.
    bindings: [IdentityBinding; IDENTITY_SLOTS],

    authorized_count: u32,
    denied_count: u32,
    msg_buf: [u8; 1024],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 { core::mem::size_of::<ModuleState>() as u32 }

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
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ModuleState>() {
            return -2;
        }
        let s = &mut *(state as *mut ModuleState);
        let sys = &*(syscalls as *const SyscallTable);
        s.syscalls = sys;
        s.in_requests = in_chan;
        s.in_identity = dev_channel_port(sys, 0, 1);
        s.out_authorized = out_chan;
        s.out_denied = dev_channel_port(sys, 1, 1);
        s.out_audit = dev_channel_port(sys, 1, 2);
        s.default_role = ROLE_OPERATOR;
        s.admin_prefix = [0u8; SVID_PREFIX_MAX];
        s.admin_prefix_len = 0;
        s.observer_prefix = [0u8; SVID_PREFIX_MAX];
        s.observer_prefix_len = 0;
        for b in s.bindings.iter_mut() {
            *b = IdentityBinding::empty();
        }
        set_defaults(s);
        if !params.is_null() && params_len >= 4 {
            parse_tlv(s, params, params_len);
        }
        dev_log(sys, 3, b"[rbac] init".as_ptr(), 11);
        0
    }
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

        // 1. Drain identity bindings BEFORE processing requests so the
        //    role table is up-to-date for any commands arriving in the
        //    same tick.
        drain_identity(s, sys);

        // 2. Authorise admin requests against the per-conn role (or
        //    `default_role` when no binding exists).
        for _ in 0..4 {
            let poll = (sys.channel_poll)(s.in_requests, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_requests, &mut s.msg_buf);
            if msg_type != wire::MSG_ADMIN_COMMAND || plen == 0 {
                continue;
            }
            let pl = plen as usize;
            if pl < 1 {
                continue;
            }
            let conn_id = s.msg_buf[0];
            let role = lookup_role(s, conn_id);
            let authorized = (role & (ROLE_OPERATOR | ROLE_BREAKGLASS)) != 0;

            if authorized {
                let poll_out = (sys.channel_poll)(s.out_authorized, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    wire_channels::channel_write_msg(
                        sys,
                        s.out_authorized,
                        wire::MSG_ADMIN_COMMAND,
                        &s.msg_buf[..pl],
                    );
                }
                s.authorized_count += 1;
            } else {
                if s.out_denied >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_denied, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        let resp = [conn_id, wire::ADMIN_STATUS_REJECTED];
                        wire_channels::channel_write_msg(
                            sys,
                            s.out_denied,
                            wire::MSG_ADMIN_RESPONSE,
                            &resp,
                        );
                    }
                }
                s.denied_count += 1;
            }

            // Audit envelope: `[authorized:u8][role:u8][conn_id:u8]`.
            if s.out_audit >= 0 {
                let poll_out = (sys.channel_poll)(s.out_audit, 0x02);
                if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                    let audit = [authorized as u8, role, conn_id];
                    wire_channels::channel_write_msg(sys, s.out_audit, wire::MSG_METRICS, &audit);
                }
            }
        }

        0
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_identity(s: &mut ModuleState, sys: &SyscallTable) {
    if s.in_identity < 0 {
        return;
    }
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_identity, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 {
            break;
        }
        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_identity, &mut s.msg_buf);
        if msg_type != wire::MSG_PEER_IDENTITY {
            continue;
        }
        let pl = plen as usize;
        let (conn_id, _replica_id, verified, svid_off) =
            match wire::decode_peer_identity(&s.msg_buf[..pl]) {
                Some(v) => v,
                None => continue,
            };
        // Copy the SVID out of the shared scratch buffer first so the
        // subsequent `&mut s` borrow doesn't clash with the slice.
        let svid_len = pl.saturating_sub(svid_off).min(SVID_PREFIX_MAX);
        let mut svid_local = [0u8; SVID_PREFIX_MAX];
        if svid_len > 0 {
            svid_local[..svid_len].copy_from_slice(&s.msg_buf[svid_off..svid_off + svid_len]);
        }
        record_identity(s, conn_id, verified, &svid_local[..svid_len]);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut ModuleState` (or shared
/// `&ModuleState` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn record_identity(s: &mut ModuleState, conn_id: u8, verified: bool, svid: &[u8]) {
    // Refuse to downgrade a TLS-verified binding via a plaintext envelope.
    if let Some(existing) = find_binding(s, conn_id) {
        if s.bindings[existing].tls_verified && !verified {
            return;
        }
    }
    let role = role_for_svid(s, svid);
    let slot_idx = match find_binding(s, conn_id) {
        Some(i) => i,
        None => match s.bindings.iter().position(|b| b.is_empty()) {
            Some(i) => i,
            None => return, // table full; new conn loses RBAC binding.
        },
    };
    let take = svid.len().min(SVID_PREFIX_MAX);
    let b = &mut s.bindings[slot_idx];
    b.conn_id = conn_id;
    b.role = role;
    b.tls_verified = verified;
    b.svid_len = take as u8;
    b.svid[..take].copy_from_slice(&svid[..take]);
}

fn find_binding(s: &ModuleState, conn_id: u8) -> Option<usize> {
    for (i, b) in s.bindings.iter().enumerate() {
        if !b.is_empty() && b.conn_id == conn_id {
            return Some(i);
        }
    }
    None
}

fn lookup_role(s: &ModuleState, conn_id: u8) -> u8 {
    match find_binding(s, conn_id) {
        Some(i) => s.bindings[i].role,
        None => s.default_role,
    }
}

fn role_for_svid(s: &ModuleState, svid: &[u8]) -> u8 {
    // Empty prefix = no policy → fall through to default_role for
    // verified peers, observer for plaintext peers (defensible default
    // for the day someone wires identity without setting a policy).
    let admin = prefix_match(svid, &s.admin_prefix, s.admin_prefix_len as usize);
    let observer = prefix_match(svid, &s.observer_prefix, s.observer_prefix_len as usize);
    if admin {
        ROLE_OPERATOR | ROLE_BREAKGLASS
    } else if observer {
        ROLE_OBSERVER
    } else if s.admin_prefix_len == 0 && s.observer_prefix_len == 0 {
        // No policy configured. Honour module-wide default_role.
        s.default_role
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
