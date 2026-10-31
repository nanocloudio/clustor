//! directory_scope — which tier a session directory serves, and which
//! requests belong to it (docs/architecture/multi_site.md §Data locality).
//!
//! Authority is split in two: a low-rate global group whose voters span
//! sites commits each service's region owner set, its DR generation,
//! regional invalidation and the operations that move authority between
//! regions, and each regional cell's groups own everything a session, flow
//! or address is bound by. A directory is
//! deployed for one of them (`scope`) and refuses — before proposing, so
//! it never enters the log — a request in a namespace the other owns:
//! a session's state never replicates across sites, and the global log
//! carries only what a site loss must not take away.
//!
//! Pure, `no_std`, allocation-free; `#[path]`-mounted by `session_directory`
//! and the host tests.

#![allow(
    dead_code,
    reason = "shared #[path]-mounted helper; each consumer uses a subset"
)]

/// Both tiers in one group: a deployment confined to one region, which
/// omits the global tier (the default).
pub const SCOPE_ALL: u8 = 0;
/// A regional cell: sessions, flows, VIPs, failover records, attachment
/// boundaries, reservations, takeover and evacuation records; never `rg/`
/// and never a REGION operation, which is ordered with the ownership it
/// moves in the global log.
pub const SCOPE_CELL: u8 = 1;
/// The multi-site global tier: `rg/` and the operation records that move
/// authority between regions (REGION, and EVACUATION of a cell or region).
pub const SCOPE_GLOBAL: u8 = 2;

/// The request message ids (`wire.rs`).
const MSG_SR_REQUEST: u8 = 0x90;
const MSG_TR_REQUEST: u8 = 0x92;
const MSG_VB_REQUEST: u8 = 0x94;
const MSG_FO_REQUEST: u8 = 0x96;
const MSG_RG_REQUEST: u8 = 0x98;
const MSG_OP_REQUEST: u8 = 0x9A;
const MSG_AT_REQUEST: u8 = 0x9C;
const MSG_RS_REQUEST: u8 = 0x9E;

/// `MSG_DIR_OUT_OF_SCOPE` reasons (`wire.rs`).
pub const DIR_SCOPE_NAMESPACE: u8 = 1;
pub const DIR_SCOPE_OP_KIND: u8 = 2;

/// `op/` command bytes and record kinds (`operation_registry.rs`).
const OP_OP_CAS: u8 = 1;
const OP_OP_REPLAY: u8 = 2;
const OP_KIND_EVACUATION: u8 = 2;
const OP_KIND_REGION: u8 = 3;
/// A CAS body is `[op][record]`; the record's kind is its byte 24.
const OP_CAS_KIND_AT: usize = 1 + 24;

/// The `op/` record kind a request names: a CAS its record's, a REPLAY
/// `[2][kind]` the kind it asks for (0: every kind). `None` for a body too
/// short to name one, which the registry refuses itself.
fn op_kind(body: &[u8]) -> Option<u8> {
    match body.first() {
        Some(&OP_OP_CAS) => body.get(OP_CAS_KIND_AT).copied(),
        Some(&OP_OP_REPLAY) => body.get(1).copied(),
        _ => None,
    }
}

/// Whether request `msg` (its command body after the request id) belongs
/// to tier `scope`; `Err(reason)` when the other tier owns it. A message
/// that is no directory request is admitted (its own path refuses it). A
/// scope outside the three admits nothing: a mistyped tier fails closed
/// rather than serving both.
pub fn scope_admits(scope: u8, msg: u8, body: &[u8]) -> Result<(), u8> {
    match scope {
        SCOPE_ALL => Ok(()),
        SCOPE_CELL => match msg {
            MSG_RG_REQUEST => Err(DIR_SCOPE_NAMESPACE),
            MSG_OP_REQUEST if op_kind(body) == Some(OP_KIND_REGION) => Err(DIR_SCOPE_OP_KIND),
            _ => Ok(()),
        },
        SCOPE_GLOBAL => match msg {
            MSG_RG_REQUEST => Ok(()),
            // REPLAY of every kind, here, is of the global tier's kinds.
            MSG_OP_REQUEST => match op_kind(body) {
                Some(0 | OP_KIND_REGION | OP_KIND_EVACUATION) | None => Ok(()),
                Some(_) => Err(DIR_SCOPE_OP_KIND),
            },
            MSG_SR_REQUEST | MSG_TR_REQUEST | MSG_VB_REQUEST | MSG_FO_REQUEST | MSG_AT_REQUEST
            | MSG_RS_REQUEST => Err(DIR_SCOPE_NAMESPACE),
            _ => Ok(()),
        },
        _ => Err(DIR_SCOPE_NAMESPACE),
    }
}
