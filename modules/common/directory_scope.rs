//! directory_scope — which tier a session directory serves, and which
//! requests belong to it (docs/architecture/multi_site.md §Data locality).
//!
//! rfc_lb_vip §13.6 splits authority in two: a low-rate global group whose
//! voters span sites commits each service's region owner set, its DR
//! generation and regional invalidation, and each regional cell's groups
//! own everything a session, flow or address is bound by. A directory is
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
/// boundaries, reservations, takeover and evacuation records; never `rg/`.
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

/// Whether request `msg` (its command body after the request id) belongs
/// to tier `scope`; `Err(reason)` when the other tier owns it. A message
/// that is no directory request is admitted (its own path refuses it).
pub fn scope_admits(scope: u8, msg: u8, body: &[u8]) -> Result<(), u8> {
    match scope {
        SCOPE_CELL if msg == MSG_RG_REQUEST => Err(DIR_SCOPE_NAMESPACE),
        SCOPE_GLOBAL => match msg {
            MSG_RG_REQUEST => Ok(()),
            MSG_OP_REQUEST => {
                // A CAS names its record's kind; a REPLAY `[2][kind]` the
                // kind it asks for (0: every kind, which here is only the
                // global tier's).
                let kind = match body.first() {
                    Some(&OP_OP_CAS) => body.get(OP_CAS_KIND_AT).copied(),
                    Some(&OP_OP_REPLAY) => body.get(1).copied(),
                    _ => None,
                };
                match kind {
                    Some(0 | OP_KIND_REGION | OP_KIND_EVACUATION) | None => Ok(()),
                    Some(_) => Err(DIR_SCOPE_OP_KIND),
                }
            }
            MSG_SR_REQUEST | MSG_TR_REQUEST | MSG_VB_REQUEST | MSG_FO_REQUEST | MSG_AT_REQUEST
            | MSG_RS_REQUEST => Err(DIR_SCOPE_NAMESPACE),
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}
