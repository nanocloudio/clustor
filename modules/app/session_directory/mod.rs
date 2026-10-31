//! session_directory — the session-directory / reservation-authority role
//! fluxor's session protocol defines, as a Clustor replicated consumer.
//!
//! The deterministic state machine lives in
//! `modules/common/session_registry.rs` (host-tested by
//! `tests/session_registry.rs`); this module is the wiring:
//!
//! - **Requests** (`MSG_SR_REQUEST`, payload
//!   `[request_id:u64][SR_OP_* command body]`) arrive from anchors /
//!   orchestrators on `requests`. Each is wrapped in a tagged raft
//!   proposal (`replica_facade::build_tagged_proposal`) and written to
//!   `consensus.proposals_tagged` as `MSG_CLIENT_PROPOSAL`.
//! - **Committed entries** arrive back on `committed_entries` in
//!   strict order; every entry is applied to the registry. If the
//!   entry's correlation matches one of OUR pending requests, the
//!   reply (`MSG_SR_REPLY`) goes out on `replies`.
//!
//!   Replying only from the committed-entry stream is the load-bearing
//!   invariant: a reservation grant, an epoch bump, a fence record, or
//!   an auth-relevant write is acknowledged ONLY after it is
//!   quorum-committed. "Quorum-durable before emit" and "RPO-zero
//!   before acted upon" are the same boundary, and it lives on exactly
//!   this edge. There is no fast-path ack.
//!
//! - **Namespaces**: the same ports and log carry the
//!   `transport/<flow_id>` namespace (`MSG_TR_REQUEST` / `MSG_TR_REPLY`,
//!   `modules/common/transport_registry.rs`, magic `"TR"`) and the
//!   `vip/<service_address>` namespace (`MSG_VB_REQUEST` /
//!   `MSG_VB_REPLY`, `modules/common/vip_registry.rs`, magic `"VB"`) and
//!   the `fo/<operation_id>` failover-operation store (`MSG_FO_REQUEST` /
//!   `MSG_FO_REPLY`, `modules/common/failover_registry.rs`, magic `"FO"`:
//!   a coordinator's compare-and-swap record, replayed to it on
//!   reconnection), the `rg/<service>` global tier (`MSG_RG_REQUEST` /
//!   `MSG_RG_REPLY`, `modules/common/region_registry.rs`, magic `"RG"`:
//!   region owner sets, DR generations, regional invalidation) and the
//!   `op/<operation_id>` operation store (`MSG_OP_REQUEST` /
//!   `MSG_OP_REPLY`, `modules/common/operation_registry.rs`, magic `"OP"`:
//!   takeover, evacuation and DR operation records), the
//!   `att/<attachment_id>` boundaries (`MSG_AT_REQUEST` / `MSG_AT_REPLY`,
//!   `modules/common/attachment_registry.rs`, magic `"AT"`: attachment
//!   generations and service revocation boundaries) and the `rs/`
//!   reservations (`MSG_RS_REQUEST` / `MSG_RS_REPLY`,
//!   `modules/common/reservation_registry.rs`, magic `"RS"`: egress blocks
//!   per gateway incarnation and address ranges, horizons in committed
//!   time) beside the session registry (`"SR"`); each is its own
//!   deterministic state machine, proposed, committed, acknowledged and
//!   snapshotted on exactly the same path.
//! - **Profiles**: the arenas are static per
//!   `[[variant]]` (`rp2350` 64 sessions, `pi5` 4096, `server` 65536)
//!   and the `profile` parameter names the capacity a deployment admits
//!   and reports; a profile larger than the variant's arena refuses to
//!   start rather than claim it.
//! - **Snapshots**: every registry streams versioned records (a header,
//!   one record per live slot, the timing section) rather than a
//!   whole-arena image; export/install ride the standard
//!   `MSG_APP_SNAPSHOT_*` chunk envelopes, chunked at `SNAP_CHUNK` bytes,
//!   with one record's worth of staging rather than a buffer that scales
//!   with the profile. An export spans steps and holds committed applies
//!   until it completes, so the image is the state at one index; a
//!   rejected install leaves the registries empty and holds applies until
//!   an install succeeds (fail closed, never apply onto a partial image).
//! - **Telemetry**: `MON_SESSION` lines (fluxor
//!   `monitor-protocol.md`) on every continuity-relevant transition —
//!   `attached` / `relocated`, `reservation_granted`, `epoch_bump`,
//!   `fence_initiated` / `fence_confirmed`, `vip_moved` (a fenced session
//!   ACTIVATE, and a committed VIP ACTIVATE), `detached`,
//!   `unsafe_recovery_epoch_void`, `rejected` — so a failover is legible
//!   on the same channel as the rest of the platform.
//!
//! **Fence honesty.** This module records fence state and the
//! registry refuses an anchor takeover (ACTIVATE) until a fence is
//! CONFIRMED against the anchor being replaced and the takeover presents
//! that confirmation's generation, which enforces the ordering. It cannot
//! make a fence enforceable — that is the out-of-band fence agent's job, a
//! member placed outside the failure domain whose cut is power or the
//! fabric port. FENCE_CONFIRM must be proposed only from the agent's own
//! `MSG_ADDR_FENCED`, carrying the custody generation it reports.
//!
//! - **Token checks** (`MSG_TOKEN_CHECK`, `MSG_ARM_AUTH_CHECK`) arrive on
//!   `checks` and are linearizable: each is held behind a barrier entry
//!   (magic `"CK"`, no body, no state) and answered on `replies` once
//!   this replica's applied state has reached it, so a verdict reflects
//!   every command committed before the check arrived.
//! - **Deterministic timing**: this module hosts the leader-fenced time
//!   producer for its state machine. When (and only when) this node is
//!   the PRG leader per
//!   `MSG_LEADER_HINT`, its clock guard is healthy, and the timing
//!   index has work (live deadlines / due backlog / a pending
//!   duration admission), it proposes `TimeAdvance` / `TimeDrain`
//!   entries through the ordinary tagged-proposal path. An idle PRG
//!   proposes no time entries (idle coalescing). Committed
//!   timing entries come back on `committed_entries` like every other
//!   entry and are applied to the registry's embedded `TimingState` —
//!   deadlines fire ONLY during committed apply, never from a local
//!   timer.
//!
//! # Parameters (TLV v2)
//!
//! | Tag | Name       | Type | Default | Description                              |
//! |-----|------------|------|---------|------------------------------------------|
//! | 1   | replica_id | u8   | 0       | Stamped into correlation ids (uniqueness across proposers). Must equal the node's raft id — the leader fence compares it against MSG_LEADER_HINT. |
//! | 2   | smoke      | u8   | 0       | 1 = propose a BIND + two RESERVEs at boot; the committed grants prove the quorum path end-to-end (e2e assertion hook). 2 = additionally propose a KEY_PUT with a 1500 ms TTL after the grants — its committed expiry proves the deterministic-timing path end-to-end. |
//! | 3   | time_advance_period_ms | u32 | 1000 | Target committed-time cadence while deadlines are pending. |
//! | 4   | logical_max_step_ms    | u32 | 60000 | Max forward movement of logical time per proposed entry (forward-jump clamp). |
//! | 5   | clock_slew_tolerance_ms | u32 | 2000 | Wall-vs-monotonic disagreement tolerated before the backward-jump alarm. Default sized for the pi5's ~1 s-granular UNIX_MILLIS (apparent slews ≥1100 ms on healthy rigs); a tighter value false-alarms and pauses deterministic time production. |
//! | 6   | logical_staleness_ms   | u32 | 5000 | Duration-admission freshness bound: a TTL command observed while logical time lags wall time by more than this triggers a time-freshness barrier (admission-time only). |
//! | 7   | partition_id           | u32 | 0    | The raft group whose log this directory is. An engine hosting several groups writes them all to one committed stream; only this group's entries apply here. |
//! | 8   | forwarded_stream       | u8  | 0    | 1 = `committed_entries` is a forwarder's selection of the group's log (this directory's entries only, in order), so an index jump is an omission, not a loss. 0 = the whole log, where a gap is a fault recovered by snapshot install. |
//! | 9   | profile                | u8  | 0    | Capacity profile admitted and reported: 0 = rp2350 (64 sessions / 64 flows / 16 VIP bindings), 1 = pi5 (4096 / 4096 / 1024), 2 = server (65536 / 65536 / 16384). Must fit the variant's arena or init fails (-3). |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    unused_imports,
    dead_code,
    unreachable_patterns,
    reason = "the fluxor SDK is include!'d wholesale and each module consumes only a subset; defensive `_ =>` arms are intentional"
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

use abi::contracts::net::session_ctrl;
#[path = "../../common/attachment_registry.rs"]
mod attachment_registry;
#[path = "../../common/check_barrier.rs"]
mod check_barrier;
use check_barrier::{Assigned, CheckBarrier, MAX_CHECKS};
#[path = "../../common/directory_scope.rs"]
mod directory_scope;
#[path = "../../common/session_directory_face.rs"]
mod face;
#[path = "../../common/failover_registry.rs"]
mod failover_registry;
#[path = "../../common/operation_registry.rs"]
mod operation_registry;
#[path = "../../common/region_registry.rs"]
mod region_registry;
#[path = "../../common/replica_facade.rs"]
mod replica_facade;
#[path = "../../common/reservation_registry.rs"]
mod reservation_registry;
#[path = "../../common/session_registry.rs"]
mod session_registry;
/// The SDK's SHA-256: the digest the VIP registry derives emission-token
/// capabilities with (and the custody-context digest for bound keys).
#[path = "../../../target/fluxor/fluxor-abi/sdk/crypto/sha256.rs"]
mod sha256;
#[path = "../../common/slot_index.rs"]
mod slot_index;
#[path = "../../common/transport_registry.rs"]
mod transport_registry;
#[path = "../../common/vip_registry.rs"]
mod vip_registry;
use face::{
    grant_command, hello_ack, reply_to_frame, request_to_command, FACE_ATTACH, FACE_DETACH,
    FACE_EPOCH_BUMP, FACE_GRANT, FACE_NONE,
};
use session_ctrl as sc;
#[path = "../../common/timing.rs"]
mod timing;
#[path = "../../common/wal_frame.rs"]
mod wal_frame;
#[path = "../../common/wire.rs"]
mod wire;
#[path = "../../common/wire_channels.rs"]
mod wire_channels;

use attachment_registry::{
    AtExportCursor, AtInstaller, AttachmentRegistry, AttachmentReply, AT_MAX_CMD, AT_PROFILE_PI5,
    AT_PROFILE_RP2350, AT_PROFILE_SERVER, AT_REPLY_LEN, AT_SERVICES_PI5, AT_SERVICES_RP2350,
    AT_SERVICES_SERVER, AT_SNAP_MAX_UNIT, AT_ST_OK,
};
use failover_registry::{
    FailoverRegistry, FailoverReply, FoExportCursor, FoInstaller, FO_MAX_CMD, FO_OP_REPLAY,
    FO_PROFILE_PI5, FO_PROFILE_RP2350, FO_PROFILE_SERVER, FO_REPLY_LEN, FO_SNAP_MAX_UNIT, FO_ST_OK,
    FO_ST_REPLAY,
};
use operation_registry::{
    OpExportCursor, OpInstaller, OperationRegistry, OperationReply, OP_MAX_CMD, OP_OP_REPLAY,
    OP_PROFILE_PI5, OP_PROFILE_RP2350, OP_PROFILE_SERVER, OP_REPLY_LEN, OP_SNAP_MAX_UNIT, OP_ST_OK,
    OP_ST_REPLAY,
};
use region_registry::{
    RegionRegistry, RgExportCursor, RgInstaller, RgReply, RG_INVALIDATE_LEN, RG_MAX_CMD,
    RG_OP_INVALIDATE, RG_OWNERS_PI5, RG_OWNERS_RP2350, RG_OWNERS_SERVER, RG_PROFILE_PI5,
    RG_PROFILE_RP2350, RG_PROFILE_SERVER, RG_REPLY_LEN, RG_SNAP_MAX_UNIT,
};
use replica_facade::{CommitOrderError, CommittedSubscriber, TAGGED_PROPOSAL_HDR};
use reservation_registry::{
    carries_horizon, ReservationRegistry, ReservationReply, RsExportCursor, RsInstaller,
    RS_ADDRS_PI5, RS_ADDRS_RP2350, RS_ADDRS_SERVER, RS_BLOCKS_PI5, RS_BLOCKS_RP2350,
    RS_BLOCKS_SERVER, RS_MAX_CMD, RS_REPLY_LEN, RS_SNAP_MAX_UNIT, RS_ST_OK,
};
use session_registry::*;
use timing::{ClockGuard, ClockHealth};
use transport_registry::{
    encode_token_trailer, TrExportCursor, TrInstaller, TransportRegistry, TransportReply,
    TR_MAX_CMD, TR_OP_MOVE, TR_OP_MOVE_FENCED, TR_PROFILE_PI5, TR_PROFILE_RP2350,
    TR_PROFILE_SERVER, TR_REPLY_LEN, TR_SNAP_MAX_UNIT, TR_ST_OK, TR_TOKEN_LEN, TR_WIRE_REPLY_LEN,
};
use vip_registry::{
    build_seed, VbExportCursor, VbInstaller, VipRegistry, VipReply, VB_MAX_CMD, VB_OP_ACTIVATE,
    VB_OP_SEED, VB_OWNERS_PI5, VB_OWNERS_RP2350, VB_OWNERS_SERVER, VB_PROFILE_PI5,
    VB_PROFILE_RP2350, VB_PROFILE_SERVER, VB_REPLY_LEN, VB_SEED, VB_SNAP_MAX_UNIT, VB_ST_OK,
    VB_ST_UNAUTHORIZED, VB_TOKEN_LEN,
};

// ── Profile (variant-selected arenas) ───────────────────────────────
//
// The arena is a compile-time size; the `profile` parameter admits at
// most that. Variants: `rp2350` (default), `pi5`, `server`.

#[cfg(feature = "profile-server")]
mod profile {
    use super::*;
    pub const SESSIONS: usize = SR_PROFILE_SERVER;
    pub const DEADLINES: usize = SR_DEADLINES_SERVER;
    pub const FLOWS: usize = TR_PROFILE_SERVER;
    pub const BINDINGS: usize = VB_PROFILE_SERVER;
    pub const OWNERS: usize = VB_OWNERS_SERVER;
    pub const OPERATIONS: usize = FO_PROFILE_SERVER;
    pub const SERVICES: usize = RG_PROFILE_SERVER;
    pub const REGIONS: usize = RG_OWNERS_SERVER;
    pub const RECORDS: usize = OP_PROFILE_SERVER;
    pub const ATTACHMENTS: usize = AT_PROFILE_SERVER;
    pub const PRODUCERS: usize = AT_SERVICES_SERVER;
    pub const BLOCKS: usize = RS_BLOCKS_SERVER;
    pub const ADDRS: usize = RS_ADDRS_SERVER;
}
#[cfg(all(feature = "profile-pi5", not(feature = "profile-server")))]
mod profile {
    use super::*;
    pub const SESSIONS: usize = SR_PROFILE_PI5;
    pub const DEADLINES: usize = SR_DEADLINES_PI5;
    pub const FLOWS: usize = TR_PROFILE_PI5;
    pub const BINDINGS: usize = VB_PROFILE_PI5;
    pub const OWNERS: usize = VB_OWNERS_PI5;
    pub const OPERATIONS: usize = FO_PROFILE_PI5;
    pub const SERVICES: usize = RG_PROFILE_PI5;
    pub const REGIONS: usize = RG_OWNERS_PI5;
    pub const RECORDS: usize = OP_PROFILE_PI5;
    pub const ATTACHMENTS: usize = AT_PROFILE_PI5;
    pub const PRODUCERS: usize = AT_SERVICES_PI5;
    pub const BLOCKS: usize = RS_BLOCKS_PI5;
    pub const ADDRS: usize = RS_ADDRS_PI5;
}
#[cfg(not(any(feature = "profile-pi5", feature = "profile-server")))]
mod profile {
    use super::*;
    pub const SESSIONS: usize = SR_PROFILE_RP2350;
    pub const DEADLINES: usize = SR_DEADLINES_RP2350;
    pub const FLOWS: usize = TR_PROFILE_RP2350;
    pub const BINDINGS: usize = VB_PROFILE_RP2350;
    pub const OWNERS: usize = VB_OWNERS_RP2350;
    pub const OPERATIONS: usize = FO_PROFILE_RP2350;
    pub const SERVICES: usize = RG_PROFILE_RP2350;
    pub const REGIONS: usize = RG_OWNERS_RP2350;
    pub const RECORDS: usize = OP_PROFILE_RP2350;
    pub const ATTACHMENTS: usize = AT_PROFILE_RP2350;
    pub const PRODUCERS: usize = AT_SERVICES_RP2350;
    pub const BLOCKS: usize = RS_BLOCKS_RP2350;
    pub const ADDRS: usize = RS_ADDRS_RP2350;
}

type Registry = SessionRegistry<{ profile::SESSIONS }, { profile::DEADLINES }>;
type Transport = TransportRegistry<{ profile::FLOWS }>;
type Vip = VipRegistry<{ profile::BINDINGS }, { profile::OWNERS }>;
type Failover = FailoverRegistry<{ profile::OPERATIONS }>;
type Region = RegionRegistry<{ profile::SERVICES }, { profile::REGIONS }>;
type Operations = OperationRegistry<{ profile::RECORDS }>;
type Attachments = AttachmentRegistry<{ profile::ATTACHMENTS }, { profile::PRODUCERS }>;
type Reservations = ReservationRegistry<{ profile::BLOCKS }, { profile::ADDRS }>;

/// `profile` parameter values.
const PROFILE_RP2350: u8 = 0;
const PROFILE_PI5: u8 = 1;
const PROFILE_SERVER: u8 = 2;

/// What a profile value admits in each arena. Owner widths are not
/// admitted counts: they are the variant's record shape, fixed at build.
#[derive(Clone, Copy)]
struct Admits {
    sessions: usize,
    flows: usize,
    bindings: usize,
    operations: usize,
    services: usize,
    records: usize,
    attachments: usize,
    producers: usize,
    blocks: usize,
    addrs: usize,
}

fn profile_admits(profile: u8) -> Option<Admits> {
    match profile {
        PROFILE_RP2350 => Some(Admits {
            sessions: SR_PROFILE_RP2350,
            flows: TR_PROFILE_RP2350,
            bindings: VB_PROFILE_RP2350,
            operations: FO_PROFILE_RP2350,
            services: RG_PROFILE_RP2350,
            records: OP_PROFILE_RP2350,
            attachments: AT_PROFILE_RP2350,
            producers: AT_SERVICES_RP2350,
            blocks: RS_BLOCKS_RP2350,
            addrs: RS_ADDRS_RP2350,
        }),
        PROFILE_PI5 => Some(Admits {
            sessions: SR_PROFILE_PI5,
            flows: TR_PROFILE_PI5,
            bindings: VB_PROFILE_PI5,
            operations: FO_PROFILE_PI5,
            services: RG_PROFILE_PI5,
            records: OP_PROFILE_PI5,
            attachments: AT_PROFILE_PI5,
            producers: AT_SERVICES_PI5,
            blocks: RS_BLOCKS_PI5,
            addrs: RS_ADDRS_PI5,
        }),
        PROFILE_SERVER => Some(Admits {
            sessions: SR_PROFILE_SERVER,
            flows: TR_PROFILE_SERVER,
            bindings: VB_PROFILE_SERVER,
            operations: FO_PROFILE_SERVER,
            services: RG_PROFILE_SERVER,
            records: OP_PROFILE_SERVER,
            attachments: AT_PROFILE_SERVER,
            producers: AT_SERVICES_SERVER,
            blocks: RS_BLOCKS_SERVER,
            addrs: RS_ADDRS_SERVER,
        }),
        _ => None,
    }
}

/// The digest every namespace derives with.
fn digest(m: &[u8]) -> [u8; 32] {
    sha256::sha256(m)
}

/// Fluxor's continuity provider asks whether a per-flow emission token is
/// the flow's current one (`[token:48]`, TRANSPORT_CONTINUITY's
/// `MSG_TOKEN_CHECK`); answered `[token:48][verdict:u8]`.
const MSG_FLOW_TOKEN_CHECK: u8 = 0xC2;
const MSG_FLOW_TOKEN_VERDICT: u8 = 0xC3;
/// Fluxor's `ip` asks before arming an address under `arm_authority`
/// (`identity::MSG_ARM_AUTH_CHECK`): `[addr:16][generation:u32 LE]
/// [boot_incarnation:16][auth_len:u16 LE][auth]`, the auth a VIP emission
/// token; answered `[addr:16][generation:u32 LE][sha256(auth):32]
/// [verdict:u8]`.
const MSG_ARM_AUTH_CHECK: u8 = 0x7A;
const MSG_ARM_AUTH_VERDICT: u8 = 0x7B;
/// The largest auth an arm check carries (Fluxor's `ARM_AUTH_MAX`).
const ARM_AUTH_MAX: usize = 160;
/// The largest check either provider sends: an arm check carrying
/// `ARM_AUTH_MAX` bytes of auth.
const CHECK_REQ_MAX: usize = 16 + 4 + 16 + 2 + ARM_AUTH_MAX;

/// A token check's log barrier: an entry of this prefix alone, changing
/// no state. Its commit orders the check after every command committed
/// before the check arrived (raft appends it behind them all), so a
/// replica whose applied state has reached it answers as the group's
/// committed state then stood, never from a lagging view.
const CK_CMD_MAGIC: [u8; 2] = *b"CK";

/// An arm check whose auth is longer than any Fluxor sends is refused, not
/// dropped: the verdict names the digest of the whole auth, so the
/// provider matches it to its request rather than waiting out its timeout.
unsafe fn refuse_oversized_arm_check(s: &mut ModuleState, plen: usize) {
    let sys = &*s.syscalls;
    s.token_checks = s.token_checks.saturating_add(1);
    s.token_refusals = s.token_refusals.saturating_add(1);
    if plen < 38 {
        return;
    }
    let mut out = [0u8; 16 + 4 + 32 + 1];
    out[..20].copy_from_slice(&s.msg_buf[..20]);
    out[20..52].copy_from_slice(&digest(&s.msg_buf[38..plen]));
    out[52] = 0x80 | VB_ST_UNAUTHORIZED;
    let _ = wire_channels::channel_write_msg(sys, s.out_replies, MSG_ARM_AUTH_VERDICT, &out);
}

/// Answer a token check from this replica's applied registries — called
/// once they have reached the check's barrier: the verdict is 0 for a
/// token that verifies, else the registry's refusal code (`0x80 |` it);
/// an unseeded group or a malformed check refuses.
unsafe fn answer_token_check(s: &mut ModuleState, msg_type: u8, req: &[u8]) {
    let sys = &*s.syscalls;
    s.token_checks = s.token_checks.saturating_add(1);
    if msg_type == MSG_FLOW_TOKEN_CHECK {
        let mut out = [0u8; TR_TOKEN_LEN + 1];
        let Some(v) = s
            .transport
            .answer_token_check(req, &s.vip.seed, digest, &mut out)
        else {
            return;
        };
        if v != 0 {
            s.token_refusals = s.token_refusals.saturating_add(1);
        }
        let _ = wire_channels::channel_write_msg(sys, s.out_replies, MSG_FLOW_TOKEN_VERDICT, &out);
    } else {
        let mut out = [0u8; 16 + 4 + 32 + 1];
        let Some(v) = s.vip.answer_arm_check(req, digest, &mut out) else {
            return;
        };
        if v != 0 {
            s.token_refusals = s.token_refusals.saturating_add(1);
        }
        let _ = wire_channels::channel_write_msg(sys, s.out_replies, MSG_ARM_AUTH_VERDICT, &out);
    }
}

/// Two-byte prefix on every replicated registry command so registry
/// entries are unambiguous in the shared raft log (admin ops, client
/// KV commands, and future consumers share the same entry stream —
/// an opcode byte alone is not a namespace).
const SR_CMD_MAGIC: [u8; 2] = *b"SR";
/// The transport namespace's prefix (`transport_registry.rs`).
const TR_CMD_MAGIC: [u8; 2] = *b"TR";
/// The VIP namespace's prefix (`vip_registry.rs`).
const VB_CMD_MAGIC: [u8; 2] = *b"VB";
/// The failover-operation namespace's prefix (`failover_registry.rs`).
const FO_CMD_MAGIC: [u8; 2] = *b"FO";
/// The global tier's prefix (`region_registry.rs`).
const RG_CMD_MAGIC: [u8; 2] = *b"RG";
/// The operation store's prefix (`operation_registry.rs`).
const OP_CMD_MAGIC: [u8; 2] = *b"OP";
/// The attachment boundaries' prefix (`attachment_registry.rs`).
const AT_CMD_MAGIC: [u8; 2] = *b"AT";
/// The reservations' prefix (`reservation_registry.rs`).
const RS_CMD_MAGIC: [u8; 2] = *b"RS";

/// Which namespace a pending proposal answers on.
const NS_SR: u8 = 0;
const NS_TR: u8 = 1;
const NS_VB: u8 = 2;
const NS_FO: u8 = 3;
const NS_RG: u8 = 4;
const NS_OP: u8 = 5;
const NS_AT: u8 = 6;
const NS_RS: u8 = 7;

const fn max_usize(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

/// Largest command body any namespace replicates (derived from the
/// registries' own bounds).
const CMD_MAX: usize = max_usize(
    max_usize(
        max_usize(max_usize(SR_MAX_CMD, TR_MAX_CMD), VB_MAX_CMD),
        FO_MAX_CMD,
    ),
    max_usize(
        max_usize(RG_MAX_CMD, OP_MAX_CMD),
        max_usize(AT_MAX_CMD, RS_MAX_CMD),
    ),
);
/// Largest streamed-snapshot unit any registry exports (derived).
const SNAP_UNIT_MAX: usize = max_usize(
    max_usize(
        max_usize(
            max_usize(SR_SNAP_MAX_UNIT, TR_SNAP_MAX_UNIT),
            VB_SNAP_MAX_UNIT,
        ),
        FO_SNAP_MAX_UNIT,
    ),
    max_usize(
        max_usize(RG_SNAP_MAX_UNIT, OP_SNAP_MAX_UNIT),
        max_usize(AT_SNAP_MAX_UNIT, RS_SNAP_MAX_UNIT),
    ),
);
/// Largest reply any namespace encodes (derived; the transport reply
/// with its token trailer).
const REPLY_MAX: usize = max_usize(
    max_usize(
        max_usize(max_usize(SR_REPLY_LEN, TR_WIRE_REPLY_LEN), VB_REPLY_LEN),
        FO_REPLY_LEN,
    ),
    max_usize(
        max_usize(RG_REPLY_LEN, OP_REPLY_LEN),
        max_usize(AT_REPLY_LEN, RS_REPLY_LEN),
    ),
);
const _: () = assert!(
    CMD_MAX + 2 <= MSG_BUF && TR_WIRE_REPLY_LEN > TR_REPLY_LEN,
    "every namespace's command fits the entry body"
);

/// Pending request table: correlation → request_id. Small — the
/// directory is a control-plane service; a full table backpressures
/// new requests rather than dropping replies.
const MAX_PENDING: usize = 16;

/// Reclaim TTL for pending-proposal slots. A slot whose
/// `MSG_PROPOSAL_ASSIGNED` (or committed entry) is lost would
/// otherwise leak forever — and after `MAX_PENDING` leaks the module
/// stops consuming requests until restart. An order of magnitude
/// above the raft propose→commit window (the per-second cadences used
/// elsewhere in this module), so a live proposal is never reclaimed.
/// There is no substrate timeout reply shape (`SR_ST_*` has none), so
/// the requester's reply-timeout retry is the client-visible signal —
/// the same policy as the consumed-but-unproposable drop in step 2.
const PENDING_TTL_MS: u64 = 10_000;

/// Snapshot chunk body size. The streamed image is a header plus one
/// record per live slot per namespace (~300 bytes a session, ~230 a flow,
/// ~1.2 KiB a VIP binding), so an idle rig exports in one chunk and a
/// full rp2350 arena in a few dozen; a profile-sized export spans steps.
/// A record may be larger than a chunk: the staging holds a chunk plus
/// the largest record.
const SNAP_CHUNK: usize = 1024;

/// Snapshot section order within one image: the session registry, the
/// transport registry, the VIP registry, the failover-operation store, the
/// global tier, the operation store, the attachment boundaries, then the
/// reservations. The session registry's header leads the image, so its
/// `SNAPSHOT_VERSION` marks the whole image, and an image of any other
/// shape is refused.
const SNAP_SECTION_SR: u8 = 0;
const SNAP_SECTION_TR: u8 = 1;
const SNAP_SECTION_VB: u8 = 2;
const SNAP_SECTION_FO: u8 = 3;
const SNAP_SECTION_RG: u8 = 4;
const SNAP_SECTION_OP: u8 = 5;
const SNAP_SECTION_AT: u8 = 6;
const SNAP_SECTION_RS: u8 = 7;
const SNAP_SECTION_DONE: u8 = 8;

/// Scratch buffer: committed entries carry the command body
/// (SR_CMD_MAGIC + SR_MAX_CMD) under a 16-byte entry header; snapshot
/// chunks are APP_SNAPSHOT_HDR + SNAP_CHUNK. Sized to the shared WAL
/// entry-body cap (modules/common/wal_frame.rs) — the one value every
/// proposal-carrying buffer in the graph must agree on.
const MSG_BUF: usize = wal_frame::MAX_ENTRY_BODY;

const SMOKE_IDLE: u8 = 0;
const SMOKE_BIND_SENT: u8 = 1;
const SMOKE_RESERVE1_SENT: u8 = 2;
const SMOKE_RESERVE2_SENT: u8 = 3;
const SMOKE_KEY_ARM: u8 = 4;
const SMOKE_KEY_SENT: u8 = 5;
const SMOKE_DONE: u8 = 6;
const SMOKE_OFF: u8 = 0xFF;
/// `smoke: 3`, the site-loss smoke: the leader commits a regional
/// INVALIDATE of `SITE_SMOKE_REGION` one readiness higher every
/// `SITE_SMOKE_PERIOD_MS`, and every replica logs each one it applies
/// (`[sess_dir] site smoke applied readiness=N`) — a commit heartbeat a
/// site-loss test counts across the loss.
const SMOKE_SITE: u8 = 3;
const SITE_SMOKE_PERIOD_MS: u64 = 300;
const SITE_SMOKE_REGION: [u8; 16] = *b"SITE-LOSS-SMOKE1";

use directory_scope::{scope_admits, SCOPE_ALL};

/// TTL for the smoke KEY_PUT (smoke = 2): long enough to commit the
/// put before expiry, short enough for an e2e to observe the fire.
const SMOKE_KEY_TTL_MS: u32 = 1500;

/// Smoke-session identity (only used with `smoke = 1`).
const SMOKE_SID: [u8; SR_SESSION_ID] = *b"SMOKE-SESSION-01";
const SMOKE_ANCHOR: [u8; SR_PEER_ID] = *b"SMOKE-A0";
const SMOKE_WORKER: [u8; SR_PEER_ID] = *b"SMOKE-W0";

#[repr(C)]
struct ModuleState {
    syscalls: *const SyscallTable,

    in_entries: i32,           // in[0]: MSG_COMMITTED_ENTRY from consensus
    in_requests: i32,          // in[1]: MSG_SR_REQUEST from anchors/orchestrators
    in_snapshot_chunk: i32,    // in[2]: MSG_APP_SNAPSHOT_CHUNK / RESET (install)
    in_snapshot_request: i32,  // in[3]: MSG_APP_SNAPSHOT_REQUEST
    in_proposal_assigned: i32, // in[4]: MSG_PROPOSAL_ASSIGNED from consensus
    in_leader_state: i32,      // in[5]: MSG_LEADER_HINT from consensus
    in_ctrl: i32,              // in[6]: SessionCtrlV1 commands from anchors
    in_checks: i32,            // in[7]: token checks from continuity / address providers
    out_proposals: i32,        // out[0]: MSG_CLIENT_PROPOSAL to consensus.proposals_tagged
    out_replies: i32,          // out[1]: every namespace's replies, verdicts, out-of-scope answers
    out_metrics: i32,          // out[2]: MSG_METRICS to operations
    out_snapshot_export: i32,  // out[3]: MSG_APP_SNAPSHOT_CHUNK to durability
    out_ctrl: i32,             // out[4]: SessionCtrlV1 replies and grants to anchors

    // Params
    replica_id: u8,
    smoke: u8,
    smoke_phase: u8,
    /// `scope`: which tier this directory serves (`SCOPE_*`); a request
    /// in a namespace the other tier owns is refused before proposal.
    scope: u8,
    /// The raft group this directory's log is: the committed stream
    /// carries every group's entries, each numbered from 1, and only
    /// this group's are applied here. A proposal the engine assigns to
    /// another group can never be answered and is counted, not waited
    /// for.
    partition_id: u16,
    /// The committed stream reaching this module is a forwarder's
    /// selection of the group's log — this directory's own entries, in
    /// order — rather than the whole log. An index jump is then the
    /// forwarder's omission of other consumers' entries, not a loss,
    /// and the cursor follows it; a lost entry of this directory's own
    /// shows as an unanswered proposal, reclaimed by the pending TTL.
    forwarded_stream: u8,
    _pad4: u8,

    /// The replicated state machines: sessions, flows, VIP bindings,
    /// failover operations, region owner sets, operation records,
    /// attachment boundaries and reservations.
    registry: Registry,
    transport: Transport,
    vip: Vip,
    failover: Failover,
    region: Region,
    ops: Operations,
    attachments: Attachments,
    reservations: Reservations,
    /// Capacity profile parameter (tag 9).
    profile: u8,

    /// Strict-commit-order subscriber.
    subscriber: CommittedSubscriber,

    /// Correlation allocator: `(replica_id << 56) | counter`.
    corr_counter: u64,

    /// Pending proposals awaiting commit: correlation (allocated at
    /// propose), requester id, and the wal_index raft assigned (0
    /// until the MSG_PROPOSAL_ASSIGNED arrives). The committed entry
    /// whose index equals `pending_idx[i]` is proposal i — raft
    /// strips the tag header before the WAL, so index is the only
    /// sound attribution (content matching would misattribute
    /// byte-identical commands from concurrent proposers, which for
    /// RESERVE means handing two anchors the same counter block).
    pending_corr: [u64; MAX_PENDING],
    pending_req: [u64; MAX_PENDING],
    pending_idx: [u64; MAX_PENDING],
    /// dev_millis stamp at propose time, for the TTL reclaim.
    pending_born_ms: [u64; MAX_PENDING],
    pending_used: [bool; MAX_PENDING],
    /// The contract verb a pending proposal answers (`FACE_*`), or
    /// `FACE_NONE` for one taken on the registry's own request port.
    pending_face: [u8; MAX_PENDING],
    /// The raft group the engine assigned each pending proposal to.
    pending_part: [u16; MAX_PENDING],
    /// The namespace (`NS_*`) a pending proposal answers on.
    pending_ns: [u8; MAX_PENDING],

    /// Token checks awaiting their barrier (`CK_CMD_MAGIC`): a table of
    /// their own, so checks and registry commands never wait on each
    /// other's slots.
    checks: CheckBarrier<CHECK_REQ_MAX>,

    // Counters (metrics)
    requests_in: u32,
    /// Fluxor providers' token checks answered (flow and address), and
    /// how many refused.
    token_checks: u32,
    token_refusals: u32,
    /// Requests refused for this directory's tier (`MSG_DIR_OUT_OF_SCOPE`).
    scope_refusals: u32,
    /// The site-loss smoke (`smoke: 3`): when the leader last proposed.
    site_smoke_ms: u64,
    proposals_out: u32,
    /// Pending slots reclaimed by the TTL (lost assignment/commit).
    proposals_expired: u32,
    /// Token checks dropped unanswered: their barrier was lost, or raft
    /// assigned it to another group.
    checks_expired: u32,
    replies_out: u32,
    applied_ok: u32,
    applied_rejected: u32,
    stream_gaps: u32,
    /// Committed entries of other raft groups seen on the shared stream
    /// and left alone.
    foreign_entries: u32,
    /// Proposals the engine assigned to a group other than this
    /// directory's: never applied here, never answered.
    misrouted: u32,

    // ── Deterministic timing ────────────────────────────────────────
    /// Current PRG leader per MSG_LEADER_HINT (0xFF = unknown).
    leader_id: u8,
    /// Node-local pause reason (wire::TIMING_PAUSE_*), metrics/why.
    pause_reason: u8,
    _pad3: [u8; 2],
    // Params (tags 3–6).
    time_advance_period_ms: u32,
    logical_max_step_ms: u32,
    clock_slew_tolerance_ms: u32,
    logical_staleness_ms: u32,
    /// Leader-side wall-clock discipline. Never consulted in apply.
    clock_guard: ClockGuard,
    /// Monotonic throttle stamps for time proposals.
    last_advance_propose_ms: u64,
    last_drain_propose_ms: u64,
    /// Last sampled wall clock (leader only; lag metric).
    last_unix_ms: u64,
    /// Committed timing entries applied (metrics).
    time_advance_applied: u32,
    time_drain_applied: u32,

    /// Cached scheduler index for MON_SESSION emission.
    self_idx: u8,
    _pad1: [u8; 7],
    last_metrics_ms: u64,

    /// Snapshot install: bytes received so far (the next chunk's offset),
    /// the section being fed, and whether an install is in progress.
    snap_in_off: u32,
    install_section: u8,
    install_active: bool,
    /// Committed applies are held: an install began (or failed) and the
    /// registries are not the state at the subscriber's cursor until one
    /// succeeds.
    hold_applies: bool,
    _pad2: u8,
    sr_installer: SrInstaller,
    tr_installer: TrInstaller,
    vb_installer: VbInstaller,
    fo_installer: FoInstaller,
    rg_installer: RgInstaller,
    op_installer: OpInstaller,
    at_installer: AtInstaller,
    rs_installer: RsInstaller,

    /// Snapshot export: active while an image is being streamed across
    /// steps (committed applies hold so the image is one index's state).
    export_active: bool,
    export_section: u8,
    _pad5: [u8; 2],
    export_term: u64,
    export_last_idx: u64,
    export_off: u64,
    sr_cursor: SrExportCursor,
    tr_cursor: TrExportCursor,
    vb_cursor: VbExportCursor,
    fo_cursor: FoExportCursor,
    rg_cursor: RgExportCursor,
    op_cursor: OpExportCursor,
    at_cursor: AtExportCursor,
    rs_cursor: RsExportCursor,
    /// Failover replay: after a committed REPLAY of ours, every live
    /// record goes to `fo_replay_req` in creation order, one per
    /// writable step slot, then the end-of-replay reply.
    fo_replay_active: bool,
    _pad7: [u8; 3],
    fo_replay_sent: u32,
    fo_replay_req: u64,
    fo_replay_after: u64,
    /// A replay committed while one streams waits here, then starts when
    /// the stream ends (0: none). A later one takes the place; its
    /// predecessor's requester, unanswered, resends.
    fo_replay_queued: u64,
    /// Operation replay: as the failover replay, for the live records of
    /// `op_replay_kind` (0: every kind).
    op_replay_active: bool,
    op_replay_kind: u8,
    _pad8: [u8; 2],
    op_replay_sent: u32,
    op_replay_req: u64,
    op_replay_after: u64,
    /// As `fo_replay_queued`, with the kind it asks for.
    op_replay_queued: u64,
    op_replay_queued_kind: u8,
    _pad9: [u8; 7],
    /// A SEED proposal is in flight (do not propose another until it
    /// commits or the pending slot expires).
    seed_proposed_ms: u64,
    /// Staged export bytes not yet framed (`snap_buf[..snap_staged]`).
    snap_staged: u32,
    _pad6: u32,

    msg_buf: [u8; MSG_BUF],
    mon_buf: [u8; 192],
    /// Export staging: one chunk plus the largest unit that can straddle
    /// its end. Install needs no staging (the installers carry a partial
    /// unit themselves). Independent of the profile.
    snap_buf: [u8; SNAP_CHUNK + SNAP_UNIT_MAX],
}

mod params_def {
    use super::p_u32;
    use super::p_u8;
    use super::ModuleState;
    use super::SCHEMA_MAX;

    define_params! {
        ModuleState;

        1, replica_id, u8, 0
            => |s, d, len| { s.replica_id = p_u8(d, len, 0, 0); };

        2, smoke, u8, 0
            => |s, d, len| { s.smoke = p_u8(d, len, 0, 0); };

        3, time_advance_period_ms, u32, 1000
            => |s, d, len| { s.time_advance_period_ms = p_u32(d, len, 0, 1000); };

        4, logical_max_step_ms, u32, 60000
            => |s, d, len| { s.logical_max_step_ms = p_u32(d, len, 0, 60000); };

        // Must clear the pi5's coarse UNIX_MILLIS: the wall clock
        // there advances in ~1 s steps, so a healthy rig shows
        // apparent slews ≥1100 ms. A tolerance under that raises
        // spurious backward-jump alarms, which pause deterministic
        // time production. 2000 clears 1.1 s with margin while still
        // catching real clock breakage.
        5, clock_slew_tolerance_ms, u32, 2000
            => |s, d, len| { s.clock_slew_tolerance_ms = p_u32(d, len, 0, 2000); };

        6, logical_staleness_ms, u32, 5000
            => |s, d, len| { s.logical_staleness_ms = p_u32(d, len, 0, 5000); };
        7, partition_id, u32, 0
            => |s, d, len| { s.partition_id = p_u32(d, len, 0, 0) as u16; };
        8, forwarded_stream, u8, 0
            => |s, d, len| { s.forwarded_stream = p_u8(d, len, 0, 0); };
        9, profile, u8, 0
            => |s, d, len| { s.profile = p_u8(d, len, 0, 0); };
        // Which tier this directory serves (docs/architecture/multi_site.md):
        // 0 both (one region, no global tier — the default), 1 a regional
        // cell (sessions, flows, VIPs, failover records, attachments,
        // reservations, takeover and evacuation records; never `rg/`), 2
        // the multi-site global tier (`rg/` and REGION / EVACUATION
        // operation records only). A request for the other tier is
        // answered `MSG_DIR_OUT_OF_SCOPE`, never proposed.
        10, scope, u8, 0, enum { all=0, cell=1, global=2 }
            => |s, d, len| { s.scope = p_u8(d, len, 0, 0); };
    }
}

// ── Proposal path ───────────────────────────────────────────────────

/// Allocate a correlation id unique across proposers: replica_id in
/// the top byte, a monotonic counter below. Correlation 0 is reserved
/// by the facade; the counter starts at 1.
fn next_correlation(s: &mut ModuleState) -> u64 {
    s.corr_counter = s.corr_counter.wrapping_add(1);
    ((s.replica_id as u64) << 56) | (s.corr_counter & 0x00FF_FFFF_FFFF_FFFF)
}

/// Propose a session-registry command. Registers (correlation →
/// request_id) in the pending table so the committed-entry pass can
/// route the reply. Returns false when the pending table or the
/// proposal channel is full.
unsafe fn propose(s: &mut ModuleState, request_id: u64, body: &[u8]) -> bool {
    propose_ns(s, request_id, body, FACE_NONE, NS_SR)
}

/// `propose` for a command that answers a contract verb: the committed
/// reply goes back on `ctrl_out` as that verb's frame.
unsafe fn propose_on(s: &mut ModuleState, request_id: u64, body: &[u8], face: u8) -> bool {
    propose_ns(s, request_id, body, face, NS_SR)
}

/// `propose` into namespace `ns`: the body is prefixed with that
/// namespace's magic and the committed reply goes out as its message id.
unsafe fn propose_ns(s: &mut ModuleState, request_id: u64, body: &[u8], face: u8, ns: u8) -> bool {
    let sys = &*s.syscalls;
    if body.len() > CMD_MAX {
        return false;
    }
    let Some(slot) = (0..MAX_PENDING).find(|&i| !s.pending_used[i]) else {
        return false;
    };
    if !wire_channels::writable(sys, s.out_proposals) {
        return false;
    }
    let corr = next_correlation(s);
    let mut tagged = [0u8; 2 + CMD_MAX];
    tagged[..2].copy_from_slice(match ns {
        NS_TR => &TR_CMD_MAGIC,
        NS_VB => &VB_CMD_MAGIC,
        NS_FO => &FO_CMD_MAGIC,
        NS_RG => &RG_CMD_MAGIC,
        NS_OP => &OP_CMD_MAGIC,
        NS_AT => &AT_CMD_MAGIC,
        NS_RS => &RS_CMD_MAGIC,
        _ => &SR_CMD_MAGIC,
    });
    tagged[2..2 + body.len()].copy_from_slice(body);
    let mut prop = [0u8; TAGGED_PROPOSAL_HDR + 2 + CMD_MAX];
    let n = match replica_facade::build_tagged_proposal(&mut prop, corr, &tagged[..2 + body.len()])
    {
        Ok(n) => n,
        Err(_) => return false,
    };
    let wrote = wire_channels::channel_write_msg(
        sys,
        s.out_proposals,
        wire::MSG_CLIENT_PROPOSAL,
        &prop[..n],
    );
    if wrote <= 0 {
        return false;
    }
    s.pending_corr[slot] = corr;
    s.pending_req[slot] = request_id;
    s.pending_idx[slot] = 0;
    s.pending_born_ms[slot] = dev_millis(sys);
    s.pending_used[slot] = true;
    s.pending_face[slot] = face;
    s.pending_ns[slot] = ns;
    s.proposals_out = s.proposals_out.saturating_add(1);
    true
}

/// Propose an internal entry (timing, a check's barrier) outside the
/// pending table: the committed entry itself is the effect, or its
/// caller tracks the returned correlation. `None` when the proposal ring
/// has no space (retry next step).
unsafe fn propose_raw(s: &mut ModuleState, body: &[u8]) -> Option<u64> {
    let sys = &*s.syscalls;
    if !wire_channels::writable(sys, s.out_proposals) {
        return None;
    }
    let corr = next_correlation(s);
    let mut prop = [0u8; TAGGED_PROPOSAL_HDR + max_usize(wire::TIMING_ENTRY_LEN, 2)];
    let n = replica_facade::build_tagged_proposal(&mut prop, corr, body).ok()?;
    let wrote = wire_channels::channel_write_msg(
        sys,
        s.out_proposals,
        wire::MSG_CLIENT_PROPOSAL,
        &prop[..n],
    );
    if wrote <= 0 {
        return None;
    }
    s.proposals_out = s.proposals_out.saturating_add(1);
    Some(corr)
}

/// Hold the check in `msg_buf[..plen]` behind a barrier: propose the
/// barrier and keep the check until this replica's applied state has
/// reached it. False when no check slot is free or the proposal ring
/// refuses the barrier.
unsafe fn take_check(s: &mut ModuleState, msg_type: u8, plen: usize) -> bool {
    if !s.checks.has_room() {
        return false;
    }
    let Some(corr) = propose_raw(s, &CK_CMD_MAGIC) else {
        return false;
    };
    let sys = &*s.syscalls;
    let n = plen.min(CHECK_REQ_MAX);
    s.checks.hold(
        corr,
        s.partition_id,
        dev_millis(sys),
        msg_type,
        &s.msg_buf[..n],
    )
}

/// Answer every held check whose barrier this replica's applied state
/// (`applied`, the committed cursor) has reached. Never over a partial
/// install; a check stays held while `replies` has no room.
unsafe fn answer_checks_through(s: &mut ModuleState, applied: u64) {
    if s.hold_applies || s.install_active {
        return;
    }
    let sys = &*s.syscalls;
    let mut req = [0u8; CHECK_REQ_MAX];
    while wire_channels::writable(sys, s.out_replies) {
        let Some((msg, n)) = s.checks.take_ready(applied, &mut req) else {
            return;
        };
        answer_token_check(s, msg, &req[..n]);
    }
}

/// True when this node is the current PRG leader per MSG_LEADER_HINT.
fn is_leader(s: &ModuleState) -> bool {
    s.leader_id != 0xFF && s.leader_id == s.replica_id
}

/// Duration-admission freshness barrier. ADMISSION-TIME ONLY: the check
/// compares the local wall clock against replicated logical time before
/// PROPOSING a duration command; it is never re-evaluated during apply.
/// Returns true when the command may be proposed now (time fresh, or this
/// node is not the leader so the proposal cannot commit anyway); on a stale
/// clock it proposes a TimeAdvance barrier entry first and reports whether
/// the command may follow it in the same submission order.
unsafe fn ensure_time_fresh(s: &mut ModuleState) -> bool {
    let sys = &*s.syscalls;
    if !is_leader(s) {
        return true;
    }
    let logical = s.registry.timing.logical_now_ms();
    let unix = dev_unix_millis(sys);
    if unix == 0 {
        // No trusted wall clock: refuse duration admission (fail
        // closed — a 0 source is never a valid epoch instant).
        return false;
    }
    if unix.saturating_sub(logical) <= s.logical_staleness_ms as u64 {
        return true;
    }
    let mono = dev_millis(sys);
    if s.clock_guard.sample(mono, unix) != ClockHealth::Healthy {
        return false;
    }
    let Some(t) = s.clock_guard.propose_time(logical, unix) else {
        return false;
    };
    let mut body = [0u8; wire::TIMING_ENTRY_LEN];
    let n = wire::encode_time_entry(&mut body, wire::TIMING_OP_ADVANCE, t);
    if n == 0 || propose_raw(s, &body[..n]).is_none() {
        return false;
    }
    // The barrier is in the log ahead of the command; whether it made
    // time FULLY fresh depends on the step clamp — admit only when it
    // did, otherwise the requester retries while catch-up continues.
    unix.saturating_sub(t) <= s.logical_staleness_ms as u64
}

/// Apply one committed timing entry to the embedded state machine.
unsafe fn apply_timing_entry(s: &mut ModuleState, body: &[u8]) {
    let sys = &*s.syscalls;
    let Some((op, time_ms)) = wire::decode_time_entry(body) else {
        // Unknown timing entry versions fail closed.
        dev_log(sys, 2, b"[sess_dir] bad time entry".as_ptr(), 25);
        return;
    };
    let r = if op == wire::TIMING_OP_ADVANCE {
        s.time_advance_applied = s.time_advance_applied.saturating_add(1);
        s.registry.apply_time_advance(time_ms)
    } else {
        s.time_drain_applied = s.time_drain_applied.saturating_add(1);
        s.registry.apply_time_drain(time_ms)
    };
    if r.fired > 0 {
        dev_log(sys, 3, b"[sess_dir] deadline fired".as_ptr(), 25);
    }
}

// ── Telemetry ───────────────────────────────────────────────────────

fn fmt_u32(mut v: u32, out: &mut [u8; 12]) -> &[u8] {
    let mut i = 12;
    if v == 0 {
        i -= 1;
        out[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &out[i..]
}

/// One log line per contract verdict, in the vocabulary every
/// `session.directory` provider logs, so a rig reads this directory and
/// any other the same way:
///
///   [directory] bound epoch=<e>
///   [directory] stale epoch=<e>
///   [directory] detached epoch=<e>
///   [directory] granted start=<s> len=<l>
unsafe fn log_face(s: &ModuleState, face: u8, reply: &SessionReply) {
    let sys = &*s.syscalls;
    let mut a = [0u8; 12];
    let mut b = [0u8; 12];
    let mut line = [0u8; 80];
    let parts: [&[u8]; 4] = match (face, reply.status) {
        (FACE_GRANT, SR_ST_OK) => [
            b"[directory] granted start=",
            fmt_u32(reply.a as u32, &mut a),
            b" len=",
            fmt_u32(reply.b as u32, &mut b),
        ],
        (FACE_GRANT, _) => return,
        (FACE_DETACH, SR_ST_OK) => [
            b"[directory] detached epoch=",
            fmt_u32(reply.epoch, &mut a),
            b"",
            b"",
        ],
        (_, SR_ST_OK) => [
            b"[directory] bound epoch=",
            fmt_u32(reply.epoch, &mut a),
            b"",
            b"",
        ],
        (_, SR_ST_STALE_EPOCH) => [
            b"[directory] stale epoch=",
            fmt_u32(reply.epoch, &mut a),
            b"",
            b"",
        ],
        _ => [
            b"[directory] refused epoch=",
            fmt_u32(reply.epoch, &mut a),
            b"",
            b"",
        ],
    };
    let mut p = 0usize;
    for part in parts {
        let n = part.len().min(80 - p);
        line[p..p + n].copy_from_slice(&part[..n]);
        p += n;
    }
    dev_log(sys, 3, line.as_ptr(), p);
}

/// Emit a MON_SESSION line for a committed registry transition.
unsafe fn mon_reply(s: &mut ModuleState, reply: &SessionReply) {
    let sys = &*s.syscalls;
    if s.self_idx == 0xFF {
        let idx = dev_self_index(sys);
        if idx >= 0 {
            s.self_idx = idx as u8;
        }
    }
    let (event, reason): (u8, &[u8]) = if reply.status != SR_ST_OK {
        let reason: &[u8] = match reply.status {
            SR_ST_STALE_EPOCH => b"stale_epoch",
            SR_ST_RECOVERY_VOID => b"recovery_void",
            SR_ST_FENCE_REQUIRED => b"fence_required",
            SR_ST_FENCE_STALE => b"fence_stale",
            SR_ST_FLOOR_REGRESSION => b"floor_regression",
            SR_ST_UNKNOWN_SESSION => b"unknown_session",
            SR_ST_NO_CAPACITY => b"no_capacity",
            SR_ST_RECOVERY_STALE => b"recovery_stale",
            SR_ST_DEADLINE_CAPACITY => b"deadline_capacity",
            SR_ST_CONTEXT_MISMATCH => b"context_mismatch",
            SR_ST_GRANT_INVALID => b"grant_invalid",
            SR_ST_RESERVATION_BEHIND => b"reservation_behind",
            SR_ST_MIRROR_REGRESSION => b"mirror_regression",
            _ => b"malformed",
        };
        (MON_EV_REJECTED, reason)
    } else {
        match reply.op {
            // A first binding attaches; a binding advanced to a new
            // generation relocated.
            SR_OP_BIND if reply.a == 0 => (MON_EV_ATTACHED, b""),
            SR_OP_BIND => (MON_EV_RELOCATED, b""),
            SR_OP_EPOCH_BUMP => (MON_EV_EPOCH_BUMP, b""),
            SR_OP_RESERVE => (MON_EV_RESERVATION_GRANTED, b""),
            SR_OP_FENCE_REQUEST => (MON_EV_FENCE_INITIATED, b""),
            SR_OP_FENCE_CONFIRM => (MON_EV_FENCE_CONFIRMED, b""),
            // The fenced takeover: the attachment's anchor moved, which
            // is what lets the address follow it.
            SR_OP_ACTIVATE => (MON_EV_VIP_MOVED, b""),
            SR_OP_UNBIND => (MON_EV_DETACHED, b""),
            SR_OP_RECOVERY_MARK => (MON_EV_UNSAFE_RECOVERY_EPOCH_VOID, b""),
            // Key custody (KEY_PUT, KEY_PUT_BOUND, KEY_WIPE, transfer
            // grants and their consumption) is deliberately silent: it
            // must not leak activity patterns to the log. RX_FLOOR,
            // MIRROR_MARK and COUNTER_FLOOR are high-rate checkpoints.
            _ => return,
        }
    };
    let status: &[u8] = if reply.status == SR_ST_OK { b"ok" } else { b"" };
    let mon_ptr = s.mon_buf.as_mut_ptr();
    let _ = dev_mon_session(
        sys,
        s.self_idx,
        event,
        reply.session_id.as_ptr(),
        reply.epoch,
        core::ptr::null(),
        core::ptr::null(),
        reason,
        status,
        mon_ptr,
        192,
    );
}

// ── Module interface ────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ModuleState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: per the module ABI, the kernel passes a valid,
    // exclusively-borrowed `state` of at least `module_state_size()`
    // bytes and a live syscall table.
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
        s.in_entries = in_chan;
        s.in_requests = dev_channel_port(sys, 0, 1);
        s.in_snapshot_chunk = dev_channel_port(sys, 0, 2);
        s.in_snapshot_request = dev_channel_port(sys, 0, 3);
        s.in_proposal_assigned = dev_channel_port(sys, 0, 4);
        s.in_leader_state = dev_channel_port(sys, 0, 5);
        s.in_ctrl = dev_channel_port(sys, 0, 6);
        s.in_checks = dev_channel_port(sys, 0, 7);
        s.out_proposals = out_chan;
        s.out_replies = dev_channel_port(sys, 1, 1);
        s.out_metrics = dev_channel_port(sys, 1, 2);
        s.out_snapshot_export = dev_channel_port(sys, 1, 3);
        s.out_ctrl = dev_channel_port(sys, 1, 4);

        s.replica_id = 0;
        s.smoke = 0;
        s.smoke_phase = SMOKE_IDLE;
        s.scope = SCOPE_ALL;
        s.scope_refusals = 0;
        s.site_smoke_ms = 0;
        s.profile = PROFILE_RP2350;
        s.subscriber = CommittedSubscriber::new(0);
        s.corr_counter = 0;
        s.pending_corr = [0; MAX_PENDING];
        s.pending_req = [0; MAX_PENDING];
        s.pending_idx = [0; MAX_PENDING];
        s.pending_born_ms = [0; MAX_PENDING];
        s.pending_used = [false; MAX_PENDING];
        s.pending_face = [FACE_NONE; MAX_PENDING];
        s.pending_part = [0; MAX_PENDING];
        s.pending_ns = [NS_SR; MAX_PENDING];
        s.checks = CheckBarrier::new();
        s.checks_expired = 0;
        s.requests_in = 0;
        s.token_checks = 0;
        s.token_refusals = 0;
        s.proposals_out = 0;
        s.proposals_expired = 0;
        s.replies_out = 0;
        s.applied_ok = 0;
        s.applied_rejected = 0;
        s.stream_gaps = 0;
        s.foreign_entries = 0;
        s.misrouted = 0;
        s.leader_id = 0xFF;
        s.pause_reason = wire::TIMING_PAUSE_NOT_LEADER;
        s._pad3 = [0; 2];
        s.last_advance_propose_ms = 0;
        s.last_drain_propose_ms = 0;
        s.last_unix_ms = 0;
        s.time_advance_applied = 0;
        s.time_drain_applied = 0;
        s.self_idx = 0xFF;
        s._pad1 = [0; 7];
        s.last_metrics_ms = 0;
        s.snap_in_off = 0;
        s.install_section = SNAP_SECTION_SR;
        s.install_active = false;
        s.hold_applies = false;
        s._pad2 = 0;
        s.sr_installer = SrInstaller::new();
        s.tr_installer = TrInstaller::new();
        s.vb_installer = VbInstaller::new();
        s.fo_installer = FoInstaller::new();
        s.rg_installer = RgInstaller::new();
        s.op_installer = OpInstaller::new();
        s.at_installer = AtInstaller::new();
        s.rs_installer = RsInstaller::new();
        s.export_active = false;
        s.export_section = SNAP_SECTION_SR;
        s._pad5 = [0; 2];
        s.export_term = 0;
        s.export_last_idx = 0;
        s.export_off = 0;
        s.sr_cursor = SrExportCursor::new();
        s.tr_cursor = TrExportCursor::new();
        s.vb_cursor = VbExportCursor::new();
        s.fo_cursor = FoExportCursor::new();
        s.rg_cursor = RgExportCursor::new();
        s.op_cursor = OpExportCursor::new();
        s.at_cursor = AtExportCursor::new();
        s.rs_cursor = RsExportCursor::new();
        s.fo_replay_active = false;
        s._pad7 = [0; 3];
        s.fo_replay_sent = 0;
        s.fo_replay_req = 0;
        s.fo_replay_after = 0;
        s.fo_replay_queued = 0;
        s.op_replay_active = false;
        s.op_replay_kind = 0;
        s._pad8 = [0; 2];
        s.op_replay_sent = 0;
        s.op_replay_req = 0;
        s.op_replay_after = 0;
        s.op_replay_queued = 0;
        s.op_replay_queued_kind = 0;
        s._pad9 = [0; 7];
        s.seed_proposed_ms = 0;
        s.snap_staged = 0;
        s._pad6 = 0;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if s.smoke == 0 || s.smoke == SMOKE_SITE {
            s.smoke_phase = SMOKE_OFF;
        }
        // The profile must fit this variant's arenas: a build admitting
        // less than the named profile cannot claim it.
        let Some(admits) = profile_admits(s.profile) else {
            dev_log(sys, 1, b"[sess_dir] unknown profile".as_ptr(), 26);
            return -3;
        };
        if admits.sessions > profile::SESSIONS
            || admits.flows > profile::FLOWS
            || admits.bindings > profile::BINDINGS
            || admits.operations > profile::OPERATIONS
            || admits.services > profile::SERVICES
            || admits.records > profile::RECORDS
            || admits.attachments > profile::ATTACHMENTS
            || admits.producers > profile::PRODUCERS
            || admits.blocks > profile::BLOCKS
            || admits.addrs > profile::ADDRS
        {
            dev_log(sys, 1, b"[sess_dir] profile exceeds arena".as_ptr(), 32);
            return -3;
        }
        if s.scope > directory_scope::SCOPE_GLOBAL {
            let m = b"[sess_dir] unknown scope";
            dev_log(sys, 1, m.as_ptr(), m.len());
            return -22;
        }
        // In place: a profile-sized registry does not fit on the stack.
        s.registry.reset(admits.sessions as u32);
        s.transport.reset(admits.flows as u32);
        // Unseeded: the leader proposes the group's capability seed from
        // the kernel CSPRNG once (step 5.7); until it commits, ACTIVATE
        // answers NOT_READY on every replica.
        s.vip.reset(admits.bindings as u32);
        s.failover.reset(admits.operations as u32);
        // The global tier is seeded by the same SEED, under its derived
        // seed (`apply_committed_vip`).
        s.region.reset(admits.services as u32);
        s.ops.reset(admits.records as u32);
        s.attachments
            .reset(admits.attachments as u32, admits.producers as u32);
        s.reservations
            .reset(admits.blocks as u32, admits.addrs as u32);
        s.clock_guard = ClockGuard::new(
            s.logical_max_step_ms as u64,
            s.clock_slew_tolerance_ms as u64,
        );

        dev_log(sys, 3, b"[sess_dir] init".as_ptr(), 15);
        0
    }
}

/// Handle one committed entry. raft strips the tagged-proposal header
/// before the WAL, so `command` is the raw body: registry traffic is
/// `[b"SR"][SR_OP_* command]`; anything else (admin ops, other
/// consumers) is ignored. Every registry entry is applied on every
/// replica; the reply is relayed only by the replica whose pending
/// proposal was assigned exactly this wal index.
unsafe fn apply_committed(s: &mut ModuleState, index: u64, command: &[u8]) {
    // Substrate timing entries (TimeAdvance / TimeDrain) apply to the
    // registry's embedded TimingState on every replica — the ONLY path on
    // which a deadline can fire.
    if wire::has_timing_magic(command) {
        apply_timing_entry(s, command);
        return;
    }
    // A check's barrier changes no state on any replica; its commit is
    // the whole of its effect (`answer_checks_through`).
    if command == CK_CMD_MAGIC || command.len() <= 2 {
        return;
    }
    if command[..2] == TR_CMD_MAGIC {
        apply_committed_transport(s, index, &command[2..]);
        return;
    }
    if command[..2] == VB_CMD_MAGIC {
        apply_committed_vip(s, index, &command[2..]);
        return;
    }
    if command[..2] == FO_CMD_MAGIC {
        apply_committed_failover(s, index, &command[2..]);
        return;
    }
    if command[..2] == RG_CMD_MAGIC {
        apply_committed_region(s, index, &command[2..]);
        return;
    }
    if command[..2] == OP_CMD_MAGIC {
        apply_committed_operation(s, index, &command[2..]);
        return;
    }
    if command[..2] == AT_CMD_MAGIC {
        apply_committed_attachment(s, index, &command[2..]);
        return;
    }
    if command[..2] == RS_CMD_MAGIC {
        apply_committed_reservation(s, index, &command[2..]);
        return;
    }
    if command[..2] != SR_CMD_MAGIC {
        return;
    }
    let body = &command[2..];
    let reply = s.registry.apply(body);
    if reply.status == SR_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    mon_reply(s, &reply);

    // Route the reply if this replica proposed the entry at `index`.
    let Some(slot) = take_pending(s, index, NS_SR) else {
        return;
    };
    let request_id = s.pending_req[slot];
    let face = s.pending_face[slot];
    s.pending_face[slot] = FACE_NONE;

    smoke_advance(s, &reply);

    if face != FACE_NONE {
        let sys = &*s.syscalls;
        log_face(s, face, &reply);
        let mut out = [0u8; 64];
        if s.out_ctrl >= 0 {
            if let Some((msg, n)) = reply_to_frame(face, &reply, &mut out) {
                let wrote = wire_channels::channel_write_msg(sys, s.out_ctrl, msg, &out[..n]);
                if wrote > 0 {
                    s.replies_out = s.replies_out.saturating_add(1);
                }
            }
        }
        // A binding the anchor now holds is granted its first block of
        // egress-counter values under the epoch it holds it at.
        if reply.status == SR_ST_OK && (face == FACE_ATTACH || face == FACE_EPOCH_BUMP) {
            let mut body = [0u8; SR_MAX_CMD];
            let n = grant_command(&reply.session_id, reply.epoch, &mut body);
            let _ = propose_on(s, 0, &body[..n], FACE_GRANT);
        }
        return;
    }

    if s.out_replies >= 0 && request_id != 0 {
        let sys = &*s.syscalls;
        let mut out = [0u8; 8 + SR_REPLY_LEN];
        out[..8].copy_from_slice(&request_id.to_le_bytes());
        let _ = reply.encode(&mut out[8..]);
        let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_SR_REPLY, &out);
        if wrote > 0 {
            s.replies_out = s.replies_out.saturating_add(1);
        }
    }
}

/// The pending slot whose assigned wal index is `index` in namespace
/// `ns`, released. A proposal of another namespace at that index is this
/// replica's too, but it is answered on its own path.
fn take_pending(s: &mut ModuleState, index: u64, ns: u8) -> Option<usize> {
    let slot = (0..MAX_PENDING).find(|&i| {
        s.pending_used[i]
            && s.pending_idx[i] != 0
            && s.pending_idx[i] == index
            && s.pending_ns[i] == ns
    })?;
    s.pending_used[slot] = false;
    Some(slot)
}

/// A committed `"TR"` entry: apply to the transport registry on every
/// replica; relay the reply as `MSG_TR_REPLY` when it was ours, with the
/// token trailer (the promoted emitter's `FlowToken` after a committed
/// MOVE_FENCED, minted under the group's capability seed).
unsafe fn apply_committed_transport(s: &mut ModuleState, index: u64, body: &[u8]) {
    let sys = &*s.syscalls;
    // A fenced move needs the session namespace's confirmed fence on the
    // emitter it replaces (session id = flow id): read from replicated
    // state at this log position, so every replica decides alike.
    let registry = &s.registry;
    let fenced =
        |flow: &[u8; 16], old: &[u8; 8], gen: u32| registry.fence_confirmed_on(flow, old, gen);
    let reply: TransportReply = s.transport.apply_fenced(body, &fenced);
    if reply.status == TR_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
        if reply.op == TR_OP_MOVE || reply.op == TR_OP_MOVE_FENCED {
            dev_log(sys, 3, b"[sess_dir] flow moved".as_ptr(), 21);
        }
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let Some(slot) = take_pending(s, index, NS_TR) else {
        return;
    };
    let request_id = s.pending_req[slot];
    if s.out_replies >= 0 && request_id != 0 {
        let token = s.transport.reply_token(&reply, &s.vip.seed, digest);
        let mut out = [0u8; 8 + TR_WIRE_REPLY_LEN];
        out[..8].copy_from_slice(&request_id.to_le_bytes());
        let _ = reply.encode(&mut out[8..8 + TR_REPLY_LEN]);
        let _ = encode_token_trailer(token.as_ref(), &mut out[8 + TR_REPLY_LEN..]);
        let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_TR_REPLY, &out);
        if wrote > 0 {
            s.replies_out = s.replies_out.saturating_add(1);
        }
    }
}

/// A committed `"VB"` entry: apply to the VIP registry on every replica
/// (a committed ACTIVATE is the address moving — `vip_moved` on the
/// monitor channel, keyed by service id and vip epoch); relay the reply
/// as `MSG_VB_REPLY` when it was ours.
unsafe fn apply_committed_vip(s: &mut ModuleState, index: u64, body: &[u8]) {
    let sys = &*s.syscalls;
    let reply: VipReply = s.vip.apply(body, digest);
    // The group's capability seed is one SEED: the global tier adopts it
    // (under its derived seed) on the same committed entry, every replica.
    if reply.status == VB_ST_OK && reply.op == VB_OP_SEED {
        s.region.adopt_seed(body, digest);
    }
    if reply.status == VB_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
        if reply.op == VB_OP_ACTIVATE {
            mon_vip_moved(s, &reply);
        }
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let Some(slot) = take_pending(s, index, NS_VB) else {
        return;
    };
    let request_id = s.pending_req[slot];
    if s.out_replies >= 0 && request_id != 0 {
        let mut out = [0u8; 8 + VB_REPLY_LEN];
        out[..8].copy_from_slice(&request_id.to_le_bytes());
        let _ = reply.encode(&mut out[8..]);
        let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_VB_REPLY, &out);
        if wrote > 0 {
            s.replies_out = s.replies_out.saturating_add(1);
        }
    }
}

/// A committed `"FO"` entry: apply to the failover-operation store on
/// every replica; relay the reply as `MSG_FO_REPLY` when it was ours. A
/// committed REPLAY of ours starts the replay pump (`pump_fo_replay`):
/// it is a read through the log, so every record a coordinator could have
/// been answered with is in the state it streams.
unsafe fn apply_committed_failover(s: &mut ModuleState, index: u64, body: &[u8]) {
    let reply: FailoverReply = s.failover.apply(body, digest);
    if reply.status == FO_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let Some(slot) = take_pending(s, index, NS_FO) else {
        return;
    };
    let request_id = s.pending_req[slot];
    if request_id == 0 || s.out_replies < 0 {
        return;
    }
    if reply.op == FO_OP_REPLAY && reply.status == FO_ST_OK {
        // One stream at a time, run to its end: a replay committed while
        // one streams waits its turn rather than cutting it off.
        if s.fo_replay_active {
            s.fo_replay_queued = request_id;
        } else {
            start_fo_replay(s, request_id);
        }
        return;
    }
    send_fo_reply(s, request_id, &reply);
}

fn start_fo_replay(s: &mut ModuleState, request_id: u64) {
    s.fo_replay_active = true;
    s.fo_replay_req = request_id;
    s.fo_replay_after = 0;
    s.fo_replay_sent = 0;
}

unsafe fn send_fo_reply(s: &mut ModuleState, request_id: u64, reply: &FailoverReply) -> bool {
    let sys = &*s.syscalls;
    let mut out = [0u8; 8 + FO_REPLY_LEN];
    out[..8].copy_from_slice(&request_id.to_le_bytes());
    let _ = reply.encode(&mut out[8..]);
    let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_FO_REPLY, &out);
    if wrote > 0 {
        s.replies_out = s.replies_out.saturating_add(1);
        true
    } else {
        false
    }
}

/// Stream the replay a committed REPLAY started: each live record as a
/// `REPLAY` reply in creation order, then the end-of-replay reply (op
/// REPLAY, status OK, the count sent). Paced by `replies` being writable;
/// the cursor is a creation sequence, so a record created during the
/// replay is streamed too and one finished during it is not.
unsafe fn pump_fo_replay(s: &mut ModuleState) {
    let sys = &*s.syscalls;
    let mut budget = 8;
    while s.fo_replay_active && budget > 0 {
        budget -= 1;
        if !wire_channels::writable(sys, s.out_replies) {
            return;
        }
        let next = s
            .failover
            .replay_next(s.fo_replay_after)
            .map(|(seq, rec)| (seq, *rec));
        let req = s.fo_replay_req;
        match next {
            Some((seq, record)) => {
                let reply = FailoverReply {
                    op: FO_OP_REPLAY,
                    status: FO_ST_REPLAY,
                    present: true,
                    live: s.failover.live,
                    record,
                };
                if !send_fo_reply(s, req, &reply) {
                    return;
                }
                s.fo_replay_after = seq;
                s.fo_replay_sent = s.fo_replay_sent.saturating_add(1);
            }
            None => {
                let mut end = FailoverReply::zero();
                end.op = FO_OP_REPLAY;
                end.status = FO_ST_OK;
                end.live = s.fo_replay_sent;
                if !send_fo_reply(s, req, &end) {
                    return;
                }
                s.fo_replay_active = false;
                if s.fo_replay_queued != 0 {
                    let next = s.fo_replay_queued;
                    s.fo_replay_queued = 0;
                    start_fo_replay(s, next);
                }
            }
        }
    }
}

/// A committed `"RG"` entry: apply to the global tier on every replica;
/// relay the reply as `MSG_RG_REPLY` when it was ours.
unsafe fn apply_committed_region(s: &mut ModuleState, index: u64, body: &[u8]) {
    let sys = &*s.syscalls;
    let reply: RgReply = s.region.apply(body, digest);
    if s.smoke == SMOKE_SITE
        && reply.vip.status == VB_ST_OK
        && body.len() == RG_INVALIDATE_LEN
        && body[0] == RG_OP_INVALIDATE
        && body[17..33] == SITE_SMOKE_REGION
    {
        let mut line = [0u8; 64];
        let head = b"[sess_dir] site smoke applied readiness=";
        line[..head.len()].copy_from_slice(head);
        let n = fmt_u32_raw(
            line.as_mut_ptr().add(head.len()),
            reply.invalidated_readiness as u32,
        );
        dev_log(sys, 3, line.as_ptr(), head.len() + n);
    }
    if reply.vip.status == VB_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let Some(slot) = take_pending(s, index, NS_RG) else {
        return;
    };
    let request_id = s.pending_req[slot];
    if s.out_replies >= 0 && request_id != 0 {
        let mut out = [0u8; 8 + RG_REPLY_LEN];
        out[..8].copy_from_slice(&request_id.to_le_bytes());
        let _ = reply.encode(&mut out[8..]);
        let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_RG_REPLY, &out);
        if wrote > 0 {
            s.replies_out = s.replies_out.saturating_add(1);
        }
    }
}

/// A committed `"OP"` entry: apply to the operation store on every
/// replica; relay the reply as `MSG_OP_REPLY` when it was ours. A
/// committed REPLAY of ours starts the replay pump (`pump_op_replay`)
/// for the kind it named, exactly as `fo/`'s does.
unsafe fn apply_committed_operation(s: &mut ModuleState, index: u64, body: &[u8]) {
    let reply: OperationReply = s.ops.apply(body, digest);
    if reply.status == OP_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let Some(slot) = take_pending(s, index, NS_OP) else {
        return;
    };
    let request_id = s.pending_req[slot];
    if request_id == 0 || s.out_replies < 0 {
        return;
    }
    if reply.op == OP_OP_REPLAY && reply.status == OP_ST_OK {
        if s.op_replay_active {
            s.op_replay_queued = request_id;
            s.op_replay_queued_kind = reply.kind;
        } else {
            start_op_replay(s, request_id, reply.kind);
        }
        return;
    }
    send_op_reply(s, request_id, &reply);
}

fn start_op_replay(s: &mut ModuleState, request_id: u64, kind: u8) {
    s.op_replay_active = true;
    s.op_replay_kind = kind;
    s.op_replay_req = request_id;
    s.op_replay_after = 0;
    s.op_replay_sent = 0;
}

unsafe fn send_op_reply(s: &mut ModuleState, request_id: u64, reply: &OperationReply) -> bool {
    let sys = &*s.syscalls;
    let mut out = [0u8; 8 + OP_REPLY_LEN];
    out[..8].copy_from_slice(&request_id.to_le_bytes());
    let _ = reply.encode(&mut out[8..]);
    let wrote = wire_channels::channel_write_msg(sys, s.out_replies, wire::MSG_OP_REPLY, &out);
    if wrote > 0 {
        s.replies_out = s.replies_out.saturating_add(1);
        true
    } else {
        false
    }
}

/// Stream the replay a committed operation REPLAY started: each live
/// record of the kind as a `REPLAY` reply in creation order, then the
/// end-of-replay reply (op REPLAY, status OK, the kind, the count sent).
unsafe fn pump_op_replay(s: &mut ModuleState) {
    let sys = &*s.syscalls;
    let mut budget = 8;
    while s.op_replay_active && budget > 0 {
        budget -= 1;
        if !wire_channels::writable(sys, s.out_replies) {
            return;
        }
        let next = s
            .ops
            .replay_next(s.op_replay_after, s.op_replay_kind)
            .map(|(seq, rec)| (seq, *rec));
        let req = s.op_replay_req;
        match next {
            Some((seq, record)) => {
                let reply = OperationReply {
                    op: OP_OP_REPLAY,
                    status: OP_ST_REPLAY,
                    present: true,
                    kind: record[operation_registry::OP_AT_KIND],
                    live: s.ops.live,
                    record,
                };
                if !send_op_reply(s, req, &reply) {
                    return;
                }
                s.op_replay_after = seq;
                s.op_replay_sent = s.op_replay_sent.saturating_add(1);
            }
            None => {
                let mut end = OperationReply::zero();
                end.op = OP_OP_REPLAY;
                end.status = OP_ST_OK;
                end.kind = s.op_replay_kind;
                end.live = s.op_replay_sent;
                if !send_op_reply(s, req, &end) {
                    return;
                }
                s.op_replay_active = false;
                if s.op_replay_queued != 0 {
                    let (next, kind) = (s.op_replay_queued, s.op_replay_queued_kind);
                    s.op_replay_queued = 0;
                    start_op_replay(s, next, kind);
                }
            }
        }
    }
}

/// A committed `"AT"` entry: apply to the attachment boundaries on every
/// replica; relay the reply as `MSG_AT_REPLY` when it was ours.
unsafe fn apply_committed_attachment(s: &mut ModuleState, index: u64, body: &[u8]) {
    let reply: AttachmentReply = s.attachments.apply(body);
    if reply.status == AT_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let mut out = [0u8; 8 + AT_REPLY_LEN];
    let _ = reply.encode(&mut out[8..]);
    relay_reply(s, index, NS_AT, wire::MSG_AT_REPLY, &mut out);
}

/// A committed `"RS"` entry: apply to the reservations at the committed
/// logical time of this log position (the timing state's, replicated, so
/// every replica decides a horizon alike); relay the reply as
/// `MSG_RS_REPLY` when it was ours.
unsafe fn apply_committed_reservation(s: &mut ModuleState, index: u64, body: &[u8]) {
    let now = s.registry.timing.logical_now_ms();
    let reply: ReservationReply = s.reservations.apply(body, now);
    if reply.status == RS_ST_OK {
        s.applied_ok = s.applied_ok.saturating_add(1);
    } else {
        s.applied_rejected = s.applied_rejected.saturating_add(1);
    }
    let mut out = [0u8; 8 + RS_REPLY_LEN];
    let _ = reply.encode(&mut out[8..]);
    relay_reply(s, index, NS_RS, wire::MSG_RS_REPLY, &mut out);
}

/// Send `out` (`[request_id:8]` then the encoded reply) as `msg` when the
/// entry at `index` was this replica's proposal in namespace `ns`.
unsafe fn relay_reply(s: &mut ModuleState, index: u64, ns: u8, msg: u8, out: &mut [u8]) {
    let Some(slot) = take_pending(s, index, ns) else {
        return;
    };
    let request_id = s.pending_req[slot];
    if s.out_replies < 0 || request_id == 0 {
        return;
    }
    out[..8].copy_from_slice(&request_id.to_le_bytes());
    let sys = &*s.syscalls;
    if wire_channels::channel_write_msg(sys, s.out_replies, msg, out) > 0 {
        s.replies_out = s.replies_out.saturating_add(1);
    }
}

/// `MON_EV_VIP_MOVED` for a committed VIP ACTIVATE: the service id in
/// the session-id field, the vip epoch (low 32 bits) as the epoch.
unsafe fn mon_vip_moved(s: &mut ModuleState, reply: &VipReply) {
    let sys = &*s.syscalls;
    if s.self_idx == 0xFF {
        let idx = dev_self_index(sys);
        if idx >= 0 {
            s.self_idx = idx as u8;
        }
    }
    let mut service_id = [0u8; 16];
    service_id.copy_from_slice(&reply.key[..16]);
    let mon_ptr = s.mon_buf.as_mut_ptr();
    let _ = dev_mon_session(
        sys,
        s.self_idx,
        MON_EV_VIP_MOVED,
        service_id.as_ptr(),
        reply.vip_epoch as u32,
        core::ptr::null(),
        core::ptr::null(),
        b"vip_activate",
        b"ok",
        mon_ptr,
        192,
    );
}

/// Smoke sequence: BIND → RESERVE(4096) → RESERVE(4096). The second
/// grant landing at start=4096 in the log is the end-to-end proof
/// that grants are quorum-committed, monotone, and never re-handed
/// out. Requests are self-originated (request_id 0 → no reply frame).
unsafe fn smoke_advance(s: &mut ModuleState, reply: &SessionReply) {
    if s.smoke_phase == SMOKE_OFF || s.smoke_phase == SMOKE_DONE {
        return;
    }
    let sys = &*s.syscalls;
    let mut cmd = [0u8; SR_MAX_CMD];
    match (s.smoke_phase, reply.op, reply.status) {
        (SMOKE_BIND_SENT, SR_OP_BIND, SR_ST_OK) => {
            let n = build_reserve(&mut cmd, &SMOKE_SID, 1, 0, 4096);
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_RESERVE1_SENT;
            }
        }
        (SMOKE_RESERVE1_SENT, SR_OP_RESERVE, SR_ST_OK) => {
            let n = build_reserve(&mut cmd, &SMOKE_SID, 1, 0, 4096);
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_RESERVE2_SENT;
            }
        }
        (SMOKE_RESERVE2_SENT, SR_OP_RESERVE, SR_ST_OK) => {
            if s.smoke >= 2 {
                // Timing smoke: arm a TTL'd key. The proposal happens
                // from the step loop (SMOKE_KEY_ARM) so the freshness
                // barrier can retry until duration admission passes.
                s.smoke_phase = SMOKE_KEY_ARM;
            } else {
                s.smoke_phase = SMOKE_DONE;
                dev_log(sys, 3, b"[sess_dir] smoke complete".as_ptr(), 25);
            }
        }
        (SMOKE_KEY_SENT, SR_OP_KEY_PUT, SR_ST_OK) => {
            s.smoke_phase = SMOKE_DONE;
            dev_log(sys, 3, b"[sess_dir] smoke complete".as_ptr(), 25);
        }
        (_, _, st) if st != SR_ST_OK => {
            // A refused smoke step is a real failure signal; stop.
            s.smoke_phase = SMOKE_DONE;
            dev_log(sys, 1, b"[sess_dir] smoke refused".as_ptr(), 24);
        }
        _ => {}
    }
}

// ── Streamed snapshot helpers ───────────────────────────────────────

/// Begin an install: clear the registries and hold applies until an
/// image installs.
fn install_begin(s: &mut ModuleState) {
    // A replay streams committed state, which an install replaces: every
    // stream stops unended, and its requester resends once the install
    // has the group's state again.
    s.fo_replay_active = false;
    s.fo_replay_queued = 0;
    s.op_replay_active = false;
    s.op_replay_queued = 0;
    s.sr_installer = s.registry.install_begin();
    s.tr_installer = s.transport.install_begin();
    s.vb_installer = s.vip.install_begin();
    s.fo_installer = s.failover.install_begin();
    s.rg_installer = s.region.install_begin();
    s.op_installer = s.ops.install_begin();
    s.at_installer = s.attachments.install_begin();
    s.rs_installer = s.reservations.install_begin();
    s.install_section = SNAP_SECTION_SR;
    s.install_active = true;
    s.hold_applies = true;
    s.snap_in_off = 0;
}

/// Abandon an install: the registries stay cleared and applies held.
fn install_abandon(s: &mut ModuleState) {
    s.install_active = false;
    s.snap_in_off = 0;
    s.hold_applies = true;
}

/// Feed one chunk body through the sections in order. False on a
/// rejected image.
fn install_feed(s: &mut ModuleState, mut bytes: &[u8]) -> bool {
    while !bytes.is_empty() {
        match s.install_section {
            SNAP_SECTION_SR => {
                let Ok(n) = s.registry.install_feed(&mut s.sr_installer, bytes) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.sr_installer.done() {
                    s.install_section = SNAP_SECTION_TR;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_TR => {
                let Ok(n) = s.transport.install_feed(&mut s.tr_installer, bytes) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.tr_installer.done() {
                    s.install_section = SNAP_SECTION_VB;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_VB => {
                let Ok(n) = s.vip.install_feed(&mut s.vb_installer, bytes) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.vb_installer.done() {
                    s.install_section = SNAP_SECTION_FO;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_FO => {
                let Ok(n) = s.failover.install_feed(&mut s.fo_installer, bytes, digest) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.fo_installer.done() {
                    s.install_section = SNAP_SECTION_RG;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_RG => {
                let Ok(n) = s.region.install_feed(&mut s.rg_installer, bytes) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.rg_installer.done() {
                    s.install_section = SNAP_SECTION_OP;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_OP => {
                let Ok(n) = s.ops.install_feed(&mut s.op_installer, bytes, digest) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.op_installer.done() {
                    s.install_section = SNAP_SECTION_AT;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_AT => {
                let Ok(n) = s.attachments.install_feed(&mut s.at_installer, bytes) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.at_installer.done() {
                    s.install_section = SNAP_SECTION_RS;
                } else if n == 0 {
                    return false;
                }
            }
            SNAP_SECTION_RS => {
                let Ok(n) = s.reservations.install_feed(&mut s.rs_installer, bytes) else {
                    return false;
                };
                bytes = &bytes[n..];
                if s.rs_installer.done() {
                    s.install_section = SNAP_SECTION_DONE;
                } else if n == 0 {
                    return false;
                }
            }
            _ => return false, // bytes past the image's end
        }
    }
    true
}

/// Every section must have ended exactly where its counts said.
fn install_finish(s: &mut ModuleState) -> bool {
    let sr = s.registry.install_finish(&mut s.sr_installer);
    let tr = s.transport.install_finish(&mut s.tr_installer);
    let vb = s.vip.install_finish(&mut s.vb_installer);
    let fo = s.failover.install_finish(&mut s.fo_installer);
    let rg = s.region.install_finish(&mut s.rg_installer);
    let op = s.ops.install_finish(&mut s.op_installer);
    let at = s.attachments.install_finish(&mut s.at_installer);
    let rs = s.reservations.install_finish(&mut s.rs_installer);
    sr && tr && vb && fo && rg && op && at && rs && s.install_section == SNAP_SECTION_DONE
}

/// Stage export units until a chunk is ready or the image ends.
fn export_stage(s: &mut ModuleState) {
    while (s.snap_staged as usize) < SNAP_CHUNK && s.export_section != SNAP_SECTION_DONE {
        let at = s.snap_staged as usize;
        let n = match s.export_section {
            SNAP_SECTION_SR => s
                .registry
                .export_next(&mut s.sr_cursor, &mut s.snap_buf[at..]),
            SNAP_SECTION_TR => s
                .transport
                .export_next(&mut s.tr_cursor, &mut s.snap_buf[at..]),
            SNAP_SECTION_VB => s.vip.export_next(&mut s.vb_cursor, &mut s.snap_buf[at..]),
            SNAP_SECTION_FO => s
                .failover
                .export_next(&mut s.fo_cursor, &mut s.snap_buf[at..]),
            SNAP_SECTION_RG => s
                .region
                .export_next(&mut s.rg_cursor, &mut s.snap_buf[at..]),
            SNAP_SECTION_OP => s.ops.export_next(&mut s.op_cursor, &mut s.snap_buf[at..]),
            SNAP_SECTION_AT => s
                .attachments
                .export_next(&mut s.at_cursor, &mut s.snap_buf[at..]),
            _ => s
                .reservations
                .export_next(&mut s.rs_cursor, &mut s.snap_buf[at..]),
        };
        if n == 0 {
            s.export_section += 1;
            continue;
        }
        s.snap_staged += n as u32;
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // SAFETY: per the module ABI, `state` is valid and exclusively
    // borrowed; the syscall table is live.
    unsafe {
        let s = &mut *(state as *mut ModuleState);
        let sys = &*s.syscalls;

        // 0) Proposal assignments — drained FIRST: raft emits the
        //    assignment (`[correlation:8][partition:2][wal_index:8]`)
        //    at flush time, strictly before the entry can commit, so
        //    processing assignments ahead of committed entries
        //    preserves that order within a step. The wal_index is the
        //    attribution the committed-entry pass matches on.
        if s.in_proposal_assigned >= 0 {
            for _ in 0..8 {
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_proposal_assigned, &mut s.msg_buf)
                else {
                    break;
                };
                if msg_type != wire::MSG_PROPOSAL_ASSIGNED || (plen as usize) < 18 {
                    continue;
                }
                let corr = u64::from_le_bytes([
                    s.msg_buf[0],
                    s.msg_buf[1],
                    s.msg_buf[2],
                    s.msg_buf[3],
                    s.msg_buf[4],
                    s.msg_buf[5],
                    s.msg_buf[6],
                    s.msg_buf[7],
                ]);
                let partition = u16::from_le_bytes([s.msg_buf[8], s.msg_buf[9]]);
                let wal_index = u64::from_le_bytes([
                    s.msg_buf[10],
                    s.msg_buf[11],
                    s.msg_buf[12],
                    s.msg_buf[13],
                    s.msg_buf[14],
                    s.msg_buf[15],
                    s.msg_buf[16],
                    s.msg_buf[17],
                ]);
                for i in 0..MAX_PENDING {
                    if s.pending_used[i] && s.pending_corr[i] == corr {
                        s.pending_idx[i] = wal_index;
                        s.pending_part[i] = partition;
                        if partition != s.partition_id {
                            s.misrouted = s.misrouted.saturating_add(1);
                            dev_log(sys, 2, b"[sess_dir] misrouted".as_ptr(), 20);
                        }
                        break;
                    }
                }
                // A barrier in another group's log orders nothing in
                // this one: its check is dropped unanswered.
                if s.checks.assign(corr, partition, wal_index) == Assigned::Foreign {
                    s.misrouted = s.misrouted.saturating_add(1);
                    s.checks_expired = s.checks_expired.saturating_add(1);
                }
            }
        }

        // 0.5) Pending-slot TTL reclaim. Nothing else frees a slot
        //      whose MSG_PROPOSAL_ASSIGNED (or committed entry) is
        //      lost, and MAX_PENDING such leaks wedge the request path
        //      until restart. The requester sees the same signal as any
        //      other lost proposal: a reply timeout → retry.
        {
            let now = dev_millis(sys);
            for i in 0..MAX_PENDING {
                if s.pending_used[i] && now.wrapping_sub(s.pending_born_ms[i]) > PENDING_TTL_MS {
                    s.pending_used[i] = false;
                    s.proposals_expired = s.proposals_expired.saturating_add(1);
                    dev_log(sys, 2, b"[sess_dir] pending expired".as_ptr(), 26);
                }
            }
            let dropped = s.checks.expire(now);
            s.checks_expired = s.checks_expired.saturating_add(dropped);
        }

        // 1) Committed entries — apply in strict order, reply on match.
        //    Held while an export streams (the image is one index's
        //    state) and from a begun or failed install until one
        //    succeeds (never apply onto a partial image).
        let hold = s.export_active || s.hold_applies;
        for _ in 0..16 {
            if hold {
                break;
            }
            let Some((msg_type, plen)) = wire_channels::next_msg(sys, s.in_entries, &mut s.msg_buf)
            else {
                break;
            };
            if msg_type != wire::MSG_COMMITTED_ENTRY {
                continue;
            }
            let plen = plen as usize;
            match wire::decode_committed_entry_hdr(&s.msg_buf[..plen]) {
                Some((partition, _, _)) if partition != s.partition_id => {
                    s.foreign_entries = s.foreign_entries.saturating_add(1);
                    continue;
                }
                _ => {}
            }
            match s.subscriber.ingest_committed_entry(&s.msg_buf[..plen]) {
                Ok(entry) => {
                    // Copy the command out of msg_buf so apply can
                    // borrow module state freely.
                    let mut cmd = [0u8; 2 + CMD_MAX];
                    let n = entry.command.len().min(cmd.len());
                    cmd[..n].copy_from_slice(&entry.command[..n]);
                    let index = entry.index;
                    apply_committed(s, index, &cmd[..n]);
                }
                Err(CommitOrderError::GapInPerEntryStream { observed, .. })
                    if s.forwarded_stream != 0 =>
                {
                    // A forwarder handed us the next of OUR entries; the
                    // indices it skipped were other consumers'. Follow it.
                    let term = wire::decode_committed_entry_hdr(&s.msg_buf[..plen])
                        .map_or(0, |(_, term, _)| term);
                    s.subscriber.reset_to(observed - 1, term);
                    if let Ok(entry) = s.subscriber.ingest_committed_entry(&s.msg_buf[..plen]) {
                        let mut cmd = [0u8; 2 + CMD_MAX];
                        let n = entry.command.len().min(cmd.len());
                        cmd[..n].copy_from_slice(&entry.command[..n]);
                        let index = entry.index;
                        apply_committed(s, index, &cmd[..n]);
                    }
                }
                Err(CommitOrderError::GapInPerEntryStream { .. }) => {
                    s.stream_gaps = s.stream_gaps.saturating_add(1);
                    dev_log(sys, 2, b"[sess_dir] gap".as_ptr(), 14);
                    // Recovery is a snapshot install (below).
                }
                Err(_) => {
                    dev_log(sys, 2, b"[sess_dir] bad entry".as_ptr(), 20);
                }
            }
        }

        // 1.5) Token checks (Fluxor's `auth_req`), on their own port and
        //      their own slot table, so registry commands and checks never
        //      wait on each other. Each is held behind a barrier entry and
        //      answered once applied state reaches it; a check no slot or
        //      proposal could take stays in the channel. Then every held
        //      check whose barrier the entries above applied is answered.
        if s.in_checks >= 0 {
            for _ in 0..MAX_CHECKS {
                if !s.checks.has_room()
                    || !wire_channels::writable(sys, s.out_proposals)
                    || !wire_channels::writable(sys, s.out_replies)
                {
                    break;
                }
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_checks, &mut s.msg_buf)
                else {
                    break;
                };
                let plen = (plen as usize).min(s.msg_buf.len());
                if msg_type == MSG_ARM_AUTH_CHECK && plen > CHECK_REQ_MAX {
                    // Refused whatever the state: no barrier needed.
                    refuse_oversized_arm_check(s, plen);
                    continue;
                }
                if msg_type != MSG_FLOW_TOKEN_CHECK && msg_type != MSG_ARM_AUTH_CHECK {
                    continue;
                }
                // Both gates were open above, so only a ring that filled
                // between the check and the write loses the frame — and
                // an unanswered check is a refusal.
                if !take_check(s, msg_type, plen) {
                    s.checks_expired = s.checks_expired.saturating_add(1);
                }
            }
        }
        answer_checks_through(s, s.subscriber.cursor());

        // 2) Requests — propose each as a tagged raft entry. When the
        //    pending table is full the frame stays in the channel for
        //    the next step; a full proposal ring drops the consumed
        //    request (see the note at the propose() call below).
        if s.in_requests >= 0 {
            for _ in 0..4 {
                let has_free = s.pending_used.iter().any(|u| !u);
                if !has_free {
                    break;
                }
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_requests, &mut s.msg_buf)
                else {
                    break;
                };
                let (ns, cmd_max) = match msg_type {
                    wire::MSG_SR_REQUEST => (NS_SR, SR_MAX_CMD),
                    wire::MSG_TR_REQUEST => (NS_TR, TR_MAX_CMD),
                    wire::MSG_VB_REQUEST => (NS_VB, VB_MAX_CMD),
                    wire::MSG_FO_REQUEST => (NS_FO, FO_MAX_CMD),
                    wire::MSG_RG_REQUEST => (NS_RG, RG_MAX_CMD),
                    wire::MSG_OP_REQUEST => (NS_OP, OP_MAX_CMD),
                    wire::MSG_AT_REQUEST => (NS_AT, AT_MAX_CMD),
                    wire::MSG_RS_REQUEST => (NS_RS, RS_MAX_CMD),
                    _ => continue,
                };
                let plen = plen as usize;
                if plen <= 8 || plen > 8 + cmd_max {
                    continue;
                }
                s.requests_in = s.requests_in.saturating_add(1);
                if let Err(why) = scope_admits(s.scope, msg_type, &s.msg_buf[8..plen]) {
                    s.scope_refusals = s.scope_refusals.saturating_add(1);
                    let mut out = [0u8; 10];
                    out[..8].copy_from_slice(&s.msg_buf[..8]);
                    out[8] = msg_type;
                    out[9] = why;
                    let _ = wire_channels::channel_write_msg(
                        sys,
                        s.out_replies,
                        wire::MSG_DIR_OUT_OF_SCOPE,
                        &out,
                    );
                    continue;
                }
                let request_id = u64::from_le_bytes([
                    s.msg_buf[0],
                    s.msg_buf[1],
                    s.msg_buf[2],
                    s.msg_buf[3],
                    s.msg_buf[4],
                    s.msg_buf[5],
                    s.msg_buf[6],
                    s.msg_buf[7],
                ]);
                let mut body = [0u8; CMD_MAX];
                let blen = plen - 8;
                body[..blen].copy_from_slice(&s.msg_buf[8..plen]);
                // A horizon is counted from committed time, so a command
                // carrying one is admitted only behind the time-freshness
                // barrier (as a duration is): stale time would end the
                // horizon early in wall terms. Not admitted now, it is
                // dropped and the requester's retry finds time fresh.
                if ns == NS_RS && carries_horizon(&body[..blen]) && !ensure_time_fresh(s) {
                    continue;
                }
                // A request that cannot be proposed right now is
                // DROPPED here (we already consumed the frame) — the
                // requester retries on reply timeout. Dropping beats
                // wedging the ring.
                let _ = propose_ns(s, request_id, &body[..blen], FACE_NONE, ns);
            }
        }

        // 2b) The contract's verbs from anchors. HELLO is answered here;
        //     everything else is a replicated command answered after
        //     commit, on the frame its face names.
        if s.in_ctrl >= 0 {
            for _ in 0..8 {
                let has_free = s.pending_used.iter().any(|u| !u);
                if !has_free {
                    break;
                }
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_ctrl, &mut s.msg_buf)
                else {
                    break;
                };
                let plen = plen as usize;
                if msg_type == sc::CMD_SC_HELLO {
                    let mut ack = [0u8; 16];
                    let n = hello_ack(s.replica_id, &mut ack);
                    dev_log(sys, 3, b"[directory] hello".as_ptr(), 17);
                    if s.out_ctrl >= 0 {
                        let _ = wire_channels::channel_write_msg(
                            sys,
                            s.out_ctrl,
                            sc::MSG_SC_HELLO_ACK,
                            &ack[..n],
                        );
                    }
                    continue;
                }
                let mut payload = [0u8; 64];
                let take = plen.min(64);
                payload[..take].copy_from_slice(&s.msg_buf[..take]);
                let mut body = [0u8; SR_MAX_CMD];
                let Some((blen, face)) = request_to_command(msg_type, &payload[..take], &mut body)
                else {
                    continue;
                };
                s.requests_in = s.requests_in.saturating_add(1);
                let _ = propose_on(s, 0, &body[..blen], face);
            }
        }

        // 3) Smoke kick-off: propose the BIND once the proposal ring
        //    is writable (leadership settles behind it; the proposal
        //    simply commits when the group is ready).
        if s.smoke_phase == SMOKE_IDLE {
            let mut cmd = [0u8; SR_MAX_CMD];
            let n = build_bind(
                &mut cmd,
                &SMOKE_SID,
                1,
                &SMOKE_ANCHOR,
                &SMOKE_WORKER,
                SR_BIND_FENCE_REQUIRED,
            );
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_BIND_SENT;
                dev_log(sys, 3, b"[sess_dir] smoke bind sent".as_ptr(), 26);
            }
        }

        // 3.5) Timing smoke: arm the TTL'd key once duration admission
        //      passes the freshness barrier (retries every step).
        if s.smoke_phase == SMOKE_KEY_ARM && ensure_time_fresh(s) {
            let mut cmd = [0u8; SR_MAX_CMD];
            let n = build_key_put(&mut cmd, &SMOKE_SID, 1, SMOKE_KEY_TTL_MS, b"smoke-key");
            if n > 0 && propose(s, 0, &cmd[..n]) {
                s.smoke_phase = SMOKE_KEY_SENT;
                dev_log(sys, 3, b"[sess_dir] smoke key sent".as_ptr(), 25);
            }
        }

        // 4) Snapshot install (catch-up path): chunks feed the streamed
        //    installers section by section; nothing is buffered whole.
        if s.in_snapshot_chunk >= 0 {
            for _ in 0..4 {
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_snapshot_chunk, &mut s.msg_buf)
                else {
                    break;
                };
                let pl = plen as usize;
                match msg_type {
                    wire::MSG_APP_SNAPSHOT_RESET => install_begin(s),
                    wire::MSG_APP_SNAPSHOT_CHUNK => {
                        if let Some((_term, last_idx, off, done, hdr)) =
                            wire::decode_app_snapshot_chunk(&s.msg_buf[..pl])
                        {
                            // An offset-zero chunk starts an image, whatever
                            // an earlier transfer left half-fed: a sender that
                            // restarts its transfer is not then refused for it.
                            if off == 0 {
                                install_begin(s);
                            }
                            if !s.install_active || off != u64::from(s.snap_in_off) {
                                // Out-of-order chunk: abandon this install.
                                install_abandon(s);
                                continue;
                            }
                            let mut body = [0u8; MSG_BUF];
                            let body_len = pl - hdr;
                            body[..body_len].copy_from_slice(&s.msg_buf[hdr..pl]);
                            if !install_feed(s, &body[..body_len]) {
                                dev_log(sys, 1, b"[sess_dir] snapshot corrupt".as_ptr(), 27);
                                install_abandon(s);
                                continue;
                            }
                            s.snap_in_off = s.snap_in_off.saturating_add(body_len as u32);
                            if done {
                                if install_finish(s) {
                                    s.subscriber = CommittedSubscriber::new(last_idx);
                                    s.hold_applies = false;
                                    dev_log(sys, 3, b"[sess_dir] snapshot installed".as_ptr(), 29);
                                } else {
                                    dev_log(sys, 1, b"[sess_dir] snapshot corrupt".as_ptr(), 27);
                                }
                                s.install_active = false;
                                s.snap_in_off = 0;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // 5) Snapshot export on request: streamed across steps, one
        //    chunk per channel write, applies held meanwhile.
        if !s.export_active
            && s.in_snapshot_request >= 0
            && s.out_snapshot_export >= 0
            && wire_channels::readable(sys, s.in_snapshot_request)
        {
            let (msg_type, plen) =
                wire_channels::channel_read_msg(sys, s.in_snapshot_request, &mut s.msg_buf);
            let req = if msg_type == wire::MSG_APP_SNAPSHOT_REQUEST {
                wire::decode_term_index(&s.msg_buf[..plen as usize])
            } else {
                None
            };
            if let Some((term, last_idx)) = req {
                s.export_active = true;
                s.export_section = SNAP_SECTION_SR;
                s.export_term = term;
                s.export_last_idx = last_idx;
                s.export_off = 0;
                s.sr_cursor = SrExportCursor::new();
                s.tr_cursor = TrExportCursor::new();
                s.vb_cursor = VbExportCursor::new();
                s.fo_cursor = FoExportCursor::new();
                s.rg_cursor = RgExportCursor::new();
                s.op_cursor = OpExportCursor::new();
                s.at_cursor = AtExportCursor::new();
                s.rs_cursor = RsExportCursor::new();
                s.snap_staged = 0;
            }
        }
        if s.export_active {
            for _ in 0..8 {
                if !wire_channels::writable(sys, s.out_snapshot_export) {
                    break;
                }
                export_stage(s);
                let staged = s.snap_staged as usize;
                let done = s.export_section == SNAP_SECTION_DONE;
                if staged < SNAP_CHUNK && !done {
                    // The staging cannot be short of a chunk before the end.
                    s.export_active = false;
                    break;
                }
                let n = SNAP_CHUNK.min(staged);
                let last = done && n == staged;
                let mut out = [0u8; wire::APP_SNAPSHOT_HDR + SNAP_CHUNK];
                let en = wire::encode_app_snapshot_chunk(
                    &mut out,
                    s.export_term,
                    s.export_last_idx,
                    s.export_off,
                    last,
                    &s.snap_buf[..n],
                );
                if en == 0
                    || wire_channels::channel_write_msg(
                        sys,
                        s.out_snapshot_export,
                        wire::MSG_APP_SNAPSHOT_CHUNK,
                        &out[..en],
                    ) <= 0
                {
                    // The channel took nothing; the chunk stays staged.
                    break;
                }
                s.snap_buf.copy_within(n..staged, 0);
                s.snap_staged = (staged - n) as u32;
                s.export_off += n as u64;
                if last {
                    s.export_active = false;
                    break;
                }
            }
        }

        // 5.5) Leader hints — the fence for the time producer.
        if s.in_leader_state >= 0 {
            for _ in 0..8 {
                let Some((msg_type, plen)) =
                    wire_channels::next_msg(sys, s.in_leader_state, &mut s.msg_buf)
                else {
                    break;
                };
                if msg_type == wire::MSG_LEADER_HINT && plen >= 1 {
                    s.leader_id = s.msg_buf[0];
                }
            }
        }

        // 5.6) Deterministic time production, leader-fenced. Only the
        //      current leader samples wall time and proposes TimeAdvance /
        //      TimeDrain; an idle index proposes nothing (idle
        //      coalescing); an unhealthy clock makes deadlines late
        //      rather than firing from an untrusted source.
        if !is_leader(s) {
            s.pause_reason = wire::TIMING_PAUSE_NOT_LEADER;
            s.last_unix_ms = 0;
        } else {
            let mono = dev_millis(sys);
            let unix = dev_unix_millis(sys);
            s.last_unix_ms = unix;
            let health = s.clock_guard.sample(mono, unix);
            let logical = s.registry.timing.logical_now_ms();
            if health != ClockHealth::Healthy {
                s.pause_reason = wire::TIMING_PAUSE_CLOCK_ALARM;
            } else if s.registry.timing.has_due() {
                // Committed due backlog: continue with drain entries
                // through the already-committed time fence. Advancing
                // pauses so due work stays within apply budgets.
                s.pause_reason = wire::TIMING_PAUSE_DRAIN_BACKLOG;
                if mono.wrapping_sub(s.last_drain_propose_ms) >= 50 {
                    let mut body = [0u8; wire::TIMING_ENTRY_LEN];
                    let n = wire::encode_time_entry(&mut body, wire::TIMING_OP_DRAIN, logical);
                    if n > 0 && propose_raw(s, &body[..n]).is_some() {
                        s.last_drain_propose_ms = mono;
                    }
                }
            } else if s.registry.timing.live > 0 || s.reservations.horizon_pending(logical) {
                // Live deadlines, or a reservation horizon still to pass:
                // committed time must keep moving for either to end.
                s.pause_reason = wire::TIMING_PAUSE_NONE;
                if mono.wrapping_sub(s.last_advance_propose_ms) >= s.time_advance_period_ms as u64 {
                    if let Some(t) = s.clock_guard.propose_time(logical, unix) {
                        let mut body = [0u8; wire::TIMING_ENTRY_LEN];
                        let n = wire::encode_time_entry(&mut body, wire::TIMING_OP_ADVANCE, t);
                        if n > 0 && propose_raw(s, &body[..n]).is_some() {
                            s.last_advance_propose_ms = mono;
                        }
                    }
                }
            } else {
                // No live deadlines: idle tick coalescing.
                s.pause_reason = wire::TIMING_PAUSE_IDLE;
            }
        }

        // 5.6) The site-loss smoke: the leader commits the smoke region's
        //      next INVALIDATE every period. The command is a function of
        //      the readiness alone, so two leaders proposing the same one
        //      commit one invalidation and a retry is answered from it.
        if s.smoke == SMOKE_SITE && is_leader(s) && !s.hold_applies {
            let now = dev_millis(sys);
            if now.wrapping_sub(s.site_smoke_ms) >= SITE_SMOKE_PERIOD_MS {
                let readiness = s.region.invalidated_at(&SITE_SMOKE_REGION) + 1;
                let mut op_id = [0u8; 16];
                op_id[..8].copy_from_slice(&readiness.to_le_bytes());
                op_id[8..].copy_from_slice(b"SITESMKE");
                let mut cmd = [0u8; RG_INVALIDATE_LEN];
                let n = region_registry::build_invalidate(
                    &mut cmd,
                    &op_id,
                    &SITE_SMOKE_REGION,
                    readiness,
                );
                if n > 0 && propose_ns(s, 0, &cmd[..n], FACE_NONE, NS_RG) {
                    s.site_smoke_ms = now;
                }
            }
        }

        // 5.7) VIP capability seed, leader-proposed once per group from
        //      the kernel CSPRNG and replicated like any command, so every
        //      replica mints and verifies the same emission tokens. Not a
        //      restart concern: the seed lives in the log and the
        //      snapshot. Retried after the pending TTL if the proposal
        //      was lost; a second committed SEED is refused CONFLICT.
        if is_leader(s) && !s.vip.seeded() && !s.hold_applies {
            let now = dev_millis(sys);
            if now.wrapping_sub(s.seed_proposed_ms) > PENDING_TTL_MS {
                let mut seed = [0u8; VB_SEED];
                if dev_csprng_fill(sys, seed.as_mut_ptr(), VB_SEED) == 0 && seed != [0u8; VB_SEED] {
                    let mut op_id = [0u8; 16];
                    op_id[..8].copy_from_slice(&now.to_le_bytes());
                    op_id[8] = s.replica_id;
                    let mut cmd = [0u8; VB_MAX_CMD];
                    let n = build_seed(&mut cmd, &op_id, &seed);
                    if n > 0 && propose_ns(s, 0, &cmd[..n], FACE_NONE, NS_VB) {
                        s.seed_proposed_ms = now;
                        dev_log(sys, 3, b"[sess_dir] vip seed proposed".as_ptr(), 27);
                    }
                }
            }
        }

        // 5.8) Failover replay: stream the live records a committed
        //      REPLAY asked for, as `replies` has room.
        pump_fo_replay(s);
        pump_op_replay(s);

        // 6) Heartbeat metrics.
        let now = dev_millis(sys);
        if now.wrapping_sub(s.last_metrics_ms) >= 1000 && s.out_metrics >= 0 {
            s.last_metrics_ms = now;
            let mut buf = [0u8; 32];
            buf[0..8].copy_from_slice(&s.subscriber.cursor().to_le_bytes());
            buf[8..12].copy_from_slice(&s.applied_ok.to_le_bytes());
            buf[12..16].copy_from_slice(&s.applied_rejected.to_le_bytes());
            buf[16..20].copy_from_slice(&s.requests_in.to_le_bytes());
            buf[20..24].copy_from_slice(&s.replies_out.to_le_bytes());
            buf[24..28].copy_from_slice(&s.stream_gaps.to_le_bytes());
            buf[28..32].copy_from_slice(&s.registry.recovery_epoch.to_le_bytes());
            if wire_channels::writable(sys, s.out_metrics) {
                wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf);
            }

            // Typed timing series for /metrics export.
            let logical = s.registry.timing.logical_now_ms();
            let lag = if is_leader(s) && s.last_unix_ms > 0 {
                s.last_unix_ms.saturating_sub(logical)
            } else {
                0
            };
            let samples: [(u16, u8, i64); 9] = [
                (
                    wire::metric_ids::TIMING_LOGICAL_TIME_MS,
                    wire::METRIC_KIND_GAUGE,
                    logical as i64,
                ),
                (
                    wire::metric_ids::TIMING_LOGICAL_LAG_MS,
                    wire::METRIC_KIND_GAUGE,
                    lag as i64,
                ),
                (
                    wire::metric_ids::TIMING_ADVANCE_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.time_advance_applied as i64,
                ),
                (
                    wire::metric_ids::TIMING_DRAIN_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.time_drain_applied as i64,
                ),
                (
                    wire::metric_ids::TIMING_DEADLINES_ACTIVE,
                    wire::METRIC_KIND_GAUGE,
                    s.registry.timing.live as i64,
                ),
                (
                    wire::metric_ids::TIMING_DUE_DEPTH,
                    wire::METRIC_KIND_GAUGE,
                    s.registry.timing.due_depth() as i64,
                ),
                (
                    wire::metric_ids::TIMING_FIRED_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.registry.deadlines_fired as i64,
                ),
                (
                    wire::metric_ids::TIMING_NOOP_TOTAL,
                    wire::METRIC_KIND_COUNTER,
                    s.registry.deadline_noop as i64,
                ),
                (
                    wire::metric_ids::TIMING_PAUSE_REASON,
                    wire::METRIC_KIND_GAUGE,
                    s.pause_reason as i64,
                ),
            ];
            for (metric_id, kind, value) in samples {
                if !wire_channels::writable(sys, s.out_metrics) {
                    break;
                }
                let mut mb = [0u8; wire::METRIC_SAMPLE_LEN];
                wire::encode_metric_sample(
                    &mut mb,
                    wire::SOURCE_ID_TIMING,
                    0,
                    metric_id,
                    kind,
                    value,
                );
                wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &mb);
            }
        }

        0
    }
}
