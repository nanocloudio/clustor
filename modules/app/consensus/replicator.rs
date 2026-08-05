//! replicator — pipelines AppendEntries to followers, collects acks,
//! and emits match-index + durability updates.
//!
//! Receives batched entries from raft's AE seam ring, frames them as
//! peer RPCs via `net_out` to `peer_router`, and processes
//! `MSG_APPEND_ENTRIES_RESP` envelopes from peers to drive per-peer
//! replication state. Two outputs ride on each successful response:
//!   - the coalesced per-replica match array (to the commit component)
//!     — the follower's `last_log_index`, used for the standard Raft
//!     match-quorum.
//!   - `cross_durability_ack` (to durability's `ack`) — a
//!     synthesized `MSG_FSYNC_ACK` carrying the follower's
//!     `local_wal_durable_index` so the leader's durability ledger
//!     can compute quorum-fsync per spec §10.4.1.
//!
//! Per-step bound (Discipline §5): ≤4 AE fan-outs, ≤8 acks, ≤8 WAL
//! read-back replies, one catch-up sweep over MAX_NODES, ≤4 snapshot
//! chunk forwards.

use super::abi::SyscallTable;
use super::seam::SeamRing;
use super::types::*;
use super::{dev_log, dev_millis, wire, wire_channels};

/// Drain the E2 match seam: copy the coalesced per-replica match
/// indices into `out` and clear the dirty flag. Returns `false` (and
/// leaves `out` untouched) when nothing is pending. The dispatch
/// table's accessor — the composition layer never reads the fields.
pub fn take_matches(s: &mut Repl, out: &mut [Index; MAX_NODES]) -> bool {
    if !s.match_dirty {
        return false;
    }
    s.match_dirty = false;
    *out = s.match_out;
    true
}

const METRICS_INTERVAL_MS: u64 = 1000;

/// Outstanding WAL read-back request slot. Bounded so a slow WAL
/// cannot accumulate unbounded in-flight requests.
const MAX_PENDING_WAL_REQS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct PeerState {
    /// Steps since the last catch-up ship without an ack. Transit is
    /// lossy (a momentarily-full consumer channel drops the frame and
    /// no ack ever comes), so `inflight` must decay or the catch-up
    /// gate deadlocks. ~500 steps ≈ 0.5 s at the 1 kHz metadata
    /// domain, comfortably past a healthy ack round-trip.
    inflight_age: u16,
    next_index: Index,
    match_index: Index,
    inflight: u8,
    active: bool,
    /// Joint-consensus catch-up flag (RFC §1.2). When a new voter
    /// joins via `CONFIG_CHANGE_OP_JOINT`, the leader marks it as
    /// non-voting so its match_index doesn't count toward quorum
    /// until it has replicated up to a stable point. Promoted to
    /// voting once `match_index >= leader.last_log_index - VOTING_LAG`.
    voting: bool,
    /// Last (term, index) we know lives at `next_index - 1` on this
    /// peer. Used as the `prev_log_*` of the next AE. Updated either
    /// via WAL read-back or by recording the per-batch tip.
    prev_log_index: Index,
    prev_log_term: Term,
}

impl PeerState {
    /// The pre-leadership peer slot: every field zero, matching the
    /// kernel-zeroed module state the standalone `replicator` booted
    /// from (it activated slots in `module_new` without ever writing
    /// the rest of the struct).
    ///
    /// `next_index` MUST start at 0, not 1. It is the "have I ever
    /// replicated to this peer" flag that `drive_catchup` reads
    /// (`next > 0 && next <= tip`): a node that has never led has no
    /// idea where any peer's log ends, so it must not ship
    /// AppendEntries. Seeding it to 1 makes every replica — followers
    /// included — fan catch-up AEs at the current term as soon as a
    /// WAL tip probe answers, and a leader that receives an AE at its
    /// own term steps down (`handle_append_entries`, `role !=
    /// ROLE_FOLLOWER`). The result is perpetual leadership churn.
    /// Real values arrive from `process_acks` / `on_voter_set` once
    /// this node is actually the leader.
    const fn zero() -> Self {
        Self {
            next_index: 0,
            match_index: 0,
            inflight: 0,
            inflight_age: 0,
            active: false,
            voting: false,
            prev_log_index: 0,
            prev_log_term: 0,
        }
    }
}

/// How far behind a non-voting peer is allowed to be before it
/// auto-promotes to voting. Aggressive (small) values let the joint
/// transition complete quickly; large values bias toward "the new
/// voter must really be caught up". The Raft paper recommends a
/// single round's worth of log delta as a reasonable default.
const VOTING_LAG_THRESHOLD: u64 = 64;

/// Pending WAL read-back: maps a request_id we issued to the peer
/// that prompted it so the reply can be turned into a targeted AE.
#[derive(Clone, Copy)]
#[repr(C)]
struct PendingWalReq {
    request_id: u32,
    /// Peer that needs the entry. 0xFF means slot is unused.
    peer: u8,
    /// Index requested (= peer.next_index - 1 at issue time).
    wal_index: u64,
    /// Steps this request has been outstanding. The WAL round-trip can
    /// span several steps (module scheduling is not same-step), so an
    /// in-flight slot must keep its `request_id` stable until the reply
    /// arrives or the TTL expires — see `issue_wal_request`.
    age: u16,
}

impl PendingWalReq {
    const fn zero() -> Self {
        Self { request_id: 0, peer: 0xFF, wal_index: 0, age: 0 }
    }
}

/// Steps before an unanswered WAL request slot is freed for reissue.
/// Covers a lost round-trip (request or reply dropped on a full
/// channel) without letting the per-step catch-up renudge invalidate a
/// reply that is merely still in transit. Matches the inflight-decay
/// horizon (`PeerState::inflight_age`).
const PENDING_WAL_REQ_TTL: u16 = 500;

#[repr(C)]
pub struct Repl {
    // Channels
    pub in_ack: i32,            // in: responses from peers via peer_router
    pub in_snapshot_rx: i32,    // in: export chunks from the snapshot side
    pub out_net: i32,           // out: RPC frames to peer_router
    pub out_lag: i32,           // out: lag signal to admission
    pub out_snapshot_import: i32, // out: import chunks to the snapshot side
    pub out_metrics: i32,       // out: metrics (shared module port)
    pub out_wal_request: i32,   // out: MSG_WAL_ENTRY_REQUEST to wal
    pub out_snapshot_request: i32, // out: MSG_SNAPSHOT_INSTALL_REQUEST to the snapshot side
    pub out_cross_durability_ack: i32, // out: synthesized MSG_FSYNC_ACK to durability's ack (§10.4.1)

    // ── Seams ───────────────────────────────────────────────
    /// E2: coalesced per-replica max of follower match indices —
    /// many acks per step collapse to one array. The dispatch table
    /// drains it via [`take_matches`] and delivers to
    /// `commit::on_match`.
    match_out: [Index; MAX_NODES],
    match_dirty: bool,

    /// E11 seam (the leader-state hint raft already publishes on
    /// `leader_state`, delivered in-module): AppendEntries is a
    /// leader-only RPC. Delivered by the dispatch table right after
    /// raft steps, so it is current for this step's fan-out.
    is_leader: bool,

    // Config
    pub self_id: ReplicaId,
    pub peer_count: u8,
    pub pipeline_depth: u8,
    pub partition_id: u16,
    structural_lag_bytes: u32,

    // Per-peer state
    peers: [PeerState; MAX_NODES],

    /// Last `local_wal_durable_index` we forwarded to
    /// durability's `ack` for each peer (§10.4.1). Used to
    /// suppress redundant fsync-ack forwards: AE responses arrive on
    /// every heartbeat round whether or not the follower's durable
    /// index actually advanced, and the ledger already discards
    /// regressions, but we'd rather not burn the channel write either.
    last_forwarded_durable: [Index; MAX_NODES],

    /// Last batch we broadcast — both the (term, index) pair and the
    /// preceding (term, index). Used to populate per-peer prev_log_*
    /// for catch-up AEs without forcing an immediate WAL read-back.
    last_emitted_index: Index,
    last_emitted_term: Term,
    last_emitted_prev_index: Index,
    last_emitted_prev_term: Term,

    /// Current voter set bitmask from raft (RFC §1.2). A peer
    /// id present here is a current voter; peers not in the set are
    /// either non-existent or non-voting catch-up.
    current_voters: u8,
    /// Joint voter set bitmask. When `joint_active`, peers in
    /// `joint_voters & !current_voters` are the *new* voters that
    /// need to be promoted from non-voting after catching up.
    joint_voters: u8,
    joint_active: bool,

    // Pending WAL read-back requests issued for catch-up.
    pending: [PendingWalReq; MAX_PENDING_WAL_REQS],
    next_request_id: u32,

    // Metrics
    rpcs_sent: u32,
    acks_received: u32,
    nacks_received: u32,
    /// Tip probing: the raft entries stream is best-effort (its emit
    /// drops silently when the ring is momentarily full and there
    /// is no re-emit), so `last_emitted_index` can freeze behind the
    /// WAL. A periodic read-back for tip+1 against the local WAL
    /// advances the tip from the durable source instead.
    tip_probe_cooldown: u16,
    /// Failure responses due to follower WAL backpressure (busy), counted
    /// separately from divergence NACKs so the in-flight gauge stays exact
    /// and a backpressure storm doesn't masquerade as log divergence.
    backpressure_responses: u32,
    catchup_sent: u32,
    last_metrics_ms: u64,

    // Scratch
    msg_buf: [u8; 4096],
}

/// Initialise every field to its pre-param default. Channel handles
/// and params are assigned by `mod.rs` afterwards; `arm` runs the
/// post-param boot logic.
pub fn init(s: &mut Repl) {
    s.in_ack = -1;
    s.in_snapshot_rx = -1;
    s.out_net = -1;
    s.out_lag = -1;
    s.out_snapshot_import = -1;
    s.out_metrics = -1;
    s.out_wal_request = -1;
    s.out_snapshot_request = -1;
    s.out_cross_durability_ack = -1;
    s.match_out = [0; MAX_NODES];
    s.match_dirty = false;
    s.is_leader = false;
    s.self_id = 0;
    s.peer_count = 0;
    s.pipeline_depth = 8;
    s.partition_id = 0;
    s.structural_lag_bytes = 256 * 1024 * 1024;
    s.peers = [PeerState::zero(); MAX_NODES];
    s.last_forwarded_durable = [0; MAX_NODES];
    s.last_emitted_index = 0;
    s.last_emitted_term = 0;
    s.last_emitted_prev_index = 0;
    s.last_emitted_prev_term = 0;
    s.current_voters = 0;
    s.joint_voters = 0;
    s.joint_active = false;
    s.pending = [PendingWalReq::zero(); MAX_PENDING_WAL_REQS];
    s.next_request_id = 1;
    s.rpcs_sent = 0;
    s.acks_received = 0;
    s.nacks_received = 0;
    s.tip_probe_cooldown = 0;
    s.backpressure_responses = 0;
    s.catchup_sent = 0;
    s.last_metrics_ms = 0;
    for b in s.msg_buf.iter_mut() { *b = 0; }
}

/// Post-param boot logic: peer activation + init logs. Called by
/// `mod.rs` after channel handles and params are in place.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn arm(s: &mut Repl, sys: &SyscallTable) {
    // Activate peer slots. Initial set: 0..peer_count exclusive
    // of self. Every initial peer is voting; non-voting state is
    // entered only when a joint-consensus add brings a new peer
    // online (see `on_voter_set`).
    for i in 0..s.peer_count as usize {
        if i < MAX_NODES && i != s.self_id as usize {
            s.peers[i].active = true;
            s.peers[i].voting = true;
        }
    }

    // Log channel handles for debugging
    if s.out_net >= 0 {
        dev_log(sys, 3, b"[repl] net ok".as_ptr(), 13);
    } else {
        dev_log(sys, 3, b"[repl] net -1".as_ptr(), 13);
    }
    dev_log(sys, 3, b"[repl] init".as_ptr(), 11);
}

/// Deliver raft's current leadership state (E11). Message-shaped
/// per Discipline §2: the dispatch table calls this after `raft::step`
/// and before `replicator::step`, exactly where the old
/// `leader_state` channel hint would have landed a tick later.
pub fn on_leader_state(s: &mut Repl, is_leader: bool) {
    s.is_leader = is_leader;
}

/// One replicator step. `ae` is raft's AppendEntries outbox ring (E1),
/// drained here at the original ≤4/step bound. Voter-set updates are
/// delivered by the dispatch table via [`on_voter_set`] BEFORE this
/// step runs, so peer activation state is current before the AE
/// responses below are processed.
///
/// # Safety
///
/// Caller must hold exclusive component borrows and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn step(s: &mut Repl, ae: &mut SeamRing<8192>, sys: &SyscallTable) {
    // 1. Process inbound entries from raft → fan out to peers
    replicate_entries(s, sys, ae);

    // 2. Process ack responses from peers
    process_acks(s, sys);

    // 3. WAL read-back replies are delivered by the dispatch table's
    //    entry_reply demux via `on_wal_reply` (bit-31-clear request-id
    //    half) and turned into targeted AEs there.

    // 3b. Periodic catch-up driver: nudge every lagging follower toward
    //     the leader's tip each tick, independent of ack timing. The
    //     periodic AE fan-out only ever sends the TIP, so a follower that
    //     fell behind (failover, transient drop) relies entirely on
    //     targeted read-backs; driving them here (not just on ack events)
    //     keeps catch-up converging even when a follower's acks stall
    //     under load. Deduped by the pending table, so this can't pile up.
    drive_catchup(s, sys);

    // 4. Forward snapshot chunks
    forward_snapshots(s, sys);

    // 5. Emit metrics
    emit_metrics(s, sys);
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn replicate_entries(s: &mut Repl, sys: &SyscallTable, ae: &mut SeamRing<8192>) {
    // Process up to 4 entries per step
    for _ in 0..4 {
        if ae.is_empty() { break; }

        // Check output readiness (gate kept before each pop so a frame
        // is never consumed from the ring while `net_out` is full).
        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { break; }

        let (msg_type, plen) = match ae.pop(&mut s.msg_buf) {
            Some(v) => v,
            None => break,
        };
        if msg_type != wire::MSG_APPEND_ENTRIES || (plen as usize) < wire::AE_HDR_LEN { continue; }

        // Snapshot the AE header so we can record the per-peer
        // prev_log_* tip for catch-up retries.
        if let Some((_term, _leader, prev_idx, prev_term, _lc, ent_term, ent_idx)) =
            wire::decode_append_entries(&s.msg_buf[..plen as usize])
        {
            // Heartbeat-style AE has ent_idx == 0 — don't bump our tip.
            if ent_idx != 0 {
                s.last_emitted_prev_index = prev_idx;
                s.last_emitted_prev_term = prev_term;
                s.last_emitted_index = ent_idx;
                s.last_emitted_term = ent_term;
            }
        }

        // Fan out to each active peer with a routed envelope so
        // peer_router can demux to the correct connection.
        let payload = &s.msg_buf[..plen as usize];
        for i in 0..MAX_NODES {
            if !s.peers[i].active { continue; }
            if i == s.self_id as usize { continue; }
            let w = wire_channels::channel_write_routed_partitioned(
                sys, s.out_net, i as u8, s.partition_id,
                wire::MSG_APPEND_ENTRIES, payload,
            );
            if w > 0 {
                s.rpcs_sent += 1;
            } else {
                dev_log(sys, 3, b"[repl] send fail".as_ptr(), 16);
            }
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn process_acks(s: &mut Repl, sys: &SyscallTable) {
    if s.in_ack < 0 { return; }

    // Inbound shape from peer_router.peer_rx is the 5-byte partitioned
    // envelope. peer_router fans out a single channel to every per-
    // partition consensus instance (fluxor inserts a tee), so each
    // instance sees every ack and filters by its own partition_id.
    for _ in 0..8 {
        let poll = (sys.channel_poll)(s.in_ack, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (partition_id, msg_type, plen) =
            wire_channels::channel_read_partitioned(sys, s.in_ack, &mut s.msg_buf);
        if plen == 0 && msg_type == 0 { break; }
        if partition_id != s.partition_id { continue; }
        if plen < 17 { continue; }

        match msg_type {
            wire::MSG_APPEND_ENTRIES_RESP => {
                // Debug level: fires per AppendEntries response — hot path.
                dev_log(sys, 4, b"[repl] ack".as_ptr(), 10);
                let (term, index, replica, success, durable_index, busy) =
                    match wire::decode_append_entries_resp(&s.msg_buf[..plen as usize]) {
                        Some(v) => v,
                        None => continue,
                    };

                // Forward the follower's `local_wal_durable_index` to
                // the leader's durability `ack` as a synthesized
                // MSG_FSYNC_ACK keyed by the follower's replica id
                // (spec §10.4.1). Only forward strictly-advancing
                // values to keep the channel quiet on steady-state
                // heartbeats — the ledger also drops
                // regressions, but we'd rather not burn the write.
                if (replica as usize) < MAX_NODES
                    && durable_index > s.last_forwarded_durable[replica as usize]
                    && s.out_cross_durability_ack >= 0
                {
                    let poll_d = (sys.channel_poll)(s.out_cross_durability_ack, 0x02);
                    if poll_d > 0 && (poll_d as u32 & 0x02) != 0 {
                        let mut ack = [0u8; 17];
                        wire::encode_fsync_ack(&mut ack, term, durable_index, replica);
                        wire_channels::channel_write_msg(
                            sys,
                            s.out_cross_durability_ack,
                            wire::MSG_FSYNC_ACK,
                            &ack[..17],
                        );
                        s.last_forwarded_durable[replica as usize] = durable_index;
                    }
                }

                if (replica as usize) < MAX_NODES && s.peers[replica as usize].active {
                    if success {
                        // Snapshot before mutating; only forward when
                        // we make actual progress so the commit quorum
                        // index doesn't see redundant entries
                        // for the same match_index.
                        let prev_match = s.peers[replica as usize].match_index;
                        let was_voting = s.peers[replica as usize].voting;
                        let peer = &mut s.peers[replica as usize];
                        if peer.inflight > 0 { peer.inflight -= 1; }
                        peer.inflight_age = 0;
                        if index > peer.match_index {
                            peer.match_index = index;
                            peer.next_index = index + 1;
                        }
                        // Forward match update to commit ONLY
                        // when this peer is currently a voter (RFC §1.2
                        // non-voting catch-up). New voters joining via
                        // joint consensus catch up in non-voting state
                        // first; their match_index doesn't enter the
                        // quorum median until they're promoted.
                        // E2 seam: coalesced per-replica max + dirty flag
                        // (was a MSG_APPEND_ENTRIES_RESP channel write).
                        if was_voting && index > prev_match {
                            let r = replica as usize;
                            if index > s.match_out[r] {
                                s.match_out[r] = index;
                            }
                            s.match_dirty = true;
                        }
                        // Auto-promote: a non-voting peer that's caught
                        // up to within `VOTING_LAG_THRESHOLD` of the
                        // leader's tip becomes a full voter.
                        maybe_promote(s, sys, replica);
                        // Proactive catch-up: if this peer is still behind the
                        // leader's tip, pipeline the next missing entry NOW via
                        // a WAL read-back instead of waiting for the periodic
                        // tip-broadcast to NACK. Converges a lagging follower in
                        // O(gap) read-backs rather than O(gap) NACK round-trips
                        // — the difference between a follower that recovers in
                        // ~ms and one that wedges commit after a failover.
                        let pn = s.peers[replica as usize].next_index;
                        if s.peers[replica as usize].active
                            && pn > 0
                            && pn <= s.last_emitted_index
                        {
                            issue_wal_request(s, sys, replica, pn);
                        }
                        // Count the ack ONLY on success — failures are counted
                        // below — so the in-flight gauge retires each RPC once.
                        s.acks_received = s.acks_received.saturating_add(1);
                    } else if busy {
                        // Follower WAL backpressure, NOT log divergence: the
                        // entry was rejected only because the follower's WAL
                        // channel was momentarily full. Release the in-flight
                        // slot and leave next_index UNCHANGED so the next
                        // replication tick retries the SAME entry — rolling
                        // back here would drive needless log repair / snapshot
                        // recovery under load.
                        let peer = &mut s.peers[replica as usize];
                        if peer.inflight > 0 { peer.inflight -= 1; }
                        peer.inflight_age = 0;
                        s.backpressure_responses = s.backpressure_responses.saturating_add(1);
                        let _ = term;
                    } else {
                        // NACK: follower's log doesn't agree with our
                        // prev_log_* at this index (a gap because it's behind,
                        // or a conflict it just truncated). The reply carries
                        // the follower's CURRENT last_log_index — which, after
                        // it handled this AE, is authoritative for "what I
                        // have". Set next_index = that + 1 directly rather than
                        // decrementing by one: the decrement dance can roll
                        // next_index BACK below real progress when a stale
                        // tip-broadcast NACK arrives after a catch-up entry
                        // already advanced the follower (the periodic send
                        // fans the tip to every peer regardless of next_index).
                        let peer = &mut s.peers[replica as usize];
                        if peer.inflight > 0 { peer.inflight -= 1; }
                        peer.inflight_age = 0;
                        s.nacks_received = s.nacks_received.saturating_add(1);
                        let new_next = index.saturating_add(1).max(1);
                        peer.next_index = new_next;
                        // Term advance: stay safe if the follower bumped term.
                        let _ = term;
                        // Read back the entry the follower is MISSING — the one
                        // at next_index (the first it doesn't have), NOT
                        // next_index-1 (an entry it already holds, which would
                        // replay idempotently and never advance it).
                        issue_wal_request(s, sys, replica, new_next);
                    }
                }
            }
            wire::MSG_HEARTBEAT_RESP | wire::MSG_REQUEST_VOTE_RESP | wire::MSG_PRE_VOTE_RESP => {
                // Forward vote/heartbeat responses to raft via net_out
                // (they'll be routed back through the peer surface → raft's rpc)
                // For now, these pass through the same path.
            }
            wire::MSG_INSTALL_SNAPSHOT | wire::MSG_SNAPSHOT_CHUNK => {
                // Inbound snapshot chunk from leader. Forward to
                // the snapshot side via out_snapshot_import so it can
                // accumulate / install (RFC §5.13).
                if s.out_snapshot_import >= 0 {
                    let poll_out = (sys.channel_poll)(s.out_snapshot_import, 0x02);
                    if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                        wire_channels::channel_write_msg(
                            sys, s.out_snapshot_import,
                            msg_type, &s.msg_buf[..plen as usize],
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Nudge every active follower that is behind the leader's tip toward it via
/// a targeted WAL read-back. Idempotent per tick: `issue_wal_request` dedups
/// by `(peer, index)` and the table caps in-flight requests, so calling this
/// every step just keeps the catch-up pipeline primed without flooding.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` and supply a
/// `&SyscallTable` whose function pointers reach live kernel routines per
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drive_catchup(s: &mut Repl, sys: &SyscallTable) {
    // TTL sweep: free request slots whose round-trip evidently died
    // (request or reply dropped on a full channel) so the renudge below
    // can reissue them. In-transit replies keep their slot — and its
    // request_id — untouched. Runs before every early return so slots
    // age even while no peer is active.
    for slot in s.pending.iter_mut() {
        if slot.peer != 0xFF {
            slot.age = slot.age.saturating_add(1);
            if slot.age >= PENDING_WAL_REQ_TTL {
                *slot = PendingWalReq::zero();
            }
        }
    }

    // AppendEntries is leader-only. A follower (or a demoted ex-leader,
    // whose `next_index` values survive the transition) must not ship
    // catch-up AEs: they carry the CURRENT term, and a leader that
    // receives an AE at its own term steps down — so a single stray
    // catch-up from a follower unseats the cluster's leader and the
    // churn repeats. The tip probe is gated with it: `last_emitted_index`
    // only feeds the catch-up path.
    if !s.is_leader {
        return;
    }

    // A genuine single-voter graph has no catch-up work. Avoid probing WAL
    // tip+1 forever: those random reads move the shared descriptor and burn
    // the same hot core as durable appends.
    if !s.peers.iter().any(|peer| peer.active) {
        return;
    }

    // Tip probe (see `tip_probe_cooldown`): every ~500 steps ask the WAL
    // for tip+1. PROBE_PEER replies advance the tip; NotFound is the
    // steady state at the true tip and costs one small round-trip.
    if s.tip_probe_cooldown > 0 {
        s.tip_probe_cooldown -= 1;
    } else {
        s.tip_probe_cooldown = 500;
        let probe_idx = s.last_emitted_index.saturating_add(1);
        issue_wal_request(s, sys, PROBE_PEER, probe_idx);
    }
    let tip = s.last_emitted_index;
    if tip == 0 {
        return;
    }
    for i in 0..MAX_NODES {
        if i == s.self_id as usize {
            continue;
        }
        // Inflight decay (see PeerState::inflight_age).
        if s.peers[i].inflight > 0 {
            s.peers[i].inflight_age = s.peers[i].inflight_age.saturating_add(1);
            if s.peers[i].inflight_age >= 500 {
                s.peers[i].inflight = 0;
                s.peers[i].inflight_age = 0;
            }
        }
        if !s.peers[i].active {
            continue;
        }
        let next = s.peers[i].next_index;
        // Behind the tip → fetch the first entry it's missing. (`next == 0`
        // shouldn't happen, but guard so we never request index 0.)
        if next > 0 && next <= tip {
            issue_wal_request(s, sys, i as u8, next);
        }
    }
}

/// Pseudo peer id for tip probes (never a real replica slot).
const PROBE_PEER: u8 = 0xFE;

unsafe fn issue_wal_request(
    s: &mut Repl,
    sys: &SyscallTable,
    peer: u8,
    wal_index: u64,
) {
    if s.out_wal_request < 0 || wal_index == 0 { return; }
    // Catch-up gating: while a shipped catch-up AE is unacknowledged,
    // don't reissue for this peer — the per-step renudge would
    // otherwise re-read and re-ship the same entry every tick until
    // the ack round-trips. Probes are exempt (they don't ship).
    if peer != PROBE_PEER
        && (peer as usize) < MAX_NODES
        && s.peers[peer as usize].inflight >= 1
    {
        return;
    }

    // A request for this (peer, index) is already in flight: leave it
    // alone. Reassigning a fresh `request_id` here would invalidate the
    // reply currently in transit — the WAL round-trip spans steps, and
    // this function is renudged every step, so recycling live slots
    // livelocks catch-up (every reply arrives with a stale id and is
    // dropped). A lost round-trip is recovered by the slot TTL sweep in
    // `drive_catchup`.
    for slot in s.pending.iter() {
        if slot.peer == peer && slot.wal_index == wal_index {
            return;
        }
    }
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in s.pending.iter().enumerate() {
        if slot.peer == 0xFF { slot_idx = Some(i); break; }
    }
    let slot_idx = match slot_idx {
        Some(i) => i,
        None => return, // table full — wait for in-flight to drain
    };

    let request_id = s.next_request_id;
    // Stay in the bit-31-CLEAR half of the shared entry_request id
    // namespace: bit 31 marks apply's refetch ids (see
    // apply::ENTRY_REQUEST_ID_BIT), and the mod.rs reply demux routes
    // on it. An unmasked wrap into that half would misroute every
    // WAL reply until the counter wraps again.
    s.next_request_id = (s.next_request_id.wrapping_add(1) & 0x7FFF_FFFF).max(1);
    s.pending[slot_idx] = PendingWalReq { request_id, peer, wal_index, age: 0 };

    let poll_out = (sys.channel_poll)(s.out_wal_request, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 {
        // Channel full — free the slot so we retry next tick.
        s.pending[slot_idx] = PendingWalReq::zero();
        return;
    }
    let mut req = [0u8; wire::WAL_ENTRY_REQUEST_LEN];
    wire::encode_wal_entry_request(&mut req, request_id, wal_index);
    wire_channels::channel_write_msg(sys, s.out_wal_request, wire::MSG_WAL_ENTRY_REQUEST, &req);
}

/// Deliver a voter-set update from raft (E10; was the `voter_set`
/// channel). Activates new peers in
/// non-voting state and drops removed peers cleanly.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn on_voter_set(
    s: &mut Repl,
    sys: &SyscallTable,
    current: u8,
    joint: u8,
    joint_active: bool,
) {
    s.current_voters = current;
    s.joint_voters = joint;
    s.joint_active = joint_active;
    // Activate any peer that's in either set; deactivate
    // peers that have been dropped entirely.
    let union = current | joint;
    for id in 0..MAX_NODES as u8 {
        if id == s.self_id {
            continue;
        }
        let i = id as usize;
        let in_union = (union & (1u8 << id)) != 0;
        if in_union && !s.peers[i].active {
            // New peer: activate, start at last_log_index + 1
            // for the leader's known log tip, non-voting until
            // caught up.
            s.peers[i] = PeerState {
                next_index: s.last_emitted_index.max(1),
                match_index: 0,
                inflight: 0,
                inflight_age: 0,
                active: true,
                voting: false,
                prev_log_index: 0,
                prev_log_term: 0,
            };
            dev_log(sys, 3, b"[repl] new peer".as_ptr(), 15);
        } else if !in_union && s.peers[i].active {
            // Removed peer: drop active flag so no further AEs
            // are sent to it. Match-index history is left in
            // place in case a re-add happens.
            s.peers[i].active = false;
            s.peers[i].voting = false;
            dev_log(sys, 3, b"[repl] drop peer".as_ptr(), 16);
        } else if in_union && s.peers[i].active && !s.peers[i].voting {
            // Peer is in current_voters (not just joint) → eligible
            // for promotion to voting status. The promotion itself
            // happens once match_index is close enough; until then
            // leave the flag false.
            let _ = i;
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
/// Promote a non-voting peer to voting once its match_index is
/// within `VOTING_LAG_THRESHOLD` of the leader's last-emitted tip.
/// Called from the AE-success branch in `process_acks`.
unsafe fn maybe_promote(s: &mut Repl, sys: &SyscallTable, peer: u8) {
    let i = peer as usize;
    if i >= MAX_NODES {
        return;
    }
    if !s.peers[i].active || s.peers[i].voting {
        return;
    }
    if s.last_emitted_index == 0 {
        return;
    }
    let lag = s.last_emitted_index.saturating_sub(s.peers[i].match_index);
    if lag <= VOTING_LAG_THRESHOLD {
        // Promote only when the peer is also in current_voters (not
        // just joint). During joint-consensus, the joint set may
        // include not-yet-current voters; we wait for the C_new
        // commit to install them into `current_voters` before flipping
        // their voting flag.
        if (s.current_voters & (1u8 << peer)) != 0 {
            s.peers[i].voting = true;
            dev_log(sys, 3, b"[repl] promoted".as_ptr(), 15);
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn request_snapshot_install(s: &Repl, sys: &SyscallTable, target: u8) {
    if s.out_snapshot_request < 0 { return; }
    let poll = (sys.channel_poll)(s.out_snapshot_request, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let buf = [target; 1];
    wire_channels::channel_write_msg(
        sys, s.out_snapshot_request, wire::MSG_SNAPSHOT_INSTALL_REQUEST, &buf,
    );
}

/// Deliver one MSG_WAL_ENTRY_REPLY from the shared `entry_reply`
/// fan-in (dispatch-table demux, bit-31-CLEAR request-id half — was
/// the dedicated `wal_reply` input, drained ≤8/step) and turn it into
/// a targeted catch-up AE.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn on_wal_reply(s: &mut Repl, sys: &SyscallTable, msg: &[u8], plen: u16) {
    // Stage the frame in this component's scratch (the demux buffer is
    // shared), mirroring the truncating channel-read contract.
    let pl = (plen as usize).min(s.msg_buf.len()).min(msg.len());
    s.msg_buf[..pl].copy_from_slice(&msg[..pl]);
    let (request_id, term, index, prev_term, body_off) =
        match wire::decode_wal_entry_reply(&s.msg_buf[..pl]) {
            Some(v) => v,
            None => return,
        };

    // Match against pending slots; if not found, drop silently —
    // we may have already retried with a fresher request_id.
    let mut slot_idx: Option<usize> = None;
    for (i, slot) in s.pending.iter().enumerate() {
        if slot.request_id == request_id && slot.peer != 0xFF {
            slot_idx = Some(i);
            break;
        }
    }
    let slot_idx = match slot_idx { Some(i) => i, None => return };
    let peer = s.pending[slot_idx].peer;
    s.pending[slot_idx] = PendingWalReq::zero();
    if peer == PROBE_PEER {
        // Tip probe answered. NOT_FOUND echoes the requested index
        // with term=0 and NO body, so it must never advance the
        // tip. Only a FOUND reply (term != 0, body present) does.
        if term != 0 && body_off < pl && index > s.last_emitted_index {
            s.last_emitted_index = index;
        }
        return;
    }
    if peer as usize >= MAX_NODES || !s.peers[peer as usize].active { return; }

    // Empty body means the WAL doesn't have the index any more —
    // snapshot install is the recovery path. Issue a targeted
    // install request to the snapshot side; see RFC §4.2.
    if pl <= body_off {
        request_snapshot_install(s, sys, peer);
        return;
    }

    // Build a catch-up AE: send entry `index` with prev_log = (index-1,
    // prev_term). prev_term comes from the WAL reply (the true term of
    // index-1), so the follower's log-match succeeds instead of seeing a
    // spurious term conflict and truncating. `term` (of `index`) is the
    // entry's own term, used as the AE's entry_term.
    let prev_idx = index.saturating_sub(1);
    let body = &s.msg_buf[body_off..pl];

    let peer_state = &s.peers[peer as usize];
    let leader_commit = peer_state.match_index; // conservative — follower clamps anyway
    let _ = leader_commit;

    // The AE's `term` is the LEADER's current term (so a higher-term
    // follower accepts the leader's authority), NOT the read-back entry's
    // term — those differ exactly in the cross-term failover catch-up
    // case. `entry_term` is the entry's own term (`term`).
    let ae_term = if s.last_emitted_term >= term { s.last_emitted_term } else { term };
    let mut ae_buf = [0u8; 4096];
    let total = wire::encode_append_entries(
        &mut ae_buf,
        ae_term,
        s.self_id,
        prev_idx,
        prev_term,
        // leader_commit: use our last-emitted index (clamped on follower).
        s.last_emitted_index,
        term,
        index,
        body,
    );
    if total == 0 { return; }

    let poll_out = (sys.channel_poll)(s.out_net, 0x02);
    if poll_out <= 0 || (poll_out as u32 & 0x02) == 0 { return; }
    let w = wire_channels::channel_write_routed_partitioned(
        sys,
        s.out_net,
        peer,
        s.partition_id,
        wire::MSG_APPEND_ENTRIES,
        &ae_buf[..total],
    );
    if w > 0 {
        s.catchup_sent = s.catchup_sent.saturating_add(1);
        s.rpcs_sent = s.rpcs_sent.saturating_add(1);
        s.peers[peer as usize].inflight =
            s.peers[peer as usize].inflight.saturating_add(1);
        s.peers[peer as usize].inflight_age = 0;
        let peer_state = &mut s.peers[peer as usize];
        peer_state.prev_log_index = prev_idx;
        peer_state.prev_log_term = prev_term;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn forward_snapshots(s: &mut Repl, sys: &SyscallTable) {
    if s.in_snapshot_rx < 0 { return; }

    for _ in 0..4 {
        let poll = (sys.channel_poll)(s.in_snapshot_rx, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_snapshot_rx, &mut s.msg_buf);
        if plen == 0 { continue; }

        let pass_through = matches!(
            msg_type,
            wire::MSG_SNAPSHOT_CHUNK | wire::MSG_INSTALL_SNAPSHOT
        );
        if !pass_through { continue; }

        // Forward to peers. Broadcast for now — a lagging-follower
        // detector that targets a specific peer is a future
        // improvement (RFC §5.13).
        let target = wire::TARGET_BROADCAST;
        let poll_out = (sys.channel_poll)(s.out_net, 0x02);
        if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
            wire_channels::channel_write_routed_partitioned(
                sys, s.out_net, target, s.partition_id,
                msg_type, &s.msg_buf[..plen as usize],
            );
        }
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Repl` (or shared
/// `&Repl` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn emit_metrics(s: &mut Repl, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    // Typed metric samples (RFC §4.3) so the telemetry export table
    // carries replicator counters. The MSG_METRICS envelope is
    // still emitted below for observers that parse it.
    let mid = wire::SOURCE_ID_REPLICATOR;
    let pid = s.partition_id;
    let kc = wire::METRIC_KIND_COUNTER;
    let kg = wire::METRIC_KIND_GAUGE;
    // §4.2 saturation gauge: AppendEntries dispatched but not yet
    // acked/nacked — the in-flight replication depth. Each response retires
    // exactly one RPC and increments exactly one of acks/nacks/backpressure,
    // so subtracting all three keeps the gauge exact.
    let inflight = s.rpcs_sent
        .saturating_sub(s.acks_received)
        .saturating_sub(s.nacks_received)
        .saturating_sub(s.backpressure_responses);
    let samples: [(u16, u8, i64); 6] = [
        (wire::metric_ids::REPL_RPCS_SENT, kc, i64::from(s.rpcs_sent)),
        (wire::metric_ids::REPL_ACKS_RECEIVED, kc, i64::from(s.acks_received)),
        (wire::metric_ids::REPL_NACKS_RECEIVED, kc, i64::from(s.nacks_received)),
        (wire::metric_ids::REPL_CATCHUP_SENT, kc, i64::from(s.catchup_sent)),
        (wire::metric_ids::REPL_INFLIGHT_DEPTH, kg, i64::from(inflight)),
        (wire::metric_ids::REPL_BACKPRESSURE, kc, i64::from(s.backpressure_responses)),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut sbuf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut sbuf, mid, pid, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &sbuf);
    }

    // rpcs_sent(4) + acks_received(4) + nacks(4) + catchup(4) = 16 bytes
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&s.rpcs_sent.to_le_bytes());
    buf[4..8].copy_from_slice(&s.acks_received.to_le_bytes());
    buf[8..12].copy_from_slice(&s.nacks_received.to_le_bytes());
    buf[12..16].copy_from_slice(&s.catchup_sent.to_le_bytes());

    let poll = (sys.channel_poll)(s.out_metrics, 0x02);
    if poll > 0 && (poll as u32 & 0x02) != 0 {
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRICS, &buf[..16]);
    }
}
