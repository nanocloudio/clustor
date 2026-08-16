//! commit — computes the quorum commit index from match indices and
//! durability proofs.
//!
//! Receives coalesced match-index updates from the replicator via
//! [`on_match`] (E2), durability proofs from durability's ledger, CP
//! cache state from admission, and voter-set updates from raft via
//! [`on_voter_set`] (E10). When the commit index advances it raises two
//! monotone horizon latches — one for apply, one for raft — which the
//! dispatch table drains every step (E3/E4): always deliverable, so no
//! per-consumer retry state is needed.
//!
//! Per-step bound (Discipline §5): ≤32 durability proofs, ≤8 CP-state
//! frames, one quorum recompute.

use super::abi::SyscallTable;
use super::seam::HorizonLatch;
use super::types::*;
use super::{dev_millis, dev_report_step_effect, step_effect, wire, wire_channels};

const METRICS_INTERVAL_MS: u64 = 1000;

#[repr(C)]
pub struct Commit {
    // Channels
    pub in_durable: i32,     // in: DurabilityProof from durability's ledger
    pub out_metrics: i32,    // out: MSG_METRIC_SAMPLE (shared module port)
    pub out_retention_floor: i32, // out: MSG_COMPACTION_FLOOR to durability's retention_floor

    // ── Seams ───────────────────────────────────────────────
    /// E3: commit horizon → apply.
    pub horizon_out: HorizonLatch,
    /// E4: commit horizon → raft. Dedicated so apply-side
    /// backpressure can never stall raft's commit feedback.
    pub raft_commit_out: HorizonLatch,
    /// Set by [`on_match`] / [`on_voter_set`]; consumed at the top of
    /// [`step`] as the "anything changed" trigger.
    pub match_changed: bool,

    // Configuration
    pub voter_count: u8,
    pub durability_mode: u8,  // DUR_STRICT / DUR_GROUP_FSYNC / DUR_RELAXED
    pub self_id: ReplicaId,
    pub partition_id: u16,

    // Metrics
    commit_advances: u32,
    last_metrics_ms: u64,

    /// Current and joint voter NodeSet bitmasks (RFC §1.2). Until
    /// raft pushes the first voter-set update, the
    /// commit tracker falls back to `voter_count` for the median —
    /// preserving the existing single-config behaviour.
    current_voters: NodeSet,
    joint_voters: NodeSet,
    joint_active: bool,

    // Per-replica match index tracking
    match_indices: [Index; MAX_NODES],

    /// Last min-match retention floor emitted (see `emit_retention_floor`).
    last_floor_emitted: Index,

    // Durability state
    durable_index: Index,

    // Commit state
    committed_index: Index,
    committed_term: Term,

    /// §5.4.2 current-term fence from raft (E12): (leader term, first
    /// index of that term — the election no-op). While set, the quorum
    /// tally may not advance the commit index below the fence: prior-term
    /// entries commit only transitively, once the fence entry itself has
    /// quorum. Index 0 = no fence (follower, or before this node's first
    /// election).
    term_fence_index: Index,
    /// Term the fence belongs to. Fences are monotone in term; a lower
    /// one is a stale delivery and is ignored.
    term_fence_term: Term,

    // CP state
    cp_cache_state: u8,
    strict_fallback: bool,

    // Scratch
    msg_buf: [u8; 32],
}

/// Initialise every field to its pre-param default. Channel handles
/// and params are assigned by `mod.rs` afterwards; `arm` runs the
/// post-param boot logic.
pub fn init(s: &mut Commit) {
    s.in_durable = -1;
    s.out_metrics = -1;
    s.out_retention_floor = -1;
    s.horizon_out = HorizonLatch::new();
    s.raft_commit_out = HorizonLatch::new();
    s.match_changed = false;
    s.voter_count = 1;
    s.durability_mode = DUR_GROUP_FSYNC;
    s.self_id = 0;
    s.partition_id = 0;
    s.commit_advances = 0;
    s.last_metrics_ms = 0;
    s.current_voters = NodeSet::empty();
    s.joint_voters = NodeSet::empty();
    s.joint_active = false;
    s.match_indices = [0; MAX_NODES];
    s.last_floor_emitted = 0;
    s.durable_index = 0;
    s.committed_index = 0;
    s.committed_term = 0;
    s.term_fence_index = 0;
    s.term_fence_term = 0;
    s.cp_cache_state = 0;
    s.strict_fallback = false;
    s.msg_buf = [0u8; 32];
}

/// Post-param boot logic: voter-count clamp + init log. Called by
/// `mod.rs` after channel handles and params are in place.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn arm(s: &mut Commit, sys: &SyscallTable) {
    // `voter_count` is operator-supplied; clamp here so the
    // downstream `quorum_index` slice access can never panic on
    // a typo'd cluster config. `NodeSet`-side mutators have a
    // matching guard for completeness.
    if (s.voter_count as usize) > MAX_NODES {
        s.voter_count = MAX_NODES as u8;
    }

    super::dev_log(sys, 3, b"[commit] init".as_ptr(), 13);
}

/// Deliver one coalesced match-index update from the replicator (E2;
/// per-replica monotone max + changed flag).
pub fn on_match(s: &mut Commit, replica: u8, index: Index) {
    if (replica as usize) < MAX_NODES && index > s.match_indices[replica as usize] {
        s.match_indices[replica as usize] = index;
        s.match_changed = true;
    }
}

/// Deliver the (term, first-index-of-term) fence from a freshly-elected
/// leader (seam E12), and reset the per-replica match tallies with it.
/// Match indices are monotone only within a leadership: across a term
/// change a stale one can name a log position conflict repair has since
/// rewritten. Peers re-report under the new term within a round-trip —
/// the fence entry's own AE forces it.
/// Arrives twice per leadership: `index == 0` when raft takes office
/// (the fence is ARMED but its index is not yet known — no commit may
/// advance by counting until it is, or the window between election and
/// the no-op landing would commit prior-term entries under either a
/// zero fence or this node's previous reign's), then again with the
/// real index once the no-op is in the WAL.
pub fn on_term_fence(s: &mut Commit, term: Term, index: Index) {
    if term < s.term_fence_term { return; }
    if term > s.term_fence_term {
        // New leadership. Match indices are monotone only WITHIN a
        // leadership: across a term change a stale one can name a log
        // position conflict repair has since rewritten. Peers re-report
        // within a round-trip; this node's own slot is local truth, so
        // re-seed it from `durable_index` rather than zeroing it
        // (`drain_durability` only refreshes the slot on a proof
        // STRICTLY above `durable_index`, which a quiescent leader may
        // not see for some time). Only on a term CHANGE — the armed and
        // resolved fences of one term must not reset it twice and drop
        // peer tallies already gathered under it.
        s.match_indices = [0; MAX_NODES];
        if (s.self_id as usize) < MAX_NODES {
            s.match_indices[s.self_id as usize] = s.durable_index;
        }
        s.term_fence_term = term;
    }
    // `Index::MAX` blocks every counting-based advance while armed.
    s.term_fence_index = if index == 0 { Index::MAX } else { index };
    s.match_changed = true;
}

/// Deliver a voter-set update from raft (seam E10). Anything that changes the active quorum forces
/// a commit-advance recheck.
pub fn on_voter_set(s: &mut Commit, current: u8, joint: u8, joint_active: bool) {
    s.current_voters = NodeSet(current);
    s.joint_voters = NodeSet(joint);
    s.joint_active = joint_active;
    s.voter_count = s.current_voters.count();
    s.match_changed = true;
}

/// One commit step.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Commit` and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel routines
/// per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
pub unsafe fn step(s: &mut Commit, sys: &SyscallTable) {
    let mut changed = false;

    // 1. Match-index updates (and voter-set changes) were delivered by
    //    the dispatch table via on_match / on_voter_set before this
    //    step; the coalesced flag is the change trigger.
    if s.match_changed {
        s.match_changed = false;
        changed = true;
    }

    // 2. Drain durability proofs
    changed |= drain_durability(s, sys);

    // 3. CP cache state is delivered by the dispatch table's cp_state
    //    demux via `on_cache_state` before this step runs.

    // 4. Recompute commit index if anything changed
    if changed {
        advance_commit(s);
        dev_report_step_effect(sys, step_effect::WORK_DONE);
    } else {
        // Re-raise the commit horizon even on quiet steps — the latches
        // are drained by the dispatch table the same step, so delivery
        // can never be lost (no drop-under-backpressure retry needed).
        emit_committed(s);
    }

    // 5. Periodic metrics
    emit_metrics(s, sys);

    // 6. Retention floor for snapshot/compaction gating.
    emit_retention_floor(s, sys);
}

/// Publish min(match_indices over the active voter set) as a
/// MSG_COMPACTION_FLOOR so the snapshot side defers snapshot triggers —
/// and therefore WAL compaction — past what the slowest LIVE voter has
/// replicated. Without this floor a leader-local snapshot can compact
/// entries a lagging follower still needs, and with manifest-only
/// snapshots (no state body) that follower can never catch up: it
/// NACK-refetches a compacted index forever and its permanent lag signal
/// makes the flow controller strangle proposal credits. A DEAD follower
/// therefore pins the floor — the safe default until state-body snapshots
/// make install-based catch-up lossless; operators drop dead voters via
/// membership change.
///
/// Emitted only on change; dropped under backpressure (the next change
/// or step re-emits — the gate degrades toward NOT compacting, which is
/// always safe). Wire shape (10 bytes, shared with lattice):
/// `[kpg_id:u16 LE][floor_revision:u64 LE]`.
unsafe fn emit_retention_floor(s: &mut Commit, sys: &SyscallTable) {
    if s.out_retention_floor < 0 { return; }
    let mut floor = Index::MAX;
    let mut any = false;
    for id in 0..MAX_NODES as u8 {
        let in_set = if s.current_voters.count() > 0 {
            s.current_voters.contains(id)
                || (s.joint_active && s.joint_voters.contains(id))
        } else {
            // Pre-voter-set fallback: ids 0..voter_count (mirrors the
            // quorum computation's fallback).
            id < s.voter_count
        };
        if in_set {
            any = true;
            if s.match_indices[id as usize] < floor {
                floor = s.match_indices[id as usize];
            }
        }
    }
    if !any || floor == Index::MAX { return; }
    if floor == s.last_floor_emitted { return; }
    let poll = (sys.channel_poll)(s.out_retention_floor, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return; }
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&s.partition_id.to_le_bytes());
    buf[2..10].copy_from_slice(&floor.to_le_bytes());
    wire_channels::channel_write_msg(sys, s.out_retention_floor, wire::MSG_COMPACTION_FLOOR, &buf);
    s.last_floor_emitted = floor;
}

/// Emit commit-index gauge + commit-advance counter as typed samples
/// (RFC §4.3). Dropped under backpressure — telemetry never stalls the
/// consensus path.
///
/// # Safety
///
/// Caller must supply a valid `&SyscallTable` per the module ABI.
unsafe fn emit_metrics(s: &mut Commit, sys: &SyscallTable) {
    if s.out_metrics < 0 { return; }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.last_metrics_ms) < METRICS_INTERVAL_MS { return; }
    s.last_metrics_ms = now;

    let mid = wire::SOURCE_ID_COMMIT;
    let pid = s.partition_id;
    let samples: [(u16, u8, i64); 2] = [
        (wire::metric_ids::COMMIT_INDEX, wire::METRIC_KIND_GAUGE, s.committed_index as i64),
        (wire::metric_ids::COMMIT_ADVANCES, wire::METRIC_KIND_COUNTER, i64::from(s.commit_advances)),
    ];
    for &(metric_id, kind, value) in samples.iter() {
        let poll = (sys.channel_poll)(s.out_metrics, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 { break; }
        let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
        wire::encode_metric_sample(&mut buf, mid, pid, metric_id, kind, value);
        wire_channels::channel_write_msg(sys, s.out_metrics, wire::MSG_METRIC_SAMPLE, &buf);
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Commit` (or shared
/// `&Commit` where the signature uses one) and supply a valid
/// `&SyscallTable` whose function pointers reach live kernel
/// routines per the module ABI in `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn drain_durability(s: &mut Commit, sys: &SyscallTable) -> bool {
    if s.in_durable < 0 { return false; }
    let mut changed = false;
    // Cap 32 per step (matches the durability ledger's ack-drain bound).
    for _ in 0..32 {
        let poll = (sys.channel_poll)(s.in_durable, 0x01);
        if poll <= 0 || (poll as u32 & 0x01) == 0 { break; }

        let (msg_type, plen) = wire_channels::channel_read_msg(sys, s.in_durable, &mut s.msg_buf);
        if msg_type != wire::MSG_DURABILITY_PROOF || (plen as usize) < wire::DURABILITY_PROOF_LEN {
            continue;
        }

        // partition_id is part of the proof envelope but the commit
        // tracker is per-partition; we just discard it (the proof always
        // matches our slot because each durability ledger only fans
        // out to one commit tracker).
        let (_partition_id, term, index, _replica) = wire::decode_durability_proof(&s.msg_buf);
        if index > s.durable_index {
            s.durable_index = index;
            s.committed_term = term;
            changed = true;

            // Self-match: the local durable index counts as this node's
            // match index for quorum computation. Essential for single-node
            // clusters and for the leader's own vote in multi-node quorum.
            if (s.self_id as usize) < MAX_NODES && index > s.match_indices[s.self_id as usize] {
                s.match_indices[s.self_id as usize] = index;
            }
        }
    }
    changed
}

/// Deliver one MSG_CACHE_STATE frame from the shared `cp_state`
/// fan-in (dispatch-table demux, capped 8/step there — the ledger-
/// precedent bound).
pub fn on_cache_state(s: &mut Commit, msg: &[u8], plen: u16) {
    if plen >= 1 {
        s.cp_cache_state = wire::decode_cache_state(msg);
        s.strict_fallback = s.cp_cache_state >= CP_STALE;
    }
}

/// # Safety
///
/// Caller must hold an exclusive `&mut Commit` per the module ABI in
/// `target/fluxor/fluxor-abi/sdk/abi.rs`.
unsafe fn advance_commit(s: &mut Commit) {
    // Compute quorum match index. If a voter-set update has populated
    // `current_voters` we use the joint-aware path (RFC §1.2); during
    // joint mode the effective commit index is the minimum of the two
    // medians so an entry must be replicated to a majority of BOTH
    // sets before it counts as committed. Otherwise we fall back to
    // the legacy fixed-range `voter_count` median.
    let quorum_match = if s.current_voters.count() > 0 {
        let current_median = quorum_index_for_set(&s.match_indices, s.current_voters);
        if s.joint_active && s.joint_voters.count() > 0 {
            let joint_median = quorum_index_for_set(&s.match_indices, s.joint_voters);
            if current_median < joint_median {
                current_median
            } else {
                joint_median
            }
        } else {
            current_median
        }
    } else {
        quorum_index(&s.match_indices, s.voter_count)
    };

    // Apply durability mode
    let effective_mode = if s.strict_fallback { DUR_STRICT } else { s.durability_mode };

    let new_commit = match effective_mode {
        DUR_STRICT | DUR_GROUP_FSYNC => {
            // Commit only up to what's durably synced
            if quorum_match < s.durable_index { quorum_match } else { s.durable_index }
        }
        DUR_RELAXED => quorum_match,
        _ => quorum_match,
    };

    // §5.4.2 current-term gate: while the quorum sits below the current
    // term's first entry, the commit index may not advance by counting.
    // A prior-term entry with quorum can still be legally overwritten by
    // a higher-term leader (Raft Fig. 8); it commits transitively, when
    // the fence entry itself commits.
    if s.term_fence_index > 0
        && new_commit > s.committed_index
        && new_commit < s.term_fence_index
    {
        emit_committed(s);
        return;
    }

    if new_commit > s.committed_index {
        // Count committed ENTRIES, not advance events: a single advance can
        // jump the commit index by many entries (group fsync), and throughput
        // benchmarks read this as entries committed.
        let advanced = (new_commit - s.committed_index).min(u32::MAX as Index) as u32;
        s.committed_index = new_commit;
        s.commit_advances = s.commit_advances.saturating_add(advanced);
    }
    // Delivery rides the horizon latches (E3/E4), drained by the dispatch
    // table every step — always deliverable, duplicates harmless.
    emit_committed(s);
}

/// Raise the current commit horizon on both latches (E3 apply-side,
/// E4 raft-side). The latches are monotone latest-wins and the
/// dispatch table drains them the same step, so delivery can never
/// fail and no per-consumer retry state is needed. The horizon is the absolute
/// committed high-water, so duplicate raises are harmless.
unsafe fn emit_committed(s: &mut Commit) {
    // raft-side horizon — delivered independently of apply, so commit
    // advances even while apply is busy with a group-commit burst.
    s.raft_commit_out.raise(s.committed_term, s.committed_index);
    // apply-side horizon.
    s.horizon_out.raise(s.committed_term, s.committed_index);
}
