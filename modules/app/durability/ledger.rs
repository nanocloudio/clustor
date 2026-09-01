//! ledger — per-replica fsynced indices and quorum durability proofs.
//!
//! Receives FsyncAck evidence from two sources:
//!   - the local [`wal`](super::wal) component's durability point,
//!     delivered in-module every step it advances;
//!   - `consensus.cross_durability_ack` on the leader (the `ack`
//!     port), which synthesizes per-peer FsyncAcks from the
//!     `durable_index` field each follower stamps into its
//!     AppendEntriesResponse envelope.
//!
//! Maintains a per-replica `progress[]` array and emits
//! `MSG_DURABILITY_PROOF` whenever the quorum-durable index advances
//! `wal_committed_index`. Followers see only their own
//! slot advance and therefore never emit a proof — the proof is a
//! leader-side artifact that gates `consensus.committed_entries`.
//!
//! This component is the entire quorum-durability surface: the
//! `volatile` variant compiles it out, so a volatile composition is
//! structurally incapable of emitting a durability proof.

use super::abi::SyscallTable;
use super::types::{
    quorum_index, quorum_index_for_set, Index, NodeSet, ReplicaId, Term, MAX_NODES,
};
use super::{dev_log, wire, wire_channels};

#[repr(C)]
pub struct Ledger {
    /// Per-slot inbox for cross-node fsync acks, filled by the
    /// module's intake demux.
    pub inbox_ack: super::inbox::Inbox,
    pub in_ack: i32,     // in: FsyncAck from replicator (cross-node)
    pub out_quorum: i32, // out: 19-byte DurabilityProof

    // Configuration
    pub self_id: ReplicaId,
    pub voter_count: u8,
    pub partition_id: u16,

    /// Voter sets for the durability tally, mirrored from raft's
    /// voter-set latch via `MSG_VOTER_SET_UPDATE` on the entry stream.
    ///
    /// The ledger must run the SAME union quorum `commit` runs. During
    /// joint consensus an entry is durable only when a majority of BOTH
    /// `C_old` and `C_new` have fsynced it: `commit` takes
    /// `min(quorum_match, durable_index)`, so a durable_index computed
    /// over `C_old` alone would let an entry commit that survives only
    /// on the old configuration — exactly the committed-entry loss a
    /// membership change must not permit.
    ///
    /// Empty until the first update lands, which is why the tally falls
    /// back to the `voter_count` median: a graph that never changes
    /// membership behaves exactly as before.
    current_voters: NodeSet,
    joint_voters: NodeSet,
    joint_active: bool,

    // Per-replica durable index tracking
    progress: [Index; MAX_NODES],
    /// Term each replica's ack carried when its `progress` slot last
    /// advanced — the term of that replica's durable tip. Pairs the
    /// proof's term with its index; an ack's term alone can be ahead of
    /// the quorum index.
    term_at: [Term; MAX_NODES],

    // Quorum state
    committed_index: Index,
    committed_term: Term,
    /// A quorum advance whose DurabilityProof has not yet been
    /// delivered (`out_quorum` full at emit time). Retried every step:
    /// heartbeat acks at an unchanged index never re-fire the
    /// `new_quorum > committed_index` edge, so without this latch one
    /// dropped proof stalls commit until the next write arrives.
    proof_pending: bool,

    // Scratch
    msg_buf: [u8; 32],
}

pub unsafe fn init(l: &mut Ledger) {
    l.inbox_ack = super::inbox::Inbox::new();
    l.in_ack = -1;
    l.out_quorum = -1;
    l.self_id = 0;
    l.voter_count = 1;
    l.partition_id = 0;
    l.current_voters = NodeSet::empty();
    l.joint_voters = NodeSet::empty();
    l.joint_active = false;
    l.progress = [0; MAX_NODES];
    l.term_at = [0; MAX_NODES];
    l.committed_index = 0;
    l.committed_term = 0;
    l.proof_pending = false;
}

/// Clamp `voter_count` after params land so the downstream
/// `quorum_index` slice access can never panic on a typo'd cluster
/// config.
pub fn clamp_voters(l: &mut Ledger) {
    if (l.voter_count as usize) > MAX_NODES {
        l.voter_count = MAX_NODES as u8;
    }
}

/// Adopt a new voter configuration for the durability tally. Mirrors
/// `consensus::commit::on_voter_set`; the two must stay in step or the
/// union-quorum guarantee is only half-enforced.
pub fn on_voter_set(l: &mut Ledger, current: u8, joint: u8, joint_active: bool) {
    l.current_voters = NodeSet(current);
    l.joint_voters = NodeSet(joint);
    l.joint_active = joint_active;
    let n = l.current_voters.count();
    if n > 0 {
        l.voter_count = n;
    }
}

/// The durable high-water across the effective configuration.
///
/// Single config: the median over `current_voters`. Joint consensus:
/// the MINIMUM of the two medians, so an index counts as durable only
/// once a majority of each configuration has fsynced it.
fn durable_quorum(l: &Ledger) -> Index {
    if l.current_voters.count() == 0 {
        // No voter-set update yet — median over the fixed `0..voter_count`
        // range.
        return quorum_index(&l.progress, l.voter_count);
    }
    let current = quorum_index_for_set(&l.progress, l.current_voters);
    if l.joint_active && l.joint_voters.count() > 0 {
        let joint = quorum_index_for_set(&l.progress, l.joint_voters);
        if current < joint {
            current
        } else {
            joint
        }
    } else {
        current
    }
}

/// Record one fsync acknowledgement. `replica` slots beyond
/// `MAX_NODES` are dropped; per-replica indices only advance.
pub fn on_ack(l: &mut Ledger, term: Term, index: Index, replica: ReplicaId) -> bool {
    if replica as usize >= MAX_NODES {
        return false;
    }
    let mut advanced = false;
    if index > l.progress[replica as usize] {
        l.progress[replica as usize] = index;
        l.term_at[replica as usize] = term;
        advanced = true;
    }
    advanced
}

/// Per-step bound: ≤32 cross-node acks drained + at most one quorum
/// recompute and proof emit.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Ledger` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(l: &mut Ledger, sys: &SyscallTable, local_advanced: bool) {
    let mut advanced = local_advanced;

    // Drain cross-node acks
    if l.in_ack >= 0 {
        for _ in 0..32 {
            // Pre-routed into this slot's inbox by the module's intake
            // demux, so every ack here is this group's.
            let Some((msg_type, plen)) = l.inbox_ack.next(sys, &mut l.msg_buf) else {
                break;
            };
            if msg_type != wire::MSG_FSYNC_ACK {
                continue;
            }

            // Slice to the declared payload: `msg_buf` is reused
            // across messages, so a short frame must not read the
            // previous one's tail.
            let Some((term, index, replica)) = wire::decode_fsync_ack(&l.msg_buf[..plen as usize])
            else {
                continue;
            };
            if on_ack(l, term, index, replica) {
                advanced = true;
            }
        }
    }

    // If any progress changed, recompute quorum
    if advanced {
        let new_quorum = durable_quorum(l);

        if new_quorum > l.committed_index {
            l.committed_index = new_quorum;

            // Pair the proof's term with its index. Every supporter's
            // durable tip is at or past `new_quorum`, so its term bounds
            // the entry's term from above; the minimum is the tightest
            // such bound, and is exact whenever some supporter's tip IS
            // the quorum index. Monotone, and never moves without an
            // index basis.
            let mut t = Term::MAX;
            for i in 0..MAX_NODES {
                if l.progress[i] >= new_quorum && l.term_at[i] < t {
                    t = l.term_at[i];
                }
            }
            if t != Term::MAX && t > l.committed_term {
                l.committed_term = t;
            }
            l.proof_pending = true;
        }
    }

    // Emit DurabilityProof (19 bytes; partition_id at front). The latch
    // stays set until a write is confirmed, so a full channel defers —
    // never drops — the proof.
    if l.proof_pending {
        if l.out_quorum < 0 {
            l.proof_pending = false; // no consumer wired
        } else {
            if wire_channels::writable(sys, l.out_quorum) {
                let mut proof = [0u8; wire::DURABILITY_PROOF_LEN];
                wire::encode_durability_proof(
                    &mut proof,
                    l.partition_id,
                    l.committed_term,
                    l.committed_index,
                    l.self_id,
                );
                // Bare envelope, deliberately: the proof's own payload
                // already carries `partition_id` (see
                // `encode_durability_proof` above), so consumers filter
                // on that. Wrapping it in the partitioned envelope too
                // would duplicate the field AND break `quantum`'s
                // `flow` module, which reads this same channel.
                let w = wire_channels::channel_write_msg(
                    sys,
                    l.out_quorum,
                    wire::MSG_DURABILITY_PROOF,
                    &proof,
                );
                if w > 0 {
                    l.proof_pending = false;
                    // Debug level: fires per quorum event — hot path.
                    dev_log(sys, 4, b"[dur] quorum".as_ptr(), 12);
                }
            }
        }
    }
}
