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
//! (spec §10.4.1 `wal_committed_index`). Followers see only their own
//! slot advance and therefore never emit a proof — the proof is a
//! leader-side artifact that gates `consensus.committed_entries`.
//!
//! This component is the entire quorum-durability surface: the
//! `volatile` variant compiles it out, so a volatile composition is
//! structurally incapable of emitting a durability proof.

use super::abi::SyscallTable;
use super::types::{quorum_index, Index, ReplicaId, Term, MAX_NODES};
use super::{dev_log, wire, wire_channels};

#[repr(C)]
pub struct Ledger {
    pub in_ack: i32,     // in: FsyncAck from replicator (cross-node)
    pub out_quorum: i32, // out: 19-byte DurabilityProof

    // Configuration
    pub self_id: ReplicaId,
    pub voter_count: u8,
    pub partition_id: u16,

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
    l.in_ack = -1;
    l.out_quorum = -1;
    l.self_id = 0;
    l.voter_count = 1;
    l.partition_id = 0;
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
            let poll = (sys.channel_poll)(l.in_ack, 0x01);
            if poll <= 0 || (poll as u32 & 0x01) == 0 {
                break;
            }

            let (msg_type, plen) = wire_channels::channel_read_msg(sys, l.in_ack, &mut l.msg_buf);
            if msg_type != wire::MSG_FSYNC_ACK || plen < 17 {
                continue;
            }

            let (term, index, replica) = wire::decode_fsync_ack(&l.msg_buf);
            if on_ack(l, term, index, replica) {
                advanced = true;
            }
        }
    }

    // If any progress changed, recompute quorum
    if advanced {
        let new_quorum = quorum_index(&l.progress, l.voter_count);

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
            let poll_out = (sys.channel_poll)(l.out_quorum, 0x02);
            if poll_out > 0 && (poll_out as u32 & 0x02) != 0 {
                let mut proof = [0u8; wire::DURABILITY_PROOF_LEN];
                wire::encode_durability_proof(
                    &mut proof,
                    l.partition_id,
                    l.committed_term,
                    l.committed_index,
                    l.self_id,
                );
                let w = wire_channels::channel_write_msg(
                    sys, l.out_quorum, wire::MSG_DURABILITY_PROOF, &proof,
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
