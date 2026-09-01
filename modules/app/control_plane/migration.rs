//! Migration state machine.
//!
//! Every elastic operation (shard move, PRG activation, node add, node
//! drain, replica move) runs through one durable, idempotent,
//! recoverable state machine:
//!
//! ```text
//!   PLANNED -> PROVISIONING -> COPYING -> CATCHING_UP -> FENCED
//!           -> ACTIVE -> RETIRING -> DONE
//!                     \
//!                      -> ABORTED   (only before FENCED)
//! ```
//!
//! ## The rules this component enforces
//!
//! - **MIG-DURABLE** — the phase transition is emitted BEFORE the work
//!   of that phase begins. A controller crash resumes by reading the
//!   phase and re-running it, so the record is the source of truth
//!   rather than any in-memory progress.
//! - **MIG-IDEMPOTENT** — advancing is driven by an explicit
//!   `phase_complete` signal, and a repeated signal for a phase already
//!   left is ignored. Re-running a phase in full must be safe, so this
//!   component never treats "I already did half of that" as state.
//! - **MIG-ONEWAY** — `FENCED` is the point of no return. Before it,
//!   abort restores the old placement at the old epoch. After it the
//!   target has begun accepting at the new epoch, so restoring the old
//!   placement would give two groups the same shards; abort is refused
//!   and the operator must roll forward.
//! - **MIG-BOUNDED** — each phase carries a deadline. A timeout BEFORE
//!   the fence aborts; a timeout AFTER it alerts and retries, never
//!   reverts.
//! - **MIG-SERIAL** — one migration at a time per shard and per PRG.
//!   This component holds a single active migration, which is the
//!   strongest form of that rule and the one whose invariants are
//!   checkable.
//!
//! What lives elsewhere: the *work* of each phase (activating a slot,
//! installing a snapshot, streaming a WAL tail) belongs to the
//! substrate and the controller. This component owns only the phase
//! sequence and the safety rules over it — which is the part that must
//! never be wrong.

use super::abi::SyscallTable;
use super::{dev_log, wire, wire_channels};

/// Migration slots. One is the enforceable form of MIG-SERIAL; a
/// controller that wants concurrent migrations across disjoint PRGs
/// needs a per-PRG lock first, which is a control-plane design step,
/// not a bigger array here.
pub const MAX_ACTIVE: usize = 1;

/// How long to wait before re-proposing a phase record that has been
/// written but has not yet come back committed. Comfortably above a
/// healthy commit round trip, so the steady-state cost of MIG-DURABLE is
/// one record per phase; short enough that a proposal genuinely lost to
/// a leader change is re-sent long before `phase_timeout_ms` (30s)
/// would abort the migration under MIG-BOUNDED.
const RECORD_RETRY_MS: u64 = 500;

#[repr(C)]
pub struct Migration {
    /// Out: migration records to the durable log / operator surface.
    pub out_record: i32,

    /// Zero when no migration is active.
    migration_id: u64,
    phase: u8,
    source_prg: u16,
    target_prg: u16,
    epoch: u64,
    shard_count: u16,
    /// First shard of the batch this migration moves. The set is
    /// `[base_shard, base_shard + shard_count)` — named rather than
    /// implied, because "every shard of the source PRG" is 2^18 entries
    /// and no bounded override table can carry it.
    base_shard: u32,
    /// Wall-clock deadline for the CURRENT phase.
    deadline_ms: u64,
    /// Per-phase budget, applied on each transition.
    phase_timeout_ms: u64,

    /// Phase records written to the proposal channel.
    records_proposed: u32,
    /// Phase records seen COMMITTED. The gap between this and
    /// `records_proposed` is migrations waiting on durability.
    records_committed: u32,

    /// True while the current phase's record has not been emitted.
    /// MIG-DURABLE: the work of a phase may not begin until this
    /// clears, so a phase whose record could not be written is retried
    /// rather than silently entered.
    record_pending: bool,
    /// Wall clock of the last proposal write for the pending record, or
    /// 0 when none has been written since `record_pending` was raised.
    /// `record_pending` clears only on COMMIT, so without this the
    /// retry in `step` fires every tick and the log fills with dozens of
    /// byte-identical copies of one phase record while its first copy is
    /// still in flight. Retrying on an interval keeps the crash-recovery
    /// property (a proposal dropped by a leader change is still re-sent)
    /// at one copy per interval instead of one per tick.
    record_sent_ms: u64,

    // Metrics
    pub started: u32,
    pub completed: u32,
    pub aborted: u32,
    pub aborts_refused: u32,
    pub timeouts_pre_fence: u32,
    pub timeouts_post_fence: u32,
    pub illegal_transitions: u32,
    /// Migrations adopted from the log after a restart. Non-zero means
    /// this controller resumed work it did not start.
    pub resumed: u32,

    msg_buf: [u8; wire::MIGRATION_RECORD_LEN],
}

pub fn init(m: &mut Migration) {
    m.out_record = -1;
    m.migration_id = 0;
    m.phase = wire::MIG_DONE;
    m.source_prg = 0;
    m.target_prg = 0;
    m.epoch = 0;
    m.shard_count = 0;
    m.deadline_ms = 0;
    m.phase_timeout_ms = 30_000;
    m.record_pending = false;
    m.record_sent_ms = 0;
    m.records_proposed = 0;
    m.records_committed = 0;
    m.started = 0;
    m.completed = 0;
    m.aborted = 0;
    m.aborts_refused = 0;
    m.timeouts_pre_fence = 0;
    m.timeouts_post_fence = 0;
    m.illegal_transitions = 0;
    m.resumed = 0;
    m.msg_buf = [0u8; wire::MIGRATION_RECORD_LEN];
}

/// True when a migration is in flight (not terminal).
pub fn is_active(m: &Migration) -> bool {
    m.migration_id != 0 && !wire::mig_is_terminal(m.phase)
}

/// Current phase, for callers that gate on it.
/// First shard of the batch being moved; the set is
/// `[base_shard, base_shard + shard_count)`.
pub fn base_shard(m: &Migration) -> u32 {
    m.base_shard
}

/// How many shards the batch covers.
pub fn shard_count(m: &Migration) -> u16 {
    m.shard_count
}

pub fn phase(m: &Migration) -> u8 {
    m.phase
}

/// The migration's id, zero when none is held.
pub fn id(m: &Migration) -> u64 {
    m.migration_id
}

/// The PRG GAINING the shards — the group a target node must bring up
/// during PROVISIONING.
pub fn target_prg(m: &Migration) -> u16 {
    m.target_prg
}

/// True while the current phase's record has not committed. The phase's
/// work may not begin until this clears (MIG-DURABLE).
pub fn record_pending(m: &Migration) -> bool {
    m.record_pending
}

/// The PRG losing the shards — the one a fence must name while the
/// migration holds at `MIG_FENCED`.
pub fn source_prg(m: &Migration) -> u16 {
    m.source_prg
}

/// Begin a migration. Refused while one is already in flight
/// (MIG-SERIAL) — the caller retries once the current one terminates.
pub fn begin(
    m: &mut Migration,
    now: u64,
    migration_id: u64,
    source_prg: u16,
    target_prg: u16,
    epoch: u64,
    shard_count: u16,
    base_shard: u32,
) -> bool {
    if is_active(m) || migration_id == 0 {
        return false;
    }
    // The batch must fit the override table every node applies, or the
    // cutover would emit more overrides than some node can hold and the
    // nodes would disagree about who owns the tail.
    if shard_count as usize > wire::SHARD_MAP_MAX_ENTRIES {
        return false;
    }
    m.migration_id = migration_id;
    m.phase = wire::MIG_PLANNED;
    m.source_prg = source_prg;
    m.target_prg = target_prg;
    m.epoch = epoch;
    m.shard_count = shard_count;
    m.base_shard = base_shard;
    m.deadline_ms = now + m.phase_timeout_ms;
    m.record_pending = true;
    m.record_sent_ms = 0;
    m.started = m.started.wrapping_add(1);
    true
}

/// The controller reports that the current phase's work finished.
///
/// Advances one step. Ignored when the migration is not active, when
/// the phase named does not match the current one (a late signal for a
/// phase already left — MIG-IDEMPOTENT), or when the record for the
/// current phase has not been durably emitted yet (MIG-DURABLE).
pub fn phase_complete(m: &mut Migration, now: u64, phase_done: u8) -> bool {
    if !is_active(m) || m.record_pending || phase_done != m.phase {
        return false;
    }
    let Some(next) = wire::mig_next(m.phase) else {
        return false;
    };
    advance(m, now, next)
}

/// Abort the migration. Refused once fenced (MIG-ONEWAY): past that
/// point the target is accepting at the new epoch, and restoring the
/// old placement would let two groups own the same shards.
pub fn abort(m: &mut Migration, now: u64) -> bool {
    if !is_active(m) {
        return false;
    }
    if wire::mig_is_committed(m.phase) {
        m.aborts_refused = m.aborts_refused.wrapping_add(1);
        return false;
    }
    advance(m, now, wire::MIG_ABORTED)
}

/// Deadline check (MIG-BOUNDED). Before the fence a timeout aborts;
/// after it, a timeout is counted and the deadline re-armed — the
/// migration must roll forward, so a stalled post-fence phase is an
/// operator problem, never an automatic revert.
pub fn on_tick(m: &mut Migration, now: u64) {
    if !is_active(m) || now < m.deadline_ms {
        return;
    }
    if wire::mig_is_committed(m.phase) {
        m.timeouts_post_fence = m.timeouts_post_fence.wrapping_add(1);
        m.deadline_ms = now + m.phase_timeout_ms;
        return;
    }
    m.timeouts_pre_fence = m.timeouts_pre_fence.wrapping_add(1);
    advance(m, now, wire::MIG_ABORTED);
}

/// Apply a transition after checking it is legal.
fn advance(m: &mut Migration, now: u64, to: u8) -> bool {
    if !wire::mig_transition_ok(m.phase, to) {
        m.illegal_transitions = m.illegal_transitions.wrapping_add(1);
        return false;
    }
    m.phase = to;
    m.deadline_ms = now + m.phase_timeout_ms;
    // MIG-DURABLE: the record for the phase just entered must reach the
    // log before that phase's work begins.
    m.record_pending = true;
    m.record_sent_ms = 0;
    match to {
        wire::MIG_DONE => m.completed = m.completed.wrapping_add(1),
        wire::MIG_ABORTED => m.aborted = m.aborted.wrapping_add(1),
        _ => {}
    }
    true
}

/// Per-step bound: at most one record emit.
///
/// # Safety
///
/// Caller must hold an exclusive `&mut Migration` and supply a valid
/// `&SyscallTable` per the module ABI.
pub unsafe fn step(m: &mut Migration, sys: &SyscallTable, now: u64) {
    on_tick(m, now);

    if !m.record_pending || m.migration_id == 0 {
        return;
    }
    if m.out_record < 0 {
        // No durable sink wired: nothing can be recorded, so nothing may
        // proceed on the strength of a record. Leave `record_pending`
        // set — a graph without the sink simply cannot run migrations,
        // which is the honest behaviour.
        return;
    }
    if !wire_channels::writable(sys, m.out_record) {
        return; // retried next step
    }
    // Suppress the re-propose while the first copy is plausibly still in
    // flight. `record_pending` cannot clear until the record COMMITS, so
    // it stands across every tick of one commit round-trip; without this
    // gate each of those ticks writes another identical record.
    if m.record_sent_ms != 0 && now.wrapping_sub(m.record_sent_ms) < RECORD_RETRY_MS {
        return;
    }
    wire::encode_migration_record(
        &mut m.msg_buf,
        m.migration_id,
        m.phase,
        m.source_prg,
        m.target_prg,
        m.epoch,
        m.shard_count,
        m.deadline_ms,
            m.base_shard,
    );
    // The record goes through Raft as an ordinary opaque proposal,
    // magic-prefixed so the controller recognises its own record coming
    // back. `record_pending` is deliberately NOT cleared here: a channel
    // write means "accepted for proposal", and MIG-DURABLE needs
    // "committed". Clearing on the write would let the next phase's work
    // begin on the strength of a record a crash could still lose —
    // exactly the guarantee this rule exists to provide. `on_committed`
    // is the only thing that clears it.
    let mut body = [0u8; 2 + wire::MIGRATION_RECORD_LEN];
    body[..2].copy_from_slice(&wire::MIG_CMD_MAGIC);
    body[2..].copy_from_slice(&m.msg_buf);
    // KEYED to `wire::CP_RECORD_SHARD` so the phase record lands on
    // partition 0, the distinguished CP-Raft group. Untagged it would go
    // to whichever hosted group's `drain_proposals` read the shared
    // channel first — an arbitrary partition at K>1.
    let mut keyed = [0u8; wire::KEYED_PROPOSAL_HDR + 2 + wire::MIGRATION_RECORD_LEN];
    let n = wire::encode_keyed_proposal(&mut keyed, wire::CP_RECORD_SHARD, &body);
    if n <= 0 {
        return;
    }
    let w = wire_channels::channel_write_msg(
        sys,
        m.out_record,
        wire::MSG_CLIENT_PROPOSAL_KEYED,
        &keyed[..n as usize],
    );
    if w > 0 {
        // A zero `now` would read as "never sent" and defeat the gate.
        m.record_sent_ms = if now == 0 { 1 } else { now };
        m.records_proposed = m.records_proposed.wrapping_add(1);
        dev_log(sys, 3, b"[mig] phase".as_ptr(), 11);
    }
}

/// A committed entry arrived. When it is THIS controller's record for
/// the phase currently held, the phase is durable and its work may
/// begin (MIG-DURABLE).
///
/// Matching on `(migration_id, phase)` is enough to identify the
/// record: MIG-SERIAL means one migration at a time and phases never
/// repeat within one, so no correlation table is needed. A record from
/// an older migration, or for a phase already left, simply does not
/// match and is ignored — which is also what makes replay safe.
pub fn on_committed(m: &mut Migration, now: u64, body: &[u8]) {
    if !wire::is_migration_record(body) {
        return;
    }
    let Some((
        migration_id,
        phase,
        source_prg,
        target_prg,
        epoch,
        shard_count,
        _deadline,
        base_shard,
    )) =
        wire::decode_migration_record(&body[2..2 + wire::MIGRATION_RECORD_LEN])
    else {
        return;
    };

    if migration_id == m.migration_id {
        if m.record_pending && phase == m.phase {
            m.record_pending = false;
            m.record_sent_ms = 0;
            m.records_committed = m.records_committed.wrapping_add(1);
        } else if phase > m.phase {
            // Replay catching up. The phase constants are declared in
            // sequence order, so "later in the log" is "numerically
            // greater" — and a phase can only be AHEAD of the one held
            // during replay: in normal operation the controller never
            // advances past its last committed record, because
            // `phase_complete` refuses while `record_pending` stands.
            // Comparing rather than blindly adopting is what stops a
            // re-delivered older record from rewinding a live
            // migration.
            m.phase = phase;
            m.record_pending = false;
            m.record_sent_ms = 0;
            m.deadline_ms = now + m.phase_timeout_ms;
        }
        return;
    }

    // A record for a migration this controller does not hold. On WAL
    // replay after a restart that is the ONLY way an interrupted
    // migration comes back: the log is the source of truth
    // (MIG-DURABLE), so the phase it last recorded is the phase to
    // resume from. Records replay in log order, so a finished migration
    // is adopted and then walked to its own terminal phase, leaving
    // this controller correctly idle.
    //
    // Only adopt into a free slot. A live migration is never displaced
    // by a record from a different one (MIG-SERIAL).
    if is_active(m) {
        return;
    }
    m.migration_id = migration_id;
    m.phase = phase;
    m.source_prg = source_prg;
    m.target_prg = target_prg;
    m.epoch = epoch;
    m.shard_count = shard_count;
    // Adopted with the rest, and load-bearing: a node that learns this
    // migration from the LOG rather than from the command still has to
    // emit the cutover overrides, and it cannot name the batch without
    // this. Resuming without it would leave that node routing the moved
    // shards to their old owner while the others moved on.
    m.base_shard = base_shard;
    // The record IS the durability proof — it just came off the log —
    // so the resumed phase is not pending. Re-arm the deadline from NOW
    // rather than trusting the recorded one: that wall clock belongs to
    // the run that died, and a stale deadline would abort the migration
    // the instant it resumed (MIG-BOUNDED would fire on restart).
    m.record_pending = false;
    m.record_sent_ms = 0;
    m.deadline_ms = now + m.phase_timeout_ms;
    m.resumed = m.resumed.wrapping_add(1);
}
