//! Per-component step-time accounting for composite modules
//! (standards `fluxor-modules.md` §8 rule 8).
//!
//! The kernel's step histogram sees a composite as one scheduler
//! entity. The composite's dispatch table restores per-component
//! granularity: it brackets each `component::step` call with
//! `dev_micros` reads, records the elapsed time here, and publishes
//! each component's histogram on its metrics tick as cumulative
//! bucket samples (`metric_id = wire::hist::COMP_STEP_BASE + i`,
//! `module_id` = the component's source id). The bucket edges match
//! the kernel's per-module step histogram, so component and module
//! distributions compare directly.
//!
//! Consumers mount this file as a sibling of `wire.rs` /
//! `wire_channels.rs`:
//!
//! ```ignore
//! #[path = "../../common/step_accounting.rs"]
//! mod step_accounting;
//! ```

use super::abi::SyscallTable;
use super::wire;

/// Bucket count: one per `COMP_STEP_US` bound + the `+Inf` bucket.
pub const COMP_STEP_BUCKETS: usize = wire::hist::COMP_STEP_US.len() + 1;

/// One component's step-time histogram. Owned by the composition
/// layer (the dispatch table), never by the component it measures.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompStepHist {
    buckets: [u32; COMP_STEP_BUCKETS],
}

impl CompStepHist {
    pub const fn new() -> Self {
        Self { buckets: [0; COMP_STEP_BUCKETS] }
    }

    /// Classify one component step's elapsed time.
    #[inline]
    pub fn record(&mut self, elapsed_us: u64) {
        let b = wire::hist::bucket(&wire::hist::COMP_STEP_US, elapsed_us);
        self.buckets[b] = self.buckets[b].saturating_add(1);
    }

    /// Emit the histogram on `chan` as cumulative bucket samples
    /// (`wire::hist` contract: bucket i carries the count of samples
    /// `<= bound[i]`), tagged with the component's `source_id` and the
    /// module's `partition_id`.
    ///
    /// The whole bucket set goes out in ONE `channel_write`. Ring
    /// writes are atomic, so the snapshot lands whole or not at all; a
    /// partial emission would expose fresh low buckets beside stale
    /// high ones — a non-monotone cumulative set. Counts are
    /// cumulative, so a dropped snapshot re-publishes complete next
    /// tick.
    ///
    /// # Safety
    ///
    /// Caller must supply a valid `&SyscallTable` per the module ABI;
    /// `chan` must be a channel handle owned by the calling module
    /// (or negative for "unwired").
    pub unsafe fn emit(&self, sys: &SyscallTable, chan: i32, source_id: u8, partition_id: u16) {
        if chan < 0 {
            return;
        }
        // Early-out only: poll(OUT) means ">=1 byte free", not "the
        // snapshot fits" — the write below is the authority.
        let poll = (sys.channel_poll)(chan, 0x02);
        if poll <= 0 || (poll as u32 & 0x02) == 0 {
            return;
        }
        const FRAME_LEN: usize = wire::ENVELOPE_HDR + wire::METRIC_SAMPLE_LEN;
        const SNAPSHOT_LEN: usize = FRAME_LEN * COMP_STEP_BUCKETS;
        // The snapshot must fit the ring or it could never be delivered.
        const _: () = assert!(SNAPSHOT_LEN <= super::abi::CHANNEL_BUFFER_SIZE);
        let mut frames = [0u8; SNAPSHOT_LEN];
        let mut cum: i64 = 0;
        for i in 0..COMP_STEP_BUCKETS {
            cum += i64::from(self.buckets[i]);
            let at = i * FRAME_LEN;
            wire::encode_header(
                &mut frames[at..at + wire::ENVELOPE_HDR],
                wire::MSG_METRIC_SAMPLE,
                wire::METRIC_SAMPLE_LEN as u16,
            );
            let mut sample = [0u8; wire::METRIC_SAMPLE_LEN];
            wire::encode_metric_sample(
                &mut sample,
                source_id,
                partition_id,
                wire::hist::COMP_STEP_BASE + i as u16,
                wire::METRIC_KIND_HISTOGRAM,
                cum,
            );
            frames[at + wire::ENVELOPE_HDR..at + FRAME_LEN].copy_from_slice(&sample);
        }
        // Result unchecked: a full channel drops the whole snapshot,
        // which the next tick re-publishes complete.
        (sys.channel_write)(chan, frames.as_ptr(), frames.len());
    }

    /// Cumulative bucket values for message-shaped in-module delivery
    /// (the operations composite hands these straight to its
    /// telemetry component instead of crossing a channel).
    pub fn cumulative(&self) -> [i64; COMP_STEP_BUCKETS] {
        let mut out = [0i64; COMP_STEP_BUCKETS];
        let mut cum: i64 = 0;
        for i in 0..COMP_STEP_BUCKETS {
            cum += i64::from(self.buckets[i]);
            out[i] = cum;
        }
        out
    }
}
