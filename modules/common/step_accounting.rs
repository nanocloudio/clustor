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
use super::{wire, wire_channels};

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
    /// module's `partition_id`. A full or unwired channel drops the
    /// remainder — counts are cumulative, so the next tick
    /// re-publishes complete state.
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
        let mut cum: i64 = 0;
        for i in 0..COMP_STEP_BUCKETS {
            cum += i64::from(self.buckets[i]);
            let poll = (sys.channel_poll)(chan, 0x02);
            if poll <= 0 || (poll as u32 & 0x02) == 0 {
                return;
            }
            let mut buf = [0u8; wire::METRIC_SAMPLE_LEN];
            wire::encode_metric_sample(
                &mut buf,
                source_id,
                partition_id,
                wire::hist::COMP_STEP_BASE + i as u16,
                wire::METRIC_KIND_HISTOGRAM,
                cum,
            );
            wire_channels::channel_write_msg(sys, chan, wire::MSG_METRIC_SAMPLE, &buf);
        }
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
