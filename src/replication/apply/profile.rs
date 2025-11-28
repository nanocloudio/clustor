use crate::profile::{PartitionProfile, ProfileCapabilityError, ProfileCapabilityRegistry};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_P99_WINDOW: usize = 10_000;

#[derive(Debug, Clone)]
pub struct ApplyProfile {
    pub partition_profile: PartitionProfile,
    pub max_batch_ns: u64,
    pub max_batch_entries: usize,
    pub handoff_queue_len: usize,
    pub budget_breach_threshold: u32,
    pub p99_window: usize,
    pub ack_max_defer_ms: u64,
    pub aggregator: bool,
}

impl Default for ApplyProfile {
    fn default() -> Self {
        Self {
            partition_profile: PartitionProfile::Latency,
            max_batch_ns: 2_000_000, // 2 ms
            max_batch_entries: 512,
            handoff_queue_len: 1024,
            budget_breach_threshold: 5,
            p99_window: DEFAULT_P99_WINDOW,
            ack_max_defer_ms: 250,
            aggregator: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ApplyProfileLimits {
    max_batch_ns: u64,
    max_batch_entries: usize,
    ack_max_defer_ms: u64,
}

impl ApplyProfileLimits {
    fn for_profile(profile: PartitionProfile, aggregator: bool) -> Self {
        if aggregator {
            return Self {
                max_batch_ns: 6_000_000,
                max_batch_entries: 2_048,
                ack_max_defer_ms: 750,
            };
        }
        match profile {
            PartitionProfile::Latency | PartitionProfile::Zfs => Self {
                max_batch_ns: 2_000_000,
                max_batch_entries: 512,
                ack_max_defer_ms: 250,
            },
            PartitionProfile::Throughput => Self {
                max_batch_ns: 4_000_000,
                max_batch_entries: 512,
                ack_max_defer_ms: 400,
            },
            PartitionProfile::Wan => Self {
                max_batch_ns: 5_000_000,
                max_batch_entries: 512,
                ack_max_defer_ms: 500,
            },
        }
    }
}

impl ApplyProfile {
    pub fn for_profile(profile: PartitionProfile) -> Self {
        Self {
            partition_profile: profile,
            ..Self::default()
        }
    }

    pub fn with_partition_profile(mut self, profile: PartitionProfile) -> Self {
        self.partition_profile = profile;
        self
    }

    pub fn aggregator(
        registry: &ProfileCapabilityRegistry,
        profile: PartitionProfile,
    ) -> Result<Self, ProfileCapabilityError> {
        registry.ensure_aggregator_allowed(profile)?;
        Ok(Self {
            partition_profile: profile,
            max_batch_ns: 6_000_000,
            max_batch_entries: 2_048,
            handoff_queue_len: 1_024,
            budget_breach_threshold: 5,
            p99_window: DEFAULT_P99_WINDOW,
            ack_max_defer_ms: 750,
            aggregator: true,
        })
    }

    pub fn validate(&self) -> Result<(), ApplyProfileError> {
        if self.max_batch_ns == 0 {
            return Err(ApplyProfileError::InvalidMaxBatch);
        }
        if self.max_batch_entries == 0 {
            return Err(ApplyProfileError::InvalidBatchEntries);
        }
        if self.handoff_queue_len == 0 {
            return Err(ApplyProfileError::InvalidQueueDepth);
        }
        if self.p99_window == 0 {
            return Err(ApplyProfileError::InvalidWindow);
        }
        self.validate_limits()
    }

    fn limits(&self) -> ApplyProfileLimits {
        ApplyProfileLimits::for_profile(self.partition_profile, self.aggregator)
    }

    fn validate_limits(&self) -> Result<(), ApplyProfileError> {
        let limits = self.limits();
        if self.max_batch_ns > limits.max_batch_ns {
            return Err(ApplyProfileError::MaxBatchNsExceedsProfile {
                observed: self.max_batch_ns,
                ceiling: limits.max_batch_ns,
                profile: self.partition_profile,
                aggregator: self.aggregator,
            });
        }
        if self.max_batch_entries > limits.max_batch_entries {
            return Err(ApplyProfileError::MaxBatchEntriesExceedProfile {
                observed: self.max_batch_entries,
                ceiling: limits.max_batch_entries,
                profile: self.partition_profile,
                aggregator: self.aggregator,
            });
        }
        if self.ack_max_defer_ms > limits.ack_max_defer_ms {
            return Err(ApplyProfileError::AckDeferExceedsProfile {
                observed: self.ack_max_defer_ms,
                ceiling: limits.ack_max_defer_ms,
                profile: self.partition_profile,
                aggregator: self.aggregator,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyProfileReport {
    pub profile_name: String,
    pub aggregator: bool,
    pub p95_batch_ns: u64,
    pub p99_batch_ns: u64,
    pub max_batch_entries: usize,
    pub max_ack_defer_ms: u64,
    pub auto_demoted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhyApply {
    pub decision_trace_id: String,
    pub profile: ApplyProfileReport,
    pub guardrail_level: f32,
    pub guardrail_threshold: u32,
    pub spec_clause: String,
}

#[derive(Debug, Error)]
pub enum ApplyProfileError {
    #[error("max batch duration must be non-zero")]
    InvalidMaxBatch,
    #[error("max batch entries must be non-zero")]
    InvalidBatchEntries,
    #[error("handoff queue size must be non-zero")]
    InvalidQueueDepth,
    #[error("p99 window must be non-zero")]
    InvalidWindow,
    #[error(
        "max batch duration {observed}ns exceeds {profile:?} ceiling {ceiling}ns (aggregator={aggregator})"
    )]
    MaxBatchNsExceedsProfile {
        observed: u64,
        ceiling: u64,
        profile: PartitionProfile,
        aggregator: bool,
    },
    #[error(
        "max batch entries {observed} exceeds {profile:?} ceiling {ceiling} (aggregator={aggregator})"
    )]
    MaxBatchEntriesExceedProfile {
        observed: usize,
        ceiling: usize,
        profile: PartitionProfile,
        aggregator: bool,
    },
    #[error(
        "ack defer {observed}ms exceeds {profile:?} ceiling {ceiling}ms (aggregator={aggregator})"
    )]
    AckDeferExceedsProfile {
        observed: u64,
        ceiling: u64,
        profile: PartitionProfile,
        aggregator: bool,
    },
}
