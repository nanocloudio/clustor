use clustor::persistence::snapshot::SnapshotImportRetryPolicy;
use std::time::Duration;

pub fn fast_retry_policy() -> SnapshotImportRetryPolicy {
    SnapshotImportRetryPolicy {
        max_retries: 0,
        base_delay: Duration::ZERO,
        max_delay: Duration::ZERO,
        time_budget: Duration::ZERO,
        jitter_fraction: 0.0,
    }
}
