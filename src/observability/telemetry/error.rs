use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum TelemetryError {
    #[error("unknown histogram {0}")]
    UnknownHistogram(String),
    #[error("metrics shard lock poisoned")]
    ShardPoisoned,
    #[error("metrics catalog corrupt: {0}")]
    MetricsCatalog(String),
}
