use crate::consensus::StrictFallbackState;
use std::time::Instant;
use thiserror::Error;

const MAX_SNAPSHOT_IMPORT_REASON_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictFallbackSnapshotImportReason(String);

impl StrictFallbackSnapshotImportReason {
    pub fn new(reason: impl Into<String>) -> Result<Self, StrictFallbackSnapshotImportError> {
        let reason = reason.into();
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            return Err(StrictFallbackSnapshotImportError::MissingReason);
        }
        if trimmed.len() > MAX_SNAPSHOT_IMPORT_REASON_LEN {
            return Err(StrictFallbackSnapshotImportError::ReasonTooLong {
                length: trimmed.len(),
                max: MAX_SNAPSHOT_IMPORT_REASON_LEN,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct StrictFallbackSnapshotImportRecord {
    pub reason: StrictFallbackSnapshotImportReason,
    pub strict_state: StrictFallbackState,
    pub cache_age_ms: Option<u64>,
    pub issued_at: Instant,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StrictFallbackSnapshotImportError {
    #[error("snapshot import requires strict fallback LocalOnly (state = {state:?})")]
    StateNotLocalOnly { state: StrictFallbackState },
    #[error("snapshot import blocked: trust cache expired")]
    TrustCacheExpired,
    #[error("snapshot import reason missing")]
    MissingReason,
    #[error("snapshot import reason too long (len={length}, max={max})")]
    ReasonTooLong { length: usize, max: usize },
}
