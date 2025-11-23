use crate::consensus::{
    DurabilityProof, StrictFallbackBlockingReason, StrictFallbackState, StrictFallbackWhy,
};
use serde::Serialize;
use thiserror::Error;

use super::cache::CpCacheState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CpUnavailableReason {
    NeededForReadIndex,
    CacheExpired,
    CircuitBreakerOpen,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpUnavailableResponse {
    pub reason: CpUnavailableReason,
    pub retry_after_ms: u64,
    pub strict_state: StrictFallbackState,
    pub last_local_proof: Option<DurabilityProof>,
    pub pending_entries: u64,
    pub cache_warning_ms_remaining: Option<u64>,
    pub explanation: Option<StrictFallbackWhy>,
    pub ledger_index: Option<u64>,
    pub required_index: Option<u64>,
    pub decision_epoch: u64,
    pub strict_fallback_blocking_reason: Option<StrictFallbackBlockingReason>,
}

#[derive(Debug, Error)]
pub enum CpGuardError {
    #[error("control plane unavailable ({clause}): {response:?}")]
    Unavailable {
        clause: &'static str,
        response: Box<CpUnavailableResponse>,
    },
}

impl CpGuardError {
    pub fn from_response(clause: &'static str, response: CpUnavailableResponse) -> Self {
        Self::Unavailable {
            clause,
            response: Box::new(response),
        }
    }

    pub fn clause(&self) -> &'static str {
        match self {
            CpGuardError::Unavailable { clause, .. } => clause,
        }
    }

    pub fn response(&self) -> &CpUnavailableResponse {
        match self {
            CpGuardError::Unavailable { response, .. } => response,
        }
    }

    pub fn into_response(self) -> CpUnavailableResponse {
        match self {
            CpGuardError::Unavailable { response, .. } => *response,
        }
    }
}

pub type CpGuardResult<T = ()> = Result<T, CpGuardError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadIndexPermit {
    pub quorum_index: u64,
    pub last_published_proof: Option<DurabilityProof>,
    pub cache_state: CpCacheState,
}
