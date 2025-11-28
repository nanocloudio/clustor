use crate::profile::PartitionProfile;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CpCacheState {
    Fresh,
    Cached { age_ms: u64 },
    Stale { age_ms: u64 },
    Expired { age_ms: u64 },
}

impl CpCacheState {
    pub(crate) fn age_ms(&self) -> Option<u64> {
        match self {
            CpCacheState::Fresh => None,
            CpCacheState::Cached { age_ms }
            | CpCacheState::Stale { age_ms }
            | CpCacheState::Expired { age_ms } => Some(*age_ms),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CpCachePolicy {
    proof_ttl_ms: u64,
    cache_fresh_ms: u64,
    cache_warn_ms: u64,
    cache_grace_ms: u64,
}

impl CpCachePolicy {
    pub fn new(proof_ttl_ms: u64) -> Self {
        let cache_grace_ms = 300_000u64;
        let cache_warn_ms =
            ((3 * cache_grace_ms) / 4).max(cache_grace_ms.saturating_sub(60_000u64));
        Self {
            proof_ttl_ms,
            cache_fresh_ms: 60_000,
            cache_warn_ms,
            cache_grace_ms,
        }
    }

    pub fn for_profile(profile: PartitionProfile) -> Self {
        Self::new(profile.config().cp_durability_proof_ttl_ms)
    }

    pub fn with_cache_windows(mut self, fresh_ms: u64, grace_ms: u64) -> Self {
        self.cache_fresh_ms = fresh_ms.min(grace_ms);
        self.cache_grace_ms = grace_ms;
        self.cache_warn_ms = ((3 * grace_ms) / 4).max(grace_ms.saturating_sub(60_000u64));
        self
    }

    pub fn proof_ttl_ms(&self) -> u64 {
        self.proof_ttl_ms
    }

    pub fn cache_fresh_ms(&self) -> u64 {
        self.cache_fresh_ms
    }

    pub fn cache_warn_ms(&self) -> u64 {
        self.cache_warn_ms
    }

    pub fn cache_grace_ms(&self) -> u64 {
        self.cache_grace_ms
    }

    pub fn warning_ms_remaining(&self, age_ms: u64) -> Option<u64> {
        if age_ms >= self.cache_grace_ms {
            Some(0)
        } else if age_ms >= self.cache_warn_ms {
            Some(self.cache_grace_ms.saturating_sub(age_ms))
        } else {
            None
        }
    }
}

impl Default for CpCachePolicy {
    fn default() -> Self {
        Self::new(43_200_000)
    }
}
