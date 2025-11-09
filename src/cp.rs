pub mod client;

use crate::consensus::{
    ConsensusCore, ConsensusCoreStatus, DurabilityProof, GateOperation,
    StrictFallbackBlockingReason, StrictFallbackState, StrictFallbackWhy,
};
use crate::durability::recovery::RecoveryStatus;
use crate::profile::PartitionProfile;
use crate::telemetry::MetricsRegistry;
use log::{info, warn};
use serde::Serialize;
use std::time::Instant;
use thiserror::Error;

const CP_CACHE_SPEC: &str = "§11.ControlPlaneCache";
const READ_INDEX_SPEC: &str = "§3.3.ReadIndex";
const ADMIN_GUARD_SPEC: &str = "§13.AdminAPI";
const SNAPSHOT_IMPORT_SPEC: &str = "§8.SnapshotImport";

pub struct CpProofCoordinator {
    kernel: ConsensusCore,
    retry_after_ms: u64,
    cache_state: CpCacheState,
    cache_policy: CpCachePolicy,
    last_publish_at: Option<Instant>,
    last_snapshot_import: Option<StrictFallbackSnapshotImportRecord>,
}

impl CpProofCoordinator {
    pub fn new(kernel: ConsensusCore) -> Self {
        Self {
            kernel,
            retry_after_ms: 250,
            cache_state: CpCacheState::Fresh,
            cache_policy: CpCachePolicy::default(),
            last_publish_at: None,
            last_snapshot_import: None,
        }
    }

    pub fn with_retry_after(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = retry_after_ms.max(250);
        self
    }

    pub fn with_cache_policy(mut self, policy: CpCachePolicy) -> Self {
        self.cache_policy = policy;
        self
    }

    pub fn load_local_ledger(&mut self, proof: DurabilityProof, now: Instant) {
        self.kernel.enter_strict_fallback(proof, now);
    }

    pub fn publish_cp_proof(&mut self, proof: DurabilityProof) {
        let now = Instant::now();
        self.publish_cp_proof_at(proof, now);
    }

    pub fn publish_cp_proof_at(&mut self, proof: DurabilityProof, now: Instant) {
        self.last_publish_at = Some(now);
        self.kernel.mark_proof_published(proof);
        let previous = self.cache_state;
        self.cache_state = CpCacheState::Fresh;
        self.log_cache_transition(previous, "cp_proof_published");
    }

    pub fn set_cache_state(&mut self, state: CpCacheState) {
        let previous = self.cache_state;
        self.cache_state = state;
        self.log_cache_transition(previous, "manual_override");
    }

    pub fn apply_cache_policy(
        &mut self,
        cache_age_ms: u64,
        policy: &CpCachePolicy,
    ) -> CpCacheState {
        let previous = self.cache_state;
        if cache_age_ms >= policy.ttl_ms() {
            self.cache_state = CpCacheState::Expired;
        } else {
            self.cache_state = CpCacheState::Fresh;
        }
        self.log_cache_transition(previous, "ttl_policy");
        self.cache_state
    }

    pub fn refresh_cache_state(&mut self, now: Instant) -> CpCacheState {
        if let Some(age_ms) = self.cache_age_ms(now) {
            let policy = self.cache_policy;
            self.apply_cache_policy(age_ms, &policy)
        } else {
            self.cache_state
        }
    }

    pub fn guard_read_index(&mut self, now: Instant) -> Result<(), ReadIndexError> {
        self.refresh_cache_state(now);
        if matches!(self.cache_state, CpCacheState::Expired) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CacheExpired);
            warn!(
                "event=read_index_guard clause={} outcome=cache_expired retry_after_ms={} cache_state={:?}",
                READ_INDEX_SPEC,
                self.retry_after_ms,
                self.cache_state
            );
            return Err(ReadIndexError::cache_expired(self.build_response(
                CpUnavailableReason::CacheExpired,
                None,
                None,
                None,
            )));
        }

        let evaluation = self.kernel.evaluate_gate(GateOperation::ReadIndex);
        if evaluation.allowed {
            return Ok(());
        }

        self.kernel.record_gate_block(&evaluation);
        let explanation = self.kernel.explain_gate(&evaluation, now);
        warn!(
            "event=read_index_guard clause={} outcome=strict_fallback_block operation={:?} cache_state={:?}",
            READ_INDEX_SPEC,
            evaluation.operation,
            self.cache_state
        );
        Err(ReadIndexError::needed_for_read_index(self.build_response(
            CpUnavailableReason::NeededForReadIndex,
            explanation,
            None,
            None,
        )))
    }

    pub fn guard_read_index_with_quorum(
        &mut self,
        quorum_index: u64,
        now: Instant,
    ) -> Result<ReadIndexPermit, ReadIndexError> {
        self.guard_read_index(now)?;
        if let Some(proof) = self.kernel.last_published_proof() {
            if quorum_index < proof.index {
                self.kernel
                    .record_blocking_reason(StrictFallbackBlockingReason::NeededForReadIndex);
                warn!(
                    "event=read_index_guard clause={} outcome=quorum_regression quorum_index={} required_index={} cache_state={:?}",
                    READ_INDEX_SPEC,
                    quorum_index,
                    proof.index,
                    self.cache_state
                );
                return Err(ReadIndexError::needed_for_read_index(self.build_response(
                    CpUnavailableReason::NeededForReadIndex,
                    None,
                    Some(quorum_index),
                    Some(proof.index),
                )));
            }
        }
        Ok(ReadIndexPermit { quorum_index })
    }

    pub fn guard_admin(&mut self, now: Instant) -> Result<(), AdminGuardError> {
        self.refresh_cache_state(now);
        if matches!(self.cache_state, CpCacheState::Expired) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CacheExpired);
            warn!(
                "event=admin_guard clause={} outcome=cache_expired cache_state={:?}",
                ADMIN_GUARD_SPEC, self.cache_state
            );
            return Err(AdminGuardError::cache_expired(self.build_response(
                CpUnavailableReason::CacheExpired,
                None,
                None,
                None,
            )));
        }
        if self.kernel.is_strict_fallback() {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::NeededForReadIndex);
            warn!(
                "event=admin_guard clause={} outcome=strict_fallback_block cache_state={:?}",
                ADMIN_GUARD_SPEC, self.cache_state
            );
            return Err(AdminGuardError::needed_for_read_index(self.build_response(
                CpUnavailableReason::NeededForReadIndex,
                None,
                None,
                None,
            )));
        }
        Ok(())
    }

    pub fn consensus_core_status(&self, now: Instant) -> ConsensusCoreStatus {
        self.kernel.status(now)
    }

    pub fn consensus_core(&self) -> &ConsensusCore {
        &self.kernel
    }

    pub fn consensus_core_mut(&mut self) -> &mut ConsensusCore {
        &mut self.kernel
    }

    pub fn publish_cache_metrics(&self, registry: &mut MetricsRegistry, now: Instant) {
        let age = self.cache_age_ms(now).unwrap_or(0);
        registry.set_gauge("cp.cache_age_ms", age);
    }

    pub fn cache_age_ms(&self, now: Instant) -> Option<u64> {
        self.last_publish_at
            .map(|published| now.saturating_duration_since(published).as_millis() as u64)
    }

    pub fn apply_recovery_status(&mut self, status: &RecoveryStatus, now: Instant) {
        if status.strict_required {
            let proof = status.proof.unwrap_or_else(|| DurabilityProof::new(0, 0));
            self.kernel.enter_strict_fallback(proof, now);
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::NeededForReadIndex);
        }
    }

    pub fn authorize_snapshot_import(
        &mut self,
        reason: StrictFallbackSnapshotImportReason,
        now: Instant,
    ) -> Result<StrictFallbackSnapshotImportRecord, StrictFallbackSnapshotImportError> {
        let state = self.kernel.state();
        if !matches!(state, StrictFallbackState::LocalOnly) {
            warn!(
                "event=snapshot_import_guard clause={} outcome=strict_state_block strict_state={:?}",
                SNAPSHOT_IMPORT_SPEC,
                state
            );
            return Err(StrictFallbackSnapshotImportError::StateNotLocalOnly { state });
        }
        self.refresh_cache_state(now);
        if matches!(self.cache_state, CpCacheState::Expired) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CacheExpired);
            warn!(
                "event=snapshot_import_guard clause={} outcome=cache_expired cache_state={:?}",
                SNAPSHOT_IMPORT_SPEC, self.cache_state
            );
            return Err(StrictFallbackSnapshotImportError::TrustCacheExpired);
        }
        let record = StrictFallbackSnapshotImportRecord {
            reason,
            strict_state: state,
            cache_age_ms: self.cache_age_ms(now),
            issued_at: now,
        };
        self.last_snapshot_import = Some(record.clone());
        info!(
            "event=snapshot_import_authorized clause={} state={:?} cache_state={:?} cache_age_ms={:?}",
            SNAPSHOT_IMPORT_SPEC,
            state,
            self.cache_state,
            record.cache_age_ms
        );
        Ok(record)
    }

    pub fn last_snapshot_import(&self) -> Option<&StrictFallbackSnapshotImportRecord> {
        self.last_snapshot_import.as_ref()
    }

    fn build_response(
        &self,
        reason: CpUnavailableReason,
        explanation: Option<StrictFallbackWhy>,
        ledger_index: Option<u64>,
        required_index: Option<u64>,
    ) -> CpUnavailableResponse {
        CpUnavailableResponse {
            reason,
            retry_after_ms: self.retry_after_ms,
            strict_state: self.kernel.state(),
            last_local_proof: self.kernel.last_local_proof(),
            pending_entries: self.kernel.pending_entries(),
            cache_warning_ms_remaining: self.cache_state.warning_ms(),
            explanation,
            ledger_index,
            required_index,
            decision_epoch: self.kernel.decision_epoch(),
            strict_fallback_blocking_reason: self.kernel.blocking_reason(),
        }
    }

    fn log_cache_transition(&self, previous: CpCacheState, reason: &str) {
        if previous != self.cache_state {
            info!(
                "event=cp_cache_state clause={} prev_state={:?} next_state={:?} reason={} decision_epoch={}",
                CP_CACHE_SPEC,
                previous,
                self.cache_state,
                reason,
                self.kernel.decision_epoch()
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CpCacheState {
    Fresh,
    Warning { ms_remaining: u64 },
    Expired,
}

impl CpCacheState {
    pub fn warning_ms(&self) -> Option<u64> {
        match self {
            CpCacheState::Warning { ms_remaining } => Some(*ms_remaining),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CpCachePolicy {
    ttl_ms: u64,
}

impl CpCachePolicy {
    pub fn new(ttl_ms: u64) -> Self {
        Self { ttl_ms }
    }

    pub fn for_profile(profile: PartitionProfile) -> Self {
        Self::new(profile.config().cp_durability_proof_ttl_ms)
    }

    pub fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
}

impl Default for CpCachePolicy {
    fn default() -> Self {
        Self::new(300_000)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CpUnavailableReason {
    NeededForReadIndex,
    CacheExpired,
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

#[derive(Debug, Error)]
#[error("CpUnavailable: {response:?}")]
pub struct ReadIndexError {
    pub response: Box<CpUnavailableResponse>,
}

impl ReadIndexError {
    fn needed_for_read_index(response: CpUnavailableResponse) -> Self {
        Self {
            response: Box::new(response),
        }
    }

    fn cache_expired(response: CpUnavailableResponse) -> Self {
        Self {
            response: Box::new(response),
        }
    }

    pub fn response(&self) -> &CpUnavailableResponse {
        &self.response
    }
}

#[derive(Debug, Error)]
#[error("CpUnavailable: {response:?}")]
pub struct AdminGuardError {
    response: Box<CpUnavailableResponse>,
}

impl AdminGuardError {
    fn needed_for_read_index(response: CpUnavailableResponse) -> Self {
        Self {
            response: Box::new(response),
        }
    }

    fn cache_expired(response: CpUnavailableResponse) -> Self {
        Self {
            response: Box::new(response),
        }
    }

    pub fn response(&self) -> &CpUnavailableResponse {
        &self.response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ConsensusCore, ConsensusCoreConfig, DurabilityProof, StrictFallbackState,
    };
    use crate::telemetry::MetricsRegistry;
    use std::time::{Duration, Instant};

    #[test]
    fn read_index_blocks_until_cp_ack() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(1, 10), now);

        let err = coordinator
            .guard_read_index(now + Duration::from_millis(1))
            .expect_err("ReadIndex should fail while LocalOnly");
        assert_eq!(err.response.reason, CpUnavailableReason::NeededForReadIndex);
        assert_eq!(err.response.strict_state, StrictFallbackState::LocalOnly);
        assert!(err.response.explanation.is_some());
        assert_eq!(
            err.response.strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::NeededForReadIndex)
        );
        assert_eq!(err.response.decision_epoch, 1);
        assert_eq!(
            err.response.explanation.as_ref().unwrap().blocking_reason,
            StrictFallbackBlockingReason::NeededForReadIndex
        );

        coordinator.publish_cp_proof_at(DurabilityProof::new(1, 10), now);
        assert!(coordinator
            .guard_read_index(now + Duration::from_millis(2))
            .is_ok());
    }

    #[test]
    fn cache_expiry_forces_cp_unavailable() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(1, 5), now);
        coordinator.set_cache_state(CpCacheState::Expired);

        let err = coordinator
            .guard_read_index(now)
            .expect_err("cache expiry should block reads");
        assert_eq!(err.response.reason, CpUnavailableReason::CacheExpired);
        assert!(err.response.explanation.is_none());
        assert_eq!(
            err.response.strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::CacheExpired)
        );
        assert_eq!(err.response.decision_epoch, 1);

        coordinator.set_cache_state(CpCacheState::Warning {
            ms_remaining: 30_000,
        });
        coordinator.load_local_ledger(DurabilityProof::new(2, 20), now);
        let err = coordinator
            .guard_read_index(now)
            .expect_err("LocalOnly should still block reads");
        assert_eq!(err.response.cache_warning_ms_remaining, Some(30_000));
    }

    #[test]
    fn recovery_status_forces_strict_mode() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        let status = RecoveryStatus {
            strict_required: true,
            truncation: None,
            proof: Some(DurabilityProof::new(4, 40)),
        };
        coordinator.apply_recovery_status(&status, now);
        let snapshot = coordinator.consensus_core_status(now);
        assert_eq!(snapshot.state, StrictFallbackState::LocalOnly);
        assert_eq!(
            snapshot.blocking_reason,
            Some(StrictFallbackBlockingReason::NeededForReadIndex)
        );
    }

    #[test]
    fn recovery_status_noop_when_clean() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        let status = RecoveryStatus {
            strict_required: false,
            truncation: None,
            proof: Some(DurabilityProof::new(0, 0)),
        };
        coordinator.apply_recovery_status(&status, now);
        let snapshot = coordinator.consensus_core_status(now);
        assert_eq!(snapshot.state, StrictFallbackState::Healthy);
    }

    #[test]
    fn proof_ttl_enforces_cache_expiry_and_metrics() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator =
            CpProofCoordinator::new(kernel).with_cache_policy(CpCachePolicy::new(1_000));
        let now = Instant::now();
        coordinator.publish_cp_proof_at(DurabilityProof::new(5, 50), now);
        let mut registry = MetricsRegistry::new("clustor");
        coordinator.publish_cache_metrics(&mut registry, now + Duration::from_millis(600));
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.gauges["clustor.cp.cache_age_ms"], 600);
        let state = coordinator.refresh_cache_state(now + Duration::from_millis(2_000));
        assert!(matches!(state, CpCacheState::Expired));
    }

    #[test]
    fn ledger_gap_blocks_read_index() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(3, 30), now);
        coordinator.publish_cp_proof_at(DurabilityProof::new(3, 30), now);

        let err = coordinator
            .guard_read_index_with_quorum(10, now + Duration::from_millis(1))
            .expect_err("ledger gap should block");
        assert_eq!(err.response.ledger_index, Some(10));
        assert_eq!(err.response.required_index, Some(30));
        assert_eq!(
            err.response.strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::NeededForReadIndex)
        );
    }

    #[test]
    fn snapshot_import_guard_requires_local_only_state() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        let err = coordinator
            .authorize_snapshot_import(
                StrictFallbackSnapshotImportReason::new("DRFailover").unwrap(),
                now,
            )
            .expect_err("imports require LocalOnly");
        assert!(matches!(
            err,
            StrictFallbackSnapshotImportError::StateNotLocalOnly { state }
            if state == StrictFallbackState::Healthy
        ));
    }

    #[test]
    fn snapshot_import_guard_rejects_expired_cache() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(1, 1), now);
        coordinator.set_cache_state(CpCacheState::Expired);

        let err = coordinator
            .authorize_snapshot_import(
                StrictFallbackSnapshotImportReason::new("DRFailover").unwrap(),
                now + Duration::from_millis(1),
            )
            .expect_err("expired cache must block imports");
        assert!(matches!(
            err,
            StrictFallbackSnapshotImportError::TrustCacheExpired
        ));
    }

    #[test]
    fn snapshot_import_guard_records_reason_and_cache_age() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(2, 20), now);
        let reason = StrictFallbackSnapshotImportReason::new("DRBootstrap").unwrap();
        let record = coordinator
            .authorize_snapshot_import(reason.clone(), now + Duration::from_millis(5))
            .expect("import authorized");
        assert_eq!(record.reason, reason);
        assert_eq!(record.strict_state, StrictFallbackState::LocalOnly);
        assert!(coordinator.last_snapshot_import().is_some());
        let snapshot = coordinator.last_snapshot_import().unwrap();
        assert_eq!(snapshot.reason.as_str(), "DRBootstrap");
        assert_eq!(
            snapshot.cache_age_ms,
            coordinator.cache_age_ms(now + Duration::from_millis(5))
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadIndexPermit {
    pub quorum_index: u64,
}
