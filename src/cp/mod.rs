pub mod client;

mod breaker;
mod cache;
mod guard;
#[cfg(feature = "snapshot-crypto")]
mod strict;

pub use cache::{CpCachePolicy, CpCacheState};
pub use guard::{
    CpGuardError, CpGuardResult, CpUnavailableReason, CpUnavailableResponse, ReadIndexPermit,
};
#[cfg(feature = "snapshot-crypto")]
pub use strict::{
    StrictFallbackSnapshotImportError, StrictFallbackSnapshotImportReason,
    StrictFallbackSnapshotImportRecord,
};

#[cfg(feature = "snapshot-crypto")]
use crate::consensus::StrictFallbackState;
use crate::consensus::{
    ConsensusCore, ConsensusCoreStateSnapshot, ConsensusCoreStatus, DurabilityProof, GateOperation,
    GateViolation, StrictFallbackBlockingReason, StrictFallbackMetricsPublisher, StrictFallbackWhy,
};
use crate::durability::recovery::RecoveryStatus;
use crate::read_index::{ReadGateClause, ReadGateEvaluator, ReadGateInputs, ReadGateTelemetry};
use crate::telemetry::MetricsRegistry;
use breaker::CpCircuitBreaker;
use log::{info, warn};
use std::time::{Duration, Instant};

const CP_CACHE_SPEC: &str = "§11.ControlPlaneCache";
const READ_INDEX_SPEC: &str = "§3.3.ReadIndex";
const ADMIN_GUARD_SPEC: &str = "§13.AdminAPI";
#[cfg(feature = "snapshot-crypto")]
const SNAPSHOT_IMPORT_SPEC: &str = "§8.SnapshotImport";
const STRICT_GATE_SPEC_CP: &str = "§0.5.StrictFallbackGate";
const CP_BREAKER_SPEC: &str = "§11.1.ControlPlaneCircuitBreaker";
const CP_BREAKER_FAILURE_THRESHOLD: u32 = 3;
const CP_BREAKER_COOLDOWN: Duration = Duration::from_secs(5);

pub struct CpProofCoordinator {
    kernel: ConsensusCore,
    retry_after_ms: u64,
    cache_state: CpCacheState,
    cache_warning_ms_remaining: Option<u64>,
    cache_policy: CpCachePolicy,
    last_publish_at: Option<Instant>,
    #[cfg(feature = "snapshot-crypto")]
    last_snapshot_import: Option<StrictFallbackSnapshotImportRecord>,
    strict_metrics: StrictFallbackMetricsPublisher,
    read_gate_status: ReadGateTelemetry,
    breaker: CpCircuitBreaker,
}

impl CpProofCoordinator {
    pub fn new(kernel: ConsensusCore) -> Self {
        Self {
            kernel,
            retry_after_ms: 250,
            cache_state: CpCacheState::Fresh,
            cache_warning_ms_remaining: None,
            cache_policy: CpCachePolicy::default(),
            last_publish_at: None,
            #[cfg(feature = "snapshot-crypto")]
            last_snapshot_import: None,
            strict_metrics: StrictFallbackMetricsPublisher::new(),
            read_gate_status: ReadGateTelemetry::blocked(ReadGateClause::StrictFallback),
            breaker: CpCircuitBreaker::new(CP_BREAKER_FAILURE_THRESHOLD, CP_BREAKER_COOLDOWN),
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
        self.cache_warning_ms_remaining = None;
        self.log_cache_transition(previous, "cp_proof_published");
    }

    pub fn set_cache_state(&mut self, state: CpCacheState) {
        let previous = self.cache_state;
        self.cache_state = state;
        self.cache_warning_ms_remaining = state
            .age_ms()
            .and_then(|age| self.cache_policy.warning_ms_remaining(age));
        self.log_cache_transition(previous, "manual_override");
    }

    pub fn apply_cache_policy(
        &mut self,
        cache_age_ms: u64,
        policy: &CpCachePolicy,
    ) -> CpCacheState {
        let previous = self.cache_state;
        let half_grace = policy.cache_grace_ms() / 2;
        let state = if cache_age_ms <= policy.cache_fresh_ms() {
            CpCacheState::Fresh
        } else if cache_age_ms <= half_grace {
            CpCacheState::Cached {
                age_ms: cache_age_ms,
            }
        } else if cache_age_ms < policy.cache_grace_ms() {
            CpCacheState::Stale {
                age_ms: cache_age_ms,
            }
        } else {
            CpCacheState::Expired {
                age_ms: cache_age_ms,
            }
        };
        self.cache_state = state;
        self.cache_warning_ms_remaining = policy.warning_ms_remaining(cache_age_ms);
        self.log_cache_transition(previous, "cache_policy");
        state
    }

    pub fn refresh_cache_state(&mut self, now: Instant) -> CpCacheState {
        if let Some(age_ms) = self.cache_age_ms(now) {
            let policy = self.cache_policy;
            self.apply_cache_policy(age_ms, &policy)
        } else {
            self.cache_state
        }
    }

    pub fn guard_read_index(&mut self, now: Instant) -> Result<(), CpGuardError> {
        self.ensure_breaker_allows(now)?;
        self.refresh_cache_state(now);
        if matches!(self.cache_state, CpCacheState::Expired { .. }) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CacheExpired);
            self.read_gate_status = ReadGateTelemetry::blocked(ReadGateClause::CacheNotFresh);
            warn!(
                "event=read_index_guard clause={} outcome=cache_expired retry_after_ms={} cache_state={:?}",
                READ_INDEX_SPEC,
                self.retry_after_ms,
                self.cache_state
            );
            self.record_breaker_failure(now);
            return Err(CpGuardError::from_response(
                READ_INDEX_SPEC,
                self.build_response(CpUnavailableReason::CacheExpired, None, None, None),
            ));
        }

        if matches!(self.cache_state, CpCacheState::Stale { .. }) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::NeededForReadIndex);
            self.read_gate_status = ReadGateTelemetry::blocked(ReadGateClause::CacheNotFresh);
            warn!(
                "event=read_index_guard clause={} outcome=cache_not_fresh state={:?}",
                READ_INDEX_SPEC, self.cache_state
            );
            self.record_breaker_failure(now);
            return Err(CpGuardError::from_response(
                READ_INDEX_SPEC,
                self.build_response(CpUnavailableReason::NeededForReadIndex, None, None, None),
            ));
        }

        let evaluation = self.kernel.evaluate_gate(GateOperation::ReadIndex);
        if evaluation.allowed {
            self.read_gate_status = ReadGateTelemetry::allowed();
            self.record_breaker_success();
            return Ok(());
        }

        self.kernel.record_gate_block(&evaluation);
        let explanation = self.kernel.explain_gate(&evaluation, now);
        self.read_gate_status = ReadGateTelemetry::blocked(ReadGateClause::StrictFallback);
        warn!(
            "event=read_index_guard clause={} outcome=strict_fallback_block operation={:?} cache_state={:?}",
            READ_INDEX_SPEC,
            evaluation.operation,
            self.cache_state
        );
        self.record_breaker_failure(now);
        Err(CpGuardError::from_response(
            READ_INDEX_SPEC,
            self.build_response(
                CpUnavailableReason::NeededForReadIndex,
                explanation,
                None,
                None,
            ),
        ))
    }

    pub fn guard_read_index_with_quorum(
        &mut self,
        quorum_index: u64,
        now: Instant,
    ) -> Result<ReadIndexPermit, CpGuardError> {
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
                self.record_breaker_failure(now);
                return Err(CpGuardError::from_response(
                    READ_INDEX_SPEC,
                    self.build_response(
                        CpUnavailableReason::NeededForReadIndex,
                        None,
                        Some(quorum_index),
                        Some(proof.index),
                    ),
                ));
            }
        }
        self.record_breaker_success();
        Ok(ReadIndexPermit {
            quorum_index,
            last_published_proof: self.kernel.last_published_proof(),
            cache_state: self.cache_state,
        })
    }

    pub fn evaluate_read_index_permit(
        &mut self,
        inputs: ReadGateInputs,
        now: Instant,
    ) -> Result<ReadIndexPermit, CpGuardError> {
        self.guard_read_index(now)?;
        let evaluation = ReadGateEvaluator::evaluate(
            self.kernel.is_strict_fallback(),
            matches!(self.cache_state, CpCacheState::Fresh),
            self.kernel.last_local_proof(),
            self.kernel.last_published_proof(),
            &inputs,
        );
        self.read_gate_status = evaluation.telemetry;
        if evaluation.allowed {
            self.record_breaker_success();
            Ok(ReadIndexPermit {
                quorum_index: inputs.raft_commit_index,
                last_published_proof: self.kernel.last_published_proof(),
                cache_state: self.cache_state,
            })
        } else {
            let clause = evaluation
                .failed_clause
                .unwrap_or(ReadGateClause::StrictFallback);
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::NeededForReadIndex);
            let response = self.build_read_gate_response(clause, &inputs);
            self.record_breaker_failure(now);
            Err(CpGuardError::from_response(READ_INDEX_SPEC, response))
        }
    }

    pub fn guard_admin(&mut self, now: Instant) -> Result<(), CpGuardError> {
        self.ensure_breaker_allows(now)?;
        self.refresh_cache_state(now);
        if matches!(self.cache_state, CpCacheState::Expired { .. }) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CacheExpired);
            warn!(
                "event=admin_guard clause={} outcome=cache_expired cache_state={:?}",
                ADMIN_GUARD_SPEC, self.cache_state
            );
            self.record_breaker_failure(now);
            return Err(CpGuardError::from_response(
                ADMIN_GUARD_SPEC,
                self.build_response(CpUnavailableReason::CacheExpired, None, None, None),
            ));
        }
        self.record_breaker_success();
        Ok(())
    }

    pub fn guard_durability_transition(&mut self, now: Instant) -> CpGuardResult<()> {
        self.guard_strict_operation(GateOperation::EnableGroupFsync, now)
    }

    pub fn guard_lease_enable(&mut self, now: Instant) -> CpGuardResult<()> {
        self.guard_strict_operation(GateOperation::EnableLeaseReads, now)
    }

    pub fn guard_follower_capability_grant(&mut self, now: Instant) -> CpGuardResult<()> {
        self.guard_strict_operation(GateOperation::GrantFollowerReadSnapshotCapability, now)
    }

    pub fn guard_snapshot_delta_enable(&mut self, now: Instant) -> CpGuardResult<()> {
        self.guard_strict_operation(GateOperation::EnableSnapshotDelta, now)
    }

    pub fn consensus_core_status(&self, now: Instant) -> ConsensusCoreStatus {
        self.kernel.status(now)
    }

    pub fn consensus_core_state(&self) -> ConsensusCoreStateSnapshot {
        self.kernel.snapshot_state()
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

    pub fn record_cache_refresh(&mut self, now: Instant) {
        let previous = self.cache_state;
        self.last_publish_at = Some(now);
        self.cache_state = CpCacheState::Fresh;
        self.cache_warning_ms_remaining = None;
        self.log_cache_transition(previous, "cache_refresh");
    }

    pub fn cache_refresh_due(&self, now: Instant) -> bool {
        self.cache_age_ms(now)
            .map(|age| age >= self.cache_policy.cache_warn_ms())
            .unwrap_or(false)
    }

    pub fn publish_strict_fallback_metrics(
        &mut self,
        registry: &mut MetricsRegistry,
        now: Instant,
    ) {
        let telemetry = self.kernel.telemetry(now);
        self.strict_metrics.publish(registry, &telemetry);
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

    #[cfg(feature = "snapshot-crypto")]
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
        if matches!(self.cache_state, CpCacheState::Expired { .. }) {
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

    #[cfg(feature = "snapshot-crypto")]
    pub fn last_snapshot_import(&self) -> Option<&StrictFallbackSnapshotImportRecord> {
        self.last_snapshot_import.as_ref()
    }

    pub fn read_gate_status(&self) -> ReadGateTelemetry {
        self.read_gate_status
    }

    pub fn publish_read_gate_metrics(&self, metrics: &mut MetricsRegistry) {
        metrics.set_gauge(
            "cp.read_gate.can_serve_readindex",
            if self.read_gate_status.can_serve {
                1
            } else {
                0
            },
        );
        metrics.set_gauge(
            "cp.read_gate.failed_clause_id",
            self.read_gate_status.clause_metric(),
        );
        metrics.set_gauge(
            "cp.read_gate.failed_clause_present",
            if self.read_gate_status.failed_clause.is_some() {
                1
            } else {
                0
            },
        );
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
            cache_warning_ms_remaining: self.cache_warning_ms_remaining,
            explanation,
            ledger_index,
            required_index,
            decision_epoch: self.kernel.decision_epoch(),
            strict_fallback_blocking_reason: self.kernel.blocking_reason(),
        }
    }

    fn build_read_gate_response(
        &self,
        clause: ReadGateClause,
        inputs: &ReadGateInputs,
    ) -> CpUnavailableResponse {
        let (ledger, required) = if matches!(clause, ReadGateClause::IndexInequality) {
            (
                Some(inputs.wal_committed_index),
                Some(inputs.raft_commit_index),
            )
        } else {
            (None, None)
        };
        self.build_response(
            CpUnavailableReason::NeededForReadIndex,
            None,
            ledger,
            required,
        )
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

    fn ensure_breaker_allows(&mut self, now: Instant) -> Result<(), CpGuardError> {
        if self.breaker.is_open(now) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CircuitBreakerOpen);
            warn!(
                "event=cp_circuit_breaker clause={} outcome=open decision_epoch={}",
                CP_BREAKER_SPEC,
                self.kernel.decision_epoch()
            );
            let mut response =
                self.build_response(CpUnavailableReason::CircuitBreakerOpen, None, None, None);
            if let Some(remaining) = self.breaker.cooldown_remaining_ms(now) {
                response.retry_after_ms = remaining.max(self.retry_after_ms);
            }
            return Err(CpGuardError::from_response(CP_BREAKER_SPEC, response));
        }
        Ok(())
    }

    fn record_breaker_failure(&mut self, now: Instant) {
        self.breaker.record_failure(now);
    }

    fn record_breaker_success(&mut self) {
        self.breaker.record_success();
    }

    fn guard_strict_operation(
        &mut self,
        operation: GateOperation,
        now: Instant,
    ) -> CpGuardResult<()> {
        self.ensure_breaker_allows(now)?;
        self.refresh_cache_state(now);
        let evaluation = self.kernel.evaluate_gate(operation);
        if !evaluation.allowed {
            self.kernel.record_gate_block(&evaluation);
            let violation = match evaluation.violation {
                Some(violation) => violation,
                None => {
                    warn!(
                        "event=strict_gate clause={} operation={:?} violation=missing decision_epoch={}",
                        STRICT_GATE_SPEC_CP,
                        operation,
                        self.kernel.decision_epoch()
                    );
                    return Err(CpGuardError::from_response(
                        STRICT_GATE_SPEC_CP,
                        self.build_response(
                            CpUnavailableReason::NeededForReadIndex,
                            self.kernel.explain_gate(&evaluation, now),
                            None,
                            None,
                        ),
                    ));
                }
            };
            let reason = match violation {
                GateViolation::CpUnavailableCacheExpired => CpUnavailableReason::CacheExpired,
                _ => CpUnavailableReason::NeededForReadIndex,
            };
            warn!(
                "event=strict_gate clause={} operation={:?} violation={:?} reason={:?} decision_epoch={}",
                STRICT_GATE_SPEC_CP,
                operation,
                violation,
                reason,
                self.kernel.decision_epoch()
            );
            if reason != CpUnavailableReason::NeededForReadIndex {
                self.record_breaker_failure(now);
            }
            return Err(CpGuardError::from_response(
                STRICT_GATE_SPEC_CP,
                self.build_response(
                    reason,
                    self.kernel.explain_gate(&evaluation, now),
                    None,
                    None,
                ),
            ));
        }

        if matches!(self.cache_state, CpCacheState::Expired { .. }) {
            self.kernel
                .record_blocking_reason(StrictFallbackBlockingReason::CacheExpired);
            warn!(
                "event=strict_gate clause={} operation={:?} outcome=cache_expired decision_epoch={}",
                STRICT_GATE_SPEC_CP,
                operation,
                self.kernel.decision_epoch()
            );
            self.record_breaker_failure(now);
            return Err(CpGuardError::from_response(
                STRICT_GATE_SPEC_CP,
                self.build_response(CpUnavailableReason::CacheExpired, None, None, None),
            ));
        }

        self.record_breaker_success();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ConsensusCore, ConsensusCoreConfig, DurabilityProof, StrictFallbackState,
    };
    use crate::telemetry::MetricsRegistry;
    use crate::CommitVisibility;
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
        let response = err.response();
        assert_eq!(response.reason, CpUnavailableReason::NeededForReadIndex);
        assert_eq!(response.strict_state, StrictFallbackState::LocalOnly);
        assert!(response.explanation.is_some());
        assert_eq!(
            response.strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::NeededForReadIndex)
        );
        assert_eq!(response.decision_epoch, 1);
        assert_eq!(
            response.explanation.as_ref().unwrap().blocking_reason,
            StrictFallbackBlockingReason::NeededForReadIndex
        );

        coordinator.publish_cp_proof_at(DurabilityProof::new(1, 10), now);
        assert!(coordinator
            .guard_read_index(now + Duration::from_millis(2))
            .is_ok());
    }

    #[test]
    fn read_index_permit_requires_predicate() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(2, 20), now);
        coordinator
            .publish_cp_proof_at(DurabilityProof::new(2, 20), now + Duration::from_millis(1));
        let inputs = ReadGateInputs {
            commit_visibility: CommitVisibility::DurableOnly,
            wal_committed_index: 20,
            raft_commit_index: 20,
        };
        let permit = coordinator
            .evaluate_read_index_permit(inputs, now + Duration::from_millis(2))
            .expect("predicate should pass");
        assert_eq!(permit.quorum_index, 20);
        assert!(coordinator.read_gate_status().can_serve);
    }

    #[test]
    fn read_gate_reports_failed_clause() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(3, 30), now);
        coordinator
            .publish_cp_proof_at(DurabilityProof::new(3, 30), now + Duration::from_millis(1));
        let inputs = ReadGateInputs {
            commit_visibility: CommitVisibility::CommitAllowsPreDurable,
            wal_committed_index: 30,
            raft_commit_index: 30,
        };
        let err = coordinator
            .evaluate_read_index_permit(inputs, now + Duration::from_millis(2))
            .expect_err("predicate should reject");
        assert_eq!(
            err.response().reason,
            CpUnavailableReason::NeededForReadIndex
        );
        assert_eq!(
            coordinator.read_gate_status().failed_clause,
            Some(ReadGateClause::CommitVisibility)
        );
    }

    #[test]
    fn read_gate_surfaces_index_gap() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(4, 40), now);
        coordinator
            .publish_cp_proof_at(DurabilityProof::new(4, 40), now + Duration::from_millis(1));
        let inputs = ReadGateInputs {
            commit_visibility: CommitVisibility::DurableOnly,
            wal_committed_index: 39,
            raft_commit_index: 40,
        };
        let err = coordinator
            .evaluate_read_index_permit(inputs, now + Duration::from_millis(2))
            .expect_err("index gap should block");
        assert_eq!(err.response().ledger_index, Some(39));
        assert_eq!(err.response().required_index, Some(40));
        assert_eq!(
            coordinator.read_gate_status().failed_clause,
            Some(ReadGateClause::IndexInequality)
        );
    }

    #[test]
    fn read_gate_metrics_publish_status() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let coordinator = CpProofCoordinator::new(kernel);
        let mut registry = MetricsRegistry::new("clustor");
        coordinator.publish_read_gate_metrics(&mut registry);
        let snapshot = registry.snapshot();
        assert_eq!(
            snapshot
                .gauges
                .get("clustor.cp.read_gate.failed_clause_present"),
            Some(&1)
        );
    }

    #[test]
    fn cache_expiry_forces_cp_unavailable() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(1, 5), now);
        coordinator.set_cache_state(CpCacheState::Expired { age_ms: 400_000 });

        let err = coordinator
            .guard_read_index(now)
            .expect_err("cache expiry should block reads");
        let response = err.response();
        assert_eq!(response.reason, CpUnavailableReason::CacheExpired);
        assert!(response.explanation.is_none());
        assert_eq!(
            response.strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::CacheExpired)
        );
        assert_eq!(response.decision_epoch, 1);

        coordinator.set_cache_state(CpCacheState::Stale { age_ms: 270_000 });
        coordinator.load_local_ledger(DurabilityProof::new(2, 20), now);
        let err = coordinator
            .guard_read_index(now)
            .expect_err("LocalOnly should still block reads");
        assert_eq!(err.response().cache_warning_ms_remaining, Some(30_000));
    }

    #[test]
    fn circuit_breaker_opens_and_recovers() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let mut now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(1, 10), now);
        for _ in 0..CP_BREAKER_FAILURE_THRESHOLD {
            let err = coordinator
                .guard_read_index(now)
                .expect_err("strict fallback should block");
            assert_eq!(
                err.response().reason,
                CpUnavailableReason::NeededForReadIndex
            );
            now += Duration::from_millis(1);
        }
        let err = coordinator
            .guard_read_index(now)
            .expect_err("breaker should open");
        assert_eq!(
            err.response().reason,
            CpUnavailableReason::CircuitBreakerOpen
        );
        assert_eq!(
            err.response().strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::CircuitBreakerOpen)
        );
        now += Duration::from_secs(10);
        coordinator.publish_cp_proof_at(DurabilityProof::new(1, 10), now);
        assert!(coordinator
            .guard_read_index(now + Duration::from_millis(1))
            .is_ok());
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
        let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 500);
        let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
        let now = Instant::now();
        coordinator.publish_cp_proof_at(DurabilityProof::new(5, 50), now);
        let mut registry = MetricsRegistry::new("clustor");
        coordinator.publish_cache_metrics(&mut registry, now + Duration::from_millis(600));
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.gauges["clustor.cp.cache_age_ms"], 600);
        let state = coordinator.refresh_cache_state(now + Duration::from_millis(600));
        assert!(matches!(state, CpCacheState::Expired { .. }));
    }

    #[test]
    fn strict_fallback_metrics_publish_through_coordinator() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let mut registry = MetricsRegistry::new("clustor");
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(8, 80), now);
        coordinator.consensus_core_mut().register_strict_write();
        coordinator.publish_strict_fallback_metrics(&mut registry, now + Duration::from_millis(1));
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.gauges["clustor.strict_fallback_state"], 1);
        assert_eq!(
            snapshot.gauges["clustor.strict_fallback_pending_entries"],
            1
        );
        assert_eq!(snapshot.gauges["clustor.strict_fallback_decision_epoch"], 1);
        assert_eq!(
            snapshot.gauges["clustor.strict_fallback_blocking_reason.None"],
            1
        );
    }

    #[test]
    fn cache_refresh_due_follows_warning_window() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 800);
        let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
        let now = Instant::now();
        coordinator.publish_cp_proof_at(DurabilityProof::new(9, 90), now);
        assert!(
            !coordinator.cache_refresh_due(now + Duration::from_millis(200)),
            "warn threshold should not trigger early"
        );
        let warn_time = now + Duration::from_millis(650);
        assert!(
            coordinator.cache_refresh_due(warn_time),
            "warning should fire after cache_warn_ms"
        );
        coordinator.record_cache_refresh(warn_time);
        assert!(
            !coordinator.cache_refresh_due(warn_time + Duration::from_millis(10)),
            "manual refresh resets warning window"
        );
    }

    #[test]
    fn read_index_permit_exposes_proof_and_cache_state() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(12, 120), now);
        coordinator.publish_cp_proof_at(DurabilityProof::new(12, 120), now);
        let permit = coordinator
            .guard_read_index_with_quorum(120, now + Duration::from_millis(1))
            .expect("permit should be granted");
        assert_eq!(permit.quorum_index, 120);
        assert_eq!(
            permit.last_published_proof,
            Some(DurabilityProof::new(12, 120))
        );
        assert!(matches!(permit.cache_state, CpCacheState::Fresh));
    }

    #[test]
    fn read_gate_errors_track_cache_transitions() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 500);
        let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(4, 40), now);

        let err = coordinator
            .guard_read_index(now + Duration::from_millis(1))
            .expect_err("LocalOnly blocks read index");
        assert_eq!(
            err.response().reason,
            CpUnavailableReason::NeededForReadIndex
        );

        coordinator.publish_cp_proof_at(DurabilityProof::new(4, 40), now);
        assert!(coordinator
            .guard_read_index(now + Duration::from_millis(2))
            .is_ok());

        let expired_at = now + Duration::from_millis(600);
        let err = coordinator
            .guard_read_index(expired_at)
            .expect_err("expired cache blocks read index");
        assert_eq!(err.response().reason, CpUnavailableReason::CacheExpired);

        coordinator.record_cache_refresh(expired_at);
        assert!(coordinator
            .guard_read_index(expired_at + Duration::from_millis(1))
            .is_ok());
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
        assert_eq!(err.response().ledger_index, Some(10));
        assert_eq!(err.response().required_index, Some(30));
        assert_eq!(
            err.response().strict_fallback_blocking_reason,
            Some(StrictFallbackBlockingReason::NeededForReadIndex)
        );
    }

    #[cfg(feature = "snapshot-crypto")]
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

    #[cfg(feature = "snapshot-crypto")]
    #[test]
    fn snapshot_import_guard_rejects_expired_cache() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(1, 1), now);
        coordinator.set_cache_state(CpCacheState::Expired { age_ms: 400_000 });

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

    #[cfg(feature = "snapshot-crypto")]
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

    #[test]
    fn durability_transition_guard_tracks_strict_state() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(5, 50), now);

        let err = coordinator
            .guard_durability_transition(now + Duration::from_millis(1))
            .expect_err("group fsync should be gated");
        let response = err.response();
        assert_eq!(response.reason, CpUnavailableReason::NeededForReadIndex);
        assert_eq!(response.strict_state, StrictFallbackState::LocalOnly);
        assert!(response.explanation.is_some());

        coordinator
            .publish_cp_proof_at(DurabilityProof::new(5, 50), now + Duration::from_millis(2));
        assert!(coordinator
            .guard_durability_transition(now + Duration::from_millis(3))
            .is_ok());
    }

    #[test]
    fn lease_enable_guard_respects_cache_and_strict_states() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let policy = CpCachePolicy::new(1_000).with_cache_windows(100, 1_000);
        let mut coordinator = CpProofCoordinator::new(kernel).with_cache_policy(policy);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(7, 70), now);

        let err = coordinator
            .guard_lease_enable(now + Duration::from_millis(1))
            .expect_err("leases blocked while LocalOnly");
        assert_eq!(
            err.response().reason,
            CpUnavailableReason::NeededForReadIndex
        );

        coordinator
            .publish_cp_proof_at(DurabilityProof::new(7, 70), now + Duration::from_millis(2));
        let expired_state = coordinator.refresh_cache_state(now + Duration::from_millis(1_200));
        assert!(matches!(expired_state, CpCacheState::Expired { .. }));
        let err = coordinator
            .guard_lease_enable(now + Duration::from_millis(1_200))
            .expect_err("expired cache blocks leases");
        assert_eq!(err.response().reason, CpUnavailableReason::CacheExpired);
    }

    #[test]
    fn strict_fallback_scenario_matches_gate_table() {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let mut coordinator = CpProofCoordinator::new(kernel);
        let now = Instant::now();
        coordinator.load_local_ledger(DurabilityProof::new(11, 110), now);

        let group = coordinator
            .guard_durability_transition(now + Duration::from_millis(1))
            .expect_err("group fsync blocked while LocalOnly");
        assert_eq!(
            group.response().reason,
            CpUnavailableReason::NeededForReadIndex
        );

        let lease = coordinator
            .guard_lease_enable(now + Duration::from_millis(1))
            .expect_err("leases blocked while LocalOnly");
        assert_eq!(
            lease.response().reason,
            CpUnavailableReason::NeededForReadIndex
        );

        let follower = coordinator
            .guard_follower_capability_grant(now + Duration::from_millis(1))
            .expect_err("follower capability blocked while LocalOnly");
        assert_eq!(
            follower.response().reason,
            CpUnavailableReason::NeededForReadIndex
        );

        let delta = coordinator
            .guard_snapshot_delta_enable(now + Duration::from_millis(1))
            .expect_err("snapshot delta blocked while LocalOnly");
        assert_eq!(delta.response().reason, CpUnavailableReason::CacheExpired);

        coordinator.publish_cp_proof_at(
            DurabilityProof::new(11, 110),
            now + Duration::from_millis(2),
        );

        type StrictGuardFn = fn(&mut CpProofCoordinator, Instant) -> CpGuardResult<()>;
        let mut validators: [StrictGuardFn; 4] = [
            CpProofCoordinator::guard_durability_transition,
            CpProofCoordinator::guard_lease_enable,
            CpProofCoordinator::guard_follower_capability_grant,
            CpProofCoordinator::guard_snapshot_delta_enable,
        ];
        for guard in validators.iter_mut() {
            (guard)(&mut coordinator, now + Duration::from_millis(3))
                .expect("gate should clear after proof published");
        }
    }
}
