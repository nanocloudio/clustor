pub mod client;

mod breaker;
mod cache;
mod guard;
pub mod placement;
mod read_index;
#[cfg(feature = "snapshot-crypto")]
mod strict;

pub use cache::{CpCachePolicy, CpCacheState};
pub use guard::{
    CpGuardError, CpGuardResult, CpUnavailableReason, CpUnavailableResponse, ReadIndexPermit,
};
pub use placement::{CpPlacementClient, PlacementRecord, PlacementSnapshot, RoutingEpochError};
pub use read_index::{
    CommitVisibility, ReadGateClause, ReadGateDecision, ReadGateEvaluator, ReadGateInputs,
    ReadGateTelemetry,
};
#[cfg(feature = "snapshot-crypto")]
pub use strict::{
    StrictFallbackSnapshotImportError, StrictFallbackSnapshotImportReason,
    StrictFallbackSnapshotImportRecord,
};

use crate::durability::recovery::RecoveryStatus;
#[cfg(feature = "snapshot-crypto")]
use crate::replication::consensus::StrictFallbackState;
use crate::replication::consensus::{
    ConsensusCore, ConsensusCoreStateSnapshot, ConsensusCoreStatus, DurabilityProof, GateOperation,
    GateViolation, StrictFallbackBlockingReason, StrictFallbackMetricsPublisher, StrictFallbackWhy,
};
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
