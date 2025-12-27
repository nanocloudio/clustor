use crate::profile::PartitionProfile;
use crate::telemetry::MetricsRegistry;
use crate::terminology::{
    RuntimeTerm, TERM_FOLLOWER_READ_SNAPSHOT, TERM_GROUP_FSYNC, TERM_LEASE_ENABLE,
    TERM_SNAPSHOT_DELTA, TERM_STRICT,
};
use log::{info, warn};
use serde::Serialize;
use std::time::{Duration, Instant};

const STRICT_FALLBACK_SPEC: &str = "§3.1.1.StrictFallback";
const STRICT_GATE_SPEC: &str = "§3.3.ReadIndex";

/// Telemetry-facing strict fallback states from §0.5 / §2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StrictFallbackState {
    Healthy,
    LocalOnly,
    /// CP acknowledged the proof and cleared the gate. Behaves like `Healthy`.
    ProofPublished,
}

impl StrictFallbackState {
    pub fn as_metric(self) -> u64 {
        match self {
            StrictFallbackState::Healthy => 0,
            StrictFallbackState::LocalOnly => 1,
            StrictFallbackState::ProofPublished => 2,
        }
    }
}

/// Configuration knobs lifted directly from the specification.
#[derive(Debug, Clone)]
pub struct ConsensusCoreConfig {
    alert_after: Duration,
    local_only_demote_after: Duration,
}

impl ConsensusCoreConfig {
    pub const DEFAULT_ALERT_MS: u64 = 30_000;
    pub const DEFAULT_LOCAL_ONLY_DEMOTE_MS: u64 = 14_400_000;

    pub fn new(alert_after: Duration, local_only_demote_after: Duration) -> Self {
        Self {
            alert_after,
            local_only_demote_after,
        }
    }

    pub fn alert_after(&self) -> Duration {
        self.alert_after
    }

    pub fn local_only_demote_after(&self) -> Duration {
        self.local_only_demote_after
    }

    pub fn for_profile(profile: PartitionProfile) -> Self {
        let config = profile.config();
        Self {
            alert_after: Duration::from_millis(Self::DEFAULT_ALERT_MS),
            local_only_demote_after: Duration::from_millis(
                config.strict_fallback_local_only_demote_ms,
            ),
        }
    }
}

impl Default for ConsensusCoreConfig {
    fn default() -> Self {
        Self {
            alert_after: Duration::from_millis(Self::DEFAULT_ALERT_MS),
            local_only_demote_after: Duration::from_millis(Self::DEFAULT_LOCAL_ONLY_DEMOTE_MS),
        }
    }
}

/// `(term, index)` pair representing the durability proof horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DurabilityProof {
    pub term: u64,
    pub index: u64,
}

impl DurabilityProof {
    pub fn new(term: u64, index: u64) -> Self {
        Self { term, index }
    }
}

/// Operations that the strict-fallback gate mediates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GateOperation {
    EnableGroupFsync,
    EnableLeaseReads,
    GrantFollowerReadSnapshotCapability,
    EnableSnapshotDelta,
    ReadIndex,
}

impl GateOperation {
    pub fn metric_label(&self) -> &'static str {
        match self {
            GateOperation::EnableGroupFsync => "DurabilityTransitionToGroup",
            GateOperation::EnableLeaseReads => "LeaseEnable",
            GateOperation::GrantFollowerReadSnapshotCapability => "FollowerCapabilityGrant",
            GateOperation::EnableSnapshotDelta => "SnapshotDeltaEnable",
            GateOperation::ReadIndex => "ReadIndex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GateViolation {
    ModeConflictStrictFallback,
    CpUnavailableNeededForReadIndex,
    CpUnavailableCacheExpired,
    FollowerCapabilityRevoked,
}

/// Prioritized rejection reasons per §0.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StrictFallbackBlockingReason {
    CacheExpired,
    NeededForReadIndex,
    ModeConflictStrictFallback,
    CircuitBreakerOpen,
}

impl StrictFallbackBlockingReason {
    fn metric_label(&self) -> &'static str {
        match self {
            StrictFallbackBlockingReason::CacheExpired => "CacheExpired",
            StrictFallbackBlockingReason::NeededForReadIndex => "NeededForReadIndex",
            StrictFallbackBlockingReason::ModeConflictStrictFallback => {
                "ModeConflictStrictFallback"
            }
            StrictFallbackBlockingReason::CircuitBreakerOpen => "CircuitBreakerOpen",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GateEvaluation {
    pub operation: GateOperation,
    pub allowed: bool,
    pub violation: Option<GateViolation>,
}

impl GateEvaluation {
    pub fn allow(operation: GateOperation) -> Self {
        Self {
            operation,
            allowed: true,
            violation: None,
        }
    }

    pub fn reject(operation: GateOperation, violation: GateViolation) -> Self {
        Self {
            operation,
            allowed: false,
            violation: Some(violation),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DemotionReason {
    LocalOnlyTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DemotionStatus {
    pub should_demote: bool,
    pub reason: Option<DemotionReason>,
}

impl DemotionStatus {
    pub fn none() -> Self {
        Self {
            should_demote: false,
            reason: None,
        }
    }

    pub fn timeout() -> Self {
        Self {
            should_demote: true,
            reason: Some(DemotionReason::LocalOnlyTimeout),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusCoreStatus {
    pub state: StrictFallbackState,
    pub strict_fallback: bool,
    pub pending_entries: u64,
    pub local_only_duration: Option<Duration>,
    pub should_alert: bool,
    pub demotion: DemotionStatus,
    pub last_local_proof: Option<DurabilityProof>,
    pub last_published_proof: Option<DurabilityProof>,
    pub decision_epoch: u64,
    pub blocking_reason: Option<StrictFallbackBlockingReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateBlockMetrics {
    pub durability_transition_to_group: u64,
    pub lease_enable: u64,
    pub follower_capability_grant: u64,
    pub snapshot_delta_enable: u64,
    pub read_index: u64,
}

impl GateBlockMetrics {
    fn bump(&mut self, operation: GateOperation) {
        match operation {
            GateOperation::EnableGroupFsync => {
                self.durability_transition_to_group =
                    self.durability_transition_to_group.saturating_add(1);
            }
            GateOperation::EnableLeaseReads => {
                self.lease_enable = self.lease_enable.saturating_add(1);
            }
            GateOperation::GrantFollowerReadSnapshotCapability => {
                self.follower_capability_grant = self.follower_capability_grant.saturating_add(1);
            }
            GateOperation::EnableSnapshotDelta => {
                self.snapshot_delta_enable = self.snapshot_delta_enable.saturating_add(1);
            }
            GateOperation::ReadIndex => {
                self.read_index = self.read_index.saturating_add(1);
            }
        }
    }

    fn spec_counts(&self) -> [(&'static str, u64); 4] {
        [
            (
                GateOperation::EnableGroupFsync.metric_label(),
                self.durability_transition_to_group,
            ),
            (
                GateOperation::EnableLeaseReads.metric_label(),
                self.lease_enable,
            ),
            (
                GateOperation::GrantFollowerReadSnapshotCapability.metric_label(),
                self.follower_capability_grant,
            ),
            (
                GateOperation::EnableSnapshotDelta.metric_label(),
                self.snapshot_delta_enable,
            ),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusCoreTelemetry {
    pub state: StrictFallbackState,
    pub blocking_read_index: bool,
    pub pending_entries: u64,
    pub last_local_proof: Option<DurabilityProof>,
    pub last_published_proof: Option<DurabilityProof>,
    pub alert_active: bool,
    pub demotion: DemotionStatus,
    pub gate_blocks: GateBlockMetrics,
    pub decision_epoch: u64,
    pub blocking_reason: Option<StrictFallbackBlockingReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusCoreStateSnapshot {
    pub state: StrictFallbackState,
    pub strict_fallback: bool,
    pub pending_entries: u64,
    pub last_local_proof: Option<DurabilityProof>,
    pub last_published_proof: Option<DurabilityProof>,
    pub decision_epoch: u64,
    pub blocking_reason: Option<StrictFallbackBlockingReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrictFallbackWhy {
    pub operation: GateOperation,
    pub violation: GateViolation,
    pub state: StrictFallbackState,
    pub pending_entries: u64,
    pub last_local_proof: Option<DurabilityProof>,
    pub local_only_duration: Option<Duration>,
    pub operation_term: Option<RuntimeTerm>,
    pub decision_epoch: u64,
    pub blocking_reason: StrictFallbackBlockingReason,
}

#[derive(Debug)]
pub struct ConsensusCore {
    config: ConsensusCoreConfig,
    state: StrictFallbackState,
    strict_fallback: bool,
    local_only_since: Option<Instant>,
    override_expires_at: Option<Instant>,
    pending_entries: u64,
    last_local_proof: Option<DurabilityProof>,
    last_published_proof: Option<DurabilityProof>,
    gate_blocks: GateBlockMetrics,
    decision_epoch: u64,
    blocking_reason: Option<StrictFallbackBlockingReason>,
}

impl ConsensusCore {
    pub fn new(config: ConsensusCoreConfig) -> Self {
        Self {
            config,
            state: StrictFallbackState::Healthy,
            strict_fallback: false,
            local_only_since: None,
            override_expires_at: None,
            pending_entries: 0,
            last_local_proof: None,
            last_published_proof: None,
            gate_blocks: GateBlockMetrics::default(),
            decision_epoch: 0,
            blocking_reason: None,
        }
    }

    pub fn config(&self) -> &ConsensusCoreConfig {
        &self.config
    }

    pub fn state(&self) -> StrictFallbackState {
        self.state
    }

    pub fn is_strict_fallback(&self) -> bool {
        self.strict_fallback
    }

    pub fn pending_entries(&self) -> u64 {
        self.pending_entries
    }

    pub fn gate_blocks(&self) -> GateBlockMetrics {
        self.gate_blocks
    }

    pub fn last_local_proof(&self) -> Option<DurabilityProof> {
        self.last_local_proof
    }

    pub fn last_published_proof(&self) -> Option<DurabilityProof> {
        self.last_published_proof
    }

    pub fn decision_epoch(&self) -> u64 {
        self.decision_epoch
    }

    pub fn blocking_reason(&self) -> Option<StrictFallbackBlockingReason> {
        self.blocking_reason
    }

    pub fn record_blocking_reason(&mut self, reason: StrictFallbackBlockingReason) {
        self.blocking_reason = Some(reason);
    }

    fn bump_decision_epoch(&mut self) {
        self.decision_epoch = self.decision_epoch.saturating_add(1);
    }

    pub fn enter_strict_fallback(&mut self, proof: DurabilityProof, now: Instant) {
        let transitioned = !matches!(self.state, StrictFallbackState::LocalOnly);
        self.last_local_proof = Some(proof);
        self.strict_fallback = true;
        self.blocking_reason = None;
        if transitioned {
            self.state = StrictFallbackState::LocalOnly;
            self.local_only_since = Some(now);
            self.bump_decision_epoch();
            info!(
                "event=strict_fallback_state clause={} next_state=LocalOnly term={} index={} term_id={} decision_epoch={}",
                STRICT_FALLBACK_SPEC,
                proof.term,
                proof.index,
                TERM_STRICT.term_id,
                self.decision_epoch
            );
        }
    }

    pub fn mark_proof_published(&mut self, proof: DurabilityProof) {
        let state_changed = !matches!(self.state, StrictFallbackState::ProofPublished);
        self.last_published_proof = Some(proof);
        self.state = StrictFallbackState::ProofPublished;
        self.strict_fallback = false;
        self.local_only_since = None;
        self.override_expires_at = None;
        self.pending_entries = 0;
        self.blocking_reason = None;
        if state_changed {
            self.bump_decision_epoch();
            info!(
                "event=strict_fallback_state clause={} next_state=ProofPublished term={} index={} decision_epoch={}",
                STRICT_FALLBACK_SPEC,
                proof.term,
                proof.index,
                self.decision_epoch
            );
        }
    }

    pub fn mark_healthy(&mut self) {
        let state_changed = !matches!(self.state, StrictFallbackState::Healthy);
        self.state = StrictFallbackState::Healthy;
        self.strict_fallback = false;
        self.local_only_since = None;
        self.override_expires_at = None;
        self.blocking_reason = None;
        if state_changed {
            self.bump_decision_epoch();
            info!(
                "event=strict_fallback_state clause={} next_state=Healthy decision_epoch={}",
                STRICT_FALLBACK_SPEC, self.decision_epoch
            );
        }
    }

    pub fn register_strict_write(&mut self) {
        if self.strict_fallback {
            self.pending_entries = self.pending_entries.saturating_add(1);
        }
    }

    pub fn evaluate_gate(&self, operation: GateOperation) -> GateEvaluation {
        if !self.is_strict_fallback() {
            return GateEvaluation::allow(operation);
        }

        let violation = match operation {
            GateOperation::EnableGroupFsync => GateViolation::ModeConflictStrictFallback,
            GateOperation::EnableLeaseReads => GateViolation::CpUnavailableNeededForReadIndex,
            GateOperation::GrantFollowerReadSnapshotCapability => {
                GateViolation::FollowerCapabilityRevoked
            }
            GateOperation::EnableSnapshotDelta => GateViolation::CpUnavailableCacheExpired,
            GateOperation::ReadIndex => GateViolation::CpUnavailableNeededForReadIndex,
        };

        GateEvaluation::reject(operation, violation)
    }

    pub fn guard(&mut self, operation: GateOperation) -> Result<(), GateViolation> {
        let evaluation = self.evaluate_gate(operation);
        if evaluation.allowed {
            Ok(())
        } else {
            self.record_gate_block(&evaluation);
            debug_assert!(
                evaluation.violation.is_some(),
                "gate evaluation must include violation when rejected"
            );
            Err(evaluation
                .violation
                .unwrap_or(GateViolation::ModeConflictStrictFallback))
        }
    }

    pub fn record_gate_block(&mut self, evaluation: &GateEvaluation) {
        if !evaluation.allowed {
            let Some(violation) = evaluation.violation else {
                debug_assert!(
                    false,
                    "blocked evaluation must include violation (operation={:?})",
                    evaluation.operation
                );
                return;
            };
            self.gate_blocks.bump(evaluation.operation);
            let reason = Self::blocking_reason_for_violation(violation);
            self.record_blocking_reason(reason);
            warn!(
                "event=strict_fallback_gate clause={} operation={:?} violation={:?} blocking_reason={:?} state={:?} pending_entries={} term_id={}",
                STRICT_GATE_SPEC,
                evaluation.operation,
                violation,
                reason,
                self.state,
                self.pending_entries,
                TERM_STRICT.term_id
            );
        }
    }

    pub fn renew_local_only_override(&mut self, ttl: Duration, now: Instant) {
        self.override_expires_at = now.checked_add(ttl);
        self.bump_decision_epoch();
    }

    pub fn clear_local_only_override(&mut self) {
        if self.override_expires_at.take().is_some() {
            self.bump_decision_epoch();
        }
    }

    pub fn local_only_override_active(&self, now: Instant) -> bool {
        matches!(self.override_expires_at, Some(expires) if expires > now)
    }

    pub fn status(&self, now: Instant) -> ConsensusCoreStatus {
        let local_only_duration = self.local_only_duration(now);
        let should_alert = matches!(self.state, StrictFallbackState::LocalOnly)
            && local_only_duration
                .map(|elapsed| elapsed >= self.config.alert_after())
                .unwrap_or(false);

        let should_demote = matches!(self.state, StrictFallbackState::LocalOnly)
            && !self.local_only_override_active(now)
            && local_only_duration
                .map(|elapsed| elapsed >= self.config.local_only_demote_after())
                .unwrap_or(false);

        ConsensusCoreStatus {
            state: self.state,
            strict_fallback: self.strict_fallback,
            pending_entries: self.pending_entries,
            local_only_duration,
            should_alert,
            demotion: if should_demote {
                DemotionStatus::timeout()
            } else {
                DemotionStatus::none()
            },
            last_local_proof: self.last_local_proof,
            last_published_proof: self.last_published_proof,
            decision_epoch: self.decision_epoch,
            blocking_reason: self.blocking_reason,
        }
    }

    pub fn telemetry(&self, now: Instant) -> ConsensusCoreTelemetry {
        let status = self.status(now);
        ConsensusCoreTelemetry {
            state: status.state,
            blocking_read_index: status.strict_fallback,
            pending_entries: status.pending_entries,
            last_local_proof: status.last_local_proof,
            last_published_proof: status.last_published_proof,
            alert_active: status.should_alert,
            demotion: status.demotion,
            gate_blocks: self.gate_blocks,
            decision_epoch: status.decision_epoch,
            blocking_reason: status.blocking_reason,
        }
    }

    pub fn snapshot_state(&self) -> ConsensusCoreStateSnapshot {
        ConsensusCoreStateSnapshot {
            state: self.state,
            strict_fallback: self.strict_fallback,
            pending_entries: self.pending_entries,
            last_local_proof: self.last_local_proof,
            last_published_proof: self.last_published_proof,
            decision_epoch: self.decision_epoch,
            blocking_reason: self.blocking_reason,
        }
    }

    pub fn explain_gate(
        &self,
        evaluation: &GateEvaluation,
        now: Instant,
    ) -> Option<StrictFallbackWhy> {
        let violation = evaluation.violation?;
        let operation_term = match evaluation.operation {
            GateOperation::EnableGroupFsync => Some(TERM_GROUP_FSYNC),
            GateOperation::EnableLeaseReads => Some(TERM_LEASE_ENABLE),
            GateOperation::GrantFollowerReadSnapshotCapability => Some(TERM_FOLLOWER_READ_SNAPSHOT),
            GateOperation::EnableSnapshotDelta => Some(TERM_SNAPSHOT_DELTA),
            _ => None,
        };
        Some(StrictFallbackWhy {
            operation: evaluation.operation,
            violation,
            state: self.state,
            pending_entries: self.pending_entries,
            last_local_proof: self.last_local_proof,
            local_only_duration: self.local_only_duration(now),
            operation_term,
            decision_epoch: self.decision_epoch,
            blocking_reason: Self::blocking_reason_for_violation(violation),
        })
    }

    fn local_only_duration(&self, now: Instant) -> Option<Duration> {
        self.local_only_since
            .map(|since| now.saturating_duration_since(since))
    }

    fn blocking_reason_for_violation(violation: GateViolation) -> StrictFallbackBlockingReason {
        match violation {
            GateViolation::CpUnavailableCacheExpired => StrictFallbackBlockingReason::CacheExpired,
            GateViolation::CpUnavailableNeededForReadIndex => {
                StrictFallbackBlockingReason::NeededForReadIndex
            }
            GateViolation::ModeConflictStrictFallback
            | GateViolation::FollowerCapabilityRevoked => {
                StrictFallbackBlockingReason::ModeConflictStrictFallback
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct StrictFallbackMetricsPublisher {
    last_gate_blocks: GateBlockMetrics,
}

impl StrictFallbackMetricsPublisher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&mut self, registry: &mut MetricsRegistry, telemetry: &ConsensusCoreTelemetry) {
        registry.set_gauge(
            "strict_fallback_blocking_read_index",
            telemetry.blocking_read_index as u64,
        );
        registry.set_gauge("strict_fallback_state", telemetry.state.as_metric());
        registry.set_gauge("strict_fallback_pending_entries", telemetry.pending_entries);
        registry.set_gauge("strict_fallback_decision_epoch", telemetry.decision_epoch);

        let (term, index) = telemetry
            .last_local_proof
            .map(|proof| (proof.term, proof.index))
            .unwrap_or((0, 0));
        registry.set_gauge("strict_fallback_last_local_proof.term", term);
        registry.set_gauge("strict_fallback_last_local_proof.index", index);

        self.publish_blocking_reasons(registry, telemetry.blocking_reason);
        self.publish_gate_counters(registry, telemetry.gate_blocks);

        // Maintain last gate snapshot for delta computation.
        self.last_gate_blocks = telemetry.gate_blocks;
    }

    fn publish_blocking_reasons(
        &self,
        registry: &mut MetricsRegistry,
        active: Option<StrictFallbackBlockingReason>,
    ) {
        const REASONS: [StrictFallbackBlockingReason; 4] = [
            StrictFallbackBlockingReason::CacheExpired,
            StrictFallbackBlockingReason::NeededForReadIndex,
            StrictFallbackBlockingReason::ModeConflictStrictFallback,
            StrictFallbackBlockingReason::CircuitBreakerOpen,
        ];
        for reason in REASONS {
            let value = if Some(reason) == active { 1 } else { 0 };
            registry.set_gauge(
                format!("strict_fallback_blocking_reason.{}", reason.metric_label()),
                value,
            );
        }
        registry.set_gauge(
            "strict_fallback_blocking_reason.None",
            if active.is_none() { 1 } else { 0 },
        );
    }

    fn publish_gate_counters(&self, registry: &mut MetricsRegistry, current: GateBlockMetrics) {
        for (label, value) in current.spec_counts() {
            let previous = match label {
                "DurabilityTransitionToGroup" => {
                    self.last_gate_blocks.durability_transition_to_group
                }
                "LeaseEnable" => self.last_gate_blocks.lease_enable,
                "FollowerCapabilityGrant" => self.last_gate_blocks.follower_capability_grant,
                "SnapshotDeltaEnable" => self.last_gate_blocks.snapshot_delta_enable,
                _ => 0,
            };
            if value > previous {
                registry.inc_counter(
                    format!("strict_fallback_gate_blocked.{}", label),
                    value - previous,
                );
            }
        }
    }
}
