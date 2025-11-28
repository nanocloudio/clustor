use crate::replication::consensus::StrictFallbackState;
use log::{info, warn};
use serde::Serialize;

use super::{
    SNAPSHOT_CATCHUP_THRESHOLD_BYTES, SNAPSHOT_LOG_BYTES_TARGET, SNAPSHOT_MAX_INTERVAL_MS,
    SNAPSHOT_ONLY_SPEC,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SnapshotExportTelemetry {
    pub chunk_rate_bytes_per_sec: u64,
    pub backlog_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SnapshotTriggerReason {
    LogBytes,
    Interval,
    FollowerLag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SnapshotTriggerDecision {
    pub should_trigger: bool,
    pub reason: Option<SnapshotTriggerReason>,
    pub log_bytes: u64,
    pub follower_lag_bytes: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SnapshotCadenceTelemetry {
    pub log_bytes_target: u64,
    pub catchup_threshold_bytes: u64,
    pub last_snapshot_ms: u64,
    pub idle_duration_ms: u64,
    pub pending_reason: Option<SnapshotTriggerReason>,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotTriggerConfig {
    pub log_bytes_target: u64,
    pub max_interval_ms: u64,
    pub catchup_threshold_bytes: u64,
}

impl Default for SnapshotTriggerConfig {
    fn default() -> Self {
        Self {
            log_bytes_target: SNAPSHOT_LOG_BYTES_TARGET,
            max_interval_ms: SNAPSHOT_MAX_INTERVAL_MS,
            catchup_threshold_bytes: SNAPSHOT_CATCHUP_THRESHOLD_BYTES,
        }
    }
}

impl SnapshotTriggerConfig {
    pub fn new(log_bytes_target: u64, max_interval_ms: u64, catchup_threshold_bytes: u64) -> Self {
        Self {
            log_bytes_target,
            max_interval_ms,
            catchup_threshold_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotTrigger {
    config: SnapshotTriggerConfig,
    last_snapshot_ms: Option<u64>,
    pending_reason: Option<SnapshotTriggerReason>,
}

impl SnapshotTrigger {
    pub fn new(config: SnapshotTriggerConfig) -> Self {
        Self {
            config,
            last_snapshot_ms: None,
            pending_reason: None,
        }
    }

    pub fn record_snapshot(&mut self, now_ms: u64) {
        self.last_snapshot_ms = Some(now_ms);
        self.pending_reason = None;
    }

    pub fn evaluate(
        &mut self,
        log_bytes: u64,
        follower_lag_bytes: u64,
        now_ms: u64,
    ) -> SnapshotTriggerDecision {
        let elapsed = self
            .last_snapshot_ms
            .map(|last| now_ms.saturating_sub(last))
            .unwrap_or(0);
        let reason = if log_bytes >= self.config.log_bytes_target {
            Some(SnapshotTriggerReason::LogBytes)
        } else if elapsed >= self.config.max_interval_ms {
            Some(SnapshotTriggerReason::Interval)
        } else if follower_lag_bytes >= self.config.catchup_threshold_bytes {
            Some(SnapshotTriggerReason::FollowerLag)
        } else {
            None
        };
        if reason.is_some() {
            self.pending_reason = reason;
        }
        SnapshotTriggerDecision {
            should_trigger: reason.is_some(),
            reason,
            log_bytes,
            follower_lag_bytes,
            elapsed_ms: elapsed,
        }
    }

    pub fn telemetry(&self, now_ms: u64) -> SnapshotCadenceTelemetry {
        let idle = self
            .last_snapshot_ms
            .map(|last| now_ms.saturating_sub(last))
            .unwrap_or(0);
        SnapshotCadenceTelemetry {
            log_bytes_target: self.config.log_bytes_target,
            catchup_threshold_bytes: self.config.catchup_threshold_bytes,
            last_snapshot_ms: self.last_snapshot_ms.unwrap_or(0),
            idle_duration_ms: idle,
            pending_reason: self.pending_reason,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotReadiness {
    pub manifest_id: String,
    pub base_index: u64,
    pub content_hash: String,
    pub applied_index_snapshot: u64,
    pub last_advertised_ready_index: u64,
    pub manifest_generated_ms: u64,
}

impl SnapshotReadiness {
    pub fn readiness_ratio(&self) -> f64 {
        if self.last_advertised_ready_index == 0 {
            return 0.0;
        }
        let ratio = self.applied_index_snapshot as f64 / self.last_advertised_ready_index as f64;
        ratio.clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotReadRequest {
    pub partition_id: String,
    pub read_semantics_snapshot_only: bool,
    pub strict_state: StrictFallbackState,
    pub cp_cache_age_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SnapshotReadResponse {
    pub manifest_id: String,
    pub base_index: u64,
    pub content_hash: String,
    pub applied_index: u64,
    pub readiness_ratio: f64,
    pub headers: SnapshotReadHeaders,
}

#[derive(Debug, Clone)]
pub struct SnapshotReadHeaders {
    pub snapshot_only: bool,
    pub snapshot_manifest_id: String,
    pub cp_cache_age_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SnapshotReadError {
    MissingSnapshotOnlyHeader,
    StrictStateUnavailable { state: StrictFallbackState },
    SnapshotOnlyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SnapshotOnlyReadyState {
    Healthy,
    Degraded,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotFallbackTelemetry {
    pub partition_ready_ratio_snapshot: f64,
    pub snapshot_manifest_age_ms: u64,
    pub snapshot_only_ready_state: SnapshotOnlyReadyState,
    pub snapshot_only_min_ready_ratio: f64,
    pub snapshot_only_slo_breach_total: u64,
}

#[derive(Debug, Clone)]
pub struct SnapshotFallbackController {
    readiness: SnapshotReadiness,
    min_ready_ratio: f64,
    slo_tracker: SnapshotSloTracker,
}

impl SnapshotFallbackController {
    pub const SNAPSHOT_ONLY_MIN_READY_RATIO: f64 = 0.80;

    pub fn new(readiness: SnapshotReadiness) -> Self {
        Self {
            readiness,
            min_ready_ratio: Self::SNAPSHOT_ONLY_MIN_READY_RATIO,
            slo_tracker: SnapshotSloTracker::new(400, 300_000),
        }
    }

    pub fn with_min_ready_ratio(mut self, ratio: f64) -> Self {
        self.min_ready_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    pub fn readiness(&self) -> &SnapshotReadiness {
        &self.readiness
    }

    pub fn update_readiness(&mut self, readiness: SnapshotReadiness) {
        self.readiness = readiness;
    }

    pub fn handle_request(
        &self,
        request: SnapshotReadRequest,
    ) -> Result<SnapshotReadResponse, SnapshotReadError> {
        if !request.read_semantics_snapshot_only {
            warn!(
                "event=snapshot_read_reject clause={} partition_id={} reason=missing_snapshot_only_header strict_state={:?}",
                SNAPSHOT_ONLY_SPEC,
                request.partition_id,
                request.strict_state
            );
            return Err(SnapshotReadError::MissingSnapshotOnlyHeader);
        }
        match request.strict_state {
            StrictFallbackState::LocalOnly | StrictFallbackState::ProofPublished => {}
            other => {
                warn!(
                    "event=snapshot_read_reject clause={} partition_id={} reason=strict_state_unavailable strict_state={:?}",
                    SNAPSHOT_ONLY_SPEC,
                    request.partition_id,
                    other
                );
                return Err(SnapshotReadError::StrictStateUnavailable { state: other });
            }
        }
        let ratio = self.readiness_ratio();
        if ratio + f64::EPSILON < self.min_ready_ratio {
            warn!(
                "event=snapshot_read_reject clause={} partition_id={} reason=readiness_ratio readiness_ratio={:.3} min_ready_ratio={} strict_state={:?}",
                SNAPSHOT_ONLY_SPEC,
                request.partition_id,
                ratio,
                self.min_ready_ratio,
                request.strict_state
            );
            return Err(SnapshotReadError::SnapshotOnlyUnavailable);
        }
        info!(
            "event=snapshot_read_grant clause={} partition_id={} readiness_ratio={:.3} min_ready_ratio={} strict_state={:?} cp_cache_age_ms={}",
            SNAPSHOT_ONLY_SPEC,
            request.partition_id,
            ratio,
            self.min_ready_ratio,
            request.strict_state,
            request.cp_cache_age_ms
        );
        Ok(SnapshotReadResponse {
            manifest_id: self.readiness.manifest_id.clone(),
            base_index: self.readiness.base_index,
            content_hash: self.readiness.content_hash.clone(),
            applied_index: self.readiness.applied_index_snapshot,
            readiness_ratio: ratio,
            headers: SnapshotReadHeaders {
                snapshot_only: true,
                snapshot_manifest_id: self.readiness.manifest_id.clone(),
                cp_cache_age_ms: request.cp_cache_age_ms,
            },
        })
    }

    pub fn telemetry(&self, now_ms: u64) -> SnapshotFallbackTelemetry {
        SnapshotFallbackTelemetry {
            partition_ready_ratio_snapshot: self.readiness_ratio(),
            snapshot_manifest_age_ms: now_ms.saturating_sub(self.readiness.manifest_generated_ms),
            snapshot_only_ready_state: self.ready_state(),
            snapshot_only_min_ready_ratio: self.min_ready_ratio,
            snapshot_only_slo_breach_total: self.slo_tracker.breaches(),
        }
    }

    pub fn record_snapshot_only_result(&mut self, latency_ms: u64, success: bool, now_ms: u64) {
        self.slo_tracker.record(latency_ms, success, now_ms);
    }

    fn readiness_ratio(&self) -> f64 {
        self.readiness.readiness_ratio()
    }

    fn ready_state(&self) -> SnapshotOnlyReadyState {
        let ratio = self.readiness_ratio();
        if ratio + f64::EPSILON < self.min_ready_ratio {
            if ratio <= f64::EPSILON {
                SnapshotOnlyReadyState::Expired
            } else {
                SnapshotOnlyReadyState::Degraded
            }
        } else {
            SnapshotOnlyReadyState::Healthy
        }
    }
}

#[derive(Debug, Clone)]
struct SnapshotSloTracker {
    window_start_ms: u64,
    window_total: u64,
    window_success: u64,
    latency_breach: bool,
    slo_latency_budget_ms: u64,
    slo_window_ms: u64,
    breaches: u64,
}

impl SnapshotSloTracker {
    fn new(latency_budget_ms: u64, window_ms: u64) -> Self {
        Self {
            window_start_ms: 0,
            window_total: 0,
            window_success: 0,
            latency_breach: false,
            slo_latency_budget_ms: latency_budget_ms,
            slo_window_ms: window_ms,
            breaches: 0,
        }
    }

    fn record(&mut self, latency_ms: u64, success: bool, now_ms: u64) {
        if self.window_start_ms == 0 {
            self.window_start_ms = now_ms;
        }
        if now_ms.saturating_sub(self.window_start_ms) > self.slo_window_ms {
            self.reset_window(now_ms);
        }
        self.window_total = self.window_total.saturating_add(1);
        if success {
            self.window_success = self.window_success.saturating_add(1);
        }
        if latency_ms > self.slo_latency_budget_ms {
            self.latency_breach = true;
        }
        let success_ratio = if self.window_total == 0 {
            1.0
        } else {
            self.window_success as f64 / self.window_total as f64
        };
        if success_ratio < 0.995 || self.latency_breach {
            self.breaches = self.breaches.saturating_add(1);
            self.reset_window(now_ms);
        }
    }

    fn reset_window(&mut self, now_ms: u64) {
        self.window_start_ms = now_ms;
        self.window_total = 0;
        self.window_success = 0;
        self.latency_breach = false;
    }

    fn breaches(&self) -> u64 {
        self.breaches
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotImportNodeTelemetrySnapshot {
    pub usage_bytes: u64,
    pub peak_usage_bytes: u64,
    pub limit_bytes: u64,
}
