use log::{info, warn};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::pipeline::{SnapshotImportError, SnapshotQueueLimit};
use super::{SnapshotExportTelemetry, SNAPSHOT_THROTTLE_SPEC};

#[derive(Debug)]
pub struct SnapshotExportController {
    max_inflight_bytes: usize,
    rate_limit_bytes_per_sec: u64,
    backlog_bytes: usize,
    window_start: Option<Instant>,
    window_bytes: u64,
    last_rate: u64,
    last_state: SnapshotThrottleState,
}

impl SnapshotExportController {
    pub fn new(max_inflight_bytes: usize, rate_limit_bytes_per_sec: u64) -> Self {
        Self {
            max_inflight_bytes,
            rate_limit_bytes_per_sec,
            backlog_bytes: 0,
            window_start: None,
            window_bytes: 0,
            last_rate: 0,
            last_state: SnapshotThrottleState::Open,
        }
    }

    pub fn enqueue(&mut self, chunk_bytes: usize, now: Instant) -> SnapshotThrottleEnvelope {
        self.backlog_bytes = self.backlog_bytes.saturating_add(chunk_bytes);
        self.record_rate(chunk_bytes as u64, now);
        let envelope = self.envelope();
        self.log_envelope(&envelope, "enqueue");
        envelope
    }

    pub fn complete(&mut self, chunk_bytes: usize) {
        self.backlog_bytes = self.backlog_bytes.saturating_sub(chunk_bytes);
        let envelope = self.envelope();
        self.log_envelope(&envelope, "complete");
    }

    pub fn telemetry(&self) -> SnapshotExportTelemetry {
        SnapshotExportTelemetry {
            chunk_rate_bytes_per_sec: self.last_rate,
            backlog_bytes: self.backlog_bytes as u64,
        }
    }

    fn record_rate(&mut self, bytes: u64, now: Instant) {
        match self.window_start {
            Some(start) if now.duration_since(start) < Duration::from_secs(1) => {}
            _ => {
                self.window_start = Some(now);
                self.window_bytes = 0;
            }
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes);
        if self.rate_limit_bytes_per_sec == 0 {
            self.last_rate = self.window_bytes;
        } else {
            self.last_rate = self.window_bytes.min(self.rate_limit_bytes_per_sec);
        }
    }

    fn envelope(&self) -> SnapshotThrottleEnvelope {
        if self.backlog_bytes > self.max_inflight_bytes {
            SnapshotThrottleEnvelope {
                state: SnapshotThrottleState::Throttled(SnapshotThrottleReason::InFlightBytes {
                    buffered: self.backlog_bytes,
                    limit: self.max_inflight_bytes,
                }),
                buffered_bytes: self.backlog_bytes,
            }
        } else if self.rate_limit_bytes_per_sec > 0
            && self.window_bytes > self.rate_limit_bytes_per_sec
        {
            SnapshotThrottleEnvelope {
                state: SnapshotThrottleState::Throttled(SnapshotThrottleReason::RateLimit {
                    observed_bps: self.window_bytes,
                    limit_bps: self.rate_limit_bytes_per_sec,
                }),
                buffered_bytes: self.backlog_bytes,
            }
        } else {
            SnapshotThrottleEnvelope {
                state: SnapshotThrottleState::Open,
                buffered_bytes: self.backlog_bytes,
            }
        }
    }

    fn log_envelope(&mut self, envelope: &SnapshotThrottleEnvelope, phase: &str) {
        if self.last_state == envelope.state {
            return;
        }
        match &envelope.state {
            SnapshotThrottleState::Open => info!(
                "event=snapshot_throttle_open clause={} phase={} buffered_bytes={}",
                SNAPSHOT_THROTTLE_SPEC, phase, envelope.buffered_bytes
            ),
            SnapshotThrottleState::Throttled(reason) => warn!(
                "event=snapshot_throttle clause={} phase={} reason={:?} buffered_bytes={}",
                SNAPSHOT_THROTTLE_SPEC, phase, reason, envelope.buffered_bytes
            ),
        }
        self.last_state = envelope.state.clone();
    }
}

#[derive(Debug, Clone)]
pub struct AppendEntriesBatch {
    pub chunk_id: String,
    pub bytes: usize,
    pub entries: usize,
}

impl AppendEntriesBatch {
    pub fn new(chunk_id: impl Into<String>, bytes: usize, entries: usize) -> Self {
        Self {
            chunk_id: chunk_id.into(),
            bytes,
            entries,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotThrottleState {
    Open,
    Throttled(SnapshotThrottleReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotThrottleReason {
    InFlightBytes {
        buffered: usize,
        limit: usize,
    },
    RateLimit {
        observed_bps: u64,
        limit_bps: u64,
    },
    SnapshotImport {
        buffered_entries: usize,
        entry_limit: usize,
        buffered_bytes: usize,
        byte_limit: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotThrottleEnvelope {
    pub state: SnapshotThrottleState,
    pub buffered_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotImportConfig {
    pub max_inflight_bytes: usize,
    pub resume_ratio: f32,
    pub max_bytes_per_second: u64,
    pub max_inflight_entries: usize,
    pub max_inflight_batches: usize,
}

impl SnapshotImportConfig {
    pub fn new(max_inflight_bytes: usize) -> Self {
        Self {
            max_inflight_bytes,
            resume_ratio: 0.6,
            max_bytes_per_second: 0,
            max_inflight_entries: 8_192,
            max_inflight_batches: 512,
        }
    }

    pub fn with_resume_ratio(mut self, ratio: f32) -> Self {
        self.resume_ratio = ratio;
        self
    }

    pub fn with_bandwidth(mut self, max_bytes_per_second: u64) -> Self {
        self.max_bytes_per_second = max_bytes_per_second;
        self
    }

    pub fn with_entry_limit(mut self, max_entries: usize) -> Self {
        self.max_inflight_entries = max_entries;
        self
    }

    pub fn with_batch_limit(mut self, max_batches: usize) -> Self {
        self.max_inflight_batches = max_batches.max(1);
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct SnapshotImportTelemetry {
    throttle_events: u64,
    resume_events: u64,
    max_buffered_bytes: usize,
    last_reason: Option<SnapshotThrottleReason>,
}

impl SnapshotImportTelemetry {
    fn record_transition(
        &mut self,
        previous: &SnapshotThrottleState,
        current: &SnapshotThrottleState,
        buffered: usize,
    ) {
        if buffered > self.max_buffered_bytes {
            self.max_buffered_bytes = buffered;
        }
        match (previous, current) {
            (SnapshotThrottleState::Open, SnapshotThrottleState::Throttled(reason)) => {
                self.throttle_events += 1;
                self.last_reason = Some(reason.clone());
            }
            (SnapshotThrottleState::Throttled(_), SnapshotThrottleState::Throttled(reason)) => {
                self.last_reason = Some(reason.clone());
            }
            (SnapshotThrottleState::Throttled(_), SnapshotThrottleState::Open) => {
                self.resume_events += 1;
            }
            _ => {}
        }
    }

    fn snapshot(&self) -> SnapshotImportTelemetrySnapshot {
        SnapshotImportTelemetrySnapshot {
            throttle_events: self.throttle_events,
            resume_events: self.resume_events,
            max_buffered_bytes: self.max_buffered_bytes,
            last_reason: self.last_reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotImportTelemetrySnapshot {
    pub throttle_events: u64,
    pub resume_events: u64,
    pub max_buffered_bytes: usize,
    pub last_reason: Option<SnapshotThrottleReason>,
}

#[derive(Debug)]
pub struct SnapshotAppendEntriesCoordinator {
    config: SnapshotImportConfig,
    buffered_bytes: usize,
    buffered_entries: usize,
    inflight: VecDeque<AppendEntriesBatch>,
    telemetry: SnapshotImportTelemetry,
    last_state: SnapshotThrottleState,
    rate_window_start: Instant,
    rate_window_bytes: u64,
}

impl SnapshotAppendEntriesCoordinator {
    pub fn new(max_inflight_bytes: usize) -> Self {
        Self::with_config(SnapshotImportConfig::new(max_inflight_bytes))
    }

    pub fn with_config(config: SnapshotImportConfig) -> Self {
        Self {
            config,
            buffered_bytes: 0,
            buffered_entries: 0,
            inflight: VecDeque::new(),
            telemetry: SnapshotImportTelemetry::default(),
            last_state: SnapshotThrottleState::Open,
            rate_window_start: Instant::now(),
            rate_window_bytes: 0,
        }
    }

    pub fn enqueue(
        &mut self,
        batch: AppendEntriesBatch,
    ) -> Result<SnapshotThrottleEnvelope, SnapshotImportError> {
        self.enqueue_at(batch, Instant::now())
    }

    pub fn enqueue_at(
        &mut self,
        batch: AppendEntriesBatch,
        now: Instant,
    ) -> Result<SnapshotThrottleEnvelope, SnapshotImportError> {
        self.ensure_queue_capacity(&batch)?;
        self.buffered_bytes += batch.bytes;
        self.buffered_entries += batch.entries;
        let bytes = batch.bytes;
        self.inflight.push_back(batch);
        self.record_transfer(bytes_to_u64(bytes), now);
        Ok(self.envelope_at(now))
    }

    pub fn complete(
        &mut self,
        chunk_id: &str,
    ) -> Result<SnapshotThrottleEnvelope, SnapshotImportError> {
        self.complete_at(chunk_id, Instant::now())
    }

    pub fn complete_at(
        &mut self,
        chunk_id: &str,
        now: Instant,
    ) -> Result<SnapshotThrottleEnvelope, SnapshotImportError> {
        let pos = self
            .inflight
            .iter()
            .position(|batch| batch.chunk_id == chunk_id)
            .ok_or_else(|| SnapshotImportError::UnknownChunk {
                chunk_id: chunk_id.to_string(),
            })?;
        let batch = self
            .inflight
            .remove(pos)
            .ok_or_else(|| SnapshotImportError::UnknownChunk {
                chunk_id: chunk_id.to_string(),
            })?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(batch.bytes);
        self.buffered_entries = self.buffered_entries.saturating_sub(batch.entries);
        self.refresh_rate_window(now);
        Ok(self.envelope_at(now))
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn buffered_entries(&self) -> usize {
        self.buffered_entries
    }

    pub fn inflight_batches(&self) -> impl Iterator<Item = &AppendEntriesBatch> {
        self.inflight.iter()
    }

    pub fn telemetry(&self) -> SnapshotImportTelemetrySnapshot {
        self.telemetry.snapshot()
    }

    pub fn config(&self) -> SnapshotImportConfig {
        self.config
    }

    fn envelope_at(&mut self, now: Instant) -> SnapshotThrottleEnvelope {
        self.refresh_rate_window(now);
        let mut reason = None;
        if let Some(buffer_reason) = self.import_limit_reason() {
            reason = Some(buffer_reason);
        } else if let Some(rate_reason) = self.rate_limit_reason() {
            reason = Some(rate_reason);
        }

        let state = match reason {
            Some(reason) => SnapshotThrottleState::Throttled(reason),
            None => SnapshotThrottleState::Open,
        };
        self.telemetry
            .record_transition(&self.last_state, &state, self.buffered_bytes);
        self.last_state = state.clone();
        SnapshotThrottleEnvelope {
            state,
            buffered_bytes: self.buffered_bytes,
        }
    }

    fn import_limit_reason(&self) -> Option<SnapshotThrottleReason> {
        let entry_cap = self.config.max_inflight_entries;
        let byte_cap = self.config.max_inflight_bytes;
        let entries_over_limit = self.buffered_entries >= entry_cap;
        let bytes_over_limit = self.buffered_bytes >= byte_cap;
        let throttled_due_to_import = matches!(
            self.last_state,
            SnapshotThrottleState::Throttled(SnapshotThrottleReason::SnapshotImport { .. })
        );
        if throttled_due_to_import {
            let entries_above_resume = self.buffered_entries > self.resume_entry_threshold();
            let bytes_above_resume = self.buffered_bytes > self.resume_byte_threshold();
            if !entries_above_resume && !bytes_above_resume {
                return None;
            }
        } else if !entries_over_limit && !bytes_over_limit {
            return None;
        }
        if entries_over_limit || bytes_over_limit {
            return Some(SnapshotThrottleReason::SnapshotImport {
                buffered_entries: self.buffered_entries,
                entry_limit: entry_cap,
                buffered_bytes: self.buffered_bytes,
                byte_limit: byte_cap,
            });
        }
        None
    }

    fn resume_byte_threshold(&self) -> usize {
        let ratio = self.config.resume_ratio.clamp(0.0, 1.0);
        ((self.config.max_inflight_bytes as f32) * ratio).ceil() as usize
    }

    fn resume_entry_threshold(&self) -> usize {
        let ratio = self.config.resume_ratio.clamp(0.0, 1.0);
        ((self.config.max_inflight_entries as f32) * ratio).ceil() as usize
    }

    fn ensure_queue_capacity(&self, batch: &AppendEntriesBatch) -> Result<(), SnapshotImportError> {
        let next_bytes = self.buffered_bytes.saturating_add(batch.bytes);
        if next_bytes > self.config.max_inflight_bytes {
            return Err(SnapshotImportError::QueueLimit {
                kind: SnapshotQueueLimit::Bytes,
                observed: next_bytes,
                limit: self.config.max_inflight_bytes,
            });
        }
        let next_entries = self.buffered_entries.saturating_add(batch.entries);
        if next_entries > self.config.max_inflight_entries {
            return Err(SnapshotImportError::QueueLimit {
                kind: SnapshotQueueLimit::Entries,
                observed: next_entries,
                limit: self.config.max_inflight_entries,
            });
        }
        if self.inflight.len() >= self.config.max_inflight_batches {
            return Err(SnapshotImportError::QueueLimit {
                kind: SnapshotQueueLimit::Batches,
                observed: self.inflight.len().saturating_add(1),
                limit: self.config.max_inflight_batches,
            });
        }
        Ok(())
    }

    fn record_transfer(&mut self, bytes: u64, now: Instant) {
        if self.config.max_bytes_per_second == 0 {
            return;
        }
        self.refresh_rate_window(now);
        self.rate_window_bytes = self.rate_window_bytes.saturating_add(bytes);
    }

    fn refresh_rate_window(&mut self, now: Instant) {
        if now.duration_since(self.rate_window_start) >= Duration::from_secs(1) {
            self.rate_window_start = now;
            self.rate_window_bytes = 0;
        }
    }

    fn rate_limit_reason(&self) -> Option<SnapshotThrottleReason> {
        if self.config.max_bytes_per_second == 0 {
            return None;
        }
        if self.rate_window_bytes > self.config.max_bytes_per_second {
            Some(SnapshotThrottleReason::RateLimit {
                observed_bps: self.rate_window_bytes,
                limit_bps: self.config.max_bytes_per_second,
            })
        } else {
            None
        }
    }
}

fn bytes_to_u64(bytes: usize) -> u64 {
    bytes.try_into().unwrap_or(u64::MAX)
}
