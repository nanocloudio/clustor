use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub struct LearnerCatchUpConfig {
    pub max_index_slack: u64,
    pub max_byte_slack: u64,
    pub max_idle_ms: u64,
}

impl Default for LearnerCatchUpConfig {
    fn default() -> Self {
        Self {
            max_index_slack: 1_024,
            max_byte_slack: 32 * 1024 * 1024,
            max_idle_ms: 30_000,
        }
    }
}

#[derive(Debug, Clone)]
struct ProgressSample {
    index: u64,
    bytes: u64,
    at: Instant,
}

#[derive(Debug)]
pub struct LearnerCatchUpEvaluator {
    config: LearnerCatchUpConfig,
    last_progress: Option<ProgressSample>,
}

impl LearnerCatchUpEvaluator {
    pub fn new(config: LearnerCatchUpConfig) -> Self {
        Self {
            config,
            last_progress: None,
        }
    }

    pub fn record_progress(&mut self, index: u64, bytes: u64, now: Instant) {
        self.last_progress = Some(ProgressSample {
            index,
            bytes,
            at: now,
        });
    }

    pub fn evaluate(&self, leader_index: u64, leader_bytes: u64, now: Instant) -> CatchUpDecision {
        if let Some(progress) = &self.last_progress {
            let index_gap = leader_index.saturating_sub(progress.index);
            let byte_gap = leader_bytes.saturating_sub(progress.bytes);
            if index_gap > self.config.max_index_slack {
                return CatchUpDecision::Lagging {
                    reason: CatchUpReason::IndexGap { gap: index_gap },
                };
            }
            if byte_gap > self.config.max_byte_slack {
                return CatchUpDecision::Lagging {
                    reason: CatchUpReason::ByteGap { gap: byte_gap },
                };
            }
            if now.saturating_duration_since(progress.at).as_millis() as u64
                > self.config.max_idle_ms
            {
                return CatchUpDecision::Lagging {
                    reason: CatchUpReason::IdleTimeout {
                        idle_ms: now.saturating_duration_since(progress.at).as_millis() as u64,
                    },
                };
            }
            CatchUpDecision::Healthy
        } else {
            CatchUpDecision::Lagging {
                reason: CatchUpReason::NeverProgressed,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUpDecision {
    Healthy,
    Lagging { reason: CatchUpReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUpReason {
    IndexGap { gap: u64 },
    ByteGap { gap: u64 },
    IdleTimeout { idle_ms: u64 },
    NeverProgressed,
}
