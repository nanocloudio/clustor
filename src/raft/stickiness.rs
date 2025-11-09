use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct DeviceLatencyConfig {
    pub max_device_latency_ms: u64,
    pub moving_average_window: Duration,
    pub degrade_consecutive: u32,
    pub recover_consecutive: u32,
}

impl Default for DeviceLatencyConfig {
    fn default() -> Self {
        Self {
            max_device_latency_ms: 20,
            moving_average_window: Duration::from_millis(500),
            degrade_consecutive: 3,
            recover_consecutive: 5,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LeaderStickinessConfig {
    pub min_leader_term: Duration,
    pub device_latency: DeviceLatencyConfig,
}

impl Default for LeaderStickinessConfig {
    fn default() -> Self {
        Self {
            min_leader_term: Duration::from_millis(750),
            device_latency: DeviceLatencyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyGuardReason {
    ConsecutiveSamples,
    MovingAverageExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickinessDecision {
    Maintain,
    PendingStepDown {
        reason: LatencyGuardReason,
        remaining_ms: u64,
    },
    StepDownRequired {
        reason: LatencyGuardReason,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct StickinessTelemetry {
    pub degraded: bool,
    pub moving_average_ms: u64,
    pub sample_count: usize,
    pub consecutive_high: u32,
    pub consecutive_low: u32,
    pub leader_uptime_ms: u64,
    pub min_leader_term_ms: u64,
}

pub struct LeaderStickinessController {
    config: LeaderStickinessConfig,
    leader_since: Instant,
    samples: VecDeque<(Instant, Duration)>,
    consecutive_high: u32,
    consecutive_low: u32,
    degraded: bool,
    last_reason: Option<LatencyGuardReason>,
}

impl LeaderStickinessController {
    pub fn new(config: LeaderStickinessConfig, leader_since: Instant) -> Self {
        Self {
            config,
            leader_since,
            samples: VecDeque::new(),
            consecutive_high: 0,
            consecutive_low: 0,
            degraded: false,
            last_reason: None,
        }
    }

    pub fn reset_leader(&mut self, now: Instant) {
        self.leader_since = now;
        self.degraded = false;
        self.consecutive_high = 0;
        self.consecutive_low = 0;
        self.samples.clear();
        self.last_reason = None;
    }

    pub fn record_fsync_sample(&mut self, sample: Duration, now: Instant) -> StickinessDecision {
        self.samples.push_back((now, sample));
        self.evict_stale_samples(now);

        let threshold = Duration::from_millis(self.config.device_latency.max_device_latency_ms);
        let recovery_threshold = threshold.mul_f64(0.8);

        if sample >= threshold {
            self.consecutive_high = self.consecutive_high.saturating_add(1);
            self.consecutive_low = 0;
        } else if sample <= recovery_threshold {
            self.consecutive_low = self.consecutive_low.saturating_add(1);
            self.consecutive_high = 0;
        } else {
            self.consecutive_high = 0;
            self.consecutive_low = 0;
        }

        if self.consecutive_high >= self.config.device_latency.degrade_consecutive {
            self.degraded = true;
            self.last_reason = Some(LatencyGuardReason::ConsecutiveSamples);
        }

        if (self.samples.len() as u32) >= self.config.device_latency.degrade_consecutive
            && self.moving_average() >= threshold
        {
            self.degraded = true;
            self.last_reason = Some(LatencyGuardReason::MovingAverageExceeded);
        }

        if self.degraded && self.consecutive_low >= self.config.device_latency.recover_consecutive {
            self.degraded = false;
            self.last_reason = None;
        }

        self.decision(now)
    }

    fn decision(&self, now: Instant) -> StickinessDecision {
        if !self.degraded {
            return StickinessDecision::Maintain;
        }

        let uptime = now.saturating_duration_since(self.leader_since);
        if uptime >= self.config.min_leader_term {
            StickinessDecision::StepDownRequired {
                reason: self
                    .last_reason
                    .unwrap_or(LatencyGuardReason::ConsecutiveSamples),
            }
        } else {
            StickinessDecision::PendingStepDown {
                reason: self
                    .last_reason
                    .unwrap_or(LatencyGuardReason::ConsecutiveSamples),
                remaining_ms: (self.config.min_leader_term - uptime).as_millis() as u64,
            }
        }
    }

    pub fn telemetry(&self, now: Instant) -> StickinessTelemetry {
        StickinessTelemetry {
            degraded: self.degraded,
            moving_average_ms: self.moving_average().as_millis() as u64,
            sample_count: self.samples.len(),
            consecutive_high: self.consecutive_high,
            consecutive_low: self.consecutive_low,
            leader_uptime_ms: now.saturating_duration_since(self.leader_since).as_millis() as u64,
            min_leader_term_ms: self.config.min_leader_term.as_millis() as u64,
        }
    }

    fn moving_average(&self) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let total_nanos: u128 = self
            .samples
            .iter()
            .map(|(_, sample)| sample.as_nanos())
            .sum();
        let average_nanos = total_nanos / (self.samples.len() as u128);
        Duration::from_nanos(average_nanos.min(u128::from(u64::MAX)) as u64)
    }

    fn evict_stale_samples(&mut self, now: Instant) {
        while let Some((ts, _)) = self.samples.front() {
            if now.duration_since(*ts) > self.config.device_latency.moving_average_window {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_down_requires_min_term() {
        let mut controller =
            LeaderStickinessController::new(LeaderStickinessConfig::default(), Instant::now());
        let now = controller.leader_since;
        let first = controller.record_fsync_sample(Duration::from_millis(30), now);
        assert!(matches!(first, StickinessDecision::Maintain));
        let second = controller
            .record_fsync_sample(Duration::from_millis(30), now + Duration::from_millis(1));
        assert!(matches!(second, StickinessDecision::Maintain));
        let third = controller
            .record_fsync_sample(Duration::from_millis(30), now + Duration::from_millis(2));
        assert!(matches!(third, StickinessDecision::PendingStepDown { .. }));

        let later = now + Duration::from_millis(1000);
        let decision = controller.record_fsync_sample(Duration::from_millis(25), later);
        assert!(matches!(
            decision,
            StickinessDecision::StepDownRequired { .. }
        ));
    }

    #[test]
    fn recovers_after_consecutive_low_samples() {
        let mut controller =
            LeaderStickinessController::new(LeaderStickinessConfig::default(), Instant::now());
        let start = controller.leader_since + Duration::from_millis(800);
        for i in 0..3 {
            controller
                .record_fsync_sample(Duration::from_millis(30), start + Duration::from_millis(i));
        }
        for i in 0..5 {
            let decision = controller.record_fsync_sample(
                Duration::from_millis(5),
                start + Duration::from_millis(100 + i as u64),
            );
            if i < 4 {
                assert!(matches!(
                    decision,
                    StickinessDecision::StepDownRequired { .. }
                ));
            } else {
                assert!(matches!(decision, StickinessDecision::Maintain));
            }
        }
    }
}
