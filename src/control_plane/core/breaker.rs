use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub(crate) struct CpCircuitBreaker {
    failures: u32,
    threshold: u32,
    cooldown: Duration,
    open_until: Option<Instant>,
}

impl CpCircuitBreaker {
    pub(crate) fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            failures: 0,
            threshold: threshold.max(1),
            cooldown,
            open_until: None,
        }
    }

    pub(crate) fn record_failure(&mut self, now: Instant) {
        if self.is_open(now) {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= self.threshold {
            self.open_until = Some(now + self.cooldown);
        }
    }

    pub(crate) fn record_success(&mut self) {
        self.failures = 0;
        self.open_until = None;
    }

    pub(crate) fn is_open(&mut self, now: Instant) -> bool {
        if let Some(until) = self.open_until {
            if now >= until {
                self.open_until = None;
                self.failures = 0;
                return false;
            }
            return true;
        }
        false
    }

    pub(crate) fn cooldown_remaining_ms(&self, now: Instant) -> Option<u64> {
        self.open_until
            .and_then(|until| until.checked_duration_since(now))
            .map(|duration| duration.as_millis() as u64)
    }
}
