use rand::{thread_rng, Rng};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum RetryStrategy {
    Linear,
    Exponential,
}

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    strategy: RetryStrategy,
    max_attempts: usize,
    base_delay: Duration,
    max_delay: Option<Duration>,
    jitter_fraction: f64,
    skip_first_delay: bool,
    time_budget: Option<Duration>,
}

impl RetryPolicy {
    pub fn linear(max_attempts: usize, base_delay: Duration) -> Self {
        Self::new(RetryStrategy::Linear, max_attempts, base_delay)
    }

    pub fn exponential(max_attempts: usize, base_delay: Duration) -> Self {
        Self::new(RetryStrategy::Exponential, max_attempts, base_delay)
    }

    fn new(strategy: RetryStrategy, max_attempts: usize, base_delay: Duration) -> Self {
        Self {
            strategy,
            max_attempts: max_attempts.max(1),
            base_delay,
            max_delay: None,
            jitter_fraction: 0.0,
            skip_first_delay: false,
            time_budget: None,
        }
    }

    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = if max_delay.is_zero() {
            None
        } else {
            Some(max_delay)
        };
        self
    }

    pub fn with_jitter(mut self, fraction: f64) -> Self {
        self.jitter_fraction = fraction.max(0.0);
        self
    }

    pub fn with_skip_first_delay(mut self, skip: bool) -> Self {
        self.skip_first_delay = skip;
        self
    }

    pub fn with_time_budget(mut self, budget: Option<Duration>) -> Self {
        self.time_budget = budget.filter(|duration| !duration.is_zero());
        self
    }

    pub fn handle(&self) -> RetryHandle {
        self.handle_from(Instant::now())
    }

    pub fn handle_from(&self, start: Instant) -> RetryHandle {
        let deadline = self
            .time_budget
            .and_then(|budget| start.checked_add(budget));
        RetryHandle {
            policy: self.clone(),
            attempts: 0,
            deadline,
        }
    }

    fn delay_for_attempt(&self, attempt: usize) -> Duration {
        if self.base_delay.is_zero() {
            return Duration::ZERO;
        }
        let raw = match self.strategy {
            RetryStrategy::Linear => self.base_delay.saturating_mul(attempt as u32),
            RetryStrategy::Exponential => {
                let shift = attempt.saturating_sub(1).min(31);
                let factor = 1u128 << shift;
                let base = self.base_delay.as_millis();
                let scaled = base.saturating_mul(factor);
                Duration::from_millis(scaled.min(u128::from(u64::MAX)) as u64)
            }
        };
        let bounded = if let Some(max) = self.max_delay.filter(|max| !max.is_zero()) {
            raw.min(max)
        } else {
            raw
        };
        if bounded.is_zero() || self.jitter_fraction <= 0.0 {
            bounded
        } else {
            let jitter = self.jitter_fraction.min(1.0);
            let min = (1.0 - jitter).max(0.0);
            let max = 1.0 + jitter;
            let factor = thread_rng().gen_range(min..=max);
            let millis = bounded.as_millis() as f64;
            let jittered = (millis * factor).round().max(0.0);
            Duration::from_millis(jittered.min(u128::from(u64::MAX) as f64) as u64)
        }
    }
}

pub struct RetryHandle {
    policy: RetryPolicy,
    attempts: usize,
    deadline: Option<Instant>,
}

impl RetryHandle {
    pub fn next_delay(&mut self) -> Option<Duration> {
        if self.attempts + 1 >= self.policy.max_attempts {
            return None;
        }
        let next = self.attempts + 1;
        let mut delay = self.policy.delay_for_attempt(next);
        if self.policy.skip_first_delay && next == 1 {
            delay = Duration::ZERO;
        }
        if let Some(deadline) = self.deadline {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            if !delay.is_zero() {
                match now.checked_add(delay) {
                    Some(next_instant) if next_instant <= deadline => {}
                    _ => return None,
                }
            }
        }
        self.attempts = next;
        Some(delay)
    }

    pub fn attempts(&self) -> usize {
        self.attempts
    }
}
