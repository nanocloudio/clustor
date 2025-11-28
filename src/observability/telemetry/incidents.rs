use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct IncidentCorrelator {
    cooldown: Duration,
    last_event: HashMap<String, Instant>,
}

impl IncidentCorrelator {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            cooldown,
            last_event: HashMap::new(),
        }
    }

    pub fn record(&mut self, incident_key: impl Into<String>, now: Instant) -> IncidentDecision {
        let key = incident_key.into();
        match self.last_event.get(&key) {
            Some(last) if now.saturating_duration_since(*last) < self.cooldown => {
                IncidentDecision::Suppressed
            }
            _ => {
                self.last_event.insert(key, now);
                IncidentDecision::Triggered
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentDecision {
    Triggered,
    Suppressed,
}

#[derive(Debug, Default)]
pub struct CpDegradationMetrics {
    pub cache_warning_events: u64,
    pub cache_expired_events: u64,
    pub strict_only_transitions: u64,
}

impl CpDegradationMetrics {
    pub fn record_warning(&mut self) {
        self.cache_warning_events = self.cache_warning_events.saturating_add(1);
    }

    pub fn record_expired(&mut self) {
        self.cache_expired_events = self.cache_expired_events.saturating_add(1);
    }

    pub fn record_strict_only(&mut self) {
        self.strict_only_transitions = self.strict_only_transitions.saturating_add(1);
    }
}
