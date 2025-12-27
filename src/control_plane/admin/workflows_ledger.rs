use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct IdempotencyLedger<T: Clone> {
    entries: HashMap<String, LedgerRecord<T>>,
    retention: Duration,
}

#[derive(Debug, Clone)]
struct LedgerRecord<T: Clone> {
    response: T,
    stored_at: Instant,
}

impl<T: Clone> IdempotencyLedger<T> {
    pub fn new(retention: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            retention,
        }
    }

    pub fn record(&mut self, key: String, response: T, now: Instant) {
        self.entries.insert(
            key,
            LedgerRecord {
                response,
                stored_at: now,
            },
        );
        self.evict(now);
    }

    pub fn get(&mut self, key: &str, now: Instant) -> Option<T> {
        self.evict(now);
        self.entries.get(key).map(|record| record.response.clone())
    }

    fn evict(&mut self, now: Instant) {
        self.entries
            .retain(|_, record| now.saturating_duration_since(record.stored_at) < self.retention);
    }

    pub fn retention(&self) -> Duration {
        self.retention
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
