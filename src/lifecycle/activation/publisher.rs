use std::collections::HashMap;

use super::state::{WarmupReadinessRecord, WarmupReadinessSnapshot};

#[derive(Debug)]
pub struct WarmupReadinessPublisher {
    publish_period_ms: u64,
    skipped_publications_total: u64,
    last_publish_ms: Option<u64>,
    records: HashMap<String, WarmupReadinessRecord>,
}

impl WarmupReadinessPublisher {
    pub fn new(publish_period_ms: u64) -> Self {
        Self {
            publish_period_ms: publish_period_ms.max(1),
            skipped_publications_total: 0,
            last_publish_ms: None,
            records: HashMap::new(),
        }
    }

    pub fn publish_period_ms(&self) -> u64 {
        self.publish_period_ms
    }

    pub fn skipped_publications_total(&self) -> u64 {
        self.skipped_publications_total
    }

    pub fn upsert(&mut self, record: WarmupReadinessRecord) {
        self.records.insert(record.partition_id.clone(), record);
    }

    pub fn snapshot(&mut self, now_ms: u64) -> WarmupReadinessSnapshot {
        if let Some(last) = self.last_publish_ms {
            if now_ms.saturating_sub(last) > self.publish_period_ms.saturating_mul(2) {
                self.skipped_publications_total = self.skipped_publications_total.saturating_add(1);
            }
        }
        self.last_publish_ms = Some(now_ms);
        let mut records: Vec<_> = self.records.values().cloned().collect();
        records.sort_by(|a, b| a.partition_id.cmp(&b.partition_id));
        WarmupReadinessSnapshot {
            records,
            publish_period_ms: self.publish_period_ms,
            skipped_publications_total: self.skipped_publications_total,
        }
    }
}
