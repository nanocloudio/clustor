use std::collections::VecDeque;
use std::time::Instant;

const DEFAULT_CAPACITY: usize = 512;

#[derive(Debug, Clone)]
pub struct AdminAuditRecord {
    pub action: String,
    pub partition_id: String,
    pub reason: Option<String>,
    pub recorded_at: Instant,
    pub spec_clause: String,
}

#[derive(Debug, Clone)]
pub struct AdminAuditStore {
    capacity: usize,
    entries: VecDeque<AdminAuditRecord>,
}

impl AdminAuditStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: VecDeque::with_capacity(capacity.max(1)),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Records a new audit event and returns the evicted record if the ring buffer overflowed.
    pub fn record(&mut self, record: AdminAuditRecord) -> Option<AdminAuditRecord> {
        let evicted = if self.entries.len() == self.capacity {
            self.entries.pop_front()
        } else {
            None
        };
        self.entries.push_back(record);
        evicted
    }

    /// Records a new audit event and invokes the provided spill hook if an old entry is evicted.
    pub fn record_with_spill<F>(&mut self, record: AdminAuditRecord, mut spill: F)
    where
        F: FnMut(AdminAuditRecord),
    {
        if let Some(evicted) = self.record(record) {
            spill(evicted);
        }
    }

    pub fn snapshot(&self) -> Vec<AdminAuditRecord> {
        self.entries.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
