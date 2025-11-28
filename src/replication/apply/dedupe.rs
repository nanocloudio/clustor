use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct DedupeConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl Default for DedupeConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DedupeToken {
    pub term: u64,
    pub index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupeSnapshotEntry {
    pub token: DedupeToken,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupeSnapshot {
    pub entries: Vec<DedupeSnapshotEntry>,
}

pub struct DedupeCache {
    config: DedupeConfig,
    entries: HashMap<DedupeToken, usize>,
    order: VecDeque<DedupeToken>,
    bytes_used: usize,
}

impl DedupeCache {
    pub fn new(config: DedupeConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes_used: 0,
        }
    }

    pub fn contains(&self, token: &DedupeToken) -> bool {
        self.entries.contains_key(token)
    }

    pub fn insert(&mut self, token: DedupeToken, size_bytes: usize) -> bool {
        if self.entries.contains_key(&token) {
            return false;
        }
        self.entries.insert(token, size_bytes);
        self.order.push_back(token);
        self.bytes_used += size_bytes;
        self.evict();
        true
    }

    pub fn prune_below(&mut self, base_index: u64) {
        let mut retained = VecDeque::with_capacity(self.order.len());
        while let Some(token) = self.order.pop_front() {
            if token.index >= base_index {
                retained.push_back(token);
            } else if let Some(size) = self.entries.remove(&token) {
                self.bytes_used = self.bytes_used.saturating_sub(size);
            }
        }
        self.order = retained;
    }

    pub fn snapshot(&self) -> DedupeSnapshot {
        let entries = self
            .order
            .iter()
            .filter_map(|token| {
                self.entries.get(token).map(|size| DedupeSnapshotEntry {
                    token: *token,
                    size_bytes: *size,
                })
            })
            .collect();
        DedupeSnapshot { entries }
    }

    pub fn replay(&mut self, snapshot: DedupeSnapshot) {
        self.clear();
        for entry in snapshot.entries {
            self.insert(entry.token, entry.size_bytes);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes_used = 0;
    }

    fn evict(&mut self) {
        while self.entries.len() > self.config.max_entries
            || self.bytes_used > self.config.max_bytes
        {
            if let Some(oldest) = self.order.pop_front() {
                if let Some(size) = self.entries.remove(&oldest) {
                    self.bytes_used = self.bytes_used.saturating_sub(size);
                }
            } else {
                break;
            }
        }
    }
}
