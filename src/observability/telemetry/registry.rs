use super::error::TelemetryError;
use super::histogram::{canonical_histogram_bounds, metrics_bucket_catalog, Histogram};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard};

const METRICS_SHARD_COUNT: usize = 8;

#[derive(Debug)]
pub struct MetricsRegistry {
    namespace: String,
    counters: HashMap<String, u64>,
    histograms: HashMap<String, Histogram>,
    gauges: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct SharedMetricsRegistry {
    prefix: Arc<String>,
    shards: Arc<Vec<Mutex<MetricsShard>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub counters: HashMap<String, u64>,
    pub histograms: HashMap<String, Vec<u64>>,
    pub gauges: HashMap<String, u64>,
}

#[derive(Debug, Default)]
pub struct MetricsDelta {
    pub counters: Vec<(String, u64)>,
    pub histograms: Vec<(String, Vec<u64>)>,
    pub gauges: Vec<(String, u64)>,
}

#[derive(Debug, Default)]
pub struct MetricsCursor {
    pub(crate) counters: HashMap<String, u64>,
    pub(crate) histograms: HashMap<String, Vec<u64>>,
    pub(crate) gauges: HashMap<String, u64>,
}

impl MetricsCursor {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Default)]
struct MetricsShard {
    counters: HashMap<String, Arc<CounterCell>>,
    histograms: HashMap<String, Arc<HistogramCell>>,
    gauges: HashMap<String, Arc<GaugeCell>>,
}

#[derive(Debug)]
struct CounterCell {
    value: AtomicU64,
}

impl CounterCell {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    fn add(&self, delta: u64) -> u64 {
        atomic_saturating_add(&self.value, delta)
    }

    fn snapshot(&self) -> u64 {
        self.value.load(AtomicOrdering::Relaxed)
    }
}

#[derive(Debug)]
struct GaugeCell {
    value: AtomicU64,
}

impl GaugeCell {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    fn set(&self, value: u64) {
        self.value.store(value, AtomicOrdering::Relaxed);
    }

    fn snapshot(&self) -> u64 {
        self.value.load(AtomicOrdering::Relaxed)
    }
}

#[derive(Debug)]
struct HistogramCell {
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
}

impl HistogramCell {
    fn canonical(max_value: u64) -> Self {
        Self::with_bounds(&canonical_histogram_bounds(max_value))
    }

    fn with_bounds(bounds: &[f64]) -> Self {
        Self {
            buckets: bounds.to_vec(),
            counts: bounds.iter().map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn observe(&self, value: f64) {
        if self.buckets.is_empty() {
            return;
        }
        let idx = self.bucket_index(value);
        if let Some(bucket) = self.counts.get(idx) {
            atomic_saturating_add(bucket, 1);
        }
    }

    fn snapshot(&self) -> Vec<u64> {
        self.counts
            .iter()
            .map(|count| count.load(AtomicOrdering::Relaxed))
            .collect()
    }

    fn bucket_index(&self, value: f64) -> usize {
        if value.is_nan() {
            return self.counts.len().saturating_sub(1);
        }
        match self
            .buckets
            .binary_search_by(|bucket| bucket.partial_cmp(&value).unwrap_or(Ordering::Greater))
        {
            Ok(pos) => pos,
            Err(pos) if pos < self.counts.len() => pos,
            _ => self.counts.len().saturating_sub(1),
        }
    }
}

impl MetricsRegistry {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            counters: HashMap::new(),
            histograms: HashMap::new(),
            gauges: HashMap::new(),
        }
    }

    pub fn inc_counter(&mut self, name: impl Into<String>, delta: u64) -> u64 {
        let key = self.qualify(name.into());
        let counter = self.counters.entry(key).or_insert(0);
        *counter = counter.saturating_add(delta);
        *counter
    }

    pub fn register_histogram(
        &mut self,
        name: impl Into<String>,
        max_value: u64,
    ) -> &mut Histogram {
        let key = self.qualify(name.into());
        self.histograms
            .entry(key)
            .or_insert_with(|| Histogram::canonical(max_value))
    }

    pub fn register_histogram_with_bounds(
        &mut self,
        name: impl Into<String>,
        bounds: &[f64],
    ) -> &mut Histogram {
        let key = self.qualify(name.into());
        self.histograms
            .entry(key)
            .or_insert_with(|| Histogram::with_bounds(bounds))
    }

    pub fn register_golden_histograms(&mut self) -> Result<(), TelemetryError> {
        let catalog = metrics_bucket_catalog()?;
        for (metric, bucket) in catalog.metrics() {
            self.register_histogram_with_bounds(metric.to_string(), &bucket.bounds);
        }
        Ok(())
    }

    pub fn observe_histogram(
        &mut self,
        name: impl Into<String>,
        value: f64,
    ) -> Result<(), TelemetryError> {
        let key = self.qualify(name.into());
        let histogram = self
            .histograms
            .get_mut(&key)
            .ok_or_else(|| TelemetryError::UnknownHistogram(key.clone()))?;
        histogram.observe(value);
        Ok(())
    }

    pub fn set_gauge(&mut self, name: impl Into<String>, value: u64) {
        let key = self.qualify(name.into());
        self.gauges.insert(key, value);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            counters: self.counters.clone(),
            histograms: self
                .histograms
                .iter()
                .map(|(name, hist)| (name.clone(), hist.counts.clone()))
                .collect(),
            gauges: self.gauges.clone(),
        }
    }

    fn qualify(&self, name: String) -> String {
        let namespace = if self.namespace.ends_with('.') {
            self.namespace.clone()
        } else {
            format!("{}.", self.namespace)
        };
        if name.starts_with(&namespace) {
            name
        } else {
            format!("{}{}", namespace, name)
        }
    }
}

impl SharedMetricsRegistry {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self::with_shards(namespace, METRICS_SHARD_COUNT)
    }

    pub fn with_shards(namespace: impl Into<String>, shards: usize) -> Self {
        assert!(shards > 0, "shared metrics registry requires shards");
        let raw = namespace.into();
        let prefix = if raw.ends_with('.') {
            raw.clone()
        } else {
            format!("{}.", raw)
        };
        let shard_vec: Vec<Mutex<MetricsShard>> = (0..shards)
            .map(|_| Mutex::new(MetricsShard::default()))
            .collect();
        Self {
            prefix: Arc::new(prefix),
            shards: Arc::new(shard_vec),
        }
    }

    pub fn inc_counter(&self, name: impl Into<String>, delta: u64) -> Result<u64, TelemetryError> {
        let key = self.qualify(name.into());
        let cell = {
            let mut guard = self.lock_shard(&key)?;
            guard
                .counters
                .entry(key.clone())
                .or_insert_with(|| Arc::new(CounterCell::new()))
                .clone()
        };
        Ok(cell.add(delta))
    }

    pub fn register_histogram(
        &self,
        name: impl Into<String>,
        max_value: u64,
    ) -> Result<(), TelemetryError> {
        let key = self.qualify(name.into());
        let mut guard = self.lock_shard(&key)?;
        guard
            .histograms
            .entry(key)
            .or_insert_with(|| Arc::new(HistogramCell::canonical(max_value)));
        Ok(())
    }

    pub fn register_histogram_with_bounds(
        &self,
        name: impl Into<String>,
        bounds: &[f64],
    ) -> Result<(), TelemetryError> {
        let key = self.qualify(name.into());
        let mut guard = self.lock_shard(&key)?;
        guard
            .histograms
            .entry(key)
            .or_insert_with(|| Arc::new(HistogramCell::with_bounds(bounds)));
        Ok(())
    }

    pub fn register_golden_histograms(&self) -> Result<(), TelemetryError> {
        let catalog = metrics_bucket_catalog()?;
        for (metric, bucket) in catalog.metrics() {
            self.register_histogram_with_bounds(metric.to_string(), &bucket.bounds)?;
        }
        Ok(())
    }

    pub fn observe_histogram(
        &self,
        name: impl Into<String>,
        value: f64,
    ) -> Result<(), TelemetryError> {
        let key = self.qualify(name.into());
        let histogram = {
            let guard = self.lock_shard(&key)?;
            guard
                .histograms
                .get(&key)
                .cloned()
                .ok_or_else(|| TelemetryError::UnknownHistogram(key.clone()))?
        };
        histogram.observe(value);
        Ok(())
    }

    pub fn set_gauge(&self, name: impl Into<String>, value: u64) -> Result<(), TelemetryError> {
        let key = self.qualify(name.into());
        let cell = {
            let mut guard = self.lock_shard(&key)?;
            guard
                .gauges
                .entry(key.clone())
                .or_insert_with(|| Arc::new(GaugeCell::new()))
                .clone()
        };
        cell.set(value);
        Ok(())
    }

    pub fn snapshot(&self) -> Result<MetricsSnapshot, TelemetryError> {
        let mut counters = HashMap::new();
        let mut histograms = HashMap::new();
        let mut gauges = HashMap::new();
        for shard in self.shards.iter() {
            let guard = shard.lock().map_err(|_| TelemetryError::ShardPoisoned)?;
            for (name, cell) in guard.counters.iter() {
                counters.insert(name.clone(), cell.snapshot());
            }
            for (name, cell) in guard.histograms.iter() {
                histograms.insert(name.clone(), cell.snapshot());
            }
            for (name, cell) in guard.gauges.iter() {
                gauges.insert(name.clone(), cell.snapshot());
            }
        }
        Ok(MetricsSnapshot {
            counters,
            histograms,
            gauges,
        })
    }

    pub fn delta_snapshot(
        &self,
        cursor: &mut MetricsCursor,
    ) -> Result<MetricsDelta, TelemetryError> {
        let mut delta = MetricsDelta::default();
        let mut seen_counters = HashSet::new();
        let mut seen_histograms = HashSet::new();
        let mut seen_gauges = HashSet::new();
        for shard in self.shards.iter() {
            let guard = shard.lock().map_err(|_| TelemetryError::ShardPoisoned)?;
            for (name, cell) in guard.counters.iter() {
                seen_counters.insert(name.clone());
                let value = cell.snapshot();
                if cursor.counters.get(name).copied() != Some(value) {
                    cursor.counters.insert(name.clone(), value);
                    delta.counters.push((name.clone(), value));
                }
            }
            for (name, cell) in guard.histograms.iter() {
                seen_histograms.insert(name.clone());
                let snapshot = cell.snapshot();
                if cursor.histograms.get(name).map(|v| v == &snapshot) != Some(true) {
                    cursor.histograms.insert(name.clone(), snapshot.clone());
                    delta.histograms.push((name.clone(), snapshot));
                }
            }
            for (name, cell) in guard.gauges.iter() {
                seen_gauges.insert(name.clone());
                let value = cell.snapshot();
                if cursor.gauges.get(name).copied() != Some(value) {
                    cursor.gauges.insert(name.clone(), value);
                    delta.gauges.push((name.clone(), value));
                }
            }
        }
        cursor
            .counters
            .retain(|name, _| seen_counters.contains(name));
        cursor
            .histograms
            .retain(|name, _| seen_histograms.contains(name));
        cursor.gauges.retain(|name, _| seen_gauges.contains(name));
        Ok(delta)
    }

    fn shard_for(&self, key: &str) -> &Mutex<MetricsShard> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.shards.len();
        &self.shards[idx]
    }

    fn lock_shard(&self, key: &str) -> Result<MutexGuard<'_, MetricsShard>, TelemetryError> {
        self.shard_for(key)
            .lock()
            .map_err(|_| TelemetryError::ShardPoisoned)
    }

    fn qualify(&self, name: String) -> String {
        if name.starts_with(self.prefix.as_str()) {
            name
        } else {
            format!("{}{}", self.prefix, name)
        }
    }
}

fn atomic_saturating_add(cell: &AtomicU64, delta: u64) -> u64 {
    let mut current = cell.load(AtomicOrdering::Relaxed);
    loop {
        let new_value = current.saturating_add(delta);
        match cell.compare_exchange(
            current,
            new_value,
            AtomicOrdering::Relaxed,
            AtomicOrdering::Relaxed,
        ) {
            Ok(_) => return new_value,
            Err(actual) => current = actual,
        }
    }
}
