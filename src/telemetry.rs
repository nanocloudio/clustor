use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::cmp::Ordering;
use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;

const METRICS_BUCKETS_JSON: &str = include_str!("../artifacts/metrics_buckets.json");
static METRICS_CATALOG: OnceLock<Result<MetricsBucketCatalog, TelemetryError>> = OnceLock::new();
const METRICS_SHARD_COUNT: usize = 8;

#[derive(Debug)]
pub struct MetricsRegistry {
    namespace: String,
    counters: HashMap<String, u64>,
    histograms: HashMap<String, Histogram>,
    gauges: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<f64>,
    counts: Vec<u64>,
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

fn canonical_histogram_bounds(max_value: u64) -> Vec<f64> {
    let mut buckets = Vec::new();
    let mut current = 1u64;
    while current < max_value {
        buckets.push(current as f64);
        current = (current as f64 * 1.5).ceil() as u64;
    }
    buckets.push(max_value as f64);
    buckets
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

#[derive(Debug, Clone)]
pub struct SharedMetricsRegistry {
    prefix: Arc<String>,
    shards: Arc<Vec<Mutex<MetricsShard>>>,
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

impl Histogram {
    pub fn canonical(max_value: u64) -> Self {
        let buckets = canonical_histogram_bounds(max_value);
        Self::with_bounds(&buckets)
    }

    pub fn with_bounds(bounds: &[f64]) -> Self {
        Self {
            buckets: bounds.to_vec(),
            counts: vec![0; bounds.len()],
        }
    }

    pub fn observe(&mut self, value: f64) {
        if self.buckets.is_empty() {
            return;
        }
        let idx = if value.is_nan() {
            self.counts.len() - 1
        } else {
            match self
                .buckets
                .binary_search_by(|bucket| bucket.partial_cmp(&value).unwrap_or(Ordering::Greater))
            {
                Ok(pos) => pos,
                Err(pos) if pos < self.counts.len() => pos,
                _ => self.counts.len() - 1,
            }
        };
        if let Some(bucket) = self.counts.get_mut(idx) {
            *bucket = bucket.saturating_add(1);
        }
    }
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
    counters: HashMap<String, u64>,
    histograms: HashMap<String, Vec<u64>>,
    gauges: HashMap<String, u64>,
}

impl MetricsCursor {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsBucketCatalog {
    schema_version: u64,
    clause_coverage_hash: String,
    buckets: HashMap<String, MetricBucketSpec>,
}

#[derive(Debug, Clone)]
pub struct MetricBucketSpec {
    pub metric: String,
    pub unit: String,
    pub bounds: Vec<f64>,
    pub notes: String,
}

#[derive(Debug, Deserialize)]
struct MetricsBucketsArtifact {
    schema_version: u64,
    clause_coverage_hash: String,
    buckets: Vec<MetricBucketEntry>,
}

#[derive(Debug, Deserialize)]
struct MetricBucketEntry {
    metric: String,
    unit: String,
    bounds: Vec<f64>,
    notes: String,
}

pub fn metrics_bucket_catalog() -> Result<&'static MetricsBucketCatalog, TelemetryError> {
    match METRICS_CATALOG.get_or_init(|| {
        let artifact: Result<MetricsBucketsArtifact, _> = from_str(METRICS_BUCKETS_JSON);
        artifact
            .map(MetricsBucketCatalog::from_artifact)
            .map_err(|err| TelemetryError::MetricsCatalog(err.to_string()))
    }) {
        Ok(catalog) => Ok(catalog),
        Err(err) => Err(err.clone()),
    }
}

impl MetricsBucketCatalog {
    fn from_artifact(artifact: MetricsBucketsArtifact) -> Self {
        let buckets = artifact
            .buckets
            .into_iter()
            .map(|entry| {
                let metric = entry.metric.clone();
                (
                    metric.clone(),
                    MetricBucketSpec {
                        metric,
                        unit: entry.unit,
                        bounds: entry.bounds,
                        notes: entry.notes,
                    },
                )
            })
            .collect();
        Self {
            schema_version: artifact.schema_version,
            clause_coverage_hash: artifact.clause_coverage_hash,
            buckets,
        }
    }

    pub fn schema_version(&self) -> u64 {
        self.schema_version
    }

    pub fn clause_coverage_hash(&self) -> &str {
        &self.clause_coverage_hash
    }

    pub fn metric(&self, name: &str) -> Option<&MetricBucketSpec> {
        self.buckets.get(name)
    }

    pub fn metrics(&self) -> impl Iterator<Item = (&str, &MetricBucketSpec)> {
        self.buckets
            .iter()
            .map(|(name, spec)| (name.as_str(), spec))
    }
}

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

#[derive(Debug, Error, Clone)]
pub enum TelemetryError {
    #[error("unknown histogram {0}")]
    UnknownHistogram(String),
    #[error("metrics shard lock poisoned")]
    ShardPoisoned,
    #[error("metrics catalog corrupt: {0}")]
    MetricsCatalog(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_enforces_namespace_and_histograms() {
        let mut registry = MetricsRegistry::new("clustor");
        registry.inc_counter("cp.cache_hits", 1);
        let histogram = registry.register_histogram("latency_ns", 1000);
        assert!(!histogram.buckets.is_empty());
        registry.observe_histogram("latency_ns", 450.0).unwrap();
        assert!(registry
            .snapshot()
            .counters
            .contains_key("clustor.cp.cache_hits"));
    }

    #[test]
    fn incident_correlator_applies_cooldown() {
        let mut correlator = IncidentCorrelator::new(Duration::from_secs(30));
        let now = Instant::now();
        assert_eq!(
            correlator.record("cp-outage", now),
            IncidentDecision::Triggered
        );
        assert_eq!(
            correlator.record("cp-outage", now + Duration::from_secs(5)),
            IncidentDecision::Suppressed
        );
    }

    #[test]
    fn metrics_catalog_exposes_artifact_buckets() {
        let catalog = metrics_bucket_catalog().expect("catalog");
        assert_eq!(catalog.schema_version(), 1);
        assert_eq!(
            catalog.clause_coverage_hash(),
            "1ba843275e5702b7077ca8f3aecf3c61c4f934813f4a5bbbfbe56a1c063397da"
        );
        let spec = catalog
            .metric("clustor.wal.fsync_latency_ms")
            .expect("fsync metric");
        assert_eq!(spec.unit, "ms");
        assert!(spec.bounds.len() > 5);
    }

    #[test]
    fn register_golden_histograms_registers_artifact_metrics() {
        let mut registry = MetricsRegistry::new("clustor");
        registry
            .register_golden_histograms()
            .expect("golden histograms");
        registry
            .observe_histogram("clustor.wal.fsync_latency_ms", 5.0)
            .unwrap();
        let snapshot = registry.snapshot();
        assert!(snapshot
            .histograms
            .contains_key("clustor.wal.fsync_latency_ms"));
    }

    #[test]
    fn shared_registry_tracks_counters_and_gauges() {
        let registry = SharedMetricsRegistry::new("clustor");
        registry.inc_counter("apply.events", 2).unwrap();
        registry.set_gauge("apply.queue_depth", 8).unwrap();
        registry
            .register_histogram("apply.latency_ns", 1_000)
            .unwrap();
        registry
            .observe_histogram("apply.latency_ns", 250.0)
            .unwrap();
        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.counters.get("clustor.apply.events"), Some(&2));
        assert_eq!(snapshot.gauges.get("clustor.apply.queue_depth"), Some(&8));
    }

    #[test]
    fn shared_registry_delta_snapshot_emits_only_changes() {
        let registry = SharedMetricsRegistry::with_shards("clustor", 1);
        registry.inc_counter("cp.hit", 1).unwrap();
        registry.register_histogram("latency_ns", 128).unwrap();
        registry.observe_histogram("latency_ns", 42.0).unwrap();
        registry.set_gauge("connections", 5).unwrap();
        let mut cursor = MetricsCursor::default();
        let first = registry.delta_snapshot(&mut cursor).unwrap();
        assert_eq!(first.counters.len(), 1);
        assert_eq!(first.histograms.len(), 1);
        assert_eq!(first.gauges.len(), 1);
        let second = registry.delta_snapshot(&mut cursor).unwrap();
        assert!(second.counters.is_empty());
        assert!(second.histograms.is_empty());
        assert!(second.gauges.is_empty());
        registry.inc_counter("cp.hit", 2).unwrap();
        let third = registry.delta_snapshot(&mut cursor).unwrap();
        assert_eq!(third.counters.len(), 1);
        assert_eq!(third.counters[0].1, 3);
    }
}
