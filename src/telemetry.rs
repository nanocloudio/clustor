use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use thiserror::Error;

const METRICS_BUCKETS_JSON: &str = include_str!("../artifacts/metrics_buckets.json");
static METRICS_CATALOG: OnceLock<MetricsBucketCatalog> = OnceLock::new();

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
            .entry(key.clone())
            .or_insert_with(|| Histogram::canonical(max_value));
        self.histograms.get_mut(&key).unwrap()
    }

    pub fn register_histogram_with_bounds(
        &mut self,
        name: impl Into<String>,
        bounds: &[f64],
    ) -> &mut Histogram {
        let key = self.qualify(name.into());
        self.histograms
            .entry(key.clone())
            .or_insert_with(|| Histogram::with_bounds(bounds));
        self.histograms.get_mut(&key).unwrap()
    }

    pub fn register_golden_histograms(&mut self) {
        let catalog = metrics_bucket_catalog();
        for (metric, bucket) in catalog.metrics() {
            self.register_histogram_with_bounds(metric.to_string(), &bucket.bounds);
        }
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

impl Histogram {
    pub fn canonical(max_value: u64) -> Self {
        let mut buckets = Vec::new();
        let mut current = 1u64;
        while current < max_value {
            buckets.push(current as f64);
            current = (current as f64 * 1.5).ceil() as u64;
        }
        buckets.push(max_value as f64);
        Self::with_bounds(&buckets)
    }

    pub fn with_bounds(bounds: &[f64]) -> Self {
        Self {
            buckets: bounds.to_vec(),
            counts: vec![0; bounds.len()],
        }
    }

    pub fn observe(&mut self, value: f64) {
        if let Some((idx, _)) = self
            .buckets
            .iter()
            .enumerate()
            .find(|(_, bucket)| value <= **bucket)
        {
            self.counts[idx] = self.counts[idx].saturating_add(1);
        } else if let Some(last) = self.counts.last_mut() {
            *last = last.saturating_add(1);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub counters: HashMap<String, u64>,
    pub histograms: HashMap<String, Vec<u64>>,
    pub gauges: HashMap<String, u64>,
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

pub fn metrics_bucket_catalog() -> &'static MetricsBucketCatalog {
    METRICS_CATALOG.get_or_init(|| {
        let artifact: MetricsBucketsArtifact =
            from_str(METRICS_BUCKETS_JSON).expect("metrics buckets artifact is valid JSON");
        MetricsBucketCatalog::from_artifact(artifact)
    })
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

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("unknown histogram {0}")]
    UnknownHistogram(String),
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
        let catalog = metrics_bucket_catalog();
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
        registry.register_golden_histograms();
        registry
            .observe_histogram("clustor.wal.fsync_latency_ms", 5.0)
            .unwrap();
        let snapshot = registry.snapshot();
        assert!(snapshot
            .histograms
            .contains_key("clustor.wal.fsync_latency_ms"));
    }
}
