use super::error::TelemetryError;
use serde::Deserialize;
use serde_json::from_str;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::OnceLock;

const METRICS_BUCKETS_JSON: &str = r#"{
  "schema_version": 1,
  "clause_coverage_hash": "1ba843275e5702b7077ca8f3aecf3c61c4f934813f4a5bbbfbe56a1c063397da",
  "buckets": [
    {
      "metric": "clustor.wal.fsync_latency_ms",
      "unit": "ms",
      "bounds": [
        0.25,
        0.5,
        1.0,
        2.0,
        4.0,
        6.0,
        8.0,
        10.0,
        15.0,
        20.0,
        30.0,
        40.0,
        60.0,
        80.0,
        100.0
      ],
      "notes": "WAL fsync latency buckets for strict durability guardrails."
    },
    {
      "metric": "clustor.raft.commit_latency_ms",
      "unit": "ms",
      "bounds": [
        0.5,
        1.0,
        2.0,
        4.0,
        6.0,
        8.0,
        10.0,
        15.0,
        20.0,
        30.0,
        40.0,
        60.0,
        80.0,
        100.0
      ],
      "notes": "Per-partition Raft commit latency histogram."
    },
    {
      "metric": "clustor.snapshot.transfer_seconds",
      "unit": "s",
      "bounds": [
        1.0,
        2.0,
        4.0,
        8.0,
        16.0,
        32.0,
        64.0,
        128.0,
        256.0
      ],
      "notes": "Snapshot transfer duration buckets."
    },
    {
      "metric": "clustor.flow.apply_batch_latency_ms",
      "unit": "ms",
      "bounds": [
        0.25,
        0.5,
        1.0,
        2.0,
        4.0,
        6.0,
        8.0,
        10.0
      ],
      "notes": "Apply pipeline batch latency buckets."
    }
  ]
}"#;
static METRICS_CATALOG: OnceLock<Result<MetricsBucketCatalog, TelemetryError>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct Histogram {
    pub(crate) buckets: Vec<f64>,
    pub(crate) counts: Vec<u64>,
}

pub(crate) fn canonical_histogram_bounds(max_value: u64) -> Vec<f64> {
    let mut buckets = Vec::new();
    let mut current = 1u64;
    while current < max_value {
        buckets.push(current as f64);
        current = (current as f64 * 1.5).ceil() as u64;
    }
    buckets.push(max_value as f64);
    buckets
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
