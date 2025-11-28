mod error;
mod histogram;
mod incidents;
mod registry;

pub use error::TelemetryError;
pub use histogram::{metrics_bucket_catalog, Histogram, MetricBucketSpec, MetricsBucketCatalog};
pub use incidents::{CpDegradationMetrics, IncidentCorrelator, IncidentDecision};
pub use registry::{
    MetricsCursor, MetricsDelta, MetricsRegistry, MetricsSnapshot, SharedMetricsRegistry,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

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
