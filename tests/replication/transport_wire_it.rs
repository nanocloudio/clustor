use clustor::replication::consensus::CatalogVersion;
use clustor::replication::transport::{
    BundleNegotiationEntry, BundleNegotiationLog, NegotiationError, WireCatalogNegotiator,
};
use serde_json::from_str;
use std::fs;
use tempfile::tempdir;

fn catalog(major: u8, minor: u8, forward: u8) -> CatalogVersion {
    CatalogVersion {
        major,
        minor,
        forward_parse_max_minor: forward,
    }
}

fn read_entries(log: &BundleNegotiationLog) -> Vec<BundleNegotiationEntry> {
    if !log.path().exists() {
        return Vec::new();
    }
    let contents =
        fs::read_to_string(log.path()).expect("bundle negotiation log should read successfully");
    contents
        .lines()
        .map(|line| from_str(line).expect("entry should decode"))
        .collect()
}

#[test]
fn negotiator_accepts_and_logs_handshake() {
    let dir = tempdir().unwrap();
    let log = BundleNegotiationLog::new(dir.path().join("bundle_negotiation.log"));
    let negotiator = WireCatalogNegotiator::new("partition-a", log.clone());
    let local = catalog(0, 1, 2);
    let remote = catalog(0, 1, 1);
    negotiator.negotiate(local, remote).unwrap();
    let entries = read_entries(&log);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].accepted);
}

#[test]
fn negotiator_rejects_incompatible_minor() {
    let dir = tempdir().unwrap();
    let log = BundleNegotiationLog::new(dir.path().join("bundle_negotiation.log"));
    let negotiator = WireCatalogNegotiator::new("partition-b", log.clone());
    let local = catalog(0, 1, 1);
    let remote = catalog(0, 3, 3);
    let err = negotiator.negotiate(local, remote).unwrap_err();
    assert!(matches!(err, NegotiationError::WireCatalogMismatch { .. }));
    let entries = read_entries(&log);
    assert!(!entries[0].accepted);
}

#[test]
fn revoke_forward_tolerance_sets_minor_cap() {
    let dir = tempdir().unwrap();
    let log = BundleNegotiationLog::new(dir.path().join("bundle_negotiation.log"));
    let negotiator = WireCatalogNegotiator::new("partition-c", log.clone());
    let local = catalog(0, 1, 2);
    let remote = catalog(0, 2, 2);
    let updated = negotiator
        .revoke_forward_tolerance(local, remote, "catalog diverged")
        .unwrap();
    assert_eq!(updated.forward_parse_max_minor, updated.minor);
    let entries = read_entries(&log);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].reason.as_deref(), Some("catalog diverged"));
}
