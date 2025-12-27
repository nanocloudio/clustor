use clustor::{
    BundleNegotiationEntry, CatalogNegotiationReport, CatalogVersion, ForwardCompatTracker,
    SegmentHeader, SegmentHeaderError,
};
use std::path::Path;
use tempfile::tempdir;

fn read_negotiation_entries(path: &Path) -> Vec<BundleNegotiationEntry> {
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid negotiation entry"))
        .collect()
}

fn test_catalog_report(tempdir: &tempfile::TempDir) -> CatalogNegotiationReport {
    CatalogNegotiationReport {
        partition_id: "segment-header".into(),
        log_path: tempdir.path().join("wire").join("bundle_negotiation.log"),
        local_version: CatalogVersion::new(0, 1, 2),
        remote_version: CatalogVersion::new(0, 1, 1),
    }
}

#[test]
fn segment_header_unknown_version_revokes_forward_tolerance() {
    let tmp = tempdir().unwrap();
    let mut report = test_catalog_report(&tmp);
    let mut tracker = ForwardCompatTracker::new(&mut report);

    let header = SegmentHeader::new(1, 99, 4);
    let mut bytes = header.encode();
    bytes[0] = 9; // simulate future WAL format

    let err = SegmentHeader::decode_with_tracker(&bytes, &mut tracker).unwrap_err();
    assert!(matches!(
        err,
        SegmentHeaderError::UnsupportedFormatVersion { .. }
    ));

    let entries = read_negotiation_entries(&report.log_path);
    assert_eq!(entries.len(), 1);
    assert!(entries[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("segment_header.wal_format_version"));
}

#[test]
fn segment_header_decode_with_report_helpers_tracker() {
    let tmp = tempdir().unwrap();
    let mut report = test_catalog_report(&tmp);
    let header = SegmentHeader::new(1, 99, 4);
    let mut bytes = header.encode();
    bytes[0] = 9;
    let err = SegmentHeader::decode_with_report(&bytes, &mut report).unwrap_err();
    assert!(matches!(
        err,
        SegmentHeaderError::UnsupportedFormatVersion { .. }
    ));
    let entries = read_negotiation_entries(&report.log_path);
    assert_eq!(entries.len(), 1);
}
