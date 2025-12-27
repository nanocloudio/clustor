use super::readyz_support::disk_override;
use clustor::OverrideError;

#[test]
fn disk_override_validates_schema() {
    let doc = disk_override("1000");
    assert!(doc.validate(10).is_ok());
    assert!(doc.is_active(10).unwrap());
}

#[test]
fn disk_override_rejects_bad_inputs() {
    let mut doc = disk_override("100");
    assert!(matches!(
        doc.validate(500),
        Err(OverrideError::Expired { .. })
    ));
    doc.devices[0].sys_path = "nvme0n1".into();
    let err = doc.validate(1).unwrap_err();
    assert!(matches!(
        err,
        OverrideError::InvalidField {
            field: "devices[].sys_path",
            ..
        }
    ));
}

#[test]
fn disk_override_rejects_invalid_expiration() {
    let mut doc = disk_override("1000");
    doc.expires_at_ms = "invalid".into();
    assert!(matches!(
        doc.expiration_epoch_ms(),
        Err(OverrideError::InvalidField { field, .. }) if field == "expires_at_ms"
    ));
    assert!(doc.validate(0).is_err());
}

#[test]
fn override_status_reflects_ttl() {
    let doc = disk_override("10");
    let status = clustor::OverrideStatus::from_disk_override(&doc, 5).expect("override");
    assert!(status.active);
    let status = clustor::OverrideStatus::from_disk_override(&doc, 20).expect("override");
    assert!(!status.active);
}

#[test]
fn override_status_invalid_doc_fails() {
    let mut doc = disk_override("10");
    doc.expires_at_ms = "invalid".into();
    assert!(clustor::OverrideStatus::from_disk_override(&doc, 0).is_err());
}
