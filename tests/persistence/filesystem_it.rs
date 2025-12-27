#[path = "../support/persistence/filesystem.rs"]
mod filesystem_support;

use clustor::lifecycle::bootstrap::boot_record::BootRecordStore;
use clustor::persistence::filesystem::{
    DiskPolicyError, Ext4DataMode, FilesystemDetector, OrderedFilesystemProfile, RejectionReason,
    StackAttestation, ZfsLogBias, ZfsSyncPolicy,
};
use filesystem_support::{ext4_stack, write_through_device, zfs_stack};
use std::time::SystemTime;
use tempfile::tempdir;

#[test]
fn ext4_ordered_profile_is_supported() {
    let stack = ext4_stack(Ext4DataMode::Ordered);
    let eval = FilesystemDetector::evaluate(&stack);
    assert!(eval.is_supported());
    assert_eq!(eval.profile, Some(OrderedFilesystemProfile::Ext4Strict));
    assert!(eval.rejections.is_empty());
}

#[test]
fn ext4_rejects_non_ordered_data_mode() {
    let stack = ext4_stack(Ext4DataMode::Writeback);
    let eval = FilesystemDetector::evaluate(&stack);
    assert!(!eval.is_supported());
    assert!(matches!(
        eval.rejections.as_slice(),
        [RejectionReason::Ext4DataModeNotOrdered { observed }]
        if *observed == Ext4DataMode::Writeback
    ));
}

#[test]
fn multi_device_without_attestation_is_rejected() {
    let mut stack = ext4_stack(Ext4DataMode::Ordered);
    stack.attestation = StackAttestation::Unknown;
    stack.devices.push(write_through_device("nvme1n1", true));
    let eval = FilesystemDetector::evaluate(&stack);
    assert!(!eval.is_supported());
    assert!(eval
        .rejections
        .contains(&RejectionReason::StackAttestationMissing));
}

#[test]
fn zfs_requires_sync_and_logbias() {
    let stack = zfs_stack(ZfsSyncPolicy::Standard, ZfsLogBias::Latency, false);
    let eval = FilesystemDetector::evaluate(&stack);
    assert!(!eval.is_supported());
    assert!(eval
        .rejections
        .iter()
        .any(|reason| matches!(reason, RejectionReason::ZfsSyncNotAlways { .. })));
    assert!(eval
        .rejections
        .iter()
        .any(|reason| matches!(reason, RejectionReason::ZfsLogBiasNotThroughput { .. })));
    assert!(eval
        .rejections
        .iter()
        .any(|reason| matches!(reason, RejectionReason::ZfsDeviceMissingFua { .. })));
}

#[test]
fn verify_disk_policy_records_success() {
    let stack = ext4_stack(Ext4DataMode::Ordered);
    let dir = tempdir().expect("temp dir");
    let store = BootRecordStore::new(dir.path().join("boot.json"));
    let now = SystemTime::now();
    let record = clustor::persistence::filesystem::verify_disk_policy(&stack, &store, now)
        .expect("supported stack should pass");
    assert_eq!(record.profile, Some(OrderedFilesystemProfile::Ext4Strict));
    let persisted = store.load_or_default().expect("boot record load");
    assert_eq!(persisted.disk_policy, Some(record));
}

#[test]
fn verify_disk_policy_propagates_rejections() {
    let stack = ext4_stack(Ext4DataMode::Writeback);
    let dir = tempdir().expect("temp dir");
    let store = BootRecordStore::new(dir.path().join("boot.json"));
    let now = SystemTime::now();
    let err = clustor::persistence::filesystem::verify_disk_policy(&stack, &store, now)
        .expect_err("unsupported stack rejected");
    assert!(matches!(err, DiskPolicyError::Rejected { .. }));
    let persisted = store.load_or_default().expect("boot record load");
    let policy = persisted
        .disk_policy
        .expect("disk policy stored despite rejection");
    assert!(policy
        .rejections
        .iter()
        .any(|reason| matches!(reason, RejectionReason::Ext4DataModeNotOrdered { .. })));
}
