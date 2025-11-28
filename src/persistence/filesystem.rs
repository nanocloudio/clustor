use crate::lifecycle::bootstrap::boot_record::{
    BootRecordError, BootRecordStore, DiskPolicyRecord,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::SystemTime;
use thiserror::Error;

/// Describes the filesystem that backs the WAL + durability ledger.
#[derive(Debug, Clone)]
pub struct FilesystemStack {
    pub descriptor: FilesystemDescriptor,
    pub devices: Vec<DeviceCapabilities>,
    pub attestation: StackAttestation,
}

#[derive(Debug, Clone)]
pub enum FilesystemDescriptor {
    Ext4(Ext4Options),
    Xfs(XfsOptions),
    Zfs(ZfsOptions),
    Unknown { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackAttestation {
    Documented,
    Unknown,
}

impl StackAttestation {
    pub fn is_documented(self) -> bool {
        matches!(self, StackAttestation::Documented)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ext4Options {
    pub data_mode: Ext4DataMode,
    pub barriers_enabled: bool,
    pub auto_da_alloc: bool,
    pub commit_interval_secs: u32,
    pub journal_checksum: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ext4DataMode {
    Ordered,
    Writeback,
    Journal,
}

impl fmt::Display for Ext4DataMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ext4DataMode::Ordered => write!(f, "ordered"),
            Ext4DataMode::Writeback => write!(f, "writeback"),
            Ext4DataMode::Journal => write!(f, "journal"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XfsOptions {
    pub log_block_size_kib: u32,
    pub barriers_disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZfsOptions {
    pub sync_policy: ZfsSyncPolicy,
    pub log_bias: ZfsLogBias,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZfsSyncPolicy {
    Standard,
    Always,
    Disabled,
}

impl fmt::Display for ZfsSyncPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZfsSyncPolicy::Standard => write!(f, "standard"),
            ZfsSyncPolicy::Always => write!(f, "always"),
            ZfsSyncPolicy::Disabled => write!(f, "disabled"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZfsLogBias {
    Throughput,
    Latency,
}

impl fmt::Display for ZfsLogBias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZfsLogBias::Throughput => write!(f, "throughput"),
            ZfsLogBias::Latency => write!(f, "latency"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub sys_path: String,
    pub serial: String,
    pub write_cache: WriteCachePolicy,
    pub supports_flush: bool,
    pub supports_fua: bool,
}

impl DeviceCapabilities {
    fn label(&self) -> String {
        format!("{}#{}", self.sys_path, self.serial)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteCachePolicy {
    WriteThrough,
    WriteBack,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderedFilesystemProfile {
    Ext4Strict,
    XfsStrict,
    ZfsStrict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemEvaluation {
    pub profile: Option<OrderedFilesystemProfile>,
    pub rejections: Vec<RejectionReason>,
}

impl FilesystemEvaluation {
    pub fn is_supported(&self) -> bool {
        self.profile.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectionReason {
    UnsupportedFilesystem {
        detected: String,
    },
    StackAttestationMissing,
    DeviceMissingFlushOrFua {
        device: String,
    },
    DeviceWriteCacheUnsafe {
        device: String,
        policy: WriteCachePolicy,
    },
    DeviceWriteBackMissingFua {
        device: String,
    },
    Ext4DataModeNotOrdered {
        observed: Ext4DataMode,
    },
    Ext4BarriersDisabled,
    Ext4AutoDaAllocDisabled,
    Ext4CommitIntervalTooHigh {
        observed_secs: u32,
    },
    Ext4JournalChecksumDisabled,
    XfsLogBlockTooSmall {
        observed_kib: u32,
    },
    XfsBarrierDisabled,
    ZfsSyncNotAlways {
        observed: ZfsSyncPolicy,
    },
    ZfsLogBiasNotThroughput {
        observed: ZfsLogBias,
    },
    ZfsDeviceMissingFua {
        device: String,
    },
}

pub struct FilesystemDetector;

impl FilesystemDetector {
    pub fn evaluate(stack: &FilesystemStack) -> FilesystemEvaluation {
        let mut rejections = Vec::new();

        Self::validate_devices(stack, &mut rejections);
        Self::validate_attestation(stack, &mut rejections);

        let candidate_profile = match &stack.descriptor {
            FilesystemDescriptor::Ext4(opts) => {
                Self::validate_ext4(opts, &mut rejections);
                Some(OrderedFilesystemProfile::Ext4Strict)
            }
            FilesystemDescriptor::Xfs(opts) => {
                Self::validate_xfs(opts, &mut rejections);
                Some(OrderedFilesystemProfile::XfsStrict)
            }
            FilesystemDescriptor::Zfs(opts) => {
                Self::validate_zfs(opts, stack, &mut rejections);
                Some(OrderedFilesystemProfile::ZfsStrict)
            }
            FilesystemDescriptor::Unknown { name } => {
                rejections.push(RejectionReason::UnsupportedFilesystem {
                    detected: name.clone(),
                });
                None
            }
        };

        FilesystemEvaluation {
            profile: if rejections.is_empty() {
                candidate_profile
            } else {
                None
            },
            rejections,
        }
    }

    fn validate_devices(stack: &FilesystemStack, rejections: &mut Vec<RejectionReason>) {
        for device in &stack.devices {
            if matches!(device.write_cache, WriteCachePolicy::Unsafe) {
                rejections.push(RejectionReason::DeviceWriteCacheUnsafe {
                    device: device.label(),
                    policy: device.write_cache,
                });
            }

            if !device.supports_flush && !device.supports_fua {
                rejections.push(RejectionReason::DeviceMissingFlushOrFua {
                    device: device.label(),
                });
            }

            if matches!(device.write_cache, WriteCachePolicy::WriteBack) && !device.supports_fua {
                rejections.push(RejectionReason::DeviceWriteBackMissingFua {
                    device: device.label(),
                });
            }
        }
    }

    fn validate_attestation(stack: &FilesystemStack, rejections: &mut Vec<RejectionReason>) {
        if stack.devices.len() > 1 && !stack.attestation.is_documented() {
            rejections.push(RejectionReason::StackAttestationMissing);
        }
    }

    fn validate_ext4(opts: &Ext4Options, rejections: &mut Vec<RejectionReason>) {
        if opts.data_mode != Ext4DataMode::Ordered {
            rejections.push(RejectionReason::Ext4DataModeNotOrdered {
                observed: opts.data_mode,
            });
        }
        if !opts.barriers_enabled {
            rejections.push(RejectionReason::Ext4BarriersDisabled);
        }
        if !opts.auto_da_alloc {
            rejections.push(RejectionReason::Ext4AutoDaAllocDisabled);
        }
        if opts.commit_interval_secs > 5 {
            rejections.push(RejectionReason::Ext4CommitIntervalTooHigh {
                observed_secs: opts.commit_interval_secs,
            });
        }
        if !opts.journal_checksum {
            rejections.push(RejectionReason::Ext4JournalChecksumDisabled);
        }
    }

    fn validate_xfs(opts: &XfsOptions, rejections: &mut Vec<RejectionReason>) {
        if opts.log_block_size_kib < 256 {
            rejections.push(RejectionReason::XfsLogBlockTooSmall {
                observed_kib: opts.log_block_size_kib,
            });
        }
        if opts.barriers_disabled {
            rejections.push(RejectionReason::XfsBarrierDisabled);
        }
    }

    fn validate_zfs(
        opts: &ZfsOptions,
        stack: &FilesystemStack,
        rejections: &mut Vec<RejectionReason>,
    ) {
        if opts.sync_policy != ZfsSyncPolicy::Always {
            rejections.push(RejectionReason::ZfsSyncNotAlways {
                observed: opts.sync_policy,
            });
        }
        if opts.log_bias != ZfsLogBias::Throughput {
            rejections.push(RejectionReason::ZfsLogBiasNotThroughput {
                observed: opts.log_bias,
            });
        }

        for device in &stack.devices {
            if !device.supports_fua {
                rejections.push(RejectionReason::ZfsDeviceMissingFua {
                    device: device.label(),
                });
            }
        }
    }
}

pub fn verify_disk_policy(
    stack: &FilesystemStack,
    store: &BootRecordStore,
    now: SystemTime,
) -> Result<DiskPolicyRecord, DiskPolicyError> {
    let evaluation = FilesystemDetector::evaluate(stack);
    let rejections = evaluation.rejections.clone();
    let record = DiskPolicyRecord {
        profile: evaluation.profile,
        rejections: rejections.clone(),
        evaluated_at_ms: system_time_to_ms(now),
    };
    let mut boot = store.load_or_default()?;
    boot.disk_policy = Some(record.clone());
    store.persist(&boot)?;
    if evaluation.is_supported() {
        Ok(record)
    } else {
        Err(DiskPolicyError::Rejected {
            reasons: rejections,
        })
    }
}

#[derive(Debug, Error)]
pub enum DiskPolicyError {
    #[error(transparent)]
    BootRecord(#[from] BootRecordError),
    #[error("disk policy rejected: {reasons:?}")]
    Rejected { reasons: Vec<RejectionReason> },
}

fn system_time_to_ms(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::bootstrap::boot_record::BootRecordStore;
    use std::time::SystemTime;
    use tempfile::tempdir;

    fn ext4_stack(data_mode: Ext4DataMode) -> FilesystemStack {
        FilesystemStack {
            descriptor: FilesystemDescriptor::Ext4(Ext4Options {
                data_mode,
                barriers_enabled: true,
                auto_da_alloc: true,
                commit_interval_secs: 5,
                journal_checksum: true,
            }),
            devices: vec![DeviceCapabilities {
                sys_path: "/sys/block/nvme0n1".into(),
                serial: "s1".into(),
                write_cache: WriteCachePolicy::WriteThrough,
                supports_flush: true,
                supports_fua: true,
            }],
            attestation: StackAttestation::Documented,
        }
    }

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
        stack.devices.push(DeviceCapabilities {
            sys_path: "/sys/block/nvme1n1".into(),
            serial: "s2".into(),
            write_cache: WriteCachePolicy::WriteThrough,
            supports_flush: true,
            supports_fua: true,
        });
        let eval = FilesystemDetector::evaluate(&stack);
        assert!(!eval.is_supported());
        assert!(eval
            .rejections
            .contains(&RejectionReason::StackAttestationMissing));
    }

    #[test]
    fn zfs_requires_sync_and_logbias() {
        let stack = FilesystemStack {
            descriptor: FilesystemDescriptor::Zfs(ZfsOptions {
                sync_policy: ZfsSyncPolicy::Standard,
                log_bias: ZfsLogBias::Latency,
            }),
            devices: vec![DeviceCapabilities {
                sys_path: "/sys/block/sda".into(),
                serial: "disk0".into(),
                write_cache: WriteCachePolicy::WriteBack,
                supports_flush: true,
                supports_fua: false,
            }],
            attestation: StackAttestation::Documented,
        };

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
        let record = verify_disk_policy(&stack, &store, now).expect("supported stack should pass");
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
        let err = verify_disk_policy(&stack, &store, now).expect_err("unsupported stack rejected");
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
}
