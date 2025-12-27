use clustor::persistence::filesystem::{
    DeviceCapabilities, Ext4DataMode, Ext4Options, FilesystemDescriptor, FilesystemStack,
    StackAttestation, WriteCachePolicy, ZfsLogBias, ZfsOptions, ZfsSyncPolicy,
};

pub fn ext4_stack(data_mode: Ext4DataMode) -> FilesystemStack {
    FilesystemStack {
        descriptor: FilesystemDescriptor::Ext4(Ext4Options {
            data_mode,
            barriers_enabled: true,
            auto_da_alloc: true,
            commit_interval_secs: 5,
            journal_checksum: true,
        }),
        devices: vec![write_through_device("nvme0n1", true)],
        attestation: StackAttestation::Documented,
    }
}

pub fn write_through_device(label: &str, supports_fua: bool) -> DeviceCapabilities {
    DeviceCapabilities {
        sys_path: format!("/sys/block/{label}"),
        serial: format!("serial-{label}"),
        write_cache: WriteCachePolicy::WriteThrough,
        supports_flush: true,
        supports_fua,
    }
}

pub fn zfs_stack(sync: ZfsSyncPolicy, log_bias: ZfsLogBias, supports_fua: bool) -> FilesystemStack {
    FilesystemStack {
        descriptor: FilesystemDescriptor::Zfs(ZfsOptions {
            sync_policy: sync,
            log_bias,
        }),
        devices: vec![DeviceCapabilities {
            sys_path: "/sys/block/sda".into(),
            serial: "disk0".into(),
            write_cache: WriteCachePolicy::WriteBack,
            supports_flush: true,
            supports_fua,
        }],
        attestation: StackAttestation::Documented,
    }
}
