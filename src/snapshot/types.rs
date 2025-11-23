pub(crate) const SNAPSHOT_EXPORT_SPEC: &str = "§5.2.SnapshotExport";
pub(crate) const SNAPSHOT_THROTTLE_SPEC: &str = "§7.1.SnapshotThrottle";
pub(crate) const SNAPSHOT_ONLY_SPEC: &str = "§8.SnapshotOnly";
pub(crate) const SNAPSHOT_LOG_BYTES_TARGET: u64 = 512 * 1024 * 1024;
pub(crate) const SNAPSHOT_MAX_INTERVAL_MS: u64 = 15 * 60 * 1000;
pub(crate) const SNAPSHOT_CATCHUP_THRESHOLD_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const SNAPSHOT_IMPORT_NODE_FLOOR_BYTES: u64 = 8 * 1024 * 1024 * 1024;
