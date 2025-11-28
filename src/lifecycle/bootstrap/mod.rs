//! Bootstrap-time utilities: filesystem vetting, probes, and boot records.

pub mod boot_record;
pub mod pipeline;
pub mod probe;

pub use crate::persistence::filesystem;
pub use filesystem::{
    verify_disk_policy, DeviceCapabilities, DiskPolicyError, Ext4DataMode, Ext4Options,
    FilesystemDescriptor, FilesystemDetector, FilesystemEvaluation, FilesystemStack,
    OrderedFilesystemProfile, RejectionReason, StackAttestation, WriteCachePolicy, XfsOptions,
    ZfsLogBias, ZfsOptions, ZfsSyncPolicy,
};

pub use boot_record::{BootRecord, BootRecordError, BootRecordStore, DiskPolicyRecord};

pub use crate::replication::transport::{CatalogNegotiationConfig, CatalogNegotiationReport};
pub use pipeline::{
    BootstrapConfig, BootstrapError, BootstrapEvent, BootstrapPipeline, BootstrapReport,
    BootstrapRequest, BootstrapStep, ClusterProfile, ManifestValidationConfig, ProfileError,
    ProfileLoader, ShutdownAction, ShutdownError, ShutdownManager, ShutdownStatus,
};
pub use probe::{
    run_probe_and_persist, FsyncProbeConfig, FsyncProbeContext, FsyncProbeResult, FsyncProbeRunner,
    FsyncProbeTelemetry, GroupFsyncDecision, GroupFsyncGuard, GroupFsyncGuardConfig,
    GuardrailReason, ProbeError, ProbeIoError, ProbeTarget, ProbeTelemetrySink, TelemetryError,
};
