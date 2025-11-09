//! Bootstrap-time utilities: filesystem vetting, probes, and boot records.

pub mod boot_record;
pub mod filesystem;
pub mod pipeline;
pub mod probe;

pub use filesystem::{
    DeviceCapabilities, Ext4DataMode, Ext4Options, FilesystemDescriptor, FilesystemDetector,
    FilesystemEvaluation, FilesystemStack, OrderedFilesystemProfile, RejectionReason,
    StackAttestation, WriteCachePolicy, XfsOptions, ZfsLogBias, ZfsOptions, ZfsSyncPolicy,
};

pub use boot_record::{BootRecord, BootRecordError, BootRecordStore};

pub use crate::transport::{CatalogNegotiationConfig, CatalogNegotiationReport};
pub use pipeline::{
    BootstrapConfig, BootstrapError, BootstrapEvent, BootstrapPipeline, BootstrapReport,
    BootstrapRequest, BootstrapStep, ClusterProfile, ManifestValidationConfig, ProfileError,
    ProfileLoader, ShutdownManager, ShutdownStatus,
};
pub use probe::{
    run_probe_and_persist, FsyncProbeConfig, FsyncProbeContext, FsyncProbeResult, FsyncProbeRunner,
    FsyncProbeTelemetry, GroupFsyncDecision, GroupFsyncGuard, GroupFsyncGuardConfig,
    GuardrailReason, ProbeError, ProbeIoError, ProbeTarget, ProbeTelemetrySink, TelemetryError,
};
