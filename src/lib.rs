//! Core library entrypoint for the Clustor consensus core.
//! Currently exposes the strict-fallback state machine described in
//! `docs/specification.md` §0.5 and §2.1.1.
#![deny(unreachable_pub)]
#![deny(unused_must_use)]
#![cfg_attr(docsrs, warn(missing_docs))]

pub mod control_plane;
pub mod lifecycle;
#[cfg(feature = "net")]
pub mod net;
pub mod observability;
pub mod persistence;
pub mod replication;
pub mod security;
pub mod spec;
pub mod util;

// Re-export reorganized modules for API stability.
pub use observability::{readyz, system_log, telemetry};
#[cfg(feature = "snapshot-crypto")]
pub use persistence::snapshot;
pub use persistence::{durability, storage};

// Legacy module aliases for moved spec helpers.
pub use spec::fixtures as spec_fixtures;
pub use spec::matrix as spec_matrix;
pub use spec::self_test as spec_self_test;
pub use spec::terminology;
// Legacy module aliases for moved capability helpers.
pub use control_plane::capabilities::feature_guard;
pub use control_plane::capabilities::profile;
// Legacy module alias for durability fence helpers.
pub use durability::fence as dr;
// Legacy module aliases for shared utilities.
pub use util::config as config_utils;
pub use util::retry;

#[doc(hidden)]
pub mod error {
    pub use crate::util::error::*;
}

#[doc(hidden)]
pub mod cp_raft {
    pub use crate::control_plane::core::placement::{
        CpPlacementClient, PlacementRecord, PlacementSnapshot, RoutingEpochError,
    };
}

#[cfg(feature = "snapshot-crypto")]
#[doc(hidden)]
pub mod follower {
    pub use crate::snapshot::{
        FollowerCapabilityGate, FollowerReadError, FollowerSnapshotReadError,
    };
}

#[doc(hidden)]
pub mod read_index {
    pub use crate::control_plane::core::{
        CommitVisibility, ReadGateClause, ReadGateDecision, ReadGateEvaluator, ReadGateInputs,
        ReadGateTelemetry,
    };
}

#[doc(hidden)]
pub mod overrides {
    pub use crate::readyz::{
        DiskOverrideDevice, DiskOverrideDocument, DiskWriteCacheMode, OverrideError,
        OverrideStatus, OverrideType, QueueFlags,
    };
}

#[cfg(feature = "net")]
#[doc(hidden)]
pub mod why {
    pub use crate::net::control_plane::why::*;
}

#[doc(hidden)]
pub mod wire {
    pub use crate::replication::transport::{
        BundleNegotiationEntry, BundleNegotiationLog, NegotiationError, WireCatalogNegotiator,
    };
}

#[doc(hidden)]
pub mod protocol {
    pub use crate::replication;
    pub use crate::replication::*;
}

pub use lifecycle::activation::{
    readiness_digest, ActivationBarrier, ActivationBarrierDecision, ActivationBarrierEvaluator,
    ActivationBarrierState, ActivationDigestError, ShadowApplyState, WarmupReadinessPublisher,
    WarmupReadinessRecord, WarmupReadinessSnapshot,
};

pub use replication::*;

pub use control_plane::*;

pub use dr::{DrFenceError, DrFenceManager, FenceState};
pub use system_log::{SystemLogEntry, SystemLogError};
pub use util::error::{ClustorError, GuardError, SerializationError};

pub use durability::{
    AckHandle, AckRecord, DurabilityAckMessage, DurabilityLedger, DurabilityMetricsPublisher,
    IoMode, LedgerError, LedgerUpdate,
};
pub use readyz::{
    map_partition_ratios, map_partition_ratios_with_barriers, readyz_from_warmup_snapshot,
    DiskOverrideDevice, DiskOverrideDocument, DiskWriteCacheMode, OverrideError, OverrideStatus,
    OverrideType, QueueFlags, ReadyExplain, ReadyStateHealth, ReadyStateProbe,
    ReadyzCapabilityRecord, ReadyzRecord, ReadyzSnapshot,
};
#[cfg(feature = "snapshot-crypto")]
pub use snapshot::{FollowerCapabilityGate, FollowerReadError};

#[cfg(feature = "admin-http")]
pub use control_plane::admin::{
    AdminCapability, AdminError, AdminHandler, AdminRequestContext, AdminService,
    AdminServiceError, CreatePartitionRequest, CreatePartitionResponse, DurabilityMode,
    IdempotencyLedger, PartitionSpec, ReplicaSpec, SetDurabilityModeRequest,
    SetDurabilityModeResponse, SnapshotThrottleRequest, SnapshotThrottleResponse,
    SnapshotTriggerRequest, SnapshotTriggerResponse, ThrottleExplainResponse,
    TransferLeaderRequest, TransferLeaderResponse,
};
pub use control_plane::capabilities::feature_guard::{
    future_gates, FeatureCapabilityMatrix, FeatureCapabilityState, FeatureGateState,
    FeatureGateTelemetry, FeatureGateTelemetryEntry, FeatureManifest, FeatureManifestBuilder,
    FeatureManifestEntry, FeatureManifestError, FutureGateDescriptor, ParkedFeatureAudit,
    ParkedFeatureError, ParkedFeatureGate,
};
#[cfg(all(feature = "net", feature = "snapshot-crypto"))]
pub use net::WhySnapshotBlocked;
#[cfg(feature = "net")]
pub use net::{
    load_identity_from_pem, load_trust_store_from_pem, HttpCpTransport, HttpCpTransportBuilder,
    LocalRole, RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkClientOptions,
    RaftNetworkServer, RaftNetworkServerConfig, RaftNetworkServerHandle, ReadyzHttpServer,
    ReadyzHttpServerConfig, ReadyzHttpServerHandle, ReadyzPublisher, TlsIdentity, TlsTrustStore,
    WhyHttpServer, WhyHttpServerConfig, WhyHttpServerHandle, WhyNotLeader, WhyPublisher,
    WhySchemaHeader,
};
#[cfg(all(feature = "net", feature = "admin-http"))]
pub use net::{AdminHttpServer, AdminHttpServerConfig, AdminHttpServerHandle};
#[cfg(all(feature = "management", feature = "async-net"))]
pub use net::{AsyncManagementHttpServer, AsyncManagementHttpServerHandle};
#[cfg(feature = "management")]
pub use net::{ManagementHttpServer, ManagementHttpServerConfig, ManagementHttpServerHandle};
#[cfg(feature = "admin-http")]
pub use security::{
    BreakGlassAudit, BreakGlassAuditLog, BreakGlassToken, RbacManifest, RbacManifestCache,
    RbacPrincipal, RbacRole,
};
pub use security::{
    Certificate, KeyEpochWatcher, MtlsIdentityManager, SecurityError, SerialNumber, SpiffeId,
};
#[cfg(feature = "snapshot-crypto")]
pub use snapshot::{
    AppendEntriesBatch, CommitEpochEntry, DedupShardDigest, HmacManifestSigner, ManifestEncryption,
    ManifestError, ManifestSignature, ManifestSigner, ManifestVerification,
    ManifestVerificationError, SignedSnapshotManifest, SnapshotAppendEntriesCoordinator,
    SnapshotAuthorizationError, SnapshotAuthorizer, SnapshotCadenceTelemetry, SnapshotChunk,
    SnapshotChunkExporter, SnapshotChunkPayload, SnapshotDeltaChainState,
    SnapshotDeltaChainTelemetry, SnapshotDeltaPolicy, SnapshotDeltaPolicyError, SnapshotExportCaps,
    SnapshotExportController, SnapshotExportError, SnapshotExportProfile, SnapshotExportTelemetry,
    SnapshotFallbackController, SnapshotFallbackTelemetry, SnapshotImportConfig,
    SnapshotImportError, SnapshotImportNodeBudget, SnapshotImportNodeTelemetrySnapshot,
    SnapshotImportRetryPolicy, SnapshotImportTelemetrySnapshot, SnapshotImportValidationError,
    SnapshotImportValidator, SnapshotKind, SnapshotManifest, SnapshotManifestBuilder,
    SnapshotManifestVerifier, SnapshotOnlyReadyState, SnapshotReadError, SnapshotReadHeaders,
    SnapshotReadRequest, SnapshotReadResponse, SnapshotReadiness, SnapshotThrottleEnvelope,
    SnapshotThrottleReason, SnapshotThrottleState, SnapshotTrigger, SnapshotTriggerConfig,
    SnapshotTriggerDecision, SnapshotTriggerReason,
};
pub use spec::fixtures::{
    FixtureBundle, FixtureBundleGenerator, FixtureEntry, FixtureError, SpecLint,
};
pub use spec::matrix::{MatrixOutcome, MatrixReport, MatrixRunner, MatrixScenario};
pub use spec::self_test::{
    SpecSelfTestError, SpecSelfTestHarness, SpecSelfTestResult, SpecTestOutcome,
};
pub use spec::terminology::{
    runtime_terms, RuntimeTerm, TERM_DURABILITY_RECORD, TERM_FOLLOWER_READ_SNAPSHOT,
    TERM_GROUP_FSYNC, TERM_LEASE_ENABLE, TERM_SNAPSHOT_DELTA, TERM_STRICT,
};
pub use storage::{
    CompactionAuthAck, CompactionBlockReason, CompactionDecision, CompactionGate,
    CompactionMetadata, CompactionPlanRequest, CompactionState, CryptoError, DataEncryptionKey,
    EntryFrame, EntryFrameBuilder, EntryFrameError, FrameHeader, FsyncMode, GroupFsyncPolicy,
    GroupFsyncPolicyTelemetry, KeyEpoch, KeyEpochError, KeyEpochTracker, ManifestAuthorizationLog,
    ManifestGate, ManifestLogError, MerkleDigest, NonceLedgerConfig, NonceLedgerError,
    NonceReservationAbandon, NonceReservationLedger, NonceReservationRange,
    NonceReservationTelemetry, SegmentHandle, SegmentHeader, SegmentHeaderError, SegmentHealth,
    SegmentManager, SegmentPosition, SegmentSkipReason, SnapshotAuthorizationRecord, StorageLayout,
    StorageLayoutError, StorageMetadata, StorageMetadataError, StorageMetadataStore, StoragePaths,
    StorageState, WalAead, WalAppendResult, WalReplayError, WalReplayResult, WalReplayScanner,
    WalReservation, WalTruncation, WalWriter, WalWriterError, MAX_RESERVATION_BLOCKS,
    WAL_CRYPTO_BLOCK_BYTES,
};
pub use telemetry::{
    CpDegradationMetrics, IncidentCorrelator, IncidentDecision, MetricsRegistry, MetricsSnapshot,
    SharedMetricsRegistry, TelemetryError,
};
