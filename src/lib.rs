//! Core library entrypoint for the Clustor consensus core.
//! Currently exposes the strict-fallback state machine described in
//! `docs/specification.md` §0.5 and §2.1.1.
#![deny(unreachable_pub)]
#![deny(unused_must_use)]
#![cfg_attr(docsrs, warn(missing_docs))]

pub mod activation;
#[cfg(feature = "admin-http")]
pub mod admin;
pub mod apply;
pub mod bootstrap;
pub mod config_utils;
pub mod consensus;
pub mod cp;
pub mod cp_raft;
pub mod dr;
pub mod durability;
pub mod error;
pub mod feature_guard;
pub mod flow;
#[cfg(feature = "snapshot-crypto")]
pub mod follower;
pub mod membership;
#[cfg(feature = "net")]
pub mod net;
pub mod overrides;
pub mod profile;
pub mod raft;
pub mod read_index;
pub mod readyz;
pub mod retry;
pub mod security;
#[cfg(feature = "snapshot-crypto")]
pub mod snapshot;
pub mod spec_fixtures;
pub mod spec_matrix;
pub mod spec_self_test;
pub mod storage;
pub mod system_log;
pub mod telemetry;
pub mod terminology;
pub mod transport;
pub mod why;
pub mod wire;

pub use activation::{
    readiness_digest, ActivationBarrier, ActivationBarrierDecision, ActivationBarrierEvaluator,
    ActivationBarrierState, ActivationDigestError, ShadowApplyState, WarmupReadinessPublisher,
    WarmupReadinessRecord, WarmupReadinessSnapshot,
};
pub use apply::{
    AckHandleError, AckHandleFailureReason, AckHandleMetrics, AckHandlePolicy, AckHandleStatus,
    AckHandleSupervisor, AckTimeoutInfo, ApplyBatch, ApplyBudgetDecision, ApplyEntry, ApplyMetrics,
    ApplyProfile, ApplyProfileError, ApplyProfileReport, ApplyRuntime, ApplyScheduler,
    ApplySchedulerError, DedupeCache, DedupeConfig, DedupeSnapshot, DedupeToken,
    InMemoryAckHandleMetrics, InMemoryApplyMetrics, ManagedAckHandle, ReplayGuard,
    TelemetryAckHandleMetrics, TelemetryApplyMetrics,
};
pub use consensus::{
    BundleDigest, CatalogVersion, ConsensusCore, ConsensusCoreConfig, ConsensusCoreManifest,
    ConsensusCoreManifestBuilder, ConsensusCoreManifestError, ConsensusCoreStateSnapshot,
    ConsensusCoreStatus, ConsensusCoreTelemetry, DemotionReason, DemotionStatus, DurabilityProof,
    GateBlockMetrics, GateEvaluation, GateOperation, GateViolation, ProofBundleRef, RaftLogEntry,
    RaftLogError, RaftLogStore, RaftMetadata, RaftMetadataError, RaftMetadataStore, SectionHash,
    StrictFallbackBlockingReason, StrictFallbackMetricsPublisher, StrictFallbackState,
    StrictFallbackWhy, TermIndexSnapshot,
};

pub use cp::{
    client::{CpApiTransport, CpClientError, CpControlPlaneClient, TransportResponse},
    CpCachePolicy, CpCacheState, CpGuardError, CpProofCoordinator, CpUnavailableReason,
    CpUnavailableResponse, ReadIndexPermit,
};
#[cfg(feature = "snapshot-crypto")]
pub use cp::{
    StrictFallbackSnapshotImportError, StrictFallbackSnapshotImportReason,
    StrictFallbackSnapshotImportRecord,
};
pub use cp_raft::{CpPlacementClient, PlacementRecord, PlacementSnapshot, RoutingEpochError};
pub use dr::{DrFenceError, DrFenceManager, FenceState};
pub use error::{ClustorError, GuardError, SerializationError};
pub use profile::{
    CapabilityGateViolation, PartitionProfile, ProfileCapabilities, ProfileCapability,
    ProfileCapabilityError, ProfileCapabilityRegistry,
};
pub use read_index::{
    CommitVisibility, ReadGateClause, ReadGateEvaluator, ReadGateInputs, ReadGateTelemetry,
};
pub use system_log::{SystemLogEntry, SystemLogError};

#[cfg(feature = "async-net")]
pub use raft::runtime_scaffold::{RaftNodeCallbacks, RaftNodeHandle, RaftNodeScaffold};
pub use raft::{
    AppendEntriesFrameError, AppendEntriesOutcome, AppendEntriesProcessor, AppendEntriesRequest,
    AppendEntriesResponse, CandidateState, DeviceLatencyConfig, ElectionController,
    ElectionProfile, ElectionTimer, HeartbeatBatcher, HighRttState, LatencyGuardReason,
    LeaderStickinessConfig, LeaderStickinessController, LeaderStickinessGate, PartitionQuorum,
    PartitionQuorumConfig, PartitionQuorumStatus, PreVoteDecision, PreVoteRejectReason,
    PreVoteResponse, PreVoteResponseFrameError, QuorumError, ReplicaId, ReplicaProgress,
    RequestVoteFrameError, RequestVoteRejectReason, RequestVoteRequest, RequestVoteResponse,
    StickinessDecision, StickinessTelemetry,
};

pub use durability::{
    AckHandle, AckRecord, DurabilityAckMessage, DurabilityLedger, DurabilityMetricsPublisher,
    IoMode, LedgerError, LedgerUpdate,
};
pub use flow::{
    CreditHint, DualCreditPidController, FlowDecision, FlowIncidentKind, FlowLagClass, FlowProfile,
    FlowSloIncidentRecord, FlowSloMonitor, FlowThrottleEnvelope, FlowThrottleReason,
    FlowThrottleState, IngestStatusCode, QuotaOverrideRecord, TenantFlowController,
    TenantFlowDecision, TenantQuota, TenantQuotaManager,
};
#[cfg(feature = "snapshot-crypto")]
pub use follower::{FollowerCapabilityGate, FollowerReadError};
pub use membership::{
    evaluate_survivability, CatchUpDecision, CatchUpReason, LearnerCatchUpConfig,
    LearnerCatchUpEvaluator, SurvivabilityInputs, SurvivabilityReport, SurvivabilityResult,
};
pub use overrides::{DiskOverrideDevice, DiskOverrideDocument, DiskWriteCacheMode, OverrideError};
pub use readyz::{
    map_partition_ratios, map_partition_ratios_with_barriers, readyz_from_warmup_snapshot,
    OverrideStatus, OverrideType, ReadyExplain, ReadyStateHealth, ReadyStateProbe,
    ReadyzCapabilityRecord, ReadyzRecord, ReadyzSnapshot,
};

#[cfg(feature = "admin-http")]
pub use admin::{
    AdminCapability, AdminError, AdminHandler, AdminRequestContext, AdminService,
    AdminServiceError, CreatePartitionRequest, CreatePartitionResponse, DurabilityMode,
    IdempotencyLedger, PartitionSpec, ReplicaSpec, SetDurabilityModeRequest,
    SetDurabilityModeResponse, SnapshotThrottleRequest, SnapshotThrottleResponse,
    SnapshotTriggerRequest, SnapshotTriggerResponse, ThrottleExplainResponse,
    TransferLeaderRequest, TransferLeaderResponse,
};
pub use feature_guard::{
    future_gates, FeatureCapabilityMatrix, FeatureCapabilityState, FeatureGateState,
    FeatureGateTelemetry, FeatureGateTelemetryEntry, FeatureManifest, FeatureManifestBuilder,
    FeatureManifestEntry, FeatureManifestError, FutureGateDescriptor, ParkedFeatureAudit,
    ParkedFeatureError, ParkedFeatureGate,
};
#[cfg(feature = "net")]
pub use net::{
    load_identity_from_pem, load_trust_store_from_pem, HttpCpTransport, HttpCpTransportBuilder,
    RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkClientOptions, RaftNetworkServer,
    RaftNetworkServerConfig, RaftNetworkServerHandle, ReadyzHttpServer, ReadyzHttpServerConfig,
    ReadyzHttpServerHandle, ReadyzPublisher, TlsIdentity, TlsTrustStore, WhyHttpServer,
    WhyHttpServerConfig, WhyHttpServerHandle, WhyPublisher,
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
pub use spec_fixtures::{
    FixtureBundle, FixtureBundleGenerator, FixtureEntry, FixtureError, SpecLint,
};
pub use spec_matrix::{MatrixOutcome, MatrixReport, MatrixRunner, MatrixScenario};
pub use spec_self_test::{
    SpecSelfTestError, SpecSelfTestHarness, SpecSelfTestResult, SpecTestOutcome,
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
pub use terminology::{
    runtime_terms, RuntimeTerm, TERM_DURABILITY_RECORD, TERM_FOLLOWER_READ_SNAPSHOT,
    TERM_GROUP_FSYNC, TERM_STRICT,
};
pub use transport::{
    heartbeat::HeartbeatScheduler,
    raft::{RaftRpcHandler, RaftRpcServer, RaftTransportError},
    CatalogNegotiationConfig, CatalogNegotiationReport, ForwardCompatTracker,
};
#[cfg(feature = "snapshot-crypto")]
pub use why::WhySnapshotBlocked;
pub use why::{LocalRole, WhyNotLeader, WhySchemaHeader};
pub use wire::{
    BundleNegotiationEntry, BundleNegotiationLog, NegotiationError, WireCatalogNegotiator,
};
