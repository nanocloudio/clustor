//! Consensus-core components shared across the runtime.

pub mod kernel;
pub mod log_store;
pub mod manifest;

pub use kernel::{
    ConsensusCore, ConsensusCoreConfig, ConsensusCoreStatus, ConsensusCoreTelemetry,
    DemotionReason, DemotionStatus, DurabilityProof, GateBlockMetrics, GateEvaluation,
    GateOperation, GateViolation, StrictFallbackBlockingReason, StrictFallbackMetricsPublisher,
    StrictFallbackState, StrictFallbackWhy,
};
pub use log_store::{
    RaftLogEntry, RaftLogError, RaftLogStore, RaftMetadata, RaftMetadataError, RaftMetadataStore,
    TermIndexSnapshot,
};
pub use manifest::{
    BundleDigest, CatalogVersion, ConsensusCoreManifest, ConsensusCoreManifestBuilder,
    ConsensusCoreManifestError, ProofBundleRef, SectionHash,
};
