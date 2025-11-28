//! Capability gating: partition profiles and feature-gate manifests.

pub mod feature_guard;
pub mod profile;

pub use feature_guard::{
    future_gates, FeatureCapabilityMatrix, FeatureCapabilityState, FeatureGateState,
    FeatureGateTelemetry, FeatureGateTelemetryEntry, FeatureManifest, FeatureManifestBuilder,
    FeatureManifestEntry, FeatureManifestError, FutureGateDescriptor, ParkedFeatureAudit,
    ParkedFeatureError, ParkedFeatureGate,
};

pub use profile::{
    CapabilityGateViolation, PartitionProfile, PartitionProfileConfig, ProfileCapabilities,
    ProfileCapability, ProfileCapabilityError, ProfileCapabilityRegistry,
};
