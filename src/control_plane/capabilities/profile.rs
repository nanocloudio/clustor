use crate::telemetry::MetricsRegistry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PartitionProfile {
    Latency,
    Throughput,
    Wan,
    Zfs,
}

impl PartitionProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            PartitionProfile::Latency => "latency",
            PartitionProfile::Throughput => "throughput",
            PartitionProfile::Wan => "wan",
            PartitionProfile::Zfs => "zfs",
        }
    }

    pub fn config(&self) -> PartitionProfileConfig {
        match self {
            PartitionProfile::Latency => PartitionProfileConfig {
                ingest_ops_target: Some(50_000),
                throughput_alert_floor: Some(40_000),
                strict_fallback_local_only_demote_ms: 14_400_000,
                cp_durability_proof_ttl_ms: 43_200_000,
            },
            PartitionProfile::Throughput => PartitionProfileConfig {
                ingest_ops_target: Some(120_000),
                throughput_alert_floor: Some(100_000),
                strict_fallback_local_only_demote_ms: 14_400_000,
                cp_durability_proof_ttl_ms: 86_400_000,
            },
            PartitionProfile::Wan => PartitionProfileConfig {
                ingest_ops_target: Some(25_000),
                throughput_alert_floor: Some(20_000),
                strict_fallback_local_only_demote_ms: 21_600_000,
                cp_durability_proof_ttl_ms: 64_800_000,
            },
            PartitionProfile::Zfs => PartitionProfileConfig {
                ingest_ops_target: None,
                throughput_alert_floor: None,
                strict_fallback_local_only_demote_ms: 14_400_000,
                cp_durability_proof_ttl_ms: 43_200_000,
            },
        }
    }

    pub fn variants() -> [PartitionProfile; 4] {
        [
            PartitionProfile::Latency,
            PartitionProfile::Throughput,
            PartitionProfile::Wan,
            PartitionProfile::Zfs,
        ]
    }
}

impl FromStr for PartitionProfile {
    type Err = ProfileCapabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "latency" | "cp" | "control_plane" => Ok(PartitionProfile::Latency),
            "throughput" => Ok(PartitionProfile::Throughput),
            "wan" => Ok(PartitionProfile::Wan),
            "zfs" => Ok(PartitionProfile::Zfs),
            other => Err(ProfileCapabilityError::UnknownProfile {
                profile: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionProfileConfig {
    pub ingest_ops_target: Option<u64>,
    pub throughput_alert_floor: Option<u64>,
    pub strict_fallback_local_only_demote_ms: u64,
    pub cp_durability_proof_ttl_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileCapability {
    GroupFsync,
    DeltaSnapshots,
    Observers,
    CommitAllowsPreDurable,
    Aggregator,
    Blake3HashSuite,
}

#[derive(Debug, Clone, Default)]
pub struct ProfileCapabilities {
    allowed: HashSet<ProfileCapability>,
}

impl ProfileCapabilities {
    pub fn new(capabilities: impl IntoIterator<Item = ProfileCapability>) -> Self {
        Self {
            allowed: capabilities.into_iter().collect(),
        }
    }

    pub fn allows(&self, capability: ProfileCapability) -> bool {
        self.allowed.contains(&capability)
    }
}

#[derive(Debug, Clone)]
pub struct ProfileCapabilityRegistry {
    map: HashMap<PartitionProfile, ProfileCapabilities>,
}

impl ProfileCapabilityRegistry {
    pub fn with_capabilities(map: HashMap<PartitionProfile, ProfileCapabilities>) -> Self {
        Self { map }
    }

    pub fn ensure_capability(
        &self,
        profile: PartitionProfile,
        capability: ProfileCapability,
    ) -> Result<(), ProfileCapabilityError> {
        if self.allows(profile, capability) {
            Ok(())
        } else {
            Err(ProfileCapabilityError::CapabilityForbidden {
                profile,
                capability,
            })
        }
    }

    pub fn ensure_group_fsync_allowed(
        &self,
        profile: PartitionProfile,
    ) -> Result<(), ProfileCapabilityError> {
        self.ensure_capability(profile, ProfileCapability::GroupFsync)
    }

    pub fn ensure_delta_snapshots_allowed(
        &self,
        profile: PartitionProfile,
    ) -> Result<(), ProfileCapabilityError> {
        self.ensure_capability(profile, ProfileCapability::DeltaSnapshots)
    }

    pub fn ensure_observers_allowed(
        &self,
        profile: PartitionProfile,
    ) -> Result<(), ProfileCapabilityError> {
        self.ensure_capability(profile, ProfileCapability::Observers)
    }

    pub fn ensure_commit_allows_pre_durable(
        &self,
        profile: PartitionProfile,
    ) -> Result<(), ProfileCapabilityError> {
        self.ensure_capability(profile, ProfileCapability::CommitAllowsPreDurable)
    }

    pub fn ensure_aggregator_allowed(
        &self,
        profile: PartitionProfile,
    ) -> Result<(), ProfileCapabilityError> {
        self.ensure_capability(profile, ProfileCapability::Aggregator)
    }

    pub fn ensure_blake3_allowed(
        &self,
        profile: PartitionProfile,
    ) -> Result<(), ProfileCapabilityError> {
        self.ensure_capability(profile, ProfileCapability::Blake3HashSuite)
    }

    pub fn allows(&self, profile: PartitionProfile, capability: ProfileCapability) -> bool {
        self.map
            .get(&profile)
            .map(|caps| caps.allows(capability))
            .unwrap_or(false)
    }

    pub fn guard_operation(
        &self,
        profile: PartitionProfile,
        capability: ProfileCapability,
        operation: impl Into<String>,
    ) -> Result<(), CapabilityGateViolation> {
        if self.allows(profile, capability) {
            Ok(())
        } else {
            Err(CapabilityGateViolation {
                profile,
                capability,
                operation: operation.into(),
            })
        }
    }

    pub fn record_metrics(&self, registry: &mut MetricsRegistry) {
        for profile in PartitionProfile::variants() {
            let prefix = format!("profile.capability.{}", profile.as_str());
            for capability in [
                ProfileCapability::Aggregator,
                ProfileCapability::GroupFsync,
                ProfileCapability::DeltaSnapshots,
            ] {
                let gauge = format!("{prefix}.{}", capability.telemetry_label());
                let allowed = if self.allows(profile, capability) {
                    1
                } else {
                    0
                };
                registry.set_gauge(gauge, allowed);
            }
        }
    }
}

impl Default for ProfileCapabilityRegistry {
    fn default() -> Self {
        let mut map = HashMap::new();
        map.insert(
            PartitionProfile::Latency,
            ProfileCapabilities::new([
                ProfileCapability::DeltaSnapshots,
                ProfileCapability::Aggregator,
            ]),
        );
        map.insert(
            PartitionProfile::Throughput,
            ProfileCapabilities::new([
                ProfileCapability::GroupFsync,
                ProfileCapability::DeltaSnapshots,
                ProfileCapability::Observers,
                ProfileCapability::CommitAllowsPreDurable,
                ProfileCapability::Aggregator,
                ProfileCapability::Blake3HashSuite,
            ]),
        );
        map.insert(
            PartitionProfile::Wan,
            ProfileCapabilities::new([
                ProfileCapability::GroupFsync,
                ProfileCapability::DeltaSnapshots,
                ProfileCapability::Observers,
                ProfileCapability::Aggregator,
                ProfileCapability::Blake3HashSuite,
            ]),
        );
        map.insert(
            PartitionProfile::Zfs,
            ProfileCapabilities::new([
                ProfileCapability::DeltaSnapshots,
                ProfileCapability::Aggregator,
            ]),
        );
        Self { map }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProfileCapabilityError {
    #[error("profile {profile} is unknown")]
    UnknownProfile { profile: String },
    #[error("capability {capability:?} not allowed for profile {profile:?}")]
    CapabilityForbidden {
        profile: PartitionProfile,
        capability: ProfileCapability,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{operation} blocked: profile {profile:?} forbids capability {capability}")]
pub struct CapabilityGateViolation {
    pub profile: PartitionProfile,
    pub capability: ProfileCapability,
    pub operation: String,
}

impl fmt::Display for ProfileCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            ProfileCapability::GroupFsync => "Group-Fsync",
            ProfileCapability::DeltaSnapshots => "delta snapshots",
            ProfileCapability::Observers => "observers",
            ProfileCapability::CommitAllowsPreDurable => "CommitAllowsPreDurable",
            ProfileCapability::Aggregator => "Aggregator profile",
            ProfileCapability::Blake3HashSuite => "BLAKE3 hash suite",
        };
        write!(f, "{label}")
    }
}

impl ProfileCapability {
    fn telemetry_label(&self) -> &'static str {
        match self {
            ProfileCapability::GroupFsync => "group_fsync",
            ProfileCapability::DeltaSnapshots => "delta_snapshots",
            ProfileCapability::Observers => "observers",
            ProfileCapability::CommitAllowsPreDurable => "commit_allows_pre_durable",
            ProfileCapability::Aggregator => "aggregator",
            ProfileCapability::Blake3HashSuite => "blake3",
        }
    }
}
