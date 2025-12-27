use crate::replication::consensus::CatalogVersion;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Append-only log capturing every bundle negotiation outcome for a partition.
#[derive(Debug, Clone)]
pub struct BundleNegotiationLog {
    path: PathBuf,
}

impl BundleNegotiationLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, entry: &BundleNegotiationEntry) -> Result<(), NegotiationError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Negotiates catalog compatibility and records the outcome.
pub struct WireCatalogNegotiator {
    partition_id: String,
    log: BundleNegotiationLog,
}

impl WireCatalogNegotiator {
    pub fn new(partition_id: impl Into<String>, log: BundleNegotiationLog) -> Self {
        Self {
            partition_id: partition_id.into(),
            log,
        }
    }

    pub fn negotiate(
        &self,
        local: CatalogVersion,
        remote: CatalogVersion,
    ) -> Result<CatalogVersion, NegotiationError> {
        if local.major != remote.major {
            return self.reject(local, remote, "catalog major mismatch");
        }
        if remote.minor > local.forward_parse_max_minor {
            return self.reject(local, remote, "remote minor exceeds local tolerance");
        }
        if local.minor > remote.forward_parse_max_minor {
            return self.reject(local, remote, "local minor exceeds remote tolerance");
        }
        let entry = BundleNegotiationEntry::accepted(&self.partition_id, local, remote);
        self.log.append(&entry)?;
        Ok(local)
    }

    pub fn revoke_forward_tolerance(
        &self,
        mut local: CatalogVersion,
        remote: CatalogVersion,
        reason: impl Into<String>,
    ) -> Result<CatalogVersion, NegotiationError> {
        local.forward_parse_max_minor = local.minor;
        let entry =
            BundleNegotiationEntry::revoked(&self.partition_id, local, remote, reason.into());
        self.log.append(&entry)?;
        Ok(local)
    }

    fn reject(
        &self,
        local: CatalogVersion,
        remote: CatalogVersion,
        reason: impl Into<String>,
    ) -> Result<CatalogVersion, NegotiationError> {
        let entry =
            BundleNegotiationEntry::rejected(&self.partition_id, local, remote, reason.into());
        self.log.append(&entry)?;
        let reason = entry
            .reason
            .clone()
            .ok_or_else(|| NegotiationError::MissingReason {
                partition_id: self.partition_id.clone(),
            })?;
        Err(NegotiationError::WireCatalogMismatch { reason })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleNegotiationEntry {
    pub timestamp_ms: u64,
    pub partition_id: String,
    pub accepted: bool,
    pub reason: Option<String>,
    pub local: CatalogVersion,
    pub remote: CatalogVersion,
}

impl BundleNegotiationEntry {
    fn accepted(partition_id: &str, local: CatalogVersion, remote: CatalogVersion) -> Self {
        Self::new(partition_id, true, None, local, remote)
    }

    fn rejected(
        partition_id: &str,
        local: CatalogVersion,
        remote: CatalogVersion,
        reason: String,
    ) -> Self {
        Self::new(partition_id, false, Some(reason), local, remote)
    }

    fn revoked(
        partition_id: &str,
        local: CatalogVersion,
        remote: CatalogVersion,
        reason: String,
    ) -> Self {
        Self::new(partition_id, false, Some(reason), local, remote)
    }

    fn new(
        partition_id: &str,
        accepted: bool,
        reason: Option<String>,
        local: CatalogVersion,
        remote: CatalogVersion,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            timestamp_ms,
            partition_id: partition_id.into(),
            accepted,
            reason,
            local,
            remote,
        }
    }
}

#[derive(Debug, Error)]
pub enum NegotiationError {
    #[error("wire catalog mismatch: {reason}")]
    WireCatalogMismatch { reason: String },
    #[error("missing rejection reason for partition {partition_id}")]
    MissingReason { partition_id: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}
