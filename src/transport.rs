use crate::consensus::CatalogVersion;
pub mod heartbeat;
pub mod raft;
use crate::wire::{BundleNegotiationLog, NegotiationError, WireCatalogNegotiator};
use std::path::{Path, PathBuf};

/// Configuration describing how a partition records catalog negotiations.
#[derive(Debug, Clone)]
pub struct CatalogNegotiationConfig {
    pub partition_id: String,
    pub log_path: PathBuf,
    pub remote_version: CatalogVersion,
}

impl CatalogNegotiationConfig {
    /// Resolves the negotiation log path relative to the dataset root when necessary.
    pub fn resolved_log_path(&self, dataset_root: &Path) -> PathBuf {
        if self.log_path.is_absolute() {
            self.log_path.clone()
        } else {
            dataset_root.join(&self.log_path)
        }
    }

    /// Performs the on-wire negotiation and records the outcome in `bundle_negotiation.log`.
    pub fn negotiate(
        &self,
        dataset_root: &Path,
        local_catalog: CatalogVersion,
    ) -> Result<CatalogNegotiationReport, NegotiationError> {
        let log_path = self.resolved_log_path(dataset_root);
        let log = BundleNegotiationLog::new(log_path.clone());
        let negotiator = WireCatalogNegotiator::new(self.partition_id.clone(), log);
        let negotiated = negotiator.negotiate(local_catalog, self.remote_version)?;
        Ok(CatalogNegotiationReport {
            partition_id: self.partition_id.clone(),
            log_path,
            local_version: negotiated,
            remote_version: self.remote_version,
        })
    }
}

/// Result of a transport catalog negotiation. Carries the persisted log location so runtime
/// components can record revocations when forward-compatibility violations are detected.
#[derive(Debug, Clone)]
pub struct CatalogNegotiationReport {
    pub partition_id: String,
    pub log_path: PathBuf,
    pub local_version: CatalogVersion,
    pub remote_version: CatalogVersion,
}

impl CatalogNegotiationReport {
    /// Returns true when the local transport advertised tolerance for a future minor.
    pub fn forward_tolerance_active(&self) -> bool {
        self.local_version.forward_parse_max_minor > self.local_version.minor
    }

    /// Full path to `bundle_negotiation.log`.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Explicitly revokes the forward-compatibility pledge and records the reason.
    pub fn revoke_forward_tolerance(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<CatalogVersion, NegotiationError> {
        let log = BundleNegotiationLog::new(self.log_path.clone());
        let negotiator = WireCatalogNegotiator::new(self.partition_id.clone(), log);
        let updated =
            negotiator.revoke_forward_tolerance(self.local_version, self.remote_version, reason)?;
        self.local_version = updated;
        Ok(self.local_version)
    }

    /// Records that the peer sent an unknown field. Returns true when this triggered a revocation.
    pub fn note_unknown_field(
        &mut self,
        field_name: impl Into<String>,
    ) -> Result<bool, NegotiationError> {
        let field_name = field_name.into();
        self.record_forward_compat_violation(format!("unknown field: {field_name}"))
    }

    /// Generic helper for recording a violation that should revoke forward compatibility.
    pub fn record_forward_compat_violation(
        &mut self,
        detail: impl Into<String>,
    ) -> Result<bool, NegotiationError> {
        if !self.forward_tolerance_active() {
            return Ok(false);
        }
        self.revoke_forward_tolerance(format!("forward compatibility revoked: {}", detail.into()))?;
        Ok(true)
    }
}

/// Helper passed to parsers so they can revoke forward compatibility when they encounter
/// unexpected fields or frames after advertising `forward_parse_max_minor`.
pub struct ForwardCompatTracker<'a> {
    report: Option<&'a mut CatalogNegotiationReport>,
}

impl<'a> ForwardCompatTracker<'a> {
    pub fn new(report: &'a mut CatalogNegotiationReport) -> Self {
        Self {
            report: Some(report),
        }
    }

    pub fn noop() -> Self {
        Self { report: None }
    }

    pub fn note_unknown_field(
        &mut self,
        field_name: impl Into<String>,
    ) -> Result<bool, NegotiationError> {
        match self.report.as_mut() {
            Some(report) => report.note_unknown_field(field_name),
            None => Ok(false),
        }
    }

    pub fn record_violation(
        &mut self,
        detail: impl Into<String>,
    ) -> Result<bool, NegotiationError> {
        match self.report.as_mut() {
            Some(report) => report.record_forward_compat_violation(detail),
            None => Ok(false),
        }
    }
}
