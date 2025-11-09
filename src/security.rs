use crate::storage::crypto::{KeyEpoch, KeyEpochTracker};
use crate::telemetry::MetricsRegistry;
use log::{info, warn};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use thiserror::Error;

const SECURITY_SPEC: &str = "§12.Mtls";
const SECURITY_QUARANTINE_REASON_MTLS: &str = "VOCAB.Security.Quarantine.MtlsRevocation";

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct SerialNumber(Vec<u8>);

impl SerialNumber {
    pub const MAX_LEN: usize = 20;

    pub fn from_u64(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        Self::from_be_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn from_be_bytes(raw: &[u8]) -> Self {
        let mut first_non_zero = 0;
        while first_non_zero < raw.len().saturating_sub(1) && raw[first_non_zero] == 0 {
            first_non_zero += 1;
        }
        let slice = &raw[first_non_zero..];
        if slice.is_empty() {
            SerialNumber(vec![0])
        } else {
            SerialNumber(slice.to_vec())
        }
    }
}

fn serial_hex(serial: &SerialNumber) -> String {
    hex::encode(serial.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeId {
    pub fn parse(id: &str) -> Result<Self, SecurityError> {
        let trimmed = id
            .strip_prefix("spiffe://")
            .ok_or_else(|| SecurityError::InvalidSpiffeId(id.to_string()))?;
        let mut parts = trimmed.splitn(2, '/');
        let trust_domain = parts
            .next()
            .ok_or_else(|| SecurityError::InvalidSpiffeId(id.to_string()))?;
        let path = parts
            .next()
            .ok_or_else(|| SecurityError::InvalidSpiffeId(id.to_string()))?;
        Ok(Self {
            trust_domain: trust_domain.to_string(),
            path: format!("/{path}"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub spiffe_id: SpiffeId,
    pub serial: SerialNumber,
    pub valid_from: Instant,
    pub valid_until: Instant,
}

#[derive(Debug)]
pub struct MtlsIdentityManager {
    active: Certificate,
    pending: Option<Certificate>,
    trust_domain: String,
    dual_validity: Duration,
    revoked_serials: HashSet<SerialNumber>,
    last_revocation_update: Instant,
    revocation_ttl: Duration,
}

impl MtlsIdentityManager {
    pub fn new(
        active: Certificate,
        trust_domain: impl Into<String>,
        dual_validity: Duration,
        revocation_ttl: Duration,
        now: Instant,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            dual_validity,
            revoked_serials: HashSet::new(),
            last_revocation_update: now,
            revocation_ttl,
            pending: None,
            active,
        }
    }

    pub fn offer_next(&mut self, certificate: Certificate) {
        self.pending = Some(certificate);
    }

    pub fn rotate(&mut self, now: Instant) -> Result<(), SecurityError> {
        if let Some(pending) = &self.pending {
            if pending.valid_from > now {
                warn!(
                    "event=mtls_rotation_block clause={} reason=certificate_not_yet_valid trust_domain={} pending_valid_from={:?}",
                    SECURITY_SPEC,
                    self.trust_domain,
                    pending.valid_from
                );
                return Err(SecurityError::CertificateNotYetValid);
            }
            if pending.valid_until < now {
                warn!(
                    "event=mtls_rotation_block clause={} reason=certificate_expired trust_domain={} pending_valid_until={:?}",
                    SECURITY_SPEC,
                    self.trust_domain,
                    pending.valid_until
                );
                return Err(SecurityError::CertificateExpired);
            }
        }
        if let Some(next) = self.pending.take() {
            info!(
                "event=mtls_rotation clause={} trust_domain={} new_serial={} valid_from={:?} valid_until={:?}",
                SECURITY_SPEC,
                self.trust_domain,
                serial_hex(&next.serial),
                next.valid_from,
                next.valid_until
            );
            self.active = next;
        }
        Ok(())
    }

    pub fn verify_peer(
        &mut self,
        certificate: &Certificate,
        now: Instant,
    ) -> Result<(), SecurityError> {
        self.refresh_revocations(now);
        if certificate.spiffe_id.trust_domain != self.trust_domain {
            warn!(
                "event=mtls_verify_reject clause={} reason=trust_domain_mismatch expected_trust_domain={} observed_trust_domain={} spiffe_id={:?}",
                SECURITY_SPEC,
                self.trust_domain,
                certificate.spiffe_id.trust_domain,
                certificate.spiffe_id
            );
            return Err(SecurityError::TrustDomainMismatch);
        }
        if certificate.valid_from > now {
            return Err(SecurityError::CertificateNotYetValid);
        }
        if certificate.valid_until < now {
            return Err(SecurityError::CertificateExpired);
        }
        if self.revoked_serials.contains(&certificate.serial) {
            return Err(SecurityError::CertificateRevoked);
        }
        if let Some(threshold) = self.active.valid_from.checked_sub(self.dual_validity) {
            if certificate.valid_from < threshold {
                return Err(SecurityError::DualValidityViolation);
            }
        }
        Ok(())
    }

    pub fn revoke_serial(&mut self, serial: SerialNumber, now: Instant) {
        let serial_hex = serial_hex(&serial);
        self.revoked_serials.insert(serial);
        self.last_revocation_update = now;
        info!(
            "event=mtls_quarantine clause={} serial={} reason_id={} revoked_total={}",
            SECURITY_SPEC,
            serial_hex,
            SECURITY_QUARANTINE_REASON_MTLS,
            self.revoked_serials.len()
        );
    }

    fn refresh_revocations(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_revocation_update) > self.revocation_ttl {
            self.revoked_serials.clear();
            self.last_revocation_update = now;
        }
    }
}

#[derive(Debug)]
pub struct KeyEpochWatcher {
    trackers: HashMap<String, KeyEpochTracker>,
    overrides: HashMap<String, OverrideWindow>,
    max_lag: u32,
}

impl Default for KeyEpochWatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct OverrideWindow {
    pub reason: String,
    pub expires_at: Instant,
}

impl KeyEpochWatcher {
    pub fn new() -> Self {
        Self {
            trackers: HashMap::new(),
            overrides: HashMap::new(),
            max_lag: 0,
        }
    }

    pub fn observe(
        &mut self,
        scope: impl Into<String>,
        epoch: KeyEpoch,
        now: Instant,
    ) -> Result<(), SecurityError> {
        let scope = scope.into();
        let tracker = self.trackers.entry(scope.clone()).or_default();
        tracker.observe(epoch).map_err(SecurityError::from)?;
        self.recompute_max_lag();
        let lag = self.scope_lag(&scope);
        if lag > 1 {
            if let Some(window) = self.overrides.get(&scope) {
                if now > window.expires_at {
                    return Err(SecurityError::OverrideExpired {
                        scope,
                        reason: window.reason.clone(),
                    });
                }
                return Ok(());
            }
            return Err(SecurityError::KeyEpochLag { scope, lag });
        }
        Ok(())
    }

    pub fn allow_override(
        &mut self,
        scope: impl Into<String>,
        reason: impl Into<String>,
        ttl: Duration,
        now: Instant,
    ) {
        let scope = scope.into();
        self.overrides.insert(
            scope,
            OverrideWindow {
                reason: reason.into(),
                expires_at: now + ttl,
            },
        );
    }

    pub fn max_lag(&self) -> u32 {
        self.max_lag
    }

    pub fn publish_metrics(&self, registry: &mut MetricsRegistry) {
        registry.set_gauge("security.key_epoch_lag", self.max_lag as u64);
    }

    fn scope_epoch(&self, scope: &str) -> Option<KeyEpoch> {
        self.trackers
            .get(scope)
            .and_then(|tracker| tracker.current())
    }

    fn scope_lag(&self, scope: &str) -> u32 {
        let Some(scope_epoch) = self.scope_epoch(scope) else {
            return 0;
        };
        let Some(max_epoch) = self.max_epoch() else {
            return 0;
        };
        Self::lag_between(max_epoch, scope_epoch)
    }

    fn lag_between(max_epoch: KeyEpoch, scope_epoch: KeyEpoch) -> u32 {
        let kek = max_epoch
            .kek_version
            .saturating_sub(scope_epoch.kek_version);
        let dek = max_epoch.dek_epoch.saturating_sub(scope_epoch.dek_epoch);
        let mac = max_epoch
            .integrity_mac_epoch
            .saturating_sub(scope_epoch.integrity_mac_epoch);
        kek.max(dek).max(mac)
    }

    fn max_epoch(&self) -> Option<KeyEpoch> {
        let mut max_epoch: Option<KeyEpoch> = None;
        for tracker in self.trackers.values() {
            if let Some(epoch) = tracker.current() {
                max_epoch = Some(match max_epoch {
                    None => epoch,
                    Some(current) => KeyEpoch {
                        kek_version: current.kek_version.max(epoch.kek_version),
                        dek_epoch: current.dek_epoch.max(epoch.dek_epoch),
                        integrity_mac_epoch: current
                            .integrity_mac_epoch
                            .max(epoch.integrity_mac_epoch),
                    },
                });
            }
        }
        max_epoch
    }

    fn recompute_max_lag(&mut self) {
        let Some(max_epoch) = self.max_epoch() else {
            self.max_lag = 0;
            return;
        };
        let mut lag = 0;
        for tracker in self.trackers.values() {
            if let Some(epoch) = tracker.current() {
                lag = lag.max(Self::lag_between(max_epoch, epoch));
            }
        }
        self.max_lag = lag;
    }
}

#[derive(Debug, Clone)]
pub struct BreakGlassToken {
    pub token_id: String,
    pub spiffe_id: SpiffeId,
    pub scope: String,
    pub ticket_url: String,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct BreakGlassAudit {
    pub scope: String,
    pub used_by: String,
    pub ticket_url: String,
    pub used_at: Instant,
    pub token_id: String,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct RbacManifestCache {
    roles: HashMap<String, Vec<String>>,
    breakglass_audit: Vec<BreakGlassAudit>,
    last_refresh: Option<Instant>,
    grace: Duration,
}

impl RbacManifestCache {
    pub fn new(grace: Duration) -> Self {
        Self {
            roles: HashMap::new(),
            breakglass_audit: Vec::new(),
            last_refresh: None,
            grace,
        }
    }

    pub fn load_manifest(&mut self, roles: HashMap<String, Vec<String>>, now: Instant) {
        self.roles = roles;
        self.last_refresh = Some(now);
    }

    pub fn authorize(
        &self,
        role: &str,
        capability: &str,
        now: Instant,
    ) -> Result<(), SecurityError> {
        let refreshed = self.last_refresh.ok_or(SecurityError::RbacUnavailable)?;
        if now.saturating_duration_since(refreshed) > self.grace {
            return Err(SecurityError::RbacStale);
        }
        let caps = self.roles.get(role).ok_or(SecurityError::Unauthorized)?;
        if caps.iter().any(|c| c == capability) {
            Ok(())
        } else {
            Err(SecurityError::Unauthorized)
        }
    }

    pub fn apply_breakglass(
        &mut self,
        token: BreakGlassToken,
        capability: &str,
        now: Instant,
    ) -> Result<(), SecurityError> {
        if now > token.expires_at {
            return Err(SecurityError::BreakGlassExpired);
        }
        if token.scope != capability {
            return Err(SecurityError::BreakGlassScopeMismatch);
        }
        let audit = BreakGlassAudit {
            scope: token.scope,
            used_by: format!("{}{}", token.spiffe_id.trust_domain, token.spiffe_id.path),
            ticket_url: token.ticket_url,
            used_at: now,
            token_id: token.token_id,
            expires_at: token.expires_at,
        };
        self.breakglass_audit.push(audit);
        Ok(())
    }

    pub fn audit_log(&self) -> &[BreakGlassAudit] {
        &self.breakglass_audit
    }
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),
    #[error("certificate not yet valid")]
    CertificateNotYetValid,
    #[error("certificate expired")]
    CertificateExpired,
    #[error("certificate revoked")]
    CertificateRevoked,
    #[error("certificate violates dual validity window")]
    DualValidityViolation,
    #[error("trust domain mismatch")]
    TrustDomainMismatch,
    #[error("key epoch replay detected: {0}")]
    KeyEpochReplay(#[from] crate::storage::crypto::KeyEpochError),
    #[error("key epoch lag detected for {scope}: {lag} epoch(s) behind")]
    KeyEpochLag { scope: String, lag: u32 },
    #[error("override expired for {scope}: {reason}")]
    OverrideExpired { scope: String, reason: String },
    #[error("RBAC manifest unavailable")]
    RbacUnavailable,
    #[error("RBAC manifest stale")]
    RbacStale,
    #[error("capability unauthorized")]
    Unauthorized,
    #[error("break-glass token expired")]
    BreakGlassExpired,
    #[error("break-glass scope mismatch")]
    BreakGlassScopeMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtls_manager_enforces_revocation() {
        let now = Instant::now();
        let active = Certificate {
            spiffe_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
            serial: SerialNumber::from_u64(1),
            valid_from: now - Duration::from_secs(60),
            valid_until: now + Duration::from_secs(600),
        };
        let mut manager = MtlsIdentityManager::new(
            active.clone(),
            "example.org",
            Duration::from_secs(600),
            Duration::from_secs(120),
            now,
        );
        let peer = Certificate {
            spiffe_id: active.spiffe_id.clone(),
            serial: SerialNumber::from_u64(99),
            valid_from: now - Duration::from_secs(60),
            valid_until: now + Duration::from_secs(60),
        };
        manager.verify_peer(&peer, now).unwrap();
        manager.revoke_serial(SerialNumber::from_u64(99), now);
        let err = manager.verify_peer(&peer, now).unwrap_err();
        assert!(matches!(err, SecurityError::CertificateRevoked));
    }

    #[test]
    fn key_epoch_watcher_allows_override() {
        let mut watcher = KeyEpochWatcher::new();
        let now = Instant::now();
        watcher.allow_override("partition-1", "maintenance", Duration::from_secs(30), now);
        watcher
            .observe(
                "partition-1",
                KeyEpoch {
                    kek_version: 1,
                    dek_epoch: 1,
                    integrity_mac_epoch: 1,
                },
                now + Duration::from_secs(10),
            )
            .unwrap();
    }

    #[test]
    fn rbac_cache_records_breakglass_usage() {
        let mut cache = RbacManifestCache::new(Duration::from_secs(30));
        let mut roles = HashMap::new();
        roles.insert("operator".into(), vec!["CreatePartition".into()]);
        let now = Instant::now();
        cache.load_manifest(roles, now);
        cache.authorize("operator", "CreatePartition", now).unwrap();

        let token = BreakGlassToken {
            token_id: "token-1".into(),
            spiffe_id: SpiffeId::parse("spiffe://example.org/operator").unwrap(),
            scope: "ThrottleOverride".into(),
            ticket_url: "https://ticket/1".into(),
            expires_at: now + Duration::from_secs(60),
        };
        cache
            .apply_breakglass(token, "ThrottleOverride", now)
            .unwrap();
        let audit = cache.audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].token_id, "token-1");
        assert_eq!(audit[0].expires_at, now + Duration::from_secs(60));
    }
}
