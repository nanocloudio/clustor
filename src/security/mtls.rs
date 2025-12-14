use crate::storage::crypto::{KeyEpoch, KeyEpochTracker};
use crate::telemetry::MetricsRegistry;
use log::{info, warn};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::certs::{serial_hex, Certificate, SerialNumber};
use super::errors::SecurityError;

const SECURITY_SPEC: &str = "§12.Mtls";
const SECURITY_QUARANTINE_REASON_MTLS: &str = "VOCAB.Security.Quarantine.MtlsRevocation";
const REVOCATION_MAX_STALENESS_MS: u64 = 300_000;
const REVOCATION_FAIL_CLOSED_MS: u64 = 600_000;
const REVOCATION_WAIVER_EXTENSION_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy)]
pub enum RevocationSource {
    Ocsp,
    Crl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationState {
    Fresh,
    Stale,
    Waived,
    FailClosed,
}

#[derive(Debug)]
struct RevocationFeedState {
    last_refresh: Option<Instant>,
    available: bool,
}

impl RevocationFeedState {
    fn new(now: Instant) -> Self {
        Self {
            last_refresh: Some(now),
            available: true,
        }
    }

    fn mark_refresh(&mut self, now: Instant) {
        self.last_refresh = Some(now);
        self.available = true;
    }

    fn mark_unavailable(&mut self) {
        self.available = false;
        self.last_refresh = None;
    }

    fn age(&self, now: Instant) -> Option<Duration> {
        self.last_refresh
            .map(|ts| now.saturating_duration_since(ts))
    }
}

#[derive(Debug)]
struct RevocationWaiver {
    reason: String,
    expires_at: Instant,
}

pub struct MtlsIdentityManager {
    active: Certificate,
    pending: Option<Certificate>,
    trust_domain: String,
    revoked_serials: HashSet<SerialNumber>,
    last_revocation_update: Instant,
    revocation_ttl: Duration,
    ocsp: RevocationFeedState,
    crl: RevocationFeedState,
    revocation_max_staleness: Duration,
    revocation_fail_closed: Duration,
    waiver_extension: Duration,
    revocation_waiver: Option<RevocationWaiver>,
    quarantined: bool,
    revocation_required: bool,
}

impl MtlsIdentityManager {
    pub fn new(
        active: Certificate,
        trust_domain: impl Into<String>,
        revocation_ttl: Duration,
        now: Instant,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            revoked_serials: HashSet::new(),
            last_revocation_update: now,
            revocation_ttl,
            ocsp: RevocationFeedState::new(now),
            crl: RevocationFeedState::new(now),
            revocation_max_staleness: Duration::from_millis(REVOCATION_MAX_STALENESS_MS),
            revocation_fail_closed: Duration::from_millis(REVOCATION_FAIL_CLOSED_MS),
            waiver_extension: Duration::from_millis(REVOCATION_WAIVER_EXTENSION_MS),
            revocation_waiver: None,
            quarantined: false,
            pending: None,
            active,
            revocation_required: true,
        }
    }

    pub fn offer_next(&mut self, certificate: Certificate) {
        self.pending = Some(certificate);
    }

    pub fn record_revocation_refresh(&mut self, source: RevocationSource, now: Instant) {
        self.feed_state_mut(source).mark_refresh(now);
        self.revocation_waiver = None;
        self.quarantined = false;
    }

    pub fn mark_revocation_unavailable(&mut self, source: RevocationSource) {
        self.feed_state_mut(source).mark_unavailable();
    }

    pub fn apply_revocation_waiver(&mut self, reason: impl Into<String>, now: Instant) {
        self.revocation_waiver = Some(RevocationWaiver {
            reason: reason.into(),
            expires_at: now + self.waiver_extension,
        });
        self.quarantined = false;
    }

    pub fn clear_revocation_waiver(&mut self) {
        self.revocation_waiver = None;
    }

    pub fn revocation_state(&mut self, now: Instant) -> RevocationState {
        self.evaluate_revocation_state(now)
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined
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
        self.enforce_revocation(now)?;
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

    fn feed_state_mut(&mut self, source: RevocationSource) -> &mut RevocationFeedState {
        match source {
            RevocationSource::Ocsp => &mut self.ocsp,
            RevocationSource::Crl => &mut self.crl,
        }
    }

    fn enforce_revocation(&mut self, now: Instant) -> Result<(), SecurityError> {
        if !self.revocation_required {
            self.quarantined = false;
            return Ok(());
        }
        match self.evaluate_revocation_state(now) {
            RevocationState::Fresh => Ok(()),
            RevocationState::Waived => {
                let reason = self
                    .revocation_waiver
                    .as_ref()
                    .map(|waiver| waiver.reason.as_str())
                    .unwrap_or("waiver_active");
                warn!(
                    "event=revocation_waived clause={} reason={} trust_domain={}",
                    SECURITY_SPEC, reason, self.trust_domain
                );
                Ok(())
            }
            RevocationState::Stale => Err(SecurityError::RevocationDataStale),
            RevocationState::FailClosed => Err(SecurityError::RevocationFailClosed),
        }
    }

    fn evaluate_revocation_state(&mut self, now: Instant) -> RevocationState {
        let ocsp_age = self.ocsp.age(now);
        let crl_age = self.crl.age(now);
        let ocsp_stale = !self.ocsp.available
            || ocsp_age
                .map(|age| age > self.revocation_max_staleness)
                .unwrap_or(true);
        let crl_stale = !self.crl.available
            || crl_age
                .map(|age| age > self.revocation_max_staleness)
                .unwrap_or(true);
        let ocsp_fail = !self.ocsp.available
            || ocsp_age
                .map(|age| age > self.revocation_fail_closed)
                .unwrap_or(true);
        let crl_fail = !self.crl.available
            || crl_age
                .map(|age| age > self.revocation_fail_closed)
                .unwrap_or(true);

        if ocsp_fail && crl_fail {
            if self.waiver_active(now) {
                return RevocationState::Waived;
            }
            self.quarantined = true;
            return RevocationState::FailClosed;
        }

        if ocsp_stale || crl_stale {
            return RevocationState::Stale;
        }

        self.quarantined = false;
        RevocationState::Fresh
    }

    fn waiver_active(&mut self, now: Instant) -> bool {
        match &self.revocation_waiver {
            Some(waiver) if now <= waiver.expires_at => true,
            _ => {
                self.revocation_waiver = None;
                false
            }
        }
    }

    pub fn set_revocation_enforcement(&mut self, required: bool) {
        self.revocation_required = required;
        if !required {
            self.quarantined = false;
            self.revocation_waiver = None;
        }
    }
}

#[derive(Debug, Clone)]
pub struct OverrideWindow {
    pub reason: String,
    pub expires_at: Instant,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::certs::SpiffeId;
    use std::time::Instant;

    #[test]
    fn mtls_manager_enforces_revocation() {
        let now = Instant::now();
        let active = Certificate {
            spiffe_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
            serial: SerialNumber::from_u64(1),
            valid_from: now - Duration::from_secs(60),
            valid_until: now + Duration::from_secs(600),
        };
        let mut manager =
            MtlsIdentityManager::new(active.clone(), "example.org", Duration::from_secs(120), now);
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
    fn mtls_manager_detects_revocation_staleness() {
        let now = Instant::now();
        let active = Certificate {
            spiffe_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
            serial: SerialNumber::from_u64(1),
            valid_from: now - Duration::from_secs(60),
            valid_until: now + Duration::from_secs(600),
        };
        let mut manager =
            MtlsIdentityManager::new(active.clone(), "example.org", Duration::from_secs(120), now);
        let peer = sample_cert(now, 42);
        let stale = now + Duration::from_millis(REVOCATION_MAX_STALENESS_MS + 1);
        assert!(matches!(
            manager.verify_peer(&peer, stale),
            Err(SecurityError::RevocationDataStale)
        ));
        let fail = now + Duration::from_millis(REVOCATION_FAIL_CLOSED_MS + 1);
        assert!(matches!(
            manager.verify_peer(&peer, fail),
            Err(SecurityError::RevocationFailClosed)
        ));
        assert!(manager.is_quarantined());
        manager.record_revocation_refresh(RevocationSource::Ocsp, fail);
        manager.record_revocation_refresh(RevocationSource::Crl, fail);
        manager
            .verify_peer(&peer, fail + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn mtls_manager_honors_revocation_waiver() {
        let now = Instant::now();
        let active = sample_cert(now, 1);
        let mut manager =
            MtlsIdentityManager::new(active.clone(), "example.org", Duration::from_secs(120), now);
        let peer = sample_cert(now, 55);
        let fail = now + Duration::from_millis(REVOCATION_FAIL_CLOSED_MS + 1);
        manager.apply_revocation_waiver("ticket-123", fail);
        manager.verify_peer(&peer, fail).unwrap();
        let after_waiver = fail + Duration::from_millis(REVOCATION_WAIVER_EXTENSION_MS + 1);
        let err = manager.verify_peer(&peer, after_waiver).unwrap_err();
        assert!(matches!(err, SecurityError::RevocationFailClosed));
    }

    #[test]
    fn mtls_manager_quarantines_when_feeds_missing() {
        let now = Instant::now();
        let active = sample_cert(now, 10);
        let mut manager =
            MtlsIdentityManager::new(active.clone(), "example.org", Duration::from_secs(120), now);
        let peer = sample_cert(now, 11);
        manager.mark_revocation_unavailable(RevocationSource::Ocsp);
        manager.mark_revocation_unavailable(RevocationSource::Crl);
        let err = manager.verify_peer(&peer, now).unwrap_err();
        assert!(matches!(err, SecurityError::RevocationFailClosed));
        assert!(manager.is_quarantined());
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
        watcher
            .observe(
                "partition-1",
                KeyEpoch {
                    kek_version: 1,
                    dek_epoch: 1,
                    integrity_mac_epoch: 1,
                },
                now + Duration::from_secs(20),
            )
            .unwrap();
    }

    fn sample_cert(now: Instant, serial: u64) -> Certificate {
        Certificate {
            spiffe_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
            serial: SerialNumber::from_u64(serial),
            valid_from: now - Duration::from_secs(60),
            valid_until: now + Duration::from_secs(3_600),
        }
    }
}
