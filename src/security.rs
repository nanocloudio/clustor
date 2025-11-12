use crate::storage::crypto::{KeyEpoch, KeyEpochTracker};
use crate::telemetry::{IncidentCorrelator, MetricsRegistry};
use ed25519_dalek::{Signer, SigningKey};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const SECURITY_SPEC: &str = "§12.Mtls";
const SECURITY_QUARANTINE_REASON_MTLS: &str = "VOCAB.Security.Quarantine.MtlsRevocation";
const RBAC_CACHE_SPEC: &str = "§12.3.RbacCache";
const RBAC_STALE_INCIDENT: &str = "security.rbac_cache_stale";
const BREAKGLASS_SPIFFE_SEGMENT: &str = "breakglass";
const REVOCATION_MAX_STALENESS_MS: u64 = 300_000;
const REVOCATION_FAIL_CLOSED_MS: u64 = 600_000;
const REVOCATION_WAIVER_EXTENSION_MS: u64 = 300_000;

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

    pub fn canonical(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub spiffe_id: SpiffeId,
    pub serial: SerialNumber,
    pub valid_from: Instant,
    pub valid_until: Instant,
}

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
    dual_validity: Duration,
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
            ocsp: RevocationFeedState::new(now),
            crl: RevocationFeedState::new(now),
            revocation_max_staleness: Duration::from_millis(REVOCATION_MAX_STALENESS_MS),
            revocation_fail_closed: Duration::from_millis(REVOCATION_FAIL_CLOSED_MS),
            waiver_extension: Duration::from_millis(REVOCATION_WAIVER_EXTENSION_MS),
            revocation_waiver: None,
            quarantined: false,
            pending: None,
            active,
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

    fn feed_state_mut(&mut self, source: RevocationSource) -> &mut RevocationFeedState {
        match source {
            RevocationSource::Ocsp => &mut self.ocsp,
            RevocationSource::Crl => &mut self.crl,
        }
    }

    fn enforce_revocation(&mut self, now: Instant) -> Result<(), SecurityError> {
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
    pub issued_at: SystemTime,
}

#[derive(Debug)]
pub struct BreakGlassAudit {
    pub scope: String,
    pub actor_spiffe_id: String,
    pub ticket_url: String,
    pub used_at: SystemTime,
    pub token_id: String,
    pub expires_at: Instant,
    pub issued_at: SystemTime,
    pub api: String,
    pub result: String,
    pub partition_scope: String,
}

#[derive(Debug)]
pub struct BreakGlassAuditSegment {
    pub index: u64,
    pub digest: [u8; 32],
    pub signature: Vec<u8>,
    pub entry_count: usize,
}

#[derive(Debug)]
pub struct BreakGlassAuditLog {
    cluster_id: String,
    log_version: u32,
    signing_key: SigningKey,
    segment_size: usize,
    current_segment: Vec<String>,
    segments: Vec<BreakGlassAuditSegment>,
    previous_digest: [u8; 32],
}

impl BreakGlassAuditLog {
    pub fn new(cluster_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            log_version: 1,
            signing_key,
            segment_size: 1_000,
            current_segment: Vec::new(),
            segments: Vec::new(),
            previous_digest: [0u8; 32],
        }
    }

    pub fn with_segment_size(mut self, segment_size: usize) -> Self {
        self.segment_size = segment_size.max(1);
        self
    }

    pub fn record(&mut self, audit: &BreakGlassAudit) {
        let line = self.serialize_entry(audit);
        self.current_segment.push(line);
        if self.current_segment.len() >= self.segment_size {
            self.seal_segment();
        }
    }

    pub fn flush(&mut self) {
        if !self.current_segment.is_empty() {
            self.seal_segment();
        }
    }

    pub fn segments(&self) -> &[BreakGlassAuditSegment] {
        &self.segments
    }

    pub fn pending_entries(&self) -> &[String] {
        &self.current_segment
    }

    fn serialize_entry(&self, audit: &BreakGlassAudit) -> String {
        let payload = BreakGlassAuditEntryPayload {
            log_version: self.log_version,
            cluster_id: &self.cluster_id,
            partition_scope: &audit.partition_scope,
            scope: &audit.scope,
            token_id: &audit.token_id,
            ticket_url: &audit.ticket_url,
            issued_at_ms: format_timestamp_ms(audit.issued_at),
            used_at_ms: format_timestamp_ms(audit.used_at),
            actor_spiffe_id: &audit.actor_spiffe_id,
            api: &audit.api,
            result: &audit.result,
        };
        let payload_json =
            serde_json::to_string(&payload).expect("serialize breakglass audit payload");
        let signature = self.signing_key.sign(payload_json.as_bytes());
        let entry = BreakGlassAuditEntrySigned {
            payload,
            signature: hex::encode(signature.to_bytes()),
        };
        serde_json::to_string(&entry).expect("serialize breakglass audit entry")
    }

    fn seal_segment(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.previous_digest);
        for line in &self.current_segment {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
        }
        let digest_bytes: [u8; 32] = hasher.finalize().into();
        let signature = self.signing_key.sign(&digest_bytes);
        let segment = BreakGlassAuditSegment {
            index: self.segments.len() as u64,
            digest: digest_bytes,
            signature: signature.to_bytes().to_vec(),
            entry_count: self.current_segment.len(),
        };
        self.previous_digest = segment.digest;
        self.segments.push(segment);
        self.current_segment.clear();
    }
}

#[derive(Serialize)]
struct BreakGlassAuditEntryPayload<'a> {
    log_version: u32,
    cluster_id: &'a str,
    partition_scope: &'a str,
    scope: &'a str,
    token_id: &'a str,
    ticket_url: &'a str,
    issued_at_ms: String,
    used_at_ms: String,
    actor_spiffe_id: &'a str,
    api: &'a str,
    result: &'a str,
}

#[derive(Serialize)]
struct BreakGlassAuditEntrySigned<'a> {
    #[serde(flatten)]
    payload: BreakGlassAuditEntryPayload<'a>,
    signature: String,
}

fn format_timestamp_ms(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().to_string(),
        Err(_) => "0".into(),
    }
}

fn validate_breakglass_svid(token: &BreakGlassToken) -> Result<(), SecurityError> {
    let path = token.spiffe_id.path.trim_start_matches('/');
    let mut segments = path.split('/');
    let prefix = segments
        .next()
        .ok_or_else(|| SecurityError::BreakGlassSvidInvalid("missing SPIFFE segments".into()))?;
    if prefix != BREAKGLASS_SPIFFE_SEGMENT {
        return Err(SecurityError::BreakGlassSvidInvalid(format!(
            "expected {} prefix in SPIFFE path {}, found {prefix}",
            BREAKGLASS_SPIFFE_SEGMENT, token.spiffe_id.path
        )));
    }
    let scope_segment = segments
        .next()
        .ok_or_else(|| SecurityError::BreakGlassSvidInvalid("missing scope segment".into()))?;
    if scope_segment != token.scope {
        return Err(SecurityError::BreakGlassScopeMismatch);
    }
    let actor_segment = segments
        .next()
        .ok_or_else(|| SecurityError::BreakGlassSvidInvalid("missing actor segment".into()))?;
    if actor_segment.is_empty() {
        return Err(SecurityError::BreakGlassSvidInvalid(
            "empty actor segment".into(),
        ));
    }
    Ok(())
}

fn breakglass_scope_allows(scope: &str, capability: &str) -> bool {
    matches!(
        (scope, capability),
        ("DurabilityOverride", "SetDurabilityMode")
            | ("DurabilityOverride", "OverrideStrictOnlyBackpressure")
            | ("DurabilityOverride", "AdminOverrideKeyEpoch")
            | ("SurvivabilityOverride", "flow.structural_override")
            | ("SurvivabilityOverride", "DryRunMovePartition")
            | ("SurvivabilityOverride", "MembershipChange")
            | ("ThrottleOverride", "OverrideCredit")
            | ("ThrottleOverride", "flow.structural_hard_block")
            | ("ThrottleOverride", "WhyCreditZero")
            | ("SnapshotOverride", "SnapshotFullOverride")
            | ("SnapshotOverride", "snapshot_full_invalidated")
            | ("SnapshotOverride", "RepairModeResume")
            | ("QuarantineOverride", "AdminResumePartition")
            | ("QuarantineOverride", "AdminPausePartition")
            | ("QuarantineOverride", "OverrideStrictOnlyBackpressure")
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RbacRole {
    pub name: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RbacPrincipal {
    pub spiffe_id: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RbacManifest {
    #[serde(default)]
    pub roles: Vec<RbacRole>,
    #[serde(default)]
    pub principals: Vec<RbacPrincipal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RbacCacheState {
    Unavailable,
    Fresh,
    Grace { age_ms: u64 },
    Stale { age_ms: u64 },
}

impl RbacCacheState {
    fn metric_value(&self) -> u64 {
        match self {
            RbacCacheState::Fresh => 0,
            RbacCacheState::Grace { .. } => 1,
            RbacCacheState::Stale { .. } => 2,
            RbacCacheState::Unavailable => 3,
        }
    }
}

#[derive(Debug)]
pub struct RbacManifestCache {
    roles: HashMap<String, Vec<String>>,
    principal_roles: HashMap<String, String>,
    breakglass_audit: Vec<BreakGlassAudit>,
    breakglass_log: Option<BreakGlassAuditLog>,
    last_refresh: Option<Instant>,
    grace: Duration,
    cache_state: RbacCacheState,
    incident_correlator: IncidentCorrelator,
}

impl RbacManifestCache {
    pub fn new(grace: Duration) -> Self {
        Self {
            roles: HashMap::new(),
            principal_roles: HashMap::new(),
            breakglass_audit: Vec::new(),
            breakglass_log: None,
            last_refresh: None,
            grace,
            cache_state: RbacCacheState::Unavailable,
            incident_correlator: IncidentCorrelator::new(Duration::from_secs(30)),
        }
    }

    pub fn load_manifest(
        &mut self,
        manifest: RbacManifest,
        now: Instant,
    ) -> Result<(), SecurityError> {
        let mut roles = HashMap::new();
        for role in manifest.roles {
            let name = role.name.trim();
            if name.is_empty() {
                return Err(SecurityError::InvalidRbacManifest(
                    "role name must not be empty".into(),
                ));
            }
            if roles
                .insert(name.to_string(), role.capabilities.clone())
                .is_some()
            {
                return Err(SecurityError::InvalidRbacManifest(format!(
                    "duplicate role entry: {name}"
                )));
            }
        }
        let mut principal_roles = HashMap::new();
        for principal in manifest.principals {
            if !roles.contains_key(&principal.role) {
                return Err(SecurityError::InvalidRbacManifest(format!(
                    "principal {} references unknown role {}",
                    principal.spiffe_id, principal.role
                )));
            }
            let canonical = SpiffeId::parse(&principal.spiffe_id)?.canonical();
            if principal_roles
                .insert(canonical.clone(), principal.role.clone())
                .is_some()
            {
                return Err(SecurityError::InvalidRbacManifest(format!(
                    "duplicate principal entry: {canonical}"
                )));
            }
        }
        self.roles = roles;
        self.principal_roles = principal_roles;
        self.last_refresh = Some(now);
        self.cache_state = RbacCacheState::Fresh;
        Ok(())
    }

    pub fn install_breakglass_log(&mut self, log: BreakGlassAuditLog) {
        self.breakglass_log = Some(log);
    }

    pub fn authorize(
        &mut self,
        role: &str,
        capability: &str,
        now: Instant,
    ) -> Result<(), SecurityError> {
        self.ensure_fresh(now)?;
        let caps = self.roles.get(role).ok_or(SecurityError::Unauthorized)?;
        if caps.iter().any(|c| c == capability) {
            Ok(())
        } else {
            Err(SecurityError::Unauthorized)
        }
    }

    pub fn role_for(
        &mut self,
        principal: &SpiffeId,
        now: Instant,
    ) -> Result<String, SecurityError> {
        self.ensure_fresh(now)?;
        let canonical = principal.canonical();
        let role = self
            .principal_roles
            .get(&canonical)
            .ok_or(SecurityError::Unauthorized)?;
        Ok(role.clone())
    }

    pub fn publish_metrics(&mut self, registry: &mut MetricsRegistry, now: Instant) {
        let state = self.refresh_cache_state(now);
        registry.set_gauge("security.rbac_cache_state", state.metric_value());
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
        validate_breakglass_svid(&token)?;
        if !breakglass_scope_allows(&token.scope, capability) {
            warn!(
                "event=breakglass_scope_mismatch clause={} token_scope={} capability={}",
                RBAC_CACHE_SPEC, token.scope, capability
            );
            return Err(SecurityError::BreakGlassScopeMismatch);
        }
        let BreakGlassToken {
            token_id,
            spiffe_id,
            scope,
            ticket_url,
            expires_at,
            issued_at,
        } = token;
        let audit = BreakGlassAudit {
            scope,
            actor_spiffe_id: spiffe_id.canonical(),
            ticket_url,
            used_at: SystemTime::now(),
            token_id,
            expires_at,
            issued_at,
            api: capability.to_string(),
            result: "Success".into(),
            partition_scope: "global".into(),
        };
        if let Some(log) = &mut self.breakglass_log {
            log.record(&audit);
        }
        self.breakglass_audit.push(audit);
        Ok(())
    }

    pub fn audit_log(&self) -> &[BreakGlassAudit] {
        &self.breakglass_audit
    }

    fn ensure_fresh(&mut self, now: Instant) -> Result<(), SecurityError> {
        match self.refresh_cache_state(now) {
            RbacCacheState::Fresh | RbacCacheState::Grace { .. } => Ok(()),
            RbacCacheState::Stale { .. } => Err(SecurityError::RbacStale),
            RbacCacheState::Unavailable => Err(SecurityError::RbacUnavailable),
        }
    }

    fn refresh_cache_state(&mut self, now: Instant) -> RbacCacheState {
        let next = self.evaluate_cache_state(now);
        if next != self.cache_state {
            let previous = self.cache_state;
            self.cache_state = next;
            self.log_cache_transition(previous, next, now);
        }
        next
    }

    fn evaluate_cache_state(&self, now: Instant) -> RbacCacheState {
        let Some(refreshed) = self.last_refresh else {
            return RbacCacheState::Unavailable;
        };
        let age_ms = now.saturating_duration_since(refreshed).as_millis() as u64;
        let grace_ms = self.grace.as_millis() as u64;
        let fresh_limit = grace_ms / 2;
        if age_ms <= fresh_limit {
            RbacCacheState::Fresh
        } else if age_ms < grace_ms {
            RbacCacheState::Grace { age_ms }
        } else {
            RbacCacheState::Stale { age_ms }
        }
    }

    fn log_cache_transition(
        &mut self,
        previous: RbacCacheState,
        current: RbacCacheState,
        now: Instant,
    ) {
        if previous == current {
            return;
        }
        match current {
            RbacCacheState::Grace { age_ms } => {
                warn!(
                    "event=rbac_cache_state clause={} outcome=grace age_ms={}",
                    RBAC_CACHE_SPEC, age_ms
                );
            }
            RbacCacheState::Stale { age_ms } => {
                let decision = self.incident_correlator.record(RBAC_STALE_INCIDENT, now);
                warn!(
                    "event=rbac_cache_state clause={} outcome=stale age_ms={} decision={:?}",
                    RBAC_CACHE_SPEC, age_ms, decision
                );
            }
            RbacCacheState::Unavailable => {
                warn!(
                    "event=rbac_cache_state clause={} outcome=unavailable",
                    RBAC_CACHE_SPEC
                );
            }
            RbacCacheState::Fresh => {
                info!(
                    "event=rbac_cache_state clause={} outcome=fresh",
                    RBAC_CACHE_SPEC
                );
            }
        }
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
    #[error("invalid RBAC manifest: {0}")]
    InvalidRbacManifest(String),
    #[error("capability unauthorized")]
    Unauthorized,
    #[error("revocation data stale")]
    RevocationDataStale,
    #[error("revocation feeds unavailable; entering quarantine")]
    RevocationFailClosed,
    #[error("break-glass token expired")]
    BreakGlassExpired,
    #[error("break-glass scope mismatch")]
    BreakGlassScopeMismatch,
    #[error("break-glass SVID invalid: {0}")]
    BreakGlassSvidInvalid(String),
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
    fn mtls_manager_detects_revocation_staleness() {
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
        let mut manager = MtlsIdentityManager::new(
            active.clone(),
            "example.org",
            Duration::from_secs(600),
            Duration::from_secs(120),
            now,
        );
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
        let mut manager = MtlsIdentityManager::new(
            active.clone(),
            "example.org",
            Duration::from_secs(600),
            Duration::from_secs(120),
            now,
        );
        let peer = sample_cert(now, 11);
        manager.mark_revocation_unavailable(RevocationSource::Ocsp);
        manager.mark_revocation_unavailable(RevocationSource::Crl);
        let err = manager.verify_peer(&peer, now).unwrap_err();
        assert!(matches!(err, SecurityError::RevocationFailClosed));
        assert!(manager.is_quarantined());
    }

    fn sample_cert(now: Instant, serial: u64) -> Certificate {
        Certificate {
            spiffe_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
            serial: SerialNumber::from_u64(serial),
            valid_from: now - Duration::from_secs(60),
            valid_until: now + Duration::from_secs(3_600),
        }
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
        let now = Instant::now();
        cache
            .load_manifest(
                RbacManifest {
                    roles: vec![RbacRole {
                        name: "operator".into(),
                        capabilities: vec!["CreatePartition".into()],
                    }],
                    principals: vec![RbacPrincipal {
                        spiffe_id: "spiffe://example.org/operator".into(),
                        role: "operator".into(),
                    }],
                },
                now,
            )
            .expect("manifest loads");
        cache.authorize("operator", "CreatePartition", now).unwrap();
        let operator = SpiffeId::parse("spiffe://example.org/operator").unwrap();
        assert_eq!(cache.role_for(&operator, now).unwrap(), "operator");

        let token = BreakGlassToken {
            token_id: "token-1".into(),
            spiffe_id: SpiffeId::parse(
                "spiffe://example.org/breakglass/DurabilityOverride/operator",
            )
            .unwrap(),
            scope: "DurabilityOverride".into(),
            ticket_url: "https://ticket/1".into(),
            expires_at: now + Duration::from_secs(60),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        };
        cache
            .apply_breakglass(token, "SetDurabilityMode", now)
            .unwrap();
        let audit = cache.audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].token_id, "token-1");
        assert_eq!(audit[0].expires_at, now + Duration::from_secs(60));
    }

    #[test]
    fn breakglass_token_expiry_enforced() {
        let mut cache = RbacManifestCache::new(Duration::from_secs(30));
        let now = Instant::now();
        cache
            .load_manifest(
                RbacManifest {
                    roles: vec![RbacRole {
                        name: "operator".into(),
                        capabilities: vec!["SetDurabilityMode".into()],
                    }],
                    principals: vec![RbacPrincipal {
                        spiffe_id: "spiffe://example.org/operator".into(),
                        role: "operator".into(),
                    }],
                },
                now,
            )
            .unwrap();
        let token = BreakGlassToken {
            token_id: "token-expired".into(),
            spiffe_id: SpiffeId::parse(
                "spiffe://example.org/breakglass/DurabilityOverride/operator",
            )
            .unwrap(),
            scope: "DurabilityOverride".into(),
            ticket_url: "https://ticket/expired".into(),
            expires_at: now - Duration::from_secs(1),
            issued_at: SystemTime::UNIX_EPOCH,
        };
        let err = cache
            .apply_breakglass(token, "SetDurabilityMode", now)
            .unwrap_err();
        assert!(matches!(err, SecurityError::BreakGlassExpired));
    }

    #[test]
    fn breakglass_scope_rejects_mismatch() {
        let mut cache = RbacManifestCache::new(Duration::from_secs(30));
        let now = Instant::now();
        cache
            .load_manifest(
                RbacManifest {
                    roles: vec![RbacRole {
                        name: "operator".into(),
                        capabilities: vec!["SetDurabilityMode".into()],
                    }],
                    principals: vec![RbacPrincipal {
                        spiffe_id: "spiffe://example.org/operator".into(),
                        role: "operator".into(),
                    }],
                },
                now,
            )
            .unwrap();
        let token = BreakGlassToken {
            token_id: "token-scope".into(),
            spiffe_id: SpiffeId::parse("spiffe://example.org/breakglass/SnapshotOverride/operator")
                .unwrap(),
            scope: "SnapshotOverride".into(),
            ticket_url: "https://ticket/scope".into(),
            expires_at: now + Duration::from_secs(60),
            issued_at: SystemTime::UNIX_EPOCH,
        };
        let err = cache
            .apply_breakglass(token, "SetDurabilityMode", now)
            .unwrap_err();
        assert!(matches!(err, SecurityError::BreakGlassScopeMismatch));
    }

    #[test]
    fn rbac_cache_emits_state_metrics() {
        let mut cache = RbacManifestCache::new(Duration::from_secs(60));
        let mut registry = MetricsRegistry::new("clustor");
        let now = Instant::now();
        cache.publish_metrics(&mut registry, now);
        let snapshot = registry.snapshot();
        assert_eq!(
            snapshot
                .gauges
                .get("clustor.security.rbac_cache_state")
                .copied()
                .unwrap_or_default(),
            3
        );

        cache
            .load_manifest(
                RbacManifest {
                    roles: vec![RbacRole {
                        name: "operator".into(),
                        capabilities: vec!["CreatePartition".into()],
                    }],
                    principals: vec![RbacPrincipal {
                        spiffe_id: "spiffe://example.org/operator".into(),
                        role: "operator".into(),
                    }],
                },
                now,
            )
            .unwrap();
        let mut registry = MetricsRegistry::new("clustor");
        cache.publish_metrics(&mut registry, now);
        let snapshot = registry.snapshot();
        assert_eq!(
            snapshot
                .gauges
                .get("clustor.security.rbac_cache_state")
                .copied()
                .unwrap_or_default(),
            0
        );

        let mut registry = MetricsRegistry::new("clustor");
        cache.publish_metrics(&mut registry, now + Duration::from_secs(40));
        let snapshot = registry.snapshot();
        assert_eq!(
            snapshot
                .gauges
                .get("clustor.security.rbac_cache_state")
                .copied()
                .unwrap_or_default(),
            1
        );

        let mut registry = MetricsRegistry::new("clustor");
        cache.publish_metrics(&mut registry, now + Duration::from_secs(80));
        let snapshot = registry.snapshot();
        assert_eq!(
            snapshot
                .gauges
                .get("clustor.security.rbac_cache_state")
                .copied()
                .unwrap_or_default(),
            2
        );
    }

    #[test]
    fn breakglass_audit_log_generates_segments() {
        use ed25519_dalek::SigningKey;

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut log = BreakGlassAuditLog::new("cluster-demo", key).with_segment_size(2);
        let audit = BreakGlassAudit {
            scope: "DurabilityOverride".into(),
            actor_spiffe_id: "spiffe://example.org/breakglass/DurabilityOverride/operator".into(),
            ticket_url: "https://ticket/1".into(),
            used_at: SystemTime::UNIX_EPOCH + Duration::from_secs(200),
            token_id: "token-1".into(),
            expires_at: Instant::now() + Duration::from_secs(60),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            api: "SetDurabilityMode".into(),
            result: "Success".into(),
            partition_scope: "global".into(),
        };
        log.record(&audit);
        assert!(log.segments().is_empty());
        log.record(&audit);
        assert_eq!(log.segments().len(), 1);
        let segment = &log.segments()[0];
        assert_eq!(segment.entry_count, 2);
        assert_ne!(segment.digest, [0u8; 32]);
        assert!(!segment.signature.is_empty());
        log.flush();
        assert!(log.pending_entries().is_empty());
    }
}
