use super::certs::SpiffeId;
use super::errors::SecurityError;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const BREAKGLASS_SPIFFE_SEGMENT: &str = "breakglass";

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

    pub fn record(&mut self, audit: &BreakGlassAudit) -> Result<(), SecurityError> {
        let line = self.serialize_entry(audit)?;
        self.current_segment.push(line);
        if self.current_segment.len() >= self.segment_size {
            self.seal_segment();
        }
        Ok(())
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

    fn serialize_entry(&self, audit: &BreakGlassAudit) -> Result<String, SecurityError> {
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
        let payload_json = serde_json::to_string(&payload).map_err(SecurityError::Serialization)?;
        let signature = self.signing_key.sign(payload_json.as_bytes());
        let entry = BreakGlassAuditEntrySigned {
            payload,
            signature: hex::encode(signature.to_bytes()),
        };
        serde_json::to_string(&entry).map_err(SecurityError::Serialization)
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

pub(crate) fn validate_breakglass_svid(token: &BreakGlassToken) -> Result<(), SecurityError> {
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

pub(crate) fn breakglass_scope_allows(scope: &str, capability: &str) -> bool {
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
