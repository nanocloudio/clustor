use super::break_glass::{
    breakglass_scope_allows, validate_breakglass_svid, BreakGlassAudit, BreakGlassAuditLog,
    BreakGlassToken,
};
use super::certs::SpiffeId;
use super::errors::SecurityError;
use crate::telemetry::{IncidentCorrelator, MetricsRegistry};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

const RBAC_CACHE_SPEC: &str = "§12.3.RbacCache";
const RBAC_STALE_INCIDENT: &str = "security.rbac_cache_stale";

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
enum RbacCacheState {
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
        let actor = spiffe_id.canonical();
        info!(
            "event=breakglass_authorize clause={} scope={} actor={} capability={}",
            RBAC_CACHE_SPEC, scope, actor, capability
        );
        let audit = BreakGlassAudit {
            scope,
            actor_spiffe_id: actor,
            ticket_url,
            used_at: SystemTime::now(),
            token_id,
            expires_at,
            issued_at,
            api: capability.into(),
            result: "success".into(),
            partition_scope: "cluster".into(),
        };
        if let Some(log) = &mut self.breakglass_log {
            log.record(&audit)?;
        } else {
            self.breakglass_audit.push(audit);
        }
        Ok(())
    }

    pub fn audit_log(&self) -> &[BreakGlassAudit] {
        &self.breakglass_audit
    }

    fn ensure_fresh(&mut self, now: Instant) -> Result<(), SecurityError> {
        match self.refresh_cache_state(now) {
            RbacCacheState::Fresh => Ok(()),
            RbacCacheState::Grace { age_ms } => {
                let decision = self.incident_correlator.record(RBAC_STALE_INCIDENT, now);
                warn!(
                    "event=rbac_cache_state clause={} outcome=grace age_ms={} decision={:?}",
                    RBAC_CACHE_SPEC, age_ms, decision
                );
                Ok(())
            }
            RbacCacheState::Stale { .. } => Err(SecurityError::RbacStale),
            RbacCacheState::Unavailable => Err(SecurityError::RbacUnavailable),
        }
    }

    fn refresh_cache_state(&mut self, now: Instant) -> RbacCacheState {
        self.cache_state = match self.last_refresh {
            None => RbacCacheState::Unavailable,
            Some(refresh) => {
                let age = now.saturating_duration_since(refresh).as_millis() as u64;
                let grace_ms = self.grace.as_millis() as u64;
                let fresh_window = grace_ms.saturating_div(2).max(1);
                if age <= fresh_window {
                    RbacCacheState::Fresh
                } else if age <= grace_ms {
                    RbacCacheState::Grace { age_ms: age }
                } else {
                    RbacCacheState::Stale { age_ms: age }
                }
            }
        };
        self.cache_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::certs::SpiffeId;
    use ed25519_dalek::SigningKey;

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
    fn breakglass_token_expiration_enforced() {
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
            token_id: "token-exp".into(),
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
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut log = BreakGlassAuditLog::new("cluster-demo", key).with_segment_size(2);
        let audit = BreakGlassAudit {
            scope: "DurabilityOverride".into(),
            actor_spiffe_id: "spiffe://example.org/breakglass/DurabilityOverride/operator".into(),
            ticket_url: "https://ticket/1".into(),
            used_at: SystemTime::UNIX_EPOCH + Duration::from_secs(200),
            token_id: "token-1".into(),
            expires_at: Instant::now(),
            issued_at: SystemTime::UNIX_EPOCH,
            api: "SetDurabilityMode".into(),
            result: "success".into(),
            partition_scope: "cluster".into(),
        };
        log.record(&audit).unwrap();
        log.record(&audit).unwrap();
        log.flush();
        assert_eq!(log.segments().len(), 1);
        assert_eq!(log.segments()[0].entry_count, 2);
    }
}
