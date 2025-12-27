#![cfg(feature = "admin-http")]

use clustor::security::{
    BreakGlassAudit, BreakGlassAuditLog, BreakGlassToken, RbacManifest, RbacManifestCache,
    RbacPrincipal, RbacRole, SecurityError, SpiffeId,
};
use clustor::telemetry::MetricsRegistry;
use ed25519_dalek::SigningKey;
use std::time::{Duration, Instant, SystemTime};

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
        spiffe_id: SpiffeId::parse("spiffe://example.org/breakglass/DurabilityOverride/operator")
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
