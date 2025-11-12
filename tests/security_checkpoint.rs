use clustor::storage::crypto::KeyEpoch;
use clustor::{
    BreakGlassToken, KeyEpochWatcher, MetricsRegistry, MtlsIdentityManager, RbacManifest,
    RbacManifestCache, RbacPrincipal, RbacRole, SecurityError, SerialNumber, SpiffeId,
};
use std::time::{Duration, Instant, SystemTime};

fn sample_cert(now: Instant, serial: u64) -> clustor::security::Certificate {
    clustor::security::Certificate {
        spiffe_id: SpiffeId::parse("spiffe://example.org/node").unwrap(),
        serial: SerialNumber::from_u64(serial),
        valid_from: now - Duration::from_secs(60),
        valid_until: now + Duration::from_secs(300),
    }
}

#[test]
fn security_checkpoint_rotates_and_revokes() {
    let now = Instant::now();
    let active = sample_cert(now, 1);
    let mut manager = MtlsIdentityManager::new(
        active.clone(),
        "example.org",
        Duration::from_secs(600),
        Duration::from_secs(120),
        now,
    );
    manager
        .verify_peer(&sample_cert(now, 99), now)
        .expect("peer accepted");
    manager.revoke_serial(SerialNumber::from_u64(99), now);
    assert!(matches!(
        manager.verify_peer(&sample_cert(now, 99), now),
        Err(SecurityError::CertificateRevoked)
    ));

    let mut watcher = KeyEpochWatcher::new();
    let epoch = KeyEpoch {
        kek_version: 10,
        dek_epoch: 20,
        integrity_mac_epoch: 30,
    };
    watcher
        .observe("partition-1", epoch, now)
        .expect("first epoch");
    let err = watcher
        .observe(
            "partition-1",
            KeyEpoch {
                kek_version: 5,
                ..epoch
            },
            now,
        )
        .expect_err("regression rejected");
    assert!(matches!(err, SecurityError::KeyEpochReplay(_)));

    let mut registry = MetricsRegistry::new("clustor");
    watcher.publish_metrics(&mut registry);
    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot
            .gauges
            .get("clustor.security.key_epoch_lag")
            .copied()
            .unwrap_or_default(),
        0
    );

    let lag_error = watcher
        .observe(
            "partition-2",
            KeyEpoch {
                kek_version: 9,
                dek_epoch: 18,
                integrity_mac_epoch: 29,
            },
            now,
        )
        .expect_err("lag detected");
    if let SecurityError::KeyEpochLag { lag, .. } = lag_error {
        assert_eq!(lag, 2);
    } else {
        panic!("expected lag error");
    }

    let mut registry = MetricsRegistry::new("clustor");
    watcher.publish_metrics(&mut registry);
    let snapshot = registry.snapshot();
    assert_eq!(
        snapshot
            .gauges
            .get("clustor.security.key_epoch_lag")
            .copied()
            .unwrap_or_default(),
        2
    );

    watcher.allow_override("partition-2", "rotation", Duration::from_secs(30), now);
    watcher
        .observe(
            "partition-2",
            KeyEpoch {
                kek_version: 9,
                dek_epoch: 18,
                integrity_mac_epoch: 29,
            },
            now + Duration::from_secs(1),
        )
        .expect("override allows lagging partition");

    let mut cache = RbacManifestCache::new(Duration::from_secs(30));
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
    cache
        .authorize("operator", "CreatePartition", now)
        .expect("authorized");
    let token = BreakGlassToken {
        token_id: "token-checkpoint".into(),
        spiffe_id: SpiffeId::parse("spiffe://example.org/breakglass/DurabilityOverride/operator")
            .unwrap(),
        scope: "DurabilityOverride".into(),
        ticket_url: "https://ticket".into(),
        expires_at: now + Duration::from_secs(60),
        issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
    };
    cache
        .apply_breakglass(token, "SetDurabilityMode", now)
        .expect("token accepted");
}
