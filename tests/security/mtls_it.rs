use clustor::security::{
    Certificate, KeyEpochWatcher, MtlsIdentityManager, RevocationSource, SecurityError,
    SerialNumber, SpiffeId,
};
use clustor::KeyEpoch;
use std::time::{Duration, Instant};

const REVOCATION_MAX_STALENESS_MS: u64 = 300_000;
const REVOCATION_FAIL_CLOSED_MS: u64 = 600_000;
const REVOCATION_WAIVER_EXTENSION_MS: u64 = 300_000;

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
