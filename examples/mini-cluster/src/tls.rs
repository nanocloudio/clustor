use clustor::security::MtlsIdentityManager;
use clustor::net::TlsIdentity;
use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::time::interval;
use tokio_rustls::rustls;
use clustor::security::RevocationSource;
use parking_lot::RwLock;

pub const REVOCATION_REFRESH_INTERVAL: Duration = Duration::from_secs(240);

pub fn new_mtls_manager(
    identity: &TlsIdentity,
    trust_domain: &str,
    revocation_ttl: Duration,
) -> MtlsIdentityManager {
    MtlsIdentityManager::new(
        identity.certificate.clone(),
        trust_domain.to_string(),
        revocation_ttl,
        Instant::now(),
    )
}

pub fn build_http_tls(identity: &TlsIdentity) -> anyhow::Result<rustls::ServerConfig> {
    let cert_chain = identity.chain.clone();
    let private_key = identity.private_key.clone();
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("failed to build HTTP TLS config")?;
    Ok(config)
}

pub async fn refresh_server_revocation(
    identity: Arc<RwLock<MtlsIdentityManager>>,
) {
    let mut ticker = interval(REVOCATION_REFRESH_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let mut guard = identity.write();
        guard.record_revocation_refresh(RevocationSource::Ocsp, now);
        guard.record_revocation_refresh(RevocationSource::Crl, now);
    }
}
