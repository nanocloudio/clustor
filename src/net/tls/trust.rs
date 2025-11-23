#![cfg(feature = "net")]

use super::{CertificateError, NetError};
use log::trace;
use rustls::client::{
    verify_server_cert_signed_by_trust_anchor, ServerCertVerified, ServerCertVerifier,
};
use rustls::server::ParsedCertificate;
use rustls::{Certificate, RootCertStore, ServerName};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Clone)]
pub struct TlsTrustStore {
    pub roots: RootCertStore,
}

pub fn load_trust_store_from_pem(path: impl AsRef<Path>) -> Result<TlsTrustStore, NetError> {
    let mut reader = BufReader::new(File::open(path)?);
    let raw = certs(&mut reader).map_err(|_| CertificateError::TrustBundleRead)?;
    if raw.is_empty() {
        return Err(NetError::from(CertificateError::TrustBundleEmpty));
    }
    let mut store = RootCertStore::empty();
    let (added, _skipped) = store.add_parsable_certificates(&raw);
    if added == 0 {
        return Err(NetError::from(CertificateError::TrustBundleUnparsable));
    }
    Ok(TlsTrustStore { roots: store })
}

pub(crate) struct SpiffeServerVerifier {
    roots: Arc<RootCertStore>,
}

impl SpiffeServerVerifier {
    pub(crate) fn new(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
        }
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            self.roots.as_ref(),
            intermediates,
            now,
        )?;

        // Consume SCTs/OCSP data so rustls doesn't warn about unused iterators.
        for _ in scts {}
        if !ocsp_response.is_empty() {
            trace!(
                "ignoring OCSP response from peer ({} bytes)",
                ocsp_response.len()
            );
        }

        Ok(ServerCertVerified::assertion())
    }
}
