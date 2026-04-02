#![cfg(feature = "net")]

use super::{CertificateError, NetError};
use rustls::RootCertStore;
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Clone)]
pub struct TlsTrustStore {
    pub roots: RootCertStore,
}

pub fn load_trust_store_from_pem(path: impl AsRef<Path>) -> Result<TlsTrustStore, NetError> {
    let mut reader = BufReader::new(File::open(path)?);
    let raw = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CertificateError::TrustBundleRead)?;
    if raw.is_empty() {
        return Err(NetError::from(CertificateError::TrustBundleEmpty));
    }
    let mut store = RootCertStore::empty();
    let (added, _skipped) = store.add_parsable_certificates(raw.clone());
    if added == 0 {
        return Err(NetError::from(CertificateError::TrustBundleUnparsable));
    }
    Ok(TlsTrustStore { roots: store })
}
