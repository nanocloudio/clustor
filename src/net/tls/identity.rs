#![cfg(feature = "net")]

use super::trust::{SpiffeServerVerifier, TlsTrustStore};
use super::{CertificateError, NetError};
use crate::security::{Certificate, SerialNumber, SpiffeId};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate as RustlsCertificate, ClientConfig, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension, SubjectAlternativeName};
use x509_parser::prelude::FromDer;

#[derive(Clone)]
pub struct TlsIdentity {
    pub chain: Vec<RustlsCertificate>,
    pub private_key: PrivateKey,
    pub certificate: Certificate,
}

impl TlsIdentity {
    pub fn client_config(&self, trust: &TlsTrustStore) -> Result<ClientConfig, NetError> {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SpiffeServerVerifier::new(
                trust.roots.clone(),
            )))
            .with_client_auth_cert(self.chain.clone(), self.private_key.clone())
            .map_err(NetError::from)
    }

    pub fn server_config(&self, trust: &TlsTrustStore) -> Result<ServerConfig, NetError> {
        let verifier = Arc::new(AllowAnyAuthenticatedClient::new(trust.roots.clone()));
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.chain.clone(), self.private_key.clone())
            .map_err(NetError::from)
    }
}

pub fn load_identity_from_pem(
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    now: Instant,
) -> Result<TlsIdentity, NetError> {
    let chain = load_cert_chain(cert_path)?;
    if chain.is_empty() {
        return Err(NetError::from(CertificateError::IdentityChainEmpty));
    }
    let private_key = load_private_key(key_path)?;
    let certificate = parse_certificate_metadata(&chain[0].0, now)?;
    Ok(TlsIdentity {
        chain,
        private_key,
        certificate,
    })
}

fn load_cert_chain(path: impl AsRef<Path>) -> Result<Vec<RustlsCertificate>, NetError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut chain = Vec::new();
    for cert in certs(&mut reader).map_err(|_| CertificateError::InvalidCertificateChain)? {
        chain.push(RustlsCertificate(cert));
    }
    Ok(chain)
}

fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKey, NetError> {
    let path = path.as_ref();
    let pem = std::fs::read(path)?;

    let mut reader = Cursor::new(&pem);
    let keys = pkcs8_private_keys(&mut reader).map_err(|_| CertificateError::InvalidPkcs8Key)?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKey(key));
    }

    let mut reader = Cursor::new(&pem);
    let keys = rsa_private_keys(&mut reader).map_err(|_| CertificateError::InvalidRsaKey)?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKey(key));
    }

    let mut reader = Cursor::new(&pem);
    let keys = ec_private_keys(&mut reader).map_err(|_| CertificateError::InvalidEcKey)?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(PrivateKey(key));
    }

    Err(NetError::from(CertificateError::MissingPrivateKey))
}

pub(crate) fn parse_certificate_metadata(
    der: &[u8],
    now: Instant,
) -> Result<Certificate, NetError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|err| CertificateError::X509Parse {
        details: err.to_string(),
    })?;
    let spiffe = extract_spiffe_id(&cert)?;
    let serial = serial_from_raw(cert.tbs_certificate.raw_serial())?;
    let validity = cert.validity();
    let now_system = SystemTime::now();
    let valid_from_system = as_system_time(&validity.not_before)?;
    let valid_until_system = as_system_time(&validity.not_after)?;
    Ok(Certificate {
        spiffe_id: spiffe,
        serial,
        valid_from: project_system_time(valid_from_system, now_system, now),
        valid_until: project_system_time(valid_until_system, now_system, now),
    })
}

pub(crate) fn extract_spiffe_id(cert: &X509Certificate<'_>) -> Result<SpiffeId, NetError> {
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names }) =
            ext.parsed_extension()
        {
            for name in general_names {
                if let GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        return SpiffeId::parse(uri).map_err(|err| {
                            NetError::from(CertificateError::InvalidSpiffeId {
                                uri: uri.to_string(),
                                details: err.to_string(),
                            })
                        });
                    }
                }
            }
        }
    }
    Err(NetError::from(CertificateError::MissingSpiffeUri))
}

fn serial_from_raw(raw: &[u8]) -> Result<SerialNumber, NetError> {
    if raw.is_empty() {
        return Err(NetError::from(CertificateError::SerialMissing));
    }
    if raw.len() > SerialNumber::MAX_LEN {
        return Err(NetError::from(CertificateError::SerialTooLong {
            max: SerialNumber::MAX_LEN,
        }));
    }
    Ok(SerialNumber::from_be_bytes(raw))
}

fn as_system_time(time: &x509_parser::time::ASN1Time) -> Result<SystemTime, NetError> {
    let dt = time.to_datetime();
    let secs = dt.unix_timestamp();
    let nanos = dt.nanosecond() as u64;
    if secs >= 0 {
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64) + Duration::from_nanos(nanos))
    } else {
        let abs = secs.unsigned_abs();
        Ok(SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(abs))
            .ok_or(CertificateError::TimeBeforeUnixEpoch)?
            .checked_sub(Duration::from_nanos(nanos))
            .ok_or(CertificateError::TimeBeforeUnixEpoch)?)
    }
}

fn project_system_time(
    target: SystemTime,
    reference_system: SystemTime,
    reference_instant: Instant,
) -> Instant {
    if let Ok(delta) = target.duration_since(reference_system) {
        reference_instant + delta
    } else if let Ok(delta) = reference_system.duration_since(target) {
        reference_instant
            .checked_sub(delta)
            .unwrap_or(reference_instant)
    } else {
        reference_instant
    }
}
