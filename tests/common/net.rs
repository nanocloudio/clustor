#![cfg(test)]

use clustor::net::{load_identity_from_pem, load_trust_store_from_pem, TlsIdentity, TlsTrustStore};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::convert::TryInto;
use std::error::Error;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tempfile::TempDir;

pub struct TlsFixtures {
    pub server: TlsIdentity,
    pub client: TlsIdentity,
    pub trust: TlsTrustStore,
}

pub fn generate_tls_materials(
    dir: &TempDir,
    dns_names: &[&str],
    server_spiffe: &str,
    client_spiffe: &str,
) -> Result<TlsFixtures, Box<dyn Error>> {
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca_params().self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();
    let ca_path = dir.path().join("ca.pem");
    fs::write(&ca_path, &ca_pem)?;

    let (server_chain, server_key) = write_identity(
        dir.path(),
        "server",
        &ca_cert,
        &ca_key,
        leaf_params(server_spiffe, dns_names)?,
    )?;
    let (client_chain, client_key) = write_identity(
        dir.path(),
        "client",
        &ca_cert,
        &ca_key,
        leaf_params(client_spiffe, dns_names)?,
    )?;

    let now = Instant::now();
    let server = load_identity_from_pem(&server_chain, &server_key, now)?;
    let client = load_identity_from_pem(&client_chain, &client_key, now)?;
    let trust = load_trust_store_from_pem(&ca_path)?;

    Ok(TlsFixtures {
        server,
        client,
        trust,
    })
}

pub fn next_loopback() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral addr")
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(DnType::CommonName, "test-ca");
        dn
    };
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

fn leaf_params(spiffe: &str, dns_names: &[&str]) -> Result<CertificateParams, Box<dyn Error>> {
    let mut params = CertificateParams::new(
        dns_names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
    )?;
    if let Some(primary) = dns_names.first() {
        params.distinguished_name.push(DnType::CommonName, *primary);
    }
    params
        .subject_alt_names
        .push(SanType::URI(spiffe.try_into()?));
    Ok(params)
}

fn write_identity(
    dir: &Path,
    name: &str,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    params: CertificateParams,
) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, ca_cert, ca_key)?;
    let mut full_chain = cert.pem();
    full_chain.push_str(&ca_cert.pem());
    let chain_path = dir.join(format!("{name}-chain.pem"));
    let key_path = dir.join(format!("{name}.key"));
    fs::write(&chain_path, full_chain)?;
    fs::write(&key_path, key.serialize_pem())?;
    Ok((chain_path, key_path))
}
