#![cfg(feature = "net")]

use super::{CertificateError, NetError};
use crate::security::Certificate;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, ServerConnection};
use std::convert::TryFrom;
use std::net::TcpStream;
use std::time::Instant;

use super::identity::parse_certificate_metadata;

pub fn complete_client_handshake(
    conn: &mut ClientConnection,
    stream: &mut TcpStream,
) -> Result<(), NetError> {
    while conn.is_handshaking() {
        conn.complete_io(stream)?;
    }
    Ok(())
}

pub fn complete_server_handshake(
    conn: &mut ServerConnection,
    stream: &mut TcpStream,
) -> Result<(), NetError> {
    while conn.is_handshaking() {
        conn.complete_io(stream)?;
    }
    Ok(())
}

pub fn decode_peer_certificate(
    chain: &[CertificateDer<'_>],
    now: Instant,
) -> Result<Certificate, NetError> {
    let leaf = chain.first().ok_or(CertificateError::EmptyPeerChain)?;
    parse_certificate_metadata(leaf.as_ref(), now)
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, NetError> {
    ServerName::try_from(host.to_string()).map_err(|_| {
        NetError::from(CertificateError::InvalidDnsName {
            host: host.to_string(),
        })
    })
}
