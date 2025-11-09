use thiserror::Error;

pub mod admin;
pub mod cp;
mod http;
pub mod raft;
pub mod readyz;
pub mod tls;
pub mod why;

pub use admin::{AdminHttpServer, AdminHttpServerConfig, AdminHttpServerHandle};
pub use cp::{HttpCpTransport, HttpCpTransportBuilder};
pub use raft::{
    RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkServer, RaftNetworkServerConfig,
    RaftNetworkServerHandle,
};
pub use readyz::{
    ReadyzHttpServer, ReadyzHttpServerConfig, ReadyzHttpServerHandle, ReadyzPublisher,
};
pub use tls::{load_identity_from_pem, load_trust_store_from_pem, TlsIdentity, TlsTrustStore};
pub use why::{WhyHttpServer, WhyHttpServerConfig, WhyHttpServerHandle, WhyPublisher};

/// Errors emitted by the built-in networking helpers.
#[derive(Debug, Error)]
pub enum NetError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate error: {0}")]
    Certificate(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}
