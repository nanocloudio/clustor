use crate::control_plane::core::CpGuardError;
use thiserror::Error;

pub mod control_plane;
mod http;
#[cfg(feature = "management")]
pub mod management;
#[cfg(feature = "net")]
pub mod peer_supervisor;
pub mod readyz;
pub mod replication;
mod server;
pub mod tls;

#[cfg(feature = "admin-http")]
pub use control_plane::admin::{AdminHttpServer, AdminHttpServerConfig, AdminHttpServerHandle};
#[cfg(all(feature = "admin-http", feature = "async-net"))]
pub use control_plane::admin::{AsyncAdminHttpServer, AsyncAdminHttpServerHandle};
pub use control_plane::cp::{HttpCpTransport, HttpCpTransportBuilder};
#[cfg(feature = "snapshot-crypto")]
pub use control_plane::why::WhySnapshotBlocked;
#[cfg(feature = "async-net")]
pub use control_plane::why::{AsyncWhyHttpServer, AsyncWhyHttpServerHandle};
pub use control_plane::why::{
    LocalRole, WhyHttpServer, WhyHttpServerConfig, WhyHttpServerHandle, WhyNotLeader, WhyPublisher,
    WhySchemaHeader,
};
#[cfg(all(feature = "management", feature = "async-net"))]
pub use management::{AsyncManagementHttpServer, AsyncManagementHttpServerHandle};
#[cfg(feature = "management")]
pub use management::{
    ManagementHttpServer, ManagementHttpServerConfig, ManagementHttpServerHandle,
};
#[cfg(all(feature = "net", feature = "async-net"))]
pub use peer_supervisor::spawn_revocation_refresher;
#[cfg(feature = "net")]
pub use peer_supervisor::{PeerHealth, PeerStatus};
#[cfg(feature = "async-net")]
pub use readyz::{AsyncReadyzHttpServer, AsyncReadyzHttpServerHandle};
pub use readyz::{
    ReadyzHttpServer, ReadyzHttpServerConfig, ReadyzHttpServerHandle, ReadyzPublisher,
};
#[cfg(feature = "async-net")]
pub use replication::raft::{
    AsyncRaftNetworkClient, AsyncRaftNetworkServer, AsyncRaftNetworkServerHandle,
};
pub use replication::raft::{
    RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkClientOptions, RaftNetworkServer,
    RaftNetworkServerConfig, RaftNetworkServerHandle,
};
pub use tls::{load_identity_from_pem, load_trust_store_from_pem, TlsIdentity, TlsTrustStore};

#[cfg(feature = "http-fuzz")]
pub fn fuzz_http_request(input: &[u8]) {
    http::fuzz_http_request(input);
}

/// Errors emitted by the built-in networking helpers.
#[derive(Debug, Error)]
pub enum NetError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate error: {0}")]
    Certificate(#[from] CertificateError),
    #[error("HTTP error: {0}")]
    Http(#[from] HttpError),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    ControlPlane(#[from] CpGuardError),
}

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("identity certificate chain empty")]
    IdentityChainEmpty,
    #[error("failed to read trust bundle")]
    TrustBundleRead,
    #[error("trust bundle is empty")]
    TrustBundleEmpty,
    #[error("trust bundle does not contain parsable certificates")]
    TrustBundleUnparsable,
    #[error("peer sent empty certificate chain")]
    EmptyPeerChain,
    #[error("invalid DNS name `{host}` for certificate")]
    InvalidDnsName { host: String },
    #[error("invalid certificate chain")]
    InvalidCertificateChain,
    #[error("invalid PKCS#8 private key")]
    InvalidPkcs8Key,
    #[error("invalid RSA private key")]
    InvalidRsaKey,
    #[error("invalid SEC1 EC private key")]
    InvalidEcKey,
    #[error(
        "unsupported or missing private key material (expected PKCS#8, PKCS#1 RSA, or SEC1 EC)"
    )]
    MissingPrivateKey,
    #[error("x509 parse error: {details}")]
    X509Parse { details: String },
    #[error("certificate missing SPIFFE URI SAN")]
    MissingSpiffeUri,
    #[error("invalid SPIFFE ID `{uri}`: {details}")]
    InvalidSpiffeId { uri: String, details: String },
    #[error("certificate serial number missing")]
    SerialMissing,
    #[error("certificate serial number exceeds {max} bytes")]
    SerialTooLong { max: usize },
    #[error("certificate time before UNIX epoch")]
    TimeBeforeUnixEpoch,
    #[error("peer certificate missing ({context})")]
    MissingPeerCertificate { context: &'static str },
    #[error("client certificate missing ({context})")]
    MissingClientCertificate { context: &'static str },
}

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("connection closed while reading headers")]
    ConnectionClosedBeforeHeaders,
    #[error("missing HTTP header terminator")]
    MissingHeaderTerminator,
    #[error("HTTP headers exceed limit")]
    HeadersTooLarge,
    #[error("partial HTTP request received")]
    PartialRequest,
    #[error("HTTP request timed out")]
    RequestTimeout,
    #[error("HTTP request parse error: {0:?}")]
    RequestParse(httparse::Error),
    #[error("HTTP method missing")]
    MissingMethod,
    #[error("HTTP path missing")]
    MissingPath,
    #[error("invalid header value for {name}")]
    InvalidHeaderValue { name: String },
    #[error("invalid Content-Length header value")]
    InvalidContentLengthValue,
    #[error("HTTP body exceeds limit")]
    BodyTooLarge,
    #[error("connection closed before HTTP body completed")]
    ConnectionClosedBeforeBody,
    #[error("JSON serialization error: {0}")]
    JsonSerialize(#[from] serde_json::Error),
    #[error("response formatting failed")]
    ResponseFormat,
    #[error("HTTP response write timed out")]
    ResponseTimeout,
    #[error("control-plane transport requires https scheme (found {scheme})")]
    UnsupportedScheme { scheme: String },
    #[error("identity material not provided")]
    MissingIdentityMaterial,
    #[error("trust store not provided")]
    MissingTrustStore,
    #[error("control-plane URL missing host")]
    MissingHost,
    #[error("control-plane endpoint returned HTTP {status}")]
    UnexpectedStatus { status: u16 },
    #[error("invalid endpoint path: {0}")]
    InvalidEndpointPath(url::ParseError),
    #[error("endpoint path attempted to change host")]
    HostMismatch,
    #[error("failed to parse HTTP response")]
    ResponseParse,
    #[error("HTTP response missing status code")]
    MissingStatusCode,
    #[error("invalid Content-Length header")]
    InvalidContentLengthHeader,
    #[error("chunked transfer encoding unsupported")]
    ChunkedEncodingUnsupported,
    #[error("Content-Length header missing")]
    MissingContentLength,
    #[error("truncated HTTP body")]
    TruncatedBody,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame encoding failed for {context}: {details}")]
    FrameEncode {
        context: &'static str,
        details: String,
    },
    #[error("frame decoding failed for {context}: {details}")]
    FrameDecode {
        context: &'static str,
        details: String,
    },
    #[error("mTLS verification failed: {details}")]
    MtlsVerification { details: String },
    #[error("invalid frame length")]
    FrameLength,
    #[error("remote endpoint returned error status {status}")]
    RemoteError { status: u8, message: Option<String> },
    #[error("service lock poisoned ({context})")]
    Poisoned { context: &'static str },
    #[error("client session missing")]
    MissingSession,
    #[error("{context} server shutdown timed out")]
    ShutdownTimeout { context: &'static str },
}
