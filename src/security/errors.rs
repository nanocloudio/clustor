use crate::storage::crypto::KeyEpochError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("invalid SPIFFE ID: {0}")]
    InvalidSpiffeId(String),
    #[error("certificate not yet valid")]
    CertificateNotYetValid,
    #[error("certificate expired")]
    CertificateExpired,
    #[error("certificate revoked")]
    CertificateRevoked,
    #[error("trust domain mismatch")]
    TrustDomainMismatch,
    #[error("key epoch replay detected: {0}")]
    KeyEpochReplay(#[from] KeyEpochError),
    #[error("key epoch lag detected for {scope}: {lag} epoch(s) behind")]
    KeyEpochLag { scope: String, lag: u32 },
    #[error("override expired for {scope}: {reason}")]
    OverrideExpired { scope: String, reason: String },
    #[cfg(feature = "admin-http")]
    #[error("RBAC manifest unavailable")]
    RbacUnavailable,
    #[cfg(feature = "admin-http")]
    #[error("RBAC manifest stale")]
    RbacStale,
    #[cfg(feature = "admin-http")]
    #[error("invalid RBAC manifest: {0}")]
    InvalidRbacManifest(String),
    #[error("capability unauthorized")]
    Unauthorized,
    #[error("revocation data stale")]
    RevocationDataStale,
    #[error("revocation feeds unavailable; entering quarantine")]
    RevocationFailClosed,
    #[cfg(feature = "admin-http")]
    #[error("break-glass token expired")]
    BreakGlassExpired,
    #[cfg(feature = "admin-http")]
    #[error("break-glass scope mismatch")]
    BreakGlassScopeMismatch,
    #[cfg(feature = "admin-http")]
    #[error("break-glass SVID invalid: {0}")]
    BreakGlassSvidInvalid(String),
    #[cfg(feature = "admin-http")]
    #[error("security serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
