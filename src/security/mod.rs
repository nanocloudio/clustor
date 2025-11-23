#[cfg(feature = "admin-http")]
mod break_glass;
mod certs;
mod errors;
mod mtls;
#[cfg(feature = "admin-http")]
mod rbac;

#[cfg(feature = "admin-http")]
pub use break_glass::{BreakGlassAudit, BreakGlassAuditLog, BreakGlassToken};
pub use certs::{Certificate, SerialNumber, SpiffeId};
pub use errors::SecurityError;
pub use mtls::{
    KeyEpochWatcher, MtlsIdentityManager, OverrideWindow, RevocationSource, RevocationState,
};
#[cfg(feature = "admin-http")]
pub use rbac::{RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
