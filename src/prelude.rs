//! Convenience re-exports for downstream crates. Pull this module in via
//! `use clustor::prelude::*;` when you want the most common types without
//! spelunking the module tree.

pub use crate::durability::{AckRecord, DurabilityLedger, IoMode};
pub use crate::readyz::{ReadyExplain, ReadyStateHealth, ReadyStateProbe, ReadyzSnapshot};
pub use crate::util::error::{
    ClustorError, GuardError, Result as ClustorResult, SerializationError,
};

#[cfg(feature = "admin-http")]
pub use crate::control_plane::admin::{AdminHandler, AdminService};

#[cfg(feature = "management")]
pub use crate::net::management::ManagementHttpServer;
