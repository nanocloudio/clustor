//! Control-plane prelude: CP guardrails, capabilities, admin workflows, and CP HTTP surfaces.

#[cfg(feature = "admin-http")]
pub mod admin;
pub mod capabilities;
pub mod core;

#[cfg(feature = "admin-http")]
pub use admin::*;
pub use capabilities::*;
pub use core::*;

#[cfg(feature = "net")]
pub use crate::net::control_plane::cp::{HttpCpTransport, HttpCpTransportBuilder};
#[cfg(all(feature = "net", feature = "snapshot-crypto"))]
pub use crate::net::control_plane::why::WhySnapshotBlocked;
#[cfg(feature = "net")]
pub use crate::net::control_plane::why::{
    LocalRole, WhyHttpServer, WhyHttpServerConfig, WhyHttpServerHandle, WhyNotLeader, WhyPublisher,
    WhySchemaHeader,
};
