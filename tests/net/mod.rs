#[cfg(all(feature = "net", feature = "admin-http"))]
#[path = "../support/net/control_plane.rs"]
pub mod control_plane_support;

#[cfg(feature = "net")]
#[path = "../support/net/http_client.rs"]
pub mod http_client;

#[cfg(feature = "net")]
#[path = "../support/net/loopback.rs"]
pub mod loopback_support;

#[cfg(feature = "net")]
#[path = "../support/net/readyz_helpers.rs"]
pub mod readyz_support;

#[cfg(all(feature = "net", feature = "snapshot-crypto"))]
#[path = "../support/net/readyz_blocked.rs"]
pub mod readyz_blocked;

#[cfg(feature = "net")]
#[path = "../support/net/tls.rs"]
pub mod tls_support;

mod admin_http_integration;
mod control_plane_cp_client_it;
mod control_plane_why_schema_it;
mod http_deadline_it;
mod http_parser_fuzz;
mod http_parser_it;
mod management_http_integration;
mod management_http_it;
mod raft_integration;
mod readyz_http;
