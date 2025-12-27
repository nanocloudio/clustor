#![cfg(feature = "net")]

#[cfg(feature = "async-net")]
mod async_adapter;
#[cfg(feature = "async-net")]
pub mod async_transport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub host: String,
    pub port: u16,
}

#[cfg(feature = "async-net")]
pub use async_adapter::{
    AsyncRaftNetworkClient, AsyncRaftNetworkServer, AsyncRaftNetworkServerHandle,
};
#[cfg(feature = "async-net")]
pub use async_transport::{
    AsyncRaftTransportClient, AsyncRaftTransportClientConfig, AsyncRaftTransportClientOptions,
    AsyncRaftTransportPoolManager, AsyncRaftTransportServer, AsyncRaftTransportServerConfig,
    AsyncRaftTransportServerHandle,
};

#[cfg(feature = "async-net")]
use std::time::Duration;

#[cfg(feature = "async-net")]
pub(super) const OP_REQUEST_VOTE: u8 = 1;
#[cfg(feature = "async-net")]
pub(super) const OP_APPEND_ENTRIES: u8 = 2;
#[cfg(feature = "async-net")]
pub(super) const STATUS_OK: u8 = 0;
#[cfg(feature = "async-net")]
pub(super) const STATUS_ERR: u8 = 1;
#[cfg(feature = "async-net")]
pub(super) const RAFT_SERVER_STREAM_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "async-net")]
pub(super) const TRANSPORT_POOL_SIZE_PER_PEER_DEFAULT: usize = 1;
#[cfg(feature = "async-net")]
pub(super) const TRANSPORT_POOL_SIZE_PER_PEER_CAP: usize = 4;
#[cfg(feature = "async-net")]
pub(super) const TRANSPORT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
