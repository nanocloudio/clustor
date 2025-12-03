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

use std::time::Duration;

pub(super) const OP_REQUEST_VOTE: u8 = 1;
pub(super) const OP_APPEND_ENTRIES: u8 = 2;
pub(super) const STATUS_OK: u8 = 0;
pub(super) const STATUS_ERR: u8 = 1;
pub(super) const RAFT_SERVER_STREAM_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const TRANSPORT_POOL_SIZE_PER_PEER_DEFAULT: usize = 1;
pub(super) const TRANSPORT_POOL_SIZE_PER_PEER_CAP: usize = 4;
pub(super) const TRANSPORT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
