#![cfg(feature = "net")]

#[cfg(feature = "async-net")]
mod async_adapter;
mod client;
mod server;

#[cfg(feature = "async-net")]
pub use async_adapter::{
    AsyncRaftNetworkClient, AsyncRaftNetworkServer, AsyncRaftNetworkServerHandle,
};
pub use client::{RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkClientOptions};
pub use server::{RaftNetworkServer, RaftNetworkServerConfig, RaftNetworkServerHandle};

use std::time::Duration;

pub(super) const OP_REQUEST_VOTE: u8 = 1;
pub(super) const OP_APPEND_ENTRIES: u8 = 2;
pub(super) const STATUS_OK: u8 = 0;
pub(super) const STATUS_ERR: u8 = 1;
pub(super) const MAX_CONCURRENT_RAFT_CONNECTIONS: usize = 64;
pub(super) const RAFT_CLIENT_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const RAFT_SERVER_STREAM_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const RAFT_SERVER_IDLE_POLL: Duration = Duration::from_millis(200);
pub(super) const RAFT_CLIENT_RETRY_ATTEMPTS: usize = 3;
pub(super) const RAFT_CLIENT_BACKOFF_MS: Duration = Duration::from_millis(50);
