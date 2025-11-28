use super::client::{RaftNetworkClient, RaftNetworkClientConfig, RaftNetworkClientOptions};
use super::server::{RaftNetworkServer, RaftNetworkServerConfig, RaftNetworkServerHandle};
use crate::net::NetError;
use crate::replication::raft::{
    AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse,
};
use crate::replication::transport::raft::{RaftRpcHandler, RaftRpcServer};
use log::warn;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task;

pub struct AsyncRaftNetworkClient {
    inner: Arc<RaftNetworkClient>,
}

impl AsyncRaftNetworkClient {
    pub fn new(config: RaftNetworkClientConfig) -> Result<Self, NetError> {
        Ok(Self {
            inner: Arc::new(RaftNetworkClient::new(config)?),
        })
    }

    pub fn with_options(
        config: RaftNetworkClientConfig,
        options: RaftNetworkClientOptions,
    ) -> Result<Self, NetError> {
        Ok(Self {
            inner: Arc::new(RaftNetworkClient::with_options(config, options)?),
        })
    }

    pub async fn request_vote(
        &self,
        request: RequestVoteRequest,
        now: Instant,
    ) -> Result<RequestVoteResponse, NetError> {
        let inner = self.inner.clone();
        task::spawn_blocking(move || inner.request_vote(&request, now))
            .await
            .map_err(map_join_error)?
    }

    pub async fn append_entries(
        &self,
        request: AppendEntriesRequest,
        now: Instant,
    ) -> Result<AppendEntriesResponse, NetError> {
        self.append_entries_with_abort(request, now, || false).await
    }

    pub async fn append_entries_with_abort<F>(
        &self,
        request: AppendEntriesRequest,
        now: Instant,
        should_abort: F,
    ) -> Result<AppendEntriesResponse, NetError>
    where
        F: Fn() -> bool + Send + 'static,
    {
        let inner = self.inner.clone();
        task::spawn_blocking(move || inner.append_entries_with_abort(&request, now, should_abort))
            .await
            .map_err(map_join_error)?
    }

    pub async fn refresh_revocation(&self, now: Instant) -> Result<(), NetError> {
        let inner = self.inner.clone();
        task::spawn_blocking(move || {
            inner.refresh_revocation(now);
        })
        .await
        .map_err(map_join_error)?;
        Ok(())
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }
}

impl Clone for AsyncRaftNetworkClient {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct AsyncRaftNetworkServer;

pub struct AsyncRaftNetworkServerHandle {
    inner: Option<RaftNetworkServerHandle>,
}

impl AsyncRaftNetworkServerHandle {
    pub async fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)).await {
            warn!("event=async_raft_server_shutdown_error error={err}");
        }
    }

    pub async fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        if let Some(mut handle) = self.inner.take() {
            task::spawn_blocking(move || handle.try_shutdown(timeout))
                .await
                .map_err(map_join_error)??;
        }
        Ok(())
    }
}

impl Drop for AsyncRaftNetworkServerHandle {
    fn drop(&mut self) {
        if let Some(mut handle) = self.inner.take() {
            let _ = handle.try_shutdown(Duration::from_secs(5));
        }
    }
}

impl AsyncRaftNetworkServer {
    pub async fn spawn<H>(
        config: RaftNetworkServerConfig,
        server: RaftRpcServer<H>,
    ) -> Result<AsyncRaftNetworkServerHandle, NetError>
    where
        H: RaftRpcHandler + Send + 'static,
    {
        let handle = task::spawn_blocking(move || RaftNetworkServer::spawn(config, server))
            .await
            .map_err(map_join_error)??;
        Ok(AsyncRaftNetworkServerHandle {
            inner: Some(handle),
        })
    }
}

fn map_join_error(err: task::JoinError) -> NetError {
    NetError::Io(std::io::Error::other(format!(
        "async task cancelled: {err}"
    )))
}
