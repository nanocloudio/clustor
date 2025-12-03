use super::async_transport::{
    AsyncRaftTransportClient, AsyncRaftTransportClientConfig, AsyncRaftTransportClientOptions,
    AsyncRaftTransportServer, AsyncRaftTransportServerConfig, AsyncRaftTransportServerHandle,
};
use crate::net::NetError;
use crate::replication::raft::{
    AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse,
};
use crate::replication::transport::raft::{RaftRpcHandler, RaftRpcServer};
use log::warn;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct AsyncRaftNetworkClient {
    inner: Arc<AsyncRaftTransportClient>,
}

impl AsyncRaftNetworkClient {
    pub fn new(config: AsyncRaftTransportClientConfig) -> Result<Self, NetError> {
        Self::with_options(config, AsyncRaftTransportClientOptions::default())
    }

    pub fn with_options(
        config: AsyncRaftTransportClientConfig,
        options: AsyncRaftTransportClientOptions,
    ) -> Result<Self, NetError> {
        Ok(Self {
            inner: Arc::new(AsyncRaftTransportClient::new(config, options)?),
        })
    }

    pub async fn request_vote(
        &self,
        request: RequestVoteRequest,
        now: Instant,
    ) -> Result<RequestVoteResponse, NetError> {
        let _ = now;
        self.inner.request_vote(&request).await
    }

    pub async fn append_entries(
        &self,
        request: AppendEntriesRequest,
        now: Instant,
    ) -> Result<AppendEntriesResponse, NetError> {
        let _ = now;
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
        let _ = now;
        self.inner
            .append_entries_with_abort(&request, should_abort)
            .await
    }

    pub async fn refresh_revocation(&self, now: Instant) -> Result<(), NetError> {
        self.inner.refresh_revocation(now);
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
    inner: Option<AsyncRaftTransportServerHandle>,
}

impl AsyncRaftNetworkServerHandle {
    pub async fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)).await {
            warn!("event=async_raft_server_shutdown_error error={err}");
        }
    }

    pub async fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        let _ = timeout;
        if let Some(mut handle) = self.inner.take() {
            handle.shutdown().await;
        }
        Ok(())
    }
}

impl Drop for AsyncRaftNetworkServerHandle {
    fn drop(&mut self) {
        if let Some(mut handle) = self.inner.take() {
            // Best-effort async shutdown if a runtime is available.
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    handle.shutdown().await;
                });
            }
        }
    }
}

impl AsyncRaftNetworkServer {
    pub async fn spawn<H>(
        config: AsyncRaftTransportServerConfig,
        server: RaftRpcServer<H>,
    ) -> Result<AsyncRaftNetworkServerHandle, NetError>
    where
        H: RaftRpcHandler + Send + 'static,
    {
        let handle = AsyncRaftTransportServer::spawn(
            AsyncRaftTransportServerConfig {
                bind: config.bind,
                identity: config.identity,
                trust_store: config.trust_store,
            },
            server,
        )
        .await?;
        Ok(AsyncRaftNetworkServerHandle {
            inner: Some(handle),
        })
    }
}
