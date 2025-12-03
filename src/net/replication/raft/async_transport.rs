use super::{
    OP_APPEND_ENTRIES, OP_REQUEST_VOTE, STATUS_ERR, STATUS_OK, TRANSPORT_POOL_IDLE_TIMEOUT,
    TRANSPORT_POOL_SIZE_PER_PEER_CAP, TRANSPORT_POOL_SIZE_PER_PEER_DEFAULT,
};
use crate::control_plane::core::PlacementRecord;
use crate::net::tls::{decode_peer_certificate, server_name, TlsIdentity, TlsTrustStore};
use crate::net::{CertificateError, NetError, ProtocolError};
use crate::replication::flow::{
    CreditHint, FlowProfile, FlowThrottleEnvelope, FlowThrottleReason, FlowThrottleState,
    IngestStatusCode,
};
use crate::replication::raft::{
    AppendEntriesRequest, AppendEntriesResponse, RaftRouting, RequestVoteRequest,
    RequestVoteResponse,
};
use crate::replication::transport::raft::{RaftRpcHandler, RaftRpcServer};
use crate::retry::RetryPolicy;
use crate::security::{MtlsIdentityManager, RevocationSource};
use crate::telemetry::SharedMetricsRegistry;
use log::{debug, info, warn};
use parking_lot::Mutex as ParkingMutex;
use rustls::client::ServerName;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const NODE_SOCKET_BURST_BYTES: usize = 128 * 1024;
const NODE_SOCKET_BURST_WINDOW: Duration = Duration::from_millis(5);

type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Configures the async session pool for a single peer.
#[derive(Clone)]
pub struct AsyncSessionPoolConfig {
    pub host: String,
    pub port: u16,
    pub tls_config: Arc<ClientConfig>,
    pub server_name: ServerName,
    pub mtls: Arc<ParkingMutex<MtlsIdentityManager>>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_size: usize,
}

#[derive(Clone, Copy)]
pub struct AsyncSessionPoolTimeouts {
    pub connect: Duration,
    pub io: Duration,
    pub idle: Duration,
}

impl AsyncSessionPoolConfig {
    pub fn new(
        host: String,
        port: u16,
        identity: TlsIdentity,
        trust_store: TlsTrustStore,
        mtls: Arc<ParkingMutex<MtlsIdentityManager>>,
        timeouts: AsyncSessionPoolTimeouts,
        max_size: usize,
    ) -> Result<Self, NetError> {
        let tls_config = Arc::new(identity.client_config(&trust_store)?);
        let server_name = server_name(&host)?;
        Ok(Self {
            host,
            port,
            tls_config,
            server_name,
            mtls,
            connect_timeout: timeouts.connect.max(Duration::from_millis(1)),
            io_timeout: timeouts.io.max(Duration::from_millis(1)),
            idle_timeout: timeouts.idle.max(Duration::from_millis(1)),
            max_size: max_size.clamp(
                TRANSPORT_POOL_SIZE_PER_PEER_DEFAULT,
                TRANSPORT_POOL_SIZE_PER_PEER_CAP,
            ),
        })
    }
}

#[derive(Clone)]
pub struct AsyncSessionPool {
    inner: Arc<AsyncSessionPoolInner>,
}

struct AsyncSessionPoolInner {
    config: AsyncSessionPoolConfig,
    idle: AsyncMutex<Vec<IdleSession>>,
    permits: Arc<Semaphore>,
    leased: AtomicUsize,
    metrics: Option<SharedMetricsRegistry>,
}

struct IdleSession {
    session: AsyncClientSession,
    last_used: Instant,
}

#[derive(Clone, Copy, Debug)]
pub struct AsyncPoolSnapshot {
    pub idle: usize,
    pub leased: usize,
}

pub struct AsyncPoolLease {
    pool: Arc<AsyncSessionPoolInner>,
    session: Option<AsyncClientSession>,
    permit: Option<OwnedSemaphorePermit>,
    counted: bool,
}

impl AsyncSessionPool {
    pub fn new(config: AsyncSessionPoolConfig, metrics: Option<SharedMetricsRegistry>) -> Self {
        let permits = Arc::new(Semaphore::new(config.max_size));
        Self {
            inner: Arc::new(AsyncSessionPoolInner {
                config,
                idle: AsyncMutex::new(Vec::new()),
                permits,
                leased: AtomicUsize::new(0),
                metrics,
            }),
        }
    }

    /// Borrow a session, awaiting capacity instead of failing fast when the pool is at limit.
    pub async fn checkout(&self, now: Instant) -> Result<AsyncPoolLease, NetError> {
        let permit = self
            .inner
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| NetError::Io(io::Error::new(io::ErrorKind::Interrupted, "pool closed")))?;

        self.inner.leased.fetch_add(1, Ordering::SeqCst);

        let mut idle = self.inner.idle.lock().await;
        self.inner.evict_idle(&mut idle, now);
        let session = idle.pop().map(|managed| managed.session);
        drop(idle);

        let session = match session {
            Some(session) => {
                self.inner.record_reuse();
                debug!(
                    "event=raft_async_pool_reuse peer={}:{}",
                    self.inner.config.host, self.inner.config.port
                );
                session
            }
            None => {
                self.inner.record_connect();
                debug!(
                    "event=raft_async_pool_connect peer={}:{}",
                    self.inner.config.host, self.inner.config.port
                );
                match self.inner.connect(now).await {
                    Ok(session) => session,
                    Err(err) => {
                        self.inner.leased.fetch_sub(1, Ordering::SeqCst);
                        drop(permit);
                        return Err(err);
                    }
                }
            }
        };
        Ok(AsyncPoolLease {
            pool: self.inner.clone(),
            session: Some(session),
            permit: Some(permit),
            counted: true,
        })
    }

    pub async fn warmup(&self, now: Instant) -> Result<(), NetError> {
        let lease = self.checkout(now).await?;
        lease.release(now).await;
        Ok(())
    }

    pub async fn snapshot(&self) -> AsyncPoolSnapshot {
        let idle = self.inner.idle.lock().await;
        AsyncPoolSnapshot {
            idle: idle.len(),
            leased: self.inner.leased.load(Ordering::SeqCst),
        }
    }
}

impl AsyncSessionPoolInner {
    fn evict_idle(&self, idle: &mut Vec<IdleSession>, now: Instant) {
        idle.retain(|entry| {
            now.saturating_duration_since(entry.last_used) <= self.config.idle_timeout
        });
    }

    async fn connect(&self, now: Instant) -> Result<AsyncClientSession, NetError> {
        AsyncClientSession::connect(&self.config, now).await
    }

    async fn return_idle(&self, session: AsyncClientSession, now: Instant) {
        let mut idle = self.idle.lock().await;
        if idle.len() < self.config.max_size {
            idle.push(IdleSession {
                session,
                last_used: now,
            });
        }
    }

    fn record_reuse(&self) {
        if let Some(metrics) = &self.metrics {
            let _ = metrics.inc_counter(
                format!(
                    "transport.pool_reuse_total.{}:{}",
                    self.config.host, self.config.port
                ),
                1,
            );
        }
    }

    fn record_connect(&self) {
        if let Some(metrics) = &self.metrics {
            let _ = metrics.inc_counter(
                format!(
                    "transport.pool_connect_total.{}:{}",
                    self.config.host, self.config.port
                ),
                1,
            );
        }
    }
}

impl AsyncPoolLease {
    pub fn session(&mut self) -> Option<&mut AsyncClientSession> {
        self.session.as_mut()
    }

    pub async fn release(mut self, now: Instant) {
        if let Some(session) = self.session.take() {
            self.pool.return_idle(session, now).await;
        }
        if self.counted {
            self.pool.leased.fetch_sub(1, Ordering::SeqCst);
        }
        self.permit.take();
    }

    pub async fn discard(mut self) {
        self.session.take();
        if self.counted {
            self.pool.leased.fetch_sub(1, Ordering::SeqCst);
        }
        self.permit.take();
    }
}

pub struct AsyncClientSession {
    stream: ClientTlsStream,
}

impl AsyncClientSession {
    async fn connect(config: &AsyncSessionPoolConfig, now: Instant) -> Result<Self, NetError> {
        let target = format!("{}:{}", config.host, config.port);
        let stream =
            tokio::time::timeout(config.connect_timeout, TcpStream::connect(target.clone()))
                .await
                .map_err(|_| timeout_error("raft_async_connect", config.connect_timeout))?
                .map_err(NetError::Io)?;
        stream.set_nodelay(true).ok();

        let connector = TlsConnector::from(config.tls_config.clone());
        let tls_stream = tokio::time::timeout(
            config.connect_timeout,
            connector.connect(config.server_name.clone(), stream),
        )
        .await
        .map_err(|_| timeout_error("raft_async_tls", config.connect_timeout))?
        .map_err(NetError::from)?;

        let (_io, conn) = tls_stream.get_ref();
        let peer_chain = conn.peer_certificates().ok_or_else(|| {
            NetError::from(CertificateError::MissingPeerCertificate {
                context: "raft_async_client",
            })
        })?;
        let peer_certificate = decode_peer_certificate(peer_chain, now)?;
        let mut mtls = config.mtls.lock();
        mtls.verify_peer(&peer_certificate, now).map_err(|err| {
            NetError::from(ProtocolError::MtlsVerification {
                details: err.to_string(),
            })
        })?;

        info!(
            "event=raft_async_tls_session peer={}:{}",
            config.host, config.port
        );
        Ok(Self { stream: tls_stream })
    }

    pub async fn send(
        &mut self,
        opcode: u8,
        payload: &[u8],
        io_timeout: Duration,
    ) -> Result<Vec<u8>, NetError> {
        let mut header = [0u8; 5];
        header[0] = opcode;
        header[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());

        let io_fut = async {
            self.stream.write_all(&header).await?;
            self.stream.write_all(payload).await?;
            self.stream.flush().await?;

            let mut response_header = [0u8; 5];
            self.stream.read_exact(&mut response_header).await?;
            let status = response_header[0];
            let len = u32::from_le_bytes(
                response_header[1..5]
                    .try_into()
                    .map_err(|_| ProtocolError::FrameLength)?,
            ) as usize;
            let mut response = vec![0u8; len];
            self.stream.read_exact(&mut response).await?;

            if status == STATUS_OK {
                Ok(response)
            } else {
                let message = String::from_utf8_lossy(&response).into_owned();
                Err(NetError::from(ProtocolError::RemoteError {
                    status,
                    message: Some(message),
                }))
            }
        };

        tokio::time::timeout(io_timeout, io_fut)
            .await
            .map_err(|_| timeout_error("raft_async_io", io_timeout))?
    }
}

fn timeout_error(context: &str, duration: Duration) -> NetError {
    NetError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "{context} timed out after {} ms",
            duration.as_millis().max(1)
        ),
    ))
}

/// Async-first Raft client configuration.
pub struct AsyncRaftTransportClientConfig {
    pub host: String,
    pub port: u16,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
    pub mtls: Arc<ParkingMutex<MtlsIdentityManager>>,
}

#[derive(Clone)]
pub struct AsyncRaftTransportClientOptions {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub pool_size_per_peer_max: usize,
    pub pool_idle_timeout: Duration,
    pub pool_warmup: bool,
    pub pool_backoff: Duration,
    pub retry_policy: RetryPolicy,
    pub peer_node_id: Option<String>,
    pub metrics: Option<SharedMetricsRegistry>,
}

impl Default for AsyncRaftTransportClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            pool_size_per_peer_max: TRANSPORT_POOL_SIZE_PER_PEER_DEFAULT,
            pool_idle_timeout: TRANSPORT_POOL_IDLE_TIMEOUT,
            pool_warmup: true,
            pool_backoff: Duration::from_millis(50),
            retry_policy: RetryPolicy::linear(3, Duration::from_millis(50))
                .with_skip_first_delay(true),
            peer_node_id: None,
            metrics: None,
        }
    }
}

impl AsyncRaftTransportClientOptions {
    pub fn peer_node_id(mut self, peer: impl Into<String>) -> Self {
        self.peer_node_id = Some(peer.into());
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    pub fn pool_size_per_peer_max(mut self, size: usize) -> Self {
        self.pool_size_per_peer_max = size;
        self
    }

    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.pool_idle_timeout = timeout;
        self
    }

    pub fn pool_warmup(mut self, enabled: bool) -> Self {
        self.pool_warmup = enabled;
        self
    }

    pub fn pool_backoff(mut self, backoff: Duration) -> Self {
        self.pool_backoff = backoff;
        self
    }

    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    pub fn metrics(mut self, registry: SharedMetricsRegistry) -> Self {
        self.metrics = Some(registry);
        self
    }
}

/// Async-first Raft client (no spawn_blocking).
pub struct AsyncRaftTransportClient {
    pool: AsyncSessionPool,
    options: AsyncRaftTransportClientOptions,
    retry_policy: RetryPolicy,
    mtls: Arc<ParkingMutex<MtlsIdentityManager>>,
    backoff_until: ParkingMutex<Option<Instant>>,
    draining: AtomicBool,
    cancelled: AtomicBool,
    rpg_scheduler: ParkingMutex<RpgScheduler>,
    metrics: Option<SharedMetricsRegistry>,
}

impl AsyncRaftTransportClient {
    pub fn new(
        config: AsyncRaftTransportClientConfig,
        options: AsyncRaftTransportClientOptions,
    ) -> Result<Self, NetError> {
        let pool = AsyncSessionPool::new(
            AsyncSessionPoolConfig::new(
                config.host.clone(),
                config.port,
                config.identity.clone(),
                config.trust_store.clone(),
                config.mtls.clone(),
                AsyncSessionPoolTimeouts {
                    connect: options.connect_timeout,
                    io: options.io_timeout,
                    idle: options.pool_idle_timeout,
                },
                options.pool_size_per_peer_max,
            )?,
            options.metrics.clone(),
        );
        let options_clone = options.clone();
        let retry_policy = options.retry_policy.clone();
        Ok(Self {
            pool,
            options: options_clone.clone(),
            retry_policy,
            mtls: config.mtls,
            backoff_until: ParkingMutex::new(None),
            draining: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            rpg_scheduler: ParkingMutex::new(RpgScheduler::new()),
            metrics: options_clone.metrics.clone(),
        })
    }

    pub async fn warmup(&self, now: Instant) -> Result<(), NetError> {
        if !self.options.pool_warmup {
            return Ok(());
        }
        self.pool.warmup(now).await?;
        self.record_refresh("PlacementChange", 1);
        self.record_pool_gauges().await;
        Ok(())
    }

    pub fn refresh_revocation(&self, now: Instant) {
        let mut mtls = self.mtls.lock();
        mtls.record_revocation_refresh(RevocationSource::Ocsp, now);
        mtls.record_revocation_refresh(RevocationSource::Crl, now);
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.draining.store(true, Ordering::SeqCst);
        *self.backoff_until.lock() = Some(Instant::now() + self.options.pool_backoff);
    }

    pub fn begin_drain(&self, now: Instant) {
        self.draining.store(true, Ordering::SeqCst);
        *self.backoff_until.lock() = Some(now + self.options.pool_backoff);
    }

    pub fn clear_drain(&self) {
        self.draining.store(false, Ordering::SeqCst);
    }

    pub async fn pool_snapshot(&self) -> AsyncPoolSnapshot {
        self.pool.snapshot().await
    }

    pub async fn request_vote(
        &self,
        request: &RequestVoteRequest,
    ) -> Result<RequestVoteResponse, NetError> {
        let frame = request.encode().map_err(|err| {
            NetError::from(ProtocolError::FrameEncode {
                context: "request_vote",
                details: err.to_string(),
            })
        })?;
        let payload = self
            .send_routed(OP_REQUEST_VOTE, &frame, &request.routing, || false)
            .await?;
        RequestVoteResponse::decode(&payload).map_err(|err| {
            NetError::from(ProtocolError::FrameDecode {
                context: "request_vote",
                details: err.to_string(),
            })
        })
    }

    pub async fn append_entries(
        &self,
        request: &AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, NetError> {
        self.append_entries_with_abort(request, || false).await
    }

    pub async fn append_entries_with_abort<F>(
        &self,
        request: &AppendEntriesRequest,
        should_abort: F,
    ) -> Result<AppendEntriesResponse, NetError>
    where
        F: Fn() -> bool + Send + 'static,
    {
        let frame = request.encode().map_err(|err| {
            NetError::from(ProtocolError::FrameEncode {
                context: "append_entries",
                details: err.to_string(),
            })
        })?;
        let payload = self
            .send_routed(OP_APPEND_ENTRIES, &frame, &request.routing, should_abort)
            .await?;
        AppendEntriesResponse::decode(&payload).map_err(|err| {
            NetError::from(ProtocolError::FrameDecode {
                context: "append_entries",
                details: err.to_string(),
            })
        })
    }

    async fn send_routed<F>(
        &self,
        opcode: u8,
        payload: &[u8],
        routing: &RaftRouting,
        should_abort: F,
    ) -> Result<Vec<u8>, NetError>
    where
        F: Fn() -> bool + Send + 'static,
    {
        let key = RpgKey::from_routing(routing);
        let permit = self.reserve_rpg(&key, routing.routing_epoch, payload.len())?;
        let result = self.send(opcode, payload, should_abort).await;
        let response_bytes = result.as_ref().map(|resp| resp.len()).unwrap_or(0);
        self.release_rpg(permit, response_bytes);
        result
    }

    async fn send<F>(
        &self,
        opcode: u8,
        payload: &[u8],
        should_abort: F,
    ) -> Result<Vec<u8>, NetError>
    where
        F: Fn() -> bool + Send + 'static,
    {
        let mut retry = self.retry_policy.handle();
        loop {
            if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                return Err(cancelled_error());
            }
            if self.draining.load(Ordering::SeqCst) {
                return Err(NetError::Io(io::Error::other("raft client draining")));
            }
            let backoff_until = { *self.backoff_until.lock() };
            if let Some(until) = backoff_until {
                let now = Instant::now();
                if now < until {
                    let sleep_for = until.saturating_duration_since(now);
                    tokio::time::sleep(sleep_for).await;
                    continue;
                }
            }

            let mut lease = match self.pool.checkout(Instant::now()).await {
                Ok(lease) => lease,
                Err(err) => {
                    if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                        return Err(cancelled_error());
                    }
                    if !self.should_retry(&err) {
                        return Err(err);
                    }
                    if let Some(delay) = retry.next_delay() {
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(err);
                }
            };

            let result = lease
                .session()
                .expect("lease should carry session")
                .send(opcode, payload, self.options.io_timeout)
                .await;
            match result {
                Ok(response) => {
                    lease.release(Instant::now()).await;
                    self.record_pool_gauges().await;
                    return Ok(response);
                }
                Err(err) => {
                    lease.discard().await;
                    *self.backoff_until.lock() = Some(Instant::now() + self.options.pool_backoff);
                    if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                        return Err(cancelled_error());
                    }
                    if !self.should_retry(&err) {
                        self.record_refresh("Error", 1);
                        self.record_pool_gauges().await;
                        return Err(err);
                    }
                    if let Some(delay) = retry.next_delay() {
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    self.record_refresh("Error", 1);
                    self.record_pool_gauges().await;
                    return Err(err);
                }
            }
        }
    }

    fn should_retry(&self, err: &NetError) -> bool {
        matches!(err, NetError::Io(_) | NetError::Tls(_))
    }

    fn reserve_rpg(
        &self,
        key: &RpgKey,
        routing_epoch: u64,
        bytes: usize,
    ) -> Result<RpgPermit, NetError> {
        let outcome = {
            let mut scheduler = self.rpg_scheduler.lock();
            scheduler.reserve(key, routing_epoch, bytes, Instant::now())
        };
        match outcome {
            ReserveResult::Granted => Ok(RpgPermit {
                key: key.clone(),
                bytes,
            }),
            ReserveResult::Throttled(throttle) => {
                Err(NetError::Io(io::Error::other(throttle.explain())))
            }
        }
    }

    fn release_rpg(&self, permit: RpgPermit, response_bytes: usize) {
        let _ = {
            let mut scheduler = self.rpg_scheduler.lock();
            scheduler.release(&permit.key, permit.bytes, response_bytes)
        };
    }

    async fn record_pool_gauges(&self) {
        if self.metrics.is_none() {
            return;
        }
        let snapshot = self.pool_snapshot().await;
        self.set_metric(
            self.metric_name("pool_active"),
            (snapshot.idle + snapshot.leased) as u64,
        );
        self.set_metric(self.metric_name("pool_warm"), snapshot.idle as u64);
    }

    fn record_refresh(&self, reason: &str, count: u64) {
        if count == 0 || self.metrics.is_none() {
            return;
        }
        self.inc_metric(
            self.metric_name_with_reason("pool_refresh_total", reason),
            count,
        );
    }

    #[allow(dead_code)]
    fn record_reuse(&self) {
        if self.metrics.is_none() {
            return;
        }
        self.inc_metric(self.metric_name("pool_reuse_total"), 1);
    }

    #[allow(dead_code)]
    fn record_connect(&self) {
        if self.metrics.is_none() {
            return;
        }
        self.inc_metric(self.metric_name("pool_connect_total"), 1);
    }

    fn inc_metric(&self, name: String, delta: u64) {
        if let Some(metrics) = &self.metrics {
            let _ = metrics.inc_counter(name, delta);
        }
    }

    fn set_metric(&self, name: String, value: u64) {
        if let Some(metrics) = &self.metrics {
            let _ = metrics.set_gauge(name, value);
        }
    }

    fn metric_name(&self, base: &str) -> String {
        format!(
            "transport.{base}.{}",
            self.options
                .peer_node_id
                .clone()
                .unwrap_or_else(|| "peer".to_string())
        )
    }

    fn metric_name_with_reason(&self, base: &str, reason: &str) -> String {
        format!(
            "transport.{base}.{reason}.{}",
            self.options
                .peer_node_id
                .clone()
                .unwrap_or_else(|| "peer".to_string())
        )
    }
}

fn cancelled_error() -> NetError {
    NetError::Io(io::Error::new(
        io::ErrorKind::Interrupted,
        "raft client cancelled",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RpgKey {
    partition_id: String,
    prg_id: String,
}

impl RpgKey {
    fn from_routing(routing: &RaftRouting) -> Self {
        Self {
            partition_id: routing.partition_id.clone(),
            prg_id: routing.prg_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct RpgPermit {
    key: RpgKey,
    bytes: usize,
}

#[derive(Debug, Clone)]
struct RpgQueueState {
    credits: RpgCreditBuckets,
    inflight: u64,
    queue_depth: u64,
    routing_epoch: u64,
    last_throttle: Option<FlowThrottleEnvelope>,
}

impl RpgQueueState {
    fn new(routing_epoch: u64) -> Self {
        Self {
            credits: RpgCreditBuckets::new(FlowProfile::Latency),
            inflight: 0,
            queue_depth: 0,
            routing_epoch,
            last_throttle: None,
        }
    }
}

#[derive(Debug)]
enum ReserveResult {
    Granted,
    Throttled(FlowThrottleEnvelope),
}

struct RpgScheduler {
    queues: HashMap<RpgKey, RpgQueueState>,
    burst_owner: Option<RpgKey>,
    burst_bytes: usize,
    burst_last_reset: Instant,
}

impl RpgScheduler {
    fn new() -> Self {
        Self {
            queues: HashMap::new(),
            burst_owner: None,
            burst_bytes: 0,
            burst_last_reset: Instant::now(),
        }
    }

    fn reserve(
        &mut self,
        key: &RpgKey,
        routing_epoch: u64,
        bytes: usize,
        now: Instant,
    ) -> ReserveResult {
        self.reset_burst(now);
        let burst_throttle = self.enforce_burst(key, bytes);
        let state = self
            .queues
            .entry(key.clone())
            .or_insert_with(|| RpgQueueState::new(routing_epoch));
        state.routing_epoch = routing_epoch;
        if let Some(throttle) = burst_throttle {
            state.queue_depth = state.queue_depth.max(1);
            state.last_throttle = Some(throttle.clone());
            return ReserveResult::Throttled(throttle);
        }
        match state.credits.reserve(bytes) {
            Ok(()) => {
                state.queue_depth = state.queue_depth.saturating_sub(1);
                state.inflight = state.inflight.saturating_add(1);
                self.burst_owner = Some(key.clone());
                self.burst_bytes = self.burst_bytes.saturating_add(bytes);
                ReserveResult::Granted
            }
            Err(throttle) => {
                state.queue_depth = state.queue_depth.max(1);
                state.last_throttle = Some(throttle.clone());
                ReserveResult::Throttled(throttle)
            }
        }
    }

    fn release(&mut self, key: &RpgKey, payload_bytes: usize, response_bytes: usize) -> Option<()> {
        if let Some(state) = self.queues.get_mut(key) {
            state.inflight = state.inflight.saturating_sub(1);
            state
                .credits
                .release(payload_bytes.saturating_add(response_bytes));
            return Some(());
        }
        None
    }

    fn reset_burst(&mut self, now: Instant) {
        if now.saturating_duration_since(self.burst_last_reset) >= NODE_SOCKET_BURST_WINDOW {
            self.burst_bytes = 0;
            self.burst_owner = None;
            self.burst_last_reset = now;
        }
    }

    fn enforce_burst(&mut self, key: &RpgKey, bytes: usize) -> Option<FlowThrottleEnvelope> {
        match &self.burst_owner {
            Some(owner) if owner == key => {
                if self.burst_bytes.saturating_add(bytes) > NODE_SOCKET_BURST_BYTES {
                    let debt = (self.burst_bytes + bytes).saturating_sub(NODE_SOCKET_BURST_BYTES);
                    return Some(FlowThrottleEnvelope::new(
                        FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt {
                            byte_credit: debt as i64,
                        }),
                        CreditHint::Shed,
                        IngestStatusCode::TransientBackpressure,
                    ));
                }
                self.burst_bytes = self.burst_bytes.saturating_add(bytes);
            }
            _ => {
                self.burst_owner = Some(key.clone());
                self.burst_bytes = bytes;
            }
        }
        None
    }
}

// Per-RPG credit buckets so one partition cannot consume another's PID tokens.
#[derive(Debug, Clone)]
struct RpgCreditBuckets {
    entry_credits: i64,
    entry_credit_max: i64,
    byte_credit: i64,
    byte_credit_max: i64,
}

impl RpgCreditBuckets {
    fn new(profile: FlowProfile) -> Self {
        let params = profile.params();
        Self {
            entry_credits: params.entry_credit_max,
            entry_credit_max: params.entry_credit_max,
            byte_credit: 0,
            byte_credit_max: params.byte_credit_max,
        }
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), FlowThrottleEnvelope> {
        if self.entry_credits <= 0 {
            return Err(FlowThrottleEnvelope::new(
                FlowThrottleState::Throttled(FlowThrottleReason::EntryCreditsDepleted),
                CreditHint::Shed,
                IngestStatusCode::TransientBackpressure,
            ));
        }
        let projected = self.byte_credit.saturating_add(bytes as i64);
        if projected > self.byte_credit_max {
            return Err(FlowThrottleEnvelope::new(
                FlowThrottleState::Throttled(FlowThrottleReason::ByteCreditDebt {
                    byte_credit: projected - self.byte_credit_max,
                }),
                CreditHint::Shed,
                IngestStatusCode::TransientBackpressure,
            ));
        }
        self.entry_credits -= 1;
        self.byte_credit = projected;
        Ok(())
    }

    fn release(&mut self, combined_bytes: usize) {
        self.entry_credits = (self.entry_credits + 1).min(self.entry_credit_max);
        let debt = self.byte_credit.saturating_sub(combined_bytes as i64);
        self.byte_credit = debt.max(0);
    }
}

/// Async placement-driven pool manager.
pub struct AsyncRaftTransportPoolManager {
    identity: TlsIdentity,
    trust_store: TlsTrustStore,
    mtls: Arc<ParkingMutex<MtlsIdentityManager>>,
    options: AsyncRaftTransportClientOptions,
    peers: std::collections::HashMap<String, Arc<AsyncRaftTransportClient>>,
    endpoints: std::collections::HashMap<String, super::PeerEndpoint>,
    active_peers: std::collections::HashSet<String>,
    partition_epochs: std::collections::HashMap<String, u64>,
    draining: std::collections::HashMap<String, DrainState>,
}

struct DrainState {
    deadline: Instant,
}

impl DrainState {
    fn new(now: Instant, idle_timeout: Duration) -> Self {
        Self {
            deadline: now + idle_timeout,
        }
    }
}

impl AsyncRaftTransportPoolManager {
    pub fn new(
        identity: TlsIdentity,
        trust_store: TlsTrustStore,
        mtls: Arc<ParkingMutex<MtlsIdentityManager>>,
        options: AsyncRaftTransportClientOptions,
    ) -> Self {
        Self {
            identity,
            trust_store,
            mtls,
            options,
            peers: std::collections::HashMap::new(),
            endpoints: std::collections::HashMap::new(),
            active_peers: std::collections::HashSet::new(),
            partition_epochs: std::collections::HashMap::new(),
            draining: std::collections::HashMap::new(),
        }
    }

    pub fn register_endpoint(&mut self, peer_id: impl Into<String>, endpoint: super::PeerEndpoint) {
        self.endpoints.insert(peer_id.into(), endpoint);
    }

    pub async fn reconcile_placements(
        &mut self,
        placements: &[PlacementRecord],
        now: Instant,
    ) -> Result<(), NetError> {
        self.reap_draining(now).await;
        let mut seen_partitions = std::collections::HashSet::new();
        let mut required_peers = std::collections::HashSet::new();
        let previous_active = self.active_peers.clone();
        for record in placements {
            seen_partitions.insert(record.partition_id.clone());
            let previous_epoch = self
                .partition_epochs
                .insert(record.partition_id.clone(), record.routing_epoch);
            let placement_updated = previous_epoch != Some(record.routing_epoch);
            if placement_updated {
                info!(
                    "event=raft_async_pool_routing_update partition_id={} previous_routing_epoch={:?} routing_epoch={} peers={:?}",
                    record.partition_id,
                    previous_epoch,
                    record.routing_epoch,
                    record.members
                );
            }
            for member in &record.members {
                required_peers.insert(member.clone());
                if self.draining.remove(member).is_some() {
                    if let Some(client) = self.peers.get(member) {
                        client.clear_drain();
                    }
                }
                let needs_warmup = placement_updated || !self.peers.contains_key(member);
                if needs_warmup {
                    let client = self.ensure_client(member)?;
                    let _ = client.warmup(now).await;
                }
            }
        }
        self.partition_epochs
            .retain(|partition, _| seen_partitions.contains(partition));
        let removed: Vec<String> = previous_active
            .difference(&required_peers)
            .cloned()
            .collect();
        for peer in removed {
            if let Some(client) = self.peers.get(&peer) {
                client.begin_drain(now);
            }
            self.draining.insert(
                peer.clone(),
                DrainState::new(now, self.options.pool_idle_timeout),
            );
            info!(
                "event=raft_async_pool_drain peer={} reason=placement_removed deadline_ms={}",
                peer,
                self.options.pool_idle_timeout.as_millis().max(1) as u64
            );
        }
        self.active_peers = required_peers;
        self.reap_draining(now).await;
        Ok(())
    }

    pub fn client_for(
        &mut self,
        peer_id: &str,
    ) -> Result<Option<Arc<AsyncRaftTransportClient>>, NetError> {
        if !self.active_peers.contains(peer_id) {
            return Ok(None);
        }
        self.ensure_client(peer_id).map(Some)
    }

    pub fn active_peers(&self) -> std::collections::HashSet<String> {
        self.active_peers.clone()
    }

    fn ensure_client(&mut self, peer_id: &str) -> Result<Arc<AsyncRaftTransportClient>, NetError> {
        if let Some(client) = self.peers.get(peer_id) {
            return Ok(client.clone());
        }
        let endpoint = self
            .endpoints
            .get(peer_id)
            .ok_or_else(|| NetError::Io(io::Error::other("peer endpoint unknown")))?;
        let config = AsyncRaftTransportClientConfig {
            host: endpoint.host.clone(),
            port: endpoint.port,
            identity: self.identity.clone(),
            trust_store: self.trust_store.clone(),
            mtls: self.mtls.clone(),
        };
        let client = Arc::new(AsyncRaftTransportClient::new(
            config,
            self.options.clone().peer_node_id(peer_id.to_string()),
        )?);
        self.peers.insert(peer_id.to_string(), client.clone());
        Ok(client)
    }

    async fn reap_draining(&mut self, now: Instant) {
        let peers: Vec<String> = self.draining.keys().cloned().collect();
        for peer in peers {
            let deadline = self.draining.get(&peer).map(|state| state.deadline);
            let expired = deadline.map(|d| now >= d).unwrap_or(false);
            let should_remove = match self.peers.get(&peer) {
                Some(client) => {
                    let snapshot = client.pool_snapshot().await;
                    if snapshot.leased == 0 || expired {
                        if expired && snapshot.leased > 0 {
                            warn!(
                                "event=raft_async_pool_drain_timeout peer={} inflight={} deadline_ms={}",
                                peer,
                                snapshot.leased,
                                deadline
                                    .map(|d| d.saturating_duration_since(now).as_millis())
                                    .unwrap_or(0)
                            );
                        }
                        client.cancel();
                        true
                    } else {
                        false
                    }
                }
                None => true,
            };
            if should_remove {
                self.peers.remove(&peer);
                self.draining.remove(&peer);
                info!("event=raft_async_pool_drained peer={peer}");
            }
        }
    }
}

pub struct AsyncRaftTransportServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct AsyncRaftTransportServerHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
    pub bind: SocketAddr,
}

impl AsyncRaftTransportServerHandle {
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for AsyncRaftTransportServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

pub struct AsyncRaftTransportServer;

impl AsyncRaftTransportServer {
    pub async fn spawn<H>(
        config: AsyncRaftTransportServerConfig,
        server: RaftRpcServer<H>,
    ) -> Result<AsyncRaftTransportServerHandle, NetError>
    where
        H: RaftRpcHandler + Send + 'static,
    {
        let listener = TcpListener::bind(config.bind).await?;
        info!("event=raft_async_server_listen addr={}", config.bind);
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let acceptor = TlsAcceptor::from(tls_config);
        let server = Arc::new(server);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let (stop_notify, stop_recv) = watch::channel(false);

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        let _ = stop_notify.send(true);
                        break;
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                let acceptor = acceptor.clone();
                                let server = server.clone();
                                let mut stop_recv = stop_recv.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = handle_connection(stream, addr, acceptor, server, &mut stop_recv).await {
                                        warn!("raft async connection error from {}: {}", addr, err);
                                    }
                                });
                            }
                            Err(err) => {
                                warn!("event=raft_async_accept_error error={}", err);
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(AsyncRaftTransportServerHandle {
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
            bind: config.bind,
        })
    }
}

async fn handle_connection<H: RaftRpcHandler>(
    stream: TcpStream,
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    server: Arc<RaftRpcServer<H>>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), NetError> {
    let mut tls_stream = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream))
        .await
        .map_err(|_| timeout_error("raft_async_accept", Duration::from_secs(5)))?
        .map_err(NetError::from)?;

    let (_io, conn) = tls_stream.get_ref();
    let peer_chain = conn.peer_certificates().ok_or_else(|| {
        NetError::from(CertificateError::MissingClientCertificate {
            context: "raft_async_server",
        })
    })?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
    info!("event=raft_async_tls_session peer={addr}");

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let mut header = [0u8; 5];
        match tokio::time::timeout(
            super::RAFT_SERVER_STREAM_TIMEOUT,
            tls_stream.read_exact(&mut header),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
                info!("event=raft_async_connection_close peer={addr}");
                return Ok(());
            }
            Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => {
                info!("event=raft_async_connection_shutdown peer={addr}");
                return Ok(());
            }
            Ok(Err(err)) => return Err(NetError::Io(err)),
            Err(_) => {
                return Err(timeout_error(
                    "raft_async_read_header",
                    super::RAFT_SERVER_STREAM_TIMEOUT,
                ))
            }
        }
        let opcode = header[0];
        let len = u32::from_le_bytes(
            header[1..5]
                .try_into()
                .map_err(|_| NetError::from(ProtocolError::FrameLength))?,
        ) as usize;
        let mut payload = vec![0u8; len];
        match tokio::time::timeout(
            super::RAFT_SERVER_STREAM_TIMEOUT,
            tls_stream.read_exact(&mut payload),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
                info!("event=raft_async_connection_close peer={addr}");
                return Ok(());
            }
            Ok(Err(err)) if err.kind() == io::ErrorKind::Interrupted => {
                info!("event=raft_async_connection_shutdown peer={addr}");
                return Ok(());
            }
            Ok(Err(err)) => return Err(NetError::Io(err)),
            Err(_) => {
                return Err(timeout_error(
                    "raft_async_read_payload",
                    super::RAFT_SERVER_STREAM_TIMEOUT,
                ))
            }
        }

        let now = Instant::now();
        let outcome = match opcode {
            OP_REQUEST_VOTE => server
                .handle_request_vote(&peer_certificate, &payload, now)
                .map_err(|err| err.to_string()),
            OP_APPEND_ENTRIES => server
                .handle_append_entries(&peer_certificate, &payload, now)
                .map_err(|err| err.to_string()),
            _ => Err(format!("unknown opcode {opcode}")),
        };
        match outcome {
            Ok(response) => {
                write_response(&mut tls_stream, STATUS_OK, &response).await?;
            }
            Err(err) => {
                warn!("event=raft_async_handler_error peer={} error={}", addr, err);
                write_response(&mut tls_stream, STATUS_ERR, err.as_bytes()).await?;
            }
        }
    }
}

async fn write_response<S>(stream: &mut S, status: u8, payload: &[u8]) -> Result<(), NetError>
where
    S: AsyncWrite + Unpin + Send,
{
    let mut header = [0u8; 5];
    header[0] = status;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    Ok(())
}

#[cfg(all(test, feature = "async-net"))]
mod tests {
    use super::*;
    use crate::net::PeerEndpoint;
    use crate::net::{load_identity_from_pem, load_trust_store_from_pem};
    use crate::replication::raft::RaftRouting;
    use crate::replication::transport::raft::{RaftRpcHandler, RaftRpcServer};
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use std::convert::TryInto;
    use std::net::TcpListener;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::task::JoinHandle;

    fn tls_materials(
        now: Instant,
    ) -> (
        TlsIdentity,
        TlsTrustStore,
        Arc<ParkingMutex<MtlsIdentityManager>>,
    ) {
        let dir = TempDir::new().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.subject_alt_names.push(SanType::URI(
            "spiffe://localhost/nodes/1".try_into().unwrap(),
        ));
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let chain_path = dir.path().join("tls-chain.pem");
        let key_path = dir.path().join("tls-key.pem");
        std::fs::write(&chain_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        let identity = load_identity_from_pem(&chain_path, &key_path, now).unwrap();
        let trust = load_trust_store_from_pem(&chain_path).unwrap();
        let mtls = Arc::new(ParkingMutex::new(MtlsIdentityManager::new(
            identity.certificate.clone(),
            "localhost",
            Duration::from_secs(60),
            now,
        )));
        (identity, trust, mtls)
    }

    fn next_loopback() -> std::net::SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral socket")
            .local_addr()
            .expect("ephemeral addr")
    }

    #[derive(Clone)]
    struct FixedHandler {
        term: u64,
        delay: Option<Duration>,
    }

    impl RaftRpcHandler for FixedHandler {
        fn on_request_vote(&mut self, _request: RequestVoteRequest) -> RequestVoteResponse {
            if let Some(delay) = self.delay {
                std::thread::sleep(delay);
            }
            RequestVoteResponse {
                term: self.term,
                granted: true,
                reject_reason: None,
            }
        }

        fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
            if let Some(delay) = self.delay {
                std::thread::sleep(delay);
            }
            AppendEntriesResponse {
                term: self.term,
                success: true,
                match_index: request.prev_log_index,
                conflict_index: None,
                conflict_term: None,
            }
        }
    }

    async fn spawn_server(
        identity: TlsIdentity,
        trust: TlsTrustStore,
        handler: FixedHandler,
        routing: RaftRouting,
    ) -> AsyncRaftTransportServerHandle {
        let bind = next_loopback();
        let server_mtls = MtlsIdentityManager::new(
            identity.certificate.clone(),
            "localhost",
            Duration::from_secs(60),
            Instant::now(),
        );
        let server = RaftRpcServer::new(server_mtls, handler, routing);
        AsyncRaftTransportServer::spawn(
            AsyncRaftTransportServerConfig {
                bind,
                identity,
                trust_store: trust,
            },
            server,
        )
        .await
        .expect("async raft server spawn")
    }

    #[tokio::test]
    async fn async_client_server_roundtrip_and_reuse() {
        let now = Instant::now();
        let (identity, trust, mtls) = tls_materials(now);
        let routing = RaftRouting::alias("partition-async", 1);
        let mut server_handle = spawn_server(
            identity.clone(),
            trust.clone(),
            FixedHandler {
                term: 9,
                delay: None,
            },
            routing.clone(),
        )
        .await;

        let client = AsyncRaftTransportClient::new(
            AsyncRaftTransportClientConfig {
                host: server_handle.bind.ip().to_string(),
                port: server_handle.bind.port(),
                identity: identity.clone(),
                trust_store: trust.clone(),
                mtls: mtls.clone(),
            },
            AsyncRaftTransportClientOptions::default()
                .pool_size_per_peer_max(2)
                .pool_warmup(true),
        )
        .expect("client build");

        client.warmup(Instant::now()).await.expect("warmup");

        let vote = RequestVoteRequest {
            term: 1,
            candidate_id: "node-a".into(),
            last_log_index: 0,
            last_log_term: 0,
            pre_vote: false,
            routing: routing.clone(),
        };
        let resp1 = client.request_vote(&vote).await.expect("vote");
        assert!(resp1.granted);
        let resp2 = client.request_vote(&vote).await.expect("vote again");
        assert!(resp2.granted);

        let snapshot = client.pool_snapshot().await;
        assert!(
            snapshot.idle >= 1,
            "expected idle session after reuse, got {:?}",
            snapshot
        );

        server_handle.shutdown().await;
    }

    #[tokio::test]
    async fn async_pool_waits_not_exhausts() {
        let now = Instant::now();
        let (identity, trust, mtls) = tls_materials(now);
        let routing = RaftRouting::alias("partition-async", 1);
        let mut server_handle = spawn_server(
            identity.clone(),
            trust.clone(),
            FixedHandler {
                term: 9,
                delay: Some(Duration::from_millis(50)),
            },
            routing.clone(),
        )
        .await;

        let client = Arc::new(
            AsyncRaftTransportClient::new(
                AsyncRaftTransportClientConfig {
                    host: server_handle.bind.ip().to_string(),
                    port: server_handle.bind.port(),
                    identity: identity.clone(),
                    trust_store: trust.clone(),
                    mtls: mtls.clone(),
                },
                AsyncRaftTransportClientOptions {
                    connect_timeout: Duration::from_secs(5),
                    io_timeout: Duration::from_secs(5),
                    pool_size_per_peer_max: 1,
                    pool_idle_timeout: TRANSPORT_POOL_IDLE_TIMEOUT,
                    pool_warmup: true,
                    pool_backoff: Duration::from_millis(50),
                    retry_policy: RetryPolicy::linear(3, Duration::from_millis(50))
                        .with_skip_first_delay(true),
                    peer_node_id: None,
                    metrics: None,
                },
            )
            .expect("client build"),
        );

        let request = AppendEntriesRequest {
            term: 1,
            leader_id: "leader".into(),
            prev_log_index: 1,
            prev_log_term: 1,
            leader_commit: 1,
            entries: Vec::new(),
            routing: routing.clone(),
        };

        let c1 = client.clone();
        let r1 = request.clone();
        let c2 = client.clone();
        let r2 = request.clone();

        let h1: JoinHandle<Result<AppendEntriesResponse, NetError>> =
            tokio::spawn(async move { c1.append_entries(&r1).await });
        let h2: JoinHandle<Result<AppendEntriesResponse, NetError>> =
            tokio::spawn(async move { c2.append_entries(&r2).await });

        let (res1, res2) = tokio::join!(h1, h2);
        assert!(res1.unwrap().is_ok());
        assert!(res2.unwrap().is_ok());

        server_handle.shutdown().await;
    }

    #[tokio::test]
    async fn async_pool_manager_reconciles_and_drains() {
        let now = Instant::now();
        let (identity, trust, mtls) = tls_materials(now);

        // Spawn two peers.
        let routing = RaftRouting::alias("partition-async", 1);
        let mut server_a = spawn_server(
            identity.clone(),
            trust.clone(),
            FixedHandler {
                term: 1,
                delay: None,
            },
            routing.clone(),
        )
        .await;
        let mut server_b = spawn_server(
            identity.clone(),
            trust.clone(),
            FixedHandler {
                term: 1,
                delay: None,
            },
            routing.clone(),
        )
        .await;

        let mut manager = AsyncRaftTransportPoolManager::new(
            identity.clone(),
            trust.clone(),
            mtls.clone(),
            AsyncRaftTransportClientOptions::default().pool_idle_timeout(Duration::from_millis(20)),
        );
        manager.register_endpoint(
            "node-a",
            PeerEndpoint {
                host: server_a.bind.ip().to_string(),
                port: server_a.bind.port(),
            },
        );
        manager.register_endpoint(
            "node-b",
            PeerEndpoint {
                host: server_b.bind.ip().to_string(),
                port: server_b.bind.port(),
            },
        );

        manager
            .reconcile_placements(
                &[PlacementRecord {
                    partition_id: "partition-async".into(),
                    routing_epoch: 1,
                    lease_epoch: 1,
                    members: vec!["node-a".into(), "node-b".into()],
                }],
                now,
            )
            .await
            .expect("reconcile placements");

        assert!(manager.client_for("node-a").unwrap().is_some());
        assert!(manager.client_for("node-b").unwrap().is_some());

        // Remove placements and force drain.
        manager
            .reconcile_placements(&[], Instant::now())
            .await
            .expect("reconcile remove");
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager
            .reconcile_placements(&[], Instant::now())
            .await
            .expect("reconcile reap");
        assert!(manager.client_for("node-a").unwrap().is_none());
        assert!(manager.client_for("node-b").unwrap().is_none());

        server_a.shutdown().await;
        server_b.shutdown().await;
    }
}
