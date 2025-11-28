#![cfg(feature = "net")]

mod schema;

use crate::net::http::{
    read_request, write_json_response, HttpHandlerError, HttpRequestContext, RequestDeadline,
    SimpleHttpRequest,
};
use crate::net::server;
use crate::net::tls::{
    complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore,
};
use crate::net::{CertificateError, NetError};
use log::{error, warn};
use rustls::{ServerConfig, ServerConnection, Stream};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{atomic::AtomicBool, Arc, RwLock};
use std::time::{Duration, Instant};
#[cfg(feature = "async-net")]
use tokio::task;

#[cfg(feature = "snapshot-crypto")]
pub use schema::WhySnapshotBlocked;
pub use schema::{LocalRole, WhyNotLeader, WhySchemaHeader};

#[derive(Clone, Default)]
pub struct WhyPublisher {
    not_leader: Arc<RwLock<HashMap<String, WhyNotLeader>>>,
    #[cfg(feature = "snapshot-crypto")]
    snapshot_blocked: Arc<RwLock<HashMap<String, WhySnapshotBlocked>>>,
}

impl WhyPublisher {
    pub fn update_not_leader(&self, partition: impl Into<String>, report: WhyNotLeader) {
        match self.not_leader.write() {
            Ok(mut guard) => {
                guard.insert(partition.into(), report);
            }
            Err(poisoned) => {
                error!("why_not_leader cache poisoned; updating with recovered state");
                let mut guard = poisoned.into_inner();
                guard.insert(partition.into(), report);
            }
        }
    }

    #[cfg(feature = "snapshot-crypto")]
    pub fn update_snapshot_blocked(
        &self,
        partition: impl Into<String>,
        report: WhySnapshotBlocked,
    ) {
        match self.snapshot_blocked.write() {
            Ok(mut guard) => {
                guard.insert(partition.into(), report);
            }
            Err(poisoned) => {
                error!("why_snapshot_blocked cache poisoned; updating with recovered state");
                let mut guard = poisoned.into_inner();
                guard.insert(partition.into(), report);
            }
        }
    }

    pub fn remove_partition(&self, partition: &str) {
        match self.not_leader.write() {
            Ok(mut guard) => {
                guard.remove(partition);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.remove(partition);
            }
        }
        #[cfg(feature = "snapshot-crypto")]
        match self.snapshot_blocked.write() {
            Ok(mut guard) => {
                guard.remove(partition);
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.remove(partition);
            }
        }
    }

    fn not_leader(&self, partition: &str) -> Option<WhyNotLeader> {
        match self.not_leader.read() {
            Ok(map) => map.get(partition).cloned(),
            Err(poisoned) => poisoned.into_inner().get(partition).cloned(),
        }
    }

    #[cfg(feature = "snapshot-crypto")]
    fn snapshot_blocked(&self, partition: &str) -> Option<WhySnapshotBlocked> {
        match self.snapshot_blocked.read() {
            Ok(map) => map.get(partition).cloned(),
            Err(poisoned) => poisoned.into_inner().get(partition).cloned(),
        }
    }
}

pub struct WhyHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct WhyHttpServerHandle {
    inner: server::ServerHandle,
}

impl WhyHttpServerHandle {
    pub fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)) {
            warn!("event=why_shutdown_error error={err}");
        }
    }

    pub fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        self.inner.try_shutdown(timeout)
    }
}

impl Drop for WhyHttpServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(Duration::from_secs(5));
    }
}

pub struct WhyHttpServer;

pub(crate) const WHY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl WhyHttpServer {
    pub fn spawn(
        config: WhyHttpServerConfig,
        publisher: WhyPublisher,
    ) -> Result<WhyHttpServerHandle, NetError> {
        let listener = TcpListener::bind(config.bind)?;
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let publisher = Arc::new(publisher);
        let handler = move |stream: TcpStream,
                            addr: SocketAddr,
                            _shutdown: Arc<AtomicBool>|
              -> Result<(), NetError> {
            let tls = tls_config.clone();
            let publisher = publisher.clone();
            if let Err(err) = handle_connection(stream, tls, publisher) {
                warn!("why connection {addr} error: {err}");
            }
            Ok(())
        };
        let inner =
            server::spawn_listener("why_http", listener, None, handler).map_err(NetError::from)?;
        Ok(WhyHttpServerHandle { inner })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    publisher: Arc<WhyPublisher>,
) -> Result<(), NetError> {
    configure_why_stream(&stream)?;
    let deadline = RequestDeadline::from_timeout(WHY_REQUEST_TIMEOUT);
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    let peer_chain = conn.peer_certificates().ok_or_else(|| {
        NetError::from(CertificateError::MissingClientCertificate { context: "why" })
    })?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
    let ctx = HttpRequestContext::new(peer_certificate, deadline);
    let mut tls = Stream::new(&mut conn, &mut stream);
    let result = read_request(&mut tls)
        .map_err(|err| HttpHandlerError::request("request_read", err))
        .and_then(|request| handle_why_request(&ctx, request, publisher.as_ref(), &mut tls));
    match result {
        Ok(()) => Ok(()),
        Err(err) => map_why_handler_error(err),
    }
}

pub(crate) fn handle_why_request(
    ctx: &HttpRequestContext,
    request: SimpleHttpRequest,
    publisher: &WhyPublisher,
    stream: &mut (impl std::io::Write + ?Sized),
) -> Result<(), HttpHandlerError> {
    ctx.check_deadline(stream, "request_read")?;
    let segments = request.path_segments();
    if segments.len() == 3 && segments[0] == "why" && segments[1] == "not-leader" {
        let partition = segments[2];
        if let Some(report) = publisher.not_leader(partition) {
            ctx.check_deadline(stream, "not_leader_write")?;
            write_json_response(stream, 200, &report)
                .map_err(|err| HttpHandlerError::response("not_leader_write", err))?;
        } else {
            warn!(
                "event=why_http_bad_path path={} method={} reason=partition_missing namespace=not_leader id={}",
                request.path, request.method, partition
            );
            ctx.check_deadline(stream, "not_leader_missing")?;
            write_json_response(
                stream,
                404,
                &serde_json::json!({"error": "partition not found", "status": 404}),
            )
            .map_err(|err| HttpHandlerError::response("not_leader_missing", err))?;
        }
        return Ok(());
    }
    #[cfg(feature = "snapshot-crypto")]
    {
        if segments.len() == 3 && segments[0] == "why" && segments[1] == "snapshot-blocked" {
            let partition = segments[2];
            if let Some(report) = publisher.snapshot_blocked(partition) {
                ctx.check_deadline(stream, "snapshot_blocked_write")?;
                write_json_response(stream, 200, &report)
                    .map_err(|err| HttpHandlerError::response("snapshot_blocked_write", err))?;
            } else {
                warn!(
                    "event=why_http_bad_path path={} method={} reason=partition_missing namespace=snapshot_blocked id={}",
                    request.path, request.method, partition
                );
                ctx.check_deadline(stream, "snapshot_blocked_missing")?;
                write_json_response(
                    stream,
                    404,
                    &serde_json::json!({"error": "partition not found", "status": 404}),
                )
                .map_err(|err| HttpHandlerError::response("snapshot_blocked_missing", err))?;
            }
            return Ok(());
        }
    }
    warn!(
        "event=why_http_bad_path path={} method={} reason=unknown_route",
        request.path, request.method
    );
    ctx.check_deadline(stream, "why_unknown_route")?;
    write_json_response(
        stream,
        404,
        &serde_json::json!({"error": "not found", "status": 404}),
    )
    .map_err(|err| HttpHandlerError::response("why_unknown_route", err))
}

#[cfg(feature = "async-net")]
pub struct AsyncWhyHttpServerHandle {
    inner: Option<WhyHttpServerHandle>,
}

#[cfg(feature = "async-net")]
impl AsyncWhyHttpServerHandle {
    pub async fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)).await {
            warn!("event=why_async_shutdown_error error={err}");
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

#[cfg(feature = "async-net")]
impl Drop for AsyncWhyHttpServerHandle {
    fn drop(&mut self) {
        if let Some(mut handle) = self.inner.take() {
            let _ = handle.try_shutdown(Duration::from_secs(5));
        }
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncWhyHttpServer;

#[cfg(feature = "async-net")]
impl AsyncWhyHttpServer {
    pub async fn spawn(
        config: WhyHttpServerConfig,
        publisher: WhyPublisher,
    ) -> Result<AsyncWhyHttpServerHandle, NetError> {
        let handle = task::spawn_blocking(move || WhyHttpServer::spawn(config, publisher))
            .await
            .map_err(map_join_error)??;
        Ok(AsyncWhyHttpServerHandle {
            inner: Some(handle),
        })
    }
}

#[cfg(feature = "async-net")]
fn map_join_error(err: task::JoinError) -> NetError {
    NetError::Io(std::io::Error::other(format!(
        "why async task cancelled: {err}"
    )))
}

fn configure_why_stream(stream: &TcpStream) -> Result<(), NetError> {
    stream
        .set_read_timeout(Some(WHY_REQUEST_TIMEOUT))
        .map_err(NetError::from)?;
    stream
        .set_write_timeout(Some(WHY_REQUEST_TIMEOUT))
        .map_err(NetError::from)?;
    Ok(())
}

pub(crate) fn map_why_handler_error(err: HttpHandlerError) -> Result<(), NetError> {
    match err {
        HttpHandlerError::DeadlineExpired { stage } => {
            warn!("event=why_http_deadline_expired stage={stage}");
            Ok(())
        }
        HttpHandlerError::Request { stage, error }
        | HttpHandlerError::Response { stage, error } => {
            warn!("event=why_http_handler_error stage={stage} error={error}");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_why_request, WhyPublisher};
    use crate::control_plane::core::CpCacheState;
    use crate::net::control_plane::why::{LocalRole, WhyNotLeader, WhySchemaHeader};
    use crate::net::http::{HttpRequestContext, RequestDeadline, SimpleHttpRequest};
    use crate::replication::consensus::StrictFallbackState;
    use crate::replication::raft::PartitionQuorumStatus;
    use crate::security::{Certificate, SerialNumber, SpiffeId};
    use crate::terminology::TERM_STRICT;
    use std::time::{Duration, Instant};

    fn request_context() -> HttpRequestContext {
        let spiffe =
            SpiffeId::parse("spiffe://test.example/ns/default/sa/why").expect("spiffe parses");
        let cert = Certificate {
            spiffe_id: spiffe,
            serial: SerialNumber::from_u64(1),
            valid_from: Instant::now(),
            valid_until: Instant::now() + Duration::from_secs(60),
        };
        HttpRequestContext::new(cert, RequestDeadline::from_timeout(Duration::from_secs(5)))
    }

    fn request_for(path: &str) -> SimpleHttpRequest {
        SimpleHttpRequest {
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn publisher_with_partition() -> WhyPublisher {
        let publisher = WhyPublisher::default();
        let report = WhyNotLeader {
            header: WhySchemaHeader::new("partition-a", 1, 1, 0),
            leader_id: Some("leader-a".into()),
            local_role: LocalRole::Follower,
            strict_state: StrictFallbackState::LocalOnly,
            cp_cache_state: CpCacheState::Fresh,
            quorum_status: PartitionQuorumStatus {
                committed_index: 1,
                committed_term: 1,
                quorum_size: 1,
            },
            pending_entries: 0,
            runtime_terms: vec![TERM_STRICT],
            strict_fallback_why: None,
            truncated_ids_count: None,
            continuation_token: None,
        };
        publisher.update_not_leader("partition-a", report);
        publisher
    }

    #[test]
    fn returns_not_leader_report() {
        let ctx = request_context();
        let publisher = publisher_with_partition();
        let mut buffer = Vec::new();
        handle_why_request(
            &ctx,
            request_for("/why/not-leader/partition-a"),
            &publisher,
            &mut buffer,
        )
        .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response.contains("\"partition_id\":\"partition-a\""),
            "expected partition data in response"
        );
    }

    #[test]
    fn returns_not_found_for_missing_partition() {
        let ctx = request_context();
        let publisher = publisher_with_partition();
        let mut buffer = Vec::new();
        handle_why_request(
            &ctx,
            request_for("/why/not-leader/missing"),
            &publisher,
            &mut buffer,
        )
        .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response.contains("partition not found"));
    }

    #[cfg(feature = "snapshot-crypto")]
    #[test]
    fn returns_snapshot_blocked_report() {
        use crate::net::control_plane::why::WhySnapshotBlocked;
        use crate::snapshot::SnapshotFallbackTelemetry;
        use crate::snapshot::SnapshotOnlyReadyState;

        let ctx = request_context();
        let publisher = {
            let publisher = WhyPublisher::default();
            let report = WhySnapshotBlocked::new(
                WhySchemaHeader::new("partition-b", 1, 1, 0),
                "manifest-1",
                SnapshotFallbackTelemetry {
                    partition_ready_ratio_snapshot: 0.5,
                    snapshot_manifest_age_ms: 10,
                    snapshot_only_ready_state: SnapshotOnlyReadyState::Degraded,
                    snapshot_only_min_ready_ratio: 0.8,
                    snapshot_only_slo_breach_total: 1,
                },
                None,
                crate::snapshot::SnapshotReadError::SnapshotOnlyUnavailable,
            );
            publisher.update_snapshot_blocked("partition-b", report);
            publisher
        };
        let mut buffer = Vec::new();
        handle_why_request(
            &ctx,
            request_for("/why/snapshot-blocked/partition-b"),
            &publisher,
            &mut buffer,
        )
        .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response.contains("\"manifest_id\":\"manifest-1\""),
            "expected snapshot-blocked payload"
        );
    }
}
