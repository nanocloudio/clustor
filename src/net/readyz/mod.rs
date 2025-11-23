#![cfg(feature = "net")]

use super::http::{
    read_request, write_json_response, HttpHandlerError, HttpRequestContext, RequestDeadline,
    SimpleHttpRequest,
};
use super::server;
use super::tls::{complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore};
use super::{CertificateError, NetError};
use crate::readyz::{ReadyExplain, ReadyzSnapshot};
use log::warn;
use rustls::{ServerConfig, ServerConnection, Stream};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{atomic::AtomicBool, Arc, RwLock};
use std::time::{Duration, Instant};
#[cfg(feature = "async-net")]
use tokio::task;

pub struct ReadyzPublisher {
    snapshot: Arc<RwLock<ReadyzSnapshot>>,
}

impl ReadyzPublisher {
    pub fn new(initial: ReadyzSnapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(initial)),
        }
    }

    pub fn update(&self, snapshot: ReadyzSnapshot) {
        match self.snapshot.write() {
            Ok(mut guard) => *guard = snapshot,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                *guard = snapshot;
            }
        }
    }

    pub fn snapshot(&self) -> ReadyzSnapshot {
        match self.snapshot.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn explain(&self, partition_id: &str) -> Option<ReadyExplain> {
        match self.snapshot.read() {
            Ok(snapshot) => snapshot.why_not_ready(partition_id),
            Err(poisoned) => poisoned.into_inner().why_not_ready(partition_id),
        }
    }
}

pub struct ReadyzHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct ReadyzHttpServerHandle {
    inner: server::ServerHandle,
}

impl ReadyzHttpServerHandle {
    pub fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)) {
            warn!("event=readyz_shutdown_error error={err}");
        }
    }

    pub fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        self.inner.try_shutdown(timeout)
    }
}

impl Drop for ReadyzHttpServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(Duration::from_secs(5));
    }
}

pub struct ReadyzHttpServer;

pub(crate) const READYZ_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl ReadyzHttpServer {
    pub fn spawn(
        config: ReadyzHttpServerConfig,
        publisher: ReadyzPublisher,
    ) -> Result<ReadyzHttpServerHandle, NetError> {
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
                warn!("readyz connection {addr} error: {err}");
            }
            Ok(())
        };
        let inner = server::spawn_listener("readyz_http", listener, None, handler)
            .map_err(NetError::from)?;
        Ok(ReadyzHttpServerHandle { inner })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    publisher: Arc<ReadyzPublisher>,
) -> Result<(), NetError> {
    configure_readyz_stream(&stream)?;
    let deadline = RequestDeadline::from_timeout(READYZ_REQUEST_TIMEOUT);
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    let peer_chain = conn.peer_certificates().ok_or_else(|| {
        NetError::from(CertificateError::MissingClientCertificate { context: "readyz" })
    })?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
    let ctx = HttpRequestContext::new(peer_certificate, deadline);
    let mut tls = Stream::new(&mut conn, &mut stream);
    let result = read_request(&mut tls)
        .map_err(|err| HttpHandlerError::request("request_read", err))
        .and_then(|request| handle_readyz_request(&ctx, request, publisher.as_ref(), &mut tls));
    match result {
        Ok(()) => Ok(()),
        Err(err) => map_readyz_handler_error(err),
    }
}

pub(crate) fn handle_readyz_request(
    ctx: &HttpRequestContext,
    request: SimpleHttpRequest,
    publisher: &ReadyzPublisher,
    stream: &mut (impl std::io::Write + ?Sized),
) -> Result<(), HttpHandlerError> {
    ctx.check_deadline(stream, "request_read")?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/readyz") => {
            ctx.check_deadline(stream, "snapshot_begin")?;
            let snapshot = publisher.snapshot();
            ctx.check_deadline(stream, "snapshot_write")?;
            write_json_response(stream, 200, &snapshot)
                .map_err(|err| HttpHandlerError::response("snapshot_write", err))
        }
        ("GET", _) => {
            let segments = request.path_segments();
            if segments.len() == 2 && segments[0] == "readyz" && segments[1] == "why" {
                warn!(
                    "event=readyz_http_bad_path path={} method={} reason=missing_partition",
                    request.path, request.method
                );
                ctx.check_deadline(stream, "why_missing_partition")?;
                write_json_response(
                    stream,
                    400,
                    &serde_json::json!({"error": "partition id missing", "status": 400}),
                )
                .map_err(|err| HttpHandlerError::response("why_missing_partition", err))
            } else if segments.len() == 3 && segments[0] == "readyz" && segments[1] == "why" {
                let partition = segments[2];
                if let Some(why) = publisher.explain(partition) {
                    ctx.check_deadline(stream, "why_write")?;
                    write_json_response(stream, 200, &why)
                        .map_err(|err| HttpHandlerError::response("why_write", err))
                } else {
                    warn!(
                        "event=readyz_http_bad_path path={} method={} reason=partition_missing id={}",
                        request.path, request.method, partition
                    );
                    ctx.check_deadline(stream, "why_partition_missing")?;
                    write_json_response(
                        stream,
                        404,
                        &serde_json::json!({"error": "partition not found", "status": 404}),
                    )
                    .map_err(|err| HttpHandlerError::response("why_partition_missing", err))
                }
            } else {
                warn!(
                    "event=readyz_http_bad_path path={} method={} reason=unknown_route",
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
        }
        _ => {
            ctx.check_deadline(stream, "why_method_not_allowed")?;
            write_json_response(
                stream,
                405,
                &serde_json::json!({"error": "method not allowed", "status": 405}),
            )
            .map_err(|err| HttpHandlerError::response("why_method_not_allowed", err))
        }
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncReadyzHttpServerHandle {
    inner: Option<ReadyzHttpServerHandle>,
}

#[cfg(feature = "async-net")]
impl AsyncReadyzHttpServerHandle {
    pub async fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)).await {
            warn!("event=readyz_async_shutdown_error error={err}");
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
impl Drop for AsyncReadyzHttpServerHandle {
    fn drop(&mut self) {
        if let Some(mut handle) = self.inner.take() {
            let _ = handle.try_shutdown(Duration::from_secs(5));
        }
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncReadyzHttpServer;

#[cfg(feature = "async-net")]
impl AsyncReadyzHttpServer {
    pub async fn spawn(
        config: ReadyzHttpServerConfig,
        publisher: ReadyzPublisher,
    ) -> Result<AsyncReadyzHttpServerHandle, NetError> {
        let handle = task::spawn_blocking(move || ReadyzHttpServer::spawn(config, publisher))
            .await
            .map_err(map_join_error)??;
        Ok(AsyncReadyzHttpServerHandle {
            inner: Some(handle),
        })
    }
}

#[cfg(feature = "async-net")]
fn map_join_error(err: task::JoinError) -> NetError {
    NetError::Io(std::io::Error::other(format!(
        "readyz async task cancelled: {err}"
    )))
}

fn configure_readyz_stream(stream: &TcpStream) -> Result<(), NetError> {
    stream
        .set_read_timeout(Some(READYZ_REQUEST_TIMEOUT))
        .map_err(NetError::from)?;
    stream
        .set_write_timeout(Some(READYZ_REQUEST_TIMEOUT))
        .map_err(NetError::from)?;
    Ok(())
}

pub(crate) fn map_readyz_handler_error(err: HttpHandlerError) -> Result<(), NetError> {
    match err {
        HttpHandlerError::DeadlineExpired { stage } => {
            warn!("event=readyz_http_deadline_expired stage={stage}");
            Ok(())
        }
        HttpHandlerError::Request { stage, error }
        | HttpHandlerError::Response { stage, error } => {
            warn!("event=readyz_http_handler_error stage={stage} error={error}");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_readyz_request, ReadyzPublisher};
    use crate::activation::{ShadowApplyState, WarmupReadinessRecord};
    use crate::feature_guard::{FeatureGateState, FeatureManifestBuilder};
    use crate::net::http::{HttpRequestContext, RequestDeadline, SimpleHttpRequest};
    use crate::readyz::{ReadyStateProbe, ReadyzSnapshot};
    use crate::security::{Certificate, SerialNumber, SpiffeId};
    use ed25519_dalek::SigningKey;
    use std::time::{Duration, Instant};

    fn request_context() -> HttpRequestContext {
        let spiffe = SpiffeId::parse("spiffe://test.example/ns/default/sa/readyz").expect("spiffe");
        let cert = Certificate {
            spiffe_id: spiffe,
            serial: SerialNumber::from_u64(1),
            valid_from: Instant::now(),
            valid_until: Instant::now() + Duration::from_secs(60),
        };
        HttpRequestContext::new(cert, RequestDeadline::from_timeout(Duration::from_secs(5)))
    }

    fn publisher() -> ReadyzPublisher {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = FeatureManifestBuilder::new()
            .with_gate_state("leader_leases", FeatureGateState::Enabled)
            .build(&signing_key)
            .expect("manifest");
        let matrix = manifest.capability_matrix().expect("matrix");
        let readiness = WarmupReadinessRecord {
            partition_id: "partition-a".into(),
            bundle_id: "bundle-a".into(),
            shadow_apply_state: ShadowApplyState::Ready,
            shadow_apply_checkpoint_index: 1,
            warmup_ready_ratio: 1.0,
            updated_at_ms: 0,
        };
        let probe = ReadyStateProbe {
            readiness,
            activation_barrier_id: None,
            partition_ready_ratio: 1.0,
        };
        let snapshot = ReadyzSnapshot::new(
            vec![probe],
            1_000,
            0,
            &matrix,
            manifest.digest().expect("digest"),
            Vec::new(),
        )
        .expect("snapshot");
        ReadyzPublisher::new(snapshot)
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

    #[test]
    fn serves_readyz_snapshot() {
        let ctx = request_context();
        let publisher = publisher();
        let mut buffer = Vec::new();
        handle_readyz_request(&ctx, request_for("/readyz"), &publisher, &mut buffer)
            .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response.contains("\"partition_id\":\"partition-a\""),
            "response body should include partition data"
        );
    }

    #[test]
    fn reports_missing_partition_id() {
        let ctx = request_context();
        let publisher = publisher();
        let mut buffer = Vec::new();
        handle_readyz_request(&ctx, request_for("/readyz/why"), &publisher, &mut buffer)
            .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(
            response.contains("partition id missing"),
            "expected missing partition error"
        );
    }

    #[test]
    fn reports_unknown_path() {
        let ctx = request_context();
        let publisher = publisher();
        let mut buffer = Vec::new();
        handle_readyz_request(
            &ctx,
            request_for("/readyz/unknown"),
            &publisher,
            &mut buffer,
        )
        .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(response.contains("not found"));
    }
}
