#![cfg(all(feature = "net", feature = "admin-http"))]

use crate::control_plane::admin::*;
use crate::net::http::{
    read_request, write_json_response, HttpHandlerError, HttpRequestContext, RequestDeadline,
    SimpleHttpRequest,
};
use crate::net::server;
use crate::net::tls::{
    complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore,
};
use crate::net::{CertificateError, NetError};
use crate::security::{BreakGlassToken, Certificate, SecurityError, SpiffeId};
use log::{error, info, warn};
use rustls::{ServerConfig, ServerConnection, Stream};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
#[cfg(feature = "async-net")]
use tokio::task;
use url::form_urlencoded;

const MAX_CONCURRENT_ADMIN_CONNECTIONS: usize = 32;
pub(crate) const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct AdminHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct AdminHttpServerHandle {
    inner: server::ServerHandle,
}

impl AdminHttpServerHandle {
    pub fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)) {
            warn!("event=admin_http_shutdown_error error={err}");
        }
    }

    pub fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        self.inner.try_shutdown(timeout)
    }
}

impl Drop for AdminHttpServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(Duration::from_secs(5));
    }
}

pub struct AdminHttpServer;

impl AdminHttpServer {
    pub fn spawn(
        config: AdminHttpServerConfig,
        service: AdminService,
    ) -> Result<AdminHttpServerHandle, NetError> {
        info!("admin HTTP server listening on {}", config.bind);
        let listener = TcpListener::bind(config.bind)?;
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let shared_service = Arc::new(Mutex::new(service));
        let handler = move |stream: TcpStream,
                            addr: SocketAddr,
                            _shutdown: Arc<AtomicBool>|
              -> Result<(), NetError> {
            if let Err(err) = configure_admin_stream(&stream) {
                warn!("admin connection {addr} rejected: timeout_config_failed error={err}");
                return Ok(());
            }
            let tls = tls_config.clone();
            let service = shared_service.clone();
            if let Err(err) = handle_connection(stream, addr, tls, service) {
                warn!("admin connection {addr} error: {err}");
            }
            Ok(())
        };
        let inner = server::spawn_listener(
            "admin_http",
            listener,
            Some(MAX_CONCURRENT_ADMIN_CONNECTIONS),
            handler,
        )
        .map_err(NetError::from)?;
        Ok(AdminHttpServerHandle { inner })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    service: Arc<Mutex<AdminService>>,
) -> Result<(), NetError> {
    let deadline = RequestDeadline::from_timeout(ADMIN_REQUEST_TIMEOUT);
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    let peer_chain = conn.peer_certificates().ok_or_else(|| {
        NetError::from(CertificateError::MissingClientCertificate { context: "admin" })
    })?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
    let request_ctx = HttpRequestContext::new(peer_certificate, deadline);
    let mut tls = Stream::new(&mut conn, &mut stream);
    let request = match read_request(&mut tls) {
        Ok(req) => req,
        Err(err) => {
            warn!("invalid admin request from {addr}: {err}");
            write_json_response(
                &mut tls,
                400,
                &serde_json::json!({ "error": "invalid HTTP request", "status": 400 }),
            )?;
            return Ok(());
        }
    };
    let now = Instant::now();
    let result = handle_admin_request(&request_ctx, request, &service, &mut tls, now);
    match result {
        Ok(()) => Ok(()),
        Err(err) => map_admin_handler_error(err),
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncAdminHttpServerHandle {
    inner: Option<AdminHttpServerHandle>,
}

#[cfg(feature = "async-net")]
impl AsyncAdminHttpServerHandle {
    pub async fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)).await {
            warn!("event=admin_http_async_shutdown_error error={err}");
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
impl Drop for AsyncAdminHttpServerHandle {
    fn drop(&mut self) {
        if let Some(mut handle) = self.inner.take() {
            let _ = handle.try_shutdown(Duration::from_secs(5));
        }
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncAdminHttpServer;

#[cfg(feature = "async-net")]
impl AsyncAdminHttpServer {
    pub async fn spawn(
        config: AdminHttpServerConfig,
        service: AdminService,
    ) -> Result<AsyncAdminHttpServerHandle, NetError> {
        let handle = task::spawn_blocking(move || AdminHttpServer::spawn(config, service))
            .await
            .map_err(map_join_error)??;
        Ok(AsyncAdminHttpServerHandle {
            inner: Some(handle),
        })
    }
}

#[cfg(feature = "async-net")]
fn map_join_error(err: task::JoinError) -> NetError {
    NetError::Io(std::io::Error::other(format!(
        "admin async task cancelled: {err}"
    )))
}

fn configure_admin_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(ADMIN_REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(ADMIN_REQUEST_TIMEOUT))?;
    Ok(())
}

pub(crate) fn handle_admin_request(
    ctx: &HttpRequestContext,
    request: SimpleHttpRequest,
    service: &Arc<Mutex<AdminService>>,
    stream: &mut (impl std::io::Write + ?Sized),
    now: Instant,
) -> Result<(), HttpHandlerError> {
    ctx.check_deadline(stream, "request_read")?;
    let admin_ctx = match build_context(&request, &ctx.peer_certificate, now) {
        Ok(ctx) => ctx,
        Err(err) => {
            ctx.check_deadline(stream, "context_build")?;
            write_json_response(stream, err.status, &err.body)
                .map_err(|err| HttpHandlerError::response("context_build", err))?;
            return Ok(());
        }
    };
    ctx.check_deadline(stream, "context_ready")?;
    let mut guard = server::lock_or_poison(service, "admin service")
        .map_err(|err| HttpHandlerError::request("service_lock", err))?;
    ctx.check_deadline(stream, "service_lock")?;
    let result = dispatch_request(&mut guard, admin_ctx, request, now);
    ctx.check_deadline(stream, "service_dispatch")?;
    match result {
        Ok(response) => write_json_response(stream, 200, &response)
            .map_err(|err| HttpHandlerError::response("service_dispatch", err)),
        Err(err) => write_json_response(stream, err.status, &err.body)
            .map_err(|err| HttpHandlerError::response("service_dispatch", err)),
    }
}

fn dispatch_request(
    service: &mut AdminService,
    ctx: AdminRequestContext,
    request: SimpleHttpRequest,
    now: Instant,
) -> Result<serde_json::Value, HttpAdminError> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/admin/create-partition") => {
            let payload: CreatePartitionRequest = parse_body(&request)?;
            let response = service
                .create_partition(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "create_partition")
        }
        ("POST", "/admin/set-durability-mode") => {
            let payload: SetDurabilityModeRequest = parse_body(&request)?;
            let response = service
                .set_durability_mode(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "set_durability_mode")
        }
        ("POST", "/admin/snapshot-throttle") => {
            let payload: SnapshotThrottleRequest = parse_body(&request)?;
            let response = service
                .snapshot_throttle(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "snapshot_throttle")
        }
        ("POST", "/admin/transfer-leader") => {
            let payload: TransferLeaderRequest = parse_body(&request)?;
            let response = service
                .transfer_leader(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "transfer_leader")
        }
        ("POST", "/admin/snapshot-trigger") => {
            let payload: SnapshotTriggerRequest = parse_body(&request)?;
            let response = service
                .trigger_snapshot(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "snapshot_trigger")
        }
        ("POST", "/admin/shrink-plan") => {
            let payload: CreateShrinkPlanRequest = parse_body(&request)?;
            let response = service
                .create_shrink_plan(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "create_shrink_plan")
        }
        ("POST", "/admin/shrink-plan/arm") => {
            let payload: ArmShrinkPlanRequest = parse_body(&request)?;
            let response = service
                .arm_shrink_plan(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "arm_shrink_plan")
        }
        ("POST", "/admin/shrink-plan/cancel") => {
            let payload: CancelShrinkPlanRequest = parse_body(&request)?;
            let response = service
                .cancel_shrink_plan(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "cancel_shrink_plan")
        }
        ("GET", "/admin/shrink-plan") => {
            let response = service
                .list_shrink_plans(&ctx, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "list_shrink_plans")
        }
        ("GET", "/admin/throttle") => {
            let partition = require_query(&request, "partition_id")?;
            let trace = request
                .query
                .as_deref()
                .and_then(|q| extract_query_param(q, "decision_trace_id"))
                .unwrap_or_else(|| format!("admin-http-{}", now.elapsed().as_nanos()));
            let response = service
                .explain_throttle(&partition, trace, now)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "throttle_explain")
        }
        ("GET", "/admin/apply-report") => {
            let partition = require_query(&request, "partition_id")?;
            let response = service
                .explain_apply_profile(&partition)
                .map_err(HttpAdminError::from)?;
            serialize_response(response, "apply_report")
        }
        _ => Err(HttpAdminError::status_message(
            404,
            format!("no route for {} {}", request.method, request.path),
        )),
    }
}

fn serialize_response<T: Serialize>(
    value: T,
    context: &'static str,
) -> Result<serde_json::Value, HttpAdminError> {
    serde_json::to_value(value)
        .map_err(|err| HttpAdminError::internal(format!("failed to serialize {context}: {err}")))
}

fn build_context(
    request: &SimpleHttpRequest,
    cert: &Certificate,
    now: Instant,
) -> Result<AdminRequestContext, HttpAdminError> {
    let mut ctx = AdminRequestContext::new(cert.spiffe_id.clone());
    if let Some(raw_token) = request.header("x-breakglass-token") {
        if !raw_token.trim().is_empty() {
            let token = parse_breakglass_token(raw_token, now)?;
            ctx = ctx.with_breakglass(token);
        }
    }
    Ok(ctx)
}

fn parse_breakglass_token(
    header_value: &str,
    now: Instant,
) -> Result<BreakGlassToken, HttpAdminError> {
    #[derive(Deserialize)]
    struct BreakGlassHeader {
        token_id: String,
        scope: String,
        ticket_url: String,
        spiffe_id: String,
        expires_in_ms: u64,
    }
    let payload: BreakGlassHeader = serde_json::from_str(header_value).map_err(|err| {
        HttpAdminError::status_message(400, format!("invalid breakglass token header: {err}"))
    })?;
    let ttl = Duration::from_millis(payload.expires_in_ms);
    let spiffe = SpiffeId::parse(&payload.spiffe_id).map_err(|err| {
        HttpAdminError::status_message(400, format!("invalid breakglass SPIFFE ID: {err}"))
    })?;
    Ok(BreakGlassToken {
        token_id: payload.token_id,
        spiffe_id: spiffe,
        scope: payload.scope,
        ticket_url: payload.ticket_url,
        expires_at: now + ttl,
        issued_at: SystemTime::now(),
    })
}

fn parse_body<T: DeserializeOwned>(request: &SimpleHttpRequest) -> Result<T, HttpAdminError> {
    if request
        .header("content-type")
        .map(|value| value.eq_ignore_ascii_case("application/json"))
        != Some(true)
    {
        return Err(HttpAdminError::status_message(
            415,
            "Content-Type must be application/json",
        ));
    }
    serde_json::from_slice(&request.body)
        .map_err(|err| HttpAdminError::status_message(400, format!("invalid JSON body: {err}")))
}

fn require_query(request: &SimpleHttpRequest, key: &str) -> Result<String, HttpAdminError> {
    let query = request.query.as_ref().ok_or_else(|| {
        HttpAdminError::status_message(400, format!("missing `{}` query parameter", key))
    })?;
    extract_query_param(query, key).ok_or_else(|| {
        HttpAdminError::status_message(400, format!("missing `{}` query parameter", key))
    })
}

fn extract_query_param(query: &str, key: &str) -> Option<String> {
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.into_owned())
}

pub struct HttpAdminError {
    status: u16,
    body: serde_json::Value,
}

impl HttpAdminError {
    fn status_message(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: serde_json::json!({ "error": message.into(), "status": status }),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::status_message(500, message)
    }
}

impl From<AdminServiceError> for HttpAdminError {
    fn from(err: AdminServiceError) -> Self {
        match err {
            AdminServiceError::InvalidRequest(msg) => HttpAdminError::status_message(400, msg),
            AdminServiceError::Security(err) => match err {
                SecurityError::Unauthorized => HttpAdminError::status_message(403, "unauthorized"),
                SecurityError::Serialization(inner) => {
                    error!("admin breakglass serialization failure: {inner}");
                    HttpAdminError::internal("security service unavailable")
                }
                other => HttpAdminError::status_message(503, format!("security error: {other}")),
            },
            AdminServiceError::Admin(admin_err) => match admin_err {
                AdminError::UnknownPartition => {
                    HttpAdminError::status_message(404, "partition not registered")
                }
                AdminError::ModeConflict { current, requested } => HttpAdminError {
                    status: 409,
                    body: serde_json::json!({
                        "error": "ModeConflict",
                        "status": 409,
                        "current_mode": current,
                        "requested_mode": requested,
                    }),
                },
                AdminError::InvalidShrinkPlan { reason } => {
                    HttpAdminError::status_message(400, format!("invalid shrink plan: {reason}"))
                }
                AdminError::ShrinkPlanExists { plan_id } => HttpAdminError {
                    status: 409,
                    body: serde_json::json!({
                        "error": "ShrinkPlanExists",
                        "status": 409,
                        "plan_id": plan_id,
                    }),
                },
                AdminError::ShrinkPlanNotFound { plan_id } => HttpAdminError {
                    status: 404,
                    body: serde_json::json!({
                        "error": "ShrinkPlanNotFound",
                        "status": 404,
                        "plan_id": plan_id,
                    }),
                },
                AdminError::ShrinkPlanActive { plan_id } => HttpAdminError {
                    status: 409,
                    body: serde_json::json!({
                        "error": "ShrinkPlanActive",
                        "status": 409,
                        "plan_id": plan_id,
                    }),
                },
                AdminError::ShrinkPlanCancelled { plan_id } => HttpAdminError {
                    status: 409,
                    body: serde_json::json!({
                        "error": "ShrinkPlanCancelled",
                        "status": 409,
                        "plan_id": plan_id,
                    }),
                },
                AdminError::CpUnavailable { clause, response } => HttpAdminError {
                    status: 503,
                    body: serde_json::json!({
                        "error": "control plane unavailable",
                        "clause": clause,
                        "detail": response,
                        "status": 503
                    }),
                },
            },
        }
    }
}

pub(crate) fn map_admin_handler_error(err: HttpHandlerError) -> Result<(), NetError> {
    match err {
        HttpHandlerError::DeadlineExpired { stage } => {
            warn!("event=admin_http_deadline_expired stage={stage}");
            Ok(())
        }
        HttpHandlerError::Request { stage, error }
        | HttpHandlerError::Response { stage, error } => {
            warn!("event=admin_http_handler_error stage={stage} error={error}");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{handle_admin_request, ADMIN_REQUEST_TIMEOUT};
    use crate::control_plane::admin::{AdminHandler, AdminService};
    use crate::control_plane::core::{CpPlacementClient, CpProofCoordinator, PlacementRecord};
    use crate::net::http::{HttpRequestContext, RequestDeadline, SimpleHttpRequest};
    use crate::replication::consensus::{ConsensusCore, ConsensusCoreConfig};
    use crate::security::{Certificate, SerialNumber, SpiffeId};
    use crate::{IdempotencyLedger, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole};
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    fn request_context(spiffe: &str) -> HttpRequestContext {
        let spiffe = SpiffeId::parse(spiffe).expect("spiffe parses");
        let cert = Certificate {
            spiffe_id: spiffe,
            serial: SerialNumber::from_u64(1),
            valid_from: Instant::now(),
            valid_until: Instant::now() + Duration::from_secs(60),
        };
        HttpRequestContext::new(cert, RequestDeadline::from_timeout(ADMIN_REQUEST_TIMEOUT))
    }

    fn build_admin_service(now: Instant, principal: &str) -> AdminService {
        let kernel = ConsensusCore::new(ConsensusCoreConfig::default());
        let cp_guard = CpProofCoordinator::new(kernel);
        let placements = CpPlacementClient::new(Duration::from_secs(60));
        let ledger = IdempotencyLedger::new(Duration::from_secs(60));
        let handler = AdminHandler::new(cp_guard, placements, ledger);
        let mut rbac = RbacManifestCache::new(Duration::from_secs(600));
        rbac.load_manifest(
            RbacManifest {
                roles: vec![RbacRole {
                    name: "operator".into(),
                    capabilities: vec!["CreatePartition".into(), "ManageShrinkPlan".into()],
                }],
                principals: vec![RbacPrincipal {
                    spiffe_id: principal.into(),
                    role: "operator".into(),
                }],
            },
            now,
        )
        .expect("rbac manifest loads");
        AdminService::new(handler, rbac)
    }

    fn create_partition_request() -> SimpleHttpRequest {
        let body = json!({
            "idempotency_key": "op-1",
            "partition": {
                "partition_id": "partition-a",
                "replicas": ["replica-a"],
                "routing_epoch": 0
            },
            "replicas": [{
                "replica_id": "replica-a",
                "az": "zone-a"
            }]
        })
        .to_string()
        .into_bytes();
        SimpleHttpRequest {
            method: "POST".into(),
            path: "/admin/create-partition".into(),
            query: None,
            headers: vec![("content-type".into(), "application/json".into())],
            body,
        }
    }

    #[test]
    fn handler_accepts_authorized_request() {
        let now = Instant::now();
        let principal = "spiffe://test.example/ns/default/sa/admin";
        let service = Arc::new(Mutex::new(build_admin_service(now, principal)));
        let ctx = request_context(principal);
        let request = create_partition_request();
        let mut buffer = Vec::new();

        handle_admin_request(&ctx, request, &service, &mut buffer, now).expect("handler succeeds");

        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response.contains("\"partition_id\":\"partition-a\""),
            "expected partition id in response"
        );
    }

    #[test]
    fn handler_rejects_unauthorized_principal() {
        let now = Instant::now();
        let service = Arc::new(Mutex::new(build_admin_service(
            now,
            "spiffe://test.example/ns/default/sa/admin",
        )));
        let ctx = request_context("spiffe://test.example/ns/default/sa/other");
        let request = create_partition_request();
        let mut buffer = Vec::new();

        handle_admin_request(&ctx, request, &service, &mut buffer, now)
            .expect("handler writes error response");

        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("unauthorized"));
    }

    #[test]
    fn handler_routes_shrink_plan_requests() {
        let now = Instant::now();
        let principal = "spiffe://test.example/ns/default/sa/admin";
        let service = Arc::new(Mutex::new(build_admin_service(now, principal)));
        {
            let mut guard = service.lock().expect("service lock");
            guard.handler_mut().placements_mut().update(
                PlacementRecord {
                    partition_id: "p-shrink".into(),
                    routing_epoch: 1,
                    lease_epoch: 1,
                    members: vec!["a".into(), "b".into(), "c".into()],
                },
                now,
            );
        }
        let ctx = request_context(principal);
        let create_body = json!({
            "plan_id": "plan-http",
            "target_placements": [{
                "prg_id": "p-shrink",
                "target_members": ["a", "b"],
                "target_routing_epoch": 2
            }]
        })
        .to_string()
        .into_bytes();
        let create = SimpleHttpRequest {
            method: "POST".into(),
            path: "/admin/shrink-plan".into(),
            query: None,
            headers: vec![("content-type".into(), "application/json".into())],
            body: create_body,
        };
        let mut buffer = Vec::new();
        handle_admin_request(&ctx, create, &service, &mut buffer, now).expect("create plan");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"plan_id\":\"plan-http\""));

        let arm_body = json!({ "plan_id": "plan-http" }).to_string().into_bytes();
        let arm = SimpleHttpRequest {
            method: "POST".into(),
            path: "/admin/shrink-plan/arm".into(),
            query: None,
            headers: vec![("content-type".into(), "application/json".into())],
            body: arm_body,
        };
        let mut buffer = Vec::new();
        handle_admin_request(
            &ctx,
            arm,
            &service,
            &mut buffer,
            now + Duration::from_millis(1),
        )
        .expect("arm plan");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.contains("\"state\":\"Armed\""));

        let list = SimpleHttpRequest {
            method: "GET".into(),
            path: "/admin/shrink-plan".into(),
            query: None,
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut buffer = Vec::new();
        handle_admin_request(
            &ctx,
            list,
            &service,
            &mut buffer,
            now + Duration::from_millis(2),
        )
        .expect("list plans");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.contains("\"plans\""));
        assert!(response.contains("\"plan-http\""));
    }
}
