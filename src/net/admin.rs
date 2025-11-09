#![cfg(feature = "net")]

use super::http::{read_request, write_json_response, SimpleHttpRequest};
use super::tls::{complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore};
use super::NetError;
use crate::admin::{
    AdminRequestContext, AdminService, CreatePartitionRequest, SnapshotThrottleRequest,
    UpdateDurabilityModeRequest,
};
use crate::security::{Certificate, SecurityError};
use log::{error, info, warn};
use rustls::{ServerConfig, ServerConnection, Stream};
use serde::de::DeserializeOwned;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use url::form_urlencoded;

pub struct AdminHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct AdminHttpServerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl AdminHttpServerHandle {
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AdminHttpServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub struct AdminHttpServer;

impl AdminHttpServer {
    pub fn spawn(
        config: AdminHttpServerConfig,
        service: AdminService,
    ) -> Result<AdminHttpServerHandle, NetError> {
        let listener = TcpListener::bind(config.bind)?;
        listener.set_nonblocking(true)?;
        info!("admin HTTP server listening on {}", config.bind);
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let shared_service = Arc::new(Mutex::new(service));
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = shutdown.clone();
        let handle = thread::spawn(move || loop {
            if shutdown_flag.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, addr)) => {
                    let tls = tls_config.clone();
                    let service = shared_service.clone();
                    thread::spawn(move || {
                        if let Err(err) = handle_connection(stream, addr, tls, service) {
                            warn!("admin connection {addr} error: {err}");
                        }
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(err) => {
                    error!("admin accept error: {err}");
                    break;
                }
            }
        });
        Ok(AdminHttpServerHandle {
            shutdown,
            join: Some(handle),
        })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    service: Arc<Mutex<AdminService>>,
) -> Result<(), NetError> {
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    let peer_chain = conn
        .peer_certificates()
        .ok_or_else(|| NetError::Certificate("admin client presented no certificate".into()))?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
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
    let ctx = build_context(&request, &peer_certificate);
    let mut guard = service.lock().expect("admin service poisoned");
    match dispatch_request(&mut guard, ctx, request) {
        Ok(response) => write_json_response(&mut tls, 200, &response)?,
        Err(err) => {
            write_json_response(&mut tls, err.status, &err.body)?;
        }
    }
    Ok(())
}

fn dispatch_request(
    service: &mut AdminService,
    ctx: AdminRequestContext,
    request: SimpleHttpRequest,
) -> Result<serde_json::Value, HttpAdminError> {
    let now = Instant::now();
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/admin/create-partition") => {
            let payload: CreatePartitionRequest = parse_body(&request)?;
            let response = service
                .create_partition(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            Ok(serde_json::to_value(response).expect("serialize create_partition"))
        }
        ("POST", "/admin/update-durability-mode") => {
            let payload: UpdateDurabilityModeRequest = parse_body(&request)?;
            let response = service
                .update_durability_mode(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            Ok(serde_json::to_value(response).expect("serialize update_durability_mode"))
        }
        ("POST", "/admin/snapshot-throttle") => {
            let payload: SnapshotThrottleRequest = parse_body(&request)?;
            let response = service
                .snapshot_throttle(&ctx, payload, now)
                .map_err(HttpAdminError::from)?;
            Ok(serde_json::to_value(response).expect("serialize snapshot_throttle"))
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
            Ok(serde_json::to_value(response).expect("serialize throttle explain"))
        }
        ("GET", "/admin/apply-report") => {
            let partition = require_query(&request, "partition_id")?;
            let response = service
                .explain_apply_profile(&partition)
                .map_err(HttpAdminError::from)?;
            Ok(serde_json::to_value(response).expect("serialize apply report"))
        }
        _ => Err(HttpAdminError::status_message(
            404,
            format!("no route for {} {}", request.method, request.path),
        )),
    }
}

fn build_context(request: &SimpleHttpRequest, cert: &Certificate) -> AdminRequestContext {
    let role = request
        .header("x-admin-role")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| cert.spiffe_id.path.trim_start_matches('/').to_string());
    AdminRequestContext::new(role)
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
}

impl From<crate::admin::AdminServiceError> for HttpAdminError {
    fn from(err: crate::admin::AdminServiceError) -> Self {
        match err {
            crate::admin::AdminServiceError::InvalidRequest(msg) => {
                HttpAdminError::status_message(400, msg)
            }
            crate::admin::AdminServiceError::Security(SecurityError::Unauthorized) => {
                HttpAdminError::status_message(403, "unauthorized")
            }
            crate::admin::AdminServiceError::Security(other) => {
                HttpAdminError::status_message(503, format!("security error: {other}"))
            }
            crate::admin::AdminServiceError::Admin(admin_err) => match admin_err {
                crate::admin::AdminError::UnknownPartition => {
                    HttpAdminError::status_message(404, "partition not registered")
                }
                crate::admin::AdminError::CpUnavailable(response) => HttpAdminError {
                    status: 503,
                    body: serde_json::json!({
                        "error": "control plane unavailable",
                        "detail": response,
                        "status": 503
                    }),
                },
            },
        }
    }
}
