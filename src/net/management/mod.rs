use super::http::{
    spawn_tls_http_server, write_json_response, HttpHandlerError, HttpRequestContext,
    RequestDeadline, SimpleHttpRequest,
};
use super::readyz::{handle_readyz_request, ReadyzPublisher};
use super::tls::{TlsIdentity, TlsTrustStore};
use super::NetError;
use crate::control_plane::AdminService;
use crate::net::control_plane::admin::handle_admin_request;
use crate::net::control_plane::why::{handle_why_request, WhyPublisher};
use crate::timeouts::{
    ADMIN_REQUEST_TIMEOUT, READYZ_REQUEST_TIMEOUT, SERVER_SHUTDOWN_GRACE, WHY_REQUEST_TIMEOUT,
};
use log::{info, warn};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(feature = "async-net")]
use tokio::task;

const MANAGEMENT_MAX_CONNECTIONS: usize = 64;

pub struct ManagementHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
    pub max_connections: Option<usize>,
}

pub struct ManagementHttpServerHandle {
    inner: super::server::ServerHandle,
}

impl ManagementHttpServerHandle {
    pub fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(SERVER_SHUTDOWN_GRACE) {
            warn!("event=management_http_shutdown_error error={err}");
        }
    }

    pub fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        self.inner.try_shutdown(timeout)
    }
}

impl Drop for ManagementHttpServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(SERVER_SHUTDOWN_GRACE);
    }
}

pub struct ManagementHttpServer;

impl ManagementHttpServer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        config: ManagementHttpServerConfig,
        readyz: ReadyzPublisher,
        why: WhyPublisher,
        admin: AdminService,
    ) -> Result<ManagementHttpServerHandle, NetError> {
        info!("management HTTP server listening on {}", config.bind);
        let listener = TcpListener::bind(config.bind)?;
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let readyz = Arc::new(readyz);
        let why = Arc::new(why);
        let admin = Arc::new(Mutex::new(admin));
        let max_connections = config.max_connections.or(Some(MANAGEMENT_MAX_CONNECTIONS));
        let inner = spawn_tls_http_server(
            "management_http",
            listener,
            max_connections,
            tls_config,
            ADMIN_REQUEST_TIMEOUT,
            ManagementRoute::deadline_for_request,
            move |ctx, request, stream, now| {
                let route = ManagementRoute::from_request(&request);
                handle_management_request(
                    ctx,
                    route,
                    request,
                    readyz.as_ref(),
                    why.as_ref(),
                    &admin,
                    stream,
                    now,
                )
            },
            |err, request| {
                map_management_handler_error(ManagementRoute::from_request(request), err)
            },
        )?;
        Ok(ManagementHttpServerHandle { inner })
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_management_request(
    ctx: &HttpRequestContext,
    route: ManagementRoute,
    request: SimpleHttpRequest,
    readyz: &ReadyzPublisher,
    why: &WhyPublisher,
    admin: &Arc<Mutex<AdminService>>,
    stream: &mut dyn std::io::Write,
    now: Instant,
) -> Result<(), HttpHandlerError> {
    match route {
        ManagementRoute::Readyz => handle_readyz_request(ctx, request, readyz, stream),
        ManagementRoute::Why => handle_why_request(ctx, request, why, stream),
        ManagementRoute::Admin => handle_admin_request(ctx, request, admin, stream, now),
        ManagementRoute::Unknown => {
            warn!(
                "event=management_http_bad_path path={} method={} reason=unknown_route",
                request.path, request.method
            );
            ctx.check_deadline(stream, "management_unknown_route")?;
            write_json_response(
                stream,
                404,
                &serde_json::json!({"error": "not found", "status": 404}),
            )
            .map_err(|err| HttpHandlerError::response("management_unknown_route", err))
        }
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncManagementHttpServerHandle {
    inner: Option<ManagementHttpServerHandle>,
}

#[cfg(feature = "async-net")]
impl AsyncManagementHttpServerHandle {
    pub async fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(SERVER_SHUTDOWN_GRACE).await {
            warn!("event=management_http_async_shutdown_error error={err}");
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
impl Drop for AsyncManagementHttpServerHandle {
    fn drop(&mut self) {
        if let Some(mut handle) = self.inner.take() {
            let _ = handle.try_shutdown(SERVER_SHUTDOWN_GRACE);
        }
    }
}

#[cfg(feature = "async-net")]
pub struct AsyncManagementHttpServer;

#[cfg(feature = "async-net")]
impl AsyncManagementHttpServer {
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        config: ManagementHttpServerConfig,
        readyz: ReadyzPublisher,
        why: WhyPublisher,
        admin: AdminService,
    ) -> Result<AsyncManagementHttpServerHandle, NetError> {
        let handle =
            task::spawn_blocking(move || ManagementHttpServer::spawn(config, readyz, why, admin))
                .await
                .map_err(map_join_error)??;
        Ok(AsyncManagementHttpServerHandle {
            inner: Some(handle),
        })
    }
}

#[cfg(feature = "async-net")]
fn map_join_error(err: task::JoinError) -> NetError {
    NetError::Io(std::io::Error::other(format!(
        "management async task cancelled: {err}"
    )))
}

#[derive(Clone, Copy)]
enum ManagementRoute {
    Readyz,
    Why,
    Admin,
    Unknown,
}

impl ManagementRoute {
    fn from_request(request: &SimpleHttpRequest) -> Self {
        let path = request.path.as_str();
        if path.starts_with("/admin") {
            Self::Admin
        } else if path.starts_with("/readyz") {
            Self::Readyz
        } else if path.starts_with("/why") {
            Self::Why
        } else {
            Self::Unknown
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            Self::Readyz => READYZ_REQUEST_TIMEOUT,
            Self::Why => WHY_REQUEST_TIMEOUT,
            Self::Admin => ADMIN_REQUEST_TIMEOUT,
            Self::Unknown => ADMIN_REQUEST_TIMEOUT,
        }
    }

    fn deadline_for_request(request: &SimpleHttpRequest) -> RequestDeadline {
        RequestDeadline::from_timeout(ManagementRoute::from_request(request).timeout())
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Readyz => "readyz",
            Self::Why => "why",
            Self::Admin => "admin",
            Self::Unknown => "unknown",
        }
    }
}

fn map_management_handler_error(
    route: ManagementRoute,
    err: HttpHandlerError,
) -> Result<(), NetError> {
    match err {
        HttpHandlerError::DeadlineExpired { stage } => {
            warn!(
                "event=management_http_deadline_expired route={} stage={stage}",
                route.name()
            );
            Ok(())
        }
        HttpHandlerError::Request { stage, error }
        | HttpHandlerError::Response { stage, error } => {
            warn!(
                "event=management_http_handler_error route={} stage={stage} error={error}",
                route.name()
            );
            Err(error)
        }
    }
}
