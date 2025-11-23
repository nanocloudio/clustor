use super::admin::{handle_admin_request, ADMIN_REQUEST_TIMEOUT};
use super::http::{
    spawn_tls_http_server, write_json_response, HttpHandlerError, HttpRequestContext,
    RequestDeadline, SimpleHttpRequest,
};
use super::readyz::{handle_readyz_request, ReadyzPublisher, READYZ_REQUEST_TIMEOUT};
use super::tls::{TlsIdentity, TlsTrustStore};
use super::why::{handle_why_request, WhyPublisher, WHY_REQUEST_TIMEOUT};
use super::NetError;
use crate::admin::AdminService;
use log::{info, warn};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(feature = "async-net")]
use tokio::task;

const MANAGEMENT_REQUEST_TIMEOUT: Duration = ADMIN_REQUEST_TIMEOUT;
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
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)) {
            warn!("event=management_http_shutdown_error error={err}");
        }
    }

    pub fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        self.inner.try_shutdown(timeout)
    }
}

impl Drop for ManagementHttpServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(Duration::from_secs(5));
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
            MANAGEMENT_REQUEST_TIMEOUT,
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
        if let Err(err) = self.try_shutdown(Duration::from_secs(5)).await {
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
            let _ = handle.try_shutdown(Duration::from_secs(5));
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
            Self::Unknown => MANAGEMENT_REQUEST_TIMEOUT,
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

#[cfg(test)]
mod tests {
    use super::{handle_management_request, ManagementRoute};
    use crate::activation::WarmupReadinessRecord;
    use crate::admin::{AdminHandler, AdminService};
    use crate::consensus::{ConsensusCore, ConsensusCoreConfig, StrictFallbackState};
    use crate::cp::CpProofCoordinator;
    use crate::cp_raft::CpPlacementClient;
    use crate::feature_guard::{FeatureGateState, FeatureManifestBuilder};
    use crate::net::http::{HttpRequestContext, RequestDeadline, SimpleHttpRequest};
    use crate::net::why::WhyPublisher;
    use crate::raft::PartitionQuorumStatus;
    use crate::readyz::{ReadyStateProbe, ReadyzSnapshot};
    use crate::security::{Certificate, SerialNumber, SpiffeId};
    use crate::terminology::TERM_STRICT;
    use crate::why::{LocalRole, WhyNotLeader, WhySchemaHeader};
    use crate::{
        IdempotencyLedger, RbacManifest, RbacManifestCache, RbacPrincipal, RbacRole,
        ReadyzPublisher,
    };
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    fn request_context(spiffe: &str, timeout: Duration) -> HttpRequestContext {
        let spiffe = SpiffeId::parse(spiffe).expect("spiffe parses");
        let cert = Certificate {
            spiffe_id: spiffe,
            serial: SerialNumber::from_u64(1),
            valid_from: Instant::now(),
            valid_until: Instant::now() + Duration::from_secs(60),
        };
        HttpRequestContext::new(cert, RequestDeadline::from_timeout(timeout))
    }

    fn readyz_publisher() -> ReadyzPublisher {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let manifest = FeatureManifestBuilder::new()
            .with_gate_state("leader_leases", FeatureGateState::Enabled)
            .build(&signing_key)
            .expect("manifest");
        let matrix = manifest.capability_matrix().expect("matrix");
        let readiness = WarmupReadinessRecord {
            partition_id: "partition-a".into(),
            bundle_id: "bundle-a".into(),
            shadow_apply_state: crate::activation::ShadowApplyState::Ready,
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

    fn why_publisher() -> WhyPublisher {
        let publisher = WhyPublisher::default();
        let report = WhyNotLeader {
            header: WhySchemaHeader::new("partition-a", 1, 1, 0),
            leader_id: Some("leader-a".into()),
            local_role: LocalRole::Follower,
            strict_state: StrictFallbackState::LocalOnly,
            cp_cache_state: crate::cp::CpCacheState::Fresh,
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

    fn admin_service(now: Instant, principal: &str) -> AdminService {
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
                    capabilities: vec!["CreatePartition".into()],
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

    fn readyz_request() -> SimpleHttpRequest {
        SimpleHttpRequest {
            method: "GET".into(),
            path: "/readyz".into(),
            query: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn admin_request() -> SimpleHttpRequest {
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
    fn routes_readyz_requests() {
        let route = ManagementRoute::Readyz;
        let principal = "spiffe://test.example/ns/default/sa/admin";
        let ctx = request_context(principal, route.timeout());
        let readyz = readyz_publisher();
        let why = why_publisher();
        let admin = Arc::new(Mutex::new(admin_service(Instant::now(), principal)));
        let mut buffer = Vec::new();
        handle_management_request(
            &ctx,
            route,
            readyz_request(),
            &readyz,
            &why,
            &admin,
            &mut buffer,
            Instant::now(),
        )
        .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"partition_id\":\"partition-a\""));
    }

    #[test]
    fn routes_admin_requests() {
        let route = ManagementRoute::Admin;
        let principal = "spiffe://test.example/ns/default/sa/admin";
        let ctx = request_context(principal, route.timeout());
        let readyz = readyz_publisher();
        let why = why_publisher();
        let admin = Arc::new(Mutex::new(admin_service(Instant::now(), principal)));
        let mut buffer = Vec::new();
        handle_management_request(
            &ctx,
            route,
            admin_request(),
            &readyz,
            &why,
            &admin,
            &mut buffer,
            Instant::now(),
        )
        .expect("handler succeeds");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"partition_id\":\"partition-a\""));
    }

    #[test]
    fn responds_not_found_for_unknown_routes() {
        let route = ManagementRoute::Unknown;
        let ctx = request_context(
            "spiffe://test.example/ns/default/sa/unknown",
            route.timeout(),
        );
        let readyz = readyz_publisher();
        let why = why_publisher();
        let admin = Arc::new(Mutex::new(admin_service(
            Instant::now(),
            "spiffe://test.example/ns/default/sa/admin",
        )));
        let mut buffer = Vec::new();
        handle_management_request(
            &ctx,
            route,
            SimpleHttpRequest {
                method: "GET".into(),
                path: "/not-real".into(),
                query: None,
                headers: Vec::new(),
                body: Vec::new(),
            },
            &readyz,
            &why,
            &admin,
            &mut buffer,
            Instant::now(),
        )
        .expect("handler writes response");
        let response = String::from_utf8(buffer).expect("utf8");
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }
}
