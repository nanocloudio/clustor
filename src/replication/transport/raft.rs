use super::{CatalogNegotiationConfig, CatalogNegotiationReport, NegotiationError};
use crate::replication::consensus::CatalogVersion;
use crate::replication::raft::{
    AppendEntriesFrameError, AppendEntriesRequest, AppendEntriesResponse, RaftRouting,
    RequestVoteFrameError, RequestVoteRequest, RequestVoteResponse, RoutingValidationError,
};
use crate::security::{Certificate, MtlsIdentityManager, SecurityError};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

/// Application-defined handler for Raft RPCs.
pub trait RaftRpcHandler {
    fn on_request_vote(&mut self, request: RequestVoteRequest) -> RequestVoteResponse;
    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RoutingKey {
    partition_id: String,
    prg_id: String,
    routing_epoch: u64,
}

impl RoutingKey {
    fn from(routing: &RaftRouting) -> Self {
        Self {
            partition_id: routing.partition_id.clone(),
            prg_id: routing.prg_id.clone(),
            routing_epoch: routing.routing_epoch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PartitionKey {
    partition_id: String,
    prg_id: String,
}

impl PartitionKey {
    fn from(routing: &RaftRouting) -> Self {
        Self {
            partition_id: routing.partition_id.clone(),
            prg_id: routing.prg_id.clone(),
        }
    }
}

struct RoutingEntry<H> {
    routing: RaftRouting,
    handler: Arc<Mutex<H>>,
}

impl<H> Clone for RoutingEntry<H> {
    fn clone(&self) -> Self {
        Self {
            routing: self.routing.clone(),
            handler: self.handler.clone(),
        }
    }
}

struct RoutingTable<H> {
    by_exact: HashMap<RoutingKey, RoutingEntry<H>>,
    by_partition: HashMap<PartitionKey, RoutingEntry<H>>,
    by_partition_id: HashMap<String, RoutingEntry<H>>,
}

impl<H> RoutingTable<H> {
    fn new() -> Self {
        Self {
            by_exact: HashMap::new(),
            by_partition: HashMap::new(),
            by_partition_id: HashMap::new(),
        }
    }

    fn remove_partition(&mut self, partition: &str, prg: &str) {
        let keys: Vec<RoutingKey> = self
            .by_exact
            .keys()
            .filter(|key| key.partition_id == partition && key.prg_id == prg)
            .cloned()
            .collect();
        for key in keys {
            self.by_exact.remove(&key);
        }
        self.by_partition
            .retain(|key, _| key.partition_id != partition || key.prg_id != prg);
        self.by_partition_id.retain(|key, _| key != partition);
    }

    fn insert(&mut self, routing: RaftRouting, handler: Arc<Mutex<H>>) {
        self.remove_partition(&routing.partition_id, &routing.prg_id);
        let entry = RoutingEntry {
            routing: routing.clone(),
            handler,
        };
        self.by_exact
            .insert(RoutingKey::from(&routing), entry.clone());
        self.by_partition
            .insert(PartitionKey::from(&routing), entry.clone());
        self.by_partition_id
            .insert(routing.partition_id.clone(), entry);
    }
}

struct RoutingDemux<H> {
    table: RwLock<RoutingTable<H>>,
    version: AtomicU64,
}

impl<H> RoutingDemux<H> {
    fn new(routing: RaftRouting, handler: Arc<Mutex<H>>) -> Self {
        let mut table = RoutingTable::new();
        table.insert(routing, handler);
        Self {
            table: RwLock::new(table),
            version: AtomicU64::new(1),
        }
    }

    fn install(&self, routing: RaftRouting, handler: Arc<Mutex<H>>) -> u64 {
        {
            let mut table = self.table.write();
            table.insert(routing, handler);
        }
        self.bump_version()
    }

    fn update_epoch(&self, routing: RaftRouting) -> Option<u64> {
        let updated = {
            let mut table = self.table.write();
            let partition_key = PartitionKey::from(&routing);
            if let Some(entry) = table.by_partition.get(&partition_key) {
                let handler = entry.handler.clone();
                table.insert(routing, handler);
                true
            } else {
                false
            }
        };
        updated.then(|| self.bump_version())
    }

    fn remove(&self, partition: &str, prg: &str) -> bool {
        let mut table = self.table.write();
        let present = table.by_partition.contains_key(&PartitionKey {
            partition_id: partition.to_string(),
            prg_id: prg.to_string(),
        });
        if present {
            table.remove_partition(partition, prg);
            self.bump_version();
        }
        present
    }

    fn resolve(&self, routing: &RaftRouting) -> Result<Arc<Mutex<H>>, RoutingValidationError> {
        if routing.partition_id.is_empty()
            || routing.prg_id.is_empty()
            || routing.routing_epoch == 0
        {
            return Err(RoutingValidationError::MissingMetadata);
        }
        let table = self.table.read();
        if let Some(entry) = table.by_exact.get(&RoutingKey::from(routing)) {
            return Ok(entry.handler.clone());
        }
        if let Some(entry) = table.by_partition.get(&PartitionKey::from(routing)) {
            return Err(RoutingValidationError::RoutingEpochMismatch {
                expected: entry.routing.routing_epoch,
                observed: routing.routing_epoch,
            });
        }
        if let Some(entry) = table.by_partition_id.get(&routing.partition_id) {
            return Err(RoutingValidationError::RoutingEpochMismatch {
                expected: entry.routing.routing_epoch,
                observed: routing.routing_epoch,
            });
        }
        Err(RoutingValidationError::UnknownPlacement {
            partition_id: routing.partition_id.clone(),
            prg_id: routing.prg_id.clone(),
            routing_epoch: routing.routing_epoch,
        })
    }

    fn bump_version(&self) -> u64 {
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }
}

/// Minimal authenticated RPC endpoint for Raft leadership traffic.
pub struct RaftRpcServer<H> {
    identity: Arc<RwLock<MtlsIdentityManager>>,
    catalog: Mutex<Option<CatalogNegotiationReport>>,
    demux: RoutingDemux<H>,
}

impl<H: RaftRpcHandler> RaftRpcServer<H> {
    pub fn new(identity: MtlsIdentityManager, handler: H, routing: RaftRouting) -> Self {
        Self::with_identity(Arc::new(RwLock::new(identity)), handler, routing)
    }

    pub fn with_identity(
        identity: Arc<RwLock<MtlsIdentityManager>>,
        handler: H,
        routing: RaftRouting,
    ) -> Self {
        let handler = Arc::new(Mutex::new(handler));
        Self {
            identity,
            catalog: Mutex::new(None),
            demux: RoutingDemux::new(routing, handler),
        }
    }

    pub fn identity_handle(&self) -> Arc<RwLock<MtlsIdentityManager>> {
        self.identity.clone()
    }

    pub fn update_routing(&self, routing: RaftRouting) {
        self.demux.update_epoch(routing);
    }

    pub fn install_partition(&self, routing: RaftRouting, handler: H) -> u64 {
        self.demux.install(routing, Arc::new(Mutex::new(handler)))
    }

    pub fn remove_partition(&self, partition_id: &str, prg_id: &str) -> bool {
        self.demux.remove(partition_id, prg_id)
    }

    pub fn demux_version(&self) -> u64 {
        self.demux.version()
    }

    /// Performs catalog negotiation and persists the resulting transcript for §0.3 auditors.
    pub fn negotiate_catalog(
        &self,
        dataset_root: &Path,
        config: &CatalogNegotiationConfig,
        local_catalog: CatalogVersion,
    ) -> Result<(), NegotiationError> {
        let report = config.negotiate(dataset_root, local_catalog)?;
        let mut guard = self.catalog.lock();
        *guard = Some(report);
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    pub fn handle_request_vote(
        &self,
        peer: &Certificate,
        frame: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, RaftTransportError> {
        let mut identity = self.identity.write();
        identity
            .verify_peer(peer, now)
            .map_err(RaftTransportError::Security)?;
        let request = match RequestVoteRequest::decode(frame) {
            Ok(req) => req,
            Err(RequestVoteFrameError::MissingRoutingMetadata) => {
                return Err(self.routing_mismatch(None, RoutingValidationError::MissingMetadata));
            }
            Err(err) => {
                if matches!(err, RequestVoteFrameError::InvalidVersion { .. }) {
                    self.record_violation("request_vote.version")?;
                }
                return Err(RaftTransportError::RequestVoteFrame(err));
            }
        };
        let handler = self.resolve_handler(&request.routing)?;
        let mut guard = handler.lock();
        let response = guard.on_request_vote(request);
        response
            .encode()
            .map_err(RaftTransportError::RequestVoteFrame)
    }

    #[allow(clippy::result_large_err)]
    pub fn handle_append_entries(
        &self,
        peer: &Certificate,
        frame: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, RaftTransportError> {
        let mut identity = self.identity.write();
        identity
            .verify_peer(peer, now)
            .map_err(RaftTransportError::Security)?;
        let request = match AppendEntriesRequest::decode(frame) {
            Ok(req) => req,
            Err(AppendEntriesFrameError::MissingRoutingMetadata) => {
                return Err(self.routing_mismatch(None, RoutingValidationError::MissingMetadata));
            }
            Err(err) => {
                if matches!(err, AppendEntriesFrameError::InvalidVersion { .. }) {
                    self.record_violation("append_entries.version")?;
                }
                return Err(RaftTransportError::AppendEntriesFrame(err));
            }
        };
        let handler = self.resolve_handler(&request.routing)?;
        let mut guard = handler.lock();
        let response = guard.on_append_entries(request);
        response
            .encode()
            .map_err(RaftTransportError::AppendEntriesFrame)
    }

    #[allow(clippy::result_large_err)]
    fn record_violation(&self, detail: impl Into<String>) -> Result<(), RaftTransportError> {
        let mut guard = self.catalog.lock();
        if let Some(report) = guard.as_mut() {
            report
                .record_forward_compat_violation(detail)
                .map_err(RaftTransportError::Negotiation)?;
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn resolve_handler(&self, incoming: &RaftRouting) -> Result<Arc<Mutex<H>>, RaftTransportError> {
        match self.demux.resolve(incoming) {
            Ok(handler) => Ok(handler),
            Err(reason) => Err(self.routing_mismatch(Some(incoming.clone()), reason)),
        }
    }

    fn routing_mismatch(
        &self,
        observed: Option<RaftRouting>,
        reason: RoutingValidationError,
    ) -> RaftTransportError {
        let expected = match (&observed, &reason) {
            (Some(route), RoutingValidationError::RoutingEpochMismatch { expected, .. }) => {
                Some(RaftRouting {
                    partition_id: route.partition_id.clone(),
                    prg_id: route.prg_id.clone(),
                    routing_epoch: *expected,
                })
            }
            _ => None,
        };
        RaftTransportError::RoutingMismatch {
            expected,
            observed,
            reason,
        }
    }
}

#[derive(Debug, Error)]
pub enum RaftTransportError {
    #[error(transparent)]
    Security(#[from] SecurityError),
    #[error(transparent)]
    RequestVoteFrame(#[from] RequestVoteFrameError),
    #[error(transparent)]
    AppendEntriesFrame(#[from] AppendEntriesFrameError),
    #[error(transparent)]
    Negotiation(#[from] NegotiationError),
    #[error("routing mismatch (expected={expected:?}, observed={observed:?}, reason={reason})")]
    RoutingMismatch {
        expected: Option<RaftRouting>,
        observed: Option<RaftRouting>,
        reason: RoutingValidationError,
    },
    #[error("raft handler lock poisoned")]
    HandlerPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::transport::BundleNegotiationLog;
    use crate::security::{Certificate, SerialNumber, SpiffeId};
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;

    #[derive(Default)]
    struct MockHandler;

    impl RaftRpcHandler for MockHandler {
        fn on_request_vote(&mut self, request: RequestVoteRequest) -> RequestVoteResponse {
            RequestVoteResponse {
                term: request.term,
                granted: true,
                reject_reason: None,
            }
        }

        fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
            AppendEntriesResponse {
                term: request.term,
                success: true,
                match_index: request
                    .entries
                    .last()
                    .map(|entry| entry.index)
                    .unwrap_or(request.prev_log_index),
                conflict_index: None,
                conflict_term: None,
            }
        }
    }

    #[derive(Clone)]
    struct TaggedHandler {
        tag: u64,
    }

    impl RaftRpcHandler for TaggedHandler {
        fn on_request_vote(&mut self, _request: RequestVoteRequest) -> RequestVoteResponse {
            RequestVoteResponse {
                term: self.tag,
                granted: true,
                reject_reason: None,
            }
        }

        fn on_append_entries(&mut self, _request: AppendEntriesRequest) -> AppendEntriesResponse {
            AppendEntriesResponse {
                term: self.tag,
                success: true,
                match_index: self.tag,
                conflict_index: None,
                conflict_term: None,
            }
        }
    }

    fn certificate(spiffe: &str, serial: u64, now: Instant) -> Certificate {
        Certificate {
            spiffe_id: SpiffeId::parse(spiffe).unwrap(),
            serial: SerialNumber::from_u64(serial),
            valid_from: now - Duration::from_secs(5),
            valid_until: now + Duration::from_secs(60),
        }
    }

    fn identity_manager(now: Instant) -> MtlsIdentityManager {
        MtlsIdentityManager::new(
            certificate("spiffe://example.org/servers/leader", 1, now),
            "example.org",
            Duration::from_secs(600),
            now,
        )
    }

    fn negotiation_config(partition: &str) -> CatalogNegotiationConfig {
        CatalogNegotiationConfig {
            partition_id: partition.into(),
            log_path: PathBuf::from("bundle_negotiation.log"),
            remote_version: CatalogVersion::new(0, 1, 1),
        }
    }

    fn routing(epoch: u64) -> RaftRouting {
        RaftRouting::alias("partition-test", epoch)
    }

    fn routing_for(partition: &str, epoch: u64) -> RaftRouting {
        RaftRouting::alias(partition.to_string(), epoch)
    }

    #[test]
    fn request_vote_requires_valid_certificate() {
        let now = Instant::now();
        let peer = certificate("spiffe://example.org/clients/f1", 99, now);
        let request = RequestVoteRequest {
            term: 2,
            candidate_id: "leader-a".into(),
            last_log_index: 10,
            last_log_term: 2,
            pre_vote: false,
            routing: routing(2),
        };
        let frame = request.encode().unwrap();
        let server = RaftRpcServer::new(identity_manager(now), MockHandler, routing(2));
        let response = server
            .handle_request_vote(&peer, &frame, now)
            .expect("handshake should succeed");
        let decoded = RequestVoteResponse::decode(&response).unwrap();
        assert!(decoded.granted);
        assert_eq!(decoded.term, 2);
    }

    #[test]
    fn append_entries_rejects_invalid_peer() {
        let now = Instant::now();
        let peer = certificate("spiffe://other.org/clients/f1", 7, now);
        let request = AppendEntriesRequest::heartbeat(3, "leader-x", 0, routing(3));
        let frame = request.encode().unwrap();
        let server = RaftRpcServer::new(identity_manager(now), MockHandler, routing(3));
        let err = server
            .handle_append_entries(&peer, &frame, now)
            .expect_err("trust domain mismatch should fail");
        assert!(matches!(err, RaftTransportError::Security(_)));
    }

    #[test]
    fn routing_epoch_mismatch_surfaces_error() {
        let now = Instant::now();
        let peer = certificate("spiffe://example.org/clients/f1", 99, now);
        let request = RequestVoteRequest {
            term: 2,
            candidate_id: "leader-b".into(),
            last_log_index: 5,
            last_log_term: 2,
            pre_vote: false,
            routing: routing(4),
        };
        let frame = request.encode().unwrap();
        let server = RaftRpcServer::new(identity_manager(now), MockHandler, routing(5));
        let err = server
            .handle_request_vote(&peer, &frame, now)
            .expect_err("routing mismatch should fail");
        match err {
            RaftTransportError::RoutingMismatch { reason, .. } => {
                assert!(matches!(
                    reason,
                    RoutingValidationError::RoutingEpochMismatch {
                        expected: 5,
                        observed: 4
                    }
                ));
            }
            other => panic!("expected routing mismatch, got {other:?}"),
        }
    }

    #[test]
    fn prg_mismatch_returns_routing_epoch_mismatch() {
        let now = Instant::now();
        let peer = certificate("spiffe://example.org/clients/f0", 11, now);
        let mut routing = routing(7);
        routing.prg_id = "other-prg".into();
        let request = RequestVoteRequest {
            term: 2,
            candidate_id: "node-prg".into(),
            last_log_index: 0,
            last_log_term: 0,
            pre_vote: false,
            routing: routing.clone(),
        };
        let frame = request.encode().unwrap();
        let server = RaftRpcServer::new(
            identity_manager(now),
            MockHandler,
            RaftRouting::alias("partition-test", 7),
        );
        let err = server
            .handle_request_vote(&peer, &frame, now)
            .expect_err("prg mismatch should reject routing");
        match err {
            RaftTransportError::RoutingMismatch { reason, .. } => {
                assert!(matches!(
                    reason,
                    RoutingValidationError::RoutingEpochMismatch {
                        expected: 7,
                        observed: 7
                    }
                ));
            }
            other => panic!("expected routing mismatch, got {other:?}"),
        }
    }

    #[test]
    fn demux_rejects_unknown_partition() {
        let now = Instant::now();
        let peer = certificate("spiffe://example.org/clients/fx", 3, now);
        let server = RaftRpcServer::new(identity_manager(now), MockHandler, routing(2));
        let request = RequestVoteRequest {
            term: 1,
            candidate_id: "node-z".into(),
            last_log_index: 0,
            last_log_term: 0,
            pre_vote: false,
            routing: RaftRouting {
                partition_id: "missing".into(),
                prg_id: "missing".into(),
                routing_epoch: 9,
            },
        };
        let frame = request.encode().unwrap();
        let err = server
            .handle_request_vote(&peer, &frame, now)
            .expect_err("unknown partition should be rejected");
        match err {
            RaftTransportError::RoutingMismatch {
                expected,
                observed,
                reason,
            } => {
                assert!(expected.is_none());
                assert!(observed.is_some());
                assert!(matches!(
                    reason,
                    RoutingValidationError::UnknownPlacement { partition_id, .. }
                        if partition_id == "missing"
                ));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn catalog_negotiation_logs_and_revokes_on_violation() {
        let now = Instant::now();
        let tmp = TempDir::new().unwrap();
        let server = RaftRpcServer::new(identity_manager(now), MockHandler, routing(1));
        server
            .negotiate_catalog(
                tmp.path(),
                &negotiation_config("partition-a"),
                CatalogVersion::new(0, 1, 2),
            )
            .unwrap();
        let log = BundleNegotiationLog::new(tmp.path().join("bundle_negotiation.log"));
        let entries = log.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].accepted);

        let mut bad_frame = AppendEntriesRequest::heartbeat(4, "leader-y", 1, routing(4))
            .encode()
            .unwrap();
        bad_frame[0] = 9; // invalid frame version triggers revocation
        let peer = certificate("spiffe://example.org/clients/f2", 2, now);
        let _ = server
            .handle_append_entries(&peer, &bad_frame, now)
            .expect_err("invalid frame should fail");
        let entries = log.entries().unwrap();
        assert!(entries.len() >= 2);
        assert!(entries
            .last()
            .and_then(|entry| entry.reason.as_deref())
            .unwrap()
            .contains("append_entries.version"));
    }

    #[test]
    fn demux_routes_to_correct_handlers_and_rejects_stale_epochs() {
        let now = Instant::now();
        let peer = certificate("spiffe://example.org/clients/f3", 21, now);
        let routing_a = routing_for("partition-a", 3);
        let routing_b = routing_for("partition-b", 5);
        let server = RaftRpcServer::new(
            identity_manager(now),
            TaggedHandler { tag: 11 },
            routing_a.clone(),
        );
        server.install_partition(routing_b.clone(), TaggedHandler { tag: 22 });

        let vote_a = RequestVoteRequest {
            term: 1,
            candidate_id: "candidate-a".into(),
            last_log_index: 0,
            last_log_term: 0,
            pre_vote: false,
            routing: routing_a.clone(),
        };
        let frame_a = vote_a.encode().unwrap();
        let response_a = server
            .handle_request_vote(&peer, &frame_a, now)
            .expect("routing a should succeed");
        let decoded_a = RequestVoteResponse::decode(&response_a).unwrap();
        assert_eq!(decoded_a.term, 11);

        let vote_b = RequestVoteRequest {
            term: 1,
            candidate_id: "candidate-b".into(),
            last_log_index: 0,
            last_log_term: 0,
            pre_vote: false,
            routing: routing_b.clone(),
        };
        let frame_b = vote_b.encode().unwrap();
        let response_b = server
            .handle_request_vote(&peer, &frame_b, now)
            .expect("routing b should succeed");
        let decoded_b = RequestVoteResponse::decode(&response_b).unwrap();
        assert_eq!(decoded_b.term, 22);

        let updated_b = RaftRouting {
            routing_epoch: 6,
            ..routing_b.clone()
        };
        server.update_routing(updated_b.clone());
        let stale_frame = RequestVoteRequest {
            routing: routing_b.clone(),
            ..vote_b.clone()
        }
        .encode()
        .unwrap();
        let err = server
            .handle_request_vote(&peer, &stale_frame, now)
            .expect_err("stale epoch should be rejected");
        match err {
            RaftTransportError::RoutingMismatch { reason, .. } => {
                assert!(matches!(
                    reason,
                    RoutingValidationError::RoutingEpochMismatch {
                        expected: 6,
                        observed: 5
                    }
                ));
            }
            other => panic!("expected routing mismatch, got {other:?}"),
        }

        let refreshed_frame = RequestVoteRequest {
            routing: updated_b,
            ..vote_b
        }
        .encode()
        .unwrap();
        let refreshed = server
            .handle_request_vote(&peer, &refreshed_frame, now)
            .expect("updated epoch should route");
        let refreshed_decoded = RequestVoteResponse::decode(&refreshed).unwrap();
        assert_eq!(refreshed_decoded.term, 22);
    }
}
