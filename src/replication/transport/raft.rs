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
