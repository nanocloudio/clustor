use super::{CatalogNegotiationConfig, CatalogNegotiationReport, NegotiationError};
use crate::replication::consensus::CatalogVersion;
use crate::replication::raft::{
    AppendEntriesFrameError, AppendEntriesRequest, AppendEntriesResponse, RequestVoteFrameError,
    RequestVoteRequest, RequestVoteResponse,
};
use crate::security::{Certificate, MtlsIdentityManager, SecurityError};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use thiserror::Error;

/// Application-defined handler for Raft RPCs.
pub trait RaftRpcHandler {
    fn on_request_vote(&mut self, request: RequestVoteRequest) -> RequestVoteResponse;
    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse;
}

/// Minimal authenticated RPC endpoint for Raft leadership traffic.
pub struct RaftRpcServer<H> {
    identity: Arc<RwLock<MtlsIdentityManager>>,
    handler: H,
    catalog: Option<CatalogNegotiationReport>,
}

impl<H: RaftRpcHandler> RaftRpcServer<H> {
    pub fn new(identity: MtlsIdentityManager, handler: H) -> Self {
        Self::with_identity(Arc::new(RwLock::new(identity)), handler)
    }

    pub fn with_identity(identity: Arc<RwLock<MtlsIdentityManager>>, handler: H) -> Self {
        Self {
            identity,
            handler,
            catalog: None,
        }
    }

    pub fn identity_handle(&self) -> Arc<RwLock<MtlsIdentityManager>> {
        self.identity.clone()
    }

    /// Performs catalog negotiation and persists the resulting transcript for §0.3 auditors.
    pub fn negotiate_catalog(
        &mut self,
        dataset_root: &Path,
        config: &CatalogNegotiationConfig,
        local_catalog: CatalogVersion,
    ) -> Result<(), NegotiationError> {
        let report = config.negotiate(dataset_root, local_catalog)?;
        self.catalog = Some(report);
        Ok(())
    }

    pub fn handle_request_vote(
        &mut self,
        peer: &Certificate,
        frame: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, RaftTransportError> {
        {
            let mut identity = self
                .identity
                .write()
                .map_err(|_| RaftTransportError::IdentityPoisoned)?;
            identity
                .verify_peer(peer, now)
                .map_err(RaftTransportError::Security)?;
        }
        let request = match RequestVoteRequest::decode(frame) {
            Ok(req) => req,
            Err(err) => {
                if matches!(err, RequestVoteFrameError::InvalidVersion { .. }) {
                    self.record_violation("request_vote.version")?;
                }
                return Err(RaftTransportError::RequestVoteFrame(err));
            }
        };
        let response = self.handler.on_request_vote(request);
        response
            .encode()
            .map_err(RaftTransportError::RequestVoteFrame)
    }

    pub fn handle_append_entries(
        &mut self,
        peer: &Certificate,
        frame: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, RaftTransportError> {
        {
            let mut identity = self
                .identity
                .write()
                .map_err(|_| RaftTransportError::IdentityPoisoned)?;
            identity
                .verify_peer(peer, now)
                .map_err(RaftTransportError::Security)?;
        }
        let request = match AppendEntriesRequest::decode(frame) {
            Ok(req) => req,
            Err(err) => {
                if matches!(err, AppendEntriesFrameError::InvalidVersion { .. }) {
                    self.record_violation("append_entries.version")?;
                }
                return Err(RaftTransportError::AppendEntriesFrame(err));
            }
        };
        let response = self.handler.on_append_entries(request);
        response
            .encode()
            .map_err(RaftTransportError::AppendEntriesFrame)
    }

    fn record_violation(&mut self, detail: impl Into<String>) -> Result<(), RaftTransportError> {
        if let Some(report) = self.catalog.as_mut() {
            report
                .record_forward_compat_violation(detail)
                .map_err(RaftTransportError::Negotiation)?;
        }
        Ok(())
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
    #[error("mTLS identity manager lock poisoned")]
    IdentityPoisoned,
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
        };
        let frame = request.encode().unwrap();
        let mut server = RaftRpcServer::new(identity_manager(now), MockHandler);
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
        let request = AppendEntriesRequest::heartbeat(3, "leader-x", 0);
        let frame = request.encode().unwrap();
        let mut server = RaftRpcServer::new(identity_manager(now), MockHandler);
        let err = server
            .handle_append_entries(&peer, &frame, now)
            .expect_err("trust domain mismatch should fail");
        assert!(matches!(err, RaftTransportError::Security(_)));
    }

    #[test]
    fn catalog_negotiation_logs_and_revokes_on_violation() {
        let now = Instant::now();
        let tmp = TempDir::new().unwrap();
        let mut server = RaftRpcServer::new(identity_manager(now), MockHandler);
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

        let mut bad_frame = AppendEntriesRequest::heartbeat(4, "leader-y", 1)
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
}
