use clustor::replication::consensus::CatalogVersion;
use clustor::replication::raft::{
    AppendEntriesRequest, RaftRouting, RequestVoteRequest, RequestVoteResponse,
    RoutingValidationError,
};
use clustor::replication::transport::raft::{RaftRpcHandler, RaftRpcServer, RaftTransportError};
use clustor::replication::transport::{
    BundleNegotiationEntry, BundleNegotiationLog, CatalogNegotiationConfig,
};
use clustor::security::{Certificate, MtlsIdentityManager, SerialNumber, SpiffeId};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
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

    fn on_append_entries(
        &mut self,
        request: AppendEntriesRequest,
    ) -> clustor::replication::raft::AppendEntriesResponse {
        clustor::replication::raft::AppendEntriesResponse {
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

    fn on_append_entries(
        &mut self,
        _request: AppendEntriesRequest,
    ) -> clustor::replication::raft::AppendEntriesResponse {
        clustor::replication::raft::AppendEntriesResponse {
            term: self.tag,
            success: true,
            match_index: self.tag,
            conflict_index: None,
            conflict_term: None,
        }
    }
}

fn routing(epoch: u64) -> RaftRouting {
    RaftRouting::alias("partition-test", epoch)
}

fn routing_for(partition: &str, epoch: u64) -> RaftRouting {
    RaftRouting::alias(partition.to_string(), epoch)
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

fn load_entries(log: &BundleNegotiationLog) -> Vec<BundleNegotiationEntry> {
    read_entries(log.path())
}

fn read_entries(path: &Path) -> Vec<BundleNegotiationEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let contents = fs::read_to_string(path).expect("log readable");
    contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("entry decodes"))
        .collect()
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
    let entries = load_entries(&log);
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
    let entries = load_entries(&log);
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
