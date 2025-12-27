use clustor::security::{Certificate, MtlsIdentityManager, SerialNumber, SpiffeId};
use clustor::{
    AppendEntriesProcessor, AppendEntriesRequest, AppendEntriesResponse, BundleNegotiationEntry,
    CatalogNegotiationConfig, CatalogVersion, RaftLogEntry, RaftLogStore, RaftRouting,
    RaftRpcHandler, RaftRpcServer, RaftTransportError, RequestVoteRequest, RequestVoteResponse,
    SystemLogEntry, SystemLogError,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn read_entries(path: &Path) -> Vec<BundleNegotiationEntry> {
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid log entry"))
        .collect()
}

fn dataset_and_config(partition: &str) -> (tempfile::TempDir, PathBuf, CatalogNegotiationConfig) {
    let dir = tempdir().unwrap();
    let dataset = dir.path().join("dataset");
    std::fs::create_dir_all(&dataset).unwrap();
    let config = CatalogNegotiationConfig {
        partition_id: partition.into(),
        log_path: PathBuf::from("wire/bundle_negotiation.log"),
        remote_version: CatalogVersion::new(0, 1, 1),
    };
    (dir, dataset, config)
}

fn routing(partition: &str, epoch: u64) -> RaftRouting {
    RaftRouting::alias(partition.to_string(), epoch)
}

#[test]
fn transport_negotiation_persists_handshake_log() {
    let (_tmp, dataset, config) = dataset_and_config("partition-hs");
    let report = config
        .negotiate(&dataset, CatalogVersion::new(0, 1, 2))
        .expect("handshake succeeds");
    let entries = read_entries(report.log_path());
    assert_eq!(entries.len(), 1);
    assert!(entries[0].accepted);
    assert!(report.log_path().ends_with("bundle_negotiation.log"));
}

#[test]
fn transport_revokes_forward_tolerance_on_unknown_field() {
    let (_tmp, dataset, config) = dataset_and_config("partition-revoke");
    let mut report = config
        .negotiate(&dataset, CatalogVersion::new(0, 1, 2))
        .expect("handshake succeeds");
    assert!(report.forward_tolerance_active());
    let revoked = report
        .note_unknown_field("DurabilityAck.extra_tail_bytes")
        .expect("revocation recorded");
    assert!(revoked);
    assert!(!report.forward_tolerance_active());
    let entries = read_entries(report.log_path());
    assert_eq!(entries.len(), 2);
    assert!(!entries[1].accepted);
    assert!(entries[1]
        .reason
        .as_deref()
        .unwrap()
        .contains("unknown field"));
}

#[test]
fn transport_unknown_field_noops_without_forward_tolerance() {
    let (_tmp, dataset, config) = dataset_and_config("partition-noop");
    let mut report = config
        .negotiate(&dataset, CatalogVersion::new(0, 1, 1))
        .expect("handshake succeeds");
    assert!(!report.forward_tolerance_active());
    let revoked = report
        .note_unknown_field("DurabilityAck.extra_tail_bytes")
        .expect("note succeeds");
    assert!(!revoked);
    let entries = read_entries(report.log_path());
    assert_eq!(entries.len(), 1);
}

#[test]
fn system_log_decode_revokes_forward_tolerance_on_unknown_entry() {
    let (_tmp, dataset, config) = dataset_and_config("partition-system-log");
    let mut report = config
        .negotiate(&dataset, CatalogVersion::new(0, 1, 2))
        .expect("handshake succeeds");
    assert!(report.forward_tolerance_active());
    let err = SystemLogEntry::decode_with_report(&[0x09], &mut report)
        .expect_err("unknown wire id should fail");
    assert!(matches!(err, SystemLogError::UnknownWireId(_)));
    assert!(!report.forward_tolerance_active());
    let entries = read_entries(report.log_path());
    assert_eq!(entries.len(), 2);
    assert!(entries[1].reason.as_deref().unwrap().contains("system_log"));
}

#[test]
fn raft_transport_replication_and_revocation_checkpoint() {
    let now = Instant::now();
    let client = certificate("spiffe://example.org/clients/follower", 7, now);

    let partition_id = "partition-replica";
    let (_tmp1, dataset1, config1) = dataset_and_config(partition_id);
    let log1 = dataset1.join("raft.log");
    let handler1 = ReplicaHandler::new(&log1);
    let server1 = RaftRpcServer::new(identity_manager(now), handler1, routing(partition_id, 4));
    server1
        .negotiate_catalog(&dataset1, &config1, CatalogVersion::new(0, 1, 2))
        .unwrap();

    let append = AppendEntriesRequest {
        term: 4,
        leader_id: "leader-a".into(),
        prev_log_index: 0,
        prev_log_term: 0,
        leader_commit: 0,
        entries: vec![
            RaftLogEntry::new(4, 1, b"cmd1".to_vec()),
            RaftLogEntry::new(4, 2, b"cmd2".to_vec()),
        ],
        routing: routing(partition_id, 4),
    };
    let frame = append.encode().unwrap();
    server1
        .handle_append_entries(&client, &frame, now)
        .expect("replication succeeds");
    drop(server1);
    let follower_log = RaftLogStore::open(&log1).unwrap();
    assert_eq!(follower_log.last_index(), 2);

    let (_tmp2, dataset2, config2) = dataset_and_config(partition_id);
    let log2 = dataset2.join("raft.log");
    let handler2 = ReplicaHandler::new(&log2);
    let server2 = RaftRpcServer::new(identity_manager(now), handler2, routing(partition_id, 4));
    server2
        .negotiate_catalog(&dataset2, &config2, CatalogVersion::new(0, 1, 2))
        .unwrap();
    let mut bad_frame = frame.clone();
    bad_frame[0] = 9;
    let err = server2
        .handle_append_entries(&client, &bad_frame, now)
        .expect_err("unknown version triggers revocation");
    assert!(matches!(err, RaftTransportError::AppendEntriesFrame(_)));
    drop(server2);
    let entries = read_entries(&config2.resolved_log_path(&dataset2));
    assert_eq!(entries.len(), 2);
    assert!(entries
        .last()
        .unwrap()
        .reason
        .as_deref()
        .unwrap()
        .contains("append_entries.version"));
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

struct ReplicaHandler {
    log: RaftLogStore,
}

impl ReplicaHandler {
    fn new(path: &Path) -> Self {
        Self {
            log: RaftLogStore::open(path).unwrap(),
        }
    }
}

impl RaftRpcHandler for ReplicaHandler {
    fn on_request_vote(&mut self, request: RequestVoteRequest) -> RequestVoteResponse {
        RequestVoteResponse {
            term: request.term,
            granted: true,
            reject_reason: None,
        }
    }

    fn on_append_entries(&mut self, request: AppendEntriesRequest) -> AppendEntriesResponse {
        let mut processor = AppendEntriesProcessor::new(&mut self.log);
        let outcome = processor
            .apply(&request)
            .expect("append entries processing succeeds");
        AppendEntriesResponse {
            term: request.term,
            success: outcome.success,
            match_index: outcome.match_index,
            conflict_index: outcome.conflict_index,
            conflict_term: outcome.conflict_term,
        }
    }
}
