use clustor::replication::consensus::RaftLogEntry;
use clustor::replication::raft::rpc::{
    AppendEntriesRequest, AppendEntriesResponse, PreVoteResponse, RaftRouting,
    RequestVoteRejectReason, RequestVoteRequest, RequestVoteResponse,
};

#[test]
fn request_vote_round_trip() {
    let request = RequestVoteRequest {
        term: 5,
        candidate_id: "node-a".into(),
        last_log_index: 42,
        last_log_term: 4,
        pre_vote: true,
        routing: RaftRouting::alias("partition-a", 7),
    };
    let encoded = request.encode().unwrap();
    let decoded = RequestVoteRequest::decode(&encoded).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn response_round_trip() {
    let response = RequestVoteResponse {
        term: 6,
        granted: false,
        reject_reason: Some(RequestVoteRejectReason::LogBehind),
    };
    let encoded = response.encode().unwrap();
    let decoded = RequestVoteResponse::decode(&encoded).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn append_entries_round_trip() {
    let request = AppendEntriesRequest {
        term: 7,
        leader_id: "leader-1".into(),
        prev_log_index: 9,
        prev_log_term: 6,
        leader_commit: 8,
        entries: vec![
            RaftLogEntry::new(7, 10, b"cmd1".to_vec()),
            RaftLogEntry::new(7, 11, b"cmd2".to_vec()),
        ],
        routing: RaftRouting::alias("partition-a", 9),
    };
    let encoded = request.encode().unwrap();
    let decoded = AppendEntriesRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.leader_id, "leader-1");
    assert_eq!(decoded.entries.len(), 2);
    assert_eq!(decoded.entries[1].payload, b"cmd2");
}

#[test]
fn append_entries_response_round_trip() {
    let response = AppendEntriesResponse {
        term: 8,
        success: true,
        match_index: 42,
        conflict_index: None,
        conflict_term: None,
    };
    let encoded = response.encode().unwrap();
    let decoded = AppendEntriesResponse::decode(&encoded).unwrap();
    assert!(decoded.success);
    assert_eq!(decoded.match_index, 42);
}

#[test]
fn prevote_response_matches_spec_vector() {
    let response = PreVoteResponse {
        term: 42,
        vote_granted: true,
        high_rtt: Some(true),
    };
    let encoded = response.encode();
    assert_eq!(
        encoded,
        vec![0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01]
    );
    let decoded = PreVoteResponse::decode(&encoded).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn prevote_response_legacy_frame_decodes_without_high_rtt() {
    let legacy = vec![0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let decoded = PreVoteResponse::decode(&legacy).unwrap();
    assert_eq!(decoded.term, 42);
    assert!(!decoded.vote_granted);
    assert!(decoded.high_rtt.is_none());
}
