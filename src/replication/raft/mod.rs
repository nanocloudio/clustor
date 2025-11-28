//! Raft core utilities: quorum tracking, elections, durability ledger, etc.

pub mod append;
pub mod election;
pub mod quorum;
pub mod rpc;
#[cfg(feature = "async-net")]
pub mod runtime_scaffold;
pub mod stickiness;

pub use append::{AppendEntriesOutcome, AppendEntriesProcessor, HeartbeatBatcher};
pub use election::{
    CandidateState, ElectionController, ElectionProfile, ElectionTimer, HighRttState,
    PreVoteDecision, PreVoteRejectReason,
};

pub use quorum::{
    PartitionQuorum, PartitionQuorumConfig, PartitionQuorumStatus, QuorumError, ReplicaId,
    ReplicaProgress,
};

pub use rpc::{
    AppendEntriesFrameError, AppendEntriesRequest, AppendEntriesResponse, PreVoteResponse,
    PreVoteResponseFrameError, RequestVoteFrameError, RequestVoteRejectReason, RequestVoteRequest,
    RequestVoteResponse,
};
pub use stickiness::{
    DeviceLatencyConfig, LatencyGuardReason, LeaderStickinessConfig, LeaderStickinessController,
    LeaderStickinessGate, StickinessDecision, StickinessTelemetry,
};
