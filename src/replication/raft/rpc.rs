use crate::replication::consensus::RaftLogEntry;
use std::convert::TryInto;
use std::str::from_utf8;
use thiserror::Error;

const REQUEST_VOTE_VERSION: u8 = 2;
const REQUEST_VOTE_RESPONSE_VERSION: u8 = 1;
const APPEND_ENTRIES_VERSION: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaftRouting {
    pub partition_id: String,
    pub prg_id: String,
    pub routing_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingValidationError {
    PartitionMismatch {
        expected: String,
        observed: String,
    },
    PrgMismatch {
        expected: String,
        observed: String,
    },
    RoutingEpochMismatch {
        expected: u64,
        observed: u64,
    },
    MissingMetadata,
    UnknownPlacement {
        partition_id: String,
        prg_id: String,
        routing_epoch: u64,
    },
}

impl std::fmt::Display for RoutingValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingValidationError::PartitionMismatch { expected, observed } => write!(
                f,
                "partition mismatch (expected={expected}, observed={observed})"
            ),
            RoutingValidationError::PrgMismatch { expected, observed } => write!(
                f,
                "prg mismatch (expected={expected}, observed={observed})"
            ),
            RoutingValidationError::RoutingEpochMismatch { expected, observed } => write!(
                f,
                "routing_epoch mismatch (expected={expected}, observed={observed})"
            ),
            RoutingValidationError::MissingMetadata => write!(f, "routing metadata missing"),
            RoutingValidationError::UnknownPlacement {
                partition_id,
                prg_id,
                routing_epoch,
            } => write!(
                f,
                "unknown placement (partition_id={partition_id}, prg_id={prg_id}, routing_epoch={routing_epoch})"
            ),
        }
    }
}

impl RaftRouting {
    pub fn alias(partition_id: impl Into<String>, routing_epoch: u64) -> Self {
        let partition_id = partition_id.into();
        Self {
            prg_id: partition_id.clone(),
            partition_id,
            routing_epoch,
        }
    }

    pub fn validate(&self, expected: &RaftRouting) -> Result<(), RoutingValidationError> {
        if self.partition_id.is_empty()
            || self.prg_id.is_empty()
            || self.routing_epoch == 0
            || expected.routing_epoch == 0
        {
            return Err(RoutingValidationError::MissingMetadata);
        }
        if self.partition_id != expected.partition_id {
            return Err(RoutingValidationError::PartitionMismatch {
                expected: expected.partition_id.clone(),
                observed: self.partition_id.clone(),
            });
        }
        if self.prg_id != expected.prg_id {
            return Err(RoutingValidationError::PrgMismatch {
                expected: expected.prg_id.clone(),
                observed: self.prg_id.clone(),
            });
        }
        if self.routing_epoch != expected.routing_epoch {
            return Err(RoutingValidationError::RoutingEpochMismatch {
                expected: expected.routing_epoch,
                observed: self.routing_epoch,
            });
        }
        Ok(())
    }
}

fn read_u64_le<E, F>(bytes: &[u8], cursor: &mut usize, mut truncated: F) -> Result<u64, E>
where
    F: FnMut() -> E,
{
    if bytes.len() < *cursor + 8 {
        return Err(truncated());
    }
    let value = u64::from_le_bytes(
        bytes[*cursor..*cursor + 8]
            .try_into()
            .map_err(|_| truncated())?,
    );
    *cursor += 8;
    Ok(value)
}

fn read_u32_le<E, F>(bytes: &[u8], cursor: &mut usize, mut truncated: F) -> Result<u32, E>
where
    F: FnMut() -> E,
{
    if bytes.len() < *cursor + 4 {
        return Err(truncated());
    }
    let value = u32::from_le_bytes(
        bytes[*cursor..*cursor + 4]
            .try_into()
            .map_err(|_| truncated())?,
    );
    *cursor += 4;
    Ok(value)
}

fn read_u16_le<E, F>(bytes: &[u8], cursor: &mut usize, mut truncated: F) -> Result<u16, E>
where
    F: FnMut() -> E,
{
    if bytes.len() < *cursor + 2 {
        return Err(truncated());
    }
    let value = u16::from_le_bytes(
        bytes[*cursor..*cursor + 2]
            .try_into()
            .map_err(|_| truncated())?,
    );
    *cursor += 2;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestVoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
    pub pre_vote: bool,
    pub routing: RaftRouting,
}

impl RequestVoteRequest {
    pub fn encode(&self) -> Result<Vec<u8>, RequestVoteFrameError> {
        let candidate_bytes = self.candidate_id.as_bytes();
        if candidate_bytes.len() > u16::MAX as usize {
            return Err(RequestVoteFrameError::CandidateTooLong {
                len: candidate_bytes.len(),
            });
        }
        if self.routing.partition_id.is_empty()
            || self.routing.prg_id.is_empty()
            || self.routing.routing_epoch == 0
        {
            return Err(RequestVoteFrameError::MissingRoutingMetadata);
        }
        let partition_bytes = self.routing.partition_id.as_bytes();
        let prg_bytes = self.routing.prg_id.as_bytes();
        if partition_bytes.len() > u16::MAX as usize || prg_bytes.len() > u16::MAX as usize {
            return Err(RequestVoteFrameError::RoutingMetadataTooLong {
                partition_len: partition_bytes.len(),
                prg_len: prg_bytes.len(),
            });
        }
        let mut buf = Vec::with_capacity(
            64 + candidate_bytes.len() + partition_bytes.len() + prg_bytes.len(),
        );
        buf.push(REQUEST_VOTE_VERSION);
        buf.push(if self.pre_vote { 0x01 } else { 0x00 });
        buf.extend_from_slice(&self.routing.routing_epoch.to_le_bytes());
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.last_log_index.to_le_bytes());
        buf.extend_from_slice(&self.last_log_term.to_le_bytes());
        buf.extend_from_slice(&(candidate_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(partition_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(prg_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(candidate_bytes);
        buf.extend_from_slice(partition_bytes);
        buf.extend_from_slice(prg_bytes);
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RequestVoteFrameError> {
        if bytes.len() < 1 + 1 + 8 * 4 + 2 * 3 {
            return Err(RequestVoteFrameError::Truncated);
        }
        let version = bytes[0];
        if version != REQUEST_VOTE_VERSION {
            if version == 1 {
                return Err(RequestVoteFrameError::MissingRoutingMetadata);
            }
            return Err(RequestVoteFrameError::InvalidVersion {
                observed: version,
                expected: REQUEST_VOTE_VERSION,
            });
        }
        let flags = bytes[1];
        let mut cursor = 2;
        let routing_epoch = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let term = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let last_log_index = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let last_log_term = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let candidate_len =
            read_u16_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)? as usize;
        let partition_len =
            read_u16_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)? as usize;
        let prg_len =
            read_u16_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)? as usize;
        if bytes.len() < cursor + candidate_len + partition_len + prg_len {
            return Err(RequestVoteFrameError::Truncated);
        }
        let candidate = from_utf8(&bytes[cursor..cursor + candidate_len])
            .map_err(|_| RequestVoteFrameError::InvalidUtf8)?;
        cursor += candidate_len;
        let partition_id = from_utf8(&bytes[cursor..cursor + partition_len])
            .map_err(|_| RequestVoteFrameError::InvalidUtf8)?
            .to_string();
        cursor += partition_len;
        let prg_id = from_utf8(&bytes[cursor..cursor + prg_len])
            .map_err(|_| RequestVoteFrameError::InvalidUtf8)?
            .to_string();
        if partition_id.is_empty() || prg_id.is_empty() || routing_epoch == 0 {
            return Err(RequestVoteFrameError::MissingRoutingMetadata);
        }
        Ok(Self {
            term,
            candidate_id: candidate.to_string(),
            last_log_index,
            last_log_term,
            pre_vote: flags & 0x01 == 0x01,
            routing: RaftRouting {
                partition_id,
                prg_id,
                routing_epoch,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestVoteResponse {
    pub term: u64,
    pub granted: bool,
    pub reject_reason: Option<RequestVoteRejectReason>,
}

impl RequestVoteResponse {
    pub fn encode(&self) -> Result<Vec<u8>, RequestVoteFrameError> {
        if self.granted && self.reject_reason.is_some() {
            return Err(RequestVoteFrameError::InvalidCombination);
        }
        let mut buf = Vec::with_capacity(16);
        buf.push(REQUEST_VOTE_RESPONSE_VERSION);
        buf.push(if self.granted { 0x01 } else { 0x00 });
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.push(match self.reject_reason {
            Some(RequestVoteRejectReason::LogBehind) => 1,
            Some(RequestVoteRejectReason::TermOutOfDate) => 2,
            Some(RequestVoteRejectReason::NotLeaderEligible) => 3,
            None => 0,
        });
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RequestVoteFrameError> {
        if bytes.len() < 1 + 1 + 8 + 1 {
            return Err(RequestVoteFrameError::Truncated);
        }
        let version = bytes[0];
        if version != REQUEST_VOTE_RESPONSE_VERSION {
            return Err(RequestVoteFrameError::InvalidVersion {
                observed: version,
                expected: REQUEST_VOTE_RESPONSE_VERSION,
            });
        }
        let flags = bytes[1];
        let mut cursor = 2;
        let term = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let reason = match bytes[cursor] {
            0 => None,
            1 => Some(RequestVoteRejectReason::LogBehind),
            2 => Some(RequestVoteRejectReason::TermOutOfDate),
            3 => Some(RequestVoteRejectReason::NotLeaderEligible),
            other => {
                return Err(RequestVoteFrameError::UnknownRejectCode(other));
            }
        };
        let granted = flags & 0x01 == 0x01;
        if granted && reason.is_some() {
            return Err(RequestVoteFrameError::InvalidCombination);
        }
        Ok(Self {
            term,
            granted,
            reject_reason: reason,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestVoteRejectReason {
    LogBehind,
    TermOutOfDate,
    NotLeaderEligible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
    pub high_rtt: Option<bool>,
}

impl PreVoteResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(11);
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.push(if self.vote_granted { 1 } else { 0 });
        match self.high_rtt {
            Some(value) => {
                buf.push(1);
                buf.push(if value { 1 } else { 0 });
            }
            None => buf.push(0),
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PreVoteResponseFrameError> {
        if bytes.len() < 9 {
            return Err(PreVoteResponseFrameError::Truncated);
        }
        let mut cursor = 0;
        let term = read_u64_le(bytes, &mut cursor, || PreVoteResponseFrameError::Truncated)?;
        let vote_granted = bytes[cursor] != 0;
        cursor += 1;
        if bytes.len() == cursor {
            return Ok(Self {
                term,
                vote_granted,
                high_rtt: None,
            });
        }
        let has_high_rtt = bytes[cursor];
        cursor += 1;
        match has_high_rtt {
            0 => Ok(Self {
                term,
                vote_granted,
                high_rtt: None,
            }),
            1 => {
                if bytes.len() < cursor + 1 {
                    return Err(PreVoteResponseFrameError::Truncated);
                }
                let high_rtt = match bytes[cursor] {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(PreVoteResponseFrameError::InvalidHighRtt { value: other })
                    }
                };
                Ok(Self {
                    term,
                    vote_granted,
                    high_rtt: Some(high_rtt),
                })
            }
            other => Err(PreVoteResponseFrameError::InvalidHasHighRtt { value: other }),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PreVoteResponseFrameError {
    #[error("frame truncated")]
    Truncated,
    #[error("invalid has_high_rtt flag {value}")]
    InvalidHasHighRtt { value: u8 },
    #[error("invalid high_rtt value {value}")]
    InvalidHighRtt { value: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: String,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub leader_commit: u64,
    pub entries: Vec<RaftLogEntry>,
    pub routing: RaftRouting,
}

impl AppendEntriesRequest {
    pub fn heartbeat(
        term: u64,
        leader_id: impl Into<String>,
        leader_commit: u64,
        routing: RaftRouting,
    ) -> Self {
        Self {
            term,
            leader_id: leader_id.into(),
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit,
            entries: Vec::new(),
            routing,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, AppendEntriesFrameError> {
        let leader_bytes = self.leader_id.as_bytes();
        if leader_bytes.len() > u16::MAX as usize {
            return Err(AppendEntriesFrameError::LeaderIdTooLong {
                len: leader_bytes.len(),
            });
        }
        if self.entries.len() > u16::MAX as usize {
            return Err(AppendEntriesFrameError::TooManyEntries {
                count: self.entries.len(),
            });
        }
        let partition_bytes = self.routing.partition_id.as_bytes();
        let prg_bytes = self.routing.prg_id.as_bytes();
        if self.routing.partition_id.is_empty()
            || self.routing.prg_id.is_empty()
            || self.routing.routing_epoch == 0
        {
            return Err(AppendEntriesFrameError::MissingRoutingMetadata);
        }
        if partition_bytes.len() > u16::MAX as usize || prg_bytes.len() > u16::MAX as usize {
            return Err(AppendEntriesFrameError::RoutingMetadataTooLong {
                partition_len: partition_bytes.len(),
                prg_len: prg_bytes.len(),
            });
        }
        let mut buf =
            Vec::with_capacity(80 + leader_bytes.len() + partition_bytes.len() + prg_bytes.len());
        buf.push(APPEND_ENTRIES_VERSION);
        buf.push(0);
        buf.extend_from_slice(&self.routing.routing_epoch.to_le_bytes());
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.prev_log_index.to_le_bytes());
        buf.extend_from_slice(&self.prev_log_term.to_le_bytes());
        buf.extend_from_slice(&self.leader_commit.to_le_bytes());
        buf.extend_from_slice(&(leader_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(partition_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(prg_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(leader_bytes);
        buf.extend_from_slice(partition_bytes);
        buf.extend_from_slice(prg_bytes);
        buf.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.term.to_le_bytes());
            buf.extend_from_slice(&entry.index.to_le_bytes());
            if entry.payload.len() > u32::MAX as usize {
                return Err(AppendEntriesFrameError::PayloadTooLarge {
                    len: entry.payload.len(),
                });
            }
            buf.extend_from_slice(&(entry.payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&entry.payload);
        }
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AppendEntriesFrameError> {
        if bytes.len() < 1 + 1 + 8 * 5 + 2 * 4 {
            return Err(AppendEntriesFrameError::Truncated);
        }
        if bytes[0] != APPEND_ENTRIES_VERSION {
            if bytes[0] == 1 {
                return Err(AppendEntriesFrameError::MissingRoutingMetadata);
            }
            return Err(AppendEntriesFrameError::InvalidVersion {
                observed: bytes[0],
                expected: APPEND_ENTRIES_VERSION,
            });
        }
        let mut cursor = 2;
        let routing_epoch = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let prev_log_index =
            read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let prev_log_term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let leader_commit = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let leader_len =
            read_u16_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)? as usize;
        let partition_len =
            read_u16_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)? as usize;
        let prg_len =
            read_u16_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)? as usize;
        if bytes.len() < cursor + leader_len + partition_len + prg_len + 2 {
            return Err(AppendEntriesFrameError::Truncated);
        }
        let leader_id = from_utf8(&bytes[cursor..cursor + leader_len])
            .map_err(|_| AppendEntriesFrameError::InvalidUtf8)?
            .to_string();
        cursor += leader_len;
        let partition_id = from_utf8(&bytes[cursor..cursor + partition_len])
            .map_err(|_| AppendEntriesFrameError::InvalidUtf8)?
            .to_string();
        cursor += partition_len;
        let prg_id = from_utf8(&bytes[cursor..cursor + prg_len])
            .map_err(|_| AppendEntriesFrameError::InvalidUtf8)?
            .to_string();
        cursor += prg_len;
        if partition_id.is_empty() || prg_id.is_empty() || routing_epoch == 0 {
            return Err(AppendEntriesFrameError::MissingRoutingMetadata);
        }
        let entry_count =
            read_u16_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)? as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if bytes.len() < cursor + 8 * 2 + 4 {
                return Err(AppendEntriesFrameError::Truncated);
            }
            let term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
            let index = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
            let payload_len =
                read_u32_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)? as usize;
            if bytes.len() < cursor + payload_len {
                return Err(AppendEntriesFrameError::Truncated);
            }
            let payload = bytes[cursor..cursor + payload_len].to_vec();
            cursor += payload_len;
            entries.push(RaftLogEntry::new(term, index, payload));
        }
        Ok(Self {
            term,
            leader_id,
            prev_log_index,
            prev_log_term,
            leader_commit,
            entries,
            routing: RaftRouting {
                partition_id,
                prg_id,
                routing_epoch,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
    pub conflict_index: Option<u64>,
    pub conflict_term: Option<u64>,
}

impl AppendEntriesResponse {
    pub fn encode(&self) -> Result<Vec<u8>, AppendEntriesFrameError> {
        let mut buf = Vec::with_capacity(32);
        buf.push(APPEND_ENTRIES_VERSION);
        buf.push(if self.success { 0x01 } else { 0x00 });
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.match_index.to_le_bytes());
        buf.extend_from_slice(&self.conflict_index.unwrap_or(u64::MAX).to_le_bytes());
        buf.extend_from_slice(&self.conflict_term.unwrap_or(u64::MAX).to_le_bytes());
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AppendEntriesFrameError> {
        if bytes.len() < 1 + 1 + 8 * 4 {
            return Err(AppendEntriesFrameError::Truncated);
        }
        if bytes[0] != APPEND_ENTRIES_VERSION {
            return Err(AppendEntriesFrameError::InvalidVersion {
                observed: bytes[0],
                expected: APPEND_ENTRIES_VERSION,
            });
        }
        let success = bytes[1] & 0x01 == 0x01;
        let mut cursor = 2;
        let term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let match_index = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let conflict_index =
            read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let conflict_term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        Ok(Self {
            term,
            success,
            match_index,
            conflict_index: (conflict_index != u64::MAX).then_some(conflict_index),
            conflict_term: (conflict_term != u64::MAX).then_some(conflict_term),
        })
    }
}

#[derive(Debug, Error)]
pub enum RequestVoteFrameError {
    #[error("frame too short")]
    Truncated,
    #[error("unsupported version {observed} (expected {expected})")]
    InvalidVersion { observed: u8, expected: u8 },
    #[error("candidate id too long ({len} bytes)")]
    CandidateTooLong { len: usize },
    #[error("candidate id is not valid UTF-8")]
    InvalidUtf8,
    #[error("vote frame mixes granted and reject_reason values")]
    InvalidCombination,
    #[error("unknown reject code {0}")]
    UnknownRejectCode(u8),
    #[error("routing metadata missing")]
    MissingRoutingMetadata,
    #[error("routing metadata too long (partition {partition_len} bytes, prg {prg_len} bytes)")]
    RoutingMetadataTooLong {
        partition_len: usize,
        prg_len: usize,
    },
}

#[derive(Debug, Error)]
pub enum AppendEntriesFrameError {
    #[error("frame too short")]
    Truncated,
    #[error("unsupported version {observed} (expected {expected})")]
    InvalidVersion { observed: u8, expected: u8 },
    #[error("leader id too long ({len} bytes)")]
    LeaderIdTooLong { len: usize },
    #[error("payload exceeds u32 limit ({len} bytes)")]
    PayloadTooLarge { len: usize },
    #[error("too many entries ({count})")]
    TooManyEntries { count: usize },
    #[error("leader id is not valid UTF-8")]
    InvalidUtf8,
    #[error("routing metadata missing")]
    MissingRoutingMetadata,
    #[error("routing metadata too long (partition {partition_len} bytes, prg {prg_len} bytes)")]
    RoutingMetadataTooLong {
        partition_len: usize,
        prg_len: usize,
    },
}
