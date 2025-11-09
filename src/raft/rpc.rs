use crate::consensus::RaftLogEntry;
use std::convert::TryInto;
use std::str::from_utf8;
use thiserror::Error;

const REQUEST_VOTE_VERSION: u8 = 1;
const REQUEST_VOTE_RESPONSE_VERSION: u8 = 1;
const APPEND_ENTRIES_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestVoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
    pub pre_vote: bool,
}

impl RequestVoteRequest {
    pub fn encode(&self) -> Result<Vec<u8>, RequestVoteFrameError> {
        let candidate_bytes = self.candidate_id.as_bytes();
        if candidate_bytes.len() > u16::MAX as usize {
            return Err(RequestVoteFrameError::CandidateTooLong {
                len: candidate_bytes.len(),
            });
        }
        let mut buf = Vec::with_capacity(32 + candidate_bytes.len());
        buf.push(REQUEST_VOTE_VERSION);
        buf.push(if self.pre_vote { 0x01 } else { 0x00 });
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.last_log_index.to_le_bytes());
        buf.extend_from_slice(&self.last_log_term.to_le_bytes());
        buf.extend_from_slice(&(candidate_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(candidate_bytes);
        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RequestVoteFrameError> {
        if bytes.len() < 1 + 1 + 8 * 3 + 2 {
            return Err(RequestVoteFrameError::Truncated);
        }
        let version = bytes[0];
        if version != REQUEST_VOTE_VERSION {
            return Err(RequestVoteFrameError::InvalidVersion {
                observed: version,
                expected: REQUEST_VOTE_VERSION,
            });
        }
        let flags = bytes[1];
        let mut cursor = 2;
        let term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let last_log_index = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let last_log_term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let candidate_len =
            u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if bytes.len() < cursor + candidate_len {
            return Err(RequestVoteFrameError::Truncated);
        }
        let candidate = from_utf8(&bytes[cursor..cursor + candidate_len])
            .map_err(|_| RequestVoteFrameError::InvalidUtf8)?;
        Ok(Self {
            term,
            candidate_id: candidate.to_string(),
            last_log_index,
            last_log_term,
            pre_vote: flags & 0x01 == 0x01,
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
        let term = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        let reason = match bytes[10] {
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
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: String,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub leader_commit: u64,
    pub entries: Vec<RaftLogEntry>,
}

impl AppendEntriesRequest {
    pub fn heartbeat(term: u64, leader_id: impl Into<String>, leader_commit: u64) -> Self {
        Self {
            term,
            leader_id: leader_id.into(),
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit,
            entries: Vec::new(),
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
        let mut buf = Vec::with_capacity(64 + leader_bytes.len());
        buf.push(APPEND_ENTRIES_VERSION);
        buf.push(0);
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.prev_log_index.to_le_bytes());
        buf.extend_from_slice(&self.prev_log_term.to_le_bytes());
        buf.extend_from_slice(&self.leader_commit.to_le_bytes());
        buf.extend_from_slice(&(leader_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(leader_bytes);
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
        if bytes.len() < 1 + 1 + 8 * 4 + 2 {
            return Err(AppendEntriesFrameError::Truncated);
        }
        if bytes[0] != APPEND_ENTRIES_VERSION {
            return Err(AppendEntriesFrameError::InvalidVersion {
                observed: bytes[0],
                expected: APPEND_ENTRIES_VERSION,
            });
        }
        let mut cursor = 2;
        let term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let prev_log_index = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let prev_log_term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let leader_commit = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let leader_len = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        if bytes.len() < cursor + leader_len + 2 {
            return Err(AppendEntriesFrameError::Truncated);
        }
        let leader_id = from_utf8(&bytes[cursor..cursor + leader_len])
            .map_err(|_| AppendEntriesFrameError::InvalidUtf8)?
            .to_string();
        cursor += leader_len;
        let entry_count =
            u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if bytes.len() < cursor + 8 * 2 + 4 {
                return Err(AppendEntriesFrameError::Truncated);
            }
            let term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            let index = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            let payload_len =
                u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
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
        let term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let match_index = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let conflict_index = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let conflict_term = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_vote_round_trip() {
        let request = RequestVoteRequest {
            term: 5,
            candidate_id: "node-a".into(),
            last_log_index: 42,
            last_log_term: 4,
            pre_vote: true,
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
}
