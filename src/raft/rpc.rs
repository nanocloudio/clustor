use crate::consensus::RaftLogEntry;
use std::convert::TryInto;
use std::str::from_utf8;
use thiserror::Error;

const REQUEST_VOTE_VERSION: u8 = 1;
const REQUEST_VOTE_RESPONSE_VERSION: u8 = 1;
const APPEND_ENTRIES_VERSION: u8 = 1;

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
        let term = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let last_log_index = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let last_log_term = read_u64_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)?;
        let candidate_len =
            read_u16_le(bytes, &mut cursor, || RequestVoteFrameError::Truncated)? as usize;
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
        let term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let prev_log_index =
            read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let prev_log_term = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let leader_commit = read_u64_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)?;
        let leader_len =
            read_u16_le(bytes, &mut cursor, || AppendEntriesFrameError::Truncated)? as usize;
        if bytes.len() < cursor + leader_len + 2 {
            return Err(AppendEntriesFrameError::Truncated);
        }
        let leader_id = from_utf8(&bytes[cursor..cursor + leader_len])
            .map_err(|_| AppendEntriesFrameError::InvalidUtf8)?
            .to_string();
        cursor += leader_len;
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
}
