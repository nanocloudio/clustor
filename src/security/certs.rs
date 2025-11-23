use super::errors::SecurityError;
use std::time::Instant;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct SerialNumber(Vec<u8>);

impl SerialNumber {
    pub const MAX_LEN: usize = 20;

    pub fn from_u64(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        Self::from_be_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn from_be_bytes(raw: &[u8]) -> Self {
        let mut first_non_zero = 0;
        while first_non_zero < raw.len().saturating_sub(1) && raw[first_non_zero] == 0 {
            first_non_zero += 1;
        }
        let slice = &raw[first_non_zero..];
        if slice.is_empty() {
            SerialNumber(vec![0])
        } else {
            SerialNumber(slice.to_vec())
        }
    }
}

pub(crate) fn serial_hex(serial: &SerialNumber) -> String {
    hex::encode(serial.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeId {
    pub fn parse(id: &str) -> Result<Self, SecurityError> {
        let trimmed = id
            .strip_prefix("spiffe://")
            .ok_or_else(|| SecurityError::InvalidSpiffeId(id.to_string()))?;
        let mut parts = trimmed.splitn(2, '/');
        let trust_domain = parts
            .next()
            .ok_or_else(|| SecurityError::InvalidSpiffeId(id.to_string()))?;
        let path = parts
            .next()
            .ok_or_else(|| SecurityError::InvalidSpiffeId(id.to_string()))?;
        Ok(Self {
            trust_domain: trust_domain.to_string(),
            path: format!("/{path}"),
        })
    }

    pub fn canonical(&self) -> String {
        format!("spiffe://{}{}", self.trust_domain, self.path)
    }
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub spiffe_id: SpiffeId,
    pub serial: SerialNumber,
    pub valid_from: Instant,
    pub valid_until: Instant,
}
