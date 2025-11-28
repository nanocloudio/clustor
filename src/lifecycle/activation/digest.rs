use crate::util::error::SerializationError;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::state::WarmupReadinessRecord;

#[derive(Debug, Error)]
pub enum ActivationDigestError {
    #[error(transparent)]
    Serialization(#[from] SerializationError),
}

pub fn readiness_digest(
    records: &[WarmupReadinessRecord],
) -> Result<String, ActivationDigestError> {
    let mut builder = ReadinessDigestBuilder::with_capacity(records.len());
    for record in records {
        builder.add(record)?;
    }
    builder.finish()
}

#[derive(Default)]
pub struct ReadinessDigestBuilder {
    entries: Vec<String>,
}

impl ReadinessDigestBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    pub fn add(&mut self, record: &WarmupReadinessRecord) -> Result<(), ActivationDigestError> {
        let payload = serde_json::json!({
            "partition": record.partition_id,
            "bundle": record.bundle_id,
            "state": record.shadow_apply_state.as_str(),
            "checkpoint": record.shadow_apply_checkpoint_index,
            "ratio": (record.warmup_ready_ratio * 10_000.0).round() as i64,
            "updated_at_ms": record.updated_at_ms,
        });
        let encoded_line = serde_json::to_string(&payload).map_err(SerializationError::from)?;
        self.entries.push(encoded_line);
        Ok(())
    }

    pub fn finish(mut self) -> Result<String, ActivationDigestError> {
        if self.entries.is_empty() {
            return Ok("0x0".into());
        }
        self.entries.sort();
        let joined = self.entries.join("|");
        Ok(format!(
            "0x{}",
            hex::encode(Sha256::digest(joined.as_bytes()))
        ))
    }
}
