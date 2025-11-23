use crate::overrides::{DiskOverrideDocument, OverrideError};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OverrideType {
    Disk,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideStatus {
    pub override_id: String,
    pub override_type: OverrideType,
    pub ticket_url: String,
    pub attested_by: String,
    pub expires_at_ms: u64,
    pub active: bool,
}

impl OverrideStatus {
    pub fn from_disk_override(
        document: &DiskOverrideDocument,
        now_ms: u64,
    ) -> Result<Self, OverrideError> {
        let expires_at_ms = document.expiration_epoch_ms()?;
        Ok(Self {
            override_id: document.override_id.clone(),
            override_type: OverrideType::Disk,
            ticket_url: document.ticket_url.clone(),
            attested_by: document.attested_by.clone(),
            expires_at_ms,
            active: expires_at_ms > now_ms,
        })
    }
}
