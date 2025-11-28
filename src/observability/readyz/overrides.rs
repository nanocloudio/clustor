use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Canonical representation of the `disk_override` object described in
/// `docs/specification.md` §10.1 and §13. The document is transported as JSON
/// but validated locally before being trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskOverrideDocument {
    pub override_id: String,
    pub devices: Vec<DiskOverrideDevice>,
    pub stack_diagram: String,
    pub attested_by: String,
    pub ticket_url: String,
    pub expires_at_ms: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskOverrideDevice {
    pub sys_path: String,
    pub serial: String,
    #[serde(rename = "queue")]
    pub queue_flags: QueueFlags,
    pub write_cache: DiskWriteCacheMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueFlags {
    pub flush: bool,
    pub fua: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskWriteCacheMode {
    WriteThrough,
    WriteBack,
}

impl DiskWriteCacheMode {
    fn as_str(&self) -> &'static str {
        match self {
            DiskWriteCacheMode::WriteThrough => "write through",
            DiskWriteCacheMode::WriteBack => "write back",
        }
    }

    fn parse(value: &str) -> Result<Self, OverrideError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "write through" | "write_through" | "through" => Ok(Self::WriteThrough),
            "write back" | "write_back" | "back" => Ok(Self::WriteBack),
            other => Err(OverrideError::InvalidField {
                field: "write_cache",
                reason: format!("unsupported policy `{other}`"),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for DiskWriteCacheMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        DiskWriteCacheMode::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for DiskWriteCacheMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl DiskOverrideDocument {
    /// Parses a document from disk and performs schema validation.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, OverrideError> {
        let data = fs::read(path)?;
        let doc: DiskOverrideDocument = serde_json::from_slice(&data)?;
        Ok(doc)
    }

    pub fn load_and_validate(path: impl AsRef<Path>, now_ms: u64) -> Result<Self, OverrideError> {
        let doc = Self::load(path)?;
        doc.validate(now_ms)?;
        Ok(doc)
    }

    /// Attempts to parse a document from raw bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, OverrideError> {
        let doc: DiskOverrideDocument = serde_json::from_slice(bytes)?;
        Ok(doc)
    }

    /// Returns the parsed expiration timestamp (milliseconds since epoch).
    pub fn expiration_epoch_ms(&self) -> Result<u64, OverrideError> {
        self.expires_at_ms
            .trim()
            .parse::<u64>()
            .map_err(|_| OverrideError::InvalidField {
                field: "expires_at_ms",
                reason: "must be an unsigned integer string".into(),
            })
    }

    /// Returns true when the override remains valid at the provided clock.
    pub fn is_active(&self, now_ms: u64) -> Result<bool, OverrideError> {
        Ok(self.expiration_epoch_ms()? > now_ms)
    }

    /// Validates the document against the schema and TTL rules.
    pub fn validate(&self, now_ms: u64) -> Result<(), OverrideError> {
        if self.override_id.trim().is_empty() {
            return Err(OverrideError::InvalidField {
                field: "override_id",
                reason: "value required".into(),
            });
        }
        if self.devices.is_empty() {
            return Err(OverrideError::InvalidField {
                field: "devices",
                reason: "at least one device required".into(),
            });
        }
        if self.stack_diagram.trim().is_empty() {
            return Err(OverrideError::InvalidField {
                field: "stack_diagram",
                reason: "value required".into(),
            });
        }
        if self.attested_by.trim().is_empty() {
            return Err(OverrideError::InvalidField {
                field: "attested_by",
                reason: "value required".into(),
            });
        }
        if self.ticket_url.trim().is_empty() {
            return Err(OverrideError::InvalidField {
                field: "ticket_url",
                reason: "value required".into(),
            });
        }
        for device in &self.devices {
            device.validate()?;
        }
        let expires = self.expiration_epoch_ms()?;
        if expires <= now_ms {
            return Err(OverrideError::Expired {
                expires_at_ms: expires,
                now_ms,
            });
        }
        Ok(())
    }
}

impl DiskOverrideDevice {
    fn validate(&self) -> Result<(), OverrideError> {
        if self.sys_path.trim().is_empty() {
            return Err(OverrideError::InvalidField {
                field: "devices[].sys_path",
                reason: "value required".into(),
            });
        }
        if !self.sys_path.starts_with("/sys/block/") {
            return Err(OverrideError::InvalidField {
                field: "devices[].sys_path",
                reason: "must start with /sys/block/".into(),
            });
        }
        if self.serial.trim().is_empty() {
            return Err(OverrideError::InvalidField {
                field: "devices[].serial",
                reason: "value required".into(),
            });
        }
        // write_cache already validated by the enum parser.
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OverrideError {
    #[error("override file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("override serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid override field {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("override expired at {expires_at_ms} ms (now {now_ms} ms)")]
    Expired { expires_at_ms: u64, now_ms: u64 },
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_document(expires_at_ms: u64) -> DiskOverrideDocument {
        DiskOverrideDocument {
            override_id: "ovr-1234".into(),
            devices: vec![DiskOverrideDevice {
                sys_path: "/sys/block/nvme0n1".into(),
                serial: "nvme-001".into(),
                queue_flags: QueueFlags {
                    flush: true,
                    fua: true,
                },
                write_cache: DiskWriteCacheMode::WriteThrough,
            }],
            stack_diagram: "dm-crypt -> mdraid -> nvme0n1".into(),
            attested_by: "operator@example.com".into(),
            ticket_url: "https://tickets/1234".into(),
            expires_at_ms: expires_at_ms.to_string(),
        }
    }

    #[test]
    fn disk_override_validates_schema() {
        let doc = sample_document(1_000_000);
        assert!(doc.validate(10).is_ok());
        assert!(doc.is_active(10).unwrap());
    }

    #[test]
    fn disk_override_rejects_bad_inputs() {
        let mut doc = sample_document(100);
        assert!(matches!(
            doc.validate(500),
            Err(OverrideError::Expired { .. })
        ));
        doc.devices[0].sys_path = "nvme0n1".into();
        let err = doc.validate(1).unwrap_err();
        assert!(matches!(
            err,
            OverrideError::InvalidField {
                field: "devices[].sys_path",
                ..
            }
        ));
    }

    #[test]
    fn disk_override_rejects_invalid_expiration() {
        let mut doc = sample_document(1_000);
        doc.expires_at_ms = "invalid".into();
        assert!(matches!(
            doc.expiration_epoch_ms(),
            Err(OverrideError::InvalidField { field, .. }) if field == "expires_at_ms"
        ));
        assert!(doc.validate(0).is_err());
    }
}
