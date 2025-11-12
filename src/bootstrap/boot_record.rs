use crate::bootstrap::filesystem::{OrderedFilesystemProfile, RejectionReason};
use crate::bootstrap::probe::FsyncProbeResult;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BootRecord {
    #[serde(default)]
    pub fsync_probe: Option<FsyncProbeResult>,
    #[serde(default)]
    pub disk_policy: Option<DiskPolicyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskPolicyRecord {
    pub profile: Option<OrderedFilesystemProfile>,
    pub rejections: Vec<RejectionReason>,
    pub evaluated_at_ms: u64,
}

#[derive(Debug)]
pub struct BootRecordStore {
    path: PathBuf,
}

impl BootRecordStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_or_default(&self) -> Result<BootRecord, BootRecordError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(BootRecord::default()),
            Err(err) => Err(BootRecordError::Io(err)),
        }
    }

    pub fn persist(&self, record: &BootRecord) -> Result<(), BootRecordError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let tmp_path = self.path.with_extension("tmp");
        let mut tmp_file = fs::File::create(&tmp_path)?;
        let payload = serde_json::to_vec_pretty(record)?;
        tmp_file.write_all(&payload)?;
        tmp_file.sync_all()?;
        fs::rename(tmp_path, &self.path)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BootRecordError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
