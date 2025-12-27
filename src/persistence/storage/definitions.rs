use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct DefinitionBundle {
    pub bundle_id: String,
    pub version: u64,
    pub sha256: String,
    pub emit_version: String,
    pub definition_blob: Vec<u8>,
    pub warmup_recipe: String,
    pub emitted_at_ms: u64,
}

#[derive(Debug)]
pub struct DefinitionBundleStore {
    dir: PathBuf,
    emit_version: String,
    retain: usize,
    history: VecDeque<String>,
}

impl DefinitionBundleStore {
    pub fn new(
        dir: impl Into<PathBuf>,
        emit_version: impl Into<String>,
    ) -> Result<Self, DefinitionBundleError> {
        Self::with_retention(dir, emit_version, 2)
    }

    pub fn with_retention(
        dir: impl Into<PathBuf>,
        emit_version: impl Into<String>,
        retain: usize,
    ) -> Result<Self, DefinitionBundleError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let retain = retain.max(1);
        let mut store = Self {
            dir,
            emit_version: emit_version.into(),
            retain,
            history: VecDeque::new(),
        };
        store.history = store.load_history()?;
        store.prune_excess()?;
        Ok(store)
    }

    pub fn stage(&mut self, bundle: &DefinitionBundle) -> Result<PathBuf, DefinitionBundleError> {
        self.validate_bundle(bundle)?;
        let path = self.dir.join(format!("{}.blob", bundle.bundle_id));
        if path.exists() {
            return Err(DefinitionBundleError::DuplicateBundle {
                bundle_id: bundle.bundle_id.clone(),
            });
        }
        let tmp_path = path.with_extension("blob.tmp");
        let mut file = File::create(&tmp_path)?;
        file.write_all(&bundle.definition_blob)?;
        file.sync_all()?;
        fs::rename(&tmp_path, &path)?;
        self.history.push_back(bundle.bundle_id.clone());
        self.prune_excess()?;
        Ok(path)
    }

    pub fn retained_bundles(&self) -> Vec<String> {
        self.history.iter().cloned().collect()
    }

    fn validate_bundle(&self, bundle: &DefinitionBundle) -> Result<(), DefinitionBundleError> {
        if bundle.emit_version != self.emit_version {
            return Err(DefinitionBundleError::EmitVersionMismatch {
                expected: self.emit_version.clone(),
                observed: bundle.emit_version.clone(),
            });
        }
        let computed = format!("0x{}", hex::encode(Sha256::digest(&bundle.definition_blob)));
        if normalize_digest(&computed) != normalize_digest(&bundle.sha256) {
            return Err(DefinitionBundleError::DigestMismatch {
                expected: bundle.sha256.clone(),
                observed: computed,
            });
        }
        Ok(())
    }

    fn prune_excess(&mut self) -> Result<(), DefinitionBundleError> {
        while self.history.len() > self.retain {
            if let Some(oldest) = self.history.pop_front() {
                let path = self.dir.join(format!("{oldest}.blob"));
                if let Err(err) = fs::remove_file(&path) {
                    if err.kind() != io::ErrorKind::NotFound {
                        return Err(DefinitionBundleError::Io(err));
                    }
                }
            }
        }
        Ok(())
    }

    fn load_history(&self) -> Result<VecDeque<String>, DefinitionBundleError> {
        if !self.dir.exists() {
            return Ok(VecDeque::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("blob") {
                continue;
            }
            let bundle_id = match path.file_stem().and_then(|s| s.to_str()) {
                Some(stem) => stem.to_string(),
                None => continue,
            };
            let modified = entry
                .metadata()?
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            entries.push((modified, bundle_id));
        }
        entries.sort_by_key(|(modified, _)| *modified);
        let mut history = VecDeque::new();
        for (_, bundle_id) in entries {
            history.push_back(bundle_id);
        }
        Ok(history)
    }
}

#[derive(Debug, Error)]
pub enum DefinitionBundleError {
    #[error("emit version mismatch: expected {expected}, observed {observed}")]
    EmitVersionMismatch { expected: String, observed: String },
    #[error("definition bundle sha256 mismatch: expected {expected}, observed {observed}")]
    DigestMismatch { expected: String, observed: String },
    #[error("definition bundle {bundle_id} already staged")]
    DuplicateBundle { bundle_id: String },
    #[error(transparent)]
    Io(#[from] io::Error),
}

fn normalize_digest(input: &str) -> String {
    let trimmed = input.trim();
    let lower = trimmed.trim_start_matches("0x").trim_start_matches("0X");
    lower.to_ascii_lowercase()
}
