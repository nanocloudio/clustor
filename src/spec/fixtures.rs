use crate::feature_guard::FeatureGateTelemetryEntry;
use crate::replication::consensus::{
    CatalogVersion, ConsensusCoreManifest, ConsensusCoreManifestBuilder,
    ConsensusCoreManifestError, ProofBundleRef,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureEntry {
    pub name: String,
    pub description: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureBundle {
    pub schema_version: u32,
    pub generated_at_ms: u64,
    pub entries: Vec<FixtureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireCatalogArtifact {
    pub schema_version: u32,
    pub messages: Vec<String>,
    pub clause_coverage_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkedListSchemaArtifact {
    pub schema_version: u32,
    pub rules: Vec<String>,
    pub clause_coverage_hash: String,
}

#[derive(Debug, Clone)]
pub struct ClauseCoverageReport {
    pub clauses_tagged: usize,
    pub paragraphs: usize,
    pub clause_coverage_hash: String,
}

impl ClauseCoverageReport {
    pub fn hash(&self) -> &str {
        &self.clause_coverage_hash
    }
}

#[derive(Debug, Clone)]
pub struct TermDefinition {
    pub term_id: String,
    pub canonical: String,
    pub synonyms: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct TermRegistry {
    map: HashMap<String, TermDefinition>,
}

impl TermRegistry {
    fn new(definitions: Vec<TermDefinition>) -> Self {
        let mut map = HashMap::new();
        for def in definitions {
            map.insert(def.canonical.to_string(), def);
        }
        Self { map }
    }

    pub fn term_id(&self, canonical: &str) -> Option<&str> {
        self.map.get(canonical).map(|def| def.term_id.as_str())
    }

    pub fn definitions(&self) -> impl Iterator<Item = &TermDefinition> {
        self.map.values()
    }
}

pub struct FixtureBundleGenerator;

impl FixtureBundleGenerator {
    pub fn generate(
        entries: Vec<FixtureEntry>,
        output: impl AsRef<Path>,
    ) -> Result<FixtureBundle, FixtureError> {
        if entries.is_empty() {
            return Err(FixtureError::EmptyBundle);
        }
        let bundle = FixtureBundle {
            schema_version: 1,
            generated_at_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            entries,
        };
        let payload = serde_json::to_vec_pretty(&bundle)?;
        fs::write(output, payload)?;
        Ok(bundle)
    }
}

pub struct SpecLint;

impl SpecLint {
    pub fn validate_bundle(
        bundle: &FixtureBundle,
        spec_path: impl AsRef<Path>,
    ) -> Result<(), FixtureError> {
        if !spec_path.as_ref().exists() {
            return Err(FixtureError::MissingSpec);
        }
        if bundle.entries.iter().any(|entry| entry.name.is_empty()) {
            return Err(FixtureError::InvalidEntry);
        }
        Ok(())
    }

    pub fn clause_coverage(
        spec_path: impl AsRef<Path>,
    ) -> Result<ClauseCoverageReport, FixtureError> {
        let spec_path = spec_path.as_ref();
        if !spec_path.exists() {
            return Err(FixtureError::MissingSpec);
        }
        let contents = fs::read_to_string(spec_path)?;
        let mut tags = Vec::new();
        let mut paragraphs = 0usize;
        let mut mixed = Vec::new();
        let mut in_code_block = false;
        for (idx, line) in contents.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("```") {
                in_code_block = !in_code_block;
                continue;
            }
            if in_code_block
                || trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with('|')
            {
                continue;
            }
            let stripped = strip_list_prefix(trimmed);
            if stripped.starts_with('[') {
                paragraphs += 1;
                let mut remainder = stripped;
                let mut tags_found = 0usize;
                while remainder.starts_with('[') {
                    if let Some(end) = remainder.find(']') {
                        let token = remainder[1..end].trim();
                        if !token.is_empty() {
                            tags.push(token.to_string());
                            tags_found += 1;
                        }
                        remainder = remainder[end + 1..].trim_start();
                    } else {
                        break;
                    }
                }
                if tags_found > 1 {
                    mixed.push(idx + 1);
                }
                continue;
            }
            if looks_like_paragraph(stripped) {
                paragraphs += 1;
            }
        }
        if !mixed.is_empty() {
            return Err(FixtureError::MixedClauseTags { line: mixed[0] });
        }
        if tags.is_empty() || paragraphs == 0 {
            return Err(FixtureError::ClauseTagsMissing);
        }
        let declared = declared_coverage(&contents)
            .ok_or(FixtureError::CoverageDeclarationMissing)?
            .min(100.0);
        if (declared - 100.0).abs() > f64::EPSILON {
            return Err(FixtureError::ClauseCoverageBelowTarget { declared });
        }
        tags.sort();
        let mut hasher = Sha256::new();
        hasher.update(tags.join("|"));
        let hash = hex::encode(hasher.finalize());
        Ok(ClauseCoverageReport {
            clauses_tagged: tags.len(),
            paragraphs,
            clause_coverage_hash: hash,
        })
    }

    pub fn emit_wire_catalog(
        coverage: &ClauseCoverageReport,
        messages: Vec<String>,
        output: impl AsRef<Path>,
    ) -> Result<WireCatalogArtifact, FixtureError> {
        let artifact = WireCatalogArtifact {
            schema_version: 1,
            messages,
            clause_coverage_hash: coverage.hash().to_string(),
        };
        write_artifact(&artifact, output)?;
        Ok(artifact)
    }

    pub fn emit_chunked_list_schema(
        coverage: &ClauseCoverageReport,
        rules: Vec<String>,
        output: impl AsRef<Path>,
    ) -> Result<ChunkedListSchemaArtifact, FixtureError> {
        let artifact = ChunkedListSchemaArtifact {
            schema_version: 1,
            rules,
            clause_coverage_hash: coverage.hash().to_string(),
        };
        write_artifact(&artifact, output)?;
        Ok(artifact)
    }

    pub fn term_registry(spec_path: impl AsRef<Path>) -> Result<TermRegistry, FixtureError> {
        let spec_path = spec_path.as_ref();
        if !spec_path.exists() {
            return Err(FixtureError::MissingSpec);
        }
        let contents = fs::read_to_string(spec_path)?;
        let definitions =
            parse_term_definitions(&contents).ok_or(FixtureError::TermRegistryMissing)?;
        Ok(TermRegistry::new(definitions))
    }

    pub fn term_registry_check(
        spec_path: impl AsRef<Path>,
        required_terms: &[(&str, &str)],
    ) -> Result<(), FixtureError> {
        let registry = Self::term_registry(spec_path)?;
        for (canonical, expected) in required_terms {
            match registry.term_id(canonical) {
                Some(observed) if observed == *expected => {}
                Some(observed) => {
                    return Err(FixtureError::TermIdMismatch {
                        canonical: (*canonical).into(),
                        expected: (*expected).into(),
                        observed: observed.into(),
                    });
                }
                None => {
                    return Err(FixtureError::TermMissing {
                        canonical: (*canonical).into(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn emit_consensus_core_manifest(
        spec_path: impl AsRef<Path>,
        bundles: &[(&str, &Path)],
        catalog: CatalogVersion,
        proof_bundle: ProofBundleRef,
        feature_manifest_sha256: impl AsRef<str>,
        output: impl AsRef<Path>,
    ) -> Result<ConsensusCoreManifest, FixtureError> {
        let mut builder = ConsensusCoreManifestBuilder::new(spec_path.as_ref());
        builder = builder
            .catalog_version(catalog)
            .proof_bundle(proof_bundle)
            .feature_manifest_hash(feature_manifest_sha256.as_ref());
        for (name, path) in bundles {
            builder = builder.add_bundle(*name, (*path).to_path_buf());
        }
        let manifest = builder
            .generate()
            .map_err(FixtureError::ConsensusCoreManifest)?;
        manifest
            .write_to(output.as_ref())
            .map_err(FixtureError::ConsensusCoreManifest)?;
        Ok(manifest)
    }

    pub fn future_gate_coverage(
        spec_path: impl AsRef<Path>,
        telemetry: &[FeatureGateTelemetryEntry],
    ) -> Result<(), FixtureError> {
        let spec_path = spec_path.as_ref();
        if !spec_path.exists() {
            return Err(FixtureError::MissingSpec);
        }
        let contents = fs::read_to_string(spec_path)?;
        let expected =
            parse_future_gate_names(&contents).ok_or(FixtureError::FutureGateTableMissing)?;
        if expected.is_empty() {
            return Err(FixtureError::FutureGateTableMissing);
        }
        let mut remaining = HashMap::new();
        for entry in telemetry {
            remaining.insert(entry.feature, entry);
        }
        for feature in expected {
            match remaining.remove(feature.as_str()) {
                Some(entry) => {
                    if entry.gate_state_metric.is_empty()
                        || entry.gate_state_digest_metric.is_empty()
                        || entry.predicate_digest_metric.is_empty()
                        || entry.predicate_digest.is_empty()
                        || entry.gate_state_digest.is_empty()
                    {
                        return Err(FixtureError::FutureGateTelemetryIncomplete {
                            feature: feature.to_string(),
                        });
                    }
                }
                None => {
                    return Err(FixtureError::FutureGateTelemetryMissing {
                        feature: feature.to_string(),
                    });
                }
            }
        }
        if let Some(extra) = remaining.keys().next() {
            return Err(FixtureError::FutureGateUnknownTelemetry {
                feature: extra.to_string(),
            });
        }
        Ok(())
    }
}

fn write_artifact<T: Serialize>(
    artifact: &T,
    output: impl AsRef<Path>,
) -> Result<(), FixtureError> {
    let payload = serde_json::to_vec_pretty(artifact)?;
    fs::write(output, payload)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("fixture bundle must contain at least one entry")]
    EmptyBundle,
    #[error("specification file not found")]
    MissingSpec,
    #[error("fixture entry missing name")]
    InvalidEntry,
    #[error("specification lacks clause tags for coverage estimation")]
    ClauseTagsMissing,
    #[error("clause_tag_coverage declaration missing")]
    CoverageDeclarationMissing,
    #[error("clause_tag_coverage declared as {declared}% but must be 100%")]
    ClauseCoverageBelowTarget { declared: f64 },
    #[error("multiple clause tags found on line {line}")]
    MixedClauseTags { line: usize },
    #[error("terminology table missing from specification")]
    TermRegistryMissing,
    #[error("term `{canonical}` missing from terminology table")]
    TermMissing { canonical: String },
    #[error("term `{canonical}` expected id {expected} but found {observed}")]
    TermIdMismatch {
        canonical: String,
        expected: String,
        observed: String,
    },
    #[error("future gate table missing from specification")]
    FutureGateTableMissing,
    #[error("telemetry missing feature `{feature}` from feature manifest table")]
    FutureGateTelemetryMissing { feature: String },
    #[error("telemetry includes unknown future gate `{feature}`")]
    FutureGateUnknownTelemetry { feature: String },
    #[error("telemetry for future gate `{feature}` is incomplete")]
    FutureGateTelemetryIncomplete { feature: String },
    #[error("consensus core manifest error: {0}")]
    ConsensusCoreManifest(#[from] ConsensusCoreManifestError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("system time error: {0}")]
    Time(#[from] std::time::SystemTimeError),
}

fn parse_future_gate_names(contents: &str) -> Option<Vec<String>> {
    let mut lines = contents.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            let title = trimmed.trim_start_matches('#').trim().to_ascii_lowercase();
            if !(title.contains("feature manifest") && title.contains("futuregates")) {
                continue;
            }
            while let Some(header) = lines.next() {
                if header.trim().starts_with('|') && header.contains("Feature") {
                    // Skip the separator row
                    lines.next();
                    break;
                }
            }
            let mut entries = Vec::new();
            for row in lines {
                let trimmed = row.trim();
                if trimmed.is_empty() || !trimmed.starts_with('|') {
                    break;
                }
                if trimmed.starts_with("| ---") {
                    continue;
                }
                let cols: Vec<_> = trimmed.trim_matches('|').split('|').collect();
                if cols.is_empty() {
                    break;
                }
                let feature = cols[0].trim();
                if feature.is_empty() {
                    break;
                }
                entries.push(feature.to_string());
            }
            return Some(entries);
        }
    }
    None
}

fn strip_list_prefix(line: &str) -> &str {
    let trimmed = line.trim_start_matches(|c: char| c.is_whitespace());
    for prefix in ["- ", "* ", "+ ", "• ", "> "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.trim_start();
        }
    }
    if let Some(idx) = trimmed.find(". ") {
        if trimmed[..idx].chars().all(|c| c.is_ascii_digit()) {
            return trimmed[idx + 2..].trim_start();
        }
    }
    trimmed
}

fn looks_like_paragraph(line: &str) -> bool {
    line.chars()
        .next()
        .map(|ch| ch.is_ascii_alphanumeric() || ch == '[')
        .unwrap_or(false)
}

fn declared_coverage(contents: &str) -> Option<f64> {
    contents.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if let Some(idx) = lower.find("clause_tag_coverage") {
            let tail = &lower[idx..];
            let eq_idx = tail.find('=')?;
            let token = tail[eq_idx + 1..].split_whitespace().next()?;
            let numeric = token.trim_end_matches(['%', '`']);
            return numeric.parse::<f64>().ok();
        }
        None
    })
}

fn parse_term_definitions(contents: &str) -> Option<Vec<TermDefinition>> {
    let mut lines = contents.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            let title = trimmed.trim_start_matches('#').trim().to_ascii_lowercase();
            if !title.contains("terminology normalization") {
                continue;
            }
            // Skip header rows (column labels + divider)
            lines.next();
            lines.next();
            let mut entries = Vec::new();
            for row in lines.by_ref() {
                let trimmed = row.trim();
                if trimmed.is_empty() || !trimmed.starts_with('|') {
                    break;
                }
                if trimmed.starts_with("| ---") {
                    continue;
                }
                let columns: Vec<String> = trimmed
                    .trim_matches('|')
                    .split('|')
                    .map(|col| col.trim().trim_matches('`').to_string())
                    .collect();
                if columns.len() < 2 {
                    continue;
                }
                let term_id = columns[0].clone();
                let canonical = columns[1].clone();
                if term_id.is_empty() || canonical.is_empty() {
                    continue;
                }
                let synonyms = columns
                    .get(2)
                    .map(|syn| {
                        syn.split(',')
                            .map(|item| item.trim().trim_matches('`').to_string())
                            .filter(|item| !item.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                entries.push(TermDefinition {
                    term_id,
                    canonical,
                    synonyms,
                });
            }
            if entries.is_empty() {
                return None;
            }
            return Some(entries);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_guard::FeatureGateTelemetry;
    use crate::ConsensusCoreManifest;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;
    use tempfile::tempdir;

    #[test]
    fn fixture_bundle_generation_and_lint() {
        let tmp = tempdir().unwrap();
        let bundle_path = tmp.path().join("bundle.json");
        let entries = vec![FixtureEntry {
            name: "appendix-c".into(),
            description: "Snapshot manifest sample".into(),
            payload: serde_json::json!({"term": 7, "index": 42}),
        }];
        let bundle = FixtureBundleGenerator::generate(entries, &bundle_path).unwrap();
        assert!(bundle_path.exists());
        SpecLint::validate_bundle(&bundle, "docs/specification.md").unwrap();
    }

    #[test]
    fn clause_coverage_embeds_into_artifacts() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "clause_tag_coverage = 100%\n\n[Normative] Clause A\n[Operational] Clause B",
        )
        .unwrap();
        let coverage = SpecLint::clause_coverage(&spec_path).expect("coverage");
        let wire_path = tmp.path().join("wire_catalog.json");
        let chunk_path = tmp.path().join("chunked_list_schema.json");
        let wire = SpecLint::emit_wire_catalog(&coverage, vec!["DurabilityAck".into()], &wire_path)
            .expect("wire catalog");
        let chunk =
            SpecLint::emit_chunked_list_schema(&coverage, vec!["ChunkRule".into()], &chunk_path)
                .expect("chunked list");
        assert_eq!(wire.clause_coverage_hash, coverage.hash());
        assert_eq!(chunk.clause_coverage_hash, coverage.hash());
        assert!(wire_path.exists() && chunk_path.exists());
    }

    #[test]
    fn clause_coverage_requires_tags() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(&spec_path, "[Normative] Clause without coverage flag").unwrap();
        let err = SpecLint::clause_coverage(&spec_path).unwrap_err();
        assert!(matches!(err, FixtureError::CoverageDeclarationMissing));
    }

    #[test]
    fn clause_coverage_rejects_mixed_tags() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "clause_tag_coverage = 100%\n\n[Normative][Operational] Illegal mix\n\n[Operational] ok",
        )
        .unwrap();
        let err = SpecLint::clause_coverage(&spec_path).unwrap_err();
        assert!(matches!(err, FixtureError::MixedClauseTags { .. }));
    }

    #[test]
    fn clause_coverage_enforces_declared_percentage() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "clause_tag_coverage = 75%\n\n[Normative] Tagged paragraph",
        )
        .unwrap();
        let err = SpecLint::clause_coverage(&spec_path).unwrap_err();
        assert!(matches!(
            err,
            FixtureError::ClauseCoverageBelowTarget { .. }
        ));
    }

    #[test]
    fn term_registry_check_validates_known_terms() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "#### 1.3.1 Terminology Normalization\n\
| term_id | Canonical term | Synonyms in docs | Notes |\n\
| --- | --- | --- | --- |\n\
| `TERM-0001` | `Strict` | `Strict durability`, `Strict mode` | Means per-append fdatasync. |\n",
        )
        .unwrap();
        SpecLint::term_registry_check(&spec_path, &[("Strict", "TERM-0001")]).unwrap();
    }

    #[test]
    fn term_registry_check_surfaces_missing_terms() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "#### 1.3.1 Terminology Normalization\n\
| term_id | Canonical term | Synonyms in docs | Notes |\n\
| --- | --- | --- | --- |\n\
| `TERM-0002` | `Group-Fsync` | `Group` | Batching mode |\n",
        )
        .unwrap();
        let err =
            SpecLint::term_registry_check(&spec_path, &[("Strict", "TERM-0001")]).unwrap_err();
        assert!(matches!(err, FixtureError::TermMissing { .. }));
    }

    #[test]
    fn future_gate_coverage_matches_table() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "### Feature Manifest (FutureGates)\n\
| Feature | Gate flag / CP object | Enablement predicate | Telemetry hook |\n\
| --- | --- | --- | --- |\n\
| Leader leases | feature.leases | predicate | hook |\n\
| PID auto-tuner | flow.pid_auto_tune | predicate | hook |\n\
| Incremental snapshots | snapshot.delta_chain_max | predicate | hook |\n\
| BLAKE3 Merkle leaves | integrity.hash_suite | predicate | hook |\n",
        )
        .unwrap();
        let telemetry = FeatureGateTelemetry::new();
        SpecLint::future_gate_coverage(&spec_path, telemetry.entries()).unwrap();
    }

    #[test]
    fn future_gate_coverage_detects_missing_entries() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "### Feature Manifest (FutureGates)\n\
| Feature | Gate flag / CP object | Enablement predicate | Telemetry hook |\n\
| --- | --- | --- | --- |\n\
| Leader leases | feature.leases | predicate | hook |\n\
| PID auto-tuner | flow.pid_auto_tune | predicate | hook |\n",
        )
        .unwrap();
        let telemetry = FeatureGateTelemetry::new();
        let err =
            SpecLint::future_gate_coverage(&spec_path, &telemetry.entries()[1..]).unwrap_err();
        assert!(matches!(
            err,
            FixtureError::FutureGateTelemetryMissing { .. }
        ));
    }

    #[test]
    fn consensus_core_manifest_emits_and_verifies() {
        let tmp = tempdir().unwrap();
        let spec_path = tmp.path().join("spec.md");
        std::fs::write(
            &spec_path,
            "## 0 Safety\n## 1 Architecture\n## Appendix A App.A",
        )
        .unwrap();
        let wire_path = tmp.path().join("wire_catalog.json");
        let chunk_path = tmp.path().join("chunked_list_schema.json");
        std::fs::write(&wire_path, b"wire").unwrap();
        std::fs::write(&chunk_path, b"chunked").unwrap();

        let proof_bytes = sha2::Sha256::digest(b"proof");
        let proof_hash = hex::encode(proof_bytes);
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let signature = signing_key.sign(&ProofBundleRef::signing_message_for(11, &proof_hash));
        let proof = ProofBundleRef::new(11, proof_hash.clone(), hex::encode(signature.to_bytes()));

        let bundles = vec![
            ("wire_catalog", wire_path.as_path()),
            ("chunked_list_schema", chunk_path.as_path()),
        ];
        let manifest_path = tmp.path().join("consensus_core_manifest.json");
        let manifest = SpecLint::emit_consensus_core_manifest(
            &spec_path,
            &bundles,
            CatalogVersion::new(0, 1, 2),
            proof,
            "feature-hash",
            &manifest_path,
        )
        .expect("manifest emitted");
        assert!(manifest_path.exists());
        assert_eq!(manifest.sections.len(), 3);
        let loaded = ConsensusCoreManifest::load(&manifest_path).expect("manifest loads");
        loaded
            .verify_proof_bundle_signature(&hex::encode(signing_key.verifying_key().to_bytes()))
            .expect("signature verifies");
    }
}
