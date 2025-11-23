use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClusterConfig {
    pub trust_domain: String,
    pub ca_cert: PathBuf,
    pub nodes: Vec<NodeConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodeConfig {
    pub id: String,
    pub raft_bind: String,
    pub http_bind: String,
    #[serde(default)]
    pub management_bind: Option<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub peers: Vec<String>,
}

pub fn load_cluster_config(path: &Path) -> Result<ClusterConfig> {
    let raw = std::fs::read_to_string(path)?;
    let mut config: ClusterConfig = serde_yaml::from_str(&raw)?;
    // Normalize relative paths to be relative to the config location.
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if config.ca_cert.is_relative() {
        config.ca_cert = base.join(config.ca_cert);
    }
    for node in &mut config.nodes {
        if node.cert.is_relative() {
            node.cert = base.join(&node.cert);
        }
        if node.key.is_relative() {
            node.key = base.join(&node.key);
        }
    }
    Ok(config)
}
