use crate::config::NodeConfig;
use crate::tls::new_mtls_manager;
use anyhow::Context;
use clustor::net::{
    AsyncRaftNetworkClient, AsyncRaftTransportClientConfig, AsyncRaftTransportClientOptions,
    PeerHealth, TlsIdentity, TlsTrustStore,
};
use log::warn;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct PeerInfo {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub client: Arc<AsyncRaftNetworkClient>,
    pub health: Arc<PeerHealth>,
}

impl PeerInfo {
    pub async fn refresh_revocation(&self, now: Instant) {
        if let Err(err) = self.client.refresh_revocation(now).await {
            warn!("peer {} revocation refresh failed: {err}", self.id);
        }
    }

    pub fn force_disconnect(&self) {
        self.client.cancel();
    }
}

pub fn build_peer_map(
    node_cfg: &NodeConfig,
    all_nodes: &[NodeConfig],
    tls_identity: &TlsIdentity,
    trust_store: &TlsTrustStore,
    trust_domain: &str,
) -> anyhow::Result<Vec<PeerInfo>> {
    let index: HashMap<_, _> = all_nodes.iter().map(|n| (&n.id, n)).collect();
    let mut peers = Vec::new();
    for peer_id in &node_cfg.peers {
        let peer_cfg = index
            .get(peer_id)
            .with_context(|| format!("peer `{peer_id}` missing from config"))?;
        let addr: SocketAddr = peer_cfg.raft_bind.parse()?;
        let host = addr.ip().to_string();
        let port = addr.port();
        let mut mtls = new_mtls_manager(tls_identity, trust_domain, std::time::Duration::from_secs(600));
        mtls.rotate(Instant::now()).ok();
        let client = AsyncRaftNetworkClient::with_options(
            AsyncRaftTransportClientConfig {
                host: host.clone(),
                port,
                identity: tls_identity.clone(),
                trust_store: trust_store.clone(),
                mtls: Arc::new(Mutex::new(mtls)),
            },
            AsyncRaftTransportClientOptions::default()
                .pool_size_per_peer_max(2)
                .pool_warmup(true)
                .peer_node_id(peer_cfg.id.clone()),
        )
        .with_context(|| format!("failed to build Raft client for peer {}", peer_cfg.id))?;
        let health = Arc::new(PeerHealth::new(Instant::now()));
        peers.push(PeerInfo {
            id: peer_cfg.id.clone(),
            host,
            port,
            client: Arc::new(client),
            health,
        });
    }
    Ok(peers)
}
