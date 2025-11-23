#[cfg(feature = "async-net")]
use crate::net::AsyncRaftNetworkClient;
use log::{debug, info, warn};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(feature = "async-net")]
use tokio::task::JoinHandle;
#[cfg(feature = "async-net")]
use tokio::time::interval;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Healthy,
    Suspect,
    Down,
}

struct PeerHealthState {
    status: PeerStatus,
    has_success: bool,
    last_success: Instant,
    last_failure: Option<Instant>,
}

#[derive(Clone)]
pub struct PeerHealth {
    state: Arc<Mutex<PeerHealthState>>,
}

impl PeerHealth {
    pub fn new(now: Instant) -> Self {
        Self {
            state: Arc::new(Mutex::new(PeerHealthState {
                status: PeerStatus::Healthy,
                has_success: false,
                last_success: now,
                last_failure: None,
            })),
        }
    }

    pub fn record_success(&self, local: &str, peer: &str, now: Instant) {
        let mut state = self.state.lock();
        let previous = state.status;
        let downtime = state
            .last_failure
            .map(|ts| now.saturating_duration_since(ts));
        state.status = PeerStatus::Healthy;
        state.has_success = true;
        state.last_success = now;
        state.last_failure = None;
        drop(state);
        if matches!(previous, PeerStatus::Suspect | PeerStatus::Down) {
            if let Some(duration) = downtime {
                info!(
                    "node {} peer {} recovered after {:?}",
                    local, peer, duration
                );
            } else {
                info!("node {} peer {} recovered", local, peer);
            }
        }
    }

    pub fn record_failure(
        &self,
        local: &str,
        peer: &str,
        now: Instant,
        err: &str,
        down_after: Duration,
    ) {
        let mut state = self.state.lock();
        state.last_failure = Some(now);
        match state.status {
            PeerStatus::Healthy => {
                state.status = PeerStatus::Suspect;
                warn!(
                    "node {} peer {} marked suspect (error={} )",
                    local, peer, err
                );
            }
            PeerStatus::Suspect => {
                if now.duration_since(state.last_success) >= down_after {
                    state.status = PeerStatus::Down;
                    warn!(
                        "node {} peer {} marked down (error={}, last_success {:?} ago)",
                        local,
                        peer,
                        err,
                        now.duration_since(state.last_success)
                    );
                } else {
                    debug!("node {} peer {} still suspect (error={})", local, peer, err);
                }
            }
            PeerStatus::Down => {
                debug!("node {} peer {} still down (error={})", local, peer, err);
            }
        }
    }

    pub fn evaluate_timeout(
        &self,
        local: &str,
        peer: &str,
        now: Instant,
        suspect_after: Duration,
        down_after: Duration,
    ) {
        let mut state = self.state.lock();
        if !state.has_success {
            return;
        }
        let since_success = now.duration_since(state.last_success);
        match state.status {
            PeerStatus::Healthy => {
                if since_success >= suspect_after {
                    state.status = PeerStatus::Suspect;
                    warn!(
                        "node {} peer {} marked suspect (no success for {:?})",
                        local, peer, since_success
                    );
                }
            }
            PeerStatus::Suspect => {
                if since_success >= down_after {
                    state.status = PeerStatus::Down;
                    warn!(
                        "node {} peer {} marked down (no success for {:?})",
                        local, peer, since_success
                    );
                }
            }
            PeerStatus::Down => {}
        }
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self.status(), PeerStatus::Healthy)
    }

    pub fn status(&self) -> PeerStatus {
        self.state.lock().status
    }
}

/// Spawns a background task to refresh revocation for the provided peers.
#[cfg(feature = "async-net")]
pub fn spawn_revocation_refresher(
    peers: Vec<Arc<AsyncRaftNetworkClient>>,
    interval_duration: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(interval_duration);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            for peer in peers.iter() {
                if let Err(err) = peer.refresh_revocation(now).await {
                    debug!("peer revocation refresh failed: {err}");
                }
            }
        }
    })
}
