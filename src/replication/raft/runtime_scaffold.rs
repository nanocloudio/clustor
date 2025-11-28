use crate::replication::raft::ElectionController;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// Minimal Raft timing scaffold that drives heartbeat and election timers using
/// user-provided callbacks.
pub struct RaftNodeScaffold<Cb>
where
    Cb: RaftNodeCallbacks + 'static,
{
    callbacks: Arc<Cb>,
    controller: Mutex<ElectionController>,
    heartbeat_interval: Duration,
    notify: Arc<Notify>,
    shutdown: Arc<AtomicBool>,
    node_id: String,
}

pub trait RaftNodeCallbacks: Send + Sync {
    /// Invoked when the heartbeat timer fires and the node is the leader.
    fn on_leader_heartbeat(&self) -> PinFuture<()>;
    /// Invoked when an election should start (deadline expired and not leader).
    fn on_start_election(&self) -> PinFuture<()>;
    /// Whether the node currently believes it is the leader.
    fn is_leader(&self) -> bool;
    /// Current election deadline scheduling (called to refresh deadline on leadership contact).
    fn schedule_deadline(&self, now: Instant, timeout: Duration);
    /// Returns the time at which the next election should trigger.
    fn election_deadline(&self) -> Instant;
}

pub type PinFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send>>;

impl<Cb> RaftNodeScaffold<Cb>
where
    Cb: RaftNodeCallbacks + 'static,
{
    pub fn new(
        callbacks: Arc<Cb>,
        controller: ElectionController,
        heartbeat_interval: Duration,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            callbacks,
            controller: Mutex::new(controller),
            heartbeat_interval,
            notify: Arc::new(Notify::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            node_id: node_id.into(),
        }
    }

    pub fn spawn(self) -> RaftNodeHandle {
        let notify = self.notify.clone();
        let shutdown = self.shutdown.clone();
        let callbacks = self.callbacks.clone();
        let heartbeat_interval = self.heartbeat_interval;
        let heartbeat = tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    _ = sleep(heartbeat_interval) => {},
                    _ = notify.notified() => {},
                }
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                if callbacks.is_leader() {
                    callbacks.on_leader_heartbeat().await;
                }
            }
        });

        let notify = self.notify.clone();
        let shutdown = self.shutdown.clone();
        let callbacks = self.callbacks.clone();
        let controller = self.controller;
        let node_label = self.node_id.clone();
        let election = tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let now = Instant::now();
                let sleep_dur = callbacks.election_deadline().saturating_duration_since(now);
                tokio::select! {
                    _ = sleep(sleep_dur) => {},
                    _ = notify.notified() => {},
                }
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let now = Instant::now();
                if !callbacks.is_leader() && now >= callbacks.election_deadline() {
                    let timeout = controller.lock().next_election_timeout(node_label.clone());
                    callbacks.schedule_deadline(now, timeout);
                    callbacks.on_start_election().await;
                }
            }
        });

        RaftNodeHandle {
            shutdown: self.shutdown.clone(),
            notify: self.notify.clone(),
            tasks: vec![heartbeat, election],
        }
    }
}

pub struct RaftNodeHandle {
    shutdown: Arc<AtomicBool>,
    notify: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
}

impl RaftNodeHandle {
    pub fn wake(&self) {
        self.notify.notify_waiters();
    }

    pub fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub async fn shutdown(mut self) {
        self.signal_shutdown();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
