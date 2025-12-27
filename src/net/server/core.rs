#![cfg(feature = "net")]

use crate::net::{NetError, ProtocolError};
use crate::timeouts::SERVER_SHUTDOWN_GRACE;
use log::{error, warn};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

const ACCEPT_BACKOFF: Duration = Duration::from_millis(25);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = SERVER_SHUTDOWN_GRACE;

struct AcceptLoopState {
    done: Mutex<bool>,
    condvar: Condvar,
}

impl AcceptLoopState {
    fn new() -> Self {
        Self {
            done: Mutex::new(false),
            condvar: Condvar::new(),
        }
    }

    fn mark_stopped(&self) {
        if let Ok(mut done) = self.done.lock() {
            *done = true;
            self.condvar.notify_all();
        } else {
            self.condvar.notify_all();
        }
    }

    fn wait_for_stop(&self, timeout: Duration, name: &'static str) -> Result<(), NetError> {
        let mut guard = lock_or_poison(&self.done, "accept loop state")?;
        if *guard {
            return Ok(());
        }
        let (next, _status) = self.condvar.wait_timeout(guard, timeout).map_err(|_| {
            NetError::from(ProtocolError::Poisoned {
                context: "accept loop state",
            })
        })?;
        guard = next;
        if *guard {
            Ok(())
        } else {
            Err(NetError::from(ProtocolError::ShutdownTimeout {
                context: name,
            }))
        }
    }
}

#[derive(Default)]
pub(crate) struct ConnectionTracker {
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl ConnectionTracker {
    fn track(&self, handle: thread::JoinHandle<()>) -> Result<(), NetError> {
        let mut handles = lock_or_poison(&self.handles, "connection tracker handles")?;
        handles.push(handle);
        Ok(())
    }

    fn join_all(&self) -> Result<(), NetError> {
        let mut handles = lock_or_poison(&self.handles, "connection tracker handles")?;
        for handle in handles.drain(..) {
            let _ = handle.join();
        }
        Ok(())
    }
}

struct ConnectionLimiter {
    active: AtomicUsize,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Self {
        Self {
            active: std::sync::atomic::AtomicUsize::new(0),
            limit,
        }
    }

    fn try_acquire(&self) -> bool {
        loop {
            let value = self.active.load(Ordering::Relaxed);
            if value >= self.limit {
                return false;
            }
            if self
                .active
                .compare_exchange(value, value + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::Release);
    }
}

struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl ConnectionPermit {
    fn new(limiter: Arc<ConnectionLimiter>) -> Option<Self> {
        if limiter.try_acquire() {
            Some(Self { limiter })
        } else {
            None
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

pub(crate) struct ServerHandle {
    name: &'static str,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
    connections: Arc<ConnectionTracker>,
    state: Arc<AcceptLoopState>,
}

impl ServerHandle {
    fn new(
        name: &'static str,
        shutdown: Arc<AtomicBool>,
        join: thread::JoinHandle<()>,
        connections: Arc<ConnectionTracker>,
        state: Arc<AcceptLoopState>,
    ) -> Self {
        Self {
            name,
            shutdown,
            join: Some(join),
            connections,
            state,
        }
    }

    pub(crate) fn try_shutdown(&mut self, timeout: Duration) -> Result<(), NetError> {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            self.state.wait_for_stop(timeout, self.name)?;
            if handle.join().is_err() {
                warn!("event=server_accept_loop_panic name={}", self.name);
            }
        }
        self.connections.join_all()
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(DEFAULT_SHUTDOWN_TIMEOUT);
    }
}

pub(crate) fn spawn_listener<F>(
    name: &'static str,
    listener: TcpListener,
    max_connections: Option<usize>,
    handler: F,
) -> io::Result<ServerHandle>
where
    F: Fn(TcpStream, SocketAddr, Arc<AtomicBool>) -> Result<(), NetError> + Send + Sync + 'static,
{
    listener.set_nonblocking(true)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let tracker = Arc::new(ConnectionTracker::default());
    let handler = Arc::new(handler);
    let limiter = max_connections.map(|limit| (limit, Arc::new(ConnectionLimiter::new(limit))));
    let shutdown_handle = shutdown.clone();
    let tracker_clone = tracker.clone();
    let state = Arc::new(AcceptLoopState::new());
    let accept_state = state.clone();
    let join = thread::spawn(move || {
        let shutdown_flag = shutdown_handle;
        loop {
            if shutdown_flag.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, addr)) => {
                    let permit = if let Some((limit, limiter)) = limiter.as_ref() {
                        match ConnectionPermit::new(limiter.clone()) {
                            Some(permit) => Some(permit),
                            None => {
                                warn!(
                                    "event={}_connection_rejected addr={} reason=too_many_connections limit={}",
                                    name, addr, limit
                                );
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    let handler = handler.clone();
                    let tracker = tracker_clone.clone();
                    let shutdown_token = shutdown_flag.clone();
                    let name = name;
                    let connection = thread::spawn(move || {
                        let _permit = permit;
                        if let Err(err) = handler(stream, addr, shutdown_token) {
                            warn!("event={}_connection_error addr={} error={err}", name, addr);
                        }
                    });
                    if let Err(err) = tracker.track(connection) {
                        warn!("event={}_connection_tracking_failed error={err}", name);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_BACKOFF);
                }
                Err(err) => {
                    error!("event={}_accept_error error={err}", name);
                    break;
                }
            }
        }
        accept_state.mark_stopped();
    });
    Ok(ServerHandle::new(name, shutdown, join, tracker, state))
}

pub(crate) fn lock_or_poison<'a, T>(
    mutex: &'a Mutex<T>,
    context: &'static str,
) -> Result<MutexGuard<'a, T>, NetError> {
    mutex
        .lock()
        .map_err(|_| NetError::from(ProtocolError::Poisoned { context }))
}
