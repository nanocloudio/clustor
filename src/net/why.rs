#![cfg(feature = "net")]

use super::http::{read_request, write_json_response};
use super::tls::{complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore};
use super::NetError;
use crate::why::{WhyNotLeader, WhySnapshotBlocked};
use log::warn;
use rustls::{ServerConfig, ServerConnection, Stream};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;

#[derive(Clone, Default)]
pub struct WhyPublisher {
    not_leader: Arc<RwLock<HashMap<String, WhyNotLeader>>>,
    snapshot_blocked: Arc<RwLock<HashMap<String, WhySnapshotBlocked>>>,
}

impl WhyPublisher {
    pub fn update_not_leader(&self, partition: impl Into<String>, report: WhyNotLeader) {
        self.not_leader
            .write()
            .expect("why publisher poisoned")
            .insert(partition.into(), report);
    }

    pub fn update_snapshot_blocked(
        &self,
        partition: impl Into<String>,
        report: WhySnapshotBlocked,
    ) {
        self.snapshot_blocked
            .write()
            .expect("why publisher poisoned")
            .insert(partition.into(), report);
    }

    pub fn remove_partition(&self, partition: &str) {
        if let Ok(mut guard) = self.not_leader.write() {
            guard.remove(partition);
        }
        if let Ok(mut guard) = self.snapshot_blocked.write() {
            guard.remove(partition);
        }
    }

    fn not_leader(&self, partition: &str) -> Option<WhyNotLeader> {
        self.not_leader
            .read()
            .ok()
            .and_then(|map| map.get(partition).cloned())
    }

    fn snapshot_blocked(&self, partition: &str) -> Option<WhySnapshotBlocked> {
        self.snapshot_blocked
            .read()
            .ok()
            .and_then(|map| map.get(partition).cloned())
    }
}

pub struct WhyHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct WhyHttpServerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl WhyHttpServerHandle {
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for WhyHttpServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub struct WhyHttpServer;

impl WhyHttpServer {
    pub fn spawn(
        config: WhyHttpServerConfig,
        publisher: WhyPublisher,
    ) -> Result<WhyHttpServerHandle, NetError> {
        let listener = TcpListener::bind(config.bind)?;
        listener.set_nonblocking(true)?;
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let publisher = Arc::new(publisher);
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = shutdown.clone();
        let handle = thread::spawn(move || loop {
            if shutdown_flag.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, addr)) => {
                    let tls = tls_config.clone();
                    let publisher = publisher.clone();
                    thread::spawn(move || {
                        if let Err(err) = handle_connection(stream, tls, publisher) {
                            warn!("why connection {addr} error: {err}");
                        }
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(err) => {
                    warn!("why accept error: {err}");
                    break;
                }
            }
        });
        Ok(WhyHttpServerHandle {
            shutdown,
            join: Some(handle),
        })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    publisher: Arc<WhyPublisher>,
) -> Result<(), NetError> {
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    let peer_chain = conn
        .peer_certificates()
        .ok_or_else(|| NetError::Certificate("why client presented no certificate".into()))?;
    let _ = decode_peer_certificate(peer_chain, std::time::Instant::now())?;
    let mut tls = Stream::new(&mut conn, &mut stream);
    let request = read_request(&mut tls)?;
    let segments = request.path_segments();
    if segments.len() == 3 && segments[0] == "why" && segments[1] == "not-leader" {
        let partition = segments[2];
        if let Some(report) = publisher.not_leader(partition) {
            write_json_response(&mut tls, 200, &report)?;
        } else {
            write_json_response(
                &mut tls,
                404,
                &serde_json::json!({"error": "partition not found", "status": 404}),
            )?;
        }
    } else if segments.len() == 3 && segments[0] == "why" && segments[1] == "snapshot-blocked" {
        let partition = segments[2];
        if let Some(report) = publisher.snapshot_blocked(partition) {
            write_json_response(&mut tls, 200, &report)?;
        } else {
            write_json_response(
                &mut tls,
                404,
                &serde_json::json!({"error": "partition not found", "status": 404}),
            )?;
        }
    } else {
        write_json_response(
            &mut tls,
            404,
            &serde_json::json!({"error": "not found", "status": 404}),
        )?;
    }
    Ok(())
}
