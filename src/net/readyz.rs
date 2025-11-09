#![cfg(feature = "net")]

use super::http::{read_request, write_json_response};
use super::tls::{complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore};
use super::NetError;
use crate::readyz::{ReadyExplain, ReadyzSnapshot};
use log::warn;
use rustls::{ServerConfig, ServerConnection, Stream};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;

pub struct ReadyzPublisher {
    snapshot: Arc<RwLock<ReadyzSnapshot>>,
}

impl ReadyzPublisher {
    pub fn new(initial: ReadyzSnapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(initial)),
        }
    }

    pub fn update(&self, snapshot: ReadyzSnapshot) {
        let mut guard = self.snapshot.write().expect("readyz snapshot poisoned");
        *guard = snapshot;
    }

    pub fn snapshot(&self) -> ReadyzSnapshot {
        self.snapshot
            .read()
            .expect("readyz snapshot poisoned")
            .clone()
    }

    fn explain(&self, partition_id: &str) -> Option<ReadyExplain> {
        self.snapshot
            .read()
            .ok()
            .and_then(|snapshot| snapshot.why_not_ready(partition_id))
    }
}

pub struct ReadyzHttpServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct ReadyzHttpServerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl ReadyzHttpServerHandle {
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ReadyzHttpServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub struct ReadyzHttpServer;

impl ReadyzHttpServer {
    pub fn spawn(
        config: ReadyzHttpServerConfig,
        publisher: ReadyzPublisher,
    ) -> Result<ReadyzHttpServerHandle, NetError> {
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
                            warn!("readyz connection {addr} error: {err}");
                        }
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(err) => {
                    warn!("readyz accept error: {err}");
                    break;
                }
            }
        });
        Ok(ReadyzHttpServerHandle {
            shutdown,
            join: Some(handle),
        })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    publisher: Arc<ReadyzPublisher>,
) -> Result<(), NetError> {
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    let peer_chain = conn
        .peer_certificates()
        .ok_or_else(|| NetError::Certificate("readyz client presented no certificate".into()))?;
    let _ = decode_peer_certificate(peer_chain, std::time::Instant::now())?;
    let mut tls = Stream::new(&mut conn, &mut stream);
    let request = read_request(&mut tls)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/readyz") => {
            let snapshot = publisher.snapshot();
            write_json_response(&mut tls, 200, &snapshot)?;
        }
        ("GET", _) => {
            let segments = request.path_segments();
            if segments.len() == 2 && segments[0] == "readyz" && segments[1] == "why" {
                write_json_response(
                    &mut tls,
                    400,
                    &serde_json::json!({"error": "partition id missing", "status": 400}),
                )?;
            } else if segments.len() == 3 && segments[0] == "readyz" && segments[1] == "why" {
                let partition = segments[2];
                if let Some(why) = publisher.explain(partition) {
                    write_json_response(&mut tls, 200, &why)?;
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
        }
        _ => {
            write_json_response(
                &mut tls,
                405,
                &serde_json::json!({"error": "method not allowed", "status": 405}),
            )?;
        }
    }
    Ok(())
}
