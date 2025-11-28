#![cfg(feature = "net")]

use super::{
    MAX_CONCURRENT_RAFT_CONNECTIONS, OP_APPEND_ENTRIES, OP_REQUEST_VOTE, RAFT_SERVER_IDLE_POLL,
    RAFT_SERVER_STREAM_TIMEOUT, STATUS_ERR, STATUS_OK,
};
use crate::net::server;
use crate::net::tls::{
    complete_server_handshake, decode_peer_certificate, TlsIdentity, TlsTrustStore,
};
use crate::replication::transport::raft::{RaftRpcHandler, RaftRpcServer};
use log::{info, warn};
use rustls::{ServerConfig, ServerConnection, Stream};
use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

pub struct RaftNetworkServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct RaftNetworkServerHandle {
    inner: server::ServerHandle,
}

impl RaftNetworkServerHandle {
    pub fn shutdown(&mut self) {
        if let Err(err) = self.try_shutdown(std::time::Duration::from_secs(5)) {
            warn!("event=raft_server_shutdown_error error={err}");
        }
    }

    pub fn try_shutdown(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<(), crate::net::NetError> {
        self.inner.try_shutdown(timeout)
    }
}

impl Drop for RaftNetworkServerHandle {
    fn drop(&mut self) {
        let _ = self.try_shutdown(std::time::Duration::from_secs(5));
    }
}

pub struct RaftNetworkServer;

impl RaftNetworkServer {
    pub fn spawn<H>(
        config: RaftNetworkServerConfig,
        server: RaftRpcServer<H>,
    ) -> Result<RaftNetworkServerHandle, crate::net::NetError>
    where
        H: RaftRpcHandler + Send + 'static,
    {
        let listener = TcpListener::bind(config.bind)?;
        info!("event=raft_server_listen addr={}", config.bind);
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let shared_server = Arc::new(Mutex::new(server));
        let bind_addr = config.bind;
        let handler = move |stream: TcpStream,
                            addr: SocketAddr,
                            shutdown: Arc<AtomicBool>|
              -> Result<(), crate::net::NetError> {
            if let Err(err) = configure_server_stream(&stream) {
                warn!(
                    "event=raft_server_stream_config_error addr={} peer={addr} error={}",
                    bind_addr, err
                );
                return Ok(());
            }
            info!("event=raft_server_accept addr={} peer={addr}", bind_addr);
            let tls = tls_config.clone();
            let server = shared_server.clone();
            if let Err(err) = handle_connection(stream, addr, tls, server, shutdown) {
                warn!("raft connection error from {addr}: {err}");
            }
            Ok(())
        };
        let inner = server::spawn_listener(
            "raft_server",
            listener,
            Some(MAX_CONCURRENT_RAFT_CONNECTIONS),
            handler,
        )
        .map_err(crate::net::NetError::from)?;
        Ok(RaftNetworkServerHandle { inner })
    }
}

fn handle_connection<H: RaftRpcHandler>(
    mut stream: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    server: Arc<Mutex<RaftRpcServer<H>>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), crate::net::NetError> {
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    info!("event=raft_tls_session peer={addr}");
    stream.set_read_timeout(Some(RAFT_SERVER_IDLE_POLL)).ok();
    let peer_chain = conn.peer_certificates().ok_or_else(|| {
        crate::net::NetError::from(crate::net::CertificateError::MissingClientCertificate {
            context: "raft_server",
        })
    })?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
    let mut tls = Stream::new(&mut conn, &mut stream);
    loop {
        let mut header = [0u8; 5];
        match read_exact_with_shutdown(&mut tls, &mut header, &shutdown) {
            Ok(_) => {}
            Err(err) if matches!(err.kind(), io::ErrorKind::UnexpectedEof) => {
                info!("event=raft_connection_close peer={addr}");
                return Ok(());
            }
            Err(err) if matches!(err.kind(), io::ErrorKind::Interrupted) => {
                info!("event=raft_connection_shutdown peer={addr}");
                return Ok(());
            }
            Err(err) => return Err(crate::net::NetError::Io(err)),
        }
        let opcode = header[0];
        let len = u32::from_le_bytes(
            header[1..5]
                .try_into()
                .map_err(|_| crate::net::NetError::from(crate::net::ProtocolError::FrameLength))?,
        ) as usize;
        let mut payload = vec![0u8; len];
        if let Err(err) = read_exact_with_shutdown(&mut tls, &mut payload, &shutdown) {
            return match err.kind() {
                io::ErrorKind::UnexpectedEof => {
                    info!("event=raft_connection_close peer={addr}");
                    Ok(())
                }
                io::ErrorKind::Interrupted => {
                    info!("event=raft_connection_shutdown peer={addr}");
                    Ok(())
                }
                _ => Err(crate::net::NetError::Io(err)),
            };
        }
        let now = Instant::now();
        let mut guard = server::lock_or_poison(&server, "raft_server")?;
        let outcome = match opcode {
            OP_REQUEST_VOTE => guard
                .handle_request_vote(&peer_certificate, &payload, now)
                .map_err(|err| err.to_string()),
            OP_APPEND_ENTRIES => guard
                .handle_append_entries(&peer_certificate, &payload, now)
                .map_err(|err| err.to_string()),
            _ => Err(format!("unknown opcode {opcode}")),
        };
        drop(guard);
        match outcome {
            Ok(response) => {
                write_response(&mut tls, STATUS_OK, &response)?;
            }
            Err(err) => {
                warn!("event=raft_handler_error peer={} error={}", addr, err);
                write_response(&mut tls, STATUS_ERR, err.as_bytes())?;
            }
        }
    }
}

fn write_response(
    stream: &mut impl Write,
    status: u8,
    payload: &[u8],
) -> Result<(), crate::net::NetError> {
    let mut header = [0u8; 5];
    header[0] = status;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    Ok(())
}

fn configure_server_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(RAFT_SERVER_STREAM_TIMEOUT))?;
    stream.set_write_timeout(Some(RAFT_SERVER_STREAM_TIMEOUT))?;
    Ok(())
}

fn read_exact_with_shutdown(
    stream: &mut Stream<'_, ServerConnection, TcpStream>,
    buf: &mut [u8],
    shutdown: &Arc<AtomicBool>,
) -> io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        if shutdown.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "server shutdown",
            ));
        }
        match stream.read(&mut buf[read..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed connection",
                ))
            }
            Ok(n) => {
                read += n;
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                if shutdown.load(Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "server shutdown",
                    ));
                }
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}
