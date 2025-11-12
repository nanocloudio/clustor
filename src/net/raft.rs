#![cfg(feature = "net")]

use super::tls::{
    complete_client_handshake, complete_server_handshake, decode_peer_certificate, server_name,
    TlsIdentity, TlsTrustStore,
};
use super::NetError;
use crate::raft::{
    AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse,
};
use crate::security::{MtlsIdentityManager, RevocationSource};
use crate::transport::raft::{RaftRpcHandler, RaftRpcServer};
use log::{debug, info, warn};
use rustls::client::{
    verify_server_cert_signed_by_trust_anchor, ClientConfig, ClientConnection, ServerCertVerified,
    ServerCertVerifier, ServerName,
};
use rustls::server::ParsedCertificate;
use rustls::{Certificate as RustlsCertificate, RootCertStore};
use rustls::{Error as TlsError, ServerConfig, ServerConnection, Stream};
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const OP_REQUEST_VOTE: u8 = 1;
const OP_APPEND_ENTRIES: u8 = 2;
const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

pub struct RaftNetworkServerConfig {
    pub bind: SocketAddr,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
}

pub struct RaftNetworkServerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RaftNetworkServerHandle {
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RaftNetworkServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub struct RaftNetworkServer;

impl RaftNetworkServer {
    pub fn spawn<H>(
        config: RaftNetworkServerConfig,
        server: RaftRpcServer<H>,
    ) -> Result<RaftNetworkServerHandle, NetError>
    where
        H: RaftRpcHandler + Send + 'static,
    {
        let listener = TcpListener::bind(config.bind)?;
        listener.set_nonblocking(true)?;
        info!("event=raft_server_listen addr={}", config.bind);
        let tls_config = Arc::new(config.identity.server_config(&config.trust_store)?);
        let shared_server = Arc::new(Mutex::new(server));
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = shutdown.clone();
        let handle = thread::spawn(move || {
            while !shutdown_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        info!("event=raft_server_accept addr={} peer={addr}", config.bind);
                        let tls = tls_config.clone();
                        let server = shared_server.clone();
                        thread::spawn(move || {
                            if let Err(err) = handle_connection(stream, addr, tls, server) {
                                warn!("raft connection error from {addr}: {err}");
                            }
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(err) => {
                        warn!(
                            "event=raft_server_accept_error addr={} error={}",
                            config.bind, err
                        );
                        break;
                    }
                }
            }
        });
        Ok(RaftNetworkServerHandle {
            shutdown,
            join: Some(handle),
        })
    }
}

pub struct RaftNetworkClientConfig {
    pub host: String,
    pub port: u16,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
    pub mtls: MtlsIdentityManager,
}

pub struct RaftNetworkClient {
    host: String,
    port: u16,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
    mtls: MtlsIdentityManager,
    session: Option<ClientSession>,
}

impl RaftNetworkClient {
    pub fn new(config: RaftNetworkClientConfig) -> Result<Self, NetError> {
        let mut tls_config = config.identity.client_config(&config.trust_store)?;
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(SpiffeServerVerifier::new(
                config.trust_store.roots.clone(),
            )));
        let tls_config = Arc::new(tls_config);
        Ok(Self {
            host: config.host.clone(),
            port: config.port,
            server_name: server_name(&config.host)?,
            tls_config,
            mtls: config.mtls,
            session: None,
        })
    }

    pub fn refresh_revocation(&mut self, now: Instant) {
        self.mtls
            .record_revocation_refresh(RevocationSource::Ocsp, now);
        self.mtls
            .record_revocation_refresh(RevocationSource::Crl, now);
    }

    pub fn request_vote(
        &mut self,
        request: &RequestVoteRequest,
        now: Instant,
    ) -> Result<RequestVoteResponse, NetError> {
        let frame = request
            .encode()
            .map_err(|err| NetError::Protocol(err.to_string()))?;
        let payload = self.send(OP_REQUEST_VOTE, &frame, now)?;
        RequestVoteResponse::decode(&payload).map_err(|err| NetError::Protocol(err.to_string()))
    }

    pub fn append_entries(
        &mut self,
        request: &AppendEntriesRequest,
        now: Instant,
    ) -> Result<AppendEntriesResponse, NetError> {
        let frame = request
            .encode()
            .map_err(|err| NetError::Protocol(err.to_string()))?;
        let payload = self.send(OP_APPEND_ENTRIES, &frame, now)?;
        AppendEntriesResponse::decode(&payload).map_err(|err| NetError::Protocol(err.to_string()))
    }

    fn send(&mut self, opcode: u8, payload: &[u8], now: Instant) -> Result<Vec<u8>, NetError> {
        let mut attempts = 0;
        loop {
            attempts += 1;
            match self.ensure_session(now) {
                Ok(session) => match session.send(opcode, payload) {
                    Ok(response) => return Ok(response),
                    Err(err) => {
                        self.session.take();
                        if attempts >= 2 {
                            return Err(err);
                        }
                        continue;
                    }
                },
                Err(err) => {
                    if attempts >= 2 {
                        return Err(err);
                    }
                    continue;
                }
            }
        }
    }

    fn connect(&self) -> Result<TcpStream, NetError> {
        let target = format!("{}:{}", self.host, self.port);
        let mut last_err = None;
        for addr in target.to_socket_addrs().map_err(NetError::Io)? {
            debug!("event=raft_client_tcp_attempt peer={addr}");
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    info!("event=raft_client_tcp_connected peer={addr}");
                    return Ok(stream);
                }
                Err(err) => {
                    debug!("event=raft_client_tcp_error peer={} error={}", addr, err);
                    last_err = Some(err);
                }
            }
        }
        Err(NetError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::other("unable to connect to Raft peer")
        })))
    }

    fn ensure_session(&mut self, now: Instant) -> Result<&mut ClientSession, NetError> {
        if self.session.is_none() {
            let session = ClientSession::connect(
                self.connect()?,
                self.tls_config.clone(),
                self.server_name.clone(),
                &mut self.mtls,
                now,
            )?;
            self.session = Some(session);
        }
        Ok(self.session.as_mut().expect("session set"))
    }
}

struct ClientSession {
    stream: TcpStream,
    conn: ClientConnection,
}

impl ClientSession {
    fn connect(
        mut stream: TcpStream,
        tls_config: Arc<ClientConfig>,
        server_name: ServerName,
        mtls: &mut MtlsIdentityManager,
        now: Instant,
    ) -> Result<Self, NetError> {
        let mut conn = ClientConnection::new(tls_config, server_name)?;
        complete_client_handshake(&mut conn, &mut stream)?;
        match stream.peer_addr() {
            Ok(addr) => info!("event=raft_client_tls_session peer={addr}"),
            Err(_) => debug!("event=raft_client_tls_session peer=unknown"),
        }
        let peer_chain = conn
            .peer_certificates()
            .ok_or_else(|| NetError::Certificate("peer presented no certificate".into()))?;
        let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
        mtls.verify_peer(&peer_certificate, now)
            .map_err(|err| NetError::Protocol(format!("mTLS verification failed: {err}")))?;
        Ok(Self { stream, conn })
    }

    fn send(&mut self, opcode: u8, payload: &[u8]) -> Result<Vec<u8>, NetError> {
        let mut tls = Stream::new(&mut self.conn, &mut self.stream);
        write_frame(&mut tls, opcode, payload)?;
        read_response(&mut tls)
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        match self.stream.peer_addr() {
            Ok(addr) => info!("event=raft_client_disconnect peer={addr}"),
            Err(_) => debug!("event=raft_client_disconnect peer=unknown"),
        }
    }
}

fn handle_connection<H: RaftRpcHandler>(
    mut stream: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    server: Arc<Mutex<RaftRpcServer<H>>>,
) -> Result<(), NetError> {
    let mut conn = ServerConnection::new(tls_config)?;
    complete_server_handshake(&mut conn, &mut stream)?;
    info!("event=raft_tls_session peer={addr}");
    let peer_chain = conn
        .peer_certificates()
        .ok_or_else(|| NetError::Certificate("client presented no certificate".into()))?;
    let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
    let mut tls = Stream::new(&mut conn, &mut stream);
    loop {
        let mut header = [0u8; 5];
        match tls.read_exact(&mut header) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("event=raft_connection_close peer={addr}");
                return Ok(());
            }
            Err(err) => return Err(NetError::Io(err)),
        }
        let opcode = header[0];
        let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; len];
        tls.read_exact(&mut payload)?;
        let now = Instant::now();
        let mut guard = server.lock().expect("RaftRpcServer poisoned");
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

struct SpiffeServerVerifier {
    roots: RootCertStore,
}

impl SpiffeServerVerifier {
    fn new(roots: RootCertStore) -> Self {
        Self { roots }
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &RustlsCertificate,
        intermediates: &[RustlsCertificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(&cert, &self.roots, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }
}

fn write_frame(stream: &mut impl Write, opcode: u8, payload: &[u8]) -> Result<(), NetError> {
    let mut header = [0u8; 5];
    header[0] = opcode;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    Ok(())
}

fn read_response(stream: &mut impl Read) -> Result<Vec<u8>, NetError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let status = header[0];
    let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    if status == STATUS_OK {
        Ok(payload)
    } else {
        Err(NetError::Protocol(
            String::from_utf8(payload).unwrap_or_else(|_| "remote error".into()),
        ))
    }
}

fn write_response(stream: &mut impl Write, status: u8, payload: &[u8]) -> Result<(), NetError> {
    let mut header = [0u8; 5];
    header[0] = status;
    header[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    Ok(())
}
