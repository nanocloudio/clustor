#![cfg(feature = "net")]

use super::{
    OP_APPEND_ENTRIES, OP_REQUEST_VOTE, RAFT_CLIENT_BACKOFF_MS, RAFT_CLIENT_RETRY_ATTEMPTS,
    RAFT_CLIENT_SOCKET_TIMEOUT, STATUS_OK,
};
use crate::net::tls::{
    complete_client_handshake, decode_peer_certificate, server_name, TlsIdentity, TlsTrustStore,
};
use crate::net::CertificateError;
use crate::net::{NetError, ProtocolError};
use crate::replication::raft::{
    AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse,
};
use crate::retry::RetryPolicy;
use crate::security::{MtlsIdentityManager, RevocationSource};
use log::{debug, info};
use parking_lot::Mutex;
use rustls::client::{ClientConfig, ClientConnection, ServerName};
use rustls::Stream;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub struct RaftNetworkClientConfig {
    pub host: String,
    pub port: u16,
    pub identity: TlsIdentity,
    pub trust_store: TlsTrustStore,
    pub mtls: MtlsIdentityManager,
}

pub struct RaftNetworkClientOptions {
    socket_timeout: Duration,
    retry_policy: RetryPolicy,
}

impl Default for RaftNetworkClientOptions {
    fn default() -> Self {
        Self {
            socket_timeout: RAFT_CLIENT_SOCKET_TIMEOUT,
            retry_policy: RetryPolicy::linear(RAFT_CLIENT_RETRY_ATTEMPTS, RAFT_CLIENT_BACKOFF_MS)
                .with_skip_first_delay(true),
        }
    }
}

impl RaftNetworkClientOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn socket_timeout(mut self, timeout: Duration) -> Self {
        self.socket_timeout = timeout.max(Duration::from_millis(1));
        self
    }

    pub fn retry_backoff(mut self, max_attempts: usize, base_delay: Duration) -> Self {
        self.retry_policy =
            RetryPolicy::linear(max_attempts, base_delay).with_skip_first_delay(true);
        self
    }
}

pub struct RaftNetworkClient {
    host: String,
    port: u16,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
    socket_timeout: Duration,
    retry_policy: RetryPolicy,
    mtls: Mutex<MtlsIdentityManager>,
    session: Mutex<Option<ClientSession>>,
    active_interrupt: Mutex<Option<ClientSessionInterrupt>>,
    cancelled: AtomicBool,
}

impl RaftNetworkClient {
    pub fn new(config: RaftNetworkClientConfig) -> Result<Self, NetError> {
        Self::with_options(config, RaftNetworkClientOptions::default())
    }

    pub fn with_options(
        config: RaftNetworkClientConfig,
        options: RaftNetworkClientOptions,
    ) -> Result<Self, NetError> {
        let tls_config = Arc::new(config.identity.client_config(&config.trust_store)?);
        Ok(Self {
            host: config.host.clone(),
            port: config.port,
            server_name: server_name(&config.host)?,
            tls_config,
            socket_timeout: options.socket_timeout,
            retry_policy: options.retry_policy,
            mtls: Mutex::new(config.mtls),
            session: Mutex::new(None),
            active_interrupt: Mutex::new(None),
            cancelled: AtomicBool::new(false),
        })
    }

    pub fn refresh_revocation(&self, now: Instant) {
        let mut mtls = self.mtls.lock();
        mtls.record_revocation_refresh(RevocationSource::Ocsp, now);
        mtls.record_revocation_refresh(RevocationSource::Crl, now);
    }

    pub fn request_vote(
        &self,
        request: &RequestVoteRequest,
        now: Instant,
    ) -> Result<RequestVoteResponse, NetError> {
        let frame = request.encode().map_err(|err| {
            NetError::from(ProtocolError::FrameEncode {
                context: "request_vote",
                details: err.to_string(),
            })
        })?;
        let abort = || false;
        let payload = self.send(OP_REQUEST_VOTE, &frame, now, &abort)?;
        RequestVoteResponse::decode(&payload).map_err(|err| {
            NetError::from(ProtocolError::FrameDecode {
                context: "request_vote",
                details: err.to_string(),
            })
        })
    }

    pub fn append_entries(
        &self,
        request: &AppendEntriesRequest,
        now: Instant,
    ) -> Result<AppendEntriesResponse, NetError> {
        self.append_entries_with_abort(request, now, || false)
    }

    pub fn append_entries_with_abort<F>(
        &self,
        request: &AppendEntriesRequest,
        now: Instant,
        should_abort: F,
    ) -> Result<AppendEntriesResponse, NetError>
    where
        F: Fn() -> bool,
    {
        let frame = request.encode().map_err(|err| {
            NetError::from(ProtocolError::FrameEncode {
                context: "append_entries",
                details: err.to_string(),
            })
        })?;
        let payload = self.send(OP_APPEND_ENTRIES, &frame, now, &should_abort)?;
        AppendEntriesResponse::decode(&payload).map_err(|err| {
            NetError::from(ProtocolError::FrameDecode {
                context: "append_entries",
                details: err.to_string(),
            })
        })
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.abort_active_interrupt();
        let mut guard = self.session.lock();
        if let Some(mut session) = guard.take() {
            session.abort();
        }
    }

    fn send<F>(
        &self,
        opcode: u8,
        payload: &[u8],
        now: Instant,
        should_abort: &F,
    ) -> Result<Vec<u8>, NetError>
    where
        F: Fn() -> bool,
    {
        let mut retry = self.retry_policy.handle();
        loop {
            if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                return Err(Self::cancelled_error());
            }
            let mut session = match self.ensure_session(now) {
                Ok(session) => session,
                Err(err) => {
                    if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                        return Err(Self::cancelled_error());
                    }
                    if !self.should_retry(&err) {
                        return Err(err);
                    }
                    if let Some(delay) = retry.next_delay() {
                        self.delay_with_abort(delay, should_abort)?;
                    } else {
                        return Err(err);
                    }
                    continue;
                }
            };
            if let Err(err) = self.install_interrupt(&session) {
                self.release_interrupt();
                self.return_session(session);
                return Err(err);
            }
            match session.send(opcode, payload) {
                Ok(response) => {
                    self.release_interrupt();
                    self.return_session(session);
                    return Ok(response);
                }
                Err(err) => {
                    self.release_interrupt();
                    session.abort();
                    if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                        return Err(Self::cancelled_error());
                    }
                    if !self.should_retry(&err) {
                        return Err(err);
                    }
                    if let Some(delay) = retry.next_delay() {
                        self.delay_with_abort(delay, should_abort)?;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    fn delay_with_abort<F>(&self, delay: Duration, should_abort: &F) -> Result<(), NetError>
    where
        F: Fn() -> bool,
    {
        if delay.is_zero() {
            return Ok(());
        }
        let mut remaining = delay;
        while remaining > Duration::from_millis(0) {
            if self.cancelled.load(Ordering::SeqCst) || should_abort() {
                return Err(Self::cancelled_error());
            }
            let slice = remaining.min(Duration::from_millis(50));
            std::thread::sleep(slice);
            if slice >= remaining {
                break;
            }
            remaining -= slice;
        }
        Ok(())
    }

    fn cancelled_error() -> NetError {
        NetError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "raft client cancelled",
        ))
    }

    fn ensure_session(&self, now: Instant) -> Result<ClientSession, NetError> {
        if let Some(session) = self.session.lock().take() {
            return Ok(session);
        }
        self.connect_session(now)
    }

    fn return_session(&self, session: ClientSession) {
        let mut guard = self.session.lock();
        *guard = Some(session);
    }

    fn connect_session(&self, now: Instant) -> Result<ClientSession, NetError> {
        let stream = self.connect()?;
        let mut mtls = self.mtls.lock();
        ClientSession::connect(
            stream,
            self.tls_config.clone(),
            self.server_name.clone(),
            &mut mtls,
            now,
        )
    }

    fn install_interrupt(&self, session: &ClientSession) -> Result<(), NetError> {
        let handle = ClientSessionInterrupt::from_stream(session.stream())?;
        let mut guard = self.active_interrupt.lock();
        *guard = Some(handle);
        Ok(())
    }

    fn release_interrupt(&self) {
        self.active_interrupt.lock().take();
    }

    fn abort_active_interrupt(&self) {
        if let Some(handle) = self.active_interrupt.lock().take() {
            handle.shutdown();
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
                    stream
                        .set_read_timeout(Some(self.socket_timeout))
                        .map_err(NetError::Io)?;
                    stream
                        .set_write_timeout(Some(self.socket_timeout))
                        .map_err(NetError::Io)?;
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

    fn should_retry(&self, err: &NetError) -> bool {
        matches!(err, NetError::Io(_) | NetError::Tls(_))
    }
}

struct ClientSessionInterrupt {
    stream: TcpStream,
}

impl ClientSessionInterrupt {
    fn from_stream(stream: &TcpStream) -> Result<Self, NetError> {
        stream
            .try_clone()
            .map(|stream| Self { stream })
            .map_err(NetError::Io)
    }

    fn shutdown(self) {
        let _ = self.stream.shutdown(Shutdown::Both);
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
        let peer_chain = conn.peer_certificates().ok_or_else(|| {
            NetError::from(CertificateError::MissingPeerCertificate {
                context: "raft_client",
            })
        })?;
        let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
        mtls.verify_peer(&peer_certificate, now).map_err(|err| {
            NetError::from(ProtocolError::MtlsVerification {
                details: err.to_string(),
            })
        })?;
        Ok(Self { stream, conn })
    }

    fn stream(&self) -> &TcpStream {
        &self.stream
    }

    fn send(&mut self, opcode: u8, payload: &[u8]) -> Result<Vec<u8>, NetError> {
        let mut tls = Stream::new(&mut self.conn, &mut self.stream);
        write_frame(&mut tls, opcode, payload)?;
        read_response(&mut tls)
    }

    fn abort(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
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
    let len = u32::from_le_bytes(
        header[1..5]
            .try_into()
            .map_err(|_| NetError::from(ProtocolError::FrameLength))?,
    ) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    if status == STATUS_OK {
        Ok(payload)
    } else {
        let message = String::from_utf8(payload).ok();
        Err(NetError::from(ProtocolError::RemoteError {
            status,
            message,
        }))
    }
}
