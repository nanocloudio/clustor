#![cfg(feature = "net")]

use crate::control_plane::core::client::{
    CpApiTransport, CpClientError, TransportError, TransportResponse,
};
use crate::net::http::RequestDeadline;
use crate::net::tls::{decode_peer_certificate, server_name, TlsIdentity, TlsTrustStore};
use crate::net::{CertificateError, HttpError, NetError};
use crate::retry::RetryPolicy;
use httparse::Status;
use rustls::client::{ClientConfig, ClientConnection, ServerName};
use rustls::Stream;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const CP_HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const CP_HTTP_MAX_ATTEMPTS: usize = 3;
const CP_HTTP_BACKOFF_MS: Duration = Duration::from_millis(100);
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

pub struct HttpCpTransportBuilder {
    base_url: Url,
    identity: Option<TlsIdentity>,
    trust_store: Option<TlsTrustStore>,
    socket_timeout: Duration,
    retry_policy: RetryPolicy,
    pool_size: Option<usize>,
}

pub struct HttpCpTransport {
    authority: String,
    host: String,
    port: u16,
    base: Url,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
    socket_timeout: Duration,
    retry_policy: RetryPolicy,
    pool: Option<Arc<ConnectionPool>>,
}

impl HttpCpTransportBuilder {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, NetError> {
        let url = Url::parse(base_url.as_ref())?;
        if url.scheme() != "https" {
            return Err(NetError::from(HttpError::UnsupportedScheme {
                scheme: url.scheme().to_string(),
            }));
        }
        Ok(Self {
            base_url: ensure_trailing_slash(url),
            identity: None,
            trust_store: None,
            socket_timeout: CP_HTTP_DEFAULT_TIMEOUT,
            retry_policy: RetryPolicy::linear(CP_HTTP_MAX_ATTEMPTS, CP_HTTP_BACKOFF_MS)
                .with_skip_first_delay(true),
            pool_size: None,
        })
    }

    pub fn identity(mut self, identity: TlsIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn trust_store(mut self, trust: TlsTrustStore) -> Self {
        self.trust_store = Some(trust);
        self
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

    pub fn connection_pool(mut self, max_idle: usize) -> Self {
        if max_idle > 0 {
            self.pool_size = Some(max_idle);
        } else {
            self.pool_size = None;
        }
        self
    }

    pub fn build(self) -> Result<HttpCpTransport, NetError> {
        let identity = self.identity.ok_or(HttpError::MissingIdentityMaterial)?;
        let trust = self.trust_store.ok_or(HttpError::MissingTrustStore)?;
        let host = self
            .base_url
            .host_str()
            .ok_or(HttpError::MissingHost)?
            .to_string();
        let port = self.base_url.port_or_known_default().unwrap_or(443);
        let authority = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let tls_config = Arc::new(identity.client_config(&trust)?);
        let pool = self
            .pool_size
            .map(|size| Arc::new(ConnectionPool::new(size)));
        Ok(HttpCpTransport {
            authority,
            host: host.clone(),
            port,
            base: self.base_url,
            tls_config,
            server_name: server_name(&host)?,
            socket_timeout: self.socket_timeout,
            retry_policy: self.retry_policy,
            pool,
        })
    }
}

impl CpApiTransport for HttpCpTransport {
    fn get(&self, path: &str) -> Result<TransportResponse, CpClientError> {
        self.execute_get(path)
            .map_err(|err| CpClientError::from(TransportError::from(err)))
    }
}

impl HttpCpTransport {
    fn execute_get(&self, path: &str) -> Result<TransportResponse, NetError> {
        let mut retry = self.retry_policy.handle();
        loop {
            match self.execute_get_once(path) {
                Ok(response) => return Ok(response),
                Err(err) => {
                    if !self.should_retry(&err) {
                        return Err(err);
                    }
                    if let Some(delay) = retry.next_delay() {
                        if !delay.is_zero() {
                            std::thread::sleep(delay);
                        }
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    fn execute_get_once(&self, path: &str) -> Result<TransportResponse, NetError> {
        let url = self.build_url(path)?;
        let deadline = RequestDeadline::from_timeout(self.socket_timeout);
        let mut lease = self.acquire_stream(&deadline)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: {}\r\n\r\n",
            url,
            self.authority,
            if self.pool.is_some() {
                "keep-alive"
            } else {
                "close"
            }
        );
        {
            deadline.enforce()?;
            let (conn, io) = lease.parts();
            let mut tls = Stream::new(conn, io);
            if let Err(err) = tls.write_all(request.as_bytes()) {
                lease.mark_broken();
                return Err(map_io_error(err));
            }
            if let Err(err) = tls.flush() {
                lease.mark_broken();
                return Err(map_io_error(err));
            }
            deadline.enforce()?;
            let (status, body) = match read_http_response(&mut tls) {
                Ok(value) => value,
                Err(err) => {
                    lease.mark_broken();
                    return Err(err);
                }
            };
            if status != 200 {
                lease.mark_broken();
                return Err(NetError::from(HttpError::UnexpectedStatus { status }));
            }
            let now = Instant::now();
            let peer_chain = lease.conn().peer_certificates().ok_or_else(|| {
                NetError::from(CertificateError::MissingPeerCertificate {
                    context: "cp_transport",
                })
            })?;
            let server_certificate = decode_peer_certificate(peer_chain, now)?;
            Ok(TransportResponse {
                body,
                server_certificate,
            })
        }
    }

    fn acquire_stream(&self, deadline: &RequestDeadline) -> Result<StreamLease, NetError> {
        if let Some(pool) = &self.pool {
            if let Some(connection) = pool.checkout() {
                apply_deadline(&connection.stream, deadline)?;
                return Ok(StreamLease::pooled(connection, Some(pool.clone())));
            }
        }
        let connection = self.open_stream(deadline)?;
        let pool = self.pool.clone();
        Ok(StreamLease::pooled(connection, pool))
    }

    fn open_stream(&self, deadline: &RequestDeadline) -> Result<PooledConnection, NetError> {
        let mut last_err = None;
        let target = format!("{}:{}", self.host, self.port);
        let addrs: Vec<SocketAddr> = target.to_socket_addrs().map_err(NetError::Io)?.collect();
        if addrs.is_empty() {
            return Err(NetError::Io(io::Error::other(
                "no control-plane addresses resolved",
            )));
        }
        for addr in addrs {
            let timeout = remaining_duration(deadline)?;
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    apply_deadline(&stream, deadline)?;
                    let conn =
                        ClientConnection::new(self.tls_config.clone(), self.server_name.clone())?;
                    return Ok(PooledConnection { conn, stream });
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(NetError::Io(last_err.unwrap_or_else(|| {
            io::Error::other("unable to connect to control-plane endpoint")
        })))
    }

    fn build_url(&self, path: &str) -> Result<String, NetError> {
        let trimmed = path.trim_start_matches('/');
        let relative = if trimmed.is_empty() { "." } else { trimmed };
        let resolved = self
            .base
            .join(relative)
            .map_err(HttpError::InvalidEndpointPath)?;
        if resolved.host_str().map(|h| h != self.host).unwrap_or(true) {
            return Err(NetError::from(HttpError::HostMismatch));
        }
        let mut result = resolved.path().to_string();
        if result.is_empty() {
            result.push('/');
        }
        if let Some(query) = resolved.query() {
            result.push('?');
            result.push_str(query);
        }
        Ok(result)
    }

    fn should_retry(&self, err: &NetError) -> bool {
        matches!(err, NetError::Io(_) | NetError::Tls(_))
    }
}

struct ConnectionPool {
    max: usize,
    idle: Mutex<Vec<PooledConnection>>,
}

impl ConnectionPool {
    fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            idle: Mutex::new(Vec::new()),
        }
    }

    fn checkout(&self) -> Option<PooledConnection> {
        match self.idle.lock() {
            Ok(mut guard) => guard.pop(),
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.clear();
                None
            }
        }
    }

    fn put(&self, connection: PooledConnection) {
        match self.idle.lock() {
            Ok(mut guard) => {
                if guard.len() < self.max {
                    guard.push(connection);
                }
            }
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                if guard.len() < self.max {
                    guard.push(connection);
                }
            }
        }
    }
}

struct PooledConnection {
    conn: ClientConnection,
    stream: TcpStream,
}

struct StreamLease {
    connection: Option<PooledConnection>,
    pool: Option<Arc<ConnectionPool>>,
    reusable: bool,
}

impl StreamLease {
    fn pooled(connection: PooledConnection, pool: Option<Arc<ConnectionPool>>) -> Self {
        let reusable = pool.is_some();
        Self {
            connection: Some(connection),
            pool,
            reusable,
        }
    }

    fn parts(&mut self) -> (&mut ClientConnection, &mut TcpStream) {
        let connection = self.connection.as_mut().expect("pooled connection missing");
        (&mut connection.conn, &mut connection.stream)
    }

    fn conn(&mut self) -> &mut ClientConnection {
        &mut self
            .connection
            .as_mut()
            .expect("pooled connection missing")
            .conn
    }

    fn mark_broken(&mut self) {
        self.reusable = false;
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        if !self.reusable {
            return;
        }
        if let (Some(pool), Some(connection)) = (self.pool.take(), self.connection.take()) {
            pool.put(connection);
        }
    }
}

fn apply_deadline(stream: &TcpStream, deadline: &RequestDeadline) -> Result<(), NetError> {
    let timeout = remaining_duration(deadline)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(NetError::from)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(NetError::from)?;
    Ok(())
}

fn remaining_duration(deadline: &RequestDeadline) -> Result<Duration, NetError> {
    deadline
        .remaining()
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| NetError::from(HttpError::RequestTimeout))
}

fn read_http_response(stream: &mut impl Read) -> Result<(u16, Vec<u8>), NetError> {
    let mut buffer = Vec::new();
    let mut header_end = None;
    let mut temp = [0u8; 1024];
    while header_end.is_none() {
        let read = stream.read(&mut temp).map_err(map_read_error)?;
        if read == 0 {
            return Err(NetError::from(HttpError::ResponseParse));
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(NetError::from(HttpError::HeadersTooLarge));
        }
        if let Some(pos) = find_header_terminator(&buffer) {
            header_end = Some(pos + 4);
        }
    }
    let header_len = header_end.ok_or(HttpError::ResponseParse)?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(&buffer) {
        Ok(Status::Complete(_)) => {}
        _ => return Err(NetError::from(HttpError::ResponseParse)),
    }
    let status = response
        .code
        .ok_or_else(|| NetError::from(HttpError::MissingStatusCode))?;
    let mut content_length: Option<usize> = None;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| NetError::from(HttpError::InvalidContentLengthHeader))?;
            let len = value
                .parse::<usize>()
                .map_err(|_| NetError::from(HttpError::InvalidContentLengthValue))?;
            content_length = Some(len);
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(NetError::from(HttpError::ChunkedEncodingUnsupported));
        }
    }
    let len = content_length.ok_or_else(|| NetError::from(HttpError::MissingContentLength))?;
    if len > MAX_RESPONSE_BODY_BYTES {
        return Err(NetError::from(HttpError::BodyTooLarge));
    }
    let mut body = Vec::with_capacity(len);
    let already = buffer.len() - header_len;
    if already > 0 {
        let copy_len = already.min(len);
        body.extend_from_slice(&buffer[header_len..header_len + copy_len]);
    }
    while body.len() < len {
        let read = stream.read(&mut temp).map_err(map_read_error)?;
        if read == 0 {
            return Err(NetError::from(HttpError::TruncatedBody));
        }
        let remaining = len - body.len();
        body.extend_from_slice(&temp[..read.min(remaining)]);
    }
    Ok((status, body))
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn map_io_error(err: io::Error) -> NetError {
    if matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    ) {
        NetError::from(HttpError::RequestTimeout)
    } else {
        NetError::from(err)
    }
}

fn map_read_error(err: io::Error) -> NetError {
    if matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    ) {
        NetError::from(HttpError::RequestTimeout)
    } else {
        NetError::from(err)
    }
}

fn ensure_trailing_slash(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let mut path = url.path().to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        url.set_path(&path);
    }
    url
}
