#![cfg(feature = "net")]

use super::tls::{decode_peer_certificate, server_name, TlsIdentity, TlsTrustStore};
use super::NetError;
use crate::cp::client::{CpApiTransport, CpClientError, TransportResponse};
use rustls::client::{ClientConfig, ClientConnection, ServerName};
use rustls::Stream;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;
use url::Url;

pub struct HttpCpTransportBuilder {
    base_url: Url,
    identity: Option<TlsIdentity>,
    trust_store: Option<TlsTrustStore>,
}

pub struct HttpCpTransport {
    authority: String,
    host: String,
    port: u16,
    base: Url,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName,
}

impl HttpCpTransportBuilder {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, NetError> {
        let url = Url::parse(base_url.as_ref())?;
        if url.scheme() != "https" {
            return Err(NetError::Http(
                "control-plane transport requires https:// base URLs".into(),
            ));
        }
        Ok(Self {
            base_url: ensure_trailing_slash(url),
            identity: None,
            trust_store: None,
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

    pub fn build(self) -> Result<HttpCpTransport, NetError> {
        let identity = self
            .identity
            .ok_or_else(|| NetError::Http("identity material not provided".into()))?;
        let trust = self
            .trust_store
            .ok_or_else(|| NetError::Http("trust store not provided".into()))?;
        let host = self
            .base_url
            .host_str()
            .ok_or_else(|| NetError::Http("control-plane URL missing host".into()))?
            .to_string();
        let port = self.base_url.port_or_known_default().unwrap_or(443);
        let authority = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let tls_config = Arc::new(identity.client_config(&trust)?);
        Ok(HttpCpTransport {
            authority,
            host: host.clone(),
            port,
            base: self.base_url,
            tls_config,
            server_name: server_name(&host)?,
        })
    }
}

impl CpApiTransport for HttpCpTransport {
    fn get(&self, path: &str) -> Result<TransportResponse, CpClientError> {
        self.execute_get(path)
            .map_err(|err| CpClientError::Transport(err.to_string()))
    }
}

impl HttpCpTransport {
    fn execute_get(&self, path: &str) -> Result<TransportResponse, NetError> {
        let url = self.build_url(path)?;
        let mut stream = self.connect()?;
        let mut conn = ClientConnection::new(self.tls_config.clone(), self.server_name.clone())?;
        let mut tls = Stream::new(&mut conn, &mut stream);
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            url, self.authority
        );
        tls.write_all(request.as_bytes())?;
        tls.flush()?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response)?;
        let (status, body) = parse_http_response(&response)?;
        if status != 200 {
            return Err(NetError::Http(format!(
                "control-plane endpoint returned HTTP {status}"
            )));
        }
        let now = Instant::now();
        let peer_chain = conn
            .peer_certificates()
            .ok_or_else(|| NetError::Certificate("peer presented no certificate".into()))?;
        let server_certificate = decode_peer_certificate(peer_chain, now)?;
        Ok(TransportResponse {
            body,
            server_certificate,
        })
    }

    fn connect(&self) -> Result<TcpStream, NetError> {
        let target = format!("{}:{}", self.host, self.port);
        let mut last_err = None;
        for addr in target.to_socket_addrs().map_err(NetError::Io)? {
            match TcpStream::connect(addr) {
                Ok(stream) => return Ok(stream),
                Err(err) => last_err = Some(err),
            }
        }
        Err(NetError::Io(last_err.unwrap_or_else(|| {
            std::io::Error::other("unable to resolve control-plane endpoint")
        })))
    }

    fn build_url(&self, path: &str) -> Result<String, NetError> {
        let trimmed = path.trim_start_matches('/');
        let relative = if trimmed.is_empty() { "." } else { trimmed };
        let resolved = self
            .base
            .join(relative)
            .map_err(|err| NetError::Http(format!("invalid endpoint path: {err}")))?;
        if resolved.host_str().map(|h| h != self.host).unwrap_or(true) {
            return Err(NetError::Http(
                "endpoint path attempted to change host".into(),
            ));
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
}

fn parse_http_response(buffer: &[u8]) -> Result<(u16, Vec<u8>), NetError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let header_len = match response.parse(buffer) {
        Ok(httparse::Status::Complete(len)) => len,
        _ => {
            return Err(NetError::Http(
                "failed to parse HTTP response from control plane".into(),
            ))
        }
    };
    let status = response
        .code
        .ok_or_else(|| NetError::Http("HTTP response missing status code".into()))?;
    let mut content_length: Option<usize> = None;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| NetError::Http("invalid Content-Length header".into()))?;
            let len = value
                .parse::<usize>()
                .map_err(|_| NetError::Http("invalid Content-Length value".into()))?;
            content_length = Some(len);
        } else if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            return Err(NetError::Http(
                "chunked transfer encoding is not supported".into(),
            ));
        }
    }
    let len =
        content_length.ok_or_else(|| NetError::Http("Content-Length header missing".into()))?;
    if buffer.len() < header_len + len {
        return Err(NetError::Http("truncated HTTP body".into()));
    }
    Ok((status, buffer[header_len..header_len + len].to_vec()))
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
