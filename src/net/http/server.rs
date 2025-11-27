#![cfg(all(feature = "net", feature = "management"))]

use super::{HttpHandlerError, HttpRequestContext, RequestDeadline, SimpleHttpRequest};
use crate::net::server::{spawn_listener, ServerHandle};
use crate::net::tls::{complete_server_handshake, decode_peer_certificate};
use crate::net::{CertificateError, NetError};
use rustls::{ServerConfig, ServerConnection, Stream};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_tls_http_server<H, D, M>(
    name: &'static str,
    listener: TcpListener,
    max_connections: Option<usize>,
    tls_config: Arc<ServerConfig>,
    stream_timeout: std::time::Duration,
    deadline_for: D,
    handler: H,
    map_error: M,
) -> Result<ServerHandle, NetError>
where
    H: Fn(
            &HttpRequestContext,
            SimpleHttpRequest,
            &mut dyn Write,
            Instant,
        ) -> Result<(), HttpHandlerError>
        + Send
        + Sync
        + 'static,
    D: Fn(&SimpleHttpRequest) -> RequestDeadline + Send + Sync + 'static,
    M: Fn(HttpHandlerError, &SimpleHttpRequest) -> Result<(), NetError> + Send + Sync + 'static,
{
    let deadline_for = Arc::new(deadline_for);
    let handler = Arc::new(handler);
    let map_error = Arc::new(map_error);
    let server_tls = tls_config.clone();
    let handle = move |mut stream: TcpStream,
                       _addr: std::net::SocketAddr,
                       _shutdown: Arc<AtomicBool>|
          -> Result<(), NetError> {
        configure_stream(&stream, stream_timeout)?;
        let mut conn = ServerConnection::new(server_tls.clone())?;
        complete_server_handshake(&mut conn, &mut stream)?;
        let peer_chain = conn.peer_certificates().ok_or_else(|| {
            NetError::from(CertificateError::MissingClientCertificate { context: name })
        })?;
        let peer_certificate = decode_peer_certificate(peer_chain, Instant::now())?;
        let mut tls = Stream::new(&mut conn, &mut stream);
        let request = super::read_request(&mut tls)?;
        let deadline = deadline_for(&request);
        let ctx = HttpRequestContext::new(peer_certificate, deadline);
        let now = Instant::now();
        let result = handler(&ctx, request.clone(), &mut tls, now);
        match result {
            Ok(()) => Ok(()),
            Err(err) => map_error(err, &request),
        }
    };
    spawn_listener(name, listener, max_connections, handle).map_err(NetError::from)
}

fn configure_stream(stream: &TcpStream, timeout: std::time::Duration) -> Result<(), NetError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(NetError::from)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(NetError::from)?;
    Ok(())
}
