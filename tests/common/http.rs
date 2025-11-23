#![cfg(test)]

use clustor::net::{TlsIdentity, TlsTrustStore};
use rustls::client::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn https_request(
    addr: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    body: &[u8],
    identity: &TlsIdentity,
    trust: &TlsTrustStore,
) -> Result<HttpResponse, Box<dyn Error>> {
    let config = identity.client_config(trust)?;
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(host).map_err(|_| "invalid host")?,
    )?;
    let stream = TcpStream::connect(addr)?;
    let mut tls = StreamOwned::new(conn, stream);
    let mut request_bytes = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        method,
        path,
        host,
        body.len()
    )
    .into_bytes();
    request_bytes.extend_from_slice(body);
    tls.write_all(&request_bytes)?;

    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(Box::new(err)),
        }
    }
    let (status, payload) = parse_http_response(&response)?;
    Ok(HttpResponse {
        status,
        body: payload.to_vec(),
    })
}

fn parse_http_response(buffer: &[u8]) -> Result<(u16, &[u8]), Box<dyn Error>> {
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("response missing header terminator")?;
    let header = &buffer[..header_end];
    let status = parse_status_line(header)?;
    Ok((status, &buffer[header_end + 4..]))
}

fn parse_status_line(header: &[u8]) -> Result<u16, Box<dyn Error>> {
    let status_line_end = header
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(header.len());
    let status_line = std::str::from_utf8(&header[..status_line_end])?;
    let mut parts = status_line.split_whitespace();
    let _protocol = parts.next();
    let code = parts
        .next()
        .ok_or("missing HTTP status code")?
        .parse::<u16>()?;
    Ok(code)
}
