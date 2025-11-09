#![cfg(feature = "net")]

use super::NetError;
use httparse::Status;
use serde::Serialize;
use std::fmt::Write as _;
use std::io::{Read, Write};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SimpleHttpRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl SimpleHttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn path_segments(&self) -> Vec<&str> {
        self.path
            .trim_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect()
    }
}

pub fn read_request(stream: &mut impl Read) -> Result<SimpleHttpRequest, NetError> {
    let mut buffer = Vec::new();
    let mut header_end = None;
    let mut temp = [0u8; 1024];
    while header_end.is_none() {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            return Err(NetError::Http(
                "connection closed while reading headers".into(),
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(NetError::Http("HTTP headers exceed limit".into()));
        }
        if let Some(pos) = find_header_terminator(&buffer) {
            header_end = Some(pos + 4);
        }
    }
    let header_len = header_end.unwrap();
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(&buffer) {
        Ok(Status::Complete(_)) => {}
        Ok(Status::Partial) => {
            return Err(NetError::Http(
                "partial HTTP request received; headers incomplete".into(),
            ))
        }
        Err(err) => {
            return Err(NetError::Http(format!(
                "failed to parse HTTP request: {err}"
            )));
        }
    }
    let method = request
        .method
        .ok_or_else(|| NetError::Http("HTTP method missing".into()))?
        .to_string();
    let raw_path = request
        .path
        .ok_or_else(|| NetError::Http("HTTP path missing".into()))?;
    let (path, query) = split_path_and_query(raw_path);
    let mut header_pairs = Vec::with_capacity(request.headers.len());
    for header in request.headers.iter() {
        let value = String::from_utf8(header.value.to_vec())
            .map_err(|_| NetError::Http(format!("invalid header value for {}", header.name)))?;
        header_pairs.push((header.name.to_string(), value));
    }
    let mut content_length = 0usize;
    for (name, value) in &header_pairs {
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value
                .trim()
                .parse()
                .map_err(|_| NetError::Http("invalid Content-Length header value".into()))?;
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(NetError::Http("HTTP body exceeds limit".into()));
    }
    let mut body = Vec::with_capacity(content_length);
    let already = buffer.len() - header_len;
    if already > 0 {
        let copy_len = already.min(content_length);
        body.extend_from_slice(&buffer[header_len..header_len + copy_len]);
    }
    while body.len() < content_length {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            return Err(NetError::Http(
                "connection closed before HTTP body completed".into(),
            ));
        }
        let remaining = content_length - body.len();
        body.extend_from_slice(&temp[..read.min(remaining)]);
    }
    Ok(SimpleHttpRequest {
        method,
        path: path.to_string(),
        query: query.map(|q| q.to_string()),
        headers: header_pairs,
        body,
    })
}

pub fn write_json_response<T: Serialize>(
    stream: &mut impl Write,
    status: u16,
    payload: &T,
) -> Result<(), NetError> {
    let body =
        serde_json::to_vec(payload).map_err(|err| NetError::Http(format!("json error: {err}")))?;
    write_response(stream, status, "application/json", &body)
}

pub fn write_response(
    stream: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), NetError> {
    let mut header = String::new();
    let status_text = status_text(status);
    write!(
        header,
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
        status,
        status_text,
        body.len(),
        content_type
    )
    .expect("formatting header");
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_path_and_query(path: &str) -> (&str, Option<&str>) {
    if let Some(idx) = path.find('?') {
        (&path[..idx], Some(&path[idx + 1..]))
    } else {
        (path, None)
    }
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}
