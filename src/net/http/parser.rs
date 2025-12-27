#![cfg(feature = "net")]

use crate::net::{HttpError, NetError};
use httparse::Status;
use std::io::{self, Read};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Minimal HTTP request captured by the manual parser.
///
/// Only ASCII header names and an eagerly-buffered body are supported.
#[derive(Debug, Clone)]
pub struct SimpleHttpRequest {
    pub method: String,
    pub path: String,
    #[cfg(any(feature = "admin-http", test))]
    pub query: Option<String>,
    #[cfg(any(feature = "admin-http", test))]
    pub headers: Vec<(String, String)>,
    #[cfg(any(feature = "admin-http", test))]
    pub body: Vec<u8>,
}

impl SimpleHttpRequest {
    #[cfg(any(feature = "admin-http", test))]
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

/// Parses a blocking HTTP/1.1 request from the provided stream.
///
/// The parser expects a `Content-Length` header, rejects chunked encoding,
/// and caps header/body sizes to avoid unbounded buffering.
pub fn read_request(stream: &mut impl Read) -> Result<SimpleHttpRequest, NetError> {
    let mut buffer = Vec::new();
    let mut header_end = None;
    let mut temp = [0u8; 1024];
    while header_end.is_none() {
        let read = match stream.read(&mut temp) {
            Ok(read) => {
                if read == 0 {
                    return Err(NetError::from(HttpError::ConnectionClosedBeforeHeaders));
                }
                read
            }
            Err(err) => return Err(map_read_error(err)),
        };
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(NetError::from(HttpError::HeadersTooLarge));
        }
        if let Some(pos) = find_header_terminator(&buffer) {
            header_end = Some(pos + 4);
        }
    }
    let header_len = header_end.ok_or(HttpError::MissingHeaderTerminator)?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(&buffer) {
        Ok(Status::Complete(_)) => {}
        Ok(Status::Partial) => {
            return Err(NetError::from(HttpError::PartialRequest));
        }
        Err(err) => {
            return Err(NetError::from(HttpError::RequestParse(err)));
        }
    }
    let method = request.method.ok_or(HttpError::MissingMethod)?.to_string();
    let raw_path = request.path.ok_or(HttpError::MissingPath)?;
    let (path, query) = split_path_and_query(raw_path);
    #[cfg(not(any(feature = "admin-http", test)))]
    let _ = query;
    let mut header_pairs = Vec::with_capacity(request.headers.len());
    for header in request.headers.iter() {
        let value = String::from_utf8(header.value.to_vec()).map_err(|_| {
            HttpError::InvalidHeaderValue {
                name: header.name.to_string(),
            }
        })?;
        header_pairs.push((header.name.to_string(), value));
    }
    let mut content_length = 0usize;
    for (name, value) in &header_pairs {
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value
                .trim()
                .parse()
                .map_err(|_| HttpError::InvalidContentLengthValue)?;
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(NetError::from(HttpError::BodyTooLarge));
    }
    let mut body = Vec::with_capacity(content_length);
    let already = buffer.len() - header_len;
    if already > 0 {
        let copy_len = already.min(content_length);
        body.extend_from_slice(&buffer[header_len..header_len + copy_len]);
    }
    while body.len() < content_length {
        let read = match stream.read(&mut temp) {
            Ok(read) => {
                if read == 0 {
                    return Err(NetError::from(HttpError::ConnectionClosedBeforeBody));
                }
                read
            }
            Err(err) => return Err(map_read_error(err)),
        };
        let remaining = content_length - body.len();
        body.extend_from_slice(&temp[..read.min(remaining)]);
    }
    #[cfg(any(feature = "admin-http", test))]
    {
        Ok(SimpleHttpRequest {
            method,
            path: path.to_string(),
            query: query.map(|q| q.to_string()),
            headers: header_pairs,
            body,
        })
    }
    #[cfg(not(any(feature = "admin-http", test)))]
    {
        Ok(SimpleHttpRequest {
            method,
            path: path.to_string(),
        })
    }
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

fn map_read_error(err: io::Error) -> NetError {
    if is_timeout(&err) {
        NetError::from(HttpError::RequestTimeout)
    } else {
        NetError::from(err)
    }
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
