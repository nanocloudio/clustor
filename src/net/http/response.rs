#![cfg(feature = "net")]

use crate::net::{HttpError, NetError};
use serde::Serialize;
use serde_json::json;
use std::fmt::Write as _;
use std::io::{self, Write};

pub(crate) fn write_json_response<T: Serialize>(
    stream: &mut (impl Write + ?Sized),
    status: u16,
    payload: &T,
) -> Result<(), NetError> {
    let body = serde_json::to_vec(payload).map_err(HttpError::JsonSerialize)?;
    write_response(stream, status, "application/json", &body)
}

pub(crate) fn write_timeout_response(stream: &mut (impl Write + ?Sized)) -> Result<(), NetError> {
    write_json_response(
        stream,
        408,
        &json!({"error": "request deadline exceeded", "status": 408}),
    )
}

pub(crate) fn write_response(
    stream: &mut (impl Write + ?Sized),
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
    .map_err(|_| HttpError::ResponseFormat)?;
    stream
        .write_all(header.as_bytes())
        .map_err(map_write_error)?;
    stream.write_all(body).map_err(map_write_error)?;
    Ok(())
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

fn map_write_error(err: io::Error) -> NetError {
    if is_timeout(&err) {
        NetError::from(HttpError::ResponseTimeout)
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
