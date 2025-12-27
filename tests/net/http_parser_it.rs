#![cfg(all(feature = "net", feature = "admin-http"))]

use clustor::net::http::read_request;
use clustor::net::{HttpError, NetError};
use std::io::Cursor;

#[test]
fn parses_request_with_query_and_body() {
    let raw = b"POST /readyz?foo=bar HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest";
    let mut cursor = Cursor::new(&raw[..]);
    let request = read_request(&mut cursor).expect("request parses");
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/readyz");
    assert_eq!(request.query.as_deref(), Some("foo=bar"));
    assert_eq!(request.body, b"test");
    assert_eq!(request.header("host"), Some("localhost"));
    assert_eq!(request.path_segments(), vec!["readyz"]);
}

#[test]
fn errors_when_body_is_truncated() {
    let raw = b"POST /ok HTTP/1.1\r\nContent-Length: 4\r\n\r\nt";
    let mut cursor = Cursor::new(&raw[..]);
    let err = read_request(&mut cursor).expect_err("should fail");
    match err {
        NetError::Http(HttpError::ConnectionClosedBeforeBody) => {}
        other => panic!("unexpected error: {other}"),
    }
}
