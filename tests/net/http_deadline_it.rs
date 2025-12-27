#![cfg(feature = "net")]

use clustor::net::{HttpError, NetError};
#[path = "../support/net/deadline.rs"]
mod deadline_support;
use deadline_support::{expired_deadline, short_deadline};

#[test]
fn expired_deadline_writes_timeout() {
    let deadline = expired_deadline();
    let mut buffer = Vec::new();
    let expired = deadline
        .respond_if_expired(&mut buffer)
        .expect("writes response");
    assert!(!expired);
    let resp = String::from_utf8(buffer).expect("utf8 response");
    assert!(resp.contains("408"));
}

#[test]
fn enforce_returns_error_when_expired() {
    let deadline = expired_deadline();
    let err = deadline.enforce().expect_err("should error");
    match err {
        NetError::Http(HttpError::RequestTimeout) => {}
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn short_deadline_allows_in_progress_work() {
    let deadline = short_deadline();
    assert!(deadline.enforce().is_ok());
    let mut writer = Vec::new();
    assert!(deadline.respond_if_expired(&mut writer).unwrap());
}
