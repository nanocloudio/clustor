#![cfg(all(feature = "net", feature = "http-fuzz"))]

use super::parser::read_request;
use std::io::Cursor;

pub(crate) fn fuzz_http_request(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let _ = read_request(&mut cursor);
}
