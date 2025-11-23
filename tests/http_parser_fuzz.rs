#![cfg(all(feature = "net", feature = "http-fuzz"))]

use clustor::net::fuzz_http_request;

#[test]
fn fuzz_corpus_smoke() {
    let corpus = [
        b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"POST /why HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody".as_slice(),
    ];
    for case in corpus {
        fuzz_http_request(case);
    }
}
