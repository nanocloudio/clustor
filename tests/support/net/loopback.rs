use std::net::{SocketAddr, TcpListener};

/// Reserves and returns an ephemeral loopback address for TLS servers.
pub fn next_loopback() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral addr")
}
