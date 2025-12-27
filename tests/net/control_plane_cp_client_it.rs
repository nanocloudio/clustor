#![cfg(feature = "net")]

use super::tls_support::{generate_tls_materials, TlsFixtures};
use clustor::control_plane::core::client::{CpApiTransport, TransportResponse};
use clustor::net::control_plane::client::HttpCpTransportBuilder;
use clustor::net::http::read_request;
use clustor::net::{TlsIdentity, TlsTrustStore};
use rustls::server::ServerConfig;
use rustls::{ServerConnection, Stream};
use serde_json::json;
use std::convert::TryInto;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[derive(Clone, Copy)]
enum TestServerMode {
    KeepAlive,
    DropFirstConnection,
}

#[test]
fn connection_pool_reuses_streams() {
    let certs = TempDir::new().expect("tempdir");
    let fixtures = generate_fixtures(&certs);
    let (addr, connections, shutdown, handle) = spawn_server(
        fixtures.server.clone(),
        fixtures.trust.clone(),
        TestServerMode::KeepAlive,
    );
    let url = format!("https://localhost:{}/", addr.port());
    let transport = HttpCpTransportBuilder::new(&url)
        .expect("builder")
        .identity(fixtures.client.clone())
        .trust_store(fixtures.trust.clone())
        .connection_pool(2)
        .build()
        .expect("transport");
    let first = response_connection(&transport.get("/status").expect("first"));
    let second = response_connection(&transport.get("/status").expect("second"));
    assert_eq!(first, second, "connection id should be reused");
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    drop(transport);
    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap();
}

#[test]
fn pool_drops_connections_when_disabled() {
    let certs = TempDir::new().expect("tempdir");
    let fixtures = generate_fixtures(&certs);
    let (addr, connections, shutdown, handle) = spawn_server(
        fixtures.server.clone(),
        fixtures.trust.clone(),
        TestServerMode::KeepAlive,
    );
    let url = format!("https://localhost:{}/", addr.port());
    let transport = HttpCpTransportBuilder::new(&url)
        .expect("builder")
        .identity(fixtures.client.clone())
        .trust_store(fixtures.trust.clone())
        .build()
        .expect("transport");
    let first = response_connection(&transport.get("/status").expect("first"));
    let second = response_connection(&transport.get("/status").expect("second"));
    assert_ne!(first, second, "each request should open a new connection");
    assert!(connections.load(Ordering::SeqCst) >= 2);
    drop(transport);
    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap();
}

#[test]
fn retries_after_transient_error() {
    let certs = TempDir::new().expect("tempdir");
    let fixtures = generate_fixtures(&certs);
    let (addr, connections, shutdown, handle) = spawn_server(
        fixtures.server.clone(),
        fixtures.trust.clone(),
        TestServerMode::DropFirstConnection,
    );
    let url = format!("https://localhost:{}/", addr.port());
    let transport = HttpCpTransportBuilder::new(&url)
        .expect("builder")
        .identity(fixtures.client.clone())
        .trust_store(fixtures.trust.clone())
        .build()
        .expect("transport");
    let response = transport.get("/status").expect("retry succeeds");
    assert!(!response.body.is_empty());
    assert!(connections.load(Ordering::SeqCst) >= 2);
    drop(transport);
    shutdown.store(true, Ordering::Relaxed);
    handle.join().unwrap();
}

fn generate_fixtures(dir: &TempDir) -> TlsFixtures {
    generate_tls_materials(
        dir,
        &["localhost"],
        "spiffe://clustor.test/server",
        "spiffe://clustor.test/client",
    )
    .expect("tls fixtures")
}

fn response_connection(response: &TransportResponse) -> usize {
    let value: serde_json::Value =
        serde_json::from_slice(&response.body).expect("valid json response");
    value["connection"]
        .as_u64()
        .expect("connection id")
        .try_into()
        .expect("usize")
}

fn spawn_server(
    identity: TlsIdentity,
    trust: TlsTrustStore,
    mode: TestServerMode,
) -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let drop_first = Arc::new(AtomicBool::new(matches!(
        mode,
        TestServerMode::DropFirstConnection
    )));
    let tls_config = Arc::new(identity.server_config(&trust).expect("server config"));
    let connections_clone = connections.clone();
    let shutdown_clone = shutdown.clone();
    let drop_first_clone = drop_first.clone();
    let handle = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking failed");
        while !shutdown_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let conn_id = connections_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    handle_connection(
                        stream,
                        tls_config.clone(),
                        conn_id,
                        drop_first_clone.clone(),
                    );
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (addr, connections, shutdown, handle)
}

fn handle_connection(
    mut stream: TcpStream,
    tls: Arc<ServerConfig>,
    conn_id: usize,
    drop_first: Arc<AtomicBool>,
) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut conn = ServerConnection::new(tls).expect("server connection");
    let mut tls_stream = Stream::new(&mut conn, &mut stream);
    if drop_first.swap(false, Ordering::SeqCst) {
        return;
    }
    let mut request_index = 0usize;
    while let Ok(request) = read_request(&mut tls_stream) {
        request_index += 1;
        if request.path != "/status" {
            break;
        }
        let body = json!({
            "connection": conn_id,
            "request": request_index,
            "path": request.path,
        });
        let payload = serde_json::to_vec(&body).expect("json");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n",
            payload.len()
        );
        if tls_stream.write_all(header.as_bytes()).is_err() {
            break;
        }
        if tls_stream.write_all(&payload).is_err() {
            break;
        }
    }
}
