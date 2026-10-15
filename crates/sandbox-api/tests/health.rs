//! Local probes distinguish a responsive API process from a usable database.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::{
    Router,
    body::{Body, to_bytes},
};
use http::{Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use sandbox_api::{
    AppState, health, router,
    server::{ServerLimits, tls_acceptor},
};
use sandbox_protocol::images::ImageAllowlist;
use sandbox_store::Store;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, pki_types::ServerName},
};

struct Server {
    api: SocketAddr,
    health: SocketAddr,
    connector: TlsConnector,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<anyhow::Result<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(pool: PgPool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = listener.local_addr().unwrap();
        let health_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let health = health_listener.local_addr().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let acceptor = tls_acceptor(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        ));
        let store = Store::from_pool(pool);
        let app = router(AppState {
            store: store.clone(),
            images: ImageAllowlist::new([format!("sha256:{}", "a".repeat(64))]).unwrap(),
        });
        let (stop, signal) = oneshot::channel();
        let task = tokio::spawn(health::serve(
            listener,
            acceptor,
            app,
            ServerLimits::default(),
            health_listener,
            store,
            async {
                let _ = signal.await;
            },
        ));
        Self {
            api,
            health,
            connector,
            stop: Some(stop),
            task,
        }
    }
    async fn probe(&self, method: &str, path: &str) -> (StatusCode, http::HeaderMap, Vec<u8>) {
        request(TcpStream::connect(self.health).await.unwrap(), method, path).await
    }
    async fn api(&self, path: &str) -> StatusCode {
        let tls = self
            .connector
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(self.api).await.unwrap(),
            )
            .await
            .unwrap();
        request(tls, "GET", path).await.0
    }
    async fn shutdown(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        timeout(Duration::from_secs(3), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

async fn request<S>(socket: S, method: &str, path: &str) -> (StatusCode, http::HeaderMap, Vec<u8>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    timeout(Duration::from_secs(3), async {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .unwrap();
        let connection = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::HOST, "localhost")
                    .header(header::CONNECTION, "close")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(Body::new(response.into_body()), 1024)
            .await
            .unwrap()
            .to_vec();
        drop(sender);
        connection.await.unwrap().unwrap();
        (status, headers, bytes)
    })
    .await
    .unwrap()
}

#[test]
fn public_or_malformed_health_addresses_fail_before_startup() {
    for address in [
        "0.0.0.0:8080",
        "[::]:8080",
        "192.0.2.1:8080",
        "[::ffff:127.0.0.1]:8080",
        "localhost:8080",
        "invalid",
    ] {
        assert!(health::loopback_address(address).is_err());
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sandbox-api"))
            .args([
                "serve",
                "--health-bind",
                address,
                "--tls-cert",
                "absent-cert",
                "--tls-key",
                "absent-key",
                "--image-digest",
            ])
            .arg(format!("sha256:{}", "a".repeat(64)))
            .env_remove("DATABASE_URL")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains("--health-bind"));
        assert!(!diagnostic.contains("reading TLS"));
    }
    for address in ["127.0.0.1:0", "127.0.0.2:8080", "[::1]:8080"] {
        assert!(health::loopback_address(address).is_ok());
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn probes_are_separate_from_authenticated_project_routes(pool: PgPool) {
    let mut server = Server::start(pool.clone()).await;
    for path in ["/livez", "/readyz"] {
        let response = server.probe("GET", path).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.2, b"ok\n");
        let head = server.probe("HEAD", path).await;
        assert_eq!(head.0, StatusCode::OK);
        assert!(head.2.is_empty());
        assert_eq!(
            server.probe("POST", path).await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(server.api(path).await, StatusCode::NOT_FOUND);
    }
    assert_eq!(
        server.probe("GET", "/v1/sandboxes").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(server.api("/v1/sandboxes").await, StatusCode::UNAUTHORIZED);
    pool.close().await;
    assert_eq!(server.probe("GET", "/livez").await.0, StatusCode::OK);
    let unavailable = server.probe("GET", "/readyz").await;
    assert_eq!(unavailable.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.1[header::CACHE_CONTROL], "no-store");
    assert_eq!(unavailable.2, b"unavailable\n");
    server.shutdown().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn pool_exhaustion_has_a_bounded_probe_and_recovers_without_restart(pool: PgPool) {
    let mut server = Server::start(pool.clone()).await;
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.unwrap());
    }
    let (ready, live) = tokio::join!(
        server.probe("GET", "/readyz"),
        server.probe("GET", "/livez")
    );
    assert_eq!(ready.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(live.0, StatusCode::OK);
    // A failed health check must not close the API or consume new checkers indefinitely.
    assert_eq!(
        server.probe("GET", "/readyz").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(held);
    assert_eq!(server.probe("GET", "/readyz").await.0, StatusCode::OK);
    assert_eq!(server.api("/v1/sandboxes").await, StatusCode::UNAUTHORIZED);
    server.shutdown().await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn shutdown_closes_both_transports_and_incomplete_health_connections(pool: PgPool) {
    let mut server = Server::start(pool).await;
    assert_eq!(server.probe("GET", "/livez").await.0, StatusCode::OK);
    let mut partial = TcpStream::connect(server.health).await.unwrap();
    partial
        .write_all(b"GET /livez HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    let mut tls_partial = server
        .connector
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(server.api).await.unwrap(),
        )
        .await
        .unwrap();
    tls_partial
        .write_all(b"GET /v1/sandboxes HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    server.shutdown().await;
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(1), partial.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(!response.starts_with(b"HTTP/1.1 200"));
    response.clear();
    let _ = timeout(
        Duration::from_secs(1),
        tls_partial.read_to_end(&mut response),
    )
    .await
    .unwrap();
    assert!(!response.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn api_transport_failure_stops_the_health_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let health_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let acceptor = tls_acceptor(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let store = Store::connect("postgres://localhost/unavailable", 1)
        .await
        .unwrap();
    let result = timeout(
        Duration::from_secs(2),
        health::serve(
            listener,
            acceptor,
            Router::new(),
            ServerLimits {
                connections: 0,
                ..Default::default()
            },
            health_listener,
            store,
            std::future::pending(),
        ),
    )
    .await
    .unwrap();
    assert!(result.is_err());
}
