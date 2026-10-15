//! Optional local operator probes. These never expose Project routes or database errors.
use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::ensure;
use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
};
use http::{StatusCode, header};
use sandbox_store::Store;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use crate::server::{ServerLimits, serve as serve_api, serve_plain};

/// Clap parser: refuse public addresses before opening files or accessing storage.
pub fn loopback_address(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value.parse().map_err(|_| "invalid health socket address")?;
    if !address.ip().is_loopback() {
        return Err("health listener must use a loopback address".into());
    }
    Ok(address)
}

#[derive(Clone)]
struct Probes {
    store: Store,
    accepting: Arc<AtomicBool>,
    // Probe traffic can occupy at most one database connection; it never queues
    // another checker behind an unavailable dependency.
    checks: Arc<Semaphore>,
}

fn reply(ready: bool) -> Response {
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [(header::CACHE_CONTROL, "no-store")],
        if ready { "ok\n" } else { "unavailable\n" },
    )
        .into_response()
}

async fn ready(State(probes): State<Probes>) -> Response {
    if !probes.accepting.load(Ordering::Acquire) {
        return reply(false);
    }
    let Ok(_permit) = probes.checks.try_acquire() else {
        return reply(false);
    };
    let available = matches!(
        timeout(Duration::from_millis(500), probes.store.check_connection()).await,
        Ok(Ok(()))
    );
    // A successful query racing with shutdown must not restore readiness.
    reply(available && probes.accepting.load(Ordering::Acquire))
}

async fn stopped(mut signal: watch::Receiver<bool>) {
    let _ = signal.wait_for(|stopping| *stopping).await;
}

/// Run the HTTPS API and a separate loopback-only HTTP listener as one service.
/// Both listeners stop on shutdown or either transport failing. Database health
/// affects readiness only; it never kills the API or changes liveness.
pub async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    limits: ServerLimits,
    health_listener: TcpListener,
    store: Store,
    shutdown: impl Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    ensure!(
        health_listener.local_addr()?.ip().is_loopback(),
        "health listener must use a loopback address"
    );
    let probes = Probes {
        store,
        accepting: Arc::new(AtomicBool::new(true)),
        checks: Arc::new(Semaphore::new(1)),
    };
    let app_health = Router::new()
        .route("/livez", get(|| async { reply(true) }))
        .route("/readyz", get(ready))
        .with_state(probes.clone());
    let health_limits = ServerLimits {
        connections: 16,
        handshake: Duration::from_secs(1),
        headers: Duration::from_secs(1),
        request: Duration::from_secs(1),
        connection: Duration::from_secs(2),
        drain: Duration::from_secs(1),
    };
    let (stop, stopping) = watch::channel(false);
    let api = serve_api(listener, acceptor, app, limits, stopped(stopping.clone()));
    let health = serve_plain(
        health_listener,
        app_health,
        health_limits,
        stopped(stopping),
    );
    tokio::pin!(api, health, shutdown);
    enum Finished {
        Shutdown,
        Api(anyhow::Result<()>),
        Health(anyhow::Result<()>),
    }
    let finished = tokio::select! {
        biased;
        _ = &mut shutdown => Finished::Shutdown,
        result = &mut api => Finished::Api(result),
        result = &mut health => Finished::Health(result),
    };
    probes.accepting.store(false, Ordering::Release);
    let _ = stop.send(true);
    match finished {
        Finished::Shutdown => {
            let (api, health) = tokio::join!(api, health);
            api?;
            health?;
        }
        Finished::Api(result) => {
            let health = health.await;
            result?;
            health?;
            anyhow::bail!("API listener stopped unexpectedly");
        }
        Finished::Health(result) => {
            let api = api.await;
            result?;
            api?;
            anyhow::bail!("health listener stopped unexpectedly");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_checks_do_not_queue_and_shutdown_cannot_revive_readiness(pool: PgPool) {
        let mut held = Vec::new();
        for _ in 0..pool.options().get_max_connections() {
            held.push(pool.acquire().await.unwrap());
        }
        let probes = Probes {
            store: Store::from_pool(pool),
            accepting: Arc::new(AtomicBool::new(true)),
            checks: Arc::new(Semaphore::new(1)),
        };
        let pending = tokio::spawn(ready(State(probes.clone())));
        timeout(Duration::from_secs(2), async {
            while probes.checks.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let second = ready(State(probes.clone())).await;
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(probes.checks.available_permits(), 0);
        probes.accepting.store(false, Ordering::Release);
        drop(held);
        assert_eq!(
            pending.await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(probes.checks.available_permits(), 1);
        assert_eq!(
            ready(State(probes)).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
