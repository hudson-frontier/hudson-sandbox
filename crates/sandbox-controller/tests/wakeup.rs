//! Committed HTTP admission, transient PostgreSQL signals and fenced reconciliation.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
mod common;

use common::Fixture;
use http::StatusCode;
use sandbox_controller::{
    Tick,
    wakeup::{WakeReason, WorkWakeup},
};
use sandbox_protocol::Id;
use sandbox_store::{Store, work::WORK_CHANNEL};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgListener};
use std::time::Duration;
use tokio::time::timeout;
use tower::ServiceExt;

async fn notification(listener: &mut PgListener) {
    let message = timeout(Duration::from_secs(3), listener.try_recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(message.channel(), WORK_CHANNEL);
    assert_eq!(message.payload(), "");
}

async fn subscribed(wakeup: &mut WorkWakeup) {
    timeout(Duration::from_secs(5), async {
        while wakeup.wait().await != WakeReason::Notification {}
    })
    .await
    .unwrap();
}

async fn create(f: &Fixture, key: &str, image: char) -> (StatusCode, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/v1/sandboxes")
        .header("authorization", format!("Bearer {}", f.token))
        .header("content-type", "application/json")
        .header("idempotency-key", key)
        .body(axum::body::Body::from(
            json!({
                "image_digest":format!("sha256:{}", image.to_string().repeat(64)),
                "resources":{"vcpu":2,"memory_mib":2048,"disk_mib":8192}
            })
            .to_string(),
        ))
        .unwrap();
    let response = f.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn create_execute_cancel_and_destroy_send_only_committed_empty_hints(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    let mut listener = f.store.listen_for_work().await.unwrap();
    let (operation, sandbox) = f.admit().await;
    notification(&mut listener).await;
    let committed: (String, i32) =
        sqlx::query_as("SELECT status,attempt_count FROM operations WHERE id=$1")
            .bind(operation.uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(committed, ("queued".into(), 0));
    assert_eq!(f.fake.total_starts().await, 0);
    let mut controller = f.controller().await;
    assert_eq!(controller.tick().await.unwrap(), Tick::Confirmed);
    let (status, executed) = f.send("POST", &format!("/v1/sandboxes/{sandbox}/execute"), json!({
        "argv":["/bin/true"], "deadline_unix_ms":sandbox_fake_host::unix_ms().unwrap()+60_000
    })).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{executed}");
    notification(&mut listener).await;
    let (status, cancelled) = f
        .send(
            "POST",
            &format!(
                "/v1/operations/{}/cancel",
                executed["operation_id"].as_str().unwrap()
            ),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{cancelled}");
    notification(&mut listener).await;
    let (status, destroyed) = f
        .send(
            "POST",
            &format!("/v1/sandboxes/{sandbox}/destroy"),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{destroyed}");
    notification(&mut listener).await;
    assert_eq!(f.fake.total_commands().await, 0);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 4);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn retries_conflicts_and_policy_denials_do_not_emit_new_work(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    let mut listener = f.store.listen_for_work().await.unwrap();
    let (status, original) = create(&f, "wake-original-request", 'a').await;
    assert_eq!(status, StatusCode::ACCEPTED);
    notification(&mut listener).await;
    let (status, retry) = create(&f, "wake-original-request", 'a').await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(original["operation_id"], retry["operation_id"]);
    assert_eq!(
        create(&f, "wake-original-request", 'b').await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        create(&f, "wake-policy-denial-01", 'b').await.0,
        StatusCode::FORBIDDEN
    );
    assert!(
        timeout(Duration::from_millis(150), listener.try_recv())
            .await
            .is_err()
    );
    assert_eq!(f.fake.total_starts().await, 0);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn startup_scan_recovers_work_committed_before_subscription(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    f.admit().await;
    let mut wakeup = WorkWakeup::start(f.store.clone());
    subscribed(&mut wakeup).await;
    let mut controller = f.controller().await;
    assert_eq!(controller.tick().await.unwrap(), Tick::Confirmed);
    assert_eq!(controller.tick().await.unwrap(), Tick::Idle);
    assert_eq!(f.fake.total_starts().await, 1);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn notification_is_a_hint_and_never_execution_authority(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    let mut wakeup = WorkWakeup::start(f.store.clone());
    subscribed(&mut wakeup).await;
    sqlx::query("SELECT pg_catalog.pg_notify($1, '')")
        .bind(WORK_CHANNEL)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(wakeup.wait().await, WakeReason::Notification);
    let mut controller = f.controller().await;
    assert_eq!(controller.tick().await.unwrap(), Tick::Idle);
    assert_eq!(f.fake.total_starts().await, 0);
    sqlx::query("SELECT pg_catalog.pg_notify($1, 'untrusted-payload')")
        .bind(WORK_CHANNEL)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(wakeup.wait().await, WakeReason::Poll);
    assert_eq!(controller.tick().await.unwrap(), Tick::Idle);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn listener_disconnect_resubscribes_and_durable_work_is_still_reconciled(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    let name = format!("wakeup-test-{}", uuid::Uuid::now_v7());
    let options = pool
        .connect_options()
        .as_ref()
        .clone()
        .application_name(&name);
    let listener_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let mut wakeup = WorkWakeup::start(Store::from_pool(listener_pool.clone()));
    subscribed(&mut wakeup).await;
    let pid: i32 = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1",
    )
    .bind(&name)
    .fetch_one(&pool)
    .await
    .unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(terminated);
    f.admit().await;
    subscribed(&mut wakeup).await;
    let next: i32 = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1",
    )
    .bind(&name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(pid, next);
    let mut controller = f.controller().await;
    assert_eq!(controller.tick().await.unwrap(), Tick::Confirmed);
    assert_eq!(f.fake.total_starts().await, 1);
    drop(wakeup);
    timeout(Duration::from_secs(3), listener_pool.close())
        .await
        .unwrap();
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn unavailable_listener_does_not_block_polling_or_claims(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    f.admit().await;
    let disconnected = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy_with(pool.connect_options().as_ref().clone());
    disconnected.close().await;
    let mut wakeup = WorkWakeup::start(Store::from_pool(disconnected));
    assert_eq!(
        timeout(Duration::from_secs(2), wakeup.wait())
            .await
            .unwrap(),
        WakeReason::Poll
    );
    let mut controller = f.controller().await;
    assert_eq!(controller.tick().await.unwrap(), Tick::Confirmed);
    assert_eq!(f.fake.total_starts().await, 1);
}
