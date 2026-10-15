//! Authenticated PostgreSQL admission; fixture guest observations are synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/output.rs"]
mod fixture;
use axum::{
    Router,
    body::{Body, to_bytes},
};
use fixture::Fixture;
use http::{Request, StatusCode};
use sandbox_protocol::{Id, SandboxId};
use serde_json::{Value, json};
use sqlx::PgPool;

async fn send(
    app: &Router,
    token: &str,
    sandbox: SandboxId,
    key: &str,
    body: String,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/sandboxes/{sandbox}/execute"))
                .header("authorization", format!("Bearer {token}"))
                .header("idempotency-key", key)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
use tower::ServiceExt;
fn command(generation: i64) -> Value {
    let now = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    json!({"argv":["true"],"deadline_unix_ms":now+60000,"expected_generation":generation})
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn authenticated_generation_guard_rejects_stale_new_work_but_preserves_exact_retries(
    pool: PgPool,
) {
    let f = Fixture::new(&pool).await;
    f.finish().await;
    let other = Fixture::new(&pool).await;
    other.finish().await;
    let app = f.app(None);
    let stale = send(
        &app,
        &f.token,
        f.sandbox,
        "generation-stale-001",
        command(2).to_string(),
    )
    .await;
    assert_eq!(stale.0, StatusCode::CONFLICT);
    assert_eq!(stale.1["code"], "sandbox_generation_mismatch");
    assert!(stale.1.get("operation_id").is_none());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE project_id=$1")
        .bind(f.project.uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let body = command(1);
    let accepted = send(
        &app,
        &f.token,
        f.sandbox,
        "generation-match-001",
        body.to_string(),
    )
    .await;
    assert_eq!(accepted.0, StatusCode::ACCEPTED);
    sqlx::query("UPDATE sandboxes SET generation=2 WHERE id=$1")
        .bind(f.sandbox.uuid())
        .execute(&pool)
        .await
        .unwrap();
    let retry = send(
        &app,
        &f.token,
        f.sandbox,
        "generation-match-001",
        body.to_string(),
    )
    .await;
    assert_eq!(retry, accepted);
    let mut changed = body;
    changed["expected_generation"] = json!(2);
    let conflict = send(
        &app,
        &f.token,
        f.sandbox,
        "generation-match-001",
        changed.to_string(),
    )
    .await;
    assert_eq!(conflict.0, StatusCode::CONFLICT);
    assert_eq!(conflict.1["code"], "conflict");
    let foreign = send(
        &other.app(None),
        &other.token,
        f.sandbox,
        "generation-foreign-001",
        command(1).to_string(),
    )
    .await;
    let missing = send(
        &other.app(None),
        &other.token,
        SandboxId::generate(),
        "generation-missing-001",
        command(1).to_string(),
    )
    .await;
    assert_eq!(foreign, missing);
    assert_eq!(foreign.0, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn invalid_or_duplicated_generation_fields_are_bad_requests_without_admission(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    let app = f.app(None);
    for value in [
        json!(null),
        json!(0),
        json!(-1),
        json!(true),
        json!(1.5),
        json!("1"),
        json!(9223372036854775808u64),
    ] {
        let mut body = command(1);
        body["expected_generation"] = value;
        let response = send(
            &app,
            &f.token,
            f.sandbox,
            "generation-invalid-001",
            body.to_string(),
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST);
        assert_eq!(response.1["code"], "bad_request");
    }
    let duplicate =
        r#"{"argv":["true"],"deadline_unix_ms":1,"expected_generation":1,"expected_generation":2}"#;
    assert_eq!(
        send(
            &app,
            &f.token,
            f.sandbox,
            "generation-duplicate-001",
            duplicate.into()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE project_id=$1")
        .bind(f.project.uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
