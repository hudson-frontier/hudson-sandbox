//! Caller process restarts through HTTPS + real PostgreSQL + simulated mTLS host.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
mod common;
#[path = "../../sandbox-client/tests/support/server.rs"]
mod https;
#[path = "common/sources.rs"]
mod sources;

use axum::{
    body::Body,
    extract::State,
    middleware::{self, Next},
    response::Response,
};
use common::Fixture;
use sandbox_controller::Controller;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

async fn lose_admitted_create(
    State(first): State<Arc<AtomicBool>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let selected = request.method() == "POST" && request.uri().path() == "/v1/sandboxes";
    let mut response = next.run(request).await;
    if selected && response.status() == 202 && first.swap(false, Ordering::SeqCst) {
        *response.body_mut() = Body::from_stream(tokio_stream::iter([Err::<&'static str, _>(
            std::io::Error::other("lost fixture reply"),
        )]));
    }
    response
}

async fn invoke(
    root: &Path,
    config: &Path,
    state: &Path,
    arguments: &[&str],
    success: bool,
) -> Value {
    let python = std::env::var_os("HUDSON_SDK_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".venv-sdk/bin/python"));
    let mut command = tokio::process::Command::new(python);
    command
        .arg(root.join("sdk/python/examples/recover_operation.py"))
        .arg("--config")
        .arg(config)
        .arg("--state")
        .arg(state)
        .args(arguments)
        .env("PYTHONPATH", root.join("sdk/python/src"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("workflow subprocess deadline")
        .expect("make sdk-setup is required");
    assert_eq!(
        output.status.success(),
        success,
        "workflow action {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(if success {
        &output.stdout
    } else {
        &output.stderr
    })
    .expect("sanitized structured workflow report")
}

async fn prepare(root: &Path, server: &https::Server, kind: &str, request: Value) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let directory = server.directory.path().join(kind);
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let payload = server.directory.path().join(format!("{kind}.request.json"));
    https::private(&payload, &serde_json::to_vec(&request).unwrap());
    invoke(
        root,
        &server.config,
        &directory,
        &[
            "prepare",
            "--run-id",
            "durable-workflow-fixture-v1",
            "--kind",
            kind,
            "--request",
            payload.to_str().unwrap(),
        ],
        true,
    )
    .await;
    directory
}

async fn settle(f: &Fixture, controller: &mut Controller, operation: &str) -> Value {
    for _ in 0..40 {
        controller.tick().await.unwrap();
        let (_, observed) = f
            .send("GET", &format!("/v1/operations/{operation}"), Value::Null)
            .await;
        if matches!(
            observed["status"].as_str(),
            Some("succeeded" | "failed" | "cancelled" | "unknown")
        ) {
            return observed;
        }
        sqlx::query("UPDATE operations SET next_retry_at=NULL WHERE completed_at IS NULL")
            .execute(f.store.pool())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("bounded fixture reconciliation did not settle");
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn sdk_process_restart_preserves_real_admission_and_explicit_cleanup(pool: PgPool) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let corpus: Value =
        serde_json::from_slice(&std::fs::read(root.join("api/conformance/workflow.json")).unwrap())
            .unwrap();
    assert_eq!(corpus["version"], 1);
    let mut f = Fixture::new(&pool).await;
    let sources = Arc::new(sources::Sources::default());
    f.app = sandbox_api::router_with_uploads(
        sandbox_api::AppState {
            store: f.store.clone(),
            images: sandbox_protocol::images::ImageAllowlist::new(f.config.allowed_images.clone())
                .unwrap(),
        },
        None,
        None,
        None,
        Some(sources.clone()),
    );
    let first = Arc::new(AtomicBool::new(true));
    let server = https::Server::start(f.app.clone().layer(middleware::from_fn_with_state(
        first.clone(),
        lose_admitted_create,
    )))
    .await;
    server.edit_config(|profile| profile["request_timeout_seconds"] = 10.into());
    let mut credential: Value = serde_json::from_slice(
        &std::fs::read(server.directory.path().join("credential.json")).unwrap(),
    )
    .unwrap();
    credential["token"] = f.token.clone().into();
    let project: uuid::Uuid = sqlx::query_scalar("SELECT id FROM projects")
        .fetch_one(&pool)
        .await
        .unwrap();
    credential["project_id"] = format!("prj_{project}").into();
    https::private(
        &server.directory.path().join("credential.json"),
        &serde_json::to_vec(&credential).unwrap(),
    );
    let mut controller = f.controller().await.with_file_sources(sources.clone());

    let create = prepare(
        &root,
        &server,
        "create",
        corpus["requests"]["create"].clone(),
    )
    .await;
    let original = std::fs::read(create.join("request.json")).unwrap();
    let lost = invoke(&root, &server.config, &create, &["submit"], false).await;
    assert_eq!(lost["error"], "transport");
    assert!(!create.join("receipt.json").exists());
    assert!(
        !first.load(Ordering::SeqCst),
        "lost reply must follow a real successful admission"
    );
    let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE kind='create'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(recorded, 1);
    let admitted = invoke(&root, &server.config, &create, &["submit"], true).await;
    assert_eq!(
        std::fs::read(create.join("request.json")).unwrap(),
        original
    );
    let sandbox = admitted["sandbox_id"].as_str().unwrap();
    let create_id = admitted["operation_id"].as_str().unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations WHERE kind='create'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "lost admission retry must retain the original operation"
    );
    let (_, initial) = f
        .send("GET", &format!("/v1/sandboxes/{sandbox}"), Value::Null)
        .await;
    assert_eq!(initial["desired_state"], "running");
    assert_eq!(
        initial["observed_state"],
        corpus["readiness"]["not_ready_observed_state"]
    );
    settle(&f, &mut controller, create_id).await;
    invoke(&root, &server.config, &create, &["submit"], true).await; // Existing handle, GET only.
    let (_, ready) = f
        .send("GET", &format!("/v1/sandboxes/{sandbox}"), Value::Null)
        .await;
    assert_eq!(
        ready["observed_state"],
        corpus["readiness"]["ready_observed_state"]
    );
    assert_eq!(ready["observation_simulated"], true);

    let mut upload_request = corpus["requests"]["upload"].clone();
    upload_request["sandbox_id"] = sandbox.into();
    let upload = prepare(&root, &server, "upload", upload_request).await;
    let admitted = invoke(&root, &server.config, &upload, &["submit"], true).await;
    assert_eq!(
        settle(
            &f,
            &mut controller,
            admitted["operation_id"].as_str().unwrap()
        )
        .await["status"],
        "succeeded"
    );
    let uploaded = invoke(&root, &server.config, &upload, &["poll"], true).await;
    assert_eq!(uploaded["kind"], "file_write");

    let mut execute_request = corpus["requests"]["execute"].clone();
    execute_request["sandbox_id"] = sandbox.into();
    execute_request["body"]["deadline_unix_ms"] =
        json!(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000 + 120000);
    let execute = prepare(&root, &server, "execute", execute_request).await;
    let admitted = invoke(&root, &server.config, &execute, &["submit"], true).await;
    let execute_id = admitted["operation_id"].as_str().unwrap();
    settle(&f, &mut controller, execute_id).await;
    let observed = invoke(&root, &server.config, &execute, &["submit"], true).await;
    assert_eq!(observed["outcome"], "simulated_process_result");
    assert_eq!(f.fake.total_commands().await, 1);

    let cancel = prepare(&root, &server, "cancel", json!({"operation_id":execute_id})).await;
    let admitted = invoke(&root, &server.config, &cancel, &["submit"], true).await;
    assert_ne!(admitted["operation_id"], execute_id);
    settle(
        &f,
        &mut controller,
        admitted["operation_id"].as_str().unwrap(),
    )
    .await;
    invoke(&root, &server.config, &cancel, &["poll"], true).await;

    let destroy = prepare(
        &root,
        &server,
        "destroy",
        json!({"sandbox_id":sandbox,"body":{}}),
    )
    .await;
    let admitted = invoke(&root, &server.config, &destroy, &["submit"], true).await;
    assert_eq!(
        settle(
            &f,
            &mut controller,
            admitted["operation_id"].as_str().unwrap()
        )
        .await["status"],
        "succeeded"
    );
    let destroyed = invoke(
        &root,
        &server.config,
        &destroy,
        &["wait", "--seconds", "2"],
        true,
    )
    .await;
    assert_eq!(destroyed["outcome"], "completed");
    let outstanding: i64 =
        sqlx::query_scalar("SELECT count(*) FROM allocations WHERE released_at IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(outstanding, 0);
    assert_eq!(f.fake.total_commands().await, 1);
}
