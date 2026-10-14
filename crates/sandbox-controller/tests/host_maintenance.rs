//! Draining excludes placements while admitted work/cleanup remain service-owned.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[allow(dead_code)]
mod common;
use common::Fixture;
use sandbox_controller::Tick;
use sandbox_protocol::OperationId;
use sandbox_store::{claims::OperationKind, host_maintenance::Error, placement::PlacementError};
use serde_json::{Value, json};
use sqlx::PgPool;

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn draining_preserves_admitted_command_then_requires_explicit_destroy(pool: PgPool) {
    let f = Fixture::new(&pool).await;
    let mut controller = f.controller().await;
    let (_, sandbox) = f.admit().await;
    assert_eq!(controller.tick().await.unwrap(), Tick::Confirmed);
    f.fake.hold_next_command().await;
    let (status, admitted) = f.send("POST", &format!("/v1/sandboxes/{sandbox}/execute"), json!({"argv":["held"],"deadline_unix_ms":time::OffsetDateTime::now_utc().unix_timestamp_nanos()/1_000_000+120000})).await;
    assert_eq!(status, 202);
    let command: OperationId = admitted["operation_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(controller.tick().await.unwrap(), Tick::Confirmed);
    let drained = f.store.drain_host(f.config.host, 1).await.unwrap();
    assert_eq!(drained.outstanding_allocations, 1);
    assert_eq!(drained.reserved_vcpu, 2);
    assert_eq!(drained.reserved_memory_mib, 2048);
    assert_eq!(drained.reserved_disk_mib, 8192);
    assert_eq!(drained.unfinished_operations, 1);
    assert_eq!(drained.unknown_operations, 0);
    assert!(matches!(
        f.store.finish_host_drain(f.config.host, 1).await,
        Err(Error::Outstanding)
    ));

    // New create may be admitted by the public API, but cannot reserve this host.
    f.admit().await;
    let next = f
        .store
        .claim_next(OperationKind::Create, 30)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        f.store.reserve_create(&next, f.config.host, 1).await,
        Err(PlacementError::HostUnavailable)
    ));
    f.store.defer_claim(&next, 30).await.unwrap();
    assert_eq!(
        f.store
            .host_maintenance(f.config.host, 1)
            .await
            .unwrap()
            .outstanding_allocations,
        1
    );

    f.fake.finish_command(command, 7).await.unwrap();
    f.reclaim_now().await;
    for _ in 0..12 {
        controller.tick().await.unwrap();
        let (_, observed) = f
            .send("GET", &format!("/v1/operations/{command}"), Value::Null)
            .await;
        if observed["status"] == "failed" {
            assert_eq!(observed["result"]["exit_code"], 7);
            break;
        }
    }
    let (_, observed) = f
        .send("GET", &format!("/v1/operations/{command}"), Value::Null)
        .await;
    assert_eq!(observed["status"], "failed");
    assert_eq!(f.fake.total_commands().await, 1);
    assert_eq!(
        f.store
            .host_maintenance(f.config.host, 1)
            .await
            .unwrap()
            .status,
        "draining"
    );

    let (_, destroyed) = f
        .send(
            "POST",
            &format!("/v1/sandboxes/{sandbox}/destroy"),
            json!({}),
        )
        .await;
    let destroy = destroyed["operation_id"].as_str().unwrap();
    for _ in 0..12 {
        controller.tick().await.unwrap();
        let (_, observed) = f
            .send("GET", &format!("/v1/operations/{destroy}"), Value::Null)
            .await;
        if observed["status"] == "succeeded" {
            break;
        }
    }
    let (_, observed) = f
        .send("GET", &format!("/v1/operations/{destroy}"), Value::Null)
        .await;
    assert_eq!(observed["status"], "succeeded");
    let report = f.store.host_maintenance(f.config.host, 1).await.unwrap();
    assert_eq!(report.outstanding_allocations, 0);
    assert_eq!(report.status, "draining");
    assert_eq!(
        f.store
            .finish_host_drain(f.config.host, 1)
            .await
            .unwrap()
            .status,
        "ready"
    );
}
