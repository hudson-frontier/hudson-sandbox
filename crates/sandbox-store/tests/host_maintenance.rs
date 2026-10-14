//! Epoch-fenced draining counts, placement exclusion and explicit reopening.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use sandbox_protocol::{HostId, Id};
use sandbox_store::{Store, host_maintenance::Error};
use sqlx::PgPool;

async fn host(pool: &PgPool) -> HostId {
    let host = HostId::generate();
    sqlx::query("INSERT INTO hosts(id,status,cpu_capacity,memory_capacity_mib,disk_capacity_mib,supervisor_epoch,last_seen_at) VALUES($1,'ready',4,8192,65536,1,clock_timestamp())")
        .bind(host.uuid()).execute(pool).await.unwrap();
    host
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn drain_is_idempotent_epoch_fenced_and_requires_fresh_empty_host_to_reopen(pool: PgPool) {
    let store = Store::from_pool(pool.clone());
    let id = host(&pool).await;
    let before = store.host_maintenance(id, 1).await.unwrap();
    assert_eq!(before.status, "ready");
    let drained = store.drain_host(id, 1).await.unwrap();
    assert_eq!(drained.status, "draining");
    assert_eq!(drained.outstanding_allocations, 0);
    assert_eq!(store.drain_host(id, 1).await.unwrap(), drained);
    assert!(matches!(
        store.drain_host(id, 2).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        store.host_maintenance(id, 0).await,
        Err(Error::Conflict)
    ));
    store.observe_configured_host(id, 1).await.unwrap();
    assert_eq!(
        store.host_maintenance(id, 1).await.unwrap().status,
        "draining"
    );
    sqlx::query("UPDATE hosts SET last_seen_at=clock_timestamp()-interval '1 minute' WHERE id=$1")
        .bind(id.uuid())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.finish_host_drain(id, 1).await,
        Err(Error::Outstanding)
    ));
    store.observe_configured_host(id, 1).await.unwrap();
    let ready = store.finish_host_drain(id, 1).await.unwrap();
    assert_eq!(ready.status, "ready");
    assert!(matches!(
        store.finish_host_drain(id, 1).await,
        Err(Error::Conflict)
    ));
    sqlx::query("UPDATE hosts SET status='unhealthy' WHERE id=$1")
        .bind(id.uuid())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.drain_host(id, 1).await,
        Err(Error::Conflict)
    ));
}
