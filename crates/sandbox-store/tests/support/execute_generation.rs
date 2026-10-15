use super::*;
use std::time::Duration;

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn stale_generation_admits_no_operation_and_matching_generation_is_persisted(pool: PgPool) {
    let mut f = Fixture::new(&pool).await;
    f.request.command.expected_generation = Some(2);
    assert_eq!(
        f.store.admit_execute(&f.request).await.unwrap(),
        ExecuteAdmission::GenerationMismatch
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    f.request.command.expected_generation = Some(1);
    let operation = f.admit().await;
    let (allocation, payload): (uuid::Uuid, serde_json::Value) =
        sqlx::query_as("SELECT execution_allocation_id,payload FROM operations WHERE id=$1")
            .bind(operation.uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(allocation, f.allocation.uuid());
    assert_eq!(payload["expected_generation"], 1);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn exact_guarded_retry_keeps_its_original_operation_after_generation_changes(pool: PgPool) {
    let mut f = Fixture::new(&pool).await;
    f.request.command.expected_generation = Some(1);
    let original = f.admit().await;
    sqlx::query("UPDATE sandboxes SET generation=2 WHERE id=$1")
        .bind(f.request.sandbox_id.uuid())
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(f.admit().await, original);
    let mut changed = f.request.clone();
    changed.command.expected_generation = Some(2);
    assert_eq!(
        f.store.admit_execute(&changed).await.unwrap(),
        ExecuteAdmission::DigestConflict
    );
    changed.command.expected_generation = None;
    assert_eq!(
        f.store.admit_execute(&changed).await.unwrap(),
        ExecuteAdmission::DigestConflict
    );
    changed = f.request.clone();
    changed.idempotency_key = key();
    assert_eq!(
        f.store.admit_execute(&changed).await.unwrap(),
        ExecuteAdmission::GenerationMismatch
    );
    sqlx::query("UPDATE operations SET status='succeeded',completed_at=clock_timestamp(),response_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(original.uuid()).execute(&pool).await.unwrap();
    assert_eq!(
        f.store.admit_execute(&f.request).await.unwrap(),
        ExecuteAdmission::ResponseExpired(original)
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn guarded_queued_work_is_rejected_if_the_target_generation_changes(pool: PgPool) {
    let mut f = Fixture::new(&pool).await;
    f.request.command.expected_generation = Some(1);
    let operation = f.admit().await;
    let claim = f.claim().await;
    sqlx::query("UPDATE sandboxes SET generation=2 WHERE id=$1")
        .bind(f.request.sandbox_id.uuid())
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        f.store.prepare_execute(&claim, f.host, 1).await.unwrap(),
        ExecuteAction::Rejected
    ));
    let (attempts, status, error): (i32, String, serde_json::Value) =
        sqlx::query_as("SELECT attempt_count,status,error FROM operations WHERE id=$1")
            .bind(operation.uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(attempts, 0);
    assert_eq!(status, "failed");
    assert_eq!(error["code"], "execution_target_changed");
}

#[sqlx::test(migrator = "sandbox_store::MIGRATOR")]
async fn generation_is_rechecked_after_waiting_for_the_sandbox_lock(pool: PgPool) {
    let mut f = Fixture::new(&pool).await;
    f.request.command.expected_generation = Some(1);
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM sandboxes WHERE id=$1 FOR UPDATE")
        .bind(f.request.sandbox_id.uuid())
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let store = f.store.clone();
    let request = f.request.clone();
    let admission = tokio::spawn(async move { store.admit_execute(&request).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM sandboxes WHERE id=$1 AND project_id=$2 FOR UPDATE%')")
                .fetch_one(&pool).await.unwrap();
            if blocked { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    sqlx::query("UPDATE sandboxes SET generation=2 WHERE id=$1")
        .bind(f.request.sandbox_id.uuid())
        .execute(&mut *lock)
        .await
        .unwrap();
    lock.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), admission)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        ExecuteAdmission::GenerationMismatch
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
