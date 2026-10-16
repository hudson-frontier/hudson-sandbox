//! Lossy work-discovery hints. The operation table and fenced claims own all work.
use std::time::Duration;

use sqlx::postgres::PgListener;

use crate::{Store, StoreError};

/// Database-local, versioned channel with no identifiers or caller-provided payload.
pub const WORK_CHANNEL: &str = "hudsonbox_work_v1";

impl Store {
    /// Subscribe before scanning. A disconnected listener can lose notifications;
    /// consumers must rescan after subscription and retain periodic polling.
    /// One connection is held from this store's existing pool while subscribed.
    pub async fn listen_for_work(&self) -> Result<PgListener, StoreError> {
        let mut listener = PgListener::connect_with(self.pool())
            .await
            .map_err(StoreError::Query)?;
        // Let the owner apply its reconnect budget and force a fresh scan.
        listener.eager_reconnect(false);
        listener
            .listen(WORK_CHANNEL)
            .await
            .map_err(StoreError::Query)?;
        Ok(listener)
    }

    /// Called only after a new operation commits. Failure, cancellation or a full
    /// notification queue cannot roll back that operation or change its response.
    pub(crate) async fn notify_work(&self) {
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            sqlx::query("SELECT pg_catalog.pg_notify($1, '')")
                .bind(WORK_CHANNEL)
                .execute(self.pool())
                .await
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn notification_failure_or_pool_pressure_is_bounded_and_ignored(pool: PgPool) {
        let store = Store::from_pool(pool.clone());
        let mut held = Vec::new();
        for _ in 0..pool.options().get_max_connections() {
            held.push(pool.acquire().await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(1), store.notify_work())
            .await
            .unwrap();
        drop(held);
        pool.close().await;
        tokio::time::timeout(Duration::from_secs(1), store.notify_work())
            .await
            .unwrap();
    }
}
