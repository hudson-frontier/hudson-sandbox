//! Offline operator maintenance. Drain serializes with placement; never frees capacity.

use sandbox_protocol::{HostId, Id};
use serde::Serialize;
use sqlx::Row;

use crate::Store;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HostMaintenance {
    pub host_id: String,
    pub supervisor_epoch: i64,
    pub status: String,
    pub outstanding_allocations: i64,
    pub reserved_vcpu: i64,
    pub reserved_memory_mib: i64,
    pub reserved_disk_mib: i64,
    pub unfinished_operations: i64,
    pub unknown_operations: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("host missing, epoch changed or maintenance state incompatible")]
    Conflict,
    #[error("host still has reservations or lacks a fresh authenticated observation")]
    Outstanding,
    #[error("host maintenance storage query failed")]
    Query(#[from] sqlx::Error),
}

async fn report(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host: HostId,
    expected_epoch: i64,
) -> Result<HostMaintenance, Error> {
    let row = sqlx::query(
        "SELECT status,supervisor_epoch FROM hosts WHERE id=$1 AND supervisor_epoch=$2 FOR UPDATE",
    )
    .bind(host.uuid())
    .bind(expected_epoch)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::Conflict)?;
    let reservations: (i64,i64,i64,i64) = sqlx::query_as("SELECT count(*),COALESCE(sum(vcpu),0)::bigint,COALESCE(sum(memory_mib),0)::bigint,COALESCE(sum(disk_mib),0)::bigint FROM allocations WHERE host_id=$1 AND released_at IS NULL")
        .bind(host.uuid()).fetch_one(&mut **tx).await?;
    let work: (i64,i64) = sqlx::query_as("SELECT count(*),count(*) FILTER (WHERE o.status='unknown') FROM operations o JOIN allocations a ON a.sandbox_id=o.sandbox_id WHERE a.host_id=$1 AND a.released_at IS NULL AND o.status IN ('queued','running','unknown')")
        .bind(host.uuid()).fetch_one(&mut **tx).await?;
    Ok(HostMaintenance {
        host_id: host.to_string(),
        supervisor_epoch: row.try_get("supervisor_epoch")?,
        status: row.try_get("status")?,
        outstanding_allocations: reservations.0,
        reserved_vcpu: reservations.1,
        reserved_memory_mib: reservations.2,
        reserved_disk_mib: reservations.3,
        unfinished_operations: work.0,
        unknown_operations: work.1,
    })
}

impl Store {
    /// Count remaining reservations without interpreting absence as cleanup proof.
    pub async fn host_maintenance(
        &self,
        host: HostId,
        expected_epoch: i64,
    ) -> Result<HostMaintenance, Error> {
        if expected_epoch <= 0 {
            return Err(Error::Conflict);
        }
        let mut tx = self.pool().begin().await?;
        let value = report(&mut tx, host, expected_epoch).await?;
        tx.commit().await?;
        Ok(value)
    }

    /// Idempotently block new placements at exactly the provisioned host epoch.
    /// Existing allocations, permits, leases, request keys and histories are preserved.
    pub async fn drain_host(
        &self,
        host: HostId,
        expected_epoch: i64,
    ) -> Result<HostMaintenance, Error> {
        if expected_epoch <= 0 {
            return Err(Error::Conflict);
        }
        let mut tx = self.pool().begin().await?;
        let value = report(&mut tx, host, expected_epoch).await?;
        if !matches!(value.status.as_str(), "ready" | "draining") {
            return Err(Error::Conflict);
        }
        sqlx::query("UPDATE hosts SET status='draining',updated_at=clock_timestamp() WHERE id=$1 AND supervisor_epoch=$2")
            .bind(host.uuid()).bind(expected_epoch).execute(&mut *tx).await?;
        let value = HostMaintenance {
            status: "draining".into(),
            ..value
        };
        tx.commit().await?;
        Ok(value)
    }

    /// Explicitly reopen only a fully drained host with a fresh service observation.
    /// This does not issue epochs, alter capacity or infer resumable guest memory.
    pub async fn finish_host_drain(
        &self,
        host: HostId,
        expected_epoch: i64,
    ) -> Result<HostMaintenance, Error> {
        if expected_epoch <= 0 {
            return Err(Error::Conflict);
        }
        let mut tx = self.pool().begin().await?;
        let value = report(&mut tx, host, expected_epoch).await?;
        if value.status != "draining" {
            return Err(Error::Conflict);
        }
        let fresh: bool = sqlx::query_scalar("SELECT COALESCE(last_seen_at>clock_timestamp()-interval '30 seconds',false) FROM hosts WHERE id=$1")
            .bind(host.uuid()).fetch_one(&mut *tx).await?;
        if value.outstanding_allocations != 0 || !fresh {
            return Err(Error::Outstanding);
        }
        sqlx::query("UPDATE hosts SET status='ready',updated_at=clock_timestamp() WHERE id=$1 AND supervisor_epoch=$2")
            .bind(host.uuid()).bind(expected_epoch).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(HostMaintenance {
            status: "ready".into(),
            ..value
        })
    }
}
