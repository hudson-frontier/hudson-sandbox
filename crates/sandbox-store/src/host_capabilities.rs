//! Operator policy and authenticated runtime observation must agree before new work.
use crate::{Store, dispatch::DispatchError};
use sandbox_protocol::{HostId, Id, host_capabilities::Capabilities};
use serde_json::Value;
use sqlx::Row;

fn decode(value: &Value) -> Result<Capabilities, DispatchError> {
    let bytes = serde_json::to_vec(value).map_err(|_| DispatchError::HostCompatibility)?;
    Capabilities::from_json(&bytes).map_err(|_| DispatchError::HostCompatibility)
}

pub(crate) fn compatible(
    host: &sqlx::postgres::PgRow,
    digest: &str,
    vcpu: u64,
    memory_mib: u64,
    disk_mib: u64,
) -> Result<(), DispatchError> {
    let policy: Value = host.try_get("compatibility")?;
    let observed: Option<Value> = host.try_get("runtime_capabilities")?;
    let observed_epoch: Option<i64> = host.try_get("runtime_capabilities_epoch")?;
    if policy == serde_json::json!({}) && observed.is_none() && observed_epoch.is_none() {
        // Compatibility-preserving migration path; explicitly unqualified legacy host.
        return Ok(());
    }
    let policy = decode(&policy)?;
    let observed = decode(observed.as_ref().ok_or(DispatchError::HostCompatibility)?)?;
    if observed_epoch != Some(host.try_get::<i64, _>("supervisor_epoch")?)
        || policy != observed
        || !policy.supports(digest, vcpu, memory_mib, disk_mib)
    {
        return Err(DispatchError::HostCompatibility);
    }
    Ok(())
}

impl Store {
    /// Invalidate admission freshness after configured authenticated health failed
    /// compatibility. Keep prior metadata and all existing ownership for recovery.
    pub async fn invalidate_host_capability_observation(
        &self,
        host: HostId,
        epoch: i64,
    ) -> Result<(), DispatchError> {
        let changed = sqlx::query(
            "UPDATE hosts SET last_seen_at=NULL,updated_at=clock_timestamp()
            WHERE id=$1 AND supervisor_epoch=$2 AND supervisor_epoch>0",
        )
        .bind(host.uuid())
        .bind(epoch)
        .execute(self.pool())
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(DispatchError::HostUnavailable);
        }
        Ok(())
    }

    /// Called only after configured mTLS identity, host ID, epoch and simulation
    /// policy have been checked. Cannot create a host or issue/change its epoch.
    /// No customer can supply this metadata. Policy is installed separately by
    /// the operator; health cannot approve its own images or increase capacity.
    pub async fn observe_configured_host_with_capabilities(
        &self,
        host: HostId,
        epoch: i64,
        bytes: &[u8],
        simulated: bool,
    ) -> Result<(), DispatchError> {
        let advertised = if bytes.is_empty() {
            None
        } else {
            let value =
                Capabilities::from_json(bytes).map_err(|_| DispatchError::HostCompatibility)?;
            if value.simulated != simulated {
                return Err(DispatchError::HostCompatibility);
            }
            Some(value)
        };
        let mut tx = self.pool().begin().await?;
        let row = sqlx::query(
            "SELECT compatibility,runtime_capabilities,runtime_capabilities_epoch FROM hosts
            WHERE id=$1 AND supervisor_epoch=$2 AND supervisor_epoch>0 FOR UPDATE",
        )
        .bind(host.uuid())
        .bind(epoch)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(DispatchError::HostUnavailable)?;
        let policy: Value = row.try_get("compatibility")?;
        let previous: Option<Value> = row.try_get("runtime_capabilities")?;
        let previous_epoch: Option<i64> = row.try_get("runtime_capabilities_epoch")?;
        if policy == serde_json::json!({})
            && previous.is_none()
            && previous_epoch.is_none()
            && advertised.is_none()
        {
            // Old host/old health response: preserve existing behavior and no qualification claim.
        } else if advertised.as_ref() != Some(&decode(&policy)?) {
            return Err(DispatchError::HostCompatibility);
        }
        // Updating the policy invalidates the previous observation until matching
        // authenticated health arrives. Empty health can never clear enrollment.
        let advertised = advertised
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| DispatchError::HostCompatibility)?;
        sqlx::query(
            "UPDATE hosts SET runtime_capabilities=$3,runtime_capabilities_epoch=$4,last_seen_at=clock_timestamp(),
            updated_at=clock_timestamp() WHERE id=$1 AND supervisor_epoch=$2",
        )
        .bind(host.uuid())
        .bind(epoch)
        .bind(&advertised)
        .bind(advertised.as_ref().map(|_| epoch))
        .execute(&mut *tx)
        .await?;
        // Placement locks sandbox before host. Release the host lock before
        // touching sandbox observations to avoid the reverse lock-order cycle.
        tx.commit().await?;
        // A new epoch cannot vouch for retained work from the prior incarnation.
        sqlx::query("UPDATE sandboxes s SET observed_state='unknown',state_revision=state_revision+1,updated_at=clock_timestamp()
            FROM allocations a WHERE s.current_allocation_id=a.id AND a.host_id=$1 AND a.supervisor_epoch<>$2
            AND a.released_at IS NULL AND s.desired_state='running' AND s.observed_state='running'
            AND s.active_transition_operation_id IS NULL")
            .bind(host.uuid()).bind(epoch).execute(self.pool()).await?;
        Ok(())
    }
}
