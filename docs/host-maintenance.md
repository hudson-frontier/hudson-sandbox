# Local host maintenance

The offline `sandbox-host-manager` command provides the draining slice of [#116](https://github.com/hudson-infinity/hudson-sandbox/issues/116). It uses trusted operator database access; no new public management endpoint or guest authority is exposed. Host capability advertisements, registration/compatibility, backup/restore rehearsals and upgrade qualification remain separate work in that issue.

## Private configuration and commands

Create an operator-owned `0600` JSON file containing `version: 1` and `database_url`. Keep it outside customer payloads and source control. The reader rejects final symlinks, special/permissive/foreign-owned files, duplicate/unknown fields and files larger than 64 KiB. Errors use fixed diagnostics without printing database credentials or arbitrary query text. The command neither runs migrations nor resets data.

```sh
cargo run -p sandbox-controller --bin sandbox-host-manager -- \
  --database-config /private/database.json --host-id HOST_ID --host-epoch CURRENT_EPOCH status
cargo run -p sandbox-controller --bin sandbox-host-manager -- \
  --database-config /private/database.json --host-id HOST_ID --host-epoch CURRENT_EPOCH drain
cargo run -p sandbox-controller --bin sandbox-host-manager -- \
  --database-config /private/database.json --host-id HOST_ID --host-epoch CURRENT_EPOCH finish-drain
```

Use the explicitly provisioned typed host ID and expected positive epoch. No command issues/replaces an epoch, changes capacity, approves an image or turns an unhealthy host ready. Database access is installation-wide operator authority, not a Project credential or implicit delegation to an agent.

## Drain and completion semantics

`drain` locks the host row used by placement, transitions ready to draining and returns bounded counts. Repeated drain at the same epoch is idempotent. A changed/missing epoch or unhealthy state fails. A placement serialized after drain cannot reserve that host. Work already dispatched continues through service-owned inspection/lease/cleanup; no caller mutation is replayed. New command/upload admission on that draining host follows the existing fail-closed rules.

The report contains the status/epoch, outstanding allocations, reserved CPU/RAM/disk, unfinished operations and unknown operations associated with unreleased allocations. Counts describe database reservations; they are not independent physical cleanup receipts or proof that external effects are known. Drain preserves allocations, leases, permits, idempotency keys, histories and retirement scope. It never refunds capacity, cancels, destroys, deletes storage or promises resumable memory.

Let admitted work finish or explicitly cancel/destroy the relevant sandbox through its ordinary authenticated API. Destroy remains available after a command failure or unknown outcome. Confirm its terminal cleanup operation; reservations stay until the existing verified release path completes. Closing the manager/controller is not resource reclamation.

`finish-drain` is a separate explicit action. It requires draining status at the expected epoch, zero outstanding reservations and a fresh service observation within thirty seconds. The host row remains locked through checking/reopening, so new placement cannot race the absence check. Authenticated controller health refresh cannot promote draining automatically. Retention/retirement continue independently after a verified physical release.

## Validation and limits

[Store tests](../crates/sandbox-store/tests/host_maintenance.rs) exercise epoch fencing, idempotence, unhealthy refusal, stale health and explicit reopening. [Controller tests](../crates/sandbox-controller/tests/host_maintenance.rs) prove placement exclusion while an admitted command reports a nonzero exit, followed by explicit destruction and reopening. The command's unit test rejects unsafe/private configuration boundaries.

These PostgreSQL/simulated-host checks validate maintenance coordination, not a real host drain or backup/restore procedure. Supported-host qualification, capabilities/image compatibility, independent operator acceptance and future multi-host/cloud/provider decisions remain the [roadmap](roadmap.md). Saved-memory draining requires verified full pause/resume; it is not implied by this command.
