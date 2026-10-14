# Recover one execute request through the existing HTTP SDK

For create/upload/execute/cancel/destroy recovery, use [recover_operation.py](recover_operation.py) and the [versioned workflow contract](../../../docs/durable-workflow.md). Each caller-owned step retains its original key/payload and assigned handles; output/files and readiness use the existing SDK.

[recover_execute.py](recover_execute.py) demonstrates a narrow client recovery
contract for [sandbox #112](https://github.com/hudson-infinity/hudson-sandbox/issues/112)
and [Hudson #17](https://github.com/hudson-infinity/hudson/issues/17). It uses the
ordinary versioned HTTPS SDK. It is a source example, not a harness, workflow
engine, installer or complete workload quickstart. It needs an already-created
sandbox and a trusted private client configuration from the [client guide](../../../docs/language-clients.md).
No paid service, new transport or public deployment is involved.

## Prepare before submitting

Install the repository-pinned Python SDK dependencies with `make sdk-setup`.
Select an empty state directory for exactly one logical command. Keep that
directory and the original request until recovery is complete; do not overwrite,
edit or regenerate its key to work around an unknown outcome.

```sh
umask 077
mkdir execute-state
python3 - <<'PY'
import json
import time
from pathlib import Path
request = {"argv": ["printf", "hello"], "deadline_unix_ms": time.time_ns() // 1000000 + 60000}
Path("command.json").write_text(json.dumps(request))
PY

PYTHONPATH=sdk/python/src .venv-sdk/bin/python sdk/python/examples/recover_execute.py \
  --config /absolute/private/client.json --state execute-state prepare \
  --sandbox sbx_01996110-7c00-7000-8000-000000000001 --request command.json
```

Replace the sandbox ID with your own existing sandbox. Preparation validates the
SDK payload, saves a fresh key and the effective request including defaults, and
does **not** call the API. The original absolute deadline is retained. The local
example's request/state bound is 64 KiB, including its envelope; a request that
fits the API's body bound may exceed this example's smaller effective bound.

Records are private owned regular files, published atomically without overwrite
and fsynced before success is reported. The private owned directory is locked for
each invocation; concurrent use fails rather than sharing a mutable journal.
Before any mutation attempt, the validated saved request and its directory are
synced again; a previously interrupted publication cannot be mistaken for a
durable key merely because the file is visible. Failed sync sends no mutation and
retains the same request/key for explicit recovery.
Final-component symlinks, permissive files/directories and oversized records fail.
This protects accidental concurrency and publication, not a malicious actor with
the same user/host privileges. Use an ordinary local filesystem supporting Unix
locking, hard links and directory fsync; crash durability remains subject to that
filesystem. A killed writer may leave a private `.staging-*` file; it is never
interpreted as admission evidence.

## Submit explicitly; reconnect through the saved handle

```sh
PYTHONPATH=sdk/python/src .venv-sdk/bin/python sdk/python/examples/recover_execute.py \
  --config /absolute/private/client.json --state execute-state submit

PYTHONPATH=sdk/python/src .venv-sdk/bin/python sdk/python/examples/recover_execute.py \
  --config /absolute/private/client.json --state execute-state poll
```

`submit` sends at most one mutation attempt when no handle is saved. A transport or
protocol failure can leave admission uncertain. A later **explicit** `submit`
uses the same saved key, payload and deadline to reconcile admission; it does not
generate a new logical command. Once a handle is recorded, both `submit` and
`poll` only GET that operation. `poll` without a receipt refuses to send anything.
The example never waits in a retry loop, cancels, destroys or repeats an `unknown`
execution. Admission is not completion, and idempotent admission is not a promise
of exactly-once external side effects.

A valid `410 response_expired` admission reply retains its authorized
original handle while reporting the error. Conflicts and revoked credentials do
not become successful receipts. Operation `unknown`, response expiry and output
retention state remain explicit. Arbitrary workload results/errors are omitted
from console output; use the ordinary SDK to retrieve bounded output/files and
perform explicit cancellation/teardown under their existing contracts.

The journal binds to a digest of the trusted client configuration, credential
file and explicit CA file. It stores no credential plaintext. Changes to any of
them, including token rotation or timeout settings, **fail closed** before a saved
mutation is resubmitted. This conservative example does not implement credential
rotation/migration; an application must reconcile project identity through its
own trusted credential lifecycle. Keep configuration stable during a command.
The SDK loads a temporary private snapshot of the exact profile bytes used by
that digest, so a configuration that changes and changes back during startup
cannot silently select another origin or token. Snapshot files are mode 0600
inside a mode 0700 directory and are removed on normal exit or exception. An
uncatchable process termination may leave a private snapshot in the system's
temporary directory.
Never delete the request to bypass binding failures or create a fresh key for an
uncertain effect.

## Validation and remaining scope

Run the Python client tests with:

```sh
PYTHONPATH=sdk/python/src .venv-sdk/bin/python -m unittest discover -s sdk/python/tests
```

Tests exercise the real SDK parser/request builder against a no-network HTTPX
fixture: lost admission reply and process restart, identical key/payload/deadline,
read-only recovery, expiry, revocation/conflict, response identity validation,
private/no-clobber state and publication failures. They do not qualify TLS, the
real API/database, real microVMs or isolation. Existing shared client conformance
and HTTPS API integration own those client boundaries. The [workflow contract](../../../docs/durable-workflow.md)
and multi-mutation example cover create/readiness/output/files/stream/cancel/destroy,
including actual HTTPS/PostgreSQL process-restart tests. The separate Hudson
harness adapter and controlled runtime gate remain distinct.
