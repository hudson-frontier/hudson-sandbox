"""Recover one caller-owned workflow step through the existing authenticated SDK."""

import argparse
import asyncio
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from hudson_sandbox import Client, ClientError, models, new_idempotency_key

import recover_execute as state

KINDS = {"create", "execute", "upload", "cancel", "destroy"}
UPLOAD_CAP = 32768


class Journal(state.Journal):
    def confirm_request(self, digest):
        raw = state.private_read("request.json", self.fd, sync=True)
        if hashlib.sha256(raw).hexdigest() != digest:
            state.invalid()
        os.fsync(self.fd)


def identifier(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + state.ID, value):
        state.invalid()


def payload(kind, value):
    if not isinstance(value, dict):
        state.invalid()
    if kind == "create" and set(value) == {"body"}:
        body = dict(value["body"])
        body["resources"] = models.RequestedResources(**body["resources"])
        return {"body": models.CreateRequest(**body).to_wire()}
    if kind in ("execute", "destroy") and set(value) == {"sandbox_id", "body"}:
        identifier(value["sandbox_id"], "sbx_")
        model = models.CommandInput if kind == "execute" else models.DestroyRequest
        return {
            "sandbox_id": value["sandbox_id"],
            "body": model(**value["body"]).to_wire(),
        }
    if kind == "cancel" and set(value) == {"operation_id"}:
        identifier(value["operation_id"], "op_")
        return value
    if kind == "upload" and set(value) == {"sandbox_id", "path", "data_base64", "mode"}:
        identifier(value["sandbox_id"], "sbx_")
        path = value["path"]
        if (
            not isinstance(path, str)
            or not 1 <= len(path.encode()) <= 4096
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c == "\\" for c in path)
            or any(
                p in ("", ".", "..") or len(p.encode()) > 255 for p in path.split("/")
            )
            or path.split("/")[0] == ".hudson-transfers"
            or value["mode"] not in ("0644", "0755")
        ):
            state.invalid()
        try:
            data = base64.b64decode(value["data_base64"], validate=True)
        except (ValueError, binascii.Error):
            state.invalid()
        if (
            len(data) > UPLOAD_CAP
            or base64.b64encode(data).decode() != value["data_base64"]
        ):
            state.invalid()
        return value
    state.invalid()


def prepare(journal, binding, logical_run_id, kind, request):
    if (
        not isinstance(logical_run_id, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", logical_run_id)
        or kind not in KINDS
    ):
        state.invalid()
    value = {
        "version": 1,
        "client_binding": binding,
        "logical_run_id": logical_run_id,
        "kind": kind,
        "idempotency_key": new_idempotency_key(),
        "request": payload(kind, request),
    }
    journal.write_new("request.json", state.encode(value))


def load(journal, binding):
    raw = journal.read("request.json")
    value = state.decode(raw)
    if (
        set(value)
        != {
            "version",
            "client_binding",
            "logical_run_id",
            "kind",
            "idempotency_key",
            "request",
        }
        or type(value["version"]) is not int
        or value["version"] != 1
        or not isinstance(value["logical_run_id"], str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value["logical_run_id"])
        or value["kind"] not in KINDS
        or not isinstance(value["idempotency_key"], str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{16,128}", value["idempotency_key"])
    ):
        state.invalid()
    if value["client_binding"] != binding:
        raise state.StateError(
            "client identity changed; do not resubmit the saved step"
        )
    if payload(value["kind"], value["request"]) != value["request"]:
        state.invalid()
    return value, hashlib.sha256(raw).hexdigest()


def receipt(journal, digest):
    try:
        value = state.decode(journal.read("receipt.json"))
    except FileNotFoundError:
        return None
    if (
        set(value) != {"version", "request_sha256", "operation_id", "sandbox_id"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["request_sha256"] != digest
    ):
        state.invalid()
    identifier(value["operation_id"], "op_")
    if value["sandbox_id"] is not None:
        identifier(value["sandbox_id"], "sbx_")
    return value


def save_receipt(journal, digest, operation_id, sandbox_id):
    identifier(operation_id, "op_")
    if sandbox_id is not None:
        identifier(sandbox_id, "sbx_")
    journal.write_new(
        "receipt.json",
        state.encode(
            {
                "version": 1,
                "request_sha256": digest,
                "operation_id": operation_id,
                "sandbox_id": sandbox_id,
            }
        ),
    )


async def submit(client, saved):
    kind, request, key = saved["kind"], saved["request"], saved["idempotency_key"]
    if kind == "create":
        body = dict(request["body"])
        body["resources"] = models.RequestedResources(**body["resources"])
        return await client.create_sandbox(
            idempotency_key=key, body=models.CreateRequest(**body)
        )
    if kind == "execute":
        return await client.execute_command(
            sandbox_id=request["sandbox_id"],
            idempotency_key=key,
            body=models.CommandInput(**request["body"]),
        )
    if kind == "destroy":
        return await client.destroy_sandbox(
            sandbox_id=request["sandbox_id"],
            idempotency_key=key,
            body=models.DestroyRequest(**request["body"]),
        )
    if kind == "cancel":
        return await client.cancel_command(
            operation_id=request["operation_id"],
            idempotency_key=key,
            body=models.CancelRequest(),
        )
    return await client.upload(
        sandbox_id=request["sandbox_id"],
        idempotency_key=key,
        path=request["path"],
        data=base64.b64decode(request["data_base64"], validate=True),
        mode=request["mode"],
    )


def process_result(operation):
    value = operation.result
    if (
        operation.kind != "execute"
        or not isinstance(value, dict)
        or value.get("guest_reported") is not True
        or type(value.get("simulated")) is not bool
    ):
        return None
    exit_code, signal = value.get("exit_code"), value.get("signal")
    exited = type(exit_code) is int and 0 <= exit_code <= 255 and signal is None
    signalled = type(signal) is int and 1 <= signal <= 64 and exit_code is None
    if not (exited or signalled):
        return None
    return {
        "simulated": value["simulated"],
        "guest_reported": True,
        "exit_code": exit_code,
        "signal": signal,
    }


def classify(operation):
    if operation.response_expired:
        return "response_expired"
    if operation.status in ("queued", "running"):
        return "pending"
    if operation.status == "unknown":
        return "unknown_effects"
    if operation.status == "cancelled":
        return "cancelled"
    observed = process_result(operation)
    if observed is not None:
        return "simulated_process_result" if observed["simulated"] else "process_result"
    if operation.status == "failed":
        return "infrastructure_failure"
    if operation.kind == "execute":
        return "result_unavailable"
    return "completed"


async def recover(client, journal, binding, action, seconds=10):
    saved, digest = load(journal, binding)
    handle = receipt(journal, digest)
    if handle is None:
        if action != "submit":
            raise state.StateError(
                "no saved operation handle; explicitly submit the exact saved step to reconcile admission"
            )
        journal.confirm_request(digest)
        try:
            admitted = await submit(client, saved)
        except ClientError as error:
            if (
                error.kind == "http"
                and error.status == 410
                and error.code == "response_expired"
                and error.operation_id
            ):
                save_receipt(
                    journal,
                    digest,
                    error.operation_id,
                    saved["request"].get("sandbox_id"),
                )
            raise
        identifier(admitted.sandbox_id, "sbx_")
        if (
            admitted.status not in state.STATUSES
            or saved["request"].get("sandbox_id", admitted.sandbox_id)
            != admitted.sandbox_id
        ):
            state.invalid()
        save_receipt(journal, digest, admitted.operation_id, admitted.sandbox_id)
        return {
            "logical_run_id": saved["logical_run_id"],
            "kind": saved["kind"],
            "sandbox_id": admitted.sandbox_id,
            "operation_id": admitted.operation_id,
            "status": admitted.status,
            "admission_only": True,
        }
    # Saved handles always query; submit after a caller restart never sends POST.
    try:
        operation = (
            await client.wait(handle["operation_id"], seconds)
            if action == "wait"
            else await client.get_operation(operation_id=handle["operation_id"])
        )
    except ClientError as error:
        raise ClientError(
            error.kind, error.status, error.code, handle["operation_id"]
        ) from None
    identifier(operation.sandbox_id, "sbx_")
    if (
        operation.operation_id != handle["operation_id"]
        or operation.status not in state.STATUSES
        or operation.output_status
        not in (None, "none", "pending", "uploading", "published", "expired")
        or (
            handle["sandbox_id"] is not None
            and operation.sandbox_id != handle["sandbox_id"]
        )
    ):
        state.invalid()
    expected_kind = "file_write" if saved["kind"] == "upload" else saved["kind"]
    if operation.kind != expected_kind or (
        saved["kind"] == "cancel"
        and operation.target_operation_id != saved["request"]["operation_id"]
    ):
        state.invalid()
    report = {
        "logical_run_id": saved["logical_run_id"],
        "kind": operation.kind,
        "sandbox_id": operation.sandbox_id,
        "operation_id": operation.operation_id,
        "status": operation.status,
        "response_expired": operation.response_expired,
        "output_status": operation.output_status,
        "outcome": classify(operation),
        "admission_only": False,
    }
    if not operation.response_expired and process_result(operation) is not None:
        report["process_result"] = process_result(operation)
    return report


async def run(args):
    with (
        Journal(args.state) as journal,
        state.bound_profile(args.config) as (binding, config),
    ):
        async with Client(config) as client:
            if state.binding(args.config) != binding:
                raise state.StateError(
                    "client configuration changed during initialization"
                )
            if args.action == "prepare":
                prepare(
                    journal,
                    binding,
                    args.run_id,
                    args.kind,
                    state.decode(state.private_read(args.request)),
                )
                return {"prepared": True, "submitted": False}
            return await recover(
                client, journal, binding, args.action, getattr(args, "seconds", 10)
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    prepared = commands.add_parser("prepare")
    prepared.add_argument("--run-id", required=True)
    prepared.add_argument("--kind", choices=sorted(KINDS), required=True)
    prepared.add_argument("--request", type=Path, required=True)
    commands.add_parser("submit")
    commands.add_parser("poll")
    wait = commands.add_parser("wait")
    wait.add_argument("--seconds", type=int, choices=range(1, 61), default=10)
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args))))
        return 0
    except ClientError as error:
        print(
            json.dumps(
                {
                    "error": error.kind,
                    "status": error.status,
                    "code": error.code,
                    "operation_id": error.operation_id,
                }
            ),
            file=sys.stderr,
        )
    except state.StateError as error:
        print(str(error), file=sys.stderr)
    except KeyboardInterrupt:
        print(
            "Caller interrupted; retain saved step/key/handles. Cleanup is explicit.",
            file=sys.stderr,
        )
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(
            "Private workflow state invalid or unavailable; retain the original request/key.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
