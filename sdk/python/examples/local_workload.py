"""Finite authenticated development workload; retain the private state on failure."""

import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

from hudson_sandbox import Client, ClientError, models

import recover_execute as state
import recover_operation as steps

DATA = b"\x00\xffhudson-local-workload\n"
DATA_SHA = hashlib.sha256(DATA).hexdigest()
STDOUT = b"hudson-workload\n"
COMMAND = "/bin/cp input.bin result.bin && printf 'hudson-workload\\n'"


def optional(journal, name):
    try:
        return state.decode(journal.read(name))
    except FileNotFoundError:
        return None


def confirm(journal, name):
    state.private_read(name, journal.fd, sync=True)
    os.fsync(journal.fd)


def child(journal, name):
    try:
        os.mkdir(name, mode=0o700, dir_fd=journal.fd)
    except FileExistsError:
        pass
    os.fsync(journal.fd)
    return steps.Journal(name, directory=journal.fd)


async def step(client, root, binding, name, request, seconds):
    with child(root, name) as journal:
        if optional(journal, "request.json") is None:
            steps.prepare(journal, binding, "local-workload." + name, name, request)
        saved, digest = steps.load(journal, binding)
        # A relative execute deadline is chosen exactly once, then reused.
        expected = steps.payload(name, request)
        if name == "execute":
            expected["body"]["deadline_unix_ms"] = saved["request"]["body"][
                "deadline_unix_ms"
            ]
        if (
            saved["kind"] != name
            or saved["logical_run_id"] != "local-workload." + name
            or saved["request"] != expected
        ):
            state.invalid()
        if steps.receipt(journal, digest) is None:
            await steps.recover(client, journal, binding, "submit", seconds)
        report = await steps.recover(client, journal, binding, "wait", seconds)
        if report["status"] != "succeeded" or report["response_expired"]:
            raise state.StateError(
                "saved step is not successful; inspect its retained operation"
            )
        if name == "execute":
            result = report.get("process_result")
            if (
                result is None
                or result["exit_code"] != 0
                or result["signal"] is not None
            ):
                raise state.StateError(
                    "workload has no successful guest process result"
                )
        return report


async def read_outputs(client, root, operation, simulated):
    report = optional(root, "output.json")
    if report is not None:
        return report
    for name, expected in (("stdout", STDOUT), ("stderr", b"")):
        chunk = await client.read_output(
            operation_id=operation, output_name=name, offset=0, limit=4096
        )
        if (
            chunk.simulated != simulated
            or not chunk.eof
            or chunk.data != expected
            or chunk.size != len(expected)
            or chunk.seen != len(expected)
            or chunk.truncated
        ):
            raise ClientError("integrity")
        try:
            if root.read(name + ".bin") != chunk.data:
                raise ClientError("integrity")
        except FileNotFoundError:
            root.write_new(name + ".bin", chunk.data)
    count, cursor = 0, None
    try:
        async with asyncio.timeout(5):
            async with await client.stream_output(operation_id=operation) as stream:
                async for event in stream:
                    if event.event in ("gap", "error"):
                        raise state.StateError(
                            "output stream has a gap; retain state and inspect"
                        )
                    if event.data.simulated != simulated:
                        raise ClientError("integrity")
                    if event.event == "end" and not event.data.guest_reported:
                        raise ClientError("integrity")
                    count += 1
                    cursor = event.cursor
                    if event.event == "end" or count == 4:
                        break
    except TimeoutError:
        raise state.StateError(
            "bounded output stream wait expired; retain state"
        ) from None
    if not count or cursor is None:
        raise ClientError("protocol")
    report = {
        "stdout_bytes": len(STDOUT),
        "stderr_bytes": 0,
        "events": count,
        "cursor": cursor,
    }
    root.write_new("output.json", state.encode(report))
    return report


async def download(client, root, sandbox, simulated):
    capture = optional(root, "capture.json")
    if capture is None:
        if optional(root, "capture-started.json") is not None:
            raise state.StateError(
                "capture outcome is uncertain; use explicit teardown, not another capture"
            )
        root.write_new("capture-started.json", state.encode({"version": 1}))
        confirm(root, "capture-started.json")
        value = await client.capture_file(
            sandbox_id=sandbox, body=models.FileCaptureRequest(path="result.bin")
        )
        capture = value.to_wire()
        root.write_new("capture.json", state.encode(capture))
    capture = models.FileCaptureResponse(**capture)
    capture.to_wire()
    if (
        capture.size != len(DATA)
        or capture.sha256 != DATA_SHA
        or capture.chunk_size != 32768
        or not capture.guest_reported
        or capture.simulated != simulated
    ):
        raise ClientError("integrity")
    try:
        data = root.read("verified-download.bin")
    except FileNotFoundError:
        chunk = await client.read_captured_file(
            sandbox_id=sandbox, x_file_capture=capture.capture, offset=0, limit=32768
        )
        if (
            chunk.size != capture.size
            or chunk.sha256 != capture.sha256
            or chunk.simulated != simulated
            or not chunk.eof
            or not chunk.guest_reported
        ):
            raise ClientError("integrity")
        data = chunk.data
        if hashlib.sha256(data).hexdigest() != DATA_SHA:
            raise ClientError("integrity")
        root.write_new("verified-download.bin", data)
    if data != DATA:
        raise ClientError("integrity")
    confirm(root, "verified-download.bin")
    released = optional(root, "capture-release.json")
    if released is None:
        try:
            await client.release_file_capture(
                sandbox_id=sandbox, x_file_capture=capture.capture
            )
            released = {"confirmed": True}
        except ClientError:
            # Unknown release does not replace the capture. The explicitly
            # requested final destroy still reclaims the original allocation.
            released = {"confirmed": False}
        root.write_new("capture-release.json", state.encode(released))
    return {
        "size": len(DATA),
        "sha256": DATA_SHA,
        "capture_release_confirmed": released["confirmed"],
    }


def create_request(image):
    return {
        "body": {
            "image_digest": image,
            "resources": {"vcpu": 1, "memory_mib": 512, "disk_mib": 1024},
        }
    }


def known_sandbox(root, binding, image):
    with child(root, "create") as journal:
        if optional(journal, "request.json") is None:
            raise state.StateError(
                "no saved create request exists; no teardown was submitted"
            )
        saved, digest = steps.load(journal, binding)
        if (
            saved["kind"] != "create"
            or saved["logical_run_id"] != "local-workload.create"
            or saved["request"] != steps.payload("create", create_request(image))
        ):
            state.invalid()
        receipt = steps.receipt(journal, digest)
        if receipt is None or receipt["sandbox_id"] is None:
            raise state.StateError(
                "create admission is unknown; explicitly recover its saved create handle before teardown"
            )
        return receipt["sandbox_id"]


async def finish(client, root, binding, cleanup, seconds):
    if (
        not isinstance(cleanup, dict)
        or set(cleanup) != {"sandbox_id", "teardown_only", "simulated"}
        or type(cleanup["teardown_only"]) is not bool
        or (cleanup["simulated"] is not None and type(cleanup["simulated"]) is not bool)
    ):
        state.invalid()
    sandbox = cleanup["sandbox_id"]
    steps.identifier(sandbox, "sbx_")
    destroyed = await step(
        client, root, binding, "destroy", {"sandbox_id": sandbox, "body": {}}, seconds
    )
    report = {
        "development_only": True,
        "sandbox_id": sandbox,
        "destroy_operation_id": destroyed["operation_id"],
        "destroy_status": destroyed["status"],
        "teardown_only": cleanup["teardown_only"],
        "hardware_qualification": "pending",
        "simulated": cleanup["simulated"],
    }
    if not cleanup["teardown_only"]:
        output = optional(root, "output.json")
        released = optional(root, "capture-release.json")
        if (
            output is None
            or released is None
            or root.read("verified-download.bin") != DATA
        ):
            state.invalid()
        report.update(
            simulated=cleanup["simulated"],
            output={
                key: output[key] for key in ("stdout_bytes", "stderr_bytes", "events")
            },
            download={
                "size": len(DATA),
                "sha256": DATA_SHA,
                "capture_release_confirmed": released["confirmed"],
            },
        )
    report = saved_report(report, sandbox)
    report.pop("saved_report")
    root.write_new("completed.json", state.encode(report))
    return report


def saved_report(value, sandbox):
    base = {
        "development_only",
        "sandbox_id",
        "destroy_operation_id",
        "destroy_status",
        "teardown_only",
        "hardware_qualification",
        "simulated",
    }
    if (
        not isinstance(value, dict)
        or type(value.get("teardown_only")) is not bool
        or value.get("development_only") is not True
        or value.get("sandbox_id") != sandbox
        or value.get("destroy_status") != "succeeded"
        or value.get("hardware_qualification") != "pending"
        or (value.get("simulated") is not None and type(value["simulated"]) is not bool)
        or set(value)
        != base | (set() if value["teardown_only"] else {"output", "download"})
    ):
        state.invalid()
    steps.identifier(value["destroy_operation_id"], "op_")
    if not value["teardown_only"]:
        output, downloaded = value["output"], value["download"]
        if (
            type(value["simulated"]) is not bool
            or not isinstance(output, dict)
            or set(output) != {"stdout_bytes", "stderr_bytes", "events"}
            or output["stdout_bytes"] != len(STDOUT)
            or output["stderr_bytes"] != 0
            or type(output["events"]) is not int
            or not 1 <= output["events"] <= 4
            or not isinstance(downloaded, dict)
            or set(downloaded) != {"size", "sha256", "capture_release_confirmed"}
            or downloaded["size"] != len(DATA)
            or downloaded["sha256"] != DATA_SHA
            or type(downloaded["capture_release_confirmed"]) is not bool
        ):
            state.invalid()
    return {**value, "saved_report": True}


async def workload(
    client, root, binding, image, seconds, allow_simulated, teardown=False
):
    # Persist the caller-provisioned root directory entry before any admission.
    parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root.fd)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    header = optional(root, "workload.json")
    if header is None:
        if (
            teardown
            or not isinstance(image, str)
            or not re.fullmatch("sha256:[0-9a-f]{64}", image)
        ):
            raise state.StateError(
                "prepare a new workload with an immutable image digest"
            )
        header = {
            "version": 1,
            "client_binding": binding,
            "image_digest": image,
            "allow_simulated": allow_simulated,
        }
        root.write_new("workload.json", state.encode(header))
    if (
        set(header) != {"version", "client_binding", "image_digest", "allow_simulated"}
        or type(header["version"]) is not int
        or header["version"] != 1
        or header["client_binding"] != binding
        or type(header["allow_simulated"]) is not bool
        or not isinstance(header["image_digest"], str)
        or not re.fullmatch("sha256:[0-9a-f]{64}", header["image_digest"])
        or (image is not None and image != header["image_digest"])
        or (not teardown and header["allow_simulated"] != allow_simulated)
    ):
        raise state.StateError(
            "workload identity or settings changed; retain the original state"
        )
    complete = optional(root, "completed.json")
    if complete is not None:
        return saved_report(
            complete, known_sandbox(root, binding, header["image_digest"])
        )
    confirm(root, "workload.json")
    cleanup = optional(root, "cleanup-started.json")
    if cleanup is not None:
        if cleanup["sandbox_id"] != known_sandbox(
            root, binding, header["image_digest"]
        ):
            state.invalid()
        return await finish(client, root, binding, cleanup, seconds)
    simulated = None
    if teardown:
        sandbox = known_sandbox(root, binding, header["image_digest"])
        readiness = optional(root, "readiness.json")
        if readiness is not None:
            if (
                readiness["sandbox_id"] != sandbox
                or type(readiness["simulated"]) is not bool
            ):
                state.invalid()
            simulated = readiness["simulated"]
    if not teardown:
        created = await step(
            client,
            root,
            binding,
            "create",
            create_request(header["image_digest"]),
            seconds,
        )
        sandbox = created["sandbox_id"]
        observed = await client.get_sandbox(sandbox_id=sandbox)
        if (
            observed.sandbox_id != sandbox
            or observed.image_digest != header["image_digest"]
            or observed.observed_state != "running"
            or observed.desired_state != "running"
            or observed.generation < 1
            or not observed.observed_at
            or type(observed.observation_simulated) is not bool
        ):
            raise state.StateError(
                "sandbox has not reached authenticated observed readiness"
            )
        simulated = observed.observation_simulated
        readiness = {
            "sandbox_id": sandbox,
            "generation": observed.generation,
            "simulated": simulated,
        }
        previous = optional(root, "readiness.json")
        if previous is None:
            root.write_new("readiness.json", state.encode(readiness))
        elif previous != readiness:
            raise state.StateError(
                "sandbox generation or simulation changed; use explicit teardown"
            )
        if simulated and not allow_simulated:
            raise state.StateError(
                "simulated sandbox refused; use explicit teardown of its saved handle"
            )
        await step(
            client,
            root,
            binding,
            "upload",
            {
                "sandbox_id": sandbox,
                "path": "input.bin",
                "data_base64": base64.b64encode(DATA).decode(),
                "mode": "0644",
            },
            seconds,
        )
        executed = await step(
            client,
            root,
            binding,
            "execute",
            {
                "sandbox_id": sandbox,
                "body": {
                    "argv": ["/bin/sh", "-c", COMMAND],
                    "deadline_unix_ms": int(time.time() * 1000) + 60000,
                },
            },
            seconds,
        )
        if executed["process_result"]["simulated"] != simulated:
            raise ClientError("integrity")
        await read_outputs(client, root, executed["operation_id"], simulated)
        await download(client, root, sandbox, simulated)
    cleanup = {"sandbox_id": sandbox, "teardown_only": teardown, "simulated": simulated}
    root.write_new("cleanup-started.json", state.encode(cleanup))
    return await finish(client, root, binding, cleanup, seconds)


async def run(args):
    with (
        state.Journal(args.state) as root,
        state.bound_profile(args.config) as (binding, profile),
    ):
        async with Client(profile) as client:
            try:
                async with asyncio.timeout(5 * args.wait_seconds + 30):
                    return await workload(
                        client,
                        root,
                        binding,
                        args.image_digest,
                        args.wait_seconds,
                        args.allow_simulated,
                        args.action == "teardown",
                    )
            except TimeoutError:
                raise state.StateError(
                    "bounded workload wait expired; retain state and choose explicit recovery"
                ) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--image-digest")
    parser.add_argument("--wait-seconds", type=int, choices=range(1, 61), default=30)
    parser.add_argument("--allow-simulated", action="store_true")
    parser.add_argument("action", choices=("run", "teardown"))
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args))))
        return 0
    except ClientError as error:
        print(
            json.dumps(
                {
                    "error": error.kind
                    if error.kind
                    in {
                        "http",
                        "transport",
                        "protocol",
                        "request",
                        "integrity",
                        "wait_timeout",
                        "file",
                    }
                    else "client_error"
                }
            ),
            file=sys.stderr,
        )
    except state.StateError as error:
        print(str(error), file=sys.stderr)
    except KeyboardInterrupt:
        print(
            "Workload interrupted; retain private state and request teardown explicitly.",
            file=sys.stderr,
        )
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(
            "Local workload state unavailable; retain state and inspect saved handles.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
