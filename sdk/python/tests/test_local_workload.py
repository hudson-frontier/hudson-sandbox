"""Protocol/restart tests with an authenticated SDK and explicitly simulated responses."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import httpx
from hudson_sandbox import Client, ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
import local_workload as example

SB = "sbx_0192c4a1-72df-7000-8000-000000000001"
OPS = {
    name: "op_0192c4a1-72df-7000-8000-00000000000" + str(index)
    for index, name in enumerate(("create", "upload", "execute", "destroy"), 1)
}
IMAGE = "sha256:" + "a" * 64


def reply(status, value):
    return httpx.Response(
        status,
        headers={"cache-control": "no-store", "content-type": "application/json"},
        stream=httpx.ByteStream(json.dumps(value).encode()),
    )


class WorkloadTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.directory = self.root / "state"
        self.directory.mkdir(mode=0o700)
        for name, value in (
            (
                "credential.json",
                {
                    "version": 1,
                    "project_id": "prj_fixture",
                    "name": "local-workload",
                    "token": "private-workload-token",
                    "created_at": 1,
                    "expires_at": 4102444800,
                },
            ),
            (
                "client.json",
                {
                    "version": 1,
                    "endpoint": "https://sandbox.test",
                    "credential_file": "credential.json",
                },
            ),
        ):
            path = self.root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        self.client = Client(self.root / "client.json")
        await self.client._http.aclose()
        self.client._http = httpx.AsyncClient(transport=httpx.MockTransport(self.route))
        self.calls = []
        self.lost = None
        self.ready = True
        self.generation = 1
        self.destroyed = False
        self.corrupt = False

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp.cleanup()

    def route(self, request):
        self.assertEqual(
            request.headers["authorization"], "Bearer private-workload-token"
        )
        self.calls.append(
            (
                request.method,
                request.url.path,
                request.headers.get("idempotency-key"),
                request.content,
            )
        )
        path = request.url.path
        if request.method in ("POST", "PUT"):
            if path == "/v1/sandboxes":
                kind = "create"
            elif path.endswith("/execute"):
                kind = "execute"
            elif path.endswith("/destroy"):
                kind = "destroy"
                self.destroyed = True
            elif request.method == "PUT" and path.endswith("/files"):
                kind = "upload"
            elif path.endswith("/files/captures"):
                if self.lost == "capture":
                    self.lost = None
                    raise httpx.ReadError("private lost capture reply", request=request)
                return reply(
                    201,
                    {
                        "capture": "opaque-fixture-capture",
                        "size": len(example.DATA),
                        "sha256": example.DATA_SHA,
                        "expires_unix_ms": 4102444800000,
                        "chunk_size": 32768,
                        "simulated": True,
                        "guest_reported": True,
                    },
                )
            else:
                self.fail("unexpected POST")
            if self.lost == kind:
                self.lost = None
                raise httpx.ReadError("private lost admission reply", request=request)
            return reply(
                202,
                {
                    "sandbox_id": SB,
                    "operation_id": OPS[kind],
                    "status": "queued",
                    "status_url": "/v1/operations/" + OPS[kind],
                },
            )
        if request.method == "DELETE":
            return httpx.Response(
                204, headers={"cache-control": "no-store"}, stream=httpx.ByteStream(b"")
            )
        if path.startswith("/v1/operations/") and path.split("/")[-1] in OPS.values():
            op = path.split("/")[-1]
            kind = next(name for name, value in OPS.items() if value == op)
            value = {
                "sandbox_id": SB,
                "operation_id": op,
                "kind": "file_write" if kind == "upload" else kind,
                "status": "succeeded",
                "created_at": "2026-10-14T00:00:00Z",
            }
            if kind == "execute":
                value["result"] = {
                    "guest_reported": True,
                    "simulated": True,
                    "exit_code": 0,
                    "signal": None,
                }
            return reply(200, value)
        if path == "/v1/sandboxes/" + SB:
            return reply(
                200,
                {
                    "sandbox_id": SB,
                    "desired_state": "running",
                    "image_digest": IMAGE,
                    "observed_state": "running" if self.ready else "creating",
                    "generation": self.generation,
                    "observed_at": "2026-10-14T00:00:00Z",
                    "observation_simulated": True,
                    "resources": {"vcpu": 1, "memory_mib": 512, "disk_mib": 1024},
                    "created_at": "2026-10-14T00:00:00Z",
                },
            )
        if path.endswith("/stream"):
            body = {
                "reason": "complete",
                "stdout": {
                    "seen": len(example.STDOUT),
                    "stored": len(example.STDOUT),
                    "truncated": False,
                },
                "stderr": {"seen": 0, "stored": 0, "truncated": False},
                "simulated": True,
                "guest_reported": True,
            }
            return httpx.Response(
                200,
                headers={
                    "cache-control": "no-store",
                    "content-type": "text/event-stream",
                },
                stream=httpx.ByteStream(
                    (
                        "event: end\nid: fixture-cursor\ndata: "
                        + json.dumps(body)
                        + "\n\n"
                    ).encode()
                ),
            )
        if "/outputs/" in path:
            data = example.STDOUT if path.endswith("/stdout") else b""
            prefix = "output"
        elif path.endswith("/files/captures"):
            data = b"corrupt" if self.corrupt else example.DATA
            prefix = "file"
        else:
            self.fail("unexpected GET")
        headers = {
            "cache-control": "no-store",
            "content-type": "application/octet-stream",
            f"x-{prefix}-offset": "0",
            f"x-{prefix}-next-offset": str(len(data)),
            f"x-{prefix}-size": str(len(data)),
            f"x-{prefix}-eof": "true",
            f"x-{prefix}-simulated": "true",
        }
        if prefix == "output":
            headers.update(
                {"x-output-seen": str(len(data)), "x-output-truncated": "false"}
            )
        else:
            headers.update(
                {"x-file-sha256": example.DATA_SHA, "x-file-guest-reported": "true"}
            )
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(data))

    async def call(self, *, teardown=False, allow=True, binding="fixture-binding"):
        with example.state.Journal(self.directory) as journal:
            return await example.workload(
                self.client, journal, binding, IMAGE, 2, allow, teardown
            )

    def posts(self, kind):
        return [
            value
            for value in self.calls
            if value[0] == "POST" and value[1].endswith(kind)
        ]

    async def test_finite_flow_verifies_binary_output_download_and_preserves_simulation(
        self,
    ):
        report = await self.call()
        self.assertTrue(report["simulated"])
        self.assertEqual(report["hardware_qualification"], "pending")
        self.assertEqual(
            (self.directory / "verified-download.bin").read_bytes(), example.DATA
        )
        self.assertEqual(
            report["download"]["sha256"], hashlib.sha256(example.DATA).hexdigest()
        )
        self.assertTrue(report["download"]["capture_release_confirmed"])
        self.assertEqual(report["destroy_status"], "succeeded")
        self.assertNotIn("opaque-fixture-capture", json.dumps(report))
        self.assertNotIn("private-workload-token", json.dumps(report))
        count = len(self.calls)
        self.assertTrue((await self.call())["saved_report"])
        self.assertEqual(len(self.calls), count)

    async def test_lost_execute_reply_reuses_exact_key_payload_and_original_deadline(
        self,
    ):
        self.lost = "execute"
        with self.assertRaises(ClientError):
            await self.call()
        original = self.posts("/execute")[0]
        with patch.object(example.time, "time", return_value=4102444800):
            await self.call()
        self.assertEqual(self.posts("/execute"), [original, original])
        self.assertEqual(len(self.posts("/v1/sandboxes")), 1)

    async def test_readiness_and_simulation_must_be_observed_before_upload_or_execute(
        self,
    ):
        self.ready = False
        with self.assertRaises(example.state.StateError):
            await self.call()
        self.assertFalse(self.posts("/execute"))
        self.ready = True
        with self.assertRaises(example.state.StateError):
            await self.call(allow=False)
        self.assertFalse(self.posts("/execute"))
        await self.call(teardown=True)
        self.assertTrue(self.destroyed)

    async def test_lost_capture_reply_does_not_recapture_or_implicitly_destroy(self):
        self.lost = "capture"
        with self.assertRaises(ClientError):
            await self.call()
        with self.assertRaises(example.state.StateError):
            await self.call()
        self.assertEqual(len(self.posts("/files/captures")), 1)
        self.assertFalse(self.destroyed)
        await self.call(teardown=True)
        self.assertTrue(self.destroyed)

    async def test_teardown_never_reposts_an_unknown_create_admission(self):
        self.lost = "create"
        with self.assertRaises(ClientError):
            await self.call()
        count = len(self.calls)
        with self.assertRaises(example.state.StateError):
            await self.call(teardown=True)
        self.assertEqual(len(self.calls), count)

    async def test_expired_create_recovery_persists_identity_for_explicit_teardown(
        self,
    ):
        original_route = self.route

        def expired(request):
            if request.method == "POST" and request.url.path == "/v1/sandboxes":
                return reply(
                    410,
                    {
                        "title": "Response expired",
                        "status": 410,
                        "code": "response_expired",
                        "operation_id": OPS["create"],
                    },
                )
            return original_route(request)

        await self.client._http.aclose()
        self.client._http = httpx.AsyncClient(transport=httpx.MockTransport(expired))
        with self.assertRaises(ClientError):
            await self.call()
        directory = self.directory / "create"
        original_receipt = (directory / "receipt.json").read_bytes()
        with example.steps.Journal(directory) as journal:
            recovered = await example.steps.recover(
                self.client, journal, "fixture-binding", "poll"
            )
        self.assertEqual(recovered["sandbox_id"], SB)
        report = await self.call(teardown=True)
        self.assertTrue(report["teardown_only"])
        self.assertTrue(self.destroyed)
        self.assertEqual((directory / "receipt.json").read_bytes(), original_receipt)
        self.assertFalse(any(call[0] == "PUT" for call in self.calls))
        self.assertFalse(self.posts("/execute"))

    async def test_root_directory_sync_failure_prevents_admission(self):
        with patch.object(
            example.os, "fsync", side_effect=OSError("private sync failure")
        ):
            with self.assertRaises(OSError):
                await self.call()
        self.assertEqual(self.calls, [])

    async def test_default_mode_refuses_simulation_and_keeps_its_teardown_provenance(
        self,
    ):
        with self.assertRaisesRegex(
            example.state.StateError, "simulated sandbox refused"
        ):
            await self.call(allow=False)
        self.assertFalse(self.posts("/execute"))
        self.assertFalse(any(call[0] == "PUT" for call in self.calls))
        report = await self.call(teardown=True, allow=False)
        self.assertTrue(report["simulated"])
        self.assertTrue(report["teardown_only"])

    async def test_replacement_generation_cannot_continue_a_saved_workload(self):
        self.lost = "execute"
        with self.assertRaises(ClientError):
            await self.call()
        original = self.posts("/execute")
        self.generation = 2
        with self.assertRaisesRegex(
            example.state.StateError, "generation or simulation changed"
        ):
            await self.call()
        self.assertEqual(self.posts("/execute"), original)
        self.assertFalse(self.destroyed)

    async def test_crash_after_destroy_resumes_cleanup_without_repeating_work(self):
        self.lost = "destroy"
        with self.assertRaises(ClientError):
            await self.call()
        executed = self.posts("/execute")
        captured = self.posts("/files/captures")
        await self.call()
        self.assertEqual(self.posts("/execute"), executed)
        self.assertEqual(self.posts("/files/captures"), captured)
        self.assertEqual(self.posts("/destroy")[0], self.posts("/destroy")[1])

    async def test_changed_profile_or_download_integrity_failure_preserves_state(self):
        self.corrupt = True
        with self.assertRaises(ClientError):
            await self.call()
        count = len(self.calls)
        with self.assertRaises(example.state.StateError):
            await self.call(binding="other-profile")
        self.assertEqual(len(self.calls), count)
        self.assertFalse((self.directory / "verified-download.bin").exists())
        self.assertFalse(self.destroyed)


if __name__ == "__main__":
    unittest.main()
