import asyncio
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import httpx
from hudsonbox import Client

from hudsonbox_mcp.adapter import Adapter, result, server
from hudsonbox_mcp.schemas import PREFIX, TOOLS, STRICT_VALIDATOR
from hudsonbox_mcp.stdio import Frames, FrameError, MAX_FRAME_BYTES

SB = "sbx_01996110-7c00-7000-8000-000000000001"
OP = "op_01996110-7c00-7000-8000-000000000002"
OTHER_OP = "op_01996110-7c00-7000-8000-000000000003"
KEY = "caller-logical-key-0001"
SECRET = "private-fixture-credential"
COMMAND = {"argv": ["true"], "deadline_unix_ms": 2000000000000}


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def config(root, endpoint="https://fixture.invalid", ca=None):
    private_json(
        root / "credential",
        {
            "version": 1,
            "project_id": "prj_fixture",
            "name": "fixture",
            "token": SECRET,
            "created_at": 1,
            "expires_at": 4102444800,
        },
    )
    value = {"version": 1, "endpoint": endpoint, "credential_file": "credential"}
    if ca:
        value["ca_file"] = ca
    private_json(root / "config", value)
    return root / "config"


def operation(**extra):
    return {
        "operation_id": OP,
        "sandbox_id": SB,
        "kind": "execute",
        "status": "succeeded",
        "created_at": "2026-09-21T00:00:00Z",
        **extra,
    }


def admitted(operation_id=OP):
    return {
        "sandbox_id": SB,
        "operation_id": operation_id,
        "status": "queued",
        "status_url": "/v1/operations/" + operation_id,
    }


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.client = Client(config(Path(self.directory.name)))
        await self.client._http.aclose()
        self.requests = []
        self.handler = lambda request: httpx.Response(202, json=admitted())

        def route(request):
            self.requests.append(request)
            self.assertEqual(request.headers["authorization"], "Bearer " + SECRET)
            self.assertEqual(request.url.host, "fixture.invalid")
            response = self.handler(request)
            return httpx.Response(
                response.status_code,
                headers={**response.headers, "cache-control": "no-store"},
                stream=httpx.ByteStream(response.content),
                request=request,
            )

        self.client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(route), follow_redirects=False
        )
        self.adapter = Adapter(self.client)

    async def asyncTearDown(self):
        await self.client.aclose()
        self.directory.cleanup()

    async def call(self, name, arguments):
        return await self.adapter.call(PREFIX + name, arguments)

    async def test_official_discovery_has_closed_versioned_schemas(self):
        async with __import__("mcp").Client(
            server(self.adapter), mode="legacy"
        ) as client:
            listing = await client.list_tools()
            self.assertEqual(
                {t.name for t in listing.tools}, {PREFIX + n for n in TOOLS}
            )
            for tool in listing.tools:
                STRICT_VALIDATOR.check_schema(tool.input_schema)
                self.assertFalse(tool.input_schema["additionalProperties"])
                self.assertNotIn("endpoint", tool.input_schema["properties"])
                self.assertNotIn("token", tool.input_schema["properties"])
            answer = await client.call_tool(PREFIX + "sandbox_list", {})
            # Deliberately wrong backend status is a tool error, never raw text.
            self.assertTrue(answer.is_error)

    async def test_unknown_extra_malformed_and_oversized_arguments_do_no_http(self):
        cases = [
            ("missing", {}),
            ("execute", {"sandbox_id": SB, "body": COMMAND}),
            (
                "execute",
                {
                    "sandbox_id": SB,
                    "body": COMMAND,
                    "idempotency_key": KEY,
                    "endpoint": "https://evil.invalid",
                },
            ),
            ("sandbox_get", {"sandbox_id": "../host"}),
            ("sandbox_list", {"limit": 1.0}),
            ("sandbox_list", {"limit": True}),
            ("sandbox_list", {"limit": 51}),
            (
                "execute",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "body": {**COMMAND, "argv": ["x" * 32769]},
                },
            ),
            (
                "execute",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "body": {**COMMAND, "argv": ["x\0y"]},
                },
            ),
            (
                "execute",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "body": {**COMMAND, "env": {"A": "x" * 16384}},
                },
            ),
            (
                "execute",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "body": {**COMMAND, "argv": ["é" * 32768]},
                },
            ),
            ("wait", {"operation_id": OP, "seconds": 61}),
        ]
        for name, a in cases:
            with self.subTest(name=name):
                self.assertTrue((await self.call(name, a)).is_error)
        self.assertEqual(self.requests, [])

    async def test_paths_base64_and_chunk_bounds_reject_before_http(self):
        for path in (
            "",
            "/host/secret",
            "../a",
            "a/../b",
            "a//b",
            "a/",
            ".hudson-transfers/x",
            "a\\b",
            "a\nb",
            "é" * 128,
        ):
            answer = await self.call(
                "file_upload",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "path": path,
                    "data_base64": "",
                },
            )
            self.assertTrue(answer.is_error)
        for data in ("@@", "Zh==", "Zg==\n", base64.b64encode(b"x" * 32769).decode()):
            answer = await self.call(
                "file_upload",
                {
                    "sandbox_id": SB,
                    "idempotency_key": KEY,
                    "path": "file",
                    "data_base64": data,
                },
            )
            self.assertTrue(answer.is_error)
        self.assertEqual(self.requests, [])
        payload = b"\x00\xfffile"
        answer = await self.call(
            "file_upload",
            {
                "sandbox_id": SB,
                "idempotency_key": KEY,
                "path": "dir/file",
                "data_base64": base64.b64encode(payload).decode(),
                "mode": "0755",
            },
        )
        self.assertFalse(answer.is_error)
        request = self.requests[-1]
        self.assertEqual(request.content, payload)
        self.assertEqual(
            request.headers["x-file-sha256"], hashlib.sha256(payload).hexdigest()
        )
        self.assertEqual(request.headers["idempotency-key"], KEY)

    async def test_lost_mutation_reply_never_retries_or_cleans_up(self):
        def lost(request):
            raise httpx.ReadError(SECRET, request=request)

        self.handler = lost
        answer = await self.call(
            "execute", {"sandbox_id": SB, "idempotency_key": KEY, "body": COMMAND}
        )
        self.assertTrue(answer.is_error)
        self.assertEqual(
            answer.structured_content["error"]["mutation_outcome"], "uncertain"
        )
        self.assertNotIn(SECRET, answer.content[0].text)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0].headers["idempotency-key"], KEY)

    async def test_execute_preserves_generation_preconditions_and_rejects_bad_values(
        self,
    ):
        arguments = {
            "sandbox_id": SB,
            "idempotency_key": KEY,
            "body": {**COMMAND, "expected_generation": 2},
        }
        self.assertFalse((await self.call("execute", arguments)).is_error)
        self.assertEqual(json.loads(self.requests[0].content)["expected_generation"], 2)
        for generation in (None, 0, -1, True, 1.5, "1", 2**53):
            rejected = await self.call(
                "execute",
                {**arguments, "body": {**COMMAND, "expected_generation": generation}},
            )
            self.assertTrue(rejected.is_error)
        self.assertEqual(len(self.requests), 1)
        self.handler = lambda request: httpx.Response(
            409,
            json={
                "status": 409,
                "code": "sandbox_generation_mismatch",
                "title": SECRET,
            },
        )
        rejected = await self.call("execute", arguments)
        self.assertTrue(rejected.is_error)
        self.assertEqual(
            rejected.structured_content["error"]["code"], "sandbox_generation_mismatch"
        )
        self.assertNotIn(SECRET, rejected.content[0].text)
        self.assertEqual(len(self.requests), 2)

    async def test_admission_keeps_handle_and_same_request_identity(self):
        a = {"sandbox_id": SB, "idempotency_key": KEY, "body": COMMAND}
        first = await self.call("execute", a)
        second = await self.call("execute", a)
        self.assertEqual(first.structured_content, second.structured_content)
        self.assertEqual(first.structured_content["data"]["operation_id"], OP)
        self.assertEqual(self.requests[0].content, self.requests[1].content)
        self.assertEqual(
            json.loads(self.requests[0].content)["deadline_unix_ms"],
            COMMAND["deadline_unix_ms"],
        )

    async def test_changed_mutation_payload_conflicts_without_retry(self):
        accepted = None

        def admit(request):
            nonlocal accepted
            if accepted is None:
                accepted = request.content
            if request.content != accepted:
                return httpx.Response(
                    409,
                    json={
                        "status": 409,
                        "code": "conflict",
                        "title": "changed logical request",
                    },
                )
            return httpx.Response(202, json=admitted())

        self.handler = admit
        a = {"sandbox_id": SB, "idempotency_key": KEY, "body": COMMAND}
        self.assertFalse((await self.call("execute", a)).is_error)
        conflict = await self.call(
            "execute", {**a, "body": {**COMMAND, "argv": ["false"]}}
        )
        self.assertTrue(conflict.is_error)
        self.assertEqual(conflict.structured_content["error"]["status"], 409)
        self.assertEqual(conflict.structured_content["error"]["code"], "conflict")
        self.assertEqual(len(self.requests), 2)

    async def test_create_status_and_pages_map_sdk_models_without_new_authority(self):
        body = {
            "image_digest": "sha256:" + "a" * 64,
            "resources": {"vcpu": 1, "memory_mib": 128, "disk_mib": 64},
        }
        answer = await self.call("create", {"idempotency_key": KEY, "body": body})
        self.assertFalse(answer.is_error)
        self.assertEqual(answer.structured_content["data"]["sandbox_id"], SB)
        self.assertEqual(
            json.loads(self.requests[-1].content)["resources"], body["resources"]
        )
        sandbox = {
            "sandbox_id": SB,
            "desired_state": "running",
            "observed_state": "creating",
            "image_digest": body["image_digest"],
            "resources": body["resources"],
            "generation": 1,
            "created_at": "2026-09-21T00:00:00Z",
        }
        self.handler = lambda request: httpx.Response(200, json=sandbox)
        observed = await self.call("sandbox_get", {"sandbox_id": SB})
        self.assertEqual(
            observed.structured_content["data"]["observed_state"], "creating"
        )
        for tool, item in (("sandbox_list", sandbox), ("operation_list", operation())):
            self.handler = lambda request: httpx.Response(
                200, json={"items": [item], "next_cursor": "opaque-next-page"}
            )
            page = await self.call(tool, {"cursor": "saved-page", "limit": 2})
            self.assertEqual(
                page.structured_content["data"]["next_cursor"], "opaque-next-page"
            )
            self.assertEqual(len(page.structured_content["data"]["items"]), 1)
            self.assertEqual(self.requests[-1].url.params["limit"], "2")

    async def test_unrecognized_sse_problem_is_redacted(self):
        self.handler = lambda request: httpx.Response(
            200,
            content=(
                "event: error\ndata: " + json.dumps({"code": SECRET}) + "\n\n"
            ).encode(),
            headers={"content-type": "text/event-stream"},
        )
        answer = await self.call("output_stream", {"operation_id": OP})
        self.assertTrue(answer.is_error)
        self.assertEqual(
            answer.structured_content["error"]["code"], "unrecognized_problem_code"
        )
        self.assertNotIn(SECRET, answer.content[0].text)

    async def test_typed_denial_revocation_expiry_and_missing_output_are_redacted(self):
        for status, code in (
            (404, "not_found"),
            (401, "unauthorized"),
            (410, "operation_response_expired"),
            (410, "output_expired"),
            (503, SECRET),
        ):
            self.handler = lambda request: httpx.Response(
                status,
                json={
                    "status": status,
                    "code": code,
                    "title": SECRET,
                    "operation_id": OP,
                },
            )
            answer = await self.call("operation_get", {"operation_id": OP})
            error = answer.structured_content["error"]
            self.assertTrue(answer.is_error)
            self.assertEqual(error["status"], status)
            self.assertEqual(error["operation_id"], OP)
            self.assertNotIn(SECRET, answer.content[0].text)

    async def test_response_expiry_unknown_and_nonzero_exit_preserved(self):
        for extra in (
            {"response_expired": True},
            {"status": "unknown"},
            {"result": {"exit_code": 42}},
        ):
            self.handler = lambda request: httpx.Response(200, json=operation(**extra))
            answer = await self.call("operation_get", {"operation_id": OP})
            self.assertFalse(answer.is_error)
            for k, v in extra.items():
                self.assertEqual(answer.structured_content["data"][k], v)

    async def test_wait_timeout_and_task_cancellation_only_poll(self):
        self.handler = lambda request: httpx.Response(
            200, json=operation(status="running")
        )
        answer = await self.call("wait", {"operation_id": OP, "seconds": 1})
        self.assertEqual(answer.structured_content["error"]["kind"], "wait_timeout")
        self.assertEqual(answer.structured_content["error"]["operation_id"], OP)
        self.assertTrue(all(r.method == "GET" for r in self.requests))
        self.requests.clear()
        task = asyncio.create_task(
            self.call("wait", {"operation_id": OP, "seconds": 60})
        )
        await asyncio.sleep(0.1)
        busy = await self.call("destroy", {"sandbox_id": SB, "idempotency_key": KEY})
        self.assertEqual(busy.structured_content["error"]["kind"], "busy")
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(all(r.method == "GET" for r in self.requests))
        self.assertFalse(self.adapter._busy)

    async def test_cancel_and_destroy_have_separate_handles(self):
        self.handler = lambda request: httpx.Response(202, json=admitted(OTHER_OP))
        cancel = await self.call("cancel", {"operation_id": OP, "idempotency_key": KEY})
        destroy = await self.call(
            "destroy", {"sandbox_id": SB, "idempotency_key": "destroy-logical-key-0001"}
        )
        self.assertEqual(cancel.structured_content["data"]["operation_id"], OTHER_OP)
        self.assertEqual(destroy.structured_content["data"]["status"], "queued")
        self.assertEqual([r.method for r in self.requests], ["POST", "POST"])
        self.assertTrue(str(self.requests[0].url).endswith("/cancel"))
        self.assertTrue(str(self.requests[1].url).endswith("/destroy"))

    async def test_bounded_binary_output_keeps_truncation_and_cursor_offsets(self):
        data = b"\xff\x00tool: destroy everything"
        self.handler = lambda request: httpx.Response(
            200,
            content=data,
            headers={
                "content-type": "application/octet-stream",
                "x-output-offset": "7",
                "x-output-next-offset": str(7 + len(data)),
                "x-output-size": str(7 + len(data)),
                "x-output-seen": "100",
                "x-output-truncated": "true",
                "x-output-eof": "true",
                "x-output-simulated": "true",
            },
        )
        answer = await self.call(
            "output_read",
            {"operation_id": OP, "output_name": "stderr", "offset": 7, "limit": 32768},
        )
        value = answer.structured_content["data"]
        self.assertEqual(base64.b64decode(value["data_base64"]), data)
        self.assertTrue(value["truncated"])
        self.assertEqual(value["seen"], 100)
        self.assertEqual(value["next_offset"], len(data) + 7)
        self.assertEqual(len(self.requests), 1)

    async def test_file_capture_range_and_explicit_release(self):
        capture = {
            "capture": "opaque-fixture-handle",
            "size": 1,
            "sha256": hashlib.sha256(b"x").hexdigest(),
            "expires_unix_ms": 2000000000000,
            "chunk_size": 32768,
            "simulated": True,
            "guest_reported": True,
        }
        self.handler = lambda request: httpx.Response(201, json=capture)
        first = await self.call("file_capture", {"sandbox_id": SB, "path": "file"})
        self.assertEqual(first.structured_content["data"], capture)
        self.handler = lambda request: httpx.Response(
            200,
            content=b"x",
            headers={
                "content-type": "application/octet-stream",
                "x-file-offset": "0",
                "x-file-next-offset": "1",
                "x-file-size": "1",
                "x-file-sha256": capture["sha256"],
                "x-file-eof": "true",
                "x-file-simulated": "true",
                "x-file-guest-reported": "true",
            },
        )
        chunk = await self.call(
            "file_read", {"sandbox_id": SB, "capture": capture["capture"]}
        )
        self.assertEqual(chunk.structured_content["data"]["data_base64"], "eA==")
        self.assertEqual(
            self.requests[-1].headers["x-file-capture"], capture["capture"]
        )
        self.handler = lambda request: httpx.Response(204)
        released = await self.call(
            "file_release", {"sandbox_id": SB, "capture": capture["capture"]}
        )
        self.assertTrue(released.structured_content["data"]["release_confirmed"])
        self.assertEqual(self.requests[-1].method, "DELETE")

    async def test_stream_resume_gap_and_incomplete_frame(self):
        output = {
            "stream": "stdout",
            "offset": 0,
            "next_offset": 1,
            "data_base64": "eA==",
            "at_end": True,
            "complete": False,
            "seen": 2,
            "stored": 1,
            "truncated": True,
            "simulated": True,
            "guest_reported": True,
        }
        frame = (
            "id: checked-cursor\nevent: output\ndata: " + json.dumps(output) + "\n\n"
        )
        self.handler = lambda request: httpx.Response(
            200,
            content=(
                frame + 'event: gap\ndata: {"code":"output_expired"}\n\n'
            ).encode(),
            headers={"content-type": "text/event-stream"},
        )
        answer = await self.call(
            "output_stream",
            {"operation_id": OP, "cursor": "previous-cursor", "max_events": 4},
        )
        error = answer.structured_content["error"]
        self.assertEqual(error["kind"], "gap")
        self.assertEqual(error["code"], "output_expired")
        self.assertEqual(error["next_cursor"], "checked-cursor")
        self.assertEqual(len(error["events"]), 1)
        self.assertEqual(self.requests[-1].url.params["cursor"], "previous-cursor")
        self.handler = lambda request: httpx.Response(
            200,
            content=frame[:-1].encode(),
            headers={"content-type": "text/event-stream"},
        )
        answer = await self.call(
            "output_stream", {"operation_id": OP, "cursor": "previous-cursor"}
        )
        self.assertEqual(
            answer.structured_content["data"]["next_cursor"], "previous-cursor"
        )
        self.assertEqual(answer.structured_content["data"]["events"], [])

    async def test_oversized_result_does_not_hide_uncertainty_or_emit_secret_exception(
        self,
    ):
        self.assertTrue(result({"big": "x" * 262144}).is_error)

        def broken(request):
            raise RuntimeError(SECRET)

        self.handler = broken
        answer = await self.call(
            "execute", {"sandbox_id": SB, "idempotency_key": KEY, "body": COMMAND}
        )
        self.assertEqual(
            answer.structured_content["error"]["mutation_outcome"], "uncertain"
        )
        self.assertNotIn(SECRET, answer.content[0].text)


class FrameTests(unittest.TestCase):
    def test_frame_bounds_strict_json_ids_and_pending_requests(self):
        for raw in (
            b"x" * (MAX_FRAME_BYTES + 1),
            b"{}",
            b"\xff\n",
            b'{"jsonrpc":"2.0","id":1,"id":2}\n',
            b"[]\n",
            b'{"jsonrpc":"2.0","id":true}\n',
            b'{"jsonrpc":"2.0","id":1.0}\n',
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(FrameError):
                Frames().receive(raw)
        frames = Frames()
        for n in range(8):
            frames.receive(
                json.dumps({"jsonrpc": "2.0", "id": n, "method": "tools/list"}).encode()
                + b"\n"
            )
        with self.assertRaises(FrameError):
            frames.receive(b'{"jsonrpc":"2.0","id":8}\n')
        with self.assertRaises(FrameError):
            frames.receive(b'{"jsonrpc":"2.0","id":0}\n')
        frames.sending('{"jsonrpc":"2.0","id":0,"result":{}}\n')
        frames.receive(b'{"jsonrpc":"2.0","id":8,"method":"tools/list"}\n')


if __name__ == "__main__":
    unittest.main()
